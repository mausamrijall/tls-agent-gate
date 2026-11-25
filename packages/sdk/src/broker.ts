/**
 * Deterministic Command/Tool Broker (deny-by-default).
 *
 * The agent/LLM only *proposes* intents. The broker intercepts every
 * proposal, checks the capability policy (allowlists, argument schemas,
 * origin rules, budget/rate/timeout caps, redaction, consent), and only
 * then dispatches execution. Every allowed and blocked attempt is written
 * to the immutable audit trail.
 */
import {
  isPrivateOrLoopbackHost,
  validateSchema,
  type SchemaObject,
} from '@tls-agent-gate/core';
import { AuditTrail, DENY_REASON, type ActionKind, type AuditEvent, type AuditSink, type DenyReason } from './audit.ts';
import {
  policyAllowsCommand,
  policyAllowsOrigin,
  policyAllowsTool,
  policyRequiresConsent,
  type AgentCapabilityPolicy,
  type ToolSpec,
} from './policy.ts';
import { redactValue } from './redact.ts';
import type { SandboxRunner } from './runner.ts';
import type { AgentRequestSigner } from './signer.ts';

export type ProposedAction =
  | { kind: 'tool'; tool: string; args?: Record<string, unknown> }
  | { kind: 'command'; command: string; args?: Record<string, unknown> }
  | { kind: 'fetch'; url: string; method?: string; headers?: Record<string, string>; body?: unknown }
  | { kind: 'agent-call'; url: string; method?: string; body?: unknown; caps?: string[]; manifestSha256?: string };

export interface ToolRegistration extends ToolSpec {
  executor: ToolExecutor;
}

export interface ToolContext {
  agentId: string;
  signal: AbortSignal;
  redact(value: unknown): unknown;
}

export type ToolExecutor = (args: Record<string, unknown>, ctx: ToolContext) => unknown | Promise<unknown>;
export type CommandHandler = (args: Record<string, unknown>, ctx: ToolContext) => unknown | Promise<unknown>;

export interface ConsentRequest {
  action: ProposedAction;
  subject: string;
  origin?: string;
  detail: Record<string, unknown>;
}

export interface ActionResult {
  ok: boolean;
  decision: 'allow' | 'deny';
  reason?: DenyReason;
  /** Safe (redacted) execution result. */
  value?: unknown;
  audit?: AuditEvent;
}

export interface AgentCallResult {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  text: string;
  sanitizedText: string;
  verifiedByTarget: { domain: string } | null;
  signatureKid?: string;
  manifestSha256?: string;
  error?: string;
}

export interface BrokerOptions {
  agentId: string;
  policy: AgentCapabilityPolicy;
  tools: ToolRegistration[];
  commands: Record<string, CommandHandler>;
  signer?: AgentRequestSigner;
  runner?: SandboxRunner;
  onConsentRequired?: (req: ConsentRequest) => boolean | Promise<boolean>;
  onAuditEvent?: AuditSink;
  fetchImpl?: typeof fetch;
}

/** Run a task with an AbortController; abort + report when the timeout fires. */
async function executeWithTimeout<T>(
  controller: AbortController,
  task: () => Promise<T>,
  ms: number,
): Promise<{ timedOut: boolean; value?: T }> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<{ timedOut: true }>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ timedOut: true });
    }, ms);
    if (typeof (timer as { unref?: () => void }).unref === 'function') {
      (timer as { unref: () => void }).unref();
    }
  });
  try {
    const value = await Promise.race([Promise.resolve().then(task), timeout]);
    if (value && typeof value === 'object' && 'timedOut' in value && (value as { timedOut: boolean }).timedOut) {
      return { timedOut: true };
    }
    return { timedOut: false, value: value as T };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function bodyBytes(body: unknown): number {
  if (body === undefined || body === null) return 0;
  if (typeof body === 'string') return new TextEncoder().encode(body).byteLength;
  if (body instanceof Uint8Array) return body.byteLength;
  if (body instanceof ArrayBuffer) return body.byteLength;
  return new TextEncoder().encode(JSON.stringify(body)).byteLength;
}

function redactDetail(detail: Record<string, unknown>, rules: AgentCapabilityPolicy['dataRedactionRules']): Record<string, unknown> {
  return redactValue(detail, rules) as Record<string, unknown>;
}

export class Broker {
  readonly auditTrail: AuditTrail;
  private steps = 0;
  private calls = 0;
  private readonly opts: BrokerOptions;

  constructor(opts: BrokerOptions) {
    this.opts = opts;
    this.auditTrail = new AuditTrail(opts.agentId, opts.onAuditEvent);
  }

  /** Reset per-turn counters (call at the start of each agent turn). */
  beginTurn(): void {
    this.steps = 0;
    this.calls = 0;
  }

  private async deny(kind: ActionKind, subject: string, reason: DenyReason, detail?: Record<string, unknown>): Promise<ActionResult> {
    const audit = await this.auditTrail.append({
      action: 'denied',
      kind,
      subject,
      policyDecision: 'deny',
      reason,
      detail: detail ? redactDetail(detail, this.opts.policy.dataRedactionRules) : undefined,
    });
    return { ok: false, decision: 'deny', reason, audit };
  }

  async propose(action: ProposedAction): Promise<ActionResult> {
    this.steps++;
    if (this.steps > this.opts.policy.maxStepsPerTurn) {
      return this.deny('system', `step ${this.steps}`, DENY_REASON.StepsExceeded, { maxSteps: this.opts.policy.maxStepsPerTurn });
    }
    switch (action.kind) {
      case 'tool':
        return this.proposeTool(action);
      case 'command':
        return this.proposeCommand(action);
      case 'fetch':
        return this.proposeNetwork(action, false);
      case 'agent-call':
        return this.proposeNetwork(action, true);
    }
  }

  private checkCalls(): boolean {
    if (this.calls >= this.opts.policy.maxCallsPerTurn) return false;
    this.calls++;
    return true;
  }

  private async requestConsent(kind: ActionKind, subject: string, origin: string | undefined, action: ProposedAction): Promise<ActionResult | 'approved'> {
    const detail = redactDetail({ subject, ...(origin ? { origin } : {}) }, this.opts.policy.dataRedactionRules);
    await this.auditTrail.append({ action: 'consent_requested', kind, subject, policyDecision: 'pending', detail });
    if (!this.opts.onConsentRequired) {
      await this.auditTrail.append({ action: 'consent_denied', kind, subject, policyDecision: 'deny', reason: DENY_REASON.ConsentRequired, detail });
      return this.deny(kind, subject, DENY_REASON.ConsentRequired, { origin });
    }
    const approved = await this.opts.onConsentRequired({ action, subject, origin, detail });
    if (!approved) {
      await this.auditTrail.append({ action: 'consent_denied', kind, subject, policyDecision: 'deny', reason: DENY_REASON.ConsentDenied, detail });
      return this.deny(kind, subject, DENY_REASON.ConsentDenied, { origin });
    }
    return 'approved';
  }

  private async proposeTool(action: Extract<ProposedAction, { kind: 'tool' }>): Promise<ActionResult> {
    const name = action.tool;
    const spec = policyAllowsTool(this.opts.policy, name);
    if (!spec) {
      return this.deny('tool', name, DENY_REASON.ToolNotFound, { policy: 'allowedTools' });
    }
    const registration = this.opts.tools.find((t) => t.name === name);
    if (!registration) {
      return this.deny('tool', name, DENY_REASON.ToolNotFound, { reason: 'not registered' });
    }
    const args = action.args ?? {};

    if (spec.argSchema) {
      const result = validateSchema(args, spec.argSchema as SchemaObject);
      if (!result.valid) {
        return this.deny('tool', name, DENY_REASON.ArgumentInvalid, { errors: result.errors.slice(0, 5) });
      }
    }

    if (!this.checkCalls()) {
      return this.deny('tool', name, DENY_REASON.BudgetExceeded, { maxCalls: this.opts.policy.maxCallsPerTurn });
    }

    if (spec.requiresConsent === true || policyRequiresConsent(this.opts.policy, 'tool', name)) {
      const consent = await this.requestConsent('tool', name, undefined, action);
      if (consent !== 'approved') return consent;
    }

    await this.auditTrail.append({
      action: 'allowed',
      kind: 'tool',
      subject: name,
      policyDecision: 'allow',
      detail: { args: redactValue(args, this.opts.policy.dataRedactionRules) },
    });

    const controller = new AbortController();
    const outcome = await executeWithTimeout(
      controller,
      () => Promise.resolve(registration.executor(args, { agentId: this.opts.agentId, signal: controller.signal, redact: (v) => redactValue(v, this.opts.policy.dataRedactionRules) })),
      this.opts.policy.executionTimeoutMs,
    );

    if (outcome.timedOut) {
      return this.deny('tool', name, DENY_REASON.ExecutionTimeout, { timeoutMs: this.opts.policy.executionTimeoutMs });
    }

    const audit = await this.auditTrail.append({
      action: 'executed',
      kind: 'tool',
      subject: name,
      policyDecision: 'allow',
      detail: { result: redactValue(outcome.value, this.opts.policy.dataRedactionRules) },
    });
    return { ok: true, decision: 'allow', value: redactValue(outcome.value, this.opts.policy.dataRedactionRules), audit };
  }

  private async proposeCommand(action: Extract<ProposedAction, { kind: 'command' }>): Promise<ActionResult> {
    const name = action.command;
    if (!policyAllowsCommand(this.opts.policy, name)) {
      return this.deny('command', name, DENY_REASON.CapabilityDenied, { policy: 'allowedCommands' });
    }
    const handler = this.opts.commands[name];
    if (!handler) {
      return this.deny('command', name, DENY_REASON.CapabilityDenied, { reason: 'not registered' });
    }
    if (!this.checkCalls()) {
      return this.deny('command', name, DENY_REASON.BudgetExceeded, { maxCalls: this.opts.policy.maxCallsPerTurn });
    }
    const args = action.args ?? {};

    if (policyRequiresConsent(this.opts.policy, 'command', name)) {
      const consent = await this.requestConsent('command', name, undefined, action);
      if (consent !== 'approved') return consent;
    }

    await this.auditTrail.append({
      action: 'allowed',
      kind: 'command',
      subject: name,
      policyDecision: 'allow',
      detail: { args: redactValue(args, this.opts.policy.dataRedactionRules) },
    });

    const controller = new AbortController();
    const outcome = await executeWithTimeout(
      controller,
      () => Promise.resolve(handler(args, { agentId: this.opts.agentId, signal: controller.signal, redact: (v) => redactValue(v, this.opts.policy.dataRedactionRules) })),
      this.opts.policy.executionTimeoutMs,
    );

    if (outcome.timedOut) {
      return this.deny('command', name, DENY_REASON.ExecutionTimeout, { timeoutMs: this.opts.policy.executionTimeoutMs });
    }

    const audit = await this.auditTrail.append({
      action: 'executed',
      kind: 'command',
      subject: name,
      policyDecision: 'allow',
      detail: { result: redactValue(outcome.value, this.opts.policy.dataRedactionRules) },
    });
    return { ok: true, decision: 'allow', value: redactValue(outcome.value, this.opts.policy.dataRedactionRules), audit };
  }

  private async proposeNetwork(action: Extract<ProposedAction, { kind: 'fetch' | 'agent-call' }>, isAgentCall: boolean): Promise<ActionResult> {
    const kind: ActionKind = isAgentCall ? 'agent-call' : 'fetch';
    const url = action.url;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return this.deny(kind, url, DENY_REASON.OriginBlocked, { reason: 'invalid URL' });
    }

    if (isPrivateOrLoopbackHost(parsed.hostname) && !this.opts.policy.allowLocalAgents) {
      return this.deny(kind, url, DENY_REASON.LocalhostBlocked, { host: parsed.hostname });
    }
    if (!policyAllowsOrigin(this.opts.policy, url)) {
      return this.deny(kind, url, DENY_REASON.OriginBlocked, { origin: parsed.origin });
    }

    if (!this.checkCalls()) {
      return this.deny(kind, url, DENY_REASON.BudgetExceeded, { maxCalls: this.opts.policy.maxCallsPerTurn });
    }

    const payloadBytes = bodyBytes(action.body);
    if (payloadBytes > this.opts.policy.maxPayloadBytes) {
      return this.deny(kind, url, DENY_REASON.PayloadTooLarge, { bytes: payloadBytes, maxBytes: this.opts.policy.maxPayloadBytes });
    }

    const origin = parsed.origin;
    if (policyRequiresConsent(this.opts.policy, kind, url, origin)) {
      const consent = await this.requestConsent(kind, url, origin, action);
      if (consent !== 'approved') return consent;
    }

    const redactedBody = action.body !== undefined ? redactValue(action.body, this.opts.policy.dataRedactionRules) : undefined;
    const headers: Record<string, string> = action.kind === 'fetch' && action.headers ? { ...action.headers } : {};

    let signatureKid: string | undefined;
    let manifestSha256: string | undefined;
    if (isAgentCall && this.opts.signer) {
      const signed = await this.opts.signer.sign({
        url,
        method: action.method ?? 'GET',
        body: typeof redactedBody === 'string' ? redactedBody : redactedBody !== undefined ? JSON.stringify(redactedBody) : undefined,
      });
      Object.assign(headers, signed);
      signatureKid = this.opts.signer.keyId;
      manifestSha256 = action.kind === 'agent-call' && action.manifestSha256 ? action.manifestSha256 : this.opts.signer.manifestSha256;
    }

    await this.auditTrail.append({
      action: 'allowed',
      kind,
      subject: url,
      policyDecision: 'allow',
      detail: { origin, headers: redactValue(headers, this.opts.policy.dataRedactionRules), body: redactedBody !== undefined ? redactedBody : undefined },
      signatureKid,
      manifestSha256,
    });

    const fetchImpl = this.opts.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) {
      return this.deny(kind, url, DENY_REASON.Internal, { reason: 'no fetch available' });
    }

    const controller = new AbortController();
    const outcome = await executeWithTimeout(
      controller,
      async () => {
        const res = await fetchImpl(url, {
          method: action.method ?? 'GET',
          headers,
          body: redactedBody !== undefined ? (typeof redactedBody === 'string' ? redactedBody : JSON.stringify(redactedBody)) : undefined,
          signal: controller.signal,
        });
        const text = await res.text();
        const responseHeaders: Record<string, string> = {};
        res.headers.forEach((value, key) => {
          responseHeaders[key.toLowerCase()] = value;
        });
        const contentType = res.headers.get('content-type') ?? '';
        const sanitizedText = this.opts.runner ? await this.opts.runner.runSanitize(contentType, text) : text;
        const verifiedDomain = (responseHeaders['x-verified-agent'] ?? '').trim() || null;
        const agentResult: AgentCallResult = {
          status: res.status,
          ok: res.ok,
          headers: responseHeaders,
          text,
          sanitizedText,
          verifiedByTarget: verifiedDomain ? { domain: verifiedDomain } : null,
          signatureKid,
          manifestSha256,
        };
        return agentResult;
      },
      this.opts.policy.executionTimeoutMs,
    );

    if (outcome.timedOut) {
      return this.deny(kind, url, DENY_REASON.ExecutionTimeout, { timeoutMs: this.opts.policy.executionTimeoutMs });
    }

    const value = outcome.value as AgentCallResult;
    const audit = await this.auditTrail.append({
      action: 'executed',
      kind,
      subject: url,
      policyDecision: 'allow',
      detail: {
        status: value.status,
        verifiedByTarget: value.verifiedByTarget?.domain ?? null,
        headers: redactValue(value.headers, this.opts.policy.dataRedactionRules),
      },
      signatureKid,
      manifestSha256,
    });
    return { ok: value.ok, decision: 'allow', value, audit };
  }
}
