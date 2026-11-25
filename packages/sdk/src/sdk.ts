/**
 * Bounded Agent factory.
 *
 * `createBoundedAgent` boots an agent inside a policy-locked execution
 * container and returns a handle whose only way to do anything is to
 * *propose* actions through the deny-by-default broker.
 */
import type { AgentManifest } from '@tls-agent-gate/core';
import { AuditTrail, type AuditEvent, type AuditSink } from './audit.ts';
import { Broker, type ActionResult, type CommandHandler, type ConsentRequest, type ProposedAction, type ToolRegistration } from './broker.ts';
import { normalizePolicy, type AgentCapabilityPolicy } from './policy.ts';
import type { SandboxRunner } from './runner.ts';
import type { AgentRequestSigner } from './signer.ts';

export interface CreateBoundedAgentOptions {
  agentId?: string;
  /** Open Agentic Web manifest (optional but recommended). */
  manifest?: AgentManifest;
  /** Signature provider for outbound agent calls (core signer or browser AgentRuntime). */
  identitySigner: AgentRequestSigner;
  /** Partial capability policy; omitted fields keep the deny-by-default defaults. */
  policy?: Partial<AgentCapabilityPolicy>;
  tools?: ToolRegistration[];
  commands?: Record<string, CommandHandler>;
  onConsentRequired?: (req: ConsentRequest) => boolean | Promise<boolean>;
  onAuditEvent?: AuditSink;
  runner?: SandboxRunner;
  fetchImpl?: typeof fetch;
}

export interface BoundedAgentHandle {
  readonly agentId: string;
  readonly policy: AgentCapabilityPolicy;
  readonly manifest?: AgentManifest;
  readonly signer: AgentRequestSigner;

  /** Propose any action; the broker decides (deny-by-default). */
  propose(action: ProposedAction): Promise<ActionResult>;
  runTool(name: string, args?: Record<string, unknown>): Promise<ActionResult>;
  runCommand(name: string, args?: Record<string, unknown>): Promise<ActionResult>;
  fetch(url: string, opts?: { method?: string; headers?: Record<string, string>; body?: unknown }): Promise<ActionResult>;
  callAgent(target: { baseUrl: string; path: string }, opts?: { method?: string; body?: unknown; caps?: string[]; manifestSha256?: string }): Promise<ActionResult>;

  beginTurn(): void;
  auditTrail(): readonly AuditEvent[];
  verifyAuditTrail(): Promise<boolean>;
  dispose(): void;
}

export async function createBoundedAgent(options: CreateBoundedAgentOptions): Promise<BoundedAgentHandle> {
  const agentId = options.agentId ?? options.manifest?.name ?? 'bounded-agent';
  const policy = normalizePolicy(options.policy);

  const broker = new Broker({
    agentId,
    policy,
    tools: options.tools ?? [],
    commands: options.commands ?? {},
    signer: options.identitySigner,
    runner: options.runner,
    onConsentRequired: options.onConsentRequired,
    onAuditEvent: options.onAuditEvent,
    fetchImpl: options.fetchImpl,
  });

  const handle: BoundedAgentHandle = {
    agentId,
    policy,
    manifest: options.manifest,
    signer: options.identitySigner,

    propose: (action) => broker.propose(action),

    runTool: (name, args) => broker.propose({ kind: 'tool', tool: name, args }),

    runCommand: (name, args) => broker.propose({ kind: 'command', command: name, args }),

    fetch: (url, opts) =>
      broker.propose({
        kind: 'fetch',
        url,
        method: opts?.method,
        headers: opts?.headers,
        body: opts?.body,
      }),

    callAgent: (target, opts) => {
      const url = new URL(target.path, target.baseUrl).toString();
      return broker.propose({
        kind: 'agent-call',
        url,
        method: opts?.method,
        body: opts?.body,
        caps: opts?.caps,
        manifestSha256: opts?.manifestSha256,
      });
    },

    beginTurn: () => broker.beginTurn(),
    auditTrail: () => broker.auditTrail.snapshot(),
    verifyAuditTrail: () => broker.auditTrail.verify(),
    dispose: () => {
      // Nothing global to tear down; worker runner disposal is the caller's job.
    },
  };

  return handle;
}

export { AuditTrail };
