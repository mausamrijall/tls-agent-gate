/**
 * Immutable audit trail for bounded agents.
 *
 * Every allowed or blocked action is recorded as a structured AuditEvent.
 * Records are hash-chained (each event carries the SHA-256 of the previous
 * one, and its own hash) so any tampering within a session is detectable.
 */
import { sha256Hex } from '@tls-agent-gate/core';

export const AUDIT_ACTION = {
  Allowed: 'allowed',
  Denied: 'denied',
  ConsentRequested: 'consent_requested',
  ConsentDenied: 'consent_denied',
  Executed: 'executed',
} as const;

export type AuditAction = (typeof AUDIT_ACTION)[keyof typeof AUDIT_ACTION];

export const DENY_REASON = {
  CapabilityDenied: 'ERR_CAPABILITY_DENIED',
  ToolNotFound: 'ERR_TOOL_NOT_FOUND',
  ArgumentInvalid: 'ERR_ARGUMENT_INVALID',
  OriginBlocked: 'ERR_ORIGIN_BLOCKED',
  LocalhostBlocked: 'ERR_LOCALHOST_BLOCKED',
  BudgetExceeded: 'ERR_BUDGET_EXCEEDED',
  StepsExceeded: 'ERR_STEPS_EXCEEDED',
  PayloadTooLarge: 'ERR_PAYLOAD_TOO_LARGE',
  ExecutionTimeout: 'ERR_EXECUTION_TIMEOUT',
  ConsentDenied: 'ERR_CONSENT_DENIED',
  ConsentRequired: 'ERR_CONSENT_REQUIRED',
  Internal: 'ERR_INTERNAL',
} as const;

export type DenyReason = (typeof DENY_REASON)[keyof typeof DENY_REASON];

export type ActionKind = 'tool' | 'command' | 'fetch' | 'agent-call' | 'system';

export interface AuditEvent {
  seq: number;
  /** ISO-8601 timestamp. */
  at: string;
  agentId: string;
  action: AuditAction;
  kind: ActionKind;
  /** Tool/command name, or the full URL for fetches/agent calls. */
  subject: string;
  policyDecision: 'allow' | 'deny' | 'pending';
  reason?: DenyReason;
  /** Safe (redacted) structured detail. */
  detail?: Record<string, unknown>;
  signatureKid?: string;
  manifestSha256?: string;
  durationMs?: number;
  /** SHA-256 of the previous record (empty for the first record). */
  prevHash: string;
  /** SHA-256 over this record's fields + prevHash. */
  hash: string;
}

export interface AuditSink {
  (event: AuditEvent): void | Promise<void>;
}

export class AuditTrail {
  private events: AuditEvent[] = [];
  private lastHash = '';
  private seq = 0;
  private readonly agentId: string;
  private readonly sink?: AuditSink;

  constructor(agentId: string, sink?: AuditSink) {
    this.agentId = agentId;
    this.sink = sink;
  }

  /** Append an event; computes the hash chain. Returns the stored event. */
  async append(input: Omit<AuditEvent, 'seq' | 'at' | 'prevHash' | 'hash' | 'agentId'>): Promise<AuditEvent> {
    const seq = ++this.seq;
    const prevHash = this.lastHash;
    const record: AuditEvent = {
      ...input,
      seq,
      at: new Date().toISOString(),
      agentId: this.agentId,
      prevHash,
      hash: '',
    };
    const hash = await sha256Hex(JSON.stringify({ seq, at: record.at, agentId: record.agentId, action: record.action, kind: record.kind, subject: record.subject, policyDecision: record.policyDecision, reason: record.reason ?? null, detail: record.detail ?? null, signatureKid: record.signatureKid ?? null, manifestSha256: record.manifestSha256 ?? null, durationMs: record.durationMs ?? null, prevHash }));
    record.hash = hash;
    this.lastHash = hash;
    this.events.push(record);
    if (this.sink) await this.sink(record);
    return record;
  }

  /** Frozen snapshot of all events. */
  snapshot(): readonly AuditEvent[] {
    return this.events.map((e) => ({ ...e, detail: e.detail ? { ...e.detail } : undefined }));
  }

  get length(): number {
    return this.events.length;
  }

  /** Verify the hash chain; returns true when intact. */
  async verify(): Promise<boolean> {
    let prev = '';
    for (const e of this.events) {
      if (e.prevHash !== prev) return false;
      if (e.hash !== (await sha256Hex(JSON.stringify({ seq: e.seq, at: e.at, agentId: e.agentId, action: e.action, kind: e.kind, subject: e.subject, policyDecision: e.policyDecision, reason: e.reason ?? null, detail: e.detail ?? null, signatureKid: e.signatureKid ?? null, manifestSha256: e.manifestSha256 ?? null, durationMs: e.durationMs ?? null, prevHash: e.prevHash })))) {
        return false;
      }
      prev = e.hash;
    }
    return true;
  }
}
