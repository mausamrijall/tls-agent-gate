/**
 * @tls-agent-gate/sdk — Bounded Agent Execution SDK.
 *
 * A default-deny capability & execution boundary for agents:
 *   - policy (allowlists, schemas, origins, budget, redaction, consent)
 *   - broker (intercepts every proposal before execution)
 *   - isolated runner (WebWorker sandbox w/ fallback)
 *   - immutable, hash-chained audit trail
 *   - core signer (X-Agent-* headers for signed remote agent calls)
 */
export * from './policy.ts';
export * from './audit.ts';
export * from './redact.ts';
export * from './sanitize.ts';
export * from './runner.ts';
export * from './signer.ts';
export * from './broker.ts';
export * from './sdk.ts';
