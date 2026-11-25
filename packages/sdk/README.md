# @tls-agent-gate/sdk

**Bounded Agent Execution SDK** — a default-deny capability & execution
boundary for agents.

An agent (LLM-driven or otherwise) only ever *proposes* intents. The SDK's
broker intercepts every proposal and checks it against the signed capability
policy before anything runs. If the action is not explicitly allowlisted, has
invalid arguments, targets an unallowlisted origin, exceeds budget/rate/timeout
limits, or requires consent that was not granted — it is blocked and logged.
Nothing executes silently.

This is what protects you from a **prompt-injected or misbehaving agent** that
tries to call an unauthorized tool, read restricted context, hit a domain
outside its scope, or make an unapproved cross-site call while passing
unredacted user data.

## What it provides

- **Capability policy** (`AgentCapabilityPolicy`) — allowed tools/commands with
  JSON-Schema argument validation, allowed origins/URL patterns, `allowLocalAgents`
  (blocked by default), max calls/steps/payload, execution timeout, sensitive-field
  redaction, and consent triggers. **Deny-by-default.**
- **Command/Tool Broker** — intercepts every `tool` / `command` / `fetch` /
  `agent-call` proposal, enforces the policy, and only then dispatches. Blocked
  attempts return a structured reason code.
- **Signed remote agent calls** — when calling an HTTPS agentic endpoint, the
  SDK attaches `X-Agent-Identity`, `X-Agent-Manifest`, and `X-Agent-Signature`
  via an injected signer (browser `AgentRuntime` or a core-based signer).
- **Isolated runner** — untrusted parsing/sanitization runs inside a WebWorker
  (clean fallback for Node/tests). No raw functions or privileged globals cross
  the boundary.
- **Immutable audit trail** — hash-chained records of `allowed`, `denied`,
  `consent_requested`, `consent_denied`, and `executed` events with reason codes
  (tamper-evident within a session).

## Quick start

```ts
import { createBoundedAgent } from '@tls-agent-gate/sdk';
import { createCoreSigner } from '@tls-agent-gate/sdk';

// A signer ties the agent to its TLS-anchored identity (core-based here).
const signer = await createCoreSigner({
  identityUrl: 'https://caller.example/.well-known/agent-identity.json',
  manifestUrl: 'https://caller.example/agent-manifest.json',
  privateKeyJwk, // loaded from your secret store
  manifestText: '<exact bytes served at manifestUrl>',
});

const agent = await createBoundedAgent({
  agentId: 'my-agent',
  identitySigner: signer,
  policy: {
    // Deny-by-default: only these are allowed.
    allowedTools: [
      {
        name: 'search',
        argSchema: {
          type: 'object',
          properties: { q: { type: 'string' }, limit: { type: 'integer', maximum: 25 } },
          required: ['q'],
          additionalProperties: false,
        },
      },
    ],
    allowedCommands: ['status'],
    allowedOrigins: ['https://protected.example'],
    allowLocalAgents: false,
    maxCallsPerTurn: 20,
    maxPayloadBytes: 4096,
    executionTimeoutMs: 8000,
    dataRedactionRules: [{ pattern: /token/i }],
    requireConsentFor: [{ type: 'cross-site' }],
  },
  tools: [
    { name: 'search', executor: async (args) => runSearch(args.q) },
  ],
  commands: {
    status: () => ({ ok: true }),
  },
  onConsentRequired: async (req) => {
    return window.confirm(`Allow ${req.action.kind} to ${req.subject}?`);
  },
  onAuditEvent: (event) => pushToUi(event),
});

// Allowed + signed remote agent call:
const result = await agent.callAgent(
  { baseUrl: 'https://protected.example', path: '/api/agent/search' },
  { method: 'GET', caps: ['search'] },
);
console.log(result.decision, result.value?.verifiedByTarget);

// Anything else is blocked before it can run:
await agent.runTool('remove_all', {});            // → deny, ERR_TOOL_NOT_FOUND
await agent.runCommand('shell:rm');               // → deny, ERR_CAPABILITY_DENIED
await agent.callAgent({ baseUrl: 'https://evil.invalid', path: '/admin' }); // → deny, ERR_ORIGIN_BLOCKED

// Everything is on the audit trail:
console.log(agent.auditTrail());
console.log(await agent.verifyAuditTrail());      // true when the chain is intact
```

## Policy semantics (defaults)

| Field | Default | Meaning |
| --- | --- | --- |
| `allowedTools` / `allowedCommands` | `[]` | Allowlists. Empty ⇒ nothing runs. |
| `allowedOrigins` / `allowedTargetPatterns` | `[]` | Origin allowlist for outbound calls/agent calls. |
| `allowLocalAgents` | `false` | Blocks `localhost`/private origins unless explicitly enabled. |
| `allowedDevKeyThumbprints` | `[]` | Dev keys honored when `allowLocalAgents` is true. |
| `maxCallsPerTurn` | `50` | Executions per turn. |
| `maxStepsPerTurn` | `200` | Proposed actions per turn (denied proposals count). |
| `maxPayloadBytes` | `1 MiB` | Outbound payload cap. |
| `executionTimeoutMs` | `30_000` | Per-execution timeout. |
| `dataRedactionRules` | `[]` | Regex/key rules applied to outbound payloads and audit detail. |
| `requireConsentFor` | `[{type:'cross-site'}]` | Which actions need explicit consent. |
| `strictTools` | `true` | Undefined tools are denied. |

Deny reasons are stable machine-readable codes:
`ERR_CAPABILITY_DENIED`, `ERR_TOOL_NOT_FOUND`, `ERR_ARGUMENT_INVALID`,
`ERR_ORIGIN_BLOCKED`, `ERR_LOCALHOST_BLOCKED`, `ERR_BUDGET_EXCEEDED`,
`ERR_STEPS_EXCEEDED`, `ERR_PAYLOAD_TOO_LARGE`, `ERR_EXECUTION_TIMEOUT`,
`ERR_CONSENT_DENIED`, `ERR_CONSENT_REQUIRED`, `ERR_INTERNAL`.

## Using the browser runtime as the signer

In a browser page, reuse the `AgentRuntime` you already have:

```ts
import { AgentRuntime } from '@tls-agent-gate/browser';
import { createBoundedAgent } from '@tls-agent-gate/sdk';

const runtime = await AgentRuntime.create({ /* ... */ });
const agent = await createBoundedAgent({
  identitySigner: {
    identityUrl: runtime.identityUrl,
    keyId: runtime.agentKeyId,
    algorithm: 'Ed25519',
    manifestSha256: runtime.manifestSha256Hex,
    sign: (req) => runtime.signOutboundRequest(req.url, req.method, req.body),
  },
  /* policy/tools/... */
});
```

## Isolated runner

`createSandboxRunner({ useWorker: true, workerUrl: '/vendor/@tls-agent-gate/sdk/worker.js' })`
runs untrusted parsing/sanitization off the main thread. When no Worker is
available (Node, edge workers, tests) it falls back to a deterministic inline
implementation. The worker handles only serializable messages — it never
receives functions, DOM references, or globals.

## Audit trail

Every event is a structured record with `seq`, timestamp, `action`, `kind`,
`subject`, `policyDecision`, `reason`, redacted `detail`, `signatureKid`,
`manifestSha256`, and a hash chain (`prevHash` → `hash`). `verifyAuditTrail()`
confirms chain integrity.

## Tests

```bash
cd packages/sdk
npm test
```

Covers: allowlisted vs. blocked tools/commands, invalid arguments, unallowlisted
origins, `allowLocalAgents` enforcement, budget/timeout/payload caps, consent
approval vs. denial (and fail-closed default), redaction, signed remote calls
(header presence + offline signature verification), and audit-chain integrity.
