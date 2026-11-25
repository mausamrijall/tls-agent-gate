import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, type AgentKeyPair } from '@tls-agent-gate/core';
import { createBoundedAgent } from '../src/sdk.ts';
import { createCoreSigner } from '../src/signer.ts';
import { createSandboxRunner } from '../src/runner.ts';
import { DENY_REASON } from '../src/audit.ts';
import type { AgentCapabilityPolicy } from '../src/policy.ts';

async function makeSigner(pair?: AgentKeyPair) {
  const keyPair = pair ?? (await generateKeyPair('Ed25519'));
  const signer = await createCoreSigner({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    privateKeyJwk: keyPair.privateKeyJwk,
    manifestText: JSON.stringify({ schemaVersion: 'agent-manifest-v1', name: 'Caller', capabilities: [{ id: 'search', name: 'Search' }] }),
  });
  return { keyPair, signer };
}

function basePolicy(over?: Partial<AgentCapabilityPolicy>): Partial<AgentCapabilityPolicy> {
  return {
    allowedTools: [{ name: 'search', argSchema: { type: 'object', properties: { q: { type: 'string' }, limit: { type: 'integer', maximum: 25 } }, required: ['q'], additionalProperties: false } }],
    allowedCommands: ['status'],
    allowedOrigins: ['https://protected.example'],
    allowLocalAgents: false,
    maxCallsPerTurn: 5,
    maxStepsPerTurn: 50,
    maxPayloadBytes: 1024,
    executionTimeoutMs: 2000,
    requireConsentFor: [{ type: 'cross-site' }],
    ...over,
  };
}

async function makeAgent(over?: { policy?: Partial<AgentCapabilityPolicy>; tools?: any[]; commands?: Record<string, unknown>; fetchImpl?: typeof fetch; consent?: (r: any) => boolean | Promise<boolean>; pair?: AgentKeyPair }) {
  const { signer } = await makeSigner(over?.pair);
  const audits: any[] = [];
  const agent = await createBoundedAgent({
    agentId: 'test-agent',
    manifest: { schemaVersion: 'agent-manifest-v1', name: 'Test Agent', capabilities: [{ id: 'search', name: 'Search' }] },
    identitySigner: signer,
    policy: basePolicy(over?.policy),
    tools: over?.tools ?? [
      {
        name: 'search',
        description: 'search',
        executor: (args: Record<string, unknown>) => ({ results: [`hit:${String(args.q)}`] }),
      },
    ],
    commands: (over?.commands as Record<string, any>) ?? {
      status: () => ({ up: true }),
    },
    onConsentRequired: over?.consent,
    onAuditEvent: (e: any) => audits.push(e),
    fetchImpl: over?.fetchImpl,
    runner: createSandboxRunner({ useWorker: false }),
  });
  return { agent, audits, signer };
}

test('deny-by-default: unallowlisted tool is blocked with audit reason', async () => {
  const { agent, audits } = await makeAgent();
  const result = await agent.runTool('delete_all', {});
  assert.equal(result.decision, 'deny');
  assert.equal(result.reason, DENY_REASON.ToolNotFound);
  assert.ok(audits.some((a) => a.action === 'denied' && a.reason === DENY_REASON.ToolNotFound));
});

test('allowlisted tool executes and emits allowed + executed audits', async () => {
  const { agent, audits } = await makeAgent({ policy: { requireConsentFor: [] } });
  const result = await agent.runTool('search', { q: 'agents' });
  assert.equal(result.decision, 'allow');
  assert.deepEqual(result.value, { results: ['hit:agents'] });
  assert.ok(audits.some((a) => a.action === 'allowed' && a.kind === 'tool'));
  assert.ok(audits.some((a) => a.action === 'executed'));
});

test('invalid tool arguments are rejected by schema', async () => {
  const { agent } = await makeAgent();
  const result = await agent.runTool('search', { q: 'x', limit: 999 });
  assert.equal(result.decision, 'deny');
  assert.equal(result.reason, DENY_REASON.ArgumentInvalid);
});

test('missing required argument is rejected', async () => {
  const { agent } = await makeAgent();
  const result = await agent.runTool('search', {});
  assert.equal(result.reason, DENY_REASON.ArgumentInvalid);
});

test('command allowlist is enforced', async () => {
  const { agent } = await makeAgent();
  const ok = await agent.runCommand('status');
  assert.equal(ok.decision, 'allow');
  const blocked = await agent.runCommand('shell:rm');
  assert.equal(blocked.decision, 'deny');
  assert.equal(blocked.reason, DENY_REASON.CapabilityDenied);
});

test('unallowlisted target origin is blocked', async () => {
  const { agent } = await makeAgent({ policy: { requireConsentFor: [] } });
  const result = await agent.callAgent({ baseUrl: 'https://evil.example', path: '/admin' });
  assert.equal(result.decision, 'deny');
  assert.equal(result.reason, DENY_REASON.OriginBlocked);
});

test('localhost target is blocked unless allowLocalAgents', async () => {
  const fakeFetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;

  const { agent } = await makeAgent({ policy: { requireConsentFor: [], allowedOrigins: ['http://localhost:4174'] }, fetchImpl: fakeFetch });
  const blocked = await agent.callAgent({ baseUrl: 'http://localhost:4174', path: '/api' });
  assert.equal(blocked.reason, DENY_REASON.LocalhostBlocked);

  const { agent: local } = await makeAgent({ policy: { requireConsentFor: [], allowedOrigins: ['http://localhost:4174'], allowLocalAgents: true }, fetchImpl: fakeFetch });
  const allowed = await local.callAgent({ baseUrl: 'http://localhost:4174', path: '/api' });
  assert.equal(allowed.decision, 'allow');
});

test('budget: maxCallsPerTurn is enforced', async () => {
  const { agent } = await makeAgent({ policy: { requireConsentFor: [], maxCallsPerTurn: 2 } });
  assert.equal((await agent.runTool('search', { q: '1' })).decision, 'allow');
  assert.equal((await agent.runTool('search', { q: '2' })).decision, 'allow');
  const third = await agent.runTool('search', { q: '3' });
  assert.equal(third.decision, 'deny');
  assert.equal(third.reason, DENY_REASON.BudgetExceeded);
});

test('maxStepsPerTurn counts denied proposals', async () => {
  const { agent } = await makeAgent({ policy: { requireConsentFor: [], maxStepsPerTurn: 2 } });
  // 2 proposals then the 3rd is denied at the step gate.
  await agent.propose({ kind: 'command', command: 'status' });
  await agent.propose({ kind: 'command', command: 'status' });
  const third = await agent.propose({ kind: 'command', command: 'status' });
  assert.equal(third.reason, DENY_REASON.StepsExceeded);
});

test('payload size cap blocks oversized bodies', async () => {
  const { agent } = await makeAgent({ policy: { requireConsentFor: [], maxPayloadBytes: 32 } });
  const result = await agent.callAgent({ baseUrl: 'https://protected.example', path: '/api' }, { body: { big: 'x'.repeat(1000) } });
  assert.equal(result.reason, DENY_REASON.PayloadTooLarge);
});

test('redaction strips sensitive fields from outbound body and audit detail', async () => {
  const sent: any[] = [];
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    sent.push(init);
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;

  const { agent, audits } = await makeAgent({
    policy: { requireConsentFor: [], dataRedactionRules: [{ pattern: /token/i, replacement: '[REDACTED]' }] },
    fetchImpl,
  });
  const result = await agent.callAgent({ baseUrl: 'https://protected.example', path: '/api' }, { body: { token: 'supersecret', q: 'ok' } });
  assert.equal(result.decision, 'allow');
  const bodySent = JSON.parse(sent[0]!.body as string);
  assert.equal(bodySent.token, '[REDACTED]');
  assert.equal(bodySent.q, 'ok');
  const deniedAudits = audits.filter((a) => a.action === 'executed' || a.action === 'allowed');
  for (const a of deniedAudits) {
    assert.ok(!JSON.stringify(a).includes('supersecret'));
  }
});

test('consent approval required for cross-site call; denied consent blocks with audit', async () => {
  const fakeFetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;

  // Approval path
  const approvedAgent = await makeAgent({ consent: () => true, policy: { requireConsentFor: [{ type: 'cross-site' }] }, fetchImpl: fakeFetch });
  const approved = await approvedAgent.agent.callAgent({ baseUrl: 'https://protected.example', path: '/api' });
  assert.equal(approved.decision, 'allow');
  assert.ok(approvedAgent.audits.some((a) => a.action === 'consent_requested'));
  assert.ok(approvedAgent.audits.some((a) => a.action === 'consent_denied') === false);

  // Denial path (blocked before any fetch)
  const deniedAgent = await makeAgent({ consent: () => false, policy: { requireConsentFor: [{ type: 'cross-site' }] } });
  const denied = await deniedAgent.agent.callAgent({ baseUrl: 'https://protected.example', path: '/api' });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reason, DENY_REASON.ConsentDenied);
  assert.ok(deniedAgent.audits.some((a) => a.action === 'consent_denied'));
});

test('missing consent hook fails closed with ERR_CONSENT_REQUIRED', async () => {
  const { agent, audits } = await makeAgent({ policy: { requireConsentFor: [{ type: 'cross-site' }] } });
  const result = await agent.callAgent({ baseUrl: 'https://protected.example', path: '/api' });
  assert.equal(result.reason, DENY_REASON.ConsentRequired);
  assert.ok(audits.some((a) => a.action === 'consent_denied'));
});

test('execution timeout blocks a slow tool', async () => {
  const { agent } = await makeAgent({
    policy: { requireConsentFor: [], executionTimeoutMs: 50 },
    tools: [
      {
        name: 'search',
        executor: async () => {
          await new Promise((r) => setTimeout(r, 500));
          return { ok: true };
        },
      },
    ],
  });
  const result = await agent.runTool('search', { q: 'x' });
  assert.equal(result.decision, 'deny');
  assert.equal(result.reason, DENY_REASON.ExecutionTimeout);
});

test('audit trail is hash-chained and verifiable', async () => {
  const { agent } = await makeAgent({ policy: { requireConsentFor: [] } });
  await agent.runTool('search', { q: 'a' });
  await agent.runTool('nope', {});
  assert.equal(await agent.verifyAuditTrail(), true);
  const trail = agent.auditTrail();
  assert.ok(trail.length >= 2);
  assert.equal(trail[1]!.prevHash, trail[0]!.hash);
});
