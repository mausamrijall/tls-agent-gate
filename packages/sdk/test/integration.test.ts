import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCanonicalPayload,
  generateKeyPair,
  importPublicKeyFromJwk,
  parseSignatureHeader,
  sha256Hex,
  verifyCanonical,
} from '@tls-agent-gate/core';
import { createBoundedAgent } from '../src/sdk.ts';
import { createCoreSigner } from '../src/signer.ts';
import { createSandboxRunner } from '../src/runner.ts';

test('default policy blocks everything (deny-by-default)', async () => {
  const pair = await generateKeyPair('Ed25519');
  const signer = await createCoreSigner({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    privateKeyJwk: pair.privateKeyJwk,
  });
  const agent = await createBoundedAgent({
    agentId: 'default-deny',
    identitySigner: signer,
    policy: {}, // empty → deny-by-default
  });
  assert.equal((await agent.runTool('anything', {})).decision, 'deny');
  assert.equal((await agent.runCommand('anything')).decision, 'deny');
  assert.equal((await agent.callAgent({ baseUrl: 'https://protected.example', path: '/api' })).decision, 'deny');
});

test('signed remote agent call attaches X-Agent-* headers and verifies offline', async () => {
  const pair = await generateKeyPair('Ed25519');
  const signer = await createCoreSigner({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    privateKeyJwk: pair.privateKeyJwk,
    manifestText: '{"schemaVersion":"agent-manifest-v1","name":"Caller","capabilities":[{"id":"search","name":"Search"}]}',
  });

  const captured: { url: string; init: RequestInit }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit = {}) => {
    captured.push({ url, init });
    const headers = new Headers();
    headers.set('content-type', 'application/json');
    headers.set('x-verified-agent', 'protected.example');
    return new Response('{"hi":"verified"}', { status: 200, headers });
  }) as typeof fetch;

  const agent = await createBoundedAgent({
    agentId: 'signed-agent',
    manifest: { schemaVersion: 'agent-manifest-v1', name: 'Caller', capabilities: [{ id: 'search', name: 'Search' }] },
    identitySigner: signer,
    policy: {
      allowedOrigins: ['https://protected.example'],
      allowLocalAgents: false,
      requireConsentFor: [],
      maxCallsPerTurn: 10,
      maxStepsPerTurn: 50,
      maxPayloadBytes: 4096,
      executionTimeoutMs: 3000,
      dataRedactionRules: [],
      allowedTools: [],
      allowedCommands: [],
      allowedTargetPatterns: [],
      allowedDevKeyThumbprints: [],
      strictTools: true,
    },
    fetchImpl,
    runner: createSandboxRunner({ useWorker: false }),
  });

  const result = await agent.callAgent(
    { baseUrl: 'https://protected.example', path: '/api/agent/search?q=agents' },
    { method: 'POST', body: { q: 'agents' } },
  );

  assert.equal(result.decision, 'allow');
  assert.equal(result.ok, true);
  const callResult = result.value as { verifiedByTarget: { domain: string } | null; sanitizedText: string };
  assert.equal(callResult.verifiedByTarget?.domain, 'protected.example');
  assert.equal(callResult.sanitizedText, '{"hi":"verified"}');

  assert.equal(captured.length, 1);
  const { init, url } = captured[0]!;
  const headers = init.headers as Record<string, string>;
  assert.ok(headers['X-Agent-Identity'] ?? headers['x-agent-identity']);
  assert.ok(headers['X-Agent-Manifest'] ?? headers['x-agent-manifest']);
  assert.ok(headers['X-Agent-Signature'] ?? headers['x-agent-signature']);

  const sigHeader = (headers['X-Agent-Signature'] ?? headers['x-agent-signature']) as string;
  const sig = parseSignatureHeader(sigHeader);
  assert.ok(sig);
  assert.equal(sig.keyid, signer.keyId);

  const manifestHeader = (headers['X-Agent-Manifest'] ?? headers['x-agent-manifest']) as string;
  const manifest = parseManifestHeader(manifestHeader);
  assert.equal(manifest.url, 'https://caller.example/agent-manifest.json');

  const target = new URL(url);
  const bodySha256 = await sha256Hex(JSON.stringify({ q: 'agents' }));
  const canonical = buildCanonicalPayload({
    method: 'POST',
    urlPathAndQuery: `${target.pathname}${target.search}`,
    host: target.host.toLowerCase(),
    created: sig.created,
    nonce: sig.nonce,
    bodySha256,
    manifestSha256: manifest.sha256 ?? '',
  });

  const pub = await importPublicKeyFromJwk(pair.publicKeyJwk);
  assert.equal(await verifyCanonical(pub, canonical, sig.sig), true, 'signature matches canonical payload');
});

import { parseManifestHeader } from '@tls-agent-gate/core';
