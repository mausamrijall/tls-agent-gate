import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCanonicalPayload,
  formatManifestHeader,
  generateKeyPair,
  importPublicKeyFromJwk,
  parseManifestHeader,
  parseSignatureHeader,
  sha256Hex,
  verifyCanonical,
  type AgentManifest,
  type AgentKeyPair,
} from '@tls-agent-gate/core';
import { AgentRuntime } from '../src/agent-runtime.ts';
import { DenyConsentGate, type ConsentGate, type ConsentRequestSpec } from '../src/consent.ts';
import type { AgentFetchRequest, AgentFetchResponse } from '../src/worker.ts';

function makeManifest(): AgentManifest {
  return {
    schemaVersion: 'agent-manifest-v1',
    agent: 'https://caller.example/agent',
    name: 'Caller',
    description: 'Browser caller',
    version: '1.0.0',
    capabilities: [{ id: 'search', name: 'Search' }],
  };
}

class GrantingGate implements ConsentGate {
  approved: ConsentRequestSpec[] = [];
  async requestApproval(spec: ConsentRequestSpec): Promise<boolean> {
    this.approved.push(spec);
    return true;
  }
}

interface CapturedRequest {
  url: string;
  init: RequestInit;
}

function makeFetchMock(respond: (req: CapturedRequest) => Response) {
  const calls: CapturedRequest[] = [];
  const fetchImpl = async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init });
    return respond({ url, init });
  };
  return { calls, fetchImpl };
}

function getHeader(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return undefined;
}

async function verifyCapturedSignature(captured: CapturedRequest, pair: AgentKeyPair): Promise<void> {
  const headers = captured.init.headers as Record<string, string>;
  const signatureHeader = getHeader(headers, 'x-agent-signature');
  assert.ok(signatureHeader, 'signature header present');
  const sig = parseSignatureHeader(signatureHeader);
  assert.ok(sig);

  const identityHeader = getHeader(headers, 'x-agent-identity');
  assert.equal(identityHeader, 'https://caller.example/.well-known/agent-identity.json');

  const manifestHeader = getHeader(headers, 'x-agent-manifest');
  assert.ok(manifestHeader);
  const manifest = parseManifestHeader(manifestHeader);
  assert.equal(manifest.url, 'https://caller.example/agent-manifest.json');
  assert.deepEqual(manifest.caps, ['search']);

  const target = new URL(captured.url);
  const body = (captured.init.body as string | undefined) ?? '';
  const bodySha256 = await sha256Hex(body);
  const canonical = buildCanonicalPayload({
    method: captured.init.method ?? 'GET',
    urlPathAndQuery: `${target.pathname}${target.search}`,
    host: target.host.toLowerCase(),
    created: sig.created,
    nonce: sig.nonce,
    bodySha256,
    manifestSha256: manifest.sha256 ?? '',
  });

  const jwk = pair.publicKeyJwk as { kty: string; crv: string; x: string; y?: string };
  const pubJwk: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const pub = await importPublicKeyFromJwk(pubJwk);
  assert.equal(await verifyCanonical(pub, canonical, sig.sig), true, 'signature verifies');
}

test('runtime signs outbound requests with verifiable canonical payload', async () => {
  const pair = await generateKeyPair('Ed25519');
  const { calls, fetchImpl } = makeFetchMock(() => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  const runtime = await AgentRuntime.create({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    manifest: makeManifest(),
    privateKeyJwk: pair.privateKeyJwk,
    requireConsent: false,
    useWorker: false,
    dispatchFetch: fetchImpl,
  });

  const result = await runtime.callAgent(
    { baseUrl: 'https://protected.example', path: '/api/agent/search?q=x' },
    { method: 'POST', body: 'hello', caps: ['search'] },
  );

  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  await verifyCapturedSignature(calls[0]!, pair);
  assert.ok(runtime.agentKeyId.length > 0);
});

test('runtime parses target verification headers', async () => {
  const pair = await generateKeyPair('Ed25519');
  const { fetchImpl } = makeFetchMock(() => {
    const headers = new Headers();
    headers.set('content-type', 'application/json');
    headers.set('x-verified-agent', 'protected.example');
    headers.set('x-agent-manifest', formatManifestHeader({ url: 'https://protected.example/agent-manifest.json', sha256: 'a'.repeat(64), caps: ['quote'] }));
    return new Response('{"ok":true}', { status: 200, headers });
  });
  const runtime = await AgentRuntime.create({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    manifest: makeManifest(),
    privateKeyJwk: pair.privateKeyJwk,
    requireConsent: false,
    useWorker: false,
    dispatchFetch: fetchImpl,
  });

  const result = await runtime.callAgent({ baseUrl: 'https://protected.example', path: '/api/agent/search' });
  assert.equal(result.verifiedByTarget?.domain, 'protected.example');
  assert.equal(result.manifestFromTarget?.url, 'https://protected.example/agent-manifest.json');
});

test('deny consent gate blocks cross-origin calls before fetching', async () => {
  const pair = await generateKeyPair('Ed25519');
  const { calls, fetchImpl } = makeFetchMock(() => new Response('{}'));
  const runtime = await AgentRuntime.create({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    manifest: makeManifest(),
    privateKeyJwk: pair.privateKeyJwk,
    consentGate: new DenyConsentGate(),
    requireConsent: true,
    useWorker: false,
    dispatchFetch: fetchImpl,
  });

  const result = await runtime.callAgent({ baseUrl: 'https://protected.example', path: '/api' });
  assert.equal(result.declined, true);
  assert.equal(calls.length, 0);
  const events = runtime.inspector.list();
  assert.ok(events.some((e) => e.kind === 'consent-denied'));
});

test('granting consent gate lets the call proceed and records approval', async () => {
  const pair = await generateKeyPair('Ed25519');
  const gate = new GrantingGate();
  const { calls, fetchImpl } = makeFetchMock(() => new Response('{}', { status: 200 }));
  const runtime = await AgentRuntime.create({
    identityUrl: 'https://caller.example/.well-known/agent-identity.json',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    manifest: makeManifest(),
    privateKeyJwk: pair.privateKeyJwk,
    consentGate: gate,
    requireConsent: true,
    useWorker: false,
    dispatchFetch: fetchImpl,
  });

  const result = await runtime.callAgent({ baseUrl: 'https://protected.example', path: '/api' }, { caps: ['search'] });
  assert.equal(result.declined, false);
  assert.equal(calls.length, 1);
  assert.equal(gate.approved.length, 1);
  assert.equal(gate.approved[0]!.capabilityIds?.[0], 'search');
  assert.ok(runtime.inspector.list().some((e) => e.kind === 'consent-granted'));
});

test('performAgentFetch sanitizes hostile HTML responses', async () => {
  const { performAgentFetch } = await import('../src/worker.ts');
  const response = new Response('<p>ok</p><script>alert(1)</script>', {
    status: 200,
    headers: { 'content-type': 'text/html' },
  });
  const fetchImpl = async (): Promise<Response> => response;
  const result: AgentFetchResponse = await performAgentFetch(
    { url: 'https://x.example/', method: 'GET', headers: {} } as AgentFetchRequest,
    { fetchImpl: fetchImpl as typeof fetch },
  );
  assert.ok(!result.sanitizedText.includes('alert'));
});
