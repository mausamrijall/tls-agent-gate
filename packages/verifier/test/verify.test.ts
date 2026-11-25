import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, sha256Hex, unixNowSeconds } from '@tls-agent-gate/core';
import { MemoryNonceStore } from '../src/nonce.ts';
import { VerificationErrorCode } from '../src/types.ts';
import { verifyAgentRequest } from '../src/verify.ts';
import { assertThrowsCode, buildSignedRequest, makeFakeAgent, makeRoutesFetch, type FakeAgent } from './helpers.ts';

async function setup(opts: {
  agent?: FakeAgent;
  routes?: Record<string, { status?: number; contentType?: string; body: string }>;
  verifyOptions?: Record<string, unknown>;
} = {}) {
  const agent = opts.agent ?? (await makeFakeAgent());
  const routes = opts.routes ?? {
    [agent.docUrl]: { body: JSON.stringify(agent.doc) },
    [agent.manifestUrl]: { body: agent.manifestText },
  };
  const fetchImpl = makeRoutesFetch(routes);
  const verifyOptions = {
    fetchImpl,
    nonceStore: new MemoryNonceStore(),
    ...opts.verifyOptions,
  };
  return { agent, routes, fetchImpl, verifyOptions };
}

test('verifies a valid Ed25519-signed request', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent, { manifestSha256: await sha256Hex(agent.manifestText), manifestCaps: ['search'] });
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, true);
  assert.equal(result.domain, 'caller.example');
  assert.equal(result.identityUrl, agent.docUrl);
  assert.equal(result.keyId, agent.keyPair.kid);
  assert.equal(result.algorithm, 'Ed25519');
  assert.equal(result.usedLocalAllowlist, false);
  assert.ok(result.manifest);
  assert.equal(result.manifest!.sha256, await sha256Hex(agent.manifestText));
  assert.deepEqual(result.manifest!.caps, ['search']);
  assert.deepEqual(result.callerPolicy, { requireSignedRequests: true, allowLocalAgents: false });
});

test('verifies an ES256 (P-256) signed request', async () => {
  const agent = await makeFakeAgent({ alg: 'ES256' });
  const { verifyOptions } = await setup({ agent });
  const req = await buildSignedRequest(agent);
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, true);
  assert.equal(result.algorithm, 'ES256');
});

test('rejects a request with no identity header', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent);
  delete req.headers['x-agent-identity'];
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.MissingIdentityHeader);
});

test('rejects a non-HTTPS identity URL', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent);
  req.headers['x-agent-identity'] = agent.docUrl.replace('https://', 'http://');
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.NotHttps);
});

test('rejects an HTTP identity even on localhost when local agents are disabled', async () => {
  const agent = await makeFakeAgent({ domain: 'localhost' });
  const httpUrl = agent.docUrl.replace('https://', 'http://');
  const { verifyOptions } = await setup({
    agent,
    routes: { [httpUrl]: { body: JSON.stringify(agent.doc) } },
  });
  const req = await buildSignedRequest(agent);
  req.headers['x-agent-identity'] = httpUrl;
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.NotHttps);
});

test('allows HTTP localhost identity for an allowlisted dev key', async () => {
  const agent = await makeFakeAgent({ domain: 'localhost' });
  const httpUrl = agent.docUrl.replace('https://', 'http://');
  const { verifyOptions } = await setup({
    agent,
    routes: { [httpUrl]: { body: JSON.stringify(agent.doc) } },
    verifyOptions: {
      allowLocalAgents: true,
      allowedDevKeyThumbprints: [agent.keyPair.thumbprint],
    },
  });
  const req = await buildSignedRequest(agent);
  req.headers['x-agent-identity'] = httpUrl;
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, true);
  assert.equal(result.usedLocalAllowlist, true);
});

test('rejects a localhost identity by default', async () => {
  const agent = await makeFakeAgent({ domain: 'localhost' });
  const { verifyOptions } = await setup({ agent });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.LocalhostBlocked);
});

test('allows an allowlisted dev key on localhost', async () => {
  const agent = await makeFakeAgent({ domain: 'localhost' });
  const { verifyOptions } = await setup({
    agent,
    verifyOptions: {
      allowLocalAgents: true,
      allowedDevKeyThumbprints: [agent.keyPair.thumbprint],
    },
  });
  const req = await buildSignedRequest(agent);
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, true);
  assert.equal(result.usedLocalAllowlist, true);
});

test('rejects a localhost identity when the key is not allowlisted', async () => {
  const agent = await makeFakeAgent({ domain: 'localhost' });
  const other = await generateKeyPair('Ed25519');
  const { verifyOptions } = await setup({
    agent,
    verifyOptions: { allowLocalAgents: true, allowedDevKeyThumbprints: [other.thumbprint] },
  });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.KeyNotAllowlisted);
});

test('rejects an expired signature timestamp', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent, { created: unixNowSeconds() - 300 });
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.Expired);
});

test('rejects a future signature timestamp', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent, { created: unixNowSeconds() + 300 });
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.FutureTimestamp);
});

test('rejects a replayed nonce', async () => {
  const { agent, verifyOptions } = await setup();
  const nonce = 'abc-nonce-123';
  const req = await buildSignedRequest(agent, { nonce });
  const first = await verifyAgentRequest(req, verifyOptions);
  assert.equal(first.verified, true);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.ReplayedNonce);
});

test('rejects a tampered body', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent, { method: 'POST', body: new TextEncoder().encode('hello') });
  req.body = new TextEncoder().encode('evil');
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.InvalidSignature);
});

test('rejects a tampered manifest hash', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent, { manifestSha256: '0'.repeat(64) });
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.ManifestHashMismatch);
});

test('rejects an invalid identity document', async () => {
  const agent = await makeFakeAgent();
  const { verifyOptions } = await setup({
    agent,
    routes: { [agent.docUrl]: { body: JSON.stringify({ hello: 'world' }) } },
  });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.InvalidIdentity);
});

test('rejects an unknown key id', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent, { keyId: 'does-not-exist' });
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.KeyNotFound);
});

test('rejects a subject origin mismatch', async () => {
  const agent = await makeFakeAgent({ subjectOverride: 'https://evil.example/agent' });
  const { verifyOptions } = await setup({ agent });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.SubjectMismatch);
});

test('rejects missing manifest when manifest check is required', async () => {
  const { agent, verifyOptions } = await setup({ verifyOptions: { checkManifest: 'required' } });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.ManifestRequired);
});

test('supports dedicated agent subdomains (agent.<domain>) without rewrites', async () => {
  const agent = await makeFakeAgent({ domain: 'agent.example.com' });
  const { verifyOptions } = await setup({ agent });
  const req = await buildSignedRequest(agent);
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, true);
  assert.equal(result.domain, 'agent.example.com');
  assert.equal(result.identityUrl, 'https://agent.example.com/.well-known/agent-identity.json');
});

test('dedicated subdomain subject must match that subdomain origin', async () => {
  const agent = await makeFakeAgent({ domain: 'agent.example.com', subjectOverride: 'https://agent2.example.com/agent' });
  const { verifyOptions } = await setup({ agent });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.SubjectMismatch);
});

test('CORS expose-list includes the agent headers', async () => {
  const { EXPOSE_HEADERS_VALUE } = await import('@tls-agent-gate/core');
  assert.equal(EXPOSE_HEADERS_VALUE, 'X-Agent-Identity, X-Agent-Manifest, X-Verified-Agent');
});

test('treats a zero-length body as no body', async () => {
  const { agent, verifyOptions } = await setup();
  const req = await buildSignedRequest(agent); // no body
  req.body = new Uint8Array(0);
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, true);
});

test('passes unsigned requests when signed requests are not required', async () => {
  const { agent, verifyOptions } = await setup({ verifyOptions: { requireSignedRequests: false } });
  const req = await buildSignedRequest(agent);
  delete req.headers['x-agent-signature'];
  const result = await verifyAgentRequest(req, verifyOptions);
  assert.equal(result.verified, false);
});

test('rejects an identity fetch that returns HTTP 404', async () => {
  const agent = await makeFakeAgent();
  const { verifyOptions } = await setup({
    agent,
    routes: { [agent.docUrl]: { status: 404, body: 'nope' } },
  });
  const req = await buildSignedRequest(agent);
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.IdentityFetch);
});

test('rejects a signature produced by a different key (kid matches)', async () => {
  const agent = await makeFakeAgent();
  const attacker = await generateKeyPair('Ed25519');
  const { verifyOptions } = await setup({ agent });
  const req = await buildSignedRequest(agent, { signingKey: attacker });
  await assertThrowsCode(verifyAgentRequest(req, verifyOptions), VerificationErrorCode.InvalidSignature);
});
