import { test } from 'node:test';
import assert from 'node:assert/strict';
import { issueCapabilityToken } from '@tls-agent-gate/core';
import { MemoryNonceStore } from '../src/nonce.ts';
import { VerificationErrorCode } from '../src/types.ts';
import { verifyAgentRequest } from '../src/verify.ts';
import { assertThrowsCode, buildSignedRequest, makeFakeAgent, makeRoutesFetch } from './helpers.ts';

const SECRET = 'token-shared-secret';
const NOW = Math.floor(Date.now() / 1000);

function tokenRequest(path = '/api/agent/search?q=x') {
  return {
    method: 'GET',
    url: `http://localhost:4174${path}`,
    headers: { host: 'localhost:4174' },
    body: undefined,
  };
}

async function makeToken(over: Record<string, unknown> = {}) {
  return issueCapabilityToken(
    {
      cap: ['search'],
      origins: ['http://localhost:4174'],
      paths: ['/api/agent/search'],
      sub: 'requester.example',
      ...over,
    } as never,
    { secret: SECRET, now: NOW, ttlSeconds: 60 },
  );
}

test('capability-token mode authenticates a scoped request without signature', async () => {
  const req = tokenRequest();
  req.headers['x-agent-token'] = await makeToken();
  const result = await verifyAgentRequest(req, {
    allowCapabilityTokens: true,
    capabilityTokenSecret: SECRET,
    now: NOW * 1000,
    requiredCapability: 'search',
  });
  assert.equal(result.verified, true);
  assert.equal(result.authMethod, 'capability-token');
  assert.equal(result.algorithm, 'HS256');
  assert.equal(result.domain, 'localhost');
  assert.ok(result.keyId.length > 0);
});

test('token cannot authorize a different capability (least privilege)', async () => {
  const req = tokenRequest();
  req.headers['x-agent-token'] = await makeToken({ cap: ['quote'] });
  await assertThrowsCode(
    verifyAgentRequest(req, { allowCapabilityTokens: true, capabilityTokenSecret: SECRET, now: NOW * 1000, requiredCapability: 'search' }),
    VerificationErrorCode.TokenScopeDenied,
  );
});

test('token cannot authorize an arbitrary origin', async () => {
  const req = tokenRequest();
  req.headers['x-agent-token'] = await makeToken({ origins: ['https://protected.example'] });
  await assertThrowsCode(
    verifyAgentRequest(req, { allowCapabilityTokens: true, capabilityTokenSecret: SECRET, now: NOW * 1000 }),
    VerificationErrorCode.TokenScopeDenied,
  );
});

test('token cannot authorize an unrelated path', async () => {
  const req = tokenRequest('/admin');
  req.headers['x-agent-token'] = await makeToken();
  await assertThrowsCode(
    verifyAgentRequest(req, { allowCapabilityTokens: true, capabilityTokenSecret: SECRET, now: NOW * 1000 }),
    VerificationErrorCode.TokenScopeDenied,
  );
});

test('expired token is rejected', async () => {
  const req = tokenRequest();
  req.headers['x-agent-token'] = await issueCapabilityToken({ cap: ['search'], origins: ['http://localhost:4174'], paths: ['/api/agent/search'] }, { secret: SECRET, now: NOW - 5000, ttlSeconds: 5 });
  await assertThrowsCode(
    verifyAgentRequest(req, { allowCapabilityTokens: true, capabilityTokenSecret: SECRET, now: NOW * 1000 }),
    VerificationErrorCode.TokenExpired,
  );
});

test('wrong secret is rejected', async () => {
  const req = tokenRequest();
  req.headers['x-agent-token'] = await makeToken();
  await assertThrowsCode(
    verifyAgentRequest(req, { allowCapabilityTokens: true, capabilityTokenSecret: 'wrong-secret', now: NOW * 1000 }),
    VerificationErrorCode.TokenInvalid,
  );
});

test('token replay is rejected when a jti store is configured', async () => {
  const req = tokenRequest();
  req.headers['x-agent-token'] = await makeToken();
  const store = new MemoryNonceStore();
  const opts = { allowCapabilityTokens: true, capabilityTokenSecret: SECRET, now: NOW * 1000, capabilityTokenStore: store };
  const first = await verifyAgentRequest(req, opts);
  assert.equal(first.verified, true);
  await assertThrowsCode(verifyAgentRequest(req, opts), VerificationErrorCode.TokenReplayed);
});

test('signature still takes precedence over a token', async () => {
  const agent = await makeFakeAgent();
  const routes = { [agent.docUrl]: { body: JSON.stringify(agent.doc) }, [agent.manifestUrl]: { body: agent.manifestText } };
  const fetchImpl = makeRoutesFetch(routes);
  const req = await buildSignedRequest(agent);
  req.headers['x-agent-token'] = await makeToken({ origins: ['https://caller.example'], paths: ['/api/search'] });
  const result = await verifyAgentRequest(req, { fetchImpl, nonceStore: new MemoryNonceStore(), allowCapabilityTokens: true, capabilityTokenSecret: SECRET });
  assert.equal(result.authMethod, 'signature');
  assert.equal(result.algorithm, 'Ed25519');
});
