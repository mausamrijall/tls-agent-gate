import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeCapabilityToken,
  issueCapabilityToken,
  verifyCapabilityToken,
} from '../src/capabilityToken.ts';

const SECRET = 's3cret-shared-key';
const NOW = 1_700_000_000;

test('issue + verify a valid scoped token', async () => {
  const token = await issueCapabilityToken(
    { cap: ['search'], origins: ['https://protected.example'], paths: ['/api/agent/search'], sub: 'caller.example' },
    { secret: SECRET, now: NOW, ttlSeconds: 60 },
  );
  const claims = decodeCapabilityToken(token);
  assert.ok(claims);
  assert.equal(claims!.cap[0], 'search');
  assert.equal(claims!.iat, NOW);
  assert.equal(claims!.exp, NOW + 60);

  const check = await verifyCapabilityToken(token, {
    secret: SECRET,
    now: NOW + 30,
    requireCapability: 'search',
    requireOrigin: 'https://protected.example',
    requirePath: '/api/agent/search',
  });
  assert.equal(check.valid, true);
});

test('rejects tampered signature', async () => {
  const token = await issueCapabilityToken({ cap: ['search'] }, { secret: SECRET, now: NOW });
  const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
  const check = await verifyCapabilityToken(tampered, { secret: SECRET, now: NOW });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'bad-signature');
});

test('rejects expired token', async () => {
  const token = await issueCapabilityToken({ cap: ['search'] }, { secret: SECRET, now: NOW, ttlSeconds: 10 });
  const check = await verifyCapabilityToken(token, { secret: SECRET, now: NOW + 100 });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'expired');
});

test('rejects not-yet-valid token', async () => {
  const token = await issueCapabilityToken({ cap: ['search'], nbf: NOW + 50 }, { secret: SECRET, now: NOW });
  const check = await verifyCapabilityToken(token, { secret: SECRET, now: NOW + 10 });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'not-yet-valid');
});

test('least privilege: token for one capability cannot authorize another', async () => {
  const token = await issueCapabilityToken({ cap: ['search'] }, { secret: SECRET, now: NOW });
  const check = await verifyCapabilityToken(token, { secret: SECRET, now: NOW, requireCapability: 'delete' });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'scope-capability');
});

test('least privilege: origin scope is enforced', async () => {
  const token = await issueCapabilityToken(
    { cap: ['search'], origins: ['https://protected.example'] },
    { secret: SECRET, now: NOW },
  );
  const check = await verifyCapabilityToken(token, {
    secret: SECRET,
    now: NOW,
    requireOrigin: 'https://evil.invalid',
  });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'scope-origin');
});

test('least privilege: path scope is enforced', async () => {
  const token = await issueCapabilityToken(
    { cap: ['search'], paths: ['/api/agent/search'] },
    { secret: SECRET, now: NOW },
  );
  const check = await verifyCapabilityToken(token, {
    secret: SECRET,
    now: NOW,
    requirePath: '/admin',
  });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'scope-path');
});

test('malformed token is rejected', async () => {
  const check = await verifyCapabilityToken('not-a-token', { secret: SECRET, now: NOW });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'malformed');
});

test('wrong secret fails', async () => {
  const token = await issueCapabilityToken({ cap: ['search'] }, { secret: SECRET, now: NOW });
  const check = await verifyCapabilityToken(token, { secret: 'nope', now: NOW });
  assert.equal(check.valid, false);
});
