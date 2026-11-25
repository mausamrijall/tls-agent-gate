import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCanonicalPayload, CANONICAL_VERSION } from '../src/canonical.ts';

const base = {
  method: 'POST',
  urlPathAndQuery: '/api/search?q=agents',
  host: 'Caller.Example',
  created: 1700000000,
  nonce: '0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f',
  bodySha256: 'a'.repeat(64),
  manifestSha256: 'b'.repeat(64),
};

test('canonical payload is newline-joined in fixed order', () => {
  const canonical = buildCanonicalPayload(base);
  const lines = canonical.split('\n');
  assert.equal(lines.length, 8);
  assert.equal(lines[0], CANONICAL_VERSION);
  assert.equal(lines[1], 'POST');
  assert.equal(lines[2], '/api/search?q=agents');
  assert.equal(lines[3], 'caller.example'); // host lowercased
  assert.equal(lines[4], '1700000000');
  assert.equal(lines[5], base.nonce);
  assert.equal(lines[6], 'a'.repeat(64));
  assert.equal(lines[7], 'b'.repeat(64));
});

test('method is normalized to uppercase', () => {
  assert.ok(buildCanonicalPayload({ ...base, method: 'get' }).startsWith(`${CANONICAL_VERSION}\nGET\n`));
});

test('empty body/manifest hashes become empty lines', () => {
  const canonical = buildCanonicalPayload({ ...base, bodySha256: '', manifestSha256: '' });
  const lines = canonical.split('\n');
  assert.equal(lines[6], '');
  assert.equal(lines[7], '');
});

test('whitespace is stripped from path and host', () => {
  const canonical = buildCanonicalPayload({
    ...base,
    urlPathAndQuery: '  /api/search  ',
    host: ' EXAMPLE.com ',
  });
  const lines = canonical.split('\n');
  assert.equal(lines[2], '/api/search');
  assert.equal(lines[3], 'example.com');
});

test('deterministic across equivalent inputs', () => {
  assert.equal(
    buildCanonicalPayload(base),
    buildCanonicalPayload({ ...base, host: 'CALLER.EXAMPLE' }),
  );
});
