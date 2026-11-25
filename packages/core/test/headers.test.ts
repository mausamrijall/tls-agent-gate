import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatHeaderParams,
  formatIdentityHeader,
  formatManifestHeader,
  formatSignatureHeader,
  parseHeaderParams,
  parseIdentityHeader,
  parseManifestHeader,
  parseSignatureHeader,
} from '../src/headers.ts';

test('formatHeaderParams quotes values and lowercases keys', () => {
  assert.equal(formatHeaderParams({ KeyId: 'abc', Alg: 'ed25519' }), 'keyid="abc"; alg="ed25519"');
});

test('parseHeaderParams handles quoted and bare tokens', () => {
  const params = parseHeaderParams('keyid="abc"; alg=ed25519; created="123"');
  assert.equal(params['keyid'], 'abc');
  assert.equal(params['alg'], 'ed25519');
  assert.equal(params['created'], '123');
});

test('parseHeaderParams is tolerant of whitespace and extra separators', () => {
  const params = parseHeaderParams('  keyid = "a\\"b" ; sig="Zg" ');
  assert.equal(params['keyid'], 'a"b');
  assert.equal(params['sig'], 'Zg');
});

test('identity header is a bare URL', () => {
  const url = 'https://caller.example/.well-known/agent-identity.json';
  assert.equal(formatIdentityHeader(url), url);
  assert.equal(parseIdentityHeader(` ${url} `), url);
  assert.equal(parseIdentityHeader('https://x/; a="b"'), '');
  assert.equal(parseIdentityHeader(''), '');
});

test('manifest header round-trips', () => {
  const header = formatManifestHeader({
    url: 'https://caller.example/agent-manifest.json',
    sha256: 'a'.repeat(64),
    caps: ['search', 'quote'],
  });
  const parsed = parseManifestHeader(header);
  assert.equal(parsed.url, 'https://caller.example/agent-manifest.json');
  assert.equal(parsed.sha256, 'a'.repeat(64));
  assert.deepEqual(parsed.caps, ['search', 'quote']);
});

test('manifest header with no caps omits the caps param', () => {
  const parsed = parseManifestHeader(formatManifestHeader({ url: 'https://x/manifest.json' }));
  assert.equal(parsed.url, 'https://x/manifest.json');
  assert.equal(parsed.sha256, undefined);
  assert.equal(parsed.caps, undefined);
});

test('signature header round-trips', () => {
  const header = formatSignatureHeader({
    keyid: 'kid-1',
    alg: 'ed25519',
    created: '1700000000',
    nonce: 'n-1',
    sig: 'Zg',
  });
  const parsed = parseSignatureHeader(header);
  assert.ok(parsed);
  assert.equal(parsed.keyid, 'kid-1');
  assert.equal(parsed.alg, 'ed25519');
  assert.equal(parsed.created, '1700000000');
  assert.equal(parsed.nonce, 'n-1');
  assert.equal(parsed.sig, 'Zg');
});

test('parseSignatureHeader returns null for missing required params', () => {
  assert.equal(parseSignatureHeader('alg="ed25519"; created="1"; nonce="n"; sig="x"'), null);
  assert.equal(parseSignatureHeader(''), null);
  assert.equal(parseSignatureHeader(null), null);
});
