import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  exportSpkiB64Url,
  generateKeyPair,
  importPrivateKeyFromJwk,
  importPublicKeyFromJwk,
  signCanonical,
  thumbprintOfJwk,
  verifyCanonical,
} from '../src/crypto.ts';
import { buildCanonicalPayload } from '../src/canonical.ts';
import { utf8Encode } from '../src/encoding.ts';
import { sha256 } from '../src/sha256.ts';

const canonical = buildCanonicalPayload({
  method: 'POST',
  urlPathAndQuery: '/api/search?q=agents',
  host: 'caller.example',
  created: 1700000000,
  nonce: 'abc123',
  bodySha256: 'aa',
  manifestSha256: 'bb',
});

async function roundTripPair(alg: 'Ed25519' | 'ES256') {
  const pair = await generateKeyPair(alg);
  const pub = await importPublicKeyFromJwk(pair.publicKeyJwk);
  const priv = await importPrivateKeyFromJwk(pair.privateKeyJwk);
  const sig = await signCanonical(priv, canonical);
  assert.ok(await verifyCanonical(pub, canonical, sig));
  return { pair, pub, priv, sig };
}

test('Ed25519 key generation -> sign -> verify round-trip', async () => {
  await roundTripPair('Ed25519');
});

test('ES256 (P-256) key generation -> sign -> verify round-trip', async () => {
  await roundTripPair('ES256');
});

test('signature is a valid base64url string', async () => {
  const { sig } = await roundTripPair('Ed25519');
  assert.match(sig, /^[A-Za-z0-9_-]+$/);
});

test('verification fails on tampered payload', async () => {
  const { pub } = await roundTripPair('Ed25519');
  const sig = await signCanonical(
    await importPrivateKeyFromJwk((await generateKeyPair('Ed25519')).privateKeyJwk),
    canonical,
  );
  // Different key -> must not verify
  assert.equal(await verifyCanonical(pub, canonical, sig), false);
});

test('verification rejects malformed signatures', async () => {
  const { pub } = await roundTripPair('Ed25519');
  assert.equal(await verifyCanonical(pub, canonical, 'not-base64!'), false);
});

test('thumbprint is deterministic RFC 7638 base64url', async () => {
  const a = await generateKeyPair('Ed25519');
  const b = await generateKeyPair('Ed25519');
  assert.equal(a.thumbprint, await thumbprintOfJwk(a.publicKeyJwk));
  assert.equal(a.thumbprint.length, 43); // 32 bytes -> 43 base64url chars
  assert.notEqual(a.thumbprint, b.thumbprint);
});

test('kid defaults to thumbprint; SPKI export works', async () => {
  const pair = await generateKeyPair('Ed25519');
  assert.equal(pair.kid, pair.thumbprint);
  const spki = await exportSpkiB64Url(await importPublicKeyFromJwk(pair.publicKeyJwk, true));
  assert.equal(spki, pair.publicKeySpkiB64Url);
  assert.ok(spki.length > 40);
});

test('private key JWK round-trips through import', async () => {
  const pair = await generateKeyPair('Ed25519');
  const priv = await importPrivateKeyFromJwk(pair.privateKeyJwk);
  const sig = await signCanonical(priv, canonical);
  const pub = await importPublicKeyFromJwk(pair.publicKeyJwk);
  assert.ok(await verifyCanonical(pub, canonical, sig));
});

test('sha256 matches known vector', async () => {
  const hex = await sha256(utf8Encode('abc')).then((d) => Array.from(d, (b) => b.toString(16).padStart(2, '0')).join(''));
  assert.equal(hex, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
