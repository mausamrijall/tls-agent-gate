import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildChallengeCanonical,
  issueChallenge,
  MemoryChallengeNonceStore,
  verifyChallengeResponse,
} from '../src/challenge.ts';
import { generateKeyPair, importPrivateKeyFromJwk, signCanonical } from '../src/crypto.ts';

test('challenge round-trip verifies with the agent key', async () => {
  const pair = await generateKeyPair('Ed25519');
  const store = new MemoryChallengeNonceStore();
  const proof = await issueChallenge({ nonceStore: store, ttlMs: 45_000 });

  const canonical = buildChallengeCanonical({
    challenge: proof.challenge,
    issuedAt: proof.issuedAt,
    method: 'GET',
    urlPathAndQuery: '/api/agent/search?q=agents',
    host: 'protected.example',
  });
  const privateKey = await importPrivateKeyFromJwk(pair.privateKeyJwk);
  const sig = await signCanonical(privateKey, canonical);

  const check = await verifyChallengeResponse({
    proof,
    method: 'GET',
    url: 'https://protected.example/api/agent/search?q=agents',
    signatureB64Url: sig,
    publicKeyJwk: pair.publicKeyJwk,
    nonceStore: store,
    nowMs: proof.issuedAt + 5_000,
  });
  assert.equal(check.valid, true);
});

test('response cannot be replayed after verification', async () => {
  const pair = await generateKeyPair('Ed25519');
  const store = new MemoryChallengeNonceStore();
  const proof = await issueChallenge({ nonceStore: store, ttlMs: 45_000 });
  const canonical = buildChallengeCanonical({ challenge: proof.challenge, issuedAt: proof.issuedAt, method: 'GET', urlPathAndQuery: '/api', host: 'a.example' });
  const privateKey = await importPrivateKeyFromJwk(pair.privateKeyJwk);
  const sig = await signCanonical(privateKey, canonical);

  const first = await verifyChallengeResponse({ proof, method: 'GET', url: 'https://a.example/api', signatureB64Url: sig, publicKeyJwk: pair.publicKeyJwk, nonceStore: store, nowMs: proof.issuedAt + 5_000 });
  assert.equal(first.valid, true);

  const second = await verifyChallengeResponse({ proof, method: 'GET', url: 'https://a.example/api', signatureB64Url: sig, publicKeyJwk: pair.publicKeyJwk, nonceStore: store, nowMs: proof.issuedAt + 10_000 });
  assert.equal(second.valid, false);
  assert.equal(second.reason, 'unknown-or-replayed');
});

test('expired challenge is rejected', async () => {
  const pair = await generateKeyPair('Ed25519');
  const store = new MemoryChallengeNonceStore();
  const proof = await issueChallenge({ nonceStore: store, ttlMs: 30_000 });
  const canonical = buildChallengeCanonical({ challenge: proof.challenge, issuedAt: proof.issuedAt, method: 'GET', urlPathAndQuery: '/api', host: 'a.example' });
  const privateKey = await importPrivateKeyFromJwk(pair.privateKeyJwk);
  const sig = await signCanonical(privateKey, canonical);

  const check = await verifyChallengeResponse({ proof, method: 'GET', url: 'https://a.example/api', signatureB64Url: sig, publicKeyJwk: pair.publicKeyJwk, nonceStore: store, nowMs: proof.expiresAt + 60_000 });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'expired');
});

test('wrong key fails signature check', async () => {
  const pair = await generateKeyPair('Ed25519');
  const attacker = await generateKeyPair('Ed25519');
  const store = new MemoryChallengeNonceStore();
  const proof = await issueChallenge({ nonceStore: store, ttlMs: 45_000 });
  const canonical = buildChallengeCanonical({ challenge: proof.challenge, issuedAt: proof.issuedAt, method: 'GET', urlPathAndQuery: '/api', host: 'a.example' });
  const attackerKey = await importPrivateKeyFromJwk(attacker.privateKeyJwk);
  const sig = await signCanonical(attackerKey, canonical);

  const check = await verifyChallengeResponse({ proof, method: 'GET', url: 'https://a.example/api', signatureB64Url: sig, publicKeyJwk: pair.publicKeyJwk, nonceStore: store, nowMs: proof.issuedAt + 5_000 });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'bad-signature');
});
