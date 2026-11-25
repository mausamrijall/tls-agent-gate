/**
 * Web Crypto (crypto.subtle) wrappers for Ed25519 (primary) and ECDSA
 * P-256 / ES256 (fallback) agent keys.
 *
 * Everything is built on standard Web APIs, so this module runs unchanged
 * in browsers, edge workers, and modern Node (Node >= 20 exposes WebCrypto
 * globally).
 *
 * Key identifiers (`kid`) default to the RFC 7638 JWK thumbprint
 * (base64url SHA-256 over the lexicographically-sorted required members).
 */
import { bytesToBase64Url, base64UrlToBytes, randomBytes, utf8Encode } from './encoding.ts';
import { sha256 } from './sha256.ts';
import type { AgentKeyJwk, AgentKeyPair, KeyAlgorithm } from './types.ts';

const SUBTLE = globalThis.crypto.subtle;

function algorithmForJwk(jwk: AgentKeyJwk): AlgorithmIdentifier {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return { name: 'Ed25519' };
  }
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    // `hash` is only needed for sign/verify params, not for key import.
    return { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier;
  }
  throw new TypeError(`Unsupported JWK (kty=${jwk.kty}, crv=${jwk.crv})`);
}

function signParamsForKey(key: CryptoKey): AlgorithmIdentifier | EcdsaParams {
  return key.algorithm.name === 'Ed25519'
    ? { name: 'Ed25519' }
    : { name: 'ECDSA', hash: 'SHA-256' };
}

/**
 * RFC 7638 JWK thumbprint (base64url). For Ed25519 the required members are
 * `crv`, `kty`, `x`; for P-256 also `y`.
 */
export async function thumbprintOfJwk(jwk: AgentKeyJwk): Promise<string> {
  const members: Array<[string, string]> = [];
  if (typeof jwk.crv === 'string') members.push(['crv', jwk.crv]);
  if (typeof jwk.kty === 'string') members.push(['kty', jwk.kty]);
  if (typeof jwk.x === 'string') members.push(['x', jwk.x]);
  if (typeof jwk.y === 'string') members.push(['y', jwk.y]);
  members.sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : 0));
  const canonical = `{${members.map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`).join(',')}}`;
  const digest = await sha256(canonical);
  return bytesToBase64Url(digest);
}

/** Export a CryptoKey's public part as SPKI (DER) base64url. */
export async function exportSpkiB64Url(publicKey: CryptoKey): Promise<string> {
  const der = await SUBTLE.exportKey('spki', publicKey);
  return bytesToBase64Url(new Uint8Array(der));
}

/** Generate a fresh agent key pair (Web Crypto). */
export async function generateKeyPair(alg: KeyAlgorithm = 'Ed25519'): Promise<AgentKeyPair> {
  if (alg === 'Ed25519') {
    const pair = await SUBTLE.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const publicKeyJwk = (await SUBTLE.exportKey('jwk', pair.publicKey)) as AgentKeyJwk;
    const privateKeyJwk = (await SUBTLE.exportKey('jwk', pair.privateKey)) as AgentKeyJwk;
    const thumbprint = await thumbprintOfJwk(publicKeyJwk);
    return {
      alg,
      kid: thumbprint,
      publicKeyJwk,
      privateKeyJwk,
      publicKeySpkiB64Url: await exportSpkiB64Url(pair.publicKey),
      thumbprint,
    };
  }
  const pair = await SUBTLE.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const publicKeyJwk = (await SUBTLE.exportKey('jwk', pair.publicKey)) as AgentKeyJwk;
  const privateKeyJwk = (await SUBTLE.exportKey('jwk', pair.privateKey)) as AgentKeyJwk;
  publicKeyJwk.alg = 'ES256';
  privateKeyJwk.alg = 'ES256';
  const thumbprint = await thumbprintOfJwk(publicKeyJwk);
  return {
    alg,
    kid: thumbprint,
    publicKeyJwk,
    privateKeyJwk,
    publicKeySpkiB64Url: await exportSpkiB64Url(pair.publicKey),
    thumbprint,
  };
}

/**
 * Import a public key from its JWK representation.
 * Set `extractable` when you need to re-export (e.g. SPKI).
 */
export async function importPublicKeyFromJwk(jwk: AgentKeyJwk, extractable = false): Promise<CryptoKey> {
  const copy = { ...jwk, key_ops: ['verify'], use: 'sig' } as JsonWebKey;
  return SUBTLE.importKey('jwk', copy, algorithmForJwk(jwk) as AlgorithmIdentifier, extractable, ['verify']);
}

/** Import a private key from its JWK representation. */
export async function importPrivateKeyFromJwk(jwk: AgentKeyJwk): Promise<CryptoKey> {
  const copy = { ...jwk, key_ops: ['sign'], use: 'sig' } as JsonWebKey;
  return SUBTLE.importKey('jwk', copy, algorithmForJwk(jwk) as AlgorithmIdentifier, false, ['sign']);
}

/** Import a public key from raw (32-byte Ed25519 / uncompressed P-256) bytes. */
export async function importPublicKeyFromRaw(
  alg: KeyAlgorithm,
  raw: Uint8Array,
): Promise<CryptoKey> {
  const algo =
    alg === 'Ed25519' ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  return SUBTLE.importKey('raw', raw as BufferSource, algo as AlgorithmIdentifier, false, ['verify']);
}

/** Export a public key to its base64url SPKI DER form. */
export async function exportPublicKeyToSpkiB64Url(publicKey: CryptoKey): Promise<string> {
  return exportSpkiB64Url(publicKey);
}

/**
 * Sign a canonical string (UTF-8) and return the base64url signature.
 * `key` must be a private CryptoKey (Ed25519 or P-256).
 */
export async function signCanonical(privateKey: CryptoKey, canonical: string): Promise<string> {
  const sig = await SUBTLE.sign(signParamsForKey(privateKey), privateKey, utf8Encode(canonical));
  return bytesToBase64Url(new Uint8Array(sig));
}

/**
 * Verify a base64url signature over a canonical string.
 * `key` must be a public CryptoKey (Ed25519 or P-256).
 */
export async function verifyCanonical(
  publicKey: CryptoKey,
  canonical: string,
  signatureB64Url: string,
): Promise<boolean> {
  let sig: Uint8Array;
  try {
    sig = base64UrlToBytes(signatureB64Url);
  } catch {
    return false;
  }
  return SUBTLE.verify(
    signParamsForKey(publicKey),
    publicKey,
    sig as BufferSource,
    utf8Encode(canonical),
  );
}

/** Generate a fresh random nonce (hex, 16 bytes). */
export function generateNonce(): string {
  return Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Current time as Unix seconds. */
export function unixNowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
