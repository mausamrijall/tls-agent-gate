/**
 * Short-lived challenge-response for non-WAF origins.
 *
 * A server issues a random challenge; the requester proves cryptographic
 * possession of its agent key by signing a canonical payload that binds the
 * challenge, issue time, method, path, and host. Challenges are short-lived
 * (default 45s) and single-use (nonce reserve/consume) so responses cannot be
 * replayed.
 */
import { importPublicKeyFromJwk, signCanonical, verifyCanonical } from './crypto.ts';
import { randomHexNonce } from './encoding.ts';

export const CHALLENGE_VERSION = 'agent-tls-gate-challenge-v1';

export const DEFAULT_CHALLENGE_TTL_MS = 45_000;

export interface ChallengeProof {
  challenge: string;
  /** Epoch milliseconds at issue time. */
  issuedAt: number;
  /** Epoch milliseconds when the challenge expires. */
  expiresAt: number;
}

/**
 * Nonce store for challenges. `reserve` records an issued challenge;
 * `consume` marks it used exactly once.
 */
export interface ChallengeNonceStore {
  reserve(nonce: string, expiresAtMs: number): Promise<boolean>;
  consume(nonce: string, expiresAtMs: number): Promise<boolean>;
}

type ChallengeEntry = { status: 'reserved' | 'consumed'; expiresAtMs: number };

/** In-memory challenge store (single-instance deployments). */
export class MemoryChallengeNonceStore implements ChallengeNonceStore {
  private entries = new Map<string, ChallengeEntry>();

  private evict(now: number): void {
    for (const [k, v] of this.entries) {
      if (v.expiresAtMs <= now) this.entries.delete(k);
    }
  }

  async reserve(nonce: string, expiresAtMs: number): Promise<boolean> {
    const now = Date.now();
    this.evict(now);
    if (this.entries.has(nonce)) return false;
    this.entries.set(nonce, { status: 'reserved', expiresAtMs });
    return true;
  }

  async consume(nonce: string, expiresAtMs: number): Promise<boolean> {
    const now = Date.now();
    this.evict(now);
    const entry = this.entries.get(nonce);
    if (!entry) return false;
    if (entry.expiresAtMs <= now) {
      this.entries.delete(nonce);
      return false;
    }
    if (entry.status === 'consumed') return false;
    entry.status = 'consumed';
    return true;
  }

  get size(): number {
    return this.entries.size;
  }
}

export interface IssueChallengeOptions {
  nonceStore: ChallengeNonceStore;
  ttlMs?: number;
  nowMs?: number;
}

/** Issue a fresh, single-use challenge. */
export async function issueChallenge(options: IssueChallengeOptions): Promise<ChallengeProof> {
  const ttlMs = options.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  const nowMs = options.nowMs ?? Date.now();
  for (let attempt = 0; attempt < 5; attempt++) {
    const challenge = randomHexNonce(32);
    const expiresAt = nowMs + ttlMs;
    if (await options.nonceStore.reserve(challenge, expiresAt)) {
      return { challenge, issuedAt: nowMs, expiresAt };
    }
  }
  throw new Error('Could not reserve a unique challenge nonce');
}

export interface ChallengeCanonicalParts {
  challenge: string;
  /** Issue time in epoch milliseconds. */
  issuedAt: number;
  method: string;
  urlPathAndQuery: string;
  host: string;
}

/** The exact payload a requester signs to prove possession. */
export function buildChallengeCanonical(parts: ChallengeCanonicalParts): string {
  return [
    CHALLENGE_VERSION,
    parts.challenge,
    String(parts.issuedAt),
    parts.method.toUpperCase(),
    parts.urlPathAndQuery.replace(/^\s+|\s+$/g, ''),
    parts.host.toLowerCase().trim(),
  ].join('\n');
}

export interface VerifyChallengeResponseOptions {
  proof: ChallengeProof;
  method: string;
  url: string;
  /** Signature over buildChallengeCanonical(...) using the agent private key. */
  signatureB64Url: string;
  publicKeyJwk: JsonWebKey;
  nonceStore: ChallengeNonceStore;
  /** Max age for responses (default the challenge TTL). */
  ttlMs?: number;
  nowMs?: number;
}

export type ChallengeVerificationReason = 'expired' | 'unknown-or-replayed' | 'bad-signature' | 'malformed-url';

export interface ChallengeVerification {
  valid: boolean;
  reason?: ChallengeVerificationReason;
}

/** Verify a challenge response: freshness, single-use, and signature. */
export async function verifyChallengeResponse(
  options: VerifyChallengeResponseOptions,
): Promise<ChallengeVerification> {
  const nowMs = options.nowMs ?? Date.now();
  const ttlMs = options.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;

  if (nowMs > options.proof.expiresAt || nowMs < options.proof.issuedAt - ttlMs) {
    return { valid: false, reason: 'expired' };
  }

  // Consume the nonce first (single-use). False ⇒ unknown/expired/replayed.
  if (!(await options.nonceStore.consume(options.proof.challenge, options.proof.expiresAt))) {
    return { valid: false, reason: 'unknown-or-replayed' };
  }

  let target: URL;
  try {
    target = new URL(options.url, `https://${options.proof.challenge ? 'challenge.local' : 'challenge.local'}`);
  } catch {
    return { valid: false, reason: 'malformed-url' };
  }
  const host = target.host.toLowerCase();
  const canonical = buildChallengeCanonical({
    challenge: options.proof.challenge,
    issuedAt: options.proof.issuedAt,
    method: options.method,
    urlPathAndQuery: `${target.pathname}${target.search}`,
    host,
  });

  try {
    const publicKey = await importPublicKeyFromJwk(options.publicKeyJwk);
    const ok = await verifyCanonical(publicKey, canonical, options.signatureB64Url);
    if (!ok) return { valid: false, reason: 'bad-signature' };
  } catch {
    return { valid: false, reason: 'bad-signature' };
  }

  return { valid: true };
}

export { signCanonical };
