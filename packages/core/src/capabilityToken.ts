/**
 * Pre-Shared Capability Tokens.
 *
 * A lightweight, HMAC-SHA-256-signed token that grants **scoped** access to
 * declared agent capabilities. It is a fallback/auth-alongside mode for
 * environments that do not run a WAF / edge signature-verification layer.
 *
 * Least privilege is enforced by the scope checks:
 *   - a token for one capability can NEVER authorize unrelated capabilities
 *     (`cap` is the only capability allowlist), and
 *   - a token's origin/path scope cannot authorize arbitrary origins or paths.
 *
 * Token format: `v1.<base64url(json claims)>.<base64url(hmac-sha256)>`
 */
import { base64UrlToBytes, bytesToBase64Url, randomHexNonce, utf8Encode } from './encoding.ts';

export const CAPABILITY_TOKEN_VERSION = 'v1';

export interface CapabilityTokenClaims {
  /** Token id (unique). Enables replay detection storing `jti`. */
  jti?: string;
  /** Issuer (optional, e.g. the origin that minted the token). */
  iss?: string;
  /** Audience (optional). */
  aud?: string;
  /** Subject (optional, e.g. the requester domain). */
  sub?: string;
  /** Allowed capability/action names. Empty = no capabilities. */
  cap: string[];
  /** Allowed target origins (exact `scheme://host[:port]`). */
  origins?: string[];
  /** Allowed target path prefixes (e.g. `/api/agent/search`). */
  paths?: string[];
  /** Issued-at (Unix seconds). */
  iat: number;
  /** Expiration (Unix seconds). */
  exp: number;
  /** Not-before (Unix seconds, optional). */
  nbf?: number;
}

export interface IssueCapabilityTokenOptions {
  /** Shared secret (UTF-8) used for HMAC-SHA-256. */
  secret: string;
  /** Token lifetime in seconds (default 300). */
  ttlSeconds?: number;
  jti?: string;
  /** Current time as Unix seconds (defaults to now). */
  now?: number;
}

export interface VerifyCapabilityTokenOptions {
  secret: string;
  /** Current time as Unix seconds. */
  now?: number;
  /** Allowed clock skew in seconds (default 30). */
  skewSeconds?: number;
  /** If provided, the token MUST authorize this capability. */
  requireCapability?: string;
  /** If provided, the token MUST authorize this origin. */
  requireOrigin?: string;
  /** If provided, the token MUST authorize this path prefix. */
  requirePath?: string;
}

export type CapabilityTokenFailureReason =
  | 'malformed'
  | 'bad-signature'
  | 'expired'
  | 'not-yet-valid'
  | 'scope-capability'
  | 'scope-origin'
  | 'scope-path';

export interface CapabilityTokenVerification {
  valid: boolean;
  reason?: CapabilityTokenFailureReason;
  claims?: CapabilityTokenClaims;
}

function constantTimeEqualB64Url(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSign(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', utf8Encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, utf8Encode(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

export function serializeCapabilityToken(claims: CapabilityTokenClaims, signatureB64Url: string): string {
  return `${CAPABILITY_TOKEN_VERSION}.${bytesToBase64Url(utf8Encode(JSON.stringify(claims)))}.${signatureB64Url}`;
}

/** Sign (mint) a scoped capability token. */
export async function issueCapabilityToken(
  claims: Omit<CapabilityTokenClaims, 'iat' | 'exp'> & Partial<Pick<CapabilityTokenClaims, 'iat' | 'exp'>>,
  options: IssueCapabilityTokenOptions,
): Promise<string> {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const ttlSeconds = options.ttlSeconds ?? 300;
  const iat = claims.iat ?? now;
  const exp = claims.exp ?? iat + ttlSeconds;
  const full: CapabilityTokenClaims = {
    ...claims,
    jti: claims.jti ?? options.jti ?? randomHexNonce(16),
    iat,
    exp,
  };
  const payloadB64 = bytesToBase64Url(utf8Encode(JSON.stringify(full)));
  const input = `${CAPABILITY_TOKEN_VERSION}.${payloadB64}`;
  const sig = await hmacSign(options.secret, input);
  return serializeCapabilityToken(full, sig);
}

/** Decode without verifying (for debugging/UI). Returns null when malformed. */
export function decodeCapabilityToken(token: string): CapabilityTokenClaims | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== CAPABILITY_TOKEN_VERSION) return null;
  try {
    const json = new TextDecoder().decode(base64UrlToBytes(parts[1]!));
    const claims = JSON.parse(json) as CapabilityTokenClaims;
    if (!Array.isArray(claims.cap)) return null;
    return claims;
  } catch {
    return null;
  }
}

function scopeAllowsCapability(claims: CapabilityTokenClaims, capability: string): boolean {
  return claims.cap.includes(capability);
}

function scopeAllowsOrigin(claims: CapabilityTokenClaims, origin: string): boolean {
  if (!claims.origins || claims.origins.length === 0) return true;
  const target = origin.toLowerCase();
  return claims.origins.some((o) => o.toLowerCase() === target);
}

function scopeAllowsPath(claims: CapabilityTokenClaims, path: string): boolean {
  if (!claims.paths || claims.paths.length === 0) return true;
  return claims.paths.some((p) => path === p || path.startsWith(p.endsWith('/') ? p : `${p}/`));
}

/** Verify a token and enforce the requested scope (least privilege). */
export async function verifyCapabilityToken(
  token: string,
  options: VerifyCapabilityTokenOptions,
): Promise<CapabilityTokenVerification> {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== CAPABILITY_TOKEN_VERSION) {
    return { valid: false, reason: 'malformed' };
  }
  const payloadB64 = parts[1]!;
  const sigB64 = parts[2]!;
  const expected = await hmacSign(options.secret, `${CAPABILITY_TOKEN_VERSION}.${payloadB64}`);
  if (!constantTimeEqualB64Url(expected, sigB64)) {
    return { valid: false, reason: 'bad-signature' };
  }

  const claims = decodeCapabilityToken(token);
  if (!claims) return { valid: false, reason: 'malformed' };

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.skewSeconds ?? 30;
  if (now > claims.exp + skew) return { valid: false, reason: 'expired', claims };
  if (claims.nbf !== undefined && now + skew < claims.nbf) {
    return { valid: false, reason: 'not-yet-valid', claims };
  }

  if (options.requireCapability !== undefined && !scopeAllowsCapability(claims, options.requireCapability)) {
    return { valid: false, reason: 'scope-capability', claims };
  }
  if (options.requireOrigin !== undefined && !scopeAllowsOrigin(claims, options.requireOrigin)) {
    return { valid: false, reason: 'scope-origin', claims };
  }
  if (options.requirePath !== undefined && !scopeAllowsPath(claims, options.requirePath)) {
    return { valid: false, reason: 'scope-path', claims };
  }

  return { valid: true, claims };
}

export { scopeAllowsCapability, scopeAllowsOrigin, scopeAllowsPath };
