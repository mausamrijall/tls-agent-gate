/**
 * Shared types for the verifier package.
 */
import type { AgentKeyJwk } from '@tls-agent-gate/core';

/** Normalized request shape consumed by `verifyAgentRequest`. */
export interface VerifierRequest {
  /** HTTP method (case-insensitive). */
  method: string;
  /**
   * Absolute or root-relative URL. When relative, the `host` header is
   * used to complete it for canonical payload construction.
   */
  url: string;
  /** Lowercase header names. Values may be strings or arrays. */
  headers: Record<string, string | string[] | undefined>;
  /**
   * Raw request body bytes. Must be provided whenever the request carries
   * a body (the caller signs its SHA-256). Omit/undefined when empty.
   */
  body?: Uint8Array | ArrayBuffer | string | null;
}

export interface VerifiedManifest {
  url: string;
  sha256?: string;
  caps?: string[];
}

export interface VerificationResult {
  /** True when the request passed all checks. */
  verified: boolean;
  /** Canonical hostname of the caller (from its identity URL). */
  domain: string;
  /** Absolute URL of the caller's identity document. */
  identityUrl: string;
  /** Key id of the verified signing key. */
  keyId: string;
  /** Signature algorithm ('Ed25519' | 'ES256'). */
  algorithm: string;
  /** ISO-8601 timestamp of verification. */
  verifiedAt: string;
  /** Parsed manifest header (when present). */
  manifest: VerifiedManifest | null;
  /** Caller-declared policy (from its identity document). */
  callerPolicy: { allowLocalAgents?: boolean; allowedDevKeyThumbprints?: string[]; requireSignedRequests?: boolean } | null;
  /** True when the caller used a localhost/private-network identity that was explicitly allowlisted. */
  usedLocalAllowlist: boolean;
}

/** Store used to reject replayed nonces (single-use). */
export interface NonceStore {
  /**
   * Atomically record a nonce. Returns `false` when the nonce is already
   * known (replay) — verification must then fail.
   * `expiresAtMs` is the absolute expiry timestamp.
   */
  checkAndSet(nonce: string, expiresAtMs: number): Promise<boolean>;
  /** Optional best-effort eviction of expired entries. */
  cleanup?(): Promise<void>;
}

/** Fetch cache for identity documents / manifests. */
export interface FetchCache {
  get(url: string): Promise<string | null>;
  set(url: string, body: string, ttlMs: number): Promise<void>;
}

/** Result of fetching a remote document. */
export interface FetchedDocument {
  ok: boolean;
  status: number;
  contentType: string;
  body: string;
}

export type FetchImpl = (url: string, init?: { signal?: AbortSignal }) => Promise<Response>;

export interface VerifyOptions {
  /** Clock to use for skew checks (defaults to `Date.now`). */
  now?: number;
  /** Allowed clock skew in seconds (default 60). Set to Infinity to disable. */
  skewSeconds?: number;
  /**
   * Require the request to be signed. When `false`, unsigned requests with a
   * valid identity header are still verified (signature optional). Default true.
   */
  requireSignedRequests?: boolean;
  /**
   * Allow callers that identify via localhost / private-network origins.
   * Default false. When true, private origins are only accepted when the
   * verified signing key's thumbprint is in `allowedDevKeyThumbprints`.
   */
  allowLocalAgents?: boolean;
  /** Dev key thumbprints (RFC 7638 base64url) permitted for private origins. */
  allowedDevKeyThumbprints?: string[];
  /** Require the identity document `subject` to share the identity URL's origin. */
  requireSubjectMatch?: boolean;
  /** Enforce identity document `expiresAt` when present. */
  checkIdentityExpiry?: boolean;
  /** Manifest hash policy: 'off' (ignore), 'if-present' (default), 'required'. */
  checkManifest?: 'off' | 'if-present' | 'required';
  /** Verify advertised manifest capability ids exist in the fetched manifest (only when manifest is fetched). */
  checkManifestCaps?: boolean;
  /** Nonce store for anti-replay. Defaults to a MemoryNonceStore. */
  nonceStore?: NonceStore;
  /** Fetch cache for identity/manifest documents. Defaults to MemoryFetchCache. */
  cache?: FetchCache;
  /** Override the global fetch (for tests / edge adapters). */
  fetchImpl?: FetchImpl;
  /** Timeout for identity/manifest fetches (default 5000 ms). */
  fetchTimeoutMs?: number;
  /** Maximum identity/manifest response size (default 65536 bytes). */
  fetchMaxBytes?: number;
  /** TTL for cached identity docs (default 60s). */
  identityCacheTtlMs?: number;
  /** TTL for cached manifests (default 30s). */
  manifestCacheTtlMs?: number;
}

/** Verification failure codes (stable, machine-readable). */
export const VerificationErrorCode = {
  MissingIdentityHeader: 'ERR_MISSING_IDENTITY_HEADER',
  NotHttps: 'ERR_NOT_HTTPS',
  LocalhostBlocked: 'ERR_LOCALHOST_BLOCKED',
  MissingSignature: 'ERR_MISSING_SIGNATURE',
  MalformedSignature: 'ERR_MALFORMED_SIGNATURE',
  Expired: 'ERR_EXPIRED',
  FutureTimestamp: 'ERR_FUTURE_TIMESTAMP',
  ReplayedNonce: 'ERR_REPLAYED_NONCE',
  IdentityFetch: 'ERR_IDENTITY_FETCH',
  InvalidIdentity: 'ERR_INVALID_IDENTITY',
  IdentityExpired: 'ERR_IDENTITY_EXPIRED',
  SubjectMismatch: 'ERR_SUBJECT_MISMATCH',
  KeyNotFound: 'ERR_KEY_NOT_FOUND',
  InvalidSignature: 'ERR_SIGNATURE_INVALID',
  KeyNotAllowlisted: 'ERR_KEY_NOT_ALLOWLISTED',
  ManifestRequired: 'ERR_MANIFEST_REQUIRED',
  ManifestFetch: 'ERR_MANIFEST_FETCH',
  ManifestHashMismatch: 'ERR_MANIFEST_HASH_MISMATCH',
  ManifestCapUnknown: 'ERR_MANIFEST_CAP_UNKNOWN',
  BodyUnavailable: 'ERR_BODY_UNAVAILABLE',
  BadRequest: 'ERR_BAD_REQUEST',
} as const;

export type VerificationErrorCodeType = (typeof VerificationErrorCode)[keyof typeof VerificationErrorCode];

/** Error thrown by `verifyAgentRequest` on failure. */
export class VerificationError extends Error {
  readonly code: VerificationErrorCodeType;
  readonly statusCode: number;
  readonly details?: Record<string, string | number | boolean>;

  constructor(
    code: VerificationErrorCodeType,
    message: string,
    statusCode = 403,
    details?: Record<string, string | number | boolean>,
  ) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function isVerificationError(err: unknown): err is VerificationError {
  return err instanceof VerificationError;
}

/** Helper to read a header from a normalized record. */
export function getHeader(headers: VerifierRequest['headers'], name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (Array.isArray(value)) {
    const first = value[0];
    return first === undefined ? undefined : first;
  }
  return value;
}

/** Extract canonical request data used by signature verification. */
export interface RequestEssentials {
  method: string;
  host: string;
  pathAndQuery: string;
}

export function extractRequestEssentials(req: VerifierRequest): RequestEssentials {
  const method = req.method.toUpperCase();
  const hostHeader = getHeader(req.headers, 'host');
  let host = '';
  let pathAndQuery = '';

  try {
    const parsed = new URL(req.url, hostHeader ? `https://${hostHeader}` : 'https://invalid.local');
    host = parsed.host.toLowerCase();
    pathAndQuery = `${parsed.pathname}${parsed.search}`;
  } catch {
    // Fall back to the host header and manual path extraction.
    host = (hostHeader ?? '').toLowerCase().trim();
    const afterScheme = req.url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    const slashIdx = afterScheme.indexOf('/');
    pathAndQuery = slashIdx === -1 ? '/' : afterScheme.slice(slashIdx);
  }

  return { method, host, pathAndQuery: pathAndQuery || '/' };
}

/** Identity document shape consumed by the verifier. */
export interface FetchedIdentity {
  identityUrl: string;
  domain: string;
  doc: {
    subject?: string;
    expiresAt?: string;
    keys: { primary: { alg: string; kid: string; publicKeyJwk: AgentKeyJwk }; secondary?: { alg: string; kid: string; publicKeyJwk: AgentKeyJwk } };
    policy?: { allowLocalAgents?: boolean; allowedDevKeyThumbprints?: string[]; requireSignedRequests?: boolean };
  };
}
