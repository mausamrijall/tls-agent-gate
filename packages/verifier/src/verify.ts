/**
 * `verifyAgentRequest` — framework-agnostic request verification.
 *
 * Pipeline:
 *   1. require + parse `X-Agent-Identity` (absolute https URL)
 *   2. reject non-https and non-allowlisted private/loopback origins
 *   3. require + parse `X-Agent-Signature`, enforce timestamp skew
 *   4. single-use nonce check (anti-replay)
 *   5. fetch + cache `/.well-known/agent-identity.json` (bounded, HTTPS)
 *   6. validate the identity document schema; locate the signing key
 *   7. verify the canonical payload signature
 *   8. enforce the dev-key allowlist for private origins
 *   9. optionally check the manifest SHA-256 / capabilities
 */
import {
  buildCanonicalPayload,
  formatManifestHeader,
  HEADER_IDENTITY,
  HEADER_MANIFEST,
  HEADER_SIGNATURE,
  HEADER_TOKEN,
  importPublicKeyFromJwk,
  verifyCapabilityToken,
  parseIdentityHeader,
  parseManifestHeader,
  parseSignatureHeader,
  sha256Hex,
  thumbprintOfJwk,
  utf8Encode,
  validateIdentityDocument,
  validateManifest,
  verifyCanonical,
} from '@tls-agent-gate/core';
import { MemoryFetchCache } from './cache.ts';
import { isPrivateOrLoopbackHost } from './hostPolicy.ts';
import { fetchWithCache } from './net.ts';
import { MemoryNonceStore } from './nonce.ts';
import {
  extractRequestEssentials,
  getHeader,
  isVerificationError,
  VerificationError,
  VerificationErrorCode,
  type FetchCache,
  type NonceStore,
  type VerificationResult,
  type VerifierRequest,
  type VerifyOptions,
} from './types.ts';

const DEFAULT_SKEW_SECONDS = 60;
const DEFAULT_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_FETCH_MAX_BYTES = 65536;
const DEFAULT_IDENTITY_CACHE_TTL_MS = 60_000;
const DEFAULT_MANIFEST_CACHE_TTL_MS = 30_000;

function asOptions(opts: VerifyOptions = {}): Required<
  Pick<
    VerifyOptions,
    'skewSeconds' | 'requireSignedRequests' | 'allowLocalAgents' | 'checkManifest' | 'fetchTimeoutMs' | 'fetchMaxBytes' | 'identityCacheTtlMs' | 'manifestCacheTtlMs'
  >
> & VerifyOptions {
  return {
    skewSeconds: opts.skewSeconds ?? DEFAULT_SKEW_SECONDS,
    requireSignedRequests: opts.requireSignedRequests ?? true,
    allowLocalAgents: opts.allowLocalAgents ?? false,
    checkManifest: opts.checkManifest ?? 'if-present',
    fetchTimeoutMs: opts.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
    fetchMaxBytes: opts.fetchMaxBytes ?? DEFAULT_FETCH_MAX_BYTES,
    identityCacheTtlMs: opts.identityCacheTtlMs ?? DEFAULT_IDENTITY_CACHE_TTL_MS,
    manifestCacheTtlMs: opts.manifestCacheTtlMs ?? DEFAULT_MANIFEST_CACHE_TTL_MS,
    ...opts,
  };
}

export async function verifyAgentRequest(
  req: VerifierRequest,
  opts: VerifyOptions = {},
): Promise<VerificationResult> {
  const o = asOptions(opts);
  const nowSec = (o.now ?? Date.now()) / 1000;

  // ---- 0. Capability-token fallback (non-WAF mode) ------------------
  // When no signature is present but a pre-shared X-Agent-Token is, verify
  // the token (least privilege: capability + origin + path scope) instead of
  // requiring identity + signature. If a signature IS present, the normal
  // signature path takes precedence.
  const rawToken = getHeader(req.headers, HEADER_TOKEN);
  if (o.allowCapabilityTokens && o.capabilityTokenSecret && rawToken && !getHeader(req.headers, HEADER_SIGNATURE)) {
    return verifyCapabilityTokenMode(req, rawToken, o, nowSec);
  }

  // ---- 1. Identity header -------------------------------------------
  const rawIdentity = getHeader(req.headers, HEADER_IDENTITY);
  if (!rawIdentity) {
    throw new VerificationError(
      VerificationErrorCode.MissingIdentityHeader,
      'Missing X-Agent-Identity header — agent requests must be authenticated.',
      401,
    );
  }
  const identityUrl = parseIdentityHeader(rawIdentity);
  if (!identityUrl) {
    throw new VerificationError(VerificationErrorCode.BadRequest, 'Malformed X-Agent-Identity header.');
  }

  let identity: URL;
  try {
    identity = new URL(identityUrl);
  } catch {
    throw new VerificationError(VerificationErrorCode.BadRequest, 'X-Agent-Identity is not a valid URL.');
  }

  // ---- 2. Origin policy ----------------------------------------------
  const domain = identity.hostname.toLowerCase();
  const privateOrigin = isPrivateOrLoopbackHost(domain);
  if (identity.protocol !== 'https:') {
    // Non-HTTPS identities are only tolerated for explicitly allowlisted
    // local/private dev origins (e.g. http://localhost during testing).
    if (!(o.allowLocalAgents && privateOrigin)) {
      throw new VerificationError(
        VerificationErrorCode.NotHttps,
        'Agent identity must be anchored to an HTTPS origin.',
      );
    }
  }
  let usedLocalAllowlist = false;
  if (privateOrigin && !o.allowLocalAgents) {
    throw new VerificationError(
      VerificationErrorCode.LocalhostBlocked,
      'Agent identity originates from localhost/private network and local agents are disabled.',
      403,
      { domain },
    );
  }
  if (privateOrigin && o.allowLocalAgents && !(o.allowedDevKeyThumbprints?.length)) {
    throw new VerificationError(
      VerificationErrorCode.LocalhostBlocked,
      'Local agents are enabled but no allowedDevKeyThumbprints were configured.',
      403,
      { domain },
    );
  }

  // ---- 3. Signature header -------------------------------------------
  const rawSignature = getHeader(req.headers, HEADER_SIGNATURE);
  if (!rawSignature) {
    if (!o.requireSignedRequests) {
      return {
        verified: false,
        domain,
        authMethod: 'unsigned',
        identityUrl,
        keyId: '',
        algorithm: '',
        verifiedAt: new Date().toISOString(),
        manifest: null,
        callerPolicy: null,
        usedLocalAllowlist: false,
      };
    }
    throw new VerificationError(
      VerificationErrorCode.MissingSignature,
      'Missing X-Agent-Signature header — signed requests are required.',
      401,
    );
  }
  const signature = parseSignatureHeader(rawSignature);
  if (!signature) {
    throw new VerificationError(VerificationErrorCode.MalformedSignature, 'Malformed X-Agent-Signature header.');
  }

  const alg = signature.alg.toLowerCase();
  const keyAlg = alg === 'ed25519' ? 'Ed25519' : alg === 'es256' ? 'ES256' : null;
  if (!keyAlg) {
    throw new VerificationError(VerificationErrorCode.MalformedSignature, `Unsupported signature algorithm: ${signature.alg}`);
  }

  const created = Number(signature.created);
  if (!Number.isFinite(created)) {
    throw new VerificationError(VerificationErrorCode.MalformedSignature, 'Signature created timestamp is not a number.');
  }

  // ---- Timestamp skew -------------------------------------------------
  const skew = Number(o.skewSeconds);
  if (Number.isFinite(skew)) {
    const diff = Math.abs(created - nowSec);
    if (diff > skew) {
      const future = created > nowSec;
      throw new VerificationError(
        future ? VerificationErrorCode.FutureTimestamp : VerificationErrorCode.Expired,
        future ? 'Signature timestamp is in the future beyond allowed skew.' : 'Signature timestamp is expired beyond allowed skew.',
        401,
      );
    }
  }

  // ---- 4. Nonce replay ------------------------------------------------
  const nonceStore: NonceStore = o.nonceStore ?? new MemoryNonceStore();
  const nonceTtlMs = (Number(o.skewSeconds) || DEFAULT_SKEW_SECONDS) * 2000 + 5000;
  const expiresAtMs = Date.now() + nonceTtlMs;
  if (!(await nonceStore.checkAndSet(signature.nonce, expiresAtMs))) {
    throw new VerificationError(VerificationErrorCode.ReplayedNonce, 'Nonce was already used — possible replay.', 401);
  }

  // ---- 5. Body hash ----------------------------------------------------
  let bodySha256 = '';
  if (req.body !== undefined && req.body !== null) {
    // Normalize: a zero-length body is treated as "no body" (empty string
    // in the canonical payload), matching how callers sign bodyless GETs.
    const length =
      typeof req.body === 'string'
        ? utf8Encode(req.body).byteLength
        : (req.body as Uint8Array | ArrayBuffer).byteLength;
    if (length > 0) {
      bodySha256 = await sha256Hex(req.body as string | Uint8Array | ArrayBuffer);
    }
  }

  // ---- 6. Manifest header ----------------------------------------------
  const rawManifest = getHeader(req.headers, HEADER_MANIFEST);
  const manifest = rawManifest ? parseManifestHeader(rawManifest) : null;
  if (o.checkManifest === 'required' && !manifest) {
    throw new VerificationError(VerificationErrorCode.ManifestRequired, 'X-Agent-Manifest header is required.');
  }
  const manifestSha256 = manifest?.sha256 ?? '';

  const essentials = extractRequestEssentials(req);

  // ---- Fetch identity document (cached, bounded) -----------------------
  let identityText: string;
  try {
    identityText = await fetchWithCache(
      identityUrl,
      o.cache ?? new MemoryFetchCache(),
      o.identityCacheTtlMs,
      { timeoutMs: o.fetchTimeoutMs, maxBytes: o.fetchMaxBytes, fetchImpl: o.fetchImpl },
    );
  } catch (err) {
    throw new VerificationError(VerificationErrorCode.IdentityFetch, `Could not fetch agent identity: ${err instanceof Error ? err.message : 'unknown error'}`, 502);
  }

  let doc: unknown;
  try {
    doc = JSON.parse(identityText);
  } catch {
    throw new VerificationError(VerificationErrorCode.InvalidIdentity, 'Agent identity document is not valid JSON.', 502);
  }
  const docValidation = validateIdentityDocument(doc);
  if (!docValidation.valid) {
    const first = docValidation.errors[0];
    throw new VerificationError(
      VerificationErrorCode.InvalidIdentity,
      `Agent identity document failed validation${first ? `: ${first.path} ${first.message}` : ''}.`,
      502,
    );
  }

  const identityDoc = doc as {
    subject?: string;
    expiresAt?: string;
    keys: { primary: { alg: string; kid: string; publicKeyJwk: JsonWebKey }; secondary?: { alg: string; kid: string; publicKeyJwk: JsonWebKey } };
    policy?: { allowLocalAgents?: boolean; allowedDevKeyThumbprints?: string[]; requireSignedRequests?: boolean };
  };

  if (o.checkIdentityExpiry && identityDoc.expiresAt) {
    const expiry = Date.parse(identityDoc.expiresAt);
    if (Number.isFinite(expiry) && expiry <= Date.now()) {
      throw new VerificationError(VerificationErrorCode.IdentityExpired, 'Agent identity document has expired.');
    }
  }

  if (o.requireSubjectMatch !== false && identityDoc.subject) {
    try {
      // Compare by host (hostname:port), not by full origin: the identity
      // URL's scheme is already enforced separately, and local dev may use
      // http://localhost while the subject still reads https://localhost/agent.
      const subjectHost = new URL(identityDoc.subject).host;
      if (subjectHost !== identity.host) {
        throw new VerificationError(
          VerificationErrorCode.SubjectMismatch,
          'Agent identity subject does not match the identity URL origin.',
        );
      }
    } catch (err) {
      if (isVerificationError(err)) throw err;
      throw new VerificationError(VerificationErrorCode.SubjectMismatch, 'Agent identity subject is not a valid URL.');
    }
  }

  // ---- 8. Locate key & verify signature --------------------------------
  let keyInfo: { alg: string; publicKeyJwk: JsonWebKey } | null = null;
  for (const k of [identityDoc.keys.primary, identityDoc.keys.secondary]) {
    if (k && k.kid === signature.keyid) {
      keyInfo = { alg: k.alg, publicKeyJwk: k.publicKeyJwk };
      break;
    }
  }
  if (!keyInfo) {
    throw new VerificationError(VerificationErrorCode.KeyNotFound, `No key with kid "${signature.keyid}" in the agent identity document.`);
  }
  if (keyInfo.alg !== keyAlg) {
    throw new VerificationError(VerificationErrorCode.MalformedSignature, 'Signature algorithm does not match the declared key algorithm.');
  }

  const canonical = buildCanonicalPayload({
    method: essentials.method,
    urlPathAndQuery: essentials.pathAndQuery,
    host: essentials.host,
    created: signature.created,
    nonce: signature.nonce,
    bodySha256,
    manifestSha256,
  });

  const publicKey = await importPublicKeyFromJwk(keyInfo.publicKeyJwk);
  const valid = await verifyCanonical(publicKey, canonical, signature.sig);
  if (!valid) {
    throw new VerificationError(VerificationErrorCode.InvalidSignature, 'Signature verification failed.');
  }

  const keyThumbprint = await thumbprintOfJwk(keyInfo.publicKeyJwk);

  // ---- Private-origin allowlist (after verifying the signature) --------
  if (privateOrigin && o.allowLocalAgents) {
    if (!o.allowedDevKeyThumbprints?.includes(keyThumbprint)) {
      throw new VerificationError(
        VerificationErrorCode.KeyNotAllowlisted,
        'Local agent key is not in allowedDevKeyThumbprints.',
        403,
        { thumbprint: keyThumbprint },
      );
    }
    usedLocalAllowlist = true;
  }

  // ---- 9. Optional manifest SHA-256 / capabilities check ----------------
  if (manifest && manifest.sha256 && o.checkManifest !== 'off') {
    let manifestText: string;
    try {
      manifestText = await fetchWithCache(
        manifest.url,
        o.cache ?? new MemoryFetchCache(),
        o.manifestCacheTtlMs,
        { timeoutMs: o.fetchTimeoutMs, maxBytes: o.fetchMaxBytes, fetchImpl: o.fetchImpl },
      );
    } catch (err) {
      throw new VerificationError(VerificationErrorCode.ManifestFetch, `Could not fetch agent manifest: ${err instanceof Error ? err.message : 'unknown error'}`, 502);
    }
    const manifestHash = await sha256Hex(manifestText);
    if (manifestHash !== manifest.sha256.toLowerCase()) {
      throw new VerificationError(
        VerificationErrorCode.ManifestHashMismatch,
        'Agent manifest SHA-256 does not match the value in the header.',
      );
    }
    if (o.checkManifestCaps && manifest.caps) {
      let manifestDoc: unknown;
      try {
        manifestDoc = JSON.parse(manifestText);
      } catch {
        throw new VerificationError(VerificationErrorCode.ManifestFetch, 'Agent manifest is not valid JSON.', 502);
      }
      const manifestValidation = validateManifest(manifestDoc);
      if (!manifestValidation.valid) {
        throw new VerificationError(VerificationErrorCode.ManifestFetch, 'Agent manifest failed schema validation.', 502);
      }
      const capIds = new Set((manifestDoc as { capabilities: Array<{ id: string }> }).capabilities.map((c) => c.id));
      for (const cap of manifest.caps) {
        if (!capIds.has(cap)) {
          throw new VerificationError(VerificationErrorCode.ManifestCapUnknown, `Manifest does not advertise capability "${cap}".`);
        }
      }
    }
  }

  return {
    verified: true,
    domain,
    identityUrl,
    keyId: signature.keyid,
    algorithm: keyAlg,
    verifiedAt: new Date().toISOString(),
    manifest: manifest ? { url: manifest.url, sha256: manifest.sha256, caps: manifest.caps } : null,
    callerPolicy: identityDoc.policy ?? null,
    usedLocalAllowlist,
    authMethod: 'signature',
  };
}

/**
 * Token-mode authentication: verify a pre-shared X-Agent-Token as a
 * fallback when WAF/edge signature verification is not in use. Enforces
 * least privilege against the request's own origin + path and the required
 * capability (if configured).
 */
async function verifyCapabilityTokenMode(
  req: VerifierRequest,
  token: string,
  o: VerifyOptions,
  nowSec: number,
): Promise<VerificationResult> {
  const essentials = extractRequestEssentials(req);

  let target: URL;
  try {
    target = new URL(req.url, `https://${essentials.host}`);
  } catch {
    throw new VerificationError(VerificationErrorCode.TokenInvalid, 'Malformed request URL for capability token.', 403);
  }
  const origin = target.origin.toLowerCase();
  const path = target.pathname;

  const verification = await verifyCapabilityToken(token, {
    secret: o.capabilityTokenSecret!,
    now: Math.floor(nowSec),
    skewSeconds: o.capabilityTokenSkewSeconds ?? 30,
    requireCapability: o.requiredCapability,
    requireOrigin: origin,
    requirePath: path,
  });

  if (!verification.valid) {
    const reason = verification.reason;
    if (reason === 'expired' || reason === 'not-yet-valid') {
      throw new VerificationError(VerificationErrorCode.TokenExpired, 'Capability token expired or not yet valid.', 401);
    }
    if (reason === 'scope-capability' || reason === 'scope-origin' || reason === 'scope-path') {
      throw new VerificationError(VerificationErrorCode.TokenScopeDenied, `Capability token scope denied (${reason}).`, 403);
    }
    throw new VerificationError(VerificationErrorCode.TokenInvalid, 'Capability token invalid.', 403);
  }

  const claims = verification.claims!;

  // Optional single-use jti replay protection.
  if (claims.jti && o.capabilityTokenStore) {
    const expiresAtMs = claims.exp * 1000;
    if (!(await o.capabilityTokenStore.checkAndSet(claims.jti, expiresAtMs))) {
      throw new VerificationError(VerificationErrorCode.TokenReplayed, 'Capability token has already been used.', 401);
    }
  }

  return {
    verified: true,
    domain: essentials.host.split(':')[0]!.toLowerCase(),
    identityUrl: claims.iss ?? `https://${essentials.host}/`,
    keyId: claims.jti ?? 'capability-token',
    algorithm: 'HS256',
    verifiedAt: new Date().toISOString(),
    manifest: null,
    callerPolicy: null,
    usedLocalAllowlist: false,
    authMethod: 'capability-token',
  };
}

/** Format the response-side manifest header for echoing back to the caller. */
export function formatResponseManifestHeader(manifest: NonNullable<VerificationResult['manifest']>): string {
  return formatManifestHeader({
    url: manifest.url,
    sha256: manifest.sha256,
    caps: manifest.caps,
  });
}
