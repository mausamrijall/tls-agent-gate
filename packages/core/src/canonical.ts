/**
 * Canonical signing payload.
 *
 * Both the caller (browser/worker signer) and the verifier (edge/server)
 * must sign the exact same bytes. We define a single deterministic,
 * newline-joined string:
 *
 *   agent-tls-gate-signature-v1
 *   <METHOD>
 *   <url_path_and_query>
 *   <host>
 *   <created>            (Unix seconds as a decimal string)
 *   <nonce>
 *   <body_sha256>       (lowercase hex; empty when there is no body)
 *   <manifest_sha256>   (lowercase hex; empty when not provided)
 *
 * Rule: the leading version line is constant. Values are raw (not
 * escaped); fields after the version are emitted in fixed order, one per
 * line. The UTF-8 encoding of this string is what gets signed.
 */
import { utf8Encode } from './encoding.ts';

export const CANONICAL_VERSION = 'agent-tls-gate-signature-v1';

export interface CanonicalParts {
  /** HTTP method (case-insensitive; normalized to uppercase). */
  method: string;
  /** Path and query, e.g. `/api/search?q=x`. No fragment. */
  urlPathAndQuery: string;
  /** Host header value (normalized to lowercase). */
  host: string;
  /** Unix seconds as a string or number. */
  created: string | number;
  /** One-time nonce. */
  nonce: string;
  /** Lowercase hex SHA-256 of the request body; '' when empty. */
  bodySha256: string;
  /** Lowercase hex SHA-256 of the agent manifest; '' when absent. */
  manifestSha256: string;
}

/** Build the exact canonical string to sign/verify. */
export function buildCanonicalPayload(parts: CanonicalParts): string {
  const created = String(parts.created);
  return [
    CANONICAL_VERSION,
    parts.method.toUpperCase(),
    parts.urlPathAndQuery.replace(/^\s+|\s+$/g, ''),
    parts.host.toLowerCase().trim(),
    created,
    parts.nonce,
    parts.bodySha256 || '',
    parts.manifestSha256 || '',
  ].join('\n');
}

/** Length of the canonical payload for diagnostic/logging purposes. */
export function canonicalPayloadLength(parts: CanonicalParts): number {
  return utf8Encode(buildCanonicalPayload(parts)).length;
}
