/**
 * Codecs for the compact X-Agent-* HTTP headers.
 *
 *   X-Agent-Identity: https://caller.example/.well-known/agent-identity.json
 *
 *   X-Agent-Manifest: url="https://caller.example/agent-manifest.json";
 *                     sha256="<hex>"; caps="search,quote"
 *
 *   X-Agent-Signature: keyid="<kid>"; alg="ed25519";
 *                      created="<unix_sec>"; nonce="<uuid_or_hex>";
 *                      sig="<base64url>"
 *
 * Response:
 *   X-Verified-Agent: <caller-domain>
 *   X-Agent-Manifest: <echo of the caller's verified manifest>
 *   Access-Control-Expose-Headers: X-Agent-Identity, X-Agent-Manifest,
 *                                  X-Verified-Agent
 *
 * Structured values use a lightweight `key="value"; key2="value2"`
 * parameter list (similar to Cache-Control). Parsing is tolerant of
 * whitespace, quoting, and ordering.
 */

export const HEADER_IDENTITY = 'X-Agent-Identity';
export const HEADER_MANIFEST = 'X-Agent-Manifest';
export const HEADER_SIGNATURE = 'X-Agent-Signature';
export const HEADER_VERIFIED_AGENT = 'X-Verified-Agent';
export const HEADER_EXPOSE = 'Access-Control-Expose-Headers';

export const EXPOSE_HEADERS_VALUE = `${HEADER_IDENTITY}, ${HEADER_MANIFEST}, ${HEADER_VERIFIED_AGENT}`;

function escapeParam(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/** Format a parameter list as `k="v"; k2="v2"`. Keys are lowercased. */
export function formatHeaderParams(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${k.toLowerCase()}="${escapeParam(String(v))}"`)
    .join('; ');
}

/**
 * Parse a structured parameter list. Accepts both quoted values and bare
 * tokens. Returns insertion-ordered keys (lowercased).
 */
export function parseHeaderParams(header: string | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  const re = /([A-Za-z0-9_.-]+)\s*=\s*(?:"((?:\\.|[^"])*)"|([^;\s]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(header)) !== null) {
    const key = m[1]!.toLowerCase();
    const value = m[2] !== undefined ? m[2] : m[3]!;
    // Unescape quoted value.
    out[key] = value.replace(/\\(["\\])/g, '$1');
  }
  return out;
}

/** --- X-Agent-Identity -------------------------------------------------- */

/** The identity header is simply the absolute https URL of the identity document. */
export function formatIdentityHeader(identityUrl: string): string {
  return identityUrl.trim();
}

export function parseIdentityHeader(header: string | undefined | null): string {
  const value = (header ?? '').trim();
  // Reject anything with parameters — the identity header is a bare URL.
  if (value.includes(';')) return '';
  return value;
}

/** --- X-Agent-Manifest --------------------------------------------------- */

export interface ManifestHeaderParams {
  url: string;
  sha256?: string;
  caps?: string[];
}

export function formatManifestHeader(params: ManifestHeaderParams): string {
  const entries: Record<string, string> = { url: params.url };
  if (params.sha256) entries.sha256 = params.sha256;
  if (params.caps && params.caps.length) entries.caps = params.caps.join(',');
  return formatHeaderParams(entries);
}

export function parseManifestHeader(header: string | undefined | null): ManifestHeaderParams {
  const params = parseHeaderParams(header);
  const url = params['url'] ?? '';
  const caps = params['caps'] ? params['caps'].split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  const result: ManifestHeaderParams = { url };
  if (params['sha256']) result.sha256 = params['sha256'];
  if (caps && caps.length) result.caps = caps;
  return result;
}

/** --- X-Agent-Signature ------------------------------------------------ */

export interface SignatureHeaderParams {
  keyid: string;
  alg: string;
  created: string;
  nonce: string;
  sig: string;
  /** Optional extra params (e.g. `cnonce`, `ext`). */
  extra?: Record<string, string>;
}

export function formatSignatureHeader(params: SignatureHeaderParams): string {
  const entries: Record<string, string> = {
    keyid: params.keyid,
    alg: params.alg,
    created: String(params.created),
    nonce: params.nonce,
    sig: params.sig,
  };
  if (params.extra) {
    for (const [k, v] of Object.entries(params.extra)) entries[k] = v;
  }
  return formatHeaderParams(entries);
}

export function parseSignatureHeader(header: string | undefined | null): SignatureHeaderParams | null {
  if (!header) return null;
  const params = parseHeaderParams(header);
  const keyid = params['keyid'];
  const alg = params['alg'];
  const created = params['created'];
  const nonce = params['nonce'];
  const sig = params['sig'];
  if (!keyid || !alg || !created || !nonce || !sig) return null;
  const { keyid: _k, alg: _a, created: _c, nonce: _n, sig: _s, ...extra } = params;
  return { keyid, alg, created, nonce, sig, extra };
}

/** --- X-Verified-Agent (response) -------------------------------------- */

export function formatVerifiedAgentHeader(domain: string): string {
  return domain.trim();
}

export function parseVerifiedAgentHeader(header: string | undefined | null): string {
  return (header ?? '').trim();
}
