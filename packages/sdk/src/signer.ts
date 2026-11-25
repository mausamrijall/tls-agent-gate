/**
 * Identity signer abstraction.
 *
 * The SDK never touches private keys directly — an `AgentRequestSigner` is
 * injected (either the browser `AgentRuntime` or a core-based signer). It
 * returns the `X-Agent-Identity` / `X-Agent-Manifest` /
 * `X-Agent-Signature` headers for an outbound request.
 */
import {
  buildCanonicalPayload,
  formatManifestHeader,
  formatSignatureHeader,
  generateNonce,
  importPrivateKeyFromJwk,
  sha256Hex,
  signCanonical,
  thumbprintOfJwk,
  unixNowSeconds,
  utf8Encode,
  type KeyAlgorithm,
} from '@tls-agent-gate/core';

export interface OutboundRequest {
  url: string;
  method: string;
  body?: string | Uint8Array | null;
}

export interface AgentRequestSigner {
  readonly identityUrl: string;
  readonly keyId: string;
  readonly algorithm: string;
  /** Manifest SHA-256 the signer will advertise (optional). */
  readonly manifestSha256?: string;
  /** Return headers to attach to the outbound request. */
  sign(req: OutboundRequest): Promise<Record<string, string>>;
}

export interface CoreSignerOptions {
  identityUrl: string;
  manifestUrl: string;
  privateKeyJwk: JsonWebKey;
  algorithm?: KeyAlgorithm;
  /** Exact manifest bytes served at manifestUrl (used for the SHA-256). */
  manifestText?: string;
  /** Explicit manifest SHA-256 (overrides manifestText). */
  manifestSha256?: string;
}

/** Build a signer directly from core WebCrypto primitives (Node/browser). */
export async function createCoreSigner(opts: CoreSignerOptions): Promise<AgentRequestSigner> {
  const algorithm = opts.algorithm ?? 'Ed25519';
  const privateKey = await importPrivateKeyFromJwk(opts.privateKeyJwk);

  const prk = opts.privateKeyJwk as { kid?: string; kty?: string; crv?: string; x?: string; y?: string };
  const keyId =
    prk.kid ??
    (await thumbprintOfJwk({ kty: prk.kty, crv: prk.crv, x: prk.x, y: prk.y } as JsonWebKey));

  const manifestSha256 =
    opts.manifestSha256 ??
    (opts.manifestText !== undefined ? await sha256Hex(opts.manifestText) : '');

  return {
    identityUrl: opts.identityUrl,
    keyId,
    algorithm,
    async sign(req: OutboundRequest): Promise<Record<string, string>> {
      const target = new URL(req.url);
      const bodyBytes = typeof req.body === 'string' ? utf8Encode(req.body) : req.body ?? new Uint8Array();
      const bodySha256 = bodyBytes.byteLength > 0 ? await sha256Hex(bodyBytes) : '';
      const created = unixNowSeconds();
      const nonce = generateNonce();
      const canonical = buildCanonicalPayload({
        method: req.method,
        urlPathAndQuery: `${target.pathname}${target.search}`,
        host: target.host.toLowerCase(),
        created,
        nonce,
        bodySha256,
        manifestSha256: manifestSha256 || '',
      });
      const signature = await signCanonical(privateKey, canonical);
      const headers: Record<string, string> = {
        'X-Agent-Identity': opts.identityUrl,
        'X-Agent-Signature': formatSignatureHeader({
          keyid: keyId,
          alg: algorithm === 'ES256' ? 'es256' : 'ed25519',
          created: String(created),
          nonce,
          sig: signature,
        }),
      };
      if (manifestSha256) {
        headers['X-Agent-Manifest'] = formatManifestHeader({
          url: opts.manifestUrl,
          sha256: manifestSha256,
        });
      }
      return headers;
    },
  };
}
