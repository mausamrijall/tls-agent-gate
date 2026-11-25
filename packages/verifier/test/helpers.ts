/**
 * Test harness: builds fake agents (identity docs + manifest) and signed
 * requests without any network I/O.
 */
import {
  buildCanonicalPayload,
  formatManifestHeader,
  formatSignatureHeader,
  generateKeyPair,
  generateNonce,
  importPrivateKeyFromJwk,
  sha256Hex,
  signCanonical,
  unixNowSeconds,
  type AgentIdentityDocument,
  type AgentKeyPair,
} from '@tls-agent-gate/core';
import type { VerifierRequest, FetchImpl } from '../src/types.ts';

export interface FakeAgent {
  domain: string;
  keyPair: AgentKeyPair;
  doc: AgentIdentityDocument;
  docUrl: string;
  manifestUrl: string;
  manifestText: string;
}

export async function makeFakeAgent(
  opts: { domain?: string; alg?: 'Ed25519' | 'ES256'; subjectOverride?: string } = {},
): Promise<FakeAgent> {
  const domain = opts.domain ?? 'caller.example';
  const keyPair = await generateKeyPair(opts.alg ?? 'Ed25519');
  const docUrl = `https://${domain}/.well-known/agent-identity.json`;
  const manifestUrl = `https://${domain}/agent-manifest.json`;
  const doc: AgentIdentityDocument = {
    schemaVersion: 'agent-identity-v1',
    subject: opts.subjectOverride ?? `https://${domain}/agent`,
    createdAt: '2026-01-01T00:00:00Z',
    manifestUrl,
    keys: {
      primary: { alg: keyPair.alg, kid: keyPair.kid, publicKeyJwk: keyPair.publicKeyJwk },
    },
    policy: { requireSignedRequests: true, allowLocalAgents: false },
  };
  const manifestText = JSON.stringify({
    schemaVersion: 'agent-manifest-v1',
    agent: `https://${domain}/agent`,
    name: 'Caller Agent',
    description: 'Test caller',
    version: '1.0.0',
    capabilities: [{ id: 'search', name: 'Search', description: 'Search the web' }],
  });
  return { domain, keyPair, doc, docUrl, manifestUrl, manifestText };
}

export interface BuildRequestOptions {
  method?: string;
  url?: string;
  host?: string;
  body?: Uint8Array | string;
  created?: number;
  nonce?: string;
  manifestSha256?: string;
  manifestCaps?: string[];
  keyId?: string;
  /** Override the signing key (e.g. for negative tests). Defaults to agent.keyPair. */
  signingKey?: AgentKeyPair;
}

export async function buildSignedRequest(
  agent: FakeAgent,
  opts: BuildRequestOptions = {},
): Promise<VerifierRequest> {
  const method = (opts.method ?? 'GET').toUpperCase();
  const url = opts.url ?? `https://${agent.domain}/api/search?q=agents`;
  const host = opts.host ?? new URL(url).host.toLowerCase();
  const body = opts.body ?? new Uint8Array();
  // Canonical rule: no body / zero-length body signs an empty bodySha256.
  const bodyLength = body instanceof Uint8Array ? body.byteLength : String(body).length;
  const bodySha256 = bodyLength > 0 ? await sha256Hex(body) : '';
  const manifestSha256 = opts.manifestSha256 ?? '';
  const created = opts.created ?? unixNowSeconds();
  const nonce = opts.nonce ?? generateNonce();

  const target = new URL(url, `https://${host}`);
  const canonical = buildCanonicalPayload({
    method,
    urlPathAndQuery: `${target.pathname}${target.search}`,
    host,
    created,
    nonce,
    bodySha256,
    manifestSha256,
  });

  const signingKey = opts.signingKey ?? agent.keyPair;
  const privateKey = await importPrivateKeyFromJwk(signingKey.privateKeyJwk);
  const sig = await signCanonical(privateKey, canonical);

  const headers: Record<string, string> = {
    host,
    'x-agent-identity': agent.docUrl,
    'x-agent-signature': formatSignatureHeader({
      keyid: opts.keyId ?? agent.keyPair.kid,
      alg: signingKey.alg === 'Ed25519' ? 'ed25519' : 'es256',
      created: String(created),
      nonce,
      sig,
    }),
  };
  if (manifestSha256 || opts.manifestCaps) {
    headers['x-agent-manifest'] = formatManifestHeader({
      url: agent.manifestUrl,
      sha256: manifestSha256 || undefined,
      caps: opts.manifestCaps,
    });
  }
  return { method, url, headers, body };
}

/** Build a fetch implementation that routes known URLs to canned text. */
export function makeRoutesFetch(routes: Record<string, { status?: number; contentType?: string; body: string }>): FetchImpl {
  return async (url: string) => {
    const route = routes[url];
    if (!route) return new Response('not found', { status: 404 });
    return new Response(route.body, {
      status: route.status ?? 200,
      headers: { 'content-type': route.contentType ?? 'application/json' },
    });
  };
}

export function assertThrowsCode(promise: Promise<unknown>, code: string): Promise<void> {
  return promise.then(
    () => {
      throw new Error(`Expected VerificationError ${code}`);
    },
    (err: unknown) => {
      const e = err as { code?: string };
      if (e.code !== code) throw new Error(`Expected code ${code}, got ${e.code}`);
    },
  );
}
