/**
 * `probe` — inspect a live agent endpoint.
 *
 * Steps:
 *   1. fetch the site's identity document from `/.well-known/agent-identity.json`
 *   2. fetch and validate its manifest
 *   3. send an unauthenticated request (does the endpoint enforce?)
 *   4. send a signed request with an ephemeral dev key (does the verifier
 *      reject it with a meaningful code?)
 *   5. optionally perform a real signed call with --identity-url/--key-file
 */
import { readFile } from 'node:fs/promises';
import {
  buildCanonicalPayload,
  formatSignatureHeader,
  generateKeyPair,
  generateNonce,
  importPrivateKeyFromJwk,
  parseVerifiedAgentHeader,
  signCanonical,
  thumbprintOfJwk,
  unixNowSeconds,
  validateIdentityDocument,
  validateManifest,
} from '@tls-agent-gate/core';

export interface ProbeOptions {
  url: string;
  timeoutMs?: number;
  identityUrl?: string;
  keyFile?: string;
  json?: boolean;
}

export interface ProbeFinding {
  identityUrl: string;
  identityValid: boolean;
  identityErrors: string[];
  manifestUrl: string | null;
  manifestValid: boolean | null;
  manifestErrors: string[];
  unauthStatus: number;
  signedStatus: number;
  signedResponseCode: string | null;
  verifiedDomain: string | null;
  enforcement: 'verified' | 'rejects-signed' | 'not-enforced' | 'error';
  /** Set when the optional --key-file/--identity-url real call errors. */
  realCallError?: string | null;
}

async function fetchText(url: string, timeoutMs: number): Promise<{ status: number; text: string; headers: Headers }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
  const text = await res.text();
  return { status: res.status, text, headers: res.headers };
}

function parseErrorCode(text: string): string | null {
  try {
    const json = JSON.parse(text) as { error?: { code?: string } };
    return json.error?.code ?? null;
  } catch {
    return null;
  }
}

export async function probe(opts: ProbeOptions): Promise<ProbeFinding> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const origin = new URL(opts.url).origin;
  const identityUrl = `${origin}/.well-known/agent-identity.json`;

  // 1. Identity document.
  const identityFetch = await fetchText(identityUrl, timeoutMs);
  let identityValid = false;
  let identityErrors: string[] = [];
  let manifestUrl: string | null = null;
  if (identityFetch.status === 200) {
    try {
      const parsed = JSON.parse(identityFetch.text) as { manifestUrl?: string };
      const result = validateIdentityDocument(parsed);
      identityValid = result.valid;
      identityErrors = result.errors.map((e) => (e.path ? `${e.path}: ${e.message}` : e.message));
      manifestUrl = parsed.manifestUrl ?? null;
    } catch {
      identityErrors = ['Identity document is not valid JSON'];
    }
  } else {
    identityErrors = [`HTTP ${identityFetch.status} fetching identity document`];
  }

  // 2. Manifest.
  let manifestValid: boolean | null = null;
  let manifestErrors: string[] = [];
  if (manifestUrl) {
    try {
      const manifestFetch = await fetchText(manifestUrl, timeoutMs);
      if (manifestFetch.status === 200) {
        const result = validateManifest(JSON.parse(manifestFetch.text));
        manifestValid = result.valid;
        manifestErrors = result.errors.map((e) => (e.path ? `${e.path}: ${e.message}` : e.message));
      } else {
        manifestErrors = [`HTTP ${manifestFetch.status} fetching manifest`];
      }
    } catch (err) {
      manifestErrors = [`Manifest fetch failed: ${err instanceof Error ? err.message : String(err)}`];
    }
  }

  // 3. Unauthenticated probe.
  let unauthStatus = 0;
  try {
    unauthStatus = (await fetchText(opts.url, timeoutMs)).status;
  } catch {
    unauthStatus = 0;
  }

  // 4. Signed probe with an ephemeral dev key.
  let signedStatus = 0;
  let signedResponseCode: string | null = null;
  let verifiedDomain: string | null = null;
  try {
    const keyPair = await generateKeyPair('Ed25519');
    const target = new URL(opts.url);
    const created = unixNowSeconds();
    const nonce = generateNonce();
    const canonical = buildCanonicalPayload({
      method: 'GET',
      urlPathAndQuery: `${target.pathname}${target.search}`,
      host: target.host.toLowerCase(),
      created,
      nonce,
      bodySha256: '',
      manifestSha256: '',
    });
    const privateKey = await importPrivateKeyFromJwk(keyPair.privateKeyJwk);
    const sig = await signCanonical(privateKey, canonical);
    const identityForProbe = opts.identityUrl ?? 'https://probe.tls-agent-gate.invalid/.well-known/agent-identity.json';
    const res = await fetch(opts.url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        'x-agent-identity': identityForProbe,
        'x-agent-signature': formatSignatureHeader({
          keyid: keyPair.kid,
          alg: 'ed25519',
          created: String(created),
          nonce,
          sig,
        }),
      },
    });
    signedStatus = res.status;
    const text = await res.text();
    signedResponseCode = parseErrorCode(text);
    verifiedDomain = parseVerifiedAgentHeader(res.headers.get('x-verified-agent') ?? '') || null;
  } catch {
    signedStatus = 0;
  }

  // 5. Optional real signed call (requires matching key + deployed identity).
  let enforcement: ProbeFinding['enforcement'] = 'not-enforced';
  if (verifiedDomain) enforcement = 'verified';
  else if (signedStatus >= 400 || signedResponseCode) enforcement = 'rejects-signed';
  else if (signedStatus === 200) enforcement = 'not-enforced';
  else enforcement = 'error';

  const finding: ProbeFinding = {
    identityUrl,
    identityValid,
    identityErrors,
    manifestUrl,
    manifestValid,
    manifestErrors,
    unauthStatus,
    signedStatus,
    signedResponseCode,
    verifiedDomain,
    enforcement,
  };
  finding.realCallError = null;

  if (opts.keyFile && opts.identityUrl) {
    try {
      const keyRaw = await readFile(opts.keyFile, 'utf8');
      const jwk = JSON.parse(keyRaw) as JsonWebKey;
      const pairKid =
        (jwk as { kid?: string }).kid ??
        (await thumbprintOfJwk({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey));
      const pair = {
        privateKeyJwk: jwk,
        kid: pairKid,
        alg: jwk.crv === 'P-256' ? ('ES256' as const) : ('Ed25519' as const),
      };
      const target = new URL(opts.url);
      const created = unixNowSeconds();
      const nonce = generateNonce();
      const canonical = buildCanonicalPayload({
        method: 'GET',
        urlPathAndQuery: `${target.pathname}${target.search}`,
        host: target.host.toLowerCase(),
        created,
        nonce,
        bodySha256: '',
        manifestSha256: '',
      });
      const privateKey = await importPrivateKeyFromJwk(jwk);
      const sig = await signCanonical(privateKey, canonical);
      const realRes = await fetch(opts.url, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          'x-agent-identity': opts.identityUrl,
          'x-agent-signature': formatSignatureHeader({
            keyid: pair.kid,
            alg: pair.alg === 'ES256' ? 'es256' : 'ed25519',
            created: String(created),
            nonce,
            sig,
          }),
        },
      });
      const realDomain = parseVerifiedAgentHeader(realRes.headers.get('x-verified-agent') ?? '') || null;
      if (realDomain) {
        verifiedDomain = realDomain;
        enforcement = 'verified';
      } else {
        const body = await realRes.text();
        const code = parseErrorCode(body);
        if (code) signedResponseCode = code;
      }
    } catch (err) {
      finding.realCallError = err instanceof Error ? err.message : String(err);
    }
  }

  // The optional real call may have updated the local variables after
  // `finding` was snapshotted — reconcile them.
  finding.verifiedDomain = verifiedDomain;
  finding.enforcement = enforcement;
  if (signedResponseCode) finding.signedResponseCode = signedResponseCode;

  return finding;
}

export function renderProbe(finding: ProbeFinding): string {
  const lines: string[] = [];
  lines.push(`Identity document : ${finding.identityUrl}`);
  lines.push(`  valid          : ${finding.identityValid ? 'yes' : 'NO'}`);
  for (const e of finding.identityErrors.slice(0, 5)) lines.push(`    - ${e}`);
  if (finding.manifestUrl) {
    lines.push(`Manifest         : ${finding.manifestUrl}`);
    lines.push(`  valid          : ${finding.manifestValid === null ? 'unknown' : finding.manifestValid ? 'yes' : 'NO'}`);
    for (const e of finding.manifestErrors.slice(0, 5)) lines.push(`    - ${e}`);
  }
  lines.push(`Unauthenticated probe -> HTTP ${finding.unauthStatus || 'ERR'}`);
  lines.push(`Signed probe           -> HTTP ${finding.signedStatus || 'ERR'}${finding.signedResponseCode ? ` (${finding.signedResponseCode})` : ''}`);
  if (finding.verifiedDomain) lines.push(`X-Verified-Agent      -> ${finding.verifiedDomain}`);
  if (finding.realCallError) lines.push(`Real call error        -> ${finding.realCallError}`);
  lines.push(`Enforcement            -> ${finding.enforcement}`);
  return lines.join('\n');
}
