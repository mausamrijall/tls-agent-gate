#!/usr/bin/env node
/**
 * Live beta test for the tls-agent-gate demo sites.
 *
 * Starts the active requester (Site B) and the passive capability provider
 * (Site A), then runs a battery of REAL HTTP-level beta checks:
 *
 *   1. Public OAW assets on Site B (manifest / identity / runtime.js)
 *   2. Provider identity + declared capabilities
 *   3. Unsigned call → 401
 *   4. Spoofed identity (unreachable issuer) → 502
 *   5. Signed search + status → 200 + X-Verified-Agent + CORS expose headers
 *   6. Fresh nonce per request (two calls, distinct nonces)
 *   7. Replayed identical signed request → 401 ERR_REPLAYED_NONCE
 *   8. Expired timestamp → 401 ERR_EXPIRED
 *   9. Tampered body → 403 ERR_SIGNATURE_INVALID
 *  10. Capability-token mode (provider started with CAPABILITY_TOKEN_SECRET):
 *      valid scoped token → 200 + X-Verified-Agent; scope violation → 403;
 *      wrong secret → 403
 *  11. Provider audit trail contains executed capability events
 *
 * Usage: `npm run beta` (from the repo root). Requires `npm run build` first.
 */
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildCanonicalPayload,
  formatSignatureHeader,
  generateNonce,
  importPrivateKeyFromJwk,
  issueCapabilityToken,
  sha256Hex,
  signCanonical,
  thumbprintOfJwk,
  unixNowSeconds,
} from '@tls-agent-gate/core';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const REQ_DIR = join(ROOT, 'examples', 'site-b-requester');
const PROV_DIR = join(ROOT, 'examples', 'site-a-provider');
const TOKEN_SECRET = 'beta-token-secret';
const BASE_REQ = 'http://localhost:4174';
const BASE_PROV = 'http://localhost:4173';

let passes = 0;
let fails = 0;
function ok(name, cond, extra = '') {
  if (cond) {
    passes++;
    console.log(`  ✔ ${name}${extra ? ` — ${extra}` : ''}`);
  } else {
    fails++;
    console.log(`  ✖ ${name}${extra ? ` — ${extra}` : ''}`);
  }
}

async function get(url, headers = {}) {
  const res = await fetch(url, { headers });
  const text = await res.text().catch(() => '');
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* not json */
  }
  return { res, text, json };
}

async function waitFor(url, ms = 15000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(1500) });
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

// ---- signed-request helpers (deterministic knobs for negative tests) ----
async function signedHeaders(keyHolder, keyId, { url, method = 'GET', created = unixNowSeconds(), nonce, bodySha256 = '', manifestSha256 = '' }) {
  const target = new URL(url);
  const nonceFinal = nonce ?? generateNonce();
  const canonical = buildCanonicalPayload({
    method,
    urlPathAndQuery: `${target.pathname}${target.search}`,
    host: target.host.toLowerCase(),
    created,
    nonce: nonceFinal,
    bodySha256,
    manifestSha256,
  });
  const priv = await importPrivateKeyFromJwk(keyHolder.privateKeyJwk);
  const sig = await signCanonical(priv, canonical);
  return {
    'X-Agent-Identity': 'http://localhost:4174/.well-known/agent-identity.json',
    'X-Agent-Signature': formatSignatureHeader({ keyid: keyId, alg: 'ed25519', created: String(created), nonce: nonceFinal, sig }),
  };
}

const children = [];
function startServer(dir, port, extraEnv = {}) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: dir,
    env: { ...process.env, PORT: String(port), ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', () => {});
  child.stderr.on('data', () => {});
  children.push(child);
  return child;
}

function cleanup() {
  for (const child of children) {
    try {
      child.kill('SIGTERM');
    } catch {
      /* already gone */
    }
  }
}

process.on('exit', cleanup);

console.log('tls-agent-gate — live beta test');
console.log('────────────────────────────────────────────────────────');

try {
  // Use Site B's real dev key (the provider allowlists its thumbprint).
  const requesterKeyRaw = await readFile(join(REQ_DIR, 'public', 'keys', 'agent.key.jwk.json'), 'utf8');
  const requesterKey = JSON.parse(requesterKeyRaw);
  const keyId = await thumbprintOfJwk({ kty: requesterKey.kty, crv: requesterKey.crv, x: requesterKey.x });
  const keyHolder = { privateKeyJwk: requesterKey };

  console.log('\n[setup] starting Site B (requester) on :4174 …');
  startServer(REQ_DIR, 4174);
  if (!(await waitFor(`${BASE_REQ}/agent-manifest.json`))) throw new Error('Site B did not come up');

  console.log('[setup] starting Site A (provider, token mode ON) on :4173 …');
  startServer(PROV_DIR, 4173, { CAPABILITY_TOKEN_SECRET: TOKEN_SECRET });
  if (!(await waitFor(`${BASE_PROV}/agent-manifest.json`))) throw new Error('Site A did not come up');

  // ---- 1. Requester public OAW assets ----------------------------------
  console.log('\n[1] Site B — Open Agentic Web public assets');
  const reqManifest = await get(`${BASE_REQ}/agent-manifest.json`);
  ok('manifest served (200)', reqManifest.res.status === 200);
  ok('manifest conforms (schemaVersion + capabilities)', reqManifest.json?.schemaVersion === 'agent-manifest-v1' && Array.isArray(reqManifest.json?.capabilities));
  const reqIdentity = await get(`${BASE_REQ}/.well-known/agent-identity.json`);
  ok('identity served (200)', reqIdentity.res.status === 200);
  ok('identity has primary Ed25519 key', reqIdentity.json?.keys?.primary?.alg === 'Ed25519');
  const runtime = await get(`${BASE_REQ}/runtime.js`);
  ok('browser runtime file served (200)', runtime.res.status === 200);

  // ---- 2. Provider identity + capabilities ------------------------------
  console.log('\n[2] Site A — provider identity & declared capabilities');
  const provManifest = await get(`${BASE_PROV}/agent-manifest.json`);
  ok('provider manifest served (200)', provManifest.res.status === 200);
  const caps = provManifest.json?.capabilities?.map((c) => c.id) ?? [];
  ok('declares search + status capabilities', caps.includes('search') && caps.includes('status'), caps.join(','));

  // ---- 3. Unsigned -----------------------------------------------
  console.log('\n[3] unsigned requester → provider');
  const unsignedRes = await fetch(`${BASE_PROV}/api/agent/search?q=x`, { signal: AbortSignal.timeout(5000) });
  const unsignedBody = await unsignedRes.text();
  ok('rejected with 401', unsignedRes.status === 401, `HTTP ${unsignedRes.status}`);
  ok('reason ERR_MISSING_IDENTITY_HEADER', unsignedBody.includes('ERR_MISSING_IDENTITY_HEADER'));

  // ---- 4. Spoofed identity ---------------------------------------
  console.log('\n[4] spoofed identity (unreachable issuer)');
  const spoof = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}/api/agent/search?q=x` });
  const spoofRes = await fetch(`${BASE_PROV}/api/agent/search?q=x`, { headers: { ...spoof, 'X-Agent-Identity': 'http://localhost:9/.well-known/agent-identity.json' }, signal: AbortSignal.timeout(5000) });
  const spoofBody = await spoofRes.text();
  ok('rejected with 502 (identity fetch failure)', spoofRes.status === 502, `HTTP ${spoofRes.status}`);
  ok('reason ERR_IDENTITY_FETCH', spoofBody.includes('ERR_IDENTITY_FETCH'));

  // ---- 5. Signed search + status ----------------------------------
  console.log('\n[5] signed capability calls (search + status)');
  for (const path of ['/api/agent/search?q=beta', '/api/agent/status']) {
    const headers = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}${path}` });
    const r = await fetch(`${BASE_PROV}${path}`, { headers, signal: AbortSignal.timeout(5000) });
    const body = await r.text();
    ok(`signed ${path.split('?')[0]} → 200`, r.status === 200, `HTTP ${r.status}`);
    ok('   X-Verified-Agent present', (r.headers.get('x-verified-agent') ?? '') !== '');
    ok('   CORS expose headers include the agent trio', (r.headers.get('access-control-expose-headers') ?? '').includes('X-Agent-Identity') && (r.headers.get('access-control-expose-headers') ?? '').includes('X-Verified-Agent'));
    void body;
  }

  // ---- 6. Fresh nonce per request ---------------------------------
  console.log('\n[6] per-request freshness (distinct nonces)');
  const h1 = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}/api/agent/search?q=a` });
  const h2 = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}/api/agent/search?q=b` });
  const nonce1 = h1['X-Agent-Signature'].match(/nonce="([^"]+)"/)?.[1];
  const nonce2 = h2['X-Agent-Signature'].match(/nonce="([^"]+)"/)?.[1];
  ok('nonces differ between consecutive requests', nonce1 && nonce2 && nonce1 !== nonce2);

  // ---- 7. Replay --------------------------------------------------
  console.log('\n[7] replay of an identical signed request');
  const replayNonce = generateNonce();
  const replayHeaders = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}/api/agent/search?q=replay`, nonce: replayNonce });
  const replay1 = await fetch(`${BASE_PROV}/api/agent/search?q=replay`, { headers: replayHeaders, signal: AbortSignal.timeout(5000) });
  const replay2 = await fetch(`${BASE_PROV}/api/agent/search?q=replay`, { headers: replayHeaders, signal: AbortSignal.timeout(5000) });
  const replayBody2 = await replay2.text();
  ok('first use accepted (200)', replay1.status === 200, `HTTP ${replay1.status}`);
  ok('second use rejected (401 replay)', replay2.status === 401 && replayBody2.includes('ERR_REPLAYED_NONCE'), `HTTP ${replay2.status}`);

  // ---- 8. Expired timestamp ---------------------------------------
  console.log('\n[8] expired signature timestamp');
  const expiredHeaders = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}/api/agent/search?q=x`, created: unixNowSeconds() - 300 });
  const expiredRes = await fetch(`${BASE_PROV}/api/agent/search?q=x`, { headers: expiredHeaders, signal: AbortSignal.timeout(5000) });
  const expiredBody = await expiredRes.text();
  ok('rejected with 401 ERR_EXPIRED', expiredRes.status === 401 && expiredBody.includes('ERR_EXPIRED'), `HTTP ${expiredRes.status}`);

  // ---- 9. Tampered body -------------------------------------------
  console.log('\n[9] tampered body');
  const tamperNonce = generateNonce();
  const tamperHeaders = await signedHeaders(keyHolder, keyId, { url: `${BASE_PROV}/api/agent/search`, method: 'POST', nonce: tamperNonce, bodySha256: await sha256Hex('hello') });
  const tamperRes = await fetch(`${BASE_PROV}/api/agent/search`, { method: 'POST', body: 'evil', headers: tamperHeaders, signal: AbortSignal.timeout(5000) });
  const tamperBody = await tamperRes.text();
  ok('rejected with 403 ERR_SIGNATURE_INVALID', tamperRes.status === 403 && tamperBody.includes('ERR_SIGNATURE_INVALID'), `HTTP ${tamperRes.status}`);

  // ---- 10. Capability-token mode ----------------------------------
  console.log('\n[10] capability-token mode (non-WAF fallback)');
  const goodToken = await issueCapabilityToken(
    { cap: ['search'], origins: [BASE_PROV], paths: ['/api/agent/search'] },
    { secret: TOKEN_SECRET, ttlSeconds: 60 },
  );
  const tokenOk = await fetch(`${BASE_PROV}/api/agent/search?q=token`, { headers: { 'X-Agent-Token': goodToken }, signal: AbortSignal.timeout(5000) });
  ok('valid scoped token → 200', tokenOk.status === 200, `HTTP ${tokenOk.status}`);
  ok('   X-Verified-Agent present', (tokenOk.headers.get('x-verified-agent') ?? '') !== '');

  const badScopeToken = await issueCapabilityToken(
    { cap: ['search'], origins: ['https://evil.invalid'], paths: ['/api/agent/search'] },
    { secret: TOKEN_SECRET, ttlSeconds: 60 },
  );
  const tokenScope = await fetch(`${BASE_PROV}/api/agent/search?q=token`, { headers: { 'X-Agent-Token': badScopeToken }, signal: AbortSignal.timeout(5000) });
  const tokenScopeBody = await tokenScope.text();
  ok('scope violation → 403 ERR_TOKEN_SCOPE_DENIED', tokenScope.status === 403 && tokenScopeBody.includes('ERR_TOKEN_SCOPE_DENIED'), `HTTP ${tokenScope.status}`);

  const wrongSecretToken = await issueCapabilityToken({ cap: ['search'], origins: [BASE_PROV], paths: ['/api/agent/search'] }, { secret: 'wrong', ttlSeconds: 60 });
  const tokenBad = await fetch(`${BASE_PROV}/api/agent/search?q=token`, { headers: { 'X-Agent-Token': wrongSecretToken }, signal: AbortSignal.timeout(5000) });
  const tokenBadBody = await tokenBad.text();
  ok('wrong secret → 403 ERR_TOKEN_INVALID', tokenBad.status === 403 && tokenBadBody.includes('ERR_TOKEN_INVALID'), `HTTP ${tokenBad.status}`);

  // ---- 11. Provider audit trail ------------------------------------
  console.log('\n[11] provider bounded-agent audit trail');
  const auditsRes = await get(`${BASE_PROV}/debug/audits`);
  const audits = auditsRes.json ?? [];
  ok('audit endpoint reachable (200)', auditsRes.res.status === 200);
  ok('contains executed capability events', audits.some((a) => a.action === 'executed' && a.kind === 'tool'));

  // ---- 12. Requester SDK boundary (live, offline denial) ------------
  console.log('\n[12] requester SDK boundary (deny-by-default, no network)');
  const { createBoundedAgent, createSandboxRunner } = await import('@tls-agent-gate/sdk');
  const keyRaw = await readFile(join(REQ_DIR, 'public', 'keys', 'agent.key.jwk.json'), 'utf8');
  const signer = (await import('@tls-agent-gate/sdk')).createCoreSigner;
  const bSigner = await signer({
    identityUrl: 'http://localhost:4174/.well-known/agent-identity.json',
    manifestUrl: 'http://localhost:4174/agent-manifest.json',
    privateKeyJwk: JSON.parse(keyRaw),
    manifestText: await readFile(join(REQ_DIR, 'public', 'agent-manifest.json'), 'utf8'),
  });
  const bAgent = await createBoundedAgent({
    agentId: 'beta-requester',
    identitySigner: bSigner,
    policy: { allowedOrigins: [BASE_PROV], allowLocalAgents: true, requireConsentFor: [{ type: 'cross-site' }] },
    tools: [],
    commands: {},
    onConsentRequired: () => true,
    runner: createSandboxRunner({ useWorker: false }),
  });
  const den = await bAgent.callAgent({ baseUrl: 'https://evil.invalid', path: '/admin' });
  ok('unallowlisted origin denied (ERR_ORIGIN_BLOCKED)', den.reason === 'ERR_ORIGIN_BLOCKED');
  ok('audit chain verifies', await bAgent.verifyAuditTrail());
} catch (err) {
  fails++;
  console.log(`\n  ✖ beta run aborted: ${err instanceof Error ? err.message : String(err)}`);
} finally {
  cleanup();
}

console.log('\n────────────────────────────────────────────────────────');
console.log(`beta test summary: ${passes} passed, ${fails} failed`);
process.exit(fails > 0 ? 1 : 0);
