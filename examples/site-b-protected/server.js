/**
 * Site B (protected service) dev server.
 *
 * Serves:
 *   - its own agent identity + manifest at /.well-known/agent-identity.json
 *     and /agent-manifest.json (generated on first run)
 *   - a protected agent API at /api/agent/* behind the tls-agent-gate
 *     verifier. Unverified scrapers / localhost callers get 401/403.
 *   - a small status page.
 *
 * Run: npm start (default http://localhost:4174)
 */
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { thumbprintOfJwk } from '../../packages/core/dist/esm/index.js';
import { formatManifestHeader, EXPOSE_HEADERS_VALUE } from '../../packages/core/dist/esm/index.js';
import { verifyAgentRequest } from '../../packages/verifier/dist/esm/verify.js';
import { VerificationError } from '../../packages/verifier/dist/esm/types.js';
import { MemoryNonceStore } from '../../packages/verifier/dist/esm/nonce.js';
import { MemoryFetchCache } from '../../packages/verifier/dist/esm/cache.js';
import { createBoundedAgent } from '../../packages/sdk/dist/esm/sdk.js';
import { createCoreSigner } from '../../packages/sdk/dist/esm/signer.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '../..');
const PUBLIC_DIR = join(__dirname, 'public');
const PORT = Number(process.env.PORT || 4174);
const HOST = process.env.HOST || 'localhost';
const DOMAIN = `${HOST}:${PORT}`;
const CALLER_URL = process.env.CALLER_URL || 'http://localhost:4173';

const MANIFEST = {
  schemaVersion: 'agent-manifest-v1',
  agent: `http://${DOMAIN}/agent`,
  name: 'Protected Service Agent (B)',
  description: 'A service agent behind the tls-agent-gate verifier. Rejects unverified scrapers.',
  version: '1.0.0',
  capabilities: [
    { id: 'search', name: 'Search', description: 'Search the protected service' },
  ],
};

// Shared identity/verifier setup.
let verifierOptions;
const nonceStore = new MemoryNonceStore();
const fetchCache = new MemoryFetchCache();
let serviceAgent; // bounded agent (SDK)

async function ensureSetup() {
  const identityPath = join(PUBLIC_DIR, '.well-known', 'agent-identity.json');
  const manifestPath = join(PUBLIC_DIR, 'agent-manifest.json');
  await mkdir(join(PUBLIC_DIR, '.well-known'), { recursive: true });
  if (!existsSync(identityPath)) {
    console.log('[site-b] generating dev identity document…');
    const cliPath = join(ROOT, 'packages/cli/dist/esm/cli.js');
    execFileSync(process.execPath, [cliPath, 'keygen', '--out', PUBLIC_DIR, '--domain', DOMAIN, '--allow-local'], {
      stdio: 'inherit',
    });
    const doc = JSON.parse(await readFile(identityPath, 'utf8'));
    doc.subject = `http://${DOMAIN}/agent`;
    doc.manifestUrl = `http://${DOMAIN}/agent-manifest.json`;
    await writeFile(identityPath, `${JSON.stringify(doc, null, 2)}\n`);
  }
  if (!existsSync(manifestPath)) {
    await writeFile(manifestPath, `${JSON.stringify(MANIFEST, null, 2)}\n`);
  }

  // Discover the caller (Site A) dev key thumbprint so it can be allowlisted.
  let allowedDevKeyThumbprints = [];
  try {
    const res = await fetch(`${CALLER_URL}/.well-known/agent-identity.json`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      const doc = await res.json();
      const tp = await thumbprintOfJwk(doc.keys.primary.publicKeyJwk);
      allowedDevKeyThumbprints = [tp];
    }
  } catch {
    // Caller not up yet — local calls will be rejected until it is.
  }

  verifierOptions = {
    allowLocalAgents: true,
    allowedDevKeyThumbprints,
    nonceStore,
    cache: fetchCache,
    fetchTimeoutMs: 3000,
    fetchMaxBytes: 65536,
    checkManifest: 'if-present',
  };
  console.log(`[site-b] allowed dev thumbprints: ${allowedDevKeyThumbprints.join(', ') || '(none — start Site A first)'}`);
}

// Boot the bounded service agent (SDK): it may only run the 'search' tool
// and cannot make any outbound calls by itself.
async function ensureServiceAgent() {
  const keyRaw = await readFile(join(PUBLIC_DIR, 'keys', 'agent.key.jwk.json'), 'utf8');
  const privateKeyJwk = JSON.parse(keyRaw);
  const signer = await createCoreSigner({
    identityUrl: `http://${DOMAIN}/.well-known/agent-identity.json`,
    manifestUrl: `http://${DOMAIN}/agent-manifest.json`,
    privateKeyJwk,
    manifestText: await readFile(join(PUBLIC_DIR, 'agent-manifest.json'), 'utf8'),
  });
  serviceAgent = await createBoundedAgent({
    agentId: `site-b-protected:${DOMAIN}`,
    manifest: MANIFEST,
    identitySigner: signer,
    policy: {
      allowedTools: [
        {
          name: 'search',
          argSchema: {
            type: 'object',
            properties: { q: { type: 'string' } },
            required: ['q'],
            additionalProperties: false,
          },
        },
      ],
      allowedCommands: [],
      allowedOrigins: [],
      allowLocalAgents: false,
      requireConsentFor: [],
      maxCallsPerTurn: 100,
      maxStepsPerTurn: 500,
      maxPayloadBytes: 8192,
      executionTimeoutMs: 5000,
    },
    tools: [
      {
        name: 'search',
        description: 'Search the protected service corpus',
        executor: (args) => ({
          query: args.q,
          hits: [`result for "${args.q}"`, `another hit for "${args.q}"`],
        }),
      },
    ],
    commands: {},
    onAuditEvent: (e) => {
      // Audits are also mirrored to stdout for server-side visibility.
      console.log(`[site-b audit] #${e.seq} ${e.action} ${e.kind}:${e.subject}${e.reason ? ` (${e.reason})` : ''}`);
    },
  });
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, x-agent-identity, x-agent-manifest, x-agent-signature',
    'access-control-expose-headers': EXPOSE_HEADERS_VALUE,
  };
}

async function handleApi(req, res, url) {
  // Read raw body (the caller signs its SHA-256).
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);

  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;

  try {
    const result = await verifyAgentRequest(
      {
        method: req.method,
        url: `http://${req.headers.host}${req.url}`,
        headers,
        body,
      },
      verifierOptions,
    );

    // Execute the capability through the bounded service agent (SDK).
    const q = url.searchParams.get('q') ?? '';
    const toolResult = await serviceAgent.runTool('search', { q });
    if (!toolResult.ok) {
      res.writeHead(403, { 'content-type': 'application/json; charset=utf-8', ...corsHeaders() });
      res.end(JSON.stringify({ error: { code: toolResult.reason ?? 'ERR_CAPABILITY_DENIED', message: 'Service capability denied by bounded agent policy' } }));
      return;
    }

    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      ...corsHeaders(),
      'x-verified-agent': result.domain,
      ...(result.manifest
        ? {
            'x-agent-manifest': formatManifestHeader({
              url: result.manifest.url,
              sha256: result.manifest.sha256,
              caps: result.manifest.caps,
            }),
          }
        : {}),
    });
    res.end(JSON.stringify({ ok: true, verifiedDomain: result.domain, query: q, answer: toolResult.value }));
  } catch (err) {
    if (err instanceof VerificationError) {
      res.writeHead(err.statusCode, { 'content-type': 'application/json; charset=utf-8', ...corsHeaders() });
      res.end(JSON.stringify({ error: { code: err.code, message: err.message } }));
      return;
    }
    throw err;
  }
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${DOMAIN}`);
  const pathname = decodeURIComponent(url.pathname);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders());
    res.end();
    return;
  }

  try {
    if (pathname.startsWith('/api/agent/')) {
      await handleApi(req, res, url);
      return;
    }
    if (pathname === '/debug/audits') {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', ...corsHeaders() });
      res.end(JSON.stringify(serviceAgent.auditTrail(), null, 2));
      return;
    }

    const staticPath = join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
    const body = await readFile(staticPath);
    const ext = pathname.slice(pathname.lastIndexOf('.')) || '.html';
    res.writeHead(200, { 'content-type': MIME[ext] ?? 'application/octet-stream' });
    res.end(body);
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : undefined;
    if (code === 'ENOENT') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('404 not found');
    } else {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(`500 error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
});

await ensureSetup();
await ensureServiceAgent();
server.listen(PORT, HOST, () => {
  console.log(`[site-b] protected service running at http://${DOMAIN}`);
  console.log(`[site-b] protected API: http://${DOMAIN}/api/agent/search?q=agents`);
  console.log(`[site-b] bounded agent audits: http://${DOMAIN}/debug/audits`);
});
