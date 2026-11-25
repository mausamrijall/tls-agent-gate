/**
 * Site A (caller) dev server.
 *
 * Serves:
 *   - the caller's static page (public/)
 *   - its agent identity + manifest at /.well-known/agent-identity.json and
 *     /agent-manifest.json (generated on first run)
 *   - the built workspace packages under /vendor/@tls-agent-gate/* so the
 *     page can import the browser runtime without a bundler
 *   - /dev-key.json with the DEV private key (dev only — never do this in
 *     production; load keys from a secret store instead)
 *
 * Run: npm start (default http://localhost:4173)
 */
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '../..');
const PUBLIC_DIR = join(__dirname, 'public');
const PORT = Number(process.env.PORT || 4174);
const HOST = process.env.HOST || 'localhost';
const DOMAIN = `${HOST}:${PORT}`;

const MANIFEST = {
  schemaVersion: 'agent-manifest-v1',
  agent: `http://${DOMAIN}/agent`,
  name: 'Caller Site (A)',
  description: 'Demonstrates discovering and calling a peer agent behind the tls-agent-gate verifier.',
  version: '1.0.0',
  capabilities: [
    { id: 'search', name: 'Search', description: 'Search an agent endpoint' },
    { id: 'quote', name: 'Quote', description: 'Request a quote from a service agent' },
  ],
};

const VENDOR_VIRTUAL = {
  '/vendor/@tls-agent-gate/core/': join(ROOT, 'packages/core/dist/esm/'),
  '/vendor/@tls-agent-gate/browser/': join(ROOT, 'packages/browser/dist/esm/'),
  '/vendor/@tls-agent-gate/sdk/': join(ROOT, 'packages/sdk/dist/esm/'),
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

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
    // For local dev we serve over http, so set the subject + manifestUrl to match.
    const doc = JSON.parse(await readFile(identityPath, 'utf8'));
    doc.subject = `http://${DOMAIN}/agent`;
    doc.manifestUrl = `http://${DOMAIN}/agent-manifest.json`;
    await writeFile(identityPath, `${JSON.stringify(doc, null, 2)}\n`);
  }
  if (!existsSync(manifestPath)) {
    await writeFile(manifestPath, `${JSON.stringify(MANIFEST, null, 2)}\n`);
  }
}

async function readFileSafe(path, base) {
  const full = normalize(path);
  if (!full.startsWith(base)) throw new Error('forbidden path');
  return readFile(full);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${DOMAIN}`);
  const pathname = decodeURIComponent(url.pathname);
  try {
    let body;
    let mime = 'application/octet-stream';

    if (pathname === '/dev-key.json') {
      // DEV-ONLY endpoint for the demo. In production the private key must
      // never be exposed over HTTP — load it from a secret store instead.
      if (process.env.NODE_ENV === 'production') {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'dev-key endpoint disabled in production' }));
        return;
      }
      body = await readFile(join(PUBLIC_DIR, 'keys', 'agent.key.jwk.json'));
      mime = 'application/json; charset=utf-8';
    } else {
      for (const [prefix, base] of Object.entries(VENDOR_VIRTUAL)) {
        if (pathname.startsWith(prefix)) {
          const rel = pathname.slice(prefix.length);
          body = await readFileSafe(join(base, rel), base);
          mime = MIME['.js'] ?? 'application/octet-stream';
          break;
        }
      }
      if (body === undefined) {
        const staticPath = join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
        body = await readFile(staticPath);
        const ext = pathname.slice(pathname.lastIndexOf('.')) || '.html';
        mime = MIME[ext] ?? 'application/octet-stream';
      }
    }

    res.writeHead(200, { 'content-type': mime });
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
server.listen(PORT, HOST, () => {
  console.log(`[site-b] requester running at http://${DOMAIN}`);
  console.log(`[site-b] dev identity: http://${DOMAIN}/.well-known/agent-identity.json`);
});
