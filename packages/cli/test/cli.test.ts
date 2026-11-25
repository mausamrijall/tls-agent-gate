import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../src/cli.ts';
import { validateFile } from '../src/validate.ts';
import type { CliIo } from '../src/cli.ts';

function makeIo() {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIo = {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
  };
  return { io, out, err };
}

test('keygen writes identity + keys; validate accepts the result', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tag-'));
  try {
    const { io, out, err } = makeIo();
    const code = await main(['keygen', '--out', dir, '--domain', 'caller.example', '--secondary'], io);
    assert.equal(code, 0, err.join('\n'));

    const identityPath = join(dir, '.well-known', 'agent-identity.json');
    const privatePath = join(dir, 'keys', 'agent.key.jwk.json');
    const publicPath = join(dir, 'keys', 'agent.pub.jwk.json');
    assert.ok(existsSync(identityPath));
    assert.ok(existsSync(privatePath));
    assert.ok(existsSync(publicPath));

    const identity = JSON.parse(readFileSync(identityPath, 'utf8'));
    assert.equal(identity.schemaVersion, 'agent-identity-v1');
    assert.equal(identity.subject, 'https://caller.example/agent');
    assert.ok(identity.keys.primary.publicKeyJwk.x);
    assert.ok(identity.keys.secondary, 'secondary key written');

    const validation = await validateFile(identityPath, 'identity');
    assert.equal(validation.valid, true);

    // private key file must not be world-readable
    const mode = (await import('node:fs/promises')).stat(privatePath).then((s) => s.mode & 0o777);
    assert.equal(await mode, 0o600);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('validate rejects an invalid identity document', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tag-'));
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify({ schemaVersion: 'wrong' }));
  try {
    const { io, err } = makeIo();
    const code = await main(['validate', bad], io);
    assert.equal(code, 1);
    assert.ok(err.length === 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('validate accepts a valid manifest', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tag-'));
  const manifest = join(dir, 'manifest.json');
  writeFileSync(
    manifest,
    JSON.stringify({
      schemaVersion: 'agent-manifest-v1',
      name: 'A',
      capabilities: [{ id: 'search', name: 'Search' }],
    }),
  );
  try {
    const { io, err } = makeIo();
    const code = await main(['validate', manifest, '--kind', 'manifest'], io);
    assert.equal(code, 0, err.join('\n'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--help prints usage and exits 0', async () => {
  const { io } = makeIo();
  const code = await main(['--help'], io);
  assert.equal(code, 0);
});
