import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from '../src/crypto.ts';
import { agentIdentitySchema, isAgentIdentityDocument, validateIdentityDocument } from '../src/validate/identity.ts';
import { agentManifestSchema, isAgentManifest, validateManifest } from '../src/validate/manifest.ts';
import { validateSchema } from '../src/validate/miniSchema.ts';
import type { AgentIdentityDocument, AgentManifest } from '../src/types.ts';

async function makeIdentity(overrides: Partial<AgentIdentityDocument> = {}): Promise<AgentIdentityDocument> {
  const pair = await generateKeyPair('Ed25519');
  return {
    schemaVersion: 'agent-identity-v1',
    subject: 'https://caller.example/agent',
    createdAt: '2026-01-01T00:00:00Z',
    manifestUrl: 'https://caller.example/agent-manifest.json',
    keys: {
      primary: {
        alg: 'Ed25519',
        kid: pair.kid,
        publicKeyJwk: pair.publicKeyJwk,
      },
    },
    policy: { allowLocalAgents: false, requireSignedRequests: true },
    ...overrides,
  };
}

function makeManifest(overrides: Partial<AgentManifest> = {}): AgentManifest {
  return {
    schemaVersion: 'agent-manifest-v1',
    agent: 'https://caller.example/agent',
    name: 'Caller',
    description: 'Demo caller agent',
    version: '1.0.0',
    capabilities: [{ id: 'search', name: 'Search', description: 'Search the web' }],
    ...overrides,
  };
}

test('valid identity document passes', async () => {
  const doc = await makeIdentity();
  assert.equal(validateIdentityDocument(doc).valid, true);
  assert.equal(isAgentIdentityDocument(doc), true);
});

test('identity with missing schemaVersion fails', async () => {
  const doc = await makeIdentity();
  delete (doc as Partial<AgentIdentityDocument>).schemaVersion;
  const result = validateIdentityDocument(doc);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.message.includes('schemaVersion')));
});

test('identity with unknown key algorithm fails', async () => {
  const doc = await makeIdentity();
  doc.keys.primary.alg = 'RSA' as never;
  assert.equal(validateIdentityDocument(doc).valid, false);
});

test('identity with secondary P-256 key is valid', async () => {
  const secondary = await generateKeyPair('ES256');
  const doc = await makeIdentity({
    keys: {
      primary: (await makeIdentity()).keys.primary,
      secondary: { alg: 'ES256', kid: secondary.kid, publicKeyJwk: secondary.publicKeyJwk },
    },
  });
  assert.equal(validateIdentityDocument(doc).valid, true);
});

test('valid manifest passes', () => {
  assert.equal(validateManifest(makeManifest()).valid, true);
  assert.equal(isAgentManifest(makeManifest()), true);
});

test('manifest without capabilities fails', () => {
  const m = makeManifest({ capabilities: [] });
  assert.equal(validateManifest(m).valid, false);
});

test('manifest with invalid trust.manifestSha256 fails', () => {
  const m = makeManifest({ trust: { manifestSha256: 'not-hex' } });
  assert.equal(validateManifest(m).valid, false);
});

test('mini schema rejects wrong top-level type', () => {
  const result = validateSchema([1, 2], agentIdentitySchema);
  assert.equal(result.valid, false);
});

test('mini schema validates enum/const and nested paths', async () => {
  const doc = await makeIdentity({ keys: undefined as never });
  const result = validateIdentityDocument(doc);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === 'keys'));
});
