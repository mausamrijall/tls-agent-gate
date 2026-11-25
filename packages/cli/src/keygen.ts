/**
 * `keygen` — generate an agent identity document + key material.
 */
import { writeFile, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import {
  generateKeyPair,
  type AgentIdentityDocument,
  type AgentKeyPair,
  type KeyAlgorithm,
} from '@tls-agent-gate/core';

export interface KeygenOptions {
  outDir: string;
  domain: string;
  subject?: string;
  primary?: KeyAlgorithm;
  secondary?: boolean;
  kidOverride?: string;
  allowLocalAgents?: boolean;
}

export interface KeygenResult {
  identityPath: string;
  privateKeyPath: string;
  publicKeyPath: string;
  primary: AgentKeyPair;
  secondary?: AgentKeyPair;
  identity: AgentIdentityDocument;
}

export async function keygen(opts: KeygenOptions): Promise<KeygenResult> {
  const primary = await generateKeyPair(opts.primary ?? 'Ed25519');
  if (opts.kidOverride) primary.kid = opts.kidOverride;

  let secondary: AgentKeyPair | undefined;
  if (opts.secondary) {
    secondary = await generateKeyPair('ES256');
  }

  const domain = opts.domain.toLowerCase().replace(/^https?:\/\//, '');
  const subject = opts.subject ?? `https://${domain}/agent`;
  const identity: AgentIdentityDocument = {
    schemaVersion: 'agent-identity-v1',
    subject,
    createdAt: new Date().toISOString(),
    manifestUrl: `https://${domain}/agent-manifest.json`,
    keys: {
      primary: {
        alg: primary.alg,
        kid: primary.kid,
        publicKeyJwk: primary.publicKeyJwk,
        use: 'sig',
      },
      ...(secondary
        ? {
            secondary: {
              alg: secondary.alg,
              kid: secondary.kid,
              publicKeyJwk: secondary.publicKeyJwk,
              use: 'sig' as const,
            },
          }
        : {}),
    },
    policy: {
      allowLocalAgents: opts.allowLocalAgents ?? false,
      requireSignedRequests: true,
    },
  };

  const wellKnownDir = join(opts.outDir, '.well-known');
  const keysDir = join(opts.outDir, 'keys');
  await mkdir(wellKnownDir, { recursive: true });
  await mkdir(keysDir, { recursive: true, mode: 0o700 });

  const identityPath = join(wellKnownDir, 'agent-identity.json');
  const privateKeyPath = join(keysDir, 'agent.key.jwk.json');
  const publicKeyPath = join(keysDir, 'agent.pub.jwk.json');

  await writeFile(identityPath, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o644 });
  await writeFile(privateKeyPath, `${JSON.stringify(primary.privateKeyJwk, null, 2)}\n`, { mode: 0o600 });
  await chmod(privateKeyPath, 0o600);
  await writeFile(publicKeyPath, `${JSON.stringify(primary.publicKeyJwk, null, 2)}\n`, { mode: 0o644 });

  return { identityPath, privateKeyPath, publicKeyPath, primary, secondary, identity };
}
