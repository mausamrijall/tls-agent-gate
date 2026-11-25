/**
 * `validate` — check identity/manifest JSON against the bundled schemas.
 */
import { readFile } from 'node:fs/promises';
import {
  isAgentIdentityDocument,
  isAgentManifest,
  validateIdentityDocument,
  validateManifest,
  type ValidationResult,
} from '@tls-agent-gate/core';

export type ValidateKind = 'identity' | 'manifest' | 'auto';

export interface ValidateOutcome {
  file: string;
  kind: 'identity' | 'manifest';
  valid: boolean;
  errors: string[];
}

export function validateJsonString(raw: string, kind: ValidateKind): { kind: 'identity' | 'manifest'; result: ValidationResult } {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error('Input is not valid JSON');
  }

  if (kind === 'auto') {
    const looksManifest = typeof data === 'object' && data !== null && !Array.isArray(data) && 'capabilities' in data;
    return looksManifest
      ? { kind: 'manifest', result: validateManifest(data) }
      : { kind: 'identity', result: validateIdentityDocument(data) };
  }
  if (kind === 'manifest') return { kind: 'manifest', result: validateManifest(data) };
  return { kind: 'identity', result: validateIdentityDocument(data) };
}

export async function validateFile(path: string, kind: ValidateKind): Promise<ValidateOutcome> {
  const raw = await readFile(path, 'utf8');
  const { kind: resolvedKind, result } = validateJsonString(raw, kind);
  return {
    file: path,
    kind: resolvedKind,
    valid: result.valid,
    errors: result.errors.map((e) => (e.path ? `${e.path}: ${e.message}` : e.message)),
  };
}

export { isAgentIdentityDocument, isAgentManifest };
