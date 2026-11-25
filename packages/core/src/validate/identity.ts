/**
 * Runtime validation for agent identity documents.
 */
import agentIdentitySchemaJson from '../schemas/agent-identity.schema.json' with { type: 'json' };
import type { AgentIdentityDocument } from '../types.ts';
import { validateSchema, type SchemaObject, type ValidationResult } from './miniSchema.ts';

export const agentIdentitySchema = agentIdentitySchemaJson as SchemaObject;

/** Validate an identity document against the agent-identity JSON Schema. */
export function validateIdentityDocument(doc: unknown): ValidationResult {
  return validateSchema(doc, agentIdentitySchema);
}

/** Type guard that also performs full validation. */
export function isAgentIdentityDocument(doc: unknown): doc is AgentIdentityDocument {
  return validateIdentityDocument(doc).valid;
}

/** Extract the primary (and optional secondary) public key info for a kid. */
export function findKeyById(
  doc: AgentIdentityDocument,
  kid: string,
): { alg: string; publicKeyJwk: JsonWebKey } | null {
  for (const key of [doc.keys.primary, doc.keys.secondary]) {
    if (key && key.kid === kid) {
      return { alg: key.alg, publicKeyJwk: key.publicKeyJwk };
    }
  }
  return null;
}
