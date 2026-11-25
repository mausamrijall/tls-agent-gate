/**
 * Runtime validation for agent manifests.
 */
import agentManifestSchemaJson from '../schemas/agent-manifest.schema.json' with { type: 'json' };
import type { AgentManifest } from '../types.ts';
import { validateSchema, type SchemaObject, type ValidationResult } from './miniSchema.ts';

export const agentManifestSchema = agentManifestSchemaJson as SchemaObject;

/** Validate a manifest against the agent-manifest JSON Schema. */
export function validateManifest(doc: unknown): ValidationResult {
  return validateSchema(doc, agentManifestSchema);
}

/** Type guard that also performs full validation. */
export function isAgentManifest(doc: unknown): doc is AgentManifest {
  return validateManifest(doc).valid;
}

/** Return the capability ids advertised in a manifest. */
export function listCapabilityIds(manifest: AgentManifest): string[] {
  return manifest.capabilities.map((c) => c.id);
}
