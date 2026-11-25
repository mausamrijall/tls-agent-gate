/**
 * Shared TypeScript shapes for the tls-agent-gate protocol.
 *
 * These interfaces mirror the JSON Schemas shipped in `src/schemas/`:
 *   - agent-identity.schema.json
 *   - agent-manifest.schema.json
 * Keep them in sync when the schemas change.
 */

/** Supported signature algorithms (Web Crypto `crypto.subtle`). */
export type KeyAlgorithm = 'Ed25519' | 'ES256';

/** A JWK public/private key object as exported by Web Crypto. */
export type AgentKeyJwk = JsonWebKey;

/**
 * A freshly generated agent key pair. `kid` defaults to the RFC 7638
 * thumbprint. Private key JWK should never be published — it belongs in a
 * secret store / env var.
 */
export interface AgentKeyPair {
  alg: KeyAlgorithm;
  kid: string;
  publicKeyJwk: AgentKeyJwk;
  privateKeyJwk: AgentKeyJwk;
  /** Public key in SPKI (DER) form, base64url. */
  publicKeySpkiB64Url: string;
  /** RFC 7638 thumbprint (base64url). */
  thumbprint: string;
}

/** The public part of an agent key declared in an identity document. */
export interface AgentKeyInfo {
  /** Algorithm identifier: `Ed25519` (primary) or `ES256` (ECDSA P-256). */
  alg: KeyAlgorithm;
  /** Key identifier: defaults to the RFC 7638 JWK thumbprint. */
  kid: string;
  /** Public key as JSON Web Key (RFC 7517). */
  publicKeyJwk: AgentKeyJwk;
  /** Intended use (always `sig` for agent keys). */
  use?: 'sig';
  /** ISO-8601 expiration for this specific key (optional). */
  expiresAt?: string;
}

/** Security policy that a participant advertises/accepts. */
export interface AgentPolicy {
  /** Allow agents that identify via localhost / private-network origins. Default false. */
  allowLocalAgents?: boolean;
  /** Dev key thumbprints (RFC 7638, base64url) allowed when `allowLocalAgents` is true. */
  allowedDevKeyThumbprints?: string[];
  /** Require a valid X-Agent-Signature on every agent request. Default true for protected sites. */
  requireSignedRequests?: boolean;
}

/** TLS-anchored agent identity document served at `https://<domain>/.well-known/agent-identity.json`. */
export interface AgentIdentityDocument {
  schemaVersion: 'agent-identity-v1';
  /** Identifier of the agent/principal (e.g. https://host.example/agent). */
  subject: string;
  /** ISO-8601 creation time. */
  createdAt: string;
  /** Optional ISO-8601 expiry for the whole document. */
  expiresAt?: string;
  /** Canonical location of the agent manifest (https URL). */
  manifestUrl?: string;
  keys: {
    primary: AgentKeyInfo;
    secondary?: AgentKeyInfo;
  };
  policy?: AgentPolicy;
}

/** One advertised capability inside an agent manifest. */
export interface Capability {
  id: string;
  name: string;
  description?: string;
  /** JSON Schema describing the input for this capability. */
  inputSchema?: Record<string, unknown>;
  /** JSON Schema describing the output for this capability. */
  outputSchema?: Record<string, unknown>;
}

/** Open Agentic Web agent manifest (`https://<domain>/agent-manifest.json`). */
export interface AgentManifest {
  schemaVersion: 'agent-manifest-v1';
  /** Optional canonical agent identity (https URL of the identity document). */
  agent?: string;
  name: string;
  description?: string;
  version?: string;
  icon?: string;
  homepage?: string;
  capabilities: Capability[];
  trust?: AgentPolicy & { manifestSha256?: string };
}
