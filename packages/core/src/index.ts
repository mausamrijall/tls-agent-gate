/**
 * @tls-agent-gate/core — protocol primitives for tls-agent-gate.
 *
 * Zero runtime dependencies. Runs in browsers, edge workers, and Node
 * via standard Web APIs.
 *
 * Submodules:
 *   - encoding / sha256  : bytes, hex, base64url, digests
 *   - crypto             : WebCrypto Ed25519 / P-256 keys, thumbprints, sign/verify
 *   - canonical          : deterministic payload that gets signed
 *   - headers            : X-Agent-* header codecs
 *   - validate           : JSON Schemas + runtime validators
 */

export * from './types.ts';
export * from './encoding.ts';
export * from './sha256.ts';
export * from './crypto.ts';
export * from './canonical.ts';
export * from './headers.ts';
export * from './hostPolicy.ts';
export * from './capabilityToken.ts';
export * from './challenge.ts';
export * from './validate/miniSchema.ts';
export * from './validate/identity.ts';
export * from './validate/manifest.ts';
