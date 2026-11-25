# @tls-agent-gate/core

Protocol primitives for `tls-agent-gate`. **Zero runtime dependencies** — all
you need is the platform's Web Crypto (`crypto.subtle`), `TextEncoder`, and
`fetch`-independent helpers. Runs unchanged in browsers, edge workers, and Node
≥ 22.

## What's inside

| Module | Exports (selected) |
| --- | --- |
| `encoding` | `bytesToBase64Url`, `base64UrlToBytes`, `bytesToHex`, `hexToBytes`, `utf8Encode`, `randomBytes`, `randomHexNonce` |
| `sha256` | `sha256`, `sha256Hex` |
| `crypto` | `generateKeyPair`, `thumbprintOfJwk`, `importPublicKeyFromJwk`, `importPrivateKeyFromJwk`, `signCanonical`, `verifyCanonical`, `exportSpkiB64Url`, `generateNonce`, `unixNowSeconds` |
| `canonical` | `buildCanonicalPayload`, `CANONICAL_VERSION` |
| `headers` | `formatSignatureHeader`, `parseSignatureHeader`, `formatManifestHeader`, `parseManifestHeader`, `formatIdentityHeader`, `parseIdentityHeader`, `formatVerifiedAgentHeader`, header-name constants |
| `validate` | JSON Schemas (`agentIdentitySchema`, `agentManifestSchema`), `validateIdentityDocument`, `validateManifest`, `validateSchema` (mini JSON Schema engine) |

## Key handling example

```ts
import {
  generateKeyPair,
  buildCanonicalPayload,
  signCanonical,
  verifyCanonical,
  importPrivateKeyFromJwk,
  importPublicKeyFromJwk,
  formatSignatureHeader,
  parseSignatureHeader,
} from '@tls-agent-gate/core';

const pair = await generateKeyPair('Ed25519'); // | kid = RFC 7638 thumbprint

const payload = buildCanonicalPayload({
  method: 'POST',
  urlPathAndQuery: '/api/agent/search?q=agents',
  host: 'caller.example',
  created: Math.floor(Date.now() / 1000),
  nonce: '1c293a2ed0c4f2b07064e8f0ffa719f9',
  bodySha256: '',            // or hex hash of the body
  manifestSha256: 'ab12…',
});

const privateKey = await importPrivateKeyFromJwk(pair.privateKeyJwk);
const signature = await signCanonical(privateKey, payload);

const header = formatSignatureHeader({
  keyid: pair.kid,
  alg: 'ed25519',
  created: String(created),
  nonce,
  sig: signature,
});

// On the verifier side:
const parsed = parseSignatureHeader(header);
const publicKey = await importPublicKeyFromJwk(pair.publicKeyJwk);
const ok = await verifyCanonical(publicKey, payload, parsed!.sig);
```

## JSON Schemas

The schemas live in `src/schemas/` and are also published as subpath exports:

```
@tls-agent-gate/core/agent-identity.schema.json
@tls-agent-gate/core/agent-manifest.schema.json
```

Use them with any JSON Schema tooling (ajv, etc.). The runtime validators
(`validateIdentityDocument`, `validateManifest`) implement the same rules with
zero dependencies via `validate/miniSchema.ts`.

## Canonical signing spec

The payload is a UTF-8, newline-joined string:

```
agent-tls-gate-signature-v1
<METHOD>
<url_path_and_query>
<host>
<created>
<nonce>
<body_sha256>
<manifest_sha256>
```

Rules:

- `METHOD` is uppercased; `host` is lowercased; whitespace is trimmed from the
  path and host.
- An empty body hashes to an empty string (not the hash of empty bytes).
- `created` is Unix seconds and must be within the verifier's skew window.
- `nonce` must be unique per key/created window (verifiers enforce single-use).

## Tests

```bash
cd packages/core
npm test
```
