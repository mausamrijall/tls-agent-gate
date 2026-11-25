# tls-agent-gate

**A security & trust layer for the Open Agentic Web.**

`tls-agent-gate` is a modular, open-source toolkit that lets websites and
browser-based agent networks:

1. **Bind an agent's cryptographic identity** (`Ed25519` primary via Web Crypto
   `crypto.subtle`, with `ECDSA P-256` support) to a live HTTPS production
   domain through `https://<domain>/.well-known/agent-identity.json` — anchored
   by the domain's TLS/HTTPS origin, so no new centralized CA is needed.
2. **Advertise compact manifest/capability metadata and cryptographic request
   signatures in HTTP headers** (`X-Agent-Identity`, `X-Agent-Manifest`,
   `X-Agent-Signature`) without bloating headers or leaking secrets.
3. **Block unauthenticated scrapers, spoofed headers, and `localhost` /
   private-network origins by default** (`allowLocalAgents: false`), while
   supporting explicit per-site developer allowlisting
   (`allowLocalAgents: true` + `allowedDevKeyThumbprints`) for local testing.
4. **Run untrusted peer fetching/parsing inside an isolated `WebWorker`
   sandbox** with strict input sanitization and explicit user-consent hooks
   before cross-site agent calls.
5. **Conform to the Open Agentic Web browser runtime & manifest model** so any
   web framework (static HTML, React/Next.js, Vue, Node, Cloudflare Workers,
   Python, Go, PHP) can adopt it cleanly.

Compatible with the **Cognizant AI Lab / MIT NANDA Open Agentic Web MVP
Profile 0.2** model.

---

## Repository layout

| Path | Description |
| --- | --- |
| `packages/core` | JSON Schemas + runtime validators, canonical signing payload builder, Web Crypto `Ed25519`/`P-256` keys, thumbprints, `X-Agent-*` header codecs. **Zero runtime dependencies.** |
| `packages/verifier` | Framework-agnostic `verifyAgentRequest` (HTTPS/origin policy, localhost/private blocking, timestamp skew + nonce replay protection, identity fetch/cache, signature & manifest hash verification) plus **Cloudflare Workers** and **Node/Express/Connect** adapters. |
| `packages/browser` | Browser runtime: `WebWorker` sandboxed fetcher/parser, sanitization, user-consent gate, outbound `fetch` wrapper that signs requests and parses `X-Verified-Agent` / `X-Agent-Manifest` responses, BYOK LLM helper, Trust Inspector. |
| `packages/sdk` | **Bounded Agent Execution SDK** — a default-deny capability & execution boundary: allowlisted tools/commands with schema validation, origin allowlists, `allowLocalAgents` enforcement, budget/rate/timeout caps, redaction, consent gates, signed remote agent calls, and an immutable hash-chained audit trail. |
| `packages/cli` | `tls-agent-gate` CLI: `keygen`, `validate`, `probe`. |
| `examples/site-a-caller` | A conforming Open Agentic Web caller site (manifest + browser runtime + UI) that discovers/calls a peer agent with consent. |
| `examples/site-b-protected` | A protected service agent site behind the verifier that rejects unverified scrapers/localhost callers. |

## Quick start

```bash
npm install
npm run build
npm test        # runs every package's unit tests
```

### Run the two-site demo (local, no deployment needed)

```bash
# Terminal 1 — caller site
npm start --workspace site-a-caller        # http://localhost:4173

# Terminal 2 — protected service (starts after the caller so it can
# auto-discover the caller's dev key thumbprint)
npm start --workspace site-b-protected     # http://localhost:4174
```

Then open http://localhost:4173, enter `http://localhost:4174/api/agent/search?q=agents`
and press **Run signed agent call**. You'll see:

- the consent prompt before the cross-origin call,
- a `200` response with `X-Verified-Agent: localhost`,
- the Trust Inspector log with the exact headers exchanged.

The same page also includes a **Bounded Agent (SDK)** panel proving the
default-deny boundary:

- **Allowed cross-site call** — succeeds (signed, consent-gated) and returns
  the protected service's answer;
- **Denied: unallowlisted tool** — `ERR_TOOL_NOT_FOUND` from the SDK,
  never executed;
- **Denied: unallowlisted origin** — `ERR_ORIGIN_BLOCKED` from the SDK,
  never fetched.

Every outcome lands in the immutable, hash-chained audit feed on the page.
Site B exposes its own bounded-agent audit trail at
`http://localhost:4174/debug/audits`.

Meanwhile, `curl http://localhost:4174/api/agent/search?q=agents` (no signature)
returns `401 {"error":{"code":"ERR_MISSING_IDENTITY_HEADER",…}}`.

### CLI

```bash
node packages/cli/dist/esm/cli.js keygen --out ./site-a --domain caller.example
node packages/cli/dist/esm/cli.js validate ./site-a/.well-known/agent-identity.json
node packages/cli/dist/esm/cli.js probe https://protected.example/api/agent
```

## The protocol at a glance

### Identity document (`/.well-known/agent-identity.json`)

```json
{
  "schemaVersion": "agent-identity-v1",
  "subject": "https://caller.example/agent",
  "createdAt": "2026-01-01T00:00:00Z",
  "manifestUrl": "https://caller.example/agent-manifest.json",
  "keys": {
    "primary": {
      "alg": "Ed25519",
      "kid": "<RFC-7638 thumbprint>",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "…" }
    }
  },
  "policy": { "allowLocalAgents": false, "requireSignedRequests": true }
}
```

Only the operator holding a valid public TLS certificate for the domain can
serve HTTPS there — TLS/PKI is the identity root.

### Headers

```
X-Agent-Identity:    https://caller.example/.well-known/agent-identity.json
X-Agent-Manifest:    url="https://caller.example/agent-manifest.json"; sha256="<hex>"; caps="search,quote"
X-Agent-Signature:   keyid="<kid>"; alg="ed25519"; created="<unix_sec>"; nonce="<hex>"; sig="<base64url>"
```

Response headers set by the verifier on success:

```
X-Verified-Agent: caller.example
X-Agent-Manifest: url="…"; sha256="…"; caps="…"
Access-Control-Expose-Headers: X-Agent-Identity, X-Agent-Manifest, X-Verified-Agent
```

### Canonical signing payload

Both sides sign exactly these bytes (UTF-8, newline-joined):

```
agent-tls-gate-signature-v1
<METHOD>
<url_path_and_query>
<host>
<created>          (Unix seconds)
<nonce>
<body_sha256>      (lowercase hex; empty when no body)
<manifest_sha256>  (lowercase hex; empty when not provided)
```

## Security properties & defaults

- **Default deny.** Requests without `X-Agent-Identity` or a valid signature
  get `401/403`.
- **HTTPS-only identity anchor** — except an explicit local-dev override
  (`allowLocalAgents` + allowlisted dev key thumbprint) for `localhost`/private
  origins.
- **Anti-replay.** Every signature carries a one-time nonce; verifiers track
  nonces with TTL eviction (`ERR_REPLAYED_NONCE`).
- **Clock skew** tolerance (default ±60s).
- **Bounded, cached, sanitized fetching.** Identity/manifest fetches enforce a
  timeout and a 64 KiB size cap, and never run remote content in the main
  thread.
- **No secrets in headers.** Only public key material, hashes, and signatures
  travel over the wire; private keys live in secret stores (or, for the demo,
  a dev-only endpoint that refuses to run in `NODE_ENV=production`).

## Adopting in your framework

- **Static/React/Next/Vue/Astro** — add the browser runtime:
  `packages/browser` (see [`packages/browser/README.md`](packages/browser/README.md)).
- **Node/Express/Fastify** — `createVerifierMiddleware`:
  [`packages/verifier/README.md`](packages/verifier/README.md) (includes Go,
  Python, and Laravel/PHP integration snippets).
- **Cloudflare Workers** — `createCloudflareHandler`:
  [`packages/verifier/README.md`](packages/verifier/README.md).
- **Bounded agents (any stack)** — wrap the agent in a deny-by-default
  capability boundary: `packages/sdk`
  (see [`packages/sdk/README.md`](packages/sdk/README.md)).

## Development phases

This repository is built in five phases (all implemented):

1. `packages/core` — schemas, canonical signing, Web Crypto.
2. `packages/verifier` — edge/server verifier + adapters.
3. `packages/browser` — browser runtime, consent, WebWorker sandbox.
4. `packages/cli` — `keygen` / `validate` / `probe`.
5. `packages/sdk` — Bounded Agent Execution SDK (default-deny boundary).
6. `examples/` — Site A (caller) and Site B (protected service), plus this
   documentation.

## License

Apache-2.0. See [LICENSE](LICENSE).
