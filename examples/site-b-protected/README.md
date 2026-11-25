# Site B — Protected Service Agent

A **protected service agent** behind the `tls-agent-gate` verifier. It:

- rejects unverified scrapers (no `X-Agent-Identity` → `401`),
- rejects localhost/private-origin callers unless the caller's dev key is
  allowlisted,
- verifies Ed25519/P-256 signatures, nonces, timestamps, and (optionally)
  manifest SHA-256 hashes,
- injects `X-Verified-Agent` and `X-Agent-Manifest` response headers.

## Run

```bash
npm start          # http://localhost:4174
```

Start Site A first (on :4173) so Site B can auto-discover the caller's dev key
thumbprint for the local allowlist. If Site A is not running, local calls are
rejected with `ERR_KEY_NOT_ALLOWLISTED` until it is.

## Try it

```bash
# No signature — must be rejected:
curl -i http://localhost:4174/api/agent/search?q=agents
# → 401 {"error":{"code":"ERR_MISSING_IDENTITY_HEADER",…}}

# Signed call (from Site A's browser UI):
# → 200 {"ok":true,"verifiedDomain":"localhost",…}
#   X-Verified-Agent: localhost
```

## Production notes

- Replace the local dev allowlist with real allowlisted thumbprints (or disable
  `allowLocalAgents` entirely).
- Mount this behind your own HTTPS origin; identity docs are still fetched over
  HTTPS by callers.
- The server here is a teaching example; in production pair the same
  `verifyAgentRequest` logic with your framework's middleware (see
  `packages/verifier`).
