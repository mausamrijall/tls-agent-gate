# @tls-agent-gate/verifier

Framework-agnostic request verification for the Open Agentic Web.

`verifyAgentRequest` implements the server-side half of `tls-agent-gate`:

1. require + parse `X-Agent-Identity` (absolute HTTPS URL),
2. reject non-HTTPS and non-allowlisted private/loopback origins,
3. require + parse `X-Agent-Signature`, enforce timestamp skew (±60s default),
4. single-use nonce check (anti-replay),
5. fetch + cache `/.well-known/agent-identity.json` (timeout, 64 KiB cap),
6. validate the identity document schema and locate the signing key,
7. verify the canonical payload signature,
8. enforce the dev-key allowlist for private origins,
9. optionally verify the manifest SHA-256 / capability ids.

## Usage

```ts
import { verifyAgentRequest, VerificationError, MemoryNonceStore, MemoryFetchCache } from '@tls-agent-gate/verifier';

const result = await verifyAgentRequest(
  {
    method: req.method,
    url: `https://${req.headers.host}${req.url}`,
    headers: req.headers,           // lowercased
    body: rawBodyBytes,             // Buffer/Uint8Array; required if a body exists
  },
  {
    allowLocalAgents: false,
    nonceStore: new MemoryNonceStore(),
    cache: new MemoryFetchCache(),
    fetchTimeoutMs: 5000,
    fetchMaxBytes: 65536,
    checkManifest: 'if-present',
  },
);

// result.verified === true → proceed; set response headers:
// X-Verified-Agent: result.domain
// X-Agent-Manifest: <echo of result.manifest>
// Access-Control-Expose-Headers: X-Agent-Identity, X-Agent-Manifest, X-Verified-Agent
```

On failure a `VerificationError` is thrown with a stable machine-readable
`code` and an HTTP `statusCode`. Example codes:

| Code | Meaning | HTTP |
| --- | --- | --- |
| `ERR_MISSING_IDENTITY_HEADER` | no `X-Agent-Identity` | 401 |
| `ERR_NOT_HTTPS` | identity not HTTPS (unless local-dev allowlisted) | 403 |
| `ERR_LOCALHOST_BLOCKED` | localhost/private origin & local agents disabled | 403 |
| `ERR_MISSING_SIGNATURE` / `ERR_MALFORMED_SIGNATURE` | signing problem | 401/403 |
| `ERR_EXPIRED` / `ERR_FUTURE_TIMESTAMP` | clock skew exceeded | 401 |
| `ERR_REPLAYED_NONCE` | nonce already used | 401 |
| `ERR_IDENTITY_FETCH` / `ERR_INVALID_IDENTITY` | identity doc unavailable/invalid | 502 |
| `ERR_KEY_NOT_FOUND` | kid not in identity doc | 403 |
| `ERR_SIGNATURE_INVALID` | signature did not verify | 403 |
| `ERR_KEY_NOT_ALLOWLISTED` | local dev key not in allowlist | 403 |
| `ERR_MANIFEST_HASH_MISMATCH` | manifest hash mismatch | 403 |

## Node / Express / Connect adapter

```ts
import express from 'express';
import { createVerifierMiddleware } from '@tls-agent-gate/verifier/node';

const app = express();

// IMPORTANT: the verifier needs the raw body bytes. Mount a raw parser first.
app.use('/api/agent', express.raw({ limit: '1mb' }));
app.use('/api/agent', createVerifierMiddleware({
  allowLocalAgents: false,
}));

app.post('/api/agent/search', (req, res) => {
  // req.verifiedAgent is set with the verification result.
  res.json({ ok: true, verifiedDomain: req.verifiedAgent.domain });
});
```

The middleware sets `X-Verified-Agent`, `X-Agent-Manifest`, and
`Access-Control-Expose-Headers` on success, and returns a JSON error body on
failure.

## Cloudflare Workers adapter

```ts
import { createCloudflareHandler } from '@tls-agent-gate/verifier/cloudflare';

export default {
  fetch: createCloudflareHandler(
    async (request, env, ctx, verified) => {
      return new Response(JSON.stringify({ ok: true, domain: verified.domain }), {
        headers: { 'content-type': 'application/json' },
      });
    },
    { allowLocalAgents: false },
  ),
};
```

The wrapper attaches the verification headers to every successful response and
returns `401/403` JSON for unverified requests. A lower-level
`verifyCloudflareRequest(request, options)` API is also exported.

## Adopting in other backends

The protocol is just HTTP headers + a signed canonical payload + a JSON file,
so any backend can verify in minutes. In each case:

1. read `X-Agent-Identity`, `X-Agent-Signature`, `X-Agent-Manifest`;
2. build the canonical payload (see `@tls-agent-gate/core`);
3. fetch the identity document (with timeout + size cap), resolve the `kid`,
   and verify the signature over the canonical string;
4. enforce the same origin policy (no private/loopback unless allowlisted).

### Go

```go
// Pseudocode for the verification flow. Use a real validator for JWK/Ed25519.
import (
  "crypto/ed25519"
  "encoding/base64"
  "encoding/json"
  "net/http"
)

func verifyAgentRequest(w http.ResponseWriter, r *http.Request) bool {
  identityURL := r.Header.Get("X-Agent-Identity")
  if identityURL == "" {
    http.Error(w, `{"error":{"code":"ERR_MISSING_IDENTITY_HEADER"}}`, http.StatusUnauthorized)
    return false
  }
  // 1. policy checks (https, localhost/private blocking)
  // 2. fetch identity doc (bounded), resolve kid -> public key
  // 3. canonical string: strings.Join([]string{version, method, pathQuery,
  //      host, created, nonce, bodySha256, manifestSha256}, "\n")
  // 4. sig, _ := base64.RawURLEncoding.DecodeString(sigB64Url)
  //    ok := ed25519.Verify(pub, []byte(canonical), sig)
  // 5. set X-Verified-Agent: domain
  return true
}
```

### Python (FastAPI)

```python
from fastapi import Request, Response, HTTPException
import httpx, json, hashlib, base64
from nacl.signing import VerifyKey

async def verify_agent_request(req: Request) -> dict:
    identity_url = req.headers.get("x-agent-identity")
    if not identity_url:
        raise HTTPException(401, detail={"code": "ERR_MISSING_IDENTITY_HEADER"})
    # Origin policy + bounded fetch of the identity document
    async with httpx.AsyncClient(timeout=5.0) as client:
        doc = (await client.get(identity_url, follow_redirects=False)).json()
    # Build canonical string; base64url-decode signature; verify Ed25519
    verify_key = VerifyKey(base64.urlsafe_b64decode(doc["keys"]["primary"]["publicKeyJwk"]["x"]))
    verify_key.verify(canonical.encode(), base64.urlsafe_b64decode(sig))
    return {"domain": identity_url.split("/")[2], "verified": True}
```

### PHP (Laravel)

```php
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Http;

protected function verifyAgent(Request $request): JsonResponse
{
    $identityUrl = $request->header('X-Agent-Identity');
    if (! $identityUrl) {
        return response()->json(['error' => ['code' => 'ERR_MISSING_IDENTITY_HEADER']], 401);
    }
    $doc = Http::timeout(5)->get($identityUrl)->json();
    // 1. origin policy (https + no private/loopback unless allowlisted)
    // 2. canonical payload (newline-joined fields)
    // 3. base64url decode signature; verify Ed25519 (sodium_crypto_sign_verify_detached)
    // 4. $response->header('X-Verified-Agent', $domain);
    return response()->json(['ok' => true, 'verifiedDomain' => $domain]);
}
```

> Note: production deployments should still apply platform-level SSRF guards
> (e.g. egress filtering) — identity URLs are fetched by the verifier.

## Tests

```bash
cd packages/verifier
npm test
```

The suite covers valid signatures, expired/future timestamps, replayed nonces,
tampered bodies, manifest-hash mismatches, blocked localhost, allowlisted dev
keys, ESL/Ed25519, invalid schemas, and the Cloudflare/Node adapters.
