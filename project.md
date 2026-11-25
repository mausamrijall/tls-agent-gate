1. System & Blueprint Architecture (tls-agent-gate)

The core design separates portable protocol logic (@agent-tls-gate/core) from environment adapters (Browser runtime + WebWorker sandbox, Node/Express/Fastify middleware, Cloudflare Worker/Edge gate, and static/framework manifest helpers) so any web stack (React, Next.js, Vue, Astro, Laravel, Go, Python, or plain HTML) can adopt it.
Plaintext

+-----------------------------------------------------------------------+
|                    CALLER SITE (Browser / Agent Runtime)              |
|                                                                       |
|  [Host Page / UI] ---> [Consent Gate] ---> [WebWorker Sandbox]        |
|                              |                   |                    |
|                              |         (Fetch / Parse / Sanitize)     |
|                              v                   v                    |
|                [Web Crypto Ed25519 Signer] ---> Outbound HTTP Request  |
|                 - Signs method+path+ts+nonce     Headers:             |
|                 - Attaches X-Agent-* headers     X-Agent-Identity     |
|                                                  X-Agent-Manifest     |
|                                                  X-Agent-Signature    |
+-----------------------------------------------------------------------+
                                   |
                                   | HTTPS + TLS Cert Chain
                                   v
+-----------------------------------------------------------------------+
|                  TARGET SITE (Edge / Server / Middleware)             |
|                                                                       |
|  1. Reject unverified localhost / private IPs unless policy allows    |
|  2. Enforce timestamp skew & nonce replay cache                       |
|  3. Fetch & cache https://<caller>/.well-known/agent-identity.json   |
|  4. Verify Ed25519/P-256 signature & optional manifest SHA-256        |
|  5. Inject X-Verified-Agent: <domain> & X-Agent-Manifest response hdrs|
|  6. Pass to App / Agent Handler (or return 401/403 for raw scrapers)  |
+-----------------------------------------------------------------------+

Core Protocol & Trust Primitives

    TLS-Anchored Identity Document (/.well-known/agent-identity.json):

        Served strictly over https:// by any participating production site ([https://example.com/.well-known/agent-identity.json](https://example.com/.well-known/agent-identity.json)).

        Because only the operator with a valid public TLS certificate for example.com can serve HTTPS on that domain, TLS/PKI acts as the identity root without needing a new centralized CA.

        Declares public keys (Ed25519 primary, ECDSA P-256 optional), key IDs (kid), expiration timestamps, manifestUrl, and security policy (allowLocalAgents, allowedDevKeyThumbprints, requireSignedRequests).

    Compact Discovery & Auth Headers:

        X-Agent-Identity: [https://caller.example/.well-known/agent-identity.json](https://caller.example/.well-known/agent-identity.json)

        X-Agent-Manifest: url="[https://caller.example/agent-manifest.json](https://caller.example/agent-manifest.json)"; sha256="<hex>"; caps="search,quote"

        X-Agent-Signature: keyid="<kid>"; alg="ed25519"; created="<unix_sec>"; nonce="<uuid_or_hex>"; sig="<base64>"

        Response headers include X-Agent-Manifest and Access-Control-Expose-Headers: X-Agent-Identity, X-Agent-Manifest, X-Verified-Agent so browser fetch() callers can inspect peer capabilities and verification status.

    Configurable Local / Dev Agent Policy:

        Default (allowLocalAgents: false): Blocks localhost, 127.0.0.1, ::1, .local, and private IP ranges (10.x, 172.16-31.x, 192.168.x) as well as unsigned scraper traffic.

        Explicit Dev Override (allowLocalAgents: true + allowedDevKeyThumbprints): Allows a developer's local key thumbprint (or explicitly allowlisted local agent) to authenticate during testing without opening the floodgates to arbitrary scrapers.

    Sandboxed Browser Fetch & Crawl Worker:

        Runs network fetching, HTML/JSON parsing, and schema checks inside a WebWorker with strict message contracts.

        Strips executable scripts/active event handlers and treats remote manifests/pages as untrusted input, requiring explicit user approval before invoking cross-origin agent actions.

2. Framework-Agnostic Adoption Blueprint (Any Stack)

Because the core protocol is just HTTP headers + a .well-known JSON file + a signed canonical payload, any framework can adopt it in minutes:

    Static Sites / Plain HTML / Astro / Next.js / React / Vue: Drop in the browser runtime script (agent-manifest.json + runtime.js + /.well-known/agent-identity.json), use the browser signer for outbound agent calls, and keep UI/state in your framework of choice.

    Edge / CDN (Cloudflare Workers / Fastly / Vercel Edge): Run the verifier at the edge before origin/LLM compute is touched, blocking unauthenticated scrapers early and forwarding X-Verified-Agent.

    Backend Frameworks (Node/Express/Fastify, Go, Rust, Python/FastAPI, PHP/Laravel): Use the framework middleware/adapter to validate X-Agent-* headers on agent/API endpoints and return signed capability headers.

    Open Agentic Web Spec Compatibility: Keeps standard agent-manifest.json network metadata intact while adding a trust object and shipping a CLI validator (npx tls-agent-gate validate) so any team can verify their manifest, identity file, and headers.

3. System Development Guide (Phased Build Plan)

Build in 5 focused phases so you always have a working, testable artifact at every step:

    Phase 1 — Schemas & Canonical Signing Spec (packages/core):

        Finalize agent-identity.schema.json and agent-manifest.schema.json.

        Define deterministic canonical signing input (e.g., newline-joined version, method, url_path_and_query, host, created, nonce, body_sha256, manifest_sha256) so browser and server implementations sign identical bytes.

        Implement Ed25519 (and P-256 fallback) key generation, thumbprint hashing, signing, and verification using Web Crypto (crypto.subtle).   

    Phase 2 — Edge & Server Verifier Middleware (packages/verifier):

        Enforce https:// and SSRF/localhost checks (unless allowLocalAgents explicitly matches an allowlisted dev key thumbprint).

        Enforce clock skew (±60s) and single-use nonce tracking (with TTL eviction).

        Fetch /.well-known/agent-identity.json with strict timeout, size cap, and short-lived cache; verify signature and optional manifestSha256.

        Ship a Cloudflare Worker adapter and a Node/HTTP middleware adapter.

    Phase 3 — Browser Runtime, Consent & WebWorker Sandbox (packages/browser):

        Implement the Open Agentic Web browser runtime contract (agent-manifest.json + runtime entry) with pluggable LLM/BYOK config.

        Route peer inspection and page/manifest fetches through a dedicated WebWorker that sanitizes untrusted text/HTML and emits structured events.

        Add a clean user-consent hook for cross-site agent calls and a live Trust & Header Inspector panel.

    Phase 4 — CLI & Spec Conformance Tool (packages/cli):

        Create a zero-friction CLI (init, keygen, sign-test, verify-site) that scaffolds /.well-known/agent-identity.json and validates any URL's manifest, headers, and signature flow.

    Phase 5 — Two Live HTTPS Demo Sites + 2-Minute Video:

        Deploy Site A (Agentic Discovery & Orchestrator) and Site B (Protected Service Agent behind the verifier) on public HTTPS URLs.

        Record a crisp < 2 min YouTube demo featuring you speaking (not AI voiceover), showing: (1) a raw scraper/localhost request getting rejected (401/403), (2) Site A's signed request passing TLS-anchored verification with live X-Agent-* header inspection, and (3) sandboxed cross-site agent execution.
