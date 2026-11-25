# Site A — Agentic Caller

A conforming Open Agentic Web **caller** site. It:

- serves its own `agent-manifest.json` and `/.well-known/agent-identity.json`
  (auto-generated on first run),
- signs outbound requests with an Ed25519 key via the browser runtime,
- routes peer fetching through the WebWorker sandbox,
- prompts the user for consent before cross-origin agent calls,
- shows a live Trust & Header Inspector panel.

## Run

```bash
npm start          # http://localhost:4173
```

On first boot it generates a **dev** identity + keys under `public/` and
prints them. The dev private key is exposed only at `/dev-key.json`, which is
disabled when `NODE_ENV=production`.

Then start [Site B](../site-b-protected) and use the page to call
`http://localhost:4174/api/agent/search?q=agents`.

## Deployment

This is a static site plus a tiny dev server. Deploy `public/` to any static
host (Cloudflare Pages, Netlify, S3, nginx) and:

1. serve `/.well-known/agent-identity.json` (the real, non-local identity) over HTTPS,
2. serve `agent-manifest.json` over HTTPS,
3. load the private key from a secret store — never from `/dev-key.json`.
