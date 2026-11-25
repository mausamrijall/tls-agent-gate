# Site B — Active Agent Requester

Site B is the active requester side of the flow: it **initiates every
capability request with signed `X-Agent-Identity` / `X-Agent-Manifest` /
`X-Agent-Signature` headers**, gets verified by Site A, and completes the
capability flow.

The page demonstrates:

- the **signed runtime call** — the browser runtime signs each request with an
  Ed25519 key anchored to Site B's identity origin; Site A verifies it and
  echoes back `X-Verified-Agent`,
- a **Bounded Agent (SDK)** panel — an allowed cross-site call succeeds, while
  an unallowlisted tool and an unallowlisted origin are blocked with clear
  audit reasons (all events appear in the immutable, hash-chained audit feed).

## Run

```bash
npm start          # http://localhost:4174
```

Start Site B (requester) **before** Site A (provider, http://localhost:4173)
so the provider can discover this site's dev key thumbprint. Then open the
page and call `http://localhost:4173/api/agent/search?q=agents`.

## What you'll see

- consent prompt before the cross-origin call,
- `200` response with `X-Verified-Agent: localhost` and the provider's answer,
- Trust Inspector log with the exact headers exchanged,
- SDK audit feed showing `allowed`/`executed` for the permitted call and
  `denied` + reason for the blocked ones.

## Deployment

Static site + dev server. In production:

1. deploy `public/` to any static HTTPS host,
2. serve `/.well-known/agent-identity.json` and `agent-manifest.json` over HTTPS,
3. load the private key from a secret store — never from `/dev-key.json`.
