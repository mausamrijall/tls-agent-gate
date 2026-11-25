# Site A — Passive Capability Provider

Site A holds **no autonomous agent loop**. It is the passive provider side of
the flow:

- publishes its Open Agentic Web identity
  (`/.well-known/agent-identity.json`) and manifest (`agent-manifest.json`),
- exposes protected capability endpoints (`/api/agent/*`) behind the
  `tls-agent-gate` verifier,
- rejects unsigned/untrusted callers with `401/403`,
- accepts signed requests from an allowlisted requester, injects
  `X-Verified-Agent` + `X-Agent-Manifest`, and completes the capability flow,
- executes each capability through a bounded agent (SDK) that may only run
  allowlisted tools, with an immutable audit trail.

## Run

```bash
npm start          # http://localhost:4173
```

**Order matters:** start Site B (http://localhost:4174) first so Site A can
discover B's dev key thumbprint and allowlist it for local testing. If Site B
is not running, local requester calls are rejected with
`ERR_KEY_NOT_ALLOWLISTED`.

## Try it

```bash
# Unsigned — must be rejected:
curl -i http://localhost:4173/api/agent/search?q=agents
# → 401 {"error":{"code":"ERR_MISSING_IDENTITY_HEADER",…}}

# Signed (from Site B's browser UI):
# → 200 {"ok":true,"verifiedDomain":"localhost","answer":{…}}
#   X-Verified-Agent: localhost

# Bounded-agent audit trail:
curl http://localhost:4173/debug/audits
```

## Production notes

- Replace the local dev allowlist with real allowlisted thumbprints (or disable
  `allowLocalAgents` entirely).
- Serve over HTTPS in production; identity + manifest stay at the same origin.
- The `search` capability here is executed by a bounded agent with a strict,
  deny-by-default policy — see `packages/sdk`.
