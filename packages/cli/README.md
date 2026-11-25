# @tls-agent-gate/cli

`tls-agent-gate` — command-line tooling for the Open Agentic Web.

```
USAGE
  tls-agent-gate <command> [options]

COMMANDS
  keygen    Generate .well-known/agent-identity.json + key material
  validate   Check identity/manifest JSON against the bundled schemas
  probe      Inspect a live HTTPS agent endpoint and report verification behavior

GLOBAL
  --help   show help
```

## keygen

```bash
tls-agent-gate keygen --out ./site-a --domain caller.example --secondary
```

Writes:

- `./site-a/.well-known/agent-identity.json` — the TLS-anchored identity
  document (deploy this to `https://caller.example/.well-known/agent-identity.json`),
- `./site-a/keys/agent.key.jwk.json` — **private** key (chmod 600; keep out of
  source control, load from a secret store in production),
- `./site-a/keys/agent.pub.jwk.json` — public key.

Options: `--domain`, `--subject`, `--primary ed25519|es256`, `--secondary`
(adds a P-256 fallback key), `--allow-local`, `--kid override`, `--out`.

## validate

```bash
tls-agent-gate validate ./site-a/.well-known/agent-identity.json
tls-agent-gate validate ./agent-manifest.json --kind manifest
cat manifest.json | tls-agent-gate validate - --kind auto
```

Exit code `0` = valid, `1` = invalid (with the schema errors listed).

## probe

```bash
tls-agent-gate probe https://protected.example/api/agent
```

Fetches the target's identity + manifest, validates them, sends an
unauthenticated probe and a signed probe with an ephemeral key, and prints a
diagnostic report:

```
Identity document : https://protected.example/.well-known/agent-identity.json
  valid          : yes
Manifest         : https://protected.example/agent-manifest.json
  valid          : yes
Unauthenticated probe -> HTTP 401
Signed probe           -> HTTP 403 (ERR_KEY_NOT_FOUND)
Enforcement            -> rejects-signed
```

To run a fully-authenticated call (requires a deployed identity + matching key):

```bash
tls-agent-gate probe https://protected.example/api/agent \
  --identity-url https://caller.example/.well-known/agent-identity.json \
  --key-file ./keys/agent.key.jwk.json
# X-Verified-Agent -> caller.example
# Enforcement        -> verified
```

## Development

```bash
cd packages/cli
npm test
npm run build
```
