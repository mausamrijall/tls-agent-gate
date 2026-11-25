# @tls-agent-gate/browser

Browser runtime for the Open Agentic Web. It lets a website act as an
**agentic caller**: sign outbound agent requests with a Web Crypto key, route
peer fetching through an isolated `WebWorker` sandbox, and require explicit user
consent before cross-origin agent calls.

## Features

- **`AgentRuntime`** — signs requests with `X-Agent-Identity` /
  `X-Agent-Manifest` / `X-Agent-Signature` using the canonical payload.
- **WebWorker sandbox** — all remote fetching/parsing happens in a worker with
  strict timeouts, response-size caps, and sanitization of untrusted content.
- **Consent gate** — fail-closed by default; provide a `ConsentGate` (or use
  the included `PromptConsentGate` dialog).
- **Trust Inspector** — records consent, outbound signing, and inbound
  verification events; renders a lightweight panel.
- **BYOK LLM helper** — configure a personal API key (sessionStorage only) for
  agent tasks without leaking it into the page.
- **Framework-agnostic** — plain ESM; drop it into React/Next.js/Vue/Astro or
  a static page.

## Quick start

```ts
import {
  AgentRuntime,
  PromptConsentGate,
  TrustInspector,
} from '@tls-agent-gate/browser';

const runtime = await AgentRuntime.create({
  identityUrl: `https://${location.host}/.well-known/agent-identity.json`,
  manifestUrl: `https://${location.host}/agent-manifest.json`,
  manifest: {
    schemaVersion: 'agent-manifest-v1',
    agent: `https://${location.host}/agent`,
    name: 'My Caller',
    capabilities: [{ id: 'search', name: 'Search' }],
  },
  manifestText: await (await fetch('/agent-manifest.json')).text(), // exact bytes served
  privateKeyJwk,              // loaded from your secret store (never hardcode)
  consentGate: new PromptConsentGate(),
  requireConsent: true,
});

const result = await runtime.callAgent(
  { baseUrl: 'https://protected.example', path: '/api/agent/search?q=agents' },
  { method: 'GET', caps: ['search'], description: 'Query the protected service' },
);

console.log(result.verifiedByTarget);   // { domain: 'protected.example' } when verified
console.log(result.sanitizedText);      // sanitized response body## WebWorker sandbox

The runtime spawns a module worker (`./worker.js`) and sends `agent-fetch`
messages. The worker enforces:

- a timeout (default 10s),
- a maximum response size (default 2 MiB),
- sanitization: HTML responses have active elements stripped
  (`<script>`, event handlers, `javascript:` URLs, `<meta refresh>`, comments,
  …) before text is returned.

Because the fetch happens inside the worker, hostile remote content never runs
on the page's main thread. In non-browser environments (tests, SSR) the runtime
falls back to an inline fetcher.

## Consent

```ts
import { DenyConsentGate } from '@tls-agent-gate/browser';

// Default (fail-closed): every cross-origin call is denied unless you supply
// a gate. Provide your own:
const runtime = await AgentRuntime.create({
  // ...
  consentGate: {
    async requestApproval(spec) {
      return window.confirm(`Call ${spec.targetDomain}? ${spec.capabilityIds?.join(', ')}`);
    },
  },
});
```

## Trust Inspector

```ts
import { TrustInspector } from '@tls-agent-gate/browser';

const inspector = new TrustInspector();
// pass into AgentRuntime.create({ inspector })
inspector.renderInto(document.querySelector('#inspector'));
```

## BYOK LLM helper

```ts
import { configureLlm, saveLlmConfig, loadLlmConfig } from '@tls-agent-gate/browser';

saveLlmConfig({ provider: 'anthropic', model: 'claude-sonnet-5', apiKey: '…' });
const { complete } = configureLlm(loadLlmConfig()!);
const { text } = await complete('Summarize the agent result');
```

Keys live in `sessionStorage` only — the page never writes them to
`localStorage`, cookies, or the agent runtime.

## Tests

```bash
cd packages/browser
npm test
```
