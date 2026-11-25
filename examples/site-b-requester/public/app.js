/**
 * Site A caller app — uses the tls-agent-gate browser runtime + SDK.
 */
import {
  AgentRuntime,
  PromptConsentGate,
  TrustInspector,
} from '/vendor/@tls-agent-gate/browser/index.js';
import { createBoundedAgent } from '/vendor/@tls-agent-gate/sdk/index.js';

const STATUS = document.querySelector('#status');
const RESULT = document.querySelector('#result');
const CALL_BTN = document.querySelector('#call');
const INSPECTOR_EL = document.querySelector('#inspector');
const SDK_RESULT = document.querySelector('#sdk-result');
const SDK_AUDIT = document.querySelector('#sdk-audit');

function setStatus(text, ok = true) {
  STATUS.textContent = text;
  STATUS.style.background = ok ? '#ecfdf5' : '#fef2f2';
  STATUS.style.color = ok ? '#065f46' : '#991b1b';
  STATUS.style.borderColor = ok ? '#a7f3d0' : '#fecaca';
}

const manifest = {
  schemaVersion: 'agent-manifest-v1',
  agent: `http://${location.host}/agent`,
  name: 'Active Requester Site (B)',
  description: 'Demonstrates calling a peer agent behind the tls-agent-gate verifier.',
  version: '1.0.0',
  capabilities: [
    { id: 'search', name: 'Search' },
    { id: 'quote', name: 'Quote' },
  ],
};

let runtime = null;
let bounded = null;
let manifestText = '';

function renderAudits() {
  if (!bounded) return;
  const events = bounded.auditTrail();
  if (events.length === 0) return;
  SDK_AUDIT.textContent = events
    .map((e) => {
      const reason = e.reason ? ` reason=${e.reason}` : '';
      return `#${e.seq} ${e.action} kind=${e.kind} subject=${e.subject}${reason} hash=${e.hash.slice(0, 10)}…`;
    })
    .join('\n');
}

async function bootstrap() {
  try {
    setStatus('booting runtime…');
    const keyResp = await fetch('/dev-key.json');
    if (!keyResp.ok) throw new Error(`dev-key fetch failed: HTTP ${keyResp.status}`);
    const privateKeyJwk = await keyResp.json();

    const manifestResp = await fetch('/agent-manifest.json');
    manifestText = await manifestResp.text();

    const inspector = new TrustInspector();
    runtime = await AgentRuntime.create({
      identityUrl: `http://${location.host}/.well-known/agent-identity.json`,
      manifestUrl: `http://${location.host}/agent-manifest.json`,
      manifest,
      manifestText,
      privateKeyJwk,
      consentGate: new PromptConsentGate(),
      requireConsent: true,
    });

    window.__inspector = inspector;
    inspector.renderInto(INSPECTOR_EL);

    // ---- Bounded Agent (SDK) ----------------------------------------
    const gate = new PromptConsentGate();
    bounded = await createBoundedAgent({
      agentId: 'site-b-requester',
      manifest,
      identitySigner: {
        identityUrl: runtime.identityUrl,
        keyId: runtime.agentKeyId,
        algorithm: 'Ed25519',
        manifestSha256: runtime.manifestSha256Hex,
        sign: (req) => runtime.signOutboundRequest(req.url, req.method, req.body),
      },
      policy: {
        allowedTools: [
          {
            name: 'search',
            argSchema: {
              type: 'object',
              properties: { q: { type: 'string' } },
              required: ['q'],
              additionalProperties: false,
            },
          },
        ],
        allowedCommands: ['status'],
        allowedOrigins: ['http://localhost:4173', 'http://127.0.0.1:4173'],
        allowLocalAgents: true,
        maxCallsPerTurn: 20,
        maxStepsPerTurn: 100,
        maxPayloadBytes: 4096,
        executionTimeoutMs: 8000,
        dataRedactionRules: [{ pattern: /token/i }],
        requireConsentFor: [{ type: 'cross-site' }],
      },
      tools: [
        {
          name: 'search',
          description: 'Search (local demo tool)',
          executor: (args) => ({ ok: true, tool: 'search', q: args.q }),
        },
      ],
      commands: {
        status: () => ({ up: true, agent: manifest.name }),
      },
      onConsentRequired: async (req) => {
        const origin = req.origin ? new URL(req.origin).host : 'local';
        return gate.requestApproval({
          targetDomain: origin,
          capabilityIds: req.action.kind === 'agent-call' ? req.action.caps : undefined,
          description: req.action.kind === 'agent-call' ? 'SDK agent cross-site call' : `SDK ${req.action.kind}: ${req.subject}`,
        });
      },
      onAuditEvent: renderAudits,
    });

    renderAudits();
    setStatus('ready — runtime + bounded agent booted');
    CALL_BTN.disabled = false;
  } catch (err) {
    setStatus(`bootstrap failed: ${err instanceof Error ? err.message : String(err)}`, false);
  }
}

CALL_BTN.addEventListener('click', async () => {
  if (!runtime) return;
  CALL_BTN.disabled = true;
  setStatus('calling peer agent…');
  try {
    const target = new URL(document.querySelector('#target-url').value.trim());
    const result = await runtime.callAgent(
      { baseUrl: target.origin, path: target.pathname + target.search },
      { method: 'GET', caps: ['search'], description: 'Query the protected service agent' },
    );
    RESULT.textContent = JSON.stringify(result, null, 2);
    window.__inspector.renderInto(INSPECTOR_EL);
    setStatus(result.ok ? `done — HTTP ${result.status}` : result.declined ? 'blocked by consent gate' : `HTTP ${result.status}${result.error ? ` (${result.error})` : ''}`, result.ok || result.declined);
  } catch (err) {
    RESULT.textContent = String(err);
    setStatus('call error', false);
  } finally {
    CALL_BTN.disabled = false;
  }
});

document.querySelector('#sdk-allowed').addEventListener('click', async () => {
  const r = await bounded.callAgent(
    { baseUrl: 'http://localhost:4173', path: '/api/agent/search?q=sdk' },
    { method: 'GET', caps: ['search'] },
  );
  SDK_RESULT.textContent = JSON.stringify({ ok: r.ok, decision: r.decision, reason: r.reason ?? null, value: r.value }, null, 2);
  renderAudits();
});

document.querySelector('#sdk-denied-tool').addEventListener('click', async () => {
  const r = await bounded.runTool('remove_all', {});
  SDK_RESULT.textContent = JSON.stringify({ ok: r.ok, decision: r.decision, reason: r.reason, audit: r.audit && { action: r.audit.action, subject: r.audit.subject, reason: r.audit.reason } }, null, 2);
  renderAudits();
});

document.querySelector('#sdk-denied-origin').addEventListener('click', async () => {
  const r = await bounded.callAgent({ baseUrl: 'https://evil.invalid', path: '/admin' });
  SDK_RESULT.textContent = JSON.stringify({ ok: r.ok, decision: r.decision, reason: r.reason, audit: r.audit && { action: r.audit.action, subject: r.audit.subject, reason: r.audit.reason } }, null, 2);
  renderAudits();
});

bootstrap();
