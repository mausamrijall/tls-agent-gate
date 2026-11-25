/**
 * Site A caller app — uses the tls-agent-gate browser runtime.
 */
import {
  AgentRuntime,
  PromptConsentGate,
  TrustInspector,
} from '/vendor/@tls-agent-gate/browser/index.js';

const STATUS = document.querySelector('#status');
const RESULT = document.querySelector('#result');
const CALL_BTN = document.querySelector('#call');
const INSPECTOR_EL = document.querySelector('#inspector');

function setStatus(text, ok = true) {
  STATUS.textContent = text;
  STATUS.style.background = ok ? '#ecfdf5' : '#fef2f2';
  STATUS.style.color = ok ? '#065f46' : '#991b1b';
  STATUS.style.borderColor = ok ? '#a7f3d0' : '#fecaca';
}

const manifest = {
  schemaVersion: 'agent-manifest-v1',
  agent: `http://${location.host}/agent`,
  name: 'Caller Site (A)',
  description: 'Demonstrates calling a peer agent behind the tls-agent-gate verifier.',
  version: '1.0.0',
  capabilities: [
    { id: 'search', name: 'Search' },
    { id: 'quote', name: 'Quote' },
  ],
};

let runtime = null;

async function bootstrap() {
  try {
    setStatus('booting runtime…');
    const keyResp = await fetch('/dev-key.json');
    if (!keyResp.ok) throw new Error(`dev-key fetch failed: HTTP ${keyResp.status}`);
    const privateKeyJwk = await keyResp.json();

    // Use the exact manifest bytes served at /agent-manifest.json so the
    // signed manifest SHA-256 matches what the verifier will fetch.
    const manifestResp = await fetch('/agent-manifest.json');
    const manifestText = await manifestResp.text();

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
    setStatus('ready — runtime signed with Ed25519 key ' + runtime.agentKeyId.slice(0, 12) + '…');
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

bootstrap();
