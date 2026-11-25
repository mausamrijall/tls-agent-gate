/**
 * Site B's Open Agentic Web browser-runtime entry.
 *
 * A conforming site should expose a browser runtime file. Here we re-export
 * the tls-agent-gate browser runtime (WebWorker sandbox, consent gate, Trust
 * Inspector, BYOK LLM helper) so any page/module can import it from a stable
 * public URL: `/runtime.js`.
 */
export * from '/vendor/@tls-agent-gate/browser/index.js';
