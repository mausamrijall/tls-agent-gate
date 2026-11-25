/**
 * BYOK (Bring Your Own Key) LLM configuration helper.
 *
 * This books the *configuration* of a personal LLM API key for agent
 * tasks. Keys are stored in `sessionStorage` only when the user opts in —
 * never in `localStorage`, never in cookies, and never sent to the agent
 * runtime. The `complete()` wrapper records which model/provider was used
 * so the Trust Inspector can surface it.
 */
import type { TrustInspector } from './trust-inspector.ts';

export type LlmProvider = 'openai' | 'anthropic' | 'custom';

export interface LlmConfig {
  provider: LlmProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface LlmOutput {
  text: string;
  usage?: Record<string, number>;
}

const SESSION_KEY = 'tls-agent-gate:llm';

export function saveLlmConfig(cfg: LlmConfig): void {
  if (typeof sessionStorage === 'undefined') return;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(cfg));
}

export function loadLlmConfig(): LlmConfig | null {
  if (typeof sessionStorage === 'undefined') return null;
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as LlmConfig;
  } catch {
    return null;
  }
}

export function clearLlmConfig(): void {
  if (typeof sessionStorage === 'undefined') return;
  sessionStorage.removeItem(SESSION_KEY);
}

function defaultEndpoint(cfg: LlmConfig): string {
  switch (cfg.provider) {
    case 'openai':
      return 'https://api.openai.com/v1/chat/completions';
    case 'anthropic':
      return 'https://api.anthropic.com/v1/messages';
    default:
      return cfg.baseUrl ?? '';
  }
}

/**
 * Create a `complete()` wrapper for the configured provider. `apiKey` may
 * be passed explicitly or read from sessionStorage (via loadLlmConfig).
 */
export function configureLlm(cfg: LlmConfig, inspector?: TrustInspector): { complete: (prompt: string) => Promise<LlmOutput> } {
  const baseUrl = cfg.baseUrl || defaultEndpoint(cfg);
  return {
    async complete(prompt: string): Promise<LlmOutput> {
      if (!cfg.apiKey) throw new Error('No API key configured for LLM (configureLlm)');
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      let body: string;
      if (cfg.provider === 'anthropic') {
        headers['x-api-key'] = cfg.apiKey;
        body = JSON.stringify({ model: cfg.model, max_tokens: 1024, messages: [{ role: 'user', content: prompt }] });
      } else if (cfg.provider === 'openai') {
        headers.authorization = `Bearer ${cfg.apiKey}`;
        body = JSON.stringify({ model: cfg.model, messages: [{ role: 'user', content: prompt }] });
      } else {
        headers.authorization = `Bearer ${cfg.apiKey}`;
        body = JSON.stringify({ model: cfg.model, prompt });
      }

      const res = await fetch(baseUrl, { method: 'POST', headers, body });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`LLM request failed (HTTP ${res.status}): ${text.slice(0, 300)}`);
      }
      const json = (await res.json()) as Record<string, unknown>;
      let text = '';
      if (Array.isArray(json.choices) && (json.choices as Array<{ message?: { content?: string } }>)[0]?.message?.content) {
        text = (json.choices as Array<{ message: { content: string } }>)[0]!.message.content;
      } else if (Array.isArray(json.content)) {
        text = (json.content as Array<{ text?: string }>).map((c) => c.text ?? '').join('');
      } else if (typeof json.content === 'string') {
        text = json.content;
      }
      inspector?.add({ kind: 'sandbox-fetch', at: Date.now(), detail: { llm: cfg.provider, model: cfg.model } });
      return { text, usage: json.usage as Record<string, number> | undefined };
    },
  };
}
