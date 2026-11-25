/**
 * Sandboxed WebWorker fetcher.
 *
 * All outbound peer fetching/parsing happens in this worker so hostile
 * remote content never executes on the page's main thread. The worker:
 *
 *   1. enforces a strict timeout and response-size cap
 *   2. sanitizes the response body before returning it
 *   3. communicates via a minimal message contract
 *
 * The host page talks to it through `AgentRuntime` (see agent-runtime.ts).
 */
import { sanitizeRemoteContent } from './sanitize.ts';

export interface AgentFetchRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

export interface AgentFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  fetchImpl?: typeof fetch;
}

export interface AgentFetchResponse {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  text: string;
  sanitizedText: string;
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

/** Core fetch routine — used by both the worker host and inline fallback. */
export async function performAgentFetch(
  req: AgentFetchRequest,
  opts: AgentFetchOptions = {},
): Promise<AgentFetchResponse> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
  if (!fetchImpl) {
    return { ok: false, status: 0, headers: {}, text: '', sanitizedText: '', error: 'No fetch available' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body ?? undefined,
      signal: controller.signal,
    });

    let text: string;
    const reader = res.body?.getReader();
    if (reader) {
      const decoder = new TextDecoder();
      let bytes = 0;
      let chunks = '';
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > maxBytes) {
          await reader.cancel();
          return { ok: false, status: res.status, headers: {}, text: '', sanitizedText: '', error: 'Response exceeded maximum allowed size' };
        }
        chunks += decoder.decode(value, { stream: true });
      }
      text = chunks + decoder.decode();
    } else {
      const buffer = await res.arrayBuffer();
      if (buffer.byteLength > maxBytes) {
        return { ok: false, status: res.status, headers: {}, text: '', sanitizedText: '', error: 'Response exceeded maximum allowed size' };
      }
      text = new TextDecoder().decode(buffer);
    }

    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    const contentType = res.headers.get('content-type') ?? '';
    return {
      ok: res.ok,
      status: res.status,
      headers,
      text,
      sanitizedText: sanitizeRemoteContent(contentType, text),
    };
  } catch (err) {
    const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return { ok: false, status: 0, headers: {}, text: '', sanitizedText: '', error: message };
  } finally {
    clearTimeout(timer);
  }
}

/** Start the worker host (message loop). Only called inside a worker. */
export function startWorkerHost(): void {
  const scope = globalThis as unknown as {
    postMessage(message: unknown): void;
    onmessage: ((ev: MessageEvent) => void) | null;
  };
  scope.onmessage = async (ev: MessageEvent) => {
    const msg = ev.data as { id: number; type: string; req: AgentFetchRequest; opts?: AgentFetchOptions } | undefined;
    if (!msg || msg.type !== 'agent-fetch') return;
    const result = await performAgentFetch(msg.req, msg.opts);
    scope.postMessage({ type: 'agent-fetch-result', id: msg.id, ...result });
  };
}

// Auto-start only when we are inside a dedicated worker global scope.
if (typeof window === 'undefined' && typeof postMessage === 'function') {
  startWorkerHost();
}
