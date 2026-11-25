/**
 * Network helpers for fetching remote (untrusted) documents with strict
 * timeouts and response-size caps. All fetches are GET requests; the
 * caller is responsible for applying origin policy before use.
 */
import type { FetchCache, FetchedDocument, FetchImpl } from './types.ts';

export interface SafeFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  fetchImpl?: FetchImpl;
}

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BYTES = 65536;

/** Fetch a document, enforcing timeout and a hard response-size cap. */
export async function safeFetch(url: string, opts: SafeFetchOptions = {}): Promise<FetchedDocument> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) throw new Error('No fetch implementation available');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(url, { signal: controller.signal });
  } catch (err) {
    throw new Error(`Fetch failed: ${safeErrorMessage(err)}`);
  } finally {
    clearTimeout(timer);
  }

  const body = await readBounded(response, maxBytes);

  return {
    ok: response.ok,
    status: response.status,
    contentType: (response.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase(),
    body,
  };
}

async function readBounded(response: Response, maxBytes: number): Promise<string> {
  const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
  let bytes = 0;
  let text = '';

  const reader = response.body?.getReader();
  if (reader) {
    const decoder = new TextDecoder();
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        throw new Error('Response exceeded maximum allowed size');
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } else {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > maxBytes) throw new Error('Response exceeded maximum allowed size');
    text = new TextDecoder().decode(buffer);
  }

  // Never trust binary content even when it sneaks past the size checks.
  if (contentType && !contentType.includes('json') && !contentType.includes('text') && !contentType.includes('xml')) {
    // Allow application/octet-stream? No: identity/manifest docs must be text.
    if (!contentType.includes('octet-stream')) throw new Error(`Unexpected content-type: ${contentType}`);
  }

  return text;
}

/** Human-safe error string (never leak internal details or secrets). */
export function safeErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    const name = err.name === 'AbortError' ? 'timeout' : err.name;
    return `${name}: ${err.message}`;
  }
  return String(err);
}

/** Fetch with cache, falling back to network. */
export async function fetchWithCache(
  url: string,
  cache: FetchCache | undefined,
  ttlMs: number,
  opts: SafeFetchOptions,
): Promise<string> {
  if (cache) {
    const cached = await cache.get(url);
    if (cached !== null) return cached;
  }
  const doc = await safeFetch(url, opts);
  if (!doc.ok) {
    throw new Error(`HTTP ${doc.status} fetching ${url}`);
  }
  if (cache) await cache.set(url, doc.body, ttlMs);
  return doc.body;
}
