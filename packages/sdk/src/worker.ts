/**
 * Sandbox worker entry for the bounded-agent SDK.
 *
 * Handles `sanitize` jobs (and is extensible to other pure jobs). Runs
 * with no access to window/DOM/fetch — only serializable messages cross
 * the boundary.
 */
import { sanitizeRemoteContent } from './sanitize.ts';
import type { SandboxJob, SandboxResult } from './runner.ts';

export function startSdkWorkerHost(): void {
  const scope = globalThis as unknown as {
    postMessage(message: unknown): void;
    onmessage: ((ev: MessageEvent) => void) | null;
  };
  scope.onmessage = async (ev: MessageEvent) => {
    const job = ev.data as SandboxJob | undefined;
    if (!job) return;
    try {
      if (job.type === 'sanitize') {
        const value = sanitizeRemoteContent(job.payload.contentType, job.payload.text);
        const result: SandboxResult = { id: job.id, ok: true, value };
        scope.postMessage(result);
        return;
      }
      scope.postMessage({ id: job.id, ok: false, error: `unknown job type: ${String(job.type)}` } satisfies SandboxResult);
    } catch (err) {
      scope.postMessage({
        id: job.id,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      } satisfies SandboxResult);
    }
  };
}

if (typeof window === 'undefined' && typeof postMessage === 'function') {
  startSdkWorkerHost();
}
