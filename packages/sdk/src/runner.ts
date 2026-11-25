/**
 * Isolated runner abstraction.
 *
 * Untrusted parsing/sanitization (and, where the app opts in, orchestration
 * jobs) run inside a WebWorker when available, with a deterministic fallback
 * for non-worker/test environments. Messages are JSON-serializable only —
 * no raw functions or privileged globals cross the boundary.
 */
import { sanitizeRemoteContent } from './sanitize.ts';

export type SandboxJobType = 'sanitize';

export interface SandboxJob {
  id: number;
  type: SandboxJobType;
  payload: { contentType: string; text: string; maxLength?: number };
}

export interface SandboxResult {
  id: number;
  ok: boolean;
  value?: unknown;
  error?: string;
}

export interface SandboxRunner {
  runSanitize(contentType: string, text: string): Promise<string>;
  dispose(): void;
}

export interface SandboxRunnerOptions {
  useWorker?: boolean;
  workerUrl?: string;
  /** Optional custom sanitizer for the fallback path. */
  fallbackSanitize?: (contentType: string, text: string) => string;
}

const INLINE_SANITIZE = (contentType: string, text: string) => sanitizeRemoteContent(contentType, text);

export function createSandboxRunner(options: SandboxRunnerOptions = {}): SandboxRunner {
  const useWorker = options.useWorker ?? true;
  const sanitize = options.fallbackSanitize ?? INLINE_SANITIZE;

  if (useWorker && typeof Worker !== 'undefined' && options.workerUrl) {
    return new WorkerSandboxRunner(options.workerUrl, sanitize);
  }
  return new InlineRunner(sanitize);
}

/** Deterministic fallback used in Node, edge workers, and tests. */
class InlineRunner implements SandboxRunner {
  private sanitize: (contentType: string, text: string) => string;

  constructor(sanitize: (contentType: string, text: string) => string) {
    this.sanitize = sanitize;
  }

  async runSanitize(contentType: string, text: string): Promise<string> {
    return this.sanitize(contentType, text);
  }

  dispose(): void {
    /* nothing to dispose */
  }
}

/** WebWorker-backed runner. */
class WorkerSandboxRunner implements SandboxRunner {
  private worker: Worker;
  private seq = 0;
  private pending = new Map<number, { resolve: (v: string) => void; reject: (e: unknown) => void }>();
  private readonly fallback: (contentType: string, text: string) => string;

  constructor(workerUrl: string, fallback: (contentType: string, text: string) => string) {
    this.fallback = fallback;
    this.worker = new Worker(workerUrl, { type: 'module' });
    this.worker.onmessage = (ev: MessageEvent) => {
      const msg = ev.data as SandboxResult | undefined;
      if (!msg) return;
      const pending = this.pending.get(msg.id);
      if (!pending) return;
      this.pending.delete(msg.id);
      if (msg.ok && typeof msg.value === 'string') pending.resolve(msg.value);
      else pending.reject(new Error(msg.error ?? 'sandbox job failed'));
    };
    this.worker.onerror = (ev: ErrorEvent) => {
      for (const [, p] of this.pending) p.reject(new Error(`sandbox worker error: ${ev.message}`));
      this.pending.clear();
    };
  }

  runSanitize(contentType: string, text: string): Promise<string> {
    const id = ++this.seq;
    const promise = new Promise<string>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    const job: SandboxJob = { id, type: 'sanitize', payload: { contentType, text } };
    this.worker.postMessage(job);
    return promise;
  }

  dispose(): void {
    this.worker.terminate();
    this.pending.clear();
  }
}
