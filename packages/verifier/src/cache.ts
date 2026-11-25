/**
 * In-memory fetch cache for identity documents and manifests.
 */
import type { FetchCache } from './types.ts';

export class MemoryFetchCache implements FetchCache {
  private entries = new Map<string, { body: string; expiresAtMs: number }>();
  private maxEntries: number;

  constructor(maxEntries = 500) {
    this.maxEntries = maxEntries;
  }

  async get(url: string): Promise<string | null> {
    const entry = this.entries.get(url);
    if (!entry) return null;
    if (entry.expiresAtMs <= Date.now()) {
      this.entries.delete(url);
      return null;
    }
    return entry.body;
  }

  async set(url: string, body: string, ttlMs: number): Promise<void> {
    if (this.entries.size >= this.maxEntries) this.evict();
    this.entries.set(url, { body, expiresAtMs: Date.now() + ttlMs });
  }

  private evict(): void {
    if (this.entries.size < this.maxEntries) return;
    let oldest: string | null = null;
    let oldestTs = Infinity;
    for (const [url, entry] of this.entries) {
      if (entry.expiresAtMs < oldestTs) {
        oldestTs = entry.expiresAtMs;
        oldest = url;
      }
    }
    if (oldest) this.entries.delete(oldest);
  }
}
