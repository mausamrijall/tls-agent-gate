/**
 * In-memory nonce store with TTL eviction. Suitable for single-instance
 * deployments. For multi-instance (e.g. many Workers in a region), back
 * this with a shared KV/Redis store implementing `NonceStore`.
 */
import type { NonceStore } from './types.ts';

export class MemoryNonceStore implements NonceStore {
  private entries = new Map<string, number>();
  private maxEntries: number;

  constructor(maxEntries = 100_000) {
    this.maxEntries = maxEntries;
  }

  async checkAndSet(nonce: string, expiresAtMs: number): Promise<boolean> {
    const now = Date.now();
    // Opportunistic eviction of expired entries.
    if (this.entries.size > this.maxEntries) this.evict(now);
    const existing = this.entries.get(nonce);
    if (existing !== undefined && existing > now) return false;
    this.entries.set(nonce, expiresAtMs);
    this.evict(now);
    return true;
  }

  async cleanup(): Promise<void> {
    this.evict(Date.now());
  }

  private evict(now: number): void {
    for (const [nonce, expiry] of this.entries) {
      if (expiry <= now) this.entries.delete(nonce);
    }
  }

  /** Test helper / diagnostics. */
  get size(): number {
    return this.entries.size;
  }
}
