/**
 * Lightweight Trust Inspector: records trust-related events and renders a
 * small panel so users can see exactly who was verified, which headers were
 * exchanged, and which decisions were made.
 */
import type { ManifestHeaderParams } from '@tls-agent-gate/core';

export type TrustEventKind =
  | 'consent-granted'
  | 'consent-denied'
  | 'outbound-signed'
  | 'inbound-verified'
  | 'inbound-unverified'
  | 'sandbox-fetch';

export interface TrustEvent {
  kind: TrustEventKind;
  at: number;
  detail: Record<string, unknown>;
}

export interface VerifiedAgentEntry {
  domain: string;
  verifiedAt: string;
  keyId?: string;
  algorithm?: string;
  manifest?: ManifestHeaderParams | null;
}

export class TrustInspector {
  private events: TrustEvent[] = [];
  private agents = new Map<string, VerifiedAgentEntry>();

  add(event: TrustEvent): void {
    this.events.push(event);
    if (event.kind === 'inbound-verified' && typeof event.detail.domain === 'string') {
      this.agents.set(event.detail.domain, {
        domain: event.detail.domain,
        verifiedAt: new Date(event.at).toISOString(),
        keyId: event.detail.keyId as string | undefined,
        algorithm: event.detail.algorithm as string | undefined,
        manifest: event.detail.manifest as ManifestHeaderParams | null | undefined,
      });
    }
  }

  list(): readonly TrustEvent[] {
    return this.events;
  }

  verifiedAgents(): Map<string, VerifiedAgentEntry> {
    return this.agents;
  }

  /** Render the inspector panel into a container element. */
  renderInto(el: HTMLElement): void {
    el.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.style.cssText = 'font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;max-height:340px;overflow:auto;';

    const title = document.createElement('div');
    title.textContent = 'Trust Inspector';
    title.style.cssText = 'font-weight:700;color:#0b6e4f;margin-bottom:8px;';
    wrap.append(title);

    if (this.agents.size) {
      const h = document.createElement('div');
      h.textContent = 'Verified agents:';
      h.style.cssText = 'font-weight:600;margin:6px 0 4px;';
      wrap.append(h);
      for (const entry of this.agents.values()) {
        const line = document.createElement('div');
        line.textContent = `${entry.domain} — verified ${entry.verifiedAt}${entry.keyId ? ` · key ${entry.keyId.slice(0, 12)}…` : ''}`;
        wrap.append(line);
      }
    }

    const h2 = document.createElement('div');
    h2.textContent = 'Event log:';
    h2.style.cssText = 'font-weight:600;margin:10px 0 4px;';
    wrap.append(h2);
    for (const event of this.events) {
      const line = document.createElement('div');
      const stamp = new Date(event.at).toISOString().slice(11, 19);
      const detail = JSON.stringify(event.detail);
      line.textContent = `[${stamp}] ${event.kind} ${detail}`;
      line.style.cssText = 'border-top:1px dashed #e2e8f0;padding:2px 0;';
      wrap.append(line);
    }
    el.append(wrap);
  }
}
