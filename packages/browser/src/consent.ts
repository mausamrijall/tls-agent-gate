/**
 * User-consent hooks for cross-site agent calls.
 *
 * The Open Agentic Web model requires an explicit user decision before a
 * site invokes a peer agent on another origin. `ConsentGate` is that
 * decision point. The default is fail-closed: a `DenyConsentGate` blocks
 * everything unless you provide a gate (or an `onConsentRequired` hook).
 */

export interface ConsentRequestSpec {
  /** Origin of the peer agent (e.g. `protected.example`). */
  targetDomain: string;
  /** Capability ids the caller intends to invoke. */
  capabilityIds?: string[];
  /** Human-readable justification shown in the UI. */
  description?: string;
}

export interface ConsentGate {
  /** Resolve `true` to approve the cross-site call, `false` to deny. */
  requestApproval(spec: ConsentRequestSpec): Promise<boolean>;
}

/** Fail-closed default. */
export class DenyConsentGate implements ConsentGate {
  async requestApproval(): Promise<boolean> {
    return false;
  }
}

export interface PromptConsentGateOptions {
  /** Timeout before auto-denying (default 30s). */
  timeoutMs?: number;
  /** Where to mount the dialog (default document.body). */
  container?: HTMLElement;
  /** Custom label for the approve button. */
  approveLabel?: string;
  /** Custom label for the deny button. */
  denyLabel?: string;
}

/**
 * Minimal, dependency-free consent dialog. It is intentionally plain so it
 * can be replaced with a framework component (React/Vue/etc.) in real apps.
 */
export class PromptConsentGate implements ConsentGate {
  private opts: Required<Omit<PromptConsentGateOptions, 'container'>> & { container?: HTMLElement };

  constructor(opts: PromptConsentGateOptions = {}) {
    this.opts = { timeoutMs: 30_000, approveLabel: 'Allow', denyLabel: 'Deny', ...opts };
  }

  requestApproval(spec: ConsentRequestSpec): Promise<boolean> {
    return new Promise((resolve) => {
      const container = this.opts.container ?? document.body;
      const overlay = document.createElement('div');
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      overlay.style.cssText =
        'position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:9999;font-family:system-ui,sans-serif;';
      const card = document.createElement('div');
      card.style.cssText = 'background:#fff;color:#111;max-width:420px;width:90%;border-radius:10px;padding:20px;box-shadow:0 10px 40px rgba(0,0,0,.3);';
      const title = document.createElement('h3');
      title.textContent = 'Approve agent call?';
      const detail = document.createElement('p');
      detail.style.cssText = 'font-size:14px;line-height:1.5;word-break:break-word;';
      const caps = spec.capabilityIds?.length ? `\nCapabilities: ${spec.capabilityIds.join(', ')}` : '';
      detail.textContent = `Allow this page to call the agent at ${spec.targetDomain}?${caps}\n${spec.description ?? ''}`;
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;margin-top:16px;';
      const deny = document.createElement('button');
      deny.textContent = this.opts.denyLabel;
      const allow = document.createElement('button');
      allow.textContent = this.opts.approveLabel;
      allow.style.cssText = 'background:#0b6e4f;color:#fff;border:0;padding:6px 14px;border-radius:6px;cursor:pointer;';
      const finish = (approved: boolean) => {
        overlay.remove();
        resolve(approved);
      };
      deny.addEventListener('click', () => finish(false));
      allow.addEventListener('click', () => finish(true));
      row.append(deny, allow);
      card.append(title, detail, row);
      overlay.append(card);
      container.append(overlay);
      const timer = setTimeout(() => finish(false), this.opts.timeoutMs);
      overlay.addEventListener('remove', () => clearTimeout(timer));
    });
  }
}
