/**
 * AgentRuntime — browser-side runtime for calling peer agents.
 *
 * The runtime:
 *   - loads the caller's private signing key (WebCrypto)
 *   - signs outbound requests with the canonical tls-agent-gate payload
 *   - attaches X-Agent-Identity / X-Agent-Manifest / X-Agent-Signature
 *   - funnels peer fetching through the sandboxed WebWorker
 *   - enforces a user-consent gate before cross-origin calls
 *   - reflects verification results into a Trust Inspector
 */
import {
  buildCanonicalPayload,
  formatManifestHeader,
  formatSignatureHeader,
  generateNonce,
  HEADER_IDENTITY,
  HEADER_MANIFEST,
  HEADER_SIGNATURE,
  importPrivateKeyFromJwk,
  parseManifestHeader,
  parseVerifiedAgentHeader,
  sha256Hex,
  signCanonical,
  thumbprintOfJwk,
  unixNowSeconds,
  utf8Decode,
  utf8Encode,
  validateManifest,
  type AgentManifest,
  type KeyAlgorithm,
} from '@tls-agent-gate/core';
import { DenyConsentGate, type ConsentGate, type ConsentRequestSpec } from './consent.ts';
import { TrustInspector } from './trust-inspector.ts';
import { performAgentFetch, type AgentFetchRequest, type AgentFetchResponse } from './worker.ts';

export interface AgentRuntimeConfig {
  /** Absolute URL of this agent's identity document. */
  identityUrl: string;
  /** Absolute URL of this agent's manifest. */
  manifestUrl: string;
  /** This agent's manifest (validated at startup). */
  manifest: AgentManifest;
  /** Private signing key (JWK). Never publish this. */
  privateKeyJwk: JsonWebKey;
  algorithm?: KeyAlgorithm;
  /** Consent gate; defaults to a fail-closed DenyConsentGate. */
  consentGate?: ConsentGate;
  /** Trust inspector (optional). */
  inspector?: TrustInspector;
  /** Require consent before cross-origin calls (default true). */
  requireConsent?: boolean;
  /** URL of the worker module; defaults to ./worker.js next to the runtime. */
  workerUrl?: string;
  /** Force inline fetch instead of the WebWorker (testing / non-browser). */
  useWorker?: boolean;
  fetchTimeoutMs?: number;
  maxResponseBytes?: number;
  /** Override the fetch implementation (tests). */
  dispatchFetch?: typeof fetch | null;
  /**
   * Exact text served at `manifestUrl`. Used to compute the manifest
   * SHA-256 that is signed. When omitted the runtime tries to fetch the
   * manifest bytes itself; if that fails it falls back to serializing the
   * `manifest` object (which must match the deployed bytes).
   */
  manifestText?: string;
}

export interface CallAgentOptions {
  method?: string;
  body?: string | Uint8Array | null;
  /** Capability ids being invoked (shown in the consent dialog). */
  caps?: string[];
  description?: string;
  /** Override the default consent requirement for this call. */
  requireConsent?: boolean;
}

export interface AgentResult {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  text: string;
  sanitizedText: string;
  error?: string;
  /** True when the call was blocked by the consent gate. */
  declined: boolean;
  /** Set when the target echoed a verified caller identity. */
  verifiedByTarget: { domain: string } | null;
  /** Manifest the target echoed back (if any). */
  manifestFromTarget: ReturnType<typeof parseManifestHeader> | null;
}

export class AgentRuntime {
  private config: Required<Pick<AgentRuntimeConfig, 'identityUrl' | 'manifestUrl' | 'manifest' | 'privateKeyJwk' | 'algorithm' | 'requireConsent' | 'useWorker' | 'fetchTimeoutMs' | 'maxResponseBytes'>> & AgentRuntimeConfig;
  private consentGate: ConsentGate;
  readonly inspector: TrustInspector;
  private privateKey: CryptoKey;
  private keyId: string;
  private manifestSha256 = '';
  private worker: Worker | null = null;
  private seq = 0;
  private pending = new Map<number, { resolve: (r: AgentFetchResponse) => void; reject: (e: unknown) => void }>();

  private constructor() {
    this.inspector = new TrustInspector();
    this.consentGate = new DenyConsentGate();
    this.privateKey = {} as CryptoKey;
    this.keyId = '';
    this.config = {} as AgentRuntime['config'];
  }

  static async create(config: AgentRuntimeConfig): Promise<AgentRuntime> {
    const runtime = new AgentRuntime();
    const manifestResult = validateManifest(config.manifest);
    if (!manifestResult.valid) {
      const first = manifestResult.errors[0];
      throw new Error(`Invalid agent manifest${first ? ` (${first.path} ${first.message})` : ''}`);
    }
    runtime.config = {
      algorithm: 'Ed25519' as KeyAlgorithm,
      requireConsent: true,
      useWorker: true,
      fetchTimeoutMs: 10_000,
      maxResponseBytes: 2 * 1024 * 1024,
      ...config,
    };
    runtime.consentGate = config.consentGate ?? new DenyConsentGate();
    runtime.privateKey = await importPrivateKeyFromJwk(config.privateKeyJwk);
    const prk = config.privateKeyJwk as { kid?: string; kty?: string; crv?: string; x?: string; y?: string };
    if (prk.kid) {
      runtime.keyId = prk.kid;
    } else {
      const pubJwk: JsonWebKey = { kty: prk.kty, crv: prk.crv, x: prk.x, y: prk.y } as JsonWebKey;
      runtime.keyId = await thumbprintOfJwk(pubJwk);
    }
    runtime.manifestSha256 = await resolveManifestSha256(config);
    return runtime;
  }

  get agentKeyId(): string {
    return this.keyId;
  }

  private async buildSignedHeaders(url: string, method: string, body?: string | Uint8Array | null): Promise<Record<string, string>> {
    const target = new URL(url);
    const bodyBytes = typeof body === 'string' ? utf8Encode(body) : body ?? new Uint8Array();
    const bodySha256 = bodyBytes.byteLength > 0 ? await sha256Hex(bodyBytes) : '';
    const created = unixNowSeconds();
    const nonce = generateNonce();
    const canonical = buildCanonicalPayload({
      method,
      urlPathAndQuery: `${target.pathname}${target.search}`,
      host: target.host.toLowerCase(),
      created,
      nonce,
      bodySha256,
      manifestSha256: this.manifestSha256 || '',
    });
    const signature = await signCanonical(this.privateKey, canonical);
    const headers: Record<string, string> = {
      [HEADER_IDENTITY]: this.config.identityUrl,
      [HEADER_SIGNATURE]: formatSignatureHeader({
        keyid: this.keyId,
        alg: this.config.algorithm === 'ES256' ? 'es256' : 'ed25519',
        created: String(created),
        nonce,
        sig: signature,
      }),
    };
    if (this.manifestSha256) {
      headers[HEADER_MANIFEST] = formatManifestHeader({
        url: this.config.manifestUrl,
        sha256: this.manifestSha256,
        caps: this.config.manifest.capabilities.map((c) => c.id),
      });
    }
    return headers;
  }

  private isSameOrigin(url: string): boolean {
    if (typeof location === 'undefined') return false;
    try {
      return new URL(url).origin === location.origin;
    } catch {
      return false;
    }
  }

  async callAgent(target: { baseUrl: string; path: string }, opts: CallAgentOptions = {}): Promise<AgentResult> {
    const url = new URL(target.path, target.baseUrl).toString();
    const method = (opts.method ?? 'GET').toUpperCase();
    const body = opts.body ?? undefined;

    const needConsent = opts.requireConsent ?? this.config.requireConsent;
    if (needConsent && !this.isSameOrigin(url)) {
      const spec: ConsentRequestSpec = {
        targetDomain: new URL(url).host,
        capabilityIds: opts.caps,
        description: opts.description,
      };
      const approved = await this.consentGate.requestApproval(spec);
      this.inspector.add({
        kind: approved ? 'consent-granted' : 'consent-denied',
        at: Date.now(),
        detail: { targetDomain: spec.targetDomain },
      });
      if (!approved) {
        return { ok: false, status: 0, headers: {}, text: '', sanitizedText: '', declined: true, verifiedByTarget: null, manifestFromTarget: null };
      }
    }

    const signedHeaders = await this.buildSignedHeaders(url, method, body);
    const outbound: AgentFetchRequest = {
      url,
      method,
      headers: signedHeaders,
      body: typeof body === 'string' ? body : body ? utf8Decode(body) : undefined,
    };
    this.inspector.add({ kind: 'outbound-signed', at: Date.now(), detail: { url, keyId: this.keyId } });

    const response = await this.runInSandbox(outbound);

    const verifiedDomain = parseVerifiedAgentHeader(response.headers['x-verified-agent']);
    const manifestHeader = response.headers['x-agent-manifest'];
    const targetManifest = manifestHeader ? parseManifestHeader(manifestHeader) : null;
    if (verifiedDomain) {
      this.inspector.add({ kind: 'inbound-verified', at: Date.now(), detail: { domain: verifiedDomain, manifest: targetManifest } });
    } else if (!response.error) {
      this.inspector.add({ kind: 'inbound-unverified', at: Date.now(), detail: { status: response.status } });
    }

    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      text: response.text,
      sanitizedText: response.sanitizedText,
      error: response.error,
      declined: false,
      verifiedByTarget: verifiedDomain ? { domain: verifiedDomain } : null,
      manifestFromTarget: targetManifest,
    };
  }

  private runInSandbox(req: AgentFetchRequest): Promise<AgentFetchResponse> {
    const useWorker = this.config.useWorker && typeof Worker !== 'undefined';
    if (!useWorker) {
      if (this.config.dispatchFetch) {
        return performAgentFetch(req, {
          timeoutMs: this.config.fetchTimeoutMs,
          maxBytes: this.config.maxResponseBytes,
          fetchImpl: this.config.dispatchFetch,
        });
      }
      return performAgentFetch(req, { timeoutMs: this.config.fetchTimeoutMs, maxBytes: this.config.maxResponseBytes });
    }

    const id = ++this.seq;
    const promise = new Promise<AgentFetchResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.getWorker().postMessage({
      type: 'agent-fetch',
      id,
      req,
      opts: { timeoutMs: this.config.fetchTimeoutMs, maxBytes: this.config.maxResponseBytes },
    });
    return promise;
  }

  private getWorker(): Worker {
    if (this.worker) return this.worker;
    const workerUrl = this.config.workerUrl ?? new URL('./worker.js', import.meta.url).href;
    const worker = new Worker(workerUrl, { type: 'module' });
    worker.onmessage = (ev: MessageEvent) => {
      const msg = ev.data as { type: string; id: number } | undefined;
      if (!msg || msg.type !== 'agent-fetch-result') return;
      const pending = this.pending.get(msg.id);
      if (!pending) return;
      this.pending.delete(msg.id);
      pending.resolve(ev.data as AgentFetchResponse);
    };
    worker.onerror = (ev: ErrorEvent) => {
      // Reject all pending requests rather than hanging.
      for (const [, pending] of this.pending) {
        pending.reject(new Error(`Worker error: ${ev.message}`));
      }
      this.pending.clear();
    };
    this.worker = worker;
    return worker;
  }

  dispose(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.pending.clear();
  }
}

/**
 * Compute the manifest SHA-256 that must match the bytes the verifier will
 * fetch at `manifestUrl`. Preference order: explicit `manifestText` > live
 * fetch of `manifestUrl` > local serialization of the manifest object.
 */
async function resolveManifestSha256(config: AgentRuntimeConfig): Promise<string> {
  if (config.manifestText !== undefined) {
    return sha256Hex(config.manifestText);
  }
  try {
    const res = await fetch(config.manifestUrl, { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      const text = await res.text();
      return sha256Hex(text);
    }
  } catch {
    // Network unavailable — fall through to local serialization.
  }
  return sha256Hex(JSON.stringify(config.manifest));
}
