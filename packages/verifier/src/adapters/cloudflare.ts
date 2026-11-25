/**
 * Cloudflare Workers adapter.
 *
 * Usage:
 *   import { createCloudflareHandler } from '@tls-agent-gate/verifier/cloudflare';
 *
 *   export default {
 *     fetch: createCloudflareHandler(
 *       async (request, env, ctx, verified) => {
 *         return new Response('hello verified agent');
 *       },
 *       { allowLocalAgents: false },
 *     ),
 *   };
 *
 * The `verified` result is passed as the 4th argument to your handler and
 * the response gets `X-Verified-Agent` + `X-Agent-Manifest` headers.
 */
import {
  EXPOSE_HEADERS_VALUE,
  HEADER_EXPOSE,
  HEADER_MANIFEST,
  HEADER_VERIFIED_AGENT,
} from '@tls-agent-gate/core';
import { VerificationError, type VerificationResult, type VerifierRequest, type VerifyOptions } from '../types.ts';
import { formatResponseManifestHeader, verifyAgentRequest } from '../verify.ts';

export type CloudflareEnv = Record<string, unknown>;
export type CloudflareContext = { waitUntil?: (p: Promise<unknown>) => void };

/** Convert a Worker `Request` into the normalized `VerifierRequest`. */
export async function toCloudflareVerifierRequest(request: Request): Promise<VerifierRequest> {
  const headers: Record<string, string | string[] | undefined> = {};
  request.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  let body: ArrayBuffer | undefined;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    try {
      // Clone so the original request body stays intact for downstream handlers.
      body = await request.clone().arrayBuffer();
    } catch {
      body = undefined;
    }
  }
  return { method: request.method, url: request.url, headers, body };
}

/** Verify a Worker request. Returns the normalized request + result on success. */
export async function verifyCloudflareRequest(
  request: Request,
  options: VerifyOptions = {},
): Promise<{ plain: VerifierRequest; result: VerificationResult }> {
  const plain = await toCloudflareVerifierRequest(request);
  const result = await verifyAgentRequest(plain, options);
  return { plain, result };
}

type WorkerHandler = (
  request: Request,
  env: CloudflareEnv,
  ctx: CloudflareContext,
  verified?: VerificationResult,
) => Response | Promise<Response>;

function jsonError(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Wrap a worker handler with verification. Handler receives the verified result. */
export function createCloudflareHandler(handler: WorkerHandler, options: VerifyOptions = {}): WorkerHandler {
  return async (request, env, ctx) => {
    try {
      const { result } = await verifyCloudflareRequest(request, options);
      const response = await handler(request, env, ctx, result);
      const headers = new Headers(response.headers);
      headers.set(HEADER_VERIFIED_AGENT, result.domain);
      if (result.manifest) {
        headers.set(HEADER_MANIFEST, formatResponseManifestHeader(result.manifest));
      }
      headers.set(HEADER_EXPOSE, EXPOSE_HEADERS_VALUE);
      return new Response(response.body, { status: response.status, headers });
    } catch (err) {
      if (err instanceof VerificationError) {
        return jsonError(err.statusCode, err.code, err.message);
      }
      // eslint-disable-next-line no-console
      console.error('[tls-agent-gate] verifier internal error', err);
      return jsonError(500, 'ERR_INTERNAL', 'Internal verification error');
    }
  };
}

export { VerificationError, VerificationErrorCode } from '../types.ts';
