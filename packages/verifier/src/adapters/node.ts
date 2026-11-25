/**
 * Node/Express/Connect adapter: `createVerifierMiddleware`.
 *
 * Usage (Express):
 *   import express from 'express';
 *   import { createVerifierMiddleware } from '@tls-agent-gate/verifier/node';
 *
 *   app.use(express.raw({ limit: '1mb' })); // reads raw body as Buffer — required
 *   app.use('/api/agent', createVerifierMiddleware({ allowLocalAgents: false }));
 *
 * Important: the verifier needs the raw request body bytes because the
 * caller signs the SHA-256 of exactly those bytes. Mount `express.raw()`
 * (or `connect.raw()`) BEFORE this middleware. If you use `express.json()`
 * the parsed object is not byte-identical to what was signed.
 */
import {
  EXPOSE_HEADERS_VALUE,
  HEADER_EXPOSE,
  HEADER_MANIFEST,
  HEADER_VERIFIED_AGENT,
} from '@tls-agent-gate/core';
import {
  VerificationError,
  VerificationErrorCode,
  type VerificationResult,
  type VerifierRequest,
  type VerifyOptions,
} from '../types.ts';
import { formatResponseManifestHeader, verifyAgentRequest } from '../verify.ts';

export type NodeHandler = (req: unknown, res: unknown, next: (err?: unknown) => void) => void;

export interface NodeMiddlewareOptions extends VerifyOptions {
  /** Called after successful verification (before next()). */
  onVerified?: (req: Record<string, unknown>, result: VerificationResult) => void;
}

function convertHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[] | undefined> {
  const out: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v;
  }
  return out;
}

function readRawBody(req: { body?: unknown }): VerifierRequest['body'] {
  const body = req.body;
  if (body === undefined || body === null) return undefined;
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) {
    return body as string | Uint8Array;
  }
  if (body instanceof ArrayBuffer) return body;
  throw new VerificationError(
    VerificationErrorCode.BodyUnavailable,
    'Raw request body is unavailable (mount express.raw()/connect.raw() before the verifier).',
    400,
  );
}

/**
 * Express/Connect-style middleware. Mount after a raw body parser.
 */
export function createVerifierMiddleware(options: NodeMiddlewareOptions = {}): NodeHandler {
  return async (req: unknown, res: unknown, next: (err?: unknown) => void) => {
    const nodeReq = req as Record<string, unknown> & { method: string; url: string; headers: Record<string, string | string[] | undefined>; body?: unknown };
    const nodeRes = res as { setHeader?: (name: string, value: string) => void; status?: (code: number) => { json: (body: unknown) => void }; end?: (body?: unknown) => void };

    try {
      const body = readRawBody(nodeReq);
      const result = await verifyAgentRequest(
        {
          method: nodeReq.method,
          url: (nodeReq.originalUrl as string) || nodeReq.url,
          headers: convertHeaders(nodeReq.headers),
          body,
        },
        options,
      );

      if (nodeRes.setHeader) {
        nodeRes.setHeader(HEADER_VERIFIED_AGENT, result.domain);
        if (result.manifest) {
          nodeRes.setHeader(HEADER_MANIFEST, formatResponseManifestHeader(result.manifest));
        }
        nodeRes.setHeader(HEADER_EXPOSE, EXPOSE_HEADERS_VALUE);
      }
      nodeReq.verifiedAgent = result;
      options.onVerified?.(nodeReq, result);
      next();
    } catch (err) {
      if (err instanceof VerificationError) {
        if (nodeRes.status) {
          nodeRes.status(err.statusCode).json({ error: { code: err.code, message: err.message } });
        } else if (nodeRes.end) {
          nodeRes.end(JSON.stringify({ error: { code: err.code, message: err.message } }));
        } else {
          next(err);
        }
        return;
      }
      // Unexpected error: log safely, never leak internals to callers.
      // eslint-disable-next-line no-console
      console.error('[tls-agent-gate] verifier internal error', err);
      if (nodeRes.status) {
        nodeRes.status(500).json({ error: { code: 'ERR_INTERNAL', message: 'Internal verification error' } });
      } else if (nodeRes.end) {
        nodeRes.end(JSON.stringify({ error: { code: 'ERR_INTERNAL', message: 'Internal verification error' } }));
      } else {
        next(err);
      }
    }
  };
}

export { VerificationError, VerificationErrorCode } from '../types.ts';
