/**
 * SHA-256 helpers built on Web Crypto (`crypto.subtle.digest`).
 */
import { bytesToHex, utf8Encode } from './encoding.ts';

/** SHA-256 digest. Accepts strings (UTF-8), bytes, or ArrayBuffers. */
export async function sha256(data: string | Uint8Array | ArrayBuffer): Promise<Uint8Array> {
  let source: Uint8Array | ArrayBuffer;
  if (typeof data === 'string') {
    source = utf8Encode(data);
  } else if (data instanceof Uint8Array) {
    source = data;
  } else {
    source = data;
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', source as BufferSource);
  return new Uint8Array(digest);
}

/** SHA-256 as lowercase hex. Used for `bodySha256` / `manifestSha256` in signatures. */
export async function sha256Hex(data: string | Uint8Array | ArrayBuffer): Promise<string> {
  return bytesToHex(await sha256(data));
}
