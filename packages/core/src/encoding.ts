/**
 * Encoding helpers (base64url, hex, UTF-8) with no dependencies beyond
 * standard Web APIs so this module runs unchanged in browsers, edge
 * workers, and modern Node.
 *
 * `btoa`/`atob` are global in browsers and Node >= 16, and `TextEncoder`/
 * `TextDecoder` are global in both.
 */

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Encode bytes as unpadded base64url (RFC 4648 §5). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  // btoa takes a binary string; chunk to avoid stack limits on large inputs.
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode unpadded base64url into bytes. Accepts padded input too. */
export function base64UrlToBytes(input: string): Uint8Array {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  // Restore padding.
  const pad = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(pad);
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const HEX_ALPHABET = '0123456789abcdef';

/** Encode bytes as lowercase hex. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const hi = bytes[i]! >> 4;
    const lo = bytes[i]! & 0xf;
    out += HEX_ALPHABET.charAt(hi) + HEX_ALPHABET.charAt(lo);
  }
  return out;
}

/** Decode a hex string into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new TypeError('Invalid hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** UTF-8 encode. */
export function utf8Encode(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value);
}

/** UTF-8 decode. Decodes replacement characters for invalid sequences. */
export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** Generate `n` cryptographically random bytes. */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Generate a hex nonce of `nBytes` (default 16). */
export function randomHexNonce(nBytes = 16): string {
  return bytesToHex(randomBytes(nBytes));
}

export { BASE64_ALPHABET };
