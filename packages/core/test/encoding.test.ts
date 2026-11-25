import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
  utf8Decode,
  utf8Encode,
} from '../src/encoding.ts';

test('bytesToBase64Url encodes RFC 4648 test vectors (unpadded)', () => {
  assert.equal(bytesToBase64Url(utf8Encode('')), '');
  assert.equal(bytesToBase64Url(utf8Encode('f')), 'Zg');
  assert.equal(bytesToBase64Url(utf8Encode('fo')), 'Zm8');
  assert.equal(bytesToBase64Url(utf8Encode('foo')), 'Zm9v');
  assert.equal(bytesToBase64Url(utf8Encode('foob')), 'Zm9vYg');
  assert.equal(bytesToBase64Url(utf8Encode('fooba')), 'Zm9vYmE');
  assert.equal(bytesToBase64Url(utf8Encode('foobar')), 'Zm9vYmFy');
});

test('base64UrlToBytes decodes and is the inverse of encode', () => {
  for (const s of ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
    const bytes = utf8Encode(s);
    assert.deepEqual(base64UrlToBytes(bytesToBase64Url(bytes)), bytes);
  }
});

test('base64url uses URL-safe alphabet (RFC 4648 §5)', () => {
  // 0xFF 0xFB 0xEF -> "//vv" in standard base64, "__vv" in URL-safe form
  assert.equal(bytesToBase64Url(new Uint8Array([0xff, 0xfb, 0xef])), '__vv');
  assert.deepEqual(base64UrlToBytes('__vv'), new Uint8Array([0xff, 0xfb, 0xef]));
});

test('base64UrlToBytes tolerates padded input', () => {
  assert.deepEqual(base64UrlToBytes('Zg=='), utf8Encode('f'));
});

test('bytesToHex / hexToBytes round-trip', () => {
  const bytes = new Uint8Array([0x00, 0x01, 0xab, 0xcd, 0xef, 0xff]);
  assert.equal(bytesToHex(bytes), '0001abcdefff');
  assert.deepEqual(hexToBytes('0001abcdefff'), bytes);
  assert.throws(() => hexToBytes('xyz'));
  assert.throws(() => hexToBytes('abc'));
});

test('utf8 round-trip with non-ASCII', () => {
  const s = 'héllo 👋 世界';
  assert.equal(utf8Decode(utf8Encode(s)), s);
});
