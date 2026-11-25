// RFC 6238 TOTP (HMAC-SHA1, 30-second steps, 6 digits) for driving TOTP enrolment and login in the
// e2e suite, plus the RFC 4648 base32 decoding of the shared secret.

import { createHmac } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decodes RFC 4648 base32 (case-insensitive; padding, spaces and dashes ignored). */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) {
      throw new Error(`invalid base32 character ${JSON.stringify(ch)}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** Encodes bytes as unpadded RFC 4648 base32. */
export function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** RFC 4226 HOTP value for `counter`. */
export function hotp(secret: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];
  return (code % 10 ** digits).toString().padStart(digits, '0');
}

/**
 * The RFC 6238 TOTP code (SHA-1, 30 s, 6 digits) for a base32 secret at Unix time `unixSeconds`
 * (default: now).
 */
export function totp(base32Secret: string, unixSeconds: number = Date.now() / 1000): string {
  return hotp(base32Decode(base32Secret), Math.floor(unixSeconds / 30));
}
