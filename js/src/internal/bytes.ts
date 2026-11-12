/** Byte, text and encoding helpers. Web platform APIs only (no Buffer, no node:*). */

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

/** Strict UTF-8 decode; throws on invalid input. */
export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const HEX: string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

export function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += HEX[b[i]!];
  return s;
}

export function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function be32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

export function be64(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

/** True if every UTF-16 unit is < 0x80 (same as Python's ``str.isascii``). */
export function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) return false;
  return true;
}

/** Number of Unicode code points (Python ``len(str)``). */
export function cpLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** Code-point aware slice (Python ``s[start:end]`` for non-negative/negative indexes). */
export function cpSlice(s: string, start: number, end?: number): string {
  if (isAscii(s)) return s.slice(start, end);
  return Array.from(s).slice(start, end).join("");
}

// ---------------------------------------------------------------------------
// base64 / base64url
// ---------------------------------------------------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DEC_URL = new Int16Array(128).fill(-1);
for (let i = 0; i < 64; i++) DEC_URL[B64URL.charCodeAt(i)] = i;

function encode64(b: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + alphabet[n & 63]!;
  }
  const rest = b.length - i;
  if (rest === 1) {
    const n = b[i]! << 16;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + (pad ? "==" : "");
  } else if (rest === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + (pad ? "=" : "");
  }
  return out;
}

/** base64url without padding. */
export function b64url(b: Uint8Array): string {
  return encode64(b, B64URL, false);
}

/** Standard base64 with padding. */
export function b64std(b: Uint8Array): string {
  return encode64(b, B64, true);
}

/**
 * Strict base64url decode. Accepts optional trailing ``=`` padding (like
 * Python's decoder after re-padding) and rejects every other non-alphabet
 * character. Returns null on invalid input.
 */
export function b64urlDecode(s: string): Uint8Array | null {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 61 /* = */) end--;
  const pads = s.length - end;
  if (pads > 2) return null;
  if (pads && (end + pads) % 4 !== 0) return null;
  const rem = end % 4;
  if (rem === 1) return null;
  const out = new Uint8Array(((end * 3) >> 2) | 0);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < end; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? DEC_URL[c]! : -1;
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

// ---------------------------------------------------------------------------
// base32 (RFC 4648), matching Python's base64.b32encode / b32decode
// ---------------------------------------------------------------------------

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** base32 without padding. */
export function b32encode(b: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const byte of b) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

/**
 * Decode padded base32 exactly like Python's ``base64.b32decode`` (no casefold):
 * the length must be a multiple of 8, padding must be one of the valid amounts
 * and appear only at the end. Returns null on invalid input.
 */
export function b32decodePadded(s: string): Uint8Array | null {
  if (s.length % 8 !== 0) return null;
  let end = s.length;
  while (end > 0 && s[end - 1] === "=") end--;
  const pad = s.length - end;
  // Valid amounts of padding in the last quantum: 0, 1, 3, 4, 6.
  if (![0, 1, 3, 4, 6].includes(pad)) return null;
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < end; i++) {
    const v = B32.indexOf(s[i]!);
    if (v < 0) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/** Constant-time byte comparison (length leaks, contents don't). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Constant-time string comparison that never throws (like Python's
 * ``utils.safe_equals``): compares UTF-8 bytes; non-strings are unequal.
 */
export function safeEquals(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return bytesEqual(utf8(a), utf8(b));
}

// ---------------------------------------------------------------------------
// CRC-32 (zlib)
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
