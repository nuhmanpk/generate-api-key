/**
 * Zero-dependency QR code encoder for MFA setup (otpauth:// URIs).
 *
 * Mirrors the Python `generateapikey.qr` module, which uses the `qrcode`
 * package with `QRCode(border=2, error_correction=ERROR_CORRECT_M)`,
 * `add_data(data)` and `make(fit=True)`. The encoder reproduces that
 * library's behaviour so the produced matrices are identical:
 *
 * - data is UTF-8 encoded and split into numeric / alphanumeric / byte
 *   segments exactly like `qrcode.util.optimal_data_chunks(minimum=20)`;
 * - the smallest version (1-40) that fits at error correction level M is used;
 * - the mask is chosen by the ISO/IEC 18004 penalty rules, evaluated the way
 *   `qrcode` does it (format/version areas blank while scoring).
 *
 * Uses only `Uint8Array` and `TextEncoder`, so it runs in browsers, Node,
 * Deno, Bun and Cloudflare Workers.
 *
 * @module
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MODE_NUMBER = 1;
const MODE_ALPHA_NUM = 2;
const MODE_8BIT_BYTE = 4;

/** Quiet-zone width in modules (matches `QRCode(border=2)`). */
const BORDER = 2;

/** Optimisation threshold used by `qrcode`'s `add_data(optimize=20)`. */
const OPTIMIZE_MIN = 20;

const ALPHA_NUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/** Error-correction level M format indicator bits (00). */
const EC_LEVEL_M_BITS = 0;

/**
 * RS block layout for ECC level M, versions 1..40:
 * groups of (count, totalCodewords, dataCodewords).
 */
const RS_BLOCKS_M: readonly (readonly number[])[] = [
  [1, 26, 16], [1, 44, 28], [1, 70, 44], [2, 50, 32], [2, 67, 43],
  [4, 43, 27], [4, 49, 31], [2, 60, 38, 2, 61, 39], [3, 58, 36, 2, 59, 37],
  [4, 69, 43, 1, 70, 44], [1, 80, 50, 4, 81, 51], [6, 58, 36, 2, 59, 37],
  [8, 59, 37, 1, 60, 38], [4, 64, 40, 5, 65, 41], [5, 65, 41, 5, 66, 42],
  [7, 73, 45, 3, 74, 46], [10, 74, 46, 1, 75, 47], [9, 69, 43, 4, 70, 44],
  [3, 70, 44, 11, 71, 45], [3, 67, 41, 13, 68, 42], [17, 68, 42], [17, 74, 46],
  [4, 75, 47, 14, 76, 48], [6, 73, 45, 14, 74, 46], [8, 75, 47, 13, 76, 48],
  [19, 74, 46, 4, 75, 47], [22, 73, 45, 3, 74, 46], [3, 73, 45, 23, 74, 46],
  [21, 73, 45, 7, 74, 46], [19, 75, 47, 10, 76, 48], [2, 74, 46, 29, 75, 47],
  [10, 74, 46, 23, 75, 47], [14, 74, 46, 21, 75, 47], [14, 74, 46, 23, 75, 47],
  [12, 75, 47, 26, 76, 48], [6, 75, 47, 34, 76, 48], [29, 74, 46, 14, 75, 47],
  [13, 74, 46, 32, 75, 47], [40, 75, 47, 7, 76, 48], [18, 75, 47, 31, 76, 48],
];

const ALIGNMENT_POSITIONS: readonly (readonly number[])[] = [
  [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42],
  [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62],
  [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78],
  [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90], [6, 28, 50, 72, 94],
  [6, 26, 50, 74, 98], [6, 30, 54, 78, 102], [6, 28, 54, 80, 106],
  [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118],
  [6, 26, 50, 74, 98, 122], [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130],
  [6, 30, 56, 82, 108, 134], [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142],
  [6, 34, 62, 90, 118, 146], [6, 30, 54, 78, 102, 126, 150],
  [6, 24, 50, 76, 102, 128, 154], [6, 28, 54, 80, 106, 132, 158],
  [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166],
  [6, 30, 58, 86, 114, 142, 170],
];

/** Data capacity in bits for each version at level M (index 0 unused). */
const BIT_LIMITS_M: readonly number[] = [0].concat(
  RS_BLOCKS_M.map((groups) => {
    let total = 0;
    for (let i = 0; i < groups.length; i += 3) {
      total += (groups[i] as number) * (groups[i + 2] as number);
    }
    return total * 8;
  }),
);

// ---------------------------------------------------------------------------
// Galois field GF(256) and Reed-Solomon
// ---------------------------------------------------------------------------

const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  EXP[255] = EXP[0] as number;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[((LOG[a] as number) + (LOG[b] as number)) % 255] as number;
}

const generatorCache = new Map<number, Uint8Array>();

/** Generator polynomial of degree `n`, highest-order coefficient first. */
function rsGenerator(n: number): Uint8Array {
  const cached = generatorCache.get(n);
  if (cached) return cached;
  let poly: Uint8Array = new Uint8Array([1]);
  for (let i = 0; i < n; i++) {
    const next: Uint8Array = new Uint8Array(poly.length + 1);
    const root = EXP[i] as number;
    for (let j = 0; j < poly.length; j++) {
      const c = poly[j] as number;
      next[j] = (next[j] as number) ^ c;
      next[j + 1] = (next[j + 1] as number) ^ gfMul(c, root);
    }
    poly = next;
  }
  generatorCache.set(n, poly);
  return poly;
}

/** Reed-Solomon error-correction codewords for `data`. */
function rsEncode(data: Uint8Array, ecCount: number): Uint8Array {
  const gen = rsGenerator(ecCount);
  const rem = new Uint8Array(ecCount);
  for (let i = 0; i < data.length; i++) {
    const factor = (data[i] as number) ^ (rem[0] as number);
    rem.copyWithin(0, 1);
    rem[ecCount - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < ecCount; j++) {
        rem[j] = (rem[j] as number) ^ gfMul(gen[j + 1] as number, factor);
      }
    }
  }
  return rem;
}

// ---------------------------------------------------------------------------
// Segmentation (mirrors qrcode.util.optimal_data_chunks)
// ---------------------------------------------------------------------------

interface Segment {
  mode: number;
  bytes: Uint8Array;
}

function isDigit(b: number): boolean {
  return b >= 0x30 && b <= 0x39;
}

function isAlphaNum(b: number): boolean {
  return b < 0x80 && ALPHA_NUM.includes(String.fromCharCode(b));
}

/**
 * Split `data` into alternating [matched, bytes] pieces, mirroring
 * `qrcode.util._optimal_split` with the regexes built by
 * `optimal_data_chunks`.
 */
function optimalSplit(
  data: Uint8Array,
  test: (b: number) => boolean,
  short: boolean,
  minimum: number,
): [boolean, Uint8Array][] {
  const out: [boolean, Uint8Array][] = [];
  if (data.length === 0) return out;
  if (short) {
    // Python regex `^X+$`: `$` also matches before one trailing "\n".
    // "\n" is never in either class, so a trailing one is simply excluded.
    const end = data[data.length - 1] === 0x0a ? data.length - 1 : data.length;
    let match = end > 0;
    for (let i = 0; i < end && match; i++) if (!test(data[i] as number)) match = false;
    if (match) {
      out.push([true, data.subarray(0, end)]);
      if (end < data.length) out.push([false, data.subarray(end)]);
    } else {
      out.push([false, data]);
    }
    return out;
  }
  // Pattern `X{minimum,}`: leftmost run of at least `minimum`, greedy.
  let pos = 0;
  let i = 0;
  while (i < data.length) {
    if (!test(data[i] as number)) {
      i++;
      continue;
    }
    let j = i;
    while (j < data.length && test(data[j] as number)) j++;
    if (j - i >= minimum) {
      if (i > pos) out.push([false, data.subarray(pos, i)]);
      out.push([true, data.subarray(i, j)]);
      pos = j;
    }
    i = j;
  }
  if (pos < data.length) out.push([false, data.subarray(pos)]);
  return out;
}

function optimalSegments(data: Uint8Array, minimum = OPTIMIZE_MIN): Segment[] {
  const short = data.length <= minimum;
  const segments: Segment[] = [];
  for (const [isNum, chunk] of optimalSplit(data, isDigit, short, minimum)) {
    if (isNum) {
      segments.push({ mode: MODE_NUMBER, bytes: chunk });
      continue;
    }
    for (const [isAlpha, sub] of optimalSplit(chunk, isAlphaNum, short, minimum)) {
      segments.push({ mode: isAlpha ? MODE_ALPHA_NUM : MODE_8BIT_BYTE, bytes: sub });
    }
  }
  return segments;
}

// ---------------------------------------------------------------------------
// Bit buffer and codeword construction
// ---------------------------------------------------------------------------

class BitBuffer {
  bytes: number[] = [];
  length = 0;

  put(num: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) this.putBit(((num >>> i) & 1) === 1);
  }

  putBit(bit: boolean): void {
    const idx = this.length >>> 3;
    if (this.bytes.length <= idx) this.bytes.push(0);
    if (bit) this.bytes[idx] = (this.bytes[idx] as number) | (0x80 >>> (this.length & 7));
    this.length++;
  }
}

function lengthBits(mode: number, version: number): number {
  if (version < 10) return mode === MODE_NUMBER ? 10 : mode === MODE_ALPHA_NUM ? 9 : 8;
  if (version < 27) return mode === MODE_NUMBER ? 12 : mode === MODE_ALPHA_NUM ? 11 : 16;
  return mode === MODE_NUMBER ? 14 : mode === MODE_ALPHA_NUM ? 13 : 16;
}

function sizeClass(version: number): number {
  return version < 10 ? 0 : version < 27 ? 1 : 2;
}

function writeSegments(buf: BitBuffer, segments: Segment[], version: number): void {
  for (const seg of segments) {
    const d = seg.bytes;
    buf.put(seg.mode, 4);
    buf.put(d.length, lengthBits(seg.mode, version));
    if (seg.mode === MODE_NUMBER) {
      for (let i = 0; i < d.length; i += 3) {
        const n = Math.min(3, d.length - i);
        let value = 0;
        for (let k = 0; k < n; k++) value = value * 10 + ((d[i + k] as number) - 0x30);
        buf.put(value, n === 3 ? 10 : n === 2 ? 7 : 4);
      }
    } else if (seg.mode === MODE_ALPHA_NUM) {
      for (let i = 0; i < d.length; i += 2) {
        const a = ALPHA_NUM.indexOf(String.fromCharCode(d[i] as number));
        if (i + 1 < d.length) {
          const b = ALPHA_NUM.indexOf(String.fromCharCode(d[i + 1] as number));
          buf.put(a * 45 + b, 11);
        } else {
          buf.put(a, 6);
        }
      }
    } else {
      for (let i = 0; i < d.length; i++) buf.put(d[i] as number, 8);
    }
  }
}

/** Smallest version that fits, mirroring `QRCode.best_fit`. */
function bestFit(segments: Segment[], start = 1): number {
  const buf = new BitBuffer();
  writeSegments(buf, segments, start);
  const needed = buf.length;
  let version = start;
  while (version <= 40 && (BIT_LIMITS_M[version] as number) < needed) version++;
  if (version > 40) {
    throw new RangeError(`QR data too long: ${needed} bits exceeds version 40-M capacity`);
  }
  if (sizeClass(version) !== sizeClass(start)) return bestFit(segments, version);
  return version;
}

function createCodewords(version: number, segments: Segment[]): Uint8Array {
  const buf = new BitBuffer();
  writeSegments(buf, segments, version);
  const bitLimit = BIT_LIMITS_M[version] as number;
  if (buf.length > bitLimit) throw new RangeError("QR data overflow");
  for (let i = 0, n = Math.min(bitLimit - buf.length, 4); i < n; i++) buf.putBit(false);
  while (buf.length % 8 !== 0) buf.putBit(false);
  const fill = (bitLimit - buf.length) >>> 3;
  for (let i = 0; i < fill; i++) buf.put(i % 2 === 0 ? 0xec : 0x11, 8);

  const groups = RS_BLOCKS_M[version - 1] as readonly number[];
  const dcBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;
  let maxDc = 0;
  let maxEc = 0;
  for (let g = 0; g < groups.length; g += 3) {
    const count = groups[g] as number;
    const total = groups[g + 1] as number;
    const dc = groups[g + 2] as number;
    for (let k = 0; k < count; k++) {
      const block = Uint8Array.from(buf.bytes.slice(offset, offset + dc));
      offset += dc;
      dcBlocks.push(block);
      ecBlocks.push(rsEncode(block, total - dc));
      maxDc = Math.max(maxDc, dc);
      maxEc = Math.max(maxEc, total - dc);
    }
  }
  const out: number[] = [];
  for (let i = 0; i < maxDc; i++) for (const b of dcBlocks) if (i < b.length) out.push(b[i] as number);
  for (let i = 0; i < maxEc; i++) for (const b of ecBlocks) if (i < b.length) out.push(b[i] as number);
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// Matrix construction
// ---------------------------------------------------------------------------

/** Module grid: 0 = light, 1 = dark, -1 = not yet set. */
type Grid = Int8Array[];

function bitLength(n: number): number {
  let d = 0;
  while (n !== 0) {
    d++;
    n >>>= 1;
  }
  return d;
}

function bchTypeInfo(data: number): number {
  const G15 = 0b10100110111;
  let d = data << 10;
  while (bitLength(d) - bitLength(G15) >= 0) d ^= G15 << (bitLength(d) - bitLength(G15));
  return ((data << 10) | d) ^ 0b101010000010010;
}

function bchTypeNumber(data: number): number {
  const G18 = 0b1111100100101;
  let d = data << 12;
  while (bitLength(d) - bitLength(G18) >= 0) d ^= G18 << (bitLength(d) - bitLength(G18));
  return (data << 12) | d;
}

function maskBit(pattern: number, i: number, j: number): boolean {
  switch (pattern) {
    case 0: return (i + j) % 2 === 0;
    case 1: return i % 2 === 0;
    case 2: return j % 3 === 0;
    case 3: return (i + j) % 3 === 0;
    case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
    case 5: return ((i * j) % 2) + ((i * j) % 3) === 0;
    case 6: return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0;
    default: return (((i * j) % 3) + ((i + j) % 2)) % 2 === 0;
  }
}

function blankGrid(version: number): Grid {
  const n = version * 4 + 17;
  const m: Grid = [];
  for (let r = 0; r < n; r++) m.push(new Int8Array(n).fill(-1));

  const probe = (row: number, col: number): void => {
    for (let r = -1; r < 8; r++) {
      if (row + r <= -1 || n <= row + r) continue;
      for (let c = -1; c < 8; c++) {
        if (col + c <= -1 || n <= col + c) continue;
        const dark =
          (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
          (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
          (r >= 2 && r <= 4 && c >= 2 && c <= 4);
        (m[row + r] as Int8Array)[col + c] = dark ? 1 : 0;
      }
    }
  };
  probe(0, 0);
  probe(n - 7, 0);
  probe(0, n - 7);

  const pos = ALIGNMENT_POSITIONS[version - 1] as readonly number[];
  for (const row of pos) {
    for (const col of pos) {
      if ((m[row] as Int8Array)[col] !== -1) continue;
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const dark = r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0);
          (m[row + r] as Int8Array)[col + c] = dark ? 1 : 0;
        }
      }
    }
  }

  for (let r = 8; r < n - 8; r++) {
    const rowArr = m[r] as Int8Array;
    if (rowArr[6] === -1) rowArr[6] = r % 2 === 0 ? 1 : 0;
  }
  const row6 = m[6] as Int8Array;
  for (let c = 8; c < n - 8; c++) if (row6[c] === -1) row6[c] = c % 2 === 0 ? 1 : 0;
  return m;
}

function setCell(m: Grid, r: number, c: number, dark: boolean): void {
  (m[r] as Int8Array)[c] = dark ? 1 : 0;
}

function buildMatrix(version: number, codewords: Uint8Array, mask: number, test: boolean): Grid {
  const m = blankGrid(version);
  const n = m.length;

  // Format information (vertical and horizontal copies).
  const typeBits = bchTypeInfo((EC_LEVEL_M_BITS << 3) | mask);
  for (let i = 0; i < 15; i++) {
    const mod = !test && ((typeBits >> i) & 1) === 1;
    if (i < 6) setCell(m, i, 8, mod);
    else if (i < 8) setCell(m, i + 1, 8, mod);
    else setCell(m, n - 15 + i, 8, mod);
  }
  for (let i = 0; i < 15; i++) {
    const mod = !test && ((typeBits >> i) & 1) === 1;
    if (i < 8) setCell(m, 8, n - i - 1, mod);
    else if (i < 9) setCell(m, 8, 15 - i - 1 + 1, mod);
    else setCell(m, 8, 15 - i - 1, mod);
  }
  setCell(m, n - 8, 8, !test);

  // Version information.
  if (version >= 7) {
    const bits = bchTypeNumber(version);
    for (let i = 0; i < 18; i++) {
      const mod = !test && ((bits >> i) & 1) === 1;
      setCell(m, Math.floor(i / 3), (i % 3) + n - 8 - 3, mod);
      setCell(m, (i % 3) + n - 8 - 3, Math.floor(i / 3), mod);
    }
  }

  // Data placement in the zig-zag order.
  let inc = -1;
  let row = n - 1;
  let bitIndex = 7;
  let byteIndex = 0;
  for (let start = n - 1; start > 0; start -= 2) {
    const col = start <= 6 ? start - 1 : start; // skip the vertical timing column
    for (;;) {
      for (let c = col; c >= col - 1; c--) {
        const rowArr = m[row] as Int8Array;
        if (rowArr[c] === -1) {
          let dark = false;
          if (byteIndex < codewords.length) {
            dark = (((codewords[byteIndex] as number) >> bitIndex) & 1) === 1;
          }
          if (maskBit(mask, row, c)) dark = !dark;
          rowArr[c] = dark ? 1 : 0;
          bitIndex--;
          if (bitIndex === -1) {
            byteIndex++;
            bitIndex = 7;
          }
        }
      }
      row += inc;
      if (row < 0 || n <= row) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
  return m;
}

// ---------------------------------------------------------------------------
// Mask penalty (mirrors qrcode.util.lost_point)
// ---------------------------------------------------------------------------

function lostPoint(m: Grid): number {
  const n = m.length;
  const at = (r: number, c: number): number => (m[r] as Int8Array)[c] as number;
  let points = 0;

  // Rule 1: runs of >= 5 same-colour modules, N1 + (len - 5) = len - 2.
  for (let r = 0; r < n; r++) {
    let prev = at(r, 0);
    let len = 0;
    for (let c = 0; c < n; c++) {
      if (at(r, c) === prev) len++;
      else {
        if (len >= 5) points += len - 2;
        len = 1;
        prev = at(r, c);
      }
    }
    if (len >= 5) points += len - 2;
  }
  for (let c = 0; c < n; c++) {
    let prev = at(0, c);
    let len = 0;
    for (let r = 0; r < n; r++) {
      if (at(r, c) === prev) len++;
      else {
        if (len >= 5) points += len - 2;
        len = 1;
        prev = at(r, c);
      }
    }
    if (len >= 5) points += len - 2;
  }

  // Rule 2: 2x2 blocks of the same colour.
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = at(r, c);
      if (v === at(r, c + 1) && v === at(r + 1, c) && v === at(r + 1, c + 1)) points += 3;
    }
  }

  // Rule 3: finder-like 1:1:3:1:1 patterns with 4 light modules on a side.
  const P1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const P2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  const matches = (get: (k: number) => number): boolean => {
    let a = true;
    let b = true;
    for (let k = 0; k < 11 && (a || b); k++) {
      const v = get(k);
      if (v !== P1[k]) a = false;
      if (v !== P2[k]) b = false;
    }
    return a || b;
  };
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n - 10; c++) if (matches((k) => at(r, c + k))) points += 40;
  }
  for (let c = 0; c < n; c++) {
    for (let r = 0; r < n - 10; r++) if (matches((k) => at(r + k, c))) points += 40;
  }

  // Rule 4: dark-module proportion.
  let dark = 0;
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) dark += at(r, c);
  const percent = dark / (n * n);
  points += Math.trunc(Math.abs(percent * 100 - 50) / 5) * 10;
  return points;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function encode(data: string): Grid {
  const segments = optimalSegments(new TextEncoder().encode(data));
  const version = bestFit(segments);
  const codewords = createCodewords(version, segments);
  let best = 0;
  let min = 0;
  for (let mask = 0; mask < 8; mask++) {
    const p = lostPoint(buildMatrix(version, codewords, mask, true));
    if (mask === 0 || min > p) {
      min = p;
      best = mask;
    }
  }
  return buildMatrix(version, codewords, best, false);
}

/**
 * Encode `data` as a QR code (ECC level M, smallest fitting version) and
 * return the module matrix, including the 2-module quiet border.
 *
 * Identical to Python's `qrcode.QRCode(border=2, error_correction=M)` +
 * `add_data(data)` + `make(fit=True)` + `get_matrix()`.
 *
 * @param data Text to encode (UTF-8), e.g. an `otpauth://` URI.
 * @returns Square matrix indexed `[row][col]`; `true` means a dark module.
 * @throws {RangeError} If the data does not fit in a version 40 code.
 */
export function qrMatrix(data: string): boolean[][] {
  const grid = encode(data);
  const size = grid.length + BORDER * 2;
  const out: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const row: boolean[] = new Array<boolean>(size).fill(false);
    const src = grid[r - BORDER];
    if (src) for (let c = 0; c < src.length; c++) row[c + BORDER] = src[c] === 1;
    out.push(row);
  }
  return out;
}

/**
 * Render a QR code as text for a terminal, two module rows per line using
 * half-block characters (`█`, `▀`, `▄` and U+00A0 no-break space).
 *
 * Output is identical to Python `qrcode`'s `print_ascii(invert=...)` with a
 * 2-module border, ending with `"\n"`.
 *
 * @param data Text to encode (UTF-8).
 * @param options.invert Swap dark and light characters (for dark-on-light
 *   terminals); the trailing half row is drawn as light border.
 * @returns The multi-line string.
 */
export function qrAscii(data: string, options: { invert?: boolean } = {}): string {
  const invert = options.invert === true;
  const grid = encode(data);
  const n = grid.length;
  // cp437 bytes 255, 223, 220, 219 as decoded by Python.
  const codes = [" ", "▀", "▄", "█"];
  if (invert) codes.reverse();
  const get = (x: number, y: number): number => {
    if (invert && Math.max(x, y) >= n + BORDER) return 1;
    if (Math.min(x, y) < 0 || Math.max(x, y) >= n) return 0;
    return (grid[x] as Int8Array)[y] as number;
  };
  let out = "";
  for (let r = -BORDER; r < n + BORDER; r += 2) {
    for (let c = -BORDER; c < n + BORDER; c++) {
      out += codes[get(r, c) + (get(r + 1, c) << 1)] as string;
    }
    out += "\n";
  }
  return out;
}

/**
 * Render a QR code as a standalone SVG document with a single `<path>`,
 * sized in module units (1 module = 1 unit = 1mm), like Python `qrcode`'s
 * `SvgPathImage`. Safe to embed directly in HTML.
 *
 * @param data Text to encode (UTF-8).
 * @returns The SVG markup.
 */
export function qrSvg(data: string): string {
  const matrix = qrMatrix(data);
  const size = matrix.length;
  let d = "";
  for (let r = 0; r < size; r++) {
    const row = matrix[r] as boolean[];
    for (let c = 0; c < size; c++) {
      if (row[c]) d += `M${c},${r}H${c + 1}V${r + 1}H${c}z`;
    }
  }
  return (
    `<?xml version='1.0' encoding='UTF-8'?>\n` +
    `<svg width="${size}mm" height="${size}mm" version="1.1" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">` +
    `<path d="${d}" id="qr-path" fill="#000000" fill-opacity="1" fill-rule="nonzero" stroke="none" /></svg>`
  );
}

// ---------------------------------------------------------------------------
// PNG encoding (CRC-32, Adler-32, zlib stored blocks)
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

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = (CRC_TABLE[(c ^ (bytes[i] as number)) & 0xff] as number) ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function adler32(bytes: Uint8Array): number {
  let a = 1;
  let b = 0;
  const MOD = 65521;
  for (let i = 0; i < bytes.length; ) {
    const end = Math.min(i + 5552, bytes.length);
    for (; i < end; i++) {
      a += bytes[i] as number;
      b += a;
    }
    a %= MOD;
    b %= MOD;
  }
  return ((b << 16) | a) >>> 0;
}

/** zlib stream using uncompressed ("stored") deflate blocks. */
function zlibStored(raw: Uint8Array): Uint8Array {
  const MAX = 65535;
  const blocks = Math.max(1, Math.ceil(raw.length / MAX));
  const out = new Uint8Array(2 + blocks * 5 + raw.length + 4);
  out[0] = 0x78;
  out[1] = 0x01;
  let o = 2;
  for (let i = 0; i < blocks; i++) {
    const start = i * MAX;
    const len = Math.min(MAX, raw.length - start);
    out[o++] = i === blocks - 1 ? 1 : 0;
    out[o++] = len & 0xff;
    out[o++] = len >>> 8;
    out[o++] = ~len & 0xff;
    out[o++] = (~len >>> 8) & 0xff;
    out.set(raw.subarray(start, start + len), o);
    o += len;
  }
  const ad = adler32(raw);
  out[o++] = ad >>> 24;
  out[o++] = (ad >>> 16) & 0xff;
  out[o++] = (ad >>> 8) & 0xff;
  out[o++] = ad & 0xff;
  return out;
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + data.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, data.length);
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  view.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)));
  return out;
}

/**
 * Render a QR code as a PNG image (1-bit grayscale, black on white,
 * including the 2-module quiet border), like Python `qrcode`'s `PyPNGImage`.
 *
 * Synchronous and dependency-free: image data is stored in uncompressed
 * deflate blocks, so files are larger than a compressed encoder would make
 * (roughly `(size*scale/8) * size*scale` bytes).
 *
 * @param data Text to encode (UTF-8).
 * @param options.scale Pixels per module (positive integer, default 10).
 * @returns The PNG file bytes.
 * @throws {RangeError} If `scale` is not a positive integer.
 */
export function qrPng(data: string, options: { scale?: number } = {}): Uint8Array {
  const scale = options.scale ?? 10;
  if (!Number.isInteger(scale) || scale < 1) {
    throw new RangeError("scale must be a positive integer");
  }
  const matrix = qrMatrix(data);
  const px = matrix.length * scale;
  const rowBytes = Math.ceil(px / 8);
  const raw = new Uint8Array((rowBytes + 1) * px);
  for (let y = 0; y < px; y++) {
    const mrow = matrix[Math.floor(y / scale)] as boolean[];
    const base = y * (rowBytes + 1);
    raw[base] = 0; // filter: none
    for (let x = 0; x < px; x++) {
      // 1 = white (light), 0 = black (dark).
      if (!mrow[Math.floor(x / scale)]) {
        const idx = base + 1 + (x >>> 3);
        raw[idx] = (raw[idx] as number) | (0x80 >>> (x & 7));
      }
    }
  }
  const ihdr = new Uint8Array(13);
  const v = new DataView(ihdr.buffer);
  v.setUint32(0, px);
  v.setUint32(4, px);
  ihdr[8] = 1; // bit depth
  ihdr[9] = 0; // colour type: grayscale
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace
  const parts = [
    new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlibStored(raw)),
    pngChunk("IEND", new Uint8Array(0)),
  ];
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
