import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { qrAscii, qrMatrix, qrPng, qrSvg } from "../src/qr.js";

interface Reference {
  data: string;
  version: number;
  matrix: string[];
  ascii: string;
  asciiInvert: string;
}

// Generated from Python `qrcode` (QRCode(border=2, ERROR_CORRECT_M), add_data, make(fit=True)).
const refs: Reference[] = JSON.parse(
  readFileSync(new URL("./fixtures/qr-reference.json", import.meta.url), "utf8"),
);

const toBits = (m: boolean[][]): string[] => m.map((row) => row.map((v) => (v ? "1" : "0")).join(""));
const label = (s: string): string => JSON.stringify(s.length > 40 ? `${s.slice(0, 40)}... (${s.length})` : s);

describe("qrMatrix matches Python qrcode", () => {
  for (const ref of refs) {
    it(`matrix for ${label(ref.data)} (v${ref.version})`, () => {
      const m = qrMatrix(ref.data);
      expect(m.length).toBe(ref.version * 4 + 17 + 4);
      expect(toBits(m)).toEqual(ref.matrix);
    });
  }
});

describe("qrAscii matches Python print_ascii", () => {
  for (const ref of refs) {
    it(`ascii for ${label(ref.data)}`, () => {
      expect(qrAscii(ref.data)).toBe(ref.ascii);
      expect(qrAscii(ref.data, { invert: false })).toBe(ref.ascii);
      expect(qrAscii(ref.data, { invert: true })).toBe(ref.asciiInvert);
    });
  }
});

describe("qrMatrix", () => {
  it("throws when data exceeds version 40-M capacity", () => {
    expect(() => qrMatrix("q".repeat(2332))).toThrow(RangeError);
  });
});

describe("qrSvg", () => {
  const uri = "otpauth://totp/MyApp:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp";

  it("is a single-path SVG in module units", () => {
    const svg = qrSvg(uri);
    const size = qrMatrix(uri).length;
    expect(svg.startsWith("<?xml")).toBe(true);
    expect(svg).toContain(`viewBox="0 0 ${size} ${size}"`);
    expect(svg.match(/<path /g)?.length).toBe(1);
    expect(svg.trimEnd().endsWith("</svg>")).toBe(true);
  });

  it("draws one square per dark module", () => {
    const svg = qrSvg(uri);
    const dark = qrMatrix(uri).flat().filter(Boolean).length;
    expect(svg.match(/M\d+,\d+H\d+V\d+H\d+z/g)?.length).toBe(dark);
  });
});

// Minimal PNG reader for the format qrPng writes (stored deflate, 1-bit gray).
function readPng(png: Uint8Array): { width: number; height: number; pixel: (x: number, y: number) => number } {
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  expect(Array.from(png.subarray(0, 8))).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  let off = 8;
  let width = 0;
  let height = 0;
  const idat: Uint8Array[] = [];
  const types: string[] = [];
  while (off < png.length) {
    const len = view.getUint32(off);
    const type = String.fromCharCode(...png.subarray(off + 4, off + 8));
    types.push(type);
    const body = png.subarray(off + 8, off + 8 + len);
    if (type === "IHDR") {
      width = view.getUint32(off + 8);
      height = view.getUint32(off + 12);
      expect(Array.from(body.subarray(8))).toEqual([1, 0, 0, 0, 0]);
    } else if (type === "IDAT") {
      idat.push(body);
    }
    off += 12 + len;
  }
  expect(types).toEqual(["IHDR", "IDAT", "IEND"]);
  const z = idat[0] as Uint8Array;
  expect(z[0]).toBe(0x78);
  const raw: number[] = [];
  let p = 2;
  for (;;) {
    const final = (z[p] as number) & 1;
    const len = (z[p + 1] as number) | ((z[p + 2] as number) << 8);
    raw.push(...z.subarray(p + 5, p + 5 + len));
    p += 5 + len;
    if (final) break;
  }
  const rowBytes = Math.ceil(width / 8) + 1;
  expect(raw.length).toBe(rowBytes * height);
  return {
    width,
    height,
    pixel: (x, y) => ((raw[y * rowBytes + 1 + (x >> 3)] as number) >> (7 - (x & 7))) & 1,
  };
}

describe("qrPng", () => {
  const uri = "otpauth://totp/MyApp:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp";

  it("encodes the matrix at 10 px per module by default", () => {
    const m = qrMatrix(uri);
    const img = readPng(qrPng(uri));
    expect(img.width).toBe(m.length * 10);
    expect(img.height).toBe(m.length * 10);
    let mismatches = 0;
    for (let y = 0; y < img.height; y++) {
      for (let x = 0; x < img.width; x++) {
        const dark = (m[Math.floor(y / 10)] as boolean[])[Math.floor(x / 10)];
        if (img.pixel(x, y) !== (dark ? 0 : 1)) mismatches++;
      }
    }
    expect(mismatches).toBe(0);
  });

  it("honours scale", () => {
    const m = qrMatrix(uri);
    const img = readPng(qrPng(uri, { scale: 3 }));
    expect(img.width).toBe(m.length * 3);
    expect(img.pixel(0, 0)).toBe(1);
    expect(img.pixel(2 * 3, 2 * 3)).toBe(0); // finder pattern corner
  });

  it("splits large images across several stored deflate blocks", () => {
    const data = "q".repeat(2331); // version 40, 1810 x 1810 px
    const img = readPng(qrPng(data));
    expect(img.width).toBe(181 * 10);
    expect(img.pixel(25, 25)).toBe(0);
    expect(img.pixel(img.width - 1, img.height - 1)).toBe(1);
  });

  it("rejects a bad scale", () => {
    expect(() => qrPng("x", { scale: 0 })).toThrow(RangeError);
    expect(() => qrPng("x", { scale: 1.5 })).toThrow(RangeError);
  });
});
