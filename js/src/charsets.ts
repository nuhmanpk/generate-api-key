/** Named character sets, charset resolution and entropy (spec §1). */

const lower = "abcdefghijklmnopqrstuvwxyz";
const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const digits = "0123456789";

/** Named character sets available via the ``charset`` option. Same as Python's ``CHARSETS``. */
export const CHARSETS = Object.freeze({
  alphanumeric: lower + upper + digits,
  base62: digits + upper + lower,
  alphabetic: lower + upper,
  numeric: digits,
  hex: digits + "abcdef",
  base16: digits + "ABCDEF",
  base32: upper + "234567",
  crockford: "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
  base64url: lower + upper + digits + "-_",
  // base58 = base62 minus the ambiguous chars 0, O, I and l
  base58: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  // letters and digits that are hard to confuse when read aloud or by eye
  unambiguous: "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz",
} as const);

export type CharsetName = keyof typeof CHARSETS;
export type Case = "mixed" | "lower" | "upper";

const AMBIGUOUS = new Set(["0", "O", "1", "I", "l"]);
const NO_AMBIGUOUS = new Set(["base58", "unambiguous", "crockford"]);

/** A resolved alphabet: its code points, plus whether the fast byte path applies. */
export interface Alphabet {
  readonly chars: string;
  readonly points: readonly string[];
  readonly ascii: boolean;
}

const cache = new Map<string, Alphabet>();

/**
 * Resolve a preset name (or a literal string of characters) and apply ``case``.
 * Duplicates are removed (first occurrence kept) so every character is equally
 * likely. Throws for fewer than 2 distinct characters or an unknown case.
 */
export function buildCharset(charset: CharsetName | (string & {}) = "alphanumeric", caseMode: Case = "mixed"): string {
  return alphabet(charset, caseMode).chars;
}

/** @internal */
export function alphabet(charset: string, caseMode: Case = "mixed"): Alphabet {
  if (typeof charset !== "string") throw new TypeError("charset must be a string.");
  const id = caseMode + "\u0000" + charset;
  const hit = cache.get(id);
  if (hit) return hit;
  let chars: string = Object.prototype.hasOwnProperty.call(CHARSETS, charset) ? CHARSETS[charset as CharsetName] : charset;
  if (caseMode === "lower") chars = chars.toLowerCase();
  else if (caseMode === "upper") chars = chars.toUpperCase();
  else if (caseMode !== "mixed") throw new RangeError("case must be one of 'mixed', 'lower', 'upper'.");
  let points = Array.from(chars);
  if (NO_AMBIGUOUS.has(charset) && caseMode !== "mixed") points = points.filter((c) => !AMBIGUOUS.has(c));
  points = [...new Set(points)];
  if (points.length < 2) throw new RangeError(`charset must contain at least 2 distinct characters: ${JSON.stringify(charset)}`);
  const result: Alphabet = Object.freeze({
    chars: points.join(""),
    points: Object.freeze(points),
    ascii: points.every((c) => c.length === 1 && c.charCodeAt(0) < 0x80),
  });
  if (cache.size < 256) cache.set(id, result);
  return result;
}

/** Bits of entropy in a random key of ``length`` drawn from ``charset``. */
export function entropyBits(length: number, charset: CharsetName | (string & {}) = "alphanumeric", caseMode: Case = "mixed"): number {
  return length * Math.log2(alphabet(charset, caseMode).points.length);
}
