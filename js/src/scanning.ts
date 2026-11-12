/**
 * Make leaked keys findable (spec §8): regexes for secret scanners and a
 * ``findKeys`` helper. Keys with a distinctive prefix and a checksum are easy
 * for GitHub secret scanning, gitleaks or trufflehog to detect.
 */

import { type Case, type CharsetName, alphabet } from "./charsets.js";
import { CHECKSUM_LENGTH, verifyChecksum } from "./keys.js";

const CHECKSUM_CLASS = "[0-9A-Za-z]";
const PY_SPECIAL = new Set("()[]{}?*+-|^$\\.&~# \t\n\r\v\f");

/** Python's ``re.escape``. */
function pyEscape(s: string): string {
  return Array.from(s, (c) => (PY_SPECIAL.has(c) ? "\\" + c : c)).join("");
}

/** Escaping that is valid in a JS ``u``-mode regex (``-`` needs no escape outside a class). */
function jsEscape(s: string): string {
  return s.replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&");
}

function klass(chars: readonly string[], esc: (c: string) => string): string {
  return "[" + chars.map((c) => ("\\]^-[".includes(c) ? esc(c) : c)).join("") + "]";
}

export interface KeyPatternOptions {
  length?: number;
  separator?: string;
  charset?: CharsetName | (string & {});
  case?: Case;
  checksum?: boolean;
}

function parts(prefix: string, o: KeyPatternOptions): { chars: readonly string[]; length: number; sep: string; checksum: boolean } {
  if (typeof prefix !== "string" || !prefix) throw new RangeError("prefix must be a non-empty string (a prefix is what makes keys detectable).");
  const length = o.length ?? 32;
  if (!Number.isInteger(length) || length < 1) throw new RangeError("length must be a positive integer.");
  return { chars: alphabet(o.charset ?? "alphanumeric", o.case ?? "mixed").points, length, sep: o.separator ?? "-", checksum: o.checksum ?? true };
}

/**
 * Regex **source** matching keys from ``generateApiKey`` — the exact same
 * string Python's ``key_pattern`` returns (Python ``re`` / PCRE syntax).
 * For use in JavaScript, call {@link keyRegExp}.
 */
export function keyPattern(prefix: string, options: KeyPatternOptions = {}): string {
  const p = parts(prefix, options);
  const body = klass(p.chars, (c) => "\\" + c) + `{${p.length}}`;
  const tail = p.checksum ? `${CHECKSUM_CLASS}{${CHECKSUM_LENGTH}}` : "";
  return `(?<![0-9A-Za-z_-])${pyEscape(prefix + p.sep)}${body}${tail}(?![0-9A-Za-z_-])`;
}

/** A JavaScript ``RegExp`` (flags ``gu``) equivalent to {@link keyPattern}. */
export function keyRegExp(prefix: string, options: KeyPatternOptions = {}): RegExp {
  const p = parts(prefix, options);
  const body = klass(p.chars, (c) => "\\" + c) + `{${p.length}}`;
  const tail = p.checksum ? `${CHECKSUM_CLASS}{${CHECKSUM_LENGTH}}` : "";
  return new RegExp(`(?<![0-9A-Za-z_\\-])${jsEscape(prefix + p.sep)}${body}${tail}(?![0-9A-Za-z_\\-])`, "gu");
}

/**
 * All keys found in ``text`` (unique, in order). With ``validate`` (default)
 * and checksums on, candidates must also pass {@link verifyChecksum}.
 */
export function findKeys(text: unknown, prefix: string, options: KeyPatternOptions & { validate?: boolean } = {}): string[] {
  const re = keyRegExp(prefix, options);
  if (typeof text !== "string") return [];
  let found = [...text.matchAll(re)].map((m) => m[0]);
  if ((options.validate ?? true) && (options.checksum ?? true)) found = found.filter((k) => verifyChecksum(k));
  return [...new Set(found)];
}

/** A ``[[rules]]`` TOML block for ``.gitleaks.toml`` that detects your keys. */
export function gitleaksRule(prefix: string, ruleId: string, options: KeyPatternOptions & { description?: string } = {}): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(ruleId ?? "")) throw new RangeError("rule_id must be letters, digits, '.', '_' or '-'.");
  const regex = keyPattern(prefix, options).replace("(?<![0-9A-Za-z_-])", "").replace("(?![0-9A-Za-z_-])", "");
  const desc = options.description || `${prefix} API key`;
  return `[[rules]]\nid = "${ruleId}"\ndescription = "${desc}"\nregex = '''${regex}'''\nkeywords = ["${prefix}"]\n`;
}
