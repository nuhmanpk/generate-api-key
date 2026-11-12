/**
 * JSON serialisation matching Python's ``json.dumps(obj, separators=(",", ":"))``
 * with the default ``ensure_ascii=True``: non-ASCII is escaped as ``\uXXXX``,
 * floats use Python's ``repr``, optional ``sort_keys`` by code point. This makes
 * newly signed tokens byte-identical to the Python package's output.
 */

function escapeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

/** Python ``float.__repr__`` for a finite JS number that isn't an integer. */
function pyFloat(x: number): string {
  // toExponential() without an argument yields the shortest round-trip digits, like repr.
  const [mant, expStr] = x.toExponential().split("e") as [string, string];
  const exp = Number(expStr);
  const neg = mant.startsWith("-");
  const digits = mant.replace("-", "").replace(".", "");
  let body: string;
  if (exp < -4 || exp >= 16) {
    const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    body = `${m}e${exp < 0 ? "-" : "+"}${String(Math.abs(exp)).padStart(2, "0")}`;
  } else if (exp < 0) {
    body = `0.${"0".repeat(-exp - 1)}${digits}`;
  } else if (digits.length > exp + 1) {
    body = `${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
  } else {
    body = `${digits}${"0".repeat(exp + 1 - digits.length)}.0`;
  }
  return (neg ? "-" : "") + body;
}

function number(x: number): string {
  if (Number.isNaN(x)) return "NaN";
  if (x === Infinity) return "Infinity";
  if (x === -Infinity) return "-Infinity";
  // JSON has one number type; integral values are written as ints (Python ints).
  if (Number.isInteger(x)) return Object.is(x, -0) ? "-0.0" : BigInt(x).toString();
  return pyFloat(x);
}

const cmpCodePoints = (a: string, b: string): number => {
  const A = Array.from(a);
  const B = Array.from(b);
  for (let i = 0; i < Math.min(A.length, B.length); i++) {
    const d = A[i]!.codePointAt(0)! - B[i]!.codePointAt(0)!;
    if (d) return d;
  }
  return A.length - B.length;
};

export function pyDumps(value: unknown, sortKeys = false): string {
  if (value === null || value === undefined) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return number(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) return "[" + value.map((v) => pyDumps(v, sortKeys)).join(",") + "]";
  if (typeof value === "object") {
    const maybe = value as { toJSON?: () => unknown };
    if (typeof maybe.toJSON === "function") return pyDumps(maybe.toJSON(), sortKeys);
    let keys = Object.keys(value).filter((k) => (value as Record<string, unknown>)[k] !== undefined);
    if (sortKeys) keys = keys.sort(cmpCodePoints);
    return "{" + keys.map((k) => escapeString(k) + ":" + pyDumps((value as Record<string, unknown>)[k], sortKeys)).join(",") + "}";
  }
  throw new TypeError(`Object of type ${typeof value} is not JSON serializable`);
}

/** Python ``str()`` of a JSON-decoded primitive (used for the token purpose check). */
export function pyStr(v: unknown): string {
  if (typeof v === "string") return v;
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "number") return number(v);
  return pyDumps(v);
}
