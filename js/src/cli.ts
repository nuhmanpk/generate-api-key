/**
 * Command line interface (Node.js): ``npx @nuhmanpk/generateapikey`` / ``generate-api-key``.
 * Same commands and flags as the Python CLI.
 *
 *   generate-api-key [options]          API keys (default)
 *   generate-api-key totp ...           new authenticator secret + setup URI/QR
 *   generate-api-key code SECRET        current TOTP code for a secret
 *   generate-api-key recovery ...       recovery codes
 *   generate-api-key otp ...            email/SMS one-time code
 *   generate-api-key token ...          signed magic-link token
 */

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import {
  CHARSETS,
  VERSION,
  deriveApiKey,
  entropyBits,
  generateApiKey,
  generateApiKeys,
  generateOtp,
  generateRecoveryCodes,
  generateSignedToken,
  generateTotpSecret,
  hashApiKey,
  hashOtp,
  hashRecoveryCode,
  totp,
  totpUri,
  type Case,
  type OtpAlgorithm,
} from "./index.js";

// Secrets on the command line leak via `ps`, shell history and CI logs, so every
// secret option also reads from an environment variable or stdin ("-").
const ENV_SECRET = "GENERATEAPIKEY_SECRET";
const ENV_PEPPER = "GENERATEAPIKEY_PEPPER";
const ENV_TOTP_SECRET = "GENERATEAPIKEY_TOTP_SECRET";

const AGENT_RULES = `## API keys, MFA and tokens

Use the \`generateapikey\` package (\`npm i @nuhmanpk/generateapikey\` / \`pip install generateapikey\`) instead of
hand-rolling crypto.getRandomValues / Math.random / uuid code for API keys, 2FA/TOTP, recovery codes,
one-time codes, magic links, signed tokens or JWTs. Zero-dependency, typed, Web Crypto only.
- Don't guess its API: run \`npx @nuhmanpk/generateapikey --llms\` (full guide for the installed version).
- Store only hashes (\`await hashApiKey(key)\`), verify with \`verify*\` (constant-time), never compare with ===.
- Encrypt TOTP secrets at rest (\`SecretBox\`) and rate-limit every code check (\`AttemptLimiter\`).
- Web apps: use the adapters (@nuhmanpk/generateapikey/hono, /express, /fastify, /koa, /next, /web) instead of writing key auth by hand.`;

let stdinCache: string[] | null = null;
function stdinLine(): string {
  stdinCache ??= readFileSync(0, "utf8").split(/\r?\n/);
  return stdinCache.shift() ?? "";
}

function resolve(value: string | undefined, env: string): string | undefined {
  if (value === "-") return stdinLine();
  if (value === undefined) return process.env[env] || undefined;
  return value;
}

const num = (v: string | undefined, d: number): number => (v === undefined ? d : Number(v));

function emit(json: boolean, data: unknown, text: string): void {
  console.log(json ? JSON.stringify(data, null, 2) : text);
}

const KEY_HELP = `usage: generate-api-key [options]

Generate secure API keys and MFA secrets.

options:
  -n, --count N          number of keys (default 1)
  -l, --length N         body length (default 32)
  -c, --charset NAME     preset (${Object.keys(CHARSETS).join(", ")}) or literal characters
      --case CASE        mixed | lower | upper
  -p, --prefix PREFIX    prefix, e.g. sk
      --separator S      between prefix and body (default -)
  -d, --dashes           group body with dashes
      --dash-group N     (default 4)
      --checksum         append 6-char CRC32 checksum
      --expiry MINUTES   expiry in minutes
      --secret S         derive deterministically from secret + seed ('-' = stdin, or $${ENV_SECRET})
      --seed S           seed for derived keys
      --include S        extra context for derived keys
      --hash             also print sha256 hash for storage
      --pepper P         server-side pepper for --hash ('-' = stdin, or $${ENV_PEPPER})
      --json             output JSON
      --entropy          print entropy bits and exit
      --llms             print the usage guide for AI coding agents and exit
      --agent-rules      print a snippet for AGENTS.md / CLAUDE.md / .cursor/rules and exit
  -V, --version          print version
  -h, --help             show this help

MFA commands (run '<command> -h' for options):
  totp       new authenticator-app secret, setup URI and QR
  code       current TOTP code for a secret
  recovery   single-use recovery codes
  otp        email/SMS one-time code
  token      signed magic-link / verification token`;

async function runKeys(argv: string[]): Promise<number> {
  const { values: a } = parseArgs({
    args: argv,
    options: {
      count: { type: "string", short: "n" },
      length: { type: "string", short: "l" },
      charset: { type: "string", short: "c" },
      case: { type: "string" },
      prefix: { type: "string", short: "p" },
      separator: { type: "string" },
      dashes: { type: "boolean", short: "d" },
      "dash-group": { type: "string" },
      checksum: { type: "boolean" },
      expiry: { type: "string" },
      secret: { type: "string" },
      seed: { type: "string" },
      include: { type: "string" },
      hash: { type: "boolean" },
      pepper: { type: "string" },
      json: { type: "boolean" },
      entropy: { type: "boolean" },
      llms: { type: "boolean" },
      "agent-rules": { type: "boolean" },
      version: { type: "boolean", short: "V" },
      help: { type: "boolean", short: "h" },
    },
    strict: true,
  });
  if (a.help) return void console.log(KEY_HELP), 0;
  if (a.version) return void console.log(`generate-api-key ${VERSION}`), 0;
  if (a["agent-rules"]) return void console.log(AGENT_RULES), 0;
  if (a.llms) return void console.log(readFileSync(new URL("../llms.txt", import.meta.url), "utf8")), 0;
  const length = num(a.length, 32);
  const charset = a.charset ?? "alphanumeric";
  const caseMode = (a.case ?? "mixed") as Case;
  if (a.entropy) return void console.log(entropyBits(length, charset, caseMode).toFixed(1)), 0;
  const secret = a.seed !== undefined ? resolve(a.secret, ENV_SECRET) : a.secret;
  const pepper = resolve(a.pepper, ENV_PEPPER);
  const fmt = {
    length,
    charset,
    case: caseMode,
    prefix: a.prefix ?? null,
    separator: a.separator ?? "-",
    dashes: !!a.dashes,
    dashGroup: num(a["dash-group"], 4),
    checksum: !!a.checksum,
  };
  const expiry = a.expiry === undefined ? undefined : Number(a.expiry);
  const onWeakKey = (m: string): void => console.error(`warning: ${m}`);
  let keys: { key: string; expiresAt: number | null }[];
  if (secret !== undefined || a.seed !== undefined) {
    if (!secret || !a.seed) throw new RangeError("Provide both 'secret' and 'seed', or neither.");
    const k = expiry === undefined ? await deriveApiKey({ ...fmt, secret, seed: a.seed, include: a.include ?? null }) : await deriveApiKey({ ...fmt, secret, seed: a.seed, include: a.include ?? null, expiry });
    keys = [{ key: String(k), expiresAt: typeof k === "string" ? null : k.expiresAt }];
  } else {
    if (a.include) throw new RangeError("--include requires --secret and --seed.");
    const count = num(a.count, 1);
    if (expiry === undefined) keys = generateApiKeys(count, { ...fmt, onWeakKey }).map((key) => ({ key, expiresAt: null }));
    else keys = Array.from({ length: count }, (_, i) => generateApiKey({ ...fmt, expiry, onWeakKey: i ? false : onWeakKey })).map((k) => ({ key: k.value, expiresAt: k.expiresAt }));
  }
  if (a.json) {
    const rows = await Promise.all(
      keys.map(async (k) => ({ key: k.key, ...(k.expiresAt !== null ? { expires_at: k.expiresAt } : {}), ...(a.hash ? { hash: await hashApiKey(k.key, pepper) } : {}) })),
    );
    console.log(JSON.stringify(rows.length === 1 ? rows[0] : rows, null, 2));
  } else {
    for (const k of keys) console.log(a.hash ? `${k.key}\t${await hashApiKey(k.key, pepper)}` : k.key);
  }
  return 0;
}

async function runMfa(command: string, argv: string[]): Promise<number> {
  const { values: a, positionals } = parseArgs({
    args: argv,
    allowPositionals: command === "code",
    options: {
      json: { type: "boolean" },
      help: { type: "boolean", short: "h" },
      account: { type: "string", short: "a" },
      issuer: { type: "string", short: "i" },
      digits: { type: "string" },
      period: { type: "string" },
      algorithm: { type: "string" },
      qr: { type: "boolean" },
      count: { type: "string", short: "n" },
      length: { type: "string", short: "l" },
      hash: { type: "boolean" },
      pepper: { type: "string" },
      expiry: { type: "string" },
      secret: { type: "string", short: "s" },
      purpose: { type: "string" },
      data: { type: "string" },
    },
    strict: true,
  });
  if (a.help) {
    console.log(`usage: generate-api-key ${command} [options]  (same options as the Python CLI; see README)`);
    return 0;
  }
  const json = !!a.json;
  const pepper = resolve(a.pepper, ENV_PEPPER);
  const algorithm = (a.algorithm ?? "sha1") as OtpAlgorithm;
  if (command === "totp") {
    if (!a.account) throw new RangeError("the following arguments are required: -a/--account");
    const secret = generateTotpSecret();
    const uri = totpUri(secret, a.account, a.issuer ?? null, { digits: num(a.digits, 6), period: num(a.period, 30), algorithm });
    emit(json, { secret, uri }, `secret: ${secret}\nuri:    ${uri}`);
    if (a.qr) {
      const { qrAscii } = await import("./qr.js");
      (json ? console.error : console.log)(qrAscii(uri));
    }
  } else if (command === "code") {
    const secret = resolve(positionals[0], ENV_TOTP_SECRET);
    if (!secret) throw new RangeError(`pass the secret as an argument, '-' (stdin) or $${ENV_TOTP_SECRET}.`);
    const period = num(a.period, 30);
    const code = await totp(secret, null, { digits: num(a.digits, 6), period, algorithm });
    const left = period - (Math.floor(Date.now() / 1000) % period);
    emit(json, { code, valid_for: left }, `${code}  (${left}s left)`);
  } else if (command === "recovery") {
    const codes = generateRecoveryCodes(num(a.count, 10), num(a.length, 10));
    if (json) console.log(JSON.stringify(await Promise.all(codes.map(async (code) => ({ code, ...(a.hash ? { hash: await hashRecoveryCode(code, pepper) } : {}) }))), null, 2));
    else for (const c of codes) console.log(a.hash ? `${c}\t${await hashRecoveryCode(c, pepper)}` : c);
  } else if (command === "otp") {
    const code = generateOtp(num(a.digits, 6), num(a.expiry, 10));
    const data: Record<string, unknown> = { code: code.value, expires_at: code.expiresAt };
    if (a.hash) data.hash = await hashOtp(code, pepper);
    emit(json, data, a.hash ? `${code.value}\t${data.hash}` : code.value);
  } else if (command === "token") {
    const secret = resolve(a.secret, ENV_SECRET);
    if (!secret) throw new RangeError(`pass --secret, '-' (stdin) or $${ENV_SECRET}.`);
    const payload: unknown = JSON.parse(a.data ?? "{}");
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new RangeError("--data must be a JSON object.");
    const token = await generateSignedToken(secret, payload as Record<string, unknown>, { purpose: a.purpose ?? "default", expiry: num(a.expiry, 15) });
    emit(json, { token }, token);
  }
  return 0;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  try {
    const [first, ...rest] = argv;
    if (first && ["totp", "code", "recovery", "otp", "token"].includes(first)) return await runMfa(first, rest);
    return await runKeys(argv);
  } catch (e) {
    console.error(`error: ${(e as Error).message}`);
    return 2;
  }
}

main().then((code) => {
  process.exitCode = code;
});
