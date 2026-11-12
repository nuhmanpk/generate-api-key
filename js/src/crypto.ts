/**
 * Encrypt secrets at rest (TOTP secrets, webhook secrets…) with AES-256-GCM (spec §11).
 * Same token format as Python's ``generateapikey.crypto.SecretBox``: a value
 * encrypted in one language decrypts in the other.
 */

import { b64url, b64urlDecode, concat, fromUtf8, isAscii, utf8 } from "./internal/bytes.js";
import { buf, digest, randomBytes, subtle } from "./internal/webcrypto.js";

const VERSION = "v1";

/** Ciphertext is malformed, was tampered with, or no key matches. */
export class DecryptionError extends Error {
  override name = "DecryptionError";
}

/** New random 256-bit key as URL-safe base64 (store it in env / a secret manager). */
export function generateEncryptionKey(): string {
  return b64url(randomBytes(32));
}

function loadKey(key: unknown): Uint8Array {
  const raw = typeof key === "string" ? b64urlDecode(key) : null;
  if (!raw || raw.length !== 32) throw new RangeError("encryption key must be 32 bytes, URL-safe base64 (use generateEncryptionKey()).");
  return raw;
}

async function keyId(raw: Uint8Array): Promise<string> {
  return b64url((await digest("SHA-256", concat(utf8("generateapikey.v1.keyid"), raw))).subarray(0, 6));
}

const aadBytes = (aad: string | null | undefined): Uint8Array<ArrayBuffer> | undefined => {
  if (aad == null) return undefined;
  if (typeof aad !== "string") throw new TypeError("aad must be a string.");
  return buf(utf8(aad));
};

/** AES-256-GCM encryption with key rotation. Create with ``await SecretBox.create(key, oldKeys)``. */
export class SecretBox {
  private constructor(
    private readonly currentId: string,
    private readonly keys: Map<string, CryptoKey>,
  ) {}

  /** ``key`` encrypts and decrypts; ``oldKeys`` only decrypt (rotation). */
  static async create(key: string, oldKeys: readonly string[] = []): Promise<SecretBox> {
    if (typeof oldKeys === "string") throw new TypeError("oldKeys must be an array of keys, not a string.");
    const keys = new Map<string, CryptoKey>();
    const add = async (k: string): Promise<string> => {
      const raw = loadKey(k);
      const id = await keyId(raw);
      if (!keys.has(id)) keys.set(id, await subtle().importKey("raw", buf(raw), "AES-GCM", false, ["encrypt", "decrypt"]));
      return id;
    };
    const currentId = await add(key);
    for (const k of oldKeys) await add(k);
    return new SecretBox(currentId, keys);
  }

  /** Id of the current key (8 chars), as embedded in tokens. */
  get keyId(): string {
    return this.currentId;
  }

  /** Encrypt ``plaintext``; ``aad`` (e.g. user id) must match on decrypt. */
  async encrypt(plaintext: string, aad?: string | null): Promise<string> {
    if (typeof plaintext !== "string") throw new TypeError("plaintext must be a string.");
    const nonce = randomBytes(12);
    const params: AesGcmParams = { name: "AES-GCM", iv: buf(nonce) };
    const ad = aadBytes(aad);
    if (ad) params.additionalData = ad;
    const ct = new Uint8Array(await subtle().encrypt(params, this.keys.get(this.currentId)!, buf(utf8(plaintext))));
    return `${VERSION}.${this.currentId}.${b64url(concat(nonce, ct))}`;
  }

  /** Decrypt a value from {@link encrypt}. Throws {@link DecryptionError}. */
  async decrypt(token: string, aad?: string | null): Promise<string> {
    if (typeof token !== "string" || !isAscii(token)) throw new DecryptionError("invalid ciphertext");
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== VERSION) throw new DecryptionError("invalid ciphertext");
    const key = this.keys.get(parts[1]!);
    if (!key) throw new DecryptionError("no key for this ciphertext (was it rotated out?)");
    const blob = b64urlDecode(parts[2]!);
    if (!blob || blob.length < 12 + 16) throw new DecryptionError("invalid ciphertext");
    try {
      const params: AesGcmParams = { name: "AES-GCM", iv: buf(blob.slice(0, 12)) };
      const ad = aadBytes(aad);
      if (ad) params.additionalData = ad;
      return fromUtf8(new Uint8Array(await subtle().decrypt(params, key, buf(blob.slice(12)))));
    } catch (e) {
      if (e instanceof TypeError && /aad/.test(e.message)) throw e;
      throw new DecryptionError("invalid ciphertext or associated data");
    }
  }

  /** True if ``token`` was encrypted with an old key; re-encrypt it. */
  needsRotation(token: unknown): boolean {
    const parts = typeof token === "string" ? token.split(".") : [];
    return parts.length === 3 && parts[1] !== this.currentId;
  }

  /** Re-encrypt ``token`` under the current key (no-op if already current). */
  async rotate(token: string, aad?: string | null): Promise<string> {
    if (!this.needsRotation(token)) return token;
    return this.encrypt(await this.decrypt(token, aad), aad);
  }

  /** Never shows key material. */
  toString(): string {
    return `SecretBox(keyId='${this.currentId}', keys=${this.keys.size})`;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}
