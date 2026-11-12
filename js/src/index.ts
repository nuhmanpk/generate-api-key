/**
 * generateapikey — secure API keys and MFA on Web Crypto, zero dependencies.
 * Wire-compatible with the Python package (spec v1): keys, hashes, codes,
 * tokens and ciphertexts made in one language verify in the other.
 *
 * @example
 * import { generateApiKey, hashApiKey, verifyApiKey } from "@nuhmanpk/generateapikey";
 * const key = generateApiKey({ prefix: "sk", checksum: true });
 * const stored = await hashApiKey(key);        // store this, never the raw key
 * await verifyApiKey(key, stored);              // true
 *
 * @packageDocumentation
 */

/** Package version. */
export const VERSION = "0.6.0";
/** Wire-format spec version implemented (spec/SPEC.md). */
export const SPEC_VERSION = 1;

export { CHARSETS, buildCharset, entropyBits, type Case, type CharsetName } from "./charsets.js";
export {
  ApiKey,
  CHECKSUM_LENGTH,
  KDF_ITERATIONS,
  RECOMMENDED_ENTROPY,
  addDashes,
  computeChecksum,
  deriveApiKey,
  generateApiKey,
  generateApiKeys,
  hashApiKey,
  hashCode,
  isExpired,
  randomKey,
  subkey,
  verifyApiKey,
  verifyChecksum,
  verifyCode,
  type DeriveOptions,
  type ExpiringKeyOptions,
  type KeyFormatOptions,
  type KeyOptions,
} from "./keys.js";
export {
  AttemptLimiter,
  REDIS_LIMITER_SCRIPT,
  RECOVERY_ALPHABET,
  RedisAttemptLimiter,
  findTotpStep,
  generateOtp,
  generateRecoveryCodes,
  generateTotpSecret,
  googleMigrationUri,
  hashOtp,
  hashRecoveryCode,
  hotp,
  hotpUri,
  normalizeRecoveryCode,
  steamCode,
  totp,
  totpNow,
  totpUri,
  verifyHotp,
  verifyOtp,
  verifyRecoveryCode,
  verifySteamCode,
  verifyTotp,
  type HotpOptions,
  type MigrationAccount,
  type OtpAlgorithm,
  type OtpSecret,
  type RedisLike,
  type TotpOptions,
  type VerifyTotpOptions,
} from "./mfa.js";
export {
  MIN_SECRET_LENGTH,
  decodeJwt,
  decodeJwtJwks,
  encodeJwt,
  generateSignedToken,
  verifySignedToken,
  type AsymAlg,
  type AsymKey,
  type DecodeJwtOptions,
  type EncodeJwtOptions,
  type HsAlg,
  type Jwks,
  type JwtAlgorithm,
  type SignedTokenOptions,
  type TokenMeta,
} from "./tokens.js";
export { hasAllScopes, hasAnyScope, hasScope, parseScopes, type Scopes } from "./scopes.js";
export { findKeys, gitleaksRule, keyPattern, keyRegExp, type KeyPatternOptions } from "./scanning.js";
export { DecryptionError, SecretBox, generateEncryptionKey } from "./crypto.js";
export {
  APIKeyAuth,
  AuthError,
  MAX_KEY_LENGTH,
  issueApiKey,
  keyHint,
  pathExcluded,
  recordIsActive,
  rotateApiKey,
  type APIKeyAuthOptions,
  type HeadersLike,
  type IssueOptions,
  type IssuedKey,
  type LimiterLike,
  type QueryLike,
  type Rotation,
} from "./auth.js";
export {
  KEYSTORE_SCHEMA,
  KeyStore,
  MemoryKeyStorage,
  SqlKeyStorage,
  isKeyActive,
  type CreateOptions,
  type CreatedKey,
  type KeyRecord,
  type KeyRow,
  type KeyStorage,
  type SqlDriver,
} from "./keystore.js";
export { safeEquals as timingSafeEqual } from "./internal/bytes.js";
export { clearKeyCache } from "./internal/webcrypto.js";
