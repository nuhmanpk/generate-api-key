"""Micro-benchmarks. Run: python benchmarks/bench.py"""

from __future__ import annotations

import string
import timeit
from secrets import choice

from generateapikey import generate_api_key, hash_api_key, verify_api_key
from generateapikey.mfa import generate_totp_secret, hash_otp, totp, verify_totp
from generateapikey.utils import random_key

N = 20_000
ALNUM = string.ascii_letters + string.digits


def bench(label: str, fn, n: int = N) -> float:
    t = min(timeit.repeat(fn, number=n, repeat=3)) / n
    print(f"{label:<44} {t * 1e6:9.2f} us/op   {1 / t:>12,.0f} ops/s")
    return t


def main() -> None:
    print(f"{'operation':<44} {'time':>12}   {'throughput':>16}")
    naive = bench("baseline: ''.join(secrets.choice) x32", lambda: "".join(choice(ALNUM) for _ in range(32)))
    fast = bench("random_key(32)  (rejection sampling)", lambda: random_key(32, ALNUM))
    print(f"{'  -> speed-up vs baseline':<44} {naive / fast:9.1f}x")
    bench("generate_api_key()", generate_api_key)
    bench("generate_api_key(prefix, checksum)", lambda: generate_api_key(prefix="sk", checksum=True))
    bench("generate_api_key(secret, seed)  derived", lambda: generate_api_key("s" * 32, "user-1"))
    key = generate_api_key()
    stored = hash_api_key(key, "pepper")
    bench("verify_api_key (HMAC-SHA256)", lambda: verify_api_key(key, stored, "pepper"))
    secret = generate_totp_secret()
    code = totp(secret)
    bench("verify_totp (window=1)", lambda: verify_totp(secret, code))
    bench("hash_otp (PBKDF2 100k, deliberately slow)", lambda: hash_otp("123456"), n=20)


if __name__ == "__main__":
    main()
