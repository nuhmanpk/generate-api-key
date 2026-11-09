"""Head-to-head benchmarks against popular libraries.

Run: pip install pyotp itsdangerous pyjwt shortuuid nanoid && python benchmarks/compare.py
Libraries that are not installed are skipped. Pass --markdown for README tables.
"""

from __future__ import annotations

import secrets
import string
import sys
import time
import timeit
from typing import Callable

import generateapikey as g

N = 20_000
ALNUM = string.ascii_letters + string.digits
SECRET = "s" * 32


def t(fn: Callable[[], object], n: int = N) -> float:
    fn()
    return min(timeit.repeat(fn, number=n, repeat=5)) / n


def sections() -> list[tuple[str, list[tuple[str, float]]]]:
    out: list[tuple[str, list[tuple[str, float]]]] = []

    gen = [
        ("generateapikey `generate_api_key()`", t(g.generate_api_key)),
        (
            "generateapikey `generate_api_key(prefix, checksum)`",
            t(lambda: g.generate_api_key(prefix="sk", checksum=True)),
        ),
        ("`secrets.token_urlsafe(32)`", t(lambda: secrets.token_urlsafe(32))),
        ("`secrets.choice` loop (32 chars)", t(lambda: "".join(secrets.choice(ALNUM) for _ in range(32)))),
    ]
    try:
        import shortuuid

        gen.append(("`shortuuid.uuid()`", t(shortuuid.uuid)))
    except ImportError:
        pass
    try:
        import nanoid

        gen.append(("`nanoid.generate()`", t(nanoid.generate)))
    except ImportError:
        pass
    out.append(("Generate a key", gen))

    key = g.generate_api_key()
    stored = g.hash_api_key(key, "pepper")
    out.append(
        (
            "Verify a stored key",
            [("generateapikey `verify_api_key`", t(lambda: g.verify_api_key(key, stored, "pepper")))],
        )
    )

    mfa = []
    secret = g.generate_totp_secret()
    code = g.totp_now(secret)
    mfa.append(("generateapikey `verify_totp`", t(lambda: g.verify_totp(secret, code))))
    mfa.append(("generateapikey `totp_uri`", t(lambda: g.totp_uri(secret, "a@b.c", "App"))))
    try:
        import pyotp

        p = pyotp.TOTP(secret)
        mfa.append(("pyotp `TOTP.verify`", t(lambda: p.verify(code, valid_window=1))))
        mfa.append(("pyotp `provisioning_uri`", t(lambda: p.provisioning_uri("a@b.c", "App"))))
    except ImportError:
        pass
    out.append(("TOTP", mfa))

    tok = []
    token = g.generate_signed_token(SECRET, {"u": 1}, expiry=60)
    tok.append(
        ("generateapikey `generate_signed_token`", t(lambda: g.generate_signed_token(SECRET, {"u": 1}, expiry=60)))
    )
    tok.append(("generateapikey `verify_signed_token`", t(lambda: g.verify_signed_token(token, SECRET))))
    try:
        from itsdangerous import URLSafeTimedSerializer

        s = URLSafeTimedSerializer(SECRET)
        it = s.dumps({"u": 1})
        tok.append(("itsdangerous `dumps`", t(lambda: s.dumps({"u": 1}))))
        tok.append(("itsdangerous `loads`", t(lambda: s.loads(it, max_age=60))))
    except ImportError:
        pass
    try:
        import jwt

        jt = jwt.encode({"u": 1, "exp": int(time.time()) + 600}, SECRET, algorithm="HS256")
        tok.append(
            (
                "PyJWT `encode` (HS256)",
                t(lambda: jwt.encode({"u": 1, "exp": int(time.time()) + 600}, SECRET, algorithm="HS256")),
            )
        )
        tok.append(("PyJWT `decode` (HS256)", t(lambda: jwt.decode(jt, SECRET, algorithms=["HS256"]))))
    except ImportError:
        pass
    out.append(("Signed, expiring tokens", tok))
    return out


def main() -> None:
    md = "--markdown" in sys.argv
    for title, rows in sections():
        best = min(v for _, v in rows)
        if md:
            print(f"\n**{title}**\n\n| Library / call | µs per op | ops/s | vs fastest |\n|---|--:|--:|--:|")
        else:
            print(f"\n{title}")
        for name, v in sorted(rows, key=lambda r: r[1]):
            if md:
                cells = [name, f"{v * 1e6:.2f}", f"{1 / v:,.0f}", f"{v / best:.1f}×"]
                if name.startswith("generateapikey"):  # highlight our rows
                    cells = [f"**{c}**" for c in cells]
                print("| " + " | ".join(cells) + " |")
            else:
                print(f"  {name:<52} {v * 1e6:9.2f} us  {1 / v:>12,.0f} ops/s")


if __name__ == "__main__":
    main()
