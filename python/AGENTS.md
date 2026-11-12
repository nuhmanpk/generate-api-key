# AGENTS.md

Guidance for AI coding agents working **on** the Python package (`python/` in the monorepo; see the root `AGENTS.md` for the repo layout and `spec/SPEC.md` for the cross-language wire formats). To *use* the library, read [generateapikey/llms-full.txt](generateapikey/llms-full.txt).

## Project

`generateapikey` is a zero-dependency Python (>= 3.9) library for API keys and MFA. It is published to PyPI as `generateapikey`.

```
generateapikey/
  __init__.py     generate_api_key, ApiKey, batch/async, legacy generateApiKey(), re-exports
  utils.py        charsets, unbiased rejection sampling, derivation, checksum, hashing
  mfa.py          TOTP/HOTP, recovery codes, OTP, AttemptLimiter
  tokens.py       signed expiring tokens
  qr.py           QR output (optional `qrcode` extra, imported lazily)
  crypto.py       SecretBox (AES-GCM) for secrets at rest  [crypto extra]
  limiters.py     Redis attempt limiters (atomic Lua)       [redis extra]
  integrations/   __init__ = framework-agnostic APIKeyAuth core; adapters: fastapi starlette django drf
                  flask litestar sanic aiohttp quart falcon
                  (each imports its framework at module import -> only loaded when the user imports it)
  __main__.py     CLI (`generate-api-key`)
  llms-full.txt   LLM usage guide, shipped in the wheel, printed by `--llms`
generateApiKey.py back-compat alias for the old import name; keep it working
tests/            pytest; test_compat.py guards the old import name and version sync;
                  test_docs.py guards documented imports; test_examples.py runs examples/
examples/, benchmarks/
```

## Commands

```bash
cd python
pip install -e ".[dev]"            # test deps + every extra + ruff/mypy/bandit/pre-commit
pytest -q                          # passes on 3.9-3.14
ruff check . && ruff format --check . && mypy && bandit -q -r generateapikey generateApiKey.py
python -m build && twine check dist/*
```

## Rules

- **No runtime dependencies.** Use the standard library only. Anything else goes behind an optional extra and a lazy import, like `qr.py`.
- **Security primitives:** use `secrets` for randomness, `utils.safe_equals` (bytes `hmac.compare_digest`, never raises) for every secret comparison, and rejection sampling for alphabet mapping (never `byte % n`). Verification loops must not exit early on a match.
- **Public API is stable.** Don't rename or remove exported names or change defaults without a deprecation path and a CHANGELOG entry. The legacy `generateApiKey()` and the `generateApiKey` module alias must keep working.
- **Version lives in two places:** `pyproject.toml` and `generateapikey/__init__.py`. A test enforces that they match. Don't switch to `attr:` dynamic versioning: on case-insensitive filesystems setuptools resolves it to the `generateApiKey.py` alias.
- **When adding a public function:** add it to `__all__`, give it a typed signature and docstring, write tests, and update README.md, `generateapikey/llms-full.txt` and CHANGELOG.md.
- **Framework adapters stay thin.** All auth logic lives in `integrations/__init__.py` so every framework behaves the same. Adapters only map request -> `extract`/`authenticate` and `AuthError` -> response. Test each adapter against the real framework (`pytest.importorskip`).
- **MFA code must match the RFCs.** Keep the RFC 4226/6238 test vectors in `tests/test_mfa.py` passing.
- Supported Python is 3.9+. Use `from __future__ import annotations` and `typing.Optional`/`Union` rather than runtime `X | Y`.
