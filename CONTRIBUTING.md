# Contributing

Thanks for helping! Bug reports, docs fixes, new framework adapters and features are all welcome.

## Setup

```bash
git clone https://github.com/nuhmanpk/generate-api-key
cd generate-api-key
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Checks (CI runs the same)

```bash
pytest -q                 # all tests, all frameworks
ruff check . && ruff format --check .
mypy                      # strict
bandit -q -r generateapikey generateApiKey.py
```

## Guidelines

- **No runtime dependencies.** Anything third-party goes behind an optional extra and a lazy import.
- **Security first.** Use `secrets` for randomness and `utils.safe_equals` for comparisons. Verifiers must return False/None on bad input, never raise. Add a test with hostile input.
- **Framework adapters stay thin.** Logic belongs in `generateapikey/integrations/__init__.py`. Test each adapter against the real framework, guarded by `pytest.importorskip`.
- **Docs:** when you change the public API, update `README.md`, `generateapikey/llms-full.txt` (the guide AI agents read) and `CHANGELOG.md`. `tests/test_docs.py` fails if a documented import doesn't exist.
- Supports Python 3.9+.

## Security issues

Please report them privately. See [SECURITY.md](SECURITY.md).
