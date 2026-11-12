"""The old ``generateApiKey`` import name must keep working after the rename."""

import asyncio
import importlib
import sys
import warnings


def _fresh_import(name):
    for mod in [m for m in sys.modules if m == "generateApiKey" or m.startswith("generateApiKey.")]:
        del sys.modules[mod]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        module = importlib.import_module(name)
    return module, caught


def test_old_name_aliases_new_package():
    import generateapikey

    old, caught = _fresh_import("generateApiKey")
    assert old is generateapikey
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_old_from_imports_work():
    _fresh_import("generateApiKey")
    # importlib avoids import-sorting differences between case-sensitive and
    # case-insensitive filesystems (generateApiKey vs generateapikey).
    old = importlib.import_module("generateApiKey")
    old_mfa = importlib.import_module("generateApiKey.mfa")
    old_utils = importlib.import_module("generateApiKey.utils")

    assert callable(old_mfa.verify_totp)
    assert len(old.generate_api_key()) == 32
    assert "hex" in old_utils.CHARSETS
    assert asyncio.run(old.generateApiKey("s", "seed")).__class__.__name__ == "ApiKey"


def test_submodules_are_the_same_objects():
    import generateapikey.utils

    _fresh_import("generateApiKey")
    import generateApiKey.utils

    assert generateApiKey.utils is generateapikey.utils


def test_version_matches_pyproject():
    import pathlib
    import re

    import generateapikey

    text = (pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', text, re.M).group(1) == generateapikey.__version__


def test_root_files_copied_in_sync():
    """python/ carries copies of root files (the sdist can't reach above python/)."""
    import pathlib

    import pytest

    here = pathlib.Path(__file__).parents[1]
    root = here.parent
    if here.name != "python" or not (root / "AGENTS.md").is_file():
        pytest.skip("not running inside the monorepo checkout (e.g. from an sdist)")
    for name in ("LICENSE", "SECURITY.md", "CONTRIBUTING.md"):
        assert (here / name).read_bytes() == (root / name).read_bytes(), f"python/{name} is out of sync with /{name}"
    if (root / "js" / "LICENSE").exists():
        assert (root / "js" / "LICENSE").read_bytes() == (root / "LICENSE").read_bytes(), (
            "js/LICENSE is out of sync with /LICENSE"
        )


def test_version_matches_npm_package():
    """PyPI and npm releases carry the same version number."""
    import json
    import pathlib

    import pytest

    import generateapikey

    pkg = pathlib.Path(__file__).parents[2] / "js" / "package.json"
    if not pkg.is_file():
        pytest.skip("not running inside the monorepo checkout")
    assert json.loads(pkg.read_text(encoding="utf-8"))["version"] == generateapikey.__version__
