"""Backwards-compatible alias: ``import generateApiKey`` -> ``generateapikey``.

The package was renamed to lowercase in 0.5.0. Old imports keep working,
including submodules such as ``generateApiKey.utils``.
"""

import importlib
import sys
import warnings

import generateapikey as _pkg

warnings.warn(
    "'generateApiKey' was renamed to 'generateapikey'; update your imports.",
    DeprecationWarning,
    stacklevel=2,
)

# Submodules that existed (or were documented) under the old name. Optional-
# dependency modules (crypto, limiters, integrations) are not aliased.
for _name in ("utils", "mfa", "tokens", "qr"):
    sys.modules[f"{__name__}.{_name}"] = importlib.import_module(f"generateapikey.{_name}")
sys.modules[__name__] = _pkg
