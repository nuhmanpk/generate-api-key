"""Make leaked keys findable: regexes for secret scanners and a ``find_keys`` helper.

Keys with a distinctive ``prefix`` and a checksum are easy for GitHub secret
scanning, gitleaks or trufflehog to detect, and the checksum removes false
positives::

    from generateapikey.scanning import key_pattern, find_keys, gitleaks_rule

    key_pattern("sk")                      # regex string
    find_keys(log_text, "sk")              # only strings with a valid checksum
    print(gitleaks_rule("sk", "acme-api-key"))   # paste into .gitleaks.toml
"""

from __future__ import annotations

import re

from .utils import CHECKSUM_LENGTH, build_charset, verify_checksum

__all__ = ["find_keys", "gitleaks_rule", "key_pattern"]

_CHECKSUM_CLASS = "[0-9A-Za-z]"


def _class(chars: str) -> str:
    return "[" + "".join(re.escape(c) if c in "\\]^-[" else c for c in chars) + "]"


def key_pattern(
    prefix: str,
    *,
    length: int = 32,
    separator: str = "-",
    charset: str = "alphanumeric",
    case: str = "mixed",
    checksum: bool = True,
) -> str:
    """Regex (Python ``re`` / most engines) matching keys from ``generate_api_key``.

    Pass the same ``prefix``, ``length``, ``separator``, ``charset`` and
    ``checksum`` you issue keys with. The pattern doesn't match inside longer
    alphanumeric strings.
    """
    if not isinstance(prefix, str) or not prefix:
        raise ValueError("prefix must be a non-empty string (a prefix is what makes keys detectable).")
    if isinstance(length, bool) or not isinstance(length, int) or length < 1:
        raise ValueError("length must be a positive integer.")
    body = _class(build_charset(charset, case)) + f"{{{length}}}"
    tail = f"{_CHECKSUM_CLASS}{{{CHECKSUM_LENGTH}}}" if checksum else ""
    return rf"(?<![0-9A-Za-z_-]){re.escape(prefix + separator)}{body}{tail}(?![0-9A-Za-z_-])"


def find_keys(
    text: str,
    prefix: str,
    *,
    validate: bool = True,
    **options: object,
) -> list[str]:
    """All keys found in ``text``. With ``validate=True`` (and ``checksum=True``) a candidate
    must also pass :func:`~generateapikey.verify_checksum`, which removes look-alikes."""
    checksum = bool(options.get("checksum", True))
    pattern = re.compile(key_pattern(prefix, **options))  # type: ignore[arg-type]
    found = pattern.findall(text) if isinstance(text, str) else []
    if validate and checksum:
        found = [k for k in found if verify_checksum(k)]
    return list(dict.fromkeys(found))


def gitleaks_rule(prefix: str, rule_id: str, *, description: str = "", **options: object) -> str:
    """A ``[[rules]]`` TOML block for ``.gitleaks.toml`` that detects your keys."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", rule_id or ""):
        raise ValueError("rule_id must be letters, digits, '.', '_' or '-'.")
    regex = key_pattern(prefix, **options)  # type: ignore[arg-type]
    # gitleaks (Go RE2) has no lookbehind: use a word-boundary-free form.
    regex = regex.replace(r"(?<![0-9A-Za-z_-])", "").replace(r"(?![0-9A-Za-z_-])", "")
    desc = description or f"{prefix} API key"
    return (
        f"[[rules]]\nid = \"{rule_id}\"\ndescription = \"{desc}\"\nregex = '''{regex}'''\nkeywords = [\"{prefix}\"]\n"
    )
