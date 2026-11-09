"""Permission scopes for API keys: ``read:users``, wildcards like ``read:*`` and ``*``.

Scopes are not secrets, so plain comparison is fine. Store them with the key's
record (a list, or a space/comma separated string) and check them per route.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Optional, Union

__all__ = ["has_all_scopes", "has_any_scope", "has_scope", "parse_scopes"]

_SPLIT = re.compile(r"[\s,]+")


def parse_scopes(scopes: Union[str, Iterable[str], None]) -> frozenset[str]:
    """Normalise ``"read write"``, ``"read,write"`` or ``["read", "write"]`` to a frozenset."""
    if scopes is None:
        return frozenset()
    if isinstance(scopes, str):
        return frozenset(s for s in _SPLIT.split(scopes) if s)
    return frozenset(s for s in scopes if isinstance(s, str) and s)


def has_scope(granted: Union[str, Iterable[str], None], required: str) -> bool:
    """True if ``required`` is covered by ``granted``.

    ``*`` grants everything; ``read:*`` grants ``read:users`` and ``read:users:list``
    (and ``read`` itself). ``read:users`` grants only ``read:users``.
    """
    if not isinstance(required, str) or not required:
        return False
    have = parse_scopes(granted)
    if "*" in have or required in have:
        return True
    parts = required.split(":")
    return any(":".join(parts[:i]) + ":*" in have for i in range(1, len(parts))) or (required + ":*") in have


def has_all_scopes(granted: Union[str, Iterable[str], None], required: Iterable[str]) -> bool:
    """True if every scope in ``required`` is covered (an empty ``required`` is True)."""
    have = parse_scopes(granted)
    return all(has_scope(have, r) for r in ([required] if isinstance(required, str) else required))


def has_any_scope(granted: Union[str, Iterable[str], None], required: Iterable[str]) -> bool:
    """True if at least one scope in ``required`` is covered."""
    have = parse_scopes(granted)
    return any(has_scope(have, r) for r in ([required] if isinstance(required, str) else required))


def _scopes_of(record: object, field: str = "scopes") -> Optional[Union[str, Iterable[str]]]:  # pragma: no cover
    return getattr(record, field, None)
