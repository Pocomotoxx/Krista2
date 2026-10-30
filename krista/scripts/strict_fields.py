"""Strict, type-checked field predicates shared by the record validators.

Truthiness and ``str()`` coercion let ``None``, ``True``, ``1`` or ``[None]``
pass as an approval or evidence reference, and set membership crashes on an
unhashable value. These helpers decide presence by type, never by coercion.
"""

from __future__ import annotations

import math
from typing import Any, Iterable


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_real_bool(value: Any) -> bool:
    return isinstance(value, bool)


def is_finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def is_nonnegative_number(value: Any) -> bool:
    return is_finite_number(value) and value >= 0


def enum_member(value: Any, allowed: Iterable[Any]) -> bool:
    """Membership that never raises on an unhashable or non-string value."""
    if not isinstance(value, str):
        return False
    return value in set(allowed)


def _key_name(key: Any) -> str:
    return str(key).casefold().replace("-", "_").replace(" ", "_")


def has_forbidden_key(value: Any, forbidden: Iterable[str]) -> bool:
    """True when any dict key, at any depth, matches a forbidden name.

    Matching is case-insensitive and treats ``-``/space as ``_``, so ``Prompt``
    and ``raw-text`` cannot hide behind spelling or nesting. Top-level-only
    ``set(record) & FORBIDDEN`` checks miss both.
    """
    names = {_key_name(name) for name in forbidden}

    def walk(node: Any) -> bool:
        if isinstance(node, dict):
            return any(_key_name(key) in names or walk(item) for key, item in node.items())
        if isinstance(node, list):
            return any(walk(item) for item in node)
        return False

    return walk(value)


def nonempty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(is_nonempty_string(item) for item in value)


def string_items(value: Any) -> list[str]:
    """The non-empty string members of a list; anything else yields []."""
    if not isinstance(value, list):
        return []
    return [item for item in value if is_nonempty_string(item)]


def same_identity(left: Any, right: Any) -> bool:
    """Case- and whitespace-insensitive identity comparison of two names."""
    if not (is_nonempty_string(left) and is_nonempty_string(right)):
        return False
    return left.strip().casefold() == right.strip().casefold()
