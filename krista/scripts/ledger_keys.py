"""One forbidden-key rule for every local ledger.

A ledger record carries references and counts, never raw content or secrets.
The runtime and delegation ledgers share this check so neither can drift
narrower than the other or than runtime/LOCAL_LEDGER_POLICY.md.
"""

from __future__ import annotations

from typing import Any

FORBIDDEN_KEYS = frozenset({
    "prompt", "response", "message", "content", "task", "authorization", "token",
    "credential", "credentials", "secret", "password", "passwd", "private_key",
    "api_key", "apikey",
})
_FORBIDDEN_FRAGMENTS = ("secret", "password", "passwd", "credential", "private_key", "api_key", "apikey")


def forbidden_key(key: object) -> bool:
    name = str(key).casefold().replace("-", "_").strip()
    return name in FORBIDDEN_KEYS or any(fragment in name for fragment in _FORBIDDEN_FRAGMENTS)


def contains_forbidden(value: Any) -> bool:
    if isinstance(value, dict):
        return any(forbidden_key(key) or contains_forbidden(item) for key, item in value.items())
    if isinstance(value, list):
        return any(contains_forbidden(item) for item in value)
    return False
