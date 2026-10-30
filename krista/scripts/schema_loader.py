"""Load enforced field sets and enums from a schema's JSON source.

The migration from prose-only schemas to a single machine-readable source starts
here. A validator that once hardcoded its required fields reads them from
`runtime/schemas/<name>.schema.json` instead, so the shape is defined once. The
prose `<name>.schema.md` keeps the intent and rules; it no longer restates the
field list, so the two cannot drift.

Dependency-free by design: the JSON is a small, fixed structure this repository
controls, not an external JSON Schema document, so no `jsonschema` package is
needed. Procedural rules — state chains, cross-field checks — stay in the
validator; only the declarative data lives here.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "runtime" / "schemas"


@cache
def load_schema(name: str) -> dict:
    """Return the JSON schema source for `name` (without the .schema.json suffix)."""
    path = SCHEMA_DIR / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def required(name: str, section: str) -> set[str]:
    """Return the required-field set for a section (e.g. 'trace' or 'record')."""
    return set(load_schema(name)[section]["required"])


class EnumSet(frozenset):
    """Allowed enum values whose membership test is False for unhashable input.

    A list or dict in an enum field is a clean rejection, not a TypeError.
    """

    def __contains__(self, value: object) -> bool:
        try:
            return frozenset.__contains__(self, value)
        except TypeError:
            return False


def enum(name: str, section: str, field: str) -> EnumSet:
    """Return the allowed values for an enum field within a section (membership)."""
    return EnumSet(enum_list(name, section, field))


def enum_list(name: str, section: str, field: str) -> list[str]:
    """Return the allowed values in declared order (for enums whose order matters)."""
    return list(load_schema(name)[section]["enums"][field])


def mapping(name: str, section: str, field: str) -> dict[str, str]:
    """Return a declarative mapping (e.g. content_profile -> required format)."""
    return dict(load_schema(name)[section]["mappings"][field])


def string_list(name: str, section: str, field: str) -> list[str]:
    """Return a declarative list from the section's `lists` block, in order."""
    return list(load_schema(name)[section]["lists"][field])


def has_json_source(name: str) -> bool:
    return (SCHEMA_DIR / f"{name}.schema.json").is_file()
