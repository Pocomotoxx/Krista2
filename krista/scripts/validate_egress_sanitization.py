"""Validate an egress-sanitization-record: the pre-output PII/secret gate.

Before a substantive output leaves as an artifact or deliverable, the gate in
runtime/EGRESS_SANITIZATION_POLICY.md classifies each scanned unit
(ALLOWED/SANITIZED/BLOCKED/EXCLUDED), names the rule that decided it, and blocks
the output when a critical secret cannot be removed. This validator checks the
record's shape and those invariants only; it does not run a scanner, judge
whether a classification is the right reading of the content, or certify legal
compliance.

Structure and invariants:
- PASSED forbids any BLOCKED unit; BLOCKED requires at least one BLOCKED unit
  (the output stays incomplete, not completed).
- A SANITIZED, BLOCKED, or EXCLUDED unit must name a non-empty rule_locator:
  no silent sanitization.
- An ALLOWED unit carries no finding (finding_kind "none", count 0); a SANITIZED
  or BLOCKED unit has at least one finding.
- finding_kind is a short category label, never the sensitive value itself: a
  lowercase slug (letters, digits, '-', '_'), at most 40 characters, and no
  credential shape.
- No string anywhere in the record (values or keys) may carry a credential or
  secret-assignment shape (scripts/redaction.py find_secrets): the record that
  attests removal must not itself retain the secret.
- NOT_ATTEMPTED and UNVERIFIABLE require a non-empty limitation and carry no
  units.
- assurance_level is DECLARED or UNVERIFIABLE, never VERIFIED: the record
  describes a scan and carries no independently checkable evidence.

Concept adapted from the external m1guel1982/mova-context egress model; no code
or text copied. See runtime/EGRESS_SANITIZATION_POLICY.md.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.redaction import find_secrets
from scripts.schema_loader import enum, required as required_fields, string_list
from scripts.strict_fields import enum_member

SCHEMA = "egress-sanitization-record"
REQUIRED = required_fields(SCHEMA, "record")
UNIT_REQUIRED = required_fields(SCHEMA, "unit")
SCOPE = enum(SCHEMA, "record", "scope")
GATE_STATUS = enum(SCHEMA, "record", "gate_status")
ASSURANCE = enum(SCHEMA, "record", "assurance_level")
DECISION = enum(SCHEMA, "unit", "decision")

_NO_UNITS = frozenset(string_list(SCHEMA, "record", "no_units"))
_FINDING_DECISIONS = frozenset(string_list(SCHEMA, "unit", "finding_decisions"))
_RULE_REQUIRED = frozenset(string_list(SCHEMA, "unit", "rule_required"))
_LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
_SECRET_CATEGORIES = frozenset(string_list(SCHEMA, "unit", "secret_categories"))


def _secret_strings(node: object, path: str, errors: list[str]) -> None:
    if isinstance(node, str):
        hits = [c for c in find_secrets(node) if c in _SECRET_CATEGORIES]
        if hits:
            errors.append(f"{path or 'record'} carries a secret-shaped value ({', '.join(hits)}); the record must not retain it")
    elif isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            _secret_strings(key, f"{child} (key)", errors)
            _secret_strings(value, child, errors)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _secret_strings(value, f"{path}[{index}]", errors)


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _is_nonempty_string(value: object) -> bool:
    """True only for an actual non-empty str — bool/int/list/None all fail."""
    return isinstance(value, str) and bool(value.strip())


def _validate_unit(index: int, unit: object) -> list[str]:
    where = f"unit[{index}]"
    if not isinstance(unit, dict):
        return [f"{where} must be an object"]
    errors = [f"{where} missing required field: {name}" for name in sorted(UNIT_REQUIRED - set(unit))]
    if errors:
        return errors

    decision = unit.get("decision")
    if decision not in DECISION:
        return [f"{where} decision must be ALLOWED, SANITIZED, BLOCKED, or EXCLUDED"]

    if not _is_nonempty_string(unit.get("unit_ref")):
        errors.append(f"{where} unit_ref must be a non-empty locator")

    count = unit.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        errors.append(f"{where} count must be a non-negative integer")
        count = None

    finding = _text(unit.get("finding_kind")) or "none"
    if finding != "none":
        if not _LABEL.fullmatch(finding) or find_secrets(finding):
            errors.append(f"{where} finding_kind must be a short category label, never the sensitive value")

    if decision in _RULE_REQUIRED and not _is_nonempty_string(unit.get("rule_locator")):
        errors.append(f"{where} {decision} requires a non-empty rule_locator (no silent decision)")

    if decision == "ALLOWED":
        if finding != "none":
            errors.append(f"{where} ALLOWED carries no finding; finding_kind must be 'none'")
        if count not in (None, 0):
            errors.append(f"{where} ALLOWED requires count 0")
    if decision in _FINDING_DECISIONS:
        if finding == "none":
            errors.append(f"{where} {decision} requires a finding_kind category")
        if count is not None and count < 1:
            errors.append(f"{where} {decision} requires count >= 1")

    return errors


def validate(record: dict) -> list[str]:
    if not isinstance(record, dict):
        return ["record must be an object"]
    errors = [f"missing required field: {name}" for name in sorted(REQUIRED - set(record))]
    if errors:
        return errors

    if record["record_type"] != "egress-sanitization-record":
        errors.append("record_type must be egress-sanitization-record")
    if not _is_nonempty_string(record.get("execution_id")):
        errors.append("execution_id must be a non-empty string")
    if not _is_nonempty_string(record.get("target_ref")):
        errors.append("target_ref must be a non-empty locator")
    if not enum_member(record.get("scope"), SCOPE):
        errors.append("scope must be OUTPUT_ARTIFACT, DELIVERABLE_TEXT, or DOMAIN_SENSITIVE")
    if not enum_member(record.get("gate_status"), GATE_STATUS):
        errors.append("gate_status must be PASSED, BLOCKED, NOT_ATTEMPTED, or UNVERIFIABLE")
    if not enum_member(record.get("assurance_level"), ASSURANCE):
        errors.append("assurance_level must be DECLARED or UNVERIFIABLE (never VERIFIED: a self-describing record cannot verify itself)")
    units = record.get("units")
    if not isinstance(units, list):
        errors.append("units must be a list")
        units = []
    if errors:
        return errors

    gate_status = record["gate_status"]
    _secret_strings(record, "", errors)

    for index, unit in enumerate(units):
        errors.extend(_validate_unit(index, unit))

    decisions = [u.get("decision") for u in units if isinstance(u, dict)]
    has_blocked = "BLOCKED" in decisions

    if gate_status in _NO_UNITS:
        if units:
            errors.append(f"{gate_status} gate carries no units")
        if not _is_nonempty_string(record.get("limitation")):
            errors.append(f"{gate_status} gate requires a non-empty limitation")
    else:
        if not units:
            errors.append(f"{gate_status} gate requires at least one scanned unit")
        if gate_status == "PASSED" and has_blocked:
            errors.append("PASSED gate cannot contain a BLOCKED unit")
        if gate_status == "BLOCKED" and not has_blocked:
            errors.append("BLOCKED gate requires at least one BLOCKED unit")

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_egress_sanitization.py RECORD.json")
        return 2
    errors = validate(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    print("Egress sanitization validation: " + ("PASS" if not errors else "FAIL"))
    if errors:
        print(*[f"- {error}" for error in errors], sep="\n")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
