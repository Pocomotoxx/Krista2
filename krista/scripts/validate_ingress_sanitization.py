"""Validate an ingress-sanitization-record: the pre-model data-minimisation gate.

Before context built from data-sensitive material reaches a model or a delegated
agent, the gate in runtime/INGRESS_SANITIZATION_POLICY.md classifies each unit
(ADMITTED_AS_IS / TRANSFORMED / WITHHELD / EXCLUDED), names the technique and the
deciding rule, and states what the detector could and could not see. This
validator checks the record's shape and those invariants only; it does not run a
detector, judge whether a transformation is adequate, or certify anonymization.

Structure and invariants:
- ADMITTED forbids any WITHHELD unit and any residual finding; WITHHELD requires a
  WITHHELD unit (the context stays at home).
- A TRANSFORMED unit names a technique, a finding category, a count >= 1 and a
  rule_locator; WITHHELD and EXCLUDED units name a rule_locator; an ADMITTED_AS_IS
  unit carries no finding.
- The record's technique list is exactly the techniques of its TRANSFORMED units.
- A PSEUDONYMIZATION unit states who holds the mapping (HOST_VAULT or DISCARDED);
  the mapping itself, and any original value, never appears in the record.
- A DELEGATED_AGENT destination needs a delegation_ref.
- A SECRETS_ONLY detector cannot see personal data, so the limitation must say so.
- NOT_ATTEMPTED and UNVERIFIABLE carry no units or techniques and a real limitation.
- assurance_level is DECLARED or UNVERIFIABLE, never VERIFIED.
- No string anywhere may carry a credential or secret-assignment shape, and no key
  at any depth may be a value/mapping/prompt field.
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
from scripts.strict_fields import enum_member, has_forbidden_key, is_nonempty_string

SCHEMA = "ingress-sanitization-record"
REQUIRED = required_fields(SCHEMA, "record")
UNIT_REQUIRED = required_fields(SCHEMA, "unit")
TOKEN_CHECK_REQUIRED = required_fields(SCHEMA, "token_check")
DESTINATION = enum(SCHEMA, "record", "destination_class")
COVERAGE = enum(SCHEMA, "record", "detection_coverage")
GATE_STATUS = enum(SCHEMA, "record", "gate_status")
TECHNIQUE = enum(SCHEMA, "record", "technique")
ASSURANCE = enum(SCHEMA, "record", "assurance_level")
TOKEN_STATUS = enum(SCHEMA, "record", "token_check_status")
DECISION = enum(SCHEMA, "unit", "decision")
CUSTODY = enum(SCHEMA, "unit", "mapping_custody")

_NO_UNITS = frozenset(string_list(SCHEMA, "record", "no_units"))
_FORBIDDEN = frozenset(string_list(SCHEMA, "record", "forbidden_fields"))
_RULE_REQUIRED = frozenset(string_list(SCHEMA, "unit", "rule_required"))
_SECRET_CATEGORIES = frozenset(string_list(SCHEMA, "unit", "secret_categories"))
_LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")


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


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _real_limitation(value: object) -> bool:
    return is_nonempty_string(value) and value.strip().casefold() != "none"


def _validate_unit(index: int, unit: object) -> tuple[list[str], str | None]:
    where = f"unit[{index}]"
    if not isinstance(unit, dict):
        return [f"{where} must be an object"], None
    errors = [f"{where} missing required field: {name}" for name in sorted(UNIT_REQUIRED - set(unit))]
    if errors:
        return errors, None

    decision = unit["decision"]
    if not enum_member(decision, DECISION):
        return [f"{where} decision must be ADMITTED_AS_IS, TRANSFORMED, WITHHELD, or EXCLUDED"], None

    if not is_nonempty_string(unit["unit_ref"]):
        errors.append(f"{where} unit_ref must be a non-empty locator")

    count, residual = unit["count"], unit["residual_findings"]
    if not _count(count):
        errors.append(f"{where} count must be a non-negative integer")
        count = None
    if not _count(residual):
        errors.append(f"{where} residual_findings must be a non-negative integer")
        residual = None

    finding = unit["finding_kind"]
    if not isinstance(finding, str) or not finding.strip():
        errors.append(f"{where} finding_kind must be a category label or 'none'")
        finding = "none"
    elif finding != "none" and (not _LABEL.fullmatch(finding) or find_secrets(finding)):
        errors.append(f"{where} finding_kind must be a short category label, never the sensitive value")

    if decision in _RULE_REQUIRED and not is_nonempty_string(unit.get("rule_locator")):
        errors.append(f"{where} {decision} requires a non-empty rule_locator (no silent decision)")

    technique = unit.get("technique")
    custody = unit.get("mapping_custody")
    if decision == "TRANSFORMED":
        if not enum_member(technique, TECHNIQUE):
            errors.append(f"{where} TRANSFORMED requires a technique ({', '.join(sorted(TECHNIQUE))})")
        if finding == "none":
            errors.append(f"{where} TRANSFORMED requires a finding_kind category")
        if count is not None and count < 1:
            errors.append(f"{where} TRANSFORMED requires count >= 1")
        if technique == "PSEUDONYMIZATION":
            if not enum_member(custody, CUSTODY):
                errors.append(f"{where} PSEUDONYMIZATION requires mapping_custody HOST_VAULT or DISCARDED")
        elif custody is not None:
            errors.append(f"{where} mapping_custody applies to PSEUDONYMIZATION only")
    else:
        if technique is not None:
            errors.append(f"{where} only a TRANSFORMED unit carries a technique")
        if custody is not None:
            errors.append(f"{where} only a PSEUDONYMIZATION unit carries mapping_custody")

    if decision == "ADMITTED_AS_IS":
        if finding != "none":
            errors.append(f"{where} ADMITTED_AS_IS carries no finding; finding_kind must be 'none'")
        if count not in (None, 0):
            errors.append(f"{where} ADMITTED_AS_IS requires count 0")
    if decision in {"ADMITTED_AS_IS", "TRANSFORMED"} and residual not in (None, 0):
        errors.append(f"{where} {decision} cannot leave a residual finding; WITHHELD the unit instead")

    return errors, technique if decision == "TRANSFORMED" and enum_member(technique, TECHNIQUE) else None


def _validate_token_check(check: object, techniques: set[str]) -> list[str]:
    errors: list[str] = []
    if not isinstance(check, dict):
        return ["output_token_check must be an object"]
    errors.extend(f"output_token_check missing {name}" for name in sorted(TOKEN_CHECK_REQUIRED - set(check)))
    if errors:
        return errors
    if "PSEUDONYMIZATION" not in techniques:
        errors.append("output_token_check applies only when PSEUDONYMIZATION was used")
    status, unknown, missing = check["status"], check["unknown_tokens"], check["missing_tokens"]
    if not enum_member(status, TOKEN_STATUS):
        errors.append("output_token_check.status must be CONSISTENT, INCONSISTENT, or NOT_CHECKED")
    if not _count(unknown) or not _count(missing):
        errors.append("output_token_check counts must be non-negative integers")
    elif status == "CONSISTENT" and (unknown or missing):
        errors.append("a CONSISTENT token check cannot report unknown or missing tokens")
    elif status == "INCONSISTENT" and not (unknown or missing):
        errors.append("an INCONSISTENT token check must report unknown or missing tokens")
    elif status == "NOT_CHECKED" and (unknown or missing):
        errors.append("a NOT_CHECKED token check carries no counts")
    return errors


def validate(record: dict) -> list[str]:
    if not isinstance(record, dict):
        return ["record must be an object"]
    errors = [f"missing required field: {name}" for name in sorted(REQUIRED - set(record))]
    if errors:
        return errors

    if record["record_type"] != "ingress-sanitization-record":
        errors.append("record_type must be ingress-sanitization-record")
    for name in ("execution_id", "context_ref", "detector_ref"):
        if not is_nonempty_string(record[name]):
            errors.append(f"{name} must be a non-empty string")
    if not enum_member(record["destination_class"], DESTINATION):
        errors.append("destination_class must be INTERNAL_MODEL, EXTERNAL_MODEL, or DELEGATED_AGENT")
    if not enum_member(record["detection_coverage"], COVERAGE):
        errors.append("detection_coverage must be SECRETS_ONLY, SECRETS_AND_PII_PATTERNS, or HOST_DECLARED")
    if not enum_member(record["gate_status"], GATE_STATUS):
        errors.append("gate_status must be ADMITTED, WITHHELD, NOT_ATTEMPTED, or UNVERIFIABLE")
    if not enum_member(record["assurance_level"], ASSURANCE):
        errors.append("assurance_level must be DECLARED or UNVERIFIABLE (never VERIFIED: a self-describing record cannot verify itself)")
    units, techniques = record["units"], record["techniques"]
    if not isinstance(units, list):
        errors.append("units must be a list")
    if not isinstance(techniques, list) or not all(enum_member(item, TECHNIQUE) for item in techniques):
        errors.append("techniques must be a list of known techniques")
    if errors:
        return errors

    if record["destination_class"] == "DELEGATED_AGENT" and not is_nonempty_string(record.get("delegation_ref")):
        errors.append("a DELEGATED_AGENT destination requires a delegation_ref (the agent sees only its own slice)")
    if has_forbidden_key(record, _FORBIDDEN):
        errors.append("record carries a value, mapping, or prompt field; it holds metadata only")
    _secret_strings(record, "", errors)

    used: set[str] = set()
    decisions: list[str] = []
    residuals = 0
    for index, unit in enumerate(units):
        unit_errors, technique = _validate_unit(index, unit)
        errors.extend(unit_errors)
        if technique:
            used.add(technique)
        if isinstance(unit, dict):
            decisions.append(unit.get("decision"))
            if _count(unit.get("residual_findings")):
                residuals += unit["residual_findings"]

    if set(techniques) != used or len(set(techniques)) != len(techniques):
        errors.append("techniques must list exactly the techniques of the TRANSFORMED units, once each")

    status = record["gate_status"]
    limitation = record["limitation"]
    if status in _NO_UNITS:
        if units or techniques:
            errors.append(f"{status} gate carries no units or techniques")
        if not _real_limitation(limitation):
            errors.append(f"{status} gate requires a real limitation (not empty, not 'none')")
    else:
        if not units:
            errors.append(f"{status} gate requires at least one context unit")
        if status == "ADMITTED":
            if "WITHHELD" in decisions:
                errors.append("ADMITTED gate cannot contain a WITHHELD unit")
            if residuals:
                errors.append("ADMITTED gate cannot leave a residual finding")
        if status == "WITHHELD" and "WITHHELD" not in decisions:
            errors.append("WITHHELD gate requires at least one WITHHELD unit")
        if record["detection_coverage"] == "SECRETS_ONLY" and not _real_limitation(limitation):
            errors.append("a SECRETS_ONLY detector cannot see personal data; the limitation must say so")

    if "output_token_check" in record:
        errors.extend(_validate_token_check(record["output_token_check"], set(techniques)))

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_ingress_sanitization.py RECORD.json")
        return 2
    try:
        record = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Ingress sanitization validation: FAIL\n- unreadable record: {error}")
        return 1
    errors = validate(record)
    print("Ingress sanitization validation: " + ("PASS" if not errors else "FAIL"))
    if errors:
        print(*[f"- {error}" for error in errors], sep="\n")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
