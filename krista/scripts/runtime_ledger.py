"""Write privacy-minimized Krista execution and evidence JSONL ledgers."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.ledger_keys import contains_forbidden  # noqa: E402




def ledger_root(value: str | None = None) -> Path:
    raw = value or os.environ.get("KRISTA_RUNTIME_LOG_ROOT")
    if not raw:
        raise ValueError("KRISTA_RUNTIME_LOG_ROOT is required")
    target = Path(raw).expanduser().resolve()
    if not target.is_absolute() or ROOT == target or ROOT in target.parents:
        raise ValueError("ledger root must be an absolute directory outside the repository")
    target.mkdir(parents=True, exist_ok=True)
    return target


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _ledger_path(root: Path, kind: str) -> Path:
    return root / {
        "execution": "executions.jsonl",
        "evidence": "evidence.jsonl",
        "calibration": "calibrations.jsonl",
        "decision": "decisions.jsonl",
    }[kind]


def _previous_hash(path: Path) -> str:
    if not path.is_file() or not path.read_text(encoding="utf-8").strip(): return "GENESIS"
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return json.loads(lines[-1])["record_hash"] if lines else "GENESIS"


def _check_decision_event(root: Path, record: dict[str, Any]) -> None:
    """A decision event is appended only if the whole assessment stream stays valid."""
    from scripts.validate_decision_assessment import validate

    path = _ledger_path(root, "decision")
    earlier = []
    if path.is_file():
        earlier = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        earlier = [event for event in earlier if event.get("assessment_id") == record["assessment_id"]]
    errors = validate([*earlier, record])
    if errors:
        raise ValueError("decision event rejected: " + "; ".join(errors[:3]))


def append_record(root: Path, kind: str, record: dict[str, Any]) -> dict[str, Any]:
    if contains_forbidden(record):
        raise ValueError("raw prompt, response, or secret-like fields are not permitted")
    required = {
        "execution": {"execution_id", "repository", "revision", "assurance_level", "module_state_counts", "claim_status_counts", "evidence_refs"},
        "evidence": {"evidence_id", "scope", "source", "supports_claims"},
        "calibration": {"execution_id", "repository", "revision", "status", "observation_counts", "evidence_refs", "next_check_ref"},
        "decision": {"record_type", "event_id", "assessment_id", "point"},
    }[kind]
    if required - set(record):
        raise ValueError(f"{kind} record missing required fields")
    if kind == "decision":
        _check_decision_event(root, record)
    if kind == "calibration":
        status = record["status"]
        if set(record) != required:
            raise ValueError("calibration record contains unsupported fields")
        if status not in {"NO_NEW_LESSON", "CANDIDATE_LESSON", "VERIFIED_LESSON"}:
            raise ValueError("invalid calibration status")
        if set(record["observation_counts"]) != {"error", "user_correction", "test_result"} or any(
            not isinstance(value, int) or value < 0 for value in record["observation_counts"].values()
        ):
            raise ValueError("calibration observation counts must be the required non-negative integers")
        if not isinstance(record["evidence_refs"], list) or not all(isinstance(value, str) and value for value in record["evidence_refs"]):
            raise ValueError("calibration evidence references must be non-empty strings")
        if not isinstance(record["next_check_ref"], str) or not record["next_check_ref"]:
            raise ValueError("calibration next-check reference must be a non-empty string")
        if status in {"CANDIDATE_LESSON", "VERIFIED_LESSON"} and not record["evidence_refs"]:
            raise ValueError("candidate or verified lesson requires evidence references")
        if status == "VERIFIED_LESSON" and record["next_check_ref"] == "UNVERIFIABLE":
            raise ValueError("verified lesson requires a passed follow-up reference")
        _execution(root, record["execution_id"])
    path = _ledger_path(root, kind)
    enriched = {**record, "ledger_id": str(uuid.uuid4()), "recorded_at": datetime.now(UTC).isoformat(), "previous_hash": _previous_hash(path)}
    enriched["record_hash"] = _digest(enriched)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(enriched, sort_keys=True) + "\n")
    return enriched


def verify_ledger(root: Path, kind: str) -> list[str]:
    path = _ledger_path(root, kind)
    if not path.is_file(): return ["ledger does not exist"]
    errors: list[str] = []; previous = "GENESIS"
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip(): continue
        record = json.loads(line)
        supplied = record.pop("record_hash", None)
        if record.get("previous_hash") != previous: errors.append(f"line {index}: previous hash mismatch")
        if supplied != _digest(record): errors.append(f"line {index}: record hash mismatch")
        previous = supplied or ""
    return errors


def _execution(root: Path, execution_id: str) -> dict[str, Any]:
    path = root / "executions.jsonl"
    if not path.is_file():
        raise ValueError("execution ledger does not exist")
    matches = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and json.loads(line)["execution_id"] == execution_id]
    if len(matches) != 1:
        raise ValueError("execution ID must resolve to exactly one record")
    return matches[0]


def export_summary(root: Path, execution_id: str, approval_ref: str, destination_root: Path | None = None) -> Path:
    if not approval_ref.strip():
        raise ValueError("explicit approval reference is required")
    if not isinstance(execution_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", execution_id) or ".." in execution_id:
        raise ValueError("execution_id must be a plain identifier (letters, digits, '.', '_', '-')")
    record = _execution(root, execution_id)
    claims = Counter(record["claim_status_counts"])
    lines = [
        "# Approved Execution Summary",
        "",
        f"- Execution ID: `{record['execution_id']}`",
        f"- Repository: `{record['repository']}`",
        f"- Revision: `{record['revision']}`",
        f"- Assurance: `{record['assurance_level']}`",
        f"- Approval reference: `{approval_ref}`",
        "",
        "## Aggregate counts",
        "",
        "| Category | Count |",
        "| --- | ---: |",
    ]
    for name, count in sorted({**record["module_state_counts"], **claims}.items()): lines.append(f"| {name} | {count} |")
    lines += ["", "## Evidence references", ""] + [f"- `{item}`" for item in record["evidence_refs"]]
    destination = (destination_root or ROOT) / "outputs" / "execution-summaries" / f"{execution_id}.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger-root")
    commands = parser.add_subparsers(dest="command", required=True)
    append = commands.add_parser("append"); append.add_argument("--kind", choices=("execution", "evidence", "calibration", "decision"), required=True); append.add_argument("--input", type=Path, required=True)
    summary = commands.add_parser("export-summary"); summary.add_argument("--execution-id", required=True); summary.add_argument("--approval-ref", required=True)
    verify = commands.add_parser("verify"); verify.add_argument("--kind", choices=("execution", "evidence", "calibration", "decision"), required=True)
    args = parser.parse_args()
    root = ledger_root(args.ledger_root)
    if args.command == "append":
        result = append_record(root, args.kind, json.loads(args.input.read_text(encoding="utf-8")))
        print(json.dumps({"ledger_id": result["ledger_id"], "recorded_at": result["recorded_at"]}))
    elif args.command == "export-summary":
        print(export_summary(root, args.execution_id, args.approval_ref))
    else:
        errors = verify_ledger(root, args.kind)
        print("Ledger verification: " + ("PASS" if not errors else "FAIL"))
        if errors: print(*errors, sep="\n"); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
