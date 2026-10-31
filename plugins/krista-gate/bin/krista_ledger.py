#!/usr/bin/env python3
"""Append-only, hash-chained local ledger for the gate, in the format of KRISTA's runtime_ledger.

One JSON line per record. Each line carries `ledger_id`, `recorded_at`, `previous_hash` and `record_hash`, where
`record_hash` is the SHA-256 of the line without that field (sorted keys, compact separators) and `previous_hash`
is the previous line's `record_hash` (`GENESIS` for the first). KRISTA's `runtime_ledger.verify_ledger` and this
module therefore verify each other's files; `decisions.jsonl` is the file name KRISTA uses for the `decision` kind.

    krista_ledger.py verify --root <dir> [--kind gate|ingress|egress|decision]
    krista_ledger.py tail --root <dir> --kind <kind> [-n 5]
    krista_ledger.py append-decision --root <dir> <event.json>

The ledger root is chosen by the launcher (KRISTA_RUNTIME_LOG_ROOT). It must be an absolute directory outside the
project, so the agent that is being logged cannot write the log through its own tools. Writers take an exclusive lock
(flock) for the whole read-validate-append step, so parallel hooks and subagents cannot fork the chain. Records are
metadata: references, digests, enums, counts. A raw prompt, response, content or credential field is refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

GENESIS = "GENESIS"
FILES = {"gate": "gate.jsonl", "ingress": "ingress.jsonl", "egress": "egress.jsonl", "decision": "decisions.jsonl"}
RESERVED = {"ledger_id", "recorded_at", "previous_hash", "record_hash"}
TAIL_BYTES = 1 << 16


class LedgerError(Exception):
    """The ledger cannot be written or is not trustworthy; callers treat this as a refusal to proceed."""


def digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def ledger_root(value: str | None, project_root: Path | None = None) -> Path:
    """The validated ledger directory, created private (0700) when missing."""
    if not value:
        raise LedgerError("no ledger root is configured (KRISTA_RUNTIME_LOG_ROOT)")
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise LedgerError("the ledger root must be an absolute path")
    root = raw.resolve()
    if project_root is not None:
        project = project_root.resolve()
        if root == project or project in root.parents or root in project.parents:
            raise LedgerError("the ledger root must be outside the project: the logged agent could otherwise write it")
    if fcntl is None:
        raise LedgerError("the ledger needs POSIX file locking")
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if stat.S_IMODE(root.stat().st_mode) & stat.S_IWOTH:
            raise LedgerError("the ledger root is world-writable")
    except OSError as exc:
        raise LedgerError(f"the ledger root is unusable: {type(exc).__name__}") from None
    return root


def _last_line(fd: int) -> str | None:
    size = os.fstat(fd).st_size
    if size == 0:
        return None
    data = os.pread(fd, min(size, TAIL_BYTES), max(0, size - TAIL_BYTES))
    lines = [line for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()]
    if not lines:
        return None
    if size > TAIL_BYTES and len(lines) == 1:
        raise LedgerError("the last ledger line is longer than the tail window")
    return lines[-1]


def _lines(fd: int) -> list[str]:
    size = os.fstat(fd).st_size
    data = os.pread(fd, size, 0) if size else b""
    return [line for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()]


def append(root: Path, kind: str, record: dict, check: Callable[[list[dict]], None] | None = None) -> dict:
    """Append one record under an exclusive lock; `check(existing)` runs under the lock and may refuse by raising."""
    if kind not in FILES:
        raise LedgerError(f"unknown ledger kind {kind!r}")
    if not isinstance(record, dict) or RESERVED & set(record):
        raise LedgerError("the record is not an object, or uses a reserved ledger field")
    path = root / FILES[kind]
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError as exc:
        raise LedgerError(f"the ledger file cannot be opened: {type(exc).__name__}") from None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        last = _last_line(fd)
        try:
            previous = json.loads(last)["record_hash"] if last else GENESIS
        except (ValueError, KeyError, TypeError):
            raise LedgerError("the last ledger line is not valid; refusing to extend a broken chain") from None
        if check is not None:
            try:
                existing = [json.loads(line) for line in _lines(fd)]
            except ValueError:
                raise LedgerError("the ledger holds an unreadable line; refusing to extend a broken chain") from None
            check(existing)
        enriched = {**record, "ledger_id": str(uuid.uuid4()), "recorded_at": datetime.now(timezone.utc).isoformat(), "previous_hash": previous}
        enriched["record_hash"] = digest(enriched)
        os.write(fd, (json.dumps(enriched, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
        return enriched
    except OSError as exc:
        raise LedgerError(f"the ledger write failed: {type(exc).__name__}") from None
    finally:
        os.close(fd)


def verify(root: Path, kind: str) -> list[str]:
    path = root / FILES[kind]
    if not path.is_file():
        return [f"{FILES[kind]}: ledger does not exist"]
    errors: list[str] = []
    previous = GENESIS
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            errors.append(f"line {number}: not valid JSON")
            previous = ""
            continue
        if not isinstance(record, dict):
            errors.append(f"line {number}: not a JSON object")
            previous = ""
            continue
        supplied = record.pop("record_hash", None)
        if record.get("previous_hash") != previous:
            errors.append(f"line {number}: previous hash mismatch")
        if supplied != digest(record):
            errors.append(f"line {number}: record hash mismatch")
        previous = supplied or ""
    return errors


def tail(root: Path, kind: str, count: int = 5) -> list[dict]:
    path = root / FILES[kind]
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows[-count:]


def last_value(root: Path, kind: str, field: str, where: dict[str, object], window: int = 500) -> object | None:
    """The newest value of `field` among the last `window` records that match every `where` item."""
    path = root / FILES[kind]
    if not path.is_file():
        return None
    for line in reversed(path.read_text(encoding="utf-8").splitlines()[-window:]):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and all(row.get(k) == v for k, v in where.items()) and field in row:
            return row[field]
    return None


def load_krista(krista_root: Path):
    """Import the pinned KRISTA modules the ledger commands need, after checking the pin."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import pin

    problems = pin.verify(krista_root)
    if problems:
        raise LedgerError("the pinned KRISTA copy is not intact: " + "; ".join(problems))
    sys.path.insert(0, str(krista_root))
    import importlib

    return importlib.import_module("scripts.validate_decision_assessment"), importlib.import_module("scripts.ledger_keys")


def append_decision(root: Path, event: dict, validator, keys) -> dict:
    """Append a decision-assessment event only if the whole assessment stream stays valid (KRISTA's own rule)."""
    if keys.contains_forbidden(event):
        raise LedgerError("a raw prompt, response or secret-like field is not permitted in a ledger record")
    if not isinstance(event, dict) or not isinstance(event.get("assessment_id"), str):
        raise LedgerError("the event names no assessment_id")

    def check(existing: list[dict]) -> None:
        stream = [row for row in existing if row.get("assessment_id") == event["assessment_id"]]
        errors = validator.validate([*stream, event])
        if errors:
            raise LedgerError("decision event rejected: " + "; ".join(errors[:3]))

    return append(root, "decision", event, check)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--root", required=True)
    v.add_argument("--kind", choices=sorted(FILES))
    t = sub.add_parser("tail")
    t.add_argument("--root", required=True)
    t.add_argument("--kind", choices=sorted(FILES), required=True)
    t.add_argument("-n", type=int, default=5)
    a = sub.add_parser("append-decision")
    a.add_argument("--root", required=True)
    a.add_argument("event")
    args = parser.parse_args(argv)
    try:
        root = ledger_root(args.root)
        if args.command == "verify":
            kinds = [args.kind] if args.kind else [k for k in sorted(FILES) if (root / FILES[k]).is_file()]
            problems = [f"{k}: {e}" for k in kinds for e in verify(root, k)]
            print("Ledger verification: " + ("PASS" if not problems and kinds else "FAIL"))
            for problem in problems or ([] if kinds else ["no ledger files found"]):
                print(f"- {problem}")
            return int(bool(problems) or not kinds)
        if args.command == "tail":
            for row in tail(root, args.kind, args.n):
                print(json.dumps(row, sort_keys=True))
            return 0
        validator, keys = load_krista(Path(__file__).resolve().parents[3] / "krista")
        event = json.loads(Path(args.event).read_text(encoding="utf-8"))
        written = append_decision(root, event, validator, keys)
        print(json.dumps({"ledger_id": written["ledger_id"], "recorded_at": written["recorded_at"]}))
        return 0
    except (LedgerError, OSError, ValueError) as exc:
        print(f"ledger: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
