"""Ingress and egress filters at the tool boundary, and the KRISTA records that describe each decision.

The detector is KRISTA's own, pinned: `scripts/repo_scan.py` (credential and Hungarian personal-identifier shapes) and
`scripts/redaction.py` (credential and secret-assignment shapes). It is a heuristic: it finds known shapes, it does not
find a name, an address or a secret of a shape it has never seen. Every record says so in its `limitation`.

Ingress is what is about to reach the model: a prompt, a file the Read tool or a read-only command opens. A hook cannot
mask a value, only admit or withhold the whole unit, so the only outcomes are ADMITTED and WITHHELD.
Egress is what is about to leave the model's control: content written to a file, a staged file or a commit message,
the inputs of a network or MCP tool. The outcomes are PASSED and BLOCKED.

The records follow runtime/schemas/ingress-sanitization-record and egress-sanitization-record and are checked with
KRISTA's own validators before they are logged. They hold digests, categories and counts, never the value.
"""

from __future__ import annotations

import fnmatch
import hashlib
import stat
from collections import Counter
from pathlib import Path

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
CREDENTIAL_CATEGORIES = ("credential", "secret_assignment")
LIMITATION_PII = ("Heuristic shape detector: credential shapes and Hungarian personal identifiers (e-mail, phone, tax and "
                  "social-security numbers, IBAN, bank account). Names, addresses and free-text personal data are not detected.")
LIMITATION_SECRETS = "Heuristic shape detector: credential shapes only. Personal data is not detected because the PII filter is off."


class Detector:
    """Secret and personal-identifier shapes found in a text, as category counts."""

    def __init__(self, redaction, repo_scan, pii: bool = True) -> None:
        self.redaction, self.repo_scan, self.pii = redaction, repo_scan, pii
        self.secret_kinds = set(repo_scan.SECRET_SHAPES) | set(CREDENTIAL_CATEGORIES)
        self.pii_kinds = set(repo_scan.PII_SHAPES)

    @property
    def coverage(self) -> str:
        return "SECRETS_AND_PII_PATTERNS" if self.pii else "SECRETS_ONLY"

    @property
    def limitation(self) -> str:
        return LIMITATION_PII if self.pii else LIMITATION_SECRETS

    def scan(self, text: str) -> Counter:
        found: Counter = Counter()
        for _line, kind in self.repo_scan.scan_text(text):
            if kind in self.secret_kinds or (self.pii and kind in self.pii_kinds):
                found[kind] += 1
        for category in self.redaction.find_secrets(text):
            if category in CREDENTIAL_CATEGORIES:
                found[category] += 1
        return found


def ref(prefix: str, value: str) -> str:
    """A locator that identifies a unit without carrying it: its kind and a short digest."""
    return f"{prefix}:sha256:{hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()[:16]}"


def allowlisted(rel: str, absolute: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(rel, p) or fnmatch.fnmatchcase(absolute, p) for p in patterns)


def read_for_scan(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[str | None, str]:
    """(text, status): ok, binary, toolarge, unreadable, or missing (not a file: nothing to scan)."""
    try:
        info = path.stat()
    except OSError:
        return None, "missing"
    if not stat.S_ISREG(info.st_mode):
        return None, "missing"
    if info.st_size > max_bytes:
        return None, "toolarge"
    try:
        data = path.read_bytes()
    except OSError:
        return None, "unreadable"
    if b"\x00" in data[:8192]:
        return None, "binary"
    return data.decode("utf-8", errors="replace"), "ok"


def _units(findings: Counter, decision: str, rule: str, unit_ref: str, extra: dict | None = None) -> list[dict]:
    return [{"unit_ref": f"{unit_ref}#{kind}", "decision": decision, "finding_kind": kind, "count": count, "rule_locator": rule, **(extra or {})}
            for kind, count in sorted(findings.items())]


def ingress_record(execution_id: str, context_ref: str, detector: Detector, detector_ref: str, status: str, findings: Counter | None = None,
                   reason: str = "") -> dict:
    """ADMITTED (nothing found), WITHHELD (something found), EXCLUDED via the allowlist, or UNVERIFIABLE (not scannable)."""
    base = {"record_type": "ingress-sanitization-record", "execution_id": execution_id, "context_ref": context_ref,
            "destination_class": "EXTERNAL_MODEL", "detector_ref": detector_ref, "detection_coverage": detector.coverage,
            "techniques": [], "assurance_level": "DECLARED", "limitation": detector.limitation}
    if status == "ADMITTED":
        units = [{"unit_ref": context_ref, "decision": "ADMITTED_AS_IS", "finding_kind": "none", "count": 0, "residual_findings": 0}]
    elif status == "WITHHELD":
        units = [{**u, "residual_findings": 0} for u in _units(findings or Counter(), "WITHHELD", "krista-gate:ingress:shape-detector", context_ref)]
    elif status == "EXCLUDED":
        units = [{"unit_ref": context_ref, "decision": "EXCLUDED", "finding_kind": "none", "count": 0, "residual_findings": 0,
                  "rule_locator": "krista-gate:ingress:allowlist"}]
        status = "ADMITTED"
    else:
        return {**base, "gate_status": "UNVERIFIABLE", "units": [], "assurance_level": "UNVERIFIABLE",
                "limitation": f"Not scanned: {reason}. {detector.limitation}"}
    return {**base, "gate_status": status, "units": units}


def egress_record(execution_id: str, target_ref: str, detector: Detector, status: str, findings: Counter | None = None, scope: str = "OUTPUT_ARTIFACT",
                  reason: str = "") -> dict:
    """PASSED (nothing found, or the target is allowlisted), BLOCKED, or UNVERIFIABLE (not scannable)."""
    base = {"record_type": "egress-sanitization-record", "execution_id": execution_id, "target_ref": target_ref, "scope": scope,
            "assurance_level": "DECLARED", "limitation": detector.limitation}
    if status == "UNVERIFIABLE":
        return {**base, "gate_status": "UNVERIFIABLE", "units": [], "assurance_level": "UNVERIFIABLE",
                "limitation": f"Not scanned: {reason}. {detector.limitation}"}
    if status == "PASSED":
        units = [{"unit_ref": target_ref, "decision": "ALLOWED", "finding_kind": "none", "count": 0}]
    elif status == "EXCLUDED":
        units = [{"unit_ref": target_ref, "decision": "EXCLUDED", "finding_kind": "none", "count": 0, "rule_locator": "krista-gate:egress:allowlist"}]
        status = "PASSED"
    else:
        units = _units(findings or Counter(), "BLOCKED", "krista-gate:egress:shape-detector", target_ref)
    return {**base, "gate_status": status, "units": units}


def kinds_text(findings: Counter) -> str:
    """Category names and counts for a message to the agent: never a value."""
    return ", ".join(f"{kind} x{count}" for kind, count in sorted(findings.items()))
