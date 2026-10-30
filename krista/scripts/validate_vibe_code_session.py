"""Validate the portable vibe-code session contract.

This validator checks structure and safety invariants only. It never inspects
or executes the target repository and never proves that a change is correct.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.schema_loader import enum, string_list
from scripts.strict_fields import enum_member, is_nonempty_string
from scripts.test_plan_guard import violations as test_plan_violations

# The declarative shape (mode and protected_paths_check enums, permitted action
# vocabulary) is defined once in runtime/schemas/vibe-code-session.schema.json.
# Procedural rules (mode/action compatibility, authorized-write path requirement,
# per-phase and per-receipt evidence) stay below.
MODES = enum("vibe-code-session", "record", "mode")
PROTECTED_PATHS_CHECK = enum("vibe-code-session", "record", "protected_paths_check")
ALLOWED_ACTIONS = set(string_list("vibe-code-session", "record", "actions"))
PHASE_STATUS = enum("vibe-code-session", "record", "phase_status")
RECEIPT_STATUS = enum("vibe-code-session", "record", "receipt_status")
REVIEW_STATUS = enum("vibe-code-session", "record", "review_status")
OPEN_QUESTION_STATUS = enum("vibe-code-session", "record", "open_question_status")
TASK_KIND = enum("vibe-code-session", "record", "task_kind")
REPRODUCTION_OUTCOME = enum("vibe-code-session", "record", "reproduction_outcome")
SYMPTOM_STATUS = enum("vibe-code-session", "record", "symptom_status")
CAUSE_STATUS = enum("vibe-code-session", "record", "cause_status")
# runtime/VIBE_CODE_DEVELOPMENT_POLICY.md: merge, release, and deployment are
# blocked in every mode; the default branch is read-only.
BLOCKED_ACTIONS = frozenset(string_list("vibe-code-session", "record", "blocked_actions"))
WRITE_ACTIONS = frozenset(string_list("vibe-code-session", "record", "write_actions"))
DEFAULT_BRANCHES = frozenset(string_list("vibe-code-session", "record", "default_branches"))
GATED_PHASES = frozenset(string_list("vibe-code-session", "record", "gated_phases"))
GATED_PHASE_STATUSES = frozenset(string_list("vibe-code-session", "record", "gated_phase_statuses"))


def _unsafe_path(value: object) -> bool:
    """An allowlist entry must be a repository-relative path."""
    if not is_nonempty_string(value):
        return True
    text = value.strip()
    if text.startswith(("/", "~", "\\")) or PureWindowsPath(text).drive:
        return True
    return ".." in PurePosixPath(text.replace("\\", "/")).parts


def _within(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(path, pattern) or path == pattern or path.startswith(pattern.rstrip("/") + "/"):
            return True
    return False


def _branch(value: object) -> str:
    if not isinstance(value, str):
        return ""
    name = value.strip()
    for prefix in ("refs/heads/", "origin/", "refs/remotes/origin/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.casefold()


def _open_question_errors(data: dict, writes: bool, mode: object) -> list[str]:
    """A blocking question that is still open stops implementation (skill: Required target contract)."""
    questions = data.get("open_questions")
    if questions is None:
        # An authorized write must state its open questions; an empty list says there are none.
        return ["authorized write requires open_questions (an empty list states there are none)"] if mode == "AUTHORIZED_WRITE" else []
    if not isinstance(questions, list):
        return ["open_questions must be a list"]
    errors: list[str] = []
    blocking_open = False
    for index, item in enumerate(questions):
        label = f"open_questions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label} must be an object")
            blocking_open = True
            continue
        status, blocking = item.get("status"), item.get("blocking")
        if not is_nonempty_string(item.get("question")):
            errors.append(f"{label} needs a non-empty question")
        if not isinstance(blocking, bool):
            errors.append(f"{label}.blocking must be true or false")
        if not enum_member(status, OPEN_QUESTION_STATUS):
            errors.append(f"{label}.status is invalid")
        elif status == "ANSWERED" and not is_nonempty_string(item.get("answer_ref")):
            errors.append(f"{label} is ANSWERED and needs an answer_ref")
        elif status == "ASSUMED":
            if not is_nonempty_string(item.get("assumption")):
                errors.append(f"{label} is ASSUMED and needs an assumption")
            if blocking is True:
                errors.append(f"{label} is blocking and can be closed only by an answer, not an assumption")
        # Malformed entries fail closed: they keep the gate shut.
        if status == "OPEN" and blocking is True or not enum_member(status, OPEN_QUESTION_STATUS) or not isinstance(blocking, bool):
            blocking_open = True
        elif status == "ASSUMED" and blocking is True:
            blocking_open = True
    if blocking_open:
        if writes:
            errors.append("a blocking open question forbids write actions until it is answered")
        changed = data.get("changed_paths")
        if isinstance(changed, list) and changed:
            errors.append("a blocking open question forbids changed_paths until it is answered")
        for phase in data.get("phases") if isinstance(data.get("phases"), list) else []:
            if (
                isinstance(phase, dict)
                and str(phase.get("name", "")).strip().casefold() in GATED_PHASES
                and phase.get("status") in GATED_PHASE_STATUSES
            ):
                errors.append(f"phase {phase.get('name')!r} cannot be {phase.get('status')} while a blocking open question is unanswered")
    return errors


def derived_reproduction_outcome(before: object, after: object) -> str:
    """What the before/after pair on one reproduction supports; the claim may not exceed it."""
    if after == "FAIL":
        return "NOT_FIXED"
    if after != "PASS":
        return "NOT_RUN"
    return "FIXED" if before == "FAIL" else "PARTIAL"


def _reproduction_errors(data: dict, writes: bool) -> list[str]:
    """A defect fix is judged by one reproduction run before and after (skill: Development loop)."""
    block = data.get("reproduction")
    kind = data.get("task_kind")
    errors: list[str] = []
    if "task_kind" in data and not enum_member(kind, TASK_KIND):
        errors.append("task_kind is invalid")
    if block is None:
        if kind == "DEFECT" and writes:
            errors.append("a defect fix that writes needs a reproduction (the same test run before and after)")
        return errors
    if not isinstance(block, dict):
        return errors + ["reproduction must be an object"]
    errors.extend(f"reproduction: {problem}" for problem in test_plan_violations([block]))
    before, after = block.get("before"), block.get("after")
    for name, value in (("before", before), ("after", after)):
        if not enum_member(value, RECEIPT_STATUS):
            errors.append(f"reproduction.{name} is invalid")
        elif value in ("PASS", "FAIL") and not is_nonempty_string(block.get(f"{name}_ref")):
            errors.append(f"reproduction.{name} is {value} and needs {name}_ref (the evidence of that run)")
    if not enum_member(block.get("outcome"), REPRODUCTION_OUTCOME):
        errors.append("reproduction.outcome is invalid")
    elif enum_member(before, RECEIPT_STATUS) and enum_member(after, RECEIPT_STATUS):
        derived = derived_reproduction_outcome(before, after)
        if block["outcome"] != derived:
            errors.append(f"reproduction.outcome {block['outcome']} does not follow from before {before} and after {after}: the pair supports {derived}")
    if block.get("outcome") == "FIXED":
        before_rev, after_rev = block.get("before_revision"), block.get("after_revision")
        if not (is_nonempty_string(before_rev) and is_nonempty_string(after_rev)):
            errors.append("FIXED needs before_revision and after_revision")
        elif before_rev == after_rev or "UNVERIFIABLE" in (before_rev, after_rev):
            errors.append("FIXED needs two different, known revisions: the same test must fail on one and pass on the other")
    symptom, cause = block.get("symptom_status"), block.get("cause_status")
    if not enum_member(symptom, SYMPTOM_STATUS):
        errors.append("reproduction.symptom_status is invalid")
    elif symptom == "OBSERVED" and before != "FAIL":
        errors.append("a symptom is OBSERVED only when the reproduction failed before the fix; otherwise it is only REPORTED")
    if not enum_member(cause, CAUSE_STATUS):
        errors.append("reproduction.cause_status is invalid")
    elif cause == "DERIVED" and block.get("outcome") != "FIXED":
        errors.append("a cause is DERIVED only from a confirmed fix; otherwise it is INFERRED or HYPOTHETICAL")
    return errors


def validate(data: dict) -> list[str]:
    if not isinstance(data, dict):
        return ["data must be a JSON object"]
    errors: list[str] = []
    mode = data.get("mode")
    if not enum_member(mode, MODES):
        errors.append("invalid mode")
        mode = None

    target = data.get("target")
    scope = data.get("scope")
    if not isinstance(target, dict) or not isinstance(scope, dict):
        return errors + ["target and scope must be objects"]

    actions = scope.get("actions")
    if not isinstance(actions, list):
        errors.append("scope.actions must be a list")
        actions = []
    elif any(not enum_member(action, ALLOWED_ACTIONS) for action in actions):
        errors.append("scope.actions contains an invalid value")
    actions = [action for action in actions if isinstance(action, str)]
    if mode == "CANDIDATE_ONLY" and any(action in actions for action in BLOCKED_ACTIONS):
        errors.append("candidate-only cannot merge or deploy")
    elif any(action in actions for action in BLOCKED_ACTIONS):
        errors.append("merge and deploy are blocked in every mode")
    if mode == "PLAN_ONLY" and any(action in actions for action in {"edit", "commit", "push", "merge", "deploy"}):
        errors.append("plan-only cannot edit, commit, push, merge, or deploy")
    allowed_paths = scope.get("allowed_paths")
    if mode == "AUTHORIZED_WRITE" and (
        not isinstance(allowed_paths, list) or not any(isinstance(path, str) and path.strip() for path in allowed_paths)
    ):
        errors.append("authorized write requires allowed_paths")
    allowed = [path.strip() for path in allowed_paths if is_nonempty_string(path)] if isinstance(allowed_paths, list) else []
    if isinstance(allowed_paths, list) and any(_unsafe_path(path) for path in allowed_paths):
        errors.append("allowed_paths must be repository-relative (no absolute, home, drive, or '..' entries)")
    forbidden_paths = scope.get("forbidden_paths", [])
    forbidden = [path.strip() for path in forbidden_paths if is_nonempty_string(path)] if isinstance(forbidden_paths, list) else []

    writes = any(action in actions for action in WRITE_ACTIONS)
    if writes and _branch(target.get("branch")) in DEFAULT_BRANCHES:
        errors.append("the default branch is read-only; write to a task branch or worktree")

    if not enum_member(target.get("protected_paths_check"), PROTECTED_PATHS_CHECK):
        errors.append("invalid protected_paths_check")
    elif target["protected_paths_check"] == "FAIL" and writes:
        errors.append("protected_paths_check FAIL blocks any write")

    changed = data.get("changed_paths", [])
    if not isinstance(changed, list) or not all(is_nonempty_string(path) for path in changed):
        errors.append("changed_paths must be a list of non-empty strings")
    else:
        if changed and mode == "PLAN_ONLY":
            errors.append("plan-only cannot change paths")
        outside = [path for path in changed if not _within(path.strip(), allowed)]
        if changed and mode != "PLAN_ONLY" and outside:
            errors.append("changed_paths outside the allowlist: " + ", ".join(sorted(outside)[:5]))
        hit = [path for path in changed if _within(path.strip(), forbidden)]
        if hit:
            errors.append("changed_paths touch forbidden paths: " + ", ".join(sorted(hit)[:5]))

    phases = data.get("phases")
    if not isinstance(phases, list) or not phases:
        errors.append("phases must be a non-empty list")
    else:
        for phase in phases:
            if not isinstance(phase, dict):
                errors.append("phase must be an object")
                continue
            if not enum_member(phase.get("status"), PHASE_STATUS):
                errors.append(f"phase status {phase.get('status')!r} is invalid (VERIFIED, PUSHED, MERGED, DEPLOYED are not session statuses)")
            elif phase["status"] == "PASS" and not is_nonempty_string(phase.get("evidence_ref")):
                errors.append("PASS phase requires evidence_ref")

    receipts = data.get("test_receipts", [])
    if not isinstance(receipts, list):
        errors.append("test_receipts must be a list")
        receipts = []
    for receipt in receipts:
        if not isinstance(receipt, dict):
            errors.append("test receipt must be an object")
            continue
        if not enum_member(receipt.get("status"), RECEIPT_STATUS):
            errors.append(f"test receipt status {receipt.get('status')!r} is invalid")
        elif receipt["status"] == "PASS" and not is_nonempty_string(receipt.get("evidence_ref")):
            errors.append("PASS test receipt requires evidence_ref")
    if "review_status" in data and not enum_member(data.get("review_status"), REVIEW_STATUS):
        errors.append(f"review_status {data.get('review_status')!r} is invalid")
    errors.extend(_open_question_errors(data, writes, mode))
    errors.extend(_reproduction_errors(data, writes))

    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_vibe_code_session.py <json-file>")
        return 2
    try:
        data = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Vibe-code session: FAIL - {exc}")
        return 1
    errors = validate(data)
    if errors:
        print("Vibe-code session: FAIL")
        print(*[f"- {error}" for error in errors], sep="\n")
        return 1
    print("Vibe-code session: PASS (shape and safety invariants only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
