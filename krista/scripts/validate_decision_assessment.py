"""Validate append-only decision-assessment event streams.

A decision assessment (runtime/DECISION_ASSESSMENT_POLICY.md) walks a general decision
through eight logged decision points, D1 to D8. Each event records that a gate was
passed, who decided, which references it rests on, and where the user-facing
explanation lives. It never holds the content. This validator checks structure and the
stream's invariants only: it does not read a source, judge a claim, or prove that a
human or a model did what an event says.

Per event:
- the field set required by its point, the actor allowed at that point, and a
  human_ref on every human-made event (never on a model-made one);
- an explanation block naming the response (KR- request id or UNVERIFIABLE) and all
  seven template sections;
- NOT_LOGGED_NO_LEDGER implies UNVERIFIABLE assurance; assurance is never VERIFIED;
- no raw-content key, secret shape or personal-data shape anywhere.

Per claim (D3), the citation rule:
- a claim with no source can only be HYPOTHETICAL: it is a hypothesis, not evidence;
- OBSERVED needs sources the session retrieved or the user supplied, each with a content
  digest; DERIVED needs at least one such source; a source the model only recalled
  caps the claim at INFERRED.

Per stream:
- D1 first and once; D2 criteria before any evidence; criteria change only by an
  explicit superseding D2 with a reason; D1 to D6 are frozen once D7 is recorded.
- D4 counts the AGAINST claims actually logged. D6 covers exactly the current criteria
  and may not recommend ACCEPT past a failed criterion, an insufficient countercheck or a
  weak key claim. A regulated domain (legal, HR, medical, financial) is framing only: no D6.
- D7 is human-only, needs a D6 that is newer than all evidence, states honestly whether it
  departs from the recommendation, and must hand a change to this system to the RFC.
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
from scripts.repo_scan import scan_text
from scripts.schema_loader import enum, mapping, required as required_fields, string_list
from scripts.strict_fields import enum_member, has_forbidden_key, is_nonempty_string, is_real_bool
from scripts.validate_decision_protocol import read_events

SCHEMA = "decision-assessment-event"
REQUIRED = required_fields(SCHEMA, "event")
REQUIRED_BY_POINT = {point: set(fields) for point, fields in mapping(SCHEMA, "event", "required_by_point").items()}
ALLOWED_ACTORS = {point: set(actors) for point, actors in mapping(SCHEMA, "event", "allowed_actors").items()}
RECOMMENDATION_FOR_DECISION = mapping(SCHEMA, "event", "recommendation_for_decision")

POINT = enum(SCHEMA, "event", "point")
ACTOR = enum(SCHEMA, "event", "actor_kind")
LOG_STATUS = enum(SCHEMA, "event", "log_status")
ASSURANCE = enum(SCHEMA, "event", "assurance_level")
STAKES = enum(SCHEMA, "event", "stakes")
REVERSIBILITY = enum(SCHEMA, "event", "reversibility")
DATA_CLASS = enum(SCHEMA, "event", "data_class")
DOMAIN_ROUTE = enum(SCHEMA, "event", "domain_route")
SUBJECT_KIND = enum(SCHEMA, "event", "subject_kind")
CLAIM_STATUS = enum(SCHEMA, "event", "claim_status")
DIRECTION = enum(SCHEMA, "event", "direction")
RETRIEVAL = enum(SCHEMA, "event", "retrieval")
COUNTERCHECK = enum(SCHEMA, "event", "countercheck")
RECOMMENDATION = enum(SCHEMA, "event", "recommendation")
CRITERION_RESULT = enum(SCHEMA, "event", "criterion_result")
DOWNGRADE_REASON = enum(SCHEMA, "event", "downgrade_reason")
DECISION = enum(SCHEMA, "event", "decision")
HANDOFF = enum(SCHEMA, "event", "handoff")
OUTCOME_REVIEW = enum(SCHEMA, "event", "outcome_review")
CHANGE_REASON = enum(SCHEMA, "event", "criteria_change_reason")

SECTIONS = frozenset(string_list(SCHEMA, "event", "explanation_sections"))
REGULATED = frozenset(string_list(SCHEMA, "event", "regulated_routes"))
SANITIZED_CLASSES = frozenset(string_list(SCHEMA, "event", "sanitized_classes"))
WEAK = frozenset(string_list(SCHEMA, "event", "weak_statuses"))
FROZEN = frozenset(string_list(SCHEMA, "event", "frozen_after_decision"))
FORBIDDEN = frozenset(string_list(SCHEMA, "event", "forbidden_fields"))
SECRET_CATEGORIES = frozenset(string_list(SCHEMA, "event", "secret_categories"))

_REQUEST_ID = re.compile(r"^KR-[0-9a-f]{12}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LOCATOR = re.compile(r"^\S{3,500}$")
_EVIDENCE_POINTS = frozenset({"D2", "D3", "D4", "D5"})


def _locator(value: object) -> bool:
    return isinstance(value, str) and bool(_LOCATOR.match(value))


def _locators(value: object, minimum: int = 1) -> bool:
    return isinstance(value, list) and len(value) >= minimum and all(_locator(item) for item in value)


def _strings(node: object, path: str = "event"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _strings(value, f"{path}[{index}]")


def _content_errors(event: dict) -> list[str]:
    errors: list[str] = []
    if has_forbidden_key(event, FORBIDDEN):
        errors.append("a raw-content field is forbidden; the event holds references, not content")
    for path, text in _strings(event):
        if [c for c in find_secrets(text) if c in SECRET_CATEGORIES]:
            errors.append(f"{path} carries a secret-shaped value")
        elif scan_text(text):
            errors.append(f"{path} carries a secret or personal-data shaped value")
    return errors


def _explanation_errors(event: dict) -> list[str]:
    block = event.get("explanation")
    if not isinstance(block, dict):
        return ["explanation must be an object"]
    errors: list[str] = []
    request_id = block.get("request_id")
    if request_id != "UNVERIFIABLE" and not (isinstance(request_id, str) and _REQUEST_ID.match(request_id)):
        errors.append("explanation.request_id must be a KR- request id or UNVERIFIABLE")
    sections = block.get("sections")
    if not isinstance(sections, list) or not all(isinstance(item, str) for item in sections):
        errors.append("explanation.sections must be a list of section names")
    elif set(sections) != SECTIONS or len(sections) != len(set(sections)):
        errors.append("explanation.sections must name each of the seven template sections exactly once")
    return errors


def _source_errors(status: object, sources: object) -> list[str]:
    """The citation rule: what a claim may rest on."""
    if not isinstance(sources, list):
        return ["source_refs must be a list"]
    errors: list[str] = []
    for index, source in enumerate(sources):
        label = f"source_refs[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
            continue
        if not _locator(source.get("locator")):
            errors.append(f"{label}.locator must be a locator without spaces, not prose")
        if not enum_member(source.get("retrieval"), RETRIEVAL):
            errors.append(f"{label}.retrieval is invalid")
        digest = source.get("content_digest")
        if digest is not None and not (isinstance(digest, str) and _DIGEST.match(digest)):
            errors.append(f"{label}.content_digest must be 64 lowercase hex characters")
    if errors or not enum_member(status, CLAIM_STATUS):
        return errors
    firm = [s for s in sources if s.get("retrieval") in ("RETRIEVED_THIS_SESSION", "USER_SUPPLIED")]
    if not sources:
        if status != "HYPOTHETICAL":
            errors.append("a claim with no source can only be HYPOTHETICAL; an uncited claim is not evidence")
    elif status in ("OBSERVED", "DERIVED") and not firm:
        errors.append(f"{status} needs a source the session retrieved or the user supplied; a recalled source caps the claim at INFERRED")
    if status == "OBSERVED":
        if len(firm) != len(sources):
            errors.append("OBSERVED may rest only on retrieved or user-supplied sources")
        if any(not (isinstance(s.get("content_digest"), str) and _DIGEST.match(s["content_digest"])) for s in firm):
            errors.append("OBSERVED needs a content_digest on every source")
    return errors


def _point_errors(event: dict, point: str) -> list[str]:
    errors: list[str] = []
    if point == "D1":
        for name, allowed in (("stakes", STAKES), ("reversibility", REVERSIBILITY), ("data_class", DATA_CLASS),
                              ("domain_route", DOMAIN_ROUTE), ("subject_kind", SUBJECT_KIND)):
            if not enum_member(event.get(name), allowed):
                errors.append(f"{name} is invalid")
        if not _locator(event.get("decision_owner_ref")):
            errors.append("decision_owner_ref must be a reference")
        if event.get("data_class") in SANITIZED_CLASSES and not _locator(event.get("sanitization_ref")):
            errors.append("personal or sensitive data needs a sanitization_ref (the ingress record)")
    elif point == "D2":
        if not _locators(event.get("criteria_refs")):
            errors.append("criteria_refs must be a non-empty list of references")
        elif len(set(event["criteria_refs"])) != len(event["criteria_refs"]):
            errors.append("criteria_refs must not repeat")
        has_supersede, has_reason = "supersedes_event_id" in event, "criteria_change_reason" in event
        if has_supersede != has_reason:
            errors.append("supersedes_event_id and criteria_change_reason go together")
        if has_reason and not enum_member(event.get("criteria_change_reason"), CHANGE_REASON):
            errors.append("criteria_change_reason is invalid")
    elif point == "D3":
        if not _locator(event.get("claim_ref")):
            errors.append("claim_ref must be a reference")
        if not enum_member(event.get("claim_status"), CLAIM_STATUS):
            errors.append("claim_status is invalid")
        if not enum_member(event.get("direction"), DIRECTION):
            errors.append("direction is invalid")
        if not is_real_bool(event.get("key_claim")):
            errors.append("key_claim must be true or false")
        errors.extend(_source_errors(event.get("claim_status"), event.get("source_refs")))
    elif point == "D4":
        if not enum_member(event.get("countercheck"), COUNTERCHECK):
            errors.append("countercheck is invalid")
        found = event.get("against_found")
        if isinstance(found, bool) or not isinstance(found, int) or found < 0:
            errors.append("against_found must be a non-negative integer")
        if not is_nonempty_string(event.get("search_scope_ref")):
            errors.append("search_scope_ref must name what was searched for counter-evidence")
    elif point == "D5":
        if not _locators(event.get("option_refs"), 2):
            errors.append("option_refs needs at least two references")
        if event.get("includes_no_action") is not True:
            errors.append("the option set must include the do-nothing option (includes_no_action true)")
    elif point == "D6":
        if not enum_member(event.get("recommendation"), RECOMMENDATION):
            errors.append("recommendation is invalid")
        results = event.get("criteria_results")
        if not isinstance(results, list) or not results:
            errors.append("criteria_results must be a non-empty list")
        else:
            for index, item in enumerate(results):
                if not isinstance(item, dict) or not _locator(item.get("criterion_ref")) or not enum_member(item.get("result"), CRITERION_RESULT):
                    errors.append(f"criteria_results[{index}] needs a criterion_ref and a result")
        has_from, has_reason = "downgraded_from" in event, "downgrade_reason" in event
        if has_from != has_reason:
            errors.append("downgraded_from and downgrade_reason go together")
        if has_from and event.get("downgraded_from") != "RECOMMEND_ACCEPT":
            errors.append("only a RECOMMEND_ACCEPT can be recorded as downgraded")
        if has_reason and not enum_member(event.get("downgrade_reason"), DOWNGRADE_REASON):
            errors.append("downgrade_reason is invalid")
        if has_from and event.get("recommendation") == "RECOMMEND_ACCEPT":
            errors.append("a downgraded recommendation cannot still be RECOMMEND_ACCEPT")
    elif point == "D7":
        if not enum_member(event.get("decision"), DECISION):
            errors.append("decision is invalid")
        if not is_real_bool(event.get("departs_from_recommendation")):
            errors.append("departs_from_recommendation must be true or false")
        if not enum_member(event.get("handoff"), HANDOFF):
            errors.append("handoff is invalid")
        elif event["handoff"] != "NONE":
            if not _locator(event.get("handoff_ref")):
                errors.append("a handoff needs a handoff_ref")
            if event.get("decision") != "GO":
                errors.append("only a GO decision can hand off")
    elif point == "D8":
        if not enum_member(event.get("outcome_review"), OUTCOME_REVIEW):
            errors.append("outcome_review is invalid")
        if not _locator(event.get("review_ref")):
            errors.append("review_ref must be a reference")
    return errors


def event_errors(event: object) -> list[str]:
    """Checks that need no stream context."""
    if not isinstance(event, dict):
        return ["event must be an object"]
    errors: list[str] = []
    if event.get("record_type") != "decision_assessment_event":
        errors.append("record_type must be decision_assessment_event")
    missing = [name for name in sorted(REQUIRED) if name not in event]
    if missing:
        return errors + [f"missing required field: {name}" for name in missing]
    for name in ("event_id", "assessment_id"):
        if not is_nonempty_string(event.get(name)):
            errors.append(f"{name} must be a non-empty string")
    point = event.get("point")
    if not enum_member(point, POINT):
        return errors + ["point is invalid"]
    if not enum_member(event.get("actor_kind"), ACTOR):
        errors.append("actor_kind is invalid")
    elif event["actor_kind"] not in ALLOWED_ACTORS[point]:
        errors.append(f"{point} cannot be made by {event['actor_kind']}")
    elif event["actor_kind"] == "HUMAN" and not _locator(event.get("human_ref")):
        errors.append("a human-made event needs a human_ref")
    elif event["actor_kind"] == "MODEL" and "human_ref" in event:
        errors.append("a model-made event cannot carry a human_ref")
    if not enum_member(event.get("log_status"), LOG_STATUS):
        errors.append("log_status is invalid")
    if not enum_member(event.get("assurance_level"), ASSURANCE):
        errors.append("assurance_level must be DECLARED or UNVERIFIABLE")
    elif event.get("log_status") == "NOT_LOGGED_NO_LEDGER" and event["assurance_level"] != "UNVERIFIABLE":
        errors.append("an event that was not logged carries UNVERIFIABLE assurance")
    errors.extend(_explanation_errors(event))
    errors.extend(f"{point} missing required field: {name}" for name in sorted(REQUIRED_BY_POINT[point]) if name not in event)
    errors.extend(_point_errors(event, point))
    errors.extend(_content_errors(event))
    return errors


class _Stream:
    def __init__(self) -> None:
        self.seq = 0
        self.d1: dict | None = None
        self.criteria: list[str] = []
        self.criteria_events: set[str] = set()
        self.claims: dict[str, dict] = {}
        self.last_d4: dict | None = None
        self.last_d6: dict | None = None
        self.last_d6_seq = 0
        self.last_evidence_seq = 0
        self.decided = False
        self.d3_or_d6_seen = False

    @property
    def regulated(self) -> bool:
        return bool(self.d1) and self.d1.get("domain_route") in REGULATED

    def against_logged(self) -> int:
        return sum(1 for claim in self.claims.values() if claim.get("direction") == "AGAINST")

    def accept_blockers(self) -> list[str]:
        blockers = []
        key_for = [c for c in self.claims.values() if c.get("direction") == "FOR" and c.get("key_claim") is True]
        if not key_for:
            blockers.append("EVIDENCE_WEAK")
        elif any(c.get("claim_status") == "HYPOTHETICAL" for c in key_for):
            blockers.append("KEY_CLAIM_HYPOTHETICAL")
        elif any(c.get("claim_status") in WEAK for c in key_for):
            blockers.append("EVIDENCE_WEAK")
        if not self.last_d4 or self.last_d4.get("countercheck") != "SUFFICIENT":
            blockers.append("COUNTEREVIDENCE_MISSING")
        return blockers


def _stream_errors(event: dict, state: _Stream, line: object) -> list[str]:
    point, errors = event["point"], []
    tag = f"line {line}: {point}"
    if state.d1 is None and point != "D1":
        return [f"line {line}: the first event of an assessment must be D1"]
    if point == "D1":
        if state.d1 is not None:
            return [f"{tag} an assessment has exactly one D1"]
        state.d1 = event
    elif state.decided and point in FROZEN:
        return [f"{tag} is frozen: the decision is recorded; start a new assessment instead of editing this one"]
    elif state.decided and point == "D7":
        return [f"{tag} an assessment has exactly one decision; a new decision is a new assessment"]
    state.seq += 1
    if point == "D2":
        refs = event.get("criteria_refs") if isinstance(event.get("criteria_refs"), list) else []
        superseded = event.get("supersedes_event_id")
        if state.criteria:
            if superseded not in state.criteria_events:
                errors.append(f"{tag} changes the criteria and must supersede an earlier D2 (supersedes_event_id) with a reason")
        elif superseded is not None:
            errors.append(f"{tag} supersedes nothing: there is no earlier D2")
        state.criteria, state.criteria_events = list(refs), state.criteria_events | {event["event_id"]}
        state.last_evidence_seq = state.seq
    elif point == "D3":
        if not state.criteria:
            errors.append(f"{tag} evidence cannot precede the criteria (D2)")
        if isinstance(event.get("claim_ref"), str):
            state.claims[event["claim_ref"]] = event
        state.last_evidence_seq = state.seq
    elif point == "D4":
        if not state.criteria:
            errors.append(f"{tag} the countercheck needs the criteria (D2) first")
        if isinstance(event.get("against_found"), int) and event["against_found"] != state.against_logged():
            errors.append(f"{tag} against_found {event['against_found']} does not match the {state.against_logged()} AGAINST claim(s) logged")
        state.last_d4, state.last_evidence_seq = event, state.seq
    elif point == "D5":
        if not state.criteria:
            errors.append(f"{tag} the options need the criteria (D2) first")
        state.last_evidence_seq = state.seq
    elif point == "D6":
        if state.regulated:
            errors.append(f"{tag} a regulated domain is framing only: no recommendation")
        if not state.criteria or state.last_d4 is None:
            errors.append(f"{tag} a recommendation needs the criteria (D2) and a countercheck (D4)")
        results = event.get("criteria_results") if isinstance(event.get("criteria_results"), list) else []
        covered = [r.get("criterion_ref") for r in results if isinstance(r, dict)]
        if state.criteria and (sorted(covered) != sorted(state.criteria)):
            errors.append(f"{tag} criteria_results must cover exactly the current criteria")
        blockers = state.accept_blockers()
        outcomes = [r.get("result") for r in results if isinstance(r, dict)]
        if "NOT_MET" in outcomes:
            blockers.append("CRITERION_NOT_MET")
        if "UNKNOWN" in outcomes:
            blockers.append("CRITERIA_UNKNOWN")
        if event.get("recommendation") == "RECOMMEND_ACCEPT" and blockers:
            errors.append(f"{tag} cannot recommend ACCEPT: {', '.join(dict.fromkeys(blockers))}")
        if "downgrade_reason" in event and event["downgrade_reason"] not in blockers:
            errors.append(f"{tag} downgrade_reason {event['downgrade_reason']} is not a reason this stream has")
        state.last_d6, state.last_d6_seq = event, state.seq
    elif point == "D7":
        if state.last_d6 is None and not state.regulated:
            errors.append(f"{tag} a decision follows a recommendation (D6) unless the domain is regulated")
        elif state.last_d6 is not None and state.last_d6_seq < state.last_evidence_seq:
            errors.append(f"{tag} the recommendation is stale: criteria or evidence changed after it")
        decision = event.get("decision")
        if state.last_d6 is not None and isinstance(event.get("departs_from_recommendation"), bool) and decision in RECOMMENDATION_FOR_DECISION:
            departs = RECOMMENDATION_FOR_DECISION[decision] != state.last_d6.get("recommendation")
            if event["departs_from_recommendation"] != departs:
                errors.append(f"{tag} departs_from_recommendation is {event['departs_from_recommendation']} but the decision {'departs from' if departs else 'follows'} the recommendation")
        elif state.last_d6 is None and event.get("departs_from_recommendation") is True:
            errors.append(f"{tag} there is no recommendation to depart from")
        kind = (state.d1 or {}).get("subject_kind")
        if decision == "GO" and kind == "KRISTA_CHANGE" and event.get("handoff") != "RFC":
            errors.append(f"{tag} a GO on a change to this system must hand off to the RFC")
        if event.get("handoff") == "RFC" and kind != "KRISTA_CHANGE":
            errors.append(f"{tag} only a change to this system goes to the RFC")
        state.decided = True
    elif point == "D8" and not state.decided:
        errors.append(f"{tag} the outcome review follows a decision (D7)")
    return errors


def validate(events: list[dict]) -> list[str]:
    if not isinstance(events, list):
        return ["events must be a list of event objects"]
    errors: list[str] = []
    seen: set[str] = set()
    streams: dict[str, _Stream] = {}
    for index, event in enumerate(events, 1):
        line = event.get("_line", index) if isinstance(event, dict) else index
        problems = event_errors(event)
        errors.extend(f"line {line}: {problem}" for problem in problems)
        if not isinstance(event, dict) or problems and not (is_nonempty_string(event.get("event_id")) and is_nonempty_string(event.get("assessment_id")) and enum_member(event.get("point"), POINT)):
            continue
        if event["event_id"] in seen:
            errors.append(f"line {line}: event_id {event['event_id']} is not unique")
            continue
        seen.add(event["event_id"])
        if problems:
            continue
        errors.extend(_stream_errors(event, streams.setdefault(event["assessment_id"], _Stream()), line))
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "validate":
        print("usage: validate_decision_assessment.py validate <events.jsonl>")
        return 2
    try:
        errors = validate(read_events(Path(argv[2])))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"Decision assessment validation: FAIL\n- {exc}")
        return 1
    print("Decision assessment validation: " + ("FAIL" if errors else "PASS (structure and invariants only)"))
    for error in errors:
        print(f"- {error}")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
