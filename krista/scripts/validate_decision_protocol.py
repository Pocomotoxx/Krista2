"""Validate append-only RFC/Decision Protocol event streams."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.schema_loader import enum, mapping, string_list
from scripts.strict_fields import enum_member, has_forbidden_key, is_nonempty_string, same_identity

# The declarative shape (states, recommendations, lifecycle transitions, and
# forbidden raw-content fields) is defined once in
# runtime/schemas/decision-protocol-event.schema.json. Procedural rules — the
# required-field checks, the lifecycle chain, and cross-field requirements —
# stay below.
STATES = enum("decision-protocol-event", "event", "state")
# An auditor recommends; a human decides. A recommendation is advisory and is
# valid only during review, so it can never be presented as the decision itself.
AUDITOR_RECOMMENDATIONS = enum("decision-protocol-event", "event", "auditor_recommendation")
PRE_DECISION_STATES = set(string_list("decision-protocol-event", "event", "pre_decision_states"))
TRANSITIONS = {state: set(nexts) for state, nexts in mapping("decision-protocol-event", "event", "transitions").items()}
FORBIDDEN = set(string_list("decision-protocol-event", "event", "forbidden_fields"))


def read_events(path: Path) -> list[dict]:
    events = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"line {number}: event must be an object")
        event["_line"] = number
        events.append(event)
    return events


def contains_forbidden(value: object) -> bool:
    if isinstance(value, dict):
        return has_forbidden_key(value, FORBIDDEN)
    if isinstance(value, list):
        return any(contains_forbidden(item) for item in value)
    return False


def refs(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(is_nonempty_string(item) for item in value)


def validate(events: list[dict]) -> list[str]:
    if not isinstance(events, list):
        return ["events must be a list of event objects"]
    errors: list[str] = []
    seen_events: set[str] = set()
    state_by_protocol: dict[str, str] = {}
    implementation_actors: dict[str, str] = {}
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict):
            errors.append(f"event {index}: must be an object")
            continue
        line = event.get("_line", "?")
        event_id, protocol, state = event.get("event_id"), event.get("protocol_id"), event.get("state")
        if event.get("record_type") != "decision_protocol_event":
            errors.append(f"line {line}: record_type must be decision_protocol_event")
        if not isinstance(event_id, str) or not event_id or event_id in seen_events:
            errors.append(f"line {line}: event_id must be unique and non-empty")
        else:
            seen_events.add(event_id)
        if not isinstance(protocol, str) or not protocol:
            errors.append(f"line {line}: protocol_id is required")
            continue
        if not enum_member(state, STATES):
            errors.append(f"line {line}: invalid state")
            continue
        if contains_forbidden(event):
            errors.append(f"line {line}: raw-content field is forbidden")
        if not refs(event.get("provenance_refs")):
            errors.append(f"line {line}: provenance_refs must be a non-empty string array")
        previous = state_by_protocol.get(protocol)
        if previous is None:
            if state != "DRAFT" or event.get("previous_state") is not None:
                errors.append(f"line {line}: first protocol event must be DRAFT with null previous_state")
        elif event.get("previous_state") != previous or state not in TRANSITIONS[previous]:
            errors.append(f"line {line}: invalid transition from {previous} to {state}")
        if state == "PROPOSED" and not refs(event.get("proposal_refs")):
            errors.append(f"line {line}: PROPOSED requires proposal_refs")
        if state in {"ACCEPTED", "REJECTED"} and not is_nonempty_string(event.get("human_approval_ref")):
            errors.append(f"line {line}: {state} requires human_approval_ref")
        recommendation = event.get("auditor_recommendation")
        if recommendation is not None:
            if recommendation not in AUDITOR_RECOMMENDATIONS:
                errors.append(f"line {line}: invalid auditor_recommendation")
            elif state not in PRE_DECISION_STATES:
                errors.append(f"line {line}: auditor_recommendation is a review-phase advisory and is only valid in DRAFT or PROPOSED, not {state}")
        if state == "IMPLEMENTED":
            if not refs(event.get("implementation_refs")):
                errors.append(f"line {line}: IMPLEMENTED requires implementation_refs")
            actor = event.get("implementation_actor_ref")
            if not is_nonempty_string(actor):
                errors.append(f"line {line}: IMPLEMENTED requires implementation_actor_ref")
            else:
                implementation_actors[protocol] = actor
        if state == "VERIFIED":
            for field in ("implementation_refs", "review_refs", "test_refs"):
                if not refs(event.get(field)):
                    errors.append(f"line {line}: VERIFIED requires {field}")
            reviewer = event.get("reviewer_ref")
            if not is_nonempty_string(reviewer):
                errors.append(f"line {line}: VERIFIED requires reviewer_ref")
            elif same_identity(reviewer, implementation_actors.get(protocol)):
                errors.append(f"line {line}: VERIFIED reviewer must be independent")
        state_by_protocol[protocol] = state
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "validate":
        print("usage: validate_decision_protocol.py validate <events.jsonl>")
        return 2
    try:
        errors = validate(read_events(Path(argv[2])))
    except (OSError, ValueError) as exc:
        print(f"Decision protocol validation: FAIL\n- {exc}")
        return 1
    if errors:
        print("Decision protocol validation: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Decision protocol validation: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
