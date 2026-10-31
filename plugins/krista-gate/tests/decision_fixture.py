"""Decision-event builders copied from KRISTA scripts/tests/test_decision_assessment.py, used to feed the ledger real streams."""

DIGEST = "a" * 64
SECTIONS = ["DECISION_AND_DECIDER", "EVIDENCE_AND_LEVEL", "COUNTEREVIDENCE", "OPTIONS",
            "UNVERIFIABLE_ITEMS", "GATE_RESULT", "NEXT_HUMAN_STEP"]


def ev(point, n, **fields):
    actor = "MODEL" if point in ("D6",) else "HUMAN"
    base = {
        "record_type": "decision_assessment_event", "event_id": f"e{n}", "assessment_id": "A1", "point": point,
        "actor_kind": actor, "log_status": "LOGGED_LOCAL", "assurance_level": "DECLARED",
        "explanation": {"request_id": "KR-0123456789ab", "sections": list(SECTIONS)},
    }
    if actor == "HUMAN":
        base["human_ref"] = f"chat:turn-{n}"
    base.update(fields)
    return base


def d1(**f):
    return ev("D1", 1, decision_owner_ref="owner:user", stakes="MEDIUM", reversibility="REVERSIBLE",
              data_class="INTERNAL", domain_route="NONE", subject_kind="GENERAL", **f)


def d2(n=2, refs=("crit:cost", "crit:risk"), **f):
    return ev("D2", n, criteria_refs=list(refs), **f)


def d3(n, ref="claim:1", status="OBSERVED", direction="FOR", key=True, sources=None, **f):
    if sources is None:
        sources = [{"locator": "https://example.org/report", "retrieval": "RETRIEVED_THIS_SESSION", "content_digest": DIGEST}]
    actor = {"actor_kind": "MODEL"}
    e = ev("D3", n, claim_ref=ref, claim_status=status, direction=direction, key_claim=key, source_refs=sources, **f)
    e.update(actor)
    e.pop("human_ref", None)
    return e


def d4(n, found=0, check="SUFFICIENT", **f):
    e = ev("D4", n, countercheck=check, against_found=found, search_scope_ref="scope:web-and-user-docs", **f)
    e["actor_kind"] = "MODEL"
    e.pop("human_ref", None)
    return e


def d5(n):
    return ev("D5", n, option_refs=["opt:a", "opt:none"], includes_no_action=True)


def d6(n, rec="RECOMMEND_ACCEPT", results=("MET", "MET"), crit=("crit:cost", "crit:risk"), **f):
    return ev("D6", n, recommendation=rec, criteria_results=[{"criterion_ref": c, "result": r} for c, r in zip(crit, results)], **f)


def d7(n, decision="GO", departs=False, handoff="NONE", **f):
    return ev("D7", n, decision=decision, departs_from_recommendation=departs, handoff=handoff, **f)


def good():
    return [d1(), d2(), d3(3), d4(4), d5(5), d6(6), d7(7)]


