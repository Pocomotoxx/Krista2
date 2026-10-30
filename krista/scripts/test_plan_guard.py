"""A test plan must be runnable, not just named.

External audits noted that the proposed regression tests were often just names:
`test_besv_snapshot_atomicity`, `test_replayed_belief_rejected`. A name tells a
reviewer nothing about how to run the test or how to tell whether it failed. This
guard requires each declared test plan to carry the parts that make it
reproducible: an input, an oracle, a failure signature, an environment, and a
command to run it.

No I/O, no side effects: pass the plans, get back what each is missing.
"""

from __future__ import annotations

# A named test that omits any of these cannot be run or judged by someone else.
REQUIRED_FIELDS = (
    "test_id",            # the identifier
    "input",              # the fixture or input generator
    "oracle",             # what decides pass or fail
    "failure_signature",  # what a failure looks like
    "environment",        # where it runs (target hardware, emulator, x86 CI)
    "repro_command",      # the exact command to reproduce it
)


def _missing(plan: dict) -> list[str]:
    missing: list[str] = []
    for field in REQUIRED_FIELDS:
        value = plan.get(field)
        if not isinstance(value, str) or not value.strip():
            missing.append(field)
    return missing


def violations(plans: list[dict]) -> list[str]:
    """Return, per plan, the fields that keep it from being reproducible.

    An empty result means every plan carries an input, oracle, failure
    signature, environment, and repro command, each a non-empty string.
    """
    problems: list[str] = []
    if not isinstance(plans, list):
        return ["test_plans must be a list"]
    for index, plan in enumerate(plans):
        if not isinstance(plan, dict):
            problems.append(f"plan[{index}] must be an object")
            continue
        missing = _missing(plan)
        if missing:
            problems.append(f"plan[{index}] is not reproducible; missing: {', '.join(missing)}")
    return problems
