# krista-gate

Fail-closed `PreToolUse` gate that enforces a KRISTA vibe-code session record at the tool boundary.
Design, rules, measurements and limits: `docs/krista/PHASE1_GATE.hu.md`.

    python3 -I -m unittest discover -s tests          # unit tests (stdlib only)
    python3 tests/live/live_probe.py                   # manual live probe, needs the claude CLI
    python3 -I bin/pin.py check                        # verify the pinned KRISTA files
    python3 -I bin/pin.py update --from <KRISTA clone> # refresh the pin from a clean checkout
