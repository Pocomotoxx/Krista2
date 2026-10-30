# krista-gate

Fail-closed `PreToolUse` gate that enforces a KRISTA vibe-code session record at the tool boundary.
Design, rules, measurements and limits: `docs/krista/PHASE1_GATE.hu.md`.

    python3 -I -m unittest discover -s tests          # unit tests (stdlib only)
    python3 tests/live/live_probe.py                   # manual live probe, needs the claude CLI
    python3 -I bin/pin.py check                        # verify the pinned KRISTA files
    python3 -I bin/pin.py update --from <KRISTA clone> # refresh the pin from a clean checkout

## Phase 2: ledger and filters

The same fail-closed command now also runs on `UserPromptSubmit` and `Stop`, and `Read` is in the tool matcher. It scans what
reaches the model (prompt, files opened by `Read` or `cat`/`head`/`tail`/`grep`/`wc`) and what leaves it (written content, `git add`,
commit messages, network and MCP inputs, the last chat message) for credential and Hungarian personal-identifier shapes, and appends
every decision to a hash-chained ledger in the format of KRISTA's `runtime_ledger`. See `docs/krista/PHASE2_LEDGER_FILTERS.hu.md`.

    KRISTA_RUNTIME_LOG_ROOT=/var/lib/krista/ledger  KRISTA_LEDGER_REQUIRED=1
    python3 bin/krista_ledger.py verify --root /var/lib/krista/ledger
