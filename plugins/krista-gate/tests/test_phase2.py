"""Phase 2: the hash-chained ledger, the ingress and egress filters, the prompt and Stop hooks."""

import json
import multiprocessing
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
sys.path.insert(0, str(PLUGIN / "bin"))
sys.path.insert(0, str(HERE))

import krista_filters as filters  # noqa: E402
import krista_gate as gate  # noqa: E402
import krista_ledger as ledger  # noqa: E402
from decision_fixture import d1, d2, d3, d4, d5, d6, d7, good  # noqa: E402
from test_gate import GATE, VALIDATOR, GateCase, base_record  # noqa: E402

KRISTA = PLUGIN.parents[1] / "krista"
MODULES = gate.load_modules()
# Built at run time so this file holds no secret-shaped literal.
TOKEN = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jK5"
EMAIL = "someone" + "@example.hu"
PASSWORD_LINE = "password = '" + "hunter2hunter2" + "'\n"


def worker(args):
    root, n = args
    for i in range(10):
        ledger.append(Path(root), "gate", {"record_type": "gate_decision", "n": n, "i": i})


class Tmp(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.logs = self.base / "logs"
        self.logs.mkdir(mode=0o700)


class LedgerChain(Tmp):
    def test_append_chains_and_verifies(self):
        for i in range(3):
            ledger.append(self.logs, "gate", {"record_type": "gate_decision", "i": i})
        self.assertEqual(ledger.verify(self.logs, "gate"), [])
        rows = ledger.tail(self.logs, "gate", 10)
        self.assertEqual(rows[0]["previous_hash"], "GENESIS")
        self.assertEqual(rows[1]["previous_hash"], rows[0]["record_hash"])

    def test_every_kind_of_tampering_is_found(self):
        for i in range(3):
            ledger.append(self.logs, "gate", {"record_type": "gate_decision", "i": i})
        path = self.logs / "gate.jsonl"
        original = path.read_text()
        lines = original.splitlines()
        cases = {
            "edited field": "\n".join([lines[0], lines[1].replace('"i": 1', '"i": 9'), lines[2]]) + "\n",
            "deleted line": "\n".join([lines[0], lines[2]]) + "\n",
            "swapped lines": "\n".join([lines[1], lines[0], lines[2]]) + "\n",
            "garbage line": original + "{not json\n",
            "non-object line": original + "[1]\n",
        }
        for name, text in cases.items():
            path.write_text(text)
            self.assertTrue(ledger.verify(self.logs, "gate"), name)
        path.write_text(original)
        self.assertEqual(ledger.verify(self.logs, "gate"), [])

    def test_a_broken_chain_is_not_extended(self):
        ledger.append(self.logs, "gate", {"record_type": "x"})
        with open(self.logs / "gate.jsonl", "a") as handle:
            handle.write("garbage\n")
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.logs, "gate", {"record_type": "y"})

    def test_parallel_writers_cannot_fork_the_chain(self):
        with multiprocessing.Pool(6) as pool:
            pool.map(worker, [(str(self.logs), n) for n in range(6)])
        self.assertEqual(ledger.verify(self.logs, "gate"), [])
        self.assertEqual(len(ledger.tail(self.logs, "gate", 1000)), 60)

    def test_reserved_fields_and_unknown_kinds_are_refused(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.logs, "gate", {"record_hash": "x"})
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.logs, "nope", {})

    def test_the_root_must_be_absolute_private_and_outside_the_project(self):
        project = self.base / "project"
        project.mkdir()
        with self.assertRaises(ledger.LedgerError):
            ledger.ledger_root(None)
        with self.assertRaises(ledger.LedgerError):
            ledger.ledger_root("relative/dir")
        for inside in (project, project / "logs", self.base):
            with self.assertRaises(ledger.LedgerError, msg=str(inside)):
                ledger.ledger_root(str(inside), project)
        open_dir = self.base / "open"
        open_dir.mkdir()
        open_dir.chmod(0o777)
        with self.assertRaises(ledger.LedgerError):
            ledger.ledger_root(str(open_dir), project)
        made = ledger.ledger_root(str(self.base / "elsewhere" / "ledger"), project)
        self.assertEqual(stat.S_IMODE(made.stat().st_mode), 0o700)

    def test_krista_runtime_ledger_and_this_ledger_verify_each_other(self):
        sys.path.insert(0, str(KRISTA))
        import importlib

        runtime = importlib.import_module("scripts.runtime_ledger")
        events = good()
        runtime.append_record(self.logs, "decision", events[0])
        ledger.append(self.logs, "decision", events[1])
        runtime.append_record(self.logs, "decision", events[2])
        self.assertEqual(runtime.verify_ledger(self.logs, "decision"), [])
        self.assertEqual(ledger.verify(self.logs, "decision"), [])
        lines = (self.logs / "decisions.jsonl").read_text().splitlines()
        (self.logs / "decisions.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
        self.assertTrue(runtime.verify_ledger(self.logs, "decision"))
        self.assertTrue(ledger.verify(self.logs, "decision"))


class DecisionEvents(Tmp):
    def setUp(self):
        super().setUp()
        self.validator, self.keys = ledger.load_krista(KRISTA)

    def test_a_valid_stream_is_appended_and_verifies(self):
        for event in good():
            ledger.append_decision(self.logs, event, self.validator, self.keys)
        self.assertEqual(ledger.verify(self.logs, "decision"), [])
        self.assertEqual(len(ledger.tail(self.logs, "decision", 20)), 7)

    def test_an_event_that_breaks_the_stream_is_refused_and_not_written(self):
        events = good()
        ledger.append_decision(self.logs, events[0], self.validator, self.keys)
        before = (self.logs / "decisions.jsonl").read_text()
        with self.assertRaises(ledger.LedgerError):
            ledger.append_decision(self.logs, events[6], self.validator, self.keys)  # D7 without D2..D6
        self.assertEqual((self.logs / "decisions.jsonl").read_text(), before)

    def test_raw_text_and_a_missing_assessment_are_refused(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.append_decision(self.logs, {**good()[0], "prompt": "text"}, self.validator, self.keys)
        with self.assertRaises(ledger.LedgerError):
            ledger.append_decision(self.logs, {"record_type": "decision_assessment_event"}, self.validator, self.keys)

    def test_the_command_line_appends_and_verifies(self):
        event = self.base / "event.json"
        event.write_text(json.dumps(good()[0]))
        run = lambda *args: subprocess.run([sys.executable, "-I", str(PLUGIN / "bin" / "krista_ledger.py"), *args], capture_output=True, text=True)
        self.assertEqual(run("append-decision", "--root", str(self.logs), str(event)).returncode, 0)
        self.assertEqual(run("verify", "--root", str(self.logs)).returncode, 0)
        event.write_text(json.dumps({**good()[0], "prompt": "x"}))
        self.assertEqual(run("append-decision", "--root", str(self.logs), str(event)).returncode, 1)


class DetectorAndRecords(unittest.TestCase):
    def setUp(self):
        self.detector = filters.Detector(MODULES.redaction, MODULES.repo_scan)

    def test_credential_and_identifier_shapes_are_found_and_clean_text_is_not(self):
        self.assertIn("github-token", self.detector.scan(TOKEN))
        self.assertIn("secret_assignment", self.detector.scan(PASSWORD_LINE))
        self.assertIn("email", self.detector.scan(EMAIL))
        self.assertFalse(self.detector.scan("def add(a, b):\n    return a + b\n"))

    def test_pii_can_be_switched_off_but_credentials_cannot(self):
        quiet = filters.Detector(MODULES.redaction, MODULES.repo_scan, pii=False)
        self.assertFalse(quiet.scan(EMAIL))
        self.assertTrue(quiet.scan(TOKEN))
        self.assertEqual(quiet.coverage, "SECRETS_ONLY")

    def test_every_record_shape_passes_the_pinned_validators_and_holds_no_value(self):
        found = self.detector.scan(TOKEN + EMAIL)
        execution = filters.ref("session", "s1")
        records = [
            ("ingress", filters.ingress_record(execution, "file:x", self.detector, "d@1", "ADMITTED")),
            ("ingress", filters.ingress_record(execution, "file:x", self.detector, "d@1", "WITHHELD", found)),
            ("ingress", filters.ingress_record(execution, "file:x", self.detector, "d@1", "EXCLUDED")),
            ("ingress", filters.ingress_record(execution, "file:x", self.detector, "d@1", "UNVERIFIABLE", reason="binary file")),
            ("egress", filters.egress_record(execution, "file:x", self.detector, "PASSED")),
            ("egress", filters.egress_record(execution, "file:x", self.detector, "EXCLUDED")),
            ("egress", filters.egress_record(execution, "file:x", self.detector, "BLOCKED", found)),
            ("egress", filters.egress_record(execution, "file:x", self.detector, "UNVERIFIABLE", reason="too large")),
        ]
        for kind, record in records:
            errors = (MODULES.ingress if kind == "ingress" else MODULES.egress).validate(record)
            self.assertEqual(errors, [], (kind, record))
            text = json.dumps(record)
            self.assertNotIn(TOKEN, text)
            self.assertNotIn(EMAIL, text)

    def test_read_for_scan_statuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "t.txt").write_text("hello")
            (root / "b.bin").write_bytes(b"\x00\x01")
            (root / "big.txt").write_text("x" * 100)
            self.assertEqual(filters.read_for_scan(root / "t.txt"), ("hello", "ok"))
            self.assertEqual(filters.read_for_scan(root / "b.bin")[1], "binary")
            self.assertEqual(filters.read_for_scan(root / "big.txt", 10)[1], "toolarge")
            self.assertEqual(filters.read_for_scan(root / "absent")[1], "missing")
            self.assertEqual(filters.read_for_scan(root)[1], "missing")


class Boundary(GateCase):
    def setUp(self):
        super().setUp()
        (self.root / "docs" / "note.md").write_text("plain note\n")
        (self.root / "src" / "leak.py").write_text(f'KEY = "{TOKEN}"\n')
        (self.root / "src" / "mail.txt").write_text(f"reach me at {EMAIL}\n")
        (self.root / "src" / "blob.bin").write_bytes(b"\x00\x01\x02")
        self.meta = {}

    def gate_call(self, tool, tool_input, **kwargs):
        env = {"CLAUDE_PROJECT_DIR": str(self.root), "KRISTA_SESSION_RECORD": str(self.record_path), **kwargs.pop("env", {})}
        self.put(kwargs.pop("record", None) or base_record())
        event = {"tool_name": tool, "tool_input": tool_input, "cwd": str(self.root), "permission_mode": "default", "session_id": "s1", **kwargs}
        return gate.decide(event, env, validator=VALIDATOR, branch_fn=lambda root: "task/x", meta=self.meta)

    # ----- ingress
    def test_read_withholds_a_file_with_a_credential_or_an_identifier(self):
        self.assertDenied(self.gate_call("Read", {"file_path": "src/leak.py"}), "G-INGRESS")
        self.assertDenied(self.gate_call("Read", {"file_path": "src/mail.txt"}), "G-INGRESS")
        self.assertEqual([r["gate_status"] for r in self.meta["ingress"]], ["WITHHELD", "WITHHELD"])

    def test_read_admits_clean_text_and_records_binary_as_unverifiable(self):
        self.assertAllowed(self.gate_call("Read", {"file_path": "docs/note.md"}))
        self.assertAllowed(self.gate_call("Read", {"file_path": "src/blob.bin"}))
        self.assertEqual([r["gate_status"] for r in self.meta["ingress"]], ["ADMITTED", "UNVERIFIABLE"])

    def test_the_denial_names_categories_never_the_value(self):
        decision, code, message = self.gate_call("Read", {"file_path": "src/leak.py"})
        self.assertIn("github-token", message)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn(TOKEN, json.dumps(self.meta))

    def test_pii_filter_off_admits_identifiers_but_still_withholds_credentials(self):
        env = {"KRISTA_FILTER_PII": "off"}
        self.assertAllowed(self.gate_call("Read", {"file_path": "src/mail.txt"}, env=env))
        self.assertDenied(self.gate_call("Read", {"file_path": "src/leak.py"}, env=env), "G-INGRESS")

    def test_allowlisted_paths_are_not_scanned_and_say_so(self):
        env = {"KRISTA_FILTER_ALLOW_PATHS": "src/leak.py"}
        self.assertAllowed(self.gate_call("Read", {"file_path": "src/leak.py"}, env=env))
        self.assertIn("allowlist", json.dumps(self.meta["ingress"]))

    def test_a_file_above_the_size_limit_is_withheld(self):
        self.assertDenied(self.gate_call("Read", {"file_path": "docs/note.md"}, env={"KRISTA_FILTER_MAX_BYTES": "3"}), "G-INGRESS")
        self.assertEqual(self.meta["ingress"][-1]["gate_status"], "UNVERIFIABLE")

    def test_read_only_commands_scan_the_files_they_open(self):
        for command in ("cat src/leak.py", "head src/leak.py", "tail src/leak.py", "grep KEY src/leak.py", "wc src/leak.py"):
            self.assertDenied(self.gate_call("Bash", {"command": command}), "G-INGRESS")
        self.assertAllowed(self.gate_call("Bash", {"command": "cat docs/note.md"}))
        self.assertAllowed(self.gate_call("Bash", {"command": "ls src"}))

    def test_the_prompt_is_scanned(self):
        blocked = self.gate_call("", {}, hook_event_name="UserPromptSubmit", prompt=f"use {TOKEN} please")
        self.assertDenied(blocked, "G-INGRESS")
        self.assertNotIn(TOKEN, blocked[2])
        self.assertAllowed(self.gate_call("", {}, hook_event_name="UserPromptSubmit", prompt="fix the failing test"))
        self.assertDenied(self.gate_call("", {}, hook_event_name="UserPromptSubmit"), "G-ERR")

    # ----- egress
    def test_write_tools_block_content_that_carries_a_credential(self):
        leak = f'KEY = "{TOKEN}"'
        self.assertDenied(self.gate_call("Write", {"file_path": "src/new.py", "content": leak}), "G-EGRESS")
        self.assertDenied(self.gate_call("Edit", {"file_path": "src/a.py", "old_string": "x", "new_string": leak}), "G-EGRESS")
        self.assertDenied(self.gate_call("MultiEdit", {"file_path": "src/a.py", "edits": [{"new_string": "ok"}, {"new_string": leak}]}), "G-EGRESS")
        self.assertDenied(self.gate_call("NotebookEdit", {"notebook_path": "tests/n.ipynb", "new_source": leak}), "G-EGRESS")
        self.assertAllowed(self.gate_call("Write", {"file_path": "src/new.py", "content": "x = 1\n"}))
        self.assertEqual({r["gate_status"] for r in self.meta["egress"]}, {"BLOCKED", "PASSED"})

    def test_path_denials_come_before_content_scanning(self):
        self.assertDenied(self.gate_call("Write", {"file_path": "README.md", "content": TOKEN}), "G-PATH")

    def test_git_add_scans_the_file_and_commit_scans_the_message(self):
        self.assertDenied(self.gate_call("Bash", {"command": "git add src/leak.py"}), "G-EGRESS")
        self.assertAllowed(self.gate_call("Bash", {"command": "git add src/a.py"}))
        self.assertDenied(self.gate_call("Bash", {"command": f"git commit -m 'add {TOKEN}'"}), "G-EGRESS")
        self.assertDenied(self.gate_call("Bash", {"command": f"git commit --message='add {TOKEN}'"}), "G-EGRESS")
        self.assertAllowed(self.gate_call("Bash", {"command": "git commit -m 'fix parser'"}))

    def test_git_add_of_a_binary_is_recorded_unverifiable_and_a_big_file_is_blocked(self):
        self.assertAllowed(self.gate_call("Bash", {"command": "git add src/blob.bin"}))
        self.assertEqual(self.meta["egress"][-1]["gate_status"], "UNVERIFIABLE")
        self.assertDenied(self.gate_call("Bash", {"command": "git add src/a.py"}, env={"KRISTA_FILTER_MAX_BYTES": "2"}), "G-EGRESS")

    def test_network_and_mcp_inputs_are_scanned_after_authorization(self):
        network = {"KRISTA_GATE_NETWORK": "1"}
        self.assertDenied(self.gate_call("WebFetch", {"url": "https://example.org", "prompt": TOKEN}, env=network), "G-EGRESS")
        self.assertDenied(self.gate_call("WebSearch", {"query": f"what is {EMAIL}"}, env=network), "G-EGRESS")
        self.assertAllowed(self.gate_call("WebSearch", {"query": "python flock"}, env=network))
        self.assertDenied(self.gate_call("WebSearch", {"query": TOKEN}), "G-NET")
        allow = {"KRISTA_GATE_MCP_ALLOW": "mcp__docs__*"}
        self.assertDenied(self.gate_call("mcp__docs__search", {"q": {"nested": [TOKEN]}}, env=allow), "G-EGRESS")
        self.assertAllowed(self.gate_call("mcp__docs__search", {"q": "flock"}, env=allow))

    def test_egress_allowlist_excludes_a_fixture_path(self):
        env = {"KRISTA_FILTER_ALLOW_PATHS": "tests/fixtures/*"}
        (self.root / "tests" / "fixtures").mkdir()
        self.assertAllowed(self.gate_call("Write", {"file_path": "tests/fixtures/k.txt", "content": TOKEN}, env=env))

    # ----- Stop
    def transcript(self, *entries):
        path = self.base / "transcript.jsonl"
        path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
        return str(path)

    @staticmethod
    def assistant(text):
        return {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}

    def test_stop_flags_a_message_that_carried_a_credential_but_only_once(self):
        path = self.transcript({"type": "user", "message": {"content": "hi"}}, self.assistant(f"the key is {TOKEN}"))
        flagged = self.gate_call("", {}, hook_event_name="Stop", transcript_path=path)
        self.assertDenied(flagged, "G-EGRESS")
        self.assertNotIn(TOKEN, flagged[2])
        self.assertIn("cannot be recalled", flagged[2])
        self.assertAllowed(self.gate_call("", {}, hook_event_name="Stop", transcript_path=path, stop_hook_active=True))

    def test_stop_passes_clean_text_and_ignores_older_turns_and_unreadable_transcripts(self):
        old_leak = [{"type": "user", "message": {"content": "q1"}}, self.assistant(TOKEN), {"type": "user", "message": {"content": "q2"}}, self.assistant("fine")]
        self.assertAllowed(self.gate_call("", {}, hook_event_name="Stop", transcript_path=self.transcript(*old_leak)))
        self.assertAllowed(self.gate_call("", {}, hook_event_name="Stop", transcript_path=str(self.base / "absent.jsonl")))
        self.assertAllowed(self.gate_call("", {}, hook_event_name="Stop"))

    def test_stop_reads_text_blocks_around_tool_results_of_the_same_turn(self):
        entries = [{"type": "user", "message": {"content": "q"}}, self.assistant("before"),
                   {"type": "user", "message": {"content": [{"type": "tool_result", "content": "ok"}]}}, self.assistant(f"after {TOKEN}")]
        self.assertDenied(self.gate_call("", {}, hook_event_name="Stop", transcript_path=self.transcript(*entries)), "G-EGRESS")


class LedgerWiring(GateCase):
    """The gate's command line writes the ledger and fails closed when it must."""

    def setUp(self):
        super().setUp()
        self.logs = self.base / "logs"
        self.put(base_record())
        (self.root / "docs" / "note.md").write_text("plain\n")

    def call(self, event, env=None):
        environment = {"PATH": os.environ["PATH"], "CLAUDE_PROJECT_DIR": str(self.root), "KRISTA_SESSION_RECORD": str(self.record_path),
                       "KRISTA_RUNTIME_LOG_ROOT": str(self.logs), **(env or {})}
        return subprocess.run([sys.executable, "-I", str(GATE)], input=json.dumps({"cwd": str(self.root), "session_id": "s1", **event}),
                              capture_output=True, text=True, env=environment)

    def test_decisions_and_records_are_logged_and_the_chains_verify(self):
        self.assertEqual(self.call({"tool_name": "Read", "tool_input": {"file_path": "docs/note.md"}, "tool_use_id": "t1"}).returncode, 0)
        self.assertEqual(self.call({"tool_name": "Bash", "tool_input": {"command": "touch x"}, "permission_mode": "bypassPermissions"}).returncode, 2)
        for kind in ("gate", "ingress"):
            self.assertEqual(ledger.verify(self.logs, kind), [], kind)
        gate_rows = [r for r in ledger.tail(self.logs, "gate", 20) if r["record_type"] == "gate_decision"]
        self.assertEqual([(r["tool"], r["decision"], r["code"]) for r in gate_rows], [("Read", "allow", "G-OK"), ("Bash", "deny", "G-BASH")])
        self.assertEqual(gate_rows[1]["permission_mode"], "bypassPermissions")
        self.assertNotIn("touch", (self.logs / "gate.jsonl").read_text())

    def test_a_changed_session_record_is_logged_once_per_change(self):
        read = {"tool_name": "Write", "tool_input": {"file_path": "src/n.py", "content": "x"}}
        self.call(read)
        self.call(read)
        self.put(base_record(mode="AUTHORIZED_WRITE", open_questions=[]))
        self.call(read)
        changes = [r for r in ledger.tail(self.logs, "gate", 50) if r["record_type"] == "session_record_changed"]
        self.assertEqual(len(changes), 2)
        self.assertNotEqual(changes[0]["record_digest"], changes[1]["record_digest"])

    def test_a_blocked_write_leaves_a_blocked_egress_record_without_the_value(self):
        done = self.call({"tool_name": "Write", "tool_input": {"file_path": "src/n.py", "content": TOKEN}})
        self.assertEqual(done.returncode, 2)
        self.assertIn("G-EGRESS", done.stderr)
        self.assertNotIn(TOKEN, done.stderr)
        text = (self.logs / "egress.jsonl").read_text()
        self.assertIn("BLOCKED", text)
        self.assertNotIn(TOKEN, text)

    def test_prompt_and_stop_hooks_run_through_the_command_line(self):
        self.assertEqual(self.call({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}).returncode, 0)
        blocked = self.call({"hook_event_name": "UserPromptSubmit", "prompt": TOKEN})
        self.assertEqual(blocked.returncode, 2)
        self.assertNotIn(TOKEN, blocked.stderr)
        self.assertEqual(ledger.verify(self.logs, "ingress"), [])

    def test_a_ledger_that_cannot_be_written_turns_an_allow_into_g_log(self):
        read = {"tool_name": "Read", "tool_input": {"file_path": "docs/note.md"}}
        inside = self.root / "logs"
        for env in ({"KRISTA_RUNTIME_LOG_ROOT": str(inside)}, {"KRISTA_RUNTIME_LOG_ROOT": "relative"}):
            done = self.call(read, env)
            self.assertEqual(done.returncode, 2, env)
            self.assertIn("G-LOG", done.stderr)
        self.assertFalse(inside.exists())
        blocked_file = self.base / "file-not-dir"
        blocked_file.write_text("x")
        self.assertEqual(self.call(read, {"KRISTA_RUNTIME_LOG_ROOT": str(blocked_file / "sub")}).returncode, 2)

    def test_a_required_ledger_with_no_root_blocks_and_an_optional_one_does_not(self):
        read = {"tool_name": "Read", "tool_input": {"file_path": "docs/note.md"}}
        no_root = {"KRISTA_RUNTIME_LOG_ROOT": ""}
        self.assertEqual(self.call(read, no_root).returncode, 0)
        done = self.call(read, {**no_root, "KRISTA_LEDGER_REQUIRED": "1"})
        self.assertEqual(done.returncode, 2)
        self.assertIn("G-LOG", done.stderr)

    def test_a_broken_chain_blocks_further_calls(self):
        read = {"tool_name": "Read", "tool_input": {"file_path": "docs/note.md"}}
        self.assertEqual(self.call(read).returncode, 0)
        with open(self.logs / "gate.jsonl", "a") as handle:
            handle.write("garbage\n")
        self.assertEqual(self.call(read).returncode, 2)

    def test_a_denial_stays_a_denial_when_the_ledger_also_fails(self):
        done = self.call({"tool_name": "Bash", "tool_input": {"command": "touch x"}}, {"KRISTA_RUNTIME_LOG_ROOT": "relative"})
        self.assertEqual(done.returncode, 2)
        self.assertIn("G-BASH", done.stderr)


if __name__ == "__main__":
    unittest.main()
