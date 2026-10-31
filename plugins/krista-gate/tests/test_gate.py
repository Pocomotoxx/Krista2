"""Decision table of the KRISTA gate, its pin, its command line and its fail-closed wrapper."""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
sys.path.insert(0, str(PLUGIN / "bin"))

import krista_gate as gate  # noqa: E402
import pin  # noqa: E402

VALIDATOR = gate.load_validator()
GATE = PLUGIN / "bin" / "krista_gate.py"


def base_record(**overrides):
    record = {
        "mode": "CANDIDATE_ONLY",
        "target": {"repository": "owner/repo", "branch": "task/x", "protected_paths_check": "PASS"},
        "scope": {"actions": ["read", "edit", "test", "commit", "push"], "allowed_paths": ["src/**", "tests/**", "docs/note.md"],
                  "forbidden_paths": ["src/secrets"]},
        "phases": [{"name": "implement", "status": "CANDIDATE", "evidence_ref": None}],
        "test_receipts": [{"command": "python3 -m unittest", "status": "NOT_ATTEMPTED", "evidence_ref": None}],
        "open_questions": [],
    }
    record.update(overrides)
    return record


class GateCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(os.path.realpath(tmp.name))
        self.root = base / "project"
        for sub in ("src", "tests", "docs", ".claude", "outside_target"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        (self.root / "src" / "a.py").write_text("x = 1\n")
        (self.root / "outside").mkdir()
        self.record_path = base / "session.json"
        self.base = base

    def put(self, record):
        self.record_path.write_text(json.dumps(record), encoding="utf-8")

    def run_gate(self, tool, tool_input, record="default", env=None, branch="task/x", cwd=None):
        if record == "default":
            record = base_record()
        if isinstance(record, dict):
            self.put(record)
        environment = {"CLAUDE_PROJECT_DIR": str(self.root)}
        if record is not None:
            environment["KRISTA_SESSION_RECORD"] = str(self.record_path)
        environment.update(env or {})
        event = {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd or self.root), "permission_mode": "default"}
        return gate.decide(event, environment, validator=VALIDATOR, branch_fn=lambda root: branch)

    def assertDenied(self, result, code):
        self.assertEqual(result[0], "deny", result)
        self.assertEqual(result[1], code, result)

    def assertAllowed(self, result):
        self.assertEqual(result[0], "allow", result)


class WriteTools(GateCase):
    def test_allowed_path_passes_and_relative_path_resolves_against_cwd(self):
        self.assertAllowed(self.run_gate("Write", {"file_path": str(self.root / "src" / "new.py")}))
        self.assertAllowed(self.run_gate("Edit", {"file_path": "new.py"}, cwd=self.root / "src"))
        self.assertAllowed(self.run_gate("MultiEdit", {"file_path": "docs/note.md"}))
        self.assertAllowed(self.run_gate("NotebookEdit", {"notebook_path": "tests/n.ipynb"}))

    def test_no_record_or_an_unusable_record_blocks_every_write(self):
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=None), "G-NOREC")
        self.record_path.write_text("not json")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=False), "G-NOREC")
        self.record_path.write_text("[]")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=False), "G-NOREC")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record={**base_record(), "mode": "ANYTHING"}), "G-NOREC")
        missing = self.run_gate("Write", {"file_path": "src/a.py"}, record=False, env={"KRISTA_SESSION_RECORD": str(self.base / "absent.json")})
        self.assertDenied(missing, "G-NOREC")

    def test_authorized_write_without_declared_open_questions_is_an_invalid_record(self):
        record = base_record(mode="AUTHORIZED_WRITE")
        record.pop("open_questions")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=record), "G-NOREC")

    def test_paths_outside_the_allowlist_or_the_project_are_denied(self):
        self.assertDenied(self.run_gate("Write", {"file_path": "README.md"}), "G-PATH")
        self.assertDenied(self.run_gate("Write", {"file_path": "/etc/passwd"}), "G-PATH")
        self.assertDenied(self.run_gate("Write", {"file_path": "../escape.py"}), "G-PATH")
        self.assertDenied(self.run_gate("Write", {"file_path": str(self.base / "elsewhere.py")}), "G-PATH")
        self.assertDenied(self.run_gate("Write", {}), "G-PATH")
        self.assertDenied(self.run_gate("Write", {"file_path": "  "}), "G-PATH")

    def test_a_symlink_is_judged_by_where_it_points(self):
        os.symlink(self.base / "elsewhere.py", self.root / "src" / "link_out.py")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/link_out.py"}), "G-PATH")
        os.symlink(self.root / ".claude" / "settings.json", self.root / "src" / "link_prot.py")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/link_prot.py"}), "G-PROT")

    def test_forbidden_and_protected_paths_win_over_the_allowlist(self):
        self.assertDenied(self.run_gate("Write", {"file_path": "src/secrets/key.txt"}), "G-FORB")
        wide = base_record()
        wide["scope"]["allowed_paths"] = ["*"]
        for target in (".claude/settings.json", ".claude/helpers/x.cjs", "CLAUDE.md", "AGENTS.md", ".git/config", ".githooks/pre-commit",
                       "krista/scripts/validate_vibe_code_session.py", "plugins/krista-gate/bin/krista_gate.py", ".mcp.json", ".krista/x"):
            self.assertDenied(self.run_gate("Write", {"file_path": target}, record=wide), "G-PROT")

    def test_secrets_files_and_extra_protected_patterns(self):
        wide = base_record()
        wide["scope"]["allowed_paths"] = ["*"]
        for target in (".env", ".env.local", "src/.env"):
            self.assertDenied(self.run_gate("Write", {"file_path": target}, record=wide), "G-PROT")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/vendor/x.py"}, env={"KRISTA_GATE_PROTECTED": "src/vendor/**:other/**"}), "G-PROT")

    def test_the_edit_action_is_required(self):
        read_only = base_record()
        read_only["scope"]["actions"] = ["read"]
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=read_only), "G-ACT")
        plan = base_record(mode="PLAN_ONLY")
        plan["scope"]["actions"] = ["read"]
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=plan), "G-ACT")

    def test_default_branch_rule_is_independent_of_the_target_branch_rule(self):
        no_target_branch = base_record()
        no_target_branch["target"] = {"protected_paths_check": "PASS"}
        result = self.run_gate("Write", {"file_path": "src/a.py"}, record=no_target_branch, branch="main")
        self.assertDenied(result, "G-BRANCH")
        self.assertIn("default branch", result[2])
        mismatch = self.run_gate("Write", {"file_path": "src/a.py"}, branch="task/other")
        self.assertIn("target branch", mismatch[2])

    def test_branch_rules(self):
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, branch="main"), "G-BRANCH")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, branch="origin/Master"), "G-BRANCH")
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, branch="task/other"), "G-BRANCH")
        self.assertAllowed(self.run_gate("Write", {"file_path": "src/a.py"}, branch=None))


class OpenQuestions(GateCase):
    def question(self, **fields):
        return {"question": "Which database?", "blocking": True, "status": "OPEN", **fields}

    def test_a_blocking_open_question_blocks_writes_until_it_is_answered(self):
        record = base_record(open_questions=[self.question()])
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=record), "G-OPENQ")
        record["open_questions"] = [self.question(status="ANSWERED", answer_ref="chat:7")]
        self.assertAllowed(self.run_gate("Write", {"file_path": "src/a.py"}, record=record))

    def test_an_assumption_does_not_release_a_blocking_question(self):
        record = base_record(open_questions=[self.question(status="ASSUMED", assumption="Postgres")])
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=record), "G-OPENQ")

    def test_a_non_blocking_question_does_not_block(self):
        record = base_record(open_questions=[self.question(blocking=False)])
        self.assertAllowed(self.run_gate("Write", {"file_path": "src/a.py"}, record=record))

    def test_malformed_entries_fail_closed(self):
        for bad in ("none", ["why"], [{"question": "q"}], [self.question(blocking="yes")], [self.question(status="DONE")]):
            record = base_record(open_questions=bad)
            self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=record), "G-OPENQ")

    def test_the_record_is_read_on_every_call(self):
        record = base_record(open_questions=[self.question()])
        self.assertDenied(self.run_gate("Write", {"file_path": "src/a.py"}, record=record), "G-OPENQ")
        record["open_questions"] = []
        self.assertAllowed(self.run_gate("Write", {"file_path": "src/a.py"}, record=record))

    def test_reading_stays_possible_but_nothing_else_while_a_question_is_open(self):
        record = base_record(open_questions=[self.question()])
        for command in ("ls", "pwd", "git status", "cat src/a.py", "git diff"):
            self.assertAllowed(self.run_gate("Bash", {"command": command}, record=record))
        for command in ("python3 -m unittest", "touch src/x", "git commit -m msg", "git add src/a.py"):
            result = self.run_gate("Bash", {"command": command}, record=record)
            self.assertEqual(result[0], "deny", command)
        self.assertDenied(self.run_gate("Bash", {"command": "python3 -m unittest"}, record=record), "G-OPENQ")

    def test_gate_agrees_with_the_validator_on_what_a_blocking_question_is(self):
        cases = [
            [], [self.question()], [self.question(blocking=False)], [self.question(status="ANSWERED", answer_ref="r:1")],
            [self.question(status="ANSWERED")], [self.question(status="ASSUMED", assumption="x")],
            [self.question(status="ASSUMED", assumption="x", blocking=False)], [self.question(status="DONE")],
            [self.question(blocking="yes")], [self.question(blocking=None)], ["why"], [{}], [self.question(), self.question(blocking=False)],
            [self.question(status="ANSWERED", answer_ref="r:1"), self.question(blocking=False, status="OPEN")],
        ]
        for questions in cases:
            record = base_record(open_questions=questions)
            record["scope"]["actions"] = ["read", "edit"]
            reported = any("forbids write actions" in e for e in VALIDATOR.validate(copy.deepcopy(record)))
            self.assertEqual(gate.blocking_open(record), reported, questions)
        self.assertTrue(gate.blocking_open(base_record(open_questions="none")))
        self.assertFalse(gate.blocking_open(base_record()))


class BashRules(GateCase):
    def test_read_only_commands_need_no_record_but_stay_inside_the_project(self):
        for command in ("ls", "ls -la src", "pwd", "git status", "git diff", "git log", "cat src/a.py", "head -n 3 src/a.py", "wc -l src/a.py",
                        "grep -n x src/a.py", "git show", "git rev-parse HEAD", "git branch --show-current"):
            self.assertAllowed(self.run_gate("Bash", {"command": command}, record=None))
        for command in ("cat /etc/passwd", "ls ..", "cat .env", "cat src/../../outside_secret", "head ../x"):
            self.assertDenied(self.run_gate("Bash", {"command": command}, record=None), "G-BASH")

    def test_shell_syntax_is_never_a_simple_command(self):
        for command in ("ls; rm -rf src", "echo x > f", "cat a | sh", "ls $(whoami)", "ls `id`", "ls *", "ls && ls", "ls & ls", "cat <f",
                        "ls\nrm x", "ls ~", "ls \\n", "ls {a,b}", "ls #x", "ls !x"):
            self.assertDenied(self.run_gate("Bash", {"command": command}), "G-BASH")

    def test_a_command_that_cannot_be_parsed_is_denied_with_its_own_reason(self):
        for command in ('ls "src', "cat 'a", "ls 'a\"b"):
            result = self.run_gate("Bash", {"command": command})
            self.assertDenied(result, "G-BASH")
            self.assertIn("could not be parsed", result[2], command)
        self.assertIn("empty", self.run_gate("Bash", {"command": "  "})[2])

    def test_undeclared_commands_are_denied(self):
        for command in ("touch src/x", "rm -rf src", "node -e 1", "curl http://example.invalid", "python3 -c 1", "npm install", "sh run.sh", "", "   "):
            self.assertDenied(self.run_gate("Bash", {"command": command}), "G-BASH")
        self.assertDenied(self.run_gate("Bash", {}), "G-BASH")
        self.assertDenied(self.run_gate("Bash", {"command": 7}), "G-BASH")

    def test_a_declared_test_command_runs_only_verbatim_and_with_the_test_action(self):
        self.assertAllowed(self.run_gate("Bash", {"command": "python3 -m unittest"}))
        self.assertAllowed(self.run_gate("Bash", {"command": "python3   -m  unittest "}))
        self.assertDenied(self.run_gate("Bash", {"command": "python3 -m unittest -v"}), "G-BASH")
        self.assertDenied(self.run_gate("Bash", {"command": "python3 -m unittest; rm -rf src"}), "G-BASH")
        no_test = base_record()
        no_test["scope"]["actions"] = ["read", "edit"]
        self.assertDenied(self.run_gate("Bash", {"command": "python3 -m unittest"}, record=no_test), "G-ACT")
        self.assertDenied(self.run_gate("Bash", {"command": "python3 -m unittest"}, record=None), "G-BASH")

    def test_a_declared_command_may_contain_shell_syntax_because_a_human_wrote_it(self):
        record = base_record(test_receipts=[{"command": "make test && make lint", "status": "NOT_ATTEMPTED", "evidence_ref": None}])
        self.assertAllowed(self.run_gate("Bash", {"command": "make test && make lint"}, record=record))
        self.assertDenied(self.run_gate("Bash", {"command": "make test && make lint && id"}, record=record), "G-BASH")

    def test_the_reproduction_command_counts_as_declared(self):
        repro = {"test_id": "t", "input": "i", "oracle": "o", "failure_signature": "f", "environment": "e", "repro_command": "pytest -k repro",
                 "before": "NOT_ATTEMPTED", "after": "NOT_ATTEMPTED", "outcome": "NOT_RUN", "symptom_status": "REPORTED", "cause_status": "INFERRED"}
        record = base_record(task_kind="DEFECT", reproduction=repro)
        self.assertAllowed(self.run_gate("Bash", {"command": "pytest -k repro"}, record=record))


class GitRules(GateCase):
    def test_add_takes_explicit_allowed_files(self):
        self.assertAllowed(self.run_gate("Bash", {"command": "git add src/a.py"}))
        self.assertAllowed(self.run_gate("Bash", {"command": "git add -- src/a.py"}))
        for command in ("git add -A", "git add .", "git add src", "git add .env", "git add ../x", "git add README.md", "git add", "git add --force src/a.py",
                        "git add src/secrets/k"):
            self.assertEqual(self.run_gate("Bash", {"command": command})[0], "deny", command)

    def test_add_commit_and_push_need_their_actions(self):
        for action, command in (("commit", "git add src/a.py"), ("commit", 'git commit -m "msg"'), ("push", "git push origin task/x")):
            record = base_record()
            record["scope"]["actions"] = [a for a in record["scope"]["actions"] if a != action]
            self.assertDenied(self.run_gate("Bash", {"command": command}, record=record), "G-ACT")

    def test_commit_allows_only_a_message(self):
        for command in ('git commit -m "msg"', "git commit --message msg", "git commit --message=msg"):
            self.assertAllowed(self.run_gate("Bash", {"command": command}))
        for command in ("git commit -a -m x", "git commit --amend -m x", 'git commit -am "x"', "git commit --no-verify -m x", "git commit -F f", "git commit",
                        "git commit -m x -m y", "git commit -m x --amend"):
            self.assertDenied(self.run_gate("Bash", {"command": command}), "G-GIT")

    def test_commit_is_refused_on_a_default_branch(self):
        self.assertDenied(self.run_gate("Bash", {"command": "git commit -m x"}, branch="main"), "G-BRANCH")

    def test_push_allows_only_the_checked_out_task_branch(self):
        self.assertAllowed(self.run_gate("Bash", {"command": "git push origin task/x"}))
        self.assertAllowed(self.run_gate("Bash", {"command": "git push -u origin task/x"}))
        for command in ("git push --force origin task/x", "git push -f origin task/x", "git push origin main", "git push origin :task/x", "git push origin HEAD",
                        "git push origin +task/x", "git push --delete origin task/x", "git push origin task/x task/y", "git push", "git push origin",
                        "git push --force-with-lease origin task/x", "git push origin -d"):
            self.assertEqual(self.run_gate("Bash", {"command": command})[0], "deny", command)
        self.assertDenied(self.run_gate("Bash", {"command": "git push origin task/other"}), "G-GIT")
        self.assertDenied(self.run_gate("Bash", {"command": "git push origin master"}), "G-BRANCH")

    def test_each_git_refusal_names_its_own_reason(self):
        cases = {
            "git -c core.hooksPath=x status": "global options",
            "git --git-dir=x status": "global options",
            "git branch -D x": "may only list",
            "git branch newbranch": "may only list",
            "git reset --hard": "not allowed by the gate",
            "git diff --output=out.txt": "output redirection",
            "git add": "explicit file paths",
            "git add -p src/a.py": "explicit file paths",
        }
        for command, reason in cases.items():
            result = self.run_gate("Bash", {"command": command})
            self.assertEqual(result[0], "deny", command)
            self.assertIn(reason, result[2], command)

    def test_adding_a_directory_is_refused_even_when_the_record_allows_it(self):
        record = base_record()
        record["scope"]["allowed_paths"] = ["src/**", "docs"]
        self.assertDenied(self.run_gate("Bash", {"command": "git add docs"}, record=record), "G-GIT")
        self.assertIn("files, not directories", self.run_gate("Bash", {"command": "git add docs"}, record=record)[2])

    def test_other_git_forms_are_denied(self):
        for command in ("git -c core.hooksPath=x status", "git --git-dir=x status", "git reset --hard", "git checkout main", "git clean -fd", "git config x y",
                        "git stash", "git rebase main", "git merge x", "git diff --output=out.txt", "git log -o out.txt", "git branch -D x", "git remote add x y"):
            result = self.run_gate("Bash", {"command": command}, record=None)
            self.assertEqual(result[0], "deny", command)
            self.assertIn(result[1], ("G-GIT", "G-BASH"), command)
        self.assertDenied(self.run_gate("Bash", {"command": "git reset --hard"}), "G-GIT")


class BranchReading(unittest.TestCase):
    def test_a_missing_git_means_no_branch_and_a_hang_or_failure_blocks(self):
        from unittest import mock

        with mock.patch.object(gate.subprocess, "run", side_effect=FileNotFoundError):
            self.assertIsNone(gate.current_branch(Path("/tmp")))
        for failure in (subprocess.TimeoutExpired("git", 3), PermissionError("no")):
            with mock.patch.object(gate.subprocess, "run", side_effect=failure):
                with self.assertRaises(gate.Denied) as caught:
                    gate.current_branch(Path("/tmp"))
                self.assertEqual(caught.exception.code, "G-ERR")
        not_a_repo = mock.Mock(returncode=128, stdout="")
        with mock.patch.object(gate.subprocess, "run", return_value=not_a_repo):
            self.assertIsNone(gate.current_branch(Path("/tmp")))

    def test_a_real_checkout_reports_its_branch_even_before_the_first_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", "-b", "task/real", tmp], check=True)
            self.assertEqual(gate.current_branch(Path(tmp)), "task/real")
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", "-b", "main", tmp], check=True)
            self.assertEqual(gate.current_branch(Path(tmp)), "main")

    def test_a_detached_head_is_reported_and_a_plain_directory_has_no_branch(self):
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
               "PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "")}
        with tempfile.TemporaryDirectory() as tmp:
            for argv in (["init", "-q", "-b", "task/real"], ["commit", "-q", "--allow-empty", "-m", "x"], ["checkout", "-q", "--detach"]):
                subprocess.run(["git", "-C", tmp, *argv], check=True, env=env, capture_output=True)
            self.assertEqual(gate.current_branch(Path(tmp)), "HEAD")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(gate.current_branch(Path(tmp)))

    def test_the_default_branch_rule_holds_in_a_real_repository_without_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp)) / "project"
            (root / "src").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
            record = base_record()
            record["target"] = {"protected_paths_check": "PASS"}
            (Path(tmp) / "s.json").write_text(json.dumps(record))
            event = {"tool_name": "Write", "tool_input": {"file_path": "src/a.py"}, "cwd": str(root)}
            result = gate.decide(event, {"CLAUDE_PROJECT_DIR": str(root), "KRISTA_SESSION_RECORD": str(Path(tmp) / "s.json")}, validator=VALIDATOR)
            self.assertEqual(result[:2], ("deny", "G-BRANCH"))


class OtherTools(GateCase):
    def test_network_needs_a_separate_authorization(self):
        for tool in ("WebFetch", "WebSearch"):
            self.assertDenied(self.run_gate(tool, {"url": "https://example.org"}), "G-NET")
            self.assertAllowed(self.run_gate(tool, {"url": "https://example.org"}, env={"KRISTA_GATE_NETWORK": "1"}))
            self.assertDenied(self.run_gate(tool, {}, env={"KRISTA_GATE_NETWORK": "true"}), "G-NET")

    def test_mcp_tools_are_denied_unless_the_launcher_allows_them(self):
        self.assertDenied(self.run_gate("mcp__probe__terminal_execute", {"command": "id"}), "G-MCP")
        self.assertAllowed(self.run_gate("mcp__docs__search", {}, env={"KRISTA_GATE_MCP_ALLOW": "mcp__docs__*"}))
        self.assertDenied(self.run_gate("mcp__probe__terminal_execute", {}, env={"KRISTA_GATE_MCP_ALLOW": "mcp__docs__*,mcp__other__x"}), "G-MCP")

    def test_read_tools_pass_and_unknown_tools_are_denied(self):
        for tool in ("Glob", "Grep", "LS"):
            self.assertAllowed(self.run_gate(tool, {"file_path": ".env"}, record=None))
        self.assertAllowed(self.run_gate("Read", {"file_path": "README.md"}, record=None))
        self.assertDenied(self.run_gate("Read", {"file_path": ".env"}, record=None), "G-INGRESS")
        self.assertDenied(self.run_gate("SomethingNew", {}), "G-TOOL")
        self.assertDenied(gate.decide({"tool_input": {}}, {}, validator=VALIDATOR), "G-TOOL")
        self.assertDenied(gate.decide({"tool_name": ""}, {}, validator=VALIDATOR), "G-TOOL")


class Pin(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.copy = Path(tmp.name) / "krista"
        shutil.copytree(pin.PIN_DIR, self.copy)

    def test_the_shipped_pin_is_intact(self):
        self.assertEqual(pin.verify(), [])
        self.assertEqual(len((pin.PIN_DIR / "PINNED_COMMIT").read_text().strip()), 40)

    def test_a_changed_or_missing_or_unlisted_file_is_detected(self):
        target = self.copy / "scripts" / "validate_vibe_code_session.py"
        target.write_text(target.read_text() + "\n# tampered\n")
        self.assertEqual(pin.verify(self.copy), ["changed: scripts/validate_vibe_code_session.py"])
        target.unlink()
        self.assertEqual(pin.verify(self.copy), ["missing: scripts/validate_vibe_code_session.py"])
        manifest = json.loads((self.copy / "MANIFEST.json").read_text())
        manifest["files"]["scripts/extra.py"] = "0" * 64
        (self.copy / "MANIFEST.json").write_text(json.dumps(manifest))
        self.assertIn("manifest does not list exactly the pinned files", pin.verify(self.copy))
        (self.copy / "MANIFEST.json").write_text("not json")
        self.assertEqual(len(pin.verify(self.copy)), 1)

    def test_the_gate_refuses_to_import_a_tampered_copy(self):
        (self.copy / "scripts" / "strict_fields.py").write_text("# tampered\n")
        with self.assertRaises(gate.Denied) as caught:
            gate.load_validator(self.copy)
        self.assertEqual(caught.exception.code, "G-PIN")
        shutil.rmtree(self.copy)
        with self.assertRaises(gate.Denied):
            gate.load_validator(self.copy)


class CommandLine(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        (self.tmp / "project" / "src").mkdir(parents=True)
        (self.tmp / "session.json").write_text(json.dumps(base_record()))
        self.env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp), "CLAUDE_PROJECT_DIR": str(self.tmp / "project"),
                    "KRISTA_SESSION_RECORD": str(self.tmp / "session.json"), "KRISTA_GATE_LOG": str(self.tmp / "gate.log")}

    def call(self, payload, env=None, command=None):
        text = payload if isinstance(payload, str) else json.dumps(payload)
        argv = command or [sys.executable, "-I", str(GATE)]
        return subprocess.run(argv, input=text, capture_output=True, text=True, env=env or self.env, cwd=str(self.tmp), timeout=60)

    def test_allow_and_deny_exit_codes_and_messages(self):
        ok = self.call({"tool_name": "Write", "tool_input": {"file_path": "src/a.py"}, "cwd": str(self.tmp / "project")})
        self.assertEqual((ok.returncode, ok.stderr), (0, ""))
        no = self.call({"tool_name": "Write", "tool_input": {"file_path": "README.md"}, "cwd": str(self.tmp / "project")})
        self.assertEqual(no.returncode, 2)
        self.assertIn("KRISTA-GATE G-PATH", no.stderr)

    def test_garbage_input_blocks_instead_of_passing(self):
        for text in ("", "not json", "[]", "null", '{"tool_name": 7}', "\xff\xfe"):
            result = self.call(text)
            self.assertEqual(result.returncode, 2, repr(text))
            self.assertNotIn("Traceback", result.stderr)

    def test_the_decision_log_holds_metadata_and_never_the_command(self):
        self.call({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(self.tmp / "project")})
        self.call({"tool_name": "Bash", "tool_input": {"command": "touch SECRET_MARKER_9"}, "cwd": str(self.tmp / "project"), "permission_mode": "bypassPermissions"})
        lines = [json.loads(line) for line in (self.tmp / "gate.log").read_text().splitlines()]
        self.assertEqual([(l["tool"], l["decision"], l["code"]) for l in lines], [("Bash", "allow", "G-OK"), ("Bash", "deny", "G-BASH")])
        self.assertEqual(lines[1]["permission_mode"], "bypassPermissions")
        self.assertNotIn("SECRET_MARKER_9", (self.tmp / "gate.log").read_text())

    def test_a_tampered_pin_blocks_every_tool_through_the_command_line(self):
        shutil.copytree(pin.PIN_DIR, self.tmp / "krista")
        copy_root = self.tmp / "plugins" / "krista-gate" / "bin"
        shutil.copytree(GATE.parent, copy_root, ignore=shutil.ignore_patterns("__pycache__"))
        (self.tmp / "krista" / "scripts" / "strict_fields.py").write_text("# tampered\n")
        result = self.call({"tool_name": "Read", "tool_input": {}}, command=[sys.executable, "-I", str(copy_root / "krista_gate.py")])
        self.assertEqual(result.returncode, 2)
        self.assertIn("G-PIN", result.stderr)


class Wrapper(unittest.TestCase):
    """The hook command in hooks.json turns every failure of the gate into a block."""

    def command(self):
        hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
        return hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    def run_wrapped(self, env, payload):
        return subprocess.run(["/bin/sh", "-c", self.command()], input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)

    def test_matcher_covers_every_tool_the_gate_decides_on(self):
        matcher = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["matcher"]
        for tool in ("Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "mcp__"):
            self.assertIn(tool, matcher)

    def test_ok_passes_and_deny_blocks_and_a_missing_runtime_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp))
            (root / "src").mkdir()
            (root / "s.json").write_text(json.dumps(base_record()))
            env = {"PATH": os.environ["PATH"], "HOME": str(root), "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "CLAUDE_PROJECT_DIR": str(root),
                   "KRISTA_SESSION_RECORD": str(root / "s.json")}
            good = {"tool_name": "Write", "tool_input": {"file_path": "src/a.py"}, "cwd": str(root)}
            self.assertEqual(self.run_wrapped(env, good).returncode, 0)
            bad = {"tool_name": "Write", "tool_input": {"file_path": "README.md"}, "cwd": str(root)}
            self.assertEqual(self.run_wrapped(env, bad).returncode, 2)
            self.assertEqual(self.run_wrapped({**env, "PATH": "/nonexistent"}, good).returncode, 2)
            self.assertEqual(self.run_wrapped({**env, "CLAUDE_PLUGIN_ROOT": str(root / "absent")}, good).returncode, 2)


if __name__ == "__main__":
    unittest.main()
