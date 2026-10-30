"""The machine-level policy: rendering, installing into a protected tree, and checking."""

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN / "bin"))

import managed  # noqa: E402


def quiet(function, *args, **kwargs):
    """Call a function that prints its outcome, keeping the test output clean."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return function(*args, **kwargs)


class ManagedPolicy(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        self.root = self.tmp / "gate"
        self.assertEqual(quiet(managed.install_tree, self.root), 0)
        self.out = self.tmp / "etc" / "managed-settings.json"

    def install(self, **kw):
        return quiet(managed.install, self.root, self.out, kw.pop("profile", "strict"), kw.pop("force", False), kw.pop("allow_user_owned", True),
                     kw.pop("allow_unsafe", False))

    def test_install_tree_copies_the_gate_and_the_pin_and_drops_the_tests(self):
        self.assertTrue(managed.gate_script(self.root).is_file())
        self.assertEqual(managed.pin.verify(self.root / "krista"), [])
        self.assertFalse((self.root / "plugins" / "krista-gate" / "tests").exists())
        self.assertEqual(quiet(managed.install_tree, self.root), 1)

    def test_the_installed_tree_is_not_writable_by_group_or_others(self):
        for entry in [self.root, *self.root.rglob("*")]:
            if not entry.is_symlink():
                self.assertFalse(entry.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH), entry)

    def test_strict_policy_locks_hooks_and_bypass_and_passes_its_own_check(self):
        self.assertEqual(self.install(), 0)
        policy = json.loads(self.out.read_text())
        self.assertTrue(policy["allowManagedHooksOnly"])
        self.assertEqual(policy["permissions"]["disableBypassPermissionsMode"], "disable")
        command = policy["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertTrue(command.startswith("/bin/sh -c 'timeout 5"))
        self.assertTrue(command.endswith(str(managed.gate_script(self.root))))
        self.assertEqual(managed.check(self.out), [])

    def test_the_coexist_profile_is_refused_unless_the_unsafe_flag_is_given(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(managed.install(self.root, self.out, "coexist", False, True), 1)
        self.assertIn("can be bypassed", errors.getvalue())
        self.assertFalse(self.out.exists())

    def test_coexist_policy_leaves_other_hooks_and_is_reported_as_not_strict(self):
        self.assertEqual(self.install(profile="coexist", allow_unsafe=True), 0)
        policy = json.loads(self.out.read_text())
        self.assertNotIn("allowManagedHooksOnly", policy)
        self.assertEqual(managed.check(self.out, "coexist"), [])
        self.assertTrue(any("allowManagedHooksOnly" in p for p in managed.check(self.out, "strict")))

    def test_the_matcher_is_the_plugins_matcher(self):
        hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
        self.assertEqual(managed.render(self.root)["hooks"]["PreToolUse"][0]["matcher"], hooks["hooks"]["PreToolUse"][0]["matcher"])

    def test_check_names_each_weakening(self):
        self.install()
        good = json.loads(self.out.read_text())

        def tamper(change):
            policy = json.loads(json.dumps(good))
            change(policy)
            path = self.tmp / "tampered.json"
            path.write_text(json.dumps(policy))
            return managed.check(path)

        cases = {
            "no PreToolUse hook runs the gate": lambda p: p["hooks"].update(PreToolUse=[]),
            "does not cover Write": lambda p: p["hooks"]["PreToolUse"][0].update(matcher="Bash|mcp__.*|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch"),
            "does not cover mcp__": lambda p: p["hooks"]["PreToolUse"][0].update(matcher="Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch"),
            "disableBypassPermissionsMode": lambda p: p["permissions"].pop("disableBypassPermissionsMode"),
            "allowManagedHooksOnly": lambda p: p.pop("allowManagedHooksOnly"),
            "no PreToolUse hook runs the gate (wrapper)": lambda p: p["hooks"]["PreToolUse"][0]["hooks"][0].update(command="python3 -I " + str(managed.gate_script(self.root))),
            "does not exist": lambda p: p["hooks"]["PreToolUse"][0]["hooks"][0].update(command=managed.WRAPPER + " " + str(self.tmp / "nowhere" / "plugins" / "krista-gate" / "bin" / "krista_gate.py")),
        }
        for reason, change in cases.items():
            problems = tamper(change)
            self.assertTrue(any(reason.split(" (")[0] in p for p in problems), (reason, problems))

    def test_check_reports_a_changed_pin_next_to_the_gate(self):
        self.install()
        target = self.root / "krista" / "scripts" / "strict_fields.py"
        target.chmod(0o644)
        target.write_text("# tampered\n")
        self.assertTrue(any("pinned KRISTA copy" in p for p in managed.check(self.out)))

    def test_check_survives_garbage(self):
        for text in ("", "not json", "[]", "null", '{"hooks": 7, "permissions": []}'):
            path = self.tmp / "g.json"
            path.write_text(text)
            self.assertTrue(managed.check(path), text)
        self.assertTrue(managed.check(self.tmp / "absent.json"))

    def test_install_does_not_overwrite_a_managed_file_without_force(self):
        self.assertEqual(self.install(), 0)
        self.out.write_text('{"someone": "else"}')
        self.assertEqual(self.install(), 1)
        self.assertEqual(json.loads(self.out.read_text()), {"someone": "else"})
        self.assertEqual(self.install(force=True), 0)

    def test_install_refuses_a_gate_tree_the_agent_could_write(self):
        target = self.root / "plugins" / "krista-gate" / "bin" / "krista_gate.py"
        target.chmod(0o666)
        self.assertEqual(self.install(allow_user_owned=False), 1)
        self.assertFalse(self.out.exists())
        link = self.root / "link"
        os.symlink(target, link)
        target.chmod(0o644)
        self.assertTrue(any("symlink" in i for i in managed.protected(self.root)))

    def test_install_needs_a_gate_in_the_tree(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(managed.install(self.tmp / "empty", self.out, "strict", False, True), 1)
        self.assertIn("no gate at", errors.getvalue())
        self.assertFalse(self.out.exists())

    def test_install_tree_refuses_a_pin_that_is_not_intact(self):
        dest = self.tmp / "second"
        with mock.patch.object(managed.pin, "verify", return_value=["changed: scripts/strict_fields.py"]):
            self.assertEqual(quiet(managed.install_tree, dest), 1)
        self.assertFalse(dest.exists())

    def test_install_reports_a_policy_that_fails_its_own_check(self):
        target = self.root / "krista" / "scripts" / "strict_fields.py"
        target.chmod(0o644)
        target.write_text("# tampered\n")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(managed.install(self.root, self.out, "strict", False, True), 1)
        self.assertIn("the check failed", errors.getvalue())

    def test_check_requires_an_absolute_gate_path(self):
        policy = managed.render(self.root)
        command = policy["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        policy["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = command.replace(str(managed.gate_script(self.root)), "plugins/krista-gate/bin/krista_gate.py")
        path = self.tmp / "relative.json"
        path.write_text(json.dumps(policy))
        self.assertIn("the gate path is not absolute", managed.check(path))

    def test_a_tree_owned_by_someone_else_is_not_protected(self):
        real = Path.lstat

        def foreign(path):
            info = real(path)
            return types.SimpleNamespace(st_mode=info.st_mode, st_uid=1000)

        with mock.patch.object(Path, "lstat", foreign):
            issues = managed.protected(self.root)
        self.assertTrue(issues)
        self.assertTrue(all("not owned by root" in i for i in issues))

    def test_command_line_render_and_check(self):
        run = lambda *a: subprocess.run([sys.executable, "-I", str(PLUGIN / "bin" / "managed.py"), *a], capture_output=True, text=True, timeout=60)
        rendered = run("render", "--gate-root", str(self.root))
        self.assertEqual(rendered.returncode, 0)
        self.assertTrue(json.loads(rendered.stdout)["allowManagedHooksOnly"])
        (self.tmp / "p.json").write_text(rendered.stdout)
        self.assertEqual(run("check", str(self.tmp / "p.json")).returncode, 0)
        self.assertEqual(run("check", str(self.tmp / "absent.json")).returncode, 1)
        self.assertEqual(run("install", "--gate-root", str(self.root), "--out", str(self.out), "--profile", "bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
