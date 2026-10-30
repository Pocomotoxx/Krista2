"""Ruflo's worker staging requires the krista-gate plugin: the real patched source file is executed.

headless-plugins.ts is copied unchanged next to two tiny stubs for its two sibling imports and run with
Node's built-in type stripping, so the assertions are about the shipped code, not a model of it.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SRC = REPO / "v3" / "@claude-flow" / "cli" / "src"

RUNNER = r"""
import { withHeadlessPlugins, requiredPluginDirs, RequiredPluginError } from './headless-plugins.ts'
const scenario = JSON.parse(process.argv[2])
const resolver = (names: string[]) => ({
  resolved: names.filter((n) => !n.endsWith('-missing')).map((n) => ({ name: n, path: '/plugins/' + n })),
  missing: names.filter((n) => n.endsWith('-missing')).map((n) => ({ name: n })),
})
const warns: string[] = []
try {
  const r = withHeadlessPlugins(scenario.argv ?? ['--print'], scenario.env ?? {}, {
    env: scenario.env ?? {}, resolver: resolver as any, warn: (l: string) => warns.push(l), requiredOnly: scenario.requiredOnly, profile: scenario.profile,
  })
  console.log(JSON.stringify({ ok: true, argv: r.argv, added: r.added, missing: r.missing, required: r.required, warns, envKeys: Object.keys(r.env) }))
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: (e as Error).name, isRequired: e instanceof RequiredPluginError, message: (e as Error).message }))
}
"""


class WorkerProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.harness = Path(os.path.realpath(cls._tmp.name))
        text = (SRC / "mods" / "headless-plugins.ts").read_text(encoding="utf-8")
        text = text.replace("from './install.js'", "from './install_stub.ts'").replace("from './plugin-paths.js'", "from './paths_stub.ts'")
        (cls.harness / "headless-plugins.ts").write_text(text, encoding="utf-8")
        (cls.harness / "install_stub.ts").write_text("export const ENABLE_ENV = 'CLAUDE_CODE_ENABLE_FUNCTION_HOOKS'\n")
        (cls.harness / "paths_stub.ts").write_text("export type ResolveOptions = any\nexport type PluginPaths = any\nexport function resolvePluginPaths(){ return {resolved:[],missing:[]} }\n")
        (cls.harness / "run.ts").write_text(RUNNER)
        cls.good = cls.harness / "gate"
        (cls.good / ".claude-plugin").mkdir(parents=True)
        (cls.good / "hooks").mkdir()
        (cls.good / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "krista-gate"}))
        (cls.good / "hooks" / "hooks.json").write_text("{}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def run_scenario(self, **scenario):
        done = subprocess.run(["node", "--experimental-strip-types", "--no-warnings", "run.ts", json.dumps(scenario)], cwd=self.harness,
                              capture_output=True, text=True, timeout=60, env={"PATH": os.environ["PATH"], "HOME": str(self.harness)})
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout.strip().splitlines()[-1])

    def env(self, **extra):
        return {"KRISTA_GATE_PLUGIN_DIR": str(self.good), **extra}

    def test_a_worker_is_refused_when_the_launcher_names_no_gate(self):
        for env in ({}, {"KRISTA_GATE_PLUGIN_DIR": ""}, {"KRISTA_GATE_PLUGIN_DIR": "   "}):
            result = self.run_scenario(env=env)
            self.assertEqual((result["ok"], result["isRequired"]), (False, True), env)
            self.assertIn("refusing to start a worker", result["message"])

    def test_the_folder_must_really_be_the_gate_plugin(self):
        wrong_name = self.harness / "other"
        (wrong_name / ".claude-plugin").mkdir(parents=True)
        (wrong_name / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "ruflo-mods"}))
        no_hooks = self.harness / "nohooks"
        (no_hooks / ".claude-plugin").mkdir(parents=True)
        (no_hooks / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "krista-gate"}))
        bad_json = self.harness / "badjson"
        (bad_json / ".claude-plugin").mkdir(parents=True)
        (bad_json / ".claude-plugin" / "plugin.json").write_text("not json")
        cases = {str(self.harness / "absent"): "no readable", str(wrong_name): "is not the krista-gate plugin",
                 str(no_hooks): "no hooks/hooks.json", str(bad_json): "no readable", "relative/gate": "absolute paths"}
        for directory, reason in cases.items():
            result = self.run_scenario(env={"KRISTA_GATE_PLUGIN_DIR": directory})
            self.assertEqual((result["ok"], result["isRequired"]), (False, True), directory)
            self.assertIn(reason, result["message"], directory)

    def test_a_valid_gate_is_added_to_every_worker(self):
        result = self.run_scenario(env=self.env())
        self.assertTrue(result["ok"])
        self.assertEqual(result["required"], [str(self.good)])
        self.assertEqual(result["argv"][-2:], ["--plugin-dir", str(self.good)])
        self.assertEqual(result["argv"].count(str(self.good)), 1)

    def test_the_none_profile_cannot_switch_the_gate_off(self):
        result = self.run_scenario(env=self.env(RUFLO_HEADLESS_PLUGINS="none"))
        self.assertEqual(result["argv"], ["--print", "--plugin-dir", str(self.good)])
        self.assertEqual(result["added"], [])

    def test_a_missing_profile_plugin_does_not_remove_the_gate(self):
        result = self.run_scenario(env=self.env(RUFLO_HEADLESS_PLUGINS="ruflo-mods,other-missing"))
        self.assertIn(str(self.good), result["argv"])
        self.assertEqual(result["missing"], ["other-missing"])
        self.assertTrue(any("not found" in w for w in result["warns"]))

    def test_the_gate_is_added_next_to_the_profile_plugins(self):
        result = self.run_scenario(env=self.env(RUFLO_HEADLESS_PLUGINS="ruflo-mods"))
        self.assertEqual(result["argv"], ["--print", "--plugin-dir", "/plugins/ruflo-mods", "--plugin-dir", str(self.good)])
        self.assertEqual(result["added"], ["ruflo-mods"])

    def test_a_gate_the_caller_already_passes_is_not_duplicated(self):
        result = self.run_scenario(env=self.env(), argv=["--print", "--plugin-dir", str(self.good)])
        self.assertEqual(result["argv"].count(str(self.good)), 1)

    def test_required_only_mode_adds_the_gate_and_nothing_else(self):
        result = self.run_scenario(env=self.env(), requiredOnly=True)
        self.assertEqual(result["argv"], ["--print", "--plugin-dir", str(self.good)])
        self.assertEqual((result["added"], result["missing"]), ([], []))
        self.assertNotIn("CLAUDE_CODE_ENABLE_FUNCTION_HOOKS", result["envKeys"])
        self.assertFalse(self.run_scenario(env={}, requiredOnly=True)["ok"])

    def test_a_bad_gate_stops_the_worker_even_when_the_profile_is_empty(self):
        for profile in ("none", "ruflo-mods"):
            result = self.run_scenario(env={"KRISTA_GATE_PLUGIN_DIR": str(self.harness / "absent"), "RUFLO_HEADLESS_PLUGINS": profile})
            self.assertFalse(result["ok"], profile)

    def test_every_folder_in_a_list_must_be_valid(self):
        bad = f"{self.good}{os.pathsep}{self.harness / 'absent'}"
        self.assertFalse(self.run_scenario(env={"KRISTA_GATE_PLUGIN_DIR": bad})["ok"])


class SpawnSurface(unittest.TestCase):
    """Every product code path that starts `claude` is staged, or is a documented exception."""

    SCANNED = [SRC] + sorted((REPO / "plugins").glob("*/scripts")) + sorted((REPO / "plugins").glob("*/hooks"))
    SPAWNS = re.compile(r"spawn(Sync)?\(\s*['\"]claude['\"]|resolveClaudeLaunchCommand\(|childSpawn\(\s*\w*[Ll]aunch")
    STAGED = re.compile(r"withHeadlessPlugins\(|KRISTA_GATE_PLUGIN_DIR")
    # Not workers: no tools or no project, so there is nothing for the gate to guard.
    CLI = "v3/@claude-flow/cli/src/"
    EXCEPTIONS = {
        CLI + "services/fable-harness.ts": "judge and advisor call: runs in an empty temp directory, no tools granted, input is a JSON batch",
        CLI + "mods/headless-check.ts": "self-test: the prompt is 'reply ok', no tools",
        CLI + "runtime/claude-command.ts": "resolves the executable; spawns nothing",
        "plugins/ruflo-console/scripts/bench-startup.mjs": "runs `claude plugin test`: validates a plugin, starts no model session",
        "plugins/ruflo-plugin-creator/scripts/test-scaffold-mod.mjs": "runs `claude --version` and `claude plugin <validate>`: starts no model session",
    }

    def test_every_claude_spawn_site_is_staged_or_documented(self):
        sites = []
        for root in self.SCANNED:
            for path in root.rglob("*"):
                if path.suffix not in (".ts", ".mjs", ".cjs", ".js") or "node_modules" in path.parts or "__tests__" in path.parts or ".test." in path.name or ".spec." in path.name:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                if self.SPAWNS.search(text):
                    sites.append((path, text))
        self.assertGreaterEqual(len(sites), 5, "the scan found suspiciously few spawn sites")
        unguarded = []
        for path, text in sites:
            rel = path.relative_to(REPO).as_posix()
            if not self.STAGED.search(text) and rel not in self.EXCEPTIONS:
                unguarded.append(rel)
        self.assertEqual(unguarded, [], "a path that starts claude neither stages the gate nor is a documented exception")

    def test_every_documented_exception_still_exists_and_has_a_reason(self):
        for rel, reason in self.EXCEPTIONS.items():
            self.assertTrue((REPO / rel).is_file(), rel)
            self.assertGreater(len(reason), 20)

    def test_the_staged_files_really_reference_the_gate(self):
        for rel in ("commands/hive-mind.ts", "commands/hive-mind-worker.ts", "services/headless-worker-executor.ts"):
            text = (SRC / rel).read_text(encoding="utf-8")
            self.assertIn("withHeadlessPlugins(", text, rel)
        self.assertIn("KRISTA_GATE_PLUGIN_DIR", (REPO / "plugins/ruflo-testgen/scripts/tdd-repair/tdd-repair.mjs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
