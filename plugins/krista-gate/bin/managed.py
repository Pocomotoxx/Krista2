#!/usr/bin/env python3
"""Machine-level KRISTA policy: render, install and check Claude Code managed settings.

Managed settings rank above user, project, local and command-line settings, so they bind every `claude`
process on the machine however it was started: an interactive session, a Ruflo worker, a hive-mind child,
a teammate, a script. The gate then no longer depends on a plugin being staged or on a profile variable.

    managed.py render --gate-root <dir> [--profile strict|coexist]
    managed.py install-tree --dest <dir>                      copy the gate and the pinned KRISTA files to a protected place
    managed.py install --gate-root <dir> --out <file> [--profile ...] [--force] [--allow-user-owned]
    managed.py check <managed-settings.json>

Profiles:
  strict   (default) also sets allowManagedHooksOnly, so no project, user or plugin hook runs. A hook of
           another tool can then neither rewrite a tool input after the gate approved it nor race the gate.
           Ruflo's own hook-handler and its plugin hooks do not run in this profile.
  coexist  UNSAFE, kept only so the bypass stays measurable. Other hooks keep running, and a live probe showed
           that a project hook returning updatedInput rewrote a command AFTER the gate had allowed the original
           (`ls` became `touch ...` and ran). `install` refuses it unless --allow-unsafe is given.

Both profiles set permissions.disableBypassPermissionsMode, so --dangerously-skip-permissions and
bypassPermissions are refused.

The policy file is only as strong as the place it and the gate live in: root-owned and not writable by the
user the agent runs as. `install` refuses a gate tree that is group- or world-writable, or owned by someone
else than root, unless --allow-user-owned is given (for tests and single-user machines).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pin  # noqa: E402

PROFILES = ("strict", "coexist")
EVENTS = ("PreToolUse", "UserPromptSubmit", "Stop")
REQUIRED_TOOLS = ("Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "mcp__")
WRAPPER = "/bin/sh -c 'timeout 5 \"$@\"; [ $? -eq 0 ] || exit 2' _ python3 -I"


def matcher() -> str:
    """The tool matcher, read from the plugin's hooks.json so the two cannot drift."""
    hooks = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    return hooks["hooks"]["PreToolUse"][0]["matcher"]


def gate_script(gate_root: Path) -> Path:
    return gate_root / "plugins" / "krista-gate" / "bin" / "krista_gate.py"


def render(gate_root: Path, profile: str = "strict") -> dict:
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    gate_root = gate_root.resolve()
    hook = {"type": "command", "command": f"{WRAPPER} {gate_script(gate_root)}", "timeout": 10}
    policy: dict = {
        "hooks": {"PreToolUse": [{"matcher": matcher(), "hooks": [hook]}], "UserPromptSubmit": [{"hooks": [dict(hook)]}], "Stop": [{"hooks": [dict(hook)]}]},
        "permissions": {"disableBypassPermissionsMode": "disable"},
    }
    if profile == "strict":
        policy["allowManagedHooksOnly"] = True
    return policy


def check(path: Path, profile: str = "strict") -> list[str]:
    """Problems with an installed or rendered policy; empty means it enforces the gate under `profile`."""
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"policy unreadable: {type(exc).__name__}"]
    if not isinstance(policy, dict):
        return ["policy is not a JSON object"]
    problems = []
    hooks = policy.get("hooks") if isinstance(policy.get("hooks"), dict) else {}

    def gate_entries(event: str) -> tuple[list[dict], list[str]]:
        entries = [e for e in hooks.get(event, []) if isinstance(e, dict)] if isinstance(hooks.get(event), list) else []
        commands = [h.get("command", "") for e in entries for h in e.get("hooks", []) if isinstance(h, dict)]
        return entries, [c for c in commands if isinstance(c, str) and c.startswith(WRAPPER + " ") and c.endswith("krista_gate.py")]

    entries, gate_commands = gate_entries("PreToolUse")
    if not gate_commands:
        problems.append("no PreToolUse hook runs the gate through the fail-closed wrapper")
    else:
        script = Path(gate_commands[0][len(WRAPPER) + 1:])
        if not script.is_absolute():
            problems.append("the gate path is not absolute")
        elif not script.is_file():
            problems.append(f"the gate script does not exist: {script}")
        else:
            root = script.parents[3]
            if pin.verify(root / "krista"):
                problems.append("the pinned KRISTA copy next to the gate is missing or changed")
    covering = [e.get("matcher", "") for e in entries if any(isinstance(h, dict) and h.get("command") in gate_commands for h in e.get("hooks", []))]
    for tool in REQUIRED_TOOLS:
        if not any(tool in m for m in covering):
            problems.append(f"the gate matcher does not cover {tool}")
    for event in EVENTS[1:]:
        if not gate_entries(event)[1]:
            problems.append(f"no {event} hook runs the gate through the fail-closed wrapper")
    permissions = policy.get("permissions") if isinstance(policy.get("permissions"), dict) else {}
    if permissions.get("disableBypassPermissionsMode") != "disable":
        problems.append("permissions.disableBypassPermissionsMode is not \"disable\"")
    if profile == "strict" and policy.get("allowManagedHooksOnly") is not True:
        problems.append("allowManagedHooksOnly is not true: another hook may rewrite a tool input after the gate approved it")
    return problems


def protected(path: Path) -> list[str]:
    """Why a tree is not a safe home for the gate: anything the agent's user could write."""
    issues = []
    for entry in [path, *path.rglob("*")]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            issues.append(f"symlink: {entry}")
        elif info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            issues.append(f"group- or world-writable: {entry}")
        elif info.st_uid != 0:
            issues.append(f"not owned by root: {entry}")
    return issues


def install_tree(dest: Path) -> int:
    if dest.exists():
        print(f"{dest} exists; remove it first", file=sys.stderr)
        return 1
    problems = pin.verify()
    if problems:
        print("the pinned KRISTA copy is not intact: " + "; ".join(problems), file=sys.stderr)
        return 1
    (dest / "plugins").mkdir(parents=True)
    shutil.copytree(PLUGIN_ROOT, dest / "plugins" / "krista-gate", ignore=shutil.ignore_patterns("__pycache__", "tests"))
    shutil.copytree(REPO_ROOT / "krista", dest / "krista")
    for entry in [dest, *dest.rglob("*")]:
        if not entry.is_symlink():
            entry.chmod(entry.stat().st_mode & ~(stat.S_IWGRP | stat.S_IWOTH))
    print(f"installed the gate tree at {dest}")
    return 0


def install(gate_root: Path, out: Path, profile: str, force: bool, allow_user_owned: bool, allow_unsafe: bool = False) -> int:
    if profile == "coexist" and not allow_unsafe:
        print("the coexist profile can be bypassed: another hook may rewrite a tool input after the gate allowed it. "
              "Use the strict profile, or pass --allow-unsafe to accept that.", file=sys.stderr)
        return 1
    if not gate_script(gate_root).is_file():
        print(f"no gate at {gate_script(gate_root)}", file=sys.stderr)
        return 1
    if out.exists() and not force:
        print(f"{out} exists; managed settings are not merged automatically (use --force to replace)", file=sys.stderr)
        return 1
    if not allow_user_owned:
        issues = protected(gate_root)
        if issues:
            print("the gate tree is not protected from the agent's user:\n  " + "\n  ".join(issues[:5]), file=sys.stderr)
            return 1
    policy = render(gate_root, profile)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".managed-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(policy, handle, indent=2)
        handle.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)
    problems = check(out, profile)
    if problems:
        print("installed, but the check failed: " + "; ".join(problems), file=sys.stderr)
        return 1
    print(f"installed {profile} policy at {out}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("render")
    r.add_argument("--gate-root", type=Path, required=True)
    r.add_argument("--profile", choices=PROFILES, default="strict")
    t = sub.add_parser("install-tree")
    t.add_argument("--dest", type=Path, required=True)
    i = sub.add_parser("install")
    i.add_argument("--gate-root", type=Path, required=True)
    i.add_argument("--out", type=Path, required=True)
    i.add_argument("--profile", choices=PROFILES, default="strict")
    i.add_argument("--force", action="store_true")
    i.add_argument("--allow-user-owned", action="store_true")
    i.add_argument("--allow-unsafe", action="store_true", help="permit the coexist profile, which another hook can bypass by rewriting a tool input")
    c = sub.add_parser("check")
    c.add_argument("policy", type=Path)
    c.add_argument("--profile", choices=PROFILES, default="strict")
    args = parser.parse_args(argv)
    if args.command == "render":
        print(json.dumps(render(args.gate_root, args.profile), indent=2))
        return 0
    if args.command == "install-tree":
        return install_tree(args.dest)
    if args.command == "install":
        return install(args.gate_root, args.out, args.profile, args.force, args.allow_user_owned, args.allow_unsafe)
    problems = check(args.policy, args.profile)
    print("managed policy check: " + ("PASS" if not problems else "FAIL"))
    for problem in problems:
        print(f"- {problem}")
    return int(bool(problems))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
