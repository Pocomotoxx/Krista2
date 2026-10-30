#!/usr/bin/env python3
"""KRISTA PreToolUse gate (phase 1): path, action and open-question checks at the tool boundary.

Exit 0 allows the call, exit 2 blocks it; the reason goes to stderr. Wrap the command so that any
failure of the gate itself also blocks (see hooks/hooks.json): Claude Code lets a call through when
a hook crashes, times out or is missing.

The authorization is the vibe-code session record (KRISTA runtime/schemas/vibe-code-session):
    KRISTA_SESSION_RECORD   absolute path to the record, set by the launcher, outside the workspace
    KRISTA_GATE_NETWORK     "1" authorizes WebFetch and WebSearch
    KRISTA_GATE_MCP_ALLOW   comma-separated tool names or fnmatch patterns allowed for mcp__ tools
    KRISTA_GATE_PROTECTED   colon-separated extra repository-relative patterns that are never writable
    KRISTA_GATE_LOG         optional path of a metadata-only decision log (tool, decision, code)

What it enforces, and what it cannot:
  - A write tool needs a valid record that allows `edit`, no blocking open question, a path inside
    the project and inside `allowed_paths`, outside `forbidden_paths` and the protected set, and a
    current branch that is neither a default branch nor different from the record's target branch.
  - Bash is not parsed for paths. It runs only when it is a read-only command, a test command the
    record declares verbatim, or a narrow git add / commit / push that the record's actions allow.
  - The record is checked on every call, so answering a blocking question releases the gate.
  - It does not read file contents, judge a command's effect, or prove the record is true.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
KRISTA_ROOT = REPO_ROOT / "krista"

WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
NETWORK_TOOLS = {"WebFetch", "WebSearch"}
READ_TOOLS = {"Read", "Glob", "Grep", "LS", "NotebookRead"}

# Never writable, whatever the record says: the gate's own configuration and the places that switch it off.
PROTECTED = (".claude/**", ".git/**", ".githooks/**", ".krista/**", "krista/**", "plugins/krista-gate/**",
             "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json")

# A shell string with any of these is never a simple command: chaining, redirection, substitution, globbing.
_SHELL_META = re.compile(r"[;&|<>`$(){}\\\n\r*?\[\]~!#]")
_READONLY_COMMANDS = {"pwd", "ls", "cat", "head", "tail", "wc", "grep"}
_GIT_READONLY = {"status", "diff", "log", "show", "rev-parse", "ls-files"}
_GIT_BRANCH_READ_FLAGS = {"--show-current", "--list", "-l", "-a", "-r", "-v"}
_REMOTE = re.compile(r"^[A-Za-z0-9._-]+$")
_BRANCH = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]*$")
_SECRET_NAME = re.compile(r"(^|/)\.env($|\.)")


class Denied(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_validator(krista_root: Path = KRISTA_ROOT):
    """Import KRISTA's session validator from the pinned copy, after checking its digests."""
    try:
        files = json.loads((krista_root / "MANIFEST.json").read_text(encoding="utf-8"))["files"]
        bad = [rel for rel, expected in files.items() if sha256(krista_root / rel) != expected]
    except (OSError, ValueError, KeyError):
        raise Denied("G-PIN", "the pinned KRISTA copy is missing or unreadable") from None
    if bad:
        raise Denied("G-PIN", f"the pinned KRISTA copy was changed: {', '.join(sorted(bad))}")
    sys.path.insert(0, str(krista_root))
    import importlib

    return importlib.import_module("scripts.validate_vibe_code_session")


def normalise_branch(value: object) -> str:
    if not isinstance(value, str):
        return ""
    name = value.strip()
    for prefix in ("refs/heads/", "origin/", "refs/remotes/origin/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.casefold()


def within(path: str, patterns: list[str]) -> bool:
    """Same matching as KRISTA's validator: glob, exact, or under a directory pattern."""
    for pattern in patterns:
        if fnmatch.fnmatchcase(path, pattern) or path == pattern or path.startswith(pattern.rstrip("/") + "/"):
            return True
    return False


def blocking_open(record: dict) -> bool:
    """A blocking question that is open, or an entry too malformed to trust, keeps implementation shut."""
    questions = record.get("open_questions")
    if questions is None:
        return False
    if not isinstance(questions, list):
        return True
    for item in questions:
        if not isinstance(item, dict):
            return True
        status, blocking = item.get("status"), item.get("blocking")
        if status not in ("OPEN", "ANSWERED", "ASSUMED") or not isinstance(blocking, bool):
            return True
        if blocking and status in ("OPEN", "ASSUMED"):
            return True
    return False


class Policy:
    """What the session record authorizes, read once per call."""

    def __init__(self, record: dict | None, problem: str = "") -> None:
        self.record, self.problem = record, problem
        scope = (record or {}).get("scope") if isinstance((record or {}).get("scope"), dict) else {}
        self.mode = (record or {}).get("mode")
        self.actions = {a for a in scope.get("actions", []) if isinstance(a, str)} if isinstance(scope.get("actions"), list) else set()
        self.allowed = [p.strip() for p in scope.get("allowed_paths", []) if isinstance(p, str) and p.strip()] if isinstance(scope.get("allowed_paths"), list) else []
        self.forbidden = [p.strip() for p in scope.get("forbidden_paths", []) if isinstance(p, str) and p.strip()] if isinstance(scope.get("forbidden_paths"), list) else []
        target = (record or {}).get("target") if isinstance((record or {}).get("target"), dict) else {}
        self.target_branch = normalise_branch(target.get("branch"))
        declared = []
        for receipt in (record or {}).get("test_receipts", []) if isinstance((record or {}).get("test_receipts"), list) else []:
            if isinstance(receipt, dict) and isinstance(receipt.get("command"), str):
                declared.append(receipt["command"])
        repro = (record or {}).get("reproduction")
        if isinstance(repro, dict) and isinstance(repro.get("repro_command"), str):
            declared.append(repro["repro_command"])
        self.declared_commands = {" ".join(c.split()) for c in declared if c.strip()}

    @property
    def valid(self) -> bool:
        return self.record is not None and not self.problem

    def allows(self, action: str) -> bool:
        return self.valid and self.mode != "PLAN_ONLY" and action in self.actions


def load_record(env: dict, validator) -> Policy:
    path = env.get("KRISTA_SESSION_RECORD")
    if not path:
        return Policy(None, "no session record is configured (KRISTA_SESSION_RECORD)")
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return Policy(None, "the session record is missing or not valid JSON")
    if not isinstance(record, dict):
        return Policy(None, "the session record is not a JSON object")
    if blocking_open(record):
        return Policy(record, "OPENQ")
    errors = validator.validate(record)
    if errors:
        return Policy(None, f"the session record is invalid: {errors[0]}")
    return Policy(record)


def project_root(event: dict, env: dict) -> Path:
    return Path(os.path.realpath(env.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()))


def current_branch(root: Path) -> str | None:
    """The checked-out branch, "HEAD" when detached, or None when the project is not a git worktree."""
    try:
        # symbolic-ref also works on a branch that has no commit yet; rev-parse HEAD does not.
        done = subprocess.run(["git", "-C", str(root), "symbolic-ref", "--short", "-q", "HEAD"], capture_output=True, text=True,
                              timeout=3, env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")})
    except FileNotFoundError:
        return None
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("G-ERR", "the current branch could not be read") from None
    if done.returncode == 0:
        return done.stdout.strip()
    # Exit 1 is a detached HEAD: no branch name, so it never matches the record's target branch.
    return "HEAD" if done.returncode == 1 else None


def require_valid(policy: Policy, what: str) -> None:
    if policy.problem == "OPENQ":
        raise Denied("G-OPENQ", f"{what} is blocked: a blocking open question is not answered yet. Ask the human, then record the answer.")
    if not policy.valid:
        raise Denied("G-NOREC", f"{what} is blocked: {policy.problem}.")


def require_action(policy: Policy, action: str, what: str) -> None:
    if not policy.allows(action):
        raise Denied("G-ACT", f"{what} needs the `{action}` action in a CANDIDATE_ONLY or AUTHORIZED_WRITE session record.")


def check_branch(policy: Policy, root: Path, branch_fn, defaults) -> str | None:
    branch = branch_fn(root)
    if branch is None:
        return None
    name = normalise_branch(branch)
    if name in defaults:
        raise Denied("G-BRANCH", "the default branch is read-only; work on a task branch.")
    if policy.target_branch and name != policy.target_branch:
        raise Denied("G-BRANCH", f"the checked-out branch is not the record's target branch ({policy.target_branch}).")
    return name


def check_path(raw: object, cwd: Path, root: Path, policy: Policy, env: dict) -> str:
    """Repository-relative path of a write target, or a denial. Symlinks are resolved first."""
    if not isinstance(raw, str) or not raw.strip():
        raise Denied("G-PATH", "the tool call names no file path.")
    target = Path(raw) if os.path.isabs(raw) else cwd / raw
    resolved = Path(os.path.realpath(target))
    try:
        rel = resolved.relative_to(root).as_posix()
    except ValueError:
        raise Denied("G-PATH", "the path is outside the project.") from None
    extra = [p for p in env.get("KRISTA_GATE_PROTECTED", "").split(":") if p]
    if rel == "." or within(rel, list(PROTECTED) + extra):
        raise Denied("G-PROT", f"{rel} is a protected path (gate, hook, instruction or git configuration).")
    if _SECRET_NAME.search(rel):
        raise Denied("G-PROT", f"{rel} looks like a secrets file.")
    if within(rel, policy.forbidden):
        raise Denied("G-FORB", f"{rel} is in the record's forbidden_paths.")
    if not within(rel, policy.allowed):
        raise Denied("G-PATH", f"{rel} is outside the record's allowed_paths.")
    return rel


def parse_simple(command: str) -> list[str]:
    if _SHELL_META.search(command):
        raise Denied("G-BASH", "the command chains, redirects, substitutes or globs; only a simple command is allowed.")
    try:
        argv = shlex.split(command)
    except ValueError:
        raise Denied("G-BASH", "the command could not be parsed.") from None
    if not argv:
        raise Denied("G-BASH", "the command is empty.")
    return argv


def check_read_args(argv: list[str], cwd: Path, root: Path) -> None:
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        resolved = Path(os.path.realpath(Path(arg) if os.path.isabs(arg) else cwd / arg))
        try:
            rel = resolved.relative_to(root).as_posix()
        except ValueError:
            raise Denied("G-BASH", "a read-only command may only name paths inside the project.") from None
        if _SECRET_NAME.search(rel):
            raise Denied("G-BASH", "a read-only command may not read a secrets file.")


def check_git(argv: list[str], policy: Policy, cwd: Path, root: Path, env: dict, branch_fn, defaults) -> None:
    sub = argv[1] if len(argv) > 1 else ""
    rest = argv[2:]
    if not sub or sub.startswith("-"):
        raise Denied("G-GIT", "git global options are not allowed; give the subcommand first.")
    if sub in _GIT_READONLY:
        if any(a.startswith("--output") or a == "-o" for a in rest):
            raise Denied("G-GIT", "git output redirection is not allowed.")
        check_read_args(argv[1:], cwd, root)
        return
    if sub == "branch":
        if all(a in _GIT_BRANCH_READ_FLAGS for a in rest):
            return
        raise Denied("G-GIT", "git branch may only list or show the current branch.")
    if sub not in ("add", "commit", "push"):
        raise Denied("G-GIT", f"git {sub} is not allowed by the gate.")
    require_valid(policy, f"git {sub}")
    if sub == "add":
        require_action(policy, "commit", "git add")
        paths = [a for a in rest if a != "--"]
        if not paths or any(a.startswith("-") for a in paths):
            raise Denied("G-GIT", "git add takes explicit file paths and no options.")
        check_branch(policy, root, branch_fn, defaults)
        for path in paths:
            check_path(path, cwd, root, policy, env)
            if Path(os.path.realpath(Path(path) if os.path.isabs(path) else cwd / path)).is_dir():
                raise Denied("G-GIT", "git add takes files, not directories.")
        return
    if sub == "commit":
        require_action(policy, "commit", "git commit")
        if not ((len(rest) == 2 and rest[0] in ("-m", "--message")) or (len(rest) == 1 and rest[0].startswith("--message="))):
            raise Denied("G-GIT", "git commit allows only `-m <message>`: no -a, --amend, --no-verify or file options.")
        check_branch(policy, root, branch_fn, defaults)
        return
    if sub == "push":
        require_action(policy, "push", "git push")
        args = [a for a in rest if a not in ("-u", "--set-upstream")]
        if len(args) != 2 or not _REMOTE.match(args[0]) or not _BRANCH.match(args[1]):
            raise Denied("G-GIT", "git push allows only `[-u] <remote> <branch>`; no force, delete or refspec.")
        name = check_branch(policy, root, branch_fn, defaults)
        if normalise_branch(args[1]) in defaults:
            raise Denied("G-BRANCH", "pushing to a default branch is not allowed.")
        if name is not None and normalise_branch(args[1]) != name:
            raise Denied("G-GIT", "git push may only push the checked-out branch.")
        return


def check_bash(command: object, policy: Policy, cwd: Path, root: Path, env: dict, branch_fn, defaults) -> None:
    if not isinstance(command, str):
        raise Denied("G-BASH", "the Bash call carries no command.")
    if " ".join(command.split()) in policy.declared_commands:
        require_valid(policy, "a declared test command")
        require_action(policy, "test", "a declared test command")
        return
    argv = parse_simple(command)
    if argv[0] == "git":
        return check_git(argv, policy, cwd, root, env, branch_fn, defaults)
    if argv[0] in _READONLY_COMMANDS:
        return check_read_args(argv, cwd, root)
    raise Denied("G-BASH", "this command is not read-only and is not declared in the record. "
                           "Declare it in test_receipts[].command or reproduction.repro_command, or ask the human.")


def check_mcp(tool: str, env: dict) -> None:
    allowed = [p.strip() for p in env.get("KRISTA_GATE_MCP_ALLOW", "").split(",") if p.strip()]
    if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in allowed):
        raise Denied("G-MCP", f"{tool} is not authorized; MCP tools can run commands and cannot be path-checked.")


def decide(event: dict, env: dict, validator=None, branch_fn=current_branch) -> tuple[str, str, str]:
    """Return (decision, code, message); decision is "allow" or "deny"."""
    try:
        validator = validator or load_validator()
        tool = event.get("tool_name")
        tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
        if not isinstance(tool, str) or not tool:
            raise Denied("G-TOOL", "the event names no tool.")
        defaults = frozenset(validator.DEFAULT_BRANCHES)
        root = project_root(event, env)
        cwd = Path(os.path.realpath(event.get("cwd") or root))
        if tool in READ_TOOLS:
            return "allow", "G-OK", ""
        if tool in NETWORK_TOOLS:
            if env.get("KRISTA_GATE_NETWORK") != "1":
                raise Denied("G-NET", "network access needs a separate authorization (KRISTA_GATE_NETWORK).")
            return "allow", "G-OK", ""
        if tool.startswith("mcp__"):
            check_mcp(tool, env)
            return "allow", "G-OK", ""
        policy = load_record(env, validator)
        if tool == "Bash":
            if policy.problem == "OPENQ":
                # Reading stays possible while a question is open; anything else waits for the answer.
                argv = parse_simple(tool_input.get("command", "")) if isinstance(tool_input.get("command"), str) else []
                readonly = bool(argv) and (argv[0] in _READONLY_COMMANDS or (argv[0] == "git" and len(argv) > 1 and argv[1] in _GIT_READONLY))
                if not readonly:
                    require_valid(policy, "this command")
                check_bash(tool_input.get("command"), Policy(None, "OPENQ-READ"), cwd, root, env, branch_fn, defaults)
                return "allow", "G-OK", ""
            check_bash(tool_input.get("command"), policy, cwd, root, env, branch_fn, defaults)
            return "allow", "G-OK", ""
        if tool in WRITE_TOOLS:
            require_valid(policy, f"{tool}")
            require_action(policy, "edit", tool)
            check_branch(policy, root, branch_fn, defaults)
            check_path(tool_input.get(WRITE_TOOLS[tool]), cwd, root, policy, env)
            return "allow", "G-OK", ""
        raise Denied("G-TOOL", f"{tool} is not a tool the gate knows; unknown tools are denied.")
    except Denied as denial:
        return "deny", denial.code, denial.message


def log_decision(env: dict, event: dict, decision: str, code: str) -> None:
    path = env.get("KRISTA_GATE_LOG")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"t": int(time.time()), "tool": event.get("tool_name"), "decision": decision, "code": code,
                                     "permission_mode": event.get("permission_mode")}) + "\n")
    except OSError:
        pass


def main() -> int:
    event: dict = {}
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("event is not an object")
        decision, code, message = decide(event, os.environ)
    except BaseException as exc:  # noqa: BLE001 - any failure of the gate blocks the call
        decision, code, message = "deny", "G-ERR", f"the gate failed ({type(exc).__name__}) and blocks the call"
    log_decision(os.environ, event if isinstance(event, dict) else {}, decision, code)
    if decision == "deny":
        print(f"KRISTA-GATE {code}: {message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
