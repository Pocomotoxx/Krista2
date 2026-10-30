#!/usr/bin/env python3
"""KRISTA gate: path, action and open-question checks, ingress and egress filters, and a local ledger.

Exit 0 allows the call, exit 2 blocks it; the reason goes to stderr. Wrap the command so that any
failure of the gate itself also blocks (see hooks/hooks.json): Claude Code lets a call through when
a hook crashes, times out or is missing.

The authorization is the vibe-code session record (KRISTA runtime/schemas/vibe-code-session):
    KRISTA_SESSION_RECORD   absolute path to the record, set by the launcher, outside the workspace
    KRISTA_GATE_NETWORK     "1" authorizes WebFetch and WebSearch
    KRISTA_GATE_MCP_ALLOW   comma-separated tool names or fnmatch patterns allowed for mcp__ tools
    KRISTA_GATE_PROTECTED   colon-separated extra repository-relative patterns that are never writable
    KRISTA_GATE_LOG         optional path of a plain metadata-only decision log (tool, decision, code)
    KRISTA_RUNTIME_LOG_ROOT directory of the hash-chained ledger (gate, ingress, egress, decisions); outside the project
    KRISTA_LEDGER_REQUIRED  "1": no decision is allowed without a working ledger
    KRISTA_FILTER_PII       "block" (default) or "off": Hungarian personal-identifier shapes; credentials always block
    KRISTA_FILTER_ALLOW_PATHS  colon-separated patterns of files that are not scanned (test fixtures)
    KRISTA_FILTER_MAX_BYTES file size above which a read is withheld as unscannable (default 2 MiB)

What it enforces, and what it cannot:
  - A write tool needs a valid record that allows `edit`, no blocking open question, a path inside
    the project and inside `allowed_paths`, outside `forbidden_paths` and the protected set, and a
    current branch that is neither a default branch nor different from the record's target branch.
  - Bash is not parsed for paths. It runs only when it is a read-only command, a test command the
    record declares verbatim, or a narrow git add / commit / push that the record's actions allow.
  - The record is checked on every call, so answering a blocking question releases the gate.
  - Ingress: a file the Read tool or a read-only command opens, and the user's prompt, are scanned for credential and
    personal-identifier shapes and withheld whole when something is found (a hook can admit or withhold, not mask).
  - Egress: the content a write tool, `git add` or `git commit -m` is about to put in a file or a commit, and the inputs of
    a network or MCP tool, are scanned and blocked when something is found. A Stop hook flags a chat message that carried
    such a value, but it cannot recall the message: the text was already shown.
  - Every decision is appended to the ledger; if the ledger is configured and cannot be written, an allow becomes a deny.
  - It does not judge a command's effect, find a name or an address, or prove the record is true.
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
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import krista_filters as filters  # noqa: E402
import krista_ledger as ledger  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
KRISTA_ROOT = REPO_ROOT / "krista"

WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
NETWORK_TOOLS = {"WebFetch", "WebSearch"}
SCANNED_READ_TOOLS = {"Read": "file_path", "NotebookRead": "notebook_path"}
READ_TOOLS = {"Glob", "Grep", "LS"}

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
_CONTENT_READERS = {"cat", "head", "tail", "grep", "wc"}


class Denied(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_MODULES: types.SimpleNamespace | None = None


class _Pinned(types.SimpleNamespace):
    """The pinned KRISTA modules, imported on first use after every file digest was checked."""

    @property
    def ingress(self):
        import importlib

        return importlib.import_module("scripts.validate_ingress_sanitization")

    @property
    def egress(self):
        import importlib

        return importlib.import_module("scripts.validate_egress_sanitization")

    @property
    def keys(self):
        import importlib

        return importlib.import_module("scripts.ledger_keys")


def load_modules(krista_root: Path = KRISTA_ROOT) -> _Pinned:
    """Check the pin, then import the KRISTA modules the gate uses. A changed or missing file is G-PIN."""
    global _MODULES
    try:
        manifest = json.loads((krista_root / "MANIFEST.json").read_text(encoding="utf-8"))
        files = manifest["files"]
        bad = [rel for rel, expected in files.items() if sha256(krista_root / rel) != expected]
    except (OSError, ValueError, KeyError):
        raise Denied("G-PIN", "the pinned KRISTA copy is missing or unreadable") from None
    if bad:
        raise Denied("G-PIN", f"the pinned KRISTA copy was changed: {', '.join(sorted(bad))}")
    if _MODULES is not None and getattr(_MODULES, "root", None) == str(krista_root):
        return _MODULES
    sys.path.insert(0, str(krista_root))
    import importlib

    _MODULES = _Pinned(root=str(krista_root), commit=manifest.get("source_commit", "unknown"),
                       vibe=importlib.import_module("scripts.validate_vibe_code_session"),
                       redaction=importlib.import_module("scripts.redaction"), repo_scan=importlib.import_module("scripts.repo_scan"))
    return _MODULES


def load_validator(krista_root: Path = KRISTA_ROOT):
    """KRISTA's session validator from the pinned copy."""
    return load_modules(krista_root).vibe


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
        self.digest: str | None = None
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

    def summary(self) -> dict:
        """Authorization metadata for the ledger: what the record allows, never its text."""
        return {"digest": self.digest, "mode": self.mode, "actions": sorted(self.actions),
                "blocking_open": self.problem == "OPENQ" or (self.record is not None and blocking_open(self.record))}

    def allows(self, action: str) -> bool:
        return self.valid and self.mode != "PLAN_ONLY" and action in self.actions


def load_record(env: dict, validator) -> Policy:
    path = env.get("KRISTA_SESSION_RECORD")
    if not path:
        return Policy(None, "no session record is configured (KRISTA_SESSION_RECORD)")
    try:
        raw = Path(path).read_bytes()
        record = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return Policy(None, "the session record is missing or not valid JSON")
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(record, dict):
        policy = Policy(None, "the session record is not a JSON object")
    elif blocking_open(record):
        policy = Policy(record, "OPENQ")
    else:
        errors = validator.validate(record)
        policy = Policy(None, f"the session record is invalid: {errors[0]}") if errors else Policy(record)
    policy.digest = digest
    return policy


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


class Boundary:
    """Ingress and egress checks at the tool boundary. Each check leaves a KRISTA record, validated, in `meta` for the ledger."""

    def __init__(self, modules, env: dict, event: dict, meta: dict) -> None:
        self.modules, self.meta = modules, meta
        self.detector = filters.Detector(modules.redaction, modules.repo_scan, pii=env.get("KRISTA_FILTER_PII", "block") != "off")
        self.allow = [p for p in env.get("KRISTA_FILTER_ALLOW_PATHS", "").split(":") if p]
        try:
            self.max_bytes = int(env.get("KRISTA_FILTER_MAX_BYTES") or filters.DEFAULT_MAX_BYTES)
        except ValueError:
            self.max_bytes = filters.DEFAULT_MAX_BYTES
        session = event.get("session_id")
        self.execution = filters.ref("session", session) if isinstance(session, str) and session else "session:unknown"
        self.detector_ref = f"krista-gate/shape-detector@{str(getattr(modules, 'commit', 'unknown'))[:12]}"

    def _keep(self, kind: str, record: dict) -> None:
        errors = (self.modules.ingress if kind == "ingress" else self.modules.egress).validate(record)
        if errors:
            raise Denied("G-ERR", f"the {kind} record was invalid ({errors[0]}); the call is blocked")
        self.meta.setdefault(kind, []).append(record)

    def _ingress(self, unit_ref: str, status: str, findings=None, reason: str = "") -> None:
        self._keep("ingress", filters.ingress_record(self.execution, unit_ref, self.detector, self.detector_ref, status, findings, reason))

    def _egress(self, unit_ref: str, status: str, findings=None, scope: str = "OUTPUT_ARTIFACT", reason: str = "") -> None:
        self._keep("egress", filters.egress_record(self.execution, unit_ref, self.detector, status, findings, scope, reason))

    def ingress_text(self, label: str, text: str, unit_ref: str) -> None:
        found = self.detector.scan(text)
        if found:
            self._ingress(unit_ref, "WITHHELD", found)
            raise Denied("G-INGRESS", f"{label} holds {filters.kinds_text(found)} and is withheld from the model. "
                                      "Remove the values, or ask the human to allow this path (KRISTA_FILTER_ALLOW_PATHS).")
        self._ingress(unit_ref, "ADMITTED")

    def ingress_file(self, path: Path, rel: str) -> None:
        unit = filters.ref("file", rel)
        if filters.allowlisted(rel, str(path), self.allow):
            self._ingress(unit, "EXCLUDED")
            return
        text, status = filters.read_for_scan(path, self.max_bytes)
        if status in ("missing", "unreadable"):
            return
        if status == "binary":
            self._ingress(unit, "UNVERIFIABLE", reason="binary file")
            return
        if status == "toolarge":
            self._ingress(unit, "UNVERIFIABLE", reason=f"larger than {self.max_bytes} bytes")
            raise Denied("G-INGRESS", f"{rel} is larger than {self.max_bytes} bytes and cannot be scanned, so it is withheld. "
                                      "Read a smaller file, or ask the human to raise KRISTA_FILTER_MAX_BYTES.")
        self.ingress_text(rel, text or "", unit)

    def egress_text(self, label: str, text: str, unit_ref: str, rel: str | None = None, scope: str = "OUTPUT_ARTIFACT") -> None:
        if rel is not None and filters.allowlisted(rel, rel, self.allow):
            self._egress(unit_ref, "EXCLUDED", scope=scope)
            return
        found = self.detector.scan(text)
        if found:
            self._egress(unit_ref, "BLOCKED", found, scope)
            raise Denied("G-EGRESS", f"{label} would carry {filters.kinds_text(found)}; it is blocked before it leaves. "
                                     "Remove the values, or ask the human to allow this path (KRISTA_FILTER_ALLOW_PATHS).")
        self._egress(unit_ref, "PASSED", scope=scope)

    def egress_file(self, path: Path, rel: str) -> None:
        unit = filters.ref("file", rel)
        if filters.allowlisted(rel, str(path), self.allow):
            self._egress(unit, "EXCLUDED")
            return
        text, status = filters.read_for_scan(path, self.max_bytes)
        if status in ("missing", "unreadable"):
            return
        if status == "binary":
            self._egress(unit, "UNVERIFIABLE", reason="binary file")
            return
        if status == "toolarge":
            self._egress(unit, "UNVERIFIABLE", reason=f"larger than {self.max_bytes} bytes")
            raise Denied("G-EGRESS", f"{rel} is larger than {self.max_bytes} bytes and cannot be scanned before it is committed.")
        self.egress_text(rel, text or "", unit, rel)


def check_read_args(argv: list[str], cwd: Path, root: Path, boundary: Boundary | None = None) -> None:
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
        if boundary is not None:
            boundary.ingress_file(resolved, rel)


def check_git(argv: list[str], policy: Policy, cwd: Path, root: Path, env: dict, branch_fn, defaults, boundary: Boundary | None = None) -> None:
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
            rel = check_path(path, cwd, root, policy, env)
            resolved = Path(os.path.realpath(Path(path) if os.path.isabs(path) else cwd / path))
            if resolved.is_dir():
                raise Denied("G-GIT", "git add takes files, not directories.")
            if boundary is not None:
                boundary.egress_file(resolved, rel)
        return
    if sub == "commit":
        require_action(policy, "commit", "git commit")
        if not ((len(rest) == 2 and rest[0] in ("-m", "--message")) or (len(rest) == 1 and rest[0].startswith("--message="))):
            raise Denied("G-GIT", "git commit allows only `-m <message>`: no -a, --amend, --no-verify or file options.")
        check_branch(policy, root, branch_fn, defaults)
        if boundary is not None:
            message = rest[1] if len(rest) == 2 else rest[0].split("=", 1)[1]
            boundary.egress_text("the commit message", message, filters.ref("commit", message), scope="DELIVERABLE_TEXT")
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


def check_bash(command: object, policy: Policy, cwd: Path, root: Path, env: dict, branch_fn, defaults, boundary: Boundary | None = None) -> None:
    if not isinstance(command, str):
        raise Denied("G-BASH", "the Bash call carries no command.")
    if " ".join(command.split()) in policy.declared_commands:
        require_valid(policy, "a declared test command")
        require_action(policy, "test", "a declared test command")
        return
    argv = parse_simple(command)
    if argv[0] == "git":
        return check_git(argv, policy, cwd, root, env, branch_fn, defaults, boundary)
    if argv[0] in _READONLY_COMMANDS:
        return check_read_args(argv, cwd, root, boundary if argv[0] in _CONTENT_READERS else None)
    raise Denied("G-BASH", "this command is not read-only and is not declared in the record. "
                           "Declare it in test_receipts[].command or reproduction.repro_command, or ask the human.")


def check_mcp(tool: str, env: dict) -> None:
    allowed = [p.strip() for p in env.get("KRISTA_GATE_MCP_ALLOW", "").split(",") if p.strip()]
    if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in allowed):
        raise Denied("G-MCP", f"{tool} is not authorized; MCP tools can run commands and cannot be path-checked.")


def _network_text(tool: str, tool_input: dict) -> str:
    fields = ("url", "prompt") if tool == "WebFetch" else ("query",)
    return "\n".join(str(tool_input.get(f, "")) for f in fields)


def _write_text(tool: str, tool_input: dict) -> str:
    """The content a write tool is about to put in a file."""
    if tool == "Write":
        return str(tool_input.get("content", ""))
    if tool == "Edit":
        return str(tool_input.get("new_string", ""))
    if tool == "NotebookEdit":
        return str(tool_input.get("new_source", ""))
    edits = tool_input.get("edits")
    return "\n".join(str(e.get("new_string", "")) for e in edits if isinstance(e, dict)) if isinstance(edits, list) else ""


def _last_assistant_text(transcript: object, limit: int = 1 << 20) -> str | None:
    """Text of the assistant turn that ends the transcript, or None when it cannot be read."""
    if not isinstance(transcript, str) or not transcript:
        return None
    try:
        with open(transcript, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return None
    parts: list[str] = []
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("message") if isinstance(entry, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if entry.get("type") == "assistant" and isinstance(content, list):
            parts[:0] = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        elif entry.get("type") == "user":
            blocks = content if isinstance(content, list) else []
            if not blocks or any(isinstance(b, dict) and b.get("type") != "tool_result" for b in blocks):
                break
    return "\n".join(parts)


def decide_prompt(event: dict, boundary: Boundary) -> None:
    prompt = event.get("prompt")
    if not isinstance(prompt, str):
        raise Denied("G-ERR", "the prompt event carries no prompt text.")
    boundary.ingress_text("the prompt", prompt, filters.ref("prompt", prompt))


def decide_stop(event: dict, boundary: Boundary) -> None:
    if event.get("stop_hook_active"):
        return
    text = _last_assistant_text(event.get("transcript_path"))
    if text is None or not text.strip():
        return
    found = boundary.detector.scan(text)
    unit = filters.ref("message", text)
    if found:
        boundary._egress(unit, "BLOCKED", found, "DELIVERABLE_TEXT")
        raise Denied("G-EGRESS", f"your last message carried {filters.kinds_text(found)}. It was already displayed and cannot be recalled: "
                                 "tell the human that a value must be treated as exposed, and do not repeat it.")
    boundary._egress(unit, "PASSED", scope="DELIVERABLE_TEXT")


def decide(event: dict, env: dict, validator=None, branch_fn=current_branch, meta: dict | None = None, modules=None) -> tuple[str, str, str]:
    """Return (decision, code, message); decision is "allow" or "deny". `meta` collects what the ledger records."""
    meta = meta if meta is not None else {}
    try:
        modules = modules or load_modules()
        validator = validator or modules.vibe
        boundary = Boundary(modules, env, event, meta)
        kind = event.get("hook_event_name")
        if kind == "UserPromptSubmit":
            decide_prompt(event, boundary)
            return "allow", "G-OK", ""
        if kind == "Stop":
            decide_stop(event, boundary)
            return "allow", "G-OK", ""
        tool = event.get("tool_name")
        tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
        if not isinstance(tool, str) or not tool:
            raise Denied("G-TOOL", "the event names no tool.")
        defaults = frozenset(validator.DEFAULT_BRANCHES)
        root = project_root(event, env)
        cwd = Path(os.path.realpath(event.get("cwd") or root))
        if tool in READ_TOOLS:
            return "allow", "G-OK", ""
        if tool in SCANNED_READ_TOOLS:
            raw = tool_input.get(SCANNED_READ_TOOLS[tool])
            if not isinstance(raw, str) or not raw.strip():
                raise Denied("G-PATH", "the tool call names no file path.")
            resolved = Path(os.path.realpath(Path(raw) if os.path.isabs(raw) else cwd / raw))
            try:
                rel = resolved.relative_to(root).as_posix()
            except ValueError:
                rel = resolved.as_posix()
            if _SECRET_NAME.search(rel):
                raise Denied("G-INGRESS", f"{rel} looks like a secrets file and is withheld.")
            boundary.ingress_file(resolved, rel)
            return "allow", "G-OK", ""
        if tool in NETWORK_TOOLS:
            if env.get("KRISTA_GATE_NETWORK") != "1":
                raise Denied("G-NET", "network access needs a separate authorization (KRISTA_GATE_NETWORK).")
            text = _network_text(tool, tool_input)
            boundary.egress_text(f"the {tool} input", text, filters.ref("request", text), scope="DELIVERABLE_TEXT")
            return "allow", "G-OK", ""
        if tool.startswith("mcp__"):
            check_mcp(tool, env)
            text = json.dumps(tool_input, sort_keys=True, default=str)
            boundary.egress_text(f"the {tool} input", text, filters.ref("request", text), scope="DELIVERABLE_TEXT")
            return "allow", "G-OK", ""
        policy = load_record(env, validator)
        meta["policy"] = policy.summary()
        if tool == "Bash":
            if policy.problem == "OPENQ":
                # Reading stays possible while a question is open; anything else waits for the answer.
                argv = parse_simple(tool_input.get("command", "")) if isinstance(tool_input.get("command"), str) else []
                readonly = bool(argv) and (argv[0] in _READONLY_COMMANDS or (argv[0] == "git" and len(argv) > 1 and argv[1] in _GIT_READONLY))
                if not readonly:
                    require_valid(policy, "this command")
                check_bash(tool_input.get("command"), Policy(None, "OPENQ-READ"), cwd, root, env, branch_fn, defaults, boundary)
                return "allow", "G-OK", ""
            check_bash(tool_input.get("command"), policy, cwd, root, env, branch_fn, defaults, boundary)
            return "allow", "G-OK", ""
        if tool in WRITE_TOOLS:
            require_valid(policy, f"{tool}")
            require_action(policy, "edit", tool)
            check_branch(policy, root, branch_fn, defaults)
            rel = check_path(tool_input.get(WRITE_TOOLS[tool]), cwd, root, policy, env)
            boundary.egress_text(rel, _write_text(tool, tool_input), filters.ref("file", rel), rel)
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


def write_ledger(env: dict, event: dict, decision: str, code: str, meta: dict) -> None:
    """Append what this call produced to the ledger. Raises LedgerError when it is configured or required and cannot be written."""
    value, required = env.get("KRISTA_RUNTIME_LOG_ROOT"), env.get("KRISTA_LEDGER_REQUIRED") == "1"
    if not value and not required:
        return
    root = ledger.ledger_root(value, project_root(event, env))
    keys = load_modules().keys
    session = event.get("session_id")
    session_ref = filters.ref("session", session) if isinstance(session, str) and session else "session:unknown"

    def put(kind: str, record: dict) -> None:
        if keys.contains_forbidden(record):
            raise ledger.LedgerError("a forbidden field in a ledger record")
        ledger.append(root, kind, record)

    for record in meta.get("ingress", []):
        put("ingress", record)
    for record in meta.get("egress", []):
        put("egress", record)
    policy = meta.get("policy") or {}
    digest = policy.get("digest")
    if digest and ledger.last_value(root, "gate", "record_digest", {"record_type": "session_record_changed", "session_ref": session_ref}) != digest:
        put("gate", {"record_type": "session_record_changed", "session_ref": session_ref, "record_digest": digest,
                     "mode": policy.get("mode"), "actions": policy.get("actions"), "blocking_open": policy.get("blocking_open")})
    tool_use = event.get("tool_use_id")
    put("gate", {"record_type": "gate_decision", "hook_event": event.get("hook_event_name") or "PreToolUse", "tool": event.get("tool_name"),
                 "decision": decision, "code": code, "permission_mode": event.get("permission_mode"), "session_ref": session_ref,
                 "tool_use_ref": filters.ref("tool_use", tool_use) if isinstance(tool_use, str) and tool_use else None,
                 "record_digest": digest})


def main() -> int:
    event: dict = {}
    meta: dict = {}
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("event is not an object")
        decision, code, message = decide(event, os.environ, meta=meta)
    except BaseException as exc:  # noqa: BLE001 - any failure of the gate blocks the call
        decision, code, message = "deny", "G-ERR", f"the gate failed ({type(exc).__name__}) and blocks the call"
    event = event if isinstance(event, dict) else {}
    try:
        write_ledger(os.environ, event, decision, code, meta)
    except BaseException as exc:  # noqa: BLE001
        # A Stop hook cannot undo the message; blocking it on a ledger fault would only loop.
        if decision == "allow" and event.get("hook_event_name") != "Stop":
            decision, code, message = "deny", "G-LOG", f"the ledger could not be written ({type(exc).__name__}: {exc}); no call proceeds unlogged"
    log_decision(os.environ, event, decision, code)
    if decision == "deny":
        print(f"KRISTA-GATE {code}: {message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
