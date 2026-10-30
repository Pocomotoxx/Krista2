#!/usr/bin/env python3
"""Pin the few KRISTA files the gate imports, and verify them.

    pin.py update --from <KRISTA checkout>   copy exactly FILES into krista/, record the source commit
    pin.py check                             verify krista/ against krista/MANIFEST.json

The pinned copy is tamper-evidence, not a security boundary: the gate checks it before it imports
anything, and the path is protected from writes by the gate itself.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PIN_DIR = REPO_ROOT / "krista"
FILES = (
    "scripts/schema_loader.py",
    "scripts/strict_fields.py",
    "scripts/test_plan_guard.py",
    "scripts/validate_vibe_code_session.py",
    "runtime/schemas/vibe-code-session.schema.json",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(pin_dir: Path = PIN_DIR) -> list[str]:
    """Problems with the pinned copy; empty means every file matches its recorded digest."""
    try:
        manifest = json.loads((pin_dir / "MANIFEST.json").read_text(encoding="utf-8"))
        files = manifest["files"]
    except (OSError, ValueError, KeyError) as exc:
        return [f"manifest unreadable: {type(exc).__name__}"]
    problems = []
    if sorted(files) != sorted(FILES):
        problems.append("manifest does not list exactly the pinned files")
    for rel, expected in files.items():
        target = pin_dir / rel
        if not target.is_file():
            problems.append(f"missing: {rel}")
        elif digest(target) != expected:
            problems.append(f"changed: {rel}")
    return problems


def update(source: Path) -> int:
    status = subprocess.run(["git", "-C", str(source), "status", "--porcelain", "--", *FILES], capture_output=True, text=True)
    if status.returncode != 0 or status.stdout.strip():
        print("source checkout is not a clean git worktree for the pinned files", file=sys.stderr)
        return 1
    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if len(commit) != 40:
        print("cannot resolve the source commit", file=sys.stderr)
        return 1
    if PIN_DIR.exists():
        shutil.rmtree(PIN_DIR)
    for rel in FILES:
        (PIN_DIR / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / rel, PIN_DIR / rel)
    (PIN_DIR / "PINNED_COMMIT").write_text(commit + "\n", encoding="utf-8")
    (PIN_DIR / "MANIFEST.json").write_text(
        json.dumps({"source_commit": commit, "files": {rel: digest(PIN_DIR / rel) for rel in FILES}}, indent=1) + "\n", encoding="utf-8")
    print(f"pinned {len(FILES)} files from {commit}")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["check"] and len(argv) == 1:
        problems = verify()
        print("pin check: " + ("PASS" if not problems else "FAIL"))
        for problem in problems:
            print(f"- {problem}")
        return int(bool(problems))
    if len(argv) == 3 and argv[0] == "update" and argv[1] == "--from":
        return update(Path(argv[2]))
    print("usage: pin.py check | pin.py update --from <KRISTA checkout>")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
