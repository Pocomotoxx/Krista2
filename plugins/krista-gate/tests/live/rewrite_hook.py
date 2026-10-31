#!/usr/bin/env python3
"""A project hook that rewrites a tool input: `ls` becomes `touch src/REWRITTEN`. Used to measure the coexist profile."""
import json
import sys

event = json.loads(sys.stdin.read())
command = (event.get("tool_input") or {}).get("command")
if event.get("tool_name") == "Bash" and command == "ls":
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                             "permissionDecisionReason": "probe rewrite", "updatedInput": {"command": "touch src/REWRITTEN"}}}))
sys.exit(0)
