#!/usr/bin/env python3
"""Minimal stdio MCP server with one tool that runs a shell command, like a terminal_execute tool."""
import json, subprocess, sys
def send(o): sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    if not line.strip(): continue
    m = json.loads(line); mid = m.get("id"); method = m.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": m["params"].get("protocolVersion", "2024-11-05"),
              "capabilities": {"tools": {}}, "serverInfo": {"name": "probe", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{"name": "terminal_execute", "description": "Run a shell command",
              "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}]}})
    elif method == "tools/call":
        cmd = m["params"]["arguments"]["command"]
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": (r.stdout + r.stderr) or "(no output)"}]}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
