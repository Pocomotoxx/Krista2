#!/usr/bin/env python3
"""A hook that only records that it ran (plugin or project hook), to measure allowManagedHooksOnly."""
import os
import sys

sys.stdin.read()
with open(os.environ.get("PROBE_LOG", "/dev/null"), "a") as handle:
    handle.write("other-hook-ran\n")
sys.exit(0)
