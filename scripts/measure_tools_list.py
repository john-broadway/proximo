#!/usr/bin/env python3
"""Measure what the README states: the bytes of `tools/list` over stdio, as a client receives them.

The README said 5,544 bytes "measured on this release" for a month of releases; the door answered
4,039 (the 2026-11-19 read). A measured claim nobody re-measures is a number typed once. This
starts the stdio door as a client would, with no `PROXIMO_*` setting and a throwaway home (so it
reads no real env file, dials nothing and writes no real ledger), asks `initialize` then
`tools/list`, and prints the length of the answer line with its newline. `scripts/release.sh`
hands the number to `copy_ripple_check.py check --wire N`.

Usage: python scripts/measure_tools_list.py     # prints one integer
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def measure() -> int:
    with tempfile.TemporaryDirectory() as home:
        env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_")}
        env.update(HOME=home, PROXIMO_ENV_FILE=os.path.join(home, "none.env"),
                   PROXIMO_AUDIT_LOG=os.path.join(home, "audit.log"), PYTHONDONTWRITEBYTECODE="1")
        door = subprocess.Popen([sys.executable, "-m", "proximo"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, cwd=home)
        if door.stdin is None or door.stdout is None:
            raise SystemExit("measure_tools_list: the door has no pipes")
        try:
            def send(message: dict) -> None:
                door.stdin.write((json.dumps(message) + "\n").encode())
                door.stdin.flush()

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "measure", "version": "0"}}})
            door.stdout.readline()
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            line = door.stdout.readline()
        finally:
            door.kill()
    if len(json.loads(line)["result"]["tools"]) != 6:
        raise SystemExit("measure_tools_list: the door did not answer its six tools")
    return len(line)


if __name__ == "__main__":
    print(measure())
