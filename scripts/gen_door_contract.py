#!/usr/bin/env python3
"""The door contract: the MCP door's public interface, frozen so it changes only on purpose.

Any client of the door (an agent, an integration, a script) depends on two things: the six tools
as `tools/list` hands them over (name, description, input schema, read-only hint), and the shapes
the answers come back in (the keys of a plan, a read, a find, a refusal's words, every `needs` a
refusal can carry). THIS file, `docs/door-contract.json`, is that interface, and the suite holds
the door to it: a door that drifts from the file is red until the change is made on purpose, with
`--bump`, which raises `contract` and asks for the CHANGELOG line that tells every client the
interface moved. Values that move with an authored record (`why`, a tier) are not the contract;
their keys are.

Built in process, one estate (no `PROXIMO_TARGETS`: a registry adds `target` to three tools),
no credential, a scratch ledger, the operator's env file pointed at nothing. The one read that
needs rows is served two synthetic rows by a stand-in client, so nothing dials.

    uv run python scripts/gen_door_contract.py           # refuses if the door drifted
    uv run python scripts/gen_door_contract.py --bump    # a deliberate change: contract + 1
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "door-contract.json"
# The keys whose VALUES are protocol a client acts on; every other value is content.
PROTOCOL = ("status", "allowed", "needs", "access", "ok")
_ROWS = [{"id": "qemu/101", "type": "qemu", "node": "n1", "vmid": 101, "name": "a", "status": "running", "mem": 1},
         {"id": "lxc/102", "type": "lxc", "node": "n1", "vmid": 102, "name": "b", "status": "stopped", "mem": 2}]
# (tool, arguments, env): each answer a client meets, and each refusal lane the door can say no in.
# "ARMED" is the synthetic estate with its served token equal to its arm source. Each sample sets
# its own switches over the base env; the one order that matters is the rate pair: the first call
# under a cap of one takes the slot, the second is over the budget.
_STOP = {"plane": "pve", "method": "POST", "path": "/nodes/n1/qemu/101/status/stop"}
_CONFIG = {"plane": "pve", "method": "PUT", "path": "/nodes/n1/qemu/101/config", "args": {"memory": "2048"}}
SAMPLES: list[tuple[str, dict[str, Any], dict[str, str]]] = [
    ("proximo_find", {"query": "stop a vm"}, {}),
    ("proximo_plan", dict(_STOP), {}),
    # a restore without `unique`: the plan carries a note (notes.toml), a key no other sample fires
    ("proximo_plan", {"plane": "pve", "method": "POST", "path": "/nodes/n1/qemu",
                      "args": {"vmid": "103", "archive": "local:backup/vzdump-qemu-101.vma.zst"}}, {}),
    # a consulted address (consult.toml): the plan carries the consult section, here on a box with no
    # credential (it says why it could not look and raises to the judge's worst case)
    ("proximo_plan", {"plane": "pve", "method": "DELETE", "path": "/nodes/n1/storage/local/content/vm-101-disk-0"}, {}),
    ("proximo_call", dict(_STOP), {}),
    ("proximo_call", dict(_STOP, confirm=True), {}),
    ("proximo_read", {"plane": "pve", "path": "/cluster/resources"}, {}),
    ("proximo_read", {"plane": "pve", "path": "/no/such/address"}, {}),
    ("proximo_call", dict(_CONFIG, confirm=True), {"ARMED": "1"}),
    ("proximo_call", dict(_STOP, confirm=True), {"ARMED": "1"}),
    ("proximo_call", dict(_STOP, confirm=True), {"ARMED": "1", "PROXIMO_RATE_MAX": "1"}),
    ("proximo_call", dict(_STOP, confirm=True), {"ARMED": "1", "PROXIMO_RATE_MAX": "1"}),
    ("proximo_call", dict(_STOP, confirm=True), {"ARMED": "1", "PROXIMO_FORBID": "pve:POST /nodes"}),
    ("proximo_call", dict(_STOP, confirm=True), {"ARMED": "1", "CONSENT": "1"}),
    ("proximo_call", dict(_STOP, confirm=True), {"ARMED": "1", "TRIP": "1"}),
    ("proximo_call", {"plane": "pve", "method": "PUT", "path": "/nodes/n1/qemu/101/config",
                      "args": {"no-such-argument": "1"}, "confirm": True}, {"ARMED": "1"}),
    ("proximo_call", {"plane": "pbs", "method": "POST", "path": "/access/ticket", "confirm": True}, {"ARMED": "1"}),
    ("proximo_read", {"plane": "pve", "path": "/nodes/n1/lxc/101/probe", "params": {"probe": "disk"}}, {}),
    ("proximo_read", {"plane": "pmg", "path": "/version"}, {}),
    ("audit_entries", {"limit": 1}, {}),
    ("audit_verify", {}, {}),
]
# Keys whose values are the vendor's content (its parameters, its records), not the door's shape.
_VENDOR = frozenset({"arguments", "before", "current", "data", "params", "published_parameters"})


def needs_vocabulary() -> list[str]:
    """Every `needs` the core can put on a refusal, swept from the code (tests/test_needs_are_documented.py
    holds the docs to the same sweep): a `Refusal(...)`'s first argument, a `Verdict(...)`'s third, a
    `needs=` keyword, a `"needs":` dict key, and the opt-in lanes, which refuse under their own name."""
    from proximo.core import spine
    found = set(spine._LANES)
    for py in (ROOT / "src" / "proximo" / "core").rglob("*.py"):
        for n in ast.walk(ast.parse(py.read_text())):
            if isinstance(n, ast.Call):
                fn = getattr(n.func, "id", getattr(n.func, "attr", ""))
                pos = {"Refusal": 0, "Verdict": 2}.get(fn)
                if pos is not None and len(n.args) > pos and isinstance(n.args[pos], ast.Constant):
                    found.add(n.args[pos].value)
                found |= {k.value.value for k in n.keywords
                          if k.arg == "needs" and isinstance(k.value, ast.Constant)}
            elif isinstance(n, ast.Dict):
                found |= {v.value for k, v in zip(n.keys, n.values, strict=True)
                          if isinstance(k, ast.Constant) and k.value == "needs" and isinstance(v, ast.Constant)}
    return sorted(v for v in found if isinstance(v, str) and v)


def _shape(answer: Any, depth: int = 2) -> Any:
    """The keys of an answer two levels down (not under the vendor's own content), with the protocol
    values kept and a list of records shown by its first."""
    if not isinstance(answer, dict):
        return type(answer).__name__
    out: dict[str, Any] = {"keys": sorted(answer)}
    out |= {k: answer[k] for k in PROTOCOL if k in answer}
    for k, v in sorted(answer.items()):
        if isinstance(v, list) and v and isinstance(v[0], dict):
            out[f"{k}[]"] = sorted(v[0])
        elif isinstance(v, dict) and v and depth > 1 and k not in _VENDOR:
            out[f"{k}."] = _shape(v, depth - 1)
    return out


def _authored() -> list[str]:
    """Every authored sentence a refusal can quote (a tier's why, a held line), longest first."""
    from proximo.core import engine
    said = {s for row in engine.table().values() for s in (row.why, row.held) if s}
    return sorted(said, key=len, reverse=True)


def _words(text: str, scratch: str) -> str:
    """A refusal's words with what is not the door's taken out: an authored sentence (content, as
    a tier's why is), the scratch dir, ids, times."""
    for said in _authored():
        text = text.replace(said, "<why>")
    text = text.replace(scratch, "<scratch>")
    text = re.sub(r"\d{4}-\d\d-\d\dT[\d:.]+(?:\+00:00|Z)?", "<time>", text)
    return re.sub(r"\b[0-9a-f]{12,}\b", "<id>", text)


def _answer(server: Any, name: str, args: dict[str, Any], scratch: str) -> Any:
    from proximo.core import mcpcompat
    try:
        result = asyncio.run(server.call_tool(name, args))
    except Exception as exc:          # a refusal reaches the client as its own words
        return {"refused": _words(str(exc), scratch)}
    out = mcpcompat.in_process_result(result)
    if isinstance(out, tuple):        # 1.x: (content_blocks, structured)
        blocks, structured = out
        raw = structured if structured else json.loads(blocks[0].text)
    else:
        raw = out.get("result", out) if isinstance(out, dict) else json.loads(out[0].text)
    shape = _shape(raw)
    if isinstance(raw, dict) and isinstance(raw.get("reason"), str):   # a plan's refusal, in words
        shape["reason"] = _words(raw["reason"], scratch)
    return shape


class _Estate:
    """The synthetic box behind the one wire client: a POST answers a task id, a task's status
    says it finished, any other GET answers the rows (a list) or one record (a dict)."""
    def call(self, method: str, path: str, params: Any = None) -> Any:
        if method != "GET":
            return "UPID:n1:00000001:00000002:00000003:qmstop:101:root@pam:"
        if path.endswith("/status") and "/tasks/" in path:
            return {"status": "stopped", "exitstatus": "OK"}
        if path.endswith("/config") or path.endswith("/current"):
            return {"memory": "1024", "name": "a", "status": "running"}
        return [dict(r) for r in _ROWS]


def build() -> dict[str, Any]:
    """The contract as the door serves it now (everything but the `contract` number). The process
    environment is put back as it was found, so a suite's own pins survive the run."""
    saved = dict(os.environ)
    try:
        return _build()
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _sample_env(env: dict[str, str], scratch: str) -> dict[str, str]:
    """A sample's switches as the process environment: ARMED serves the arm source's bytes,
    CONSENT points at an empty grant directory, TRIP at a tripped file; the rest as written."""
    out = {k: v for k, v in env.items() if k.startswith("PROXIMO_")}
    if env.get("ARMED"):
        out |= {"PROXIMO_API_BASE_URL": "https://pve.example.invalid:8006/api2/json",
                "PROXIMO_TOKEN_PATH": os.path.join(scratch, "served.token"),
                "PROXIMO_ARM_SOURCE": os.path.join(scratch, "arm.token")}
    if env.get("CONSENT"):
        out["PROXIMO_CONSENT_DIR"] = os.path.join(scratch, "consent")
    if env.get("TRIP"):
        out["PROXIMO_CONTAIN_TRIP_PATH"] = os.path.join(scratch, "trip")
    return out


def _build() -> dict[str, Any]:
    for var in list(os.environ):
        if var.startswith("PROXIMO_"):
            del os.environ[var]
    scratch = tempfile.mkdtemp(prefix="door-contract-")
    base = {"PROXIMO_ENV_FILE": os.path.join(scratch, "absent.env"),
            "PROXIMO_AUDIT_LOG": os.path.join(scratch, "audit.log")}
    os.environ.update(base)
    for name in ("served.token", "arm.token"):
        path = os.path.join(scratch, name)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write("PVEAPIToken=door@pve!contract=00000000-0000-0000-0000-000000000000\n")
    os.mkdir(os.path.join(scratch, "consent"), 0o700)
    with open(os.path.join(scratch, "trip"), "w") as f:
        f.write("tripped by the door contract's sample\n")
    from proximo.core import engine, mcpcompat
    from proximo.core.doors import mcp as door

    server = door.build_server()
    tools = []
    for t in asyncio.run(server.list_tools()):
        d = t.model_dump(mode="json")
        tools.append({"name": d["name"], "description": d.get("description"),
                      "inputSchema": d.get("inputSchema") or d.get("input_schema"),
                      "readOnlyHint": mcpcompat.annotations_read_only(t.annotations)})
    real = engine._client
    # The pve wire is the synthetic estate; every other plane keeps its real client, so an
    # unconfigured one refuses as it would on a box (nothing dials: no plane has a base URL).
    engine._client = lambda product, c=None: _Estate() if product == "pve" else real(product, c)
    answers = []
    try:
        for name, args, env in SAMPLES:
            for var in [v for v in os.environ if v.startswith("PROXIMO_")]:
                del os.environ[var]
            os.environ.update(base | _sample_env(env, scratch))
            answers.append({"tool": name, "arguments": args, "env": sorted(env),
                            "answer": _answer(server, name, args, scratch)})
    finally:
        engine._client = real
    if scratch in json.dumps(answers):
        raise SystemExit(f"gen_door_contract: an answer carries the scratch path {scratch}; it is not a contract")
    return {"tools": tools, "answers": answers, "needs": needs_vocabulary()}


def render(contract: int, body: dict[str, Any]) -> str:
    head = {"contract": contract,
            "about": ("Proximo's MCP door as any client meets it: the six tools and the shapes their "
                      "answers take. Generated by scripts/gen_door_contract.py; a change raises `contract` "
                      "and the CHANGELOG says so. A release that leaves the number alone leaves the door alone.")}
    return json.dumps(head | body, indent=2, sort_keys=False) + "\n"


def committed() -> dict[str, Any] | None:
    return json.loads(OUT.read_text()) if OUT.exists() else None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--bump", action="store_true", help="the door changed on purpose: write it as contract + 1")
    a = p.parse_args(argv)
    body, old = build(), committed()
    if old is not None and {k: old[k] for k in body} == body:
        print(f"door contract {old['contract']}: unchanged")
        return 0
    if old is not None and not a.bump:
        print(f"gen_door_contract: the door no longer matches contract {old['contract']} "
              "(re-run with --bump if the change is on purpose, and add the CHANGELOG line)", file=sys.stderr)
        return 1
    n = old["contract"] + 1 if old is not None else 1
    OUT.write_text(render(n, body))
    print(f"wrote {OUT.name}: door contract {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
