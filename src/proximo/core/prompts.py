"""The five runbooks, as MCP prompts over the six core tools (capability `runbook-prompts`).

A runbook is plain text that puts a small model on the guarded path for a common job. It adds no
authority: every step it names runs through the same `govern` and `execute` as a step the model
invented. Each speaks only the six tools and the core's rules: an address not in hand is found
(`proximo_find`), never guessed; a change is planned (`proximo_plan`) before it is called; a
`proximo_call` without `confirm` returns the plan and mutates nothing; the receipts are read with
`audit_verify` pinned to a head.

A runbook says only what the tools do. A lean read drops every number, so a step that reads memory,
size or time says `fields="all"`; a template path is replaced with the row's values before it is
planned; a call waits on the vendor's task for `wait` seconds (600 at most) and says `timed_out`
when the task outlasts it; a ledger row carries its time, action, target, outcome and who asked,
and not the plan. Every `METHOD /path` a runbook names is a published address of the table and
every argument name it quotes is a published parameter of that address: `tests/test_core_prompts.py`
resolves each one against the table and the door's own tool list, and bounds each prompt's size
(the 4K window), so a runbook cannot go stale silently. Stdlib only: the SDK is touched in
`register` alone, which `doors/mcp.build_server` calls, so every door serves the same five.
"""
from __future__ import annotations

import re
from collections.abc import Callable

PLANE = "pve"
_P = "proximo_plan pve"
_R = "proximo_read pve GET"
_APPROVE = ("Show the plan (verdict, tier, current, change) to the operator and wait. Call with "
            "confirm=true ONLY after they approve; if anything reads unexpected, stop. ")
_WAIT = ("proximo_call, same address and args, confirm=true, wait=600 (without confirm it only "
         "returns the plan). If task.timed_out is true the task still runs: poll proximo_read pve "
         "GET /nodes/{node}/tasks/{upid}/status with wait=600 until it finishes, before step 4.")
_FIND = "Unsure of an address? proximo_find first; never guess a path."
_END = "A failed step is reported, never forced."

_VMID = re.compile(r"[0-9]{3,9}")                       # PVE allows 100 to 999999999
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}")   # a node name or a DNS-label hostname
_HEAD = re.compile(r"[0-9a-f]{64}")


def _arg(value: str, shape: re.Pattern[str], name: str, what: str) -> str:
    """An argument is spliced into text a model obeys, so anything but the exact shape is refused:
    a quote rewrites the args JSON, a newline adds a step, a long value blows the size bound."""
    if not isinstance(value, str) or not shape.fullmatch(value) or (name == "guest" and int(value) < 100):
        raise ValueError(f"{name} must be {what}; refusing to build a runbook from it")
    return value


def _guest(v: str) -> str:
    return _arg(v, _VMID, "guest", "a vmid, digits only, 100 to 999999999")


def _node(v: str, name: str = "node") -> str:
    return _arg(v, _HOST, name, "a name of letters, digits, dots and dashes, at most 63 characters")


def safe_migration(guest: str, target_node: str) -> str:
    """Runbook: migrate a guest (by vmid) to another node safely (look, plan, call, verify)."""
    guest, target_node = _guest(guest), _node(target_node, "target_node")
    return (
        f"Migrate guest {guest} (a vmid) to node {target_node}. {_FIND}\n\n"
        f"1. Look: {_R} /cluster/resources with params {{\"type\": \"vm\"}} and fields=\"all\" (a "
        f"lean read drops the numbers): vmid {guest}'s node, type (qemu or lxc), maxmem; confirm "
        f"{target_node} has free memory. Then {_R} /nodes/{{node}}/qemu/{{vmid}}/config (or "
        f"{_R} /nodes/{{node}}/lxc/{{vmid}}/config) for the disks' storage. Replace {{node}}, "
        f"{{vmid}} below.\n"
        f"2. Plan, args {{\"target\": \"{target_node}\"}} plus: for a VM, {_P} POST "
        f"/nodes/{{node}}/qemu/{{vmid}}/migrate with \"online\": true if running, "
        f"\"with-local-disks\": true and \"targetstorage\" if disks are local. For a container, "
        f"{_P} POST /nodes/{{node}}/lxc/{{vmid}}/migrate with \"restart\": true if running, "
        f"\"target-storage\" if disks are local. The plan lists the names it accepts.\n"
        f"3. {_APPROVE}{_WAIT}\n"
        f"4. Verify: {_R} /nodes/{target_node}/qemu/{{vmid}}/status/current (or the lxc twin): "
        f"the status on {target_node}.\n\n"
        f"Report the plan, the task's end, the status. {_END}"
    )


def diagnose_cluster(node: str = "") -> str:
    """Runbook: read-only health sweep of the cluster (DIAGNOSE, no changes)."""
    node = node.strip()
    scope = f" Focus on node {_node(node)}." if node else ""
    return (
        f"Run a read-only health sweep of the Proxmox cluster.{scope} Reads only: proximo_read; "
        f"proximo_call is not used. {_FIND}\n\n"
        f"1. {_R} /cluster/status: quorum and each node's online state. Those names are {{node}} "
        f"below.\n"
        f"2. {_R} /nodes/{{node}} with diagnose=true, per node in scope: status, storage, the "
        f"failed tasks among the last 50, and advisory flags (memory or storage over 90%, inactive "
        f"storage).\n"
        f"3. {_R} /cluster/resources: every guest's run state.\n"
        f"4. {_R} /nodes/{{node}}/tasks with params {{\"errors\": true, \"limit\": 50}}: the tasks "
        f"the vendor marked as errors.\n\n"
        f"Say what is healthy and what needs attention. Propose any fix for the operator to approve "
        f"separately; do not run it here."
    )


def provision_container(node: str, hostname: str) -> str:
    """Runbook: provision a new LXC within policy (look, plan, call, verify)."""
    node, hostname = _node(node), _node(hostname, "hostname")
    return (
        f"Provision LXC {hostname} on node {node}. {_FIND}\n\n"
        f"1. Look: {_R} /cluster/resources with fields=\"all\" (a lean read drops the numbers); "
        f"confirm {node} has free memory. {_R} /cluster/nextid for a free vmid. "
        f"{_R} /nodes/{node}/storage with params {{\"content\": \"vztmpl\"}} for a template "
        f"storage, then {_R} /nodes/{node}/storage/{{storage}}/content with the same params for "
        f"the template's volid. Replace {{storage}} with it.\n"
        f"2. Plan: {_P} POST /nodes/{node}/lxc with args \"vmid\", \"hostname\" \"{hostname}\", "
        f"\"ostemplate\" (the volid), \"storage\", \"memory\", \"cores\", \"rootfs\", \"net0\", "
        f"\"unprivileged\" true. The plan lists the names it accepts, and says if the "
        f"vmid exists.\n"
        f"3. {_APPROVE}{_WAIT}\n"
        f"4. Verify: {_R} /nodes/{node}/lxc/{{vmid}}/status/current and confirm it exists.\n\n"
        f"{_END}"
    )


def safe_backup(guest: str) -> str:
    """Runbook: back up a guest (by vmid) and verify the backup landed."""
    guest = _guest(guest)
    return (
        f"Back up guest {guest} (a vmid) and verify it. {_FIND}\n\n"
        f"1. Look: {_R} /cluster/resources with fields=\"all\" (a lean read drops the numbers) "
        f"for vmid {guest} and its node; {_R} /nodes/{{node}}/storage with params "
        f"{{\"content\": \"backup\"}} for a backup storage. Replace {{node}} and {{storage}} below "
        f"with those names.\n"
        f"2. Plan: {_P} POST /nodes/{{node}}/vzdump with args {{\"vmid\": \"{guest}\", "
        f"\"storage\": \"{{storage}}\", \"mode\": \"snapshot\"}}. Check storage and mode against "
        f"the plan's published_parameters.\n"
        f"3. {_APPROVE}{_WAIT}\n"
        f"4. Verify: {_R} /nodes/{{node}}/storage/{{storage}}/content with params "
        f"{{\"content\": \"backup\", \"vmid\": {guest}}} and fields=\"all\"; confirm a volume for "
        f"{guest} with ctime newer than the call.\n\n"
        f"Report storage, size and ctime; no new volume listed means unconfirmed. {_END}"
    )


def review_receipts(expected_head: str = "") -> str:
    """Runbook: verify the PROVE ledger against a head you hold, and read what it holds."""
    head = expected_head.strip()
    if head and not _HEAD.fullmatch(head):
        raise ValueError("expected_head must be empty or 64 lowercase hex characters; "
                         "refusing to build a runbook from it")
    pin = (f"audit_verify with expected_head={head}: a pinned head catches a cut tail."
           if head else
           "audit_verify with no expected_head: the chain is checked but the tail is unproven "
           "(tail_verified false). Say so; ask for a head recorded earlier.")
    return (
        "Review Proximo's PROVE receipts, the tamper-evident ledger.\n\n"
        f"1. {pin} It reports ok, entries, head and tail_verified. If ok is false, STOP and report "
        "possible tampering; treat recent activity as suspect.\n"
        "2. audit_entries with mutations_only=true and a limit: the newest mutations, executed "
        "and refused, each with ts, action, target, outcome and principal (who asked). A row does "
        "not carry the plan, the pillars or the undo id; do not report those. It says when it "
        "truncated.\n"
        "3. Report the chain's state, the head and the mutations by outcome. Say what the rows say, "
        "never more: a row records a call, not the estate after it."
    )


RUNBOOKS: tuple[Callable[..., str], ...] = (
    safe_migration, diagnose_cluster, provision_container, safe_backup, review_receipts)


def register(server: object) -> None:
    """Register the five on an MCP server instance (the SDK's `prompt` decorator, both majors)."""
    for fn in RUNBOOKS:
        server.prompt()(fn)  # type: ignore[attr-defined]
