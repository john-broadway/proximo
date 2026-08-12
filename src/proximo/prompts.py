"""Safe-runbook MCP prompts — user-invoked front doors for common Proxmox
operations. Each prompt returns a plain-language runbook that steers the agent
down Proximo's guarded path: check capacity, PLAN before you mutate, verify
after, and keep the receipts. Prompts are templates, not tool-callers — they add
no new authority; they lower the "where do I start" barrier and point at the safe
sequence the trust spine already enforces.

Registered on the shared FastMCP instance the same way the tool wrappers are
(import proximo.server, decorate on its `mcp`); server.py imports this module at
the bottom for the registration side effect.
"""

from __future__ import annotations

import proximo.server as _proximo_server

mcp = _proximo_server.mcp


@mcp.prompt()
def safe_migration(guest: str, target_node: str) -> str:
    """Runbook: migrate a guest to another node safely (plan-first, verify-after)."""
    return (
        f"Migrate guest {guest} to node {target_node} safely, following Proximo's "
        f"guarded path. Do not skip steps.\n\n"
        f"1. Check the destination has room: call `pve_cluster_resources` and confirm "
        f"{target_node} has free CPU, memory, and storage for {guest}.\n"
        f"2. Plan before you move: call `pve_guest_migrate` for {guest} -> {target_node} "
        f"in its default dry-run/plan mode. Read the returned plan and blast radius; do "
        f"not proceed if it reports anything unexpected.\n"
        f"3. Execute the migration only after the plan looks right.\n"
        f"4. Verify: call `pve_guest_status` for {guest} and confirm it is running on "
        f"{target_node}.\n\n"
        f"Report the plan, the result, and the final status. If any step fails, stop and "
        f"surface it rather than forcing the move."
    )


@mcp.prompt()
def diagnose_cluster(node: str = "") -> str:
    """Runbook: read-only health sweep of the cluster (DIAGNOSE, no changes)."""
    scope = f" Focus on node {node}." if node.strip() else ""
    return (
        f"Run a read-only health sweep of the Proxmox cluster.{scope} This is DIAGNOSE "
        f"only — do not change anything.\n\n"
        f"Use only read-only tools, in this order:\n"
        f"1. `pve_cluster_status` — overall cluster and quorum health.\n"
        f"2. `pve_doctor` — surfaced problems and misconfigurations.\n"
        f"3. `pve_list_guests` — inventory and per-guest run state.\n"
        f"4. `pve_tasks_list(errors=True)` — failed/warning tasks from PVE's own history "
        f"filter (the bare call only windows the newest 50).\n\n"
        f"Summarize what's healthy and what needs attention. Do not run any tool that "
        f"mutates state; if a fix is needed, propose it for the operator to approve "
        f"separately."
    )


@mcp.prompt()
def provision_container(node: str, hostname: str) -> str:
    """Runbook: provision a new LXC within policy (plan-first, verify-after)."""
    return (
        f"Provision a new LXC container named {hostname} on node {node}, following "
        f"Proximo's guarded path.\n\n"
        f"1. Check capacity: call `pve_cluster_resources` and confirm {node} has free "
        f"resources for the container.\n"
        f"2. Plan before you create: call `pve_create_container` for {hostname} on {node} "
        f"in its default dry-run/plan mode. Review the plan.\n"
        f"3. Create it only after the plan looks right.\n"
        f"4. Verify: call `pve_guest_status` for the new container and confirm it exists "
        f"(and is running if you started it).\n\n"
        f"Keep it within policy — stop and ask if anything looks off rather than forcing "
        f"the create."
    )


@mcp.prompt()
def safe_backup(guest: str) -> str:
    """Runbook: back up a guest and verify the backup actually landed."""
    return (
        f"Back up guest {guest} and verify the result.\n\n"
        f"1. Plan the backup: call `pve_backup` for {guest} in its default dry-run/plan "
        f"mode; review the target storage and mode.\n"
        f"2. Run the backup after the plan looks right.\n"
        f"3. Verify: call `pve_backup_list` and confirm a fresh backup for {guest} exists "
        f"with the expected timestamp.\n\n"
        f"Report the backup's storage, size, and timestamp. If verification does not show "
        f"the new backup, treat it as unconfirmed and surface it."
    )


@mcp.prompt()
def review_receipts() -> str:
    """Runbook: verify Proximo's PROVE ledger integrity (the receipts)."""
    return (
        "Verify Proximo's PROVE receipts — the tamper-evident audit ledger.\n\n"
        "1. Call `audit_verify` to check the hash-chained ledger. It reports whether the "
        "chain is intact, how many entries it holds, and the current head hash.\n"
        "2. If it does NOT verify, STOP and report a possible tampering or anchor problem — "
        "treat recent activity as suspect until the chain is explained.\n"
        "3. If it verifies, report the entry count and head as confirmation the record is intact.\n\n"
        "Note: Proximo exposes integrity *verification* as a tool, not entry dumping — the "
        "ledger's individual records are read off-box (at its configured path), and that "
        "separation is part of what makes the receipts trustworthy. Do not fabricate an "
        "activity summary from the verification result alone; to read the actions themselves, "
        "inspect the ledger off-box."
    )
