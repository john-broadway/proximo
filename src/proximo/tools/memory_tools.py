"""Tier-1 estate memory tools (see proximo/memory.py for the rails).

Split module in the tools/ wrapper pattern — logic lives in proximo.memory; this is the
governed doorway. proximo_recall is classified ADVERSARIAL in taint.py: recalled names/tags
originate from adversarial-classified reads and must re-enter the taint model, not launder
through storage.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.memory import baseline_state, recall_state
from proximo.server import _audited, tool


@tool()
def proximo_recall(
    since: Annotated[str | None, Field(description="Optional change window: ISO8601 (`2026-07-29T00:00:00`) or relative (`24h`, `7d`). Adds appeared / status_changed / not_seen_since diffs.")] = None,
    detail: Annotated[str, Field(description="Row depth: `summary` (counts only), `lean` (default: identity + status), `full` (timestamps, prev_status).")] = "lean",
    journal: Annotated[int, Field(description="Include the newest N diagnosis-journal entries (pve_diagnose / ct_diagnose / pve_doctor digests over time). 0 (default) omits the journal; `since` also windows it.")] = 0,
    query: Annotated[str | None, Field(description="Optional filter, e.g. a guest name like 'gitea': rows narrow to the closest matches, counts still cover the whole estate. Always available; no configuration needed. Omit it to list every entity.")] = None,
) -> dict:
    """READ-ONLY: the estate map from local Tier-1 memory — NOT a live PVE read. Returns
    total/by_kind/by_status/guest_summary counts (trust guest_summary for guest-count questions;
    all counting is server-side) plus lean entity rows, stamped {source:'memory', as_of,
    age_seconds}: the data is as old as the stamp says. With `since`, also diffs: appeared,
    status_changed, and not_seen_since (last observed before the window — a fact, not a claim
    the entity is gone). journal=N adds the newest N diagnosis digests ("when did this last
    happen") — findings summaries only, never raw diagnostic output. Memory is on by default
    (PROXIMO_MEMORY=0 opts out), fed opportunistically by list reads and diagnose/doctor runs,
    derived and rebuildable. For live state use pve_list_guests / pve_cluster_resources."""
    # No _svc() here: recall is local (SQLite beside the audit log) and _svc is PVE-strict,
    # so demanding it made a PBS-only box die with a PVE-shaped env error. _audited stands
    # up the ledger itself via _ledger(), which tolerates a PVE-less box.
    return _audited("proximo_recall", "memory",
                    lambda: recall_state(since, detail, journal, query=query))


@tool()
def proximo_baseline(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to use the configured default node.")] = None,
    timeframe: Annotated[str, Field(description="Rolling RRD window the baseline covers, ENDING NOW: `hour`, `day`, `week` (default), `month`, or `year`. `day` is the last ~24 hours, NOT the calendar day; a specific date is not available.")] = "week",
    refresh: Annotated[bool, Field(description="Set `true` to pull fresh rrddata and recompute; default serves the stored rollup when one exists.")] = False,
) -> dict:
    """READ-ONLY: what "normal" looks like for one guest — cpu/mem distribution rollups
    (n/mean/p50/p95/max) from PVE rrddata, stored in local Tier-1 memory. PVE-guest-only: on a
    PBS/PMG/PDM-only deployment this tool has nothing to report (a stored rollup, if one exists,
    still answers with no PVE call; the live pull needs a configured PVE plane). With a stored
    rollup it answers from memory, age-stamped, with NO PVE call and `current: null` (never a
    fabricated reading); when missing or refresh=true it pulls rrddata, stores the rollup, and
    positions the newest sample against it. The assessment is an advisory heuristic from
    history — not an alarm, not a health verdict. On by default (PROXIMO_MEMORY=0 opts out).
    For live point-in-time state use pve_guest_status; for raw series use pve_node_rrddata
    (node-level)."""
    # api resolves LAZILY, at the moment rrddata is actually needed: the stored path
    # promises "NO PVE call", and an eager _svc() here made it demand PVE env anyway,
    # blocking the memory-only answer on a PVE-less box (2nd-lens find, 2026-07-30).
    return _audited("proximo_baseline", f"{kind}/{vmid}",
                    lambda: baseline_state(lambda: _proximo_server._svc()[1],
                                           vmid, kind, node, timeframe, refresh))
