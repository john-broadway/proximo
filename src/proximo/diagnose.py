"""DIAGNOSE pillar — read-first "what's broken" evidence gathering.

The mirror of PLAN: this pillar changes NOTHING. It runs a FIXED, curated, read-only command
battery (no arbitrary caller input -> no injection surface) plus a few structured API reads, and
aggregates them into an evidence report with *advisory* flags. Flags are signals, not a root-cause
diagnosis — surfaced, never "the cause is X" (the same do-not-overclaim posture as PLAN/PROVE).
"""

from __future__ import annotations

import math

from proximo.projection import classify_task_outcome

_DIAG_NOTE = (
    "DIAGNOSE gathers read-only evidence; flags are advisory signals (some heuristic), NOT a "
    "root-cause diagnosis. Verify before acting."
)

# Fixed read-only in-container probes (argv only — no caller input ever reaches these).
_CONTAINER_PROBES: list[tuple[str, list[str]]] = [
    ("failed_units", ["systemctl", "--failed", "--no-legend", "--no-pager"]),
    ("disk", ["df", "-h"]),
    ("recent_errors", ["journalctl", "-p", "err", "-n", "40", "--no-pager"]),
    ("memory", ["free", "-m"]),
    ("listening", ["ss", "-tlnp"]),
]

_GUEST_FIELDS = ("status", "name", "cpu", "mem", "maxmem", "disk", "maxdisk", "uptime")


def _frac(used, total) -> float | None:
    try:
        if total:
            f = float(used or 0) / float(total)
            return f if math.isfinite(f) else None  # guard inf/nan -> no crash in round()
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    return None


def diagnose_container(api, exec_, ctid: str, kind: str = "lxc", node: str | None = None) -> dict:
    """Read-only diagnosis of one container. API guest status always; the in-container battery only
    if exec_ is provided (else partial mode is disclosed, not silently empty)."""
    report: dict = {"ctid": str(ctid), "kind": kind, "note": _DIAG_NOTE}
    flags: list[str] = []

    try:
        gs = api.guest_status(ctid, kind, node)
        guest = {k: gs[k] for k in _GUEST_FIELDS if k in gs}
        report["guest"] = guest
        status = guest.get("status")
        if status and status != "running":
            flags.append(f"guest is {status} (not running)")
        df = _frac(guest.get("disk"), guest.get("maxdisk"))
        if df is not None and df > 0.9:
            flags.append(f"root disk at {round(100 * df)}% (API)")
    except Exception as e:  # never abort the whole diagnosis on one read
        report["guest"] = {"error": type(e).__name__}
        flags.append("guest status read failed — diagnosis incomplete")

    if exec_ is None:
        report["probes_skipped"] = "in-container probes skipped (exec disabled or CTID not permitted)"
        # An empty flags list must never read as "healthy" when the battery never ran.
        flags.append("in-container probes skipped — incomplete diagnosis (exec disabled or CTID not permitted)")
    else:
        probes: dict = {}
        for key, argv in _CONTAINER_PROBES:
            try:
                r = exec_.run(ctid, argv)
                probes[key] = {"returncode": r.returncode, "output": r.stdout or r.stderr}
            except Exception as e:  # a missing tool / failing probe is recorded, not fatal
                probes[key] = {"error": type(e).__name__}
        report["probes"] = probes
        fu = probes.get("failed_units", {})
        out = (fu.get("output") or "")
        # `systemctl --failed --no-legend` prints nothing on a clean system, so non-empty output is
        # the signal (no "0 loaded units" footer exists with --no-legend).
        if fu.get("returncode") == 0 and out.strip():
            flags.append("systemd reports failed unit(s) — see probes.failed_units (advisory)")
        if any("error" in p for p in probes.values()):
            flags.append("one or more in-container probes failed — diagnosis may be incomplete")

    report["flags"] = flags
    return report


def diagnose_node(api, node: str | None = None) -> dict:
    """Read-only diagnosis of a node (API-only): status + storage usage + recent failed tasks."""
    report: dict = {"node": node, "note": _DIAG_NOTE}
    flags: list[str] = []

    try:
        st = api.node_status(node)
        report["status"] = {k: st[k] for k in ("uptime", "cpu", "loadavg", "memory") if k in st}
        mem = st.get("memory")
        if isinstance(mem, dict):
            mf = _frac(mem.get("used"), mem.get("total"))
            if mf is not None and mf > 0.9:
                flags.append(f"node memory at {round(100 * mf)}%")
    except Exception as e:
        report["status"] = {"error": type(e).__name__}

    try:
        storages = api.node_storage(node) or []
        report["storage"] = storages
        for s in storages:
            name = s.get("storage", "?")
            if s.get("active") == 0:
                # Offline storage: cached used/total are stale — report the offline signal, not "full".
                flags.append(f"storage {name} is inactive (offline) — usage not evaluated")
                continue
            uf = s.get("used_fraction")
            if uf is None:
                uf = _frac(s.get("used"), s.get("total"))
            if uf is not None and math.isfinite(uf) and uf > 0.9:
                flags.append(f"storage {name} at {round(100 * uf)}%")
    except Exception as e:
        report["storage"] = {"error": type(e).__name__}

    try:
        tasks = api.node_tasks(node) or []
        # One classifier repo-wide (projection.classify_task_outcome): only genuine non-OK
        # exits are "failed" — unfinished/transient rows class "running", warnings and
        # statusless-finished rows have their own classes, never "failed".
        failed = [t for t in tasks if classify_task_outcome(t) == "failed"]
        report["failed_tasks"] = failed
        if failed:
            flags.append(f"{len(failed)} recent failed task(s)")
    except Exception as e:
        report["failed_tasks"] = {"error": type(e).__name__}

    # An all-errored (or partly-errored) diagnosis must surface in flags — empty flags would read
    # as a clean bill of health when reads actually failed.
    for section in ("status", "storage", "failed_tasks"):
        val = report.get(section)
        if isinstance(val, dict) and "error" in val:
            flags.append(f"node {section} read failed — diagnosis incomplete")

    report["flags"] = flags
    return report
