"""BACKUP-FRESHNESS FENCE — "do backups actually EXIST, and are they recent enough?"

Born from a real field wound (2026-07): a nightly vzdump job reported OK for a month while
producing nothing — its scheduler had gone stale after a node rebuild, and every surface that
was consulted repeated the job's word instead of checking the shelves. The fence is the PROVE
pillar applied to backups: it walks the ACTUAL archives on storage, per guest, and compares
their age against what the enabled job schedules promise. Job/task success is never treated
as evidence; only an archive on storage counts.

Read-only (cluster/job/resource/content GETs), advisory, never overclaims — and it NEVER fails
toward "fresh": an unreadable storage yields verdict "unknown" + complete=False, a missing
archive under an enabled job is "never", and cadence parsing that falls back is disclosed as
assumed. Routed through the PROVE ledger as a read by the server layer.
"""

from __future__ import annotations

import re
import time

from .backup import backup_list
from .doctor import collect_priv_flags, holds

_FENCE_NOTE = (
    "BACKUP-FRESHNESS FENCE — read-only: walks actual backup archives per guest and compares "
    "their age against what enabled backup jobs promise. A job or task reporting OK is NOT "
    "treated as evidence that a backup exists — only an archive found on storage counts. "
    "Cadence is a conservative heuristic parsed from each job's schedule (disclosed per job); "
    "verdicts are advisory signals, verify before acting. The fenced population is only what "
    "this token can ENUMERATE (VM.Audit per guest) — PVE silently omits guests the token "
    "cannot audit, and a deeper-path ACL grant REPLACES inherited privileges, so a scoped "
    "grant can shrink the visible fleet; compare guests_visible against the fleet size you "
    "expect."
)

_VERDICTS = ("fresh", "stale", "never", "uncovered", "unknown")

# Day-of-week tokens in a PVE calendar-event schedule => the job promises AT MOST weekly.
_DAY_TOKEN_RE = re.compile(r"\b(mon|tue|wed|thu|fri|sat|sun)\b")
# "*/N:MM" — every N hours.
_EVERY_N_HOURS_RE = re.compile(r"^\*/(\d{1,2}):")
# "*:MM", "*:0/30", "*:00" — the hour field is a wildcard => runs every hour OR tighter (sub-hourly
# minute steps). Conservatively modeled as hourly (1.0h) — the tightest cadence the fence tracks.
# (2026-07-10 audit M3: these previously fell back to assumed-daily, reporting sub-daily backups fresh.)
_SUB_DAILY_RE = re.compile(r"^\*:")
# "H/step:MM" — every `step` hours (e.g. "0/4:00" = 00:00,04:00,08:00,…). The hour STEP is the cadence.
_STEP_HOURS_RE = re.compile(r"^\d{1,2}/(\d{1,2}):")
# Bare wall-clock time(s), each "H", "HH" or "H:MM" — "02:30", "21:00,03:00", "2,22:30" (live
# form found on real infra 2026-07-09: hour-only entries are valid PVE calendar events) — daily.
_DAILY_TIMES_RE = re.compile(r"^\d{1,2}(:\d{2})?(,\d{1,2}(:\d{2})?)*$")


def _cadence_hours(schedule: object) -> tuple[float, str]:
    """Conservative cadence (hours between promised runs) parsed from a PVE calendar-event
    schedule string. Conservative = never promise TIGHTER than the schedule really is, so an
    unrecognized form falls back to daily and says so — a false 'fresh' is the sin, but so is
    crying stale over a parse we don't understand."""
    s = str(schedule or "").strip().lower()
    if not s:
        return 24.0, "assumed-daily (no schedule)"
    if "hourly" in s:
        return 1.0, "hourly"
    if _SUB_DAILY_RE.match(s):
        return 1.0, "sub-daily (hourly or tighter)"
    m = _EVERY_N_HOURS_RE.match(s)
    if m and int(m.group(1)) > 0:
        return float(m.group(1)), f"every {int(m.group(1))}h"
    ms = _STEP_HOURS_RE.match(s)
    if ms and int(ms.group(1)) > 0:
        return float(ms.group(1)), f"every {int(ms.group(1))}h (step)"
    if "monthly" in s:
        return 744.0, "monthly"
    if "weekly" in s or _DAY_TOKEN_RE.search(s):
        return 168.0, "weekly (day-restricted schedule)"
    if "daily" in s or _DAILY_TIMES_RE.match(s):
        return 24.0, "daily"
    return 24.0, f"assumed-daily (unrecognized schedule {s!r})"


def _job_cadence(job: dict) -> tuple[float, str]:
    """Cadence for one job dict — calendar-event `schedule` first, legacy `dow`+`starttime` next."""
    if job.get("schedule"):
        return _cadence_hours(job["schedule"])
    dow = job.get("dow")
    if dow:
        days = {d.strip() for d in str(dow).lower().split(",") if d.strip()}
        if len(days) >= 7:
            return 24.0, "legacy-dow (all days = daily)"
        return 168.0, "legacy-dow (day-restricted = weekly)"
    return 24.0, "assumed-daily (no schedule field)"


def _job_enabled(job: dict) -> bool:
    return str(job.get("enabled", 1)).lower() not in ("0", "false")


def _covered_vmids(job: dict, guests: list[dict]) -> set[str]:
    """Which of `guests` this job's selection (vmid | all+exclude | pool) covers.
    A node-pinned job only runs on that node — guests elsewhere are NOT covered by it."""
    cand = guests
    if job.get("node"):
        cand = [g for g in cand if g["node"] == str(job["node"])]
    if job.get("vmid"):
        ids = {v.strip() for v in str(job["vmid"]).split(",") if v.strip()}
        return {g["vmid"] for g in cand if g["vmid"] in ids}
    if job.get("all"):
        excl = {v.strip() for v in str(job.get("exclude") or "").split(",") if v.strip()}
        return {g["vmid"] for g in cand if g["vmid"] not in excl}
    if job.get("pool"):
        return {g["vmid"] for g in cand if g.get("pool") == job["pool"]}
    return set()


def _parse_jobs(raw_jobs: list[dict], guests: list[dict], max_age_hours: float | None,
                grace_hours: float, flags: list[str]) -> tuple[list[dict], dict[str, list[tuple[str, float, str]]]]:
    """Job dicts -> report rows + coverage map {vmid: [(job_id, max_age, storage)]} (enabled only)."""
    job_rows: list[dict] = []
    coverage: dict[str, list[tuple[str, float, str]]] = {}
    for j in raw_jobs:
        jid = str(j.get("id") or "?")
        cadence, source = _job_cadence(j)
        max_age = float(max_age_hours) if max_age_hours is not None else cadence + grace_hours
        enabled = _job_enabled(j)
        vmids = _covered_vmids(j, guests)
        storage = str(j.get("storage") or "")
        job_rows.append({
            "id": jid, "enabled": enabled, "storage": storage,
            "schedule": j.get("schedule") or j.get("dow"),
            "cadence_hours": cadence, "cadence_source": source, "max_age_hours": max_age,
            "covered_vmids": sorted(vmids),
        })
        if enabled:
            for v in vmids:
                coverage.setdefault(v, []).append((jid, max_age, storage))
            if vmids and source.startswith("assumed-daily (unrecognized"):
                flags.append(
                    f"backup job {jid!r} has an unrecognized schedule {j.get('schedule')!r} — "
                    f"freshness for its {len(vmids)} guest(s) uses an ASSUMED daily cadence, which "
                    "may be too lenient if the real schedule is tighter; verify the schedule"
                )
        elif vmids:
            flags.append(
                f"backup job {jid!r} is DISABLED but selects {len(vmids)} guest(s) — "
                "it provides no coverage"
            )
    return job_rows, coverage


def _walk_archives(api, storages: list[str],
                   flags: list[str]) -> tuple[dict[str, dict], list[dict], list[str], bool]:
    """The EVIDENCE — actual archives on every job-referenced storage, on every node (local
    storages hold different archives per node; shared entries dedupe by volid).
    Returns ({vmid: newest {volid, storage, ctime}}, [unreadable {node, storage, error}],
    nodes_walked, node_sight_ok). node_sight_ok is False when the node list could not be trusted
    (read failed, OR a 200 + empty response — a token without the privilege to list cluster nodes
    gets that, and the walk then silently collapses to one node; 2026-07-10 audit M6)."""
    node_sight_ok = True
    try:
        nodes = [str(n.get("node")) for n in api._get("/cluster/resources?type=node") or []]
        if not nodes:
            node_sight_ok = False
            flags.append(
                "node enumeration returned no nodes (200 + empty) — the token likely lacks the "
                "privilege to list cluster nodes; the archive walk is limited to the configured "
                f"node {getattr(api.config, 'node', None)!r}, so guests on OTHER nodes may falsely "
                "read never/stale. Verdicts are advisory only (complete=False)."
            )
    except Exception as e:
        node_sight_ok = False
        nodes = []
        flags.append(
            f"node list unreadable ({type(e).__name__}) — archive walk limited to the "
            f"configured node {getattr(api.config, 'node', None)!r}"
        )
    if not nodes:
        nodes = [str(getattr(api.config, "node", "") or "")]

    newest: dict[str, dict] = {}
    unreadable: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for storage in storages:
        for node in nodes:
            try:
                entries = backup_list(api, storage, node)
            except Exception as e:
                unreadable.append({"node": node, "storage": storage, "error": type(e).__name__})
                continue
            for ent in entries:
                volid = str(ent.get("volid") or "")
                if (storage, volid) in seen:
                    continue
                seen.add((storage, volid))
                vmid, ctime = str(ent.get("vmid")), ent.get("ctime")
                if not isinstance(ctime, (int, float)):
                    continue
                cur = newest.get(vmid)
                if cur is None or ctime > cur["ctime"]:
                    newest[vmid] = {"volid": volid, "storage": storage, "ctime": ctime}
    if unreadable:
        pairs = ", ".join(f"{u['storage']} on {u['node']}" for u in unreadable)
        flags.append(
            f"{len(unreadable)} storage read(s) failed ({pairs}) — freshness for guests "
            "relying on them is UNKNOWN, not fresh"
        )
    return newest, unreadable, nodes, node_sight_ok


def _sight_privs(api, flags: list[str]) -> dict[str, dict[str, bool]] | None:
    """The token's {priv: [paths]} map, or None when unreadable (flagged — unprovable sight).

    Why this exists (live-found 2026-07-09): PVE filters backup volumes OUT of the content
    listing per-volume — seeing one requires Datastore.AllocateSpace on the storage plus
    VM.Backup on the owner guest (or Datastore.Allocate on the storage as bypass) — and a
    token without them gets 200 + [] on a storage full of archives. A PVEAuditor token walked
    a healthy PBS storage and read 25 guests as "never backed up". Absence verdicts are only
    trustworthy when the token could have SEEN an archive if one existed."""
    try:
        return collect_priv_flags(api.access_permissions())
    except Exception as e:
        flags.append(
            f"token permission map unreadable ({type(e).__name__}) — cannot prove the token "
            "can SEE backup archives; absence-of-archive verdicts are UNKNOWN, not never/stale"
        )
        return None


def _sighted(privs: dict[str, dict[str, bool]] | None, storage: str, vmid: str) -> bool:
    """Can this token see backup volumes for `vmid` on `storage`? (PVE check_volume_access)"""
    spath = f"/storage/{storage}"
    if holds(privs, "Datastore.Allocate", spath):
        return True
    return (holds(privs, "Datastore.AllocateSpace", spath)
            and holds(privs, "VM.Backup", f"/vms/{vmid}"))


def _coverage_verdict(g: dict, cov: list, pve_uncovered: set[str] | None,
                      flags: list[str]) -> str | None:
    """The coverage half of the verdict: "uncovered" (with disagreement honesty vs PVE's own
    not-backed-up read), or None when covered — freshness evidence decides the rest."""
    if pve_uncovered is not None and g["vmid"] in pve_uncovered:
        if cov:
            flags.append(
                f"guest {g['vmid']} ({g['name']}): PVE's not-backed-up cross-check disagrees "
                "with the job parse — treating PVE as authoritative (uncovered)"
            )
        else:
            flags.append(f"guest {g['vmid']} ({g['name']}) has no enabled backup job covering it")
        return "uncovered"
    if not cov:
        flags.append(f"guest {g['vmid']} ({g['name']}) has no enabled backup job covering it")
        if pve_uncovered is not None:
            flags.append(
                f"guest {g['vmid']} ({g['name']}): job parse found no coverage but PVE does "
                "not list it as unprotected — a selection form may be unparsed; verify"
            )
        return "uncovered"
    return None


def _evidence_verdict(g: dict, cov: list, nb: dict | None, expected: float | None,
                      unreadable_storages: set[str], blind: bool, flags: list[str],
                      blind_unknowns: list[str]) -> str:
    """The evidence half of the verdict for a COVERED guest — never failing toward fresh.
    `expected` is non-None whenever cov is non-empty (min over covering jobs).

    `blind` = the token's sight over at least one covering storage is unproven. An archive we
    DID see is real evidence (fresh stands), but every absence-based verdict — "never", and
    "stale" (which asserts no NEWER archive exists) — degrades to "unknown" when blind: PVE
    hides backup volumes from an under-privileged token with a 200 + [], not an error."""
    covered_by = sorted({jid for jid, _, _ in cov})
    cov_storages = {st for _, _, st in cov}
    if nb is None:
        if cov_storages & unreadable_storages:
            return "unknown"
        if blind:
            blind_unknowns.append(g["vmid"])
            return "unknown"
        flags.append(
            f"guest {g['vmid']} ({g['name']}) has NEVER been backed up — enabled job(s) "
            f"{covered_by} cover it, but no archive exists on {sorted(cov_storages)}; "
            "the schedule's word is not an archive"
        )
        return "never"
    if expected is not None and nb["age_hours"] > expected:
        if cov_storages & unreadable_storages:
            # A newer archive may live on the covering storage we could not read — 'stale' would
            # assert no newer archive exists, which we cannot prove (2026-07-10 audit L13).
            return "unknown"
        if blind:
            blind_unknowns.append(g["vmid"])
            return "unknown"
        flags.append(
            f"guest {g['vmid']} ({g['name']}) is STALE — newest archive is "
            f"{nb['age_hours']}h old, expected <= {expected}h from job(s) {covered_by}"
        )
        return "stale"
    return "fresh"


def backup_freshness(api, max_age_hours: float | None = None, grace_hours: float = 6.0) -> dict:
    """Walk actual backup archives per guest; verdict each guest fresh/stale/never/uncovered/
    unknown against the promises of enabled backup jobs. `max_age_hours` overrides the
    schedule-derived expectation for every job; `grace_hours` pads each derived cadence."""
    now = time.time()
    flags: list[str] = []
    complete = True
    report: dict = {
        "note": _FENCE_NOTE,
        "expectation": {"grace_hours": grace_hours, "override_max_age_hours": max_age_hours},
    }

    # 1) Guests — the population the fence protects (templates are not backup targets).
    try:
        raw_guests = api._get("/cluster/resources?type=vm") or []
    except Exception as e:
        report.update(jobs=[], guests=[], guests_visible=0, unreadable=[], flags=[
            f"guest list unreadable ({type(e).__name__}) — the fence cannot run; nothing was verified"
        ], counts=dict.fromkeys(_VERDICTS, 0), complete=False)
        return report
    guests = [
        {"vmid": str(g.get("vmid")), "name": g.get("name"), "type": g.get("type"),
         "node": str(g.get("node") or ""), "pool": g.get("pool")}
        for g in raw_guests if not g.get("template")
    ]
    report["guests_visible"] = len(guests)

    # 2) Jobs — what is PROMISED. Disabled jobs promise nothing.
    jobs_ok = True
    try:
        raw_jobs = api._get("/cluster/backup") or []
    except Exception as e:
        raw_jobs, jobs_ok, complete = [], False, False
        flags.append(
            f"backup job list unreadable ({type(e).__name__}) — coverage and freshness "
            "expectations unavailable; every guest is UNKNOWN, not fresh"
        )
    job_rows, coverage = _parse_jobs(raw_jobs, guests, max_age_hours, grace_hours, flags)
    report["jobs"] = job_rows

    # 3) PVE's own coverage read — a cross-check on our selection parse, not a replacement.
    pve_uncovered: set[str] | None = None
    if jobs_ok:
        try:
            pve_uncovered = {
                str(g.get("vmid"))
                for g in (api._get("/cluster/backup-info/not-backed-up") or [])
            }
        except Exception as e:
            flags.append(
                f"PVE not-backed-up cross-check unavailable ({type(e).__name__}) — coverage "
                "verdicts rely on Proximo's own job parse alone"
            )

    # 4) The evidence walk — plus proof the token could even SEE the evidence.
    storages = sorted({r["storage"] for r in job_rows if r["storage"]})
    newest, unreadable, nodes_walked, node_sight_ok = _walk_archives(api, storages, flags)
    report["unreadable"] = unreadable
    report["nodes_walked"] = nodes_walked
    unreadable_storages = {u["storage"] for u in unreadable}
    if unreadable:
        complete = False
    if not node_sight_ok:
        complete = False
    privs = _sight_privs(api, flags)

    # 5) Verdicts — evidence vs promise, never failing toward fresh.
    guest_rows: list[dict] = []
    counts: dict[str, int] = dict.fromkeys(_VERDICTS, 0)
    blind_unknowns: list[str] = []
    for g in guests:
        cov = coverage.get(g["vmid"], [])
        expected = min((ma for _, ma, _ in cov), default=None)
        nb_raw = newest.get(g["vmid"])
        nb = None
        if nb_raw is not None:
            nb = {**nb_raw, "age_hours": round((now - nb_raw["ctime"]) / 3600, 2)}

        if not jobs_ok:
            verdict = "unknown"
        else:
            blind = any(not _sighted(privs, st, g["vmid"]) for _, _, st in cov)
            verdict = _coverage_verdict(g, cov, pve_uncovered, flags) or _evidence_verdict(
                g, cov, nb, expected, unreadable_storages, blind, flags, blind_unknowns)

        counts[verdict] += 1
        guest_rows.append({
            "vmid": g["vmid"], "name": g["name"], "type": g["type"], "node": g["node"],
            "verdict": verdict, "covered_by": sorted({jid for jid, _, _ in cov}),
            "expected_max_age_hours": expected, "newest_backup": nb,
        })

    if blind_unknowns:
        complete = False
        flags.append(
            f"{len(blind_unknowns)} guest(s) ({', '.join(blind_unknowns[:8])}"
            f"{', …' if len(blind_unknowns) > 8 else ''}) have no VISIBLE archive, but this "
            "token cannot see backup volumes — PVE's content listing hides them (200 + empty) "
            "unless the token holds Datastore.AllocateSpace on the storage AND VM.Backup on "
            "the guest (or Datastore.Allocate on the storage). Verdicts are UNKNOWN — the "
            "archives may exist. Re-run with a sighted token (e.g. PVEDatastoreUser on the "
            "storage + VM.Backup on the guests) to get real never/stale verdicts."
        )

    report["guests"] = guest_rows
    report["counts"] = counts
    report["flags"] = flags
    report["complete"] = complete
    return report
