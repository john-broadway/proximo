"""The reach grant, made observable — brick 1 of the grant model.

The CT/agent allowlists are Proximo's *reach grant*: the standing perimeter every PLAN, CONSENT
and PROVE runs inside, and the perimeter for the one channel the platform's own ACL model cannot
scope (``ssh -> pct exec`` answers to no PVE privilege). Widening it is the most consequential
change in the system — and until this module, the only one the PROVE ledger never saw: the
grant lives in env/registry config, so it could grow from 3 guests to ``*`` between two restarts
with no durable trace.

This module closes the between-restarts case: at serve time (every door — stdio, HTTP, A2A,
MCP-HTTP; never the read-only CLI verbs) the RESOLVED grant is snapshotted across the env lane
and every pve target in the registry, compared against a sidecar state file beside the ledger,
and any delta is recorded as a ``reach_grant`` PROVE entry naming exactly what was added and
removed, per lane, per source — the entry lands BEFORE the sidecar moves, so a crash between
the two re-records on the next start instead of swallowing the delta. An unchanged restart
records nothing — the ledger stays signal, not heartbeat.

HONEST LIMIT — the mid-run registry edit: the check runs at serve START. The targets registry
file is re-read on mtime change while the server runs, so an edit there changes real exec reach
immediately and is only witnessed at the NEXT serve start; reverted before that restart, it
leaves no trace here. (The env lane has no such window — a process env cannot change from
outside.) Closing that window means checking at backend-build time; deliberately not in brick 1.

Failure honesty (the checker must not fail open into a plausible answer):
- a MISSING sidecar with prior ``reach_grant`` history in the chain records ``state_missing``
  (with the last recorded digest) — never a silent "initial": deletion is the cheapest clobber;
- a present-but-unreadable sidecar records ``state_unreadable`` — same reasoning;
- an unwritable state path records ``state_write_failed`` (as a second entry — the delta entry,
  if any, already landed) and serving continues, loud on every start until fixed;
- an env lane missing its required triple is recorded ABSENT ("this deployment has no env box");
  any OTHER env-config failure is recorded as an error — absent, empty and broken are three
  different facts and conflating them fakes grant-removal entries on transient failures.

Monitor ``state_missing``/``state_unreadable``/``state_write_failed`` at least as loudly as
``changed``: a grant change that lands while the sidecar is missing or unwritable is witnessed
by those outcomes (digest vs ``last_recorded_digest``, plus the summary counts) — never as a
per-lane ``delta``, because there is no readable baseline to diff against.

Same honesty note as the taint marker: the sidecar is a real witness only when its directory
sits outside the agent's own write reach. Co-located, a compromised agent can rewrite it — but
the entries already emitted are hash-chained, so erasing history still means attacking the
PROVE chain itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from typing import Any

from .config import ProximoConfig
from .targets import load_registry

STATE_BASENAME = ".proximo-reach-grant"
_ENV_TRIPLE = ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH")


def _ids(allow: frozenset[str]) -> list[str]:
    """Canonicalize one allowlist: '*' anywhere means allow-all (ct_permitted's semantics — it
    short-circuits on '*'), so the resolved form is exactly ["*"]. Otherwise dupes collapse and
    the sort is numeric-aware so CTIDs read in estate order."""
    if "*" in allow:
        return ["*"]
    return sorted(allow, key=lambda c: (0, int(c)) if c.isdigit() else (1, c))


def resolved_lanes(cfg: Any) -> dict[str, Any]:
    """One source's resolved reach, canonicalized — the id lanes PLUS the switches that decide
    whether that reach is live and where it lands. ``enable_exec`` off means the ct lane confers
    nothing; ``ssh_target`` re-pointed means the same CTIDs on a different physical host. Those
    are behavior, so they are part of the snapshot (a digest that stays put while exec flips on
    is a digest lying about behavior). Reads the SAME parsed fields the permission gates enforce
    from — there is no second parser to drift.

    ``arm_source`` is a switch too (lens finding, 2026-08-26): unsetting it between restarts
    silently removes the exec write gate — a serve-start widening of exactly this perimeter —
    and before this field joined the snapshot that produced no entry. The PATH is recorded,
    like ``ssh_target``: a re-pointed source is a different authority, and presence-only
    would hide the re-point."""
    return {
        "ct": _ids(getattr(cfg, "ct_allowlist", frozenset()) or frozenset()),
        "agent": _ids(getattr(cfg, "agent_allowlist", frozenset()) or frozenset()),
        "exec_enabled": bool(getattr(cfg, "enable_exec", False)),
        "agent_enabled": bool(getattr(cfg, "enable_agent", False)),
        "ssh_target": getattr(cfg, "ssh_target", None),
        "arm_source": getattr(cfg, "arm_source", None),
    }


def grant_snapshot(api_factory: Any = None) -> dict[str, Any]:
    """The whole instance's resolved reach grant: the env lane plus every pve target.

    The env lane is ABSENT only when the required env triple is missing — a pure-targets
    deployment holds no env grant to snapshot. Any OTHER build failure is recorded as an error:
    labeling a transient failure (an unreachable audit anchor, a bad option) "absent" would fake
    a whole-grant REMOVED entry now and a re-ADDED one later. A registry target that fails to
    build is likewise an error under its name — silently vanishing would read as a grant removal.

    ``api_factory`` (brick 3, 2026-08-26): when the mirror is ENFORCING and a factory is given,
    the snapshot also DERIVES the served token's per-guest reach — asking PVE, per allowlisted
    guest, whether the token holds the reach privilege there (a ``*`` allowlist enumerates the
    live containers first). This is the half of the perimeter the env side cannot see: a
    ``pveum`` grant or revoke now lands as a witnessed ``mirror.derived_ct`` delta at the next
    serve start, instead of living only in PVE's ACL table. Serve-START granularity, stated
    plainly — a mid-run ``pveum`` change is enforced immediately (the mirror queries live per
    check) but witnessed at the next start. Any derive failure records ``derived_error`` and
    omits the list (the env-error precedent: the entry self-describes, and a reader treats
    list churn in an entry carrying ``derived_error`` as unproven). No factory = no derive =
    byte-identical snapshots to before this brick: zero digest churn for estates not passing
    one, and the serve seam is the only caller that does.
    """
    snap: dict[str, Any] = {}
    if any(k not in os.environ for k in _ENV_TRIPLE):
        snap["env"] = {"absent": True}
    else:
        try:
            snap["env"] = resolved_lanes(ProximoConfig.from_env())
        except Exception as e:
            snap["env"] = {"error": type(e).__name__}

    targets: dict[str, Any] = {}
    for name, fields in sorted(load_registry().items()):
        if fields.get("kind", "pve") != "pve":
            continue  # only the pve plane holds exec/agent reach
        try:
            targets[name] = resolved_lanes(ProximoConfig.from_target(fields))
        except Exception as e:
            targets[name] = {"error": type(e).__name__}
    if targets:
        snap["targets"] = targets
    # The mirror's own switch is reach config: setting/changing/clearing the reach privilege moves the
    # digest AND shows in the delta, so the flip is witnessed like any other grant change.
    # SNAPSHOT-level, deliberately not inside the env lane: reachmirror.privilege() reads the
    # process env and enforces on EVERY shape — a pure-targets box (env lane absent) still
    # mirrors, so its flips must still be witnessed (lens finding: enforced-but-unwitnessed).
    # Key absent when unset — no state churn for existing sidecars.
    m = os.environ.get("PROXIMO_REACH_PRIVILEGE", "").strip()
    if m:
        mirror: dict[str, Any] = {"privilege": m}
        if api_factory is not None:
            env_lane = snap.get("env") or {}
            if env_lane.get("absent"):
                # Pure-targets: no env API to derive through — BY DESIGN, not broken
                # (absent, empty and broken are three different facts, this module's own
                # doctrine). A stable key: no churn, and never dressed as an error.
                mirror["derived_absent"] = True
            elif "error" in env_lane:
                # The env lane itself failed to build; the factory would raise the same
                # error again. Named for what it is — the env lane's problem, transient —
                # not an opaque exception name (the lens's absent-vs-broken finding).
                mirror["derived_error"] = "env_unavailable"
            else:
                try:
                    mirror.update(_derive_reach(api_factory(), env_lane, m))
                except Exception as e:
                    mirror["derived_error"] = type(e).__name__
        snap["mirror"] = mirror
    return snap


def _derive_reach(api: Any, env_lane: dict, priv: str) -> dict[str, Any]:
    """The PVE-side half of the witness: which allowlisted CONTAINERS the SERVED token can
    actually reach under the privilege, right now.

    Scope, stated: the env ct lane only — the agent/VM lane is deliberately out of derive
    scope, because the mirror never governs VM channels (PVE gates agent exec natively,
    server-side). ``*`` enumerates the CONFIGURED NODE's live containers (``type == "lxc"``
    only — a QEMU vmid in a container-reach key would witness reach the mirror never
    grants), so guest creation/destruction moves the digest too: on an allow-all estate
    that IS a reach change. Cost, stated: one GET per guest, sequential, before serving —
    a very large allow-all estate pays real serve-start latency; scope the allowlist if
    that bites. A non-numeric allowlist entry is SKIPPED and reported (``derived_skipped``)
    rather than poisoning the whole derive with one garbage token's API error."""
    ids = env_lane.get("ct")
    if not isinstance(ids, list):
        return {"derived_error": "env_lane_unavailable"}
    out: dict[str, Any] = {}
    if ids == ["*"]:
        ids = _ids(frozenset(str(g.get("vmid")) for g in api.list_guests()
                             if g.get("type") == "lxc" and g.get("vmid") is not None))
        if ids == ["*"]:  # a guest literally enumerating as '*' cannot happen; guard anyway
            return {"derived_error": "enumeration_unusable"}
    numeric: list[str] = []
    skipped: list[str] = []
    for c in ids:
        try:
            int(c)
            numeric.append(c)
        except ValueError:
            skipped.append(c)
    if skipped:
        out["derived_skipped"] = skipped
    from .reach_audit import derived_reach
    reach = derived_reach(api, numeric, priv)
    out["derived_ct"] = [c for c in numeric if reach.get(c)]
    return out


def grant_digest(snapshot: dict[str, Any]) -> str:
    """Stable 16-hex head of the canonical snapshot (sorted keys, no whitespace drift)."""
    body = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()[:16]


def receipt_view(block: dict[str, Any]) -> dict[str, Any]:
    """The --receipt form of a doctor reach_grant block: counts + digest, never the id lists.

    Bare CTIDs match none of receipt.py's redaction patterns, so a full roster would sail
    through render() intact — exactly the estate shape --receipt exists to remove. A '*' lane
    reports its count as '*' (a count of "all" is not a number, and 1 would be a lie)."""
    out: dict[str, Any] = {
        "ct_count": _count(block.get("ct")),
        "agent_count": _count(block.get("agent")),
        "digest": block.get("lane_digest"),
    }
    if "mirror" in block:
        # A privilege NAME is not estate shape — it appears in every ACL entry PVE serves —
        # so the mirror tri-state survives the receipt intact.
        out["mirror"] = block["mirror"]
    return out


def _count(lane: object) -> object:
    if isinstance(lane, list):
        return "*" if lane == ["*"] else len(lane)
    return 0


def default_state_path(ledger: Any) -> str:
    """Beside the ledger, like the taint/contain markers — one place the operator already knows."""
    return os.path.join(os.path.dirname(ledger.path), STATE_BASENAME)


def _flat(snapshot: dict[str, Any]) -> dict[str, dict]:
    """One namespace for the delta walk — 'env' plus 'target:<name>'. The prefix is load-bearing:
    a registry target literally named "env" must never shadow the env lane (unprefixed, it did —
    an env widening then recorded an empty delta)."""
    flat: dict[str, dict] = {}
    if "env" in snapshot:
        flat["env"] = snapshot["env"]
    if "mirror" in snapshot:  # synthetic source so a privilege flip shows in the DELTA, not
        flat["mirror"] = snapshot["mirror"]  # just as an unexplained digest move
    for name, lanes in (snapshot.get("targets") or {}).items():
        flat[f"target:{name}"] = lanes
    return flat


def _delta(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Per-source, per-key added/removed (id lanes) or old/new (switches, absent/error flips).
    A source appearing or vanishing shows as whole-lane adds/removes — a target dropping out of
    the registry IS a grant change."""
    of, nf = _flat(old), _flat(new)
    out: dict[str, Any] = {}
    for src in sorted(set(of) | set(nf)):
        o, n = of.get(src, {}), nf.get(src, {})
        changes: dict[str, Any] = {}
        for key in sorted(set(o) | set(n)):
            ov, nv = o.get(key), n.get(key)
            if isinstance(ov, list) or isinstance(nv, list):
                ol = ov if isinstance(ov, list) else []
                nl = nv if isinstance(nv, list) else []
                added = [x for x in nl if x not in ol]
                removed = [x for x in ol if x not in nl]
                if added or removed:
                    changes[key] = {"added": added, "removed": removed}
            elif ov != nv:
                changes[key] = {"old": ov, "new": nv}
        if changes:
            out[src] = changes
    return out


def _counts(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Small summary for the ledger detail — counts, not the full estate roster. A '*' lane
    reports '*', same honesty as receipt_view: on an `initial` entry this summary is the ONLY
    grant content, and recording allow-all as 1 is the exact lie this module exists to end."""
    flat = _flat(snapshot)
    totals: dict[str, Any] = {"sources": len(flat), "ct": 0, "agent": 0}
    for lanes in flat.values():
        for lane in ("ct", "agent"):
            v = lanes.get(lane)
            if not isinstance(v, list):
                continue
            if v == ["*"] or totals[lane] == "*":
                totals[lane] = "*"
            else:
                totals[lane] += len(v)
    return totals


def _last_recorded_digest(ledger: Any) -> str | None:
    """The digest of the last reach_grant entry in the CURRENT chain (a sealed rotation archive
    is out of scope — stated, not hidden). Lets a missing/corrupt sidecar be answered from the
    tamper-evident record instead of trusted-file memory."""
    last: str | None = None
    try:
        with open(ledger.path, encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    e = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if e.get("action") != "reach_grant":
                    continue
                d = e.get("detail") or {}
                last = d.get("new_digest") or d.get("digest") or last
    except OSError:
        return None
    return last


def _write_state(path: str, snapshot: dict[str, Any], digest: str) -> None:
    body = json.dumps({
        "version": 1,
        "snapshot": snapshot,
        "digest": digest,
        "last_checked": datetime.now(UTC).isoformat(),
    }, sort_keys=True, indent=1)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix=".proximo-reach-grant-")  # attributable orphans
    try:
        with os.fdopen(fd, "w") as f:
            f.write(body)
        os.replace(tmp, path)  # atomic — a reader never sees a half-written state
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def check_and_record(ledger: Any, *, state_file: str | None = None,
                     door: str = "unknown", api_factory: Any = None) -> dict[str, Any]:
    """Snapshot the resolved reach grant, PROVE any delta, then persist the sidecar.

    Record-before-write, deliberately: with the sidecar written first, a crash (or ENOSPC on
    the ledger append) between the two would land the widened snapshot on disk with no entry,
    and every later start would read ``unchanged`` — the swallow this feature exists to end.
    This order's worst case is a duplicate entry after a crash, which is noise, not loss.
    Ledger failures propagate: a serve start that cannot PROVE is already broken louder than
    this check. Entries are ``mutation=False`` on purpose — the check itself changes nothing;
    the grant edit happened outside Proximo (so ``mutations_only`` ledger reads skip these:
    filter on ``action="reach_grant"`` to see them).
    """
    path = state_file or default_state_path(ledger)
    snapshot = grant_snapshot(api_factory)
    digest = grant_digest(snapshot)

    outcome = "initial"
    detail: dict[str, Any] = {"door": door, "digest": digest, "summary": _counts(snapshot)}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                loaded = json.loads(f.read())
            prior = loaded["snapshot"]
            prior_digest = loaded["digest"]
        except Exception:
            # LOUD, never a silent "initial": a clobbered sidecar must not swallow a widening.
            outcome = "state_unreadable"
            detail["last_recorded_digest"] = _last_recorded_digest(ledger)
        else:
            if prior_digest == digest:
                outcome = "unchanged"
            else:
                outcome = "changed"
                detail["old_digest"] = prior_digest
                detail["new_digest"] = digest
                detail["delta"] = _delta(prior or {}, snapshot)
                del detail["digest"]
                mprior = (prior or {}).get("mirror") or {}
                mdelta = detail["delta"].get("mirror") or {}
                if "derived_ct" in mdelta and not any(
                        k in mprior for k in ("derived_ct", "derived_error", "derived_absent")):
                    # First derive on this sidecar: the whole map lands as "added", a shape
                    # indistinguishable from an overnight mass pveum grant unless the entry
                    # says otherwise (lens finding). Say so in the record itself.
                    detail["derived_baseline"] = True
    else:
        # The file MISSING is the cheaper clobber, and it must be just as loud as corruption
        # when the chain proves this is not a first run: `initial` here would let one `rm`
        # (or an unmounted state volume) reframe a widened grant as a benign first sighting.
        last = _last_recorded_digest(ledger)
        if last is not None:
            outcome = "state_missing"
            detail["last_recorded_digest"] = last

    if outcome != "unchanged":
        ledger.record("reach_grant", target="reach-grant", mutation=False,
                      outcome=outcome, detail=detail)
    try:
        _write_state(path, snapshot, digest)
    except OSError as e:
        # Second entry, not a relabel — the delta entry above (if any) already landed, and a
        # monitor filtering outcome="changed" must not lose it to a disk problem.
        ledger.record("reach_grant", target="reach-grant", mutation=False,
                      outcome="state_write_failed",
                      detail={"door": door, "digest": digest, "error": type(e).__name__})
        return {"outcome": "state_write_failed", "digest": digest}
    return {"outcome": outcome, "digest": digest}
