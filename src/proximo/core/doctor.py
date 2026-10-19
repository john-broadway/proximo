"""DOCTOR: the gate diagnoses itself (parity row B6; `harden` folded in; the 0.45 bar: "keep, small").

The operator's verb at setup, before any agent is wired: is the record readable, is each plane
configured and reached, is the ledger's chain whole, and which of the six pillars stand. It is
CLI only (`proximo-core doctor`): the six tools are the 4K window and a seventh would move it,
and a doctor is read by the operator at a terminal, not by the model.

What it does NOT do, by the bar. 0.44's doctor translated the token's PVE privileges into a
capability vocabulary with role hints (676 lines); that re-does the vendor's RBAC in Proximo's
words (bar 4). Here the reach section is the vendor's own `GET /version` and `GET
/access/permissions`, run through the engine like any read (receipted, bounded), and the
permissions are counted and sampled by path, never translated; being reads through the engine,
they land as rows on the ledger (two per configured plane) and on a fresh box the first one
mints the audit key, which is why the ledger section is read after them. 0.44's `harden` printed four
stations with recipes; two (the reach MIRROR and the off-box PROVE anchor) have no mechanism in
the core and are not here. The kept stations are the six pillars on the core's own switches,
each read through the spine's own reader, with the line that would raise an empty one.

Stations report yes, NEVER where: no switch's path, no secret's path, no token byte lands in the
answer (a hijacked session must not learn the way to the operator's switch). Flags are advisory
and move no exit code. The exit is the shell door's contract: 0 ran whole, 3 nothing configured,
4 a configured plane unreachable or the chain unjudgeable; never 2, the spine's own refusal.
"""
from __future__ import annotations

import os
from typing import Any

from proximo.core import arm, engine, registry, shell, spine, wire
from proximo.core.errors import ProximoError
from proximo.core.ledger import (
    LedgerConfig,
    detect_mode,
    find_rotation_archive,
    in_flight,
    ledger_key,
    parse_lines,
    read_log,
    verify_lines,
)
from proximo.core.secretfile import safe_text
from proximo.core.spine import wire_error

EXIT_OK, EXIT_USAGE, EXIT_VENDOR = 0, 3, 4    # the shell door's contract (doors/cli.py); never 2


def run(ledger_cfg: Any = None) -> dict[str, Any]:
    """The report, with `exit` for the door. Every section is written even when an earlier one
    failed: a broken box is exactly when this runs."""
    lcfg = ledger_cfg or LedgerConfig.from_env()
    flags: list[str] = []
    report: dict[str, Any] = {"doctor": "proximo-core"}
    report["record"] = _record(flags)
    report["planes"], configured, unreachable = _planes(lcfg, flags)
    report["targets"] = _targets(flags)
    report["ledger"], chain_ok = _ledger(lcfg, flags)
    report["pillars"] = _pillars(report, chain_ok, flags)
    retired = spine.retired_refusal()
    report["retired"] = [retired.reason] if retired else []
    if retired:
        flags.append(f"a retired switch is set and every core door refuses mutations while it is: {retired.reason}")
    if os.environ.get("PROXIMO_SURFACES", "").strip():   # refused at every door's start (`refuse_surfaces`)
        report["retired"].append("PROXIMO_SURFACES is set, and the core has no surfaces: unset it")
        flags.append("PROXIMO_SURFACES is set: every core door refuses to start while it is; unset it")
    if not configured:
        flags.append("no plane is configured: set a plane's base URL and credential path (each plane names its own)")
    report["flags"] = flags
    report["complete"] = not flags or all(f.startswith(_ADVISORY) for f in flags)
    report["exit"] = EXIT_USAGE if not configured else EXIT_VENDOR if (unreachable or not chain_ok) else EXIT_OK
    return report


#: An EMPTY pillar is advice, not incompleteness; a TRIPPED one is neither (every mutation is refused
#: and the report must say it is not whole). Each prefix is one flag's exact opening.
_ADVISORY = ("CONSENT is inert", "CONTAIN has no trip path", "CONTAIN: no rate cap", "UNDO is off",
             "a sealed rotation archive sits beside the ledger")


def _said(exc: ProximoError) -> str:
    """A refusal the report repeats is a locator seam like the trip line: one scrubbed line."""
    return safe_text(str(exc), paths=True)


def _record(flags: list[str]) -> dict[str, Any]:
    try:
        rows = list(engine.table().values())
    except ProximoError as exc:
        flags.append(f"the record is refused, and every mutation with it: {(why := _said(exc))}")
        return {"refused": why}
    mutations = [r for r in rows if not r.excluded and r.access == engine.MUTATE
                 and (not r.gate or engine.opt_in_lane(r) is not None)]
    try:
        creates: Any = len(engine._creates())
    except ProximoError as exc:
        flags.append(f"undo.toml is refused, and every judged create's UNDO with it: {(why := _said(exc))}")
        creates = {"refused": why}
    return {"rows": len(rows), "mutations": len(mutations), "tiered": sum(1 for r in mutations if r.tier),
            "held": sum(1 for r in mutations if r.held), "creates": creates,
            "untrusted": sum(1 for r in rows if r.untrusted)}


def _planes(lcfg: Any, flags: list[str]) -> tuple[dict[str, Any], bool, bool]:
    out: dict[str, Any] = {}
    configured = unreachable = False
    for product in wire.PRODUCTS:
        try:
            cfg = wire.Plane.from_env(product)
        except RuntimeError as exc:
            text = str(exc)
            _, _, names = text.partition("env var: ")
            # The wire's own refusal (a 644 token file, two pmg modes at once) names the file's
            # path for the operator's terminal; here it is a locator and goes out scrubbed.
            out[product] = ({"configured": False, "missing": [n.strip() for n in names.split(",")]} if names
                            else {"configured": False, "error": safe_text(text, paths=True)})
            continue
        configured = True
        state = arm.arm_state(cfg)
        section: dict[str, Any] = {"configured": True, "base_url": cfg.base_url, "verify_tls": cfg.verify_tls,
                                   "fingerprint_pinned": bool(cfg.fingerprint),
                                   "arm": {"enforced": state.enforced, "armed": state.armed, "reason": state.reason}}
        if product == "pmg":
            section["credential_file"] = cfg.credential
        reach: dict[str, Any] = {}
        version = _read(product, "/version", cfg, lcfg)
        if "error" in version:
            reach["version"] = version
            flags.append(f"{product}: no reach: GET /version failed ({version['error']}); check the base URL, the "
                         f"credential file and TLS (a pin or a CA bundle)")
            unreachable = True
        else:
            reach["version"] = version["data"].get("version")
            if engine.table().get((product, "GET", "/access/permissions")) is None:
                reach["permissions"] = {"skipped": f"{product} publishes no GET /access/permissions"}
            else:
                perms = _read(product, "/access/permissions", cfg, lcfg)
                if "error" in perms:
                    reach["permissions"] = perms
                    flags.append(f"{product}: the credential reaches the box but GET /access/permissions "
                                 f"{'was cut by the door' if perms['error'] == 'cut' else 'failed'} "
                                 f"({perms['error']}); what it holds is not known")
                else:
                    paths = sorted(perms["data"])
                    reach["permissions"] = {"paths": len(paths), "sample": paths[:10]}
        section["reach"] = reach
        out[product] = section
    return out, configured, unreachable


def _read(product: str, path: str, cfg: wire.Plane, lcfg: Any) -> dict[str, Any]:
    """One vendor read through the engine: receipted, bounded; the error as a receipt would carry it."""
    try:
        env = engine.execute(engine.resolve(product, "GET", path), {}, cfg=cfg, path=path, ledger_cfg=lcfg,
                             fields="all")
    except Exception as exc:  # noqa: BLE001 -- the vendor's or the spine's; the type is the report
        return wire_error(exc) if not isinstance(exc, ProximoError) else {"error": "refused", "reason": _said(exc)}
    # A CUT IS NOT A READ. The size law hands back `truncated` with the byte count and no `data`;
    # reported as data it read "reaches the box, holds 0 permissions" (lens, 2026-10-09). A fenced
    # or non-record answer is not the record either.
    if "data" not in env:
        return {"error": "cut", "bytes": env.get("bytes"), "cap": env.get("cap")}
    if not isinstance(env["data"], dict):
        return {"error": "not a record", "shape": type(env["data"]).__name__}
    return {"data": env["data"]}


def _targets(flags: list[str]) -> dict[str, Any]:
    try:
        reg = registry.load_registry()
    except ProximoError as exc:
        flags.append(f"the target registry is set and unreadable: {(why := _said(exc))}")
        return {"configured": True, "error": why}
    return {"configured": bool(os.environ.get(registry.ENV)), "count": len(reg), "names": sorted(reg)}


def _ledger(lcfg: Any, flags: list[str]) -> tuple[dict[str, Any], bool]:
    try:
        lines = read_log(lcfg.audit_log_path)
    except ProximoError:                      # no ledger yet: a fresh box, an empty chain
        lines = []
    except OSError as exc:
        flags.append(f"the ledger cannot be read ({type(exc).__name__}); the chain cannot be judged")
        return {"keyed": True, "mode": "unreadable", "chain": f"unjudgeable: {type(exc).__name__}"}, False
    try:
        key = ledger_key(lcfg)
    except (OSError, ValueError) as exc:
        flags.append(f"the audit key cannot be read ({type(exc).__name__}); the chain cannot be judged")
        mode = detect_mode(lcfg.audit_log_path)
        return {"keyed": mode in ("keyed", "empty"), "mode": mode, "key_readable": False, "rows": len(lines),
                "chain": f"unjudgeable: {type(exc).__name__}"}, False
    # The ledger is keyed, always. `mode` is what the LOG holds now; a sealed archive beside it is
    # the log a door found unkeyed or mixed (a 0.44 box that opted out, a writer that bypassed the
    # door) and sealed on opening: named here, because the archive is evidence too.
    mode = detect_mode(lcfg.audit_log_path)
    section: dict[str, Any] = {"keyed": mode in ("keyed", "empty"), "mode": mode, "key_readable": key is not None,
                               "rows": len(lines)}
    archive = find_rotation_archive(lcfg.audit_log_path)
    if archive:
        name = os.path.basename(archive)
        was = ("keyed, archived by 0.44's opt-out" if ".keyed-" in name
               else "unkeyed or mixed when a door opened it and sealed it")
        section["sealed_archive"] = name
        flags.append(f"a sealed rotation archive sits beside the ledger ({name}): that log was {was}; "
                     "verify it with audit_verify(path=<its name>)")
    if key is None and any(x.strip() for x in lines):
        section["chain"] = "unjudgeable: configured keyed and no key is readable"
        flags.append("the ledger is configured keyed and no key is readable; its chain cannot be judged")
        return section, False
    v = verify_lines(lines, key)
    section["chain"] = "ok" if v.ok else f"broken at {v.broken_at}: {v.reason}"
    if not v.ok:
        flags.append(f"the ledger's chain is {section['chain']}; nothing after that row is evidence")
    open_rows = in_flight(parse_lines(lines))
    section["in_flight"] = len(open_rows)
    if open_rows:
        flags.append(f"{len(open_rows)} mutation(s) in flight: an executing row with no terminal row (a process died "
                     "between them, or one is running now)")
    return section, v.ok


def _pillars(report: dict[str, Any], chain_ok: bool, flags: list[str]) -> dict[str, Any]:
    p: dict[str, Any] = {}
    p["PLAN"] = {"standing": True, "how": "every mutation is planned and its executing row carries the plan"}
    if spine._env_set_nonempty(spine.CONSENT_DIR_ENV):
        p["CONSENT"] = {"standing": True, "ttl_seconds": spine._consent_ttl()}
    else:
        p["CONSENT"] = {"standing": False, "raise": f"{spine.CONSENT_DIR_ENV}=<a directory only the operator's hand "
                        "writes>: every mutation then needs a single-use grant file named by its plan's consent_id"}
        flags.append("CONSENT is inert: a plan says so, and any armed caller may mutate without a second party")
    led = report["ledger"]
    # An empty keyed ledger has no key yet (the first write mints it): standing until a row says otherwise.
    key_ok = led.get("key_readable", True) or not led.get("rows")
    p["PROVE"] = {"standing": bool(led.get("keyed")) and chain_ok and key_ok}
    creates = report["record"].get("creates") if isinstance(report["record"], dict) else None
    p["UNDO"] = {"standing": spine.undo_enabled(), "creates_judged": creates}
    if not spine.undo_enabled():
        p["UNDO"]["raise"] = f"{spine.UNDO_ENV}=on: a mutation then captures its before-state or does not run"
        flags.append("UNDO is off: no mutation captures a before-state")
    lanes: dict[str, Any] = {}
    for name, (enable, allow, *_rest) in spine._LANES.items():
        is_open = spine._env_truthy(enable)
        lanes[name] = {"open": is_open}
        if is_open and allow:
            entries, allow_all, garbled = spine._parse_allowlist(os.environ.get(allow))
            lanes[name]["allowlist"] = "*" if allow_all else len(entries)
            if garbled:
                flags.append(f"the {name} lane's allowlist is garbled: it denies every id")
    p["DIAGNOSE"] = {"standing": True, "lanes": lanes,
                     "ssh_target_configured": spine._env_set_nonempty(shell.TARGET_ENV)}
    trip = spine.contain_state()
    trip_section: dict[str, Any] = {"configured": spine._env_set_nonempty(spine.TRIP_ENV), "tripped": trip.contained}
    if trip.contained and trip.reason:
        # The file's text is the operator's reason, but the file is whatever the path names: a
        # mis-pointed trip dumped a token file whole (lens, 2026-10-09). One bounded line, no path.
        trip_section["reason"] = safe_text(trip.reason, limit=200, paths=True)
    rate_max, window = spine.rate_cap()
    p["CONTAIN"] = {"standing": trip_section["configured"], "trip": trip_section,
                    "rate": {"max": rate_max, "window": window}, "forbid": len(spine.forbid_set()),
                    "taint": {"track": spine._env_truthy(spine.TAINT_TRACK_ENV),
                              "forbid": spine._env_set_nonempty(spine.TAINT_FORBID_ENV),
                              "require_consent": spine.require_consent_when_tainted(), "fence": spine.fence_on()}}
    if not trip_section["configured"]:
        p["CONTAIN"]["raise"] = (f"{spine.TRIP_ENV}=<a file only the operator's hand creates>: its presence "
                                 "refuses every mutation at once")
        flags.append("CONTAIN has no trip path: there is no instant local kill switch")
    if trip.contained:
        why = trip_section.get("reason", "no reason written")
        flags.append(f"CONTAIN is tripped: every mutation is refused ({why})")
    if rate_max is None:
        flags.append(f"CONTAIN: no rate cap ({spine.RATE_MAX_ENV}/{spine.RATE_WINDOW_ENV}); mutations per box per "
                     "window are unbounded")
    return p
