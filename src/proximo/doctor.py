"""DOCTOR — onboarding preflight: "is my config/token right, and what can this token DO?"

A read-only self-check a stranger runs FIRST, before wiring Proximo into an MCP client. It answers
the question raw 403s don't: *which* capability is missing and *how to grant it*. Same posture as
DIAGNOSE — advisory, never overclaims, surfaces incompleteness rather than implying a clean bill.

Pure-ish: it only does read-only API calls (`version`, `access/permissions`) + reads config. No
mutation, no exec. Routed through the PROVE ledger as a read by the server layer.
"""

from __future__ import annotations

import os

_DOCTOR_NOTE = (
    "DOCTOR is a read-only preflight: it checks API reachability + the token's effective permissions "
    "and reports what this token CAN/CANNOT do. Capability gaps list the privilege + a role to grant. "
    "Absence of a capability is a config signal, not a Proximo error."
)

# (capability, required privs, role hint, match-mode). Translates raw PVE privilege names into
# "what you can actually do" + a fix for each gap. match-mode prevents OVERCLAIM:
#   "all"     — needs EVERY listed priv (most are single-priv; rollback/users are split so each is exact).
#   "any"     — interchangeable privs; any one suffices (the read/audit family).
#   "partial" — any one suffices but the held subset is named (distinct config domains).
# Rollback is its OWN row (NOT folded into snapshot): VM.Snapshot without VM.Snapshot.Rollback can
# create a restore point but CANNOT roll back — never imply the UNDO path works when it doesn't.
_CAPABILITIES: list[tuple[str, list[str], str, str]] = [
    ("Read / inspect — DIAGNOSE, lists, status",
     ["VM.Audit", "Sys.Audit", "Datastore.Audit"], "PVEAuditor", "any"),
    ("Power guests — start / stop / reboot",
     ["VM.PowerMgmt"], "PVEVMAdmin", "all"),
    ("Snapshots — create restore points",
     ["VM.Snapshot"], "PVEVMAdmin", "all"),
    ("Rollback — the UNDO pillar",
     ["VM.Snapshot.Rollback"], "PVEVMAdmin", "all"),
    ("Reconfigure guests — cpu / memory / disk / network",
     ["VM.Config.Memory", "VM.Config.Disk", "VM.Config.Network", "VM.Config.Options", "VM.Config.CPU"],
     "PVEVMAdmin", "partial"),
    ("Create / clone / destroy guests",
     ["VM.Allocate"], "PVEVMAdmin", "all"),
    ("Back up guests",
     ["VM.Backup"], "PVEVMAdmin", "all"),
    ("Define / remove storage",
     ["Datastore.Allocate"], "PVEDatastoreAdmin", "all"),
    ("Firewall + node configuration",
     ["Sys.Modify"], "PVESysAdmin", "all"),
    ("Manage tokens / ACLs",
     ["Permissions.Modify"], "PVEUserAdmin", "all"),
    ("Manage users",
     ["User.Modify"], "PVEUserAdmin", "all"),
]


def _collect_privs(perms: object) -> dict[str, list[str]]:
    """Flatten the PVE /access/permissions map ({path: {priv: 1}}) to {priv: [paths it's held on]}.
    Tolerant of either the full map or a single-path dict; ignores falsy/zero grants."""
    out: dict[str, list[str]] = {}
    if not isinstance(perms, dict):
        return out
    # Single-path shape ({priv: 1}) vs full map ({path: {priv: 1}}): detect nested dict values.
    nested = any(isinstance(v, dict) for v in perms.values())
    items = perms.items() if nested else [("/", perms)]
    for path, pmap in items:
        if not isinstance(pmap, dict):
            continue
        for priv, val in pmap.items():
            if val:
                out.setdefault(priv, []).append(str(path))
    return out


def _scope(paths: list[str]) -> str:
    return "everywhere (/)" if "/" in paths else ", ".join(sorted(set(paths)))


def doctor_check(api) -> dict:
    """Read-only preflight. `api` is an ApiBackend (or a duck-type with version/access_permissions/
    config). Returns an advisory report with reachable, version, token can/cannot, config, flags."""
    report: dict = {"note": _DOCTOR_NOTE}
    flags: list[str] = []
    complete = True
    cfg = getattr(api, "config", None)

    # 1) Connectivity + auth — the single most common stranger failure.
    try:
        ver = api.version()
        report["reachable"] = True
        report["version"] = ver if isinstance(ver, dict) else {"raw": ver}
    except Exception as e:
        report["reachable"] = False
        report["version"] = {"error": type(e).__name__}
        flags.append(
            "cannot reach / authenticate to the Proxmox API — check PROXIMO_API_BASE_URL, the token "
            "file at PROXIMO_TOKEN_PATH, and TLS/CA (PROXIMO_CA_BUNDLE / PROXIMO_VERIFY_TLS). "
            "Preflight cannot evaluate permissions until this connects."
        )
        complete = False

    # 2) Token effective permissions -> capability map (only if we got through the door).
    if report["reachable"]:
        try:
            privs = _collect_privs(api.access_permissions())
            can: list[dict] = []
            cannot: list[dict] = []
            for human, needs, role, mode in _CAPABILITIES:
                held = [p for p in needs if p in privs]
                satisfied = bool(held) if mode in ("any", "partial") else len(held) == len(needs)
                if satisfied:
                    paths = [path for p in held for path in privs[p]]
                    label = human
                    if mode == "partial" and len(held) < len(needs):
                        label = f"{human} [partial — only: {', '.join(held)}]"
                    can.append({"capability": label, "via": held, "scope": _scope(paths)})
                else:
                    missing = [p for p in needs if p not in privs] or needs
                    cannot.append({
                        "capability": human,
                        "needs": missing,
                        "hint": (f"grant {role} (or any role containing {missing[0]}) to your token: "
                                 f"pveum acl modify <path> --tokens '<user@realm!tokenid>' --roles {role} "
                                 f"(privsep tokens: grant the role to the USER too)"),
                    })
            report["token"] = {"can": can, "cannot": cannot}
            if not privs:
                flags.append(
                    "token authenticates but has NO permissions on any path — it cannot read or act. "
                    "Grant it a role (e.g. PVEAuditor to start) via pveum acl modify."
                )
        except Exception as e:
            report["token"] = {"error": type(e).__name__}
            flags.append(
                "could not read token permissions (/access/permissions) — the token likely lacks even "
                "Sys.Audit, or the API rejected it. Capability map unavailable; diagnosis incomplete."
            )
            complete = False

    # 3) Config readiness — the safety/posture signals a stranger needs to see.
    if cfg is not None:
        allow = getattr(cfg, "ct_allowlist", frozenset()) or frozenset()
        report["config"] = {
            "node": getattr(cfg, "node", None),
            "api_base_url": getattr(cfg, "api_base_url", None),
            "exec_enabled": bool(getattr(cfg, "enable_exec", False)),
            "tls_verify": bool(getattr(cfg, "verify_tls", True)),
            "ca_bundle": getattr(cfg, "ca_bundle", None),
            "ct_allowlist": ("none (exec deny-all)" if not allow
                             else "ALL (*)" if "*" in allow else f"{len(allow)} CTID(s)"),
            # Whether exec/SQL bodies are fingerprinted or written whole into the PROVE ledger.
            # This block exists for exactly this class of signal, and it was the one posture fact
            # a stranger could not read off it — the one that decides whether a password on an
            # argv lands in a durable file.
            "ledger_redaction": bool(getattr(cfg, "redact_ledger", True)),
        }
        if not getattr(cfg, "verify_tls", True) and not getattr(cfg, "ca_bundle", None):
            flags.append("TLS verification is OFF with no CA bundle — API traffic is not cert-validated.")
        if getattr(cfg, "enable_exec", False) and not allow:
            flags.append("exec is ENABLED but the CT allowlist is empty (deny-all) — no container is reachable.")

    # 4) The trust spine — four pillars standing, two sockets only the OPERATOR can fill.
    # Configured state is reported yes/no ONLY — never the paths: a doctor call from a
    # hijacked session must not learn where the operator placed the consent drop or the
    # kill-switch. The operator knows where they put their own switch.
    def _socket(env: str, build: str) -> dict:
        return {
            "configured": bool(os.environ.get(env, "").strip()),
            "erect_with": build,
        }

    report["spine"] = {
        "standing": [
            "PLAN — every mutation dry-runs to a preview first; no configuration removes it",
            "PROVE — hash-chained (keyed) audit ledger records plans and confirmations; structural",
            "UNDO — snapshot/config-revert/rollback wherever the platform holds a primitive; structural",
            "DIAGNOSE — read-only evidence battery, always available; structural",
        ],
        "yours_to_erect": {
            "CONSENT": _socket(
                "PROXIMO_CONSENT_DIR",
                "from YOUR shell (not the agent's): create a directory OUTSIDE the agent's write "
                "reach, then set PROXIMO_CONSENT_DIR to it — every mutation then needs a grant file "
                "only your hand can drop. TTL via PROXIMO_CONSENT_TTL_SECONDS.",
            ),
            "CONTAIN": _socket(
                "PROXIMO_CONTAIN_TRIP_PATH",
                "from YOUR shell (not the agent's): choose a path OUTSIDE the agent's write reach "
                "and set PROXIMO_CONTAIN_TRIP_PATH to it — touching that file halts every mutation "
                "mid-incident, no restart needed.",
            ),
        },
        "note": (
            "Four pillars ship standing. CONSENT and CONTAIN only count when their paths sit "
            "OUTSIDE the agent's reach — a pillar Proximo raised for you would be a pillar the "
            "agent could lower for itself. See SECURITY.md, 'The two-deployment trust model'."
        ),
    }

    report["principal"] = _principal_report()
    report["surfaces"] = _surfaces_report()

    # Tier-1 memory (opt-in): enabled/size/freshness. A broken db is a doctor FINDING —
    # flagged for the operator, never an exception (memory_status never raises).
    from proximo.memory import memory_status
    report["memory"] = memory_status()
    if "error" in report["memory"]:
        flags.append(f"memory db error: {report['memory']['error']}")

    report["flags"] = flags
    report["complete"] = complete
    return report


def _principal_report() -> dict:
    """The principal feature's config state: name tag, caller pins enrolled count, enrollment mode.

    Reports the WHO layer on every ledger entry. Two layers: the operator-declared NAME TAG
    (PROXIMO_PRINCIPAL) and network-face CALLER BADGE verification (PROXIMO_CALLER_KEYS_DIR).
    Degrades to a note on any error; never crashes the doctor run.
    """
    try:
        from . import principal  # deferred: lazy import; cryptography may not be installed

        process_principal = principal.process_principal()
        pins_dir = os.environ.get("PROXIMO_CALLER_KEYS_DIR", "").strip() or None

        caller_pins: dict = {
            "configured": False,
            "dir": None,
            "enrolled": None,
            "note": "",
        }

        # Determine state and generate note
        if process_principal is None and pins_dir is None:
            # Completely unconfigured
            caller_pins["note"] = (
                "no principal configured — ledger entries carry no who-asked"
            )
        elif pins_dir is not None:
            # Pins directory is configured; try to load and count
            caller_pins["configured"] = True
            caller_pins["dir"] = pins_dir
            try:
                pins = principal.load_pins(pins_dir)
                enrolled = len(pins)
                caller_pins["enrolled"] = enrolled
                if enrolled == 0:
                    caller_pins["note"] = (
                        "caller pins configured, 0 enrolled — ALL callers will be refused on network faces"
                    )
                else:
                    caller_pins["note"] = f"{enrolled} caller(s) enrolled"
            except RuntimeError as e:
                # Pin directory unreadable, bad format, symlink, etc.
                # Degrade gracefully; the note carries the error.
                caller_pins["note"] = str(e)
        elif process_principal is not None:
            # Name tag set but no pins
            caller_pins["note"] = (
                "name tag set; no caller pins (network callers unverified)"
            )

        return {
            "process_principal": process_principal,
            "caller_pins": caller_pins,
        }
    except Exception as e:  # never let introspection break a read-only preflight
        return {
            "process_principal": None,
            "caller_pins": {
                "configured": False,
                "dir": None,
                "enrolled": None,
                "note": f"principal feature not introspectable here ({type(e).__name__})",
            },
        }


def _surfaces_report() -> dict:
    """The tool-surface picture: what this server serves, per plane, and why.

    Answers the "that is a lot of tools" reaction in-band: Proximo is one audited plane over
    all four Proxmox products, but it **auto-scopes to the planes you've configured** — a
    PVE+PBS-only box serves just those tools, no flag. This block shows which planes are
    configured vs served and how to light up a hidden one. Degrades to a note on any error.
    """
    try:
        from . import server  # deferred: server imports doctor, so import here, not at module top
        registry = list(server.mcp._tool_manager._tools.keys())
        configured = server.configured_surfaces()

        def _served(plane: str) -> int:
            prefixes = server.SURFACES[plane]
            return sum(1 for n in registry if n.startswith(prefixes))

        enable = {
            "pbs": "set PROXIMO_PBS_BASE_URL (or add a pbs target to PROXIMO_TARGETS)",
            "pmg": "set PROXIMO_PMG_BASE_URL (or add a pmg target)",
            "pdm": "set PROXIMO_PDM_BASE_URL (or add a pdm target)",
            "pve": "set PROXIMO_API_BASE_URL (or add a pve target)",
            "exec": "set PROXIMO_ENABLE_EXEC=1 (grants near-root in-container exec)",
        }
        planes: dict[str, dict] = {}
        for plane in server.SURFACES:
            served = _served(plane)
            row = {"configured": plane in configured, "served_tools": served}
            if served == 0:
                row["enable_with"] = enable.get(plane, "")
            planes[plane] = row

        # Reported in precedence order, matching server._apply_surfaces. doctor's whole job is to
        # tell an operator what THIS box is actually serving, so a layer it cannot name is a layer
        # it will silently misreport — caught by dogfooding, where doctor said "auto-scoped" on a
        # box whose surface was in fact being set by PROXIMO_TOOLSETS.
        tools_spec = os.environ.get("PROXIMO_TOOLS", "").strip()
        toolsets_spec = os.environ.get("PROXIMO_TOOLSETS", "").strip()
        spec = os.environ.get("PROXIMO_SURFACES", "").strip()
        autoscope_off = os.environ.get("PROXIMO_AUTOSCOPE", "").strip().lower() in (
            "off", "0", "false", "no")
        if tools_spec:
            scoping = f"PROXIMO_TOOLS={tools_spec} — exact tools"
        elif toolsets_spec.lower() == "dynamic":
            # The count comes from the composition, never a constant: with memory on the facade
            # is 4, and a doctor that states a number it did not derive is a doctor that will
            # misreport the box it exists to describe.
            from proximo.memory import memory_enabled
            memory_first = memory_enabled()
            scoping = (
                f"PROXIMO_TOOLSETS=dynamic — search facade "
                f"({4 if memory_first else 3} facade tools resident + audit_verify"
                + ("; memory-first: proximo_recall answers estate questions in one call"
                   if memory_first else "")
                + "; the rest searchable via proximo_find_tools, still auto-scoped to "
                  "configured planes)")
        elif toolsets_spec and toolsets_spec.lower() != "all":
            scoping = f"PROXIMO_TOOLSETS={toolsets_spec} — explicit toolsets"
        elif toolsets_spec.lower() == "all":
            scoping = "PROXIMO_TOOLSETS=all — full surface (auto-scope overridden)"
        elif spec.lower() == "all":
            scoping = "PROXIMO_SURFACES=all — full surface (auto-scope overridden)"
        elif spec:
            scoping = f"PROXIMO_SURFACES={spec} — explicit"
        elif autoscope_off:
            scoping = "PROXIMO_AUTOSCOPE=off — full surface"
        elif configured - server._UTILITY_SURFACES:
            scoping = "auto-scoped to configured planes"
        else:
            scoping = "no plane configured yet — serving the full surface"

        return {
            "served_tools": len(registry),
            "scoping": scoping,
            "planes": planes,
            "note": (
                "One audited plane over all four Proxmox products; Proximo serves only the "
                "planes you've configured. Light up a plane with its PROXIMO_*_BASE_URL (or a "
                "target). Size the surface to your model, most specific wins: PROXIMO_TOOLS for "
                "exact tools, PROXIMO_TOOLSETS for domains (pve.guests, pbs.tape, …) or "
                "'dynamic' for a small search facade with everything still callable, "
                "PROXIMO_SURFACES for whole planes. Scoping is context hygiene, not an "
                "authorization control — the token ACL stays the real boundary."
            ),
        }
    except Exception as e:  # never let introspection break a read-only preflight
        return {"note": f"tool surface not introspectable here ({type(e).__name__})"}
