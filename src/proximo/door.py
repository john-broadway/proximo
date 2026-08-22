"""The door — registration scoping and the lean facade, beside lean.py.

Everything that decides WHAT a running server advertises and how a caller reaches the rest:
the four scoping layers (autoscope, PROXIMO_SURFACES, PROXIMO_TOOLSETS, PROXIMO_TOOLS), the
schema slimming pass, the lean/dynamic facade (apply_lean, dispatch_tool), the two catalogs
(FULL_CATALOG / LEAN_CATALOG — REBOUND at snapshot time, read them through this module's
attribute access, never via a static `from` import of the dict object; server.py does not
re-export them), and the unknown-tool error. Moved from server.py in the A11 3a slice (2026-08-11) — the code is
server.py's, relocated; door.py must never import server at module top (server imports door;
`_default_mcp` resolves the stdio singleton lazily instead).

`proximo_call` stays in server.py: it is a registered @mcp.tool() named in _ALWAYS_REGISTERED,
and registration is server.py's import-time side effect. The import-time CALL statements
(`_slim_registry_schemas()`, `_snapshot_full_catalog()`) also stay at server.py's bottom —
their ORDER relative to tool registration is load-bearing.
"""

from __future__ import annotations

import difflib
import os
import sys
import warnings
from collections.abc import Iterable
from typing import Any

from . import lean
from ._mcpcompat import tool_annotations_kwargs
from .backends import ProximoError
from .targets import load_registry


def _default_mcp():
    """The stdio server's own FastMCP, resolved lazily — see the module docstring."""
    from proximo.server import mcp

    return mcp


# --- PROXIMO_SURFACES — opt-in registration scoping (context hygiene + surface reduction). ---
# Unset/empty => all tools, zero behavior change. Set (e.g. "pve,exec") => tools of unpicked
# planes are REMOVED from the registry before serving, so they never reach the client's context
# at all — a structural gate, not a runtime refusal. Applied in main() AFTER load_env_file()
# (registration happens at import, before the env file is read — pruning post-load is what makes
# a file-set PROXIMO_SURFACES actually work; same footgun CONSENT hit in 0.13). audit_verify is
# always kept: PROVE is never scopeable away.
SURFACES: dict[str, tuple[str, ...]] = {
    "pve": ("pve_",),   # Proxmox VE (includes the pve_agent_* qemu-agent edge)
    "pbs": ("pbs_",),   # Proxmox Backup Server
    "pmg": ("pmg_",),   # Proxmox Mail Gateway
    "pdm": ("pdm_",),   # Proxmox Datacenter Manager (reads + governed fleet control: power/snapshot/migrate)
    "exec": ("ct_",),   # in-container exec/psql/logs/diagnose (ssh -> pct)
    "memory": ("proximo_recall", "proximo_baseline"),  # Tier-1 estate memory (default-on; PROXIMO_MEMORY=0 opts out)
    "wiki": ("proximo_wiki",),  # local docs index, prefix covers _read (opt-in via PROXIMO_WIKI)
}
# Never scopeable away, for two different reasons. `audit_verify` because PROVE must not be
# removable. `proximo_call` because it is the by-name escape hatch: the four scoping layers below
# each narrow what is ADVERTISED, and without a resident dispatcher that narrowing also removed
# capability — on every transport, with no way back inside a live session. Pinned by
# tests/test_escape_hatch.py.
_ALWAYS_REGISTERED = frozenset({"audit_verify", "audit_entries", "proximo_call"})

# --- PROXIMO_TOOLSETS — domain scoping, one layer finer than SURFACES. ---
# SURFACES scopes by plane, which is too coarse to reach a small context: pve alone is 310 tools
# (~97k tokens), still ~12x an 8k local window. Domain groups are what the field standard uses
# (GitHub's MCP server: `repos`/`issues`/`pull_requests` + per-tool override), so the vocabulary
# is one adopters already know. Grouped from the real tool names, not invented — and every tool
# must land in at least one group or it becomes unreachable the moment anyone scopes by toolset
# (tests/test_toolsets.py pins that; there is no runtime warning for an orphan).
TOOLSETS: dict[str, tuple[str, ...]] = {
    # --- Proxmox VE ---
    "pve.guests":      ("pve_guest", "pve_list_guests", "pve_clone", "pve_template", "pve_snapshot",
                        "pve_rollback", "pve_disk", "pve_cloudinit", "pve_agent", "pve_create_vm",
                        "pve_create_container", "pve_delete_guest"),
    "pve.cluster":     ("pve_cluster", "pve_node", "pve_ha", "pve_task", "pve_hardware",
                        "pve_mapping", "pve_diagnose", "pve_doctor"),
    "pve.storage":     ("pve_storage", "pve_backup", "pve_restore", "pve_replication"),
    # SDN is split out deliberately: 83 of the 87 network tools are SDN, and most operators
    # never configure it. Folding them together made "I want network tools" cost 27k tokens.
    "pve.network":     ("pve_network",),
    "pve.sdn":         ("pve_sdn",),
    "pve.firewall":    ("pve_firewall", "pve_ipset", "pve_security_groups"),
    "pve.access":      ("pve_user", "pve_role", "pve_acl", "pve_token", "pve_group", "pve_pool",
                        "pve_realm", "pve_tfa", "pve_overbroad"),
    "pve.ceph":        ("pve_ceph",),
    "pve.maintenance": ("pve_apt", "pve_acme", "pve_notification", "pve_metrics"),
    # --- Proxmox Backup Server ---
    "pbs.datastores":  ("pbs_datastore", "pbs_gc", "pbs_prune", "pbs_snapshot", "pbs_backup",
                        "pbs_verify", "pbs_sync", "pbs_admin", "pbs_s3", "pbs_remote", "pbs_key",
                        "pbs_encryption_key", "pbs_namespace", "pbs_pull", "pbs_push"),
    "pbs.tape":        ("pbs_tape",),
    "pbs.access":      ("pbs_user", "pbs_realm", "pbs_tfa", "pbs_group", "pbs_acl", "pbs_token",
                        "pbs_role", "pbs_permission"),
    "pbs.node":        ("pbs_node", "pbs_disk", "pbs_service", "pbs_subscription", "pbs_tasks"),
    "pbs.maintenance": ("pbs_apt", "pbs_acme", "pbs_notification", "pbs_metrics", "pbs_traffic",
                        "pbs_status", "pbs_version", "pbs_ping", "pbs_job"),
    # --- Proxmox Mail Gateway ---
    "pmg.quarantine":  ("pmg_quarantine", "pmg_spam", "pmg_virus", "pmg_attachment", "pmg_track"),
    "pmg.rules":       ("pmg_ruledb", "pmg_action", "pmg_who", "pmg_what", "pmg_when",
                        "pmg_customscores", "pmg_dkim", "pmg_mimetypes", "pmg_regextest",
                        "pmg_welcomelist"),
    "pmg.mail":        ("pmg_transport", "pmg_mynetworks", "pmg_fetchmail", "pmg_tlspolicy",
                        "pmg_relay", "pmg_postfix", "pmg_mail", "pmg_domain", "pmg_dnsbl",
                        "pmg_tls_inbound_domains"),
    "pmg.statistics":  ("pmg_statistics", "pmg_stat"),
    "pmg.access":      ("pmg_access", "pmg_user", "pmg_ldap", "pmg_tfa", "pmg_role", "pmg_acl",
                        "pmg_token", "pmg_group"),
    "pmg.node":        ("pmg_node", "pmg_cluster", "pmg_service", "pmg_subscription", "pmg_disk",
                        "pmg_doctor", "pmg_tasks"),
    "pmg.maintenance": ("pmg_apt", "pmg_acme", "pmg_notification", "pmg_config", "pmg_backup",
                        "pmg_metrics", "pmg_version", "pmg_ping", "pmg_pbs_remote"),
    # --- the rest ---
    "pdm":             ("pdm_",),
    "exec":            ("ct_",),
    # Tier-1 estate memory (default-on since 0.30, PROXIMO_MEMORY=0 opts out; see proximo/memory.py)
    "memory":          ("proximo_recall", "proximo_baseline"),
    # Local Proxmox docs index (opt-in via PROXIMO_WIKI; see proximo/wiki.py). One prefix
    # covers both tools; the seam is a file contract, so no builder import exists anywhere.
    "wiki":            ("proximo_wiki",),
}


def toolset_keep(names: Iterable[str], spec: str | None) -> set[str]:
    """Pure filter: which tool names stay registered under a PROXIMO_TOOLSETS spec.

    None/blank => everything (inert). Unknown name => ValueError, same fail-closed contract as
    surface_keep: a typo must refuse startup rather than quietly serve a different set than the
    operator believes they picked. `audit_verify` is never scopeable away — PROVE is not optional.
    """
    names = set(names)
    if spec is None or not spec.strip():
        return names
    picked = [t.strip().lower() for t in spec.split(",") if t.strip()]
    unknown = sorted(set(picked) - set(TOOLSETS))
    if unknown:
        raise ValueError(
            f"PROXIMO_TOOLSETS: unknown toolset(s) {unknown} — valid: {sorted(TOOLSETS)} "
            "(refusing to start rather than serve a set you didn't pick)")
    prefixes = tuple(p for t in picked for p in TOOLSETS[t])
    return {n for n in names if n.startswith(prefixes) or n in _ALWAYS_REGISTERED}


def surface_keep(names: Iterable[str], spec: str | None) -> set[str]:
    """Pure filter: which tool names stay registered under a PROXIMO_SURFACES spec.
    None/blank => everything (inert). Unknown surface name => ValueError — a typo must
    refuse startup, never silently serve a different surface than the operator believes."""
    names = set(names)
    if spec is None or not spec.strip():
        return names
    picked = [t.strip().lower() for t in spec.split(",") if t.strip()]
    unknown = sorted(set(picked) - set(SURFACES))
    if unknown:
        raise ValueError(
            f"PROXIMO_SURFACES: unknown surface(s) {unknown} — valid: {sorted(SURFACES)} "
            "(refusing to start rather than serve a surface you didn't pick)")
    prefixes = tuple(p for t in picked for p in SURFACES[t])
    return {n for n in names if n.startswith(prefixes) or n in _ALWAYS_REGISTERED}


_TRUEISH = frozenset({"1", "true", "yes", "on"})


def configured_surfaces() -> set[str]:
    """Which planes are actually configured on this box — detected, not declared.

    A plane counts as configured when its env base URL is present OR a target of that
    kind exists in PROXIMO_TARGETS. `exec` counts only when PROXIMO_ENABLE_EXEC is on.
    This is what lets a PVE+PBS-only box auto-serve just those planes' tools — no flag.
    """
    found: set[str] = set()
    for plane, env in (("pve", "PROXIMO_API_BASE_URL"), ("pbs", "PROXIMO_PBS_BASE_URL"),
                       ("pmg", "PROXIMO_PMG_BASE_URL"), ("pdm", "PROXIMO_PDM_BASE_URL")):
        if os.environ.get(env, "").strip():
            found.add(plane)
    try:  # a target of any kind configures that plane; a broken registry must not crash startup
        for fields in load_registry().values():
            kind = fields.get("kind")
            if kind in SURFACES:
                found.add(kind)
    except Exception:  # noqa: S110 — broken registry surfaces elsewhere; detection must not crash startup
        pass
    if os.environ.get("PROXIMO_ENABLE_EXEC", "").strip().lower() in _TRUEISH:
        found.add("exec")
    # Cross-plane UTILITY surfaces. They are not planes and have no base URL to detect, so their
    # configuration signal is their own opt-in env var — the shape `exec` above already has.
    # Missing them meant autoscope (on by DEFAULT) silently pruned proximo_recall,
    # proximo_baseline and both wiki tools on every real box: live-caught 2026-07-29 driving the
    # real config, with the whole suite green, because the test doubles mirror the full registry.
    from proximo.memory import memory_enabled
    from proximo.wiki import wiki_enabled
    if memory_enabled():
        found.add("memory")
    if wiki_enabled():
        found.add("wiki")
    return found


# Surfaces that are real but are NOT data planes: they can never make a config unambiguous on
# their own. See the guard in _autoscope_keep.
_UTILITY_SURFACES = frozenset({"exec", "memory", "wiki"})


def _autoscope_planes() -> set[str] | None:
    """The planes to auto-scope to, or None when autoscope must not narrow at all.

    Split out from _autoscope_keep so BOTH callers share one guard, and so the decision can be
    made without touching the server object: the no-op paths of _apply_surfaces must not read
    `_tool_manager` unnecessarily. (This once cited a pinning test by name;
    NO SUCH TEST EXISTS — verified 2026-08-02. The citation was wrong when written, which is
    worse than no citation, because it reads as coverage. What actually exercises the
    minimal-double path is test_surfaces.py::test_apply_surfaces_prunes_a_registry, and its
    double now needs `tool()` too, so the "must not touch" claim is narrower than it sounds.)
    The duplicate that this split removes had drifted — the default branch still
    read `planes - {"exec"}` after _UTILITY_SURFACES grew memory and wiki, so `PROXIMO_MEMORY=1`
    with an undetectable data plane narrowed 904 tools to 5.

    None means "leave the registry alone": autoscope explicitly off, or no data plane detectable
    (config ambiguous — never surprise an operator with an empty server).
    """
    if os.environ.get("PROXIMO_AUTOSCOPE", "").strip().lower() in ("off", "0", "false", "no"):
        return None
    planes = configured_surfaces()
    if not (planes - _UTILITY_SURFACES):
        return None
    return planes


def _autoscope_keep(names: Iterable[str]) -> set[str] | None:
    """The keep-set for auto-scoping to configured planes, or None when it must not narrow."""
    planes = _autoscope_planes()
    if planes is None:
        return None
    return surface_keep(names, ",".join(sorted(planes)))


def _prune_registry(server_mcp, keep: set[str], reason: str) -> None:
    registry = server_mcp._tool_manager._tools
    total = len(registry)
    for name in [n for n in registry if n not in keep]:
        server_mcp.remove_tool(name)
    print(f"proximo: {reason} — {len(keep)} of {total} tools registered", file=sys.stderr)


def _apply_dynamic(server_mcp) -> None:
    """The dynamic facade door: auto-scope FIRST, then swap the registry for the facade.

    The ordering is load-bearing, found by dogfooding a live PVE-only box: apply_lean snapshots
    the searchable catalog at call time, so if plane scoping hasn't run yet the facade advertises
    pmg_/pdm_ tools on a host with neither configured. Calling one can only fail — capability the
    deployment does not have, spending a small model's turns to discover it. Lean is a context
    choice; it must not widen what is reachable."""
    keep = _autoscope_keep(server_mcp._tool_manager._tools.keys())
    if keep is not None:
        _prune_registry(server_mcp, keep, "lean: auto-scoped to configured planes")
    apply_lean(server_mcp)


def _apply_catalog(server_mcp) -> None:
    """The pre-0.30 default door by name: full schemas, auto-scoped to configured planes."""
    planes = _autoscope_planes()
    if planes is None:   # autoscope off, or no data plane detected → ambiguous, touch nothing
        return
    registry = server_mcp._tool_manager._tools
    keep = surface_keep(registry.keys(), ",".join(sorted(planes)))
    if len(keep) < len(registry):   # only announce/prune when it actually narrows
        _prune_registry(server_mcp, keep,
                        f"auto-scoped to configured planes ({','.join(sorted(planes))})")


def _apply_surfaces(server_mcp=None) -> None:
    """Scope the live registry to the door the operator picked. ValueError propagates to main().

    TWO AXES, not one ladder. SCOPE answers "which planes/tools exist here"; DOOR answers "how
    are they presented" (resident schemas vs the searchable facade). PROXIMO_TOOLS and
    PROXIMO_TOOLSETS answer BOTH — naming exact tools or a domain is itself a residency choice.
    PROXIMO_SURFACES answers ONLY scope, so it narrows the world and then leaves the door at the
    default: the dynamic facade.

    Precedence: (1) explicit PROXIMO_TOOLS wins verbatim; (2) PROXIMO_TOOLSETS — domains, or the
    keywords `dynamic` (the facade), `catalog` (auto-scoped plane catalog, the pre-0.30 default)
    and `all` (full surface); (3) PROXIMO_SURFACES — planes, or `all` — scope only, facade door;
    (4) nothing picked → the dynamic facade (the 0.30 flip: a default install must fit a default
    local model's window; every tool stays reachable via proximo_find_tools →
    proximo_tool_schema → proximo_call).

    EXTERNAL VET 2026-08-02, and the reason (3) is no longer a `return`: shipped 0.30.0 treated
    SURFACES as a door, so scoping your planes silently opted you OUT of the flip. Measured on a
    live PVE+PBS box: SURFACES=pve,pbs served 569 resident tools where the facade serves 6, and
    removing a `catalog` pin bought 2 tools (571 -> 569) instead of the ~99% reduction the
    changelog promised. No error, no warning; the reviewer found it only by probing the running
    server. apply_lean's docstring had promised this composition since the flip landed — the
    ladder never routed SURFACES into it. Anyone who wants the resident catalog asks for a DOOR
    by name: PROXIMO_TOOLSETS=catalog (auto-scoped) or =all (everything)."""
    if server_mcp is None:
        server_mcp = _default_mcp()
    # ALREADY-LEANED GUARD. apply_lean has its own idempotence check, but it is unreachable on a
    # second _apply_surfaces: the prune runs FIRST and removes proximo_find_tools (it matches no
    # surface prefix and is not in _ALWAYS_REGISTERED), so apply_lean then snapshots the 3-tool
    # facade as the searchable catalog. Measured on a PVE box: a second call took the searchable
    # world 314 -> 4 on the default door and 312 -> 3 under PROXIMO_SURFACES, silently. No
    # production path calls this twice — main() and all three faces call it once — but embedders
    # do, which is precisely the audience test_apply_surfaces_twice_... names. That test could
    # not see this: it deletes every base-URL var, so autoscope declines to narrow, no prune
    # runs, and the guard it means to exercise is never reached. Refusing a re-scope is strictly
    # safer than collapsing the catalog; re-scoping a live server was never supported anyway.
    if "proximo_find_tools" in server_mcp._tool_manager._tools and LEAN_CATALOG:
        return
    # Layers, most specific first. The first one SET wins outright — they do not intersect,
    # because an operator who names exact tools has already answered the coarser question, and
    # silently ANDing a leftover PROXIMO_SURFACES from their env would serve them less than they
    # asked for with no way to see why.
    #
    # `_tool_manager` is read INSIDE each branch, never hoisted. This used to claim the
    # pass-through paths "(`all`) must not touch the server object at all" — true only of
    # PROXIMO_TOOLSETS=all, which still returns without touching it. It is FALSE for
    # PROXIMO_SURFACES=all since 0.31.0: that path skips the prune but still installs the
    # facade, so it reads and mutates the registry (external vet, 2026-08-02).
    tools_spec = os.environ.get("PROXIMO_TOOLS")
    if tools_spec and tools_spec.strip():
        _prune_registry(server_mcp, tool_keep(server_mcp._tool_manager._tools.keys(), tools_spec),
                        f"PROXIMO_TOOLS={tools_spec.strip()}")
        return

    toolsets_spec = os.environ.get("PROXIMO_TOOLSETS")
    if toolsets_spec and toolsets_spec.strip():
        picked = toolsets_spec.strip().lower()
        if picked == LEAN_KEYWORD:
            _apply_dynamic(server_mcp)
            return
        if picked == CATALOG_KEYWORD:
            _apply_catalog(server_mcp)
            return
        if picked != "all":
            _prune_registry(server_mcp,
                            toolset_keep(server_mcp._tool_manager._tools.keys(), toolsets_spec),
                            f"PROXIMO_TOOLSETS={toolsets_spec.strip()}")
        return

    spec = os.environ.get("PROXIMO_SURFACES")
    if spec and spec.strip():
        # `all` = every plane searchable (autoscope overridden), NOT every schema resident. Same
        # shape PROXIMO_AUTOSCOPE=off already ships: turning narrowing off does not change the
        # door. Prune BEFORE apply_lean — it snapshots the searchable catalog at call time, so
        # the order is what makes the operator's plane choice narrow the facade's world too.
        if spec.strip().lower() != "all":
            _prune_registry(server_mcp, surface_keep(server_mcp._tool_manager._tools.keys(), spec),
                            f"PROXIMO_SURFACES={spec.strip()}")
        # A facade over a UTILITY-ONLY world is worse than no facade. `memory`/`wiki`/`exec` are
        # cross-plane utility surfaces, not planes: scoped to those alone the searchable catalog
        # is a handful of tools, and the facade's own description tells the model "the other ~900
        # are searchable" over a world of five — a tool description is a prompt, so that is a lie
        # the model acts on. `_autoscope_planes` refuses to narrow on exactly this condition
        # (`planes - _UTILITY_SURFACES` empty); the door layer needs the same refusal, and the
        # operator who asked for five tools should simply be served those five.
        picked = {s.strip().lower() for s in spec.split(",") if s.strip()}
        if picked - _UTILITY_SURFACES:
            apply_lean(server_mcp)
        return
    _apply_dynamic(server_mcp)


# --- schema slimming — the fixed cost every client pays before asking anything. ---
# Pydantic labels each property with a `title` derived from its own key ("vmid" -> "Vmid"), and
# titles each $defs model with its class name. In a JSON schema the key already sits above the
# value, so the label restates it; across ~3k properties on ~900 tools that restatement was ~24k
# tokens of the tools/list payload. `title` is presentational only in JSON Schema (never affects
# validation or dispatch), so removing it changes nothing a client can act on.
# Applied at import, once, to the live registry — the payload is built from these dicts.
def strip_schema_titles(node: Any) -> Any:
    """Recursively drop presentational `title` keys from a generated JSON schema (in place)."""
    if isinstance(node, dict):
        node.pop("title", None)
        for value in node.values():
            strip_schema_titles(value)
    elif isinstance(node, list):
        for item in node:
            strip_schema_titles(item)
    return node


def collapse_nullable_anyof(node: Any) -> Any:
    """Rewrite `anyOf:[{type:X},{type:null}]` as `type:[X,"null"]` in place — identical schema.

    Pydantic emits the long form for every `X | None` parameter, and optional parameters are the
    common case across the surface, so the same ~30 wasted chars ride on hundreds of properties.
    ONLY the exact two-branch shape where both branches carry nothing but `type` is collapsed: a
    branch with `minLength`/`enum`/anything else cannot be folded into a type union without
    changing meaning, and a shorter schema that means something different is not a saving.
    """
    if isinstance(node, dict):
        branches = node.get("anyOf")
        if (isinstance(branches, list) and len(branches) == 2
                and all(isinstance(b, dict) and set(b) == {"type"} for b in branches)
                and any(b["type"] == "null" for b in branches)):
            node.pop("anyOf")
            node["type"] = [b["type"] for b in branches]
        for value in node.values():
            collapse_nullable_anyof(value)
    elif isinstance(node, list):
        for item in node:
            collapse_nullable_anyof(item)
    return node


def drop_unusable_target_param(schema: dict, *, registry_configured: bool) -> dict:
    """Remove `proximo_target` from a schema when there is no target registry to name.

    The parameter selects an entry in PROXIMO_TARGETS. With no registry configured, the only
    outcome of passing it is `resolve_target_fields` raising "no target registry configured" —
    so on a single-box deployment (the common one) it is a parameter that cannot succeed,
    advertised on ~every tool. That is the same rule autoscope already applies to whole planes:
    do not advertise what this box cannot serve. A configured registry keeps it untouched.
    """
    if registry_configured:
        return schema
    props = schema.get("properties")
    if isinstance(props, dict):
        props.pop("proximo_target", None)
    required = schema.get("required")
    if isinstance(required, list) and "proximo_target" in required:
        schema["required"] = [r for r in required if r != "proximo_target"]
    return schema


def _slim_registry_schemas(server_mcp=None) -> None:
    if server_mcp is None:
        server_mcp = _default_mcp()
    # Resolved ONCE, not per tool: load_registry() reads and parses a TOML file.
    try:
        registry_configured = bool(load_registry())
    except Exception as e:
        # A malformed registry is a real error, but it belongs to the code path that USES it and
        # reports it properly. Slimming must never be the thing that refuses startup, and the
        # safe direction here is to KEEP the parameter. It must not be SILENT though: every
        # sibling posture failure in this codebase warns at startup, and a registry broken by one
        # bad entry poisons every target, so an operator otherwise gets no signal until the first
        # live call against a target that used to work.
        warnings.warn(
            f"PROXIMO_TARGETS could not be read at startup ({type(e).__name__}); the target "
            "selector stays advertised and any call naming a target will fail loudly with the "
            "real error. Fix the registry file.",
            stacklevel=2,
        )
        registry_configured = True
    for tool_obj in server_mcp._tool_manager._tools.values():
        params = getattr(tool_obj, "parameters", None)
        if isinstance(params, dict):
            strip_schema_titles(params)
            collapse_nullable_anyof(params)
            drop_unusable_target_param(params, registry_configured=registry_configured)


# --- PROXIMO_TOOLS — exact-name selection, the finest scoping layer. ---
def tool_keep(names: Iterable[str], spec: str | None) -> set[str]:
    """Pure filter: exactly the named tools (plus audit_verify). Blank => inert.

    Fail-closed on an unknown name for the same reason as the coarser layers: an operator who
    typos one entry of a hand-picked list must be told, not handed a server quietly missing a
    tool they believe they enabled.
    """
    names = set(names)
    if spec is None or not spec.strip():
        return names
    picked = {t.strip() for t in spec.split(",") if t.strip()}
    unknown = sorted(picked - names)
    if unknown:
        raise ValueError(
            f"PROXIMO_TOOLS: unknown tool(s) {unknown} "
            "(refusing to start rather than serve a set you didn't pick)")
    return picked | (names & _ALWAYS_REGISTERED)


# --- LEAN / dynamic mode — the facade. ---
# Registers three small tools in place of the whole catalog. The catalog is SNAPSHOT FIRST and
# returned, because pruning the registry is what removes the schemas from tools/list — dispatch
# still needs somewhere to look the tool up. Getting that order wrong yields a server that lists
# three tools and can call none of them.
LEAN_KEYWORD = "dynamic"
# The pre-0.30 default door, kept as a one-word rollback in the upgrade note: full schemas,
# auto-scoped to configured planes. (`all` is the other, older escape: full surface, no scoping.)
CATALOG_KEYWORD = "catalog"


async def dispatch_tool(server_mcp, catalog: dict, name: str, arguments: dict):
    """Call a catalogued tool THROUGH ToolManager.call_tool — never around it.

    This is the invariant the whole mode rests on. `call_tool` resolves the Tool and awaits
    `tool.run(arguments)`, and `tool.fn` is the DECORATED function: target_aware, the PLAN gate,
    the PROVE ledger write, every opt-in control. Reaching for `tool.fn.__wrapped__` or the
    module-level function would run the body with none of them and look identical to a caller —
    a second, ungoverned mutate path. Don't.

    The tool is temporarily re-attached to the manager so call_tool can resolve it, then removed;
    the registry (what tools/list reports) is unchanged on both success and failure.

    Fail-closed on an unknown name, with the SAME did-you-mean mechanism `proximo_tool_schema`
    (lean.tool_schema) already uses, raised as ProximoError rather than a bare KeyError: a small
    model in dynamic mode calls proximo_call directly to conserve round trips, skipping the
    schema-lookup step entirely, so this is its only chance at a recoverable error instead of a
    dead end.
    """
    name = lean.resolve_alias(name)  # a fabricated verb-order guess resolves to the real tool
    if name not in catalog:
        near = difflib.get_close_matches(name, catalog, n=3, cutoff=0.6)
        hint = f" — did you mean: {', '.join(near)}" if near else ""
        raise ProximoError(f"unknown tool {name!r}{hint}")
    registry = server_mcp._tool_manager._tools
    restore = name in registry
    registry[name] = catalog[name]
    try:
        # context=None spelled out: optional on mcp 1.x, REQUIRED positional on 2.x.
        return await server_mcp._tool_manager.call_tool(name, arguments, context=None)
    finally:
        if not restore:
            registry.pop(name, None)


# The COMPLETE registry, frozen before any scoping layer runs — the escape hatch's dispatch
# source. Populated at import time at the bottom of this module, the one point where every
# @mcp.tool() decorator has fired and no _apply_surfaces() has happened yet (main() runs from a
# console-script entry point, which is structurally after import).
#
# This is LEAN_CATALOG's idea one step earlier. LEAN_CATALOG snapshots at apply_lean() call time
# and is therefore narrowed by whatever ran first — load-bearing and unchanged, because what the
# facade ADVERTISES must not exceed what this deployment can serve. FULL_CATALOG snapshots before
# the first prune of ANY layer, because what a caller can REACH by exact name must not shrink at
# all. Advertising and reachability are different questions and this module now answers them
# separately; conflating them is what made four scoping layers able to strand a working tool.
FULL_CATALOG: dict = {}


def _snapshot_full_catalog(server_mcp=None) -> dict:
    global FULL_CATALOG
    if server_mcp is None:
        server_mcp = _default_mcp()
    FULL_CATALOG = dict(server_mcp._tool_manager._tools)
    return FULL_CATALOG


def escape_catalog(server_mcp=None) -> dict:
    """The dispatch source for `proximo_call`: the full pre-prune registry when we have it.

    Falls back to the live registry only when the snapshot is empty — an embedder that built its
    own FastMCP never ran our import-time snapshot, and a hatch that reached nothing at all would
    be worse than one that reaches what is left.
    """
    if FULL_CATALOG:
        return FULL_CATALOG
    if server_mcp is None:
        server_mcp = _default_mcp()
        # _default_mcp just imported server, whose bottom-of-module _snapshot_full_catalog()
        # may have populated FULL_CATALOG this instant (door-first cold import). Re-check, or
        # a caller that CACHES this return gets the live registry — a dict a later prune
        # shrinks, violating this function's own reach-must-not-shrink contract (lens, 08-11).
        if FULL_CATALOG:
            return FULL_CATALOG
    return server_mcp._tool_manager._tools


# The catalog the facade dispatches into. Module-level so it is inspectable (tests, diagnostics)
# rather than sealed inside a closure — what lean mode offers is a real property of the running
# server, and a property nothing can read is a property nothing can check.
LEAN_CATALOG: dict = {}


def apply_lean(server_mcp=None) -> dict:
    """Swap the registry for the three-tool facade. Returns the snapshot used for dispatch.

    Snapshots whatever is registered AT CALL TIME, so any scoping applied first (auto-scope to
    configured planes, PROXIMO_SURFACES) narrows the catalog too. That ordering is load-bearing:
    see the caller in _apply_surfaces.
    """
    from proximo.memory import memory_enabled

    if server_mcp is None:
        server_mcp = _default_mcp()
    global LEAN_CATALOG
    # Idempotence guard (redteam, 2026-08-01): a second pass would snapshot the FACADE itself
    # as the searchable catalog — 906 searchable silently becomes 6. Once the facade is the
    # registry, there is nothing left to lean.
    if "proximo_find_tools" in server_mcp._tool_manager._tools:
        return LEAN_CATALOG
    catalog = dict(server_mcp._tool_manager._tools)
    LEAN_CATALOG = catalog

    # MEMORY-FIRST ANSWERING. What lean mode costs is ROUND TRIPS: every question, however
    # small, is find_tools -> tool_schema -> call, and a 9B stalled empty driving that at 8k
    # ctx. The dominant question class — what exists, how many, what changed, when did this
    # last happen — is one Tier-1 memory already holds, counted server-side and age-stamped.
    # When memory is on, proximo_recall goes resident so that class costs ONE zero-argument
    # call instead of three hops.
    #
    # KEPT, never redefined. Re-declaring a facade-local recall would run the same body with
    # no target_aware, no PLAN gate, no ledger write and no taint classification — the second
    # ungoverned path this module exists to not have. Absent from the catalog (scoped away via
    # PROXIMO_SURFACES) it stays absent: that was the operator's choice, not ours to overrule.
    recall_resident = memory_enabled() and "proximo_recall" in catalog

    # COUNT THIS BOX, NOT THE PROJECT. Both descriptions said "the other ~900", which is true
    # only of an unscoped server: a PVE-only box searches 312 and PROXIMO_SURFACES=pve,exec
    # searches 316. A tool description is a prompt — an inflated number tells a model to keep
    # searching for tools this deployment does not have. Derived from the snapshot, so it tracks
    # whatever scoping ran before it.
    searchable = len(catalog)
    if recall_resident:
        find_tools_doc = (
            "Search Proximo's full tool catalog by keyword.\n\n"
            "ESTATE QUESTIONS FIRST: if the question is what exists, how many, what changed, "
            "or when something last happened, call proximo_recall instead — it answers from "
            "local memory in one call, with no search and no schema lookup, and it stamps how "
            "old the answer is. Come here for everything else.\n\n"
            f"The facade is resident; {searchable} more tools on this server are searchable but "
            "not. Search for what you want (\"guest power\", \"ceph pool\", \"firewall\"), then "
            "call proximo_tool_schema on a result to get its arguments, then proximo_read "
            "(read-only tools) or proximo_call to run it. All terms must match."
        )
    else:
        find_tools_doc = (
            "Search Proximo's full tool catalog by keyword. START HERE.\n\n"
            f"Only this facade is loaded; {searchable} more tools on this server are searchable "
            "but not resident. Search for what you want (\"guest power\", \"ceph pool\", "
            "\"firewall\"), then call proximo_tool_schema on a result to get its arguments, "
            "then proximo_read (read-only tools) or proximo_call to run it. All terms must match."
        )

    # The facade IS the default door, so an unannotated facade swallows every readOnlyHint the
    # plane tools carry — a client sees three bare tools whichever of 906 rides through them.
    # These two only read the local catalog: readOnlyHint=True. proximo_call (server.py) is
    # False — it can dispatch a mutation, and a hint cannot vary per call (annotations ride
    # tools/list, which is static; nothing in a tools/call result carries them).
    @server_mcp.tool(description=find_tools_doc, **tool_annotations_kwargs(read_only=True))
    def proximo_find_tools(query: str, limit: int = 25) -> list[dict] | dict:
        # L5: a bare [] on a no-match query reads as a dead end and invites the model to force a
        # near-miss tool or fabricate a name. On no match, return an explicit signal + what to do
        # next instead (matches are still the plain list, so a hit path is unchanged).
        results = lean.search_tools(catalog, query, limit=limit)
        if not results:
            return {"matches": [], "note": (
                f"No tool matched {query!r}. Try broader or different terms; Proximo may simply "
                "not have this capability. If you already know the exact tool name, call it with "
                "proximo_call(tool=..., arguments=...).")}
        return results

    @server_mcp.tool(**tool_annotations_kwargs(read_only=True))
    def proximo_tool_schema(name: str) -> dict:
        """Full description + JSON input schema for one tool found via proximo_find_tools."""
        return lean.tool_schema(catalog, name)

    # THE READ DOOR (2026-08-20 external report: "the client can't tell a status read from a
    # power cycle"). proximo_call's only honest static hint is readOnlyHint=False, so in this
    # mode a client's permission policy must treat every ride through it as a possible mutation.
    # This door's True hint is an ENFORCED promise, not a label: the verdict comes from the SAME
    # leading marker that emits every readOnlyHint (lean.read_only_marker), and anything that is
    # not True — a MUTATION tool, an unmarked tool, and proximo_call itself (the laundering
    # loophole) — refuses BEFORE dispatch. Same reach as proximo_call (the full pre-prune
    # catalog), same single funnel (dispatch_tool); unknown names fall through to dispatch_tool's
    # own fail-closed did-you-mean.
    @server_mcp.tool(**tool_annotations_kwargs(read_only=True))
    async def proximo_read(tool: str, arguments: dict | None = None) -> Any:
        """READ-ONLY: run a read-only Proximo tool by exact name; refuses anything that can
        mutate (use proximo_call for those). Same flow: get the shape from proximo_tool_schema
        first."""
        resolved = lean.resolve_alias(tool)
        full = escape_catalog(server_mcp)
        target = full.get(resolved)
        if target is not None:
            # Tool.description IS fn.__doc__ for every tool today (no decorator passes an
            # explicit description= override, and the SDK copies the raw docstring), so this
            # reads the same bytes the hint derivation read at decoration time. If a tool ever
            # gains a description= override, keep its leading marker in agreement with the
            # docstring's — a split here would let the client's hint and this door disagree.
            desc = getattr(target, "description", None) or getattr(
                getattr(target, "fn", None), "__doc__", None)
            verdict = lean.read_only_marker(desc)
            if verdict is not True:
                why = ("a MUTATION tool" if verdict is False
                       else "not marked READ-ONLY, so it is refused fail-closed")
                raise ProximoError(
                    f"proximo_read refuses {resolved!r}: {why}. This door only runs read-only "
                    f"tools; run it with proximo_call(tool={resolved!r}, arguments=...) instead."
                )
        return await dispatch_tool(server_mcp=server_mcp, catalog=full,
                                   name=tool, arguments=arguments or {})

    # proximo_call is NOT redefined here. It is a module-level tool in _ALWAYS_REGISTERED, so it
    # is already resident, and it dispatches from FULL_CATALOG rather than this narrowed snapshot.
    # A facade-local redefinition would collide by name (ToolManager.add_tool returns the existing
    # tool and only WARNS), so the shadow would be silent, and it would re-narrow reachability to
    # exactly the set the escape hatch exists to see past.
    facade = {"proximo_find_tools", "proximo_tool_schema", "proximo_call", "proximo_read"}
    if recall_resident:
        facade.add("proximo_recall")
    keep = facade | set(_ALWAYS_REGISTERED)
    for name in [n for n in server_mcp._tool_manager._tools if n not in keep]:
        server_mcp.remove_tool(name)
    print(f"proximo: lean mode — {len(facade)} facade tools registered"
          f"{' (memory-first: proximo_recall resident)' if recall_resident else ''}, "
          f"{len(catalog)} searchable", file=sys.stderr)
    return catalog


def _unknown_tool_error(name: str) -> str:
    """The message for a direct tools/call naming a tool this server does not have resident. A REAL
    tool that is merely non-resident (the dynamic door lists only the facade) gets a precise pointer
    to proximo_call; a fabricated verb-order guess resolves through the alias map first; anything
    else gets did-you-mean over the full catalog. Keeps the lowercase 'unknown tool' substring the
    governed/lean faces already return, so error-matching stays uniform."""
    real = lean.resolve_alias(name)
    if real in FULL_CATALOG:
        return (f"{name!r} is not a resident tool on this server (the dynamic door lists only the "
                f"facade); call it with proximo_call(tool={real!r}, arguments=...), or search with "
                "proximo_find_tools.")
    near = difflib.get_close_matches(name, FULL_CATALOG, n=3, cutoff=0.6)
    hint = f" — did you mean: {', '.join(near)}" if near else ""
    return (f"unknown tool {name!r}{hint}. Reach any Proximo tool by name via "
            "proximo_call(tool=..., arguments=...); search the catalog with proximo_find_tools.")
