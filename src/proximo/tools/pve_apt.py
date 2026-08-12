"""APT plane: PVE patch-visibility + repository governance (Wave 1a, 2026-07-15).

Split out as its own module (not folded into pve_node.py) since APT patch/repo management is a
distinct concern from node lifecycle (disks/storage/time/hosts/dns/certs/bulk-power) — mirrors
the existing plane-per-module convention (disk_ops.py+pve_node.py, cloudinit.py+pve_guest.py,
hw_mappings.py+pve_observability.py, ...). See proximo/server.py's module docstring for the
funnel these wrappers depend on.

HONESTY LINE, shipped in every docstring below: Proxmox's API deliberately does not expose
upgrade execution; the upgrade itself happens at your console. This tool governs visibility and
repo config only.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.apt import (
    plan_apt_repository_add,
    plan_apt_repository_set,
    plan_apt_update_refresh,
)
from proximo.server import (
    _audited,
    _plan,
    run_governed,
    tool,
)

# --- Reads ---


@tool()
def pve_apt_updates_list(
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> list[dict]:
    """READ-ONLY: list available package updates (cached apt index) on a PVE node.

    GET /nodes/{node}/apt/update. Smoke-confirm: shape not live-verified — expected per-package
    dicts (Package/Title/Description/Origin/Version/OldVersion/Priority/Section/Arch). Proxmox's
    API deliberately does not expose upgrade execution; the upgrade itself happens at your
    console. This tool governs visibility only. To refresh this list first use
    pve_apt_update_refresh.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_apt_updates_list", node or cfg.node,
                    lambda: api.apt_updates_list(node))


@tool()
def pve_apt_changelog(
    name: Annotated[str, Field(description="Package name to fetch the changelog for (e.g. as listed by pve_apt_updates_list).")],
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
    version: Annotated[str | None, Field(description="Specific package version to fetch the changelog for; omit for the latest available.")] = None,
) -> str:
    """READ-ONLY: get a package's changelog text on a PVE node.

    GET /nodes/{node}/apt/changelog?name=…[&version=…]. Smoke-confirm: shape not live-verified.
    The returned text is UPSTREAM/package-maintainer-authored (not Proxmox-authored) — classified
    ADVERSARIAL content (taint.ADVERSARIAL_TOOLS), unlike the other six pve_apt_* tools. Proxmox's
    API deliberately does not expose upgrade execution; the upgrade itself happens at your
    console. This tool governs visibility only.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_apt_changelog", f"{node or cfg.node}/apt/changelog:{name}",
                    lambda: api.apt_changelog(name, node, version))


@tool()
def pve_apt_repositories_get(
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> dict:
    """READ-ONLY: get the current APT repository configuration of a PVE node.

    GET /nodes/{node}/apt/repositories. Smoke-confirm: shape not live-verified — expected
    {files, errors, digest, infos, standard-repos}. `files[].path` + entry index are the
    coordinates pve_apt_repository_set needs; `standard-repos[].handle` is what
    pve_apt_repository_add needs. Proxmox's API deliberately does not expose upgrade execution;
    the upgrade itself happens at your console. This tool governs visibility and repo config only.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_apt_repositories_get", node or cfg.node,
                    lambda: api.apt_repositories_get(node))


@tool()
def pve_apt_versions(
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> list[dict]:
    """READ-ONLY: get installed versions of important Proxmox packages on a PVE node.

    GET /nodes/{node}/apt/versions. Smoke-confirm: shape not live-verified — expected per-package
    dicts (Package/Version/OldVersion + CurrentState/RunningKernel/ManagerVersion). Proxmox's API
    deliberately does not expose upgrade execution; the upgrade itself happens at your console.
    This tool governs visibility only.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_apt_versions", node or cfg.node,
                    lambda: api.apt_versions(node))


# --- Mutations ---


@tool()
def pve_apt_update_refresh(
    node: Annotated[str | None, Field(description="PVE node name to refresh; defaults to the configured node if omitted.")] = None,
    notify: Annotated[bool | None, Field(description="If True, ask Proxmox to send a notification email about newly available packages.")] = None,
    quiet: Annotated[bool | None, Field(description="If True, ask Proxmox to omit progress output suitable only for interactive logging.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the index refresh.")] = False,
) -> dict:
    """MUTATION: resynchronize the APT package index on a PVE node (apt-get update).

    RISK_LOW: no package state change — refreshes the local index cache only. Proxmox's API
    deliberately does not expose upgrade execution; the upgrade itself happens at your console.
    This tool governs visibility only — it does NOT install or upgrade any package. Idempotent —
    safe to re-run any time. Dry-run by default (returns a PLAN); confirm=True executes (POST,
    Smoke-confirm) and returns {"status": "submitted"|"ok", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/apt/update"
    plan = _plan("pve_apt_update_refresh", tgt,
                 lambda: plan_apt_update_refresh(node, notify, quiet))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # apt_update_refresh() is documented "Returns a task UPID" but backends.py types it
    # `str | None` defensively (same honesty posture as node_startall/_stopall/_migrateall) — a
    # fixed outcome="submitted" would falsely claim an in-flight task if PVE ever answers
    # synchronously. _audited()'s callable-outcome form resolves the honest label from the
    # actual result.
    return _audited("pve_apt_update_refresh", tgt,
                    lambda: api.apt_update_refresh(node, notify, quiet),
                    mutation=True, outcome=lambda result: "ok" if result is None else "submitted",
                    detail={"confirmed": True,
                            **({"notify": notify} if notify is not None else {}),
                            **({"quiet": quiet} if quiet is not None else {})})


@tool()
def pve_apt_repository_set(
    path: Annotated[str, Field(description="Absolute path of the sources file containing the repository entry (as returned by pve_apt_repositories_get).")],
    index: Annotated[int, Field(description="0-based index of the repository entry within that file (as returned by pve_apt_repositories_get).")],
    node: Annotated[str | None, Field(description="PVE node name to configure; defaults to the configured node if omitted.")] = None,
    enabled: Annotated[bool | None, Field(description="Set the entry's enabled state; omit to leave the enabled state unchanged.")] = None,
    digest: Annotated[str | None, Field(description="Expected content digest of the repositories file, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: enable/disable one APT repository entry on a PVE node, by file path + index.

    RISK_MEDIUM: changes where packages come from — affects the NEXT upgrade's package
    provenance. CAPTURE: reads current repository state before planning (also readable directly
    via pve_apt_repositories_get); if unreadable -> complete=False. Proxmox's API deliberately
    does not expose upgrade execution; the upgrade itself happens at your console. This tool
    governs repo config only. Dry-run by default (returns a PLAN); confirm=True executes (POST,
    Smoke-confirm) and returns {"status": "ok", "result": None}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/apt/repositories:{path}#{index}"
    return run_governed(
        "pve_apt_repository_set", tgt,
        plan=lambda: plan_apt_repository_set(api, path, index, node, enabled, digest),
        execute=lambda: api.apt_repository_set(path, index, node, enabled, digest),
        confirm=confirm, detail={"path": path, "index": index})


@tool()
def pve_apt_repository_add(
    handle: Annotated[str, Field(description="Handle identifying the standard repository to add (as returned by pve_apt_repositories_get's standard-repos list, e.g. 'no-subscription').")],
    node: Annotated[str | None, Field(description="PVE node name to configure; defaults to the configured node if omitted.")] = None,
    digest: Annotated[str | None, Field(description="Expected content digest of the repositories file, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the addition.")] = False,
) -> dict:
    """MUTATION: add a standard repository to the configuration on a PVE node.

    RISK_MEDIUM: adds a new package source — affects the NEXT upgrade's package provenance.
    CAPTURE: reads current repository state before planning (also readable directly via
    pve_apt_repositories_get); if unreadable -> complete=False. No automatic revert: removing an
    added repository requires pve_apt_repository_set to disable the resulting entry (there is no
    repository-delete endpoint). Proxmox's API deliberately does not expose upgrade execution;
    the upgrade itself happens at your console. This tool governs repo config only. Dry-run by
    default (returns a PLAN); confirm=True executes (PUT, Smoke-confirm) and returns
    {"status": "ok", "result": None}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/apt/repositories:{handle}"
    return run_governed(
        "pve_apt_repository_add", tgt,
        plan=lambda: plan_apt_repository_add(api, handle, node, digest),
        execute=lambda: api.apt_repository_add(handle, node, digest),
        confirm=confirm, detail={"handle": handle})
