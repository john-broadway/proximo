"""APT plane: PMG patch-visibility + repository governance (Wave 1b, 2026-07-15).

Split out as its own module (not folded into pmg_mail.py or pmg_rules.py) since APT patch/repo
management is a distinct concern from mail routing/quarantine and RuleDB objects — mirrors the
plane-per-module convention pve_apt.py established for PVE (see its module docstring). See
proximo/server.py's module docstring for the funnel these wrappers depend on.

HONESTY LINE, shipped in every docstring below: Proxmox's API deliberately does not expose
upgrade execution; the upgrade itself happens at your console. This tool governs visibility and
repo config only.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pmg import (
    apt_changelog as pmg_apt_changelog_op,
)
from proximo.pmg import (
    apt_repositories_get as pmg_apt_repositories_get_op,
)
from proximo.pmg import (
    apt_repository_add as pmg_apt_repository_add_op,
)
from proximo.pmg import (
    apt_repository_set as pmg_apt_repository_set_op,
)
from proximo.pmg import (
    apt_update_refresh as pmg_apt_update_refresh_op,
)
from proximo.pmg import (
    apt_updates_list as pmg_apt_updates_list_op,
)
from proximo.pmg import (
    apt_versions as pmg_apt_versions_op,
)
from proximo.pmg import (
    plan_apt_repository_add as pmg_plan_apt_repository_add,
)
from proximo.pmg import (
    plan_apt_repository_set as pmg_plan_apt_repository_set,
)
from proximo.pmg import (
    plan_apt_update_refresh as pmg_plan_apt_update_refresh,
)
from proximo.server import (
    _audited,
    _plan,
    run_governed,
    tool,
)

# --- Reads ---


@tool()
def pmg_apt_updates_list(
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
) -> list[dict]:
    """READ-ONLY: list available package updates (cached apt index) on a PMG node.

    GET /nodes/{node}/apt/update. Smoke-confirm: shape not live-verified. Proxmox's API
    deliberately does not expose upgrade execution; the upgrade itself happens at your console.
    This tool governs visibility only. To refresh this list first use pmg_apt_update_refresh.
    Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    return _audited("pmg_apt_updates_list", f"pmg/{n}/apt/update",
                    lambda: pmg_apt_updates_list_op(pmg, n))


@tool()
def pmg_apt_changelog(
    name: Annotated[str, Field(description="Package name to fetch the changelog for (e.g. as listed by pmg_apt_updates_list).")],
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
    version: Annotated[str | None, Field(description="Specific package version to fetch the changelog for; omit for the latest available.")] = None,
) -> str:
    """READ-ONLY: get a package's changelog text on a PMG node.

    GET /nodes/{node}/apt/changelog?name=…[&version=…]. Smoke-confirm: shape not live-verified.
    The returned text is UPSTREAM/package-maintainer-authored (not Proxmox-authored) —
    classified ADVERSARIAL content (taint.ADVERSARIAL_TOOLS), like pve_apt_changelog and
    pbs_apt_changelog. Proxmox's API deliberately does not expose upgrade execution; the upgrade
    itself happens at your console. This tool governs visibility only. Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    return _audited("pmg_apt_changelog", f"pmg/{n}/apt/changelog:{name}",
                    lambda: pmg_apt_changelog_op(pmg, name, n, version))


@tool()
def pmg_apt_repositories_get(
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
) -> dict:
    """READ-ONLY: get the current APT repository configuration of a PMG node.

    GET /nodes/{node}/apt/repositories. Smoke-confirm: shape not live-verified — expected
    {files, errors, digest, infos, standard-repos}. `files[].path` + entry index are the
    coordinates pmg_apt_repository_set needs; `standard-repos[].handle` is what
    pmg_apt_repository_add needs. Proxmox's API deliberately does not expose upgrade execution;
    the upgrade itself happens at your console. This tool governs visibility and repo config
    only. Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    return _audited("pmg_apt_repositories_get", f"pmg/{n}/apt/repositories",
                    lambda: pmg_apt_repositories_get_op(pmg, n))


@tool()
def pmg_apt_versions(
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
) -> list[dict]:
    """READ-ONLY: get installed versions of important Proxmox packages on a PMG node.

    GET /nodes/{node}/apt/versions. Smoke-confirm: shape not live-verified. Proxmox's API
    deliberately does not expose upgrade execution; the upgrade itself happens at your console.
    This tool governs visibility only. Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    return _audited("pmg_apt_versions", f"pmg/{n}/apt/versions",
                    lambda: pmg_apt_versions_op(pmg, n))


# --- Mutations ---


@tool()
def pmg_apt_update_refresh(
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
    notify: Annotated[bool | None, Field(description="If True, ask PMG to send a notification email about newly available packages.")] = None,
    quiet: Annotated[bool | None, Field(description="If True, ask PMG to omit progress output suitable only for interactive logging.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the index refresh.")] = False,
) -> dict:
    """MUTATION: resynchronize the APT package index on a PMG node (apt-get update).

    RISK_LOW: no package state change — refreshes the local index cache only. Proxmox's API
    deliberately does not expose upgrade execution; the upgrade itself happens at your console.
    This tool governs visibility only — it does NOT install or upgrade any package. Idempotent —
    safe to re-run any time. Dry-run by default (returns a PLAN); confirm=True executes (POST,
    Smoke-confirm) and returns {"status": "submitted"|"ok", "result": <task id | None>}.
    Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    tgt = f"pmg/{n}/apt/update"
    plan = _plan("pmg_apt_update_refresh", tgt,
                 lambda: pmg_plan_apt_update_refresh(n, notify, quiet))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # apt_update_refresh() is documented "Returns a task identifier" but pmg.py types it
    # `str | None` defensively (same honesty posture as pve_apt_update_refresh /
    # pbs_apt_update_refresh) — a fixed outcome="submitted" would falsely claim an in-flight
    # task if PMG ever answers synchronously. _audited()'s callable-outcome form resolves the
    # honest label from the actual result.
    return _audited("pmg_apt_update_refresh", tgt,
                    lambda: pmg_apt_update_refresh_op(pmg, n, notify, quiet),
                    mutation=True, outcome=lambda result: "ok" if result is None else "submitted",
                    detail={"confirmed": True,
                            **({"notify": notify} if notify is not None else {}),
                            **({"quiet": quiet} if quiet is not None else {})})


@tool()
def pmg_apt_repository_set(
    path: Annotated[str, Field(description="Absolute path of the sources file containing the repository entry (as returned by pmg_apt_repositories_get).")],
    index: Annotated[int, Field(description="0-based index of the repository entry within that file (as returned by pmg_apt_repositories_get).")],
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
    enabled: Annotated[bool | None, Field(description="Set the entry's enabled state; omit to leave the enabled state unchanged.")] = None,
    digest: Annotated[str | None, Field(description="Expected content digest of the repositories file, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: enable/disable one APT repository entry on a PMG node, by file path + index.

    RISK_MEDIUM: changes where packages come from — affects the NEXT upgrade's package
    provenance. CAPTURE: reads current repository state before planning (also readable directly
    via pmg_apt_repositories_get); if unreadable -> complete=False. Proxmox's API deliberately
    does not expose upgrade execution; the upgrade itself happens at your console. This tool
    governs repo config only. Dry-run by default (returns a PLAN); confirm=True executes (POST,
    Smoke-confirm) and returns {"status": "ok", "result": None}. Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    tgt = f"pmg/{n}/apt/repositories:{path}#{index}"
    return run_governed(
        "pmg_apt_repository_set", tgt,
        plan=lambda: pmg_plan_apt_repository_set(pmg, path, index, n, enabled, digest),
        execute=lambda: pmg_apt_repository_set_op(pmg, path, index, n, enabled, digest),
        confirm=confirm, detail={"path": path, "index": index})


@tool()
def pmg_apt_repository_add(
    handle: Annotated[str, Field(description="Handle identifying the standard repository to add (as returned by pmg_apt_repositories_get's standard-repos list, e.g. 'no-subscription').")],
    node: Annotated[str | None, Field(description="PMG node name; defaults to the configured node if omitted.")] = None,
    digest: Annotated[str | None, Field(description="Expected content digest of the repositories file, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the addition.")] = False,
) -> dict:
    """MUTATION: add a standard repository to the configuration on a PMG node.

    RISK_MEDIUM: adds a new package source — affects the NEXT upgrade's package provenance.
    CAPTURE: reads current repository state before planning (also readable directly via
    pmg_apt_repositories_get); if unreadable -> complete=False. No automatic revert: removing an
    added repository requires pmg_apt_repository_set to disable the resulting entry (there is no
    repository-delete endpoint). Proxmox's API deliberately does not expose upgrade execution;
    the upgrade itself happens at your console. This tool governs repo config only. Dry-run by
    default (returns a PLAN); confirm=True executes (PUT, Smoke-confirm) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PMG_* config.
    """
    cfg, pmg = _proximo_server._pmg()
    n = node or cfg.node
    tgt = f"pmg/{n}/apt/repositories:{handle}"
    return run_governed(
        "pmg_apt_repository_add", tgt,
        plan=lambda: pmg_plan_apt_repository_add(pmg, handle, n, digest),
        execute=lambda: pmg_apt_repository_add_op(pmg, handle, n, digest),
        confirm=confirm, detail={"handle": handle})
