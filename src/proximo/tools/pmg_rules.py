"""PMG ruledb rules engine: who/what/when/action group + object CRUD, rule CRUD, and rule<->object attach/detach.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pmg import (
    action_bcc_create as pmg_action_bcc_create_op,
)
from proximo.pmg import (
    action_bcc_get as pmg_action_bcc_get_op,
)
from proximo.pmg import (
    action_bcc_update as pmg_action_bcc_update_op,
)
from proximo.pmg import (
    action_delete as pmg_action_delete_op,
)
from proximo.pmg import (
    action_disclaimer_create as pmg_action_disclaimer_create_op,
)
from proximo.pmg import (
    action_disclaimer_get as pmg_action_disclaimer_get_op,
)
from proximo.pmg import (
    action_disclaimer_update as pmg_action_disclaimer_update_op,
)
from proximo.pmg import (
    action_field_create as pmg_action_field_create_op,
)
from proximo.pmg import (
    action_field_get as pmg_action_field_get_op,
)
from proximo.pmg import (
    action_field_update as pmg_action_field_update_op,
)
from proximo.pmg import (
    action_notification_create as pmg_action_notification_create_op,
)
from proximo.pmg import (
    action_notification_get as pmg_action_notification_get_op,
)
from proximo.pmg import (
    action_notification_update as pmg_action_notification_update_op,
)
from proximo.pmg import (
    action_removeattachments_create as pmg_action_removeattachments_create_op,
)
from proximo.pmg import (
    action_removeattachments_get as pmg_action_removeattachments_get_op,
)
from proximo.pmg import (
    action_removeattachments_update as pmg_action_removeattachments_update_op,
)
from proximo.pmg import (
    plan_action_bcc_create as pmg_plan_action_bcc_create,
)
from proximo.pmg import (
    plan_action_bcc_update as pmg_plan_action_bcc_update,
)
from proximo.pmg import (
    plan_action_delete as pmg_plan_action_delete,
)
from proximo.pmg import (
    plan_action_disclaimer_create as pmg_plan_action_disclaimer_create,
)
from proximo.pmg import (
    plan_action_disclaimer_update as pmg_plan_action_disclaimer_update,
)
from proximo.pmg import (
    plan_action_field_create as pmg_plan_action_field_create,
)
from proximo.pmg import (
    plan_action_field_update as pmg_plan_action_field_update,
)
from proximo.pmg import (
    plan_action_notification_create as pmg_plan_action_notification_create,
)
from proximo.pmg import (
    plan_action_notification_update as pmg_plan_action_notification_update,
)
from proximo.pmg import (
    plan_action_removeattachments_create as pmg_plan_action_removeattachments_create,
)
from proximo.pmg import (
    plan_action_removeattachments_update as pmg_plan_action_removeattachments_update,
)
from proximo.pmg import (
    plan_ruledb_reset as pmg_plan_ruledb_reset,
)
from proximo.pmg import (
    plan_ruledb_rule_action_attach as pmg_plan_ruledb_rule_action_attach,
)
from proximo.pmg import (
    plan_ruledb_rule_action_detach as pmg_plan_ruledb_rule_action_detach,
)
from proximo.pmg import (
    plan_ruledb_rule_create as pmg_plan_ruledb_rule_create,
)
from proximo.pmg import (
    plan_ruledb_rule_delete as pmg_plan_ruledb_rule_delete,
)
from proximo.pmg import (
    plan_ruledb_rule_from_attach as pmg_plan_ruledb_rule_from_attach,
)
from proximo.pmg import (
    plan_ruledb_rule_from_detach as pmg_plan_ruledb_rule_from_detach,
)
from proximo.pmg import (
    plan_ruledb_rule_to_attach as pmg_plan_ruledb_rule_to_attach,
)
from proximo.pmg import (
    plan_ruledb_rule_to_detach as pmg_plan_ruledb_rule_to_detach,
)
from proximo.pmg import (
    plan_ruledb_rule_update as pmg_plan_ruledb_rule_update,
)
from proximo.pmg import (
    plan_ruledb_rule_what_attach as pmg_plan_ruledb_rule_what_attach,
)
from proximo.pmg import (
    plan_ruledb_rule_what_detach as pmg_plan_ruledb_rule_what_detach,
)
from proximo.pmg import (
    plan_ruledb_rule_when_attach as pmg_plan_ruledb_rule_when_attach,
)
from proximo.pmg import (
    plan_ruledb_rule_when_detach as pmg_plan_ruledb_rule_when_detach,
)
from proximo.pmg import (
    plan_what_group_create as pmg_plan_what_group_create,
)
from proximo.pmg import (
    plan_what_group_delete as pmg_plan_what_group_delete,
)
from proximo.pmg import (
    plan_what_group_update as pmg_plan_what_group_update,
)
from proximo.pmg import (
    plan_what_object_add as pmg_plan_what_object_add,
)
from proximo.pmg import (
    plan_what_object_delete as pmg_plan_what_object_delete,
)
from proximo.pmg import (
    plan_what_object_update as pmg_plan_what_object_update,
)
from proximo.pmg import (
    plan_when_group_create as pmg_plan_when_group_create,
)
from proximo.pmg import (
    plan_when_group_delete as pmg_plan_when_group_delete,
)
from proximo.pmg import (
    plan_when_group_update as pmg_plan_when_group_update,
)
from proximo.pmg import (
    plan_when_object_add as pmg_plan_when_object_add,
)
from proximo.pmg import (
    plan_when_object_delete as pmg_plan_when_object_delete,
)
from proximo.pmg import (
    plan_when_object_update as pmg_plan_when_object_update,
)
from proximo.pmg import (
    plan_who_group_create as pmg_plan_who_group_create,
)
from proximo.pmg import (
    plan_who_group_delete as pmg_plan_who_group_delete,
)
from proximo.pmg import (
    plan_who_group_update as pmg_plan_who_group_update,
)
from proximo.pmg import (
    plan_who_object_add as pmg_plan_who_object_add,
)
from proximo.pmg import (
    plan_who_object_delete as pmg_plan_who_object_delete,
)
from proximo.pmg import (
    plan_who_object_update as pmg_plan_who_object_update,
)
from proximo.pmg import (
    ruledb_reset as pmg_ruledb_reset_op,
)
from proximo.pmg import (
    ruledb_rule_action_attach as pmg_ruledb_rule_action_attach_op,
)
from proximo.pmg import (
    ruledb_rule_action_detach as pmg_ruledb_rule_action_detach_op,
)
from proximo.pmg import (
    ruledb_rule_action_groups_list as pmg_ruledb_rule_action_groups_list_op,
)
from proximo.pmg import (
    ruledb_rule_create as pmg_ruledb_rule_create_op,
)
from proximo.pmg import (
    ruledb_rule_delete as pmg_ruledb_rule_delete_op,
)
from proximo.pmg import (
    ruledb_rule_from_attach as pmg_ruledb_rule_from_attach_op,
)
from proximo.pmg import (
    ruledb_rule_from_detach as pmg_ruledb_rule_from_detach_op,
)
from proximo.pmg import (
    ruledb_rule_to_attach as pmg_ruledb_rule_to_attach_op,
)
from proximo.pmg import (
    ruledb_rule_to_detach as pmg_ruledb_rule_to_detach_op,
)
from proximo.pmg import (
    ruledb_rule_update as pmg_ruledb_rule_update_op,
)
from proximo.pmg import (
    ruledb_rule_what_attach as pmg_ruledb_rule_what_attach_op,
)
from proximo.pmg import (
    ruledb_rule_what_detach as pmg_ruledb_rule_what_detach_op,
)
from proximo.pmg import (
    ruledb_rule_when_attach as pmg_ruledb_rule_when_attach_op,
)
from proximo.pmg import (
    ruledb_rule_when_detach as pmg_ruledb_rule_when_detach_op,
)
from proximo.pmg import (
    what_group_create as pmg_what_group_create_op,
)
from proximo.pmg import (
    what_group_delete as pmg_what_group_delete_op,
)
from proximo.pmg import (
    what_group_update as pmg_what_group_update_op,
)
from proximo.pmg import (
    what_object_add as pmg_what_object_add_op,
)
from proximo.pmg import (
    what_object_delete as pmg_what_object_delete_op,
)
from proximo.pmg import (
    what_object_get as pmg_what_object_get_op,
)
from proximo.pmg import (
    what_object_update as pmg_what_object_update_op,
)
from proximo.pmg import (
    when_group_create as pmg_when_group_create_op,
)
from proximo.pmg import (
    when_group_delete as pmg_when_group_delete_op,
)
from proximo.pmg import (
    when_group_update as pmg_when_group_update_op,
)
from proximo.pmg import (
    when_object_add as pmg_when_object_add_op,
)
from proximo.pmg import (
    when_object_delete as pmg_when_object_delete_op,
)
from proximo.pmg import (
    when_object_get as pmg_when_object_get_op,
)
from proximo.pmg import (
    when_object_update as pmg_when_object_update_op,
)
from proximo.pmg import (
    who_group_create as pmg_who_group_create_op,
)
from proximo.pmg import (
    who_group_delete as pmg_who_group_delete_op,
)
from proximo.pmg import (
    who_group_update as pmg_who_group_update_op,
)
from proximo.pmg import (
    who_object_add as pmg_who_object_add_op,
)
from proximo.pmg import (
    who_object_delete as pmg_who_object_delete_op,
)
from proximo.pmg import (
    who_object_get as pmg_who_object_get_op,
)
from proximo.pmg import (
    who_object_update as pmg_who_object_update_op,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)


@tool()
def pmg_who_group_create(
    name: Annotated[str, Field(description="Name for the new 'who' object group.")],
    info: Annotated[str | None, Field(description="Optional free-text description of the group.")] = None,
    and_: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across group members; maps to API param 'and'.")] = None,
    invert: Annotated[bool | None, Field(description="If True, invert the group's match result.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a PMG RuleDB 'who' object group. Dry-run by default.

    Creates an empty group — add match objects with pmg_who_object_add; list existing groups with
    pmg_who_groups_list. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <new ogroup ID assigned by PMG>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/who"
    return run_governed(
        "pmg_who_group_create", tgt,
        plan=lambda: pmg_plan_who_group_create(name, info, and_, invert),
        execute=lambda: pmg_who_group_create_op(pmg, name, info, and_, invert),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_who_group_update(
    ogroup: Annotated[str, Field(description="Numeric 'who' object group ID (e.g. '2') from pmg_who_groups_list.")],
    name: Annotated[str | None, Field(description="New name for the group; omit to keep current value.")] = None,
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    and_: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across group members; maps to API param 'and'.")] = None,
    invert: Annotated[bool | None, Field(description="If True, invert the group's match result.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PMG RuleDB 'who' object group config. Dry-run by default.

    Renames or reconfigures the group itself; to change its match objects use
    pmg_who_object_add/pmg_who_object_update/pmg_who_object_delete. Only non-None fields are
    sent, others keep their current value. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/who/{ogroup}/config"
    return run_governed(
        "pmg_who_group_update", tgt,
        plan=lambda: pmg_plan_who_group_update(ogroup, name, info, and_, invert),
        execute=lambda: pmg_who_group_update_op(pmg, ogroup, name, info, and_, invert),
        confirm=confirm, detail={k: v for k, v in {"ogroup": ogroup, "name": name, "info": info, "and": and_, "invert": invert}.items() if v is not None})


@tool()
def pmg_who_group_delete(
    ogroup: Annotated[str, Field(description="Numeric 'who' object group ID (e.g. '2') from pmg_who_groups_list.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PMG RuleDB 'who' object group. Dry-run by default.

    Irreversible — also removes every object within the group. List groups first with
    pmg_who_groups_list; to remove just one object instead use pmg_who_object_delete.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/who/{ogroup}"
    return run_governed(
        "pmg_who_group_delete", tgt,
        plan=lambda: pmg_plan_who_group_delete(ogroup),
        execute=lambda: pmg_who_group_delete_op(pmg, ogroup),
        confirm=confirm, detail={"ogroup": ogroup})


@tool()
def pmg_what_group_create(
    name: Annotated[str, Field(description="Name for the new 'what' object group.")],
    info: Annotated[str | None, Field(description="Optional free-text description of the group.")] = None,
    and_: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across group members; maps to API param 'and'.")] = None,
    invert: Annotated[bool | None, Field(description="If True, invert the group's match result.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a PMG RuleDB 'what' object group. Dry-run by default.

    Creates an empty group — add match objects with pmg_what_object_add; list existing groups with
    pmg_what_groups_list. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <new ogroup ID assigned by PMG>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/what"
    return run_governed(
        "pmg_what_group_create", tgt,
        plan=lambda: pmg_plan_what_group_create(name, info, and_, invert),
        execute=lambda: pmg_what_group_create_op(pmg, name, info, and_, invert),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_what_group_update(
    ogroup: Annotated[str, Field(description="Numeric 'what' object group ID (e.g. '8') from pmg_what_groups_list.")],
    name: Annotated[str | None, Field(description="New name for the group; omit to keep current value.")] = None,
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    and_: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across group members; maps to API param 'and'.")] = None,
    invert: Annotated[bool | None, Field(description="If True, invert the group's match result.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PMG RuleDB 'what' object group config. Dry-run by default.

    Renames or reconfigures the group itself; to change its match objects use
    pmg_what_object_add/pmg_what_object_update/pmg_what_object_delete. Only non-None fields are
    sent, others keep their current value. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/what/{ogroup}/config"
    return run_governed(
        "pmg_what_group_update", tgt,
        plan=lambda: pmg_plan_what_group_update(ogroup, name, info, and_, invert),
        execute=lambda: pmg_what_group_update_op(pmg, ogroup, name, info, and_, invert),
        confirm=confirm, detail={k: v for k, v in {"ogroup": ogroup, "name": name, "info": info, "and": and_, "invert": invert}.items() if v is not None})


@tool()
def pmg_what_group_delete(
    ogroup: Annotated[str, Field(description="Numeric 'what' object group ID (e.g. '8') from pmg_what_groups_list.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PMG RuleDB 'what' object group. Dry-run by default.

    Irreversible — also removes every object within the group. List groups first with
    pmg_what_groups_list; to remove just one object instead use pmg_what_object_delete.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/what/{ogroup}"
    return run_governed(
        "pmg_what_group_delete", tgt,
        plan=lambda: pmg_plan_what_group_delete(ogroup),
        execute=lambda: pmg_what_group_delete_op(pmg, ogroup),
        confirm=confirm, detail={"ogroup": ogroup})


@tool()
def pmg_when_group_create(
    name: Annotated[str, Field(description="Name for the new 'when' object group.")],
    info: Annotated[str | None, Field(description="Optional free-text description of the group.")] = None,
    and_: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across group members; maps to API param 'and'.")] = None,
    invert: Annotated[bool | None, Field(description="If True, invert the group's match result.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a PMG RuleDB 'when' object group. Dry-run by default.

    Creates an empty group — add timeframe objects with pmg_when_object_add; list existing groups
    with pmg_when_groups_list. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <new ogroup ID assigned by PMG>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/when"
    return run_governed(
        "pmg_when_group_create", tgt,
        plan=lambda: pmg_plan_when_group_create(name, info, and_, invert),
        execute=lambda: pmg_when_group_create_op(pmg, name, info, and_, invert),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_when_group_update(
    ogroup: Annotated[str, Field(description="Numeric 'when' object group ID (e.g. '4') from pmg_when_groups_list.")],
    name: Annotated[str | None, Field(description="New name for the group; omit to keep current value.")] = None,
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    and_: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across group members; maps to API param 'and'.")] = None,
    invert: Annotated[bool | None, Field(description="If True, invert the group's match result.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PMG RuleDB 'when' object group config. Dry-run by default.

    Renames or reconfigures the group itself; to change its timeframes use
    pmg_when_object_add/pmg_when_object_update/pmg_when_object_delete. Only non-None fields are
    sent, others keep their current value. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/when/{ogroup}/config"
    return run_governed(
        "pmg_when_group_update", tgt,
        plan=lambda: pmg_plan_when_group_update(ogroup, name, info, and_, invert),
        execute=lambda: pmg_when_group_update_op(pmg, ogroup, name, info, and_, invert),
        confirm=confirm, detail={k: v for k, v in {"ogroup": ogroup, "name": name, "info": info, "and": and_, "invert": invert}.items() if v is not None})


@tool()
def pmg_when_group_delete(
    ogroup: Annotated[str, Field(description="Numeric 'when' object group ID (e.g. '4') from pmg_when_groups_list.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PMG RuleDB 'when' object group. Dry-run by default.

    Irreversible — also removes every timeframe within the group. List groups first with
    pmg_when_groups_list; to remove just one timeframe instead use pmg_when_object_delete.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/when/{ogroup}"
    return run_governed(
        "pmg_when_group_delete", tgt,
        plan=lambda: pmg_plan_when_group_delete(ogroup),
        execute=lambda: pmg_when_group_delete_op(pmg, ogroup),
        confirm=confirm, detail={"ogroup": ogroup})


@tool()
def pmg_who_object_add(
    ogroup: Annotated[str, Field(description="Numeric 'who' object group ID (e.g. '2') from pmg_who_groups_list.")],
    type_: Annotated[str, Field(description="Object type: email|domain|regex|ip|network|ldap|ldapuser — selects which sub-path/fields apply.")],
    email: Annotated[str | None, Field(description="Email address to match; required when type_='email'.")] = None,
    domain: Annotated[str | None, Field(description="Domain to match; required when type_='domain'.")] = None,
    regex: Annotated[str | None, Field(description="Regex pattern to match; required when type_='regex'.")] = None,
    ip: Annotated[str | None, Field(description="IP address to match; required when type_='ip'.")] = None,
    cidr: Annotated[str | None, Field(description="CIDR network to match; required when type_='network'.")] = None,
    mode: Annotated[str | None, Field(description="LDAP lookup mode; used when type_='ldap'.")] = None,
    profile: Annotated[str | None, Field(description="LDAP profile name; used for type_='ldap'; REQUIRED (with account) when type_='ldapuser'.")] = None,
    group: Annotated[str | None, Field(description="LDAP group name; used when type_='ldap'.")] = None,
    account: Annotated[str | None, Field(description="LDAP user account name; required when type_='ldapuser' (Wave 8a).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): add an object to a PMG RuleDB 'who' object group. Dry-run by default.

    To create the group first use pmg_who_group_create; list its objects with
    pmg_who_group_objects. If the group is already attached to a rule, the new object affects
    mail matching immediately. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/who/{ogroup}/{type_}"
    return run_governed(
        "pmg_who_object_add", tgt,
        plan=lambda: pmg_plan_who_object_add(
                     ogroup, type_,
                     email=email, domain=domain, regex=regex, ip=ip,
                     cidr=cidr, mode=mode, profile=profile, group=group, account=account,
                 ),
        execute=lambda: pmg_who_object_add_op(
                        pmg, ogroup, type_,
                        email=email, domain=domain, regex=regex, ip=ip,
                        cidr=cidr, mode=mode, profile=profile, group=group, account=account,
                    ),
        confirm=confirm, detail={"ogroup": ogroup, "type": type_})


@tool()
def pmg_who_object_update(
    ogroup: Annotated[str, Field(description="Numeric 'who' object group ID (e.g. '2') from pmg_who_groups_list.")],
    type_: Annotated[str, Field(description="Object type: email|domain|regex|ip|network|ldap|ldapuser — selects which sub-path/fields apply.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_who_group_objects.")],
    email: Annotated[str | None, Field(description="New email address; used when type_='email'.")] = None,
    domain: Annotated[str | None, Field(description="New domain; used when type_='domain'.")] = None,
    regex: Annotated[str | None, Field(description="New regex pattern; used when type_='regex'.")] = None,
    ip: Annotated[str | None, Field(description="New IP address; used when type_='ip'.")] = None,
    cidr: Annotated[str | None, Field(description="New CIDR network; used when type_='network'.")] = None,
    mode: Annotated[str | None, Field(description="LDAP lookup mode; used when type_='ldap'.")] = None,
    profile: Annotated[str | None, Field(description="LDAP profile name; used for type_='ldap'; REQUIRED (with account) when type_='ldapuser'.")] = None,
    group: Annotated[str | None, Field(description="LDAP group name; used when type_='ldap'.")] = None,
    account: Annotated[str | None, Field(description="New LDAP user account name; used when type_='ldapuser' (Wave 8a).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update an object in a PMG RuleDB 'who' object group. Dry-run by default.

    id_ comes from pmg_who_group_objects; type_ must match the object's existing type. Only
    non-None fields are sent, others keep their current value. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/who/{ogroup}/{type_}/{id_}"
    return run_governed(
        "pmg_who_object_update", tgt,
        plan=lambda: pmg_plan_who_object_update(
                     ogroup, type_, id_,
                     email=email, domain=domain, regex=regex, ip=ip,
                     cidr=cidr, mode=mode, profile=profile, group=group, account=account,
                 ),
        execute=lambda: pmg_who_object_update_op(
                        pmg, ogroup, type_, id_,
                        email=email, domain=domain, regex=regex, ip=ip,
                        cidr=cidr, mode=mode, profile=profile, group=group, account=account,
                    ),
        confirm=confirm, detail={k: v for k, v in {"ogroup": ogroup, "type": type_, "id": id_, "email": email, "domain": domain, "regex": regex, "ip": ip, "cidr": cidr, "mode": mode, "profile": profile, "group": group, "account": account}.items() if v is not None})


@tool()
def pmg_who_object_delete(
    ogroup: Annotated[str, Field(description="Numeric 'who' object group ID (e.g. '2') from pmg_who_groups_list.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_who_group_objects.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete an object from a PMG RuleDB 'who' object group. Dry-run by default.

    Irreversible. id_ comes from pmg_who_group_objects; to delete the whole group instead use
    pmg_who_group_delete. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/who/{ogroup}/objects/{id_}"
    return run_governed(
        "pmg_who_object_delete", tgt,
        plan=lambda: pmg_plan_who_object_delete(ogroup, id_),
        execute=lambda: pmg_who_object_delete_op(pmg, ogroup, id_),
        confirm=confirm, detail={"ogroup": ogroup, "id": id_})


@tool()
def pmg_who_object_get(
    ogroup: Annotated[str, Field(description="Numeric 'who' object group ID (e.g. '2') from pmg_who_groups_list.")],
    type_: Annotated[str, Field(description="Object type: email|domain|regex|ip|network|ldap|ldapuser — selects which sub-path applies.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_who_group_objects.")],
) -> dict:
    """READ-ONLY: get a PMG RuleDB 'who' object's settings. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: int} in the return for this endpoint; the real runtime response is presumably
    richer (type-specific fields like email/domain/account), not asserted here. ogroup/id_ are
    numeric ID strings from pmg_who_groups_list / pmg_who_group_objects.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_who_object_get", f"pmg/config/ruledb/who/{ogroup}/{type_}/{id_}",
                    lambda: pmg_who_object_get_op(pmg, ogroup, type_, id_))


# ---------------------------------------------------------------------------
# W5c: WHAT-object CRUD tools
# ---------------------------------------------------------------------------

@tool()
def pmg_what_object_add(
    ogroup: Annotated[str, Field(description="Numeric 'what' object group ID (e.g. '8') from pmg_what_groups_list.")],
    type_: Annotated[str, Field(description="Object type: contenttype|matchfield|spamfilter|virusfilter|filenamefilter|archivefilter|archivefilenamefilter.")],
    contenttype: Annotated[str | None, Field(description="MIME content type to match; used for type_='contenttype'/'archivefilter'.")] = None,
    only_content: Annotated[bool | None, Field(description="Match content only, not filename; maps to API param 'only-content'.")] = None,
    field: Annotated[str | None, Field(description="Mail header field name to match; used for type_='matchfield'.")] = None,
    value: Annotated[str | None, Field(description="Value/pattern to match against the field; used for type_='matchfield'.")] = None,
    top_part_only: Annotated[bool | None, Field(description="Restrict match to the top MIME part only; maps to API param 'top-part-only'.")] = None,
    spamlevel: Annotated[int | None, Field(description="Spam score threshold; used for type_='spamfilter'.")] = None,
    filename: Annotated[str | None, Field(description="Filename pattern to match; used for type_='filenamefilter'/'archivefilenamefilter'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): add an object to a PMG RuleDB 'what' object group. Dry-run by default.

    To create the group first use pmg_what_group_create; list its objects with
    pmg_what_group_objects. If the group is already attached to a rule, the new object affects
    mail matching immediately. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/what/{ogroup}/{type_}"
    return run_governed(
        "pmg_what_object_add", tgt,
        plan=lambda: pmg_plan_what_object_add(
                     ogroup, type_,
                     contenttype=contenttype, only_content=only_content,
                     field=field, value=value, top_part_only=top_part_only,
                     spamlevel=spamlevel, filename=filename,
                 ),
        execute=lambda: pmg_what_object_add_op(
                        pmg, ogroup, type_,
                        contenttype=contenttype, only_content=only_content,
                        field=field, value=value, top_part_only=top_part_only,
                        spamlevel=spamlevel, filename=filename,
                    ),
        confirm=confirm, detail={"ogroup": ogroup, "type": type_})


@tool()
def pmg_what_object_update(
    ogroup: Annotated[str, Field(description="Numeric 'what' object group ID (e.g. '8') from pmg_what_groups_list.")],
    type_: Annotated[str, Field(description="Object type: contenttype|matchfield|spamfilter|virusfilter|filenamefilter|archivefilter|archivefilenamefilter.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_what_group_objects.")],
    contenttype: Annotated[str | None, Field(description="New MIME content type; used for type_='contenttype'/'archivefilter'.")] = None,
    only_content: Annotated[bool | None, Field(description="Match content only, not filename; maps to API param 'only-content'.")] = None,
    field: Annotated[str | None, Field(description="Mail header field name to match; used for type_='matchfield'.")] = None,
    value: Annotated[str | None, Field(description="Value/pattern to match against the field; used for type_='matchfield'.")] = None,
    top_part_only: Annotated[bool | None, Field(description="Restrict match to the top MIME part only; maps to API param 'top-part-only'.")] = None,
    spamlevel: Annotated[int | None, Field(description="New spam score threshold; used for type_='spamfilter'.")] = None,
    filename: Annotated[str | None, Field(description="New filename pattern; used for type_='filenamefilter'/'archivefilenamefilter'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update an object in a PMG RuleDB 'what' object group. Dry-run by default.

    id_ comes from pmg_what_group_objects; type_ must match the object's existing type. Only
    non-None fields are sent, others keep their current value. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/what/{ogroup}/{type_}/{id_}"
    return run_governed(
        "pmg_what_object_update", tgt,
        plan=lambda: pmg_plan_what_object_update(
                     ogroup, type_, id_,
                     contenttype=contenttype, only_content=only_content,
                     field=field, value=value, top_part_only=top_part_only,
                     spamlevel=spamlevel, filename=filename,
                 ),
        execute=lambda: pmg_what_object_update_op(
                        pmg, ogroup, type_, id_,
                        contenttype=contenttype, only_content=only_content,
                        field=field, value=value, top_part_only=top_part_only,
                        spamlevel=spamlevel, filename=filename,
                    ),
        confirm=confirm, detail={k: v for k, v in {"ogroup": ogroup, "type": type_, "id": id_, "contenttype": contenttype, "only_content": only_content, "field": field, "value": value, "top_part_only": top_part_only, "spamlevel": spamlevel, "filename": filename}.items() if v is not None})


@tool()
def pmg_what_object_delete(
    ogroup: Annotated[str, Field(description="Numeric 'what' object group ID (e.g. '8') from pmg_what_groups_list.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_what_group_objects.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete an object from a PMG RuleDB 'what' object group. Dry-run by default.

    Irreversible. id_ comes from pmg_what_group_objects; to delete the whole group instead use
    pmg_what_group_delete. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/what/{ogroup}/objects/{id_}"
    return run_governed(
        "pmg_what_object_delete", tgt,
        plan=lambda: pmg_plan_what_object_delete(ogroup, id_),
        execute=lambda: pmg_what_object_delete_op(pmg, ogroup, id_),
        confirm=confirm, detail={"ogroup": ogroup, "id": id_})


@tool()
def pmg_what_object_get(
    ogroup: Annotated[str, Field(description="Numeric 'what' object group ID (e.g. '8') from pmg_what_groups_list.")],
    type_: Annotated[str, Field(description="Object type: contenttype|matchfield|spamfilter|virusfilter|filenamefilter|archivefilter|archivefilenamefilter.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_what_group_objects.")],
) -> dict:
    """READ-ONLY: get a PMG RuleDB 'what' object's settings. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: int} in the return for this endpoint; the real runtime response is presumably
    richer (type-specific fields), not asserted here. ogroup/id_ are numeric ID strings from
    pmg_what_groups_list / pmg_what_group_objects.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_what_object_get", f"pmg/config/ruledb/what/{ogroup}/{type_}/{id_}",
                    lambda: pmg_what_object_get_op(pmg, ogroup, type_, id_))


# ---------------------------------------------------------------------------
# W5c: WHEN-object CRUD tools
# ---------------------------------------------------------------------------

@tool()
def pmg_when_object_add(
    ogroup: Annotated[str, Field(description="Numeric 'when' object group ID (e.g. '4') from pmg_when_groups_list.")],
    start: Annotated[str, Field(description="Timeframe start time in H:i format (e.g. '08:00').")],
    end: Annotated[str, Field(description="Timeframe end time in H:i format (e.g. '17:00').")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): add a timeframe object to a PMG RuleDB 'when' object group. Dry-run by default.

    To create the group first use pmg_when_group_create; list its objects with
    pmg_when_group_objects. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/when/{ogroup}/timeframe"
    return run_governed(
        "pmg_when_object_add", tgt,
        plan=lambda: pmg_plan_when_object_add(ogroup, start=start, end=end),
        execute=lambda: pmg_when_object_add_op(pmg, ogroup, start=start, end=end),
        confirm=confirm, detail={"ogroup": ogroup})


@tool()
def pmg_when_object_update(
    ogroup: Annotated[str, Field(description="Numeric 'when' object group ID (e.g. '4') from pmg_when_groups_list.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_when_group_objects.")],
    start: Annotated[str, Field(description="New timeframe start time in H:i format (e.g. '08:00'); required, PMG rejects partial updates.")],
    end: Annotated[str, Field(description="New timeframe end time in H:i format (e.g. '17:00'); required, PMG rejects partial updates.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a timeframe object in a PMG RuleDB 'when' object group. Dry-run by default.

    id_ comes from pmg_when_group_objects; to add a new timeframe instead use
    pmg_when_object_add. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/when/{ogroup}/timeframe/{id_}"
    return run_governed(
        "pmg_when_object_update", tgt,
        plan=lambda: pmg_plan_when_object_update(ogroup, id_, start=start, end=end),
        execute=lambda: pmg_when_object_update_op(pmg, ogroup, id_, start=start, end=end),
        confirm=confirm, detail={"ogroup": ogroup, "id": id_, "start": start, "end": end})


@tool()
def pmg_when_object_delete(
    ogroup: Annotated[str, Field(description="Numeric 'when' object group ID (e.g. '4') from pmg_when_groups_list.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_when_group_objects.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a timeframe object from a PMG RuleDB 'when' object group. Dry-run by default.

    Irreversible. id_ comes from pmg_when_group_objects; to delete the whole group instead use
    pmg_when_group_delete. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/when/{ogroup}/objects/{id_}"
    return run_governed(
        "pmg_when_object_delete", tgt,
        plan=lambda: pmg_plan_when_object_delete(ogroup, id_),
        execute=lambda: pmg_when_object_delete_op(pmg, ogroup, id_),
        confirm=confirm, detail={"ogroup": ogroup, "id": id_})


@tool()
def pmg_when_object_get(
    ogroup: Annotated[str, Field(description="Numeric 'when' object group ID (e.g. '4') from pmg_when_groups_list.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_when_group_objects.")],
) -> dict:
    """READ-ONLY: get a PMG RuleDB 'when' (timeframe) object's settings. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). Unlike who/what, 'when'
    has only ONE object type (timeframe) — no type_ param, mirrors pmg_when_object_add. PMG's own
    schema types only {id: int} in the return; the real response is presumably richer (start/end
    H:i fields), not asserted here. ogroup/id_ are numeric ID strings from pmg_when_groups_list /
    pmg_when_group_objects.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_when_object_get", f"pmg/config/ruledb/when/{ogroup}/timeframe/{id_}",
                    lambda: pmg_when_object_get_op(pmg, ogroup, id_))


# ---------------------------------------------------------------------------
# W5c: ACTION CRUD tools
# ---------------------------------------------------------------------------

@tool()
def pmg_action_bcc_create(
    name: Annotated[str, Field(description="Name for the new BCC action object.")],
    target: Annotated[str, Field(description="BCC recipient email address.")],
    info: Annotated[str | None, Field(description="Optional free-text description.")] = None,
    original: Annotated[bool | None, Field(description="If True, BCC the original unmodified mail instead of the processed copy.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a BCC action object in the PMG RuleDB. Dry-run by default.

    List existing action objects with pmg_action_objects_list; attach this one to a rule with
    pmg_ruledb_rule_action_attach. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/action/bcc"
    return run_governed(
        "pmg_action_bcc_create", tgt,
        plan=lambda: pmg_plan_action_bcc_create(name, target),
        execute=lambda: pmg_action_bcc_create_op(pmg, name=name, target=target,
                                                     info=info, original=original),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_action_bcc_update(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
    name: Annotated[str | None, Field(description="New action object name; omit to keep current value.")] = None,
    target: Annotated[str | None, Field(description="New BCC recipient email address; omit to keep current value.")] = None,
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    original: Annotated[bool | None, Field(description="If True, BCC the original unmodified mail instead of the processed copy.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a BCC action object in the PMG RuleDB. Dry-run by default.

    id_ comes from pmg_action_objects_list; to create a new one instead use pmg_action_bcc_create.
    Only non-None fields are sent, others keep their current value. confirm=True executes and
    returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/action/bcc/{id_}"
    return run_governed(
        "pmg_action_bcc_update", tgt,
        plan=lambda: pmg_plan_action_bcc_update(id_, name=name, target=target,
                                                    info=info, original=original),
        execute=lambda: pmg_action_bcc_update_op(pmg, id_, name=name, target=target,
                                                     info=info, original=original),
        confirm=confirm, detail={k: v for k, v in {"id": id_, "name": name, "target": target, "info": info, "original": original}.items() if v is not None})


@tool()
def pmg_action_bcc_get(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
) -> dict:
    """READ-ONLY: get a BCC action object's settings from the PMG RuleDB. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: string} in the return; the real response is presumably richer (target/name/info/
    original), not asserted here. id_ comes from pmg_action_objects_list.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_action_bcc_get", f"pmg/config/ruledb/action/bcc/{id_}",
                    lambda: pmg_action_bcc_get_op(pmg, id_))


@tool()
def pmg_action_field_create(
    name: Annotated[str, Field(description="Name for the new field-modification action object.")],
    field: Annotated[str, Field(description="Mail header field to set.")],
    value: Annotated[str, Field(description="Value to assign to the header field.")],
    info: Annotated[str | None, Field(description="Optional free-text description.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a field-modification action object in the PMG RuleDB. Dry-run by default.

    List existing action objects with pmg_action_objects_list; attach this one to a rule with
    pmg_ruledb_rule_action_attach. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/action/field"
    return run_governed(
        "pmg_action_field_create", tgt,
        plan=lambda: pmg_plan_action_field_create(name, field, value),
        execute=lambda: pmg_action_field_create_op(pmg, name=name, field=field,
                                                       value=value, info=info),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_action_field_update(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
    name: Annotated[str, Field(description="New action object name; required (PMG rejects partial updates).")],
    field: Annotated[str, Field(description="New mail header field to set; required (PMG rejects partial updates).")],
    value: Annotated[str, Field(description="New value to assign to the header field; required (PMG rejects partial updates).")],
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a field-modification action object in the PMG RuleDB. Dry-run by default.

    id_ comes from pmg_action_objects_list; to create a new one instead use
    pmg_action_field_create. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/action/field/{id_}"
    return run_governed(
        "pmg_action_field_update", tgt,
        plan=lambda: pmg_plan_action_field_update(id_, name=name, field=field,
                                                      value=value, info=info),
        execute=lambda: pmg_action_field_update_op(pmg, id_, name=name, field=field,
                                                       value=value, info=info),
        confirm=confirm, detail={k: v for k, v in {"id": id_, "name": name, "field": field, "value": value, "info": info}.items() if v is not None})


@tool()
def pmg_action_field_get(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
) -> dict:
    """READ-ONLY: get a field-modification action object's settings from the PMG RuleDB. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: string} in the return; the real response is presumably richer (field/value/info),
    not asserted here. id_ comes from pmg_action_objects_list.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_action_field_get", f"pmg/config/ruledb/action/field/{id_}",
                    lambda: pmg_action_field_get_op(pmg, id_))


@tool()
def pmg_action_notification_create(
    name: Annotated[str, Field(description="Name for the new notification action object.")],
    to: Annotated[str, Field(description="Notification recipient email address.")],
    subject: Annotated[str, Field(description="Notification email subject line.")],
    body_text: Annotated[str, Field(description="Notification email body text; maps to API param 'body'.")],
    info: Annotated[str | None, Field(description="Optional free-text description.")] = None,
    attach: Annotated[bool | None, Field(description="If True, attach the original message to the notification.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a notification action object in the PMG RuleDB. Dry-run by default.

    List existing action objects with pmg_action_objects_list; attach this one to a rule with
    pmg_ruledb_rule_action_attach. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/action/notification"
    return run_governed(
        "pmg_action_notification_create", tgt,
        plan=lambda: pmg_plan_action_notification_create(name, to),
        execute=lambda: pmg_action_notification_create_op(
                        pmg, name=name, to=to, subject=subject,
                        body_text=body_text, info=info, attach=attach,
                    ),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_action_notification_update(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
    name: Annotated[str, Field(description="New action object name; required (PMG rejects partial updates).")],
    to: Annotated[str, Field(description="New notification recipient email address; required (PMG rejects partial updates).")],
    subject: Annotated[str, Field(description="New notification subject line; required (PMG rejects partial updates).")],
    body_text: Annotated[str, Field(description="New notification body text; maps to API param 'body'; required (PMG rejects partial updates).")],
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    attach: Annotated[bool | None, Field(description="If True, attach the original message to the notification.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a notification action object in the PMG RuleDB. Dry-run by default.

    id_ comes from pmg_action_objects_list; to create a new one instead use
    pmg_action_notification_create. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/action/notification/{id_}"
    return run_governed(
        "pmg_action_notification_update", tgt,
        plan=lambda: pmg_plan_action_notification_update(
                     id_, name=name, to=to, subject=subject,
                     body_text=body_text, info=info, attach=attach,
                 ),
        execute=lambda: pmg_action_notification_update_op(
                        pmg, id_, name=name, to=to, subject=subject,
                        body_text=body_text, info=info, attach=attach,
                    ),
        confirm=confirm, detail={k: v for k, v in {"id": id_, "name": name, "to": to, "subject": subject, "body": body_text, "info": info, "attach": attach}.items() if v is not None})


@tool()
def pmg_action_notification_get(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
) -> dict:
    """READ-ONLY: get a notification action object's settings from the PMG RuleDB. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: string} in the return; the real response is presumably richer (to/subject/body/
    info/attach — all operator-authored notification-template content, not attacker-echoed mail
    content), not asserted here. id_ comes from pmg_action_objects_list.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_action_notification_get", f"pmg/config/ruledb/action/notification/{id_}",
                    lambda: pmg_action_notification_get_op(pmg, id_))


@tool()
def pmg_action_disclaimer_create(
    name: Annotated[str, Field(description="Name for the new disclaimer action object.")],
    disclaimer: Annotated[str, Field(description="Disclaimer text to append/prepend to mail.")],
    info: Annotated[str | None, Field(description="Optional free-text description.")] = None,
    position: Annotated[str | None, Field(description="Where to insert the disclaimer: 'start' or 'end'.")] = None,
    add_separator: Annotated[bool | None, Field(description="Insert a separator line before the disclaimer; maps to API param 'add-separator'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a disclaimer action object in the PMG RuleDB. Dry-run by default.

    List existing action objects with pmg_action_objects_list; attach this one to a rule with
    pmg_ruledb_rule_action_attach. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/action/disclaimer"
    return run_governed(
        "pmg_action_disclaimer_create", tgt,
        plan=lambda: pmg_plan_action_disclaimer_create(name),
        execute=lambda: pmg_action_disclaimer_create_op(
                        pmg, name=name, disclaimer=disclaimer,
                        info=info, position=position, add_separator=add_separator,
                    ),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_action_disclaimer_update(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
    name: Annotated[str | None, Field(description="New action object name; omit to keep current value.")] = None,
    disclaimer: Annotated[str | None, Field(description="New disclaimer text; omit to keep current value.")] = None,
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    position: Annotated[str | None, Field(description="Where to insert the disclaimer: 'start' or 'end'.")] = None,
    add_separator: Annotated[bool | None, Field(description="Insert a separator line before the disclaimer; maps to API param 'add-separator'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a disclaimer action object in the PMG RuleDB. Dry-run by default.

    id_ comes from pmg_action_objects_list. Only non-None fields are sent, others keep their
    current value. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/action/disclaimer/{id_}"
    return run_governed(
        "pmg_action_disclaimer_update", tgt,
        plan=lambda: pmg_plan_action_disclaimer_update(
                     id_, name=name, disclaimer=disclaimer,
                     info=info, position=position, add_separator=add_separator,
                 ),
        execute=lambda: pmg_action_disclaimer_update_op(
                        pmg, id_, name=name, disclaimer=disclaimer,
                        info=info, position=position, add_separator=add_separator,
                    ),
        confirm=confirm, detail={k: v for k, v in {"id": id_, "name": name, "disclaimer": disclaimer, "info": info, "position": position, "add_separator": add_separator}.items() if v is not None})


@tool()
def pmg_action_disclaimer_get(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
) -> dict:
    """READ-ONLY: get a disclaimer action object's settings from the PMG RuleDB. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: string} in the return; the real response is presumably richer (disclaimer text is
    operator-authored, not attacker-echoed mail content), not asserted here. id_ comes from
    pmg_action_objects_list.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_action_disclaimer_get", f"pmg/config/ruledb/action/disclaimer/{id_}",
                    lambda: pmg_action_disclaimer_get_op(pmg, id_))


@tool()
def pmg_action_removeattachments_create(
    name: Annotated[str, Field(description="Name for the new remove-attachments action object.")],
    text: Annotated[str, Field(description="Replacement text inserted in place of removed attachments.")],
    info: Annotated[str | None, Field(description="Optional free-text description.")] = None,
    all_: Annotated[bool | None, Field(description="If True, remove all attachments; maps to API param 'all'.")] = None,
    quarantine: Annotated[bool | None, Field(description="If True, quarantine removed attachments instead of discarding them.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): create a remove-attachments action object in the PMG RuleDB. Dry-run by default.

    List existing action objects with pmg_action_objects_list; attach this one to a rule with
    pmg_ruledb_rule_action_attach. Needs PROXIMO_PMG_* config. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/action/removeattachments"
    return run_governed(
        "pmg_action_removeattachments_create", tgt,
        plan=lambda: pmg_plan_action_removeattachments_create(name),
        execute=lambda: pmg_action_removeattachments_create_op(
                        pmg, name=name, text=text, info=info,
                        all_=all_, quarantine=quarantine,
                    ),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_action_removeattachments_update(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
    name: Annotated[str | None, Field(description="New action object name; omit to keep current value.")] = None,
    text: Annotated[str | None, Field(description="New replacement text; omit to keep current value.")] = None,
    info: Annotated[str | None, Field(description="New free-text description; omit to keep current value.")] = None,
    all_: Annotated[bool | None, Field(description="If True, remove all attachments; maps to API param 'all'.")] = None,
    quarantine: Annotated[bool | None, Field(description="If True, quarantine removed attachments instead of discarding them.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a remove-attachments action object in the PMG RuleDB. Dry-run by default.

    id_ comes from pmg_action_objects_list. Only non-None fields are sent, others keep their
    current value. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/action/removeattachments/{id_}"
    return run_governed(
        "pmg_action_removeattachments_update", tgt,
        plan=lambda: pmg_plan_action_removeattachments_update(
                     id_, name=name, text=text, info=info,
                     all_=all_, quarantine=quarantine,
                 ),
        execute=lambda: pmg_action_removeattachments_update_op(
                        pmg, id_, name=name, text=text, info=info,
                        all_=all_, quarantine=quarantine,
                    ),
        confirm=confirm, detail={k: v for k, v in {"id": id_, "name": name, "text": text, "info": info, "all": all_, "quarantine": quarantine}.items() if v is not None})


@tool()
def pmg_action_removeattachments_get(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
) -> dict:
    """READ-ONLY: get a remove-attachments action object's settings from the PMG RuleDB. Needs PROXIMO_PMG_* config.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). PMG's own schema types
    only {id: string} in the return; the real response is presumably richer (replacement text is
    operator-authored, not attacker-echoed mail content), not asserted here. id_ comes from
    pmg_action_objects_list.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_action_removeattachments_get", f"pmg/config/ruledb/action/removeattachments/{id_}",
                    lambda: pmg_action_removeattachments_get_op(pmg, id_))


@tool()
def pmg_action_delete(
    id_: Annotated[str, Field(description="Compound action object ID (e.g. '13_26') from pmg_action_objects_list.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete an action object from the PMG RuleDB. Dry-run by default.

    Irreversible. PMG rejects deletion of non-editable (built-in) system action objects — check
    the 'editable' flag via pmg_action_objects_list first. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/action/objects/{id_}"
    return run_governed(
        "pmg_action_delete", tgt,
        plan=lambda: pmg_plan_action_delete(id_),
        execute=lambda: pmg_action_delete_op(pmg, id_),
        confirm=confirm, detail={"id": id_})


@tool()
def pmg_ruledb_rule_create(
    name: Annotated[str, Field(description="Name for the new RuleDB rule.")],
    priority: Annotated[int, Field(description="Rule priority 0-100; lower numbers are evaluated with higher priority.")],
    active: Annotated[bool, Field(description="Whether the rule is active on creation; defaults False since active rules affect live mail processing.")] = False,
    direction: Annotated[int | None, Field(description="Mail direction the rule applies to: 0=inbound, 1=outbound, 2=both.")] = None,
    from_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'from' groups.")] = None,
    from_invert: Annotated[bool | None, Field(description="If True, invert the 'from' group match.")] = None,
    to_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'to' groups.")] = None,
    to_invert: Annotated[bool | None, Field(description="If True, invert the 'to' group match.")] = None,
    what_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'what' groups.")] = None,
    what_invert: Annotated[bool | None, Field(description="If True, invert the 'what' group match.")] = None,
    when_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'when' groups.")] = None,
    when_invert: Annotated[bool | None, Field(description="If True, invert the 'when' group match.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create a PMG RuleDB rule. Dry-run by default.

    Creates the rule shell only — attach condition/action groups afterward with
    pmg_ruledb_rule_from_attach and its sibling attach tools; list existing rules with
    pmg_ruledb_rules_list. active defaults False (live mail is affected only once active).
    confirm=True executes and returns {"status": "ok", "result": <new rule ID assigned by PMG>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb/rules"
    return run_governed(
        "pmg_ruledb_rule_create", tgt,
        plan=lambda: pmg_plan_ruledb_rule_create(
                     name, priority, active, direction,
                     from_and, from_invert, to_and, to_invert,
                     what_and, what_invert, when_and, when_invert,
                 ),
        execute=lambda: pmg_ruledb_rule_create_op(
                        pmg, name, priority, active, direction,
                        from_and, from_invert, to_and, to_invert,
                        what_and, what_invert, when_and, when_invert,
                    ),
        confirm=confirm, detail={"name": name})


@tool()
def pmg_ruledb_rule_update(
    id_: Annotated[str, Field(description="Rule ID (positive integer string, e.g. '100').")],
    name: Annotated[str | None, Field(description="New rule name; omit to keep current value.")] = None,
    priority: Annotated[int | None, Field(description="New rule priority 0-100; lower numbers are evaluated with higher priority.")] = None,
    active: Annotated[bool | None, Field(description="Whether the rule is active; True begins live mail processing under this rule.")] = None,
    direction: Annotated[int | None, Field(description="Mail direction the rule applies to: 0=inbound, 1=outbound, 2=both.")] = None,
    from_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'from' groups.")] = None,
    from_invert: Annotated[bool | None, Field(description="If True, invert the 'from' group match.")] = None,
    to_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'to' groups.")] = None,
    to_invert: Annotated[bool | None, Field(description="If True, invert the 'to' group match.")] = None,
    what_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'what' groups.")] = None,
    what_invert: Annotated[bool | None, Field(description="If True, invert the 'what' group match.")] = None,
    when_and: Annotated[bool | None, Field(description="AND (True) vs OR (False) logic across attached 'when' groups.")] = None,
    when_invert: Annotated[bool | None, Field(description="If True, invert the 'when' group match.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PMG RuleDB rule configuration. Dry-run by default.

    Changes rule-level fields only (name/priority/active/direction/AND-invert flags) — to
    attach or detach condition/action groups use pmg_ruledb_rule_from_attach and its sibling
    attach/detach tools. Only non-None fields are sent. confirm=True executes and returns
    {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/config"
    return run_governed(
        "pmg_ruledb_rule_update", tgt,
        plan=lambda: pmg_plan_ruledb_rule_update(
                     id_, name, priority, active, direction,
                     from_and, from_invert, to_and, to_invert,
                     what_and, what_invert, when_and, when_invert,
                 ),
        execute=lambda: pmg_ruledb_rule_update_op(
                        pmg, id_, name, priority, active, direction,
                        from_and, from_invert, to_and, to_invert,
                        what_and, what_invert, when_and, when_invert,
                    ),
        confirm=confirm, detail={k: v for k, v in {"id": id_, "name": name, "priority": priority, "active": active, "direction": direction, "from_and": from_and, "from_invert": from_invert, "to_and": to_and, "to_invert": to_invert, "what_and": what_and, "what_invert": what_invert, "when_and": when_and, "when_invert": when_invert}.items() if v is not None})


@tool()
def pmg_ruledb_rule_delete(
    id_: Annotated[str, Field(description="Rule ID (positive integer string, e.g. '100').")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PMG RuleDB rule. Dry-run by default.

    Irreversible — permanently removes the rule and all its group bindings (the who/what/when/
    action groups themselves survive). List rules first with pmg_ruledb_rules_list.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}"
    return run_governed(
        "pmg_ruledb_rule_delete", tgt,
        plan=lambda: pmg_plan_ruledb_rule_delete(id_),
        execute=lambda: pmg_ruledb_rule_delete_op(pmg, id_),
        confirm=confirm, detail={"id": id_})


@tool()
def pmg_ruledb_rule_from_attach(
    id_: Annotated[str, Field(description="Rule ID to attach the group to.")],
    ogroup: Annotated[str, Field(description="Numeric 'who' group ID from pmg_who_groups_list to attach as the 'from' condition.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): attach a 'from' (sender/who) group to a PMG RuleDB rule. Dry-run by default.

    ogroup comes from pmg_who_groups_list; list a rule's current 'from' groups with
    pmg_ruledb_rule_from_list. Additive — only affects mail flow once the rule is active.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/from"
    return run_governed(
        "pmg_ruledb_rule_from_attach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_from_attach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_from_attach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_from_detach(
    id_: Annotated[str, Field(description="Rule ID to detach the group from.")],
    ogroup: Annotated[str, Field(description="Numeric 'who' group ID currently attached as the 'from' condition to detach.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): detach a 'from' (sender/who) group from a PMG RuleDB rule. Dry-run by default.

    Only removes the binding — the who-group itself is untouched (delete it separately with
    pmg_who_group_delete if desired). List current bindings with pmg_ruledb_rule_from_list.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/from/{ogroup}"
    return run_governed(
        "pmg_ruledb_rule_from_detach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_from_detach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_from_detach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_to_attach(
    id_: Annotated[str, Field(description="Rule ID to attach the group to.")],
    ogroup: Annotated[str, Field(description="Numeric 'who' group ID from pmg_who_groups_list to attach as the 'to' condition.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): attach a 'to' (recipient/who) group to a PMG RuleDB rule. Dry-run by default.

    ogroup comes from pmg_who_groups_list; list a rule's current 'to' groups with
    pmg_ruledb_rule_to_list. Additive — only affects mail flow once the rule is active.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/to"
    return run_governed(
        "pmg_ruledb_rule_to_attach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_to_attach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_to_attach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_to_detach(
    id_: Annotated[str, Field(description="Rule ID to detach the group from.")],
    ogroup: Annotated[str, Field(description="Numeric 'who' group ID currently attached as the 'to' condition to detach.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): detach a 'to' (recipient/who) group from a PMG RuleDB rule. Dry-run by default.

    Only removes the binding — the who-group itself is untouched (delete it separately with
    pmg_who_group_delete if desired). List current bindings with pmg_ruledb_rule_to_list.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/to/{ogroup}"
    return run_governed(
        "pmg_ruledb_rule_to_detach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_to_detach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_to_detach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_what_attach(
    id_: Annotated[str, Field(description="Rule ID to attach the group to.")],
    ogroup: Annotated[str, Field(description="Numeric 'what' group ID from pmg_what_groups_list to attach as a content condition.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): attach a 'what' (content) group to a PMG RuleDB rule. Dry-run by default.

    ogroup comes from pmg_what_groups_list; list a rule's current 'what' groups with
    pmg_ruledb_rule_what_list. Additive — only affects mail flow once the rule is active.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/what"
    return run_governed(
        "pmg_ruledb_rule_what_attach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_what_attach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_what_attach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_what_detach(
    id_: Annotated[str, Field(description="Rule ID to detach the group from.")],
    ogroup: Annotated[str, Field(description="Numeric 'what' group ID currently attached as a content condition to detach.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): detach a 'what' (content) group from a PMG RuleDB rule. Dry-run by default.

    Only removes the binding — the what-group itself is untouched (delete it separately with
    pmg_what_group_delete if desired). List current bindings with pmg_ruledb_rule_what_list.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/what/{ogroup}"
    return run_governed(
        "pmg_ruledb_rule_what_detach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_what_detach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_what_detach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_when_attach(
    id_: Annotated[str, Field(description="Rule ID to attach the group to.")],
    ogroup: Annotated[str, Field(description="Numeric 'when' group ID from pmg_when_groups_list to attach as a timeframe condition.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): attach a 'when' (timeframe) group to a PMG RuleDB rule. Dry-run by default.

    ogroup comes from pmg_when_groups_list; list a rule's current 'when' groups with
    pmg_ruledb_rule_when_list. Additive — only affects mail flow once the rule is active.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/when"
    return run_governed(
        "pmg_ruledb_rule_when_attach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_when_attach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_when_attach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_when_detach(
    id_: Annotated[str, Field(description="Rule ID to detach the group from.")],
    ogroup: Annotated[str, Field(description="Numeric 'when' group ID currently attached as a timeframe condition to detach.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): detach a 'when' (timeframe) group from a PMG RuleDB rule. Dry-run by default.

    Only removes the binding — the when-group itself is untouched (delete it separately with
    pmg_when_group_delete if desired). List current bindings with pmg_ruledb_rule_when_list.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/when/{ogroup}"
    return run_governed(
        "pmg_ruledb_rule_when_detach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_when_detach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_when_detach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_action_attach(
    id_: Annotated[str, Field(description="Rule ID to attach the action group to.")],
    ogroup: Annotated[str, Field(description="Numeric action group ID from pmg_action_objects_list to attach to the rule.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): attach an action group to a PMG RuleDB rule. Dry-run by default.

    ogroup comes from pmg_action_objects_list (the integer part before '_' in a compound ID like
    '13_26'); list a rule's current actions with pmg_ruledb_rule_actions_list. Additive — only
    affects mail flow once the rule is active. confirm=True executes and returns {"status": "ok",
    "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/action"
    return run_governed(
        "pmg_ruledb_rule_action_attach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_action_attach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_action_attach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


@tool()
def pmg_ruledb_rule_action_detach(
    id_: Annotated[str, Field(description="Rule ID to detach the action group from.")],
    ogroup: Annotated[str, Field(description="Numeric action group ID currently attached to the rule to detach.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): detach an action group from a PMG RuleDB rule. Dry-run by default.

    Only removes the binding — the action object itself is untouched (delete it separately with
    pmg_action_delete if desired). List current actions with pmg_ruledb_rule_actions_list.
    confirm=True executes and returns {"status": "ok", "result": <PMG's raw API response>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/ruledb/rules/{id_}/action/{ogroup}"
    return run_governed(
        "pmg_ruledb_rule_action_detach", tgt,
        plan=lambda: pmg_plan_ruledb_rule_action_detach(id_, ogroup),
        execute=lambda: pmg_ruledb_rule_action_detach_op(pmg, id_, ogroup),
        confirm=confirm, detail={"id": id_, "ogroup": ogroup})


# ---------------------------------------------------------------------------
# W6a (Wave 8a): the direct singular rule<->action-group read + RuleDB factory reset.
# See proximo/pmg.py's own W6a section header for the coordinator rulings this implements
# (RULING 1 — factory reset built RISK_HIGH; RULING 2 — the naming-symmetry-breaking name below).
# ---------------------------------------------------------------------------

@tool()
def pmg_ruledb_rule_action_groups_list(
    id_: Annotated[str, Field(description="RuleDB rule ID (positive integer string, e.g. '100').")],
) -> list[dict]:
    """READ-ONLY: list the action-group ids DIRECTLY attached to a PMG RuleDB rule. Needs PROXIMO_PMG_* config.

    Reads the singular GET /config/ruledb/rules/{id}/action endpoint PMG's own apidoc describes as
    "Get 'action' group list" — returns bare [{"id": <int>}], the same shape/trust level as the
    already-shipped pmg_ruledb_rule_from_list/to_list/what_list/when_list siblings.

    NOT THE SAME as pmg_ruledb_rule_actions_list (plural name, shipped earlier): that tool reads
    the rule's /config and extracts an embedded 'action' key whose presence in the real PMG
    response is UNVERIFIED (see that tool's own corrected docstring — Wave 8a). THIS tool reads
    the direct singular endpoint and returns exactly what it says, no config-embed indirection.
    The one-letter closeness to pmg_ruledb_rule_actions_list is a real typo-collision risk —
    this name was deliberately chosen over the sibling-symmetric "pmg_ruledb_rule_action_list" to
    make the two tools visually distinct (coordinator RULING 2).

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm).
    id_: rule ID (e.g. '100') from pmg_ruledb_rules_list.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_ruledb_rule_action_groups_list", f"pmg/config/ruledb/rules/{id_}/action",
                    lambda: pmg_ruledb_rule_action_groups_list_op(pmg, id_))


@tool()
def pmg_ruledb_reset(
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the FACTORY RESET.")] = False,
) -> dict:
    """MUTATION (HIGH): factory-reset the ENTIRE PMG RuleDB. Dry-run by default.

    Wipes EVERY rule, every who/what/when object group, and every action object back to PMG
    factory defaults — in one call. Proximo has NO undo for this: no staged/pending state to
    discard first, no dry-run companion upstream, no scoping parameter accepted (PMG's own schema
    takes zero params). Take pmg_backup_create first.

    The dry-run PLAN captures the current scope (rule count, who/what/when group counts, action
    object count) via 5 best-effort reads and renders the toll before you confirm — a capture-read
    failure degrades to an honest note rather than blocking the plan (PMG may be partially
    unreachable and the plan still needs to render). confirm=True executes and returns
    {"status": "ok", "result": None} — PMG's own schema declares this call synchronous (returns
    null), never "submitted".
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/ruledb"
    return run_governed(
        "pmg_ruledb_reset", tgt,
        plan=lambda: pmg_plan_ruledb_reset(pmg),
        execute=lambda: pmg_ruledb_reset_op(pmg),
        confirm=confirm)
