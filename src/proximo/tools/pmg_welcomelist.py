"""PMG global SMTP welcomelist wrappers (Wave 8b, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 8 decomposition". See
`proximo.pmg_welcomelist` module docstring for the full endpoint table, the schema-verified
facts, and the risk-rating reasoning (coordinator RULINGS 3 + 5).

NOT THE SAME as pmg_quarantine_welcomelist_add/list/remove (proximo/tools/pmg_mail.py): those are
a PER-MAILBOX quarantine bypass (pmail-scoped, ADVERSARIAL-classified); these 5 tools manage a
GLOBAL admin policy object with no owning mailbox at all. Naming is one word apart on purpose
(RULING 5 keeps this family's own schema vocabulary, `/config/welcomelist/*`) — every docstring
below carries this disambiguation line, and the three quarantine tools carry the reverse
cross-reference (doc-only diff, this wave).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pmg_welcomelist import (
    plan_welcomelist_object_add,
    plan_welcomelist_object_delete,
    plan_welcomelist_object_update,
    welcomelist_object_add,
    welcomelist_object_delete,
    welcomelist_object_get,
    welcomelist_object_update,
    welcomelist_objects_list,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)


@tool()
def pmg_welcomelist_objects_list() -> list[dict]:
    """READ-ONLY: list every entry across all 8 PMG global welcomelist typed families. Needs
    PROXIMO_PMG_* config.

    NOT THE SAME as pmg_quarantine_welcomelist_list (per-mailbox quarantine bypass) — this is the
    GLOBAL admin welcomelist, no owning mailbox. Schema types only {id: int} per item, no 'type'
    field (Smoke-confirm) — use pmg_welcomelist_object_get with a candidate type_ to resolve one
    id to its typed content.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_welcomelist_objects_list", "pmg/config/welcomelist/objects",
                    lambda: welcomelist_objects_list(pmg))


@tool()
def pmg_welcomelist_object_get(
    type_: Annotated[str, Field(description="Welcomelist object type: email|receiver|domain|receiver_domain|regex|receiver_regex|ip|network. Plain families (email/domain/regex/ip/network) match the SENDER side; receiver_* families match the RECIPIENT side. NO ogroup — this plane is a flat global namespace, unlike ruledb who/what/when.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_welcomelist_objects_list.")],
) -> dict:
    """READ-ONLY: get a PMG global welcomelist object's settings. Needs PROXIMO_PMG_* config.

    NOT THE SAME as the per-mailbox pmg_quarantine_welcomelist_* family. Wave 8b, schema-verified
    path — not yet live-verified (Smoke-confirm). Schema types only {id: int} in the return; the
    real response is presumably richer (the type-specific field itself), not asserted here.
    """
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_welcomelist_object_get", f"pmg/config/welcomelist/{type_}/{id_}",
                    lambda: welcomelist_object_get(pmg, type_, id_))


@tool()
def pmg_welcomelist_object_add(
    type_: Annotated[str, Field(description="Welcomelist object type: email|receiver|domain|receiver_domain|regex|receiver_regex|ip|network. Plain families (email/domain/regex/ip/network) match the SENDER side; receiver_* families match the RECIPIENT side. NO ogroup — this plane is a flat global namespace, unlike ruledb who/what/when.")],
    email: Annotated[str | None, Field(description="Email address to welcomelist; REQUIRED when type_='email' or 'receiver'.")] = None,
    domain: Annotated[str | None, Field(description="DNS domain to welcomelist; REQUIRED when type_='domain' or 'receiver_domain'.")] = None,
    regex: Annotated[str | None, Field(description="Email-address regex to welcomelist; REQUIRED when type_='regex' or 'receiver_regex'.")] = None,
    ip: Annotated[str | None, Field(description="IP address to welcomelist; REQUIRED when type_='ip'.")] = None,
    cidr: Annotated[str | None, Field(description="Network in CIDR notation to welcomelist; REQUIRED when type_='network'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): add an object to the PMG GLOBAL welcomelist. Dry-run by default.

    NOT THE SAME as pmg_quarantine_welcomelist_add (per-mailbox, RISK_LOW): this entry has NO
    bind/activate gate — it is unconditionally live cluster-wide the instant it lands, and
    matching mail bypasses spam/virus scanning for EVERY mailbox (a deliberate tier above the
    per-user tool's rating — see proximo.pmg_welcomelist module docstring RULING 3). Send only the
    ONE field matching type_ (see each param's description). confirm=True executes and returns
    {"status": "ok", "result": <new object's integer ID>}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/welcomelist/{type_}"
    return run_governed(
        "pmg_welcomelist_object_add", tgt,
        plan=lambda: plan_welcomelist_object_add(
                     type_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr,
                 ),
        execute=lambda: welcomelist_object_add(
                        pmg, type_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr,
                    ),
        confirm=confirm, detail={"type": type_})


@tool()
def pmg_welcomelist_object_update(
    type_: Annotated[str, Field(description="Welcomelist object type: email|receiver|domain|receiver_domain|regex|receiver_regex|ip|network. Plain families (email/domain/regex/ip/network) match the SENDER side; receiver_* families match the RECIPIENT side. NO ogroup — this plane is a flat global namespace, unlike ruledb who/what/when.")],
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_welcomelist_objects_list.")],
    email: Annotated[str | None, Field(description="New email address; REQUIRED when type_='email' or 'receiver'.")] = None,
    domain: Annotated[str | None, Field(description="New DNS domain; REQUIRED when type_='domain' or 'receiver_domain'.")] = None,
    regex: Annotated[str | None, Field(description="New regex; REQUIRED when type_='regex' or 'receiver_regex'.")] = None,
    ip: Annotated[str | None, Field(description="New IP address; REQUIRED when type_='ip'.")] = None,
    cidr: Annotated[str | None, Field(description="New CIDR network; REQUIRED when type_='network'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update an object in the PMG GLOBAL welcomelist. Dry-run by default.

    NOT THE SAME as the per-mailbox pmg_quarantine_welcomelist_* family (no update tool exists
    there at all). type_ must match the object's existing type; id_ comes from
    pmg_welcomelist_objects_list. The dry-run PLAN captures the object's current state via the
    typed GET (a failed capture degrades to an honest note, never blocks the plan). NO digest
    exists on this plane — no optimistic lock; a concurrent update can still race with this one.
    confirm=True executes and returns {"status": "ok", "result": None}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/welcomelist/{type_}/{id_}"
    return run_governed(
        "pmg_welcomelist_object_update", tgt,
        plan=lambda: plan_welcomelist_object_update(
                     pmg, type_, id_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr,
                 ),
        execute=lambda: welcomelist_object_update(
                        pmg, type_, id_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr,
                    ),
        confirm=confirm, detail={k: v for k, v in {"type": type_, "id": id_, "email": email, "domain": domain, "regex": regex, "ip": ip, "cidr": cidr}.items() if v is not None})


@tool()
def pmg_welcomelist_object_delete(
    id_: Annotated[str, Field(description="Object ID (numeric string) from pmg_welcomelist_objects_list.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (LOW): delete an object from the PMG GLOBAL welcomelist. Dry-run by default.

    NOT THE SAME as pmg_quarantine_welcomelist_remove (per-mailbox quarantine bypass): that tool
    removes a per-mailbox entry, no type_ concept; this removes a GLOBAL SMTP welcomelist object.

    Generic/untyped delete — no type_ needed, PMG's own DELETE endpoint is shared across all 8
    families. PROTECTIVE direction: removes a scanning bypass, re-subjecting the address/domain/
    network to normal spam/virus scanning cluster-wide — a deliberate, argued asymmetry from
    ruledb who/what object delete's own RISK_MEDIUM (see proximo.pmg_welcomelist module docstring
    RULING 3). Irreversible; re-add with pmg_welcomelist_object_add if needed. confirm=True
    executes and returns {"status": "ok", "result": None}.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/config/welcomelist/objects/{id_}"
    return run_governed(
        "pmg_welcomelist_object_delete", tgt,
        plan=lambda: plan_welcomelist_object_delete(id_),
        execute=lambda: welcomelist_object_delete(pmg, id_),
        confirm=confirm, detail={"id": id_})
