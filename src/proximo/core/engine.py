"""Resolve an address, govern it, execute it. The whole core in three functions.

    resolve(product, method, path) -> Row      the address exists and is published
    govern(row)                    -> Verdict  what the spine says about touching it
    execute(row, args)             -> dict     the vendor's data in a labelled envelope

GOVERNANCE IS DERIVED, NOT DECLARED. `access` comes from the HTTP method, so it is total over
every published address and cannot drift the way 924 docstring markers can. The human-authored
columns are the records' (`records/`: the tier, taint, secret, undo, shell and net judgements,
each with its why); `tier` (blast radius) is the one that opens a mutation, and the vendor
cannot publish it for us.

FAIL-CLOSED ON SILENCE: an address with no authored tier is REFUSED for mutation even when the
operator is armed. An untiered address is not "probably fine", it is unjudged, and the strictest
reading of an unjudged mutation is the only honest one. Authoring a tier LOOSENS; it never
enables something the absence of a tier would have allowed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import unquote

from proximo.core import apitree, arm, download, rawdoor, shell, spine, store, wire
from proximo.core.errors import ProximoError
from proximo.core.ledger import EXECUTING, LedgerConfig, open_ledger
from proximo.core.principal import ledger_principal
from proximo.core.secretfile import safe_exception_text, safe_text
from proximo.core.spine import wire_error

READ, MUTATE = "read", "mutate"

#: The authored blast-radius vocabulary. A tier outside it is NOT a tier.
#:
#: `tier is None` was the original test, and a lens broke it in one line: `tier = ""` in
#: tiers.toml is not None, so an empty string read as authored and opened the wire. The one
#: human-authored input to the whole spine was also the one input with no validation. A typo
#: must fail CLOSED, so membership is the test and the vocabulary is closed.
TIERS = frozenset({
    "read-back",   # reversible by re-running the opposite call
    "restorable",  # recoverable from a backup or snapshot that exists
    "disruptive",  # interrupts service; state survives
    "destructive", # data or configuration is gone
})


#: (drop, userinfo, rows, text, bearer): `bearer` is the line's why when the response IS a
#: credential the caller must receive (a login link), so it is served whole and labelled.
Rule = tuple[frozenset[str], frozenset[str], frozenset[str], bool, str | None]
_NO_RULE: Rule = (frozenset(), frozenset(), frozenset(), False, None)


@dataclass(frozen=True)
class Row:
    """One published address and everything known about governing it: the one JSON's row. Every
    column is computed by the build; the engine asks the row, never "which command is this?"."""

    product: str
    path: str
    method: str
    access: str
    excluded: bool
    gate: str | None
    params: Mapping[str, dict]   # a read-only view: the table is shared by every door in-process
    tier: str | None
    why: str | None = None       # the human sentence that justifies the tier; rides into the plan
    untrusted: bool = False      # the response carries guest- or externally-authored bytes (taint.toml)
    channel: str | None = None   # the sentence that classifies it; rides into the plan
    wire: str = "http"           # how the call is dialled: the vendor's API, or "ssh" (shell.toml)
    held: str | None = None      # a judged refusal: the sentence [tier.held] carries, read instead of a tier
    lane: str | None = None      # the opt-in lane a gated row is served on: agent, shell, node or download
    twin: str | None = None      # the GET at this path: UNDO's capture and the plan's current; gated, it is named
    state: str | None = None     # the parent's /current an action is read through when no twin serves
    expect: Mapping[str, Any] | None = None   # the state a power action aims at ({"status": "running"})
    net: Mapping[str, str] | None = None      # a container command's snapshot and rollback addresses (shell.toml)
    task_status: str | None = None            # where the plane reports a task this mutation submits
    secret: Rule = _NO_RULE      # what the answer withholds: the own line merged with the read twin's
    arg_secrets: frozenset[str] = frozenset()   # argument names the ledger fingerprints (a secret the caller sends)
    creates: str | None = None   # a judged create (undo.toml): a failed read-back is absence, the restore its DELETE

    @property
    def address(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def key(self) -> str:
        """The record spelling, `plane:METHOD /path`: what tiers.toml and taint.toml key on."""
        return f"{self.product}:{self.address}"


@dataclass(frozen=True)
class Verdict:
    """Allowed or not, and the reason in the operator's terms.

    `needs` names what would change the answer ("arm", "tier", "held", "contain", "config",
    "forbid", "consent", "rate", "taint", "undo", "prove", "arguments", "path", "store", or an
    opt-in lane: "agent", "shell", "node", "download"), so a refusal tells the caller what to DO
    rather than only what failed. "held" is a judgement with a sentence, not an absence: John opens it by name.
    `consent_id` is on every mutation verdict, allowed or not: it is what an operator grants.
    """

    allowed: bool
    reason: str
    needs: str | None = None
    consent_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def row_of(r: Mapping[str, Any]) -> Row:
    """One row of the one JSON (`proximo.json.gz`) as the engine governs it."""
    x = r["secret"]
    return Row(product=r["product"], path=r["path"], method=r["method"], access=r["access"],
               excluded=r["excluded"], gate=r["gate"], params=MappingProxyType(r["params"]),
               tier=r["tier"], why=r["why"], held=r["held"], untrusted=r["untrusted"],
               channel=r["channel"], wire=r["wire"], lane=r["lane"], twin=r["twin"], state=r["state"],
               expect=MappingProxyType(r["expect"]) if r["expect"] else None,
               net=MappingProxyType(r["net"]) if r["net"] else None, task_status=r["task_status"],
               secret=(frozenset(x["drop"]), frozenset(x["userinfo"]), frozenset(x["rows"]), x["text"], x["bearer"])
               if x else _NO_RULE, arg_secrets=frozenset(r["arg_secrets"]), creates=r["creates"])


@cache
def table() -> Mapping[tuple[str, str, str], Row]:
    """The governance table, keyed (product, method, path): every row of the one JSON, which
    `scripts/build_proximo_json.py` builds from the vendor's schema and the authored records
    (`records/`), refusing there any line that would do nothing. Generated; never hand-edited."""
    out = {(r["product"], r["method"], r["path"]): row_of(r) for r in apitree.published()["rows"]}
    # READ-ONLY VIEW. `@cache` means every in-process door shares this object, so handing back
    # a plain dict let one caller write a tier into the authoritative table and authorize a
    # mutation for everything else in the process. A governance table nobody can reach into is
    # cheaper than trusting that nobody does.
    return MappingProxyType(out)


@cache
def untrusted_addresses() -> frozenset[str]:
    """The record's keys, `plane:METHOD /path`: what `taint.is_adversarial` answers by address."""
    return frozenset(r.key for r in table().values() if r.untrusted)


def arg_rule(row: Row) -> Rule:
    """The rule for ledgering a mutation's ARGUMENTS: the response rule's drops (a PUT that echoes
    its resource) UNION the arg-secret names for this row's own address, so a guest exec's argv and
    a file-write's content are fingerprinted in the executing row, never written raw."""
    # Arguments are never "a bearer": a token mint's own line labels its ANSWER the credential;
    # its arguments (a comment, an expiry) are receipted by name like any other.
    return (row.secret[0] | row.arg_secrets, *row.secret[1:4], None)


def resolve(product: str, method: str, path: str) -> Row:
    """The Row for this address, or a refusal naming the nearest published alternatives.

    Unknown addresses are refused BEFORE any wire is touched and before any credential is read:
    a typo must cost nothing and reveal nothing.
    """
    if product not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {product!r}; known planes: {', '.join(apitree.PRODUCTS)}")
    method = method.upper()
    # A CONCRETE path ("/nodes/pve1/status") and a TEMPLATE ("/nodes/{node}/status") must reach
    # the same row: `find` maps either onto the published spelling, which is the table's key.
    # The SPELLING is refused before the address is matched. Without this the core governed a
    # normalized string and sent an unnormalized one: `//nodes/backup` on pbs governed as
    # `GET /nodes/{node}` while httpx collapses it to `/backup`, an EXCLUDED protocol tunnel.
    # One copy of the rule, in the module that already owned it.
    rawdoor.reject_malformed(path, allow_placeholders=True)
    published = apitree.find(product, rawdoor.canonical(path), method, wires=("http", "ssh"))
    row = table().get((product, method, published)) if published else None
    if row is None:
        nearest = apitree.nearest(product, path, method)[:5]
        near = ", ".join(nearest) or "none"
        raise ProximoError(
            f"{product} publishes no {method} {path}. Nearest published {method} paths: {near}."
            + _split_value_hint(path, nearest)
        )
    return row


def _split_value_hint(path: str, nearest: list[str]) -> str:
    """A value with a slash in it (a CIDR, a volume id) splits into two segments, so the path
    matches a published address up to its last placeholder and runs ONE segment past it. Say how
    the value goes; a bare no sends the caller to guess. Only that shape: a typo past a literal
    tail, or several segments too many, is not a split value (a lens found the count-only rule
    telling every long typo to encode). The vendor's router happens to swallow a raw slash on
    some addresses; the door does not copy that, because `{name}/{cidr}` would then read two ways.
    """
    got = apitree.norm(path).split("/")
    for cand in nearest:
        tmpl = apitree.norm(cand).split("/")
        if (len(got) == len(tmpl) + 1 and tmpl[-1] == "{}"
                and apitree.matches("/".join(got[:len(tmpl)]), "/".join(tmpl))):
            return (f" If the value for {{{placeholders(cand)[-1]}}} contains '/' "
                    f"(a CIDR, a volume id), it goes in its segment as %2F.")
    return ""


def govern(row: Row, *, cfg: wire.Plane | None = None, path: str | None = None,
           args: dict[str, Any] | None = None, ledger_cfg: Any = None,
           consent_covered: bool = False) -> Verdict:
    """What the spine says about touching this address. Pure: reads state, touches nothing.

    ARM and TIER first, then the pure pillars: CONTAIN, the retired SCOPE/LEASE switches
    (refused while set: the vendor's ACL and token `expire` keep them), FORBID, TAINT (the forbid
    coupling: a wall after an untrusted read, no consent escape), CONSENT (a look at the grant,
    never a consume; mandatory once tainted when the operator said so). `path` and `args` are
    what the call would send; they give FORBID its arguments and CONSENT its id. Without them
    the verdict is the address's alone, which is what `resolve`-time questions need.
    `ledger_cfg` names the ledger whose directory holds the taint marker; the env's when absent.
    `consent_covered` drops the two CONSENT looks and no
    other pillar: `execute` sets it only for the snapshot guarding a command that passed its own.

    The SPELLING is judged before any pillar sees the path. A lens handed `execute` a path
    nobody had resolved (`%0A` inside a value) and forbid read the split value; the late check
    before the wire caught it, but only there, and both doors were safe by convention alone.
    A refusal here raises, like `resolve`'s: a plan on a malformed path is not a verdict.
    """
    if path is not None:
        rawdoor.reject_malformed(path, allow_placeholders=True)
    if row.excluded:
        return Verdict(False, f"{row.address} is a protocol tunnel, not a REST operation", None)
    if row.gate:
        # THE GUEST-AGENT LANE IS OPT-IN, NOT A WALL. Every other gated subtree (byte streams,
        # mail bodies) the core does not serve at all; the agent subtree it serves when the
        # operator opts in and the guest is allowlisted. The opt-in is judged on the CONCRETE
        # VMID the path binds (a template path binds none and is refused, never matched `*`);
        # when it passes, the row falls through to arm, tier and the pillars like any mutation.
        lane = row.lane
        if lane is not None:
            concrete = rawdoor.canonical(path) if (path and "{" not in path) else None
            bound = bind(row, concrete) if concrete else {}
            # the download lane's id is the concrete path itself: there is no guest to allowlist
            ident = concrete if lane == "download" else bound.get("node" if lane == "node" else "vmid")
            refusal = spine.opt_in_refusal(lane, ident)
            if refusal is not None:
                return Verdict(False, refusal.reason, refusal.needs, detail=refusal.detail)
            if lane == "download":
                return Verdict(True, "download: the bytes land on this host under the cap, never in an answer")
        else:
            return Verdict(False, f"{row.address} is gated: {row.gate}", None)
    if row.access == READ:
        return Verdict(True, "read")
    if row.held:
        # A JUDGED refusal, before arm: the sentence names why the door does not open this one
        # (a login ticket the caller could use around every pillar; a batch of calls the seam
        # never sees). Opening it is a line moved from [tier.held] to [tier], John's hand.
        return Verdict(False, f"{row.address} is held: {row.held}", "held")
    if cfg is not None and getattr(cfg, "product", row.product) != row.product:
        # The arm question is asked of THIS row's box. A lens armed a pbs mutation with a pve
        # Plane whose served token matched its own arm source: the pve box's arm authorized
        # a pbs address. A config for another plane answers for another plane.
        return Verdict(False, f"{row.address} is {row.product}; the config given is for {cfg.product}", None)
    # No config is the ENV box, and the env box has one pair per plane: a pbs row asks the pbs
    # pair, never the pve one `arm_state(None)` would grade.
    state = arm.arm_state(cfg if cfg is not None or row.product == "pve" else wire.env_arm_view(row.product))
    if not state.armed:
        return Verdict(
            False,
            f"{row.address} mutates and the operator is not armed ({state.reason or 'disarmed'})",
            "arm",
        )
    # `in` on a frozenset raises TypeError for an UNHASHABLE tier, and TOML yields a dict for a
    # nested table -- so a malformed entry crashed the verdict instead of refusing it. A door
    # that distinguishes "refused" from "crashed" saw a crash. Type first, membership second.
    if not isinstance(row.tier, str) or row.tier not in TIERS:
        return Verdict(
            False,
            f"{row.address} mutates and has no authored blast-radius tier; "
            f"an unjudged mutation is refused even when armed",
            "tier",
        )
    called = rawdoor.canonical(path) if path else row.path
    args = dict(args or {})
    cid = spine.consent_id(row.product, row.method, row.path, called, args,
                           box=(cfg.base_url if cfg is not None else wire.env_base_url(row.product)) or "")
    audit_dir = _audit_dir(ledger_cfg)
    for refusal in (
        spine.contain_refusal(),
        spine.retired_refusal(),
        spine.same_user_refusal(),
        spine.forbid_refusal(row.product, row.method, called, args,
                             extra=cfg.forbid if cfg is not None else ()),
        spine.taint_refusal(audit_dir, row.product, row.method, called, args),
        None if consent_covered else spine.taint_consent_refusal(audit_dir),
        None if consent_covered else spine.consent_refusal(cid, audit_dir or "."),
    ):
        if refusal is not None:
            detail = dict(refusal.detail)
            if refusal.needs == "consent" and spine.taint_mandatory(audit_dir):
                detail["taint_required"] = True   # same outcome; DIAGNOSE sees why it was mandatory
            return Verdict(False, refusal.reason, refusal.needs, cid, detail)
    return Verdict(True, f"mutate, tier {row.tier}", consent_id=cid)


def plan(row: Row, args: dict[str, Any] | None = None, path: str | None = None,
         cfg: wire.Plane | None = None, ledger_cfg: Any = None, env: dict[str, Any] | None = None) -> dict[str, Any]:
    """The governed decision, the published schema and, for a mutation, THE TARGET AS IT STANDS.

    Writes no receipt of its own: the receipt of a mutation is the `executing` row `execute`
    writes, which carries this same preview, and the before-state on the chain is the UNDO
    capture taken at execute time. A mutation's plan reads the target's live state (B1,
    2026-09-30) through `execute` as the governed read it is: receipted, withheld, tainted and
    bounded like any read, when the box holds a credential; on a bare box it answers the
    verdict and says why `current` is not there. When consent is configured the plan names
    the grant file an operator would create, because the id is only useful with a path.
    `env` is the twin's envelope when the caller holds it already (a restore read the target to
    build its arguments moments ago); the plan diffs that record instead of reading twice.
    """
    args = dict(args or {})
    verdict = govern(row, cfg=cfg, path=path, args=args, ledger_cfg=ledger_cfg)
    if path and "{" not in path and row.access != READ and (verdict.allowed or verdict.needs in ("arm", "consent")):
        # (a tunnel, a gate, a wall keeps its own words: those refusals name what no argument
        # can fix, lens 12)
        # WHAT EXECUTE WILL REFUSE, THE PLAN REFUSES: a placeholder given twice with different
        # values is not a call that runs, so it is not a verdict of "allowed" (lens 10), and on
        # an unarmed box it is still not a no-op (lens 11): arguments come before arm, the one
        # thing the caller can fix without an operator.
        if (twice := _given_twice(row, bind(row, path), args)) is not None:
            verdict = Verdict(False, twice, "arguments", consent_id=verdict.consent_id)
    out = {
        "address": row.address, "plane": row.product, "access": row.access, "tier": row.tier,
        "why": row.why, "untrusted": row.untrusted, "channel": row.channel,
        "allowed": verdict.allowed, "reason": verdict.reason, "needs": verdict.needs,
        # Echoed as the receipt holds them: a secret-named argument fingerprinted, never raw.
        "arguments": ledgered(args, None, _plan_rule(row)) if args else args,
        "published_parameters": dict(row.params),
    }
    if verdict.consent_id:
        out["consent_id"] = verdict.consent_id
        out["consent"] = spine.consent_state(verdict.consent_id, _audit_dir(ledger_cfg) or ".")
        if out["consent"] == "advisory":
            out["reason"] = (f"{out['reason']}; consent is advisory: a grant the agent's own user owns, "
                             "a speed bump, not a lock")
        gp = spine.grant_path(verdict.consent_id)
        if gp:
            out["grant_path"] = gp
    if row.net and _snapshot_on(row, args):
        # ONE GRANT, TWO VENDOR MUTATIONS: the plan the operator approves says so (lens B5c-3).
        snap = _at(row.product, row.net["snapshot"])
        out["also"] = {"address": snap.address, "tier": snap.tier, "consent": "covered by this plan's grant",
                       "why": "snapshot=true takes the container's snapshot first; if it does not land, "
                              "the command is not run"}
    # A HELD address is never read for its live state: the plan's answer is the sentence, and a
    # read of its twin (a login's GET) would dial the vendor for a call that will not run.
    if row.access != READ and verdict.needs not in ("arguments", "held"):
        out.update(_live_state(row, args, path, cfg, ledger_cfg, env))
    if row.lane == "download" and verdict.allowed:
        # where the bytes would land; nothing is dialled, and a refused lane learns no path (lens 3)
        try:
            lands_under, cap = download.settings()
            out["download"] = {"lands_under": lands_under, "cap_bytes": cap}
        except ProximoError as exc:
            out["download"] = {"refused": str(exc)}
    return out


# ---- PLAN's live state (B1) ---------------------------------------------------------------------
# The read is the row's `twin` (the GET at the same path; 543 of the 865 mutations) or its
# `state` (the `/current` beside a PVE power or HA action; 15), both computed by the build. Where
# neither exists the plan says so in the UNDO capture's own words, so `current` is never silently
# empty (a site on 0.44 reported a plan whose `current` was `{}`, 2026-09-29). The read is
# `execute`'s: one seam for receipt, withhold, taint, the size law. `change` is the exact from/to
# per argument, compared as strings (the vendor answers 2048, the operator sends "2048", Proxmox
# booleans are 0/1); `noop` is the one branch 0.44 had (a start on a running guest, arguments the
# target already holds). The tier's authored sentence is the blast radius that has authority.

_ID_KEYS = ("id", "storage")      # identities the vendor enforces; a `name` is a display name


def _read_of(row: Row) -> tuple[Row | None, str | None, str | None, str | None]:
    """The read that shows this target: (its row, its published path, the action name when the
    read is the parent's `/current`, why there is none). A gated or tunnelled twin is named, not
    read (the UNDO capture's words)."""
    t = table()
    twin = t[(row.product, "GET", row.twin)] if row.twin else None
    if twin is not None and not twin.excluded:
        if twin.gate:
            return None, None, None, f"the read of {row.path} is gated: {twin.gate}"
        return twin, row.twin, None, None
    if row.state:
        return t[(row.product, "GET", row.state)], row.state, row.path.rpartition("/")[2], None
    return None, None, None, f"{row.product} publishes no GET {row.path}"


def _live_state(row: Row, args: dict[str, Any], path: str | None, cfg: wire.Plane | None,
                ledger_cfg: Any, env: dict[str, Any] | None = None) -> dict[str, Any]:
    twin, twin_path, action, why = _read_of(row)
    if twin is None:
        return {"current": {"why": why}}
    if not path or "{" in path:
        return {"current": {"why": "a template path names no target to read; give the concrete path"}}
    needed = [k for k, v in twin.params.items() if not v.get("optional") and k not in placeholders(twin.path)]
    if needed:                             # a read the path alone cannot ask (pmg /quarantine/content needs id)
        return {"current": {"why": f"the read {twin.address} needs {', '.join(needed)}; not read"}}
    concrete = path if twin_path == row.path else fill(cast(str, twin_path), bind(row, path))
    if env is None:
        try:
            plane = cfg if cfg is not None else wire.Plane.from_env(row.product)
        except RuntimeError as exc:        # unset, or a credential file the floor refuses: the words, no row
            return {"current": {"why": f"no credential usable on this box: {safe_exception_text(exc, paths=True)}"}}
        try:
            env = execute(twin, {}, cfg=plane, path=concrete, ledger_cfg=ledger_cfg, fields="all")
        except ProximoError as exc:        # refused by the spine, receipted by execute
            return {"current": {"why": str(exc)}}
        except Exception as exc:           # the vendor failed or is unreachable, receipted by execute
            err = wire_error(exc)
            if err.get("status") == 404 and row.method == "DELETE":
                return {"current": {"exists": False, "why": err}, "change": {}, "noop": True}
            if row.creates:                    # a judged create: the record is not there yet (undo.toml)
                return {"current": {"creates": True, "exists": False, "read_back": err},
                        "change": {"creates": rawdoor.canonical(path)}, "noop": False}
            return {"current": {"why": err}}
    if "data" not in env:                 # cut by the size law: the diff cannot be exact, say so
        size = {k: env[k] for k in ("bytes", "total", "returned") if k in env}
        return {"current": {"why": "the record is over the door's cap; the change cannot be shown", **size}}
    # ATTACKER-AUTHORED BYTES KEEP THEIR LABEL. The envelope says the twin is untrusted; a plan
    # that dropped that label handed a mail's subject to the model as a trusted fact (lens 8).
    # Fenced, the record is a wrapper, not the target: no diff against it.
    untrusted = bool(env.get("untrusted"))
    if untrusted and spine.fence_on():
        return {"current": {"untrusted": True, "channel": twin.channel, "fenced": True,
                            "why": "the target's record is attacker-authored and fenced; no diff"}}
    # THE PATH'S OWN KEYS ARE NOT STATE. `execute` strips the keys the path already binds before
    # the wire; the plan diffed them, so `vmid` read as a change on every config plan and a
    # store's own name echoed by its record made a garbage collection a no-op (lens 9).
    compared = {k: v for k, v in args.items() if k not in bind(row, path)}
    out = _diff(row, compared, path, env["data"], action)
    # A PLAN ANSWER IS AN ANSWER: the receipts fingerprint a secret-named field and the record's
    # fields (`ledgered`), and the plan echoed them raw, the live read's old value under `from`
    # and the caller's new one under `to` (found sweeping B19's 78 newly reachable addresses: a
    # PBS user update carries `password`). The same rule, by this address's own line and its twin's.
    rule = _plan_rule(row)
    out = {**out, "current": ledgered(out["current"], None, rule),
           "change": {k: ledgered(v, k, rule) if isinstance(v, dict) and set(v) <= {"from", "to"}
                      else ledgered(v, None, rule) for k, v in out["change"].items()}}
    if untrusted and isinstance(out["current"], dict):
        out["current"] = {"untrusted": True, "channel": twin.channel, **out["current"]}
    return out


def _diff(row: Row, args: dict[str, Any], path: str, data: Any, action: str | None) -> dict[str, Any]:
    """`current`, `change` and `noop` from the twin's answer. `noop` is claimed only where a
    state is compared: a power action whose status already is the expected one, or arguments
    the record already holds; an action with no arguments is never a no-op (lens 8: a PBS
    garbage collection read as one)."""
    if action is not None:
        current = (lean(data) if isinstance(data, dict) else summarize(data) if isinstance(data, list)
                   else {"data": data})
        expect = dict(row.expect or {})
        got = {k: (data.get(k) if isinstance(data, dict) else None) for k in expect}
        change = {k: {"from": got[k], "to": v} for k, v in expect.items()} if expect else {"action": action}
        return {"current": spine.bound(current), "change": change, "noop": bool(expect) and got == expect}
    if isinstance(data, list):
        if row.method != "POST":           # a PUT or DELETE whose read is the collection, not the target
            return {"current": {"collection": True, "total": len(data),
                                "why": "the read at this path is a collection, not the target; no diff"},
                    "change": {}, "noop": False}
        # A CREATE IS NOT A DIFF: the twin is the collection. Say whether an id the vendor
        # would refuse as a duplicate is already there, never the whole list.
        # `exists` is claimed only when an identity was COMPARED: an id-like argument that the
        # rows carry under the same name. A snapshot's `snapname` against rows keyed `name` was
        # never compared and read as "does not exist" (lens 9).
        keys = [k for k in args if (k == "id" or k.endswith("id") or k in _ID_KEYS)
                and any(isinstance(r, dict) and k in r for r in data)]
        if not keys:
            return {"current": {"creates": True, "identity": "not compared: no argument the rows carry by name"},
                    "change": {}, "noop": False}
        existing = next((r for r in data if isinstance(r, dict)
                         and any(k in r and str(r[k]) == str(args[k]) for k in keys)), None)
        current = {"creates": True, "exists": existing is not None, "compared": keys,
                   **({"existing": lean(existing)} if existing else {})}
        return {"current": current, "change": {}, "noop": False}
    if not isinstance(data, dict):
        return {"current": spine.bound({"data": data}), "change": {}, "noop": False}
    if row.method == "DELETE":
        return {"current": spine.bound(lean(data)), "change": {"removes": rawdoor.canonical(path)}, "noop": False}
    current = {**lean(data), **{k: data[k] for k in args if k in data}}
    change = {k: {"from": data.get(k), "to": v} for k, v in args.items()
              if k not in data or str(data[k]) != str(v)}
    return {"current": spine.bound(current), "change": change, "noop": bool(args) and not change}


def intent_id(called: str) -> str:
    """One OPERATION across attempts: what is done to what. Groups the `executing` row and its
    terminal partner for `in_flight`; nothing authorizes on it."""
    return hashlib.sha256(f"core.execute\x00{called}".encode()).hexdigest()[:12]


def placeholders(path: str) -> tuple[str, ...]:
    """The `{name}` segments of a published path, in order."""
    return tuple(seg[1:-1] for seg in path.split("/") if seg.startswith("{") and seg.endswith("}"))


def fill(template: str, values: Mapping[str, Any]) -> str:
    """`template` with every `{name}` given its value (a row's `state`, `net` or `task_status`
    made concrete). A placeholder with no value is refused, never sent as a literal."""
    out = re.sub(r"\{([^}]+)\}", lambda m: str(values[m.group(1)]) if m.group(1) in values else m.group(0), template)
    if placeholders(out):
        raise ProximoError(f"{template} needs values for {', '.join(placeholders(out))}")
    return out


def _at(product: str, address: str) -> Row:
    """The row an authored `METHOD /path` address (a row's `net`) names on `product`."""
    method, _, path = address.partition(" ")
    return table()[(product, method, path)]


def _given_twice(row: Row, bound: dict[str, str], args: dict[str, Any]) -> str | None:
    """The refusal for a placeholder the path and the arguments give different values for,
    in one place: `execute` raises it, and the plan's verdict says it (a plan that stripped
    the path's keys read a conflicting vmid as a clean no-op, lens 10)."""
    conflict = sorted(k for k, v in bound.items() if k in args and str(args[k]) != v)
    if not conflict:
        return None
    return (f"{row.address}: {', '.join(conflict)} given twice with different values "
            f"(path says {', '.join(f'{k}={bound[k]}' for k in conflict)}); "
            f"drop the argument or fix the path")


def bind(row: Row, concrete: str) -> dict[str, str]:
    """Map the caller's concrete path onto the published placeholders.

    `/nodes/pve1/qemu/101` against `/nodes/{node}/qemu/{vmid}` gives {node: pve1, vmid: 101}.
    These are the vendor's REQUIRED parameters, already supplied by the path, which is why
    `check_args` must not demand them again -- the first wire call refused a perfectly good read
    for a missing `node` that was sitting in the path all along.

    A value that carries a slash (`{cidr}` is "Network/IP specification in CIDR format") rides
    the path as `%2F`, one segment (RFC 3986); the VALUE the vendor sees is the decoded one, so
    that is what binds. `bind` DECODES, nothing else does: the address is matched, governed,
    receipted and sent on the encoded spelling, and a slash never becomes a segment.
    """
    want = [seg for seg in row.path.split("/") if seg]
    got = [seg for seg in rawdoor.canonical(concrete).split("/") if seg]
    if len(want) != len(got):
        # REFUSE, never return {}. An empty dict made execute() find no conflicts AND strip
        # nothing, so a caller-supplied `node=pve2` rode to the wire beside a path that already
        # named pve1. A guard that falls silent on the shape it cannot read is not a guard.
        raise ProximoError(
            f"{row.address}: the path {concrete!r} has {len(got)} segments, "
            f"but the published address has {len(want)}"
        )
    return {w[1:-1]: unquote(g) for w, g in zip(want, got, strict=True)
            if w.startswith("{") and w.endswith("}")}


_INDEXED = re.compile(r"^(?P<stem>.+)\[n\]$")


def _published(row: Row, name: str) -> str | None:
    """The published spelling of `name` on this address, or None when it publishes no such
    parameter. Every lookup by argument name goes through here: the type and the refusal.

    The vendor spells its REPEATED parameters with a literal index placeholder -- `net[n]`,
    `ide[n]`, `ipconfig[n]` -- while the wire only ever accepts the numbered form `net0`.
    Comparing names verbatim refused the ONLY spelling Proxmox takes and accepted `net[n]`,
    which means nothing to it. 10 addresses publish parameters in this shape.
    """
    if _INDEXED.match(name):
        # The published spelling itself is NOT a wire spelling. Accepting `net[n]` was the half
        # of this bug the first fix named and did not remove.
        return None
    if name in row.params:
        return name
    for published in row.params:
        m = _INDEXED.match(published)
        if m and re.fullmatch(re.escape(m.group("stem")) + r"\d+", name):
            return published
    return None


def coerce_args(row: Row, args: dict[str, Any]) -> dict[str, Any]:
    """Cast arguments to the types the VENDOR published for them.

    The shell door keeps every argument a string, because a CLI has nothing else. Three planes
    run values through a `_form()` that turns a bool into Proxmox's 1/0, but pdm posts JSON and
    its own docstring says it "wants real booleans, not PVE-style 1/0" -- so a governed pdm
    mutation was sending the string "1" where PDM expects `true`. Coercing HERE, from the
    published type, fixes it for every plane at once and keeps the per-plane wire shape the
    business of the backend that owns it.
    """
    out: dict[str, Any] = {}
    for name, value in args.items():
        published = _published(row, name)
        kind = row.params[published].get("type") if published else None
        if not isinstance(value, str):
            # THE SSH WIRE HAS NO FORM THAT READS 1 AS TRUE. A JSON 1 passed as `snapshot` failed
            # the `is True` test and the command ran with no net (lens B5c-1); a declared boolean
            # there is a bool or it is refused. The API planes keep Proxmox's own 0/1.
            if row.wire == "ssh" and kind == "boolean" and not isinstance(value, bool):
                raise ProximoError(f"{row.address}: {name}={value!r} is not a boolean; use true/false")
            out[name] = value
        elif kind == "boolean":
            # REFUSE WHAT WE DO NOT RECOGNISE. Mapping every unknown string to False looks
            # harmless until the parameter is named `dry-run`: "y" silently became False and a
            # preview became a live run. 59 mutating addresses publish a boolean of that shape.
            # An unreadable value is a question, not a default.
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "y", "on", "t"}:
                out[name] = True
            elif lowered in {"0", "false", "no", "n", "off", "f", ""}:
                out[name] = False
            else:
                raise ProximoError(
                    f"{row.address}: {name}={ledgered(value, name, row.secret)!r} is not a boolean "
                    f"the vendor would accept; use true/false"
                )
        elif kind in ("integer", "number"):
            # int()/float() raise ValueError, which the door reports as the caller's syntax with
            # no ledger row. Raise the type the spine speaks so it is recorded like any refusal.
            try:
                out[name] = int(value) if kind == "integer" else float(value)
            except ValueError:
                raise ProximoError(
                    f"{row.address}: {name}={ledgered(value, name, row.secret)!r} is not a valid {kind}"
                ) from None
        else:
            out[name] = value
    return out


def check_args(row: Row, args: dict[str, Any]) -> dict[str, Any]:
    """Validate args against the VENDOR's published parameter schema.

    Unknown names are refused with the published set named. Nothing is coerced or invented: an
    argument the vendor does not document is a caller mistake, and guessing what they meant is
    how a governed call becomes an ungoverned one.
    """
    unknown = sorted(n for n in args if not _published(row, n))
    if unknown:
        known = ", ".join(sorted(row.params)) or "none"
        raise ProximoError(
            f"{row.address} does not publish {', '.join(unknown)}. Published parameters: {known}"
        )
    supplied = set(args) | set(placeholders(row.path))
    missing = sorted(n for n, s in row.params.items()
                     if not s["optional"] and n not in supplied and "[n]" not in n)
    if missing:
        raise ProximoError(f"{row.address} requires {', '.join(missing)}")
    return args


def _client(product: str, cfg: wire.Plane | None = None) -> wire.Client:
    """The ONE place a wire client is built, so a test can stand a recorder here and be sure
    nothing else dials. From the caller's config when given, else the environment."""
    return wire.client(product, cfg)


def _download(row: Row, called: str, args: dict[str, Any], cfg: wire.Plane | None, ledger_cfg: Any,
              remote: str | None, fields: str | None, since: str | None, wait: int | None) -> dict[str, Any]:
    """The download lane (`proximo.core.download`): the vendor's bytes land on this host under the
    cap; the answer carries the local path, the count and the sha256, never a byte. A read's
    questions (fields, since, wait) are refused: a byte stream answers none of them."""
    if fields is not None or since is not None or wait is not None:
        reason = (f"{row.address} answers a byte stream that lands on disk; "
                  "fields, since and wait are not questions it answers")
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": reason, "needs": "arguments"}, called=called, remote=remote)
        raise ProximoError(reason)
    _taint_before_the_wire(row, ledger_cfg, called, remote)
    client = _built_client(row, cfg, ledger_cfg, called, remote)
    try:
        # The lane's addresses are the API's (a byte stream); none rides the ssh wire.
        got, cap = download.pull(cast(wire.Client, client), called, args)
    except Exception as exc:
        _record(ledger_cfg, "core.error", row, outcome="error",
                detail={"tier": row.tier, "called_path": called, **wire_error(exc)},
                called=called, remote=remote)
        raise
    _record(ledger_cfg, "core.execute", row, outcome="ok",
            detail={"tier": row.tier, "params": sorted(args), **_untrusted_detail(row),
                    "bytes": got["bytes"], "sha256": got["sha256"], "cap_bytes": cap},
            called=called, remote=remote)
    return {
        "address": row.address, "plane": row.product, "access": row.access, "derived": False,
        "matched_path": row.path, "called_path": called, "tier": row.tier, "untrusted": row.untrusted,
        "download": got, "cap_bytes": cap,
        "note": "the bytes landed on the Proximo host, never in this answer; verify the sha256 before use",
    }


def _built_client(row: Row, cfg: wire.Plane | None, ledger_cfg: Any, called: str,
                  remote: str | None) -> wire.Client | shell.ShellClient:
    """`_client`, with a build that fails (a missing or conflicting variable, a secret file
    group or other can read) receipted as a refusal naming what is wrong, never its content."""
    try:
        return shell.client(cfg) if row.wire == "ssh" else _client(row.product, cfg)
    except Exception as exc:
        reason = f"{row.product} is not configured to be called: {safe_exception_text(exc, paths=True)}"
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": reason, "needs": "config", **wire_error(exc)},
                called=called, remote=remote)
        raise ProximoError(reason) from exc


def execute(row: Row, args: dict[str, Any] | None = None, *, cfg: wire.Plane | None = None,
            path: str | None = None, ledger_cfg: Any = None, fields: str | None = None,
            since: str | None = None, wait: int | None = None, restores: str | None = None,
            net_of: tuple[Row, str, str | None] | None = None) -> dict[str, Any]:
    """Run a governed address and hand back the vendor's data in a labelled envelope.

    THE GOVERNANCE RUNS HERE, NOT IN THE CALLER. A door cannot skip it by forgetting to ask:
    every path into the wire passes `govern` first, and a refusal is recorded in the ledger with
    the same weight as an execution. A refusal nobody can audit is a refusal nobody can prove.
    `cfg.name`, when the Plane came from a registry target, rides on every row as `remote`.
    `since` (a read only) answers what changed from the snapshots the door kept, no vendor call.
    `wait` (seconds, 0..600): a mutation the vendor answers with a task id (a UPID) is polled to
    its end on the plane's own task-status address and reports finished, failed or timed out,
    never just submitted (B4); 0 submits only; unset waits TASK_WAIT_DEFAULT. On a read it is
    allowed on a task-status address alone and polls that address (0.44's pve_task_wait).
    `restores` is the id of the capture this mutation writes back (`proximo.core.undo`); it
    rides on the executing and terminal rows so the ledger links a restore to its capture.
    `net_of` is (the container command's row, its called path, its consent id), set by
    `_snapshot_first` alone: the snapshot rides the command's consent, on its own container only,
    and its receipt names the grant that covered it.
    """
    args = dict(args or {})
    # DECIDE BEFORE CONFIGURING. `ProximoConfig.from_env()` raises when the estate is not
    # configured, so building it first made every refusal depend on holding credentials -- and
    # a refusal that needs a credential has already read one. Governing first means "is this
    # allowed?" is answerable on a box with no token at all, which is also what makes `--plan`
    # safe to run anywhere. The pure pillars run inside govern; the spending ones run below,
    # after the arguments validated, so a typo never spends a grant or a budget slot.
    remote = cfg.name if cfg is not None else None
    if net_of is not None:
        _net_of_own_container(row, path, *net_of[:2])
    try:
        verdict = govern(row, cfg=cfg, path=path, args=args, ledger_cfg=ledger_cfg,
                         consent_covered=net_of is not None)
    except ProximoError as exc:
        # govern RAISES for one thing only, a malformed spelling. An attempted execute is an
        # event: the refusal is receipted like every other, with the path as given.
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": str(exc), "needs": "path"},
                called=rawdoor.canonical(path) if path else None, remote=remote)
        raise
    if not verdict.allowed:
        # THE AIMED-AT PATH, not the template. "what did this agent try" is exactly the
        # refusal question, and the receipt used to answer it with `{store}`.
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": verdict.reason, "needs": verdict.needs, **verdict.detail},
                called=rawdoor.canonical(path) if path else None, remote=remote)
        raise ProximoError(verdict.reason)
    try:
        check_args(row, args)
    except ProximoError as exc:
        # BETWEEN THE VERDICT AND THE WIRE IS STILL INSIDE THE GOVERNED PATH. An armed operator
        # whose call passed govern and then failed validation used to leave nothing behind, so
        # "what did this agent try" had no answer for exactly the calls that got furthest.
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": str(exc), "needs": "arguments"},
                called=rawdoor.canonical(path) if path else None, remote=remote)
        raise
    # bind() was dead code, and the lens showed what that cost: passing node=pve2 alongside the
    # path /nodes/pve1/... sent BOTH, and which one Proxmox honours is not ours to guess.
    bound = bind(row, path or row.path)
    if (twice := _given_twice(row, bound, args)) is not None:
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": "conflicting placeholder values", "needs": "arguments"},
                called=rawdoor.canonical(path) if path else None, remote=remote)
        raise ProximoError(twice)
    try:
        args = coerce_args(row, {k: v for k, v in args.items() if k not in bound})
    except ProximoError as exc:
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": str(exc), "needs": "arguments"},
                called=rawdoor.canonical(path) if path else None, remote=remote)
        raise
    # THE CONCRETE PATH, NEVER THE TEMPLATE. `row.path` is the published spelling with
    # `{node}` still in it; sending that to the wire asks Proxmox for a node literally named
    # "{node}". The template is the governance key; the caller's path is what gets called.
    # CHECKED BEFORE THE BACKEND IS BUILT: constructing it reads the token, and a request we
    # were never going to send must not cost a credential read.
    called = rawdoor.canonical(path or row.path)
    # Checked AGAIN at the wire, with placeholders now forbidden: resolve() admits the template
    # spelling for a plan, and only this call is authoritative about what may be sent.
    rawdoor.reject_malformed(called, allow_placeholders=True)
    if placeholders(called):
        raise ProximoError(
            f"{row.address} needs real values for {', '.join(placeholders(called))}; "
            f"call the concrete path, not the published template"
        )
    # `cfg` IS THE PLANE'S CONFIG, and the planes do not share a config type. Building a
    # ProximoConfig here and handing it to the pbs backend crashed with "'ProximoConfig' object
    # has no attribute 'base_url'": pve's config was being passed to three clients that speak a
    # different shape. Each plane builds its own; the LEDGER keeps its own, estate-wide.
    if row.lane == "download":
        return _download(row, called, args, cfg, ledger_cfg, remote, fields, since, wait)
    if row.access == READ and since is not None:
        return _recall(row, called, args, since, ledger_cfg, remote, cfg)
    if since is not None:
        raise ProximoError(f"{row.address} mutates; since= is a question about what a read saw")
    if row.access == READ:
        _taint_before_the_wire(row, ledger_cfg, called, remote)
        client = _built_client(row, cfg, ledger_cfg, called, remote)   # a read spends nothing first
        try:
            data = client.call(row.method, called, args)
        except Exception as exc:
            # A FAILED EXECUTION IS AN EVENT, NOT A NON-EVENT. Three wire-touching calls used
            # to leave two receipts: the successes. A ledger that only records what worked
            # cannot answer "what did this agent try", which is the question an incident asks.
            _record(ledger_cfg, "core.error", row, outcome="error",
                    detail={"tier": row.tier, "called_path": called, **wire_error(exc)},
                    called=called, remote=remote)
            raise
        task = None
        if wait is not None:
            # 0.44's pve_task_wait, on a UPID already in hand: the same helper, the same address
            first = [data]
            task = _task_wait(called, lambda: first.pop() if first else client.call("GET", called, args),
                              bind(row, called).get("upid"), wait)
            if task["polls"]:
                data = {"status": task["status"], "exitstatus": task["exitstatus"]}
        _record(ledger_cfg, "core.execute", row, outcome="ok",
                detail={"tier": row.tier, "params": sorted(args), **_untrusted_detail(row),
                        **({"upid": task["upid"], "polls": task["polls"], "seconds": task["seconds"]} if task else {})},
                called=called, remote=remote)
        _keep(row, called, args, data, ledger_cfg, cfg)
        return {**_envelope(row, called, data, fields), **({"task": task} if task else {})}

    # ---- a MUTATION: spend, capture, pre-record, execute, close ---------------------------
    # BUILT BEFORE ANYTHING IS SPENT, and a build that fails is a receipted refusal. Building
    # reads env and stats the secret file (the permission floor) but never reads the secret and
    # never dials. After the spending gates, a config error burned the operator's one-shot
    # consent grant and a rate slot and left no receipt (lens 2026-09-28, pmg credential mode).
    client = _built_client(row, cfg, ledger_cfg, called, remote)
    # THE SPENDING GATES. CONSENT consumes the grant the operator placed for THIS plan (single
    # use); RATE reserves a slot in the box's budget. RATE AFTER CONSENT, so a doomed attempt
    # spends nothing the operator's own approved work will need. Both refusals are receipted
    # like every other, before anything is touched.
    base_url = cfg.base_url if cfg is not None else wire.env_base_url(row.product)
    lcfg = ledger_cfg or LedgerConfig.from_env()
    audit_dir = os.path.dirname(lcfg.audit_log_path) or "."
    spent = None if net_of is not None else spine.spend_consent(verdict.consent_id or "", audit_dir)
    if isinstance(spent, spine.Spend):
        # The evidence beside the marker: an agent that deletes its marker to spend one grant
        # again leaves one more of these rows in the chain each time. REQUIRED, and a failed
        # write rolls the marker back: a spend PROVE can't hold is no spend, and it must not
        # burn the operator's approval either. The grant goes only once the row is down.
        try:
            _record(ledger_cfg, "core.consent_spent", row, outcome="ok",
                    detail={"consent_id": verdict.consent_id,
                            "grant": {"inode": spent.inode, "mtime_ns": spent.mtime_ns},
                            **({"advisory": True} if spent.advisory else {})},
                    called=called, required=True, remote=remote)
        except BaseException:
            spine.unspend(spent)
            raise
        spine.retire_grant(verdict.consent_id or "", spent)
    for refusal in (
        spent if isinstance(spent, spine.Refusal) else None,
        spine.reserve_rate(base_url, audit_dir,
                           cap=(cfg.rate_max, cfg.rate_window) if cfg is not None else (None, None)),
    ):
        if refusal is not None:
            _record(ledger_cfg, "core.refuse", row, outcome="refused",
                    detail={"reason": refusal.reason, "needs": refusal.needs, **refusal.detail},
                    called=called, remote=remote)
            raise ProximoError(refusal.reason)
    intent = intent_id(called)
    # UNDO: read back what the vendor publishes about this address BEFORE changing it. Where
    # it publishes no read, the receipt says so; where the read exists and fails, no net means
    # no risky act (the 0.44 auto-undo's rule). PROXIMO_UNDO=off is the operator's opt-out,
    # and the receipt carries it.
    undo = _undo_before(row, args, client, called, cfg, ledger_cfg, intent, remote, verdict.consent_id)
    # THE EXECUTING ROW. Written BEFORE the wire with the whole preview and the intent, closed
    # by the terminal row below. A process killed in between leaves this row open, which is
    # exactly what `in_flight` reports; without it the core answered "what was running when we
    # died" with nothing.
    preview = {"tier": row.tier, "args": ledgered(args, rule=arg_rule(row)), "consent_id": verdict.consent_id,
               "undo": undo, "intent": intent, **({"restores": restores} if restores else {}),
               **({"consent_of": {"command": net_of[1], "consent_id": net_of[2]}} if net_of else {})}
    _record(ledger_cfg, "core.execute", row, outcome=EXECUTING, detail=preview, called=called,
            required=True, remote=remote)
    _taint_before_the_wire(row, ledger_cfg, called, remote)
    try:
        data = client.call(row.method, called, args)
    except Exception as exc:
        _record(ledger_cfg, "core.error", row, outcome="error",
                detail={"tier": row.tier, "called_path": called, "intent": intent, **_capture_of(undo),
                        **wire_error(exc)},
                called=called, remote=remote)
        raise
    # A TASK-BACKED ANSWER IS SUBMITTED, NOT DONE. The vendor accepted the work and handed back
    # its id; "ok" here would let PROVE say ok for an outcome nobody has seen yet (a process
    # that dies mid-wait leaves an honest "submitted" and no task row). The wait closes it.
    submitted = spine.looks_like_upid(data)
    # THE ID ON THE ROW IS THE SHAPE OR SCRUBBED TEXT. An answer that says UPID but is not the
    # shape is the path built for odd or hostile vendor bytes; written raw it put a secret and
    # a locator in the hash chain (lens 6). A shape-valid id is bounded by its own class.
    upid = (str(data) if spine.upid_node(data) else safe_text(str(data))) if submitted else ""   # submitted: a str
    _record(ledger_cfg, "core.execute", row, outcome="submitted" if submitted else "ok",
            detail={"tier": row.tier, "params": sorted(args), "intent": intent, **_untrusted_detail(row),
                    **_capture_of(undo), **({"upid": upid} if submitted else {}),
                    **({"restores": restores} if restores else {})},
            called=called, remote=remote)
    out = {**_envelope(row, called, data), "undo": undo, "intent": intent}
    if submitted:
        out["task"] = _task_of(client, row, called, upid, TASK_WAIT_DEFAULT if wait is None else wait,
                               ledger_cfg, intent, remote)
    return out


def _capture_of(undo: dict[str, Any]) -> dict[str, str]:
    """THE TERMINAL ROW NAMES ITS CAPTURE. A restore asks how the captured mutation ended; paired
    by intent it read a LATER write at the same path as this one's landing (lens, 2026-10-08:
    a create the vendor refused, then a PUT that succeeded, and undo deleted the record that
    had been there all along). The id travels on the error row and the ok row, so the pairing
    is exact and a row without it is not a landing."""
    return {"capture": undo["id"]} if undo.get("captured") and undo.get("id") else {}


def _undo_before(row: Row, args: dict[str, Any], client: Any, called: str, cfg: Any, ledger_cfg: Any,
                 intent: str, remote: str | None, consent_id: str | None) -> dict[str, Any]:
    """The net taken before a mutation, or the receipt's words for why there is none (see execute)."""
    twin = table()[(row.product, "GET", row.twin)] if row.twin else None
    if row.net and args.get("snapshot") is True:
        undo = _snapshot_first(row, called, cfg, ledger_cfg, intent, remote, consent_id)
    elif row.wire == "ssh":
        undo = {"captured": False, "why": "a container command has no read-back"
                + ("; snapshot=true takes one first" if row.net else "")}
    elif not spine.undo_enabled():
        undo = {"captured": False, "why": f"{spine.UNDO_ENV}=off"}
    elif twin is None or twin.excluded or twin.gate:
        undo = {"captured": False, "why": (f"{row.product} publishes no GET {row.path}" if twin is None
                                            else f"the read of {row.path} is gated: {twin.gate or 'tunnel'}")}
    else:
        try:
            before: dict[str, Any] = {"before": ledgered(spine.bound(client.call("GET", called, {})),
                                                         rule=twin.secret)}
        except Exception as exc:
            # A JUDGED CREATE'S FAILED READ-BACK IS ABSENCE, AS THE VENDOR SAID IT (undo.toml):
            # the record the path names is not there yet, and the restore is its DELETE. Not
            # proof: a read can fail over a record that IS there, so the restore sends the
            # DELETE only when the ledger shows this create landed (the vendor refuses a
            # duplicate). Any other address keeps the rule: no net, no risky act.
            if not row.creates:
                reason = (f"undo unavailable: the read-back {twin.address} the vendor publishes could "
                          f"not be taken ({type(exc).__name__}); the mutation was not run")
                _record(ledger_cfg, "core.refuse", row, outcome="refused",
                        detail={"reason": reason, "needs": "undo", **wire_error(exc)},
                        called=called, remote=remote)
                raise ProximoError(reason) from exc
            before = {"absent": True, "read_back": wire_error(exc)}    # its own key: never a record's value
        # THE CAPTURE HAS AN ID: the row's own hash, handed back so a restore (B2) names THAT
        # record. `intent` is shared by every mutation at a path and would pick the latest.
        # The plane rides on the row because `governed_as` spells the address without it.
        point = _record(ledger_cfg, "core.undo_point", row, outcome="undo_point",
                        detail={"read": twin.address, **before, "intent": intent, "tier": row.tier,
                                "plane": row.product},
                        called=called, required=True, remote=remote)
        undo = {"captured": True, "read": twin.address, **({"absent": True} if "absent" in before else {}),
                "id": str((point or {}).get("entry_hash", ""))[:12]}
    return undo


def _snapshot_on(row: Row, args: dict[str, Any]) -> bool:
    """Whether a shell call's `snapshot` reads as true the way execute will read it (the CLI's
    "true" included); a value execute refuses is not a snapshot the plan announces."""
    if "snapshot" not in args:
        return False
    try:
        return coerce_args(row, {"snapshot": args["snapshot"]})["snapshot"] is True
    except ProximoError:
        return False


def _net_of_own_container(row: Row, path: str | None, cmd: Row, called: str) -> None:
    """THE CONSENT EXEMPTION IS ONE SHAPE ONLY. The snapshot's own consent id hashes a fresh
    snapname, so no grant could ever be placed for it ahead, and under enforced consent
    snapshot=true could never pass (lens B5c). It rides the guarded command's consent instead,
    and only as the snapshot the command's own `net` names, of THAT command's node and vmid."""
    try:
        own = fill(row.path, bind(cmd, called))     # the snapshot row's OWN path on THAT command's node and vmid
    except ProximoError:
        own = None
    # THE LITERAL PATH, not only the bound values: a bound comparison let the snapshot row be
    # dialled at any path of the same shape on the same container with consent skipped (lens 3 F1).
    if (not cmd.net or cmd.net["snapshot"] != f"{row.method} {row.path}"
            or path is None or rawdoor.canonical(path) != own):
        raise ProximoError("a consent exemption covers only the snapshot guarding its own container command")


SNAPSHOT_WAIT = 120     # seconds: 0.44's auto-undo waited the same for its snapshot task


def _snapshot_first(row: Row, called: str, cfg: Any, ledger_cfg: Any, intent: str,
                    remote: str | None, consent_id: str | None) -> dict[str, Any]:
    """UNDO for a container command (B5 stage 2; 0.44's `snapshot=True`). The snapshot is a
    governed mutation of its OWN, the vendor's `POST .../lxc/{vmid}/snapshot` through `execute`
    (armed, tiered, receipted, waited), so the net is as accountable as the act. FAIL-CLOSED:
    anything short of a task that finished OK refuses the command before it runs. The capture
    names the snapshot and the vendor's rollback, so `undo <id>` puts the container back."""
    where = bind(row, rawdoor.canonical(called))
    net = cast(Mapping[str, str], row.net)      # execute reaches here on `row.net and snapshot=true` alone
    snap = _at(row.product, net["snapshot"])
    name = "proximo_" + time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "_" + os.urandom(2).hex()
    path = fill(snap.path, where)

    def refused(why: str, exc: BaseException | None = None) -> ProximoError:
        reason = f"undo unavailable: the snapshot before this command did not land ({why}); the command was not run"
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": reason, "needs": "undo", "snapshot": name, **(wire_error(exc) if exc else {})},
                called=called, remote=remote)
        return ProximoError(reason)

    try:
        out = execute(snap, {"snapname": name, "description": f"before a governed command ({intent[:12]})"},
                      cfg=cfg, path=path, ledger_cfg=ledger_cfg, wait=SNAPSHOT_WAIT, net_of=(row, called, consent_id))
    except Exception as exc:
        raise refused(safe_exception_text(exc, paths=True), exc) from exc
    task = out.get("task") or {}
    if not task.get("succeeded"):
        raise refused(f"task {task.get('exitstatus') or task.get('status') or 'not seen to finish'}")
    method, _, template = net["rollback"].partition(" ")
    rollback = f"{method} {fill(template, {**where, 'snapname': name})}"
    point = _record(ledger_cfg, "core.undo_point", row, outcome="undo_point",
                    detail={"snapshot": name, "rollback": rollback, "intent": intent, "tier": row.tier,
                            "plane": row.product, "upid": task.get("upid")},
                    called=called, required=True, remote=remote)
    return {"captured": True, "snapshot": name, "rollback": rollback,
            "id": str((point or {}).get("entry_hash", ""))[:12]}


def _task_of(client: Any, row: Row, called: str, upid: str, wait: int, ledger_cfg: Any, intent: str,
             remote: str | None) -> dict[str, Any]:
    """The wait on a task-backed answer and its ONE receipt. The poll is the mutation's own
    read-back, like UNDO's: through the client already built, not governed, scoped or rated
    again (the operator was allowed the mutation; the poll reads what it did). An id that says
    UPID but is not the shape is handed back unpolled; a poll that fails is receipted with the
    vendor's status and the id, and the answer still carries the id (the vendor accepted the
    work: losing the id to an exception is what makes a caller fire it twice; lens 5)."""
    unwaited = {"upid": upid, "finished": False, "succeeded": False, "status": None, "exitstatus": None,
                "timed_out": False, "polls": 0, "seconds": 0}
    if not spine.upid_node(upid):
        return {**unwaited, "why": "the id is not a UPID shape; not polled"}
    # the node from the UPID, never the path's (a cluster call's task runs where the vendor says);
    # the remote (PDM) from the path the operator was allowed
    status_path = fill(row.task_status or "", {**bind(row, called), "node": spine.upid_node(upid), "upid": upid})
    polls = [0]
    last: dict[str, Any] = {}
    t0 = spine._CLOCK()

    def fetch():
        polls[0] += 1
        st = client.call("GET", status_path, {})
        if isinstance(st, dict):
            last.update(st)
        return st

    try:
        task = _task_wait(status_path, fetch, upid, wait)
    except Exception as exc:
        seconds = int(round(spine._CLOCK() - t0))
        seen = {"polls": polls[0], "seconds": seconds, "status": last.get("status"), "poll_error": wire_error(exc)}
        _record(ledger_cfg, "core.task", row, outcome="error",
                detail={"tier": row.tier, "intent": intent, "upid": upid, **seen}, called=called, remote=remote)
        return {**unwaited, **seen}
    if task["polls"]:
        outcome = "finished" if task["succeeded"] else ("timed_out" if task["timed_out"] else "failed")
        _record(ledger_cfg, "core.task", row, outcome=outcome,
                detail={"tier": row.tier, "intent": intent, "upid": upid, "polls": task["polls"],
                        "seconds": task["seconds"], "status": task["status"], "exitstatus": task["exitstatus"]},
                called=called, remote=remote)
    return task


TASK_WAIT_DEFAULT = 60


def _task_wait(status_path: str, fetch: Any, upid: str | None, wait: int) -> dict[str, Any]:
    """The wait, bounded 0..TASK_WAIT_MAX; 0 polls nothing and says so (polls 0). `upid` is the
    id the task dict names; on a status read it is the path's own placeholder. A task's exit
    text is vendor free text: it lands scrubbed of locators and bounded, in the receipt and in
    the answer alike (a failed command's message names hosts and paths)."""
    if upid is None or not status_path.endswith("/status") or "/tasks/" not in status_path:
        raise ProximoError(f"wait= is for a task-status address (/nodes/{{node}}/tasks/{{upid}}/status); "
                           f"{status_path} is not one")
    w = max(0, min(int(wait), spine.TASK_WAIT_MAX))
    if w == 0:
        return {"upid": upid, "finished": False, "succeeded": False, "status": None, "exitstatus": None,
                "timed_out": False, "polls": 0, "seconds": 0}
    t0 = spine._CLOCK()
    res = spine.task_wait(fetch, timeout=w)
    if isinstance(res["exitstatus"], str):
        res["exitstatus"] = safe_text(res["exitstatus"])
    return {"upid": upid, **res, "seconds": int(round(spine._CLOCK() - t0))}


# ---- TAINT at the seam ----------------------------------------------------------------------------
# The 0.44 server marked BY TOOL NAME inside `_audited`; the door serves addresses, so the row
# carries the classification (`taint.toml`) and the engine marks before the wire, on both
# branches, in the 0.44 order: a call that RAISES still taints, because an error body can carry
# attacker-shaped bytes too. A marker that cannot be written is a refusal with a receipt, never
# a read served untracked (the 0.44 `blocked:taint_mark_failed` posture). Inert with every
# PROXIMO_TAINT_* unset: no stat, no write, the envelope's `untrusted` label is the only trace.

def _audit_dir(ledger_cfg: Any) -> str:
    """The directory the marker lives in: beside the ledger, the env's ledger when none is given."""
    return os.path.dirname((ledger_cfg or LedgerConfig.from_env()).audit_log_path or "")


def _taint_before_the_wire(row: Row, ledger_cfg: Any, called: str, remote: str | None) -> None:
    if not (row.untrusted and spine.taint_tracking_on()):
        return
    audit_dir = _audit_dir(ledger_cfg)
    try:
        if not audit_dir:
            raise OSError("the ledger has no directory to hold the taint marker")
        spine.mark_tainted(audit_dir, row.key)
    except Exception as exc:  # noqa: BLE001 -- any failure to mark is a refusal to serve
        reason = (f"{row.key} is an untrusted read and the taint marker could not be written "
                  f"({type(exc).__name__}); the read was not served (fail-closed)")
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": reason, "needs": "taint", **wire_error(exc)},
                called=called, remote=remote)
        raise ProximoError(reason) from exc


def _untrusted_detail(row: Row) -> dict[str, Any]:
    """The 0.44 ledger stamp, under the same gate: tracking on, and the row is classified."""
    if row.untrusted and spine.taint_tracking_on():
        return {"untrusted": True, "content_trust": "adversarial"}
    return {}


# ---- what a receipt may carry ------------------------------------------------------------------
# The wrappers each kept their own secret key set out of the ledger (a password, an S3 secret
# key, a proxy's userinfo); the door serves every address with none of them. One rule at the one
# seam: a secret-NAMED argument is ledgered as a fingerprint (sha256 + length: proves which value
# without the value, the ledger's own idiom for ct_exec), a URL's userinfo is masked to its host,
# and the vendor's read-back captured for UNDO gets the same scrub. Names, not the vendor schema:
# the rule must be total over whatever a caller sends. `pub` in a name is a public key and stays;
# `alice@pam` is a userid, not a credential, so bare user@host without a scheme or a colon stays.
_SECRET_NAME = re.compile(
    r"pass|secret|hmac|private|keyring|certkey|credential|(^|[-_])(totp|otp)$|(keys?|tokens?)$", re.I)
_URL_AUTHORITY = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)?(?P<authority>[^/?#\s]*)")


def _fingerprint(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    shown = len(value) if isinstance(value, str) else len(blob)
    return f"[redacted sha256:{hashlib.sha256(blob.encode('utf-8')).hexdigest()[:12]} len:{shown}]"


def _mask_userinfo(text: str, *, url: bool = False) -> str:
    """`text` with a URL's userinfo masked to `[redacted]`, host[:port] kept. The userinfo ends
    at the LAST @ of the authority (a host never holds one): splitting at the first leaked the
    tail of a password that contains @, the bug pbs_admin's proxy mask fixed in Wave 5c.
    `url=True` is a field the record names as a URL, masked whatever the userinfo looks like;
    otherwise a bare `alice@pam` (no scheme, no colon) is a userid and stays."""
    m = _URL_AUTHORITY.match(text)
    if m is None or "@" not in m.group("authority"):
        return text
    userinfo, host = m.group("authority").rsplit("@", 1)
    if not url and not m.group("scheme") and ":" not in userinfo:
        return text
    return f"{m.group('scheme') or ''}[redacted]@{host}{text[m.end('authority'):]}"


def _plan_rule(row: Row) -> Rule:
    """The secret rule a PLAN answer is held to: the address's and its twin's named fields and
    the name rule, WITHOUT the bearer clause. A bearer line says the mutation's ANSWER is a
    credential; a plan holds the read's state and the caller's arguments, never that answer, and
    fingerprinting it whole made a storage create's `exists` unreadable."""
    return (*row.secret[:4], None)


def ledgered(value: Any, name: str | None = None,
             rule: Rule = _NO_RULE) -> Any:
    """`value` as a receipt may carry it: secret-named keys and the record's fields (`rule`,
    the row's `secret`) fingerprinted, URL userinfo masked (strictly in the record's URL
    fields), recursively; every other shape byte for byte. Under a BEARER line the whole value
    is the credential (a login link), so the whole value is fingerprinted, at any depth: an
    UNDO capture of such a read, or the args of a mutation at its path, never lands raw."""
    if rule[4] is not None:
        return _fingerprint(value)
    if name is not None and (name in rule[0] or (_SECRET_NAME.search(name) and "pub" not in name.lower())):
        return _fingerprint(value)
    if isinstance(value, dict):
        return {k: ledgered(v, str(k), rule) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [ledgered(v, None, rule) for v in value]
    if isinstance(value, str):
        return _mask_userinfo(value, url=name in rule[1])
    return value


def _envelope(row: Row, called: str, data: Any, fields: str | None = None) -> dict[str, Any]:
    # By the address's OWN line when it has one, else the READ's, whatever the verb: a mutation
    # that echoes its resource (PBS's PUT of an OpenID realm returns the config, client-key
    # included) carries what its read carries; a token mint answers a secret its read never
    # shows, so its own line says bearer (served whole, labelled) or drops the echo.
    # WITHHOLD, then PROJECT, then BOUND: the withheld list names every credential the vendor
    # sent, even one projection would have dropped; the cap sees the projected size.
    data, withheld = withhold(data, row.secret)
    total = len(data) if isinstance(data, list) else None
    if row.access == READ:
        data = project(data, fields)
    # THE SIZE LAW, the raw door's: a read over the cap is reported (a list cut by rows with its
    # count; anything else by size with a head), never handed to the model whole. The wrappers
    # bounded output by their defaults (a `limit`, a `lastentries`); the door serves the vendor's,
    # and some of those are unbounded.
    over = rawdoor.bounded(data) if row.access == READ else None
    if over is not None and "returned" in over and fields is None:
        # OVER THE CAP, A DEFAULT READ ANSWERS WHOLE AND SMALLER. A cut list fits and is wrong:
        # 16 of 37 rows is most of the estate missing. Rows asked for by name keep the cut, and
        # so do a list whose rows carry their own content (a log's lines) or no state to count,
        # and a summary that would not fit the cap itself (lens 2026-09-28: 150 enum fields made
        # a 9 KB "summary" against 2 KB): there the cut is the smaller answer.
        summary = summarize(data)
        if summary["tally"] and rawdoor.bounded(summary) is None:
            over = summary
    fenced = row.untrusted and spine.fence_on()
    if over is not None and "minority" in over and fenced:
        over["minority"] = spine.fence(row.key, over["minority"])
    if over is not None and "head" in over:
        over["head"] = spine.fence(row.key, over["head"]) if fenced else over["head"]
    if over is not None and "data" in over and fenced:
        over["data"] = spine.fence(row.key, over["data"])
    return {
        "address": row.address,
        "plane": row.product,
        "access": row.access,
        "derived": False,          # the vendor's bytes, never composed prose
        "matched_path": row.path,  # the published address that governed this call
        "called_path": called,     # what actually went to the wire
        "tier": row.tier,
        "untrusted": row.untrusted,   # a fact about the address, like the tier; the env gates behaviour
        **({"total": total} if total is not None else {}),   # counted at the gate, from the raw rows
        **(over if over is not None else {"data": spine.fence(row.key, data) if fenced else data}),
        **({"withheld": withheld} if withheld else {}),   # the record's fields this response carried
        # a response that IS a credential is served whole (the caller asked for it) and says so;
        # the ledger never holds a read's bytes and the store keeps lists only, so it goes no further
        **({"bearer_credential": b} if (b := row.secret[4]) else {}),
    }


# ---- OVER THE CAP: the count, a tally per state, the rows not in the most common state ---------
# A state is a field of names or flags that takes at most _STATES values across the rows (status,
# type, lock, template), counted with "(absent)" for a row that lacks it, so the one locked guest
# among 300 is an exception and not a silence. Ids and names are identity, never a state. The
# tally is across all rows; the most common state is judged WITHIN each `type` when every row has
# one, because a mixed list (cluster resources: nodes, storage, guests) measured against one mode
# called 18 of 37 live rows exceptions: storage is "available", never "running".

_STATES = 5
_ABSENT = "(absent)"


def _identity_key(k: str) -> bool:
    return k == "id" or k.endswith("id") or k in ("name", "node")


def _spell(row: dict, k: str) -> str:
    if k not in row:
        return _ABSENT
    v = row[k]
    return v if isinstance(v, str) else json.dumps(v)


def _carries_content(records: list[dict]) -> bool:
    """A field on EVERY row, unique on most of them and not an id, is the row's own content (a
    log line, a message): a tally would erase it. `tags` on cluster resources is free text too,
    but on guests only, so it does not make the estate read a log (measured live: 29 of 37)."""
    for k in {k for r in records for k in r if not _identity_key(k)}:
        vals = [r.get(k) for r in records]
        if all(k in r for r in records) and len({json.dumps(v) for v in vals}) > len(records) // 2:
            return True
    return False


def summarize(rows: list[Any]) -> dict[str, Any]:
    records = [r for r in rows if isinstance(r, dict)]
    tally: dict[str, dict[str, int]] = {}
    if _carries_content(records):
        return {"summarized": True, "tally": tally, "minority": [], "minority_total": 0}
    for k in sorted({k for r in records for k in r if not _identity_key(k)}):
        if any(k in r and not (isinstance(r[k], (str, bool)) or r[k] is None) for r in records):
            continue
        counts = Counter(_spell(r, k) for r in records)
        if len(counts) <= _STATES:
            tally[k] = dict(counts.most_common())
    group = (lambda r: _spell(r, "type")) if records and all("type" in r for r in records) else (lambda r: "")
    modes: dict[str, dict[str, str]] = {}
    for g in {group(r) for r in records}:
        members = [r for r in records if group(r) == g]
        modes[g] = {k: Counter(_spell(r, k) for r in members).most_common(1)[0][0]
                    for k, v in tally.items() if len(v) > 1}
    minority = []
    for r in records:
        odd = {k: r.get(k) for k, mode in modes[group(r)].items() if _spell(r, k) != mode}
        if odd:
            minority.append({**{k: v for k, v in r.items() if _identity_key(k)}, **odd})
    out: dict[str, Any] = {"summarized": True, "tally": tally, "minority": minority,
                           "minority_total": len(minority),
                           "note": "over the cap: counts per state and the rows not in the most "
                                   "common one; fields= or the path's params for rows"}
    # The minority gets the room the rest of the summary leaves under the cap, row by row, so
    # the whole summary fits (cut to the full cap, it pushed the summary over and lost it).
    room = rawdoor.max_bytes() - len(json.dumps({**out, "minority": [], "minority_returned": 0},
                                                default=str))
    kept, used = [], 2
    for r in minority:
        size = len(json.dumps(r, default=str)) + 2
        if used + size > room:
            out.update(minority=kept, minority_returned=len(kept))
            break
        kept.append(r)
        used += size
    return out


# ---- THE STORE: a read leaves a snapshot; since= compares two of them, no vendor call --------

def _box(row: Row, cfg: wire.Plane | None) -> str:
    return (cfg.base_url if cfg is not None else wire.env_base_url(row.product)) or ""


def _keep(row: Row, called: str, args: dict[str, Any], data: Any, ledger_cfg: Any,
          cfg: wire.Plane | None) -> None:
    """Best-effort and silent: a convenience must never fail the read it rides on."""
    if not store.enabled() or not isinstance(data, list):
        return
    try:
        rows, _ = withhold(data, row.secret)
        records = [lean(r) for r in rows if isinstance(r, dict)]
        if rows and not records:
            return
        lcfg = ledger_cfg or LedgerConfig.from_env()
        store.keep(store.directory(lcfg.audit_log_path), row.product, _box(row, cfg), called, args, records)
    except Exception:  # noqa: BLE001, S110 -- see the docstring
        pass


def _recall(row: Row, called: str, args: dict[str, Any], since: str, ledger_cfg: Any,
            remote: str | None, cfg: wire.Plane | None) -> dict[str, Any]:
    try:
        if not store.enabled():
            raise ProximoError("the store is off on this box (PROXIMO_STORE); since= needs it")
        lcfg = ledger_cfg or LedgerConfig.from_env()
        answer = store.changes(store.directory(lcfg.audit_log_path), row.product, _box(row, cfg),
                               called, args, since)
    except ProximoError as exc:
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": str(exc), "needs": "store"}, called=called, remote=remote)
        raise
    # TAINT CARRIES THROUGH THE STORE. A kept row of an untrusted read is the same guest-authored
    # bytes the live read serves (cluster resources is one: guest names ride every row), so its
    # answer marks the session and is fenced exactly as the read would be; storage never launders.
    _taint_before_the_wire(row, ledger_cfg, called, remote)
    _record(ledger_cfg, "core.recall", row, outcome="ok",
            detail={"source": "store", **answer["counts"], **_untrusted_detail(row)},
            called=called, remote=remote)
    cut = rawdoor.bounded(answer["changes"])
    if cut is not None and "returned" in cut:
        answer.update(changes=cut["data"], changes_returned=cut["returned"])
    if row.untrusted and spine.fence_on():
        answer["changes"] = spine.fence(row.key, answer["changes"])
    return {"address": row.address, "plane": row.product, "access": row.access,
            "derived": True,           # composed by the door from what it kept, not the vendor's bytes
            "matched_path": row.path, "called_path": called, "tier": row.tier,
            "untrusted": row.untrusted, **answer}


# ---- LEAN BY DEFAULT: a row keeps its names, states and ids and drops its counters ------------
# Measured 2026-09-27 on the real cluster: 37 resource rows raw cost 4,299 tokens, the 0.44
# wrapper's projection of the same rows 1,013. One rule at the gate replaces a lean tuple per
# wrapper: a string, a bool or a null is a name or a state and stays; a number is a counter
# (bytes, seconds, pressure, a pid) and goes, unless its key names an id. `fields="all"` is the
# vendor's rows untouched; `fields="a,b"` is exactly those, in that order, and a name no row
# carries is refused with the names that exist, so a typo teaches instead of thinning to nothing.
# A row that would keep nothing stays whole: projection fails OPEN, only the cap fails closed.

def lean(row: dict) -> dict:
    kept = {k: v for k, v in row.items()
            if isinstance(v, (str, bool)) or v is None or k == "id" or k.endswith("id")}
    return kept or row


def project(data: Any, fields: str | None) -> Any:
    """Row by row: a record (a dict) is projected, anything else in the list rides through as
    it came (lens 2026-09-27: one stray None used to switch lean OFF for the whole list)."""
    if fields is not None and fields.strip().lower() == "all":
        return data
    if not isinstance(data, list):
        return data
    records = [r for r in data if isinstance(r, dict)]
    if fields is None:
        return [lean(r) if isinstance(r, dict) else r for r in data]
    want = [f.strip() for f in fields.split(",") if f.strip()]
    if not want:
        raise ProximoError("fields: give names ('a,b'), 'all', or leave it out for the lean rows")
    if not records:
        raise ProximoError("fields: the rows are not records, there is nothing to project")
    have = {k for r in records for k in r}
    for name in want:
        if name not in have:
            raise ProximoError(f"fields: no row carries {name!r}; the rows carry: {', '.join(sorted(have))}")
    return [{k: r[k] for k in want if k in r} if isinstance(r, dict) else r for r in data]


# ---- what a response may carry -----------------------------------------------------------------
# The wrappers each stripped their own credentials from a READ before the model saw it (a PBS
# remote's password, a fetchmail pass, an SDN lock token); the door served the same addresses
# with none of it. One record (secrets.toml), one function, both doors: the governed engine
# below and the raw GET door (`tools/raw_door.py`) call `withhold` before an envelope exists.
# a cloud-config `password:`/`passwd:` line (also `hashed_passwd`, `plain_text_passwd`), any indent
_PASSWORD_LINE = re.compile(r"(?im)^(?P<head>[ \t-]*(?:plain_text_|hashed_)?passw(?:or)?d[ \t]*:[ \t]*)\S.*$")


def withhold(data: Any, rule: Rule) -> tuple[Any, list[str]]:
    """`data` with the rule's credential fields removed (at any depth) and its URL fields'
    userinfo masked; plus the sorted names actually withheld, for the envelope to say.
    Two shapes a field name cannot reach: a `{key, value, pending}` row (PVE's pending and
    cloud-init reads name the option in `key` and carry the secret in `value`), whose values
    are withheld when `key` is in the line's `rows`; and a text body (the rendered cloud-init
    user-data), whose `password:` lines are masked when the line says `text`.
    A row the record does not name (`_NO_RULE`) comes back untouched."""
    if rule == _NO_RULE:
        return data, []
    drop, urls, rows, text, _bearer = rule
    seen: set[str] = set()

    def walk(v: Any) -> Any:
        if isinstance(v, dict) and v.get("key") in rows:
            seen.add(v["key"])
            return {k: ("[withheld]" if k in ("value", "pending") and x is not None else x) for k, x in v.items()}
        if isinstance(v, str) and text:
            masked = _PASSWORD_LINE.sub(r"\g<head>[withheld]", v)
            if masked != v:
                seen.add("password")
            return masked
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                if k in drop:
                    seen.add(k)
                    continue
                if k in urls and isinstance(x, str) and (masked := _mask_userinfo(x, url=True)) != x:
                    seen.add(k)
                    out[k] = masked
                    continue
                out[k] = walk(x)
            return out
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(data), sorted(seen)


def _record(cfg: Any, action: str, row: Row, *, outcome: str, detail: dict,
            called: str | None = None, required: bool = False, remote: str | None = None) -> dict | None:
    """Write one ledger row and hand it back (None when a best-effort write failed). `cfg` here
    is the LEDGER's config, never a plane's.

    They were one parameter, and `conf = cfg` then handed a PbsConfig -- which has no
    `arm_source` and no `audit_log_path` -- to `arm_state` and `AuditLedger`. A refusal became
    an AttributeError on three of four planes, and a receipt crashed AFTER the wire was touched.

    BEST-EFFORT for a refusal or a read, REQUIRED before a mutation. An unconfigured box has no
    ledger path, so a refusal there cannot be recorded -- but it must still REFUSE; letting the
    audit write raise would invert that into a crash on the safe path, which is how a governance
    layer teaches operators to route around it. A read changes nothing, so bookkeeping must not
    outrank it either. But the rows written BEFORE a mutation (the undo point, the `executing`
    row) are the mutation's only trace if the process dies, and a lens showed that swallowing
    their failure let a box whose ledger could not be opened run the mutation with zero trace
    and hand back a normal envelope. 0.44 blocked there; so does this: `required=True` turns a
    failed write into a refusal, and the mutation does not run.
    """
    try:
        # THE KEYED POLICY, NOT A BARE FILE APPEND. `AuditLedger(path)` wrote an UNKEYED row, and
        # the MCP door opens the ledger keyed by default: its next `open_ledger` read the file as
        # unkeyed, sealed the whole keyed chain into an archive and started a fresh log. One
        # shell-door receipt rotated the estate's chain. Same file was never the same ledger
        # until both doors opened it through the same function.
        return open_ledger(cfg or LedgerConfig.from_env()).record(
            # THE TARGET IS WHAT RAN. `row.address` is the published template, so a receipt
            # built from it alone says `/nodes/{node}/qemu/{vmid}` and never which VM died.
            action, target=called or row.address, mutation=row.access == MUTATE,
            outcome=outcome, detail={**detail, "governed_as": row.address}, remote=remote,
            # WHO ASKED. The 0.44 rows carried the name tag and the verified badge; the core's
            # rows dropped both, so one box's ledger said who asked on one door and not the
            # other. None when neither is configured, and the row is byte-identical to before.
            principal=ledger_principal(),
        )
    except Exception as exc:  # noqa: S110 -- deliberate, see below
        # BROAD AND SILENT ON PURPOSE for the best-effort rows. A narrow tuple let an
        # AttributeError out of the ledger write and it REPLACED the wire exception the caller
        # needed to see -- the real error survived only in __context__, and the door, which
        # branches on type, exited 1 naming the ledger. Bookkeeping must never outrank the
        # thing it is bookkeeping. The required rows are the exception, and say so.
        if required:
            raise ProximoError(
                f"the audit ledger could not be written ({type(exc).__name__}) and a mutation "
                f"with no receipt does not run; fix PROXIMO_AUDIT_LOG or its directory"
            ) from exc
