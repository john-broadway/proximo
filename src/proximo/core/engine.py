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

import contextlib
import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import cache
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import unquote

from proximo.core import (
    apitree,
    arm,
    consult,
    download,
    memory,
    rawdoor,
    risk,
    safetynet,
    shell,
    sight,
    spine,
    store,
    wire,
)
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
    arg_public: frozenset[str] = frozenset()    # names the name rule would hide that are not secrets (secrets.toml)
    creates: str | None = None   # a judged create (undo.toml): a failed read-back is absence, the restore its DELETE
    notes: tuple[Mapping[str, Any], ...] = ()   # what the plan says when the arguments meet a condition (notes.toml)
    raises: tuple[Mapping[str, Any], ...] = ()  # a tier raised by a value the call names (tiers.toml [raise])
    sight: Mapping[str, Any] | None = None      # an empty answer here is judged by what the token holds (sight.toml)
    consult: str | None = None   # the judge the plan consults before the change (consult.toml; proximo.core.consult)
    one_of: Mapping[str, Any] | None = None     # a call must name at least one of these parameters (args.toml)

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
    "forbid", "consent", "rate", "taint", "undo", "prove", "arguments", "path", "store", "sight", or an
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
               if x else _NO_RULE, arg_secrets=frozenset(r["arg_secrets"]), arg_public=frozenset(r["arg_public"]),
               creates=r["creates"],
               notes=tuple(MappingProxyType({**n, "given": tuple(n.get("given", ())),
                                             "not_given": tuple(n.get("not_given", ()))})
                           for n in r["notes"]),
               raises=tuple(MappingProxyType({**x, "when": MappingProxyType(
                   {k: tuple(v) for k, v in x["when"].items()})}) for x in r["raises"]),
               sight=MappingProxyType({**r["sight"], "sighted": tuple(tuple(a) for a in r["sight"]["sighted"]),
                                       "when": MappingProxyType({k: tuple(v) for k, v in r["sight"]["when"].items()})})
               if r["sight"] else None,
               consult=r["consult"],
               one_of=MappingProxyType({**r["one_of"], "names": tuple(r["one_of"]["names"])}) if r["one_of"] else None)


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


def _NOT_SECRET_MARK(row: Row) -> frozenset[str]:  # noqa: N802 -- a marker set, read like a constant
    """The names a row's `public` line (secrets.toml) judges NOT secret, as `!name` markers beside the
    rule's drop set: `ledgered` reads a marker as 'the name rule does not apply to this name here'."""
    return frozenset("!" + n for n in row.arg_public)


def arg_rule(row: Row) -> Rule:
    """The rule for ledgering a mutation's ARGUMENTS: the response rule's drops (a PUT that echoes
    its resource) UNION the arg-secret names for this row's own address, so a guest exec's argv and
    a file-write's content are fingerprinted in the executing row, never written raw."""
    # Arguments are never "a bearer": a token mint's own line labels its ANSWER the credential;
    # its arguments (a comment, an expiry) are receipted by name like any other.
    return (row.secret[0] | row.arg_secrets | _NOT_SECRET_MARK(row), *row.secret[1:4], None)


def resolve(product: str, method: str, path: str) -> Row:
    """The Row for this address, or a refusal naming the nearest published alternatives.

    Unknown addresses are refused BEFORE any wire is touched and before any credential is read:
    a typo must cost nothing and reveal nothing.
    """
    if product not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {rawdoor.quote(product)}; known planes: {', '.join(apitree.PRODUCTS)}")
    rawdoor.check_input("method", method)          # absurd input is refused here, never echoed below
    rawdoor.check_input("path", path)
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
        raise ProximoError(
            f"{product} publishes no {method} {rawdoor.shorten(path)}. "
            + _where_instead(product, method, path, nearest) + _split_value_hint(path, nearest)
        )
    return row


def _suggestible(product: str, method: str, path: str) -> bool:
    """A path worth naming to a caller: a published row of THIS method that is not gated or held
    to a lane the caller did not open (a console tunnel, a vnc proxy) and not an ssh row."""
    row = table().get((product, method, path))
    return row is not None and not row.gate and not row.excluded and not row.held and row.wire != "ssh"


def _where_instead(product: str, method: str, path: str, nearest: list[str]) -> str:
    """The sentence after a refusal that says where to go. Paths that share leading segments come
    first (a typo past a real prefix). A path that shares none (`/containers/105`, `/snapshot`) is
    read as WORDS, the way `proximo_plan` reads them: its alphabetic segments through the same
    search the door's find uses, so `containers` reaches `lxc`. A found path is named only when
    one of the words (or its vocabulary synonym) is a segment of it: filler like `no` or `such`
    reaches addresses by their descriptions, which is not near. Never "none": a model that is
    told there is nothing nearby stops, and there is always `proximo_find` to ask."""
    nearest = [p for p in nearest if _suggestible(product, method, p)]
    if nearest:
        return f"Nearest published {method} paths: {', '.join(nearest)}."
    from proximo.core import search  # noqa: PLC0415 -- search imports this module
    words = [w.lower() for seg in path.split("/") for w in re.split(r"[^A-Za-z]+", seg) if len(w) > 1]
    if words:
        try:
            found = search.find(" ".join(words), plane=product, limit=20, method=method)["matches"]
        except ProximoError:
            found = []
        alts = {search.stem(w) for w in words}
        for w in words:
            for key in (w, search.stem(w)):
                alts |= {search.stem(m) for m in search.synonyms().get(key, ())}
        close = [m["path"] for m in found if _suggestible(product, method, m["path"]) and alts & {
            t for seg in m["path"].strip("/").split("/") if not seg.startswith("{") for t in search.tokens(seg)}]
        if close:
            return f"Nearest published {method} paths: {', '.join(close[:5])}."
    return (f"No published {method} path is close to it. Ask proximo_find with a verb and a noun "
            f"('list datastores') to see what {product} publishes.")


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


def _route_refusal(row: Row, path: str | None, cfg: wire.Plane | None, verdict: Verdict) -> Verdict | None:
    """A shell row on a named target needs its path's node mapped to an ssh destination; the refusal
    when it is not (needs=config), else None. A template path is a preview and has no node to route."""
    if row.wire != "ssh" or not path or "{" in path or not (verdict.allowed or verdict.needs in ("arm", "consent")):
        return None
    try:
        shell.resolve_target(cfg, rawdoor.canonical(path))
    except ProximoError as exc:
        return Verdict(False, str(exc), "config", consent_id=verdict.consent_id)
    return None


def plan(row: Row, args: dict[str, Any] | None = None, path: str | None = None,
         cfg: wire.Plane | None = None, ledger_cfg: Any = None, env: dict[str, Any] | None = None,
         detail: str | None = None) -> dict[str, Any]:
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

    THE PLAN IS CAPPED LIKE ANY ANSWER (the 4K window is the door's to keep, not the model's). The
    vendor publishes up to 93 parameters for one address (a qemu create plan was 3,201 real tokens),
    so `published_parameters` carries the ones the caller GAVE and the required ones it LACKS, each
    by type, and `parameters_more` counts the rest. `detail` is the full schema on request: a list of
    names ('name,memory') for those, or 'all'; asked for, it is still capped, with a `next`. Every
    key that carries the verdict (rawdoor.PROTECTED) stays whole whatever the size.
    """
    args = dict(args or {})
    unnamed: ProximoError | None = None
    try:
        path, node = default_node(row, path, args, cfg)
    except ProximoError as exc:
        path, node, unnamed = path, None, exc
    verdict = govern(row, cfg=cfg, path=path, args=args, ledger_cfg=ledger_cfg, consent_covered=_has_api_net(row))
    if unnamed is not None:
        verdict = Verdict(False, str(unnamed), "config")
    route_refused = False
    if path and "{" not in path and row.access != READ and (verdict.allowed or verdict.needs in ("arm", "consent")):
        # (a tunnel, a gate, a wall keeps its own words: those refusals name what no argument
        # can fix, lens 12)
        # WHAT EXECUTE WILL REFUSE, THE PLAN REFUSES: a placeholder given twice with different
        # values is not a call that runs, so it is not a verdict of "allowed" (lens 10), and on
        # an unarmed box it is still not a no-op (lens 11): arguments come before arm, the one
        # thing the caller can fix without an operator.
        if (twice := _given_twice(row, bind(row, path), args)) is not None:
            verdict = Verdict(False, twice, "arguments", consent_id=verdict.consent_id)
    if row.access != READ and (verdict.allowed or verdict.needs in ("arm", "consent")) \
            and (none_of := one_of_refusal(row, args)):
        # THE SAME ORDER AS THE CALL: arguments before arm. An empty call is not a no-op on an
        # unarmed box either; the one thing the caller can fix without an operator is the call.
        verdict = Verdict(False, none_of, "arguments", consent_id=verdict.consent_id)
    # The route is judged BEFORE the net's reads and the live state: a call that cannot be dialled reads nothing.
    if (unrouted := _route_refusal(row, path, cfg, verdict)) is not None:
        verdict, route_refused = unrouted, True
    # a rollback's net reads come BEFORE the consent look: the grant binds what the plan says about
    # the net, and the reads may taint the session
    view = _plan_net_view(row, args, path, cfg, ledger_cfg, verdict) if _has_api_net(row) else None
    if view is not None:
        verdict = _net_verdict(row, path, args, cfg, ledger_cfg, verdict, view)
    elif not route_refused:
        verdict = _shell_net_verdict(row, args, path, cfg, ledger_cfg, verdict)
    out = {
        "address": row.address, "plane": row.product, "access": row.access, "tier": row.tier,
        "why": row.why, "untrusted": row.untrusted, "channel": row.channel,
        "allowed": verdict.allowed, "reason": verdict.reason, "needs": verdict.needs,
        # Echoed as the receipt holds them: a secret-named argument fingerprinted, never raw.
        "arguments": ledgered(args, None, _plan_rule(row)) if args else args,
        **_parameters_of(row, args, path, detail),
    }
    if node:
        out["default_node"] = {"node": node, "from": NODE_ENV, "path": path}
    if reading := risk.hint(row, args):
        out["risk_hint"] = reading        # advice: a word and a closed list of labels, never the command
    if held := notes_held(row, args):
        out["notes"] = held
    out.update(_tier_fields(row, path, args))
    if verdict.consent_id:
        out["consent_id"] = verdict.consent_id
        out["consent"] = spine.consent_state(verdict.consent_id, _audit_dir(ledger_cfg) or ".")
        if out["consent"] == "advisory":
            out["reason"] = (f"{out['reason']}; consent is advisory: a grant the agent's own user owns, "
                             "a speed bump, not a lock")
        gp = spine.grant_path(verdict.consent_id)
        if gp:
            out["grant_path"] = gp
    if view is not None:
        out.update(_safety_net_plan(row, view))
    elif row.net and _snapshot_on(row, args):
        # ONE GRANT, TWO VENDOR MUTATIONS: the plan the operator approves says so (lens B5c-3).
        snap = _at(row.product, row.net["snapshot"])
        out["also"] = {"address": snap.address, "tier": snap.tier, "consent": "covered by this plan's grant",
                       "why": "snapshot=true takes the container's snapshot first; if it does not land, "
                              "the command is not run"}
    # A HELD address is never read for its live state: the plan's answer is the sentence, and a
    # read of its twin (a login's GET) would dial the vendor for a call that will not run.
    if row.access != READ and verdict.needs not in ("arguments", "held") and not route_refused:
        out.update(_live_state(row, args, path, cfg, ledger_cfg, env))
        if row.consult:
            _plan_consult(row, verdict, out, path, args, cfg, ledger_cfg)
    if row.lane == "download" and verdict.allowed:
        # where the bytes would land; nothing is dialled, and a refused lane learns no path (lens 3)
        try:
            lands_under, cap = download.settings()
            out["download"] = {"lands_under": lands_under, "cap_bytes": cap}
        except ProximoError as exc:
            out["download"] = {"refused": str(exc)}
    return _displayed(out, row)


_PLAN_ENTRIES = (10, 6, 4, 3, 2, 1)


#: A MUTATION PLAN to a model is the verdict and the NAMES of what it sent: the model wrote the values, so they
#: are not echoed back. A short value (up to SHORT_VALUE characters) is shown; a longer one is a length and a
#: hash, in place. Every argument name is shown (cut by echo) up to NAMES_SHOWN, and the rest counted. The whole
#: of it, every value, is the operator's: `proximo-core consent show <consent_id>`.
SHORT_VALUE = 48
NAMES_SHOWN = 48


def _echoed_entries(out: dict[str, Any], n: int, arguments: bool = True) -> dict[str, Any]:
    """`out` with the caller's `arguments` (when `arguments`) and the diff's `change` shown as at most `n`
    entries each, every key and value through the shared echo rule (rawdoor.echo), and the count of the rest.
    DISPLAY ONLY: the consent id and the wire arguments were fixed from the full values before this runs."""
    shown = dict(out)
    if arguments and isinstance(out.get("arguments"), dict) and out["arguments"]:
        shown["arguments"], more = rawdoor.echo_map(out["arguments"], n, 64)
        if more:
            shown["arguments_more"] = more
    if isinstance(out.get("change"), dict) and out["change"]:
        items = list(out["change"].items())
        rows = {}
        for k, v in items[:n]:
            both = isinstance(v, dict) and set(v) <= {"from", "to"}
            rows[rawdoor.echo(str(k), 40)] = ({a: rawdoor.echo_value(b, 64) for a, b in v.items()} if both
                                               else rawdoor.echo_value(v, 64))
        shown["change"] = rows
        if len(items) > n:
            shown["change_more"] = len(items) - n
    return shown


def _mutation_arguments(args: dict[str, Any], consent_id: str | None) -> dict[str, Any]:
    """The `arguments` of a mutation plan for a model: every name (up to NAMES_SHOWN), a short value whole, a
    long one as `[N chars sha256:<12 hex>]` in place, and the operator's command with the id."""
    shown: dict[str, Any] = {}
    long_ones: list[str] = []
    for k, v in list(args.items())[:NAMES_SHOWN]:
        key = rawdoor.echo(str(k), 64)
        text = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"), default=str)
        if v is None or isinstance(v, (bool, int, float)) or len(text) <= SHORT_VALUE:
            shown[key] = rawdoor.plain_deep(v)
        else:
            shown[key] = f"[{len(text)} chars sha256:{rawdoor.fingerprint(text)}]"
            long_ones.append(key)
    out: dict[str, Any] = {"arguments": shown}
    if len(args) > NAMES_SHOWN:
        out["arguments_more"] = len(args) - NAMES_SHOWN
    if long_ones:
        out["not_shown_whole"] = long_ones
    if long_ones or len(args) > NAMES_SHOWN:
        out["operator_view"] = f"proximo-core consent show {consent_id}" if consent_id else "proximo-core --plan"
    return out


def _displayed(out: dict[str, Any], row: Row | None = None) -> dict[str, Any]:
    """The plan as it is handed out. THE OPERATOR'S VIEW (the shell door, no model) is whole. A MODEL is
    handed the capped answer: for a read, the echoed entries bounded by the shared echo rule; for a
    MUTATION, every argument NAME and a short value (`_mutation_arguments`; a long one is its length and hash),
    and only the diff and the live record shrink to fit the plan's cap. The model wrote its values, so they
    are not echoed back; the operator's whole view is `proximo-core consent show`."""
    if rawdoor.operator_view():
        return out
    cap = rawdoor.plan_cap()
    mutation = row is not None and row.access != READ
    base = out
    if isinstance(out.get("why"), str):          # the authored tier sentence: its first sentence to a model
        base = {**out, "why": rawdoor.first_sentence(out["why"])}
    if mutation and row is not None and isinstance(out.get("arguments"), dict):
        base = {**base, **_mutation_arguments(out["arguments"], out.get("consent_id"))}
    n_args, n_change = len(out.get("arguments") or {}), len(out.get("change") or {})
    sizes = n_change if mutation else max(n_args, n_change)
    tries = [n for n in _PLAN_ENTRIES if n < sizes] or [_PLAN_ENTRIES[-1]]
    if sizes <= _PLAN_ENTRIES[0]:
        tries = [sizes] + [n for n in tries if n < sizes]
    answer = base
    for n in tries:
        answer = rawdoor.fit_answer(_echoed_entries(base, n, arguments=not mutation), cap=cap)
        body = json.dumps(answer, separators=(",", ":"), default=str)
        if rawdoor.fits(len(body.encode()), body, cap=cap):
            break
    return answer


def _brief(spec: Mapping[str, Any]) -> Any:
    """A parameter by what a caller needs to send it right: its type ("string"), and with its enum or
    default where the vendor published one. The vendor's sentence about it is `detail`."""
    extra = {k: spec[k] for k in ("enum", "default") if k in spec}
    return {"type": spec.get("type"), **extra} if extra else spec.get("type")


def _parameters_of(row: Row, args: dict[str, Any], path: str | None, detail: str | None) -> dict[str, Any]:
    """The plan's `published_parameters` (see `plan`): name -> type for the ones given and the required
    ones lacking (`required_missing` names those), or the full schema of the ones asked for."""
    if detail is not None:
        want = [n.strip() for n in detail.split(",") if n.strip()]
        if detail.strip().lower() == "all":
            return {"published_parameters": {n: dict(s) for n, s in row.params.items()}}
        shown = {n: dict(row.params[n]) for n in want if n in row.params}
        out: dict[str, Any] = {"published_parameters": shown}
        if missing := [n for n in want if n not in row.params]:
            out["unknown_parameters"] = [rawdoor.echo(n, 40) for n in missing[:10]]
        if len(row.params) > len(shown):
            out["parameters_more"] = len(row.params) - len(shown)
        return out
    given = {_published(row, k) or k for k in args}
    bound = set(placeholders(row.path)) if path and "{" not in path else set()
    lacking = [n for n, sp in row.params.items() if sp.get("optional") is False and n not in bound and n not in given]
    shown = {n: _brief(sp) for n, sp in row.params.items() if n in given or n in lacking}
    out = {"published_parameters": shown}
    if lacking:
        out["required_missing"] = lacking
    if (more := len(row.params) - len(shown)) > 0:
        out["parameters_more"] = more
        out["next"] = f"{more} more: fields='a,b' or 'all'"
    return out


def _plan_consult(row: Row, verdict: Verdict, out: dict[str, Any], path: str | None, args: dict[str, Any],
                  cfg: wire.Plane | None, ledger_cfg: Any) -> None:
    """The plan's `consult` section, the tier it raises, and the verdict the consult's own reads
    leave (see `plan`); writes into `out`."""
    # THE SECOND LOOK (consult.toml): the judge's reads, through `execute` like the twin's,
    # and the tier it raises to. On a template or a bare box it says why it could not
    # look and raises to the judge's worst case: a plan is never quieter for knowing less.
    # A plan refused for a reason the operator does not lift by arming or granting (a
    # forbid, a taint wall, no tier) dials nothing for advice on a call that will not run.
    marked_before = _marked(ledger_cfg)
    if verdict.allowed or verdict.needs in ("arm", "consent"):
        section = consult.run(row, path, args, cfg, ledger_cfg)
    else:
        section = consult.not_read(row, f"the plan is refused (needs: {verdict.needs}); the estate was not read")
    section = {**section, "seen_at": "plan"}
    tier, raised = with_consult(out["tier"], out.get("tier_raised"), section)
    if tier != out["tier"]:
        out.update(tier=tier, tier_authored=row.tier, tier_raised=raised)
    if spine.taint_tracking_on():
        # The consult's reads may have marked the session (design rule 7): judge the call again,
        # so the plan says what execute will meet, whichever ran first. The marker is the
        # evidence (govern re-stats it), not the section's flag: a read that failed at the wire
        # marked the session before it failed.
        again = govern(row, cfg=cfg, path=path, args=args, ledger_cfg=ledger_cfg, consent_covered=_has_api_net(row))
        marked_here = not marked_before and _marked(ledger_cfg)
        if not again.allowed and (verdict.allowed, verdict.needs) != (again.allowed, again.needs):
            out.update(allowed=False, needs=again.needs,
                       reason=f"{again.reason} ({_why_again(again.needs, marked_here, 'plan')})")
        elif (wall := _taint_wall(row, path, args, ledger_cfg)) is not None and out.get("needs") != wall.needs:
            # refused first for a pillar checked before taint (an unarmed plan is the workflow):
            # say the wall too, or arming would meet a refusal the plan never named
            said = (f"{wall.reason} (" + ("this plan's own consult reads marked the session" if marked_here
                                           else "the session was marked before this plan") + ")")
            # The wall is said ONCE, whole, in `also_refused` (protected: never clipped); the plan's own
            # sentence names the pillar and points at it, so the plan fits its exit ceiling with it whole.
            out["also_refused"] = [{"needs": wall.needs, "reason": said}]
            whose = "this plan's consult reads" if marked_here else "an earlier read"
            out["reason"] = (f"{out['reason']}; then refused by {wall.needs} (an untrusted read, marked by {whose}): "
                             "see also_refused")
        if not again.allowed and again.needs == "consent" and again.detail.get("taint_required"):
            # the consent coupling: the grant asked for is mandatory because the session is tainted
            out["taint_required"] = True
            out["reason"] = (f"{out['reason']}; consent is mandatory here because the session is tainted "
                             f"({spine.TAINT_REQUIRE_CONSENT_ENV})")
    if section.get("untrusted") and spine.fence_on():
        # Every field a judge may build from guest-authored text is fenced, not only the
        # names: the warnings, the why, and the tier reason the consult wrote.
        label = f"consult:{section['judge']}"
        section = {**section, **{k: spine.fence(label, section[k])
                                 for k in ("affects", "warnings", "why") if k in section}}
        if out.get("tier_raised") and str(out["tier_raised"]).startswith("consult "):
            out["tier_raised"] = spine.fence(label, out["tier_raised"])
    out["consult"] = section


def _marked(ledger_cfg: Any) -> bool:
    """Whether the session's taint marker is set (False with tracking off: nothing is marked)."""
    if not spine.taint_tracking_on():
        return False
    audit_dir = _audit_dir(ledger_cfg)
    return not audit_dir or spine.is_tainted(audit_dir)


def _why_again(needs: str | None, marked_here: bool, where: str) -> str:
    """Why the second govern refused: the consult's reads only when they set the marker and the
    refusal is a taint pillar's; otherwise the pillar that refused, by name."""
    if marked_here and needs in ("taint", "consent"):
        return f"the session was marked by this {where}'s own consult reads"
    return f"refused by {needs} when the call was judged again after the consult"


def _taint_wall(row: Row, path: str | None, args: dict[str, Any], ledger_cfg: Any) -> spine.Refusal | None:
    """The taint pillars alone, as govern asks them: the forbid wall, then the consent coupling."""
    audit_dir = _audit_dir(ledger_cfg)
    called = rawdoor.canonical(path) if path else row.path
    return (spine.taint_refusal(audit_dir, row.product, row.method, called, args)
            or spine.taint_consent_refusal(audit_dir))


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


# ---- PLAN's notes (notes.toml) ------------------------------------------------------------------
# A consequence the tier cannot say (a restore without `unique` keeps the archive's identity). The
# condition reads the call's own arguments and nothing else: never a read, so a plan is never
# quieter for knowing less, and `execute` judges it the same way for the receipt. Advice: no
# note changes a verdict.

TRUE_WORDS = frozenset({"1", "true", "yes", "y", "on", "t"})     # a boolean's spellings, as coerce_args reads them
FALSE_WORDS = frozenset({"0", "false", "no", "n", "off", "f", ""})


def bool_word(value: str) -> bool | None:
    """A boolean argument spelled as a string: True, False, or None for a spelling no one reads."""
    lowered = value.strip().lower()
    return True if lowered in TRUE_WORDS else False if lowered in FALSE_WORDS else None


def _given(row: Row, name: str, args: Mapping[str, Any]) -> bool | None:
    """Whether the call gives `name`, as the vendor will read it: True, False, or None when that
    cannot be told before the wire (a boolean of 2, a list, a string no one reads as a boolean).
    The plan asks this of the raw arguments and the receipt of the coerced ones; `coerce_args`
    reads a boolean string through the same `bool_word` and passes every other value through
    unchanged, so the two never judge the same call differently."""
    value = args.get(name)
    if value is None:
        return False
    published = _published(row, name)
    if (row.params[published].get("type") if published else None) != "boolean":
        return not (isinstance(value, str) and not value.strip())    # a value is given unless blank
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return bool_word(value)
    if type(value) is int:                       # 1.0 is not definite: the vendor's boolean refuses it
        return True if value == 1 else False if value == 0 else None
    return None


def notes_held(row: Row, args: Mapping[str, Any]) -> list[dict[str, str]]:
    """The row's notes whose condition these arguments may meet, in authored order. ONLY A
    DEFINITE ANSWER SILENCES A NOTE: a `given` name surely absent, or a `not_given` name surely
    given. What cannot be told shows the note, the safe direction for advice."""
    return [{"says": n["says"], "why": n["why"]} for n in row.notes
            if n.get("always") is True
            or (not any(_given(row, k, args) is False for k in n["given"])
                and not any(_given(row, k, args) is True for k in n["not_given"]))]


# ---- THE EFFECTIVE TIER (tiers.toml [raise]) ------------------------------------------------------
# What needs no read is judged without one. A service stop names its service in the PATH, so one
# tier per address could not say that stopping sshd cuts the door while stopping a timer does not
# (John, 2026-10-25: those are destructive). A raise moves the tier UP on a value the call names,
# never down, and never opens an untiered address (the build refuses both). The plan shows it and
# the executing receipt carries it; the ladder, when it lands, reads this and not the authored word.

def effective_tier(row: Row, path: str | None, args: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """(the tier this call is judged at, the why of the raise that set it, or None)."""
    tier, why = row.tier, None
    if not row.raises or tier not in apitree.TIER_RANK:
        return tier, why
    bound = bind(row, path) if path and "{" not in path else {}
    for x in row.raises:
        hit = True
        for name, values in x["when"].items():
            value = bound.get(name, args.get(name))
            if value is None or apitree.raise_value(value) not in values:
                hit = False
                break
        if hit and apitree.TIER_RANK[x["tier"]] > apitree.TIER_RANK[tier]:
            tier, why = x["tier"], x["why"]
    return tier, why


def with_consult(tier: str | None, raised: str | None, section: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The tier after a consult: its `raise_to` when that is ABOVE `tier`, with the reason; else
    `tier` and its own reason unchanged. An untiered address stays untiered (a consult never opens)."""
    to = section.get("raise_to")
    if tier not in apitree.TIER_RANK or to not in apitree.TIER_RANK or apitree.TIER_RANK[to] <= apitree.TIER_RANK[tier]:
        return tier, raised
    said = section.get("why") if not section.get("complete") else next(iter(section.get("warnings") or []), "")
    return to, f"consult {section.get('judge')}: {said}"


def _may_rise(row: Row, path: str | None) -> str | None:
    """On a template path no value is bound: say which raise could apply, never stay quiet."""
    if not row.raises or (path and "{" not in path):
        return None
    return "; ".join(f"{x['tier']} when {', '.join(f'{k} is {'/'.join(v)}' for k, v in x['when'].items())}"
                     for x in row.raises)


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
            env = execute(twin, {}, cfg=plane, path=concrete, ledger_cfg=ledger_cfg, fields="all", evaluating=True)
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
        out["change_untrusted"] = True     # `change.from` is the same attacker-authored record, labelled like `current`
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


NODE_ENV = "PROXIMO_NODE"
_NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def default_node(row: Row, path: str | None, args: Mapping[str, Any],
                 cfg: wire.Plane | None) -> tuple[str | None, str | None]:
    """(the path with `{node}` filled from PROXIMO_NODE, the node used or None). THE CALLER LEFT
    THE NODE OUT when the path still carries the published `{node}` segment; that segment alone is
    filled, and only where it begins the path (`/nodes/{node}/...`, this box's own node): on
    `/cluster/config/nodes/{node}` it names the node being ADDED or REMOVED, and filling it would
    aim a membership change at this box. Only on the env box's own PVE: a registry target's node is
    not this box's, and PBS, PMG and PDM name their nodes their own way. A node the caller also names in `args` is the
    caller naming it (the engine refuses the two as given twice; the environment picks no side).
    Env unset or blank is inert: the same path back, today's behaviour. Once set, a value that is
    not a node name refuses rather than reach a path (0.44's `_check_node`). Plan and call both
    ask this first, so the consent id and the receipt are for the path that runs."""
    node = os.environ.get(NODE_ENV, "")      # blank is unset; anything else is judged as written, never stripped
    if (not node.strip() or path is None or row.product != "pve" or (cfg is not None and cfg.name)
            or not row.path.startswith("/nodes/{node}") or "node" in args):
        return path, None
    segs, want = path.split("/"), row.path.split("/")
    if len(segs) != len(want) or "{node}" not in segs:
        return path, None
    if not _NODE_NAME.match(node):
        raise ProximoError(f"{NODE_ENV} is not a node name ({len(node)} characters); unset it or name the node "
                           "(letters, digits, '.', '_' and '-', starting with a letter or digit)")
    return "/".join(node if g == "{node}" and w == "{node}" else g for g, w in zip(segs, want, strict=True)), node


def _fenced(name: str, value: Any, token: Any) -> bool:
    """A fenced keyword of `execute`: absent (None) is off, the engine's own sentinel is on, anything
    else is refused, a `True` included (a flag can be spelled by anyone; the sentinel cannot)."""
    if value is None:
        return False
    if value is token:
        return True
    raise ProximoError(f"{name} is not a flag a caller can pass; it is the engine's own")


def _default_node_receipted(row: Row, path: str | None, args: Mapping[str, Any], cfg: wire.Plane | None,
                            ledger_cfg: Any, remote: str | None) -> tuple[str | None, str | None]:
    """`default_node`, a refusal receipted like every other (`needs=config`)."""
    try:
        return default_node(row, path, args, cfg)
    except ProximoError as exc:
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": str(exc), "needs": "config"}, called=rawdoor.canonical(path) if path else None,
                remote=remote)
        raise


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
            f"{row.address}: the path {rawdoor.quote(concrete)} has {len(got)} segments, "
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
        if m and re.fullmatch(re.escape(m.group("stem")) + r"[0-9]+", name):
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
                raise ProximoError(f"{row.address}: {rawdoor.echo(name, 40)}={rawdoor.quote(str(value))} "
                                   "is not a boolean; use true/false")
            out[name] = value
        elif kind == "boolean":
            # REFUSE WHAT WE DO NOT RECOGNISE. Mapping every unknown string to False looks
            # harmless until the parameter is named `dry-run`: "y" silently became False and a
            # preview became a live run. 59 mutating addresses publish a boolean of that shape.
            # An unreadable value is a question, not a default.
            word = bool_word(value)
            if word is not None:
                out[name] = word
            else:
                raise ProximoError(
                    f"{row.address}: {rawdoor.echo(name, 40)}="
                    f"{rawdoor.quote(str(ledgered(value, name, row.secret)))} is not a boolean "
                    f"the vendor would accept; use true/false"
                )
        elif kind in ("integer", "number"):
            # int()/float() raise ValueError, which the door reports as the caller's syntax with
            # no ledger row. Raise the type the spine speaks so it is recorded like any refusal.
            try:
                out[name] = int(value) if kind == "integer" else float(value)
            except ValueError:
                raise ProximoError(
                    f"{row.address}: {rawdoor.echo(name, 40)}="
                    f"{rawdoor.quote(str(ledgered(value, name, row.secret)))} is not a valid {kind}"
                ) from None
        elif kind == "array" and row.product == "pdm":
            # PDM TAKES A JSON BODY, AND AN ARRAY IS AN ARRAY. The shell door has only strings, so
            # `target-bridge=vmbr0:vmbr0` reached PDM as a scalar and PDM answered 400 "Expected
            # array - got scalar value": the first real remote-migrate found it on 0.44, whose fix
            # went in the 0.45 cut (capability pdm-typed-arrays). One value is a one-element list.
            # The form planes (pve, pbs, pmg) encode an array differently; they are left alone.
            out[name] = [value]
        else:
            out[name] = value
    return out


def _names_it(value: Any) -> bool:
    """Whether a value names its parameter as the wire will send it: a boolean, an integer or text
    with something in it. A list or a mapping is dropped by the form encoder (`noout=[]` reaches
    the vendor as an empty body), a float is no flag, and None or blank is no answer."""
    return isinstance(value, (bool, int)) or (isinstance(value, str) and bool(value.strip()))


def one_of_refusal(row: Row, args: Mapping[str, Any]) -> str | None:
    """The sentence for a call that names none of the parameters its row must name one of
    (records/args.toml), else None. PRESENCE, NOT TRUTH: `noout=0` clears a flag and is a real
    change; a value that is absent, None, blank or a shape the wire drops names nothing. Reads the arguments alone, so
    the plan and the call judge it the same way with no credential at all."""
    rule = row.one_of
    if rule is None or any(_names_it(args.get(k)) for k in rule["names"]):
        return None
    return f"{row.address} needs at least one of {', '.join(rule['names'])}: {rule['why']}"


def check_args(row: Row, args: dict[str, Any]) -> dict[str, Any]:
    """Validate args against the VENDOR's published parameter schema.

    Unknown names are refused with the published set named. Nothing is coerced or invented: an
    argument the vendor does not document is a caller mistake, and guessing what they meant is
    how a governed call becomes an ungoverned one.
    """
    unknown = sorted(n for n in args if not _published(row, n))
    if unknown:
        names = sorted(row.params)
        known = ", ".join(names[:60]) + (f" (and {len(names) - 60} more)" if len(names) > 60 else "") or "none"
        shown = ", ".join(rawdoor.echo(n, 40) for n in unknown[:5]) + (
            f" (and {len(unknown) - 5} more)" if len(unknown) > 5 else "")
        raise ProximoError(f"{row.address} does not publish {shown}. Published parameters: {known}")
    supplied = set(args) | set(placeholders(row.path))
    missing = sorted(n for n, s in row.params.items()
                     if not s["optional"] and n not in supplied and "[n]" not in n)
    if missing:
        raise ProximoError(f"{row.address} requires {', '.join(missing)}")
    if none_of := one_of_refusal(row, args):
        raise ProximoError(none_of)
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
        "matched_path": row.path, "called_path": rawdoor.echo(called, 160), "tier": row.tier,
        "untrusted": row.untrusted, "download": got, "cap_bytes": cap,
        "note": "the bytes landed on the Proximo host, never in this answer; verify the sha256 before use",
    }


def _built_client(row: Row, cfg: wire.Plane | None, ledger_cfg: Any, called: str,
                  remote: str | None) -> wire.Client | shell.ShellClient:
    """`_client`, with a build that fails (a missing or conflicting variable, a secret file
    group or other can read) receipted as a refusal naming what is wrong, never its content."""
    try:
        return shell.client(cfg, path=called) if row.wire == "ssh" else _client(row.product, cfg)
    except Exception as exc:
        reason = f"{row.product} is not configured to be called: {safe_exception_text(exc, paths=True)}"
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": reason, "needs": "config", "called_path": called, **wire_error(exc)},
                called=called, remote=remote)
        raise ProximoError(reason) from exc


def execute(row: Row, args: dict[str, Any] | None = None, *, cfg: wire.Plane | None = None,
            path: str | None = None, ledger_cfg: Any = None, fields: str | None = None,
            since: str | None = None, wait: int | None = None, restores: str | None = None,
            net_of: tuple[Row, str, str | None] | None = None, asked: str | None = None,
            evaluating: bool = False, judging: Any = None, rate_prepaid: Any = None) -> dict[str, Any]:
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
    `asked` is the words a caller typed when a door turned them into this path; a read's receipt
    carries them (capped), so the ledger shows what was said beside what ran.
    `evaluating` is the door reading for its own verdict (diagnose), not for a model: the answer
    cap is the evaluation cap (`rawdoor.evaluation_cap`), with no token cap.
    `net_of` is (the container command's row, its called path, its consent id), set by
    `_snapshot_first` alone: the snapshot rides the command's consent, on its own container only,
    and its receipt names the grant that covered it.
    `judging` is the engine's own read for a judgement it makes (a rollback's safety net reads the
    guest, its snapshot and its storage to decide whether a snapshot can and may be taken). Such a
    read is receipted, withheld and bounded like any other, and does NOT mark the session tainted:
    taint protects the model from text a guest wrote, and the caller is only ever handed a closed
    vocabulary built from it (`tests/test_net_reads_taint_nothing.py` plants text in every answer
    and reads every place for it). Only the engine passes it, and it has an effect only on a read; no door, record
    or argument can: it is a Python keyword of this function, not a parameter of any address.
    `rate_prepaid` is the safety snapshot's: its rate slot was taken with its act's, together and
    in the one spending step (`_spend_gates`), so it takes none of its own.
    """
    args = dict(args or {})
    judging = _fenced("judging", judging, safetynet.JUDGING)
    rate_prepaid = _fenced("rate_prepaid", rate_prepaid, safetynet.PREPAID)
    # DECIDE BEFORE CONFIGURING. `ProximoConfig.from_env()` raises when the estate is not
    # configured, so building it first made every refusal depend on holding credentials -- and
    # a refusal that needs a credential has already read one. Governing first means "is this
    # allowed?" is answerable on a box with no token at all, which is also what makes `--plan`
    # safe to run anywhere. The pure pillars run inside govern; the spending ones run below,
    # after the arguments validated, so a typo never spends a grant or a budget slot.
    remote = cfg.name if cfg is not None else None
    path, node = _default_node_receipted(row, path, args, cfg, ledger_cfg, remote)
    said = {"default_node": node} if node else {}
    submitted = dict(args)        # what the consent id hashes: the arguments AS SUBMITTED, before coercion
    api_net = _has_api_net(row)
    if net_of is not None:
        _net_of_own_container(row, path, *net_of[:2])
    try:
        verdict = govern(row, cfg=cfg, path=path, args=args, ledger_cfg=ledger_cfg,
                         consent_covered=net_of is not None or api_net)
    except ProximoError as exc:
        # govern RAISES for one thing only, a malformed spelling. An attempted execute is an
        # event: the refusal is receipted like every other, with the path as given.
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": str(exc), "needs": "path"},
                called=rawdoor.canonical(path) if path else None, remote=remote)
        raise
    if not verdict.allowed:
        # THE AIMED-AT PATH, not the template. "what did this agent try" is exactly the
        # refusal question, and the receipt used to answer it with `{store}`. A refused MUTATION also records
        # what it proposed (arguments as typed JSON, secrets fingerprinted, the box, the id): the row
        # `proximo-core consent show <id>` prints, recomputing the id from what it shows.
        proposed = _proposed(row, verdict, rawdoor.canonical(path) if path else row.path, cfg, args)
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": verdict.reason, "needs": verdict.needs, **verdict.detail, **proposed},
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
        _taint_before_the_wire(row, ledger_cfg, called, remote, judging=judging)
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
        # AN EMPTY LIST FROM A TOKEN THAT COULD NOT SEE IS NOT "NONE" (sight.toml): Proxmox answers
        # 200 and [] where it hides what the token may not see, so the empty answer is judged by
        # what the token holds, and refused unless it provably could have seen.
        seen = _sight(row, called, args, client, ledger_cfg, remote, data) if row.sight else {}
        task = None
        if wait is not None:
            # 0.44's pve_task_wait, on a UPID already in hand: the same helper, the same address
            first = [data]
            task = _task_wait(called, lambda: first.pop() if first else client.call("GET", called, args),
                              bind(row, called).get("upid"), wait)
            if task["polls"]:
                data = {"status": task["status"], "exitstatus": task["exitstatus"]}
        _record(ledger_cfg, "core.execute", row, outcome="ok",
                detail={"tier": row.tier, "params": sorted(args), **_untrusted_detail(row), **said,
                        **seen.get("receipt", {}), **({"asked": asked[:120]} if asked else {}),
                        **({"upid": task["upid"], "polls": task["polls"], "seconds": task["seconds"]} if task else {})},
                called=called, remote=remote)
        _keep(row, called, args, data, ledger_cfg, cfg, judging, fields=fields, evaluating=evaluating)
        return {**_envelope(row, called, data, fields, rawdoor.evaluation_cap() if evaluating else None, args),
                **seen.get("envelope", {}),
                **({"task": task} if task else {}),
                **({"default_node": {"node": node, "from": NODE_ENV}} if node else {})}

    # ---- a MUTATION: spend, capture, pre-record, execute, close ---------------------------
    # BUILT BEFORE ANYTHING IS SPENT, and a build that fails is a receipted refusal. Building
    # reads env and stats the secret file (the permission floor) but never reads the secret and
    # never dials. After the spending gates, a config error burned the operator's one-shot
    # consent grant and a rate slot and left no receipt (lens 2026-09-28, pmg credential mode).
    client = _built_client(row, cfg, ledger_cfg, called, remote)
    # THE SECOND LOOK, BEFORE ANYTHING IS SPENT. The consult's reads are receipted GETs of their
    # own; made here, a slow or failed consult never burns the operator's grant or a rate slot,
    # and the session they mark is judged before the call (design rule 7: an answer built from
    # an untrusted read marks the session like the read did), so a taint wall refuses the call
    # whether or not a plan's consult tainted the session first.
    marked_before = _marked(ledger_cfg)
    tier, raised, consult_seen = _tier_at_the_wire(row, called, args, cfg, ledger_cfg)
    _judged_after_the_consult(row, consult_seen, path, args, cfg, ledger_cfg, net_of is not None or api_net, called,
                              remote, marked_before)
    # A ROLLBACK'S NET IS READ BEFORE ANYTHING IS SPENT: a target that is not there and a grant
    # approved for a different net both refuse here, with the grant unspent and no rate slot taken.
    verdict, view = _gate_net(row, called, submitted, args, cfg, ledger_cfg, remote, verdict)
    # THE SPENDING STEP. Everything that can refuse has run: the arguments, the arm and the walls, the
    # net's reads and its snapshot's own walls, the consent look. Now the rate slots are reserved and
    # the grant spent as ONE step (`_spend_gates`), and a refusal there gives the slots back.
    # a taint marker that cannot be written refuses HERE, with nothing spent
    _taint_before_the_wire(row, ledger_cfg, called, remote, mutation=True)
    before = _read_back(row, client, called, ledger_cfg, remote, view, net_of is not None)
    give_back = _spend_gates(row, verdict, called, cfg, ledger_cfg, remote, view, net_of is not None, rate_prepaid)
    intent = intent_id(called)
    # UNDO: read back what the vendor publishes about this address BEFORE changing it. Where
    # it publishes no read, the receipt says so; where the read exists and fails, no net means
    # no risky act (the 0.44 auto-undo's rule). PROXIMO_UNDO=off is the operator's opt-out,
    # and the receipt carries it.
    try:
        undo = _undo_before(row, args, client, called, cfg, ledger_cfg, intent, remote, verdict.consent_id, view,
                            net_of is not None, before)
    except Exception as exc:
        # REFUSED AFTER THE SPEND, BEFORE THE ACT: the approval stays spent (a snapshot request may have
        # gone out under it) but the act's own rate slot goes back, it was never dialled; the safety
        # snapshot's slot goes back only when the error SAYS that request was not sent; an error that
        # does not say (a ledger that failed mid-refusal) keeps it, since the request may have gone out.
        give_back(_slots(view) if getattr(exc, "snapshot_sent", None) is False else 1)
        raise
    # THE EXECUTING ROW. Written BEFORE the wire with the whole preview and the intent, closed
    # by the terminal row below. A process killed in between leaves this row open, which is
    # exactly what `in_flight` reports; without it the core answered "what was running when we
    # died" with nothing.
    held = notes_held(row, args)
    reading = risk.hint(row, args)
    preview = {"tier": tier, **({"tier_raised": raised} if raised else {}),
               **consult_seen,
               "args": ledgered(args, rule=arg_rule(row)), "consent_id": verdict.consent_id,
               "undo": undo, "intent": intent, **({"restores": restores} if restores else {}),
               **({"notes": [n["says"] for n in held]} if held else {}),
               **said,
               **({"risk_hint": {"reading": reading["reading"], "reasons": reading["reasons"]}} if reading else {}),
               **({"consent_of": {"command": net_of[1], "consent_id": net_of[2]}} if net_of else {})}
    _record(ledger_cfg, "core.execute", row, outcome=EXECUTING, detail=preview, called=called,
            required=True, remote=remote)
    try:
        data = client.call(row.method, called, args)
    except Exception as exc:
        _wire_failed(row, tier, called, intent, undo, exc, ledger_cfg, remote, restores)
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
            detail={"tier": tier, "params": sorted(args), "intent": intent, **_untrusted_detail(row),
                    **_capture_of(undo), **({"upid": upid} if submitted else {}),
                    **({"restores": restores} if restores else {})},
            called=called, remote=remote)
    out = {**_envelope(row, called, data), "undo": undo, "intent": intent,
           **({"default_node": {"node": node, "from": NODE_ENV}} if node else {}),
           **({"risk_hint": reading} if reading else {})}
    if submitted:
        out["task"] = _task_of(client, row, called, upid, TASK_WAIT_DEFAULT if wait is None else wait,
                               ledger_cfg, intent, remote)
    return out


def _sight(row: Row, called: str, args: dict[str, Any], client: Any, ledger_cfg: Any,
           remote: str | None, data: Any) -> dict[str, Any]:
    """Judge an answer on a row that has a sight line (sight.toml). `{}` when the line does not
    apply to this question. An EMPTY answer is refused (`needs=sight`, receipted) when the token
    provably cannot see ("blind") or cannot be shown to ("unknown"). A NON-empty answer is never
    refused: it is served, and marked `partial` or `unverified` (envelope and receipt) when the
    token does not hold what shows all of it. The map is read through the same client the question
    used, as UNDO reads its twin."""
    empty = data in (None, [], {}, "")
    state, said, matched = sight.judge(row.sight or {}, bind(row, called), args,
                                       lambda: client.call("GET", "/access/permissions", {}), empty=empty)
    if state == sight.NOT_ASKED:
        return {}
    if state == sight.SIGHTED:
        return {"receipt": {"sight": state, "sight_by": matched}}
    if empty:
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": said, "needs": "sight", "state": state}, called=called, remote=remote)
        raise ProximoError(said)
    mark = "partial" if state == sight.BLIND else "unverified"
    return {"receipt": {"sight": mark}, "envelope": {"sight": mark, "sight_says": said}}
def _tier_at_the_wire(row: Row, called: str, args: dict[str, Any], cfg: wire.Plane | None,
                      ledger_cfg: Any) -> tuple[str | None, str | None, dict[str, Any]]:
    """The tier a mutation runs at, its reason, and what the receipt carries of the consult.
    THE SECOND LOOK, AGAIN: the plan may be stale, so a consulted row reads again here, through
    `execute` like any read. The section rides the EXECUTING receipt as `seen_at: execute`: what
    was read just before the call ran, not the plan the operator approved (the grant binds the
    call's path and arguments, not a consult's answer). It raises the tier the terminal rows
    carry and refuses nothing: advice raises; the ladder, when it lands, decides what a tier needs."""
    tier, raised = effective_tier(row, called, args)
    if not row.consult:
        return tier, raised, {}
    section = {**consult.run(row, called, args, cfg, ledger_cfg), "seen_at": "execute"}
    return (*with_consult(tier, raised, section), {"consult": ledgered(section)})


def _judged_after_the_consult(row: Row, consult_seen: Mapping[str, Any], path: str | None, args: dict[str, Any],
                              cfg: wire.Plane | None, ledger_cfg: Any, covered: bool, called: str,
                              remote: str | None, marked_before: bool) -> None:
    """After a consult, with taint tracking on, govern again (pure; the grant is not spent yet) and
    refuse, receipted, what the session now refuses. The SPINE'S MARKER is the evidence, never the
    section's `untrusted` flag: a consult read marks the session before its wire, so one that then
    failed, or a consult that failed after its reads landed, leaves a marked session and a section
    that never said so (lens 2). `govern` re-stats the marker itself."""
    if not (consult_seen and spine.taint_tracking_on()):
        return
    again = govern(row, cfg=cfg, path=path, args=args, ledger_cfg=ledger_cfg, consent_covered=covered)
    if not again.allowed:
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": again.reason, "needs": again.needs, **again.detail,
                        "after": _why_again(again.needs, not marked_before and _marked(ledger_cfg), "call")},
                called=called, remote=remote)
        raise ProximoError(again.reason)


def _capture_of(undo: Mapping[str, Any]) -> dict[str, str]:
    """THE TERMINAL ROW NAMES ITS CAPTURE. A restore asks how the captured mutation ended; paired
    by intent it read a LATER write at the same path as this one's landing (lens, 2026-10-08:
    a create the vendor refused, then a PUT that succeeded, and undo deleted the record that
    had been there all along). The id travels on the error row and the ok row, so the pairing
    is exact and a row without it is not a landing."""
    return {"capture": undo["id"]} if undo.get("captured") and undo.get("id") else {}


def _readback_twin(row: Row, view: Mapping[str, Any] | None, nested: bool) -> Row | None:
    """The GET twin a mutation's before-state is read from, when this call takes that kind of net at all
    (not a safety snapshot, not a rollback or shell command with a snapshot net, not an ssh command,
    not with UNDO off, and the vendor publishes a served read)."""
    if nested or row.wire == "ssh" or not spine.undo_enabled() or row.twin is None:
        return None
    if row.net and view is not None:
        return None
    twin = table()[(row.product, "GET", row.twin)]
    return None if twin.excluded or twin.gate else twin


def _read_back(row: Row, client: Any, called: str, ledger_cfg: Any, remote: str | None,
               view: Mapping[str, Any] | None, nested: bool) -> dict[str, Any] | None:
    """UNDO's read of the record BEFORE a mutation, taken BEFORE anything is spent: a read that fails
    refuses the call (no net, no risky act) with the grant and the rate slots untouched. None when this
    call takes no such read. A judged create's failed read-back is absence, as the vendor said it
    (undo.toml): the record the path names is not there yet, and the restore is its DELETE. Not proof:
    a read can fail over a record that IS there, so the restore sends the DELETE only when the ledger
    shows this create landed (the vendor refuses a duplicate). Any other address keeps the rule."""
    twin = _readback_twin(row, view, nested)
    if twin is None:
        return None
    try:
        return {"before": ledgered(spine.bound(client.call("GET", called, {})), rule=twin.secret)}
    except Exception as exc:
        if not row.creates:
            reason = (f"undo unavailable: the read-back {twin.address} the vendor publishes could "
                      f"not be taken ({type(exc).__name__}); the mutation was not run")
            _record(ledger_cfg, "core.refuse", row, outcome="refused",
                    detail={"reason": reason, "needs": "undo", **wire_error(exc)}, called=called, remote=remote)
            raise ProximoError(reason) from exc
        return {"absent": True, "read_back": wire_error(exc)}          # its own key: never a record's value


def _undo_before(row: Row, args: dict[str, Any], client: Any, called: str, cfg: Any, ledger_cfg: Any,
                 intent: str, remote: str | None, consent_id: str | None,
                 view: Mapping[str, Any] | None = None, nested: bool = False,
                 before: dict[str, Any] | None = None) -> dict[str, Any]:
    """The net taken before a mutation, or the receipt's words for why there is none (see execute).
    `nested` is a safety snapshot taken for another call: it is its own net (deleting it undoes it),
    and capturing the guest's snapshot list into the ledger for it would copy guest-authored
    descriptions there for nothing. `before` is the read-back `_read_back` took before the spend."""
    twin = table()[(row.product, "GET", row.twin)] if row.twin else None
    if nested:
        undo = {"captured": False, "why": "a safety snapshot is its own undo: deleting it puts the guest as it was"}
    elif row.net and row.wire != "ssh" and view is not None and spine.undo_enabled():
        if view["take"]:
            undo = _snapshot_first(row, called, cfg, ledger_cfg, intent, remote, consent_id, view)
        else:
            undo = {"captured": False, "why": view["why"], "skipped": "storage", "blocked": view["blocked"],
                    "cannot": view["cannot"]}
    elif row.net and row.wire == "ssh" and view is not None:
        undo = _snapshot_first(row, called, cfg, ledger_cfg, intent, remote, consent_id, view)
    elif row.wire == "ssh":
        undo = {"captured": False, "why": "a container command has no read-back"
                + ("; snapshot=true takes one first" if row.net else "")}
    elif not spine.undo_enabled():
        undo = {"captured": False, "why": f"{spine.UNDO_ENV}=off"}
    elif twin is None or twin.excluded or twin.gate:
        undo = {"captured": False, "why": (f"{row.product} publishes no GET {row.path}" if twin is None
                                            else f"the read of {row.path} is gated: {twin.gate or 'tunnel'}")}
    else:
        before = before if before is not None else {"before": None}     # `_read_back` ran for this branch
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


def _read_data(product: str, template: str, values: Mapping[str, Any], cfg: Any, ledger_cfg: Any,
               extra: Mapping[str, Any] | None = None) -> Any:
    """The data of a governed GET the safety net needs (`execute`: receipted, withheld, bounded; a
    `judging` read, so it marks nothing tainted). Raises when the plane serves no such read or the
    answer is over the cap."""
    r = table().get((product, "GET", template))
    if r is None or r.gate or r.excluded:
        raise ProximoError(f"{product} publishes no GET {template} this door serves")
    env = execute(r, dict(extra or {}), cfg=cfg, path=fill(template, values), ledger_cfg=ledger_cfg, fields="all",
                  judging=safetynet.JUDGING, evaluating=True)    # a verdict's read, never a model's
    if "data" not in env:
        raise ProximoError(f"the answer of {template} is over the door's cap")
    return env["data"]


_NEVER_SENT = frozenset({"ConnectError", "ConnectTimeout", "PoolTimeout", "UnsupportedProtocol", "InvalidURL",
                         "LocalProtocolError"})


def _delivery(exc: BaseException) -> str:
    """How far a failed request got, for the error row: `answered` (the vendor replied with an error
    status: it refused), `never-sent` (the connection never opened or the request was malformed
    locally), else `unknown` (a timeout or a reset after the request may have gone out: the vendor may
    have acted). Only the first two are known not to have landed."""
    names = {c.__name__ for c in type(exc).__mro__}
    if "HTTPStatusError" in names:
        return "answered"
    return "never-sent" if names & _NEVER_SENT else "unknown"


def _wire_failed(row: Row, tier: str | None, called: str, intent: str, undo: Mapping[str, Any], exc: Exception,
                 ledger_cfg: Any, remote: str | None, restores: str | None = None) -> None:
    """The error row of a mutation the wire failed; raises when the failure left a safety snapshot
    behind, naming it. Otherwise returns and the caller re-raises the failure as it was. The failure
    is tagged `wire_sent`: the request was sent (a refusal before the wire is not tagged)."""
    delivery = _delivery(exc)
    with contextlib.suppress(AttributeError):
        exc.wire_sent = delivery != "never-sent"        # type: ignore[attr-defined]
    _record(ledger_cfg, "core.error", row, outcome="error",
            detail={"tier": tier, "called_path": called, "intent": intent, **_capture_of(undo),
                    **({"restores": restores} if restores else {}), "delivery": delivery, **wire_error(exc)},
            called=called, remote=remote)
    if orphan := _naming_the_orphan(row, undo, exc):
        raise orphan from exc


def _naming_the_orphan(row: Row, undo: Mapping[str, Any], exc: Exception) -> ProximoError | None:
    """THE SAFETY SNAPSHOT IS ON THE GUEST AND THE CALLER MUST HEAR OF IT, not only the ledger: a
    rollback the vendor then refused leaves the net behind. Any other failure is raised as it was (None)."""
    if not undo.get("snapshot") or row.wire == "ssh":
        return None
    return ProximoError(f"{row.address} failed after its safety snapshot {undo['snapshot']} was taken "
                        f"({safe_exception_text(exc, paths=True)}); the snapshot is still on the guest, "
                        "delete it when you no longer need it")


def _storage_definitions(row: Row, where: Mapping[str, Any], node: Any, cfg: Any,
                         ledger_cfg: Any) -> tuple[dict[str, Any] | None, bool]:
    """(the storage definitions as a map by id, whether this plane can show the chain flag). PVE
    publishes them at `GET /storage`, flag included. PDM publishes only the node's storage STATUS
    list, which needs the node and never carries `snapshot-as-volume-chain`: the flag is not
    visible there, and the types that depend on it are unsettled, never read as free."""
    if row.product == "pve":
        listing, visible = _read_data("pve", "/storage", {}, cfg, ledger_cfg), True
    elif node:
        listing, visible = _read_data(row.product, "/pve/remotes/{remote}/nodes/{node}/storage",
                                      {**where, "node": node}, cfg, ledger_cfg), False
    else:
        return None, False
    if not isinstance(listing, list):
        return None, visible
    return {e["storage"]: e for e in listing if isinstance(e, dict) and isinstance(e.get("storage"), str)}, visible


def _net_view(row: Row, args: Mapping[str, Any], called: str, cfg: Any, ledger_cfg: Any) -> dict[str, Any]:
    """What the safety net of a rollback will do, from governed reads (records/undo.toml [net];
    core/safetynet.py says what stops a net and on whose volumes). Keys: `take` (a snapshot
    first), `why` (the sentence the plan and the receipt print when none is taken or the storage
    is not settled), `exists` (the rollback's target snapshot is there: True, False, or None when
    unread), `blocked`/`cannot`/`unsettled` (storage TYPES and reasons, never names), `running`
    (the guest's state now) and `node`.
    Order matters: the target is checked BEFORE any snapshot exists, because a rollback to a
    snapshot that is not there would otherwise first create a real one.
    FAIL-CLOSED: a read that fails or a storage that is not settled TAKES the net, and says so."""
    view: dict[str, Any] = {"take": True, "why": None, "exists": None, "blocked": [], "cannot": [],
                            "unsettled": [], "running": None, "node": None}
    if not spine.undo_enabled():
        view.update(take=False, why=f"{spine.UNDO_ENV}=off: the operator turned every safety net off; "
                                    "nothing is captured before this rollback")
        return view
    try:
        where = bind(row, called)
        snap = _at(row.product, cast(Mapping[str, str], row.net)["snapshot"])
    except ProximoError:
        view["why"] = "storage not read: the path is a template"
        return view
    if "{" in called or snap.path.rpartition("/")[2] != "snapshot":
        view["why"] = "storage not read: the path is a template"
        return view
    base = snap.path.removesuffix("/snapshot")
    node = args.get("node") if isinstance(args.get("node"), str) else None
    view["node"] = node
    extra = {"node": node} if node and "node" in snap.params and "node" not in where else {}

    def read(template: str, **more: Any) -> Any:
        """A governed GET of this guest; `node` rides when the caller named it, and so does anything
        in `more` that the read publishes (PDM's config read REQUIRES `state`)."""
        params = table()[(row.product, "GET", template)].params
        return _read_data(row.product, template, where, cfg, ledger_cfg,
                          {k: v for k, v in {**extra, **more}.items() if k in params})

    try:
        listed = read(snap.path)
        names = {e.get("name") for e in listed if isinstance(e, dict)} if isinstance(listed, list) else None
        view["exists"] = None if names is None else where.get("snapname") in names
    except Exception:
        view["exists"] = None
    if view["exists"] is not True:
        view["why"] = _target_unconfirmed() if view["exists"] is None else None
        return view
    _judge_storage(view, row, read, base, where, node, cfg, ledger_cfg)
    for status_t in (base + "/status/current", base + "/status"):
        if (row.product, "GET", status_t) in table():
            with contextlib.suppress(Exception):
                state = read(status_t)
                st = state.get("status") if isinstance(state, dict) else None
                view["running"] = True if st == "running" else False if st == "stopped" else None
            break
    if view["cannot"]:
        view.update(take=False, why=f"{safetynet.IMPOSSIBLE_SENTENCE} ({'; '.join(view['cannot'])})")
    elif view["blocked"]:
        view.update(take=False, why=f"{safetynet.BLOCKED_SENTENCE} ({', '.join(view['blocked'])})")
    elif view["unsettled"]:
        view["why"] = (f"storage not settled ({', '.join(view['unsettled'])}): the safety snapshot is taken, and "
                       "if the storage refuses the rollback because of it the rollback fails and the "
                       "snapshot stays")
    return view


def _target_unconfirmed() -> str:
    return ("could not confirm the snapshot to roll back to is on this guest: the rollback is refused "
            "unless it can be confirmed when it runs")


def _judge_storage(view: dict[str, Any], row: Row, read: Any, base: str, where: Mapping[str, Any], node: Any,
                   cfg: Any, ledger_cfg: Any) -> None:
    """Fill `blocked`, `cannot` and `unsettled`. The rollback is blocked only by the TARGET
    SNAPSHOT's own volumes; the safety snapshot can be taken only if the CURRENT config's volumes
    can be snapshotted (core/safetynet.py). A read that fails is never ignored: it is unsettled."""
    unsettled: set[str] = set()
    snap_vols: list[tuple[str, str]] = []
    cur_vols: list[tuple[str, str]] = []
    devices = 0
    try:
        snap_vols, unread = safetynet.volumes_of(read(base + "/config", state="active", snapshot=where["snapname"]))
        if unread:
            unsettled.add("a volume of the snapshot that names no storage")
    except Exception:
        unsettled.add("the snapshot's own config could not be read")
    try:
        # PVE's own snapshot judges the MAIN section of the config, not the pending one: on PVE the
        # read asks `current=1` (without it the answer merges `pending` in and drops pending
        # deletes); PDM publishes `state` instead, and `read` sends only what the address publishes.
        current = read(base + "/config", state="active", current=True)
        cur_vols, unread = safetynet.volumes_of(current)
        devices = safetynet.device_mounts(current)
        if unread > devices:
            unsettled.add("a volume of the guest that names no storage")
    except Exception:
        unsettled.add("the guest's config could not be read")
    try:
        defs, visible = _storage_definitions(row, where, node, cfg, ledger_cfg)
    except Exception:
        defs, visible = None, row.product == "pve"
    try:
        blocking = safetynet.judge_blocking(snap_vols, defs, visible)
        snapshottable = safetynet.judge_snapshottable(cur_vols, defs, devices)
    except Exception:   # noqa: BLE001 -- a judgement that cannot finish is unsettled (the net is taken), never a crash
        blocking, snapshottable = {"blocked": [], "unsettled": []}, {"cannot": [], "unsettled": []}
        unsettled.add(safetynet.JUDGEMENT_FAILED)
    view["blocked"], view["cannot"] = blocking["blocked"], snapshottable["cannot"]
    view["unsettled"] = sorted({*unsettled, *blocking["unsettled"], *snapshottable["unsettled"]})


def _net_signature(view: Mapping[str, Any]) -> str:
    """What the plan says about the net, in a word the consent id binds: taken, skipped or off."""
    if not spine.undo_enabled():
        return "off"
    return "taken" if view["take"] else "skipped"


_NET_SIGNATURES = ("taken", "skipped", "off")


def _net_verdict(row: Row, path: str | None, args: Mapping[str, Any], cfg: Any, ledger_cfg: Any, v0: Verdict,
                 view: Mapping[str, Any]) -> Verdict:
    """The verdict of a rollback with a net, AFTER the net's reads. `govern` ran without its two
    consent looks (the id they need depends on the net); consent is looked at here against the id
    that binds what the plan said about the net: a grant approved on "a safety snapshot is taken"
    does not cover a rollback that would run with none (the guest's storage moved since)."""
    if not v0.allowed:
        return v0
    audit_dir = _audit_dir(ledger_cfg)
    called = rawdoor.canonical(path) if path else row.path
    # `govern` ran without its two consent looks; the taint wall it applied stands (the net's reads
    # taint nothing), and the taint-requires-consent look is made here with the consent look.
    if (refusal := spine.taint_consent_refusal(audit_dir)) is not None:
        detail = dict(refusal.detail)
        if spine.taint_mandatory(audit_dir):
            detail["taint_required"] = True
        return Verdict(False, refusal.reason, refusal.needs, v0.consent_id, detail)
    view_take = bool(view["take"]) and spine.undo_enabled()
    called_path = path if path and "{" not in path else None
    if view_take and called_path is not None and "snap" not in view and view.get("exists") is not False:
        snap = _net_snapshot(row, called, dict(args))
        wall = _snapshot_wall(row, snap, cfg, ledger_cfg, v0)
        if wall is not None:
            return wall
        if isinstance(view, dict):
            view["snap"] = snap
    box = (cfg.base_url if cfg is not None else wire.env_base_url(row.product)) or ""

    def cid_for(sig: str) -> str:
        return spine.consent_id(row.product, row.method, row.path, called, dict(args), box=box, net=sig)

    sig = _net_signature(view)
    cid = cid_for(sig)
    refusal = spine.consent_refusal(cid, audit_dir or ".")
    if refusal is None:
        return Verdict(True, f"mutate, tier {row.tier}", consent_id=cid)
    reason = refusal.reason
    if any(spine.consent_state(cid_for(alt), audit_dir or ".") in ("granted", "advisory")
           for alt in _NET_SIGNATURES if alt != sig):
        reason = ("the safety net changed since the plan (a grant was approved for a rollback with a different "
                  f"net, and it now reads {sig}); plan again")
    return Verdict(False, reason, "consent", cid, {**refusal.detail, "consent_id": cid})


def _rate_cap(cfg: Any) -> tuple[int | None, int | None]:
    return (cfg.rate_max, cfg.rate_window) if cfg is not None else (None, None)


def _slots(view: Mapping[str, Any] | None) -> int:
    """What a call costs the box's budget: two when it takes a safety snapshot first (the act and its
    net are two mutations), else one."""
    return 2 if view is not None and view.get("take") and view.get("snap") else 1


def _spend_gates(row: Row, verdict: Verdict, called: str, cfg: Any, ledger_cfg: Any, remote: str | None,
                 view: Mapping[str, Any] | None, nested: bool, rate_prepaid: bool) -> Callable[[int], None]:
    """The one spending step, after EVERYTHING that can refuse has run. The order is the tightest that
    keeps a doomed attempt from costing anyone: the grant's O_EXCL marker first (a caller that has lost
    the grant to another holds no slot another caller needs), then the call's rate slots, reserved
    together (a safety snapshot's are taken with its act's), then the receipt of the spend. A rate
    refusal puts the marker back; a receipt that cannot be written puts back the marker AND the
    slots. The grant file itself goes only once the receipt is down. The safety snapshot (`nested`)
    spends no grant and, being `rate_prepaid`, takes no slot. Returns the means to give `n` of the slots
    back later, for a call refused after the spend but before anything was dialled."""
    base_url = cfg.base_url if cfg is not None else wire.env_base_url(row.product)
    lcfg = ledger_cfg or LedgerConfig.from_env()
    audit_dir = os.path.dirname(lcfg.audit_log_path) or "."
    stamp: list[float] = []
    count = _slots(view)
    spent = None if nested else spine.spend_consent(verdict.consent_id or "", audit_dir)
    refusal = spent if isinstance(spent, spine.Refusal) else None
    if refusal is None and not rate_prepaid:
        refusal = spine.reserve_rate(base_url, audit_dir, cap=_rate_cap(cfg), count=count, stamp=stamp)

    def give_back() -> None:
        if isinstance(spent, spine.Spend):
            spine.unspend(spent)
        if stamp:
            spine.release_rate(base_url, audit_dir, stamp[0], count)

    if refusal is not None:
        give_back()
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": refusal.reason, "needs": refusal.needs, **refusal.detail},
                called=called, remote=remote)
        raise ProximoError(refusal.reason)
    if isinstance(spent, spine.Spend):
        # The evidence beside the marker: an agent that deletes its marker to spend one grant
        # again leaves one more of these rows in the chain each time. REQUIRED, and a failed
        # write rolls the marker back: a spend PROVE can't hold is no spend, and it must not
        # burn the operator's approval (or the slots) either.
        try:
            _record(ledger_cfg, "core.consent_spent", row, outcome="ok",
                    detail={"consent_id": verdict.consent_id,
                            "grant": {"inode": spent.inode, "mtime_ns": spent.mtime_ns},
                            **({"advisory": True} if spent.advisory else {})},
                    called=called, required=True, remote=remote)
        except BaseException:
            give_back()
            raise
        spine.retire_grant(verdict.consent_id or "", spent)

    def release(n: int) -> None:
        if stamp:
            spine.release_rate(base_url, audit_dir, stamp[0], min(n, count))
    return release


def _has_api_net(row: Row) -> bool:
    """A rollback on the API wire: its net is taken unasked (records/undo.toml [net])."""
    return bool(row.net and row.wire != "ssh")


def _net_snapshot(row: Row, called: str, args: Mapping[str, Any]) -> dict[str, Any]:
    """The safety snapshot a call will take, fixed BEFORE anything is spent so its own walls can be
    met then: the vendor's snapshot row, its concrete path and the arguments it will send (a fresh
    name; a description naming the act; the node the caller named, which rides to the snapshot
    because PDM takes it as an optional hint and a snapshot on another node than the rollback's would
    be no net; none is invented)."""
    where = bind(row, rawdoor.canonical(called))
    snap = _at(row.product, cast(Mapping[str, str], row.net)["snapshot"])
    name = "proximo_" + time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "_" + os.urandom(2).hex()
    act = "command" if row.wire == "ssh" else "rollback"
    asked = {"node": args["node"]} if args.get("node") and "node" in snap.params and "node" not in where else {}
    return {"row": snap, "path": fill(snap.path, where), "name": name, "act": act,
            "args": {"snapname": name, "description": f"before a governed {act} ({intent_id(called)[:12]})", **asked}}


def _snapshot_wall(row: Row, snap: Mapping[str, Any], cfg: Any, ledger_cfg: Any, v0: Verdict) -> Verdict | None:
    """The safety snapshot's OWN governance (arm, tier, FORBID on its arguments, contain, taint),
    judged before the act is spent on: a wall that only the net meets (`FORBID=description=`) must
    refuse the act with its grant unspent, and the plan must show it. None when the net may be taken."""
    try:
        v = govern(snap["row"], cfg=cfg, path=snap["path"], args=dict(snap["args"]), ledger_cfg=ledger_cfg,
                   consent_covered=True)
    except ProximoError as exc:
        v = Verdict(False, str(exc), "path")
    if v.allowed:
        return None
    return Verdict(False, f"undo unavailable: the safety snapshot before this {snap['act']} would be refused "
                          f"({v.reason}); the {snap['act']} was not run. Nothing was sent to the vendor",
                   v.needs or "undo", v0.consent_id, dict(v.detail))


def _shell_net_verdict(row: Row, args: Mapping[str, Any], path: str | None, cfg: Any, ledger_cfg: Any,
                       verdict: Verdict) -> Verdict:
    """The plan of a shell command that asks for `snapshot=true`: the snapshot's own walls, shown."""
    if not (verdict.allowed and row.net and _snapshot_on(row, dict(args)) and path and "{" not in path):
        return verdict
    return _snapshot_wall(row, _net_snapshot(row, path, args), cfg, ledger_cfg, verdict) or verdict


def _proposed(row: Row, verdict: Verdict, called: str, cfg: Any, args: Mapping[str, Any],
              net: str = "") -> dict[str, Any]:
    """What a refused mutation proposed, for the row the refusal writes (`proximo-core consent show`):
    the inputs of its consent id as the ledger keeps them (a secret fingerprinted), the net signature
    when the id carries one, and the BINDING (`spine.consent_binding`) of all of it to the id. Empty
    when the verdict has no consent id."""
    if not verdict.consent_id:
        return {}
    p: dict[str, Any] = {"consent_id": verdict.consent_id, "plane": row.product, "method": row.method,
                         "published": row.path, "called": called, "box": _box(row, cfg),
                         "args": ledgered(dict(args), rule=arg_rule(row)), **({"net": net} if net else {})}
    return {"proposed": {**p, "binding": spine.consent_binding(p)}}


def _net_of_id(row: Row, verdict: Verdict, called: str, cfg: Any, args: Mapping[str, Any],
               view: Mapping[str, Any]) -> str:
    """The net signature the verdict's consent id was made with, or "" when it carries none (a refusal
    made before the net was judged keeps the plain id)."""
    sig = _net_signature(view)
    with_net = spine.consent_id(row.product, row.method, row.path, called, dict(args), box=_box(row, cfg), net=sig)
    return sig if with_net == verdict.consent_id else ""


def _gate_net(row: Row, called: str, submitted: Mapping[str, Any], args: Mapping[str, Any], cfg: Any,
              ledger_cfg: Any, remote: str | None, v0: Verdict) -> tuple[Verdict, dict[str, Any] | None]:
    """Execute's half, BEFORE the grant is spent or a rate slot taken: read the net, refuse a target
    that is not there (nothing taken), meet the safety snapshot's own walls, and judge consent
    against the net as it reads now. A refusal is receipted and sends nothing. A row with no net
    asked of this call (a shell command without `snapshot=true`) passes through. A shell command's
    snapshot is the same step: its walls are met here, before the grant."""
    if not row.net or (row.wire == "ssh" and args.get("snapshot") is not True):
        return v0, None
    if row.wire == "ssh":
        snap = _net_snapshot(row, called, args)
        view: dict[str, Any] = {"take": True, "snap": snap, "node": None, "running": True, "why": None}
        verdict = _snapshot_wall(row, snap, cfg, ledger_cfg, v0) or v0
    else:
        view = _net_view(row, args, called, cfg, ledger_cfg)
        if spine.undo_enabled() and view["exists"] is not True:
            absent = view["exists"] is False
            reason = ("undo unavailable: the snapshot to roll back to is not on this guest; nothing was taken "
                      "and the rollback was not run" if absent else
                      "undo unavailable: could not confirm the snapshot to roll back to is there; nothing was "
                      "taken and the rollback was not run")
            _record(ledger_cfg, "core.refuse", row, outcome="refused",
                    detail={"reason": reason, "needs": "arguments" if absent else "undo"}, called=called,
                    remote=remote)
            raise ProximoError(reason)
        verdict = _net_verdict(row, called, submitted, cfg, ledger_cfg, v0, view)
    if not verdict.allowed:
        # a consent refusal keeps what it proposed, net signature included, for `consent show`
        net = _net_of_id(row, verdict, called, cfg, submitted, view) if verdict.needs == "consent" else ""
        proposed = _proposed(row, verdict, called, cfg, submitted, net) if verdict.needs == "consent" else {}
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": verdict.reason, "needs": verdict.needs, **verdict.detail, **proposed},
                called=called, remote=remote)
        raise ProximoError(verdict.reason)
    return verdict, view


def _tier_fields(row: Row, path: str | None, args: Mapping[str, Any]) -> dict[str, Any]:
    """The plan's tier keys when a value rule (tiers.toml [raise]) raises or may raise this call."""
    if row.access == READ or not row.raises:
        return {}
    try:
        effective, raised = effective_tier(row, path, dict(args))
    except ProximoError:
        effective, raised = row.tier, None
    if raised:
        return {"tier": effective, "tier_authored": row.tier, "tier_raised": raised}
    may = _may_rise(row, path)
    return {"tier_may_rise": may} if may else {}


def _plan_net_view(row: Row, args: Mapping[str, Any], path: str | None, cfg: Any, ledger_cfg: Any,
                   verdict: Verdict) -> dict[str, Any]:
    """The plan's view of a rollback's net: governed reads when the call can run and names a
    concrete path, else what can be said without them."""
    on = spine.undo_enabled()
    if verdict.needs in ("arguments", "held") or not path or "{" in path:
        return {"take": on, "exists": None, "blocked": [], "cannot": [], "unsettled": [], "why": (
            "storage not read: the path is a template" if on else
            f"{spine.UNDO_ENV}=off: the operator turned every safety net off; nothing is captured before "
            "this rollback")}
    return _net_view(row, args, path, cfg, ledger_cfg)


def _safety_net_plan(row: Row, view: Mapping[str, Any]) -> dict[str, Any]:
    """The plan's `safety_net` (and `also`) of a rollback: nobody asks for this net and nobody can
    skip it, so the plan says what it will do, or why it will not, BEFORE the operator approves."""
    net: dict[str, Any] = {"taken": bool(view["take"] and view["exists"] is not False),
                           **({"why": view["why"]} if view["why"] else {}),
                           **({"snapshot_exists": view["exists"]} if view["exists"] is not None else {}),
                           **({"unsettled": view["unsettled"]} if view["unsettled"] else {})}
    if view["exists"] is False:
        net["why"] = "the snapshot to roll back to is not on this guest: the rollback would fail, and nothing is taken"
    out: dict[str, Any] = {"safety_net": net}
    if net["taken"]:
        snap = _at(row.product, cast(Mapping[str, str], row.net)["snapshot"])
        out["also"] = {"address": snap.address, "tier": snap.tier, "consent": "covered by this plan's grant",
                       "why": "a rollback takes a safety snapshot of the guest first and waits for it; if it "
                              "does not land, the rollback is not run"}
    return out


def _snapshot_on(row: Row, args: dict[str, Any]) -> bool:
    """Whether a shell command takes its net first: the CALLER asks with `snapshot`, which reads as
    true the way execute will read it (the CLI's "true" included), and a value execute refuses is
    not a snapshot the plan announces. (The API wire's net asks nobody: `_net_view`.)"""
    if not row.net or row.wire != "ssh" or "snapshot" not in args:
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
                    remote: str | None, consent_id: str | None, view: Mapping[str, Any]) -> dict[str, Any]:
    """UNDO for a container command (B5 stage 2; 0.44's `snapshot=True`) and for a rollback (0.44's
    `_pdm_auto_undo`, undo.toml [net]). The snapshot is a governed mutation of its OWN, the vendor's
    snapshot create through `execute` (armed, tiered, receipted, waited), so the net is as
    accountable as the act; it was fixed, and its own walls met, before anything was spent
    (`_net_snapshot`, `_snapshot_wall`). FAIL-CLOSED: anything short of a task that finished OK
    refuses the act before it runs. The capture names the snapshot and the vendor's rollback, so
    `undo <id>` puts the guest back."""
    where = bind(row, rawdoor.canonical(called))
    net = cast(Mapping[str, str], row.net)
    snap = view["snap"]
    name, act = snap["name"], snap["act"]

    def refused(why: str, exc: BaseException | None = None, upid: Any = None) -> ProximoError:
        # What is true depends on whether the snapshot request went out. Sent: it may have landed, so
        # it is named, to be found. Not sent (a wall, a grant, the rate cap, a connection that never
        # opened): nothing was sent. Either way the approval for this call is spent where consent is
        # enforced (something was, or could have been, sent under it); the act was never dialled.
        sent = True if exc is None else bool(getattr(exc, "wire_sent", False))
        tail = (f"The snapshot request was SENT, named {name}: if the vendor created it anyway it is still on the "
                f"guest, and deleting it is yours. The {act} was not run; where consent is enforced, the approval "
                "for this call is spent" if sent else
                "Nothing was sent to the vendor; where consent is enforced, the approval for this call is spent")
        reason = f"undo unavailable: the snapshot before this {act} did not land ({why}); the {act} was not run. {tail}"
        _record(ledger_cfg, "core.refuse", row, outcome="refused",
                detail={"reason": reason, "needs": "undo", **({"snapshot": name} if sent else {}),
                        **({"upid": upid} if upid else {}), **(wire_error(exc) if exc else {})},
                called=called, remote=remote)
        failure = ProximoError(reason)
        failure.snapshot_sent = sent                       # type: ignore[attr-defined]
        return failure

    try:
        out = execute(snap["row"], dict(snap["args"]), cfg=cfg, path=snap["path"], ledger_cfg=ledger_cfg,
                      wait=SNAPSHOT_WAIT, net_of=(row, called, consent_id), rate_prepaid=safetynet.PREPAID)
    except Exception as exc:
        raise refused(safe_exception_text(exc, paths=True), exc) from exc
    task = out.get("task") or {}
    if not task.get("succeeded"):
        # A FIXED WORD, never the task's exit status: the vendor's text can carry what a guest agent
        # said (a freeze hook's output), and what reaches the caller and the ledger is a closed vocabulary.
        # The task's id (a vendor id, not guest text) is on the row to read the real status by.
        word = ("the vendor's task ended in an error" if task.get("finished")
                else "the vendor's task did not finish in time" if task.get("timed_out")
                else "the vendor's task was not seen to finish")
        raise refused(word, upid=task.get("upid"))
    method, _, template = net["rollback"].partition(" ")
    rollback = f"{method} {fill(template, {**where, 'snapname': name})}"
    # The guest's state when the net was taken: an undo puts it back to THAT, not to "running". A
    # container command ran inside the container, so it was running; an unread state is None.
    running, node = view.get("running"), view.get("node")
    try:
        point = _record(ledger_cfg, "core.undo_point", row, outcome="undo_point",
                        detail={"snapshot": name, "rollback": rollback, "intent": intent, "tier": row.tier,
                                "plane": row.product, "upid": task.get("upid"), "running": running,
                                **({"node": node} if node else {})},
                        called=called, required=True, remote=remote)
    except Exception as exc:
        raise ProximoError(f"the safety snapshot {name} landed but its receipt could not be written "
                           f"({safe_exception_text(exc, paths=True)}); the {act} was not run and the snapshot is "
                           "still on the guest") from exc
    return {"captured": True, "snapshot": name, "rollback": rollback, "running": running,
            **({"note": view["why"]} if view.get("why") else {}),
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


def _taint_before_the_wire(row: Row, ledger_cfg: Any, called: str, remote: str | None,
                           judging: bool = False, mutation: bool = False) -> None:
    """Mark the session tainted before an untrusted answer can be served: a read's, or a mutation's
    (an exec's output, a guest-agent answer). A `judging` read (the engine's own, see `execute`) marks
    nothing: it is never served to the caller, only judged. A mutation marks BEFORE anything is spent,
    so a marker that cannot be written refuses it with its grant, its rate slots and its net untouched."""
    if judging or not (row.untrusted and spine.taint_tracking_on()):
        return
    audit_dir = _audit_dir(ledger_cfg)
    try:
        if not audit_dir:
            raise OSError("the ledger has no directory to hold the taint marker")
        spine.mark_tainted(audit_dir, row.key)
    except Exception as exc:  # noqa: BLE001 -- any failure to mark is a refusal to serve
        what = "call was not run" if mutation else "read was not served"
        kind = "returns untrusted bytes" if mutation else "is an untrusted read"
        reason = (f"{row.key} {kind} and the taint marker could not be written ({type(exc).__name__}); "
                  f"the {what} (fail-closed)")
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
    r"password|passwd|passphrase|(^|[-_])pass($|[-_])|secret|hmac|private|keyring|certkey|credential"
    r"|(^|[-_])(totp|otp)$|(keys?|tokens?)$", re.I | re.ASCII)
_URL_AUTHORITY = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)?(?P<authority>[^/?#\s]*)")


def name_looks_secret(name: str) -> bool:
    """The NAME rule: whether an argument called `name` is fingerprinted unless its address's `public` line
    (secrets.toml) judges it not a secret value. `pub` in a name is a public key and stays visible. ASCII only."""
    return bool(_SECRET_NAME.search(name)) and "pub" not in name.lower()


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
    return (row.secret[0] | _NOT_SECRET_MARK(row), *row.secret[1:4], None)


def ledgered(value: Any, name: str | None = None,
             rule: Rule = _NO_RULE) -> Any:
    """`value` as a receipt may carry it: secret-named keys and the record's fields (`rule`,
    the row's `secret`) fingerprinted, URL userinfo masked (strictly in the record's URL
    fields), recursively; every other shape byte for byte. Under a BEARER line the whole value
    is the credential (a login link), so the whole value is fingerprinted, at any depth: an
    UNDO capture of such a read, or the args of a mutation at its path, never lands raw."""
    if rule[4] is not None:
        return _fingerprint(value)
    if name is not None and (name in rule[0] or (name_looks_secret(name) and "!" + name not in rule[0])):
        return _fingerprint(value)
    if isinstance(value, dict):
        return {k: ledgered(v, str(k), rule) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [ledgered(v, None, rule) for v in value]
    if isinstance(value, str):
        return _mask_userinfo(value, url=name in rule[1])
    return value


def _envelope(row: Row, called: str, data: Any, fields: str | None = None,
              cap: rawdoor.Cap | None = None, given: dict[str, Any] | None = None) -> dict[str, Any]:
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
    fenced = row.untrusted and spine.fence_on()
    header = {
        "address": row.address,
        "plane": row.product,
        "access": row.access,
        "derived": False,          # the vendor's bytes, never composed prose
        "matched_path": row.path,  # the published address that governed this call
        "called_path": rawdoor.echo(called, 160),     # what went to the wire; a clip carries its length and hash
        "tier": row.tier,
        "untrusted": row.untrusted,   # a fact about the address, like the tier; the env gates behaviour
        **({"total": total} if total is not None else {}),   # counted at the gate, from the raw rows
        **({"withheld": withheld} if withheld else {}),   # the record's fields this response carried
        # a response that IS a credential is served whole (the caller asked for it) and says so;
        # the ledger never holds a read's bytes and the store keeps lists only, so it goes no further
        **({"bearer_credential": b} if (b := row.secret[4]) else {}),
    }
    # THE SIZE LAW, the raw door's: an answer over the cap is reported (a list cut by rows with its
    # count; anything else described by its keys and sizes), never handed to the model whole. The cap is
    # on the WHOLE answer: the header above is spent first, and a FENCED answer is measured as it will
    # be sent (the wrapper and the escaping its JSON string adds) and the data's share shrunk until the
    # whole fits. A MUTATION'S echo (a PUT that returns its resource) is capped too, except a credential
    # served whole on purpose (a token mint): a truncated secret is worse than none.
    whole = cap or rawdoor.answer_cap()
    room = whole.minus(*rawdoor.spent(header))
    answer, last, stalls = header, None, 0
    for _ in range(10):
        shown, over = _bounded_data(row, data, fields, room, whole, fenced, given)
        answer = {**header, **(over if over is not None else {"data": shown})}
        body = json.dumps(answer, separators=(",", ":"), default=str)
        stalls += last is not None and len(body) >= last
        if rawdoor.fits(len(body.encode()), body, cap=whole) or room.bytes <= 48 or stalls >= 3 or row.secret[4]:
            break           # fits; or nothing left to take; or taking more changed nothing (a credential kept whole)
        last = len(body)
        room = room.minus(2 * (len(body.encode()) - whole.bytes) + 16,
                          0 if whole.tokens is None
                          else 2 * max(rawdoor.estimate_tokens(body) - whole.tokens, 0) + 8, 48)
    return answer


def _bounded_data(row: Row, data: Any, fields: str | None, room: rawdoor.Cap, whole: rawdoor.Cap,
                  fenced: bool, given: dict[str, Any] | None = None) -> tuple[Any, dict[str, Any] | None]:
    """(the data to send, or None) and (what stands in for it when it does not fit `room`), fenced as
    the row requires. One pass of the size law; `_envelope` repeats it with a smaller room until the
    whole answer is under the cap."""
    bearer = bool(row.secret[4])
    if bearer:
        # A CREDENTIAL SERVED WHOLE IS THE CREDENTIAL, NOT EVERYTHING BESIDE IT: a token mint's scalar
        # fields (the value, its id) stay whole; its objects and lists beside them are capped.
        data, over = _bearer_split(data, room)
    else:
        over = rawdoor.bounded(data, room)
    if over is not None and "cap" in over:
        over["cap"] = whole.bytes            # the cap the operator knows, not what is left after the header
    if over is not None and "returned" in over and fields is None and not bearer:
        # OVER THE CAP, A DEFAULT READ ANSWERS WHOLE AND SMALLER. A cut list fits and is wrong:
        # 16 of 37 rows is most of the estate missing. Rows asked for by name keep the cut, and
        # so do a list whose rows carry their own content (a log's lines) or no state to count,
        # and a summary that would not fit the cap itself (lens 2026-09-28: 150 enum fields made
        # a 9 KB "summary" against 2 KB): there the cut is the smaller answer.
        # a fenced summary is ONE wrapper (below): its fixed cost comes out of the room the counts and the odd
        # rows share (the escaping its JSON string adds is caught by the whole-answer loop in `_envelope`)
        squeeze = rawdoor.Cap(room.bytes, room.tokens)
        if fenced:
            wrap = rawdoor._cost(spine.fence(row.key, ""))
            squeeze = room.minus(wrap[0], wrap[1], 48)
        summary = summarize(data, squeeze)
        if summary["tally"] and rawdoor.bounded(summary, squeeze) is None:
            over = summary
    if over is not None and "returned" in over and "summarized" not in over:
        over["next"] = _narrowing(row, fields, over["returned"], over["total"], given)   # never what was asked
    if over is not None:
        rawdoor.note_problems(over)
    if over is not None and fenced and "summarized" in over:
        # ONE wrapper for the whole summary (counts and the odd rows): the vendor's words, fenced once, so
        # a fenced estate still gets its counts inside the cap (two wrappers did not fit)
        core = {k: over.pop(k) for k in ("tally", "by_type", "minority") if k in over}
        over["summary"] = spine.fence(row.key, core)
    elif over is not None and fenced:
        for part in ("keys", "data"):                         # the vendor's words, in every form it comes in
            if part in over:
                over[part] = spine.fence(row.key, over[part])
    return (spine.fence(row.key, data) if fenced else data), over


def _bearer_split(data: Any, cap: rawdoor.Cap) -> tuple[Any, dict[str, Any] | None]:
    """(data, over) for a credential answer: the scalar fields stay whole, and the containers beside
    them are capped by the room the scalars leave. `over` is None when the whole fits."""
    if not isinstance(data, dict):
        return data, None
    scalars = {k: v for k, v in data.items() if not isinstance(v, (dict, list))}
    rest = {k: v for k, v in data.items() if isinstance(v, (dict, list))}
    room = cap.minus(*rawdoor._cost(scalars))
    over = rawdoor.bounded(rest, room) if rest else None
    if over is None:
        return data, None
    return scalars, {"data": scalars, "other_fields": {k: over["keys"].get(k) for k in over.get("keys", {})},
                     "other_fields_total": over["keys_total"], "truncated": True, "bytes": over["bytes"],
                     "cap": over["cap"], **({"note": over["note"]} if "note" in over else {}), "next": over["next"]}


#: filter-shaped parameters a list address commonly publishes, in the order worth naming
_PAGING = ("limit", "start", "offset", "since", "until", "lastentries")


def _narrowing(row: Row, fields: str | None, kept: int, total: int, given: dict[str, Any] | None = None) -> str:
    """The `next` of a list cut by rows. It NEVER suggests what was just asked: after `fields=name,status`
    it does not say to ask for `fields=name,status`. It offers a real narrowing the address publishes (its
    own filters, a paging pair), a concrete path, or says plainly that the first rows are all there is."""
    what = f"{kept} of {total} rows came back, in the vendor's order"
    placeholders_ = set(placeholders(row.path))
    filters = [n for n, sp in row.params.items()
               if n not in placeholders_ and sp.get("optional") is not False and n not in (given or {})]
    paging = [n for n in _PAGING if n in row.params]
    asked = (fields or "").strip().lower()
    advice = []
    if not asked:
        advice.append("fields='name,status' keeps fewer keys per row")
    elif asked == "all":
        advice.append("fields='name,status' (fewer keys per row) fits more of them")
    if filters:
        advice.append(f"args narrows by what this address publishes ({', '.join(filters[:4])})")
    if paging:
        advice.append(f"page with args {' and '.join(paging[:2])}")
    if "{" in row.path:
        advice.append("or read one row by its concrete path")
    if not advice:
        advice.append("this address publishes no further filter or paging: these are the first rows it has; "
                      "a concrete per-node or per-guest address (proximo_find lists them) holds fewer")
    return f"{what}: " + "; ".join(advice)


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


#: free text a guest owner (or the vendor's description) sets: never a STATE to count, however few distinct
#: values it takes on this estate
_FREE_TEXT = frozenset({"tags", "description", "comment", "notes", "title", "hostname", "text", "message", "msg"})


def _state_keys(records: list[dict]) -> dict[str, dict[str, int]]:
    """Per-key counts for the keys that are STATES: strings, bools or nulls, at most `_STATES` values, and never
    identity or free text. A key on few rows of the COMMON type (`lock` on one guest in three hundred) is kept:
    the exception is the point; one carried only by a minor type (storage `content`, node `level`) is not."""
    tally: dict[str, dict[str, int]] = {}
    typed = bool(records) and all("type" in r for r in records)
    dominant = Counter(_spell(r, "type") for r in records).most_common(1)[0][0] if typed else None
    for k in sorted({k for r in records for k in r if not _identity_key(k) and k not in _FREE_TEXT}):
        if any(k in r and not (isinstance(r[k], (str, bool)) or r[k] is None) for r in records):
            continue
        if typed and sum(k in r for r in records) * 2 < len(records) and not any(
                k in r and _spell(r, "type") == dominant for r in records):
            continue       # a sparse field of a minor type (storage `content`, node `level`), not the estate's state
        counts = Counter(_spell(r, k) for r in records)
        if len(counts) <= _STATES:
            tally[k] = dict(counts.most_common())
    return tally


def summarize(rows: list[Any], cap: rawdoor.Cap | None = None) -> dict[str, Any]:
    """Counts per state and the rows that are not in the most common one. When every row has a `type`
    (cluster resources: qemu, lxc, node, storage) the states are ALSO counted PER TYPE (`by_type`), because
    "how many containers are running" is a count of (type, status) pairs, not of two marginals."""
    records = [r for r in rows if isinstance(r, dict)]
    if _carries_content(records):
        return {"summarized": True, "tally": {}, "minority": [], "minority_total": 0}
    tally = _state_keys(records)
    typed = bool(records) and all("type" in r for r in records)
    group = (lambda r: _spell(r, "type")) if typed else (lambda r: "")
    modes: dict[str, dict[str, str]] = {}
    by_type: dict[str, dict[str, dict[str, int]]] = {}
    for g in {group(r) for r in records}:
        members = [r for r in records if group(r) == g]
        modes[g] = {k: Counter(_spell(r, k) for r in members).most_common(1)[0][0]
                    for k, v in tally.items() if len(v) > 1}
        if typed:
            counted = {k: {v: n for v, n in Counter(_spell(r, k) for r in members).most_common() if v != _ABSENT}
                       for k in tally if k != "type" and any(k in r for r in members)}
            by_type[g] = {k: v for k, v in counted.items() if v}
    minority = []
    for r in records:
        odd = {k: r.get(k) for k, mode in modes[group(r)].items() if _spell(r, k) != mode}
        if odd:
            minority.append({**{k: v for k, v in r.items() if _identity_key(k)}, **odd})
    out: dict[str, Any] = {"summarized": True, "tally": tally, **({"by_type": by_type} if typed else {}),
                           "minority": minority, "minority_total": len(minority),
                           "next": "fields='name,status' lists the rows; args (this address's filters) or a "
                                   "concrete path narrows"}
    # The minority gets the room the rest of the summary leaves under the cap, row by row, so
    # the whole summary fits (cut to the full cap, it pushed the summary over and lost it).
    compact = {"default": str, "separators": (",", ":")}
    base = json.dumps({**out, "minority": [], "minority_returned": 0}, **compact)
    used, spent = len(base.encode()), rawdoor.estimate_tokens(base)
    kept = []
    for r in minority:
        text = json.dumps(r, **compact)
        used2, spent2 = used + len(text.encode()) + 1, spent + rawdoor.estimate_tokens(text) + 1
        if not rawdoor.fits(used2, tokens=spent2, cap=cap):
            out.update(minority=kept, minority_returned=len(kept))
            break
        kept.append(r)
        used, spent = used2, spent2
    return out


# ---- THE STORE: a read leaves a snapshot; since= compares two of them, no vendor call --------

def _box(row: Row, cfg: wire.Plane | None) -> str:
    return (cfg.base_url if cfg is not None else wire.env_base_url(row.product)) or ""


def _keep(row: Row, called: str, args: dict[str, Any], data: Any, ledger_cfg: Any,
          cfg: wire.Plane | None, judging: bool = False, *, fields: str | None = None,
          evaluating: bool = False) -> None:
    """Best-effort and silent: a convenience must never fail the read it rides on. Two keepers, each
    on its own (one off, or failing, never stops the other): the store's snapshot of a list
    (`since=`), and the estate memory (`proximo.core.memory`: where, uses, changed), which also takes
    a guest's config and is fed the WITHHELD answer, never the vendor's raw bytes. A `judging` read
    (the engine's own read for a judgement it makes) keeps NOTHING in either. How the read was asked
    rides with it: a field subset (`fields`, with `all` and unset both the whole rows) or the door's
    own look for a verdict (`evaluating`) feeds memory but may not retire what it does not list
    (lens 2026-10-27: neither reached the feed, so a projected read and a plan's twin read retired)."""
    if judging:
        return
    try:
        if row.product == "pve" and row.path in memory.FEEDS and memory.enabled():
            kept, _ = withhold(data, row.secret)
            subset = None if fields is None or fields.strip().lower() == "all" else fields
            memory.feed((ledger_cfg or LedgerConfig.from_env()).audit_log_path, row.product, _box(row, cfg),
                        row.path, bind(row, called), args, kept, source=row.key, untrusted=row.untrusted,
                        fields=subset, evaluating=evaluating)
    except Exception:  # noqa: BLE001, S110 -- see the docstring
        pass
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
    # CAPPED LIKE ANY ANSWER: the header and the counts are spent first, the changes get the rest, and
    # a cut says so and how to narrow (a recall of a busy cluster is as long as the cluster).
    header = {"address": row.address, "plane": row.product, "access": row.access, "derived": True,
              "matched_path": row.path, "called_path": rawdoor.echo(called, 160), "tier": row.tier,
              "untrusted": row.untrusted,
              **{k: v for k, v in answer.items() if k != "changes"}}
    fenced = row.untrusted and spine.fence_on()
    whole = rawdoor.answer_cap()
    room = whole.minus(*rawdoor.spent(header))
    final: dict[str, Any] = {}
    last, stalls = None, 0
    for _ in range(6):
        final = _recalled(row, called, answer, room, fenced)
        body = json.dumps(final, separators=(",", ":"), default=str)
        stalls += last is not None and len(body) >= last
        if rawdoor.fits(len(body.encode()), body, cap=whole) or room.bytes <= 48 or stalls >= 3:
            break
        last = len(body)
        room = room.minus(2 * (len(body.encode()) - whole.bytes) + 16,
                          0 if whole.tokens is None
                          else 2 * max(rawdoor.estimate_tokens(body) - whole.tokens, 0) + 8, 48)
    return final


def _recalled(row: Row, called: str, answer: dict[str, Any], room: rawdoor.Cap, fenced: bool) -> dict[str, Any]:
    """The recall answer with its changes cut to `room` (and fenced when the row is untrusted)."""
    answer = dict(answer)
    cut = rawdoor.bounded(answer["changes"], room)
    if cut is not None and "returned" in cut:
        answer.update(changes=cut["data"], changes_returned=cut["returned"], changes_truncated=True,
                      next="the changes that fit; a shorter since= or a narrower path returns fewer")
    elif cut is not None:
        answer.update(changes=rawdoor.describe(answer["changes"]), changes_truncated=True, next=cut["next"])
    if cut is not None:
        rawdoor.note_problems(answer)
    if fenced:
        answer["changes"] = spine.fence(row.key, answer["changes"])
    return {"address": row.address, "plane": row.product, "access": row.access,
            "derived": True,           # composed by the door from what it kept, not the vendor's bytes
            "matched_path": row.path, "called_path": rawdoor.echo(called, 160), "tier": row.tier,
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
            names = sorted(have)
            more = f" (and {len(names) - 15} more)" if len(names) > 15 else ""
            raise ProximoError(f"fields: no row carries {rawdoor.quote(name, 40)}; the rows carry: "
                               f"{', '.join(names[:15])}{more}")
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
