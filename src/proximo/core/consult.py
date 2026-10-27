"""CONSULT: a mutation's plan takes a second look at the estate before the change.

The plan reads the TARGET (its GET twin, `engine._live_state`). Some consequences live elsewhere: a
storage volume a guest config still names, a bridge guests hang off, the last backup of a guest. A
row whose record names a judge (`records/consult.toml`, keyed on the mutation's address, with a why
naming what the vendor does not do) is consulted:

    engine.plan / engine.execute
        -> consult.run(row, path, args, cfg, ledger_cfg)
             the judge's declared reads, filled from the call's own path   } every one through
             its fan-out (each guest's config), owner first                } engine.execute,
             under MAX_READS and MAX_BYTES                                 } never a raw client
        -> estate.build(answers)                    pure (proximo.core.estate)
        -> judge.fn(call, estate) -> Finding        pure
        -> {"judge", "affects", "warnings", "complete", "raise_to", "reads", ...}

The engine adds `seen_at` ("plan" or "execute"). The section on the EXECUTING receipt is what
execute read at the wire, not the plan the operator approved: the consent grant binds the call
(its path and arguments), never the consult's answer, and no plan state reaches execute to diff.

THE RULES (the design's "Rules every piece keeps", 2026-10-25):

- One seam for the wire. A consult read is `engine.execute` on a published GET: receipted, withheld,
  taint-marked (resources and guest configs are untrusted addresses, so a consult marks the session
  like the read would), bounded by the door's size law. Nothing here builds a client.
- Fail toward the worst case. A read refused, failed, cut by the door's cap or over the budget, an
  answer of the wrong shape (`estate.shape_problems`), an empty guest config, a guest the target's
  own name says owns it missing from the guest list (the token may not see it, or it is gone), a
  judge that raises, any failure inside `run`: `complete: false`, `raise_to` = the judge's declared
  `worst`, and the reason in `why`. `run` never raises.
  "Found nothing" on an incomplete read is never "safe".
- Advice raises, never lowers, never refuses. `raise_to` is what the judge says the call deserves at
  least; the engine takes the max with the authored tier and the value raise (`apitree.TIER_RANK`),
  so the authored tier stays the floor and no judge opens anything. `execute` writes the section on
  the EXECUTING receipt and runs the call; the ladder, later, decides what a tier needs.

WRITING A JUDGE (what a later judge author adds, all in this file):

    def my_fn(call: Call, est: estate.Estate) -> Finding:          # pure: no I/O, no engine
        hit = est.guests_on_bridge(call.bound["iface"])
        return Finding(affects=tuple({"guest": g.key, "name": g.name} for g in hit),
                       warnings=(...,), raise_to="disruptive" if hit else None)

    JUDGES["my_judge"] = Judge(
        name="my_judge",
        reads=(Read("/cluster/resources", {"type": "vm"}),),      # published GETs on the row's plane;
                                                                   # {placeholders} from the call's path
        each="guest_config",                                       # a FANOUT name, or None
        fn=my_fn,
        worst="disruptive")                                        # the tier when the reads cannot finish

then a line in `records/consult.toml` for each address it judges, `scripts/build_proximo_json.py`, and
tests. The build and the loader refuse (`apitree.consult_problem`): an address that is not a served
mutation, or is held; a judge not in JUDGES; a why under eight words; a read that is not a published,
ungated GET on the row's plane, that the estate does not consume (`estate.SOURCES`), whose
placeholders the mutation's path does not bind, or whose arguments the read does not publish.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from proximo.core import apitree, estate, spine, wire
from proximo.core.errors import ProximoError
from proximo.core.secretfile import safe_exception_text

#: THE READ BUDGET. One resources read, one permissions read and one `/pending` read per guest: 94
#: guests are judged whole, so an estate of about 60 has half again as many to spare. Each read is
#: a governed round trip and a ledger row; at about 15 ms on a LAN, 96 reads is about 1.5 s for the
#: plan and the same again in execute, which is as long as a plan should spend before it answers.
#: The OTHER ceiling is the resources read itself under the door's read cap (whatever cap the
#: consult's reads get, `READ_OPTIONS`): asked for only `type,vmid,node,status`, a guest's row is
#: about 60 to 80 bytes (measured with 3- to 6-digit vmids and node names up to 17 characters),
#: so a cap of C bytes holds about C/80 guests; the door's default rows, with names, tags, pools
#: and HA state, run 100 to 170 bytes. A bigger estate is not stalled on: the plan says
#: incomplete, names what it read, and raises to the judge's worst case.
MAX_READS = 96
#: THE BYTE BUDGET, over the answers kept: no read STARTS once it is spent (the read that crosses
#: it is kept whole; nothing is discarded). The door's read cap already bounds each answer; this
#: bounds the memory a plan holds when an operator raised that cap. 768 KiB = 96 answers at a
#: generous 8 KiB each.
MAX_BYTES = 768 * 1024
#: THE ONE PLACE the consult's reads say how `engine.execute` serves them (every consult read is
#: `_Reads.read`, the single call site). They read under the door's evaluation cap: a judge reads
#: for its own verdict, never for a model, and the model cap would hold about 14 guests.
READ_OPTIONS: Mapping[str, Any] = MappingProxyType({"evaluating": True})
#: The plan answers in a 4K-token window: a handful of named dependents, and the count of the rest.
AFFECTS_SHOWN = 5
#: A guest-authored string (a name) on a receipt or a plan, cut to this.
_TEXT = 120


@dataclass(frozen=True)
class Fanout:
    """A fan-out: per guest kind, the published GET read for each guest the resources read found
    ({node} and {vmid} from the guest; PVE publishes no `{type}` placeholder), the projection
    `execute` serves it with, and the sentence for what it does not read."""

    templates: Mapping[str, str]
    fields: str | None = None
    omits: str | None = None


#: The fan-outs a judge may declare.
#: guest_config reads each guest's `GET .../pending`: BOTH views in one read (`value`, what the
#: guest runs with now, and `pending`/`delete`, what it takes at its next start), and the estate
#: keeps the union (`estate.views_from_pending`). The `/config` read answers one view per read
#: (`current=1` or the pending-applied default), which halved the guests the budget could judge.
#: `fields="all"`: the door's lean rows keep strings and drop numbers, and `delete` is a number.
#: Snapshot sections are not read (a read per snapshot per guest would spend the budget on history).
FANOUT: dict[str, Fanout] = {
    "guest_config": Fanout(
        templates={"qemu": "/nodes/{node}/qemu/{vmid}/pending", "lxc": "/nodes/{node}/lxc/{vmid}/pending"},
        fields="all",
        omits=("snapshot sections are not read: a volume only a snapshot names (its saved memory, "
               "a disk detached since) reads as free here; only the guests this token can see are judged, "
               "and a consult that cannot show the token sees them all says so: a token with very many ACL "
               "paths (about 170 bytes each) passes the door's read cap and reads as incomplete")),
}


@dataclass(frozen=True)
class Read:
    """One declared read: a published GET template on the row's plane, its fixed arguments, and the
    projection `execute` serves (None: the door's lean rows; a judge needing numbers asks by name)."""

    template: str
    args: Mapping[str, str] = field(default_factory=dict)
    fields: str | None = None


@dataclass(frozen=True)
class Call:
    """The mutation being judged: its plane, published address, concrete path, the values the path
    binds (decoded), and the arguments as sent."""

    plane: str
    address: str
    path: str
    bound: Mapping[str, str]
    args: Mapping[str, Any]


@dataclass(frozen=True)
class Finding:
    """What a judge says: who the change hits, the sentences the plan prints, and the tier it
    deserves at least (None: nothing found to raise on)."""

    affects: tuple[Mapping[str, Any], ...] = ()
    warnings: tuple[str, ...] = ()
    raise_to: str | None = None


@dataclass(frozen=True)
class Judge:
    name: str
    reads: tuple[Read, ...]
    each: str | None                               # a FANOUT name, or None
    fn: Callable[[Call, estate.Estate], Finding]
    worst: str                                     # the tier an incomplete consult raises to
    first: Callable[[Call], str | None] | None = None   # the vmid the fan-out reads first
    #: (privilege, path): what the token must hold, propagated from `path`, for the vendor's lists
    #: to hold every entry (a list Proxmox filters by privilege is the token's own, not the estate).
    #: The judge must also read the WHOLE `GET /access/permissions` map for it (no `path`: a deeper
    #: ACL that removes a guest shows only there); held or not is `Estate.sees_every`.
    sees: tuple[str, str] | None = None


# ---- the judges -----------------------------------------------------------------------------------

def _volid(call: Call) -> str:
    """The vendor's reading of `{volume}`: a volid when it carries a colon, else a name on `{storage}`."""
    volume = call.bound.get("volume", "")
    return volume if ":" in volume else f"{call.bound.get('storage', '')}:{volume}"


_OWNER_RE = re.compile(r"(?:^|[:/])(?:vm|base|subvol|basevol)-(\d+)-")
_STATE_RE = re.compile(r"(?:^|[:/])vm-\d+-state-")


def _owner(call: Call) -> str | None:
    """The guest a volume's name says owns it (`vm-101-disk-0`, `base-101-disk-1`, `subvol-105-disk-0`,
    `101/vm-101-disk-0.qcow2`; a linked clone `base-100-disk-0/vm-101-disk-0` is 101's, the LAST
    name in the path). Read first, so a cut estate still names the likeliest guest; and a guest
    named here that the guest list does not hold makes the consult incomplete."""
    found = _OWNER_RE.findall(_volid(call))
    return found[-1] if found else None


def content_delete(call: Call, est: estate.Estate) -> Finding:
    """0.44's `compute_content_delete_blast`: the guests whose config may name the volume as a DATA
    disk (`Estate.disks_using`: the volume itself, or a linked clone built on it; never a cdrom
    mount), the slots, and whether the guest still boots (the volume is its boot disk, its
    UEFI/TPM state or saved memory, or every data disk it has). A guest's saved-memory volume
    (`vm-N-state-NAME`) no config names is likely a snapshot's, which is not read: the worst case."""
    volid = _volid(call)
    using: dict[str, list[str]] = {}
    for d in est.disks_using(volid):
        using.setdefault(d.guest, []).append(d.slot)
    affects = []
    for g in est.guests:
        slots = sorted(using.get(g.key, ()))
        if not slots:
            continue
        data = {d.slot for d in est.disks_of(g.key) if d.storage and not d.cdrom}
        wont_boot = g.boot in slots or bool(estate.BOOT_CRITICAL.intersection(slots)) or set(slots) == data
        effect = f"an active disk ({', '.join(slots)}); deleting the volume destroys that disk's data"
        if wont_boot:
            effect += "; the guest will not boot"
        if g.running:
            effect += "; it is running, and losing a disk live can crash or corrupt it"
        affects.append({"guest": g.key, "name": g.name, "node": g.node, "via": slots, "effect": effect})
    if affects:
        return Finding(tuple(affects), (f"{volid} is an active disk of {len(affects)} guest(s); the vendor's "
                                        "delete publishes no check for a guest that still names it",), "destructive")
    if _STATE_RE.search(volid):
        return Finding((), (f"no guest config read names {volid}; its name is a guest's saved memory, which "
                            "a snapshot may hold, and snapshot sections are not read",), "destructive")
    return Finding((), (f"no guest config read references {volid} as a disk (an ISO, a template, a backup "
                        "or an orphan)",), None)


JUDGES: dict[str, Judge] = {
    "content_delete": Judge(name="content_delete",
                            # resources: only what the estate keys guests by, so the row stays small
                            # under the door's read cap (MAX_READS says how small); names come from
                            # each guest's own config. permissions: /cluster/resources lists only the
                            # guests the token holds VM.Audit on, so a guest it cannot see may hold
                            # the volume; the token's whole map says whether it sees them all.
                            reads=(Read("/cluster/resources", {"type": "vm"}, "type,vmid,node,status"),
                                   Read("/access/permissions", {}, "all")),
                            each="guest_config", fn=content_delete, worst="destructive", first=_owner,
                            sees=("VM.Audit", "/vms")),
}


# ---- the record's rule, shared by the build and the loader (apitree.consult_problem) ---------------

def problem(name: Any, r: Mapping[str, Any], index: Mapping[tuple[str, str, str], Mapping[str, Any]]) -> str | None:
    """Why a consult naming `name` on row `r` would do nothing or could not run; None when it can."""
    if not isinstance(name, str) or name not in JUDGES:
        return f"names judge {name!r}, which no judge in proximo.core.consult answers to"
    if r["access"] != "mutate" or r["gate"] or r["excluded"]:
        return "is not a mutation the door serves"
    if r.get("held"):
        return "sits on a held address; a held call is refused by its sentence and never consulted"
    judge = JUDGES[name]
    if judge.worst not in apitree.TIER_RANK:
        return f"names judge {name}, whose worst case {judge.worst!r} is outside the tier vocabulary"
    if judge.sees is not None and not any(x.template == "/access/permissions" and not x.args for x in judge.reads):
        return (f"names judge {name}, which judges sight ({judge.sees[0]}) without reading the whole GET "
                "/access/permissions map (a `path` or `userid` narrows it past a deeper ACL)")
    if judge.each is not None and judge.each not in FANOUT:
        return f"names judge {name}, whose fan-out {judge.each!r} is not one of {', '.join(FANOUT)}"
    bindable = set(_placeholders(r["path"]))
    fan = FANOUT.get(judge.each or "")
    for template, args, binds in ([(x.template, x.args, bindable) for x in judge.reads]
                                  + [(t, {}, {"node", "vmid"}) for t in (fan.templates.values() if fan else ())]):
        read = index.get((r["product"], "GET", template))
        if read is None or read["excluded"] or read["gate"]:
            return (f"names judge {name}, whose read GET {template} is not a published GET the door "
                    f"serves on {r['product']}")
        if template not in estate.SOURCES:
            return f"names judge {name}, whose read GET {template} the estate does not consume"
        if missing := sorted(set(_placeholders(template)) - binds):
            return (f"names judge {name}, whose read GET {template} needs {', '.join(missing)}, "
                    "which the call does not bind")
        if unknown := sorted(k for k in args if k not in read["params"]):
            return f"names judge {name}, whose read GET {template} does not publish {', '.join(unknown)}"
    return None


def _placeholders(path: str) -> tuple[str, ...]:
    return tuple(seg[1:-1] for seg in path.split("/") if seg.startswith("{") and seg.endswith("}"))


# ---- the run --------------------------------------------------------------------------------------

class _Spent(Exception):
    """The budget ran out: stop reading."""


def _text(v: Any) -> Any:
    return v[:_TEXT] if isinstance(v, str) else [_text(x) for x in v] if isinstance(v, list) else v


def _data_of(env: Mapping[str, Any]) -> tuple[bool, Any]:
    """(whole, data) from a read's envelope. Cut, summarised or reported by size means NOT whole: a
    cut list is never the population. A fenced answer is unwrapped: the fence speaks to a model,
    the judge parses data."""
    if "data" not in env or env.get("truncated") or env.get("summarized") or "returned" in env:
        return False, None
    data = env["data"]
    if isinstance(data, dict) and data.get("proximo_untrusted") is True and isinstance(data.get("data"), str):
        try:
            data = json.loads(data["data"])
        except ValueError:             # fence-shaped, not the fence's JSON: not read whole
            return False, None
    return True, data


def worse(a: str | None, b: str | None) -> str | None:
    """The higher of two tiers on `apitree.TIER_RANK`; an unknown word never wins."""
    ranked = [t for t in (a, b) if t in apitree.TIER_RANK]
    return max(ranked, key=apitree.TIER_RANK.__getitem__) if ranked else None


class _Reads:
    """The reads of one consult: each through `engine.execute`, counted against the budget, its
    answer kept whole or its shortfall named in `gaps`."""

    def __init__(self, engine: Any, row: Any, plane: wire.Plane, ledger_cfg: Any) -> None:
        self.engine, self.row, self.plane, self.ledger_cfg = engine, row, plane, ledger_cfg
        self.answers: list[estate.Answer] = []
        self.gaps: list[str] = []
        self.reads = self.bytes = 0
        self.untrusted = False

    def read(self, template: str, values: Mapping[str, str], rargs: Mapping[str, str], fields: str | None) -> Any:
        engine = self.engine
        if self.reads >= MAX_READS:
            raise _Spent(f"the read budget ({MAX_READS}) ran out")
        if self.bytes >= MAX_BYTES:
            raise _Spent(f"the byte budget ({MAX_BYTES:,}) ran out")
        self.reads += 1
        try:
            concrete = engine.fill(template, values)
            env = engine.execute(engine.table()[(self.row.product, "GET", template)], dict(rargs), cfg=self.plane,
                                 path=concrete, ledger_cfg=self.ledger_cfg, fields=fields, **READ_OPTIONS)
        except ProximoError as exc:
            self.gaps.append(f"GET {template} was refused: {exc}")
            return None
        except Exception as exc:       # the vendor failed or is unreachable; receipted by execute
            err = spine.wire_error(exc)
            self.gaps.append(f"GET {engine.fill(template, values)} failed ({err.get('status') or type(exc).__name__})")
            return None
        self.untrusted = self.untrusted or bool(env.get("untrusted"))
        whole, data = _data_of(env)
        if not whole:
            self.gaps.append(f"GET {concrete} was cut, summarised or garbled by the door's read cap; it was "
                             "not read whole")
            return None
        self.bytes += len(json.dumps(data, default=str))
        self.answers.append(estate.Answer(template, dict(values), data))
        return data

    def gather(self, judge: Judge, call: Call) -> None:
        """The judge's reads, then its fan-out over the guests the resources read found, owner first."""
        try:
            first: dict[str, Any] = {}
            for x in judge.reads:
                first[x.template] = self.read(x.template, call.bound, x.args, x.fields)
            if judge.each is None:
                return
            if "/cluster/resources" not in first:
                self.gaps.append(f"the fan-out {judge.each} has no resources read to enumerate guests from")
            fan = FANOUT[judge.each]
            guests = list(estate.guests_from_resources(first.get("/cluster/resources")))
            owner = judge.first(call) if judge.first else None
            guests.sort(key=lambda g: g.vmid != owner)          # stable: the vendor's order otherwise
            for g in guests:
                template = fan.templates.get(g.kind)
                if template is None or g.node is None:
                    self.gaps.append(f"{g.key} names no node or kind to read its config at")
                    continue
                self.read(template, {"node": g.node, "vmid": g.vmid}, {}, fan.fields)
        except _Spent as spent:
            self.gaps.append(f"{spent}; the estate was not read whole")


def worst_of(row: Any) -> str:
    """The tier a consult on `row` raises to when it cannot finish: its judge's declared worst, or
    the top of the vocabulary for a judge no registry answers to."""
    judge = JUDGES.get(getattr(row, "consult", None) or "")
    return judge.worst if judge else max(apitree.TIER_RANK, key=apitree.TIER_RANK.__getitem__)


def not_read(row: Any, why: str) -> dict[str, Any]:
    """The section for a consult that made no read: incomplete, at the worst case, saying why."""
    return {"judge": getattr(row, "consult", None), "affects": [], "warnings": [], "complete": False,
            "raise_to": worst_of(row), "reads": 0, "why": why}


def run(row: Any, path: str | None, args: Mapping[str, Any], cfg: wire.Plane | None = None,
        ledger_cfg: Any = None) -> dict[str, Any]:
    """The consult section for `row` (an `engine.Row` whose `consult` names a judge) called at `path`
    with `args`. NEVER RAISES: every shortfall, and any failure of this module's own, is
    `complete: false` at the judge's worst case. `execute` calls it on the way to the wire, and an
    exception there would leave the call with no receipt of what was seen."""
    try:
        return _run(row, path, args, cfg, ledger_cfg)
    except Exception as exc:  # noqa: BLE001 -- the consult's own failure is an incomplete consult
        return not_read(row, f"the consult failed ({type(exc).__name__}); the estate was not read whole")


def _run(row: Any, path: str | None, args: Mapping[str, Any], cfg: wire.Plane | None,
         ledger_cfg: Any) -> dict[str, Any]:
    from proximo.core import engine  # call time: engine imports this module

    judge = JUDGES.get(row.consult or "")
    worst = worst_of(row)
    out: dict[str, Any] = {"judge": row.consult, "affects": [], "warnings": [], "complete": False,
                           "raise_to": worst, "reads": 0}
    if judge is None:
        return {**out, "why": f"no judge named {row.consult!r}"}
    if not path or "{" in path:
        return {**out, "why": "a template path names no target to consult; give the concrete path"}
    try:
        bound = engine.bind(row, path)
        plane = cfg if cfg is not None else wire.Plane.from_env(row.product)
    except ProximoError as exc:
        return {**out, "why": str(exc)}
    except RuntimeError as exc:        # unset, or a credential file the floor refuses
        return {**out, "why": f"no credential usable on this box: {safe_exception_text(exc, paths=True)}"}
    call = Call(plane=row.product, address=row.address, path=path, bound=bound, args=dict(args))
    reads = _Reads(engine, row, plane, ledger_cfg)
    reads.gather(judge, call)
    gaps = reads.gaps
    est = estate.build(reads.answers)
    gaps += est.malformed
    fan = FANOUT.get(judge.each or "")
    if fan is not None:
        if est.unread:
            gaps.append(_named(sorted(est.unread), "guest config(s) unread or empty"))
    owner = judge.first(call) if judge.first else None
    if owner is not None and "/cluster/resources" in est.read and owner not in {g.vmid for g in est.guests}:
        gaps.append(f"the target names guest {owner} as its owner and the guest list does not hold it: either "
                    f"this token cannot see guest {owner} (the list is filtered by VM.Audit), or the guest is gone "
                    f"and the volume is an orphan. To tell them apart, read GET /cluster/resources with a token "
                    f"that holds VM.Audit on /vms: a guest {owner} there was hidden from this one")
    if judge.sees is not None:
        priv, where = judge.sees
        holds = est.sees_every(priv, where)
        if holds is False:
            gaps.append(f"this token's permission map does not show {priv} reaching every guest: it must be held, "
                        f"propagating, at the most specific path defined on the way to {where} ({where} if defined, "
                        f"else /), and on every {where}/<id> path defined below it. The vendor's lists hold only "
                        "the guests a token can see, so a guest it cannot see may use the volume")
        elif holds is None:
            gaps.append(f"whether this token sees every guest ({priv}) could not be read: GET /access/permissions "
                        "failed, was cut by the door's read cap (a token with very many ACL paths, about 170 bytes "
                        "each, passes it), or was no permission map")
    try:
        finding = judge.fn(call, est)
    except Exception as exc:  # noqa: BLE001 -- a judge's bug is an incomplete consult, never a crash
        finding = Finding()
        gaps.append(f"the judge failed ({type(exc).__name__})")
    complete = not gaps
    affects = [{k: _text(v) for k, v in a.items()} for a in finding.affects]
    out.update(affects=affects[:AFFECTS_SHOWN], complete=complete, reads=reads.reads,
               raise_to=finding.raise_to if complete else worse(finding.raise_to, worst),
               warnings=([f"INCOMPLETE: {gaps[0]}; absence here is not proof nothing is affected"]
                         if not complete else []) + list(finding.warnings))
    if fan is not None and fan.omits:        # said ONCE, here, not again in `warnings` (the plan has a ceiling)
        out["omits"] = fan.omits
    if len(affects) > AFFECTS_SHOWN:
        out["affects_total"] = len(affects)
    if not complete:
        out["why"] = "; ".join(gaps[:3]) + (f" (+{len(gaps) - 3} more)" if len(gaps) > 3 else "")
    if reads.untrusted:
        out["untrusted"] = True        # guest-authored names ride `affects`; the session is marked already
    return out


def _named(keys: list[str], what: str) -> str:
    return f"{len(keys)} {what}: {', '.join(keys[:AFFECTS_SHOWN])}" + (" ..." if len(keys) > AFFECTS_SHOWN else "")
