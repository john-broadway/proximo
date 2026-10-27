#!/usr/bin/env python3
"""Build the one JSON: every address Proxmox publishes, one row each, with everything Proximo judges.

    records/vendor.json.gz   the vendor's addresses, generated (scripts/build_governance_table.py)
    records/*.toml           the authored judgments: tiers, taint, secrets, undo creates, shell rows,
                             DIAGNOSE's battery, find's vocabulary, PLAN's notes, token sight,
                             PLAN's consults
              |
              v
    src/proximo/core/proximo.json.gz   the one file the engine reads

THE CHECKS RUN HERE. Every line that would do nothing (a tier key that matches no address, a taint
line on a tunnel, a create without the twins its undo needs, a shell row the vendor now publishes,
a net naming a snapshot the door does not serve) refuses the build by name, so a record that lies
to its reader never ships. They are the checks the engine ran at every start until 2026-10-19,
moved, with their words. THE COLUMNS ARE COMPUTED HERE TOO: which lane a gated row is served on,
the read that shows a mutation's target (`twin`, `state`, `expect`), where its task is reported
(`task_status`), the secret rule merged with the read twin's. The engine asks the row, never
"which command is this?". `tests/test_proximo_json.py`
rebuilds from the records and holds the committed file to it.

    uv run python scripts/build_proximo_json.py           # write the file
    uv run python scripts/build_proximo_json.py --check   # refuse if the committed file is stale
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import re
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from proximo.core import apitree, diagnose, engine, rawdoor, search, shell  # noqa: E402
from proximo.core.engine import MUTATE, READ, TIERS, placeholders  # noqa: E402
from proximo.core.errors import ProximoError  # noqa: E402

RECORDS = ROOT / "records"
VENDOR = RECORDS / "vendor.json.gz"
OUT = ROOT / "src" / "proximo" / "core" / "proximo.json.gz"
SCHEMA = 1
#: The authored inputs, by the name their refusals use.
AUTHORED = ("tiers.toml", "taint.toml", "secrets.toml", "undo.toml", "shell.toml", "diagnose.toml", "vocab.toml",
            "notes.toml", "sight.toml", "consult.toml", "args.toml")


def family(path: str) -> str:
    """The 2-segment literal cut a tier is authored against: `/nodes/{node}/qemu/{vmid}` -> `/nodes/qemu`.

    Placeholders are DROPPED, not counted, so `/nodes/{node}/qemu` and `/nodes/{node}/qemu/{vmid}/config`
    share one family. Keys are PRODUCT-PREFIXED, so the 805 ungated mutating addresses (865 with
    the gated ones) collapse to 197 families, not the 145 an unprefixed count gives -- the engine
    keys on `product:family`, and quoting the unprefixed number understated the authoring job by 36%.
    """
    segs = [s for s in path.split("/") if s and not s.startswith("{")]
    return "/" + "/".join(segs[:2])


def _toml(name: str, text: str | None) -> dict:
    if text is None:
        return {}
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ProximoError(f"{name} is not a readable TOML table ({type(exc).__name__}); the build "
                           "refuses until the record parses") from exc


def tiers(text: str | None) -> dict[str, dict[str, str]]:
    """Authored blast-radius verdicts. Absent file = nothing authored = everything strict.

    A line is `"plane:METHOD /path" = "tier"` or, the shipped form,
    `"plane:METHOD /path" = { tier = "tier", why = "the human sentence" }`. The sentence is
    what an operator reads at plan time: a grant is the tier, the reason to make it is the
    sentence, and a file that carried only the word taught nobody anything.
    """
    parsed = _toml("tiers.toml", text).get("tier", {})
    raw_families, raw_held = parsed.get("family", {}), parsed.get("held", {})
    if not isinstance(raw_families, dict) or not isinstance(raw_held, dict):
        raise ProximoError(
            "tiers.toml: `family` and `held` name the [tier.family] and [tier.held] sub-tables and "
            f"cannot also be address keys (got {raw_families!r}, {raw_held!r})."
        )
    # [tier.held]: `"plane:METHOD /path" = { why = "..." }`. A judged refusal, no tier: the
    # engine refuses the address with this sentence before arm is asked. A line that also
    # carries a tier, or an address that is tiered AND held, is an ambiguity, refused whole.
    held = {}
    for key, value in raw_held.items():
        v = value if isinstance(value, dict) else {}
        sentence = v.get("why")
        if "tier" in v:
            raise ProximoError(f"tiers.toml: held line {key!r} carries a tier; a held address has a sentence, "
                               "not a grant (move the line to [tier] to open it)")
        if not isinstance(sentence, str) or len(sentence.split()) < 4:
            raise ProximoError(f"tiers.toml: held line {key!r} is without a why; the sentence is the judgement")
        held[key] = sentence.strip()
    authored, families, why, bad = {}, {}, {}, {}
    for scope, entries in (("address", {k: v for k, v in parsed.items() if k not in ("family", "held")}),
                           ("family", dict(raw_families))):
        for key, value in entries.items():
            tier, sentence = value, None
            if isinstance(value, dict):
                tier, sentence = value.get("tier"), value.get("why")
                if not isinstance(sentence, str) or not sentence.strip():
                    bad[key] = value      # the table form exists to carry the sentence
                    continue
            if not isinstance(tier, str) or tier not in TIERS:
                bad[key] = value
                continue
            (authored if scope == "address" else families)[key] = tier
            if sentence:
                why[key] = sentence.strip()
    if bad:
        raise ProximoError(
            f"tiers.toml carries lines outside the vocabulary or without a why: {bad}. "
            f"Valid tiers: {', '.join(sorted(TIERS))}; the table form needs a non-empty `why`."
        )
    if both := sorted(set(held) & set(authored)):
        raise ProximoError(f"tiers.toml: {', '.join(both[:3])} is both held and tiered; one judgement per address")
    return {"address": authored, "family": families, "why": why, "held": held}


def raises(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, list[dict]]:
    """`tiers.toml`'s `[raise]` table: a tier RAISED by a value the call names (the service a stop
    names, John 2026-10-25). Each line names its `addresses`, `when` (a bound or published name ->
    the values), the higher `tier` and `why`. Per address, the raises the engine judges. A line
    naming no published address, or one that would not raise, is refused here; the row-level rules
    are `apitree.raise_problem`'s, shared with the loader, and run once the tiers are stamped."""
    parsed = _toml("tiers.toml", text).get("raise", {})
    if not isinstance(parsed, dict):
        raise ProximoError("tiers.toml: `raise` names the [raise.<name>] tables")
    out: dict[str, list[dict]] = {}
    for name, line in parsed.items():
        if not isinstance(line, dict) or set(line) != {"addresses", "when", "tier", "why"}:
            raise ProximoError(f"tiers.toml: raise {name!r} takes exactly addresses, when, tier and why")
        if not isinstance(line["addresses"], list) or not line["addresses"]:
            raise ProximoError(f"tiers.toml: raise {name!r} names no addresses")
        when = line["when"]
        if isinstance(when, dict):
            when = {k: [apitree.raise_value(v) for v in vals] if isinstance(vals, list) else vals
                    for k, vals in when.items()}
        for key in line["addresses"]:
            product, _, address = str(key).partition(":")
            method, _, path = address.partition(" ")
            if (product, method, path) not in rows:
                raise ProximoError(f"tiers.toml: raise {name!r} names {key!r}, which matches no published address")
            out.setdefault(key, []).append({"when": when, "tier": line["tier"], "why": line["why"]})
    return out


def untrusted(text: str | None) -> dict[str, str]:
    """The untrusted-channel record: address -> the sentence that classifies it. Absent file =
    nothing classified. A line is `"plane:METHOD /path" = { why = "the sentence" }`; a line
    without a why, or a file that does not parse, refuses the build by name: a record that cannot
    be read cannot say which reads taint, and guessing is the one thing a taint model must never do."""
    parsed = _toml("taint.toml", text).get("untrusted", {})
    if not isinstance(parsed, dict):
        raise ProximoError("taint.toml: `untrusted` must be a table of address lines")
    out, bad = {}, {}
    for key, value in parsed.items():
        why = value.get("why") if isinstance(value, dict) else None
        if not isinstance(why, str) or not why.strip():
            bad[key] = value
            continue
        out[key] = why.strip()
    if bad:
        raise ProximoError(f"taint.toml carries lines without a why: {bad}. Every line is a classification "
                           "and the sentence is the classification.")
    return out


def secrets(text: str | None) -> tuple[dict[str, dict], dict[str, list[str]]]:
    """The secret record, both halves: address -> the READ rule (fields withheld, URL fields whose
    userinfo is masked, the `key` names of `{key, value}` rows whose values are withheld, whether a
    text body's `password:` lines are masked, the bearer sentence), and address -> the ARGUMENT
    names a mutation's ledger row fingerprints.
    FAILS CLOSED where taint.toml fails open: an absent taint record marks nothing, an absent secret
    record would serve every credential it names, so absence, a parse failure, or a line without a
    why or without a field refuses the build by name."""
    if text is None:
        raise ProximoError("secrets.toml cannot be read (absent): the door would serve the credentials "
                           "the record exists to withhold")
    try:
        parsed = tomllib.loads(text).get("secret")
    except tomllib.TOMLDecodeError as exc:
        raise ProximoError(f"secrets.toml cannot be read ({type(exc).__name__}): the door would serve the "
                           "credentials the record exists to withhold") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ProximoError("secrets.toml: `secret` must be a non-empty table of address lines")
    reads, bad = {}, {}
    for key, value in parsed.items():
        v = value if isinstance(value, dict) else {}
        drop, urls, rows, text_ = v.get("drop", []), v.get("userinfo", []), v.get("rows", []), v.get("text", False)
        why, bearer = v.get("why"), v.get("bearer", False)
        if (isinstance(v.get("args"), list) or isinstance(v.get("public"), list)) and not (
                drop or urls or rows or text_ is True or bearer is True):
            continue  # an ARG line (fingerprinted, or judged not secret); the passes below own it
        if (not isinstance(why, str) or not why.strip() or not (drop or urls or rows or text_ is True or bearer is True)
                or not isinstance(text_, bool) or not isinstance(bearer, bool)
                or not all(isinstance(f, str) and f for f in [*drop, *urls, *rows])):
            bad[key] = value
            continue
        reads[key] = {"drop": sorted(drop), "userinfo": sorted(urls), "rows": sorted(rows), "text": text_,
                      "bearer": why if bearer else None}
    if bad:
        raise ProximoError(f"secrets.toml carries lines without a why or a field: {bad}")
    # Argument names a mutation's ledger row must fingerprint: a line carrying an `args` list. The
    # READ rule withholds a credential the vendor SENDS; this one, a credential the caller SENDS (a
    # guest exec's argv and stdin, a file-write's content), which the name rule does not match.
    args, bad = {}, {}
    for key, value in parsed.items():
        v = value if isinstance(value, dict) else {}
        if "args" not in v:
            continue
        names, why = v.get("args"), v.get("why")
        if (not isinstance(names, list) or not names or not all(isinstance(a, str) and a for a in names)
                or not isinstance(why, str) or not why.strip()):
            bad[key] = value
            continue
        args[key] = sorted(names)
    if bad:
        raise ProximoError(f"secrets.toml carries arg-secret lines without a why or field names: {bad}")
    return reads, args


def arg_public(text: str | None) -> dict[str, list[str]]:
    """address -> the argument names the NAME rule would fingerprint that are NOT secret values (an identifier, a
    public key, a path, a boolean): a `public` list with a `public_why` on a line of `secrets.toml`. Parsed
    after `secrets` has accepted the file."""
    parsed = tomllib.loads(text or "").get("secret") or {}
    out, bad = {}, {}
    for key, value in parsed.items():
        v = value if isinstance(value, dict) else {}
        if "public" not in v and "public_why" not in v:
            continue
        names, why = v.get("public"), v.get("public_why")
        if (not isinstance(names, list) or not names or not all(isinstance(a, str) and a for a in names)
                or not isinstance(why, str) or not why.strip()):
            bad[key] = value
            continue
        out[key] = sorted(names)
    if bad:
        raise ProximoError(f"secrets.toml carries public-argument lines without a why or names: {bad}")
    return out


def refuse_inert_public(rows: dict, public: dict) -> None:
    """A `public` name the address does not publish, or that the name rule would not have fingerprinted
    anyway, does nothing and tells its reader it did."""
    inert = []
    for key, names in public.items():
        row = next((r for r in rows.values() if r.key == key and r.access == MUTATE and not r.excluded), None)
        for n in names:
            if row is None or n not in row.params or not engine.name_looks_secret(n):
                inert.append(f"{key}: {n}")
    if inert:
        raise ProximoError(f"secrets.toml names public argument(s) that do nothing (not a parameter of a live "
                           f"mutation, or not hidden by the name rule): {', '.join(inert[:5])}")


def shell_rows(text: str | None, vendor: set[tuple[str, str, str]]) -> list[dict]:
    """The container shell lane's AUTHORED rows (shell.toml), in the table's own row shape. The
    build refuses a row the vendor also publishes (it would shadow the vendor), a method whose
    access is not the one declared, and a row without params for its path placeholders."""
    if text is None:
        raise ProximoError("shell.toml is absent; the shell lanes have no rows to serve")
    doc = _toml("shell.toml", text)
    default_gate = doc.get("gate")
    if not isinstance(default_gate, str) or not default_gate.strip():
        raise ProximoError("shell.toml carries no gate sentence; its rows would read as ungated")
    out, seen = [], set()
    for r in doc.get("row", []):
        if not isinstance(r.get("method"), str) or not isinstance(r.get("path"), str):
            raise ProximoError(f"shell.toml: a row needs a method and a path, got {sorted(r)}")
        key = ("pve", r["method"], r["path"])
        sample = r["path"].replace("{node}", "n").replace("{vmid}", "1")
        if r["method"] not in ("GET", "POST") or not shell.dialable(sample):
            raise ProximoError(f"shell.toml: {r['method']} {r['path']} is not a call the ssh wire can dial "
                               "(GET or POST, /nodes/{node}/lxc/{vmid}/<exec|psql|logs|probe>, "
                               "/nodes/{node}/probe)")
        gate = r.get("gate", default_gate)     # a row on another lane says its own words
        if not isinstance(gate, str) or not gate.strip():
            raise ProximoError(f"shell.toml: {r['method']} {r['path']} carries an empty gate sentence")
        if key in seen:
            raise ProximoError(f"shell.toml names {r['method']} {r['path']} twice")
        seen.add(key)
        if key in vendor:
            raise ProximoError(f"shell.toml: the vendor now publishes {r['method']} {r['path']}; the "
                               "authored row must move, it never shadows the vendor's")
        want = READ if r["method"] == "GET" else MUTATE
        if (r.get("access") != want or not set(placeholders(r["path"])) <= set(r.get("params", {}))
                or not str(r.get("description", "")).strip()):
            raise ProximoError(f"shell.toml: {r['method']} {r['path']} must declare access {want!r} and "
                               "publish every path placeholder as a param and a description")
        net = r.get("net")
        if net is not None and (not isinstance(net, dict) or set(net) != {"snapshot", "rollback"}
                                or not all(isinstance(v, str) and v for v in net.values())):
            raise ProximoError(f"shell.toml: {r['method']} {r['path']} net must name a snapshot and a rollback address")
        out.append({"product": "pve", "method": r["method"], "path": r["path"], "access": want,
                    "excluded": False, "gate": gate, "params": r["params"], "tier": None, "wire": "ssh",
                    "description": r["description"], "net": net})
    return out


def refuse_bad_net(rows: list[dict], index: dict[tuple[str, str, str], dict]) -> None:
    """A row's `net` promises UNDO a snapshot before the act and a rollback after, so it is refused
    unless both are POSTs the door serves on the act's OWN guest (the same `{node}`/`{vmid}` or
    `{remote}`/`{vmid}` path), the snapshot publishes `snapname` without naming one in its path,
    and the rollback names `{snapname}`. On the ssh wire (shell.toml) an ssh row's `snapshot`
    parameter without a net, or a net without one, promises an undo the engine will not take (the
    vendor's own `snapshot` parameters name a snapshot to read, not a net to take). On the API wire
    (undo.toml [net]) a net is exactly a rollback's own, `apitree.rollback_net`."""
    for r in rows:
        key, net, snap = f'{r["product"]}:{r["method"]} {r["path"]}', r["net"], r["params"].get("snapshot")
        ssh = r.get("wire", "http") == "ssh"
        if ssh and (net is None) != (snap is None):
            raise ProximoError(f"{key}: a `snapshot` parameter and a `net` come together; "
                               "one without the other promises an undo the engine will not take")
        if net is None:
            continue
        if ssh:
            if snap.get("type") != "boolean":
                raise ProximoError(f"{key}: `snapshot` must be a boolean parameter")
            own = r["path"].rpartition("/")[0] + "/"
        else:
            if net != apitree.rollback_net(r):
                raise ProximoError(f"{key}: a net on the API wire is the snapshot and rollback of its own guest")
            own = r["path"].partition("/snapshot/")[0] + "/"
        for what, address in net.items():
            method, _, path = address.partition(" ")
            t = index.get((r["product"], method, path))
            if (t is None or t["excluded"] or t["gate"] or method != "POST" or not path.startswith(own)
                    or (what == "snapshot" and ("snapname" not in t["params"] or "{snapname}" in path))
                    or (what == "rollback" and "{snapname}" not in path)):
                raise ProximoError(f"{key}: net {what} {address!r} is not a mutation the door serves "
                                   "on the command's own container")


def nets(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, dict[str, str]]:
    """`undo.toml`'s `[net]` table: the snapshot rollbacks that take a safety snapshot first, each
    with its sentence. Proxmox publishes no read of a guest to capture before a rollback discards
    what happened since the snapshot, so the only net is another snapshot, waited, and the
    rollback is not run when it does not land. The line carries only its `why`: the snapshot and
    the rollback are derived from the address (`apitree.rollback_net`), so no line can name a net
    the address does not support. Refused unless the address is a published, ungated POST rollback
    on the API wire whose guest publishes a snapshot create the door serves. Absent file = none."""
    parsed = _toml("undo.toml", text).get("net", {})
    if not isinstance(parsed, dict):
        raise ProximoError("undo.toml: `net` names the [net] table")
    out: dict[str, dict[str, str]] = {}
    for key, value in parsed.items():
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = rows.get((product, method, path))
        if row is None or row["excluded"]:
            raise ProximoError(f"undo.toml: net line {key!r} matches no published address")
        if not isinstance(value, dict) or set(value) != {"why"} or not isinstance(value["why"], str) \
                or len(value["why"].split()) < 4 or value["why"] != value["why"].strip():
            raise ProximoError(f"undo.toml: net line {key!r} takes exactly a why of four words or more; "
                               "the sentence is the judgement")
        derived = apitree.rollback_net(row)
        if (derived is None or row["access"] != MUTATE or row["gate"] or row.get("wire", "http") != "http"):
            raise ProximoError(f"undo.toml: net line {key!r} is not a snapshot rollback the door serves on the "
                               "API wire; a net is a snapshot taken first and this rollback after")
        snap = rows.get((product, "POST", derived["snapshot"].partition(" ")[2]))
        if snap is None or snap["excluded"] or snap["gate"] or "snapname" not in snap["params"]:
            raise ProximoError(f"undo.toml: net line {key!r} has no snapshot create the door serves on the "
                               "same guest; without it UNDO has no net to take")
        out[key] = derived
    return out


def lane(r: dict) -> str | None:
    """The opt-in lane a GATED row is served on when its operator switch and allowlist say so
    (spine.opt_in_refusal): the shell lanes by the row's own shape, the download lane for the
    byte streams, the guest agent's subtree (one definition, rawdoor's). None = ungated, or a
    hard gate the door never serves."""
    if not r["gate"]:
        return None
    if r.get("wire", "http") == "ssh":
        return shell.lane_of(r["path"])
    if rawdoor.is_stream(r["product"], r["path"]):
        return "download"
    return "agent" if r["product"] == "pve" and r["path"].startswith(rawdoor.AGENT_PREFIX) else None


#: What a power action aims at: `start` means `running`, `stop` means `stopped`, ...
EXPECTED = {"start": "running", "stop": "stopped", "shutdown": "stopped", "resume": "running"}


def reads_of(r: dict, index: dict[tuple[str, str, str], dict]) -> dict[str, Any]:
    """A mutation's reads: `twin`, the GET the vendor publishes at the same path (UNDO's capture
    and the plan's current; gated or tunnelled, it is named, not read), and `state`, the parent's
    `/current` an action with no served twin is read through (13 guest power actions, 2 HA), with
    `expect`, the status four of them aim at. All null on a read."""
    out: dict[str, Any] = {"twin": None, "state": None, "expect": None}
    if r["access"] != MUTATE:
        return out
    same = index.get((r["product"], "GET", r["path"]))
    out["twin"] = r["path"] if same is not None else None
    if same is None or same["excluded"]:
        parent, _, action = r["path"].rpartition("/")
        cur = index.get((r["product"], "GET", parent + "/current"))
        if cur is not None and not cur["excluded"] and not cur["gate"]:
            out["state"] = parent + "/current"
            out["expect"] = {"status": EXPECTED[action]} if action in EXPECTED else None
    return out


def task_status(r: dict, index: dict[tuple[str, str, str], dict]) -> str | None:
    """Where the plane reports a task this mutation submits: PDM's remote form under a remote's own
    tree (the remote from the path the operator was allowed), else the node's, which every plane
    publishes. Refused when the plane does not publish it: a wait on an address the plane lacks
    never closes."""
    if r["access"] != MUTATE or r["excluded"]:
        return None
    m = re.match(r"^/(pve|pbs)/remotes/\{remote\}/", r["path"])
    t = f"/{m.group(1)}/remotes/{{remote}}/tasks/{{upid}}/status" if m else "/nodes/{node}/tasks/{upid}/status"
    if (r["product"], "GET", t) not in index:
        raise ProximoError(f'{r["product"]} publishes no GET {t}; if {r["method"]} {r["path"]} submits a task '
                           "it could not be polled")
    return t


def merged_secret(own: dict | None, twin: dict | None) -> dict | None:
    """A mutation's answer is governed by its OWN line merged with its read twin's: the twin's
    drops still withhold a mutation that echoes its resource, bearer comes from the own line alone
    (lens 2 N1: an own bearer line replaced the twin's `password` drop wholesale). A read's rule is
    its own line; a mutation with no own line is governed by the twin's."""
    if own is None or twin is None:
        return twin if own is None else own
    return {"drop": sorted(set(own["drop"]) | set(twin["drop"])),
            "userinfo": sorted(set(own["userinfo"]) | set(twin["userinfo"])),
            "rows": sorted(set(own["rows"]) | set(twin["rows"])),
            "text": own["text"] or twin["text"], "bearer": own["bearer"]}


def creates(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, str]:
    """`undo.toml`'s `[create]` table: the POSTs at an item path that CREATE the record the path
    names, each with its sentence. A line promises an undo the engine will deliver, so it is
    refused unless the address is a published, ungated POST with a published, ungated GET (to read
    the record back) and DELETE (to put absence back) at the same path. Keyed on the address,
    never the shape: a POST at an item path with both twins can still be an action (a restore, a
    copy, a rule added to a group) whose "absent" would delete what was there. Absent file = none
    judged = every create at an item path keeps its refusal when its read-back fails."""
    parsed = _toml("undo.toml", text).get("create", {})
    if not isinstance(parsed, dict):
        raise ProximoError("undo.toml: `create` names the [create] table")
    out: dict[str, str] = {}
    for key, value in parsed.items():
        sentence = value.get("why") if isinstance(value, dict) else None
        if not isinstance(sentence, str) or len(sentence.split()) < 4:
            raise ProximoError(f"undo.toml: create line {key!r} is without a why; the sentence is the judgement")
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = rows.get((product, method, path))
        if row is None or row["excluded"]:
            raise ProximoError(f"undo.toml: create line {key!r} matches no published address")
        if method != "POST" or row["access"] != MUTATE or row["gate"]:
            raise ProximoError(f"undo.toml: create line {key!r} is not a POST the door serves; a create is a POST")
        for twin in ("GET", "DELETE"):
            t = rows.get((product, twin, path))
            need = "read the record back" if twin == "GET" else "put absence back"
            if t is None or t["excluded"] or t["gate"]:
                raise ProximoError(f"undo.toml: create line {key!r} has no {twin} {path} the door serves; "
                                   f"without it UNDO cannot {need}")
            # THE TWIN IS CALLED WITH THE PATH ALONE: the capture's read and the restore's delete
            # send no arguments, so a twin that requires one would refuse at check_args every time
            # and the line would promise an undo the engine never delivers.
            asks = sorted(k for k, v in t["params"].items()
                          if not v.get("optional") and k not in placeholders(t["path"]))
            if asks:
                raise ProximoError(f"undo.toml: create line {key!r}: {twin} {path} requires {', '.join(asks)} beyond "
                                   f"the path, and UNDO calls it with the path alone; it cannot {need}")
        out[key] = sentence.strip()
    return out


def notes(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, list[dict]]:
    """`notes.toml`'s `[note]` table: per address, the consequences the plan prints when the call's
    own arguments meet a line's condition (`given`, `not_given`), each with what it says and why.
    A note is advice and gates nothing; a line that could never show, or could show a name the
    address does not take, is refused here in the words the loader uses (`apitree.note_problem`).
    Absent file = no notes."""
    parsed = _toml("notes.toml", text).get("note", {})
    if not isinstance(parsed, dict):
        raise ProximoError("notes.toml: `note` names the [note] table")
    out: dict[str, list[dict]] = {}
    for key, value in parsed.items():
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = rows.get((product, method, path))
        if row is None or row["excluded"]:
            raise ProximoError(f"notes.toml: note line {key!r} matches no published address")
        if not isinstance(value, list) or not value:
            raise ProximoError(f"notes.toml: note line {key!r} is not a list of notes")
        if wrong := apitree.notes_problem(value, row):
            raise ProximoError(f"notes.toml: note line {key!r} {wrong}")
        out[key] = [{k: n[k] for k in apitree.note_keys(n)} for n in value]
    return out


def sight(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, dict]:
    """`sight.toml`'s `[sight]` table: per read address, what an EMPTY answer cannot be taken to
    mean (`what`), which privileges the token must hold for the list to have been seen at all
    (`sighted`: alternatives, each a list of `privilege@path`), when it applies (`when`: a
    parameter's values; the parameter absent counts), and the judgement (`why`). A line that could
    never be judged or names what the address does not take is refused in the words the loader
    uses (`apitree.sight_problem`). Absent file = no line."""
    parsed = _toml("sight.toml", text).get("sight", {})
    if not isinstance(parsed, dict):
        raise ProximoError("sight.toml: `sight` names the [sight] table")
    out: dict[str, dict] = {}
    for key, value in parsed.items():
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = rows.get((product, method, path))
        if row is None or row["excluded"]:
            raise ProximoError(f"sight.toml: sight line {key!r} matches no published address")
        if wrong := apitree.sight_problem(value, row, rows):
            raise ProximoError(f"sight.toml: sight line {key!r} {wrong}")
        out[key] = {k: value[k] for k in apitree.SIGHT_KEYS}
    return out


#: A consult's why names what the vendor does not do (bar 4): a sentence, not a label.
CONSULT_WHY_WORDS = 8


def consults(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, str]:
    """`consult.toml`'s `[consult]` table: per mutation address, the judge its plan consults
    (`proximo.core.consult.JUDGES`) and why. The reads are the judge's, declared in code; the line
    says which addresses consult which judge. Refused here, in the loader's words where the rule is
    shared (`apitree.consult_problem`): an address that matches nothing, a line that is not exactly
    `judge` and `why`, a why under eight words, and, once the tiers are stamped, a judge that does
    not exist or could not run on that row. Absent file = no consults."""
    parsed = _toml("consult.toml", text).get("consult", {})
    if not isinstance(parsed, dict):
        raise ProximoError("consult.toml: `consult` names the [consult] table")
    out: dict[str, str] = {}
    for key, value in parsed.items():
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = rows.get((product, method, path))
        if row is None:
            raise ProximoError(f"consult.toml: consult line {key!r} matches no published address")
        if not isinstance(value, dict) or set(value) != {"judge", "why"}:
            raise ProximoError(f"consult.toml: consult line {key!r} takes exactly judge and why")
        why = value["why"]
        if not isinstance(why, str) or len(why.split()) < CONSULT_WHY_WORDS or why != why.strip():
            raise ProximoError(f"consult.toml: consult line {key!r} is without a why of at least "
                               f"{CONSULT_WHY_WORDS} words; the sentence names what the vendor does not do")
        out[key] = value["judge"]
    return out


def one_of(text: str | None, rows: dict[tuple[str, str, str], dict]) -> dict[str, dict]:
    """`args.toml`'s `[one_of]` table: per mutation, the parameters a call must name at least one
    of (`names`) and the judgement (`why`). The vendor accepts a call that names none and does the
    nothing it asked for; the refusal is authored, on the address. A line that could never refuse,
    or names what the address does not take, is refused here in the words the loader uses
    (`apitree.one_of_problem`). Absent file = no rule."""
    parsed = _toml("args.toml", text).get("one_of", {})
    if not isinstance(parsed, dict):
        raise ProximoError("args.toml: `one_of` names the [one_of] table")
    out: dict[str, dict] = {}
    for key, value in parsed.items():
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = rows.get((product, method, path))
        if row is None or row["excluded"]:
            raise ProximoError(f"args.toml: one_of line {key!r} matches no published address")
        if wrong := apitree.one_of_problem(value, row):
            raise ProximoError(f"args.toml: one_of line {key!r} {wrong}")
        out[key] = {k: value[k] for k in apitree.ONE_OF_KEYS}
    return out


def battery(text: str | None) -> list[dict[str, Any]]:
    """`records/diagnose.toml` as the one JSON's `diagnose` list: a subject per entry (`key`, `is`,
    `shell`), its probes a list (`name` first), so the authored order rides through sorted keys.
    The words are checked by `diagnose.compile` in `build`, against the judged rows."""
    if text is None:
        raise ProximoError("diagnose.toml is absent; DIAGNOSE has no battery and the build refuses")
    raw = _toml("diagnose.toml", text).get("subject") or {}
    if not isinstance(raw, dict) or not raw:
        raise ProximoError("diagnose.toml: `subject` must be a non-empty table of subjects")
    out = []
    for key, spec in raw.items():
        probes = spec.get("probe") or {}
        # THE TABLE KEY IS THE NAME. An authored `key` or `name` field would win the merge and
        # rename the subject or probe silently (lens 2 on D3, L2-2); it is refused instead.
        if "key" in spec or any(isinstance(p, dict) and "name" in p for p in probes.values()):
            raise ProximoError(f"diagnose.toml: subject {key} carries a `key`, or one of its probes a `name`; "
                               "the table key is the name and nothing renames it")
        out.append({"key": key, **{k: v for k, v in spec.items() if k != "probe"},
                    "probe": [{"name": name, **p} for name, p in probes.items()]})
    return out


def vocab(text: str | None) -> list[dict[str, Any]]:
    """`records/vocab.toml` as the one JSON's `vocab` list (`word`, `means`, `why`), authored order
    kept. The words are checked by `search.compile_vocab` in `build`."""
    if text is None:
        raise ProximoError("vocab.toml is absent; find has no vocabulary and the build refuses")
    raw = _toml("vocab.toml", text).get("synonym") or {}
    if not isinstance(raw, dict) or not raw:
        raise ProximoError("vocab.toml: `synonym` must be a non-empty table of words")
    return [{"word": word, **(spec if isinstance(spec, dict) else {"means": spec})} for word, spec in raw.items()]


def refuse_inert_keys(rows: dict, tier: dict) -> None:
    """A tier key that matches no address is refused, never silently ignored.

    The backends spell placeholders `{n}` and `{mid}`; the vendor table spells them `{node}` and
    `{monid}`. A key carrying the wrong spelling matches nothing, the engine keeps refusing, and
    the author believes they authored something. It fails CLOSED, so it is safe -- and that is
    exactly why it would never be noticed. An authored line that does nothing is a lie the file
    tells its reader.
    """
    live_addr = {f"{r.product}:{r.method} {r.path}" for r in rows.values()}
    live_fam = {f"{r.product}:{family(r.path)}" for r in rows.values()}
    # A held line reaches a row only where a grant could: a held read or tunnel refuses nothing
    # the engine was not refusing already, and tells its reader it judged something.
    openable = {r.key for r in rows.values() if r.access == MUTATE and not r.gate and not r.excluded}
    inert = sorted([k for k in tier["address"] if k not in live_addr]
                   + [k for k in tier["family"] if k not in live_fam]
                   + [k for k in tier["held"] if k not in openable])
    if inert:
        raise ProximoError(
            f"tiers.toml names {len(inert)} key(s) that match no published address: "
            f"{', '.join(inert[:5])}{' ...' if len(inert) > 5 else ''}. "
            f"Check the placeholder spelling against the table (the vendor says {{node}}, not {{n}})."
        )


def refuse_inert_untrusted(rows: dict, record: dict[str, str]) -> None:
    """A taint line that matches no address, or matches one the engine refuses before any
    pillar (a HARD `gate`d or excluded row), does nothing and tells the reader it did. Refused.
    An OPT-IN gated row (the guest-agent lane) is served when the operator opts in, so a taint
    line on one is live, not inert."""
    live = {f"{r.product}:{r.method} {r.path}": r for r in rows.values()}
    inert = sorted(k for k in record if k not in live
                   or (live[k].gate and live[k].lane is None)
                   or live[k].excluded)
    if inert:
        raise ProximoError(
            f"taint.toml names {len(inert)} key(s) that match no address the engine serves: "
            f"{', '.join(inert[:5])}{' ...' if len(inert) > 5 else ''}. "
            f"A gated or tunnelled row is refused before taint is read; a line for it is inert."
        )


def refuse_inert_secrets(rows: dict, reads: dict) -> None:
    """A secret line that names no published address the door serves withholds nothing and would
    tell the reader it did (a placeholder spelled `{section}` where the vendor says `{profile}`).
    A line is live on a read the door serves, or on a mutation it may open (a token mint's
    one-time answer); never on a tunnel or a hard-gated byte stream."""
    live = {r.key for r in rows.values() if not r.excluded and not r.held
            and ((r.method == "GET" and not r.gate)
                 or (r.access == MUTATE and (not r.gate or r.lane is not None)))}
    inert = sorted(k for k in reads if k not in live)
    if inert:
        raise ProximoError(f"secrets.toml names {len(inert)} key(s) that match no address the door answers "
                           f"(a read it serves, or a mutation it may open; never a held, gated or tunnelled one): "
                           f"{', '.join(inert[:5])}{' ...' if len(inert) > 5 else ''}")


def refuse_inert_arg_secrets(rows: dict, args: dict) -> None:
    """An arg-secret line that names no mutating address the door serves fingerprints nothing and
    tells its reader it did. The address must be a live, non-excluded mutation (gated or not: the
    guest-agent lane is gated-opt-in and its exec/file-write are exactly these lines)."""
    live = {r.key for r in rows.values() if r.access == MUTATE and not r.excluded}
    inert = sorted(k for k in args if k not in live)
    if inert:
        raise ProximoError(f"secrets.toml names arg-secret key(s) that match no mutation the door serves: "
                           f"{', '.join(inert[:5])}{' ...' if len(inert) > 5 else ''}")


def build(vendor: list[dict], texts: dict[str, str | None]) -> dict[str, Any]:
    """The one JSON from the vendor's rows and the authored records' text (`None` = absent).
    Pure: reads nothing, writes nothing, so a test can plant a record and watch it refuse."""
    rows = [dict(r) for r in vendor]
    rows += shell_rows(texts.get("shell.toml"), {(r["product"], r["method"], r["path"]) for r in rows})
    tier, taint = tiers(texts.get("tiers.toml")), untrusted(texts.get("taint.toml"))
    reads, args = secrets(texts.get("secrets.toml"))
    public = arg_public(texts.get("secrets.toml"))
    index = {(r["product"], r["method"], r["path"]): r for r in rows}
    safety = nets(texts.get("undo.toml"), index)
    for r in rows:
        addr = f'{r["product"]}:{r["method"]} {r["path"]}'   # Row.key, before the Row exists
        fam = f'{r["product"]}:{family(r["path"])}'
        # A family line opens only what a line may open: an ungated mutating address. Without
        # this, the family's tier was stamped on every read, gated call and tunnel in the
        # family too; govern() refused those first, but a plan printed "destructive" on a GET.
        openable = r["access"] == "mutate" and not r["gate"] and not r["excluded"]
        # A HELD address is judged, not opened: the sentence is what the plan prints, and no
        # tier is stamped beside it (a family line that reaches it would read as a grant).
        held = tier["held"].get(addr) if openable else None
        r.update(
            # ADDRESS BEATS FAMILY. A family is the broad judgement; a single address that is
            # sharper (or safer) than its neighbours gets its own line and wins.
            tier=None if held else (tier["address"].get(addr) or (tier["family"].get(fam) if openable else None)),
            why=None if held else (tier["why"].get(addr) or (tier["why"].get(fam) if openable else None)),
            held=held, untrusted=addr in taint, channel=taint.get(addr), wire=r.get("wire", "http"),
            secret=merged_secret(reads.get(addr),
                                 reads.get(f'{r["product"]}:GET {r["path"]}') if r["method"] != "GET" else None),
            arg_secrets=args.get(addr, []), arg_public=public.get(addr, []), lane=lane(r),
            net=r.get("net") or safety.get(addr),
            task_status=task_status(r, index),
            **reads_of(r, index))
    refuse_bad_net(rows, index)
    made = creates(texts.get("undo.toml"), index)
    said, seen = notes(texts.get("notes.toml"), index), sight(texts.get("sight.toml"), index)
    must = one_of(texts.get("args.toml"), index)
    lifted = raises(texts.get("tiers.toml"), index)
    asked = consults(texts.get("consult.toml"), index)
    for r in rows:
        key = f'{r["product"]}:{r["method"]} {r["path"]}'
        r["creates"] = made.get(key)
        r["notes"] = said.get(key, [])
        r["sight"] = seen.get(key)
        r["one_of"] = must.get(key)
        r["raises"] = lifted.get(key, [])
        r["consult"] = asked.get(key)
        if wrong := apitree.raises_problem(r["raises"], r):
            raise ProximoError(f"tiers.toml: the raise on {key!r} {wrong}")
        if r["consult"] is not None and (wrong := apitree.consult_problem(r["consult"], r, index)):
            raise ProximoError(f"consult.toml: consult line {key!r} {wrong}")
    judged = {key: engine.row_of(r) for key, r in index.items()}
    refuse_inert_keys(judged, tier)
    refuse_inert_untrusted(judged, taint)
    refuse_inert_secrets(judged, reads)
    refuse_inert_arg_secrets(judged, args)
    refuse_inert_public(judged, public)
    bat, voc = battery(texts.get("diagnose.toml")), vocab(texts.get("vocab.toml"))
    diagnose.compile(bat, {row.key: row for row in judged.values()})   # refuses here, with its words
    search.compile_vocab(voc)
    return {"schema": SCHEMA, "rows": rows, "diagnose": bat, "vocab": voc}


def dumps(doc: dict) -> bytes:
    """THE ONE SERIALISATION: sorted keys, no spaces, no mtime in the gzip, so a rebuild's JSON is
    byte-equal. The gzip WRAPPER is not: two zlib builds of the same version deflate differently
    (Python 3.12's and 3.13's on one box, 2026-10-20), so a comparison reads `inside`, never the gz."""
    return gzip.compress(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), mtime=0)


def inside(gz: bytes) -> bytes:
    """The JSON bytes a built file carries: what a drift comparison holds, the wrapper aside."""
    return gzip.decompress(gz)


def read_inputs(root: pathlib.Path = RECORDS) -> tuple[list[dict], dict[str, str | None], dict[str, str]]:
    """The vendor rows, the authored texts (None where a file is absent), and every input's sha256."""
    vendor_bytes = (root / VENDOR.name).read_bytes()
    texts = {n: (root / n).read_text() if (root / n).exists() else None for n in AUTHORED}
    sums = {VENDOR.name: hashlib.sha256(vendor_bytes).hexdigest()}
    sums |= {n: hashlib.sha256(t.encode()).hexdigest() for n, t in texts.items() if t is not None}
    return json.loads(gzip.decompress(vendor_bytes)), texts, sums


def assemble(root: pathlib.Path = RECORDS) -> bytes:
    vendor, texts, sums = read_inputs(root)
    return dumps({**build(vendor, texts), "built": {"inputs": sums}})


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--check", action="store_true", help="refuse if the committed file is not what the records build")
    a = p.parse_args(argv)
    blob = assemble()
    if a.check:
        if not OUT.exists() or inside(OUT.read_bytes()) != inside(blob):
            print(f"build_proximo_json: {OUT.name} is not what records/ builds; run scripts/build_proximo_json.py",
                  file=sys.stderr)
            return 1
        print(f"{OUT.name}: current")
        return 0
    OUT.write_bytes(blob)
    print(f"wrote {OUT.name}: {len(json.loads(gzip.decompress(blob))['rows'])} rows, {len(blob):,} B gz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
