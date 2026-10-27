"""The four Proxmox API trees and everything Proximo judges about them, in one file: `proximo.json.gz`,
one row per address the official api-viewer publishes (plus the shell lane's authored rows), built
by `scripts/build_proximo_json.py` from `records/`. This module reads it, once, and refuses it whole
if it is not exactly the shape the engine governs. Every reader shares this one load: the engine's
table, the raw GET door (`proximo.rawdoor`), `find` (`proximo.core.search`).

Placeholder segments (`{node}`, `{vmid}`) are wildcards; a literal segment matches itself only.
"""

from __future__ import annotations

import gzip
import json
import re
import zlib
from functools import cache
from importlib import resources
from typing import Any

from proximo.core.errors import ProximoError

SCHEMA = 1
#: Every column of a row and the types it may hold. A row missing one, or carrying one more, is a
#: damaged file: refused whole, never read with a default (a row without `untrusted` is not an
#: untainted row, and one without `secret` is not a row with nothing to withhold).
_COLUMNS: dict[str, tuple[type, ...]] = {
    "product": (str,), "method": (str,), "path": (str,), "params": (dict,), "access": (str,),
    "excluded": (bool,), "gate": (str, type(None)), "tier": (str, type(None)), "why": (str, type(None)),
    "held": (str, type(None)), "untrusted": (bool,), "channel": (str, type(None)), "wire": (str,),
    "description": (str,), "secret": (dict, type(None)), "arg_secrets": (list,), "arg_public": (list,),
    "creates": (str, type(None)),
    "lane": (str, type(None)), "twin": (str, type(None)), "state": (str, type(None)), "expect": (dict, type(None)),
    "net": (dict, type(None)), "task_status": (str, type(None)), "notes": (list,), "raises": (list,),
    "sight": (dict, type(None)), "one_of": (dict, type(None)),
    "consult": (str, type(None)),
}
_SECRET = {"drop": list, "userinfo": list, "rows": list, "text": bool, "bearer": (str, type(None))}
#: The opt-in lanes a gated row may be served on (spine.opt_in_refusal); None is ungated or a hard gate.
LANES = (None, "agent", "shell", "node", "download")


@cache
def published() -> dict[str, Any]:
    """The one JSON, checked: schema, every row's columns and their types, no address twice, every
    named row carried, and every computed column what the build writes from the file's own rows."""
    try:
        doc = json.loads(gzip.decompress(resources.files("proximo.core").joinpath("proximo.json.gz").read_bytes()))
    except (OSError, EOFError, ValueError, zlib.error) as exc:  # zlib.error: bytes flipped inside the stream
        raise ProximoError(f"proximo.json.gz cannot be read ({type(exc).__name__}): every address is refused "
                           "until the package carries a readable one") from exc
    rows = doc.get("rows") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(rows, list) or not rows:
        raise ProximoError(f"proximo.json.gz is not schema {SCHEMA} with rows; every address is refused")
    # The two authored sections beside the rows: DIAGNOSE's battery (a list of subjects, each
    # with a list of probes: the authored order rides) and find's vocabulary. Their words are
    # checked by `diagnose.compile` and `search.compile_vocab`; the shape is checked here so a
    # damaged section refuses with a sentence, never a KeyError in a reader.
    bat, voc = doc.get("diagnose"), doc.get("vocab")
    if not (isinstance(bat, list) and bat and all(isinstance(s, dict) and isinstance(s.get("key"), str)
                                                   and isinstance(s.get("probe"), list)
                                                   and all(isinstance(p, dict) and isinstance(p.get("name"), str)
                                                           for p in s["probe"]) for s in bat)):
        raise ProximoError("proximo.json.gz carries no diagnose battery; every address is refused")
    if not (isinstance(voc, list) and voc and all(isinstance(v, dict) and isinstance(v.get("word"), str) for v in voc)):
        raise ProximoError("proximo.json.gz carries no find vocabulary; every address is refused")
    seen = set()
    for i, r in enumerate(rows):
        bad = (not isinstance(r, dict) or set(r) != set(_COLUMNS)
               or any(not isinstance(r[k], t) for k, t in _COLUMNS.items())
               or (r["secret"] is not None and (set(r["secret"]) != set(_SECRET)
                                                or any(not isinstance(r["secret"][k], t) for k, t in _SECRET.items())))
               or r["product"] not in PRODUCTS or r["access"] not in ("read", "mutate")
               or r["wire"] not in ("http", "ssh") or r["lane"] not in LANES
               or (r["net"] is not None and (set(r["net"]) != {"snapshot", "rollback"}
                                             or any(not isinstance(v, str) for v in r["net"].values())))
               or (r["expect"] is not None and any(not isinstance(v, str) for v in r["expect"].values())))
        if bad:
            raise ProximoError(f"proximo.json.gz row {i} is not the shape the engine governs; every address is refused")
        key = (r["product"], r["method"], r["path"])
        if key in seen:
            raise ProximoError(f"proximo.json.gz names {r['method']} {r['path']} on {r['product']} twice; "
                               "every address is refused")
        seen.add(key)
    # A column that names another row names one the file carries: a twin, a state, a task-status
    # address or a net pointing at nothing would be a KeyError at plan or execute time, not a
    # refusal, and the engine reads them without a lookup guard by design (the build proved them).
    index = {(r["product"], r["method"], r["path"]): r for r in rows}
    for r in rows:
        named = [(r["product"], "GET", a) for a in (r["twin"], r["state"], r["task_status"]) if a]
        named += [(r["product"], a.partition(" ")[0], a.partition(" ")[2]) for a in (r["net"] or {}).values()]
        if missing := [n for n in named if n not in index]:
            raise ProximoError(f"proximo.json.gz row {r['method']} {r['path']} on {r['product']} names "
                               f"{' '.join(missing[0][1:]).strip() or 'nothing'}, which the file does not carry; "
                               "every address is refused")
        if wrong := _wrong_column(r, index):
            raise ProximoError(f"proximo.json.gz row {r['method']} {r['path']} on {r['product']} {wrong}; "
                               "every address is refused")
    # The judgements the file exists to carry. A file with none of them is the shape the engine
    # governs and would serve every credential and read every guest-written answer as clean; the
    # old runtime loaders refused that at every start, and the build still does. Refused here too.
    for column, what in (
            ("secret", "withholds no field: the door would serve the credentials the record exists to withhold"),
            ("untrusted", "marks no answer untrusted: every guest-written byte would read as clean"),
            ("arg_secrets", "fingerprints no argument: a secret sent in would reach the ledger raw")):
        if not any(r[column] for r in rows):
            raise ProximoError(f"proximo.json.gz {what}; every address is refused")
    return doc


#: What a power action aims at (the build's table): the status PLAN's `noop` and `change` read against.
_EXPECTED = {"start": "running", "stop": "stopped", "shutdown": "stopped", "resume": "running"}


def _wrong_column(r: dict[str, Any], index: dict[tuple[str, str, str], dict[str, Any]]) -> str | None:
    """The first computed column that is not what the build writes from the file's own rows (lens 3
    F8 and lens 4 L4-4: the loader held the addresses, then seven rules, and a dozen shapes the
    build never writes were still served). The engine reads each column without a guard by
    design; what it relies on is derived here exactly as the build derives it, and compared."""
    from proximo.core import rawdoor, shell  # rawdoor imports this module; bound at call time, not import time

    product, path, mutate = r["product"], r["path"], r["access"] == "mutate"
    parent, _, action = path.rpartition("/")
    same, cur = index.get((product, "GET", path)), index.get((product, "GET", parent + "/current"))
    state = (parent + "/current" if mutate and (same is None or same["excluded"])
             and cur is not None and not cur["excluded"] and not cur["gate"] else None)
    remote = re.match(r"^/(pve|pbs)/remotes/\{remote\}/", path)
    want = {
        "access": "read" if r["method"] == "GET" else "mutate",   # the method's: a POST read as a read skips every gate
        "twin": path if mutate and same is not None else None,
        "state": state,
        "expect": {"status": _EXPECTED[action]} if state and action in _EXPECTED else None,
        "task_status": (None if not mutate or r["excluded"]
                        else f"/{remote.group(1)}/remotes/{{remote}}/tasks/{{upid}}/status" if remote
                        else "/nodes/{node}/tasks/{upid}/status"),
        "lane": (None if not r["gate"] else shell.lane_of(path) if r["wire"] == "ssh"
                 else "download" if rawdoor.is_stream(product, path)
                 else "agent" if product == "pve" and path.startswith(rawdoor.AGENT_PREFIX) else None),
    }
    for column, value in want.items():
        if r[column] != value:
            return f"carries {column} {r[column]!r} where the file's own rows give {value!r}"
    if r["creates"] is not None and not _is_create(r, index):
        return "carries a create that is not an ungated POST with ungated GET and DELETE twins at its path"
    if wrong := notes_problem(r["notes"], r):
        return f"carries a note the build would not write: it {wrong}"
    if wrong := raises_problem(r["raises"], r):
        return f"carries a raise the build would not write: it {wrong}"
    if r["sight"] is not None and (wrong := sight_problem(r["sight"], r, index)):
        return f"carries a sight line the build would not write: it {wrong}"
    if r["consult"] is not None and (wrong := consult_problem(r["consult"], r, index)):
        return f"carries a consult the build would not write: it {wrong}"
    if r["one_of"] is not None and (wrong := one_of_problem(r["one_of"], r)):
        return f"carries a rule the build would not write: it {wrong}"
    return _wrong_net(r, index)


#: The four keys a conditional note carries (records/notes.toml), no more.
NOTE_KEYS = ("given", "not_given", "says", "why")
#: The three keys an ALWAYS-ON note carries: no condition, and `always = true` written out. A note
#: that holds for every call to its address cannot happen by leaving a condition empty.
ALWAYS_KEYS = ("always", "says", "why")


def note_keys(n: dict[str, Any]) -> tuple[str, ...]:
    """The keys a note is held to: the always-on shape when it says `always`, else the conditional."""
    return ALWAYS_KEYS if "always" in n else NOTE_KEYS


def note_problem(n: Any, r: dict[str, Any]) -> str | None:
    """Why a note on row `r` would do nothing or mislead, in the words the build and the loader
    both refuse with; None when it is a note the engine can judge. A note rides only a mutation
    the door serves, names only parameters the address publishes, has a condition (or says
    `always = true`, written out), and says something with a reason. The build refuses the record
    line; the loader refuses the file."""
    if not isinstance(n, dict) or set(n) != set(note_keys(n) if isinstance(n, dict) else NOTE_KEYS):
        return "takes exactly given, not_given, says and why, or exactly always, says and why"
    if r["access"] != "mutate" or r["gate"] or r["excluded"]:
        return "is not a mutation the door serves"
    if "always" in n:
        if n["always"] is not True:
            return "says always but not `always = true`"
    else:
        given, not_given = n["given"], n["not_given"]
        if not (isinstance(given, list) and isinstance(not_given, list)
                and all(isinstance(k, str) for k in (*given, *not_given))):
            return "given and not_given are lists of parameter names"
        if not given and not not_given:
            return "has no condition; a note that holds for every call says `always = true`, written out"
        for k in (*given, *not_given):
            if k not in r["params"]:
                return f"names {k}, which the address does not publish"
        if both := sorted(set(given) & set(not_given)):
            return f"names {both[0]} in both given and not_given"
        if len(set(given)) != len(given) or len(set(not_given)) != len(not_given):
            return "names a parameter twice"
        for k in (*given, *not_given):
            if f"{{{k}}}" in r["path"]:
                return f"names {k}, which the path binds; it is never an argument"
    for k in ("says", "why"):
        if not isinstance(n[k], str) or len(n[k].split()) < 4:
            return f"is without a {k}; the sentence is the judgement"
        if n[k] != n[k].strip():
            return f"carries a {k} with space around it"
    return None


def notes_problem(notes: list[Any], r: dict[str, Any]) -> str | None:
    """`note_problem` for each note on a row, and no two notes with one condition."""
    for n in notes:
        if wrong := note_problem(n, r):
            return wrong
    conds = [("always",) if "always" in n else (tuple(sorted(n["given"])), tuple(sorted(n["not_given"])))
             for n in notes]
    if len(set(conds)) != len(conds):
        return "carries two notes with one condition"
    return None


#: The two keys an at-least-one rule carries (records/args.toml), no more.
ONE_OF_KEYS = ("names", "why")


def one_of_problem(x: Any, r: dict[str, Any]) -> str | None:
    """Why an at-least-one rule on row `r` would do nothing or mislead, in the words the build and
    the loader both refuse with; None when the engine can judge it. A rule rides only a mutation
    the door serves, names only parameters the address publishes (and never one the path binds,
    which is no argument), each once, and says why with the sentence that is the judgement."""
    if not isinstance(x, dict) or set(x) != set(ONE_OF_KEYS):
        return "takes exactly names and why"
    if r["access"] != "mutate" or r["gate"] or r["excluded"]:
        return "is not a mutation the door serves"
    names = x["names"]
    if not (isinstance(names, list) and all(isinstance(k, str) for k in names)):
        return "names are a list of parameter names"
    if not names:
        return "names no parameter; a rule over nothing refuses nothing"
    if len(set(names)) != len(names):
        return "names a parameter twice"
    for k in names:
        if k not in r["params"]:
            return f"names {k}, which the address does not publish"
        if f"{{{k}}}" in r["path"]:
            return f"names {k}, which the path binds; it is never an argument"
    if not isinstance(x["why"], str) or len(x["why"].split()) < 4:
        return "is without a why; the sentence is the judgement"
    if x["why"] != x["why"].strip():
        return "carries a why with space around it"
    return None


#: Severity order of the tier vocabulary (engine.TIERS), least to most. A raise moves up it only.
TIER_RANK = {"read-back": 0, "restorable": 1, "disruptive": 2, "destructive": 3}
#: The keys a raise carries on a row (records/tiers.toml [raise]), no more.
RAISE_KEYS = ("when", "tier", "why")


def raise_value(value: Any) -> str:
    """A value as a raise compares it: stripped, lower case, a trailing `.service` dropped (a
    systemd unit and its service name are one service; `SSHD` and `sshd.service` are `sshd`)."""
    v = str(value).strip().lower()
    return v[: -len(".service")] if v.endswith(".service") else v


def raise_problem(x: Any, r: dict[str, Any]) -> str | None:
    """Why a raise on row `r` would do nothing or mislead; None when the engine can judge it. A
    raise rides only a mutation the door serves that ALREADY carries a tier (a raise never opens),
    moves to a tier strictly above it, keys on names the path binds or the address publishes,
    lists the values it raises on (already in `raise_value`'s spelling), and says why."""
    if not isinstance(x, dict) or set(x) != set(RAISE_KEYS):
        return "takes exactly when, tier and why"
    if r["access"] != "mutate" or r["gate"] or r["excluded"]:
        return "is not a mutation the door serves"
    if r["tier"] not in TIER_RANK:
        return "sits on an address with no authored tier to raise; a raise never opens"
    if x["tier"] not in TIER_RANK:
        return f"names tier {x['tier']!r}, outside the vocabulary"
    if TIER_RANK[x["tier"]] <= TIER_RANK[r["tier"]]:
        return f"does not raise: {x['tier']} is not above the authored {r['tier']}"
    when = x["when"]
    if not isinstance(when, dict) or not when:
        return "has no condition; a raise that is always on is the address's own tier"
    for k, vals in when.items():
        if f"{{{k}}}" not in r["path"] and k not in r["params"]:
            return f"names {k}, which the address neither binds nor publishes"
        if not (isinstance(vals, list) and vals and all(isinstance(v, str) and v and v == raise_value(v)
                                                           for v in vals)):
            return f"lists no values for {k}, or a value not in the compared spelling"
    if not isinstance(x["why"], str) or len(x["why"].split()) < 4 or x["why"] != x["why"].strip():
        return "is without a why; the sentence is the judgement"
    return None


def raises_problem(raises: list[Any], r: dict[str, Any]) -> str | None:
    """`raise_problem` for each raise on a row."""
    for x in raises:
        if wrong := raise_problem(x, r):
            return wrong
    return None


#: The four keys a sight line carries (records/sight.toml), no more.
SIGHT_KEYS = ("when", "sighted", "what", "why")
#: One requirement of a sight line: a privilege, `@`, and the path it must be held at (`*` = anywhere,
#: `{name}` = a placeholder the path binds or a parameter the address publishes).
_REQUIREMENT = re.compile(r"^[A-Za-z]+(?:\.[A-Za-z]+)+@(?:\*|/[^\s{}]*(?:\{[^{}\s]+\}[^\s{}]*)*)$")


def sight_problem(s: Any, r: dict[str, Any], index: dict[tuple[str, str, str], dict[str, Any]]) -> str | None:
    """Why a sight line on row `r` would do nothing or mislead, in the words the build and the
    loader both refuse with; None when it is a line the engine can judge. A line rides only a read
    the door serves, on a plane that publishes the read of what the token holds (without it every
    empty list would be refused for good), names only parameters the address publishes, and says
    what is hidden and why with the sentence that is the judgement."""
    if not isinstance(s, dict) or set(s) != set(SIGHT_KEYS):
        return "takes exactly when, sighted, what and why"
    if r["access"] != "read" or r["gate"] or r["excluded"]:
        return "is not a read the door serves"
    perms = index.get((r["product"], "GET", "/access/permissions"))
    if perms is None or perms["gate"] or perms["excluded"]:
        return f"is on {r['product']}, which publishes no GET /access/permissions to judge it by"
    when = s["when"]
    if not (isinstance(when, dict) and all(isinstance(k, str) and isinstance(v, list) and v
                                           and all(isinstance(x, str) and x for x in v) for k, v in when.items())):
        return "when takes parameter names and lists of values"
    for k in when:
        if k not in r["params"]:
            return f"names {k}, which the address does not publish"
        if f"{{{k}}}" in r["path"]:
            return f"names {k}, which the path binds; it is never an argument"
    alts = s["sighted"]
    if not (isinstance(alts, list) and alts and all(isinstance(a, list) and a for a in alts)):
        return "sighted is a non-empty list of alternatives, each a non-empty list of requirements"
    for req in (x for a in alts for x in a):
        if not isinstance(req, str) or not _REQUIREMENT.match(req):
            return f"requires {req!r}, which is not privilege@path"
        for name in re.findall(r"\{([^{}]+)\}", req):
            if name not in r["params"] and f"{{{name}}}" not in r["path"]:
                return f"requires {req!r}, which names {{{name}}}, a name the address neither binds nor publishes"
    for k, least in (("what", 2), ("why", 4)):
        if not isinstance(s[k], str) or len(s[k].split()) < least:
            return f"is without a {k}; the sentence is the judgement"
        if s[k] != s[k].strip():
            return f"carries a {k} with space around it"
    return None
def consult_problem(name: Any, r: dict[str, Any], index: dict[tuple[str, str, str], dict[str, Any]]) -> str | None:
    """Why a consult (records/consult.toml) naming judge `name` on row `r` would do nothing or could
    not run; None when the engine can run it. The judge's reads are declared by the judge in code
    (`proximo.core.consult.JUDGES`), so the rule lives there and is asked here; the build refuses
    the record line, the loader refuses the file."""
    from proximo.core import consult  # consult imports this module; bound at call time, not import time

    return consult.problem(name, r, index)


def _is_create(r: dict[str, Any], index: dict[tuple[str, str, str], dict[str, Any]]) -> bool:
    """The build's `creates`: a judged create is a published, ungated, unexcluded POST whose GET
    (to read the record back) and DELETE (to put absence back) twins at the same path are served
    and callable with the path alone; UNDO sends them no arguments."""
    if r["method"] != "POST" or r["gate"] or r["excluded"]:      # access is the method's (checked first)
        return False
    for twin in ("GET", "DELETE"):
        t = index.get((r["product"], twin, r["path"]))
        if (t is None or t["excluded"] or t["gate"]
                or any(not v.get("optional") and f"{{{k}}}" not in t["path"] for k, v in t["params"].items())):
            return False
    return True


def rollback_net(r: dict[str, Any]) -> dict[str, str] | None:
    """The net a snapshot rollback on the API wire carries (records/undo.toml [net]), derived from
    the row's own address: the guest's own snapshot create, and this very rollback (a safety
    snapshot is put back by the vendor's rollback of it). None for any other address, so a record
    line cannot name a net the address does not support."""
    snap, _, name = r["path"].rpartition("/")[0].rpartition("/")
    if r["method"] != "POST" or not r["path"].endswith("/rollback") or name != "{snapname}" \
            or not snap.endswith("/snapshot"):
        return None
    return {"snapshot": f"POST {snap}", "rollback": f"POST {r['path']}"}


def _wrong_net(r: dict[str, Any], index: dict[tuple[str, str, str], dict[str, Any]]) -> str | None:
    """A net (the build's `refuse_bad_net`). On the ssh wire a boolean `snapshot` parameter and a
    net come together, and both addresses are ungated, unexcluded POSTs on the command's own
    container; on the API wire a net is exactly a rollback's own (`rollback_net`). Either way the
    snapshot publishes `snapname` without naming one, and the rollback names it."""
    net, snap = r["net"], r["params"].get("snapshot")
    ssh = r["wire"] == "ssh"
    if ssh and (net is None) != (snap is None):
        return "carries a snapshot parameter without a net, or a net without the parameter"
    if net is None:
        return None
    if ssh:
        if not isinstance(snap, dict) or snap.get("type") != "boolean":
            return "carries a net beside no boolean snapshot parameter on the ssh wire"
        own = r["path"].rpartition("/")[0] + "/"
    else:
        if net != rollback_net(r):
            return "carries a net that is not the snapshot and rollback of its own guest"
        own = r["path"].partition("/snapshot/")[0] + "/"
    for what, address in net.items():
        method, _, path = address.partition(" ")
        t = index[(r["product"], method, path)]        # present: the named-row check ran first
        if (t["excluded"] or t["gate"] or method != "POST" or not path.startswith(own)
                or (what == "snapshot" and ("snapname" not in t["params"] or "{snapname}" in path))
                or (what == "rollback" and "{snapname}" not in path)):
            return f"carries a net {what} that is not a mutation the door serves on its own container"
    return None


PRODUCTS = ("pve", "pbs", "pmg", "pdm")
SOURCES = {
    "pve": "https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js",
    "pbs": "https://pbs.proxmox.com/docs/api-viewer/apidoc.js",
    "pmg": "https://pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js",
    "pdm": "https://pdm.proxmox.com/docs/api-viewer/apidoc.js",
}
# Not REST reads or writes; dropped from every denominator and refused at the door.
EXCLUDED_PREFIXES: dict[str, tuple[str, ...]] = {
    "pve": (),
    "pbs": ("/backup/_upgrade_", "/reader/_upgrade_"),  # the backup/reader wire protocols
    "pmg": ("/config/whitelist",),  # deprecated alias of /config/welcomelist
    "pdm": (),
}
# Exact paths that are protocol roots, not reads: GET /backup and GET /reader are the HTTP/2
# upgrade handshakes of the two wire protocols above (pbs_admin.py names them the same way).
EXCLUDED_EXACT: dict[str, tuple[str, ...]] = {"pve": (), "pbs": ("/backup", "/reader"), "pmg": (), "pdm": ()}
EXCLUDED_TAILS = (  # console and migration tunnels: a ticket, then a websocket
    "vncproxy",
    "spiceproxy",
    "termproxy",
    "vncwebsocket",
    "mtunnel",
    "mtunnelwebsocket",
    "vncshell",
    "spiceshell",
)


def norm(path: str) -> str:
    """Query dropped, every `{...}` a bare `{}`, slashes collapsed, no trailing slash."""
    path = path.split("?")[0]
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return re.sub(r"/+", "/", path).rstrip("/") or "/"


def matches(lit: str, api_path: str) -> bool:
    """Segment-wise equality where a `{}` on either side matches any one segment."""
    a, b = lit.split("/"), api_path.split("/")
    return len(a) == len(b) and all(x == y or x == "{}" or y == "{}" for x, y in zip(a, b, strict=True))


def excluded(product: str, path: str) -> bool:
    return (
        path in EXCLUDED_EXACT[product]
        or path.startswith(EXCLUDED_PREFIXES[product])
        or path.rsplit("/", 1)[-1] in EXCLUDED_TAILS
    )


@cache
def raw_tree(product: str) -> tuple[tuple[str, str], ...]:
    """The vendor's `(path, method)` pairs exactly as published, placeholders named, in its order."""
    return tuple((p, m) for p, m, w in _rows(product) if w == "http")


@cache
def _rows(product: str) -> tuple[tuple[str, str, str], ...]:
    """Every row's `(path, method, wire)` on `product`: the vendor's first, the authored ssh rows
    after, so a match asks the vendor before an authored row can answer. By WIRE, not by the
    file's order: the build writes the ssh rows last, and a forged file that did not was answered
    by the ssh row first (lens 3 F8)."""
    rows = [(r["path"], r["method"], r["wire"]) for r in published()["rows"] if r["product"] == product]
    return tuple(sorted(rows, key=lambda t: t[2] != "http"))


@cache
def tree(product: str) -> frozenset[tuple[str, str]]:
    """Normalized operations, exclusions applied: the denominator and the door's whitelist."""
    return frozenset((norm(p), m) for p, m in raw_tree(product) if not excluded(product, norm(p)))


def find(product: str, path: str, method: str = "GET", wires: tuple[str, ...] = ("http",)) -> str | None:
    """The published path (placeholders named) that `path` reaches with `method`, else None. The
    vendor's rows by default; the engine asks both wires, the raw GET door (it dials HTTP) one."""
    want = norm(path)
    for raw, m, w in _rows(product):
        if m == method and w in wires and not excluded(product, norm(raw)) and matches(want, norm(raw)):
            return raw
    return None


def nearest(product: str, path: str, method: str = "GET", limit: int = 5) -> list[str]:
    """Published `method` paths sharing the longest leading segments with `path`, for a refusal
    that says where the reader could have gone instead of a bare no."""
    want = norm(path).split("/")
    scored: list[tuple[int, str]] = []
    for raw, m in raw_tree(product):
        if m != method or excluded(product, norm(raw)):
            continue
        have = norm(raw).split("/")
        common = 0
        for x, y in zip(want, have, strict=False):
            if x == y or x == "{}" or y == "{}":
                common += 1
            else:
                break
        if common > 1:
            scored.append((-common, raw))
    return [raw for _, raw in sorted(scored)[:limit]]
