"""DIAGNOSE: a subject's health reads through the engine, with advisory flags (parity row B3).

0.44 gathered evidence in three tools: a node's status, storage usage and the failures among
its last fifty tasks (`pve_diagnose`), a container's status plus an in-container shell battery
(`ct_diagnose`), and the node's API half plus a host shell battery (`pve_node_diagnose`). The
core had none of it. ONE RULE, like PLAN's read and UNDO's write: a diagnosis is a fixed battery
of the reads the vendor publishes about a subject, each run through `engine.execute`, so it is
receipted, withheld, tainted and bounded like any read, and the flags are 0.44's thresholds on
fields the vendor publishes. The battery is a record (`diagnose.toml`): a subject is a published
index address (`/nodes/{node}`, `/nodes/{node}/lxc/{vmid}`, `/nodes/{node}/qemu/{vmid}`), so a
concrete path resolves to it like any read and binds the probes' placeholders; a probe that
names an address the table does not publish as a GET, ungated or on an opt-in lane, refuses the
build (and the load re-checks), never silently serves two sections of three.

Nothing is composed from memory, and nothing incomplete is quiet. A probe the vendor fails or
the spine refuses is a section with the reason and a flag that says the diagnosis is
incomplete; the battery goes on, because a broken box is exactly when this runs. A probe the
door's cap cuts says how many rows it saw (a window is not a history: the failed-task count is
over the rows read, and the section names the window). A probe whose address is untrusted
keeps the label on its section and the whole answer; fenced, it is not read for flags and says
so. An empty flag list never reads as healthy when a read did not run. The answer is
`derived: true` (composed by the door, not the vendor's bytes), it names a half that is not
here (a VM's in-guest reads) or a lane that is closed, and its one ledger row is written AFTER
the battery with each section's outcome, never an ok stamped before the reads ran (0.44's own
lens finding on `pve_node_diagnose`).

THE SHELL BATTERIES ARE IN (2026-10-04): 0.44's five fixed in-container commands (B3, the
container shell lane, `GET .../lxc/{vmid}/probe`) and its seven host commands (the node shell
lane, `GET /nodes/{node}/probe`), each an authored read governed like any probe. A lane is opt-in
and never arm-gated (a broken box is diagnosed disarmed). A CLOSED LANE IS JUDGED ONCE, by
`engine.govern` (for a read, the lane is the whole verdict): its probes are named and not
attempted, the answer's `shell` carries the lane's own refusal, one flag says the diagnosis is
incomplete, and the ledger row holds the refusal (0.44's `probes_skipped`, "never healthy when the
battery never ran"). One line, not one per probe: seven refused sections put a lane-off node
diagnosis over the 4K door's read share. A command that does not exit clean, or whose stream the
wire cut, keeps its output and is not judged for flags.

Flags are signals, not a root cause: the sentence 0.44 carried is carried here, and the
thresholds are 0.44's (memory and storage over 90 percent, an inactive storage named rather
than called full, a guest not running, a guest's root disk over 90 percent, a task whose exit
text is neither OK nor a WARNINGS line). The task classifier is 0.44's rule in the core's words;
`tests/test_core_diagnose.py` drives both copies over the same real rows.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

from proximo.core import apitree, engine, rawdoor, shell, spine, wire
from proximo.core.errors import ProximoError
from proximo.core.secretfile import safe_exception_text, safe_text
from proximo.core.spine import wire_error

NOTE = ("DIAGNOSE gathers read-only evidence; flags are advisory signals (some heuristic), not a "
        "root-cause diagnosis. Verify before acting.")
FAILED_ROWS = 10          # failed task rows carried whole; the count survives the cut
_SHAPES = ("over", "off", "is", "failed", "lines")
_INCOMPLETE = "{name} read failed; diagnosis incomplete"


@dataclass(frozen=True)
class Probe:
    name: str
    path: str                       # the published template, the subject's placeholders inside
    keep: tuple[str, ...] | None    # a record: the fields the answer keeps
    rows: tuple[str, ...] | None    # a list: the fields each row keeps (the read's own projection)
    params: dict[str, Any]
    flags: tuple[dict[str, Any], ...]
    exits: int | None = None        # a command's probe: the exit code a complete read has


@dataclass(frozen=True)
class Subject:
    key: str                        # `plane:GET /path`, the table's spelling
    is_: str                        # what the subject is, in the operator's words
    shell: str | None               # the half that is not here, named; None when nothing is missing
    probes: Mapping[str, Probe]


def _check_flag(flag: Any, key: str, probe: str) -> None:
    where = f"diagnose.toml: flag on probe {probe} of {key}"
    if not isinstance(flag, dict) or not isinstance(flag.get("says"), str) or not flag["says"]:
        raise ProximoError(f"{where} has no `says` sentence")
    shapes = [s for s in _SHAPES if s in flag]
    if len(shapes) != 1:
        raise ProximoError(f"{where} must have exactly one shape of {', '.join(_SHAPES)}, has {shapes or 'none'}")
    if "over" in flag and not (isinstance(flag["over"], list) and len(flag["over"]) == 2
                               and all(isinstance(f, str) for f in flag["over"])
                               and isinstance(flag.get("at"), (int, float))):
        raise ProximoError(f"{where}: `over` takes [used, total] and a numeric `at`")
    if "is" in flag and "expect" not in flag:
        raise ProximoError(f"{where}: `is` takes an `expect` value")
    try:                                   # a sentence that cannot render would abort a battery at run (lens 1)
        flag["says"].format_map(_Words())
    except Exception as exc:  # noqa: BLE001 -- `{a.b}` is an AttributeError, `{a[x]}` a TypeError: any is a refusal
        raise ProximoError(f"{where}: `says` does not render ({safe_exception_text(exc)})") from exc


@cache
def subjects() -> Mapping[str, Subject]:
    """The battery from the one JSON, checked against the table (`compile`, the same check the
    build ran on `records/diagnose.toml`), in the record's own order."""
    return compile(apitree.published()["diagnose"], {r.key: r for r in engine.table().values()})


def compile(section: list[dict[str, Any]], live: Mapping[str, Any]) -> Mapping[str, Subject]:
    """The record, checked against the table: every subject and every probe is a published GET,
    ungated or on an opt-in lane (the row's `lane`, the rows `govern` serves when the operator
    opts in), or the build refuses (tiers.toml's rule: an authored line that matches nothing is a
    lie the file tells its reader). A lane that is off is judged at run, as a refused section.
    `section` is the one JSON's `diagnose` list (a subject per entry, its probes a list, so the
    authored order rides through sorted keys); `live` is the table keyed by `Row.key`. Pure, so
    the build refuses a bad record before it ships and the load refuses a damaged file."""
    out: dict[str, Subject] = {}
    inert: list[str] = []
    for spec in section:
        key = spec["key"]
        plane, _, _address = key.partition(":")
        if key not in live or live[key].method != "GET" or live[key].gate or live[key].excluded:
            inert.append(key)
        if not isinstance(spec.get("is"), str) or not isinstance(spec.get("shell", ""), str):
            raise ProximoError(f"diagnose.toml: subject {key} must say what it `is`; `shell`, if given, "
                               f"is a sentence")
        probes: dict[str, Probe] = {}
        own = set(engine.placeholders(_address.split(" ", 1)[1])) if " " in _address else set()
        for p in spec.get("probe") or []:
            name = p["name"]
            if not isinstance(p.get("path"), str) or not p["path"]:
                raise ProximoError(f"diagnose.toml: probe {name} of {key} names no path")
            pkey = f"{plane}:GET {p['path']}"
            row = live.get(pkey)
            if (row is None or (row.gate and row.lane is None) or row.excluded
                    or row.access != engine.READ):
                inert.append(pkey)
            # A PROBE IS BOUND FROM THE SUBJECT'S PATH AND NOTHING ELSE: a placeholder the subject
            # does not carry would go to the wire as a literal `{storage}`, so it refuses at load;
            # a parameter the probe does not publish would be refused by `check_args` at every
            # run, a line that can never do what it says.
            extra = set(engine.placeholders(p["path"])) - own
            if extra:
                raise ProximoError(f"diagnose.toml: probe {name} of {key} names placeholders the subject cannot "
                                   f"bind: {', '.join(sorted(extra))}")
            if row is not None:
                unpublished = sorted(k for k in (p.get("params") or {}) if not engine._published(row, k))
                if unpublished:
                    raise ProximoError(f"diagnose.toml: probe {name} of {key} sends parameters {pkey} does not "
                                       f"publish: {', '.join(unpublished)}")
            if ("keep" in p) == ("rows" in p):
                raise ProximoError(f"diagnose.toml: probe {name} of {key} must say `keep` (a record) "
                                   f"or `rows` (a list)")
            flags = tuple(p.get("flag") or ())
            for f in flags:
                _check_flag(f, key, name)
            exits = p.get("exits")
            if exits is not None and (isinstance(exits, bool) or not isinstance(exits, int) or "keep" not in p
                                      or "returncode" not in p["keep"]):
                raise ProximoError(f"diagnose.toml: probe {name} of {key}: `exits` is a whole number, on a record "
                                   f"probe that keeps `returncode`")
            probes[name] = Probe(name, p["path"], tuple(p["keep"]) if "keep" in p else None,
                                 tuple(p["rows"]) if "rows" in p else None, dict(p.get("params") or {}), flags,
                                 exits)
        out[key] = Subject(key, spec["is"], spec.get("shell"), probes)
    if inert:
        raise ProximoError(
            f"diagnose.toml names {len(inert)} key(s) that match no published ungated GET: "
            f"{', '.join(inert[:5])}{' ...' if len(inert) > 5 else ''}. "
            f"Check the placeholder spelling against the table (the vendor says {{node}}, not {{n}}).")
    return out


def task_outcome(row: Any) -> str:
    """0.44's `classify_task_outcome`, the rule in the core's words: string matching on the two
    fields every plane's task row carries, never inference. No `endtime` is running; a finished
    row's `status` is the exit text, `OK`, a `WARNINGS: n` line, or the failure's own message;
    a statusless finished row is unknown, never a healthy-looking class."""
    if not isinstance(row, dict):
        return "unknown"
    if "endtime" not in row:
        return "running"
    status = row.get("status")
    if status is None or str(status) == "":
        return "unknown"
    s = str(status)
    if s == "OK":
        return "ok"
    if s.startswith("WARNINGS: "):
        return "warnings"
    return "failed"


def run(plane: str, path: str, *, cfg: wire.Plane | None = None, ledger_cfg: Any = None) -> dict[str, Any]:
    """The battery for the subject at `path`, each probe a governed read, the flags, one row.

    `cfg` is the plane's connection when a door holds one; else the env box, and an unconfigured
    box raises the doors' own RuntimeError (there is no battery to run without a credential).
    """
    row = engine.resolve(plane, "GET", path)
    if "{" in path:
        raise ProximoError(f"a template path names no subject to diagnose; give the concrete path, not {path}")
    subs = subjects()
    sub = subs.get(row.key)
    if sub is None:
        mine = sorted(k.split(" ", 1)[1] for k in subs if k.startswith(plane + ":"))
        raise ProximoError(f"no diagnosis is authored for GET {path} ({row.address}); subjects on {plane}: "
                           f"{', '.join(mine) or 'none'}")
    plane_cfg = cfg if cfg is not None else wire.Plane.from_env(plane)
    bound = engine.bind(row, path)
    called = rawdoor.canonical(path)
    battery: dict[str, dict[str, Any]] = {}
    sections: dict[str, str] = {}
    flags: list[str] = []
    untrusted = False
    closed = _closed_lanes(plane, sub, bound, plane_cfg, ledger_cfg)
    for name, probe in sub.probes.items():
        lane = _lane_of(plane, probe)
        if lane in closed:
            closed[lane]["probes"].append(name)
            continue
        section, outcome, found = _section(plane, probe, bound, plane_cfg, ledger_cfg)
        battery[name], sections[name] = section, outcome
        flags.extend(found)
        untrusted = untrusted or bool(section.get("untrusted"))
    # A CLOSED LANE IS ONE LINE, NOT ONE PER PROBE. Seven refused sections, each carrying the
    # lane's sentence, put a lane-off node diagnosis at 1,205 tokens against the 4K door's 900.
    # The lane is judged once (by govern, the function execute asks), its probes are named and
    # not attempted, and the diagnosis says it is incomplete: 0.44's `probes_skipped`.
    skipped = {lane: c for lane, c in closed.items() if c["probes"]}
    flags.extend(f"{len(c['probes'])} {lane} probe(s) not run (see shell); diagnosis incomplete"
                 for lane, c in skipped.items())
    shell = ({"skipped": "; ".join(c["reason"] for c in skipped.values()),
              "probes": [n for c in skipped.values() for n in c["probes"]]} if skipped
             else {"skipped": sub.shell} if sub.shell else None)
    flags = _grouped(flags)
    incomplete = any(v != "ok" for v in sections.values()) or bool(skipped)
    answer: dict[str, Any] = {
        "address": row.address, "plane": plane, "access": engine.READ,
        "derived": True,           # composed by the door from governed reads, not the vendor's bytes
        "matched_path": row.path, "called_path": rawdoor.echo(called, 160), "subject": sub.is_,
        "battery": battery, "flags": flags, "incomplete": incomplete,
        **({"shell": shell} if shell else {}), "note": NOTE,
        **({"untrusted": True} if untrusted else {}),
    }
    # THE ROW AFTER THE BATTERY, with every section's outcome: the ledger holds what the reads
    # found, never an "ok" stamped before they ran.
    engine._record(ledger_cfg, "core.diagnose", row, outcome="incomplete" if incomplete else "ok",
                   detail={"sections": sections, "flags": len(flags), **({"untrusted": True} if untrusted else {}),
                           **({"skipped": skipped} if skipped else {})},
                   called=called, remote=plane_cfg.name)
    # WHAT THE MODEL SEES IS CAPPED, whatever the reads were allowed: a node with 80 storages and a
    # busy task list answered 12 KB. The sections trim one by one (their verdicts, errors and the
    # flags stay), each trimmed part named, with a `next` to ask for it by its own address.
    cap = rawdoor.composed_cap()
    body = json.dumps(answer, separators=(",", ":"), default=str)
    if not rawdoor.fits(len(body.encode()), body, cap=cap):
        answer = {**answer, "battery": _same_channels(battery)}
    return rawdoor.fit_answer(answer, descend=("battery",), cap=cap, next_text=(
        "cut for size (see trimmed), not a failed probe; read a cut part by its own address"))


def _same_channels(battery: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Seven host probes carry one `channel` sentence seven times. The label (`untrusted: true`) stays
    on every section; a repeat of the sentence says which section already carries it. Only when over the cap."""
    first: dict[str, str] = {}
    out = {}
    for name, section in battery.items():
        ch = section.get("channel")
        if isinstance(ch, str) and ch in first:
            section = {**section, "channel": f"same as {first[ch]}"}
        elif isinstance(ch, str):
            first[ch] = name
        out[name] = section
    return out


#: a flag shape repeated this many times becomes one line (36 offline storages are one finding)
GROUP_FLAGS_AT = 6


def _grouped(flags: list[str]) -> list[str]:
    """Flags of one shape ("storage nfs-0 is inactive (offline); usage not evaluated", thirty-six of
    them) as ONE line that keeps the verdict, names the first three and counts the rest, and every
    flag's text bounded: a flag is a sentence, not a place to echo a vendor's paragraph."""
    by_shape: dict[tuple[str, str], list[str]] = {}
    for flag in flags:
        m = re.match(r"^(\w+) (\S+) (.+)$", flag, re.ASCII)
        if m:
            by_shape.setdefault((m.group(1), m.group(3)), []).append(m.group(2))
    out, said = [], set()
    for flag in flags:
        m = re.match(r"^(\w+) (\S+) (.+)$", flag, re.ASCII)
        key = (m.group(1), m.group(3)) if m else None
        if key is None or len(by_shape[key]) < GROUP_FLAGS_AT:
            out.append(rawdoor.echo(flag, 200))
        elif key not in said:
            said.add(key)
            names = by_shape[key]
            verdict = re.sub(r"^is ", "are ", key[1])
            shown = ', '.join(names[:3])
            out.append(rawdoor.echo(f"{len(names)} {key[0]}s {verdict}: {shown} and {len(names) - 3} more", 200))
    return out


def _concrete(probe: Probe, bound: dict[str, str]) -> str:
    out = probe.path
    for k, v in bound.items():
        out = out.replace("{" + k + "}", v)
    return out


def _lane_of(plane: str, probe: Probe) -> str | None:
    return engine.resolve(plane, "GET", probe.path).lane


def _closed_lanes(plane: str, sub: Subject, bound: dict[str, str], plane_cfg: wire.Plane,
                  ledger_cfg: Any) -> dict[str, dict[str, Any]]:
    """Each opt-in lane the subject's probes ride, judged ONCE, and the ones whose probes would all
    be refused, with the refusal's own words: govern's (for a read the lane is the whole verdict,
    and a path the lane cannot address raises there), then, for a shell lane, the wire's own
    build (`shell.client`: a registered target, no ssh target). Every probe of a lane shares one
    template, so one judgement holds for all of them. Lanes that are open are absent: their probes
    run through execute like any other."""
    closed: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for probe in sub.probes.values():
        lane = _lane_of(plane, probe)
        if lane is None or lane in seen:
            continue
        seen.add(lane)
        prow = engine.resolve(plane, "GET", probe.path)
        try:
            verdict = engine.govern(prow, cfg=plane_cfg, path=_concrete(probe, bound), args=dict(probe.params),
                                    ledger_cfg=ledger_cfg)
            if not verdict.allowed and verdict.needs == lane:
                closed[lane] = {"reason": verdict.reason, "probes": []}
            elif prow.wire == "ssh":
                shell.client(plane_cfg)            # the build that would refuse each probe, asked once
                if not shell.dialable(_concrete(probe, bound)):
                    raise ProximoError(f"{_concrete(probe, bound)} is not an address the shell wire can dial")
        except ProximoError as exc:                # a decoded `/` in the node, a registered target, no target
            closed[lane] = {"reason": safe_text(str(exc)), "probes": []}   # bounded, redacted, no class prefix
    return closed


def _section(plane: str, probe: Probe, bound: dict[str, str], plane_cfg: wire.Plane,
             ledger_cfg: Any) -> tuple[dict[str, Any], str, list[str]]:
    """One probe: the section, its outcome (ok / error / fenced) and the flags it raised."""
    name = probe.name
    concrete = _concrete(probe, bound)
    prow = engine.resolve(plane, "GET", probe.path)
    section: dict[str, Any] = {"address": prow.address}
    # THE LABEL BEFORE THE READ. An untrusted address is untrusted whether its read answers
    # or refuses: a refusal's text can carry the rows' own keys (the projection names what
    # the rows carry), and a section that lost the label handed those bytes to the model as
    # the door's words (lens 1).
    if prow.untrusted:
        section.update(untrusted=True, channel=prow.channel)
    wanted = probe.rows                    # a local, so its narrowing holds for the checker
    projected = wanted is not None
    try:
        try:
            env = engine.execute(prow, dict(probe.params), cfg=plane_cfg, path=concrete, ledger_cfg=ledger_cfg,
                                 fields=",".join(wanted) if wanted is not None else "all", evaluating=True)
        except ProximoError as exc:
            # THE PROJECTION'S OWN REFUSAL IS NOT A FAILED READ. `fields=` refuses when no
            # row carries a named field: no rows, none finished, every storage offline. The
            # read answered; it is taken again raw (receipted again) and projected here, so an
            # all-offline node gets its inactive sentences, not "read failed" (lens 1).
            if not (projected and str(exc).startswith("fields:")):
                raise
            env = engine.execute(prow, dict(probe.params), cfg=plane_cfg, path=concrete, ledger_cfg=ledger_cfg,
                                 fields="all", evaluating=True)
            projected = False
    except ProximoError as exc:            # refused by the spine, receipted by execute
        section["error"] = {"why": _words(prow, str(exc))}
        return section, "error", [_INCOMPLETE.format(name=name)]
    except Exception as exc:               # the vendor failed or is unreachable, receipted by execute
        err = wire_error(exc)
        section["error"] = {"why": f"the vendor did not complete the read: {err['error']}", **err}
        return section, "error", [_INCOMPLETE.format(name=name)]
    if "data" not in env:                  # cut by the size law: a record that does not fit
        section["error"] = {"why": f"the record is over the door's cap ({env.get('bytes')} bytes against "
                                   f"{env.get('cap')}); not evaluated"}
        return section, "error", [_INCOMPLETE.format(name=name)]
    data = env["data"]
    if isinstance(data, dict) and "proximo_untrusted" in data:
        section["fenced"] = True
        return section, "fenced", [f"{name} is attacker-authored and fenced; not evaluated, diagnosis incomplete"]
    if wanted is not None:
        # A BODY THAT IS NOT A LIST IS NOT AN EMPTY WINDOW. A dict, a string or a number where the
        # battery expects rows read as `seen 0`, no flags, a healthy row (lens 3): the mirror of the
        # record probes' guard below, which refuses a list where a record is expected.
        if not isinstance(data, list):
            section["error"] = {"why": f"the read answered {_shape(data)}, not the list the battery expects"}
            return section, "error", [_INCOMPLETE.format(name=name)]
        rows = [r for r in data if isinstance(r, dict)]
        if not projected:
            rows = [{k: r[k] for k in wanted if k in r} for r in rows]
        # A ROW THAT CARRIES NONE OF THE FIELDS THE BATTERY READS IS NOT A ROW IT CAN JUDGE. The
        # raw re-read handed `{}` for such a row and an empty task row read as running, two
        # unreadable rows as a healthy "2 running" (lens 2). A schema the battery does not
        # know, or a body that is not the vendor's, is an unevaluated section, never a count.
        blank = sum(1 for r in rows if not r) + (len(data) - len(rows))
        if blank:
            total = len(data)
            section["error"] = {"why": f"{blank} of {total} rows carry none of the fields the battery reads "
                                       f"({', '.join(wanted)}); not evaluated"}
            return section, "error", [_INCOMPLETE.format(name=name)]
        for k in ("total", "returned", "truncated"):
            if k in env:
                section[k] = env[k]
        if env.get("truncated"):
            section["window"] = f"{len(rows)} of the {env.get('total')} most recent, cut by the door's cap"
        if any("failed" in f for f in probe.flags):
            section.update(_tasks(rows, probe))
        else:
            section["rows"] = rows
        found = _contained(probe, rows, len(rows))
    else:
        if not isinstance(data, dict):
            section["error"] = {"why": f"the read answered {_shape(data)}, not the record the battery expects"}
            return section, "error", [_INCOMPLETE.format(name=name)]
        section.update({k: data[k] for k in probe.keep or () if k in data})   # the loader: keep XOR rows
        if (why := _unjudgeable(probe, data)) is not None:
            section["error"] = {"why": why}            # the read answered: it is not "read failed"
            return section, "error", [f"{name} not evaluated; diagnosis incomplete"]
        found = _contained(probe, [data])
    if found is None:                      # the flags could not be judged: say so, keep the section
        section["error"] = {"why": f"the flags of {name} could not be evaluated from the vendor's values"}
        return section, "error", [f"{name} flags not evaluated; diagnosis incomplete"]
    return section, "ok", found


def _unjudgeable(probe: Probe, data: dict) -> str | None:
    """Why a command's record is kept but not judged, or None. A COMMAND THAT DID NOT EXIT CLEAN
    IS NOT A CLEAN READ: a `systemctl` that cannot reach systemd prints an error, not a failed
    unit. A WINDOW IS NOT A HISTORY: a stream the wire cut is a prefix, and 240 failed units read
    as "51", a cut journal as the whole of it (lens 5)."""
    rc = data.get("returncode")
    if probe.exits is not None and rc != probe.exits:
        said = ("the command is not installed here (exit 127)" if rc == 127
                else f"{probe.name} exited {rc}, not {probe.exits}")
        return f"{said}; not evaluated"
    if data.get("truncated"):
        cut = ", ".join(f"{k} was {v} characters" for k, v in sorted(data["truncated"].items()))
        return f"cut by the door's cap ({cut}); the section holds a prefix, not evaluated"
    return None


def _shape(data: Any) -> str:
    """What a body is, in words: a list, a record, a string, a number, a boolean, nothing."""
    if data is None:
        return "nothing"
    if isinstance(data, bool):
        return "a boolean"
    if isinstance(data, (int, float)):
        return "a number"
    return {list: "a list", dict: "a record", str: "a string"}.get(type(data), f"a {type(data).__name__}")


def _words(row: engine.Row, text: str) -> Any:
    """A refusal's text for the answer: the door's own words for a trusted address; for an
    untrusted one, fenced when the fence is on (the text can quote the rows), labelled otherwise."""
    if row.untrusted and spine.fence_on():
        return spine.fence(row.key, text)
    return text


def _contained(probe: Probe, records: list[dict], seen: int | None = None) -> list[str] | None:
    """The flags, or None when their evaluation raised. 0.44 contained each section in its own
    except; a vendor integer too large for a float, or a finite fraction whose percentage is not,
    raised out of the battery after its receipts and before its row (lens 1). Nothing a vendor
    value can do ends the battery or loses the row."""
    try:
        return _flags(probe, records, seen=seen)
    except Exception:  # noqa: BLE001 -- the vendor's values are not ours (an overflow too); the section says so
        return None


def _tasks(rows: list[dict], probe: Probe) -> dict[str, Any]:
    """The task window: what was asked, what was seen, the outcomes, the failed rows (bounded,
    the count whole). The rows themselves are not carried: fifty task rows are the 4K door's
    whole budget, and the diagnosis is the failures."""
    outcomes = Counter(task_outcome(r) for r in rows)
    failed = [r for r in rows if task_outcome(r) == "failed"]
    return {"asked": probe.params.get("limit"), "seen": len(rows), "by_outcome": dict(outcomes),
            "failed": failed[:FAILED_ROWS], "failed_total": len(failed)}


def _get(record: dict, dotted: str) -> Any:
    cur: Any = record
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _frac(used: Any, total: Any) -> float | None:
    try:
        if total:
            f = float(used or 0) / float(total)
            return f if math.isfinite(f) else None
    except (TypeError, ValueError, ZeroDivisionError):
        # Not a number, or nothing to divide by: not a measurement (0.44's rule). An OverflowError
        # (an integer too large for a float) is a number the arithmetic cannot judge: it rises to
        # `_contained`, and the section says its flags were not evaluated (lens 2).
        return None
    return None


def _ratio(record: dict, flag: dict) -> float | None:
    if "fraction" in flag and record.get(flag["fraction"]) is not None:
        try:
            f = float(record[flag["fraction"]])
            return f if math.isfinite(f) else None
        except (TypeError, ValueError):
            return None
    used, total = flag["over"]
    return _frac(_get(record, used), _get(record, total))


class _Words(dict):
    """A sentence's words; a name no record carries renders as 0, so a legal numeric spec
    (`{pct:d}`) renders at load and an attribute or index on a value (`{a.b}`, `{a[x]}`) does not."""

    def __missing__(self, key: str) -> int:
        return 0


def _say(flag: dict, record: dict, **words: Any) -> str:
    plain = {k: v for k, v in record.items() if isinstance(v, (str, int, float, bool)) or v is None}
    return flag["says"].format_map(_Words({**plain, **words}))


def _flags(probe: Probe, records: list[dict], seen: int | None = None) -> list[str]:
    """0.44's thresholds, per record: `off` names the row and ends its evaluation (an offline
    storage's cached usage is stale, not full); `over` compares a ratio; `is` compares a state,
    silent when the field is absent (0.44: `if status and status != "running"`); `failed`
    counts the task rows whose exit text is a failure; `lines` counts a text field's non-blank
    lines (0.44's failed-units rule: `systemctl --failed --no-legend` prints nothing when clean)."""
    out: list[str] = []
    for flag in probe.flags:
        if "failed" in flag:
            n = sum(1 for r in records if task_outcome(r) == "failed")
            if n:
                out.append(_say(flag, {}, n=n, seen=seen if seen is not None else len(records)))
    for r in records:
        for flag in probe.flags:
            if "off" in flag:
                v = r.get(flag["off"])
                if v is not None and str(v) in ("0", "False"):
                    out.append(_say(flag, r))
                    break
            elif "over" in flag:
                f = _ratio(r, flag)
                if f is not None and f > flag["at"]:
                    pct = round(100 * f) if math.isfinite(100 * f) else "over 100"
                    out.append(_say(flag, r, pct=pct))
            elif "is" in flag:
                v = r.get(flag["is"])
                if v not in (None, "") and v != flag["expect"]:
                    out.append(_say(flag, r, value=v))
            elif "lines" in flag:
                v = r.get(flag["lines"])
                n = sum(1 for line in v.splitlines() if line.strip()) if isinstance(v, str) else 0
                if n:
                    out.append(_say(flag, {}, n=n))
    return out
