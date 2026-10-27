#!/usr/bin/env python3
"""The gate round: neuter each core gate, one at a time, and let the CORE-ONLY tests catch it.

Parity row B13 asked for a core-only test that goes red for every gate; this is the harness that
proves it, run 2026-10-16 on the tree it ships with. A gate is a line in `engine.py` or
`ledger.py` where the spine refuses, spends or records; each mutation below turns one of them
off (an `if False:`, a `None` in the refusal tuple, a dropped record) and the core-only tests
(the files under tests/ that import nothing of 0.44, listed in CORE) run with `-x`. KILLED means
a test went red; SURVIVED means the neutered gate passed every core-only test and the gate is a
decoration until a test drives it. The round stops if a restore does not hash back.

Bytes, never git: each file is copied aside and restored by `cp` and a sha256 compare, so a run
that dies mid-mutation is put back by hand from the `.bak` beside the log, and the working tree
is never asked to `checkout` anything (that eats uncommitted work).

    uv run python scripts/gate_mutations.py [--out DIR] [NAME ...]

`tests/test_gate_mutations_inventory.py` holds every target string to exactly one site, so a
refactor that moves a gate turns that test red instead of this round printing SKIP.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
E = "src/proximo/core/engine.py"
L = "src/proximo/core/ledger.py"
SP = "src/proximo/core/spine.py"
AT = "src/proximo/core/apitree.py"
SI = "src/proximo/core/sight.py"
C = "src/proximo/core/consult.py"

#: (name, file, the gate as written, the gate neutered)
M = [
    ('M01-ARM', E,
     '    if not state.armed:\n        return Verdict(',
     '    if False:\n        return Verdict('),
    ('M02-TIER', E,
     '    if not isinstance(row.tier, str) or row.tier not in TIERS:',
     '    if False:'),
    ('M03-GATED', E,
     '            return Verdict(False, f"{row.address} is gated: {row.gate}", None)',
     '            pass'),
    ('M04-HELD', E,
     '    if row.held:\n',
     '    if False:\n'),
    ('M05-CROSSPLANE', E,
     '    if cfg is not None and getattr(cfg, "product", row.product) != row.product:',
     '    if False:'),
    ('M06-CONTAIN', E,
     '        spine.contain_refusal(),\n',
     '        None,\n'),
    ('M07-RETIRED', E,
     '        spine.retired_refusal(),\n',
     '        None,\n'),
    ('M08-FORBID', E,
     '        spine.forbid_refusal(row.product, row.method, called, args,\n                            '
     ' extra=cfg.forbid if cfg is not None else ()),',
     '        None,'),
    ('M09-TAINT-FORBID', E,
     '        spine.taint_refusal(audit_dir, row.product, row.method, called, args),',
     '        None,'),
    ('M10-TAINT-CONSENT', E,
     '        None if consent_covered else spine.taint_consent_refusal(audit_dir),',
     '        None,'),
    ('M11-CONSENT-CHECK', E,
     '        None if consent_covered else spine.consent_refusal(cid, audit_dir or "."),',
     '        None,'),
    ('M12-CONSENT-SPEND', E,
     '    refusal = spent if isinstance(spent, spine.Refusal) else None',
     '    refusal = None'),
    ('M13-RATE', E,
     '        refusal = spine.reserve_rate(base_url, audit_dir, cap=_rate_cap(cfg), count=count, stamp=stamp)',
     '        refusal = None'),
    ('M56-RATE-TWO-SLOTS', E,
     '    return 2 if view is not None and view.get("take") and view.get("snap") else 1',
     '    return 1'),
    ('M57-RATE-PREPAID', E,
     '    if refusal is None and not rate_prepaid:',
     '    if refusal is None:'),
    ('M14-TAINT-MARK', E,
     '    if judging or not (row.untrusted and spine.taint_tracking_on()):\n        return',
     '    if True:\n        return'),
    ('M55-JUDGING-READ-MARKS', E,
     '    if judging or not (row.untrusted and spine.taint_tracking_on()):\n        return',
     '    if not (row.untrusted and spine.taint_tracking_on()):\n        return'),
    ('M15-PROVE-CHAIN', L,
     '        if entry.get("prev_hash") != prev:\n            return LedgerVerification(False, count, lineno,\n'
     '                                      "prev_hash mismatch (entry inserted, removed, or reordered)")',
     '        if False:\n            return LedgerVerification(False, count, lineno,\n'
     '                                      "prev_hash mismatch (entry inserted, removed, or reordered)")'),
    ('M32-PROVE-CHAIN-ARCHIVE', L,
     '        if entry.get("prev_hash") != prev:\n            return LedgerVerification(False, count, lineno,\n'
     '                                      "prev_hash mismatch (entry inserted, removed, or reordered)",',
     '        if False:\n            return LedgerVerification(False, count, lineno,\n'
     '                                      "prev_hash mismatch (entry inserted, removed, or reordered)",'),
    ('M24-PROVE-KEYED', L,
     '            if entry_alg != _KEY_ALG:',
     '            if False:'),
    ('M25-PROVE-HASH', L,
     '        if not hmac.compare_digest(expected, found_hash):',
     '        if False:'),
    ('M26-PROVE-HEAD', L,
     '    if expected_head is not None and prev != expected_head:',
     '    if False:'),
    ('M16-WITHHOLD', E,
     '    if rule == _NO_RULE:\n        return data, []',
     '    if True:\n        return data, []'),
    ('M17-PLACEHOLDERS', E,
     '    if placeholders(called):\n        raise ProximoError(',
     '    if False:\n        raise ProximoError('),
    ('M18-CHECK-ARGS', E,
     '        check_args(row, args)\n    except ProximoError as exc:',
     '        pass\n    except ProximoError as exc:'),
    ('M19-UNDO-BEFORE', E,
     '        undo = _undo_before(row, args, client, called, cfg, ledger_cfg, intent, remote, verdict.cons'
     'ent_id, view,\n                            net_of is not None, before)',
     '        undo = {"state": "off"}'),
    ('M20-EXECUTING-ROW', E,
     '    _record(ledger_cfg, "core.execute", row, outcome=EXECUTING, detail=preview, called=called,\n '
     '           required=True, remote=remote)',
     '    pass'),
    ('M21-REFUSE-RECEIPT', E,
     '        _record(ledger_cfg, "core.refuse", row, outcome="refused",\n                detail={"reas'
     'on": verdict.reason, "needs": verdict.needs, **verdict.detail, **proposed},\n                called=rawdoor.c'
     'anonical(path) if path else None, remote=remote)\n        raise ProximoError(verdict.reason)',
     '        raise ProximoError(verdict.reason)'),
    ('M22-SPELLING', E,
     '    if path is not None:\n        rawdoor.reject_malformed(path, allow_placeholders=True)',
     '    if False:\n        rawdoor.reject_malformed(path, allow_placeholders=True)'),
    ('M23-EXCLUDED', E,
     '    if row.excluded:\n',
     '    if False:\n'),
    ('M27-CONSENT-OWNER', SP,
     '    if st.st_uid == _euid():\n',
     '    if False:\n'),
    ('M28-CONSENT-ONCE', SP,
     '                     os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)',
     '                     os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)'),
    ('M29-CONSENT-RECEIPT', E,
     '                    called=called, required=True, remote=remote)\n        except BaseException:',
     '                    called=called, required=False, remote=remote)\n        except BaseException:'),
    ('M30-CONSENT-UNSPEND', E,
     '            spine.unspend(spent)\n',
     '            pass\n'),
    ('M31-CONSENT-RETIRE-JUDGED', SP,
     '        if (st.st_ino, st.st_mtime_ns) == (spend.inode, spend.mtime_ns):\n',
     '        if True:\n'),
    ('M34-CONSENT-SAME-USER-OPT-IN', SP,
     '        if os.environ.get(SAME_USER_ENV) != "advisory":\n',
     '        if False:\n'),
    ('M35-CONSENT-ADVISORY-RECEIPT', SP,
     'advisory=state == "advisory")',
     'advisory=False)'),
    ('M36-CONSENT-SAME-USER-VALUE', SP,
     '    if not _env_set_nonempty(SAME_USER_ENV) or value == "advisory":   # blank is unset: inert\n',
     '    if True:\n'),
    ('M33-CONSENT-ONE-STAT', SP,
     '    try:\n        os.makedirs(os.path.join(spent_dir, SPENT_DIR)',
     '    try:\n        st = os.lstat(grant_path(cid) or "")\n        os.makedirs(os.path.join(spent_dir, SPENT_DIR)'),
    # PLAN's notes (notes.toml, #100): the plan shows them, the receipt keeps them, the loader holds them
    ('M37-NOTE-PLAN', E,
     '    if held := notes_held(row, args):\n        out["notes"] = held',
     '    if False:\n        out["notes"] = held'),
    ('M38-NOTE-RECEIPT', E,
     '               **({"notes": [n["says"] for n in held]} if held else {}),\n',
     ''),
    ('M39-NOTE-NOT-GIVEN', E,
     '                and not any(_given(row, k, args) is True for k in n["not_given"]))]',
     '                and True)]'),
    ('M40-NOTE-GIVEN', E,
     'or (not any(_given(row, k, args) is False for k in n["given"])',
     'or (True'),
    ('M41-NOTE-BOOL-WORD', E,
     '    return True if lowered in TRUE_WORDS else False if lowered in FALSE_WORDS else None',
     '    return True if lowered in TRUE_WORDS else None'),
    ('M43-NOTE-BOOLEAN-KIND', E,
     '        return not (isinstance(value, str) and not value.strip())    # a value is given unless blank',
     '        return None'),
    ('M44-NOTE-STRIP', E,
     '    lowered = value.strip().lower()\n    return True if',
     '    lowered = value.lower()\n    return True if'),
    ('M45-NOTE-EACH-GIVEN', E,
     'or (not any(_given(row, k, args) is False for k in n["given"])',
     'or (not all(_given(row, k, args) is False for k in n["given"])'),
    ('M54-NOTE-ALWAYS', E,
     '            if n.get("always") is True\n',
     '            if False\n'),
    ('M42-NOTE-LOADER', AT,
     '    if wrong := notes_problem(r["notes"], r):\n',
     '    if wrong := None:\n'),
    # TOKEN SIGHT (sight.toml): an empty list the token could not see is refused, never served as none
    ('M46-SIGHT-JUDGES-EMPTY', E,
     'seen = _sight(row, called, args, client, ledger_cfg, remote, data) if row.sight else {}',
     'seen = {}'),
    ('M47-SIGHT-UNKNOWN-REFUSED', E,
     '    if empty:\n        _record(ledger_cfg, "core.refuse", row, outcome="refused",\n'
     '                detail={"reason": said, "needs": "sight"',
     '    if False:\n        _record(ledger_cfg, "core.refuse", row, outcome="refused",\n'
     '                detail={"reason": said, "needs": "sight"'),
    ('M48-SIGHT-HELD-OR-BLIND', SI,
     '        if all(_held(flags, priv, path) for priv, path in alt):\n',
     '        if True:\n'),
    ('M49-SIGHT-UNREADABLE-IS-UNKNOWN', SI,
     '    if flags is None:\n        if empty:\n',
     '    if False:\n        if empty:\n'),
    ('M51-SIGHT-PREFIX-SEPARATOR', SI,
     'path.startswith(p + "/")',
     'path.startswith(p)'),
    ('M52-SIGHT-NONE-IS-NO-GRANT', SI,
     '            if propagate is None:                           # None is no grant\n                continue\n',
     ''),
    ('M53-SIGHT-PARTIAL-MARK', E,
     '    mark = "partial" if state == sight.BLIND else "unverified"\n',
     '    return {}\n'),
    ('M50-SIGHT-LOADER', AT,
     '    if r["sight"] is not None and (wrong := sight_problem(r["sight"], r, index)):\n',
     '    if False:\n'),
    # CONSULT (records/consult.toml): the budget, the worst case on an incomplete read, the one seam
    # for its reads, the section on the EXECUTING receipt, and the loader's rule.
    ('M60-CONSULT-BUDGET', C,
     '        if self.reads >= MAX_READS:\n',
     '        if False:\n'),
    ('M61-CONSULT-WORST', C,
     'raise_to=finding.raise_to if complete else worse(finding.raise_to, worst),',
     'raise_to=finding.raise_to,'),
    ('M62-CONSULT-SEAM', C,
     '            env = engine.execute(engine.table()[(self.row.product, "GET", template)], dict(rargs), '
     'cfg=self.plane,\n'
     '                                 path=concrete, ledger_cfg=self.ledger_cfg, fields=fields, **READ_OPTIONS)\n',
     '            env = {"data": engine._client(self.row.product, self.plane).call("GET", concrete, dict(rargs))}\n'),
    ('M63-CONSULT-RECEIPT', E,
     '               **consult_seen,\n',
     ''),
    ('M64-CONSULT-LOADER', AT,
     '    if r["consult"] is not None and (wrong := consult_problem(r["consult"], r, index)):\n',
     '    if False:\n'),
]

#: The round's test set: the whole suite. Until the cut (2026-10-18) this was a hand-kept list of
#: the tests that imported nothing of 0.44; 0.44 is gone, so a new test file joins the round by
#: existing.
CORE = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("test_*.py")
              if p.name != "test_gate_mutations_inventory.py")
              # it asserts each gate's text is AT its site: red on every mutant, a false KILL


def _sha(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _clear_pyc(root: pathlib.Path) -> None:
    # a .pyc is keyed on (mtime, size): a neutered source of the same size can outlive itself
    for d in (root / "src").rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def _pytest(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider", *CORE], cwd=root,  # noqa: S603,S607 -- our own runner, fixed argv
                          capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def run(root: pathlib.Path, out: pathlib.Path, only: list[str]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    log = open(out / "log.txt", "a", encoding="utf-8")

    def say(s: str) -> None:
        print(s, flush=True)
        log.write(s + "\n")
        log.flush()

    say(f"== gate round on {root} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    # THE BASELINE: the core-only set must be green UNMUTATED, or every mutation below reads as a
    # kill for a reason that has nothing to do with the gate (a red test, a broken venv).
    base = _pytest(root)
    base_line = [x for x in base.stdout.splitlines() if x.strip()][-1:]
    say(f"baseline: rc={base.returncode} | {base_line[0] if base_line else ''}")
    if base.returncode != 0:
        say("!!! the unmutated set is not green; no mutation can be judged. STOPPING")
        return 2
    survived = 0
    for name, rel, old, new in M:
        if only and name not in only:
            continue
        f = root / rel
        bak = out / (name + ".bak")
        shutil.copy2(f, bak)
        s0 = _sha(f)
        src = f.read_text(encoding="utf-8")
        if src.count(old) != 1:
            say(f"{name}: SKIP target found {src.count(old)} times")
            survived += 1
            continue
        t = time.time()
        try:
            f.write_text(src.replace(old, new), encoding="utf-8")
            _clear_pyc(root)
            r = _pytest(root)
        finally:
            # whatever happened above (a raise, a signal), the gate goes back before anything else
            shutil.copy2(bak, f)
            _clear_pyc(root)
        lines = [x for x in r.stdout.splitlines() if x.strip()]
        fails = [x for x in lines if x.startswith(("FAILED", "ERROR"))][:3]
        ok = _sha(f) == s0
        # A KILL IS A FAILED TEST. A collection error, a missing plugin or an empty set also exit
        # nonzero, and the first run of this round called those kills (a readback that cannot fail).
        summary = lines[-1] if lines else ""
        killed = r.returncode in (1, 2) and bool(fails) and " failed" in summary
        verdict = "KILLED" if killed else ("SURVIVED" if r.returncode == 0 else f"ERROR(rc={r.returncode})")
        say(f"{name}: rc={r.returncode} {verdict} in {time.time() - t:.0f}s restored={ok} | {summary}")
        for x in fails:
            say("    " + x[:200])
        if not ok:
            say("!!! RESTORE FAILED, STOPPING")
            return 2
        survived += 0 if killed else 1
    say(f"== done, {survived} survived")
    return 1 if survived else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=pathlib.Path, default=None,
                    help="where the log and the .bak copies go (default: a fresh mkdtemp)")
    ap.add_argument("names", nargs="*")
    a = ap.parse_args(argv)
    out = a.out if a.out is not None else pathlib.Path(tempfile.mkdtemp(prefix="gate-round-"))
    print(f"gate round: log and .bak copies in {out}")
    return run(ROOT, out, a.names)


if __name__ == "__main__":
    sys.exit(main())
