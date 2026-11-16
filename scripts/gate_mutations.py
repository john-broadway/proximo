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
MM = "src/proximo/core/memory.py"
MP = "src/proximo/core/memory_pbs.py"
MG = "src/proximo/core/memory_pmg.py"
MD = "src/proximo/core/memory_pdm.py"
MV = "src/proximo/core/memory_pve.py"
DG = "src/proximo/core/diagnose.py"
AR = "src/proximo/core/arm.py"
CL = "src/proximo/core/doors/cli.py"
MC = "src/proximo/core/doors/mcp.py"

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
    # ESTATE MEMORY on PBS: a list the token may not see whole retires nothing (absent is not proof),
    # each sight is this pass's map's or none, sync needs both, `uses` refuses a plane that relates
    # nothing, and the shell refuses a plane memory has no shape for.
    ('M70-PBS-LISTS-OWN-NOTHING-UNSEEN', MP,
     '    if db is None or not _sees(db, box, template, _sighted(who)):\n'
     '        return None\n',
     ''),
    ('M71-PBS-REMOTE-SIGHT-UNSEEN-FIRST', MP,
     '    sight(_REMOTE_SIGHT, "partial")\n',
     ''),
    ('M72-PBS-REMOTE-SIGHT-FROM-THE-MAP', MP,
     '        if remotes is True and seen is not None:',
     '        if seen is not None:'),
    ('M75-PBS-DATASTORE-SIGHT-UNSEEN-FIRST', MP,
     '    sight(_DATASTORE_SIGHT, "partial")\n',
     '    sight(_DATASTORE_SIGHT, "whole")\n'),
    ('M76-PBS-DATASTORE-SIGHT-FROM-THE-MAP', MP,
     '        if sees is True and seen is not None:',
     '        if seen is not None:'),
    ('M77-PBS-SYNC-NEEDS-EVERY-SIGHT', MP,
     '_SYNC: (_REMOTE_SIGHT, _DATASTORE_SIGHT, _PUSH_SIGHT),',
     '_SYNC: (_REMOTE_SIGHT, _PUSH_SIGHT),'),
    # SIGHT IS THE TOKEN'S: a flag names the token's public id, a read owns only for that id, an id that
    # cannot be read is blind, the engine reads it before and after the wire, learn around the map.
    ('M78-PBS-SIGHT-IS-THE-TOKENS', MP,
     'all(memory._meta(db, _PLANE, box, k) == seen for k in',
     'all(str(memory._meta(db, _PLANE, box, k)).startswith("whole:") for k in'),
    ('M79-ENGINE-ID-READ-AGAIN-AFTER-THE-WIRE', E,
     '            if who is not None and _served_id(row, cfg) != who:\n',
     '            if False:\n'),
    ('M80-PBS-LEARN-ID-HELD-STEADY', MP,
     '        seen = _sighted(before) if who() == before else None\n',
     '        seen = _sighted(before)\n'),
    ('M81-PBS-UNPARSEABLE-ID-IS-BLIND', MP,
     '    return f"whole:{who}" if isinstance(who, str) and len(who) <= memory.TEXT and _WHO.fullmatch(who) '
     'else None\n',
     '    return f"whole:{who}"\n'),
    # SYNC HAS A DIRECTION: only an every-direction read owns; learn asks for it; push sight from the map.
    ('M82-PBS-SYNC-OWNS-ONLY-EVERY-DIRECTION', MP,
     '        return template if dict(args) == _SYNC_ALL else None\n',
     '        return template\n'),
    ('M83-PBS-PUSH-SIGHT-FROM-THE-MAP', MP,
     '        if push is True and seen is not None:',
     '        if seen is not None:'),
    ('M84-PBS-LEARN-READS-SYNC-EVERY-DIRECTION', MP,
     '            read(t, t, None, _SYNC_ALL if t == _SYNC else None)\n',
     '            read(t, t)\n'),
    ('M85-PBS-PUSH-SIGHT-UNSEEN-FIRST', MP,
     '    sight(_PUSH_SIGHT, "partial")\n',
     ''),
    # CHANGED: the shape's ids, never the composite key; partial sight said where sight decides; and
    # learn's kept check per (store, namespace).
    ('M86-MEMORY-CHANGED-SHOWS-VENDOR-IDS', MM,
     '            ids = {k: v for k, v in s.show(r).items() if k != "args"} if s is not None else {"id": r["key"]}\n',
     '            ids = {"id": r["key"]}\n'),
    ('M87-MEMORY-CHANGED-PARTIAL-SIGHT', MM,
     '               + (["partial_sight"] if s is not None and s.token_sight\n',
     '               + ([] if s is not None and s.token_sight\n'),
    ('M88-MEMORY-PARTIAL-SIGHT-ONLY-WHERE-SIGHT-DECIDES', MM,
     ' if s is not None and s.token_sight\n',
     ' if s is not None\n'),
    ('M90-MEMORY-DOCTOR-LEARNED-PER-PLANE', MM,
     '    by_plane = {p: "complete" if vs == {"complete"} else "incomplete" for p, vs in sorted(learned.items())}\n',
     '    by_plane = {p: "complete" if all(v == {"complete"} for v in learned.values()) else "incomplete"\n'
     '                for p in sorted(learned)}\n'),
    ('M89-PBS-KEPT-PER-NAMESPACE', MP,
     '    for s, ns in dict.fromkeys([*((s, "") for s in stores), *asked]):\n',
     '    for s, ns in dict.fromkeys((s, "") for s in stores):\n'),
    ('M73-MEMORY-USES-RELATES-NOTHING', MM,
     '    if s is None or not s.answers_uses:\n        raise Unusable',
     '    if False:\n        raise Unusable'),
    # A shape declares its unmatched kinds, and a learn's sight is partial until it ends whole.
    ('M91-MEMORY-NO-NAME-KINDS-ANSWER-TO-NO-NAME', MM,
     '    no_id, no_name = tuple(sorted(s.no_ident_kinds)), tuple(sorted(s.no_name_kinds))\n',
     '    no_id, no_name = tuple(sorted(s.no_ident_kinds)), ()\n'),
    ('M92-MEMORY-LEARN-SIGHT-PARTIAL-AT-START', MM,
     '            _set(first, plane, box, "learn_sight", "partial")\n',
     '            pass\n'),
    ('M93-MEMORY-NO-IDENT-KINDS-ANSWER-TO-NO-ID', MM,
     '    no_id, no_name = tuple(sorted(s.no_ident_kinds)), tuple(sorted(s.no_name_kinds))\n',
     '    no_id, no_name = (), tuple(sorted(s.no_name_kinds))\n'),
    # ESTATE MEMORY on PMG: a config list a role reads at all it reads whole, so a whole read owns; the
    # node list owns when it names a node, the cluster status never; the users list filters, so it owns
    # only with the sight of the credential's own user, judged from its own record's role and held steady.
    ('M94-PMG-ONLY-AN-UNNARROWED-READ-OWNS', MG,
     '    if evaluating or fields is not None or not box or not isinstance(data, list) or args:\n',
     '    if evaluating or fields is not None or not box or not isinstance(data, list):\n'),
    ('M95-PMG-EMPTY-NODE-LIST-OWNS-NOTHING', MG,
     '        return template if data else None\n',
     '        return template\n'),
    ('M96-PMG-USERS-OWN-ONLY-WITH-SIGHT', MG,
     '        if db is not None and seen is not None and memory._meta(db, _PLANE, box, _USERS_SIGHT) == seen:\n',
     '        if True:\n'),
    ('M97-PMG-USERS-SIGHT-PARTIAL-FIRST', MG,
     '    sight("partial")\n',
     '    pass\n'),
    ('M98-PMG-SIGHT-ONLY-FOR-A-ROLE-THAT-SEES-EVERY-USER', MG,
     '            elif isinstance(role, str) and role in _SEES_EVERY_USER:\n',
     '            elif role is not None:\n'),
    ('M99-PMG-LEARN-USER-HELD-STEADY', MG,
     '            if who() != before:\n',
     '            if False:\n'),
    ('M100-PMG-ROLE-FROM-THE-OWN-RECORD', MG,
     'isinstance(mine, dict) and mine.get("userid") == before else None',
     'isinstance(mine, dict) else None'),
    ('M101-PMG-CLUSTER-STATUS-NEVER-OWNS', MG,
     '    if template == _NODES:\n',
     '    if template in (_NODES, _CLUSTER):\n'),
    ('M102-PMG-USERS-KEEP-NO-MAIL-NAMES-OR-KEYS', MG,
     '                kept = {k: r[k] for k in ("role", "realm", "enable") if r.get(k) is not None}\n',
     '                kept = dict(r)\n'),
    ('M103-PMG-LISTS-KEEP-NO-FREE-TEXT', MG,
     '                kept = {k.replace("-", "_"): r[k] for k in _DETAIL.get(kind, ()) if r.get(k) is not None}\n',
     '                kept = {k.replace("-", "_"): v for k, v in r.items()}\n'),
    ('M104-ARM-PMG-HAS-ITS-OWN-READER', AR,
     '    if getattr(cfg, "product", "") == "pmg":\n        return _pmg_user(cfg)\n',
     ''),
    ('M105-ARM-PMG-PASSWORD-MODE-NAMES-NO-ONE', AR,
     '    if not getattr(cfg, "credential", False):\n        return None\n    kind, cred = served_credential(',
     '    kind, cred = served_credential('),
    ('M106-ARM-PMG-USER-NEEDS-ITS-PASSWORD-LINE', AR,
     '    return user if password and "\\n" not in password and PMG_USER.fullmatch(user) else None\n',
     '    return user if PMG_USER.fullmatch(user) else None\n'),
    # A role is the box admin's to change after a learn: a users answer owns only while its own row is
    # there once and shows a role that sees every user.
    ('M107-PMG-USERS-OWN-ROW-SEES-EVERY-USER', MG,
     '            if isinstance(role, str) and role in _SEES_EVERY_USER:\n',
     '            if True:\n'),
    ('M108-PMG-USERS-ONE-OWN-ROW', MG,
     '            role = mine[0].get("role") if len(mine) == 1 else None\n',
     '            role = mine[0].get("role") if mine else None\n'),
    ('M109-PMG-SIGHT-USER-WITHIN-THE-BOUND', MG,
     'isinstance(who, str) and len(who) <= memory.TEXT and _WHO.fullmatch(who)',
     'isinstance(who, str) and _WHO.fullmatch(who)'),
    # Absent is not proof: a PMG list owns only when every row names itself by its field.
    ('M110-PMG-A-LIST-WITH-AN-UNKEYED-ROW-OWNS-NOTHING', MG,
     '    if not _keyed(data, _KEY.get(template, "")):\n',
     '    if False:\n'),
    ('M111-PMG-NODES-AND-USERS-ARE-KEYED-TOO', MG,
     '    if not _keyed(data, _KEY.get(template, "")):\n',
     '    if template in _LISTS and not _keyed(data, _KEY.get(template, "")):\n'),
    ('M112-PMG-EVERY-ROW-KEYED-NOT-ANY', MG,
     '    return all(isinstance(r, dict) and _text(r.get(field)) for r in data)\n',
     '    return not data or any(isinstance(r, dict) and _text(r.get(field)) for r in data)\n'),
    # A learn is not whole when a list it read could not own, and a users list that did not own leaves
    # no whole sight.
    ('M114-PMG-LEARN-NAMES-A-LIST-THAT-COULD-NOT-OWN', MG,
     '        if this_pass(db, f"read:{t}") and not this_pass(db, f"whole:{t}"):\n',
     '        if False:\n'),
    ('M115-PMG-LEARN-USERS-NOT-OWNED-NO-WHOLE-SIGHT', MG,
     '            if t == _USERS:\n                sees = False\n',
     ''),
    # ESTATE MEMORY: a kind keyed by the vendor's own one-string id (`global_ids`) answers to that key,
    # exactly, and a thing is shown once whichever of its values matched.
    ('M116-MEMORY-GLOBAL-IDS-MATCH-THE-KEY', MM,
     '    gids = tuple(sorted(k for k in s.global_ids if not kinds or k in kinds))\n',
     '    gids = ()\n'),
    ('M117-MEMORY-A-KEY-MATCH-IS-SHOWN-ONCE', MM,
     '             if (r["kind"], r["key"]) not in keyed]\n',
     '             if True]\n'),
    # ESTATE MEMORY on PDM: a list owns only when asked whole, every row keyed, not empty, and the token
    # that made the read has whole sight from the box's last learn under the same id; the combined list
    # and a remote that did not answer never retire; a remote keeps no secret.
    ('M118-PDM-ONLY-AN-UNNARROWED-READ-OWNS', MD,
     '    if evaluating or fields is not None or not box or not isinstance(data, list) or args:\n',
     '    if evaluating or fields is not None or not box or not isinstance(data, list):\n'),
    ('M119-PDM-OWNS-ONLY-WITH-THIS-TOKENS-SIGHT', MD,
     '    if need is None or db is None or seen is None or memory._meta(db, _PLANE, box, need) != seen:\n',
     '    if need is None:\n'),
    ('M120-PDM-EVERY-RESOURCE-ROW-KEYED', MD,
     '    return all(isinstance(r, dict) and _id(r.get("id")) and isinstance(r.get("type"), str)\n',
     '    return True or all(isinstance(r, dict) and _id(r.get("id")) and isinstance(r.get("type"), str)\n'),
    ('M121-PDM-REMOTES-LIST-KEYED', MD,
     '        return "remotes" if _keyed(data, "id") else None\n',
     '        return "remotes"\n'),
    ('M122-PDM-AN-EMPTY-ANSWER-OWNS-NOTHING', MD,
     '    if not data:\n        return None\n',
     ''),
    ('M123-PDM-RESOURCES-OWNED-PER-REMOTE', MD,
     '    return f"pve-resources/{remote}" if _keyed_resources(data) else None\n',
     '    return "pve-resources" if _keyed_resources(data) else None\n'),
    ('M124-PDM-AN-ERROR-GROUP-FEEDS-NOTHING', MD,
     '        if "error" in g or not isinstance(g.get("resources"), list):\n',
     '        if not isinstance(g.get("resources"), list):\n'),
    ('M125-PDM-SIGHTS-PARTIAL-FIRST', MD,
     '    sight(_RESOURCE_SIGHT, "partial")\n    sight(_VIEW_SIGHT, "partial")\n',
     ''),
    ('M126-PDM-LEARN-TOKEN-HELD-STEADY', MD,
     '        seen = _sighted(before) if who() == before else None\n',
     '        seen = _sighted(before)\n'),
    ('M127-PDM-SIGHT-IS-RESOURCE-AUDIT-ON-EVERY-REMOTE', MD,
     '        res = held.sees_every("Resource.Audit", "/resource") if held is not None else None\n',
     '        res = True if held is not None else None\n'),
    ('M128-PDM-LEARN-NAMES-A-LIST-THAT-COULD-NOT-OWN', MD,
     '        if this_pass(k) and not this_pass(f"whole:{owner}"):\n',
     '        if False:\n'),
    ('M129-PDM-LEARN-NAMES-A-REMOTE-THAT-DID-NOT-ANSWER', MD,
     '           for r in stores if not this_pass(_answered(r))]',
     '           for r in stores if False]'),
    ('M130-PDM-A-REMOTE-KEEPS-NO-FINGERPRINT', MD,
     '    return host[:memory.TEXT] if host and "=" not in host else None\n',
     '    return entry[:memory.TEXT] if host else None\n'),
    ('M131-PDM-A-PATH-PIECE-PASSES-THE-ID-CHECK', MD,
     '    if not _ok(remote):\n        return []\n',
     ''),
    ('M132-PDM-DECLARES-ITS-GLOBAL-IDS', MD,
     '    global_ids: frozenset[str] = GLOBAL_IDS\n',
     '    global_ids: frozenset[str] = frozenset()\n'),
    ('M133-PDM-VIEWS-LIST-KEYED', MD,
     '        return "views" if _keyed(data, "id") else None\n',
     '        return "views"\n'),
    # Nothing an owner retired comes back from the combined list: it feeds only what no per-remote list reads.
    ('M134-PDM-COMBINED-FEEDS-NO-OWNED-KIND', MD,
     '_IN_COMBINED = {"pbs-node": "node"}\n',
     '_IN_COMBINED = {"pbs-node": "node", "pve-qemu": "qemu", "pve-node": "node", "pve-storage": "storage"}\n'),
    # A removed remote takes its things; a PBS remote's datastores have their own owner.
    ('M135-PDM-A-REMOVED-REMOTE-TAKES-ITS-THINGS', MD,
     '        _retire_with_their_remote(db, box, t)\n',
     '        pass\n'),
    ('M136-PDM-DATASTORE-LIST-KEYED', MD,
     '        return f"pbs-datastores/{remote}" if _keyed(data, "name") else None\n',
     '        return f"pbs-datastores/{remote}"\n'),
    ('M137-PDM-LEARN-READS-EACH-PBS-REMOTES-DATASTORES', MD,
     '            read(f"/pbs/remotes/{r}/datastore", _PBS)\n',
     '            pass\n'),
    ('M138-PDM-DATASTORE-KEY-IS-THE-VENDORS-ID', MD,
     '    return f"remote/{remote}/datastore/{name}"\n',
     '    return f"{remote}/{name}"\n'),
    # A per-remote row of a type not kept is named by learn, and an odd type word is never echoed.
    ('M139-PDM-LEARN-NAMES-A-TYPE-NOT-KEPT', MD,
     '    gaps.extend(_unkept(db, box, asked, start))\n',
     ''),
    ('M140-PDM-AN-ODD-TYPE-WORD-IS-NOT-ECHOED', MD,
     '            named = f"type {t}" if _TYPE_WORD.fullmatch(t) else "a type this shape does not keep"\n',
     '            named = f"type {t}"\n'),
    ('M113-PMG-A-BOOL-IS-NO-ID', MG,
     '    if isinstance(v, bool):\n        return None\n',
     ''),
    # A combined group feeds only a remote memory holds, and learn names a group for a remote this pass's
    # remotes list does not carry (a removed remote's node stays gone); the datastore owner is per remote.
    ('M141-PDM-A-COMBINED-GROUP-FEEDS-ONLY-A-PRESENT-REMOTE', MD,
     '        if not _present(f, remote) or not _ok(remote):\n',
     '        if not _ok(remote):\n'),
    ('M142-PDM-LEARN-NAMES-A-GROUP-FOR-AN-UNLISTED-REMOTE', MD,
     '        elif r not in listed:\n',
     '        elif False:\n'),
    ('M143-PDM-A-GROUPS-REMOTE-ID-IS-BOUND-BEFORE-ITS-KEY', MD,
     '    return f"{_GROUPED}{remote}" if _ok(remote) else f"{_GROUPED}?"\n',
     '    return f"{_GROUPED}{remote}"\n'),
    ('M144-PDM-DATASTORES-OWNED-PER-REMOTE', MD,
     '        return f"pbs-datastores/{remote}" if _keyed(data, "name") else None\n',
     '        return "pbs-datastores" if _keyed(data, "name") else None\n'),
    # find asks a plane, named or not, only when the caller holds a box for it.
    ('M145-FIND-A-NAMED-PLANE-NEEDS-ITS-BOX', MC,
     '              if memory.shape(p) is not None and wire.env_base_url(p)]\n',
     '              if memory.shape(p) is not None]\n'),
    ('M146-FIND-A-PLANE-WITH-NO-SHAPE-IS-NOT-ASKED', MC,
     '              if memory.shape(p) is not None and wire.env_base_url(p)]\n',
     '              if wire.env_base_url(p)]\n'),
    ('M147-MEMORY-RESOLVE-OPENS-NOTHING-WITHOUT-A-SHAPE', MM,
     '    if shape(plane) is None:\n        return {"source": "memory", "verdict": "not_in_memory", "found": False',
     '    if False:\n        return {"source": "memory", "verdict": "not_in_memory", "found": False'),
    # The learn gap says a group was kept only when it fed; a group whose remote id no path may carry feeds
    # nothing; the shell's no-box message names the variable that plane reads.
    ('M148-PDM-LEARN-SAYS-KEPT-ONLY-WHEN-THE-GROUP-FED', MD,
     '                if r in held and this_pass(_answered(r)) else "nothing of it was kept"))\n',
     '                if r in held else "nothing of it was kept"))\n'),
    ('M149-PDM-A-GROUP-FEEDS-ONLY-A-REMOTE-A-PATH-MAY-CARRY', MD,
     '        if not _present(f, remote) or not _ok(remote):\n',
     '        if not _present(f, remote):\n'),
    ('M150-SHELL-NO-BOX-NAMES-THE-PLANES-OWN-VARIABLE', CL,
     '"no box to answer for: set {wire.base_url_var(ns.plane)} or name a --target"',
     '"no box to answer for: set {"PROXIMO_API_BASE_URL"} or name a --target"'),
    # On PDM, learn is whole only when it listed everything it shows present (and `why` always shows that
    # count), and it names a listed remote whose type it does not read or whose id came back as the other
    # product; the lists the vendor filters by the token (remotes, views) own only inside a learn's own
    # pass, which closes however it ends; a removed remote takes only its own things.
    ('M151-PDM-LEARN-IS-WHOLE-ONLY-WHEN-IT-LISTED-ALL-IT-SHOWS', MD,
     '    if unseen:\n',
     '    if False:\n'),
    ('M152-PDM-LEARN-NAMES-A-REMOTE-OF-A-TYPE-IT-DOES-NOT-READ', MD,
     '                gaps.append(_unread_type(key, kind))\n',
     '                pass\n'),
    ('M153-PDM-LEARN-NAMES-A-REMOTE-BACK-AS-THE-OTHER-PRODUCT', MD,
     '                if sides.get((key, other)):\n',
     '                if False:\n'),
    ('M154-PDM-LEARNS-PASS-CLOSES-HOWEVER-IT-ENDS', MD,
     '        _OPEN.reset(opened)\n',
     '        pass\n'),
    ('M160-PDM-THE-FILTERED-LISTS-OWN-ONLY-INSIDE-A-LEARN', MD,
     '    if template in _LEARN_ONLY and _OPEN.get() != box:\n',
     '    if False:\n'),
    ('M161-PDM-THE-UNSEEN-COUNT-IS-ALWAYS-SHOWN', MD,
     '        gaps.insert(0, f"{unseen} thing(s)',
     '        gaps.append(f"{unseen} thing(s)'),
    # A thing brought back by a read that cannot own is judged again by every owner that dropped it: such a
    # put opens every dropped sighting when the thing was gone, or when no owner holds it (a file an older
    # version left stuck); an owning put opens none, and a thing a live owner holds opens nothing. On PVE a
    # storage list read that cannot own feeds no storage, so it cannot bring back what `resources` dropped.
    ('M162-MEMORY-A-REVIVAL-OPENS-THE-DROPS', MM,
     '"UPDATE sighting SET dropped=NULL WHERE plane=? AND box=? AND nid=? AND dropped IS NOT "',
     '"UPDATE sighting SET dropped=dropped WHERE plane=? AND box=? AND nid=? AND dropped IS NOT "'),
    ('M163-MEMORY-AN-OWNING-PUT-OPENS-NO-DROP', MM,      # the opening UPDATE run by an owning put too
     '        known = self.db.execute("SELECT 1 FROM sighting WHERE plane=? AND box=? AND nid=? AND owner=?",\n',
     '        self.db.execute("UPDATE sighting SET dropped=NULL WHERE plane=? AND box=? AND nid=? "\n'
     '                        "AND dropped IS NOT NULL AND (? OR NOT EXISTS (SELECT 1 FROM sighting s "\n'
     '                        "WHERE s.plane=sighting.plane AND s.box=sighting.box AND s.nid=sighting.nid "\n'
     '                        "AND s.dropped IS NULL))", (self.plane, self.box, nid, was_gone))\n'
     '        known = self.db.execute("SELECT 1 FROM sighting WHERE plane=? AND box=? AND nid=? AND owner=?",\n'),
    ('M164-MEMORY-A-HELD-THING-OPENS-NOTHING', MM,
     '"NULL AND (? OR NOT EXISTS (SELECT 1 FROM sighting s',
     '"NULL AND (? OR 1 OR NOT EXISTS (SELECT 1 FROM sighting s'),
    ('M165-MEMORY-A-GONE-THING-OPENS-EVERY-DROP', MM,
     '(self.plane, self.box, nid, was_gone))\n',
     '(self.plane, self.box, nid, False))\n'),
    ('M166-MEMORY-A-STUCK-THING-OPENS-ITS-DROPS', MM,
     ' OR NOT EXISTS (SELECT 1 FROM sighting s WHERE s.plane=sighting.plane',
     ' OR 0 AND NOT EXISTS (SELECT 1 FROM sighting s WHERE s.plane=sighting.plane'),
    ('M167-PVE-A-STORAGE-READ-THAT-CANNOT-OWN-FEEDS-NO-STORAGE', MV,
     '    elif template == "/storage" and f.owner is None:\n',
     '    elif False:\n'),
    ('M168-PVE-NOT-ONLY-AN-ARGUMENT-STORAGE-READ-FEEDS-NO-STORAGE', MV,
     '    elif template == "/storage" and f.owner is None:\n',
     '    elif template == "/storage" and args:\n'),
    # The opening is scoped to its own plane and box: a revival opens no drop of the same nid elsewhere, and
    # an owner holding the same nid elsewhere does not count as holding it here.
    ('M169-MEMORY-A-REVIVAL-OPENS-ONLY-ITS-OWN-BOXS-DROPS', MM,
     'SET dropped=NULL WHERE plane=? AND box=? AND nid=?',
     'SET dropped=NULL WHERE plane=? AND ? IS NOT NULL AND nid=?'),
    ('M170-MEMORY-A-REVIVAL-OPENS-ONLY-ITS-OWN-PLANES-DROPS', MM,
     'SET dropped=NULL WHERE plane=? AND box=? AND nid=?',
     'SET dropped=NULL WHERE ? IS NOT NULL AND box=? AND nid=?'),
    ('M171-MEMORY-ONLY-AN-OWNER-ON-THIS-BOX-HOLDS-IT', MM,
     's.plane=sighting.plane AND "\n                            "s.box=sighting.box AND s.nid=sighting.nid',
     's.plane=sighting.plane AND "\n                            "1 AND s.nid=sighting.nid'),
    ('M172-MEMORY-ONLY-AN-OWNER-ON-THIS-PLANE-HOLDS-IT', MM,
     's.plane=sighting.plane AND "\n                            "s.box=sighting.box AND s.nid=sighting.nid',
     '1 AND "\n                            "s.box=sighting.box AND s.nid=sighting.nid'),
    # The keyed-row rule on PVE and PBS: a whole list with a row memory cannot key owns nothing (absent is
    # no proof); a row of a type the shape does not keep and the root namespace row never stop the owning;
    # a learn that read such a list says it is not whole.
    ('M173-PVE-A-LIST-WITH-AN-UNKEYABLE-ROW-OWNS-NOTHING', MV,
     '    if template not in _OWNING or not _keyed(template, data):\n',
     '    if template not in _OWNING:\n'),
    ('M174-PVE-A-ROW-THAT-IS-NO-RECORD-IS-NOT-KEYED', MV,
     '    if not all(isinstance(r, dict) for r in data):\n        return False\n',
     '    data = [r for r in data if isinstance(r, dict)]\n'),
    ('M175-PVE-A-RESOURCES-ROW-NAMES-ITS-TYPE', MV,
     '        if not all(isinstance(r.get("type"), str) for r in data):\n            return False\n',
     '        data = [r for r in data if isinstance(r.get("type"), str)]\n'),
    ('M176-PVE-EVERY-KEPT-RESOURCES-ROW-IS-KEYED', MV,
     '        return kept == (len(estate.guests_from_resources(data))',
     '        return kept >= (len(estate.guests_from_resources(data))'),
    ('M177-PVE-A-RESOURCES-ROW-OF-ANOTHER-TYPE-NEEDS-NO-KEY', MV,
     '        kept = sum(1 for r in data if r["type"] in _KEPT_TYPES)\n',
     '        kept = len(data)\n'),
    ('M178-PVE-AN-ACL-ROW-NAMES-ITS-PATH-AND-SUBJECT', MV,
     '        return len(_grants(estate.acls_from_acl(data))) == len(data)\n',
     '        return True\n'),
    ('M198-PVE-A-GRANT-SHORT-OF-ITS-KEY-IS-NOT-KEPT', MV,
     '    return [a for a in acls if a.type and a.role]\n',
     '    return list(acls)\n'),
    # THE VENDOR'S ROW, held at the frame for every plane: a list with a row short of a field the vendor
    # publishes on every row owns nothing; a field Proximo itself withholds is not asked for; null is absent.
    ('M199-PVE-LEARN-FANS-OUT-FROM-WHAT-THE-PASS-KEPT', MV,
     'WHERE e.plane=? AND e.box=? AND e.last_seen >= ? AND "',
     'JOIN sighting s ON s.plane=e.plane AND s.box=e.box AND s.nid=e.nid AND s.owner=\'resources\' '
     'WHERE e.plane=? AND e.box=? AND s.seen >= ? AND "'),
    ('M200-PBS-LEARN-JUDGES-BY-THE-TOKEN-THE-MAP-WAS-READ-UNDER', MP,
     '    db, token = db_at(), seen\n',
     '    db, token = db_at(), _sighted(who())\n'),
    ('M201-MEMORY-ONLY-A-LIST-READ-THIS-PASS-IS-CALLED-ONE-THAT-COULD-NOT-OWN', MM,
     'for what, stamp, owner in lists if since(stamp) and not since(f"whole:{owner}")]',
     'for what, stamp, owner in lists if not since(f"whole:{owner}")]'),
    # DIAGNOSE: a window the door's cap cut to no rows at all judged nothing, so it is not a clean section.
    ('M202-DIAGNOSE-A-WINDOW-CUT-TO-NO-ROWS-IS-NOT-A-CLEAN-SECTION', DG,
     '    if not kept and total:\n',
     '    if False:\n'),
    ('M203-DIAGNOSE-A-LIST-CUT-PARTWAY-IS-AN-INCOMPLETE-DIAGNOSIS', DG,
     '    if tasks or not judged:',
     '    if True:'),
    ('M204-DIAGNOSE-A-ROW-WITH-NO-USAGE-IS-NAMED-NOT-READ-AS-UNDER', DG,
     '                elif "absent" in flag and all(',
     '                elif False and all('),
    ('M205-DIAGNOSE-THE-VENDORS-UNKNOWN-IS-NOT-A-FAILED-TASK', DG,
     '    if s == "unknown":',
     '    if False:'),
    ('M206-DIAGNOSE-A-NEVER-FLAG-NAMES-ONLY-THAT-VALUE', DG,
     '                if (_same(v, flag["never"])) if "never" in flag else (not _same(v, flag["expect"])):',
     '                if (not _same(v, flag["never"])) if "never" in flag else (not _same(v, flag["expect"])):'),
    ('M207-DIAGNOSE-AN-EVIDENCE-LIST-CUT-PARTWAY-IS-A-WINDOW', DG,
     '    if tasks or not judged:',
     '    if tasks:'),
    ('M208-DIAGNOSE-A-REFUSED-PROJECTION-ASKS-AGAIN-BEFORE-IT-READS-RAW', DG,
     '            if gone is None or len(asking) == 1:',
     '            if True:'),
    ('M179-MEMORY-A-LIST-SHORT-OF-THE-VENDORS-ROW-OWNS-NOTHING', MM,
     '            if owner is not None and not _rows_as_published(plane, template, data):\n',
     '            if False:\n'),
    ('M180-MEMORY-A-WITHHELD-FIELD-IS-NOT-ASKED-OF-A-ROW', MM,
     '    return tuple(f for f in row.row if f not in row.secret[0])\n',
     '    return tuple(row.row)\n'),
    ('M195-MEMORY-EVERY-PUBLISHED-FIELD-IS-ASKED-OF-A-ROW', MM,
     'all(r.get(f) is not None for f in need) for r in data)',
     'any(r.get(f) is not None for f in need) for r in data)'),
    ('M196-MEMORY-A-ROW-THAT-IS-NO-RECORD-IS-NOT-THE-VENDORS-ROW', MM,
     '    return all(isinstance(r, dict) and all(r.get(f) is not None',
     '    return all(not isinstance(r, dict) or all(r.get(f) is not None'),
    ('M197-MEMORY-A-NULL-FIELD-IS-AN-ABSENT-ONE', MM,
     'all(r.get(f) is not None for f in need) for r in data)',
     'all(f in r for f in need) for r in data)'),
    ('M181-PVE-A-NETWORK-ROW-NAMES-ITS-IFACE', MV,
     '        return len(estate.ifaces_from_network("", data)) == len(data)\n',
     '        return True\n'),
    ('M182-PVE-A-CONTENT-ROW-NAMES-ITS-VOLID', MV,
     '        return len(estate.volumes_from_content("", data)) == len(data)\n',
     '        return True\n'),
    ('M183-PVE-A-STORAGE-JOB-OR-POOL-ROW-NAMES-ITSELF', MV,
     '    return len(count(data)) == len(data)\n',
     '    return True\n'),
    ('M184-MEMORY-A-LEARN-NAMES-A-LIST-IT-READ-THAT-DID-NOT-OWN', MM,
     'for what, stamp, owner in lists if since(stamp) and not since(f"whole:{owner}")]',
     'for what, stamp, owner in lists if since(stamp) and not since(stamp)]'),
    ('M185-PVE-LEARN-JUDGES-THE-RESOURCES-LIST', MV,
     '        ("/cluster/resources", "read:/cluster/resources", "resources"),\n',
     ''),
    ('M186-PVE-LEARN-JUDGES-THE-CONFIG-LISTS', MV,
     '        *((t, f"read:{t}", t) for t in ("/storage", "/cluster/backup", "/pools", "/access/acl")),\n',
     ''),
    ('M187-PVE-LEARN-JUDGES-EACH-NODES-NETWORK', MV,
     '          for n in nodes)]))\n',
     '          for n in ())]))\n'),
    ('M188-PBS-A-LIST-WITH-AN-UNKEYABLE-ROW-OWNS-NOTHING', MP,
     '    if any(_row_id(template, r) is None for r in data):',
     '    if False:'),
    ('M189-PBS-A-ROW-THAT-IS-NO-RECORD-IS-NOT-KEYED', MP,
     '    if not isinstance(r, dict):\n        return None\n    if template == _NAMESPACES:',
     '    if not isinstance(r, dict):\n        return ""\n    if template == _NAMESPACES:'),
    ('M190-PBS-THE-ROOT-NAMESPACE-ROW-IS-NAMED', MP,
     '        return ns if isinstance(ns, str) else None\n',
     '        return ns if isinstance(ns, str) and ns else None\n'),
    ('M191-PBS-A-NAMESPACE-ROW-NAMES-ITS-NS', MP,
     '        return ns if isinstance(ns, str) else None\n',
     '        return ns if isinstance(ns, str) else ""\n'),
    ('M192-PBS-A-GROUP-ROW-NEEDS-BOTH-HALVES-OF-ITS-ID', MP,
     '        return f"{kind}/{bid}" if kind and bid else None\n',
     '        return f"{kind}/{bid}" if kind or bid else None\n'),
    ('M193-PBS-A-ONE-ID-ROW-NAMES-ITSELF', MP,
     '    return _text(r.get(_ID_FIELD.get(template, "")))\n',
     '    return _text(r.get(_ID_FIELD.get(template, ""))) or ""\n'),
    ('M194-PBS-LEARN-NAMES-ONLY-A-LIST-THAT-HAD-ITS-SIGHT', MP,
     'for what, template, stamp, owner in lists if _sees(db, box, template, token)]))',
     'for what, template, stamp, owner in lists]))'),
    ('M155-PDM-A-REMOVED-REMOTE-TAKES-ONLY-ITS-OWN-THINGS', MD,
     '.get("remote") in gone]',
     '.get("remote") is not None]'),
    # Each id a handed-out path carries passes the id check, kind by kind (the table would serve `_x`).
    ('M156-PDM-A-STORAGES-PATH-CHECKS-ITS-ID', MD,
     '/storage/{ident}/status"] if _ok(node, ident) else []',
     '/storage/{ident}/status"] if _ok(node) else []'),
    ('M157-PDM-A-NODES-PATH-CHECKS-ITS-ID', MD,
     'if d.get("on") == "pve" and _ok(ident) else []',
     'if d.get("on") == "pve" else []'),
    ('M158-PDM-A-REMOTES-PATH-CHECKS-ITS-ID', MD,
     '        return [f"/remotes/remote/{ident}/config"] if _ok(ident) else []\n',
     '        return [f"/remotes/remote/{ident}/config"]\n'),
    ('M159-PDM-A-VIEWS-PATH-CHECKS-ITS-ID', MD,
     '        return [f"/config/views/{ident}"] if _ok(ident) else []\n',
     '        return [f"/config/views/{ident}"]\n'),
    ('M74-SHELL-PLANE-HAS-A-SHAPE', CL,
     '        if memory.shape(ns.plane) is None:\n',
     '        if False:\n'),
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
