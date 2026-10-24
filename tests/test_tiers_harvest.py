"""The tier RECORD: address-level only, honest about what it opens, and exact.

`records/tiers.toml` is the hand-authored grant the engine is built from: every line opens one
mutating address to an armed operator, with the sentence that justifies it. It was generated
once from the thin mutation wrappers' own plan functions; those wrappers and their generator
retired together (2026-09-23), so the file is the record now. These tests pin what three lens
rounds found in the generated file, against the file alone: editing it is the act of granting,
and a grant added or withdrawn moves the exact count on purpose.
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

from proximo.core import engine

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_proximo_json as bj  # noqa: E402

HARVESTED = ROOT / "records" / "tiers.toml"

#: pbs 81 · pve 53 · pmg 16 (destructive 38 · disruptive 79 · restorable 33) on 2026-09-23.
#: 152 on 2026-09-25: John's first two hand grants, LXC start and shutdown (restorable), so the
#: core can run its own lab (pve 55; restorable 35).
#: 161 on 2026-09-29: parity rows L1-L3, the operations 0.44 performed that the core refused for
#: want of a line, each carrying the 0.44 plan's own sentence: PBS prune and verify jobs (create,
#: update, delete: restorable; a prune RUN destructive, a verify run restorable) and pmg regextest
#: (read-back: a POST that reads). pbs 89 · pmg 17.
#: 179 on 2026-10-04 (lens 1): +3 address lines sharper than their family (the subscription,
#: installation-record and remote DELETEs).
#: 191 on 2026-10-24: +11 qemu/lxc power and snapshot lines (John, "all as proposed").
EXACT_GRANT = 191   # +1 2026-10-04 lens 2 N3: the subscription PUT


# --- the harvested tier file: address-level only, and honest about what it opens ---------------

#: 87 on 2026-09-26 (John: "family grain, go with 87"). 148 on 2026-10-04 (John: "every gate
#: offered"): the 61 families the harvest never reached, 118 addresses refused as unjudged, each
#: sentence from the vendor's own description; the 18 refused on purpose are [tier.held], pinned
#: in tests/test_arena.py.
EXACT_FAMILY = 147   # 2026-10-04 lens 1: the auto-install answer family's one address is held


def test_the_record_carries_the_family_lines_john_ruled():
    """2026-09-26, John: "family grain, go with 87". A family line opens every ungated mutating
    address in its family that has no address line; the loader refuses a family that matches
    nothing, a tier outside the vocabulary and a blank sentence, so the pin is the whole test."""
    import tomllib
    parsed = tomllib.loads(HARVESTED.read_text())["tier"]
    assert len(parsed.pop("family")) == EXACT_FAMILY
    parsed.pop("held")
    assert len(parsed) == EXACT_GRANT
    bj.build(*bj.read_inputs()[:2])   # the build's refusals (unpublished family, bad tier, blank why) are this test's


def test_the_record_names_only_addresses_the_table_holds_and_is_exact():
    """Every harvested key must match a published address, or the engine refuses the file at
    load. This is the guard against a placeholder re-spelling drifting silently."""
    import tomllib
    parsed = tomllib.loads(
        HARVESTED.read_text()
    )["tier"]
    parsed = {k: v for k, v in parsed.items() if k not in ("family", "held")}
    live = {f"{r.product}:{r.method} {r.path}" for r in engine.table().values()}
    assert not (set(parsed) - live), sorted(set(parsed) - live)[:5]
    assert all(v["tier"] in engine.TIERS for v in parsed.values())
    # 251 -> 169 -> 150 while a generator wrote this: each drop was a lens finding a grant
    # justified by a dry-run branch, by a sentence about another product, by a fragment, or by
    # nothing. With the file hand-authored, the count is EXACT: a line added or withdrawn is a
    # decision, and this pin is where it is made on purpose.
    assert len(parsed) == EXACT_GRANT, f"the record holds {len(parsed)} grants, the pin says {EXACT_GRANT}"


# --- the third lens round, pinned -------------------------------------------------------------

def _harvested() -> list[tuple[str, str, str]]:
    """(key, tier, justification) for every line in the shipped file, read the way the engine
    reads it: the table form, `why` mandatory."""
    import tomllib
    parsed = tomllib.loads(HARVESTED.read_text())["tier"]
    return [(k, v["tier"], v.get("why", "").strip()) for k, v in parsed.items() if k not in ("family", "held")]


def test_no_grant_ships_without_a_justification():
    """The file's own header says "judge the sentence". 84 of the previous 251 lines had none,
    and the generator counted them as successes because it had no bucket for it."""
    blank = [k for k, _t, s in _harvested() if not s]
    assert not blank, blank[:5]


def test_no_line_claims_recoverable_while_its_own_sentence_says_permanent():
    """RISK_* is a blast-SIZE axis; the tier vocabulary is a RECOVERABILITY axis. Mapping one
    onto the other by arity produced nine lines reading "PERMANENTLY ... no undo" under the
    label "disruptive" or "restorable" -- a lie to the only human who reads it."""
    bad = [(k, t, s) for k, t, s in _harvested()
           if t != "destructive"
           and re.search(r"PERMANENT|UNRECOVERABLE|IRREVERSIB|no undo|cannot be recover|gone forever",
                         s, re.I)]
    assert not bad, bad[:3]


def test_no_grant_is_inert():
    """A gated or excluded address is refused before the tier is read, so tiering it authorizes
    nothing and tells the reader it did. `_refuse_inert_keys` cannot catch this: the address
    exists, it just cannot be reached."""
    live = {f"{r.product}:{r.method} {r.path}": r for r in engine.table().values()}
    inert = [k for k, _t, _s in _harvested()
             if k in live and ((live[k].gate and live[k].lane is None)
                               or live[k].excluded or live[k].access != "mutate")]
    assert not inert, inert[:5]


@pytest.mark.parametrize("address", [
    "pbs:POST /admin/datastore/{store}/prune-datastore",   # dry-run branch justified a live prune
    "pve:POST /nodes/{node}/vzdump",                       # snapshot branch justified mode=stop
])
def test_an_address_whose_plan_branches_on_risk_is_not_granted(address):
    """Two judgements on one address means neither sentence justifies the grant, because which
    one applies depends on an argument the grant also covers."""
    assert address not in {k for k, _t, _s in _harvested()}


# --- lens round 2 (2026-09-22), restated against the file --------------------------------------
# The generator read text with a regex and shipped fragments; a plan that branched carried the
# refusal's sentence for the deletion. Its planted controls retired with it. What survives is
# the shape they protected: every why is a whole sentence, and the two branch-refused addresses
# above stay refused until a hand writes their line.

def test_every_why_is_a_sentence_not_a_fragment():
    short = [(k, s) for k, _t, s in _harvested() if len(s.split()) < 4 or s[-1] in ",("]
    assert not short, short[:3]


def test_a_record_that_does_not_parse_refuses_every_mutation_by_name(records):
    """Lens 5: `tomllib` raises on a duplicate key, and the loader's narrow except let that
    traceback out of `govern` instead of a refusal that names the file. A record that cannot be
    read grants nothing, and says so."""
    from proximo.core.errors import ProximoError

    line = '"pbs:DELETE /x" = { tier = "destructive", why = "%s" }\n'
    with pytest.raises(ProximoError, match="tiers.toml is not a readable TOML table"):
        records(**{"tiers.toml": "[tier]\n" + line % "a" + line % "b"})      # a duplicate key: TOML refuses it
