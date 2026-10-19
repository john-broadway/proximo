"""THE ARENA: every published mutation has a verdict with a sentence, and the guard sees its own failure.

John, 2026-10-04: "equip the fighter for the arena, allow them to enter the arena from any gate
offered." The tier record was harvested from the 0.44 wrappers' own sentences, so every address
the wrappers never reached arrived in the core with no line and was refused as unjudged (136 on
2026-10-04, node reboot on three planes among them). This file is the guard that makes that
silence impossible: a mutating address the vendor publishes is TIERED (open to an armed operator),
HELD (refused with its own sentence, a judgement, not an absence), GATED or EXCLUDED, and nothing
else. A table refresh that brings a new mutation with no line goes red here.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

from proximo.core import engine
from proximo.core.errors import ProximoError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

#: The held lines: 17 login-ticket addresses (the door would log in with a password the caller
#: supplies and hand back a credential usable OUTSIDE the door) + the PVE `execute` batch door
#: (inner calls never pass through resolve, tier, forbid or scope) + 2 whose ANSWER is a secret
#: set for someone who is not the caller (lens 1 B1: PDM's auto-install answer file with a root
#: password in it; PVE's internal-use node add, which answers the corosync authkey). A line added
#: or withdrawn moves this pin on purpose; opening one is John's word by name.
EXACT_HELD = 20


def _mutations():
    """Every mutation the engine may open: ungated, or gated on an opt-in lane (the guest agent,
    the container and node shell). A hard-gated byte stream or a tunnel is refused before any
    tier is read, so a line on one is inert and the record refuses it (lens 1 N6: the first
    version filtered `not r.gate` and would have let an untiered agent mutation through)."""
    return [r for r in engine.table().values()
            if not r.excluded and r.access == engine.MUTATE
            and (not r.gate or engine.opt_in_lane(r) is not None)]


def test_every_published_mutation_is_tiered_or_held():
    silent = sorted(r.key for r in _mutations()
                    if not (isinstance(r.tier, str) and r.tier in engine.TIERS) and not r.held)
    assert not silent, f"{len(silent)} published mutation(s) with no verdict: {silent[:8]}"


def test_the_held_record_is_exact_and_names_only_live_mutations():
    held = [r for r in _mutations() if r.held]
    assert len(held) == EXACT_HELD, f"{len(held)} held, the pin says {EXACT_HELD}"
    assert len(engine._tiers()["held"]) == EXACT_HELD      # every held line reached a row
    for r in held:
        assert r.tier is None and r.why is None, f"{r.key} is held AND tiered"
        assert len(r.held.split()) >= 4 and r.held[-1] not in ",(", r.key


@pytest.fixture
def armed(monkeypatch):
    from proximo.core import arm as ag
    monkeypatch.setattr(ag, "arm_state", lambda cfg=None: ag.ArmGateState(True, True, None))


def test_a_held_address_is_refused_before_arm_with_its_own_sentence(armed):
    row = engine.resolve("pve", "POST", "/nodes/{node}/execute")
    v = engine.govern(row)
    assert not v.allowed and v.needs == "held"
    assert row.held and row.held in v.reason


def test_the_control_without_its_held_line_the_address_reads_as_unjudged(armed, monkeypatch):
    """The held line is load-bearing: drop it and the same address is refused for a DIFFERENT
    reason (no tier), which a tier line would then open. The hold is the judgement."""
    real = engine._tiers()
    stripped = {**real, "held": {k: v for k, v in real["held"].items()
                                  if k != "pve:POST /nodes/{node}/execute"}}
    monkeypatch.setattr(engine, "_tiers", lambda: stripped)
    engine.table.cache_clear()
    try:
        v = engine.govern(engine.resolve("pve", "POST", "/nodes/{node}/execute"))
        assert not v.allowed and v.needs == "tier"
    finally:
        engine.table.cache_clear()


@pytest.mark.parametrize("product,method,path,family", [
    ("pve", "PUT", "/cluster/options", "pve:/cluster/options"),
    ("pve", "POST", "/nodes/{node}/status", "pve:/nodes/status"),
    ("pdm", "PUT", "/nodes/{node}/dns", "pdm:/nodes/dns"),
])
def test_a_family_line_authored_today_opens_its_address_and_its_removal_refuses_it(
        armed, monkeypatch, product, method, path, family):
    """2026-10-04's lines, planted: the address passes the tier gate with the line and is refused
    `needs=tier` without it. Later pillars may still refuse; the tier gate is what this proves."""
    row = engine.resolve(product, method, path)
    assert row.tier in engine.TIERS and row.why
    assert engine.govern(row).needs != "tier"
    real = engine._tiers()
    stripped = {**real, "family": {k: v for k, v in real["family"].items() if k != family}}
    monkeypatch.setattr(engine, "_tiers", lambda: stripped)
    engine.table.cache_clear()
    try:
        v = engine.govern(engine.resolve(product, method, path))
        assert not v.allowed and v.needs == "tier", v
    finally:
        engine.table.cache_clear()


def _record(monkeypatch, body: str):
    class _File:
        def joinpath(self, _name):
            return self

        def read_bytes(self):
            return body.encode()

    monkeypatch.setattr(engine.resources, "files", lambda _pkg: _File())
    engine._tiers.cache_clear()


@pytest.mark.parametrize("body,match", [
    ('[tier]\n"pve:POST /nodes/{node}/execute" = { tier = "destructive", why = "a sentence that is long" }\n'
     '[tier.held]\n"pve:POST /nodes/{node}/execute" = { why = "held and tiered at once, the ambiguity" }\n',
     "both held and tiered"),
    ('[tier.held]\n"pve:POST /nodes/{node}/execute" = { tier = "destructive", why = "a held line with a tier" }\n',
     "carries a tier"),
    ('[tier.held]\n"pve:POST /nodes/{node}/execute" = { why = "   " }\n', "without a why"),
    ('[tier.held]\n"pve:POST /nodes/{node}/execute" = "destructive"\n', "without a why"),
])
def test_a_held_line_that_is_ambiguous_or_blank_refuses_the_record(monkeypatch, body, match):
    _record(monkeypatch, body)
    try:
        with pytest.raises(ProximoError, match=match):
            engine._tiers()
    finally:
        engine._tiers.cache_clear()


def test_a_held_line_for_an_address_the_door_never_serves_is_refused_at_load(monkeypatch):
    real = engine._tiers()
    bogus = {**real, "held": {**real["held"], "pve:GET /version": "a held read, which the gate never reads"}}
    monkeypatch.setattr(engine, "_tiers", lambda: bogus)
    engine.table.cache_clear()
    try:
        with pytest.raises(ProximoError, match="pve:GET /version"):
            engine.table()
    finally:
        engine.table.cache_clear()


def test_a_plan_of_a_held_address_reads_no_live_state(armed):
    """Lens 1 N5: the plan of a held login address went looking for a credential to read its GET
    twin. The plan's answer is the sentence; nothing is dialled for a call that will not run."""
    out = engine.plan(engine.resolve("pve", "POST", "/access/ticket"), {}, path="/access/ticket")
    assert out["needs"] == "held" and "current" not in out


@pytest.mark.parametrize("product,method,path,field", [
    ("pve", "POST", "/access/users/{userid}/token/{tokenid}", "value"),
    ("pve", "PUT", "/access/users/{userid}/token/{tokenid}", "value"),       # regenerate (lens 2)
    ("pbs", "PUT", "/access/users/{userid}/token/{token-name}", "secret"),
    ("pdm", "POST", "/auto-install/tokens", "secret"),
    ("pdm", "POST", "/access/tfa/{userid}", "recovery"),
    ("pbs", "POST", "/access/tfa/{userid}", "recovery"),
    ("pve", "POST", "/storage", "encryption-key"),
])
def test_a_token_mint_answers_its_secret_once_labelled_as_a_credential(product, method, path, field):
    """Lens 1 B1: a mutation whose ANSWER carries a one-time secret its read twin never shows. Its
    own line governs the answer: served whole to the caller who asked, labelled, and `ledgered`
    fingerprints the whole answer so no receipt ever holds it."""
    row = engine.resolve(product, method, path)
    assert engine.secret_key(row) == row.key
    out = engine._envelope(row, row.path, {"id": "t", field: "SECRET-VALUE-1"})
    assert out["data"][field] == "SECRET-VALUE-1" and out["bearer_credential"]
    assert "SECRET-VALUE-1" not in repr(engine.ledgered({"id": "t", field: "SECRET-VALUE-1"},
                                                          rule=engine.secret_rule(row)))


def test_a_create_that_mints_and_echoes_serves_the_mint_and_withholds_the_echo():
    """Lens 2 B2: the prepared answer file MINTS its installer token (the caller never held the
    secret) and echoes the hashed root password and subscription key the caller sent."""
    row = engine.resolve("pdm", "POST", "/auto-install/prepared")
    out = engine._envelope(row, row.path, {"id": "p", "token": {"secret": "S1"}, "root-password-hashed": "H1",
                                           "subscription-key": "K1"})
    assert out["data"]["token"]["secret"] == "S1" and out["bearer_credential"]
    assert out["withheld"] == ["root-password-hashed", "subscription-key"] and "H1" not in repr(out)


def test_the_control_a_mutation_without_its_own_line_answers_by_its_read_twin():
    """`PUT /config/notes` has no line of its own and no read line: the answer passes whole, and
    the key the engine consulted is the read twin's."""
    row = engine.resolve("pdm", "PUT", "/config/notes")
    assert engine.secret_key(row) == "pdm:GET /config/notes"
    assert engine._envelope(row, row.path, {"notes": "hello"})["data"] == {"notes": "hello"}


def test_the_committed_arena_inventory_is_the_generators_output():
    """docs/arena.md is GENERATED (scripts/arena.py); a reviewer reads the inventory, never a claim.
    A stale copy is a red test, not a silent number."""
    import arena
    committed = (REPO_ROOT / "docs" / "arena.md").read_text()
    assert committed == arena.render(), "docs/arena.md is stale: python scripts/arena.py > docs/arena.md"
