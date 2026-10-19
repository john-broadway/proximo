"""The governed core: what it refuses, and the proof it refuses BEFORE the wire.

Every test here that asserts a refusal also asserts that no backend was constructed. A refusal
that happens after the credential is read and the socket is open is not a refusal, it is a race
the operator cannot see. `test_refusal_never_touches_the_wire` is the control for that whole
class: it makes the backend explode, and every refusing path must still pass.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass

import pytest

from proximo.core import apitree, engine, wire
from proximo.core.errors import ProximoError


@dataclass(frozen=True)
class EstateCfg(wire.Plane):
    """A plane config that also carries the ledger's three settings, as the big package's does."""

    audit_log_path: str = ""
    audit_key_path: str | None = None

# --- the table is the vendor's, and it must agree with a second vendored source ---------------

def test_table_covers_every_published_address():
    """The table and `apitree` are vendored from the same upstream by DIFFERENT code paths.

    If the committed table ever goes stale, these two disagree and this goes red. That is the
    whole guard against the 61% problem quietly coming back: coverage is asserted, not assumed.
    """
    for product in apitree.PRODUCTS:
        tree = {(p, m) for p, m in apitree.raw_tree(product)}
        # Authored rows (shell.toml, wire=ssh) are NOT the vendor's; test_core_shell_lane pins them exactly.
        tab = {(r.path, r.method) for r in engine.table().values() if r.product == product and r.wire == "http"}
        assert tree == tab, f"{product}: table and apitree disagree on {tree ^ tab}"


def test_access_is_derived_from_method_for_every_row():
    """The one column that replaces 924 docstring markers. Total, by construction."""
    for row in engine.table().values():
        assert row.access == ("read" if row.method == "GET" else "mutate"), row.address


# --- resolution -------------------------------------------------------------------------------

def test_concrete_and_templated_paths_reach_the_same_row():
    assert engine.resolve("pve", "GET", "/nodes/pve1/status") is \
           engine.resolve("pve", "GET", "/nodes/{node}/status")


def test_unpublished_path_is_refused_and_names_where_to_go():
    with pytest.raises(ProximoError) as e:
        engine.resolve("pve", "GET", "/nodes/pve1/not-a-thing")
    assert "publishes no" in str(e.value) and "Nearest published" in str(e.value)


def test_unknown_plane_is_refused():
    with pytest.raises(ProximoError, match="unknown plane"):
        engine.resolve("aws", "GET", "/nodes")


# --- governance -------------------------------------------------------------------------------

def test_read_is_allowed():
    assert engine.govern(engine.resolve("pve", "GET", "/nodes/{node}/status")).allowed


def test_mutation_without_arm_is_refused_and_says_what_would_fix_it(monkeypatch):
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, False, "disarmed"))
    verdict = engine.govern(engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101"))
    assert not verdict.allowed and verdict.needs == "arm"


def _untiered() -> engine.Row:
    """An ungated mutating address with its sentence stripped: the fail-closed control. Until
    2026-10-04 this picked a row the record left unjudged; that day the record stopped leaving
    any (tests/test_arena.py holds it there), so the control is manufactured from a live row the
    way `_tiered` manufactures a grant. `govern` reads the Row it is handed, never the table."""
    row = engine.resolve("pve", "PUT", "/cluster/options")
    assert row.tier in engine.TIERS and not row.gate and not row.excluded
    return engine.Row(**{**row.__dict__, "tier": None, "why": None})


def test_untiered_mutation_is_refused_EVEN_WHEN_ARMED(monkeypatch):
    """FAIL-CLOSED ON SILENCE. An unjudged mutation is not a permitted one.

    This is the property that makes an empty `tiers.toml` safe to ship: authoring a tier can only
    ever LOOSEN. If this inverts, every one of the 818 mutating addresses becomes reachable the
    moment someone arms, which is precisely the blast radius nobody judged.
    """
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, True, None))
    # Since family grain (2026-09-26) the guest destroy this test used to name is opened by the
    # pve:/nodes/qemu family line; the control is whatever the record still leaves unjudged.
    row = _untiered()
    assert row.tier is None
    verdict = engine.govern(row)
    assert not verdict.allowed and verdict.needs == "tier"


def test_excluded_tunnel_is_refused():
    excluded = [r for r in engine.table().values() if r.excluded]
    assert excluded, "no excluded rows: the exclusion data did not make it into the table"
    assert not engine.govern(excluded[0]).allowed


def test_a_hard_gated_address_is_refused_and_names_the_gate():
    """Since 2026-10-04 the five byte streams are the download lane and the agent subtree is its
    own lane, so no published row is hard gated; the shape stays the engine's (a future gate),
    and the control is manufactured from a live row the way `_tiered` manufactures a grant."""
    assert not [r for r in engine.table().values() if r.gate and engine.opt_in_lane(r) is None]
    row = engine.resolve("pve", "GET", "/version")
    verdict = engine.govern(engine.Row(**{**row.__dict__, "gate": "a planted hard gate"}))
    assert not verdict.allowed and "gated" in verdict.reason


# --- arguments are the VENDOR's, not ours -----------------------------------------------------

def test_undocumented_argument_is_refused_with_the_published_set():
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    with pytest.raises(ProximoError, match="does not publish"):
        engine.check_args(row, {"node": "pve1", "vmid": "101", "rm_rf": "yes"})


def test_required_argument_is_enforced_from_the_published_schema():
    """A required parameter the PATH cannot supply must still be demanded.

    Retargeted after the first wire call: the old version used `node`, which the path supplies,
    so once placeholders were honoured it was asserting a bug rather than a rule.
    """
    row = next(r for r in engine.table().values()
               if r.access == "read" and not r.excluded and not r.gate
               and {n for n, s in r.params.items() if not s["optional"]}
                   - set(engine.placeholders(r.path)))
    with pytest.raises(ProximoError, match="requires"):
        engine.check_args(row, {})


# --- THE CONTROL: a refusal must happen before anything is constructed ------------------------

def test_refusal_never_touches_the_wire(monkeypatch):
    """Make the backend explode. Every refusing path must still refuse cleanly.

    Planted and watched go red before it was trusted: with `govern`'s refusal removed from
    `execute`, this test fails with the boom below instead of the refusal.
    """
    def boom(product):
        raise AssertionError(f"the wire was reached for {product} on a refused call")

    # A CONFIG IS PASSED ON PURPOSE. Without it `from_env()` raises first on an unconfigured
    # box, so the test would go red for the wrong reason and the planted `boom` would never be
    # the mechanism -- green here, and red-by-accident there. Handing it a config makes the
    # backend the ONLY thing left that can fail, on any box.
    cfg = wire.Plane("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null")
    monkeypatch.setattr(engine, "_client", boom)
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, False, "disarmed"))
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    with pytest.raises(ProximoError):
        engine.execute(row, {"node": "pve1", "vmid": "101"}, cfg=cfg)


# --- THE PROPERTY JOHN ASKED FOR: it runs without a model, an agent or a protocol -------------

def test_the_core_does_not_import_mcp():
    """"with or without you", asserted mechanically.

    A dependency claim nobody tests is a comment. If the shell door ever pulls in the MCP SDK,
    the engine has quietly become a thing that needs an agent, and this goes red the same day.
    """
    out = subprocess.run(
        [sys.executable, "-c",
         "import proximo.core.doors.cli, sys; "
         "assert 'mcp' not in sys.modules, sorted(m for m in sys.modules if m.startswith('mcp'))"],
        capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr


# --- what the FIRST REAL WIRE CALL found, pinned so it cannot come back ----------------------

def test_path_placeholders_are_not_demanded_as_arguments():
    """The vendor marks `node` required because it is a PATH segment, not a query argument.

    The first live call refused a perfectly good read for a "missing" node that was sitting in
    the path. Pinning the class, not the one address: EVERY row whose placeholders cover its
    required params must validate with no arguments at all.
    """
    row = engine.resolve("pve", "GET", "/nodes/pve1/status")
    assert engine.check_args(row, {}) == {}


def test_every_row_is_satisfiable_by_its_own_path_plus_optionals():
    """Class-wide: no published address may require something neither its path nor a caller
    can supply. A row that fails this is unreachable through any door."""
    unreachable = []
    for row in engine.table().values():
        required = {n for n, s in row.params.items() if not s["optional"]}
        if required - set(engine.placeholders(row.path)) - set(row.params):
            unreachable.append(row.address)
    assert not unreachable, unreachable


def test_bind_maps_concrete_segments_onto_placeholders():
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    assert engine.bind(row, "/nodes/pve1/qemu/101") == {"node": "pve1", "vmid": "101"}


def test_executing_a_template_path_is_refused_rather_than_sent_to_the_wire(monkeypatch):
    """`row.path` still holds `{node}`. Sending it asks Proxmox for a node literally named
    "{node}" -- a 500 from the vendor instead of a refusal from us. Refuse it ourselves."""
    monkeypatch.setattr(engine, "_client",
                        lambda product: pytest.fail("template path reached the wire"))
    cfg = wire.Plane("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    with pytest.raises(ProximoError, match="needs real values"):
        engine.execute(row, {}, cfg=cfg, path="/nodes/{node}/status")


# --- what the adversarial lens found, pinned as classes ---------------------------------------

@pytest.mark.parametrize("plane,path", [
    ("pve", "//nodes/pve1/status"),            # httpx collapses -> a DIFFERENT published read
    ("pve", "/nodes/pve1#junk/status"),        # httpx truncates at '#'
    ("pve", "/nodes/pve1/status?smuggled=1"),  # query rides past check_args entirely
    ("pve", "/nodes//pve1/status"),
    ("pve", "/nodes/pve1 /status"),
    ("pve", "/nodes/pve1/../../status"),
    ("pve", "/nodes/pve1\r\nX-Evil: 1/status"),
    ("pve", "/nodes/pve1\x00null/status"),
    ("pbs", "//nodes/backup"),                 # -> /backup, an EXCLUDED protocol tunnel
    ("pbs", "//tape/backup"),
    ("pbs", "//nodes/reader"),
])
def test_a_spelling_that_the_url_layer_would_rewrite_is_refused(plane, path):
    """THE CLASS: govern must not judge one string while execute sends another.

    Each of these resolved to an innocuous published read and was ALLOWED, while the bytes that
    would have gone to the wire named something else. The pbs three are the sharp ones: they
    governed as `GET /nodes/{node}` and would have reached `/backup` and `/reader`, the wire
    protocol handshakes that `excluded` exists to refuse. Found by an adversarial lens, not by
    this suite, which is why the fix is one shared checker rather than eleven patches.
    """
    with pytest.raises(ProximoError, match="malformed path"):
        engine.resolve(plane, "GET", path)


def test_the_core_and_the_raw_door_share_ONE_copy_of_the_hardening():
    """Two copies of a rule are one check, and the copy always loses. Same function, both doors."""
    from proximo.core import rawdoor
    assert rawdoor.reject_malformed is engine.rawdoor.reject_malformed
    for bad in ("//a", "/a/../b", "/a b", "/a?x=1", "/a#f"):
        with pytest.raises(ProximoError, match="malformed path"):
            rawdoor.reject_malformed(bad, allow_placeholders=True)


@pytest.mark.parametrize("value", ["", False, 0, {}, "not-a-tier", "DESTRUCTIVE"])
def test_a_tier_outside_the_vocabulary_is_not_a_tier(value):
    """`tier is None` let `tier = ""` read as authored and open the wire.

    tiers.toml is the ONE human-authored input to the whole spine and was the one input with no
    validation. A typo must fail closed, so membership in a closed vocabulary is the test.
    """
    # NOT `value not in engine.TIERS`: an unhashable value raises TypeError from the assertion
    # itself, which is the very crash-instead-of-refuse this test exists to rule out.
    assert not (isinstance(value, str) and value in engine.TIERS)
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    armed = engine.Row(**{**row.__dict__, "tier": value})
    from proximo.core import arm as ag
    real, ag.arm_state = ag.arm_state, lambda cfg=None: ag.ArmGateState(True, True, None)
    try:
        verdict = engine.govern(armed)
    finally:
        ag.arm_state = real
    assert not verdict.allowed and verdict.needs == "tier"


def test_an_authored_tier_authorizes_only_the_armed_case():
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    tiered = engine.Row(**{**row.__dict__, "tier": "destructive"})
    from proximo.core import arm as ag
    real = ag.arm_state
    try:
        ag.arm_state = lambda cfg=None: ag.ArmGateState(True, False, "disarmed")
        assert engine.govern(tiered).needs == "arm"
        ag.arm_state = lambda cfg=None: ag.ArmGateState(True, True, None)
        assert engine.govern(tiered).allowed
    finally:
        ag.arm_state = real


def test_the_client_is_built_from_the_CALLERS_config_not_the_environment(monkeypatch):
    """`_backend` read the environment while govern and the ledger used the passed cfg, so a
    test that passed a config to isolate itself only isolated half the call."""
    seen = {}
    monkeypatch.setattr(engine.wire, "client", lambda product, cfg=None: seen.setdefault("cfg", cfg))
    mine = wire.Plane("pve", "https://mine.invalid:8006/api2/json", "/dev/null")
    engine._client("pve", mine)
    assert seen["cfg"] is mine


def test_a_usage_error_does_not_report_as_a_governance_refusal():
    """argparse exits 2, which was EXIT_REFUSED: a typo was indistinguishable from the spine
    saying no. A script branching on 2 must be reading the verdict, never argv."""
    from proximo.core.doors import cli
    assert cli.main(["pve", "GET"]) == cli.EXIT_USAGE
    assert cli.main(["pve", "GET", "/version", "notkv"]) == cli.EXIT_USAGE


# --- the mutate path, driven. It used to be `# pragma: no cover` ------------------------------

class Recorder:
    """A client that records instead of dialling. One verb, like the wire."""

    def __init__(self):
        self.calls = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, params))
        return {"ok": True}


@pytest.fixture
def armed(monkeypatch):
    from proximo.core import arm as ag
    monkeypatch.setattr(ag, "arm_state", lambda cfg=None: ag.ArmGateState(True, True, None))


@pytest.fixture
def cfg(tmp_path):
    return EstateCfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                     audit_log_path=str(tmp_path / "audit.log"))


def _tiered(row, tier="destructive"):
    return engine.Row(**{**row.__dict__, "tier": tier})


@pytest.mark.parametrize("method,path", [
    ("DELETE", "/nodes/pve1/qemu/101"),
    ("POST", "/nodes/pve1/qemu/101/status/start"),
    ("PUT", "/nodes/pve1/qemu/101/config"),
])
def test_each_mutating_verb_reaches_the_wire_only_when_armed_AND_tiered(
        method, path, monkeypatch, armed, cfg):
    rec = Recorder()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: rec)
    row = _tiered(engine.resolve("pve", method, path))
    engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path=path)
    # The mutation is the LAST call; the only thing allowed before it is UNDO's read-back of
    # the same address, where the vendor publishes one.
    assert rec.calls[-1] == (method, path, {})
    assert all(c[:2] == ("GET", path) for c in rec.calls[:-1]), rec.calls


def test_the_same_mutation_is_refused_with_the_tier_removed(monkeypatch, armed, cfg):
    """The control for the three above: identical call, tier gone, must not reach the wire."""
    monkeypatch.setattr(engine, "_client",
                        lambda product, c=None: pytest.fail("untiered mutation reached the wire"))
    row = _untiered()
    assert row.tier is None
    with pytest.raises(ProximoError, match="no authored blast-radius tier"):
        engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path=row.path.replace("{node}", "pve1"))


def test_a_failed_wire_call_leaves_a_receipt(monkeypatch, armed, cfg):
    class Boom(Recorder):
        def call(self, method, path, params=None):
            if method == "GET":
                return {}                      # the undo read-back succeeds
            raise ProximoError("the wire said no")

    monkeypatch.setattr(engine, "_client", lambda product, c=None: Boom())
    row = _tiered(engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101"))
    with pytest.raises(ProximoError):
        engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pve1/qemu/101")
    rows = [json.loads(line) for line in open(cfg.audit_log_path)]
    assert [(r["action"], r["outcome"]) for r in rows] == [
        ("core.undo_point", "undo_point"), ("core.execute", "executing"), ("core.error", "error")]
    assert rows[-1]["target"] == "/nodes/pve1/qemu/101"        # what RAN
    assert rows[-1]["detail"]["governed_as"] == row.address    # what GOVERNED it


def test_the_receipt_names_the_path_that_ran_not_the_template(monkeypatch, armed, cfg):
    """The ledger used to record `/nodes/{node}/qemu/{vmid}` and never which VM was touched."""
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Recorder())
    row = _tiered(engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101"))
    engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pve1/qemu/101")
    rows = [json.loads(line) for line in open(cfg.audit_log_path)]
    assert all(r["target"] == "/nodes/pve1/qemu/101" and r["mutation"] is True for r in rows), rows


def test_a_placeholder_given_twice_with_two_values_is_refused(monkeypatch, armed, cfg):
    """bind() was dead code: node=pve2 alongside /nodes/pve1/... sent BOTH, and which one
    Proxmox honours is not ours to guess."""
    monkeypatch.setattr(engine, "_client",
                        lambda product, c=None: pytest.fail("conflicting values reached the wire"))
    row = _tiered(engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101"))
    with pytest.raises(ProximoError, match="given twice"):
        engine.execute(row, {"node": "pve2"}, cfg=cfg, path="/nodes/pve1/qemu/101")


# --- family tiering: 145 decisions instead of 818 ---------------------------------------------

def test_family_drops_placeholders_and_cuts_at_two_literals():
    assert engine.family("/nodes/{node}/qemu/{vmid}/config") == "/nodes/qemu"
    assert engine.family("/cluster/sdn/zones/{zone}") == "/cluster/sdn"


def test_the_shipped_tiers_file_opens_exactly_what_it_says_and_every_grant_has_a_why():
    """The shipped `tiers.toml` is the harvested, ratified grant: every tiered row is a live
    mutating address, carries the human sentence that justifies it, and the count is the
    number the file says (a line that matched nothing would already have refused at load)."""
    tiered = [r for r in engine.table().values() if r.tier is not None]
    assert tiered, "the shipped tiers file authorizes nothing: the grant did not load"
    assert all(r.access == "mutate" and not r.excluded
               and (not r.gate or engine.opt_in_lane(r) is not None) for r in tiered)
    assert all(isinstance(r.why, str) and r.why.strip() for r in tiered), "a grant without a why"
    import tomllib
    from importlib import resources

    from test_tiers_harvest import EXACT_FAMILY, EXACT_GRANT  # one pin each, not copies
    shipped = tomllib.loads(resources.files("proximo.core").joinpath("tiers.toml").read_text())["tier"]
    families, _held = shipped.pop("family"), shipped.pop("held")    # held: tests/test_arena.py's pin
    assert len(shipped) == EXACT_GRANT and len(families) == EXACT_FAMILY
    assert all(r.key in shipped or f"{r.product}:{engine.family(r.path)}" in families for r in tiered)


def test_a_table_form_line_without_a_why_is_refused(tiers_file):
    """The table form exists to carry the sentence; a bare `{ tier = "x" }` is refused at load."""
    with pytest.raises(ProximoError, match="why"):
        tiers_file('[tier]\n"pve:DELETE /nodes/{node}/qemu/{vmid}" = { tier = "destructive" }\n')


def test_the_why_rides_from_the_file_into_the_plan(tiers_file):
    tiers_file('[tier]\n"pve:DELETE /nodes/{node}/qemu/{vmid}" = { tier = "destructive", why = "gone for good" }\n')
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    assert row.tier == "destructive" and row.why == "gone for good"
    assert engine.plan(row, {}, "/nodes/pve1/qemu/101")["why"] == "gone for good"


def test_no_guessed_family_draft_ships_any_more():
    """The guessed 15-family draft is deleted. A lens showed two of its fifteen lines tiered a
    family other than the one their comment reasoned about, and adopting it whole opened 360
    mutating addresses in one `cp`. The harvested address-level file replaces it."""
    from importlib import resources
    assert not resources.files("proximo.core").joinpath("tiers.draft.toml").is_file()


# --- the second lens round. M7 first: NONE of the tier wiring was driven from real TOML -------

@pytest.fixture
def tiers_file(monkeypatch):
    """Drive `_tiers()` from actual TOML bytes.

    Every tier test before this one built `engine.Row(**{**row.__dict__, "tier": ...})` by hand,
    so the address-beats-family lookup in `table()` was never executed under a non-empty file.
    That is why the whole second round of findings was green: the tests asserted the shape of a
    Row nobody loads, not the behaviour of the loader.
    """
    real = engine.resources.files

    def install(text: str):
        class _Bytes:
            def __init__(self, b):
                self._b = b

            def read_bytes(self):
                return self._b

        class _Pkg:
            def joinpath(self, name):
                if name == "tiers.toml":
                    return _Bytes(text.encode())
                return real("proximo.core").joinpath(name)

        monkeypatch.setattr(engine.resources, "files",
                            lambda pkg: _Pkg() if pkg == "proximo.core" else real(pkg))
        engine._tiers.cache_clear()
        engine.table.cache_clear()
        return engine.table()

    yield install
    monkeypatch.undo()
    engine._tiers.cache_clear()
    engine.table.cache_clear()


def test_a_family_tier_loaded_from_real_toml_reaches_its_addresses(tiers_file):
    tiers_file('[tier.family]\n"pve:/nodes/qemu" = "disruptive"\n')
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    assert row.tier == "disruptive"


def test_an_address_tier_beats_its_family_from_real_toml(tiers_file):
    tiers_file('[tier.family]\n"pve:/nodes/qemu" = "disruptive"\n\n'
               '[tier]\n"pve:DELETE /nodes/{node}/qemu/{vmid}" = "destructive"\n')
    assert engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101").tier == "destructive"
    assert engine.resolve("pve", "POST", "/nodes/pve1/qemu/101/status/start").tier == "disruptive"


def test_a_tier_key_matching_no_address_is_refused_not_silently_inert(tiers_file):
    """The backends spell `{n}`, the vendor spells `{node}`. A mis-spelled key matched nothing,
    kept refusing, and let the author believe they had authored something."""
    with pytest.raises(ProximoError, match="match no published address"):
        tiers_file('[tier]\n"pve:DELETE /nodes/{n}/ceph/mon/{mid}" = "destructive"\n')


def test_an_absent_tiers_file_means_everything_strict_not_a_crash(tiers_file, monkeypatch):
    """`_tiers()` returned a bare {} and `table()` then did tiers["address"] -> KeyError, which
    the door laundered as the CALLER's typo. The docstring promised "absent = strict"."""
    real = engine.resources.files

    class _Pkg:
        def joinpath(self, name):
            if name == "tiers.toml":
                raise FileNotFoundError(name)
            return real("proximo.core").joinpath(name)

    monkeypatch.setattr(engine.resources, "files",
                        lambda pkg: _Pkg() if pkg == "proximo.core" else real(pkg))
    engine._tiers.cache_clear()
    engine.table.cache_clear()
    assert engine.resolve("pve", "GET", "/version").tier is None


def test_family_as_an_address_key_is_refused_with_a_reason(tiers_file):
    """`[tier]\\nfamily = "destructive"` hit dict("destructive") and crashed as a usage error."""
    with pytest.raises(ProximoError, match="sub-table"):
        tiers_file('[tier]\nfamily = "destructive"\n')


# --- H1/H2: the ledger keeps its OWN config, estate-wide --------------------------------------

def test_a_refusal_is_recorded_on_an_estate_with_no_pve(monkeypatch, tmp_path):
    """`conf = cfg` handed a PbsConfig to arm_state and AuditLedger, which have no such fields:
    a refusal became an AttributeError, and a receipt crashed AFTER the wire was touched."""
    # DRIVEN, not grepped. Asserting a symbol appears in the source passes while the line that
    # USES it is deleted -- so this writes a real receipt on an estate with no PVE configured,
    # which is the case `from_env()` could not serve and `from_env_ledger()` exists for.
    log = tmp_path / "ledger.log"
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    row = engine.resolve("pbs", "DELETE", "/admin/datastore/tank/snapshots")
    with pytest.raises(ProximoError):
        engine.execute(row, {}, path="/admin/datastore/tank/snapshots")
    assert log.exists(), "no receipt on a pbs-only estate: from_env() demanded the PVE triple"
    rec = json.loads(log.read_text().strip().splitlines()[-1])
    assert rec["action"] == "core.refuse"
    assert rec["target"] == "/admin/datastore/tank/snapshots"   # aimed-at, not the template


# --- M3: bind() must be total ------------------------------------------------------------------

def test_bind_refuses_a_path_whose_shape_does_not_match_the_row():
    row = engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101")
    with pytest.raises(ProximoError, match="segments"):
        engine.bind(row, "/nodes/pve1/qemu")


# --- brick 3: the vendor's own spellings and types ---------------------------------------------

def test_the_numbered_form_of_an_indexed_parameter_is_accepted():
    """The vendor publishes `net[n]`; the wire only ever takes `net0`.

    Comparing names verbatim refused the ONLY spelling Proxmox accepts and accepted `net[n]`,
    which means nothing to it.
    """
    row = engine.resolve("pve", "POST", "/nodes/pve1/qemu")
    assert "net[n]" in row.params
    for name in ("net0", "net31"):
        assert engine.check_args(row, {"vmid": "101", name: "virtio"})
    # `net[n]` is how the vendor WRITES the parameter, not a spelling Proxmox accepts. A later
    # lens caught this test asserting the defect its own subject was written to remove.
    for name in ("net[n]", "netfoo"):
        with pytest.raises(ProximoError, match="does not publish"):
            engine.check_args(row, {"vmid": "101", name: "virtio"})


def test_arguments_are_cast_to_the_types_the_vendor_published():
    """A CLI has only strings. pdm posts JSON and its own docstring says it wants real booleans,
    so a governed pdm mutation was sending "1" where PDM expects true."""
    row = engine.resolve("pve", "POST", "/nodes/pve1/qemu")
    out = engine.coerce_args(row, {"acpi": "1", "cores": "4", "name": "vm1"})
    assert out["acpi"] is True
    assert out["cores"] == 4
    assert out["name"] == "vm1"
    assert engine.coerce_args(row, {"acpi": "false"})["acpi"] is False


def test_the_governance_table_cannot_be_written_through():
    """`@cache` means every in-process door shares one object: a plain dict let one caller write
    a tier into the authoritative table and authorize a mutation for the whole process."""
    table = engine.table()
    with pytest.raises(TypeError):
        table[("pve", "GET", "/version")] = None
    row = engine.resolve("pve", "GET", "/version")
    with pytest.raises(TypeError):
        row.params["injected"] = {}



def test_an_unrecognised_boolean_is_refused_rather_than_defaulted_to_false():
    """59 mutating addresses publish a boolean of the dry-run/force shape. Mapping every unknown
    string to False turned "y" into a live run."""
    row = engine.resolve("pve", "POST", "/nodes/pve1/qemu")
    assert engine.coerce_args(row, {"acpi": "y"})["acpi"] is True
    assert engine.coerce_args(row, {"acpi": "off"})["acpi"] is False
    with pytest.raises(ProximoError, match="not a boolean"):
        engine.coerce_args(row, {"acpi": "enabled"})


def test_a_bad_number_speaks_the_spine_rather_than_raising_valueerror():
    row = engine.resolve("pve", "POST", "/nodes/pve1/qemu")
    with pytest.raises(ProximoError, match="not a valid integer"):
        engine.coerce_args(row, {"cores": "abc"})


def test_the_published_index_spelling_is_not_a_wire_spelling():
    """`net[n]` is how the vendor WRITES a repeated parameter, not something Proxmox accepts.
    The first fix named this half of the bug in its docstring and left it in the code."""
    row = engine.resolve("pve", "POST", "/nodes/pve1/qemu")
    assert engine._published(row, "net0")
    assert not engine._published(row, "net[n]")


def test_a_validation_failure_after_the_verdict_still_leaves_a_receipt(monkeypatch, armed, tmp_path):
    """An armed operator whose call passed govern and then failed argument validation used to
    leave nothing behind -- no receipt for exactly the calls that got furthest."""
    cfg = EstateCfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                    audit_log_path=str(tmp_path / "a.log"))
    monkeypatch.setattr(engine, "_client",
                        lambda product, c=None: pytest.fail("the wire was reached"))
    row = engine.Row(**{**engine.resolve("pve", "DELETE", "/nodes/pve1/qemu/101").__dict__,
                        "tier": "destructive"})
    with pytest.raises(ProximoError, match="does not publish"):
        engine.execute(row, {"nonsense": "1"}, cfg=cfg, ledger_cfg=cfg,
                       path="/nodes/pve1/qemu/101")
    rec = json.loads((tmp_path / "a.log").read_text().strip().splitlines()[-1])
    assert rec["action"] == "core.refuse" and rec["detail"]["needs"] == "arguments"


# --- the receipt goes through the keyed policy, so both doors write ONE chain ------------------

def test_a_shell_door_receipt_does_not_rotate_the_mcp_doors_keyed_chain(tmp_path):
    """Planted 2026-09-22 before the ledger moved: one MCP-door row (keyed, the default), one
    core receipt, then the MCP door opens the ledger again. The core wrote an UNKEYED row with
    `AuditLedger(path)`, so `open_ledger` read the file as unkeyed, sealed the whole keyed chain
    into an archive and started over with ONE row. "Same ledger" was the same file only.
    """
    from proximo.core.ledger import LedgerConfig, open_ledger
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    open_ledger(cfg).record("mcp.row", target="/x", mutation=False, outcome="ok", detail={})
    row = engine.resolve("pve", "GET", "/nodes/x/status")
    engine._record(cfg, "core.execute", row, outcome="ok", detail={}, called="/nodes/x/status")
    again = open_ledger(cfg)
    verdict = again.verify()
    assert verdict.ok and verdict.entries == 2, verdict
    assert not list(tmp_path.glob("audit.log.unkeyed-*")), "the chain was sealed and rotated"
    assert all('"alg":"hmac-sha256"' in line for line in (tmp_path / "audit.log").read_text().splitlines())


def test_plan_prints_json_a_script_can_parse(capsys):
    """`--plan` crashed on the read-only params view: MappingProxyType is not JSON. Found by
    the standalone-install proof, never by the suite, because nothing here had ever driven
    main() through --plan and read what it printed."""
    from proximo.core.doors import cli
    assert cli.main(["pve", "GET", "/nodes/x/status", "--plan"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["access"] == "read" and out["allowed"] is True
    assert cli.main(["pve", "DELETE", "/nodes/x/qemu/1", "--plan"]) == cli.EXIT_REFUSED
    out = json.loads(capsys.readouterr().out)
    assert out["allowed"] is False and out["needs"] in ("arm", "tier")
    assert isinstance(out["published_parameters"], dict) and "purge" in out["published_parameters"]


# --- a config for another plane answers for another plane -------------------------------------

def test_a_config_for_another_plane_is_refused_at_govern_and_at_the_wire(monkeypatch, tmp_path):
    """Lens, 2026-09-22: a pve Plane whose served token equalled its own arm source was handed to
    a tiered pbs mutation. govern() asked the PVE box whether it was armed, said yes, and execute()
    dialled the PVE host with the PVE token while the envelope and the receipt said pbs."""
    served, source = tmp_path / "served", tmp_path / "arm-source"
    served.write_text("armed\n")
    source.write_text("armed\n")      # two files, same bytes: the pve box IS armed
    pve = wire.Plane("pve", "https://pve.invalid:8006/api2/json", str(served), arm_source=str(source))
    row = engine.Row(**{**engine.resolve("pbs", "POST", "/admin/datastore/tank/gc").__dict__,
                        "tier": "disruptive"})
    verdict = engine.govern(row, cfg=pve)
    assert not verdict.allowed and "config given is for pve" in verdict.reason
    # and the wire refuses on its own, so a caller that skipped govern still cannot cross planes
    with pytest.raises(ProximoError, match="config given is for pve"):
        wire.client("pbs", pve)
    # the control: the SAME cfg on its own plane is allowed
    mine = engine.Row(**{**engine.resolve("pve", "POST", "/nodes/x/qemu/1/status/start").__dict__,
                         "tier": "disruptive"})
    assert engine.govern(mine, cfg=pve).allowed


# --- THE SIZE LAW: the governed door reports a read over the cap, like the raw door -----------

class _Body(Recorder):
    def __init__(self, body):
        super().__init__()
        self.body = body

    def call(self, method, path, params=None):
        self.calls.append((method, path, params))
        return self.body


def test_a_read_over_the_cap_is_reported_not_served_and_its_head_is_withheld(monkeypatch, cfg):
    """The wrappers bounded output by their defaults (`limit=100` on syslog); the door serves the
    vendor's, and PVE's syslog declares none. 2026-09-24: the governed door had no cap at all."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "4096")
    # distinct lines, as a log's are: no state to count, so the rows are the answer and are cut
    big = [{"n": i, "t": f"line {i:04d} " + "x" * 30} for i in range(500)]
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(big))
    out = engine.execute(engine.resolve("pve", "GET", "/nodes/{node}/syslog"), {}, cfg=cfg, ledger_cfg=cfg,
                         path="/nodes/pve1/syslog")
    # 2026-09-27, the 4K door: a LIST over the cap is cut by rows with its count, never a head
    assert out["truncated"] is True and out["cap"] == 4096 and out["bytes"] > 4096 and "head" not in out
    assert out["total"] == 500 and 0 < out["returned"] < 500 and len(out["data"]) == out["returned"]
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(big[:3]))   # the control: under the cap
    out = engine.execute(engine.resolve("pve", "GET", "/nodes/{node}/syslog"), {}, cfg=cfg, ledger_cfg=cfg,
                         path="/nodes/pve1/syslog")
    # lean by default: `n` is a counter and goes, `t` is a name and stays
    assert out["data"] == [{"t": r["t"]} for r in big[:3]] and out["total"] == 3 and "truncated" not in out


def test_the_head_of_a_truncated_read_is_cut_from_the_withheld_body(monkeypatch, cfg):
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "1024")
    rows = [{"id": f"f{i}", "server": "mail.example", "pass": "HUNTER2"} for i in range(200)]
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(rows))
    pmg = EstateCfg("pmg", "https://unreachable.invalid:8006/api2/json", "/dev/null", audit_log_path=cfg.audit_log_path)
    out = engine.execute(engine.resolve("pmg", "GET", "/config/fetchmail"), {}, cfg=pmg, ledger_cfg=pmg,
                         path="/config/fetchmail")
    # 2026-09-27, step 5: over the cap with a state to count (`server`), the answer is the tally
    # and the minority, built from the WITHHELD rows; the credential is still named, never served
    assert out["summarized"] is True and out["tally"]["server"] == {"mail.example": 200}
    assert "HUNTER2" not in json.dumps(out) and out["withheld"] == ["pass"]
    out = engine.execute(engine.resolve("pmg", "GET", "/config/fetchmail"), {}, cfg=pmg, ledger_cfg=pmg,
                         path="/config/fetchmail", fields="all")         # rows by name: the cut
    assert out["truncated"] is True and "HUNTER2" not in json.dumps(out) and out["withheld"] == ["pass"]


# --- a placeholder value that carries a slash: the vendor's `{cidr}` is ONE segment ------------
# The proof (09-25) found the ipset wrappers sending `192.0.2.0/24` as two segments where the
# vendor publishes one `{cidr}` segment. The door's answer is RFC 3986: the slash inside a value
# is `%2F`, the address is matched and sent on the encoded spelling, and the VALUE the vendor sees
# is the decoded one.

_CIDR_ENCODED = "/cluster/firewall/ipset/sentinelset/192.0.2.0%2F24"


def test_an_encoded_slash_is_one_segment_and_binds_the_vendors_value():
    row = engine.resolve("pve", "DELETE", _CIDR_ENCODED)
    assert row.address == "DELETE /cluster/firewall/ipset/{name}/{cidr}"
    assert engine.bind(row, _CIDR_ENCODED) == {"name": "sentinelset", "cidr": "192.0.2.0/24"}


def test_the_decoded_value_beside_the_encoded_path_is_not_a_conflict(monkeypatch, armed, cfg):
    """The vendor's value is `192.0.2.0/24`; a caller who names it beside the encoded path names
    the SAME thing once, and the wire sees the encoded path with nothing repeated in the query."""
    rec = Recorder()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: rec)
    row = _tiered(engine.resolve("pve", "DELETE", _CIDR_ENCODED))
    engine.execute(row, {"cidr": "192.0.2.0/24"}, cfg=cfg, ledger_cfg=cfg, path=_CIDR_ENCODED)
    assert rec.calls[-1] == ("DELETE", _CIDR_ENCODED, {})


def test_a_raw_slash_in_a_value_is_refused_and_the_refusal_names_the_encoding():
    """Nothing decodes before the segments are matched (the control), and the refusal is not a
    bare no: it says how the value goes."""
    with pytest.raises(ProximoError, match=r"%2F") as e:
        engine.resolve("pve", "DELETE", "/cluster/firewall/ipset/sentinelset/192.0.2.0/24")
    assert "/cluster/firewall/ipset/{name}/{cidr}" in str(e.value)


@pytest.mark.parametrize("path", [
    "/cluster/firewall/nosuchthing",                    # fewer segments than the nearest address
    "/nodes/pve1/qemu/101/config/extra/segment",        # three past /nodes/{node}/qemu/{vmid} (a typo)
    "/cluster/sdn/vnets/myvnet/ips/extra",              # one past a LITERAL tail (/cluster/sdn/vnets/{vnet}/ips)
    "/access/users/root@pam/tfa/oops/extra/segment",    # the lens's own false positive
    "/cluster/acme/nosuch/x/extra",                     # one past /cluster/acme/account/{name}, prefix off
])
def test_a_plain_wrong_address_is_not_told_to_encode(path):
    """The hint is for a value that split: the path matches the address up to its last
    placeholder and runs past it. A typo past a literal tail, or a short path, is not that."""
    with pytest.raises(ProximoError) as e:
        engine.resolve("pve", "DELETE", path)
    assert "%2F" not in str(e.value), str(e.value)


def test_forbid_sees_the_decoded_value_that_rode_the_path_encoded():
    """An operator's forbid entry is written the way the vendor spells the value. A value the
    caller sent as `%2F` must not slip past it on spelling alone."""
    from proximo.core import spine
    assert spine.forbid_refusal("pve", "DELETE", _CIDR_ENCODED, {}, extra=("192.0.2.0/24",)) is not None
    assert spine.forbid_refusal("pve", "DELETE", _CIDR_ENCODED, {}, extra=("198.51.100.0/24",)) is None


def test_an_encoded_separator_inside_a_value_never_reaches_forbid():
    """The lens's bypass: `%0A` decoded into the haystack's own field separator. The spelling
    gate refuses it before any address is matched, so forbid never sees a split value."""
    with pytest.raises(ProximoError, match="malformed"):
        engine.resolve("pve", "DELETE", "/cluster/firewall/ipset/sentinelset/192.0.2.0%0A%2F24")


# --- the spelling gate stands in front of EVERY verdict, not only in front of the wire ---------
# A lens found execute() governing (forbid, consent) a path nobody had resolved, refusing it only
# at its own late check before the wire, with no receipt. Both doors happened to reuse the
# resolved path. Convention is not a gate.

_CIDR_SPLIT = "/cluster/firewall/ipset/sentinelset/192.0.2.0%0A%2F24"


def test_plan_refuses_a_malformed_path_before_any_verdict(armed, cfg):
    row = _tiered(engine.resolve("pve", "DELETE", _CIDR_ENCODED))
    with pytest.raises(ProximoError, match="malformed"):
        engine.plan(row, {}, _CIDR_SPLIT, cfg=cfg, ledger_cfg=cfg)


def test_execute_receipts_a_malformed_path_and_never_dials(monkeypatch, armed, cfg):
    monkeypatch.setattr(engine, "_client",
                        lambda product, c=None: pytest.fail("a malformed path reached the wire"))
    row = _tiered(engine.resolve("pve", "DELETE", _CIDR_ENCODED))
    with pytest.raises(ProximoError, match="malformed"):
        engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path=_CIDR_SPLIT)
    rows = [json.loads(line) for line in open(cfg.audit_log_path)]
    assert rows and rows[-1]["action"] == "core.refuse", rows
    assert rows[-1]["detail"]["needs"] == "path"


def test_plan_refuses_a_malformed_read_path_before_any_verdict(cfg):
    """A READ used to get `Verdict(True, "read")` before the path was looked at: a lying preview
    that execute would then refuse at the wire (the lens's gap)."""
    row = engine.resolve("pve", "GET", "/nodes/pve1/status")
    with pytest.raises(ProximoError, match="malformed"):
        engine.plan(row, {}, "/nodes/pve1%0A/status", cfg=None, ledger_cfg=cfg)


# --- family grain reaches only what a family line may open ------------------------------------

@pytest.mark.parametrize("method,path,what", [
    ("GET", "/nodes/{node}/qemu/{vmid}/config", "a read"),
    ("POST", "/nodes/{node}/qemu/{vmid}/vncproxy", "an excluded tunnel"),
])
def test_a_family_line_does_not_stamp_its_tier_on_what_it_cannot_open(method, path, what):
    """`pve:/nodes/qemu` is a family line (2026-09-26). govern() refuses a read and a tunnel
    before it looks at the tier, but a plan printed the family's tier on them anyway: a read
    labelled destructive, a tunnel labelled granted. The tier is the grant; only an openable
    address can hold one. (The guest-agent subtree is gated too, but opt-in, and carries its OWN
    address tier — B5, test_core_agent_gate — so it is openable and NOT a case here.)"""
    row = engine.table()[("pve", method, path)]
    assert row.tier is None and row.why is None, (what, row.tier)


def test_the_family_line_does_not_stamp_the_opt_in_gated_agent_subtree():
    """The agent subtree is gated (openable=False for the family branch), so its tier comes only
    from its own address line, never the pve family grant: an agent read stays untiered, and an
    agent mutation carries exactly its authored tier, not whatever the family would stamp."""
    assert engine.table()[("pve", "GET", "/nodes/{node}/qemu/{vmid}/agent/get-users")].tier is None
    assert engine.table()[("pve", "POST", "/nodes/{node}/qemu/{vmid}/agent/exec")].tier == "destructive"
