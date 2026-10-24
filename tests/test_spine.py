"""The gates between the verdict and the wire: CONTAIN, FORBID, CONSENT, RATE, UNDO.

Every refusal test asserts three things: the wire was not reached, a receipt names the pillar
in `needs`, and the pillar was INERT with its env unset (zero behaviour change for a box that
never opted in). Every pillar has a control that proves the gate can go red, and the seam order
is pinned by a test that trips several at once and asserts which one speaks.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from proximo.core import engine, spine, wire
from proximo.core.errors import ProximoError


class Recorder:
    """A wire that records and answers, never dials."""

    def __init__(self, answer=None, fail: Exception | None = None):
        self.calls: list[tuple[str, str, dict]] = []
        self.answer = answer if answer is not None else {"ok": 1}
        self.fail = fail

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if self.fail and method != "GET":
            raise self.fail
        return self.answer


@pytest.fixture
def armed(monkeypatch, tmp_path):
    """An armed pve box with a token file, every pillar unset, receipts to a tmp ledger."""
    tok = tmp_path / "token"
    tok.write_text("secret-token")
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))
    for var in ("PROXIMO_CONTAIN_TRIP_PATH", "PROXIMO_SCOPE_PATH", "PROXIMO_ARM_TTL",
                "PROXIMO_FORBID", "PROXIMO_CONSENT_DIR", "PROXIMO_CONSENT_TTL_SECONDS",
                "PROXIMO_RATE_MAX", "PROXIMO_RATE_WINDOW", "PROXIMO_UNDO",
                "PROXIMO_TAINT_TRACK", "PROXIMO_TAINT_FORBID", "PROXIMO_TAINT_REQUIRE_CONSENT",
                "PROXIMO_TAINT_FENCE"):
        monkeypatch.delenv(var, raising=False)
    cfg = wire.Plane("pve", "https://pve.invalid:8006/api2/json", str(tok))
    rec = Recorder()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: rec)
    return cfg, rec, tmp_path


def _tiered(monkeypatch, product, method, path, tier="read-back"):
    """A published row with an authored tier, without loading a tiers file."""
    row = engine.resolve(product, method, path)
    return engine.Row(**{**row.__dict__, "tier": tier})


def _rows() -> list[dict]:
    with open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _refusals():
    return [r for r in _rows() if r["action"] == "core.refuse"]


CFG_PATH = "/nodes/pve1/qemu/101/config"


def _config_row(monkeypatch):
    return _tiered(monkeypatch, "pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")


# --- baseline: a tiered, armed mutation with every pillar unset executes ----------------------

def test_every_pillar_is_inert_when_unset(armed, monkeypatch):
    cfg, rec, _ = armed
    row = _config_row(monkeypatch)
    out = engine.execute(row, {"cores": "2"}, cfg=cfg, path=CFG_PATH)
    assert out["data"] == {"ok": 1}
    mutations = [c for c in rec.calls if c[0] != "GET"]
    assert mutations == [("PUT", CFG_PATH, {"cores": 2})]   # cast to the vendor's integer


def test_a_secret_shaped_argument_never_reaches_the_ledger_raw(armed, monkeypatch):
    """Bucket B (2026-09-23) retired the wrappers that kept a password, a key or a proxy's
    userinfo out of the ledger, each with its own key set. The engine's executing row carried
    `args` whole, and the undo row carried the vendor's read-back whole, so the door leaked what
    the wrappers guarded. One rule at the one seam now: a secret-NAMED argument is written as a
    fingerprint (sha256 + length, proving which value without the value), a URL's userinfo is
    masked to its host, and the same scrub runs over the read-back. An address stays an address:
    `alice@pam` is a userid, not a credential."""
    cfg, rec, tmp = armed
    rec.answer = {"http-proxy": "http://svc:PLANTED-BEFORE@proxy:3128", "cores": 1}
    row = _config_row(monkeypatch)
    engine.execute(row, {"cores": "2", "cipassword": "PLANTED-PASS", "description": "http://bob:PLANTED-URL@x:1",
                         "ciuser": "alice@pam"}, cfg=cfg, path=CFG_PATH)
    raw = open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8").read()
    for planted in ("PLANTED-PASS", "PLANTED-URL", "PLANTED-BEFORE"):
        assert planted not in raw, planted
    executing = [r for r in _rows() if r["outcome"] == "executing"][-1]["detail"]["args"]
    assert executing["cores"] == 2 and executing["ciuser"] == "alice@pam"   # cast to the vendor's int, then ledgered
    assert executing["description"] == "http://[redacted]@x:1"
    assert executing["cipassword"].startswith("[redacted sha256:") and "len:12" in executing["cipassword"]
    before = [r for r in _rows() if r["action"] == "core.undo_point"][-1]["detail"]["before"]
    assert before == {"http-proxy": "http://[redacted]@proxy:3128", "cores": 1}
    # the wire got the real values: redaction is the ledger's, never the call's
    assert [c for c in rec.calls if c[0] == "PUT"][0][2]["cipassword"] == "PLANTED-PASS"


def test_the_secret_name_rule_covers_the_vendors_credential_names():
    """Lens 5: `totp`, `otp` and the plural `authorized-tokens` slipped past the name rule; the
    deleted pbs TFA wrapper kept `totp` out of its plan on purpose. Word-bounded, so `hotplug`
    and `keyboard` stay readable."""
    hidden = ("password", "cipassword", "root-password-hashed", "secret", "secret_key", "totp", "otp",
              "authorized-tokens", "lock-token", "eab_hmac_key", "client-key", "keyring", "certkey", "sshkeys")
    shown = ("hotplug", "keyboard", "keysize", "tokenid", "token-name", "public_key", "master-pubkey",
             "cores", "description", "otp-mode")
    for name in hidden:
        assert str(engine.ledgered("v", name)).startswith("[redacted"), name
    for name in shown:
        assert engine.ledgered("v", name) == "v", name


def test_an_argument_refusal_names_the_parameter_never_a_secret_value(armed, monkeypatch):
    """The argument check echoed the offending VALUE into its reason (`cores='x' is not a valid
    integer`), and the reason is the core.refuse row. A secret sent in the wrong shape reached
    the raw ledger bytes that way (advisor, 2026-09-23). The reason shows a secret-named value
    as its fingerprint; a plain value is still shown, it is the caller's own input and the
    reader's only clue."""
    cfg, rec, _ = armed
    row = _tiered(monkeypatch, "pdm", "PUT", "/auto-install/tokens/{id}")
    pdm = wire.Plane("pdm", "https://pdm.invalid:8443", cfg.token_path)
    with pytest.raises(ProximoError) as exc:
        engine.execute(row, {"regenerate-secret": "PLANTED-HOOK"}, cfg=pdm, path="/auto-install/tokens/t1")
    assert "PLANTED" not in str(exc.value) and "regenerate-secret=" in str(exc.value), str(exc.value)
    raw = open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8").read()
    assert "PLANTED" not in raw
    assert rec.calls == []
    with pytest.raises(ProximoError, match="cores='x'"):
        engine.execute(_config_row(monkeypatch), {"cores": "x"}, cfg=cfg, path=CFG_PATH)


# --- CONTAIN -----------------------------------------------------------------------------------

def test_contain_trip_refuses_before_the_wire(armed, monkeypatch):
    cfg, rec, tmp = armed
    trip = tmp / "trip"
    trip.write_text("frozen by the operator")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    row = _config_row(monkeypatch)
    with pytest.raises(ProximoError, match="contain"):
        engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    r = _refusals()[-1]
    assert r["detail"]["needs"] == "contain" and "frozen by the operator" in r["detail"]["reason"]


def test_contain_env_set_but_absent_trip_is_not_contained(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(tmp / "no-such-trip"))
    row = _config_row(monkeypatch)
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert any(c[0] == "PUT" for c in rec.calls)


def test_contain_unreadable_trip_fails_closed(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(tmp / "token" / "not-a-dir"))  # ENOTDIR
    row = _config_row(monkeypatch)
    with pytest.raises(ProximoError, match="contain"):
        engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def test_contain_never_gates_a_read(armed, monkeypatch):
    cfg, rec, tmp = armed
    (tmp / "trip").write_text("")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(tmp / "trip"))
    engine.execute(engine.resolve("pve", "GET", "/nodes/pve1/status"), {}, cfg=cfg, path="/nodes/pve1/status")
    assert rec.calls


# --- SCOPE and LEASE: retired to the vendor, refused while configured ----------------------------

@pytest.mark.parametrize("env,value", [("PROXIMO_SCOPE_PATH", "/etc/proximo/scope.json"),
                                       ("PROXIMO_ARM_TTL", "3600"),
                                       ("PROXIMO_AUDIT_KEYED", "off"),
                                       ("PROXIMO_AUDIT_KEYED", "0")])
def test_a_retired_switch_still_set_refuses_loudly(armed, monkeypatch, env, value):
    """The core no longer keeps SCOPE or LEASE: a token's ACL and its own `expire` do, at
    Proxmox (2026-10-05). The ledger's opt-out went at the cut (2026-10-18): keyed, always. A box
    still configured for any of them must not quietly lose the gate it thinks it has (or, for the
    ledger, quietly GAIN one it opted out of), so the call is refused, before the wire, naming
    the way."""
    cfg, rec, _ = armed
    monkeypatch.setenv(env, value)
    with pytest.raises(ProximoError, match=f"{env} is set, and the core no longer reads it"):
        engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    r = _refusals()[-1]
    assert r["detail"]["needs"] == "config" and r["detail"]["env"] == env
    monkeypatch.delenv(env)
    engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert any(c[0] == "PUT" for c in rec.calls)



# --- FORBID ------------------------------------------------------------------------------------

def test_forbid_matches_method_path_and_argument(armed, monkeypatch):
    cfg, rec, _ = armed
    row = _config_row(monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "delete, cores=99")
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)            # a PUT: allowed
    rec.calls.clear()
    with pytest.raises(ProximoError, match="forbid"):                            # the argument
        engine.execute(row, {"memory": "2048", "cores": "99"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    dele = _tiered(monkeypatch, "pve", "DELETE", "/nodes/{node}/qemu/{vmid}")
    with pytest.raises(ProximoError, match="forbid"):                            # the method
        engine.execute(dele, {}, cfg=cfg, path="/nodes/pve1/qemu/101")
    assert rec.calls == []
    assert _refusals()[-1]["detail"]["needs"] == "forbid"


def _documented(env: str) -> str:
    # The example the operator copies, read from the shipped file, so the doc and the wall move together.
    example = (Path(__file__).parents[1] / "packaging" / "proximo.env.example").read_text()
    return next(ln.split("=", 1)[1] for ln in example.splitlines() if ln.startswith(f"#{env}="))


def test_forbid_matches_the_documented_plane_method_path_spelling(armed, monkeypatch):
    cfg, rec, _ = armed
    monkeypatch.setenv("PROXIMO_FORBID", _documented("PROXIMO_FORBID"))   # pve:DELETE /nodes,...
    dele = _tiered(monkeypatch, "pve", "DELETE", "/nodes/{node}/qemu/{vmid}")
    with pytest.raises(ProximoError, match="forbid"):
        engine.execute(dele, {}, cfg=cfg, path="/nodes/pve1/qemu/101")
    assert rec.calls == []
    engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)   # PUT /nodes: allowed
    assert any(c[0] == "PUT" for c in rec.calls)
    monkeypatch.setenv("PROXIMO_FORBID", "pbs:DELETE /nodes")                                # another plane's entry
    rec.calls.clear()
    engine.execute(dele, {}, cfg=cfg, path="/nodes/pve1/qemu/101")
    assert any(c[0] == "DELETE" for c in rec.calls)


def test_taint_forbid_matches_the_documented_plane_method_path_spelling(armed, monkeypatch):
    cfg, rec, _ = armed
    monkeypatch.setenv("PROXIMO_TAINT_FORBID", _documented("PROXIMO_TAINT_FORBID"))   # pve:PUT /cluster/firewall,...
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    engine.execute(_syslog_row(), {}, cfg=cfg, path=SYSLOG)
    fw = _tiered(monkeypatch, "pve", "PUT", "/cluster/firewall/options")
    with pytest.raises(ProximoError, match="after an untrusted read"):
        engine.execute(fw, {"enable": "0"}, cfg=cfg, path="/cluster/firewall/options")
    assert not any(c[0] == "PUT" for c in rec.calls)


def test_forbid_empty_entries_are_dropped_not_forbid_all(armed, monkeypatch):
    cfg, rec, _ = armed
    monkeypatch.setenv("PROXIMO_FORBID", " , ,")
    engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert any(c[0] == "PUT" for c in rec.calls)


# --- CONSENT -----------------------------------------------------------------------------------

def test_consent_id_is_derivable_from_the_plan(armed, monkeypatch):
    """The operator can only grant what the plan showed. The id in `plan` and the id the
    engine checks are the SAME function of the SAME inputs, and it ignores nothing the call
    sends to the vendor."""
    cfg, rec, tmp = armed
    row = _config_row(monkeypatch)
    v = engine.govern(row, cfg=cfg, path=CFG_PATH, args={"memory": "2048"})
    assert v.consent_id == spine.consent_id("pve", "PUT", row.path, CFG_PATH, {"memory": "2048"}, box=cfg.base_url)
    assert v.consent_id != spine.consent_id("pve", "PUT", row.path, CFG_PATH, {"memory": "4096"}, box=cfg.base_url)
    assert v.consent_id != spine.consent_id("pve", "PUT", row.path, "/nodes/pve1/qemu/102/config", {"memory": "2048"},
                                            box=cfg.base_url)


def test_consent_required_then_granted_then_consumed(armed, monkeypatch):
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    row = _config_row(monkeypatch)
    args = {"memory": "2048"}
    v = engine.govern(row, cfg=cfg, path=CFG_PATH, args=args)
    assert not v.allowed and v.needs == "consent" and v.consent_id
    with pytest.raises(ProximoError, match="consent"):
        engine.execute(row, args, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    assert _refusals()[-1]["detail"]["consent_id"] == v.consent_id
    (grants / v.consent_id).write_text("")                      # the human's hand, out of band
    assert engine.govern(row, cfg=cfg, path=CFG_PATH, args=args).allowed
    engine.execute(row, args, cfg=cfg, path=CFG_PATH)
    assert any(c[0] == "PUT" for c in rec.calls)
    assert not (grants / v.consent_id).exists(), "the grant was not consumed"
    rec.calls.clear()
    with pytest.raises(ProximoError, match="consent"):        # single use
        engine.execute(row, args, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def test_consent_expired_grant_is_refused(armed, monkeypatch):
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", "10")
    row = _config_row(monkeypatch)
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={}).consent_id
    g = grants / cid
    g.write_text("")
    old = time.time() - 100
    os.utime(g, (old, old))
    with pytest.raises(ProximoError, match="expired"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == [] and g.exists(), "an expired grant is not consumed"


def test_a_grant_owned_by_the_agents_own_user_is_refused(armed, monkeypatch):
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setattr(spine, "_euid", os.geteuid)            # the grant's owner IS the agent
    row = _config_row(monkeypatch)
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={}).consent_id
    (grants / cid).write_text("")
    with pytest.raises(ProximoError, match="agent's own user"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    assert (grants / cid).exists(), "a refused grant is not consumed"
    assert _refusals()[-1]["detail"]["consent"] == "self"


def test_a_symlinked_grant_to_another_users_file_is_still_refused(armed, monkeypatch):
    # lstat + S_ISREG runs before the owner look: a link is refused, never admitted as its target
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    row = _config_row(monkeypatch)
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={}).consent_id
    (tmp / "other").write_text("")
    (grants / cid).symlink_to(tmp / "other")
    with pytest.raises(ProximoError, match="consent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def _grant_cannot_be_unlinked(monkeypatch, grants):
    """A root-placed grant in a dir the agent's user can't unlink in: `remove` refuses inside the
    grant dir only, so every other removal (rate, taint markers) behaves as it really does."""
    real = os.remove

    def remove(path, *a, **kw):
        if os.path.dirname(os.path.abspath(path)) == str(grants):
            raise PermissionError(13, "Operation not permitted", path)
        return real(path, *a, **kw)
    monkeypatch.setattr(spine.os, "remove", remove)


def _consent_box(armed, monkeypatch):
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    row = _config_row(monkeypatch)
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={}).consent_id
    return cfg, rec, tmp, grants, row, cid


def _puts(rec):
    return [c for c in rec.calls if c[0] == "PUT"]


def test_a_grant_the_agent_cannot_delete_spends_exactly_once(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    _grant_cannot_be_unlinked(monkeypatch, grants)
    (grants / cid).write_text("")
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert len(_puts(rec)) == 1
    with pytest.raises(ProximoError, match="spent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert len(_puts(rec)) == 1, "one approval bought two writes"
    assert (grants / cid).exists()
    spends = [r for r in _rows() if r["action"] == "core.consent_spent"]
    assert len(spends) == 1
    assert spends[0]["detail"]["consent_id"] == cid
    assert set(spends[0]["detail"]["grant"]) == {"inode", "mtime_ns"}


def test_a_fresh_regrant_of_the_same_plan_is_admitted_once_more(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    _grant_cannot_be_unlinked(monkeypatch, grants)
    g = grants / cid
    g.write_text("")
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    later = time.time() + 5
    os.utime(g, (later, later))                                  # the operator approves again
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert len(_puts(rec)) == 2
    with pytest.raises(ProximoError, match="spent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert len(_puts(rec)) == 2


def test_a_spent_marker_dir_that_cannot_be_made_refuses(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    audit_dir = os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"])
    with open(os.path.join(audit_dir, ".proximo-consent-spent"), "w"):
        pass                                                    # a FILE where the marker dir goes
    (grants / cid).write_text("")
    with pytest.raises(ProximoError, match="consent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def test_a_rate_refusal_after_the_spend_leaves_the_grant_spent(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    _grant_cannot_be_unlinked(monkeypatch, grants)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "0")                  # 0 = refuse everything
    (grants / cid).write_text("")
    with pytest.raises(ProximoError, match="rate"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    monkeypatch.delenv("PROXIMO_RATE_MAX")
    with pytest.raises(ProximoError, match="spent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert _puts(rec) == []
    actions = [r["action"] for r in _rows()]
    assert "core.consent_spent" in actions
    assert any(r["detail"].get("needs") == "rate" for r in _refusals())


def test_two_racing_spends_of_one_grant_one_wins(armed, monkeypatch, tmp_path):
    # The racer that passed its look before the other's marker existed: only O_EXCL stops it
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    _grant_cannot_be_unlinked(monkeypatch, grants)
    (grants / cid).write_text("")
    first = spine.spend_consent(cid, str(tmp_path))
    assert isinstance(first, spine.Spend)
    monkeypatch.setattr(spine, "_refusal_for", lambda c, state: None)       # its look said clear
    second = spine.spend_consent(cid, str(tmp_path))
    assert isinstance(second, spine.Refusal) and second.detail["consent"] == "spent"


def test_a_spend_the_ledger_cannot_hold_touches_nothing_and_keeps_the_grant(armed, monkeypatch):
    # A full disk or a lost key at the spend row: the write is REQUIRED, so nothing reaches the
    # wire, and the marker is rolled back so the operator's one approval is not burned unreceipted
    from proximo.core import ledger
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    (grants / cid).write_text("")
    real = ledger.AuditLedger.record

    def record(self, action, **kw):
        if action == "core.consent_spent":
            raise OSError(28, "No space left on device")
        return real(self, action, **kw)
    monkeypatch.setattr(ledger.AuditLedger, "record", record)
    with pytest.raises(ProximoError):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == [], "the spend PROVE could not hold reached the wire"
    assert (grants / cid).exists(), "the grant was removed before its spend was receipted"
    monkeypatch.setattr(ledger.AuditLedger, "record", real)
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)               # the same approval, once
    assert len(_puts(rec)) == 1


def _swap_after_the_look(monkeypatch, then):
    """Run `then()` the moment the look returns: any later stat of the grant path sees the swap."""
    real = spine._look

    def look(cid, spent_dir):
        out = real(cid, spent_dir)
        if sys._getframe(1).f_code.co_name == "spend_consent":   # the spend's look, not govern's
            then()
        return out
    monkeypatch.setattr(spine, "_look", look)


def test_a_grant_swapped_between_the_look_and_the_spend_spends_what_was_judged(armed, monkeypatch):
    # One stat, judged and spent: the marker is keyed on the file the checks passed, and the core
    # never removes a file it did not judge (security review, 2026-10-24: a second lstat in the
    # spend read whatever had been put at the path since the look)
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    g = grants / cid
    g.write_text("")
    judged = os.lstat(g).st_ino
    swapped = []

    def swap():
        if not swapped:
            g.rename(tmp / "judged-grant")
            g.write_text("swapped in")
            swapped.append(True)
    _swap_after_the_look(monkeypatch, swap)
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert swapped, "the swap never ran: the case proves nothing"
    spend = [r for r in _rows() if r["action"] == "core.consent_spent"][-1]
    assert spend["detail"]["grant"]["inode"] == judged
    assert g.read_text() == "swapped in", "the core removed a file it never judged"
    monkeypatch.undo()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    g.unlink()
    (tmp / "judged-grant").rename(g)                     # the judged grant comes back
    audit_dir = os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"])
    assert spine.consent_state(cid, audit_dir) == "spent", "one approval, a second write"


def test_a_re_approval_touched_onto_the_same_file_is_not_removed(armed, monkeypatch):
    # same inode, new mtime: the operator approved again after the look; retire must leave it
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    g = grants / cid
    g.write_text("")
    later = time.time() + 5
    _swap_after_the_look(monkeypatch, lambda: os.utime(g, (later, later)))
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert g.exists(), "retire removed a re-approval it never judged"


def test_one_grant_renamed_onto_another_plan_spends_once_across_both(armed, monkeypatch, tmp_path):
    # a dir the agent can rename in (outside the recipe): the marker is the FILE's, not the plan's
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    (grants / cid).write_text("")
    first = spine.spend_consent(cid, str(tmp_path))
    assert isinstance(first, spine.Spend)
    other = "f" * 64
    (grants / cid).rename(grants / other)
    second = spine.spend_consent(other, str(tmp_path))
    assert isinstance(second, spine.Refusal) and second.detail["consent"] == "spent"


def test_plan_shows_a_spent_grant_as_spent(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    _grant_cannot_be_unlinked(monkeypatch, grants)
    (grants / cid).write_text("")
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert engine.plan(row, {}, cfg=cfg, path=CFG_PATH)["consent"] == "spent"


# --- the same-user opt-in: a speed bump, said to be one ----------------------------------------------

def _self_owned_grant(armed, monkeypatch, mode=None):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)
    monkeypatch.setattr(spine, "_euid", os.geteuid)            # the grant's owner IS the agent's user
    if mode is not None:
        monkeypatch.setenv("PROXIMO_CONSENT_SAME_USER", mode)
    (grants / cid).write_text("")
    return cfg, rec, tmp, grants, row, cid


def test_a_self_owned_grant_refusal_names_the_opt_in(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _self_owned_grant(armed, monkeypatch)
    with pytest.raises(ProximoError, match="PROXIMO_CONSENT_SAME_USER=advisory"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def test_advisory_admits_a_self_owned_grant_once_and_says_so(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _self_owned_grant(armed, monkeypatch, "advisory")
    _grant_cannot_be_unlinked(monkeypatch, grants)
    assert engine.plan(row, {}, cfg=cfg, path=CFG_PATH)["consent"] == "advisory"
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert len(_puts(rec)) == 1
    spend = [r for r in _rows() if r["action"] == "core.consent_spent"][-1]
    assert spend["detail"]["advisory"] is True
    with pytest.raises(ProximoError, match="spent"):              # still one approval, one write
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert len(_puts(rec)) == 1


def test_advisory_still_honours_the_ttl(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _self_owned_grant(armed, monkeypatch, "advisory")
    monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", "10")
    old = time.time() - 100
    os.utime(grants / cid, (old, old))
    with pytest.raises(ProximoError, match="expired"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def test_an_operator_owned_grant_is_not_marked_advisory(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _consent_box(armed, monkeypatch)    # owner is "another user"
    monkeypatch.setenv("PROXIMO_CONSENT_SAME_USER", "advisory")
    (grants / cid).write_text("")
    engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    spend = [r for r in _rows() if r["action"] == "core.consent_spent"][-1]
    assert "advisory" not in spend["detail"]


@pytest.mark.parametrize("value", ["yes", "Advisory", "1", " advisory"])
def test_a_bad_same_user_value_refuses_mutations_and_leaves_reads_alone(armed, monkeypatch, value):
    cfg, rec, tmp, grants, row, cid = _self_owned_grant(armed, monkeypatch, value)
    with pytest.raises(ProximoError, match="PROXIMO_CONSENT_SAME_USER"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    assert _refusals()[-1]["detail"]["needs"] == "config"


@pytest.mark.parametrize("value", ["", "  "])
def test_an_empty_same_user_value_is_unset_not_a_config_error(armed, monkeypatch, value):
    # "env unset = inert": a blank KEY= in an EnvironmentFile is unset, so a self grant is
    # refused as "self" (the default), and nothing else is refused for it
    cfg, rec, tmp, grants, row, cid = _self_owned_grant(armed, monkeypatch, value)
    with pytest.raises(ProximoError, match="agent's own user"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert _refusals()[-1]["detail"]["needs"] == "consent"


def test_an_advisory_plan_says_so_in_its_reason(armed, monkeypatch):
    cfg, rec, tmp, grants, row, cid = _self_owned_grant(armed, monkeypatch, "advisory")
    out = engine.plan(row, {}, cfg=cfg, path=CFG_PATH)
    assert out["allowed"] and "advisory" in out["reason"] and "not a lock" in out["reason"]


def test_consent_grant_dir_unreadable_fails_closed(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(tmp / "token"))   # a file, not a dir
    with pytest.raises(ProximoError, match="consent"):
        engine.execute(_config_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


def test_invalid_arguments_do_not_consume_a_grant(armed, monkeypatch):
    """Between the verdict and the wire: a call that fails validation must not spend the
    operator's grant, or one typo costs a human another trip to the grant dir."""
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    row = _config_row(monkeypatch)
    args = {"memory": "2048", "bogus": "x"}
    cid = spine.consent_id("pve", "PUT", row.path, CFG_PATH, args, box=cfg.base_url)
    (grants / cid).write_text("")
    with pytest.raises(ProximoError, match="does not publish"):
        engine.execute(row, args, cfg=cfg, path=CFG_PATH)
    assert (grants / cid).exists()


# --- RATE --------------------------------------------------------------------------------------

def test_rate_cap_is_per_box_and_refuses_when_spent(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "3600")
    row = _config_row(monkeypatch)
    engine.execute(row, {"memory": "1"}, cfg=cfg, path=CFG_PATH)
    engine.execute(row, {"memory": "2"}, cfg=cfg, path=CFG_PATH)
    rec.calls.clear()
    with pytest.raises(ProximoError, match="rate"):
        engine.execute(row, {"memory": "3"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    r = _refusals()[-1]
    assert r["detail"]["needs"] == "rate" and r["detail"]["rate_max"] == 2
    # another box has its own budget
    other = wire.Plane("pve", "https://other.invalid:8006/api2/json", cfg.token_path)
    engine.execute(row, {"memory": "4"}, cfg=other, path=CFG_PATH)
    assert any(c[0] == "PUT" for c in rec.calls)
    # the reservation lives beside the ledger, never in the package
    assert os.path.isdir(os.path.join(os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"]), ".proximo-rate"))


def test_consent_refusal_spends_no_rate_budget(armed, monkeypatch):
    """The load-bearing order: RATE after CONSENT, so doomed attempts cannot burn the budget
    the operator's own approved work needs."""
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    row = _config_row(monkeypatch)
    for _ in range(3):
        with pytest.raises(ProximoError, match="consent"):
            engine.execute(row, {"memory": "1"}, cfg=cfg, path=CFG_PATH)
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={"memory": "1"}).consent_id
    (grants / cid).write_text("")
    engine.execute(row, {"memory": "1"}, cfg=cfg, path=CFG_PATH)   # the ONE slot is still there
    assert any(c[0] == "PUT" for c in rec.calls)


@pytest.mark.parametrize("access", ["mutation", "read"])
def test_a_client_that_cannot_be_built_spends_nothing_and_is_receipted(armed, monkeypatch, access):
    """A config error (pmg credential AND password mode set; a secret file group can read) raised
    from building the client, AFTER consent was consumed and a rate slot reserved: the operator's
    one-shot grant burned for nothing and no row said why (lens 2026-09-28). The client is built
    before anything is spent now, and a build that fails is a refusal on the ledger."""
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")

    from proximo.core.secretfile import register_secret
    register_secret("PLANTEDSECRET4242")

    def broken(product, c=None):
        raise RuntimeError("set PROXIMO_PMG_CREDENTIAL_PATH or PROXIMO_PMG_PASSWORD_PATH, not both "
                           "(https://192.0.2.7:8006 PLANTEDSECRET4242)")

    monkeypatch.setattr(engine, "_client", broken)
    row = _config_row(monkeypatch)
    if access == "read":
        row = engine.resolve("pve", "GET", "/nodes/{node}/qemu/{vmid}/config")
    args = {"memory": "1"} if access == "mutation" else {}
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args=args).consent_id
    if cid:
        (grants / cid).write_text("")
    with pytest.raises(ProximoError, match="not configured to be called"):
        engine.execute(row, args, cfg=cfg, path=CFG_PATH)
    assert _refusals()[-1]["detail"]["needs"] == "config"
    reason = _refusals()[-1]["detail"]["reason"]
    assert "not both" in reason and "192.0.2.7" not in reason and "PLANTEDSECRET4242" not in reason
    if access == "mutation":
        assert (grants / cid).exists(), "the grant was consumed by an attempt that could never run"
        monkeypatch.setattr(engine, "_client", lambda product, c=None: rec)
        engine.execute(row, args, cfg=cfg, path=CFG_PATH)            # the grant AND the one rate slot
        assert any(c[0] == "PUT" for c in rec.calls)


def test_on_a_read_the_taint_refusal_still_speaks_before_the_config_one(armed, monkeypatch):
    """A read spends nothing, so its client is built after the taint mark, and a box with both
    faults reports `taint` as it always did (lens 2026-09-28: building first shadowed it)."""
    cfg, _rec, _ = armed
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")

    def no_mark(*_a, **_k):
        raise OSError("marker dir is a symlink")

    def broken(product, c=None):
        raise RuntimeError("Missing required pve env var")

    monkeypatch.setattr(engine.spine, "mark_tainted", no_mark)
    monkeypatch.setattr(engine, "_client", broken)
    row = next(r for r in engine.table().values() if r.untrusted and r.method == "GET" and r.product == "pve"
               and not r.gate and not r.excluded)
    concrete = row.path.replace("{node}", "pve1").replace("{vmid}", "100")
    concrete = __import__("re").sub(r"\{[^}]+\}", "x", concrete)
    with pytest.raises(ProximoError, match="taint marker"):
        engine.execute(row, {}, cfg=cfg, path=concrete)
    assert _refusals()[-1]["detail"]["needs"] == "taint"


def _http(status):
    import httpx
    req = httpx.Request("PUT", "https://pve.invalid:8006/api2/json/nodes/pve1/qemu/100/config")
    # the message the way httpx writes it: it names the URL, and the row must not (the control that
    # a bare "no" could not give: a planted str(exc) stayed green, lens 2026-09-30)
    msg = f"Client error '{status}' for url '{req.url}'"
    return httpx.HTTPStatusError(msg, request=req, response=httpx.Response(status, request=req))


class _FailEvery(Recorder):
    """Fails every call, the GET included: the read path and the UNDO read-back."""

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        raise self.fail


@pytest.mark.parametrize("site", ["read", "undo", "mutation"])
@pytest.mark.parametrize("fail,status", [(_http(403), 403), (_http(500), 500), (ConnectionError("down"), None)])
def test_a_failed_wire_call_records_the_vendors_status(armed, monkeypatch, site, fail, status):
    """A site on 0.44 (2026-09-29): the ledger said HTTPStatusError and nothing else, so a 403 (a
    missing privilege) read the same as a 500 (the vendor broke). The status rides with the type;
    a failure the vendor never answered carries no status (the control)."""
    cfg, rec, _ = armed
    wire_ = _FailEvery(fail=fail) if site in ("read", "undo") else Recorder(fail=fail)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: wire_)
    if site == "read":
        row = engine.resolve("pve", "GET", "/nodes/{node}/qemu/{vmid}/config")
    else:
        row = _config_row(monkeypatch)
    with pytest.raises((ProximoError, type(fail))):
        engine.execute(row, {} if site == "read" else {"memory": "1"}, cfg=cfg, path=CFG_PATH)
    last = _rows()[-1]
    assert last["action"] == ("core.refuse" if site == "undo" else "core.error")
    assert last["detail"]["error"] == type(fail).__name__
    assert last["detail"].get("status") == status
    assert "pve.invalid" not in json.dumps(last)          # the type and the number, never the URL


class _Raising(Exception):
    @property
    def response(self):
        raise RuntimeError("will not say")


class _Odd(Exception):
    def __init__(self, status):
        self.response = type("R", (), {"status_code": status})()


class _Bad(int):
    def __int__(self):
        raise RuntimeError("will not count")


@pytest.mark.parametrize("exc,status", [
    (_Raising(), None),        # a response that raises leaves the type alone, never the row unwritten
    (_Odd(True), None),        # a bool is not a status (it is an int to isinstance)
    (_Odd("403"), None),       # a string is not a status
    (_Odd(404), 404),
    (_Odd(__import__("http").HTTPStatus.FORBIDDEN), 403),   # an IntEnum is a status (lens 2)
    (_Odd(_Bad(403)), None),   # an int that will not count leaves the type alone, never the row unwritten (lens 4)
    (ConnectionError("down"), None),
])
def test_wire_error_is_total_over_what_a_failure_can_carry(exc, status):
    row = spine.wire_error(exc)
    assert row["error"] == type(exc).__name__
    assert row.get("status") == status and set(row) <= {"error", "status"}
    assert type(row.get("status", 0)) is int          # an IntEnum lands as the plain number (lens 3)


def test_every_ledger_error_key_is_built_by_wire_error():
    """The class, not the seven sites: a ledger row that names an error under its own literal
    (`"error": type(e).__name__`) records less than the rows beside it (pdm_fleet did, lens
    2026-09-30). Any `detail=` dict or `Refusal(...)` dict in the package carrying that literal
    is the defect; the planted control is the pdm_fleet line put back. It sees LITERALS at the
    call site and nothing else: a row built by a helper and handed over under a name (the reach
    mirror's was, lens 2) is the lens's to find, and gets a driven test of its own."""
    import ast
    from pathlib import Path
    src = Path(engine.__file__).resolve().parents[1]
    hits = []
    for f in sorted(src.rglob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dicts = [k.value for k in node.keywords if k.arg == "detail"]
            if isinstance(node.func, ast.Name) and node.func.id == "Refusal":
                dicts += node.args
            for d in dicts:
                if not isinstance(d, ast.Dict):
                    continue
                for key, val in zip(d.keys, d.values, strict=True):
                    if (isinstance(key, ast.Constant) and key.value == "error"
                            and isinstance(val, ast.Attribute) and val.attr == "__name__"):
                        hits.append(f"{f.relative_to(src.parent)}:{val.lineno}")
    assert hits == [], hits


def test_rate_garbled_cap_refuses_everything(armed, monkeypatch):
    cfg, rec, _ = armed
    monkeypatch.setenv("PROXIMO_RATE_MAX", "lots")
    with pytest.raises(ProximoError, match="rate"):
        engine.execute(_config_row(monkeypatch), {"memory": "1"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


@pytest.mark.parametrize("env,value", [("PROXIMO_ARM_TTL", "0"), ("PROXIMO_ARM_TTL", "-1"),
                                       ("PROXIMO_AUDIT_KEYED", "true"), ("PROXIMO_AUDIT_KEYED", "on")])
def test_a_retired_switch_set_to_what_the_core_does_anyway_refuses_nothing(armed, monkeypatch, env, value):
    """`PROXIMO_ARM_TTL=0` was LEASE's own explicit disable, and `PROXIMO_AUDIT_KEYED=true` asked
    for the keyed ledger the core always keeps: no gate was expected that is not there, none is
    lost, nothing to refuse."""
    cfg, rec, _ = armed
    monkeypatch.setenv(env, value)
    engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert any(c[0] == "PUT" for c in rec.calls)


# --- the ORDER ---------------------------------------------------------------------------------

def test_seam_order_contain_retired_forbid_taint_consent_rate(armed, monkeypatch):
    """Trip everything at once; the pillars speak in the 0.44 order. Peel one at a time."""
    cfg, rec, tmp = armed
    (tmp / "trip").write_text("")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(tmp / "trip"))
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(tmp / "scope.json"))
    monkeypatch.setenv("PROXIMO_FORBID", "config")
    monkeypatch.setenv("PROXIMO_TAINT_FORBID", "config")
    spine.mark_tainted(_audit_dir(), "pmg_quarantine_spam")
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setenv("PROXIMO_RATE_MAX", "0")
    row = _config_row(monkeypatch)
    order = []
    peel = [
        lambda: os.remove(tmp / "trip"),
        lambda: monkeypatch.delenv("PROXIMO_SCOPE_PATH"),
        lambda: monkeypatch.delenv("PROXIMO_FORBID"),
        lambda: spine.clear_taint(_audit_dir()),
        lambda: (grants / engine.govern(row, cfg=cfg, path=CFG_PATH, args={}).consent_id).write_text(""),
    ]
    for step in [None, *peel]:
        if step:
            step()
        with pytest.raises(ProximoError):
            engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
        order.append(_refusals()[-1]["detail"]["needs"])
    assert order == ["contain", "config", "forbid", "taint", "consent", "rate"]
    assert rec.calls == []


def test_arm_and_tier_still_come_first(armed, monkeypatch):
    cfg, rec, tmp = armed
    (tmp / "trip").write_text("")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(tmp / "trip"))
    # Since family grain (2026-09-26) the guest config address carries the pve:/nodes/qemu family
    # tier; the untiered row this test needs is made in memory, which is what govern() reads.
    row = engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")
    untiered = engine.Row(**{**row.__dict__, "tier": None, "why": None})
    assert untiered.tier is None
    assert engine.govern(untiered, cfg=cfg, path=CFG_PATH).needs == "tier"
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, False, "disarmed"))
    assert engine.govern(_config_row(monkeypatch), cfg=cfg, path=CFG_PATH).needs == "arm"


# --- PROVE: the executing pre-record and the intent ---------------------------------------------

def test_a_mutation_is_recorded_before_the_wire_and_closed_after(armed, monkeypatch):
    """SIGKILL between the call and the receipt used to leave nothing in the core. Now the
    chain holds an `executing` row with the whole preview and an intent, and the terminal row
    closes it; a stranded one is what `in_flight` finds."""
    from proximo.core.ledger import in_flight
    cfg, rec, _ = armed
    row = _config_row(monkeypatch)
    engine.execute(row, {"cores": "2"}, cfg=cfg, path=CFG_PATH)
    rows = [r for r in _rows() if r["action"] == "core.execute"]
    assert [r["outcome"] for r in rows] == ["executing", "ok"]
    pre, post = rows
    assert pre["detail"]["intent"] == post["detail"]["intent"]
    assert pre["detail"]["args"] == {"cores": 2} and pre["detail"]["tier"] == "read-back"
    assert pre["target"] == CFG_PATH
    assert in_flight(_rows()) == []


def test_a_wire_failure_closes_the_interval_as_error(armed, monkeypatch):
    cfg, rec, _ = armed
    rec.fail = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    rows = [r for r in _rows() if r["action"].startswith("core.")]
    assert [r["outcome"] for r in rows][-2:] == ["executing", "error"]
    from proximo.core.ledger import in_flight
    assert in_flight(_rows()) == []


def test_a_stranded_executing_row_is_visible(armed, monkeypatch):
    """CONTROL for the pre-record: kill the process between the wire and the receipt (here:
    the recorder raises BaseException the engine does not catch) and the row stays open."""
    from proximo.core.ledger import in_flight
    cfg, rec, _ = armed

    class Died(BaseException):
        pass

    def call(method, path, params=None):
        if method == "GET":
            return {}          # the undo read-back succeeds; the process dies on the mutation
        raise Died()
    rec.call = call
    with pytest.raises(Died):
        engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert len(in_flight(_rows())) == 1


# --- UNDO: read back what the vendor publishes, before changing it ---------------------------

def test_undo_captures_the_published_read_of_the_same_address(armed, monkeypatch):
    cfg, rec, _ = armed
    rec.answer = {"memory": 1024, "cores": 2}
    row = _config_row(monkeypatch)
    out = engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls[0] == ("GET", CFG_PATH, {})
    undo = [r for r in _rows() if r["action"] == "core.undo_point"]
    assert len(undo) == 1
    assert undo[0]["detail"]["before"] == {"memory": 1024, "cores": 2}
    assert undo[0]["detail"]["read"] == "GET /nodes/{node}/qemu/{vmid}/config"
    assert out["undo"] == {"captured": True, "read": "GET /nodes/{node}/qemu/{vmid}/config",
                           "id": undo[0]["entry_hash"][:12]}        # the capture's id, for a restore (B2)


def test_undo_says_so_when_the_vendor_publishes_no_read(armed, monkeypatch):
    cfg, rec, _ = armed
    row = _tiered(monkeypatch, "pve", "POST", "/nodes/{node}/qemu/{vmid}/status/start")
    out = engine.execute(row, {}, cfg=cfg, path="/nodes/pve1/qemu/101/status/start")
    assert [c[0] for c in rec.calls] == ["POST"]
    assert out["undo"]["captured"] is False and "publishes no" in out["undo"]["why"]


def test_undo_capture_failure_refuses_the_mutation(armed, monkeypatch):
    """No net, no risky act: if the read-back the vendor DOES publish cannot be taken, the
    mutation does not run."""
    cfg, rec, _ = armed

    def call(method, path, params=None):
        if method == "GET":
            raise RuntimeError("read failed")
        rec.calls.append((method, path, params))
        return {}
    rec.call = call
    with pytest.raises(ProximoError, match="undo"):
        engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []
    assert _refusals()[-1]["detail"]["needs"] == "undo"


def test_undo_can_be_switched_off_and_the_receipt_says_so(armed, monkeypatch):
    cfg, rec, _ = armed
    monkeypatch.setenv("PROXIMO_UNDO", "off")
    out = engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert [c[0] for c in rec.calls] == ["PUT"]
    assert out["undo"] == {"captured": False, "why": "PROXIMO_UNDO=off"}


def test_undo_capture_is_bounded(armed, monkeypatch):
    cfg, rec, _ = armed
    rec.answer = {"blob": "x" * (spine.UNDO_MAX_BYTES + 1)}
    engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    d = [r for r in _rows() if r["action"] == "core.undo_point"][0]["detail"]
    assert d["before"]["truncated"] is True and d["before"]["bytes"] > spine.UNDO_MAX_BYTES
    assert len(d["before"]["sha256"]) == 64


# --- the plan tells the operator everything the gates will ask --------------------------------

def test_plan_reports_the_pillars_and_touches_nothing(armed, monkeypatch, tmp_path):
    from proximo.core.doors import mcp as door
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setenv("PROXIMO_API_BASE_URL", cfg.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", cfg.token_path)
    monkeypatch.setattr(engine.wire.Plane, "from_env", classmethod(lambda cls, p: cfg))
    row = _config_row(monkeypatch)
    monkeypatch.setattr(engine, "resolve", lambda p, m, pa: row)
    out = door.plan("pve", "PUT", CFG_PATH, {"memory": "2048"})
    assert out["needs"] == "consent"
    assert out["consent_id"] == spine.consent_id("pve", "PUT", row.path, CFG_PATH, {"memory": "2048"}, box=cfg.base_url)
    assert out["grant_path"] == str(grants / out["consent_id"])
    # B1 (2026-09-30): a mutation's plan reads the target as it stands, ONE governed GET of the
    # twin, receipted as the read it is; the plan itself still writes nothing and places no grant.
    assert rec.calls == [("GET", CFG_PATH, {})] and not list(grants.iterdir())
    assert [(r["action"], r["outcome"]) for r in _rows()] == [("core.execute", "ok")]
    assert out["change"] == {"memory": {"from": None, "to": "2048"}}   # a key the record lacks is new
    assert out["noop"] is False


# --- lens round 1 (2026-09-22): what the suite did not cover -------------------------------------

def test_a_ledger_that_cannot_be_written_blocks_the_mutation(armed, monkeypatch):
    """LENS B1. `_record` was best-effort for EVERYTHING, so a box whose ledger could not be
    opened ran the mutation with zero trace and handed back a normal envelope. A refusal may
    go unrecorded (it refuses anyway); a MUTATION with no `executing` row must not run."""
    cfg, rec, tmp = armed
    blocked = tmp / "blocked"
    blocked.write_text("not a directory")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(blocked / "audit.log"))   # ENOTDIR on open
    with pytest.raises(ProximoError, match="ledger"):
        engine.execute(_config_row(monkeypatch), {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert [c for c in rec.calls if c[0] != "GET"] == [], "the mutation ran with no receipt"


def test_a_read_still_answers_when_the_ledger_cannot_be_written(armed, monkeypatch):
    """The other half of B1: bookkeeping must not outrank a READ, which changes nothing."""
    cfg, rec, tmp = armed
    blocked = tmp / "blocked"
    blocked.write_text("not a directory")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(blocked / "audit.log"))
    out = engine.execute(engine.resolve("pve", "GET", "/nodes/pve1/status"), {}, cfg=cfg, path="/nodes/pve1/status")
    assert out["data"] == {"ok": 1}


def test_a_symlinked_or_irregular_grant_is_not_a_grant(armed, monkeypatch):
    """LENS non-blocking 3: a symlink to any fresh file, or a directory, at the grant path read
    as a grant. A grant is a REGULAR file the operator placed, nothing else."""
    cfg, rec, tmp = armed
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    row = _config_row(monkeypatch)
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={}).consent_id
    os.symlink(cfg.token_path, grants / cid)                 # fresh mtime, wrong kind
    with pytest.raises(ProximoError, match="consent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == [] and os.path.lexists(grants / cid), "the symlink was consumed"
    os.remove(grants / cid)
    (grants / cid).mkdir()
    with pytest.raises(ProximoError, match="consent"):
        engine.execute(row, {}, cfg=cfg, path=CFG_PATH)
    assert rec.calls == []


# --- a target's envelope joins the env's (the remotes brick, 2026-09-22) ------------------------

def test_tightest_cap_wins_and_a_garbled_target_cap_refuses_everything():
    assert spine.tightest((None, 60), (None, None)) == (None, 60)
    assert spine.tightest((None, 60), (5, None)) == (5, 60)
    assert spine.tightest((10, 60), (500, 86400)) == (500, 86400)   # 500/day beats 10/min
    assert spine.tightest((500, 86400), (10, 60)) == (500, 86400)
    assert spine.tightest((10, 60), (0, None))[0] == 0
    assert spine.tightest((10, 60), (10, 60)) == (10, 60)


def test_a_garbled_target_window_refuses_everything_never_reads_as_unset(tmp_path):
    """Lens 4 (2026-09-23): a target `rate_window <= 0` was read as "unset, default 60s", and with
    no rate_max beside it the window was never looked at: (None, -1) came back UNBOUNDED. 0.44's
    `_rate_candidate` calls a non-positive window garbled and collapses the box to 0 (fail-closed),
    and so does the spine now. The env cap and its window are not overridden by the garble."""
    assert spine.tightest((None, 60), (None, -1)) == (0, 60)
    assert spine.tightest((None, 60), (5, 0)) == (0, 60)
    assert spine.tightest((10, 120), (None, -1)) == (0, 120)
    assert spine.tightest((10, 60), (None, 3600)) == (10, 60)       # a window alone is not a cap
    refusal = spine.reserve_rate("https://box.invalid", str(tmp_path), (None, -1))
    assert refusal is not None and refusal.needs == "rate"


def test_a_targets_forbid_adds_to_the_floor_never_replaces_it(armed, monkeypatch):
    cfg, rec, _ = armed
    monkeypatch.setenv("PROXIMO_FORBID", "cores=9")
    row = _config_row(monkeypatch)
    edge = wire.Plane("pve", cfg.base_url, cfg.token_path, forbid=("memory=1",))
    assert engine.govern(row, cfg=edge, path=CFG_PATH, args={"cores": "9"}).needs == "forbid"    # the floor
    assert engine.govern(row, cfg=edge, path=CFG_PATH, args={"memory": "1"}).needs == "forbid"   # the target's
    assert engine.govern(row, cfg=edge, path=CFG_PATH, args={"cores": "2"}).allowed


# --- TAINT: the address record, the mark at the seam, the two couplings ------------------------
# The 0.44 server marked by tool name in `_audited`; the engine marks by ADDRESS (taint.toml)
# before the wire, and its mutations honour the same marker the wrappers write: one file, one
# copy of the functions (`spine`), so a read through either door walls a mutation through both.

SYSLOG = "/nodes/pve1/syslog"
STATUS = "/nodes/pve1/status"


def _audit_dir() -> str:
    return os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"])


def _marker_present() -> bool:
    return os.path.exists(os.path.join(_audit_dir(), ".proximo-taint", "tainted"))


def _syslog_row() -> engine.Row:
    row = engine.resolve("pve", "GET", "/nodes/{node}/syslog")
    assert row.untrusted and row.channel
    return row


def test_taint_forbid_walls_a_mutation_after_an_untrusted_read_with_no_consent_escape(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_FORBID", "config")
    row = _config_row(monkeypatch)
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert rec.calls[-1][0] == "PUT"
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    engine.execute(_syslog_row(), {}, cfg=cfg, path=SYSLOG)   # the engine's own mark
    with pytest.raises(ProximoError, match="after an untrusted read"):
        engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    r = _refusals()[-1]
    assert r["detail"]["needs"] == "taint" and r["detail"]["tainted"] is True
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={"memory": "2048"}).consent_id
    (grants / cid).write_text("")
    with pytest.raises(ProximoError, match="after an untrusted read"):
        engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert (grants / cid).exists()
    assert [c[0] for c in rec.calls if c[0] != "GET"] == ["PUT"]   # the one allowed mutation; GETs are undo


def test_an_untrusted_read_is_labelled_and_inert_with_the_env_unset(armed, monkeypatch):
    cfg, rec, tmp = armed
    out = engine.execute(_syslog_row(), {}, cfg=cfg, path=SYSLOG)
    assert out["untrusted"] is True and out["data"] == rec.answer
    assert not _marker_present()
    row = [r for r in _rows() if r["action"] == "core.execute"][-1]
    assert "untrusted" not in row["detail"]          # the 0.44 invariant: env unset, no trace


def test_a_read_outside_the_record_never_marks(armed, monkeypatch):
    """The control: same env, an address the record does not name."""
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    assert not row.untrusted
    out = engine.execute(row, {}, cfg=cfg, path=STATUS)
    assert out["untrusted"] is False and not _marker_present()


def test_a_raising_wire_still_marks(armed, monkeypatch):
    """An error body can carry attacker-shaped bytes too: the mark lands BEFORE the wire."""
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    class Down(Recorder):
        def call(self, method, path, params=None):
            raise RuntimeError("wire down")
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Down())
    with pytest.raises(RuntimeError):
        engine.execute(_syslog_row(), {}, cfg=cfg, path=SYSLOG)
    assert _marker_present()


def test_a_marker_that_cannot_be_written_refuses_the_read(armed, monkeypatch):
    """A taint-tracking box that cannot write the marker must not serve the bytes untracked."""
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    os.symlink(str(tmp / "elsewhere"), os.path.join(_audit_dir(), ".proximo-taint"))
    with pytest.raises(ProximoError, match="taint marker could not be written"):
        engine.execute(_syslog_row(), {}, cfg=cfg, path=SYSLOG)
    assert rec.calls == []
    assert _refusals()[-1]["detail"]["needs"] == "taint"


def test_the_fence_wraps_untrusted_data_when_asked_and_implies_no_tracking(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    out = engine.execute(_syslog_row(), {}, cfg=cfg, path=SYSLOG)
    assert out["data"]["proximo_untrusted"] is True and out["data"]["source"] == "pve:GET /nodes/{node}/syslog"
    assert json.loads(out["data"]["data"]) == rec.answer
    assert not _marker_present()
    clean = engine.execute(engine.resolve("pve", "GET", "/nodes/{node}/status"), {}, cfg=cfg, path=STATUS)
    assert clean["data"] == rec.answer




def test_taint_forbid_is_inert_untainted_and_only_matches_its_entries(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_FORBID", "firewall")
    row = _config_row(monkeypatch)
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    spine.mark_tainted(_audit_dir(), "x")
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)   # tainted, no match: allowed
    assert [c[0] for c in rec.calls if c[0] != "GET"] == ["PUT", "PUT"]


def test_taint_require_consent_refuses_without_a_grant_dir_then_demands_a_grant(armed, monkeypatch):
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_TAINT_REQUIRE_CONSENT", "1")
    row = _config_row(monkeypatch)
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)   # untainted: nothing changes
    spine.mark_tainted(_audit_dir(), "x")
    with pytest.raises(ProximoError, match="PROXIMO_CONSENT_DIR is not configured"):
        engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    r = _refusals()[-1]
    assert r["detail"]["needs"] == "consent" and r["detail"]["taint_required"] is True
    grants = tmp / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    with pytest.raises(ProximoError, match="consent required"):
        engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert _refusals()[-1]["detail"]["taint_required"] is True
    cid = engine.govern(row, cfg=cfg, path=CFG_PATH, args={"memory": "2048"}).consent_id
    (grants / cid).write_text("")
    engine.execute(row, {"memory": "2048"}, cfg=cfg, path=CFG_PATH)
    assert not (grants / cid).exists() and rec.calls[-1][0] == "PUT"


def test_plan_reports_the_classification_and_the_taint_wall(armed, monkeypatch):
    from proximo.core.doors import mcp as door
    cfg, rec, tmp = armed
    monkeypatch.setenv("PROXIMO_API_BASE_URL", cfg.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", cfg.token_path)
    monkeypatch.setattr(engine.wire.Plane, "from_env", classmethod(lambda cls, p: cfg))
    out = door.plan("pve", "GET", SYSLOG)
    assert out["untrusted"] is True and "log" in out["channel"] and out["allowed"]
    assert door.plan("pve", "GET", STATUS)["untrusted"] is False
    monkeypatch.setenv("PROXIMO_TAINT_FORBID", "config")
    spine.mark_tainted(_audit_dir(), "x")
    row = _config_row(monkeypatch)
    monkeypatch.setattr(engine, "resolve", lambda p, m, pa: row)
    out = door.plan("pve", "PUT", CFG_PATH, {"memory": "2048"})
    assert out["needs"] == "taint" and rec.calls == [("GET", CFG_PATH, {})]   # B1: the read, not the PUT
