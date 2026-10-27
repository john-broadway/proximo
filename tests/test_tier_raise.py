"""A TIER RAISED BY A VALUE: what needs no read is judged in govern's terms, on any box.

John, 2026-10-25: stopping or restarting the services that hold the door open (sshd, pveproxy,
pvedaemon, corosync, networking, ...) is `destructive`, while the address family stays
`restorable` for every other service. The service is a path value, not an argument, so one tier
per address could not say it: `[raise]` in `records/tiers.toml` names the addresses, the value,
the higher tier and why. A raise only raises: it never opens an untiered address and never lowers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from proximo.core import engine, wire
from proximo.core.errors import ProximoError

STOP = ("pve", "POST", "/nodes/{node}/services/{service}/stop")


@dataclass(frozen=True)
class EstateCfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


@pytest.fixture
def cfg(tmp_path):
    return EstateCfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                     audit_log_path=str(tmp_path / "audit.log"))


def _row(product="pve", action="stop"):
    return engine.resolve(product, "POST", f"/nodes/{{node}}/services/{{service}}/{action}")


@pytest.mark.parametrize("service", ["sshd", "pveproxy", "pvedaemon", "corosync", "networking", "pve-cluster"])
def test_stopping_a_service_that_holds_the_door_is_destructive(service):
    tier, why = engine.effective_tier(_row(), f"/nodes/pve1/services/{service}/stop", {})
    assert tier == "destructive" and why and "console" in why


def test_any_other_service_keeps_the_authored_tier():
    row = _row()
    assert row.tier == "restorable"
    assert engine.effective_tier(row, "/nodes/pve1/services/chronyd-not-listed/stop", {}) == ("restorable", None)


def test_starting_a_lockout_service_is_not_raised():
    row = _row(action="start")
    assert engine.effective_tier(row, "/nodes/pve1/services/sshd/start", {}) == (row.tier, None)


@pytest.mark.parametrize("spelled", ["SSHD", "sshd.service", " sshd "])
def test_the_value_is_matched_however_it_is_spelled(spelled):
    tier, _ = engine.effective_tier(_row(), f"/nodes/pve1/services/{spelled.strip()}/stop", {})
    assert tier == "destructive"


@pytest.mark.parametrize("product,service", [("pbs", "proxmox-backup-proxy"), ("pbs", "proxmox-backup"),
                                             ("pmg", "pmgproxy"), ("pmg", "pmgdaemon"), ("pbs", "sshd")])
def test_the_other_planes_raise_their_own_doors(product, service):
    tier, _ = engine.effective_tier(_row(product, "restart"), f"/nodes/n1/services/{service}/restart", {})
    assert tier == "destructive"


def test_a_template_path_cannot_be_judged_and_says_the_tier_may_rise():
    out = engine.plan(_row(), {}, "/nodes/{node}/services/{service}/stop")
    assert out["tier"] == "restorable" and "destructive" in out["tier_may_rise"]


def test_the_plan_shows_the_raised_tier_and_the_authored_one():
    out = engine.plan(_row(), {}, "/nodes/pve1/services/sshd/stop")
    assert out["tier"] == "destructive" and out["tier_authored"] == "restorable"
    assert "console" in out["tier_raised"]


def test_the_executing_receipt_carries_the_raised_tier(monkeypatch, cfg):
    from proximo.core import arm as ag
    monkeypatch.setattr(ag, "arm_state", lambda cfg=None: ag.ArmGateState(True, True, None))

    class Rec:
        def call(self, method, path, params=None):
            return {} if method == "GET" else "UPID:pve1:0001:0002:0003:srvstop:sshd:root@pam:"
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Rec())
    engine.execute(_row(), {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pve1/services/sshd/stop", wait=0)
    rows = [json.loads(line) for line in open(cfg.audit_log_path)]
    executing = [r for r in rows if r["outcome"] == "executing"]
    assert executing and executing[-1]["detail"]["tier"] == "destructive"


# --- the build holds a raise to raising ------------------------------------------------------------

_LINE = ('[raise.t]\naddresses = ["pve:POST /nodes/{node}/services/{service}/stop"]\n'
         'when = { service = ["sshd"] }\ntier = "destructive"\nwhy = "stopping it cuts the door until the console"\n')


def _tiers_with(extra: str) -> str:
    from pathlib import Path
    real = (Path(__file__).resolve().parent.parent / "records" / "tiers.toml").read_text(encoding="utf-8")
    head, sep, _ = real.partition("\n[raise.")
    return head + "\n" + extra


def test_a_planted_raise_is_what_the_engine_judges(records):
    table = records(**{"tiers.toml": _tiers_with(_LINE)})
    row = table[STOP]
    assert engine.effective_tier(row, "/nodes/pve1/services/sshd/stop", {})[0] == "destructive"
    assert engine.effective_tier(row, "/nodes/pve1/services/pveproxy/stop", {})[0] == "restorable"


@pytest.mark.parametrize("bad,words", [
    (_LINE.replace('"destructive"', '"read-back"'), "does not raise"),
    (_LINE.replace('"destructive"', '"restorable"'), "does not raise"),
    (_LINE.replace("service = ", "nosuch = "), "nosuch"),
    (_LINE.replace('["sshd"]', "[]"), "values"),
    (_LINE.replace("services/{service}/stop", "services/{service}/nosuch"), "matches no"),
    (_LINE.replace('why = "stopping it cuts the door until the console"', 'why = "x"'), "why"),
    (_LINE.replace('"destructive"', '"fatal"'), "vocabulary"),
])
def test_the_build_refuses_a_raise_that_would_not_raise(records, bad, words):
    with pytest.raises(ProximoError, match=words):
        records(**{"tiers.toml": _tiers_with(bad)})


def test_a_raise_never_opens_an_untiered_address(records):
    untiered = ('[raise.t]\naddresses = ["pve:POST /nodes/{node}/services/{service}/stop"]\n'
                'when = { service = ["sshd"] }\ntier = "destructive"\nwhy = "stopping it cuts the door"\n')
    text = _tiers_with(untiered).replace('"pve:/nodes/services" = ', '"pve:/nodes/services-gone" = ')
    with pytest.raises(ProximoError, match="no authored tier to raise"):
        records(**{"tiers.toml": text})
