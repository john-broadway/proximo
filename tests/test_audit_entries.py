"""audit_entries — reading the PROVE chain back, which nothing could do until now.

0.29.0 shipped principal-in-ledger: every entry records WHO asked. There was no tool
that read an entry back, so `audit_verify` (ok/entries/head) was the whole surface and
the answer to "who changed this guest" was unreachable through Proximo. A live qwen3:8b
found it on the real estate — asked what tool tells you who changed a config, it read
the catalog and correctly answered that none does. We shipped the claim without the
read path; this is the missing half, not a new capability.
"""
from __future__ import annotations

import pytest

from proximo import audit
from proximo.backends import ProximoError


def _ledger(tmp_path, entries):
    led = audit.AuditLedger(str(tmp_path / "audit.log"))
    for action, target, mutation, principal in entries:
        led.record(action, target=target, mutation=mutation,
                   detail={"note": "x"}, principal=principal)
    return led


def test_reads_back_who_did_what(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    _ledger(tmp_path, [
        ("pve_guest_config_set", "vmid=100", True, {"id": "ops-a", "via": "badge", "face": "http"}),
        ("pve_list_guests", "node=n1", False, None),
        ("pve_guest_power", "vmid=100", True, {"id": "ops-b", "via": "badge", "face": "stdio"}),
    ])
    out = audit.read_entries()
    assert out["total"] >= 3
    rows = out["entries"]
    assert rows[0]["action"] == "pve_guest_power", "newest first"
    assert rows[0]["principal"]["id"] == "ops-b"
    assert any(r["action"] == "pve_guest_config_set" and r["principal"]["id"] == "ops-a"
               for r in rows), "the who is not readable"


def test_filters_narrow_without_lying_about_the_total(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    _ledger(tmp_path, [
        ("pve_guest_config_set", "vmid=100", True, {"id": "ops-a", "via": "badge", "face": "http"}),
        ("pve_list_guests", "node=n1", False, None),
        ("pve_guest_power", "vmid=200", True, {"id": "ops-b", "via": "badge", "face": "stdio"}),
    ])
    only_100 = audit.read_entries(target="vmid=100")
    assert [r["action"] for r in only_100["entries"]] == ["pve_guest_config_set"]
    assert only_100["total"] == 3, "a filtered list must not masquerade as the census"
    assert only_100["matched"] == 1

    muts = audit.read_entries(mutations_only=True)
    assert {r["action"] for r in muts["entries"]} == {"pve_guest_config_set", "pve_guest_power"}

    who = audit.read_entries(principal="ops-a")
    assert [r["action"] for r in who["entries"]] == ["pve_guest_config_set"]


def test_unattributed_entries_say_so_rather_than_guessing(tmp_path, monkeypatch):
    """No principal recorded is a FACT about the ledger, never an inference about a person.
    An entry written before principals were configured must not read as anonymous-by-choice."""
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    _ledger(tmp_path, [("pve_list_guests", "node=n1", False, None)])
    row = audit.read_entries()["entries"][0]
    assert row["principal"] is None
    assert "no principal" in row["note"].lower() or "unattributed" in row["note"].lower()


def test_limit_is_bounded_and_honest(tmp_path, monkeypatch):
    """The ledger is unbounded; a read tool that returns all of it can bury a small model."""
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    _ledger(tmp_path, [("pve_list_guests", f"n={i}", False, None) for i in range(40)])
    out = audit.read_entries(limit=5)
    assert len(out["entries"]) == 5
    assert out["matched"] == 40
    assert out["truncated"] is True, "silently dropping rows reads as 'that was all of them'"


def test_missing_ledger_refuses_rather_than_reporting_an_empty_history(tmp_path, monkeypatch):
    """'No ledger' and 'nothing happened' are different facts; only one is knowable."""
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "nope.log"))
    with pytest.raises(ProximoError, match="no ledger|not exist"):
        audit.read_entries()
