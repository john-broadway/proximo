"""A rollback plan says the guest's description and tags are not reverted (capability
`rollback-keeps-description-and-tags`).

Proxmox does not snapshot a guest's `description` or `tags`, so a rollback leaves them as they
are now. 0.7.3 found it by dogfooding against a live cluster, where a description set after the
snapshot survived the rollback, and kept the sentence in the rollback plan until the 0.45 cut.
The family sentence on `/nodes/qemu` and `/nodes/lxc` says a rollback discards everything since
the snapshot, which is the claim this note corrects at the address that makes it.

The note rides the four rollback addresses (a guest's own, and the datacenter manager's proxy of
each) and holds for every call: the rollback's one argument, `start`, has nothing to do with it,
so the note is written `always = true` (John, 2026-10-25: always on). It reads no argument and no
target, so it is the same with no credential, unarmed, or with the read refused.
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core import engine

ADDRESSES = [
    ("pve", "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback", "/nodes/pve1/lxc/105/snapshot/before/rollback"),
    ("pve", "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback", "/nodes/pve1/qemu/100/snapshot/before/rollback"),
    ("pdm", "/pve/remotes/{remote}/lxc/{vmid}/snapshot/{snapname}/rollback",
     "/pve/remotes/dc1/lxc/105/snapshot/before/rollback"),
    ("pdm", "/pve/remotes/{remote}/qemu/{vmid}/snapshot/{snapname}/rollback",
     "/pve/remotes/dc1/qemu/100/snapshot/before/rollback"),
]
IDS = ["pve-lxc", "pve-qemu", "pdm-lxc", "pdm-qemu"]


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _says(out) -> list[str]:
    return [n["says"] for n in out.get("notes", [])]


@pytest.mark.parametrize("product,template,concrete", ADDRESSES, ids=IDS)
def test_the_rollback_plan_says_description_and_tags_are_not_reverted(monkeypatch, product, template, concrete):
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_TOKEN_PATH", "PROXIMO_PDM_API_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    row = engine.resolve(product, "POST", template)
    out = engine.plan(row, {}, concrete)
    says = _says(out)
    assert len(says) == 1
    assert "description" in says[0] and "tags" in says[0] and "not" in says[0]
    assert "snapshot" in out["notes"][0]["why"] and "description" in out["notes"][0]["why"]
    assert out["notes"][0]["why"] != says[0]


@pytest.mark.parametrize("product,template,concrete", ADDRESSES, ids=IDS)
def test_the_note_is_the_same_for_every_argument_the_rollback_takes(product, template, concrete):
    row = engine.resolve(product, "POST", template)
    plain = _says(engine.plan(row, {}, concrete))
    assert plain and _says(engine.plan(row, {"start": 1}, concrete)) == plain
    assert _says(engine.plan(row, {"start": False}, concrete)) == plain
    assert _says(engine.plan(row, {}, template)) == plain                  # the template spelling too


def test_only_the_rollbacks_carry_it():
    carried = sorted(r.key for r in engine.table().values()
                     if any(n.get("always") is True for n in r.notes))
    assert carried == sorted(f"{p}:POST {t}" for p, t, _ in ADDRESSES)
    # the snapshot's own create and delete say nothing about it
    for method, t in (("POST", "/nodes/{node}/qemu/{vmid}/snapshot"),
                      ("DELETE", "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}")):
        assert engine.resolve("pve", method, t).notes == ()


def test_the_note_gates_nothing(armed_plane, monkeypatch):
    class Wire:
        def call(self, method, path, params=None):
            return {}

    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    row = engine.resolve("pve", "POST", ADDRESSES[1][1])
    out = engine.plan(row, {}, ADDRESSES[1][2], cfg=armed_plane)
    assert out["allowed"] is True and out["notes"] and out["tier"] == "destructive"


def test_the_executing_row_carries_the_note(armed_plane, monkeypatch):
    class Wire:
        def call(self, method, path, params=None):
            if method == "GET" and path.endswith("/snapshot"):
                return [{"name": "before"}]
            if method == "GET" and path.endswith("/config"):
                return {"scsi0": "tank:vm-100-disk-0"}          # a blocking storage: no safety snapshot, one write
            if method == "GET" and path == "/storage":
                return [{"storage": "tank", "type": "zfspool"}]
            return None

    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    row = engine.resolve("pve", "POST", ADDRESSES[1][1])
    engine.execute(row, {}, cfg=armed_plane, path=ADDRESSES[1][2].replace("before", "before"))
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert [r["detail"].get("notes") for r in executing] == [[row.notes[0]["says"]]]
