"""The vendor's digest is the write lock (2026-11-05; John: "proxmox already provides everything").

Every config record Proxmox publishes carries a `digest`, and the write at that path accepts one:
the vendor refuses a write whose digest is not the record's ("detected modified configuration
file"). Proximo carries that value from the read to the write and builds nothing of its own:
the plan's read puts the digest among the arguments it shows, so the consent id (a hash over the
arguments) binds the operator's approval to THIS version of the record; the call sends it, so the
vendor is the lock. The caller's own digest always wins. A row that publishes no `digest`
parameter, or a read that shows none (over the cap, fenced, a collection, no twin), adds nothing.
"""
from __future__ import annotations

import json
import os

import httpx
import pytest

from proximo.core import engine, spine, wire
from proximo.core.errors import ProximoError
from test_core_undo import QEMU, QEMU_PATH, Wire, _tiered, _wire

PUT = "/nodes/{node}/qemu/{vmid}/config"
OTHER = "1111111111111111111111111111111111111111"


@pytest.fixture
def box(armed_plane):
    return armed_plane


def _row():
    return _tiered("pve", "PUT", PUT)


def _plan(box, monkeypatch, args, record=QEMU):
    w = _wire(monkeypatch, record)
    return w, engine.plan(_row(), args, cfg=box, path=QEMU_PATH)


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


class Vendor(Wire):
    """A wire that keeps the vendor's rule: a write whose digest is not the record's is refused 400."""

    def call(self, method, path, params=None):
        if method != "GET" and (params or {}).get("digest") not in (None, self.records[-1]["digest"]):
            self.calls.append((method, path, dict(params or {})))         # the request went; the vendor said no
            req = httpx.Request(method, "https://pve.invalid" + path)
            raise httpx.HTTPStatusError("detected modified configuration file", request=req,
                                        response=httpx.Response(400, request=req))
        return super().call(method, path, params)


# --- the plan: the digest it read is an argument, and the consent id covers it ---------------------

def test_the_plan_carries_the_digest_it_read_and_the_consent_id_binds_the_approval_to_it(box, monkeypatch):
    w, plan = _plan(box, monkeypatch, {"memory": "8192"})
    assert [c for c in w.calls if c[1] == QEMU_PATH] == [("GET", QEMU_PATH, {})]      # one read, nothing written
    assert plan["current"]["digest"] == QEMU["digest"]                                # the person sees the version
    assert plan["arguments"] == {"memory": "8192", "digest": QEMU["digest"]}          # and the call will send it
    assert plan["consent_id"] == spine.consent_id(
        "pve", "PUT", PUT, QEMU_PATH, {"memory": "8192", "digest": QEMU["digest"]}, box=box.base_url)
    # the lock is not a change: the diff and the no-op answer are what they were
    assert plan["change"] == {"memory": {"from": "4096", "to": "8192"}} and plan["noop"] is False


def test_a_plan_with_nothing_to_change_is_still_a_noop_with_the_lock_aboard(box, monkeypatch):
    _, plan = _plan(box, monkeypatch, {"memory": "4096"})
    assert plan["noop"] is True and plan["arguments"]["digest"] == QEMU["digest"]


def test_the_callers_own_digest_wins(box, monkeypatch):
    _, plan = _plan(box, monkeypatch, {"memory": "8192", "digest": OTHER})
    assert plan["arguments"]["digest"] == OTHER
    assert plan["consent_id"] == spine.consent_id(
        "pve", "PUT", PUT, QEMU_PATH, {"memory": "8192", "digest": OTHER}, box=box.base_url)


def test_a_row_that_publishes_no_digest_parameter_gets_none_even_when_the_record_carries_one(box, monkeypatch):
    row = _tiered("pve", "DELETE", "/nodes/{node}/qemu/{vmid}")          # the twin's record has a digest
    assert "digest" not in row.params
    _wire(monkeypatch, QEMU)
    plan = engine.plan(row, {}, cfg=box, path="/nodes/pve1/qemu/101")
    assert "digest" not in plan["arguments"] and plan["current"]["digest"] == QEMU["digest"]


def test_a_record_the_door_cannot_show_whole_lends_no_lock(box, monkeypatch):
    big = {**QEMU, "description": "n" * (spine.UNDO_MAX_BYTES + 1)}
    w, plan = _plan(box, monkeypatch, {"memory": "8192"}, big)
    assert "digest" not in plan["arguments"] and "over the door's cap" in plan["current"]["why"]
    engine.execute(_row(), {"memory": "8192"}, cfg=box, path=QEMU_PATH)
    assert w.mutations() == [("PUT", QEMU_PATH, {"memory": "8192"})]      # nothing invented at the write either


# --- the write: the digest rides to the vendor, and the vendor is the lock ------------------------

def test_the_write_sends_the_digest_the_read_back_carried_when_the_caller_sent_none(box, monkeypatch):
    w = _wire(monkeypatch, QEMU)
    engine.execute(_row(), {"memory": "8192"}, cfg=box, path=QEMU_PATH)
    assert w.mutations() == [("PUT", QEMU_PATH, {"memory": "8192", "digest": QEMU["digest"]})]
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"][-1]
    assert executing["detail"]["args"]["digest"] == QEMU["digest"]       # the receipt shows what was sent


def test_a_record_that_moved_since_the_plan_is_refused_by_the_vendor_in_its_own_words(box, monkeypatch):
    moved = {**QEMU, "memory": "2048", "digest": OTHER}
    w = Vendor(QEMU, moved)                                               # the plan reads one, the write finds another
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    plan = engine.plan(_row(), {"memory": "8192"}, cfg=box, path=QEMU_PATH)
    with pytest.raises(httpx.HTTPStatusError, match="modified configuration"):
        engine.execute(_row(), plan["arguments"], cfg=box, path=QEMU_PATH)
    assert w.mutations() == [("PUT", QEMU_PATH, {"memory": "8192", "digest": QEMU["digest"]})]
    error = [r for r in _rows() if r["action"] == "core.error"][-1]
    assert error["detail"]["status"] == 400 and error["detail"]["delivery"] != "never-sent"


# --- consent: a grant approves this version of the record ----------------------------------------

def test_a_grant_covers_the_plan_as_shown_with_its_digest_and_nothing_else(box, monkeypatch, tmp_path):
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    w, plan = _plan(box, monkeypatch, {"memory": "8192"})
    assert plan["allowed"] is False and plan["needs"] == "consent"
    (grants / plan["consent_id"]).write_text("")                        # the operator's hand, out of band
    with pytest.raises(ProximoError, match="consent"):                 # not the plan that was approved
        engine.execute(_row(), {"memory": "8192"}, cfg=box, path=QEMU_PATH)
    assert w.mutations() == []
    engine.execute(_row(), plan["arguments"], cfg=box, path=QEMU_PATH)
    assert w.mutations() == [("PUT", QEMU_PATH, {"memory": "8192", "digest": QEMU["digest"]})]
    assert spine.consent_state(plan["consent_id"], str(tmp_path)) != "granted"   # spent


def test_a_grant_for_one_version_does_not_write_another(box, monkeypatch, tmp_path):
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    moved = {**QEMU, "memory": "2048", "digest": OTHER}
    w = Vendor(QEMU, moved)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    plan = engine.plan(_row(), {"memory": "8192"}, cfg=box, path=QEMU_PATH)
    (grants / plan["consent_id"]).write_text("")
    with pytest.raises(httpx.HTTPStatusError, match="modified configuration"):
        engine.execute(_row(), plan["arguments"], cfg=box, path=QEMU_PATH)
    assert [m[2]["digest"] for m in w.mutations()] == [QEMU["digest"]]  # the approved version went, and only it


# --- the lens (2026-11-05): the verdict is judged on the id it shows, and the lock is shown whole --------

SHA256 = "f" * 64


def test_the_plan_is_judged_on_the_same_id_it_shows(box, monkeypatch, tmp_path):
    """Lens, BLOCKING: `govern` looked the grant up on the digest-less id, and the plan then showed the
    locked id with that verdict: its reason named one grant path, `consent_id` another; a grant at the
    shown id left the plan refused, a grant at the plain id let the call go with no binding at all."""
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    _, plan = _plan(box, monkeypatch, {"memory": "8192"})
    assert plan["consent_id"] in plan["reason"] and plan["consent"] == "required"      # one id, named once
    plain = spine.consent_id("pve", "PUT", PUT, QEMU_PATH, {"memory": "8192"}, box=box.base_url)
    assert plain != plan["consent_id"] and plain not in plan["reason"]
    (grants / plain).write_text("")                                                  # a grant for the wrong plan
    _, again = _plan(box, monkeypatch, {"memory": "8192"})
    assert again["allowed"] is False and again["needs"] == "consent"
    (grants / plan["consent_id"]).write_text("")                                     # the grant for THIS plan
    _, granted = _plan(box, monkeypatch, {"memory": "8192"})
    assert granted["allowed"] is True and granted["consent"] == "granted"
    assert granted["consent_id"] == plan["consent_id"]


def test_a_sha256_digest_is_shown_whole_to_the_model_so_the_plan_can_be_replayed(box, monkeypatch, tmp_path):
    """Lens, MAJOR: PBS and PDM digests are 64 hex chars, over the model view's short-value cut, so the
    model saw `[64 chars sha256:...]` and replayed the placeholder as the digest. The lock is shown whole."""
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    record = {**QEMU, "digest": SHA256}
    w, plan = _plan(box, monkeypatch, {"memory": "8192"}, record)
    assert plan["arguments"]["digest"] == SHA256 and "not_shown_whole" not in plan
    (grants / plan["consent_id"]).write_text("")
    engine.execute(_row(), plan["arguments"], cfg=box, path=QEMU_PATH)               # replayed as shown
    assert w.mutations() == [("PUT", QEMU_PATH, {"memory": "8192", "digest": SHA256})]


def test_the_lock_is_shown_even_when_the_arguments_are_more_than_the_model_view_names(box, monkeypatch):
    many = {f"description{i:02d}": "x" for i in range(engine.NAMES_SHOWN)}        # NAMES_SHOWN names already
    _, plan = _plan(box, monkeypatch, {**many, "memory": "8192"}, {**QEMU, "digest": SHA256})
    assert plan["arguments"]["digest"] == SHA256 and plan.get("arguments_more")


def test_the_second_govern_keeps_the_taint_verdict_of_the_first(box, monkeypatch, tmp_path):
    """The fold governs the plan AGAIN over the filled arguments: the only pillars whose answer can
    change are the two consent looks, and taint-requires-consent is one of them. With the session
    tainted and consent mandatory, the plan with a lock answers as the plan without one, id aside."""
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    monkeypatch.setenv("PROXIMO_TAINT_REQUIRE_CONSENT", "1")
    spine.mark_tainted(os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"]), "test")
    bare = {k: v for k, v in QEMU.items() if k != "digest"}
    _, without = _plan(box, monkeypatch, {"memory": "8192"}, bare)
    _, with_lock = _plan(box, monkeypatch, {"memory": "8192"})
    assert "digest" not in without["arguments"] and with_lock["arguments"]["digest"] == QEMU["digest"]
    for key in ("allowed", "needs", "consent"):
        assert without[key] == with_lock[key], key
    assert with_lock["allowed"] is False and with_lock["needs"] == "consent"
    said = [p["reason"].replace(p["consent_id"], "<id>") for p in (without, with_lock)]
    assert said[0] == said[1]
    (grants / with_lock["consent_id"]).write_text("")
    _, granted = _plan(box, monkeypatch, {"memory": "8192"})
    assert granted["allowed"] is True and granted["consent_id"] == with_lock["consent_id"]


def test_a_pbs_datastore_write_carries_its_64_character_digest_whole(box, monkeypatch):
    from proximo.core import wire
    pbs = wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", box.token_path)
    row = _tiered("pbs", "PUT", "/config/datastore/{name}")
    assert "digest" in row.params and row.params["digest"]["type"] == "string"
    record = {"name": "store1", "path": "/mnt/store1", "comment": "old", "digest": SHA256}
    w = _wire(monkeypatch, record)
    plan = engine.plan(row, {"comment": "new"}, cfg=pbs, path="/config/datastore/store1")
    assert plan["arguments"] == {"comment": "new", "digest": SHA256} and "not_shown_whole" not in plan
    engine.execute(row, plan["arguments"], cfg=pbs, path="/config/datastore/store1")
    assert w.mutations() == [("PUT", "/config/datastore/store1", {"comment": "new", "digest": SHA256})]


# --- the lab (2026-11-05): PBS and PDM hand the digest BESIDE the record; a delete-back replays its plan ----

PBS_DS = "/config/datastore/store1"
PBS_TOKEN_ROW = ("pbs", "POST", "/access/users/{userid}/token/{token-name}")
PBS_TOKEN_PATH = "/access/users/proximo@pbs/token/write"


def _pbs_plane(box, tmp_path):
    return wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", box.token_path)


def _real_pbs_wire(monkeypatch, records: dict[str, dict], seen: list):
    """The real wire client over a mock vendor that answers like PBS and PDM do: `{"data": <record>,
    "digest": <hex>}`, the digest beside the record (read live on the lab's PBS, 2026-11-05)."""
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path.replace("/api2/json", "", 1)
        if request.method == "GET":
            rec = records[path]
            record = {k: v for k, v in rec.items() if k != "digest"}
            return httpx.Response(200, json={"data": record, "digest": rec["digest"]})
        return httpx.Response(200, json={"data": None})

    def build(product, c=None):
        cfg = wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", records["__token__"])
        client = wire.Client(cfg)
        client._client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://pbs.invalid:8007/api2/json")
        return client
    monkeypatch.setattr(engine, "_client", build)


def test_a_pbs_record_whose_digest_rides_beside_it_still_lends_the_lock(box, monkeypatch, tmp_path):
    """PBS and PDM answer `{"data": record, "digest": hex}`: the digest is the envelope's, not the record's
    (live on the lab's PBS: /config/datastore/<name>, a user, a token, all so). The wire keeps it with the
    record, so the plan reads it, the consent id covers it, and the write sends it, as on PVE."""
    seen: list = []
    _real_pbs_wire(monkeypatch, {PBS_DS: {"name": "store1", "path": "/mnt/store1", "comment": "old", "digest": SHA256},
                                 "__token__": box.token_path}, seen)
    row = _tiered("pbs", "PUT", "/config/datastore/{name}")
    pbs = _pbs_plane(box, tmp_path)
    plan = engine.plan(row, {"comment": "new"}, cfg=pbs, path=PBS_DS)
    assert plan["current"]["digest"] == SHA256 and plan["arguments"] == {"comment": "new", "digest": SHA256}
    engine.execute(row, plan["arguments"], cfg=pbs, path=PBS_DS)
    put = [r for r in seen if r.method == "PUT"]
    from urllib.parse import parse_qs
    assert len(put) == 1
    assert parse_qs(put[0].content.decode()) == {"comment": ["new"], "digest": [SHA256]}        # PBS sends a form


def test_a_delete_back_under_consent_replays_the_plan_it_was_granted(box, monkeypatch, tmp_path):
    """Lens, then the lab: a PBS or PDM token read carries a digest (beside the record), and the token
    DELETE accepts one. Undo's delete-back planned with no arguments, so the grant was for an id with the
    digest, and then executed with none: refused. It now plans again and acts on that plan."""
    from proximo.core import undo
    from test_core_undo import CreateWire, _status_error
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    pbs = _pbs_plane(box, tmp_path)
    w = CreateWire(_status_error(404, path=PBS_TOKEN_PATH), answer={"tokenid": "proximo@pbs!write", "value": "S3CR3T"})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = _tiered(*PBS_TOKEN_ROW)
    p = engine.plan(row, {}, cfg=pbs, path=PBS_TOKEN_PATH)
    (grants / p["consent_id"]).write_text("")
    out = engine.execute(row, dict(p["arguments"]), cfg=pbs, path=PBS_TOKEN_PATH)
    ref = out["undo"]["id"]
    w2 = _wire(monkeypatch, {"tokenid": "proximo@pbs!write", "enable": True, "digest": SHA256})
    plan = undo.restore(ref, cfg=pbs)
    assert plan["arguments"] == {"digest": SHA256} and plan["needs"] == "consent"
    (grants / plan["consent_id"]).write_text("")
    done = undo.restore(ref, cfg=pbs, confirm=True)
    assert done["restores"] == ref
    assert w2.mutations() == [("DELETE", PBS_TOKEN_PATH, {"digest": SHA256})]
