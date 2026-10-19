"""THE DOWNLOAD LANE: a byte stream the vendor serves lands on THIS host's disk, never in an answer.

Parity rows L6 (0.44's pve_file_restore_download and pbs_file_download: bytes land under
PROXIMO_RESTORE_DIR in a fresh private subdirectory, capped by PROXIMO_RESTORE_MAX_BYTES, the
result carries path, byte count and sha256) and L7 (PMG's raw quarantine mail, beyond 0.44). The
lane is opt-in like every lane that touches this host (PROXIMO_ENABLE_DOWNLOAD): 0.44 asked
confirm=True per pull; the core asks the operator once per deployment and caps every pull.
"""
from __future__ import annotations

import hashlib
import os
import stat

import httpx
import pytest

from proximo.core import download, engine, rawdoor
from proximo.core.errors import ProximoError
from test_engine import EstateCfg

PVE_DL = "/nodes/pve1/storage/pbs/file-restore/download"
PVE_ARGS = {"volume": "backup/vzdump-qemu-101.vma.zst", "filepath": "L2V0Yy9zaGFkb3c="}   # /etc/shadow, b64
FIVE = sorted(f"{p}:GET {path}" for p, path in rawdoor.STREAMS)


class _Fake:
    """A wire.Client stand-in: the httpx client streams whatever `handler` answers."""

    def __init__(self, handler, auth="token"):
        self._client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://unreachable.invalid")
        self.spec = {"auth": auth}
        self.relogins = 0

    def _headers(self, mutation):
        return {"X-Test": "1"}

    def _relogin(self):
        self.relogins += 1

    def call(self, *a, **k):
        pytest.fail("the download lane dialled the JSON wire")


def _streaming(body: bytes, status=200, length=True, disposition=None):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": "application/octet-stream"}
        if disposition:
            headers["content-disposition"] = disposition
        if not length:      # a chunked answer: no Content-Length, the cap is met while streaming
            return httpx.Response(status, headers=headers, content=iter([body[:40], body[40:]]))
        return httpx.Response(status, headers={**headers, "content-length": str(len(body))}, content=body)
    return handler


@pytest.fixture
def lane(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_ENABLE_DOWNLOAD", "1")
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path / "land"))
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", "64")
    return tmp_path / "land"


@pytest.fixture
def cfg(tmp_path):
    return EstateCfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                     audit_log_path=str(tmp_path / "audit.log"))


def _wire(monkeypatch, fake):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: fake)
    return fake


def _rows(cfg):
    import json
    return [json.loads(line) for line in open(cfg.audit_log_path)]


# --- the five are a lane, not a wall --------------------------------------------------------------

def test_the_five_byte_streams_are_the_download_lane():
    assert len(FIVE) == 5
    for key in FIVE:
        plane, rest = key.split(":", 1)
        row = engine.resolve(plane, "GET", rest.split(" ", 1)[1])
        assert row.gate and engine.opt_in_lane(row) == "download", key


def test_the_lane_is_off_by_default_and_the_refusal_names_the_switch(monkeypatch, cfg):
    monkeypatch.delenv("PROXIMO_ENABLE_DOWNLOAD", raising=False)
    v = engine.govern(engine.resolve("pve", "GET", PVE_DL), cfg=cfg, path=PVE_DL)
    assert not v.allowed and v.needs == "download" and "PROXIMO_ENABLE_DOWNLOAD" in v.reason


def test_the_agent_switch_does_not_open_the_download_lane(monkeypatch, cfg):
    monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1")
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "*")
    monkeypatch.delenv("PROXIMO_ENABLE_DOWNLOAD", raising=False)
    assert engine.govern(engine.resolve("pve", "GET", PVE_DL), cfg=cfg, path=PVE_DL).needs == "download"


def test_a_template_path_names_no_download(lane, cfg):
    row = engine.resolve("pve", "GET", "/nodes/{node}/storage/{storage}/file-restore/download")
    v = engine.govern(row, cfg=cfg, path=row.path)
    assert not v.allowed and v.needs == "download"


# --- bytes land on disk, never in the answer ------------------------------------------------------

def test_the_bytes_land_private_and_the_answer_carries_only_path_count_and_hash(lane, cfg, monkeypatch):
    body = b"root:$6$salt$hash:19000:0:99999:7:::\n"
    fake = _wire(monkeypatch, _Fake(_streaming(body)))
    row = engine.resolve("pve", "GET", PVE_DL)
    out = engine.execute(row, dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    got = out["download"]
    assert got["bytes"] == len(body) and got["sha256"] == hashlib.sha256(body).hexdigest()
    assert open(got["path"], "rb").read() == body
    assert "data" not in out and body[:6] not in repr(out).encode()
    sub = os.path.dirname(got["path"])
    assert os.path.dirname(sub) == str(lane) and os.path.basename(sub).startswith("download-")
    assert stat.S_IMODE(os.stat(sub).st_mode) == 0o700 and stat.S_IMODE(os.stat(got["path"]).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(lane).st_mode) == 0o700
    assert os.path.basename(got["path"]) == "shadow"            # the caller's filepath, decoded, its basename
    assert out["cap_bytes"] == 64 and out["access"] == "read" and out["derived"] is False
    assert [(r["action"], r["outcome"]) for r in _rows(cfg)] == [("core.execute", "ok")]
    detail = _rows(cfg)[0]["detail"]
    assert detail["bytes"] == len(body) and detail["sha256"] == got["sha256"] and "path" not in detail
    assert fake.relogins == 0


def test_the_local_name_is_the_callers_argument_never_the_vendors_header(lane, cfg, monkeypatch):
    """Content-Disposition on a quarantined mail is attacker text; a listing name is guest text."""
    _wire(monkeypatch, _Fake(_streaming(b"x", disposition='attachment; filename="../../etc/cron.d/evil"')))
    row = engine.resolve("pve", "GET", PVE_DL)
    args = {**PVE_ARGS, "filepath": "Li4vLi4vZXRjL2Nyb24uZC9ldmlsCg=="}     # ../../etc/cron.d/evil\n, b64
    out = engine.execute(row, args, cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    path = out["download"]["path"]
    assert os.path.basename(path) == "evil_" and os.path.dirname(os.path.dirname(path)) == str(lane)
    assert not os.path.exists(lane / ".." / ".." / "etc" / "cron.d" / "evil")


def test_a_tar_pull_is_named_as_an_archive(lane, cfg, monkeypatch):
    _wire(monkeypatch, _Fake(_streaming(b"x")))
    out = engine.execute(engine.resolve("pve", "GET", PVE_DL), {**PVE_ARGS, "filepath": "L2V0Yw==", "tar": "1"},
                         cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert os.path.basename(out["download"]["path"]) == "etc.tar.zst"


# --- the cap, before the first byte and while streaming ---------------------------------------------

def test_a_declared_length_over_the_cap_is_refused_before_the_first_byte_and_leaves_no_dir(lane, cfg, monkeypatch):
    _wire(monkeypatch, _Fake(_streaming(b"x" * 65)))
    with pytest.raises(ProximoError, match="over PROXIMO_RESTORE_MAX_BYTES=64"):
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert not os.path.exists(lane) or list(lane.iterdir()) == []
    assert [(r["action"], r["outcome"]) for r in _rows(cfg)] == [("core.error", "error")]


def test_a_cap_crossed_while_streaming_removes_the_partial_and_its_dir(lane, cfg, monkeypatch):
    _wire(monkeypatch, _Fake(_streaming(b"x" * 65, length=False)))
    with pytest.raises(ProximoError, match="while streaming"):
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert list(lane.iterdir()) == []


def test_a_vendor_refusal_raises_and_is_receipted(lane, cfg, monkeypatch):
    _wire(monkeypatch, _Fake(_streaming(b'{"errors":"no such volume"}', status=404)))
    with pytest.raises(ProximoError, match="HTTP 404"):
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert list(lane.iterdir()) == [] and _rows(cfg)[-1]["action"] == "core.error"


def test_an_expired_ticket_logs_in_once_more(lane, cfg, monkeypatch):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(401) if calls["n"] == 1 else httpx.Response(200, content=b"mail")
    fake = _wire(monkeypatch, _Fake(handler, auth="ticket"))
    out = engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert fake.relogins == 1 and out["download"]["bytes"] == 4


# --- what the lane refuses to pretend --------------------------------------------------------------

@pytest.mark.parametrize("extra", [{"fields": "all"}, {"since": "24h"}, {"wait": 5}])
def test_fields_since_and_wait_are_not_questions_a_byte_stream_answers(lane, cfg, monkeypatch, extra):
    _wire(monkeypatch, _Fake(_streaming(b"x")))
    with pytest.raises(ProximoError, match="byte stream"):
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg,
                       path=PVE_DL, **extra)


def test_a_plan_dials_nothing_and_names_the_landing_and_the_cap(lane, cfg, monkeypatch):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: pytest.fail("a plan dialled"))
    out = engine.plan(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), path=PVE_DL, cfg=cfg)
    assert out["allowed"] and out["download"] == {"lands_under": str(lane), "cap_bytes": 64}


def test_the_quarantined_mail_is_untrusted_bytes():
    row = engine.resolve("pmg", "GET", "/quarantine/download")
    assert row.untrusted and engine.opt_in_lane(row) == "download"


def test_the_raw_get_door_still_refuses_every_stream():
    for key in FIVE:
        plane, rest = key.split(":", 1)
        path = rest.split(" ", 1)[1].replace("{store}", "s").replace("{node}", "n").replace("{storage}", "st")
        with pytest.raises(ProximoError, match="gated"):
            rawdoor.validate(plane, path)


@pytest.mark.parametrize("raw", ["lots", "0", "-1", "1_0", "64.0"])
def test_a_bad_cap_refuses_by_its_shape(lane, cfg, monkeypatch, raw):
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", raw)
    with pytest.raises(ProximoError, match="PROXIMO_RESTORE_MAX_BYTES"):
        download.settings()


# --- lens 3 folds -------------------------------------------------------------------------------------

def test_a_quarantined_mail_is_named_by_its_mailid_and_marks_the_taint(lane, cfg, monkeypatch):
    """The pmg address publishes `mailid`, not `id` (the first cut named the wrong argument and
    every mail landed as "download"); and an untrusted read on the lane couples to TAINT like any
    other: the marker is written and the receipt says untrusted."""
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    _wire(monkeypatch, _Fake(_streaming(b"From: attacker\r\n")))
    row = engine.resolve("pmg", "GET", "/quarantine/download")
    # PMG publishes a mail id as C<n>R<n>T<n>: the fixture carries a value the vendor accepts.
    out = engine.execute(row, {"mailid": "C1R2T3"}, ledger_cfg=cfg, path="/quarantine/download")
    assert os.path.basename(out["download"]["path"]) == "C1R2T3" and out["untrusted"] is True
    rows = _rows(cfg)
    assert rows[-1]["action"] == "core.execute" and rows[-1]["detail"]["untrusted"] is True
    ledger_dir = __import__("pathlib").Path(cfg.audit_log_path).parent
    assert any(p.name.startswith(".proximo-taint") for p in ledger_dir.iterdir())


def test_an_empty_filepath_beside_a_mailid_names_by_the_mailid_undecoded():
    assert download.local_name({"filepath": "", "mailid": "abcd"}) == "abcd"


@pytest.mark.parametrize("status,body", [(302, b""), (301, b"<html>moved</html>"), (204, b"")])
def test_only_a_200_is_a_download(lane, cfg, monkeypatch, status, body):
    def handler(request):
        return httpx.Response(status, headers={"location": "https://elsewhere.invalid/x"}, content=body)
    _wire(monkeypatch, _Fake(handler))
    with pytest.raises(ProximoError, match=f"HTTP {status}"):
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert list(lane.iterdir()) == [] and _rows(cfg)[-1]["action"] == "core.error"


def test_the_vendors_error_body_is_never_echoed(lane, cfg, monkeypatch):
    _wire(monkeypatch, _Fake(_streaming(b"nope PVEAPIToken=u@pam!t=SECRETTOKEN123 SECRETTOKEN123", status=401)))
    with pytest.raises(ProximoError) as exc:
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg, path=PVE_DL)
    assert "SECRETTOKEN123" not in str(exc.value) and "HTTP 401" in str(exc.value)


def test_the_refused_question_leaves_a_receipt(lane, cfg, monkeypatch):
    _wire(monkeypatch, _Fake(_streaming(b"x")))
    with pytest.raises(ProximoError):
        engine.execute(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), cfg=cfg, ledger_cfg=cfg,
                       path=PVE_DL, since="24h")
    assert [(r["action"], r["outcome"]) for r in _rows(cfg)] == [("core.refuse", "refused")]


def test_a_plan_with_the_lane_off_learns_no_landing_dir_and_a_bad_cap_does_not_crash_it(cfg, monkeypatch, tmp_path):
    monkeypatch.delenv("PROXIMO_ENABLE_DOWNLOAD", raising=False)
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path / "secret-landing"))
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", "0")
    out = engine.plan(engine.resolve("pve", "GET", PVE_DL), dict(PVE_ARGS), path=PVE_DL, cfg=cfg)
    assert out["needs"] == "download" and "download" not in out and "secret-landing" not in repr(out)


def test_the_name_limit_is_two_hundred_bytes_not_characters():
    wide = __import__("base64").b64encode(("/" + "\U0001F600" * 200).encode()).decode()
    name = download.local_name({"filepath": wide})
    assert len(name.encode()) <= 200 and name
