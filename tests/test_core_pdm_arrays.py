"""PDM's array parameters on the wire: the first real remote-migrate sent a scalar where PDM's
typed API wants an array ("Expected array - got scalar value", 400); 0.44 wrapped each in a
one-element list. The core has no wrapper: the vendor publishes `type: array` and the wire
encodes JSON. These tests send the call through `engine.execute` and the REAL `wire.Client`,
mocking only the HTTP transport (never `coerce_args`), and read the body PDM would receive."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx

from proximo.core import arm, engine, wire

ADDR = "/pve/remotes/{remote}/qemu/{vmid}/remote-migrate"
CALLED = "/pve/remotes/east/qemu/100/remote-migrate"


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


def _send(monkeypatch, tmp_path, args):
    """Run the call through the engine; return the JSON bodies PDM's mock received."""
    token = tmp_path / "pdm.token"
    token.write_text("user@pdm!t:secret")
    os.chmod(token, 0o600)
    cfg = _Cfg("pdm", "https://pdm.invalid:8443", str(token), audit_log_path=str(tmp_path / "audit.log"))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": None})

    def build(product, c=None):
        client = wire.Client(cfg)
        client._client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://pdm.invalid:8443")
        return client

    monkeypatch.setattr(engine, "_client", build)
    monkeypatch.setattr(arm, "arm_state", lambda c=None: arm.ArmGateState(True, True, None))
    row = engine.resolve("pdm", "POST", ADDR)
    assert row.tier, "the address is authored; the control below needs it to be armed-and-tiered"
    engine.execute(row, args, cfg=cfg, ledger_cfg=cfg, path=CALLED, wait=0)
    posts = [r for r in seen if r.method == "POST"]
    assert len(posts) == 1, [r.method for r in seen]
    assert posts[0].headers["content-type"].startswith("application/json")
    return json.loads(posts[0].content)


def test_the_published_type_of_the_mapping_parameters_is_array():
    row = engine.resolve("pdm", "POST", ADDR)
    assert row.params["target-bridge"]["type"] == "array"
    assert row.params["target-storage"]["type"] == "array"


def test_a_list_reaches_pdm_as_a_json_array(monkeypatch, tmp_path):
    body = _send(monkeypatch, tmp_path, {"target": "pve2", "target-bridge": ["vmbr0:vmbr0"],
                                         "target-storage": ["local-lvm:local-lvm"]})
    assert body["target-bridge"] == ["vmbr0:vmbr0"]
    assert body["target-storage"] == ["local-lvm:local-lvm"]


def test_a_scalar_from_the_shell_door_reaches_pdm_as_a_one_element_array(monkeypatch, tmp_path):
    """The shell door keeps every value a string (`target-bridge=vmbr0:vmbr0`); 0.44 wrapped the
    scalar and PDM took it. A bare string on the wire is the 400 the first live run hit."""
    body = _send(monkeypatch, tmp_path, {"target": "pve2", "target-bridge": "vmbr0:vmbr0",
                                         "target-storage": "local-lvm:local-lvm"})
    assert body["target-bridge"] == ["vmbr0:vmbr0"]
    assert body["target-storage"] == ["local-lvm:local-lvm"]
