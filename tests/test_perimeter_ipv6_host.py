"""The Host guard answers a door bound to an IPv6 address.

A client that dials `http://[::1]:8080/` sends `Host: [::1]:8080`, and Starlette's Host check
reads that as `[::1]`, brackets kept. The allowlist held the bare `::1` (and `urlparse(...)
.hostname` hands back a served IPv6 host bare too), so no Host a client could send ever matched:
every request that addressed a door by its IPv6 address was a 400, loopback or not, token or not.
The class is every IPv6 literal on the allowlist, wherever it came from (the loopback default, the
served URL, the operator's own `_ALLOWED_HOSTS`) and however it was spelled (long, upper case,
with a zone id): a client sends the compressed form, in brackets, with no zone.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("starlette", reason="the [http] extra is not installed")

from starlette.testclient import TestClient  # noqa: E402

from proximo.core import principal  # noqa: E402
from proximo.core.doors import http as face  # noqa: E402
from proximo.core.perimeter import guard  # noqa: E402

TOKEN = "t0k"  # noqa: S105 -- a test's own bearer


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    yield tmp_path
    principal.set_serving_face("stdio")


def _get(app, host: str) -> int:
    return TestClient(app, base_url="http://localhost").get("/healthz", headers={"Host": host}).status_code


def test_a_door_on_ipv6_loopback_answers_the_host_a_client_sends(env):
    app = face.build_app("http://[::1]:8080/", token=None)
    assert _get(app, "[::1]:8080") == 200
    assert _get(app, "[::1]") == 200


def test_the_loopback_default_answers_ipv6_loopback_on_an_ipv4_url(env):
    """The default allowlist names the loopback forms whatever the served host is."""
    assert _get(face.build_app("http://127.0.0.1:8080/", token=None), "[::1]:8080") == 200


def test_a_door_on_another_ipv6_address_answers_its_own_host_and_no_other(env):
    app = face.build_app("http://[fd00::5]:8080/", token=TOKEN)
    assert _get(app, "[fd00::5]:8080") == 200
    assert _get(app, "[fd00::6]:8080") == 400          # the guard still refuses a Host it does not serve
    assert _get(app, "evil.example") == 400


@pytest.mark.parametrize("given", ["fd00::5", "[fd00::5]", "FD00::5"])
def test_the_operators_own_ipv6_entry_is_matched_bare_or_bracketed(env, given):
    app = face.build_app("http://127.0.0.1:8080/", token=TOKEN, allowed_hosts=[given])
    assert _get(app, "[fd00::5]:8080") == 200
    assert _get(app, "[fd00::6]:8080") == 400
    assert _get(app, "localhost") == 400               # the operator's list replaces the default, as before


def test_an_address_written_long_answers_the_compressed_host_a_client_sends(env):
    """A client compresses what it dials: `http://[0:0:0:0:0:0:0:1]/` goes out as `Host: [::1]`."""
    app = face.build_app("http://[FD00:0::5]:8080/", token=TOKEN)
    assert _get(app, "[fd00::5]:8080") == 200
    app = face.build_app("http://127.0.0.1:8080/", token=TOKEN, allowed_hosts=["[0:0:0:0:0:0:0:1]"])
    assert _get(app, "[::1]:8080") == 200            # the bracketed entry is read too, not only passed through
    assert _get(app, "[::2]:8080") == 400


def test_a_link_local_address_with_a_zone_answers_the_host_without_it(env):
    """A Host header carries no zone id, and the check cannot parse one."""
    app = face.build_app("http://127.0.0.1:8080/", token=TOKEN, allowed_hosts=["fe80::1%eth0"])
    assert _get(app, "[fe80::1]:8080") == 200
    assert _get(app, "[fe80::2]:8080") == 400


def test_the_mcp_http_door_and_the_a2a_door_answer_on_ipv6_loopback_too(env):
    """One shared site, held by behaviour on each door and not only by the stack's class names."""
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    from proximo.core.doors import a2a, mcphttp
    mcp_app = mcphttp.build_app("http://[::1]:8080/", token=None)
    a2a_app = a2a.build_app("http://[::1]:8080/", token=None)
    for app, path in ((mcp_app, "/healthz"), (a2a_app, "/.well-known/agent-card.json")):
        client = TestClient(app, base_url="http://localhost")
        assert client.get(path, headers={"Host": "[::1]:8080"}).status_code == 200
        assert client.get(path, headers={"Host": "evil.example"}).status_code == 400


def test_the_starlette_floor_is_the_first_release_that_parses_an_ipv6_host():
    """Before starlette 1.7.0 the Host check compared the text up to the first colon, `[` for
    any bracketed IPv6 Host, so nothing in this file can hold there. Every place pyproject asks
    for starlette asks for 1.7.0 or newer."""
    import tomllib
    from pathlib import Path

    from packaging.requirements import Requirement
    from packaging.version import Version
    project = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text())["project"]
    asked = [Requirement(r) for group in project["optional-dependencies"].values() for r in group]
    floors = [Version(s.version) for r in asked if r.name == "starlette" for s in r.specifier if s.operator == ">="]
    assert len(floors) == 4                            # a2a, http, mcp-http, dev: one floor each
    assert all(f >= Version("1.7.0") for f in floors)


def test_nothing_here_adds_a_wildcard_or_rewrites_what_is_not_an_address():
    odd = ["name:8080", "*", "*.example.com", "[*]", "", "[]", "[::1", "[localhost]", "[192.0.2.4]", "1::2::3"]
    assert guard.host_patterns(odd) == odd


def test_a_name_and_an_ipv4_address_are_left_as_written():
    assert guard.host_patterns(["localhost", "127.0.0.1", "*.example.com", "*", "pve1:8006"]) == [
        "localhost", "127.0.0.1", "*.example.com", "*", "pve1:8006"]


def test_a_bare_ipv6_literal_gains_its_bracketed_form_and_keeps_its_own():
    assert guard.host_patterns(["::1"]) == ["::1", "[::1]"]
    assert guard.host_patterns(["[::1]"]) == ["[::1]"]
    assert guard.host_patterns(["::1", "[::1]"]) == ["::1", "[::1]"]
    assert guard.host_patterns(["FD00:0::5"]) == ["FD00:0::5", "[fd00:0::5]", "[fd00::5]"]
    assert guard.host_patterns(["fe80::1%eth0"]) == ["fe80::1%eth0", "[fe80::1]"]
