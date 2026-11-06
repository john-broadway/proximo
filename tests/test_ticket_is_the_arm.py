"""The ticket is the arm (2026-11-05; John: "theres a reason 0 is set by vendor").

A token is an identity: the vendor ships it with `expire` 0 and means a standing credential with
an ACL. A ticket is a session: `POST /access/ticket`, two hours on the vendor's clock, dead on its
own. A person arms by logging in from a terminal of their own; the served file then holds the
vendor's ticket, and the predicate reads the ticket's OWN issue time (hex seconds in its text,
signed by the vendor): armed iff a ticket for this box, this product, under two hours old. A job
with nobody at a keyboard keeps the token pair (`PROXIMO_ARM_SOURCE`): that path is unchanged.
"""
from __future__ import annotations

import json
import os
import stat
import time

import httpx
import pytest

from proximo.core import arm, engine, wire
from proximo.core.doors import cli
from proximo.core.errors import ProximoError

BOX = "https://pve.invalid:8006/api2/json"
_REAL_CLIENT = httpx.Client          # captured once: a helper called twice in one test must not wrap its own patch
SIG = "Zm9v0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"


def _ticket(prefix: str = "PVE", user: str = "op@pam", age: int = 10) -> str:
    return f"{prefix}:{user}:{int(time.time()) - age:08X}::{SIG}"


def _serve_ticket(path, ticket: str, box: str = BOX, csrf: str = "CSRF:0001:abc") -> None:
    path.write_text(json.dumps({"ticket": ticket, "csrf": csrf, "box": box}))
    path.chmod(0o600)


@pytest.fixture
def served(tmp_path, monkeypatch):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":
            monkeypatch.delenv(var)
    ro = tmp_path / "ro.tok"
    ro.write_text("op@pam!read=22222222-2222-2222-2222-222222222222")
    ro.chmod(0o600)
    path = tmp_path / "served.tok"
    path.write_text(ro.read_text())
    path.chmod(0o600)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", BOX)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(path))
    monkeypatch.setenv("PROXIMO_READONLY_SOURCE", str(ro))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return path


def _plane(path, product: str = "pve", box: str = BOX, readonly: str | None = None) -> wire.Plane:
    return wire.Plane(product, box, str(path), readonly_source=readonly)


# --- one reader for the served file ------------------------------------------------------------------

def test_the_reader_tells_a_token_from_a_ticket_and_refuses_what_is_neither(served, tmp_path):
    assert arm.served_credential(str(served))[0] == "token"
    _serve_ticket(served, _ticket())
    kind, cred = arm.served_credential(str(served))
    assert kind == "ticket" and cred["prefix"] == "PVE" and cred["user"] == "op@pam" and cred["box"] == BOX
    assert abs(cred["issued"] - time.time()) < 60
    no_time = json.dumps({"ticket": "PVE:op@pam:zz::s", "csrf": "c", "box": BOX})
    challenge = json.dumps({"ticket": "PVE:!tfa!abc:0001::s", "csrf": "c", "box": BOX})
    for bad in ("{not json", json.dumps({"ticket": "x"}), no_time, challenge, ""):
        served.write_text(bad)
        assert arm.served_credential(str(served))[0] == "unreadable", bad
    assert arm.served_credential(str(tmp_path / "missing"))[0] == "unreadable"


# --- the predicate: the ticket's own clock ---------------------------------------------------------------

def test_a_fresh_ticket_for_this_box_is_armed_and_names_when_it_dies(served):
    _serve_ticket(served, _ticket(age=10))
    state = arm.arm_state(_plane(served))
    assert state.enforced and state.armed and "op@pam" in state.reason and "until" in state.reason
    assert arm.arm_state().armed                       # the env box, no cfg given, reads the same file


@pytest.mark.parametrize("age", [arm.TICKET_LIFETIME + 1, arm.TICKET_LIFETIME, -120])
def test_a_ticket_past_the_vendors_two_hours_or_from_the_future_is_not_armed(served, age):
    _serve_ticket(served, _ticket(age=age))
    state = arm.arm_state(_plane(served))
    assert state.enforced and not state.armed and ("died" in state.reason or "future" in state.reason)


def test_a_ticket_for_another_box_or_another_product_is_not_armed(served):
    _serve_ticket(served, _ticket(), box="https://other.invalid:8006/api2/json")
    assert not arm.arm_state(_plane(served)).armed
    _serve_ticket(served, _ticket(prefix="PBS"))
    assert not arm.arm_state(_plane(served)).armed and "PBS" in arm.arm_state(_plane(served)).reason
    assert arm.arm_state(_plane(served, product="pbs", box=BOX)).armed       # the same file IS pbs's ticket for pbs


def test_a_served_token_with_no_pair_reads_as_it_always_has(served):
    state = arm.arm_state(_plane(served))
    assert not state.armed                                            # the token path is unchanged: no pair, no arm


def test_a_malformed_ticket_file_fails_closed(served):
    served.write_text("{")
    state = arm.arm_state(_plane(served))
    assert state.enforced and not state.armed and "ticket" in state.reason


# --- the wire: what the served file holds is what is sent -------------------------------------------------

def _wire(monkeypatch, path, product="pve", readonly=None, box=BOX):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"version": "9.2"}})
    real = _REAL_CLIENT

    def build(**kw):
        return real(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "verify"})
    monkeypatch.setattr(wire.httpx, "Client", build)
    return wire.Client(_plane(path, product, box, readonly)), seen


def test_a_served_ticket_rides_as_the_vendors_cookie_and_csrf_on_a_mutation(served, monkeypatch):
    _serve_ticket(served, _ticket(), csrf="CSRF:0001:abc")
    client, seen = _wire(monkeypatch, served)
    client.call("GET", "/version")
    client.call("PUT", "/nodes/x/qemu/1/config", {"memory": 1024})
    get, put = seen
    assert get.headers["cookie"].startswith("PVEAuthCookie=PVE:op@pam:") and "authorization" not in get.headers
    assert "csrfpreventiontoken" not in get.headers
    assert put.headers["csrfpreventiontoken"] == "CSRF:0001:abc" and put.headers["cookie"].startswith("PVEAuthCookie=")


@pytest.mark.parametrize("product,cookie", [("pbs", "PBSAuthCookie"), ("pdm", "PDMAuthCookie")])
def test_each_product_names_its_own_cookie(served, monkeypatch, product, cookie):
    _serve_ticket(served, _ticket(prefix=product.upper()))
    client, seen = _wire(monkeypatch, served, product=product)
    client.call("GET", "/version")
    assert seen[0].headers["cookie"].startswith(f"{cookie}={product.upper()}:")


def test_a_served_token_rides_as_the_header_it_always_did(served, monkeypatch):
    client, seen = _wire(monkeypatch, served)
    client.call("GET", "/version")
    assert seen[0].headers["authorization"].startswith("PVEAPIToken=op@pam!read=") and "cookie" not in seen[0].headers


def test_a_dead_ticket_sends_the_read_token_when_one_is_configured(served, monkeypatch, tmp_path):
    _serve_ticket(served, _ticket(age=arm.TICKET_LIFETIME + 5))
    client, seen = _wire(monkeypatch, served, readonly=str(tmp_path / "ro.tok"))
    client.call("GET", "/version")
    assert seen[0].headers["authorization"].startswith("PVEAPIToken=op@pam!read=") and "cookie" not in seen[0].headers


def test_a_dead_ticket_with_no_read_token_goes_out_and_the_vendor_answers(served, monkeypatch):
    _serve_ticket(served, _ticket(age=arm.TICKET_LIFETIME + 5))
    client, seen = _wire(monkeypatch, served)
    client.call("GET", "/version")
    assert seen[0].headers["cookie"].startswith("PVEAuthCookie=")          # the 401 is the vendor's word


def test_an_unreadable_served_file_refuses_before_the_wire(served, monkeypatch):
    served.write_text("{")
    client, seen = _wire(monkeypatch, served)
    with pytest.raises(ProximoError, match="ticket"):
        client.call("GET", "/version")
    assert seen == []


# --- the login: the vendor's own call ------------------------------------------------------------------

def _vendor(monkeypatch, answers: list[dict | int]):
    """A vendor whose POST /access/ticket answers each item in turn: a dict is 200 with that data, an int a status."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        a = answers.pop(0)
        return httpx.Response(a, json={"errors": {}}) if isinstance(a, int) else httpx.Response(200, json={"data": a})
    real = _REAL_CLIENT
    def build(**kw):
        return real(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "verify"})
    monkeypatch.setattr(wire.httpx, "Client", build)
    return seen


def test_ticket_login_posts_the_vendors_form_and_returns_the_ticket_and_csrf(served, monkeypatch):
    seen = _vendor(monkeypatch, [{"ticket": _ticket(), "CSRFPreventionToken": "CSRF:1:x", "username": "op@pam"}])
    out = wire.ticket_login(_plane(served), "op@pam", "hunter2")
    assert set(out) == {"ticket", "csrf", "username"} and out["csrf"] == "CSRF:1:x"
    assert seen[0].url.path.endswith("/access/ticket") and seen[0].method == "POST"
    body = seen[0].content.decode()
    assert "username=op%40pam" in body and "password=hunter2" in body and "tfa-challenge" not in body


def test_ticket_login_hands_back_a_second_factor_challenge_and_resends_with_it(served, monkeypatch):
    challenge = "PVE:!tfa!op@pam:0000000A::" + SIG
    seen = _vendor(monkeypatch, [{"ticket": challenge, "CSRFPreventionToken": "", "username": "op@pam"},
                                 {"ticket": _ticket(), "CSRFPreventionToken": "CSRF:2:y", "username": "op@pam"}])
    first = wire.ticket_login(_plane(served), "op@pam", "hunter2")
    assert first == {"tfa_challenge": challenge}
    second = wire.ticket_login(_plane(served), "op@pam", "123456", tfa_challenge=challenge)
    assert second["csrf"] == "CSRF:2:y"
    body = seen[1].content.decode()
    assert "tfa-challenge=" in body and "password=123456" in body


def test_pdm_logs_in_with_json_as_its_wire_does(served, monkeypatch):
    answer = {"ticket": _ticket("PDM"), "CSRFPreventionToken": "CSRF:3:z", "username": "op@pam"}
    seen = _vendor(monkeypatch, [answer])
    wire.ticket_login(_plane(served, "pdm", "https://pdm.invalid:8443"), "op@pam", "pw")
    assert seen[0].headers["content-type"].startswith("application/json")
    assert json.loads(seen[0].content)["password"] == "pw"


# --- the verb: a person's hand, from a terminal of their own ----------------------------------------------

def _rows(tmp_path):
    log = tmp_path / "audit.log"
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()] if log.exists() else []


@pytest.fixture
def terminal(monkeypatch):
    """A tty on stdin and a silent prompt that answers from a script."""
    answers: list[str] = []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "_prompt_secret", lambda label: answers.pop(0))
    return answers


def test_arm_refuses_without_a_terminal_and_writes_nothing(served, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    before = served.read_text()
    assert cli.main(["arm"]) == cli.EXIT_USAGE
    assert served.read_text() == before and "terminal of your own" in capsys.readouterr().err


def test_arm_logs_in_writes_the_ticket_0600_receipts_without_it_and_says_until_when(
        served, monkeypatch, terminal, capsys, tmp_path):
    terminal.append("hunter2")
    ticket = _ticket()
    _vendor(monkeypatch, [{"ticket": ticket, "CSRFPreventionToken": "CSRF:1:x", "username": "op@pam"}])
    assert cli.main(["arm"]) == 0
    out = capsys.readouterr().out
    assert "ARMED" in out and "op@pam" in out and "until" in out and ticket not in out
    assert stat.S_IMODE(served.stat().st_mode) == 0o600
    cred = json.loads(served.read_text())
    assert cred == {"ticket": ticket, "csrf": "CSRF:1:x", "box": BOX}
    assert arm.arm_state().armed
    rows = _rows(tmp_path)
    assert [(r["action"], r["detail"]["armed"]) for r in rows] == [("core.arm", True)]
    assert rows[0]["detail"]["user"] == "op@pam" and "until" in rows[0]["detail"] and ticket not in json.dumps(rows)


def test_arm_asks_for_the_second_factor_when_the_vendor_wants_one(served, monkeypatch, terminal):
    terminal.extend(["hunter2", "123456"])
    challenge = "PVE:!tfa!op@pam:0000000A::" + SIG
    seen = _vendor(monkeypatch, [{"ticket": challenge, "CSRFPreventionToken": "", "username": "op@pam"},
                                 {"ticket": _ticket(), "CSRFPreventionToken": "CSRF:2:y", "username": "op@pam"}])
    assert cli.main(["arm"]) == 0
    assert len(seen) == 2 and "tfa-challenge=" in seen[1].content.decode() and terminal == []


def test_a_password_the_vendor_refuses_arms_nothing(served, monkeypatch, terminal, capsys, tmp_path):
    terminal.append("wrong")
    _vendor(monkeypatch, [401])
    before = served.read_text()
    assert cli.main(["arm"]) == cli.EXIT_REFUSED
    assert served.read_text() == before and "401" in capsys.readouterr().err
    assert [(r["action"], r["outcome"]) for r in _rows(tmp_path)] == [("core.arm", "refused")]


def test_the_user_defaults_to_the_served_tokens_own_and_can_be_named(served, monkeypatch, terminal):
    terminal.extend(["pw", "pw"])
    seen = _vendor(monkeypatch, [{"ticket": _ticket(), "CSRFPreventionToken": "c", "username": "op@pam"},
                                 {"ticket": _ticket(user="root@pam"), "CSRFPreventionToken": "c",
                                  "username": "root@pam"}])
    assert cli.main(["arm"]) == 0 and "username=op%40pam" in seen[0].content.decode()
    assert cli.main(["arm", "--user", "root@pam"]) == 0 and "username=root%40pam" in seen[1].content.decode()


def test_arm_serves_at_the_path_named_and_disarm_puts_the_read_token_back_there(
        served, monkeypatch, terminal, tmp_path):
    terminal.append("pw")
    _vendor(monkeypatch, [{"ticket": _ticket(), "CSRFPreventionToken": "c", "username": "op@pam"}])
    other = tmp_path / "sessions" / "abc.token"
    assert cli.main(["arm", "--serve", str(other)]) == 0
    assert arm.served_credential(str(other))[0] == "ticket" and arm.served_credential(str(served))[0] == "token"
    assert cli.main(["disarm", "--serve", str(other)]) == 0
    assert other.read_text() == (tmp_path / "ro.tok").read_text()


# --- the engine: a dead ticket plans `needs: arm` and dials nothing ---------------------------------------

def test_a_mutation_on_a_dead_ticket_plans_needs_arm_with_the_time_it_died(served, monkeypatch):
    _serve_ticket(served, _ticket(age=arm.TICKET_LIFETIME + 60))
    calls: list = []
    monkeypatch.setattr(engine, "_client", lambda product, c=None: (_ for _ in ()).throw(AssertionError("dialled")))
    row = engine.resolve("pve", "POST", "/nodes/{node}/lxc/{vmid}/status/start")
    v = engine.govern(row, cfg=_plane(served), path="/nodes/x/lxc/1/status/start", args={})
    assert not v.allowed and v.needs == "arm" and "died" in v.reason and calls == []


# --- each plane has its own served path, its own pair, its own login ---------------------------------------

def test_a_pbs_arm_logs_into_pbs_and_serves_at_pbss_own_path_leaving_pves_alone(
        served, monkeypatch, terminal, tmp_path):
    pbs_ro = tmp_path / "pbs-ro.tok"
    pbs_ro.write_text("op@pbs!read=33333333-3333-3333-3333-333333333333")
    pbs_ro.chmod(0o600)
    pbs_served = tmp_path / "pbs-served.tok"
    pbs_served.write_text(pbs_ro.read_text())
    pbs_served.chmod(0o600)
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.invalid:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(pbs_served))
    monkeypatch.setenv("PROXIMO_PBS_READONLY_SOURCE", str(pbs_ro))
    terminal.append("pw")
    answer = {"ticket": _ticket("PBS", "op@pbs"), "CSRFPreventionToken": "c", "username": "op@pbs"}
    seen = _vendor(monkeypatch, [answer])
    assert cli.main(["arm", "--plane", "pbs"]) == 0
    assert seen[0].url.host == "pbs.invalid" and "username=op%40pbs" in seen[0].content.decode()
    assert arm.served_credential(str(pbs_served))[0] == "ticket" and arm.served_credential(str(served))[0] == "token"
    assert arm.arm_state(wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", str(pbs_served))).armed
    assert not arm.arm_state().armed                                          # PVE's served file is untouched
    assert cli.main(["disarm", "--plane", "pbs"]) == 0
    assert pbs_served.read_text() == pbs_ro.read_text() and arm.served_credential(str(served))[0] == "token"


def test_a_plane_with_no_served_path_refuses_by_name(served, monkeypatch, terminal, capsys):
    assert cli.main(["arm", "--plane", "pdm"]) == cli.EXIT_USAGE
    assert "PROXIMO_PDM_TOKEN_PATH" in capsys.readouterr().err


def test_a_ticket_for_another_box_or_product_is_never_sent_here(served, monkeypatch, tmp_path):
    """Security review (2026-11-05): the predicate refused a ticket for another box; the wire still sent it to
    whatever host the plane dialled. A ticket goes only to the box that issued it: the read-only token rides
    instead when one is configured, else the call is refused before the wire."""
    _serve_ticket(served, _ticket(), box="https://other.invalid:8006/api2/json")
    client, seen = _wire(monkeypatch, served)
    with pytest.raises(ProximoError, match="another box"):
        client.call("GET", "/version")
    assert seen == []
    client, seen = _wire(monkeypatch, served, readonly=str(tmp_path / "ro.tok"))
    client.call("GET", "/version")
    assert seen[0].headers["authorization"].startswith("PVEAPIToken=op@pam!read=") and "cookie" not in seen[0].headers
    _serve_ticket(served, _ticket(prefix="PBS"))                        # a PBS ticket at PVE's served path
    client, seen = _wire(monkeypatch, served)
    with pytest.raises(ProximoError, match="another box or product"):
        client.call("GET", "/version")
    assert seen == []


# --- the lens (2026-11-05): five majors, eight minors, folded by class -----------------------------------

def test_a_ticket_is_exactly_the_vendors_shape_and_nothing_else(served):
    """Lens 1 and 13: a ticket with a newline was accepted, served, read back as armed, and printed whole by
    an h11 error. A ticket is PREFIX:user@realm:HEX8::base64 and nothing else; a user with `!` is a token."""
    good = _ticket()
    assert arm.ticket_fields(good) == ("PVE", "op@pam", int(good.split(":")[2], 16))
    for bad in (good.replace("::", "::ab\ncd", 1), good + "\n", good.replace(":", ":\r", 1),
                "PVE:op@pam!tok:0000000A::" + SIG, "PVE:op@pam:0000000A:extra::" + SIG, "PVE:op@pam:0000000A::",
                "PVE:op@pam:zzzzzzzz::" + SIG, "PVE:op@pam:0000000A::s:g", 'PVE:op@pam:0000000A::si"g',
                "PVE:!tfa!op@pam:0000000A::" + SIG):
        assert arm.ticket_fields(bad) is None, bad
        _serve_ticket(served, bad)
        assert arm.served_credential(str(served))[0] == "unreadable", bad
    _serve_ticket(served, good, csrf="CSRF:1:ab\ncd")
    assert arm.served_credential(str(served))[0] == "unreadable"


def test_a_cookie_or_csrf_in_any_error_text_is_scrubbed():
    """Lens 1: the scrubber knew the token headers, not the cookie and CSRF ones the wire now sends."""
    from proximo.core.secretfile import redact
    for text in ("Illegal header value b'PVEAuthCookie=PVE:op@pam:6AEC::sig'", "PBSAuthCookie=PBS:a@b:1::s; x",
                 "PDMAuthCookie=PDM:a@b:1::s", "CSRFPreventionToken: 6AEC:abcdef", "CSRFPreventionToken=6AEC:abcdef"):
        out = redact(text)
        assert "op@pam" not in out and "6AEC" not in out and "a@b" not in out, out


def test_a_ticket_file_never_arms_pmg(served):
    """Lens 2: PMG's wire logs in with a password; a hand-written PMG ticket file at its password path read armed."""
    _serve_ticket(served, _ticket("PMG", "root@pam"), box="https://pmg.invalid:8006/api2/json")
    for credential in (False, True):
        plane = wire.Plane("pmg", "https://pmg.invalid:8006/api2/json", str(served), credential=credential)
        state = arm.arm_state(plane)
        assert not state.armed and "PMG" in state.reason


def test_a_box_that_names_nothing_never_matches(served, monkeypatch):
    """Lens 5: a ticket whose box normalised to "" matched an unset base URL."""
    for box in ("/", "   ", " / "):
        _serve_ticket(served, _ticket(), box=box)
        assert arm.served_credential(str(served))[0] == "unreadable", box
    _serve_ticket(served, _ticket())
    monkeypatch.delenv("PROXIMO_API_BASE_URL")
    assert not arm.arm_state().armed
    assert not arm.arm_state(wire.Plane("pve", "", str(served))).armed


@pytest.mark.parametrize("answer", ["PVE-garbage-no-colons-0123456789", "PVE:op@pam:ZZZZZZZZ::" + SIG,
                                    "PVE:op@pam:0000000A::ab\ncd"])
def test_arm_refuses_a_ticket_it_cannot_read_before_it_writes_anything(
        served, monkeypatch, terminal, capsys, tmp_path, answer):
    """Lens 3: the verb served the vendor's answer first and parsed it second; a ticket the reader rejects clobbered
    the served file and died uncaught with no row."""
    terminal.append("pw")
    _vendor(monkeypatch, [{"ticket": answer, "CSRFPreventionToken": "CSRF:1:abcdef", "username": "op@pam"}])
    before = served.read_text()
    assert cli.main(["arm"]) == cli.EXIT_REFUSED
    assert served.read_text() == before and "Traceback" not in capsys.readouterr().err
    assert [(r["action"], r["outcome"]) for r in _rows(tmp_path)] == [("core.arm", "refused")]


@pytest.mark.parametrize("body", [("text", "<html>"), ("json", {"data": None}), ("json", {"data": "x"}), ("json", {})])
def test_a_login_answer_that_is_not_a_login_refuses_with_a_row_and_no_traceback(served, monkeypatch, terminal, capsys,
                                                                                tmp_path, body):
    """Lens 6."""
    terminal.append("pw")
    kind, payload = body

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=payload) if kind == "text" else httpx.Response(200, json=payload)
    monkeypatch.setattr(wire.httpx, "Client", lambda **kw: _REAL_CLIENT(
        transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "verify"}))
    before = served.read_text()
    assert cli.main(["arm"]) == cli.EXIT_REFUSED
    assert served.read_text() == before and "Traceback" not in capsys.readouterr().err
    assert [(r["action"], r["outcome"]) for r in _rows(tmp_path)] == [("core.arm", "refused")]


def test_a_second_factor_asked_twice_and_a_closed_prompt_both_refuse_cleanly(served, monkeypatch, terminal, capsys):
    challenge = "PVE:!tfa!op@pam:0000000A::" + SIG
    terminal.extend(["pw", "123456"])
    _vendor(monkeypatch, [{"ticket": challenge, "CSRFPreventionToken": "", "username": "op@pam"},
                          {"ticket": challenge, "CSRFPreventionToken": "", "username": "op@pam"}])
    assert cli.main(["arm"]) == cli.EXIT_REFUSED and "Traceback" not in capsys.readouterr().err
    monkeypatch.setattr(cli, "_prompt_secret", lambda label: (_ for _ in ()).throw(EOFError()))
    assert cli.main(["arm"]) == cli.EXIT_USAGE and "Traceback" not in capsys.readouterr().err


def test_the_password_is_a_registered_secret_the_moment_it_is_sent(served, monkeypatch):
    """Lens 7."""
    from proximo.core.secretfile import redact
    _vendor(monkeypatch, [{"ticket": _ticket(), "CSRFPreventionToken": "CSRF:1:x", "username": "op@pam"}])
    wire.ticket_login(_plane(served), "op@pam", "S3cretPassw0rd!")
    assert "S3cretPassw0rd" not in redact("boom username=op%40pam&password=S3cretPassw0rd!&new-format=1")


def test_a_served_line_without_a_token_name_gives_no_default_user(served, monkeypatch, terminal, capsys):
    """Lens 8: the fallback took the line up to `!`; a line with `@` and no `!` put the whole secret on stderr."""
    served.write_text("secret@realm.with.no.bang=THISISTHESECRETVALUE")
    terminal.append("pw")
    assert cli.main(["arm"]) == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "THISISTHESECRETVALUE" not in err and "--user" in err


def test_the_read_only_token_sent_for_a_dead_or_future_ticket_keeps_the_permission_floor(served, monkeypatch, tmp_path):
    """Lens 10."""
    ro = tmp_path / "ro.tok"
    _serve_ticket(served, _ticket(age=-120))                                 # from the future: not trusted
    client, seen = _wire(monkeypatch, served, readonly=str(ro))
    client.call("GET", "/version")
    assert seen[0].headers["authorization"].startswith("PVEAPIToken=op@pam!read=")
    ro.chmod(0o644)
    _serve_ticket(served, _ticket(age=arm.TICKET_LIFETIME + 5))
    client, seen = _wire(monkeypatch, served, readonly=str(ro))
    with pytest.raises((ProximoError, RuntimeError), match="group/other"):    # the floor's own refusal
        client.call("GET", "/version")
    assert seen == []


def test_the_served_label_names_a_ticket_as_a_ticket(served):
    """Lens 11."""
    _serve_ticket(served, _ticket())
    assert engine.served_label(arm.arm_state(_plane(served))) == "the served ticket, armed at plan time"
    _serve_ticket(served, _ticket(age=arm.TICKET_LIFETIME + 5))
    label = engine.served_label(arm.arm_state(_plane(served)))
    assert label.startswith("the served credential, not armed at plan time") and "ticket died" in label


def test_a_registry_target_arms_by_name_logging_into_its_own_box(served, monkeypatch, terminal, tmp_path):
    """Lens 4: `--serve <a target's token path>` logged into the ENV box as the target's user and served the env
    box's ticket at the target's path. A target is armed by name: its box, its file, its user."""
    ttok = tmp_path / "target.tok"
    ttok.write_text("targetuser@pam!read=44444444-4444-4444-4444-444444444444")
    ttok.chmod(0o600)
    reg = tmp_path / "targets.toml"
    reg.write_text(f"[targets.other]\nkind = 'pve'\nbase_url = 'https://other.invalid:8006/api2/json'\n"
                   f"token_path = '{ttok}'\n")
    monkeypatch.setenv("PROXIMO_TARGETS", str(reg))
    terminal.append("pw")
    answer = {"ticket": _ticket(user="targetuser@pam"), "CSRFPreventionToken": "c", "username": "targetuser@pam"}
    seen = _vendor(monkeypatch, [answer])
    assert cli.main(["arm", "--target", "other"]) == 0
    assert seen[0].url.host == "other.invalid" and "username=targetuser%40pam" in seen[0].content.decode()
    from proximo.core import registry
    target = registry.plane("pve", "other")
    assert target is not None and arm.arm_state(target).armed
    assert arm.served_credential(str(served))[0] == "token"                    # the env box is untouched
    assert cli.main(["arm", "--target", "nowhere"]) == cli.EXIT_USAGE


def test_the_verbs_own_reader_refuses_what_the_file_reader_would(served):
    """The verb reads the vendor's answer through `credential_from_bytes` before it serves it. The login refuses
    the same shapes first, so this belt is reached only when the login lets one through; it is pinned here."""
    good = json.dumps({"ticket": _ticket(), "csrf": "CSRF:1:abcdef", "box": BOX}).encode()
    assert arm.credential_from_bytes(good)[0] == "ticket"
    assert arm.credential_from_bytes(b"[]")[0] == "token"        # not a ticket file: token bytes the vendor judges
    for bad in (b"", b"{", json.dumps({"ticket": _ticket() + "\n", "csrf": "c", "box": BOX}).encode(),
                json.dumps({"ticket": _ticket(), "csrf": "c\nd", "box": BOX}).encode(),
                json.dumps({"ticket": _ticket(), "csrf": "c", "box": "/"}).encode(),
                json.dumps({"ticket": "PVE:!tfa!op@pam:0000000A::" + SIG, "csrf": "c", "box": BOX}).encode()):
        kind, why = arm.credential_from_bytes(bad)
        assert kind == "unreadable" and isinstance(why, str) and why, bad
