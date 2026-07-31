"""PrincipalMiddleware — the camera at the perimeter (Task 5, spec 2026-07-16).

Badge-verified caller identity for network faces: pins configured + protected path + no/invalid
badge -> 401 (the face's ``unauthorized_body``) + a globally-bounded refusal audit entry (<=1 per
60s, process-wide, folded count — never per-source, a claimed sub is attacker-controlled). A valid
badge sets ``principal.ledger_principal()``'s ContextVar for the request only (reset in
``finally``), and ``caller_arrived`` is recorded once per caller per process. With NO
``PROXIMO_CALLER_KEYS_DIR`` the middleware is absent entirely — byte-identical to the pre-Task-5
stack. Unprotected (discovery) paths stay untouched either way.

Mirrors the starlette test-app shape used across ``tests/test_httpface_*.py`` (``TestClient`` for
sync cases) and ``tests/test_a2a_e2e.py`` (``httpx.ASGITransport`` for the concurrency case).
Badge minting reuses the ``_keypair_pem()`` shape from ``tests/test_principal_badge.py``.
"""
from __future__ import annotations

import json

import anyio
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from proximo import principal, webguard
from proximo.principal import mint_badge, public_jwk
from proximo.webguard import guard_middleware

LOCAL = "http://127.0.0.1"


def _keypair_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pin(pin_dir, name: str) -> bytes:
    """Mint a fresh EC keypair, pin its public JWK as ``<name>.jwk``, return the private PEM."""
    pem = _keypair_pem()
    (pin_dir / f"{name}.jwk").write_text(json.dumps(public_jwk(pem, name)))
    return pem


async def _echo(request):
    return JSONResponse({"principal": principal.ledger_principal()})


def _mk_app(*, token: str = "tkn", route=_echo) -> Starlette:  # noqa: S107 — test sentinel, not a real credential
    mw = guard_middleware(f"{LOCAL}:8811", face="HTTP", token=token,
                          protect=lambda p: p.startswith("/tools/"),
                          unauthorized_body={"error": "unauthorized"})
    return Starlette(routes=[Route("/tools/echo", route, methods=["POST"]),
                             Route("/openapi.json", route, methods=["GET"])], middleware=mw)


def _ledger_lines(tmp_path) -> list[dict]:
    log = tmp_path / "audit.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch, tmp_path):
    """Isolate every test from real env + the two pieces of process-wide state.

    ``webguard._refusal_state`` (the global refusal bound) and each ``PrincipalMiddleware``
    instance's ``_seen`` set are process-wide BY DESIGN (the refusal bound must not be
    per-source — a claimed sub is attacker-controlled; ``_seen`` dedupes ``caller_arrived``
    across the process). Tests reset ``_refusal_state`` directly between cases rather than
    weaken that contract; a fresh app (hence a fresh ``PrincipalMiddleware`` + fresh ``_seen``)
    is built per test via ``_mk_app``.

    The ledger is redirected by monkeypatching ``server._svc`` directly to return a real
    ``AuditLedger`` rooted at ``tmp_path`` — the same config-cache-avoiding pattern
    ``tests/test_principal.py``'s ``_wire_ledger`` helper uses, so these tests need no PVE
    API env triple (``server._ledger()`` reads ``_svc()[3]``).
    """
    from proximo import server
    from proximo.audit import AuditLedger

    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    webguard._refusal_state = {"window_start": 0.0, "folded": 0}
    # serving_face is set once per real entrypoint (httpface/a2a main()), outside webguard's own
    # job — set it here so ledger_principal()'s "face" reads "http", matching a real HTTP face.
    principal.set_serving_face("http")
    yield
    principal.set_serving_face("stdio")


# --- no pins configured: stack + behavior identical to today ---------------------------------


def test_no_pins_stack_has_no_principal_layer():
    app = _mk_app()
    names = [m.cls.__name__ for m in app.user_middleware]
    assert "PrincipalMiddleware" not in names


def test_no_pins_header_ignored():
    client = TestClient(_mk_app(), base_url=LOCAL)
    r = client.post("/tools/echo", json={},
                    headers={"Authorization": "Bearer tkn",
                             "Proximo-Principal": "garbage.not.a.badge"})
    assert r.status_code == 200
    assert r.json()["principal"] is None


# --- pins configured: fail-closed + bounded refusal audit -------------------------------------


def test_pins_no_badge_401_and_bounded_refusal_audit(monkeypatch, tmp_path):
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))
    client = TestClient(_mk_app(), base_url=LOCAL)

    for _ in range(20):
        r = client.post("/tools/echo", json={}, headers={"Authorization": "Bearer tkn"})
        assert r.status_code == 401
        assert r.json() == {"error": "unauthorized"}
        assert r.headers["WWW-Authenticate"] == "Proximo-Principal"

    entries = [e for e in _ledger_lines(tmp_path) if e["action"] == "caller_refused"]
    assert len(entries) == 1, f"expected exactly 1 folded refusal entry, got {len(entries)}"
    assert entries[0]["outcome"] == "blocked:unverified_caller"
    assert entries[0]["detail"]["folded_prior_window"] == 0  # very first window: nothing prior


def test_refusal_second_window_carries_prior_folded_count(monkeypatch, tmp_path):
    """Within-window refusals only increment the counter; the NEXT window's first refusal
    records an entry carrying that prior window's folded count."""
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))
    client = TestClient(_mk_app(), base_url=LOCAL)

    for _ in range(5):
        client.post("/tools/echo", json={}, headers={"Authorization": "Bearer tkn"})
    assert len(_ledger_lines(tmp_path)) == 1  # only the window's first refusal recorded so far

    webguard._refusal_state["window_start"] = 0.0  # force the next refusal into a "new" window
    client.post("/tools/echo", json={}, headers={"Authorization": "Bearer tkn"})

    entries = [e for e in _ledger_lines(tmp_path) if e["action"] == "caller_refused"]
    assert len(entries) == 2
    assert entries[1]["detail"]["folded_prior_window"] == 4  # 5 refusals: 1 recorded + 4 folded


def test_pins_invalid_badge_401(monkeypatch, tmp_path):
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))
    client = TestClient(_mk_app(), base_url=LOCAL)

    stranger = _keypair_pem()
    forged = mint_badge(stranger, "fleet-7")  # valid shape, unpinned key
    r = client.post("/tools/echo", json={},
                    headers={"Authorization": "Bearer tkn", "Proximo-Principal": forged})
    assert r.status_code == 401
    # No badge material anywhere in the response...
    assert forged not in json.dumps(r.json())
    assert forged not in "".join(r.headers.values())
    # ...nor in the audit ledger (the refusal entry carries only a fold count, never the badge).
    assert forged not in (tmp_path / "audit.log").read_text()
    _ = pem  # unused; keeps the pin_dir fixture shape symmetric with siblings


# --- valid badge: ContextVar set for the request, caller_arrived once per caller --------------


def test_pins_valid_badge_ledger_verified(monkeypatch, tmp_path):
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))
    client = TestClient(_mk_app(), base_url=LOCAL)

    badge = mint_badge(pem, "fleet-7")
    r = client.post("/tools/echo", json={},
                    headers={"Authorization": "Bearer tkn", "Proximo-Principal": badge})
    assert r.status_code == 200
    assert r.json()["principal"] == {"id": "fleet-7", "via": "verified", "face": "http"}
    # The "ContextVar reset in finally / no leak past the request" check does NOT belong here —
    # see test_context_var_reset_does_not_leak_past_request below for why and how it's tested.


async def test_context_var_reset_does_not_leak_past_request(monkeypatch, tmp_path):
    """``PrincipalMiddleware`` must reset the ``_active_caller`` ContextVar in ``finally``, so a
    verified caller from one request is never visible after that request completes.

    This is deliberately NOT tested by posting through the full ``guard_middleware()`` stack
    (``_mk_app()``) and checking ``principal.ledger_principal()`` in the test coroutine right
    after ``await client.post(...)`` returns — that check would be vacuous EVEN with
    ``httpx.ASGITransport`` in the same event loop/thread (i.e. even without ``TestClient``'s
    separate-thread problem the reviewer flagged). Reason: ``starlette.middleware.base.
    BaseHTTPMiddleware.__call__`` runs its OWN downstream app via ``task_group.start_soon``, so
    EVERY ``BaseHTTPMiddleware`` layer ahead of ``PrincipalMiddleware`` in the real stack
    (``CrossOriginGuardMiddleware``, ``BearerAuthMiddleware``) forks a fresh child-task context at
    that layer. ``PrincipalMiddleware.dispatch`` therefore always runs in a context that is a
    grandchild of the calling test coroutine's context — contextvars.Context mutations never
    propagate UP a task tree, so the caller test's own context reads ``None`` whether or not the
    ``finally: reset_active_caller(token)`` line is even present. Verified empirically both ways
    (see the report) before writing this test.

    The property IS genuinely observable when ``PrincipalMiddleware`` is the sole/outermost
    middleware: then its ``dispatch`` runs INLINE in the same task/context as the caller (no
    earlier ``BaseHTTPMiddleware`` layer has forked a child task yet), so ``set_active_caller``
    and ``reset_active_caller`` mutate the SAME context this test reads afterward. That is what
    this test builds — a minimal app with ONLY ``PrincipalMiddleware``, not the full perimeter —
    specifically so the assertion below is meaningful rather than trivially true.
    """
    from starlette.middleware import Middleware

    from proximo.principal import load_pins
    from proximo.webguard import PrincipalMiddleware

    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    pins = load_pins(str(pin_dir))

    mw = [Middleware(PrincipalMiddleware, pins=pins, protect=lambda p: p.startswith("/tools/"),
                     face="http", unauthorized_body={"error": "unauthorized"})]
    app = Starlette(routes=[Route("/tools/echo", _echo, methods=["POST"])], middleware=mw)
    transport = httpx.ASGITransport(app=app)

    badge = mint_badge(pem, "fleet-7")
    async with httpx.AsyncClient(transport=transport, base_url=LOCAL) as hx:
        r = await hx.post("/tools/echo", json={}, headers={"Proximo-Principal": badge})

    assert r.status_code == 200
    assert r.json()["principal"] == {"id": "fleet-7", "via": "verified", "face": "http"}
    # SAME coroutine, immediately after — genuinely meaningful here (see docstring above).
    assert principal.ledger_principal() is None


def test_caller_arrived_once(monkeypatch, tmp_path):
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))
    client = TestClient(_mk_app(), base_url=LOCAL)
    badge = mint_badge(pem, "fleet-7")

    for _ in range(2):
        r = client.post("/tools/echo", json={},
                        headers={"Authorization": "Bearer tkn", "Proximo-Principal": badge})
        assert r.status_code == 200

    arrivals = [e for e in _ledger_lines(tmp_path) if e["action"] == "caller_arrived"]
    assert len(arrivals) == 1
    assert arrivals[0]["detail"] == {"caller": "fleet-7"}
    assert arrivals[0]["principal"] == {"id": "fleet-7", "via": "verified", "face": "http"}


def test_discovery_untouched_with_pins(monkeypatch, tmp_path):
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))
    client = TestClient(_mk_app(), base_url=LOCAL)

    r = client.get("/openapi.json")  # no badge, no bearer — discovery stays open
    assert r.status_code == 200


# --- the load-bearing concurrency gate (spec test 7b) -----------------------------------------


async def test_cross_bleed_two_concurrent_callers(monkeypatch, tmp_path):
    """Two concurrent requests, two different badges: each response must echo ITS OWN verified
    caller via ``principal.ledger_principal()``. If ContextVar propagation through
    ``BaseHTTPMiddleware`` leaked between requests, one or both would observe the other's caller
    (or a stale/absent one) — that failure must not be papered over by weakening this test.

    Proves the concurrency is REAL (not accidentally serialized) by recording each request's
    start/end monotonic timestamps and asserting their in-handler windows actually overlap —
    a purely-sequential run would fail that overlap assertion even if the identity check happened
    to pass, so the test cannot pass for the wrong (serialized) reason.
    """
    import time

    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    fleet_pem = _pin(pin_dir, "fleet-7")
    ci_pem = _pin(pin_dir, "ci-runner")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))

    events: list[tuple[str | None, str, float]] = []  # (caller, "start"|"end", monotonic ts)

    async def _echo_traced(request):
        p = principal.ledger_principal()
        caller = p["id"] if p else None
        events.append((caller, "start", time.monotonic()))
        await anyio.sleep(0.05)  # yield the loop — the real interleaving window
        events.append((caller, "end", time.monotonic()))
        return JSONResponse({"principal": p})

    app = _mk_app(route=_echo_traced)
    transport = httpx.ASGITransport(app=app)
    results: dict[str, object] = {}

    async def _call(name: str, pem: bytes) -> None:
        badge = mint_badge(pem, name)
        async with httpx.AsyncClient(transport=transport, base_url=LOCAL) as hx:
            r = await hx.post("/tools/echo", json={},
                              headers={"Authorization": "Bearer tkn", "Proximo-Principal": badge})
            results[name] = (r.status_code, r.json()["principal"])

    async with anyio.create_task_group() as tg:
        tg.start_soon(_call, "fleet-7", fleet_pem)
        tg.start_soon(_call, "ci-runner", ci_pem)

    assert results["fleet-7"] == (200, {"id": "fleet-7", "via": "verified", "face": "http"})
    assert results["ci-runner"] == (200, {"id": "ci-runner", "via": "verified", "face": "http"})

    starts = {caller: ts for caller, phase, ts in events if phase == "start"}
    ends = {caller: ts for caller, phase, ts in events if phase == "end"}
    assert set(starts) == {"fleet-7", "ci-runner"}, f"expected both callers traced, got {events}"
    # Genuine overlap: each request started before the OTHER finished.
    assert starts["fleet-7"] < ends["ci-runner"], "requests did not overlap — ran serialized"
    assert starts["ci-runner"] < ends["fleet-7"], "requests did not overlap — ran serialized"


# --- startup fail-loud: a bad pin dir must refuse the app build, not silently degrade ---------


def test_bad_pins_dir_refuses_startup(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(tmp_path / "does-not-exist"))
    with pytest.raises(RuntimeError):
        _mk_app()


# --- revocation must hold against a RUNNING process, not just a fresh load_pins() ------------
#
# SECURITY.md tells operators the only revocation is deleting the caller's pin file. The unit
# test that claimed to cover this (test_revocation_is_unpin) called load_pins() FRESH after the
# delete and asserted against that new dict — so it only ever proved the loader skips a file that
# is gone. It never drove an already-built app across two requests, which is the only shape that
# can see the real behaviour: guard_middleware loaded pins ONCE at build time and the middleware
# held that dict for the process lifetime, so a deleted caller kept being honoured.

def test_deleting_a_pin_revokes_against_an_already_running_app(tmp_path, monkeypatch):
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))

    app = _mk_app()                       # built ONCE — never rebuilt below
    client = TestClient(app, base_url=LOCAL)
    badge = mint_badge(pem, "fleet-7")
    hdrs = {"Authorization": "Bearer tkn", "Proximo-Principal": badge}

    ok = client.post("/tools/echo", headers=hdrs)
    assert ok.status_code == 200, "control failed: the badge should be accepted while pinned"
    assert ok.json()["principal"]["via"] == "verified"

    (pin_dir / "fleet-7.jwk").unlink()    # the documented revocation

    revoked = client.post("/tools/echo", headers=hdrs)
    assert revoked.status_code == 401, (
        "a deleted pin did NOT revoke the caller on the running process — SECURITY.md says "
        "deleting the pin file IS the revocation")
