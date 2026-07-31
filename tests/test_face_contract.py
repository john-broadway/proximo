"""The transport-face contract, made structural: a face is a mouth, not a brain.

Transport-agnosticism is only real if it's enforced. Every network face must (1) route tool
calls through ``governed.call_governed``/``list_governed`` — never import a Proxmox backend or
call the service builders directly, (2) touch ``server`` only for the three sanctioned seams
(``_apply_surfaces`` registry scoping, ``_ledger`` rejection audits, ``_record_session``
arrival/departure entries) plus any per-face seam granted explicitly in EXTRA_SERVER_ATTRS
(today: ``server.mcp`` for the MCP-native face, which serves the spine's own protocol and so has
nothing to adapt), and (3) mount the ONE shared perimeter stack from ``webguard.guard_middleware``,
in its contract order. A new face inherits the spine by following these imports; this test refuses
the shortcut that would give a transport its own path.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "proximo"

# Every module that implements or enters a network face. A NEW FACE MUST BE ADDED HERE —
# test_new_face_modules_are_listed below fails if a face-shaped module appears unlisted.
FACE_SOURCES = (
    "httpface.py",
    "_http_entry.py",
    "_a2a_entry.py",
    "a2a/app.py",
    "a2a/executor.py",
    "a2a/card.py",
    "a2a/signing.py",
    "a2a/__main__.py",
    "a2a/__init__.py",
    "mcphttp.py",
    "_mcp_http_entry.py",
)

# A face must never reach these — they are the core's internals, behind the governed dispatch.
FORBIDDEN = (
    r"\bfrom \.+backends\b",          # the Proxmox client builders
    r"\bimport backends\b",
    r"\bProxmoxAPI\b",                # the raw client
    r"server\._svc\b",                # service builders — the spine wraps these
    r"server\._pbs\b",
    r"server\._pmg\b",
    r"server\._pdm\b",
    r"\b_audited\s*\(",               # calling the funnel directly = skipping name-based dispatch
)

# The ONLY server attributes a face may touch (the three sanctioned seams).
ALLOWED_SERVER_ATTRS = {"_apply_surfaces", "_ledger", "_record_session"}

# Per-face EXTRA seams, granted individually so the global set stays tight. The MCP-HTTP face's
# whole purpose is serving the FastMCP instance over the SDK's native transport — `server.mcp`
# IS the spine (governed.call_governed itself delegates to server.mcp.call_tool), so serving it
# is not a bypass; it is the one face with nothing to adapt. No other face gets this seam: a
# foreign-protocol face (REST, A2A) touching server.mcp would be skipping governed dispatch.
EXTRA_SERVER_ATTRS = {"mcphttp.py": {"mcp"}}


def _source(rel: str) -> str:
    return (SRC / rel).read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", FACE_SOURCES)
def test_face_never_touches_core_internals(rel):
    text = _source(rel)
    hits = [pat for pat in FORBIDDEN if re.search(pat, text)]
    assert not hits, f"{rel} reaches core internals ({hits}) — faces go through governed.call_governed."


def _server_module_names(tree: ast.AST) -> set[str]:
    """Every local name bound to proximo's ``server`` module.

    The bare AST check keys off ``Name('server')`` — but a face could import the module under
    another name (``from proximo import server as srv``) or reach it by its dotted path
    (``import proximo.server``) and touch the seam without the token ``server`` ever appearing.
    This resolves those bindings so ``srv.mcp`` / ``proximo.server.mcp`` read as seams too. Only
    proximo imports are tracked — an SDK's own ``from mcp import server`` is a different module
    and is intentionally NOT bound.
    """
    names = {"server"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "proximo" or (node.module is None and (node.level or 0) >= 1):
                names |= {a.asname or "server" for a in node.names if a.name == "server"}
        elif isinstance(node, ast.Import):
            names |= {a.asname for a in node.names if a.name == "proximo.server" and a.asname}
    return names


def _is_server_ref(node: ast.AST, names: set[str]) -> bool:
    """*node* refers to proximo's server module: a tracked name, or the dotted ``proximo.server``."""
    if isinstance(node, ast.Name):
        return node.id in names
    return (
        isinstance(node, ast.Attribute) and node.attr == "server"
        and isinstance(node.value, ast.Name) and node.value.id == "proximo"
    )


def _server_attr_uses(tree: ast.AST, names: set[str]) -> set[str]:
    """Attributes touched on proximo's ``server`` module — AST, not regex (0.24 review finding).

    The AST closes the false-POSITIVE class the old text scan suffered (an SDK's ``x.server.y`` is
    rooted at its own name ``x``, never a bare ``server``), and ``names`` closes the cheap
    false-NEGATIVES a static scan CAN resolve — the import alias and the dotted module path. What
    stays open — a fully dynamic reach (``getattr(server, ...)``, ``sys.modules[...]``) — is
    documented and asserted in ``test_seam_detector_scope_is_honest``; the real defense there is
    code review, not this test. An honest heuristic, not a sandbox.
    """
    return {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and _is_server_ref(node.value, names)
    }


@pytest.mark.parametrize("rel", FACE_SOURCES)
def test_face_server_seams_are_the_sanctioned_three(rel):
    tree = ast.parse(_source(rel))
    used = _server_attr_uses(tree, _server_module_names(tree))
    allowed = ALLOWED_SERVER_ATTRS | EXTRA_SERVER_ATTRS.get(rel, set())
    stray = used - allowed
    assert not stray, (
        f"{rel} uses server.{sorted(stray)} — a face may touch only "
        f"{sorted(allowed)}; everything else goes through the governed dispatch."
    )


def _roots_at_server(node: ast.expr, names: set[str]) -> bool:
    """True when *node* is a server reference or a bare ``server.attr[.attr…]`` chain (no Call)."""
    if _is_server_ref(node, names):
        return True
    while isinstance(node, ast.Attribute):
        node = node.value
        if _is_server_ref(node, names):
            return True
    return False


@pytest.mark.parametrize("rel", FACE_SOURCES)
def test_face_never_aliases_server(rel):
    """Binding ``server`` (or a bare ``server.attr`` chain) to a name would let every later use
    dodge the seam scan — the hop-off the 0.24 review called (``m = server.mcp``). Assignments
    of call RESULTS stay legal (``app = server.mcp.streamable_http_app()`` binds a return value,
    not the seam). A deliberate heuristic over assignment forms, not full dataflow.
    """
    tree = ast.parse(_source(rel))
    names = _server_module_names(tree)
    offending = [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr))
        and node.value is not None and _roots_at_server(node.value, names)
    ]
    assert not offending, (
        f"{rel} lines {offending}: aliasing server (or a server.* attribute chain) hides seam "
        f"usage from this contract — use server.<attr> directly at every site."
    )


def test_seam_detector_scope_is_honest():
    """What the AST seam scan catches — and, said plainly, what it does not. The gap is asserted
    rather than hidden, so nobody mistakes a heuristic for a sandbox (the regex version drew the
    same honest line; the AST moves the import-alias and dotted-path cases onto the caught side).
    """
    def attrs(src: str) -> set[str]:
        tree = ast.parse(src)
        return _server_attr_uses(tree, _server_module_names(tree))

    # CAUGHT — a future face written any of these ways still trips the contract:
    assert attrs("server.mcp.call_tool()") == {"mcp"}                           # the bare seam
    assert attrs("from proximo import server as srv\nsrv._svc()") == {"_svc"}   # import alias
    assert attrs("import proximo.server\nproximo.server._pbs()") == {"_pbs"}    # dotted path
    assert attrs("import proximo.server as ps\nps._pmg()") == {"_pmg"}          # aliased dotted
    # NOT a false positive — SDK namespaces and call results stay excused:
    assert attrs("from mcp.server.transport_security import TransportSecuritySettings") == set()
    assert attrs("app = server.mcp.streamable_http_app()") == {"mcp"}

    # NOT CAUGHT — a static scan cannot resolve a fully dynamic reach. Documented, not hidden:
    # the real defense against these is code review, not this test.
    assert attrs("m = getattr(server, 'mcp')\nm.call_tool()") == set()
    assert attrs("import sys\nsys.modules['proximo.server'].mcp.call_tool()") == set()


def test_tool_calling_faces_route_through_governed():
    # The two modules that actually execute tools must do it via the governed dispatch.
    for rel in ("httpface.py", "a2a/executor.py"):
        assert "call_governed" in _source(rel), f"{rel} does not route through governed.call_governed"


def test_new_face_modules_are_listed():
    """A face-shaped module (mounts middleware / serves a port) must be in FACE_SOURCES."""
    face_shaped = re.compile(r"guard_middleware|uvicorn\.run|Starlette\(")
    listed = {str(Path(rel)) for rel in FACE_SOURCES}
    for path in SRC.rglob("*.py"):
        rel = str(path.relative_to(SRC))
        if rel.startswith(("tools/",)) or rel in ("webguard.py",):
            continue
        if rel in listed:
            continue
        text = path.read_text(encoding="utf-8")
        assert not face_shaped.search(text), (
            f"{rel} looks like a transport face (middleware/serve/Starlette) but is not in "
            f"FACE_SOURCES — add it so the contract covers it."
        )


def _middleware_names(app) -> list[str]:
    return [m.cls.__name__ for m in app.user_middleware]


def test_faces_mount_the_same_perimeter_in_contract_order(monkeypatch, tmp_path):
    """Every factory produces the identical guard stack — the faces cannot drift.

    Also covers the conditional Principal layer (Task 5): with NO ``PROXIMO_CALLER_KEYS_DIR`` the
    stack is byte-identical to before; with it set, ``PrincipalMiddleware`` is appended LAST —
    after ``BearerAuthMiddleware`` when both are configured — per the contract order TrustedHost ->
    CrossOriginGuard -> Bearer -> Principal.
    """
    a2a_app_mod = pytest.importorskip("proximo.a2a.app")
    from proximo.httpface import build_app as build_http
    from proximo.mcphttp import build_app as build_mcp_http

    without = ["TrustedHostMiddleware", "CrossOriginGuardMiddleware"]
    with_token = [*without, "BearerAuthMiddleware"]

    assert _middleware_names(build_http(token="sentinel-token")) == with_token
    assert _middleware_names(build_http()) == without
    assert _middleware_names(a2a_app_mod.build_app(token="sentinel-token")) == with_token
    assert _middleware_names(a2a_app_mod.build_app()) == without
    # The MCP-HTTP face mounts the stack onto the SDK-built app — same contract, same order.
    assert _middleware_names(build_mcp_http(token="sentinel-token")) == with_token
    assert _middleware_names(build_mcp_http()) == without

    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(tmp_path))  # empty dir: 0 pins, still valid
    with_pins = [*without, "PrincipalMiddleware"]
    with_token_and_pins = [*with_token, "PrincipalMiddleware"]

    assert _middleware_names(build_http()) == with_pins
    assert _middleware_names(build_http(token="sentinel-token")) == with_token_and_pins
    assert _middleware_names(a2a_app_mod.build_app()) == with_pins
    assert _middleware_names(a2a_app_mod.build_app(token="sentinel-token")) == with_token_and_pins
    # The third face (mcp-http) landed AFTER this feature was written. One perimeter means it
    # cannot be the one face without a camera — pin the Principal layer on it too.
    assert _middleware_names(build_mcp_http()) == with_pins
    assert _middleware_names(build_mcp_http(token="sentinel-token")) == with_token_and_pins


# --- the contract must REQUIRE the seams, not only forbid the wrong ones --------------------
#
# Every test above is a prohibition: a face may not touch core internals, may not reach past the
# sanctioned seams. None of them require a face to actually USE those seams — so mcp-http shipped
# for two weeks tagging its NETWORK ledger entries face:"stdio" (the local-trust default) and
# recording no session entries, with the whole suite green. A prohibition-only contract cannot see
# an omission. This is the positive half.

SERVING_FACES = ("httpface.py", "a2a/app.py", "mcphttp.py")


@pytest.mark.parametrize("rel", SERVING_FACES)
def test_every_serving_face_declares_which_face_it_is(rel):
    """principal.serving_face() is a process global defaulting to "stdio". A network face that
    never sets it attributes its own remote requests to the local channel, in the tamper-evident
    log — a false statement, not a missing nicety."""
    tree = ast.parse(_source(rel))
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "set_serving_face"]
    assert calls, f"{rel} never calls set_serving_face() — its ledger entries will claim 'stdio'"
    literals = [a.value for c in calls for a in c.args if isinstance(a, ast.Constant)]
    assert literals and all(v != "stdio" for v in literals), (
        f"{rel} must name its own face, not the stdio default (got {literals!r})")


@pytest.mark.parametrize("rel", SERVING_FACES)
def test_every_serving_face_records_arrival_and_departure(rel):
    """Session entries are how a ledger reader knows a face was up. One face silently omitting
    them makes the ledger's coverage uneven in a way no reader can detect from the outside."""
    text = _source(rel)
    assert text.count("_record_session(") >= 2, (
        f"{rel} does not record both session_start and session_end")
    for kind in ("session_start", "session_end"):
        assert kind in text, f"{rel} never records {kind}"
    assert "finally:" in text, f"{rel} must record session_end in a finally, or a crash loses it"


# --- the try/finally is the POINT, so pin it with a crash ------------------------------------
#
# Every face wraps uvicorn.run in try/finally so session_end still lands when serving dies. Every
# test of that wrap monkeypatched uvicorn.run to a lambda that never raises — so a reviewer's
# mutant replacing the try/finally with plain sequential calls passed the whole suite. The test I
# added for mcp-http earlier the same day had the identical hole: I copied the pattern including
# its defect. A no-op double cannot test crash safety. Make it crash.

@pytest.mark.parametrize("mod_name,face", [("proximo.httpface", "http"),
                                           ("proximo.a2a.app", "a2a"),
                                           ("proximo.mcphttp", "mcp-http")])
def test_session_end_still_lands_when_serving_crashes(mod_name, face, tmp_path, monkeypatch):
    import uvicorn  # noqa: PLC0415

    from proximo import principal, server  # noqa: PLC0415
    from proximo.audit import AuditLedger  # noqa: PLC0415

    mod = pytest.importorskip(mod_name)

    log = tmp_path / "audit.log"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "svc-account")
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)

    def _boom(*a, **kw):
        raise RuntimeError("bind failed")

    monkeypatch.setattr(uvicorn, "run", _boom)
    try:
        with pytest.raises(RuntimeError, match="bind failed"):
            mod.main()
    finally:
        principal.set_serving_face("stdio")

    lines = [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
    ends = [e for e in lines if e["action"] == "session_end"]
    assert len(ends) == 1, (
        f"{mod_name}: serving crashed and session_end never landed — the try/finally is not doing "
        "the job its comment claims")
    assert ends[0]["detail"]["face"] == face
