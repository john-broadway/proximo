"""The output scrubber: every secret Proximo reads by path is registered at read time, and any
text that leaves through an exception is scrubbed of registered literals and auth-header shapes.

Field read 2026-09-20: two rivals ship a tested redaction layer over error output;
Proximo cut HTTP errors to a status line and kept secrets out of ProximoError by design, but had
no general scrubber. On mcp 1.x the SDK renders str(e) of ANY in-tool exception to the model, so
a subprocess error carrying an argv password, or an httpx error carrying an auth header, walked
straight out. One seam: `_secretfile.read_secret` registers; `ProximoError.__init__` scrubs its
own message; `targets.target_aware` scrubs the args of anything else a plane tool raises. The
door tools (`proximo_call`, `proximo_read`, `audit_*`) re-raise inner exceptions, which are
already scrubbed; a bare exception raised by the door itself is the documented boundary."""

from __future__ import annotations

import pytest

from proximo import _secretfile
from proximo.backends import ProximoError

SEC = "sentinel-secret-9f3a7c1e"


@pytest.fixture(autouse=True)
def _clean_registry():
    _secretfile.clear_registered_secrets()
    yield
    _secretfile.clear_registered_secrets()


def test_redact_hides_registered_literals_and_header_shapes():
    _secretfile.register_secret(SEC)
    assert _secretfile.redact(f"boom: {SEC} in the body") == "boom: <redacted> in the body"
    # the four wire shapes Proximo itself sends, even when the value was never registered
    assert _secretfile.redact("Authorization: PVEAPIToken=u@pam!t=abc-123") == "Authorization: PVEAPIToken=<redacted>"
    assert _secretfile.redact("hdr PBSAPIToken=u@pbs!t:abc-123 tail") == "hdr PBSAPIToken=<redacted> tail"
    assert _secretfile.redact("PDMAPIToken u@pdm!t:abc-123") == "PDMAPIToken <redacted>"
    assert _secretfile.redact("Authorization: Bearer eyJhbGciOi.xx.yy done") == "Authorization: Bearer <redacted> done"


def test_redact_is_a_no_op_without_a_match():
    """The control: text with nothing registered and no shape passes through byte-identical."""
    text = "arm lease expired: 'pve_guest_power' refused — armed 7203s ago; re-arm to continue"
    assert _secretfile.redact(text) == text
    assert _secretfile.redact("") == ""


def test_short_secrets_are_not_registered():
    """A rival's 2026 incident: a one-character secret shredded every gate message into noise. Floor is
    eight characters; below it the value is not registered (the header shapes still scrub)."""
    _secretfile.register_secret("secret")  # 6 chars: the fixtures' favourite
    _secretfile.register_secret("")
    assert _secretfile.redact("secret sauce") == "secret sauce"
    assert _secretfile.registered_count() == 0


def test_read_secret_reads_strips_and_registers_both_halves(tmp_path):
    p = tmp_path / "tok"
    p.write_text(f"user@pam!id={SEC}\n")
    p.chmod(0o600)
    assert _secretfile.read_secret(str(p), "PVE token file") == f"user@pam!id={SEC}"
    assert _secretfile.redact(f"x user@pam!id={SEC} y") == "x <redacted> y"
    assert _secretfile.redact(f"bare {SEC}") == "bare <redacted>"
    q = tmp_path / "pbs"
    q.write_text(f"backup@pbs!t:{SEC}-colon\n")
    q.chmod(0o600)
    _secretfile.read_secret(str(q), "PBS token file")
    assert _secretfile.redact(f"{SEC}-colon") == "<redacted>"


def test_read_secret_floors_only_when_asked(tmp_path):
    """The floor lives at config load (every loader calls refuse_exposed_secret before it builds a
    client); the reader only re-runs it for the per-call checkers (the audit anchor)."""
    p = tmp_path / "tok"
    p.write_text(f"user@pam!id={SEC}\n")
    p.chmod(0o644)
    assert _secretfile.read_secret(str(p), "PVE token file").endswith(SEC)
    with pytest.raises(RuntimeError, match="group/other-accessible"):
        _secretfile.read_secret(str(p), "PVE token file", floor=True)


def test_proximo_error_scrubs_its_own_message():
    _secretfile.register_secret(SEC)
    e = ProximoError(f"download refused: HTTP 401 body={SEC}")
    assert SEC not in str(e)
    assert "<redacted>" in str(e)
    assert isinstance(e, RuntimeError)
    # non-string args are left alone
    assert ProximoError(42).args == (42,)


def test_target_aware_scrubs_a_foreign_exception_in_place():
    """The 1.x surface: the SDK renders str(e) of whatever a tool raised. Type and cause chain
    must survive (governed.py reads the type name); only the text changes."""
    from proximo.targets import target_aware

    _secretfile.register_secret(SEC)
    inner = KeyError("k")

    @target_aware
    def tool(vmid: str) -> dict:
        raise ValueError(f"ssh root@host pct exec 9 -- mysqldump --password={SEC} db") from inner

    with pytest.raises(ValueError) as exc:
        tool(vmid="9")
    assert SEC not in str(exc.value)
    assert "--password=<redacted>" in str(exc.value)
    assert exc.value.__cause__ is inner
    assert type(exc.value) is ValueError


def test_the_boundary_a_plain_function_outside_the_wrapper_still_leaks():
    """Documented limit, pinned so it is a choice: the scrubber lives on the tool boundary and in
    ProximoError, not on every exception in the process."""
    _secretfile.register_secret(SEC)

    def plain():
        raise ValueError(f"leaks {SEC}")

    with pytest.raises(ValueError) as exc:
        plain()
    assert SEC in str(exc.value)


def test_every_backend_registers_its_secret_on_first_use(tmp_path, monkeypatch):
    """The four planes plus the web bearer: constructing the client and building the auth header
    (the read site) must leave the secret in the registry."""
    from proximo.backends import ApiBackend, ProximoConfig
    from proximo.pbs import PbsBackend, PbsConfig
    from proximo.pdm import PdmBackend, PdmConfig
    from proximo.pmg import PmgBackend, PmgConfig

    def tokfile(name: str, body: str) -> str:
        p = tmp_path / name
        p.write_text(body + "\n")
        p.chmod(0o600)
        return str(p)

    pve = tokfile("pve", f"u@pam!t={SEC}-pve")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="x1", token_path=pve, audit_log_path=str(tmp_path / "a.log")
    )
    ApiBackend(cfg)._auth_header()
    assert _secretfile.redact(f"{SEC}-pve") == "<redacted>"

    pbs = tokfile("pbs", f"u@pbs!t:{SEC}-pbs")
    PbsBackend(PbsConfig(base_url="https://x:8007", token_path=pbs, verify_tls=True, ca_bundle=None))._auth_header()
    assert _secretfile.redact(f"{SEC}-pbs") == "<redacted>"

    pdm = tokfile("pdm", f"u@pdm!t:{SEC}-pdm")
    PdmBackend(PdmConfig(base_url="https://x:8443", token_path=pdm, verify_tls=True, ca_bundle=None))._auth_header()
    assert _secretfile.redact(f"{SEC}-pdm") == "<redacted>"

    pmg = tokfile("pmg", f"{SEC}-pmg-password")
    cfg_pmg = PmgConfig(
        base_url="https://x:8006", username="root@pam", password_path=pmg, verify_tls=True, ca_bundle=None
    )
    PmgBackend(cfg_pmg)._read_password()
    assert _secretfile.redact(f"{SEC}-pmg-password") == "<redacted>"


def test_a_bad_argument_echo_is_scrubbed_at_the_wire():
    """Lens 2026-09-20 (BLOCKING): the SDK validates arguments BEFORE the tool body runs, so a
    caller-supplied value that fails coercion is echoed by pydantic OUTSIDE target_aware, and
    ValidationError carries no args[0] to scrub anyway. The wire handler Proximo owns on both
    majors (1.x: the re-registered CallToolRequest handler; 2.x: the call_tool override) is the
    seam that sees every error text on its way to the model."""
    import anyio

    import proximo.server as server
    from proximo import _mcpcompat as compat

    _secretfile.register_secret(SEC)

    @server.tool()
    def _redact_probe_int(x: int) -> dict:
        """READ-ONLY: probe."""
        return {"x": x}

    try:

        async def go():
            args = {"x": f"not-an-int-{SEC}"}
            if compat.MCP_MAJOR == 1:
                await server._proximo_call_tool("_redact_probe_int", args)
            else:
                await server.mcp.call_tool("_redact_probe_int", args)

        with pytest.raises(Exception) as exc:  # noqa: B017 — the SDK's ToolError, whichever major
            anyio.run(go)
        assert SEC not in str(exc.value), str(exc.value)
        assert "<redacted>" in str(exc.value)
    finally:
        server.mcp.remove_tool("_redact_probe_int")


def test_no_subprocess_call_in_the_tree_raises_called_process_error():
    """Lens M1: CalledProcessError renders its argv from .cmd, not args[0], so the boundary scrub
    is a no-op for it. Today no subprocess.run in src passes check=True (exec results are
    captured into ExecResult), so it is never raised; pin that so the first check=True is a
    visible choice that must also route through _audited_run's fixed messages."""
    import pathlib
    import re

    root = pathlib.Path(server_src := __import__("proximo").__file__).parent
    hits = []
    for p in sorted(root.rglob("*.py")):
        pat = r"subprocess\.(?:run|check_output|check_call)\((?:[^()]|\([^()]*\))*\)"
        for m in re.finditer(pat, p.read_text(), re.S):
            if "check=True" in m.group(0) or "check_output" in m.group(0) or "check_call" in m.group(0):
                hits.append(f"{p.relative_to(root)}: {m.group(0)[:80]}")
    assert not hits, hits
    assert server_src  # keep the import honest
