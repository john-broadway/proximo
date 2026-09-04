"""`proximo reach-audit` — the reach-privilege decision packet for the mirror.

Pins: (1) the aliasing report separates the STANDING hazard (roles carrying the candidate
privilege — every future grant of those roles silently extends shell reach) from TODAY'S
exposure (current ACL grants of those roles), and flags `/` grants in pve_overbroad_grants'
vocabulary, (2) derivation asks PVE per guest path — the granularity discovery: a guest whose
reach comes ONLY via pool propagation has no `/vms/<id>` key in the full map, and a deeper
NoAccess revokes; both are pinned so the primitive can never regress to reading the full map,
(3) the output names WHOSE map was derived (the token id — never the secret), (4) the derived
set is compared against the current env allowlist as added/removed, (5) the verb is print-only,
skips surface scoping, and announces its query count before hammering anything.
"""
from __future__ import annotations

import proximo.server as srv
from proximo import reach_audit


class _Api:
    """Double with the estate this design was probed against: 101 granted directly, 102
    reachable ONLY via pool propagation (absent from any full map — the per-path query is the
    sole truth), 103 revoked by a deeper NoAccess."""

    def __init__(self):
        self.perm_queries = []

    def _get(self, path):
        if path == "/access/roles":
            return [
                {"roleid": "Administrator", "privs": "VM.Console,Sys.Modify,VM.Audit"},
                {"roleid": "ClaudeOps", "privs": "VM.Console,VM.Audit"},
                {"roleid": "PVEAuditor", "privs": "VM.Audit"},
            ]
        if path == "/access/acl":
            return [
                {"path": "/", "roleid": "ClaudeOps", "ugid": "root@pam!claude", "type": "token",
                 "propagate": 1},
                {"path": "/pool/prod", "roleid": "Administrator", "ugid": "ops@pve",
                 "type": "user", "propagate": 1},
                {"path": "/", "roleid": "PVEAuditor", "ugid": "proximo@pve!readonly",
                 "type": "token", "propagate": 1},
            ]
        raise AssertionError(f"unexpected GET {path}")

    def access_permissions(self, path=None):
        assert path is not None, "the audit must query PER PATH — the full map lies by omission"
        self.perm_queries.append(path)
        vmid = path.rsplit("/", 1)[-1]
        if vmid == "101":
            return {path: {"VM.Console": 1, "VM.Audit": 1}}
        if vmid == "102":  # pool-membership case: reach exists ONLY via propagation
            return {path: {"VM.Console": 1}}
        if vmid == "103":  # deeper NoAccess: PVE resolves to nothing
            return {}
        return {path: {"VM.Audit": 1}}


def test_alias_report_separates_roles_from_grants():
    api = _Api()
    rep = reach_audit.alias_report(api, "VM.Console")
    assert rep["roles"] == ["Administrator", "ClaudeOps"]  # the standing hazard
    grants = {(g["ugid"], g["path"]) for g in rep["grants"]}
    assert ("root@pam!claude", "/") in grants and ("ops@pve", "/pool/prod") in grants
    assert ("proximo@pve!readonly", "/") not in grants     # PVEAuditor doesn't carry it
    root = rep["root_grants"]
    assert len(root) == 1 and root[0]["ugid"] == "root@pam!claude"
    assert any("EVERY resource" in r for r in root[0]["reasons"])  # overbroad vocabulary reused


def test_derived_reach_queries_per_guest_path():
    api = _Api()
    got = reach_audit.derived_reach(api, ["101", "102", "103"], "VM.Console")
    assert got == {"101": True, "102": True, "103": False}
    assert api.perm_queries == ["/vms/101", "/vms/102", "/vms/103"]


def test_token_id_never_the_secret(tmp_path):
    tok = tmp_path / "t"
    tok.write_text("svc@pve!mirror=sentinel-secret-value\n")
    tid = reach_audit.token_id_of(str(tok))
    assert tid == "svc@pve!mirror"
    assert "sentinel" not in tid


def test_render_compares_against_current_allowlist(monkeypatch):
    api = _Api()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,103")
    out = reach_audit.render(api, ["101", "102", "103"], ["VM.Console"],
                             token_id="svc@pve!mirror")
    assert "svc@pve!mirror" in out                       # whose map, named
    assert "queries" in out.lower()                      # count announced
    assert "+102" in out and "-103" in out            # delta vs today's grant
    assert "Administrator" in out and "ClaudeOps" in out # standing hazard visible


def test_cli_reach_audit_prints_and_never_serves(monkeypatch, capsys):
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "reach-audit", "--ctids", "101",
                                          "--priv", "VM.Console"])
    monkeypatch.setattr(srv.mcp, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("SERVED")))
    monkeypatch.setattr(reach_audit, "_api_and_token",
                        lambda token_path=None: (_Api(), "svc@pve!mirror"))
    srv.main()
    out = capsys.readouterr().out
    assert "VM.Console" in out and "svc@pve!mirror" in out


def test_reach_audit_in_the_noise_skip_tuple():
    """The quiet-verb tuple moved out of main() on 2026-09-03 (one tuple now gates BOTH the
    surface-scoping line and the env-file loader's lines); the property is unchanged: reach-audit
    is in it, and main() consults the gate before _apply_surfaces."""
    import inspect
    assert "reach-audit" in srv._QUIET_STDERR_VERBS, "reach-audit missing from the quiet-verb tuple"
    import re
    src = inspect.getsource(srv.main)
    # The gate must be THE condition on the _apply_surfaces call, not merely a substring that
    # appears somewhere earlier in main() (lens B: `if True:` in front of _apply_surfaces left
    # the loader's own `announce=not _quiet_stderr_verb()` in place and a substring search green).
    assert re.search(r"if not _quiet_stderr_verb\(\):\s*\n\s*try:\s*\n\s*_apply_surfaces\(\)", src), \
        "main() must gate _apply_surfaces() on `if not _quiet_stderr_verb():` directly"


def test_default_candidates_are_a_visible_tuple():
    assert isinstance(reach_audit.CANDIDATES, tuple) and "VM.Console" in reach_audit.CANDIDATES


def test_every_default_candidate_has_a_semantics_line():
    # The packet informs TWO axes: aliasing AND semantic fit. A candidate in the default
    # sweep with no semantics entry would print the unknown-priv fallback and silently
    # drop the second axis — so the mapping must cover the tuple.
    for priv in reach_audit.CANDIDATES:
        assert priv in reach_audit.CANDIDATE_SEMANTICS


def test_render_states_console_semantics_and_both_lanes(monkeypatch):
    # VM.Console gates a console ATTACH (login prompt), not execution — keying the mirror
    # on it would grant more than PVE means by the grant (John's catch, 2026-08-26). The
    # packet must say so beside the aliasing evidence, and the footer must present BOTH
    # lanes (de facto built-in vs custom role) rather than steering to one.
    api = _Api()
    monkeypatch.delenv("PROXIMO_CT_ALLOWLIST", raising=False)
    out = reach_audit.render(api, ["101"], ["VM.Console"], token_id="svc@pve!mirror")
    assert "semantics:" in out
    assert "NOT execution" in out and "MORE than PVE means" in out
    assert "de facto BUILT-IN" in out and "CUSTOM ROLE" in out


def test_render_unknown_priv_gets_semantics_fallback(monkeypatch):
    # An operator can audit any --priv; one outside the swept set must not print a wrong
    # semantics claim — it gets the check-it-yourself fallback instead.
    api = _Api()
    monkeypatch.delenv("PROXIMO_CT_ALLOWLIST", raising=False)
    out = reach_audit.render(api, ["101"], ["Sys.Audit"], token_id="svc@pve!mirror")
    assert "not in the swept set" in out


def test_token_id_refuses_unknown_shapes(tmp_path):
    # Lens finding: PBS/PDM token files on this estate use 'id:secret' (colon) — one
    # --token-path slip away. A splitter failing open would print the WHOLE secret; the
    # refusal must carry none of the file's content.
    import pytest as _pytest
    colon = tmp_path / "pbs"
    colon.write_text("svc@pbs!backup:sentinel-colon-secret\n")
    with _pytest.raises(ValueError) as ei:
        reach_audit.token_id_of(str(colon))
    assert "sentinel" not in str(ei.value)
    junk = tmp_path / "junk"
    junk.write_text("just-some-line-with-no-equals\n")
    with _pytest.raises(ValueError) as ei2:
        reach_audit.token_id_of(str(junk))
    assert "just-some-line" not in str(ei2.value)


def test_ctid_key_survives_isdigit_int_disagreement():
    # '²'.isdigit() is True while int('²') raises — the lens's crash input.
    out = sorted(["²", "101", "abc"], key=reach_audit._ctid_key)
    assert out[0] == "101"  # numerics first, hostiles fall to the string bucket


def test_render_header_carries_the_true_query_count():
    hdr = reach_audit.render_header(["1", "2"], ["A", "B", "C"], token_id="x@y!z")
    assert "6 per-path" in hdr and "+6 roles/ACL reads" in hdr


def test_cli_error_is_a_plain_message_not_a_trace(monkeypatch, capsys):
    import pytest as _pytest
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "reach-audit", "--ctids", "101"])
    monkeypatch.setattr(reach_audit, "_api_and_token",
                        lambda token_path=None: (_ for _ in ()).throw(
                            RuntimeError("Missing required Proximo env var: X")))
    with _pytest.raises(SystemExit) as ei:
        srv.main()
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("proximo reach-audit:") and "Traceback" not in err


def test_usage_block_names_reach_audit(monkeypatch, capsys):
    import pytest as _pytest
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "--help"])
    with _pytest.raises(SystemExit):
        srv.main()
    assert "reach-audit" in capsys.readouterr().out
