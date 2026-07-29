"""Tests for the release leak-audit — it models the PUBLIC publish transform.

Pure logic (path partition + leak-shape scan + allowlist + inline-allow marker) is unit-tested
with synthetic inputs; the git I/O (`files_in_ref`, `build_public_tree`) is tested against the
real repo. `test_current_public_surface_is_leak_clean` is the live gate: the actual tree that
would publish (after stripping deny paths) must carry no leak shapes.

NOTE: fixtures here use FAKE-but-flaggable values (a made-up internal-TLD host, a 172.31.x private
IP, a fake /root-style path), never real infrastructure, and each fixture line carries a
`leak-audit: allow` marker so this file stays clean under its own live gate.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import release_leak_audit as rla  # noqa: E402


def _git_out(args: list[str]) -> str:
    return subprocess.run(["git", *args], cwd=str(REPO_ROOT),  # noqa: S603, S607
                          capture_output=True, text=True, check=True).stdout


# --- pure: deny-path partition ---
def test_deny_prefixed_paths_are_stripped_not_kept():
    files = {".gitea/workflows/ci.yml": "x", "src/proximo/server.py": "y"}
    res = rla.audit_files(files)
    assert ".gitea/workflows/ci.yml" in res.stripped
    assert "src/proximo/server.py" in res.kept
    assert ".gitea/workflows/ci.yml" not in res.kept


def test_leak_inside_a_stripped_file_is_not_reported():
    # An internal host inside .gitea is removed from the public tree, so it must NOT be a finding.
    files = {".gitea/workflows/ci.yml": "url=forge.internal:3000"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert res.ok
    assert res.findings == []


def test_design_docs_are_stripped_from_public_tree():
    # docs/plans/ + docs/specs/ are our engineering design docs — internal by John's call 2026-07-13.
    files = {
        "docs/plans/2026-06-15-blast-radius-engine.md": "design memo",
        "docs/specs/2026-06-15-acl-blast-radius.md": "spec",
        "docs/plans/internal/COPY-CANON.md": "build-record",
        "docs/TOOLS.md": "user-facing tool reference",
        "README.md": "x",
    }
    res = rla.audit_files(files)
    assert "docs/plans/2026-06-15-blast-radius-engine.md" in res.stripped
    assert "docs/specs/2026-06-15-acl-blast-radius.md" in res.stripped
    assert "docs/plans/internal/COPY-CANON.md" in res.stripped
    assert "docs/TOOLS.md" in res.kept  # user-facing docs still publish
    assert "README.md" in res.kept


def test_claude_md_is_stripped_from_public_tree():
    # CLAUDE.md carries internal dev-memory — it must never reach the public mirror.
    files = {"CLAUDE.md": "internal dev-memory", "README.md": "x", "src/proximo/server.py": "y"}
    res = rla.audit_files(files)
    assert "CLAUDE.md" in res.stripped
    assert "CLAUDE.md" not in res.kept
    assert "README.md" in res.kept  # other root markdown still publishes


def test_leak_inside_claude_md_is_not_reported():
    # CLAUDE.md is stripped from the public tree, so internal content inside it must NOT be a finding.
    files = {"CLAUDE.md": "deploys to forge.internal:3000"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert res.ok
    assert res.findings == []


# --- pure: content leak shapes ---
def test_internal_tld_hostname_is_flagged():
    files = {"docs/x.md": "clone from forge.internal:3000 today"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert any(f.kind == "internal-host" for f in res.findings)


def test_rfc1918_ip_is_flagged():
    files = {"smoke.py": "API = 172.31.0.99 here"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert any(f.kind == "rfc1918-ip" for f in res.findings)


def test_absolute_root_path_is_flagged():
    files = {"a.py": "open('/root/secret/file')"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert any(f.kind == "root-path" for f in res.findings)


def test_pypi_token_shape_is_flagged():
    files = {"a.py": "T = 'pypi-AgEIcHlwaS5vcmcAbcd1234EFGHijkl5678'"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert any(f.kind == "token" for f in res.findings)


# --- pure: site-specific internal-identifier denylist (bare names with no generic shape) ---
def test_deny_literal_hostname_is_flagged():
    files = {"docs/x.md": "run the smoke on fakehost9000 today"}
    res = rla.audit_files(files, deny_literals=("fakehost9000",))
    assert any(f.kind == "internal-literal" and f.match == "fakehost9000" for f in res.findings)


def test_deny_literal_match_is_case_insensitive():
    files = {"docs/x.md": "node FAKEHOST9000 reported"}
    res = rla.audit_files(files, deny_literals=("fakehost9000",))
    assert any(f.kind == "internal-literal" for f in res.findings)


def test_deny_literal_is_word_boundaried_no_substring_false_positive():
    # a longer token that merely CONTAINS the literal must not trip the gate
    files = {"docs/x.md": "var fakehost90001x = 1"}
    res = rla.audit_files(files, deny_literals=("fakehost9000",))
    assert not any(f.kind == "internal-literal" for f in res.findings)


def test_no_deny_literals_means_no_internal_literal_findings():
    files = {"docs/x.md": "run on fakehost9000"}
    res = rla.audit_files(files)  # default: empty denylist -> generic gate only
    assert not any(f.kind == "internal-literal" for f in res.findings)


def test_load_deny_literals_reads_internal_only_file():
    # the real denylist lives under a stripped (.gitea) path and names the real node; loading it
    # should return a non-empty, lowercased tuple (so a bare internal hostname can be caught).
    lits = rla.load_deny_literals()
    assert isinstance(lits, tuple)
    assert all(s == s.lower() for s in lits)


# --- pure: competitor-name denylist (rival handles/products that must not leak into public copy) ---
def test_competitor_name_is_flagged():
    files = {"README.md": "faster than RivalMCP by design"}
    res = rla.audit_files(files, competitor_names=("RivalMCP",))
    assert any(f.kind == "competitor-name" and f.match == "RivalMCP" for f in res.findings)


def test_competitor_name_match_is_case_insensitive():
    files = {"docs/x.md": "compared with rivalmcp here"}
    res = rla.audit_files(files, competitor_names=("RivalMCP",))
    assert any(f.kind == "competitor-name" for f in res.findings)


def test_competitor_name_is_word_boundaried_no_substring_false_positive():
    # a longer token that merely CONTAINS the name must not trip the gate
    files = {"docs/x.md": "the RivalMCPExtended fork"}
    res = rla.audit_files(files, competitor_names=("RivalMCP",))
    assert not any(f.kind == "competitor-name" for f in res.findings)


def test_no_competitor_names_means_no_competitor_findings():
    files = {"README.md": "faster than RivalMCP"}
    res = rla.audit_files(files)  # default: empty competitor list -> generic gate only
    assert not any(f.kind == "competitor-name" for f in res.findings)


def test_competitor_name_inside_stripped_file_is_not_reported():
    # The internal landscape legitimately names rivals; it is stripped, so it must NOT be a finding.
    files = {"docs/internal/LANDSCAPE.md": "RivalMCP has 200 stars"}
    res = rla.audit_files(files, competitor_names=("RivalMCP",))
    assert res.ok
    assert res.findings == []


def test_load_competitor_names_reads_internal_only_file():
    # the denylist lives under a stripped (.gitea) path so the public tool names no rival; loading it
    # returns a lowercased tuple (empty on a public clone where the file is absent).
    names = rla.load_competitor_names()
    assert isinstance(names, tuple)
    assert all(s == s.lower() for s in names)


def test_current_public_surface_has_no_competitor_names():
    # The real publish surface must name no tracked rival — the competitor denylist over kept files.
    res = rla.audit_files(
        rla.files_in_ref("HEAD"),
        deny_literals=rla.load_deny_literals(),
        competitor_names=rla.load_competitor_names(),
    )
    assert res.ok, "competitor/internal leak in public surface:\n" + "\n".join(
        f"  {f.kind} {f.path}:{f.line}: {f.match}" for f in res.findings
    )


def test_root_ellipsis_placeholder_is_not_flagged():
    # `/root/...` in prose is rule-text, not a real path.
    files = {"CLAUDE.md": "no absolute `/root/...` paths in tracked files"}
    assert rla.audit_files(files).ok


def test_root_in_grep_pattern_is_not_flagged():
    # `/root/` as a delimiter inside a leak-grep pattern is documentation, not a path.
    files = {"docs/p.md": "grep -nE '/root/|secret' diff"}
    assert rla.audit_files(files).ok


def test_finding_records_path_and_line():
    files = {"a.py": "ok line\nbad = 172.31.9.9\n"}  # leak-audit: allow
    res = rla.audit_files(files)
    hit = next(f for f in res.findings if f.kind == "rfc1918-ip")
    assert hit.path == "a.py"
    assert hit.line == 2


def test_inline_allow_marker_suppresses_that_line():
    files = {"t.md": "ip 172.31.0.5  # leak-audit: allow\nip 172.31.0.6\n"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert all(f.line != 1 for f in res.findings)   # marked line suppressed
    assert any(f.line == 2 for f in res.findings)    # unmarked line still flagged


# --- pure: allowlist of documented examples (must NOT flag) ---
def test_rfc5737_doc_ip_is_allowed():
    files = {"README.md": "PROXIMO_API=https://192.0.2.10:8006"}
    assert rla.audit_files(files).ok


def test_example_sdn_range_is_allowed():
    files = {"scripts/live-smoke/sdn-smoke.py": 'CIDR = "10.99.99.0/24"'}
    assert rla.audit_files(files).ok


def test_example_hostname_is_allowed():
    files = {"README.md": "PROXIMO_API=https://pve.example.com:8006"}
    assert rla.audit_files(files).ok


def test_clean_file_yields_no_findings():
    files = {"src/proximo/server.py": "def main():\n    return 0\n"}
    res = rla.audit_files(files)
    assert res.ok and res.findings == []


# --- integration against the real repo (deterministic) ---
def test_files_in_ref_returns_tracked_text_files():
    files = rla.files_in_ref("HEAD")
    assert "pyproject.toml" in files
    assert isinstance(files["pyproject.toml"], str)
    assert "[project]" in files["pyproject.toml"]


def test_build_public_tree_strips_gitea_keeps_source():
    sha = rla.build_public_tree("HEAD")
    listing = _git_out(["ls-tree", "-r", "--name-only", sha])
    assert "pyproject.toml" in listing
    assert ".gitea/" not in listing


def test_build_public_tree_strips_claude_md():
    # The published tree must strip CLAUDE.md (DENY_BASENAMES), not just deny PREFIXES — a
    # basename-only deny is invisible to a prefix `git rm -r`, so build-tree must use the SAME
    # partition_paths logic as audit() or the two drift (audit says "stripped", tree publishes it).
    sha = rla.build_public_tree("HEAD")
    listing = _git_out(["ls-tree", "-r", "--name-only", sha]).splitlines()
    assert "CLAUDE.md" not in listing
    assert not any(p.endswith("/CLAUDE.md") for p in listing)


def test_build_public_tree_matches_audit_stripped_set():
    # Guard against drift: every text path build-tree publishes must be one audit() would KEEP.
    published = set(_git_out(["ls-tree", "-r", "--name-only", rla.build_public_tree("HEAD")]).splitlines())
    res = rla.audit_files(rla.files_in_ref("HEAD"))
    for p in res.stripped:
        assert p not in published, f"{p} was stripped by audit but still published by build-tree"


def test_build_public_tree_does_not_touch_real_index_or_worktree():
    before = _git_out(["status", "--porcelain"])
    rla.build_public_tree("HEAD")
    after = _git_out(["status", "--porcelain"])
    assert before == after


def test_current_public_surface_is_leak_clean():
    # The real publish surface (kept files, .gitea stripped) must carry no leak shapes — including
    # site-specific internal identifiers from the (stripped) denylist file.
    res = rla.audit_files(rla.files_in_ref("HEAD"), deny_literals=rla.load_deny_literals())
    assert res.ok, "leak shapes in public surface:\n" + "\n".join(
        f"  {f.kind} {f.path}:{f.line}: {f.match}" for f in res.findings
    )
