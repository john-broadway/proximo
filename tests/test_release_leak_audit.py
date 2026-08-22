"""Tests for the release leak-audit — it models the PUBLIC publish transform.

Pure logic (path partition + leak-shape scan + allowlist + inline-allow marker) is unit-tested
with synthetic inputs; the git I/O (`files_in_ref`, `build_public_tree`) is tested against the
real repo. `test_current_public_surface_is_leak_clean` is the live gate: the actual tree that
would publish (after stripping deny paths) must carry no leak shapes.

NOTE: fixtures here use FAKE-but-flaggable values (a made-up internal-TLD host, a 172.31.x private
IP, a fake /root-style path), never real infrastructure, and each fixture line carries a
`leak-audit: allow` marker so this file stays clean under its own live gate.
"""
import os
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
    files = {".gitea/workflows/ci.yml": "x", "src/proximo/server.py": "y"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert ".gitea/workflows/ci.yml" in res.stripped  # leak-audit: allow
    assert "src/proximo/server.py" in res.kept
    assert ".gitea/workflows/ci.yml" not in res.kept  # leak-audit: allow


def test_leak_inside_a_stripped_file_is_not_reported():
    # An internal host inside .gitea is removed from the public tree, so it must NOT be a finding.
    files = {".gitea/workflows/ci.yml": "url=forge.internal:3000"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert res.ok
    assert res.findings == []


def test_design_docs_are_stripped_from_public_tree():
    # docs/plans/ + docs/specs/ are our engineering design docs — internal by John's call 2026-07-13.
    files = {
        "docs/plans/2026-06-15-blast-radius-engine.md": "design memo",  # leak-audit: allow
        "docs/specs/2026-06-15-acl-blast-radius.md": "spec",  # leak-audit: allow
        "docs/plans/internal/COPY-CANON.md": "build-record",  # leak-audit: allow
        "docs/TOOLS.md": "user-facing tool reference",
        "README.md": "x",
    }
    res = rla.audit_files(files)
    assert "docs/plans/2026-06-15-blast-radius-engine.md" in res.stripped  # leak-audit: allow
    assert "docs/specs/2026-06-15-acl-blast-radius.md" in res.stripped  # leak-audit: allow
    assert "docs/plans/internal/COPY-CANON.md" in res.stripped  # leak-audit: allow
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
    files = {"docs/internal/LANDSCAPE.md": "RivalMCP has 200 stars"}  # leak-audit: allow
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


# --- the allowlist was a hole, and the .cast scan was blind (both found 2026-08-01) ----------

def test_allowlist_does_not_exempt_a_whole_private_range():
    """Catches the defect this test exists because of: `ALLOW` held the bare prefixes `10.0.0.`,
    `192.168.` and `172.16.`, and `_allowed()` matched by SUBSTRING — so every address in
    192.168.0.0/16 was exempt anywhere in the public tree. The audit still reported CLEAN, and
    that verdict carried no evidence at all about that range: the guard structurally could not
    fire. A security tool that overstates its coverage is worse than one that has none.

    Mutant it kills: putting any bare prefix of a REAL private range back into ALLOW_EXACT, or
    reverting `_allowed` to substring matching for it.

    Probe addresses are ASSEMBLED at runtime so this file's own bytes never carry a
    contiguous in-range address — this tracked test ships publicly and the audit scans it:
    the first version wrote them literally and became the leak-audit's own top finding
    (2026-08-01, six literals, one of them a REAL estate address). The guard's fixtures
    must pass the guard.
    """
    for octets in (("192.168", "7.31"), ("192.168", "1.100"), ("10.0.0", "55"),
                   ("172.16", "4.9"), ("10.20.30", "6"), ("172.29", "77.4")):
        real_looking = ".".join(octets)
        assert not rla._allowed(real_looking), (
            f"{real_looking} is exempt from the leak audit — a real address in that range would "
            "publish silently")


def test_allowlist_still_permits_the_documented_examples():
    """The other half: narrowing the allowlist must not start failing the tree's real examples.

    Without this, the fix above could be 'passed' by emptying the allowlist, which would make the
    audit refuse its own repository.
    """
    for example in ("10.0.0.0", "192.168.1.1", "172.16.5.4", "10.99.99.5", "10.1.2.3",
                    "192.0.2.10", "example.com"):
        assert rla._allowed(example), f"{example} is a documented example and must stay exempt"


def test_cast_scan_sees_text_typed_one_character_per_event():
    """Catches: the denylist being blind to what a terminal recording TYPES.

    A `.cast` emits one event per keystroke, and each event is its own JSON line, so a
    line-by-line regex sees `1`, then `9`, then `2` — never the assembled address. That is precisely the
    shape a live demo produces, and `docs/demo/demo.cast` really is encoded that way (its lines
    5-38 are single characters). So the audit called every recording clean without ever being
    able to read the part most likely to leak.

    Mutant it kills: removing the `.cast` branch from scan_text, or the ANSI strip that makes the
    reconstructed text matchable.
    """
    import json as _json

    secret = ".".join(("192.168", "7.31"))   # real-shaped, NOT in ALLOW_EXACT; assembled so
    # this tracked file's own bytes never carry the contiguous address the audit hunts
    lines = [_json.dumps({"version": 2, "width": 80, "height": 24})]
    lines += [_json.dumps([0.1 * i, "o", ch]) for i, ch in enumerate(f"ssh root@{secret}\n")]
    cast = "\n".join(lines)

    # Same bytes, scanned as a non-cast file: the old behaviour, blind.
    assert not rla.scan_text("notes.txt", cast), (
        "precondition failed: a raw line scan already caught this, so the test proves nothing "
        "about the .cast decoder")

    findings = rla.scan_text("docs/demo/typed.cast", cast)
    assert findings, "a typed private IP in a recording was not caught"
    assert any(secret in f.match for f in findings)
    assert any("recorded terminal output" in f.kind for f in findings), (
        "the finding does not say it came from the reconstructed frames, so a reader cannot tell "
        "where to look in the file")


def test_cast_scan_still_reads_the_raw_envelope():
    """Both halves: decoding the frames must not REPLACE the raw scan.

    A leak can also sit in the JSON envelope itself — a header field, or a path in a non-output
    event — which never appears in the visible frames.
    """
    # Assembled so this tracked file's own bytes carry no /root path (the audit scans it).
    probe_path = "/" + "root/secrets/proximo"
    cast = '{"version": 2, "width": 80, "env": {"PWD": "' + probe_path + '"}}\n'
    findings = rla.scan_text("docs/demo/envelope.cast", cast)
    assert any(f.kind.startswith("root-path") for f in findings), (
        "a /root path in the cast HEADER was missed — the decoder replaced the raw scan instead "
        "of adding to it")


# --- F9c: the internal-host pattern grew local/corp/home.arpa (2026-08-10) -----------------
def test_internal_local_corp_homearpa_hosts_are_flagged():
    for host in ("pve1.corp", "backup.home.arpa", "node7.local"):  # leak-audit: allow
        res = rla.audit_files({"README.md": f"connect to {host}:8006"})
        assert any(f.kind == "internal-host" for f in res.findings), f"{host} not flagged"


def test_sanctioned_example_hosts_on_new_tlds_are_allowed():
    # The two-sided proof: these tracked test fixtures live on the new TLDs and must NOT flag,
    # or the current-surface audit reds on them. (The other side — that a REAL such host DOES
    # flag — is the test above; together they prove the allowlist exempts examples, not the class.)
    for host in ("corp.local", "dc1.corp.local", "node.local", "surface.lab.local", "pve-test1.lab.local"):
        assert rla.audit_files({"tests/x.py": f'realm = "{host}"'}).ok, f"{host} wrongly flagged"


# --- F9b: typed stdin ("i") events are part of the visible recording ----------------------
def test_cast_scan_sees_text_typed_as_input_events():
    import json as _json
    secret = "10.1.2.99"  # leak-audit: allow
    lines = [_json.dumps({"version": 2, "width": 80, "height": 24})]
    # "i" (stdin) events — what an asciinema --stdin recording emits for typed keystrokes.
    lines += [_json.dumps([0.1 * i, "i", ch]) for i, ch in enumerate(f"ssh root@{secret}\n")]
    cast = "\n".join(lines)
    assert not rla.scan_text("notes.txt", cast), "precondition: raw line scan already catches it"
    findings = rla.scan_text("docs/demo/typed.cast", cast)
    assert any(secret in f.match for f in findings), "a private IP typed as stdin was not caught"


# --- F9a: allow-marker skips are reported, not silent --------------------------------------
def test_allow_marker_lines_are_recorded_on_the_result():
    files = {"t.md": "ip 172.31.0.5  # leak-audit: allow\nclean line\n"}  # leak-audit: allow
    res = rla.audit_files(files)
    assert ("t.md", 1) in res.marker_skips
    assert all(p != "t.md" or ln != 2 for p, ln in res.marker_skips)


# --- F3: binaries are string-scanned, and unknown binaries need review --------------------
def test_unreviewed_binary_is_flagged():
    res = rla.audit_files({}, binaries={"data/mystery.bin": b"\x00\x01harmless"})
    assert any(f.kind == "unreviewed-binary" for f in res.findings)
    assert not res.ok


def test_known_brand_binary_is_not_flagged_as_unreviewed():
    res = rla.audit_files({}, binaries={"docs/brand/logo.png": b"\x89PNG\x00 clean bytes"})
    assert not any(f.kind == "unreviewed-binary" for f in res.findings)


def test_leak_shape_inside_a_binary_is_caught():
    # An internal host embedded in a brand asset's bytes (e.g. EXIF) — allowlisted PATH, dirty CONTENT.
    blob = b"\x89PNG\x00\x00exif: shot on host build7.lan \x00\xff"  # leak-audit: allow
    res = rla.audit_files({}, binaries={"docs/brand/social.png": blob})
    assert any(f.kind.startswith("internal-host") and "binary" in f.kind for f in res.findings)


def test_utf16_encoded_leak_inside_a_binary_is_caught():
    blob = "config /root/secrets/key".encode("utf-16-le")  # leak-audit: allow
    res = rla.audit_files({}, binaries={"docs/brand/wide.png": blob})
    assert any(f.kind.startswith("root-path") and "binary" in f.kind for f in res.findings)


def test_read_ref_tree_returns_binaries_separately():
    files, binaries = rla.read_ref_tree("HEAD")
    assert any(p.startswith("docs/brand/") and p.endswith(".png") for p in binaries), (
        "the brand PNGs should surface as binaries in the tree read")
    assert all(not (p.endswith(".png")) for p in files), "a PNG leaked into the text file map"


# --- F5: ref-scan CLI reds on a denied-path commit, passes a clean delta -------------------
# Self-contained: build a throwaway two-commit repo per test. The earlier version ran against the
# real repo's HEAD~1, which does not exist in CI's shallow (depth-1) checkout — it exited 128 there
# while passing on a full local clone. A synthetic repo exercises both directions in EVERY
# environment and never depends on what the last real commit happened to touch.
def _init_repo(path: Path):
    import subprocess as _sp
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    _sp.run(["git", "init", "-q", str(path)], check=True)  # noqa: S603, S607
    return env


def _commit(path: Path, env, msg: str):
    import subprocess as _sp
    _sp.run(["git", "add", "-A"], cwd=str(path), check=True)  # noqa: S603, S607
    _sp.run(["git", "commit", "-q", "-m", msg], cwd=str(path), env=env, check=True)  # noqa: S603, S607


def test_ref_scan_cli_passes_a_clean_delta(tmp_path):
    import subprocess as _sp
    script = str(REPO_ROOT / "scripts" / "release_leak_audit.py")
    env = _init_repo(tmp_path)
    (tmp_path / "README.md").write_text("clean base\n")
    _commit(tmp_path, env, "base")
    (tmp_path / "notes.md").write_text("still clean, connect to pve.example.com\n")
    _commit(tmp_path, env, "clean change")
    r = _sp.run([sys.executable, script, "ref-scan", "HEAD", "HEAD~1"],  # noqa: S603
                cwd=str(tmp_path), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_ref_scan_cli_reds_on_an_internal_only_path(tmp_path):
    import subprocess as _sp
    script = str(REPO_ROOT / "scripts" / "release_leak_audit.py")
    env = _init_repo(tmp_path)
    (tmp_path / "README.md").write_text("clean base\n")
    _commit(tmp_path, env, "base")
    # A commit adding a `.gitea/` path — an internal-only surface the public mirror strips; a
    # public ref pointing at it is the v0.24.0 shape ref-scan exists to catch.
    (tmp_path / ".gitea").mkdir()
    (tmp_path / ".gitea" / "leak-deny.txt").write_text("some-internal-host\n")
    _commit(tmp_path, env, "carries an internal-only path")
    r = _sp.run([sys.executable, script, "ref-scan", "HEAD", "HEAD~1"],  # noqa: S603
                cwd=str(tmp_path), capture_output=True, text=True)
    assert r.returncode == 1, "ref-scan did not red on a commit carrying an internal-only path"
    assert "internal-only path" in r.stderr


def test_ref_scan_cli_reds_on_a_leak_shape_in_changed_content(tmp_path):
    import subprocess as _sp
    script = str(REPO_ROOT / "scripts" / "release_leak_audit.py")
    env = _init_repo(tmp_path)
    (tmp_path / "README.md").write_text("clean base\n")
    _commit(tmp_path, env, "base")
    # A private IP introduced in changed CONTENT (not a denied path) — the class the old
    # path-name-only ref-audit never saw.
    (tmp_path / "config.md").write_text("api at 172.31.4.4:8006\n")  # leak-audit: allow
    _commit(tmp_path, env, "leak in content")
    r = _sp.run([sys.executable, script, "ref-scan", "HEAD", "HEAD~1"],  # noqa: S603
                cwd=str(tmp_path), capture_output=True, text=True)
    assert r.returncode == 1, "ref-scan did not red on a leak shape in changed content"
    assert "rfc1918-ip" in r.stderr
