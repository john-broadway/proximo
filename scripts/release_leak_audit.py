#!/usr/bin/env python3
"""Release leak-audit — model the PUBLIC publish transform and refuse to leak internal infra.

Proximo publishes to GitHub by attaching the FULL local tree to `github/main` via
`git commit-tree` (curated orphan, fast-forward only). Nothing scans that synthetic tree:
gitleaks (CI) and the global pre-push hook see the real branch you push, not the commit-tree
that actually becomes the public commit. So a file that is legitimately tracked-but-internal
— e.g. `.gitea/` CI for the self-hosted forge, which carries the internal forge hostname —
sails straight into the public commit untouched.

This tool models that transform. It (1) STRIPS paths that must never be public (`.gitea/` —
the public mirror uses `.github/`), and (2) scans the kept files for internal-infra leak
shapes (RFC1918 IPs, internal-TLD hostnames, absolute `/root` paths, credential token shapes),
plus two INTERNAL-ONLY denylists (site-specific identifiers, and rival handles/products whose
competitive analysis is internal strategy), with an allowlist for documented example values.
Patterns are GENERIC and the denylists live under a deny prefix — this file is itself public,
so it names no real infrastructure and no competitor.

Stdlib only (runs anywhere, no install — same discipline as version_tools.py).

CLI:
  release_leak_audit.py audit [ref]       Report what would publish; exit 1 if any leak remains.
  release_leak_audit.py build-tree [ref]  Print a clean tree SHA (deny paths stripped) for
                                          `git commit-tree`, but ONLY if the kept files are
                                          leak-clean (fail-closed). Stdout = the SHA, nothing else.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Paths that legitimately live in the internal repo but must NEVER reach the public mirror.
# `.gitea/` = self-hosted-forge CI (names the internal forge host).
# `docs/plans/` + `docs/specs/` = our engineering design docs (design memos + build-records). They
# expose internal reasoning and self-identified soft spots and rot in public; the value to a USER is
# low (the user-facing surface is README/CHANGELOG/TOOLS/LICENSE/demo). Kept internal by John's call
# 2026-07-13 — the same principle already applied to POSITIONING/LANDSCAPE/ROADMAP/CEILING below.
# (`docs/plans/internal/` — the lab build-records — is subsumed by the `docs/plans/` prefix.)
# `docs/internal/` = the internal-strategy docs (LAB/CEILING/LANDSCAPE/POSITIONING/ROADMAP, relocated
# from root 2026-07-16) plus any future addition to that directory — prefix-denied so the whole
# directory is stripped, not just today's five basenames.
DENY_PREFIXES: tuple[str, ...] = (".gitea/", "docs/plans/", "docs/specs/", "docs/internal/")
# Denied by BASENAME (matches anywhere in the tree, not just root) = internal-only docs the public
# mirror must NOT carry. `CLAUDE.md` = dev-memory. POSITIONING/LANDSCAPE/ROADMAP/CEILING/LAB = internal
# strategy: competitive playbook, field survey, frozen design-thesis roadmap, and the addressable-surface
# ceiling — never the public surface (they expose the moat analysis + self-identified soft spots + the
# build-out map, and rot in public). The public set is user-facing (README/CHANGELOG/LICENSE/demo);
# strategy + build-record stay on the internal mirror. These five now live under `docs/internal/`
# (covered by the prefix above); kept here too as belt-and-suspenders basename matching in case a
# copy ever lands outside that directory.
DENY_BASENAMES: tuple[str, ...] = ("CLAUDE.md", "POSITIONING.md", "LANDSCAPE.md", "ROADMAP.md", "CEILING.md", "LAB.md")

# Site-specific internal identifiers (bare node/host names with no generic leak-shape) that must
# never publish. Sourced from this INTERNAL-ONLY file — it lives under a deny prefix, so it is
# stripped from the public mirror and can safely name real infra while THIS public tool names none.
DENY_LITERALS_FILE = ".gitea/leak-deny.txt"

# Rival handles/products whose competitive analysis is internal strategy (see docs/internal/LANDSCAPE)
# and must never surface in public copy. Same design as the literals file: INTERNAL-ONLY, under a deny
# prefix, so it is stripped from the public mirror and THIS public tool names no competitor. The
# generic ecosystem tools users legitimately reference (Terraform, Ansible, proxmoxer, …) are NOT
# listed — only distinctive tokens with low false-positive risk belong here.
COMPETITOR_DENY_FILE = ".gitea/competitor-deny.txt"

# Generic leak-shape patterns. No real infra literals — this file ships publicly.
_RFC1918 = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
_INTERNAL_HOST = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*"
    r"\.(?:lan|internal|intranet|local|corp|home\.arpa)\b",
    re.IGNORECASE,
)
# Real absolute home path: `/root/` followed by a path segment (NOT the `/root/...` ellipsis
# placeholder or a `/root/` delimiter inside a leak-grep pattern, which are doc references).
_ROOT_PATH = re.compile(r"(?<![\w./])/root/(?!\.\.\.)[\w.]")
_TOKEN = re.compile(
    r"\b(?:pypi-[A-Za-z0-9_-]{16,}"
    r"|glpat-[A-Za-z0-9_-]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16})\b"
)

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("rfc1918-ip", _RFC1918),
    ("internal-host", _INTERNAL_HOST),
    ("root-path", _ROOT_PATH),
    ("token", _TOKEN),
)

# Inline escape hatch: a line carrying this marker is skipped (e.g. THIS tool's own tests, which
# must embed leak-shaped literals to prove the patterns fire). Same spirit as gitleaks `#gitleaks:allow`.
ALLOW_MARKER = "leak-audit: allow"

# Documented, benign example values that legitimately appear in public docs / smokes.
#
# PREFIX-matched, and safe to prefix-match because these are RESERVED-FOR-DOCUMENTATION ranges
# (RFC 5737 / RFC 2606). No real infrastructure can be numbered here, so exempting the whole
# range exempts nothing that could ever be a leak.
ALLOW_PREFIX: tuple[str, ...] = (
    "192.0.2.", "198.51.100.", "203.0.113.",   # RFC 5737 documentation IP ranges
    ".example.", "example.com", "your-node",    # RFC 2606 example domains / sanctioned placeholders
    "proxmox.lan",                              # generic example host in a2a-auth allowed-hosts test
)

# EXACT-matched, one full address per entry. These are REAL private ranges (RFC 1918) used as
# examples in docstrings, fixtures and smokes — and a real deployment is numbered in exactly these
# ranges, so a prefix here would be a hole, not an exemption.
#
# It WAS a hole. Until 2026-08-01 this list carried the bare prefixes `10.0.0.`, `192.168.` and
# `172.16.`, and `_allowed()` matched by SUBSTRING — so ANY full address inside 192.168.0.0/16
# passed as allowed and the entire space was exempt anywhere in the public tree, `.md`, `.py` and
# `.cast` alike. The audit's CLEAN verdict was true but carried no evidence about that range: it
# structurally could not fire. Found by an adversarial pass on the demo assets, not by a leak.
# (No example address is written here — this file scans itself.)
#
# Adding an entry here means: this exact address is an example and will never be real infra. If a
# new fixture needs one, add the full address — never a prefix, never a range.
ALLOW_EXACT: frozenset[str] = frozenset({
    # docstring CIDR/gateway examples (blast, firewall, network, pmg, sdn_routing, TOOLS.md)
    "10.0.0.0", "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.9",
    "10.0.0.10", "10.0.0.20",
    "172.16.0.0", "172.16.5.4",
    "192.168.0.0", "192.168.0.99", "192.168.1.0", "192.168.1.1",
    # live-smoke SDN fixtures + the a2a allowed-host fixture
    "10.99.99.0", "10.99.99.1", "10.99.99.2", "10.99.99.5", "10.1.2.3",
    # Example HOSTNAMES on the internal TLDs the host pattern grew 2026-08-10. EXACT-matched (not
    # prefix) on purpose: a prefix would also clear any longer host that merely ends in the same
    # label, and a leading-dot prefix does not even clear its own bare token — so a prefix entry
    # here sprang the scanner on this very file. Each below is a full example host from a tracked
    # fixture (realm-config, mappings, and the pmg/pve cert-fingerprint tests). Proven both ways in
    # tests/test_release_leak_audit.py: a REAL internal host flags, these examples do not. (This
    # comment names no host literal on those TLDs on purpose — writing one would trip this scanner.)
    "corp.local", "dc1.corp.local", "node.local", "surface.lab.local", "pve-test1.lab.local",
})


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    match: str


@dataclass
class AuditResult:
    kept: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Lines skipped by the inline `leak-audit: allow` marker — reported, not silent. A marker
    # silences EVERY pattern on its line, so an audit that prints CLEAN while carrying markers is
    # only as trustworthy as those markers; surface them so a human sees where the gate looked away.
    marker_skips: list[tuple[str, int]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings


def _allowed(token: str) -> bool:
    """True if `token` is a sanctioned example value.

    Two rules, deliberately different. A documentation-reserved range may be matched by PREFIX
    (nothing real lives there). A real private range must match the FULL token, or the exemption
    swallows every address in it — which is exactly the defect this split fixed.
    """
    return token in ALLOW_EXACT or any(a in token for a in ALLOW_PREFIX)


def _deny_literal_pattern(deny_literals: tuple[str, ...]) -> re.Pattern[str] | None:
    """Word-boundaried, case-insensitive regex matching any of *deny_literals* (site-specific
    internal identifiers with no generic shape). None when the list is empty."""
    lits = [s.strip() for s in deny_literals if s.strip()]
    if not lits:
        return None
    return re.compile(r"\b(?:" + "|".join(re.escape(s) for s in lits) + r")\b", re.IGNORECASE)


_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][A-B0-2]|\r")


def cast_visible_text(text: str) -> str:
    """Reconstruct what a viewer actually SEES in an asciinema v2 recording.

    A `.cast` is one JSON array per line, and a terminal recording emits ONE EVENT PER KEYSTROKE
    for anything typed. So a hostname the operator typed is spread one character per line, and a
    line-by-line regex scan cannot see it: it matches `p`, then `v`, then `e`. Verified against
    docs/demo/demo.cast, whose lines 5-38 are single characters.

    That made the denylist scan structurally blind to exactly the thing a live terminal demo is
    most likely to expose — typed infra names — while still reporting the file CLEAN. Found by an
    adversarial pass on the demo assets, 2026-08-01, not by a leak.

    Concatenating the payloads and stripping ANSI gives the visible frame text, which is what a
    human reviewing the recording would read, and what this scan should see. BOTH `o` (terminal
    output) and `i` (typed stdin, present when a cast is recorded with `--stdin`) events count:
    input events are the per-keystroke channel where a typed hostname would otherwise stay
    invisible even after this reconstruction (2026-08-10).
    """
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue  # the v2 header is a JSON OBJECT on line 1; skip it
        try:
            ev = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(ev, list) and len(ev) >= 3 and ev[1] in ("o", "i") and isinstance(ev[2], str):
            out.append(ev[2])
    return _ANSI.sub("", "".join(out))


def scan_text(
    path: str, text: str,
    extra_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (),
    marker_skips: list[tuple[str, int]] | None = None,
) -> list[Finding]:
    """Leak shapes in one file's content, honoring the documented-example allowlist. *extra_patterns*
    scan alongside the built-ins (e.g. the site-specific internal-identifier denylist). When
    *marker_skips* is given, each line silenced by the inline allow-marker is appended as
    ``(path, lineno)`` so the caller can report where the gate deliberately looked away.

    A `.cast` is scanned TWICE: once raw (so a leak in the JSON envelope or the header still
    fires) and once over its reconstructed visible text (so per-keystroke-encoded text fires too).
    """
    findings: list[Finding] = []
    if path.endswith(".cast"):
        visible = cast_visible_text(text)
        if visible:
            findings += [
                Finding(path, 0, f"{f.kind} (in recorded terminal output)", f.match)
                for f in scan_text(path + "::visible", visible, extra_patterns, marker_skips)
            ]
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            if marker_skips is not None:
                marker_skips.append((path, lineno))
            continue
        for kind, pattern in (*PATTERNS, *extra_patterns):
            for m in pattern.finditer(line):
                token = m.group(0)
                if _allowed(token):
                    continue
                findings.append(Finding(path, lineno, kind, token))
    return findings


# Binary blobs publish in the tree but neither this shape-audit (which decoded to text and split
# on lines) nor gitleaks (which skips binaries) ever looked inside them — so a PNG carrying an
# internal hostname in its EXIF, a UTF-16 "text" file, or a stray sqlite would sail out unscanned.
# Two guards close that: (1) every kept binary is decoded to its extractable strings and run through
# the SAME leak patterns; (2) any binary OUTSIDE the known-clean allowlist is itself a finding, so a
# NEW binary kind gets a human before it ships. Added 2026-08-10 (audit finding F3).
#
# Known-clean = the brand art under docs/brand/. Matched by directory+extension, not exact name, so a
# re-exported titlecard whose filename carries a fresh content-hash stays covered without a list edit.
def _is_allowed_binary(path: str) -> bool:
    return path.startswith("docs/brand/") and path.endswith(".png")


def _extract_strings(blob: bytes) -> str:
    """Everything a shape pattern could match inside a binary: the single-byte-encoded text (latin-1
    is a total 1:1 byte map, so all ASCII survives and nothing raises) plus a UTF-16 decode both
    ways (so wide-encoded hostnames/paths surface). Joined with newlines so line-oriented scan_text
    treats each decode as its own span."""
    parts = [blob.decode("latin-1")]
    for enc in ("utf-16-le", "utf-16-be"):
        parts.append(blob.decode(enc, "ignore"))
    return "\n".join(parts)


def scan_binary(
    path: str, blob: bytes,
    extra_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (),
) -> list[Finding]:
    """Leak shapes inside one binary blob, plus an `unreviewed-binary` finding for any path not on
    the known-clean allowlist. Line numbers are meaningless here, so findings report line 0."""
    findings: list[Finding] = []
    if not _is_allowed_binary(path):
        findings.append(Finding(path, 0, "unreviewed-binary", path))
    for f in scan_text(path + "::bytes", _extract_strings(blob), extra_patterns):
        findings.append(Finding(path, 0, f"{f.kind} (in binary)", f.match))
    return findings


def partition_paths(
    paths, deny: tuple[str, ...] = DENY_PREFIXES
) -> tuple[list[str], list[str]]:
    """Split paths into (kept, stripped); stripped = anything under a deny prefix."""
    kept: list[str] = []
    stripped: list[str] = []
    for p in paths:
        denied = p.startswith(deny) or Path(p).name in DENY_BASENAMES
        (stripped if denied else kept).append(p)
    return kept, stripped


def audit_files(
    files: dict[str, str], deny: tuple[str, ...] = DENY_PREFIXES,
    deny_literals: tuple[str, ...] = (),
    competitor_names: tuple[str, ...] = (),
    binaries: dict[str, bytes] | None = None,
) -> AuditResult:
    """Audit a path->content map AS IF published: deny paths are stripped (and NOT scanned —
    they won't be public); kept files are scanned for leak shapes, any site-specific internal
    identifiers in *deny_literals*, and any rival handles/products in *competitor_names*. When
    *binaries* (path->bytes) is given, kept binaries are string-scanned for the same shapes and any
    binary outside the known-clean allowlist is flagged for review."""
    all_paths = list(files.keys()) + list((binaries or {}).keys())
    kept, stripped = partition_paths(all_paths, deny)
    kept_set = set(kept)
    extra: list[tuple[str, re.Pattern[str]]] = []
    for kind, names in (("internal-literal", deny_literals), ("competitor-name", competitor_names)):
        pat = _deny_literal_pattern(names)
        if pat is not None:
            extra.append((kind, pat))
    findings: list[Finding] = []
    marker_skips: list[tuple[str, int]] = []
    for p in sorted(kept_set & set(files)):
        findings.extend(scan_text(p, files[p], tuple(extra), marker_skips))
    for p in sorted(kept_set & set(binaries or {})):
        findings.extend(scan_binary(p, binaries[p], tuple(extra)))
    return AuditResult(
        kept=sorted(kept), stripped=sorted(stripped),
        findings=findings, marker_skips=marker_skips,
    )


# --- git I/O: read the real publish surface --------------------------------------------

def _repo_root() -> Path:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],  # noqa: S603, S607
                         cwd=str(Path.cwd()), capture_output=True, text=True, check=True).stdout
    return Path(out.strip())


def _read_denylist_file(rel_path: str, root: Path | None = None) -> tuple[str, ...]:
    """Read a one-token-per-line denylist (``#`` comments + blank lines ignored) from an
    INTERNAL-ONLY file under a deny prefix. Returns a lowercased tuple; empty when the file is
    absent (e.g. a public clone), so the gate degrades to shape-only rather than erroring."""
    root = root or _repo_root()
    f = root / rel_path
    if not f.exists():
        return ()
    out: list[str] = []
    for line in f.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s.lower())
    return tuple(out)


def load_deny_literals(root: Path | None = None) -> tuple[str, ...]:
    """Site-specific internal identifiers to refuse (bare node/host names with no generic shape),
    from the INTERNAL-ONLY ``DENY_LITERALS_FILE``. That file lives under a deny prefix, so it is
    stripped from the public mirror and may name real infra while this public tool names none."""
    return _read_denylist_file(DENY_LITERALS_FILE, root)


def load_competitor_names(root: Path | None = None) -> tuple[str, ...]:
    """Rival handles/products that must never appear in public copy, from the INTERNAL-ONLY
    ``COMPETITOR_DENY_FILE``. Stripped from the public mirror, so this public tool names no rival."""
    return _read_denylist_file(COMPETITOR_DENY_FILE, root)


def _git(args: list[str], cwd: Path, env: dict | None = None) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), env=env,  # noqa: S603, S607
                          capture_output=True, text=True, check=True).stdout


def read_ref_tree(
    ref: str = "HEAD", root: Path | None = None
) -> tuple[dict[str, str], dict[str, bytes]]:
    """Walk `ref`'s tree ONCE and split it into (text files, binary blobs) — together the exact
    publish surface. Text is decoded UTF-8 (lossy); binaries are kept as raw bytes so the binary
    string-scan can look inside them."""
    root = root or _repo_root()
    names = _git(["ls-tree", "-r", "--name-only", "-z", ref], root).split("\0")
    files: dict[str, str] = {}
    binaries: dict[str, bytes] = {}
    for name in filter(None, names):
        blob = subprocess.run(["git", "show", f"{ref}:{name}"], cwd=str(root),  # noqa: S603, S607
                              capture_output=True, check=True).stdout
        if b"\0" in blob[:8192]:   # binary-ish — string-scanned separately, not decoded as text
            binaries[name] = blob
        else:
            files[name] = blob.decode("utf-8", "replace")
    return files, binaries


def files_in_ref(ref: str = "HEAD", root: Path | None = None) -> dict[str, str]:
    """The tracked TEXT files in `ref`'s tree. Binaries are returned by `read_ref_tree` instead."""
    return read_ref_tree(ref, root)[0]


def changed_blobs(
    base: str, commit: str, root: Path | None = None
) -> tuple[dict[str, str], dict[str, bytes]]:
    """The files added/modified between `base` and `commit`, split (text, binary). This is the delta
    an off-main ref introduces on top of an already-curated main — the only surface worth scanning
    to decide whether that ref is publish-safe. Deleted paths are omitted (nothing to leak)."""
    root = root or _repo_root()
    names = _git(["diff", "--name-only", "--diff-filter=d", "-z", base, commit], root).split("\0")
    files: dict[str, str] = {}
    binaries: dict[str, bytes] = {}
    for name in filter(None, names):
        blob = subprocess.run(["git", "show", f"{commit}:{name}"], cwd=str(root),  # noqa: S603, S607
                              capture_output=True, check=True).stdout
        if b"\0" in blob[:8192]:
            binaries[name] = blob
        else:
            files[name] = blob.decode("utf-8", "replace")
    return files, binaries


def build_public_tree(
    ref: str = "HEAD", deny: tuple[str, ...] = DENY_PREFIXES, root: Path | None = None
) -> str:
    """Build (in an ISOLATED temp index — never touches the real index/worktree) the tree
    that should publish: `ref`'s tree with deny prefixes removed. Returns the new tree SHA
    for `git commit-tree <sha> -p github/main`."""
    root = root or _repo_root()
    fd, idx = tempfile.mkstemp(prefix="proximo-pubidx-")
    os.close(fd)
    try:
        env = {**os.environ, "GIT_INDEX_FILE": idx}
        _git(["read-tree", ref], root, env=env)
        # Strip EXACTLY the paths partition_paths denies — deny PREFIXES *and* DENY_BASENAMES — over
        # the full tree (incl. binaries). Using the same partition as audit() guarantees the published
        # tree matches the leak-audit; a prefix-only `git rm -r` is blind to a basename deny (CLAUDE.md)
        # and would publish it while audit() reported it stripped.
        all_paths = [p for p in _git(["ls-tree", "-r", "--name-only", "-z", ref], root).split("\0") if p]
        _, stripped = partition_paths(all_paths, deny)
        if stripped:
            # -f: with ref != HEAD the temp-index entry differs from both HEAD and the worktree
            # for any file changed since `ref`, and un-forced `git rm --cached` refuses that as
            # a staged-content safety. The safety protects a REAL index; this one is isolated
            # (GIT_INDEX_FILE above) and --cached never touches the worktree, so forcing is safe.
            _git(["rm", "-f", "--cached", "--quiet", "--ignore-unmatch", "--", *stripped], root, env=env)
        return _git(["write-tree"], root, env=env).strip()
    finally:
        os.unlink(idx)


def _main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "audit"
    ref = argv[1] if len(argv) > 1 else "HEAD"

    if cmd == "audit":
        files, binaries = read_ref_tree(ref)
        res = audit_files(files, deny_literals=load_deny_literals(),
                          competitor_names=load_competitor_names(), binaries=binaries)
        for p in res.stripped:
            print(f"strip (internal-only, won't publish): {p}")
        for p, ln in res.marker_skips:
            print(f"marker-skip (allow-marker silenced this line): {p}:{ln}")
        for f in res.findings:
            print(f"LEAK [{f.kind}] {f.path}:{f.line}: {f.match}", file=sys.stderr)
        if res.ok:
            print(
                f"leak-audit: CLEAN — {len(res.kept)} files would publish, "
                f"{len(res.stripped)} stripped, {len(res.marker_skips)} allow-marker line(s)"
            )
            return 0
        print(
            f"leak-audit: {len(res.findings)} leak shape(s) in the public surface — "
            "FIX before any public flip",
            file=sys.stderr,
        )
        return 1

    if cmd == "build-tree":
        files, binaries = read_ref_tree(ref)
        res = audit_files(files, deny_literals=load_deny_literals(),
                          competitor_names=load_competitor_names(), binaries=binaries)
        if not res.ok:
            for f in res.findings:
                print(f"LEAK [{f.kind}] {f.path}:{f.line}: {f.match}", file=sys.stderr)
            print("build-tree: REFUSING — leak shapes in the public surface", file=sys.stderr)
            return 1
        print(build_public_tree(ref))   # the ONLY stdout: the clean tree SHA
        return 0

    if cmd == "ref-scan":
        # Judge whether an OFF-MAIN commit is publish-safe, by the SAME rules as a release:
        # a denied internal-only PATH present (v0.24.0's shape) is a failure, and so is a leak
        # SHAPE in the changed CONTENTS — which the old ci.yml ref-audit never looked at, it
        # matched path names only. `base` defaults to origin/main.
        # Usage: ref-scan <commit> [base]
        commit = argv[1] if len(argv) > 1 else "HEAD"
        base = argv[2] if len(argv) > 2 else "origin/main"
        files, binaries = changed_blobs(base, commit)
        res = audit_files(files, deny_literals=load_deny_literals(),
                          competitor_names=load_competitor_names(), binaries=binaries)
        for p in res.stripped:
            print(f"::error::{commit} carries internal-only path: {p}", file=sys.stderr)
        for f in res.findings:
            print(f"::error::{commit} leak [{f.kind}] {f.path}:{f.line}: {f.match}", file=sys.stderr)
        # An off-main ref is UNTRUSTED, and its author could add a `leak-audit: allow` marker to
        # smuggle a leak past this scan. The marker is still honored (the changed line might be a
        # legitimate test fixture), but it is never invisible here — surface every skip so a human
        # sees exactly where this scan looked away on a ref that is not curated main.
        for p, ln in res.marker_skips:
            print(f"::warning::{commit} allow-marker silenced a scanned line: {p}:{ln}", file=sys.stderr)
        if res.stripped or res.findings:
            return 1
        print(f"ref-scan: {commit} clean vs {base} "
              f"({len(files)} text + {len(binaries)} binary file(s) changed)")
        return 0

    print("usage: release_leak_audit.py [audit|build-tree|ref-scan] [ref]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
