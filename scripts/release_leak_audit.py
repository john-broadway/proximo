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
    r"\.(?:lan|internal|intranet)\b",
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
ALLOW: tuple[str, ...] = (
    "192.0.2.", "198.51.100.", "203.0.113.",   # RFC 5737 documentation IP ranges
    "10.0.0.", "192.168.", "172.16.",           # canonical example private subnets in fixtures
    "10.99.99.", "10.1.2.3",                    # example ranges used in live-smoke / a2a fixtures
    ".example.", "example.com", "your-node",    # RFC 2606 example domains / sanctioned placeholders
    "proxmox.lan",                              # generic example host in a2a-auth allowed-hosts test
)


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

    @property
    def ok(self) -> bool:
        return not self.findings


def _allowed(token: str) -> bool:
    return any(a in token for a in ALLOW)


def _deny_literal_pattern(deny_literals: tuple[str, ...]) -> re.Pattern[str] | None:
    """Word-boundaried, case-insensitive regex matching any of *deny_literals* (site-specific
    internal identifiers with no generic shape). None when the list is empty."""
    lits = [s.strip() for s in deny_literals if s.strip()]
    if not lits:
        return None
    return re.compile(r"\b(?:" + "|".join(re.escape(s) for s in lits) + r")\b", re.IGNORECASE)


def scan_text(
    path: str, text: str,
    extra_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (),
) -> list[Finding]:
    """Leak shapes in one file's content, honoring the documented-example allowlist. *extra_patterns*
    scan alongside the built-ins (e.g. the site-specific internal-identifier denylist)."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for kind, pattern in (*PATTERNS, *extra_patterns):
            for m in pattern.finditer(line):
                token = m.group(0)
                if _allowed(token):
                    continue
                findings.append(Finding(path, lineno, kind, token))
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
) -> AuditResult:
    """Audit a path->content map AS IF published: deny paths are stripped (and NOT scanned —
    they won't be public); kept files are scanned for leak shapes, any site-specific internal
    identifiers in *deny_literals*, and any rival handles/products in *competitor_names*."""
    kept, stripped = partition_paths(files.keys(), deny)
    extra: list[tuple[str, re.Pattern[str]]] = []
    for kind, names in (("internal-literal", deny_literals), ("competitor-name", competitor_names)):
        pat = _deny_literal_pattern(names)
        if pat is not None:
            extra.append((kind, pat))
    findings: list[Finding] = []
    for p in sorted(kept):
        findings.extend(scan_text(p, files[p], tuple(extra)))
    return AuditResult(kept=sorted(kept), stripped=sorted(stripped), findings=findings)


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


def files_in_ref(ref: str = "HEAD", root: Path | None = None) -> dict[str, str]:
    """The tracked text files in `ref`'s tree = exactly the publish surface. Binaries skipped."""
    root = root or _repo_root()
    names = _git(["ls-tree", "-r", "--name-only", "-z", ref], root).split("\0")
    files: dict[str, str] = {}
    for name in filter(None, names):
        blob = subprocess.run(["git", "show", f"{ref}:{name}"], cwd=str(root),  # noqa: S603, S607
                              capture_output=True, check=True).stdout
        if b"\0" in blob[:8192]:   # binary-ish — not a text leak surface
            continue
        files[name] = blob.decode("utf-8", "replace")
    return files


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
            _git(["rm", "--cached", "--quiet", "--ignore-unmatch", "--", *stripped], root, env=env)
        return _git(["write-tree"], root, env=env).strip()
    finally:
        os.unlink(idx)


def _main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "audit"
    ref = argv[1] if len(argv) > 1 else "HEAD"

    if cmd == "audit":
        res = audit_files(files_in_ref(ref), deny_literals=load_deny_literals(),
                          competitor_names=load_competitor_names())
        for p in res.stripped:
            print(f"strip (internal-only, won't publish): {p}")
        for f in res.findings:
            print(f"LEAK [{f.kind}] {f.path}:{f.line}: {f.match}", file=sys.stderr)
        if res.ok:
            print(
                f"leak-audit: CLEAN — {len(res.kept)} files would publish, "
                f"{len(res.stripped)} stripped"
            )
            return 0
        print(
            f"leak-audit: {len(res.findings)} leak shape(s) in the public surface — "
            "FIX before any public flip",
            file=sys.stderr,
        )
        return 1

    if cmd == "build-tree":
        res = audit_files(files_in_ref(ref), deny_literals=load_deny_literals(),
                          competitor_names=load_competitor_names())
        if not res.ok:
            for f in res.findings:
                print(f"LEAK [{f.kind}] {f.path}:{f.line}: {f.match}", file=sys.stderr)
            print("build-tree: REFUSING — leak shapes in the public surface", file=sys.stderr)
            return 1
        print(build_public_tree(ref))   # the ONLY stdout: the clean tree SHA
        return 0

    print("usage: release_leak_audit.py [audit|build-tree] [ref]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
