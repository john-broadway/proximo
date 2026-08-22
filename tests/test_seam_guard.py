"""Repo-wide spelled-SDK-read guard: the seam's law, enforced everywhere the sweep wasn't.

WHY this file exists (2026-08-12): the A13 dual-major port swept every spelled SDK attribute
read (`.inputSchema`/`.input_schema`, `.isError`/`.is_error`, `.readOnlyHint`/`.read_only_hint`,
`.serverInfo`/`.server_info`) in src and tests through the `_mcpcompat` accessors — and the
v0.33.0 release run still went red, because the release workflow's inline verify script sat
OUTSIDE that sweep and read `init.serverInfo` while its unpinned client resolved mcp 2.0.0.
Third instance of the same shape in one week (workflow file, staged release scripts, fixtures):
the defect class survives wherever "the sweep scope" ends. This test ends the scope: it scans
every tracked code file in the repository, plus any local `.scratch/*.sh` staging scripts
(untracked, so local runs are STRICTER than CI — the extra coverage fires on the box where
those scripts get written, which is where the defect gets written).

Scope is ATTRIBUTE reads only (a literal dot before the name). Dict/string uses of the wire
spelling (`t["inputSchema"]`, JSON keys) are deliberately legal: the MCP wire format is
camelCase on BOTH majors (probed against mcp 2.0.0, 2026-08-12); only Python attribute
spellings diverge per major.

The allowlist pins file -> exact hit-line count, each entry with its reason. Exact counts,
because an exclusion list is a claim: a new spelled read cannot ride into an allowlisted file
under an existing entry without moving the number and failing here.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# A literal attribute read of a per-major spelled name. \b keeps `.serverInfoX` honest.
SPELLED_READ = re.compile(
    r"\.(inputSchema|input_schema|isError|is_error|"
    r"readOnlyHint|read_only_hint|serverInfo|server_info)\b"
)

CODE_SUFFIXES = {".py", ".yml", ".yaml", ".sh"}

# The ONLY places a spelled read may live, with the exact number of matching lines and why.
ALLOWLIST: dict[str, tuple[int, str]] = {
    # The seam itself: every accessor's implementation is here by definition.
    "src/proximo/_mcpcompat.py": (-1, "the seam — spelled reads are its whole job"),
    # This file: the pattern text above matches itself.
    "tests/test_seam_guard.py": (-1, "the guard — carries the pattern it hunts"),
    # (release-pypi.yml's inline verify script held the third entry until 2026-08-20: its
    # per-major read moved to scripts/pypi_smoke.py, which imports the INSTALLED wheel's own
    # seam instead of spelling one — proximo IS importable there, since the wheel under
    # verification is installed in the very venv the script runs in.)
}


def _tracked_code_files() -> list[Path]:
    # S603/S607 suppressed deliberately: fixed literal argv, no interpolation (house pattern,
    # same as test_receipt.py / test_release_leak_audit.py).
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True  # noqa: S603, S607
    ).stdout
    files = [REPO / line for line in out.splitlines() if Path(line).suffix in CODE_SUFFIXES]
    # Local-only staging scripts: present on the writing box, absent in CI checkouts.
    files += sorted((REPO / ".scratch").glob("*.sh"))
    return files


def test_no_spelled_sdk_reads_outside_the_seam() -> None:
    hits: dict[str, int] = {}
    for path in _tracked_code_files():
        text = path.read_text(errors="replace")
        n = sum(1 for line in text.splitlines() if SPELLED_READ.search(line))
        if n:
            hits[str(path.relative_to(REPO))] = n

    problems = []
    for rel, n in sorted(hits.items()):
        if rel not in ALLOWLIST:
            problems.append(f"{rel}: {n} spelled SDK read(s) outside the seam — route through _mcpcompat")
        else:
            want = ALLOWLIST[rel][0]
            if want != -1 and n != want:
                problems.append(
                    f"{rel}: {n} spelled read line(s), allowlist pins {want} — "
                    "a new read rode in (or one left); re-adjudicate and re-pin"
                )
    for rel, (want, _reason) in ALLOWLIST.items():
        if want != -1 and rel not in hits:
            problems.append(f"{rel}: allowlisted with {want} expected line(s) but has none — stale entry, remove it")

    assert not problems, "seam guard:\n" + "\n".join(problems)
