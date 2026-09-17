"""The internal-only live-smoke workflow (gitea nightly; stripped from the public mirror, so
these tests SKIP there) carries the PVE node's certificate fingerprint as an IN-REPO DEFAULT,
overridable by `vars.PROXIMO_FINGERPRINT`.

Why a test: the PVE tier failed closed every night from 2026-06-24 to 2026-09-16 (77 nights)
because the fingerprint lived only in a repo variable nobody had set. A default pinned here makes
the tier run; a wrong or rotated pin still fails closed (mismatch), which is the correct red.
The file lives under a leak-audit DENY prefix, so the pin never publishes.

Why the checks are STRUCTURAL and not `"text" in file`: an adversarial pass (2026-09-16) moved
the pin line to a stray top-level key and the first draft still passed; it appended a harmless
trailing comment and the draft went red. Each check below locates the STEP by name, then the
key inside that step, and the mutants below are kept as controls that must fail.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_WF = Path(__file__).parent.parent / ".gitea" / "workflows" / "live-smoke.yml"
pytestmark = pytest.mark.skipif(
    not _WF.is_file(), reason="internal-only live-smoke workflow is absent on the public mirror"
)

_SMOKE_STEP = "Run live smokes (advisory)"
_PBS_STEP = "Resolve + pin the test PBS CA (cert SAN is the hostname, not the IP)"
_HEX_PAIRS = r"[0-9a-f]{2}(?::[0-9a-f]{2}){31}"
_DEFAULTED = re.compile(
    r"^PROXIMO_FINGERPRINT:\s*\$\{\{\s*vars\.PROXIMO_FINGERPRINT\s*\|\|\s*'(" + _HEX_PAIRS
    + r")'\s*\}\}\s*(?:#.*)?$"
)


def _step_lines(text: str, name: str) -> list[str]:
    """The lines of the step `- name: <name>`, up to the next `- name:` at the same indent."""
    lines = text.splitlines()
    starts = [(i, m.group(1)) for i, line in enumerate(lines)
              if (m := re.match(r"^(\s*)- name: (.*)$", line)) and m.group(2).strip() == name]
    assert len(starts) == 1, f"step {name!r} must appear exactly once; found {len(starts)}"
    i, indent = starts[0]
    body = []
    for nxt in lines[i + 1:]:
        if re.match(rf"^{indent}- name: ", nxt):
            break
        body.append(nxt)
    return body


def _key_block(step: list[str], key: str) -> list[str]:
    """The lines nested under `<key>:` inside a step (deeper indent than the key), comments
    dropped. Nothing under the key = empty list; key absent = AssertionError."""
    for i, line in enumerate(step):
        m = re.match(rf"^(\s*){re.escape(key)}:\s*(\|?)\s*$", line)
        if m:
            depth = len(m.group(1))
            out = []
            for nxt in step[i + 1:]:
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= depth:
                    break
                if nxt.strip() and not nxt.lstrip().startswith("#"):
                    out.append(nxt.strip())
            return out
    raise AssertionError(f"key {key!r} not found in step")


def pin_default(text: str) -> str:
    """The pinned default from the smoke step's env, or AssertionError naming what is wrong."""
    env = _key_block(_step_lines(text, _SMOKE_STEP), "env")
    hits = [m.group(1) for line in env if (m := _DEFAULTED.match(line))]
    assert len(hits) == 1, (
        f"the {_SMOKE_STEP!r} step's env must pass PROXIMO_FINGERPRINT as "
        "`${{ vars.PROXIMO_FINGERPRINT || '<sha256, 32 lowercase colon pairs>' }}` exactly once; "
        f"found {len(hits)} in that env block"
    )
    return hits[0]


def pbs_unreachable_message(text: str) -> str:
    """The one echo in the PBS precheck's run block that names the unreachable case."""
    run = _key_block(_step_lines(text, _PBS_STEP), "run")
    joined = "\n".join(run)
    echos = re.findall(r'echo "test PBS [^\n]*unreachable[^\n]*(?:\\\n[^\n]*)?', joined)
    assert len(echos) == 1, f"expected one unreachable echo in the PBS precheck, found {len(echos)}"
    return echos[0]


# --- the real file ------------------------------------------------------------------------------

def test_pve_fingerprint_has_an_in_repo_default_the_var_overrides():
    pin = pin_default(_WF.read_text())
    assert len(set(pin.split(":"))) > 8, f"the default pin looks synthetic ({pin}); pin the real cert"


def test_pbs_precheck_names_the_route_not_just_the_box():
    # The test PBS was UP for 12 days while the nightly said "box down?": the runner (CT 3001,
    # vmbr0 only) has no route to the lab bridge. The message must name both readings.
    msg = pbs_unreachable_message(_WF.read_text())
    assert "no route" in msg and "box down" in msg


# --- controls: the mutants the first draft let through must fail HERE ----------------------------

def _real() -> str:
    return _WF.read_text()


def test_control_pin_moved_to_a_top_level_key_is_refused():
    text = _real()
    line = next(ln for ln in text.splitlines() if _DEFAULTED.match(ln.strip()))
    mutant = text.replace(line + "\n", "") + "\n" + line.strip() + "\n"
    with pytest.raises(AssertionError, match="found 0"):
        pin_default(mutant)


def test_control_pin_line_outside_the_env_block_is_refused():
    text = _real()
    line = next(ln for ln in text.splitlines() if _DEFAULTED.match(ln.strip()))
    # keep it inside the step, but demote it out of `env:` by hoisting to the step's own indent
    step_indent = re.search(r"^(\s*)- name: " + re.escape(_SMOKE_STEP), text, re.M).group(1)
    mutant = text.replace(line, step_indent + "  " + line.strip())
    with pytest.raises(AssertionError, match="found 0"):
        pin_default(mutant)


def test_control_trailing_comment_on_the_pin_line_is_fine():
    text = _real()
    line = next(ln for ln in text.splitlines() if _DEFAULTED.match(ln.strip()))
    assert pin_default(text.replace(line, line + "  # pinned 2026-09-16")) == pin_default(text)


def test_control_pbs_message_reverted_with_words_planted_elsewhere_is_refused():
    text = _real()
    msg = pbs_unreachable_message(text)
    reverted = text.replace(msg, 'echo "test PBS ${PBS_TEST_HOST}:8007 unreachable (box down?)"')
    planted = reverted.replace("name: Live-Smoke (internal only)",
                               "name: Live-Smoke (internal only)  # no route / unreachable", 1)
    assert "no route" in planted  # the words ARE in the file, just not where they matter
    assert "no route" not in pbs_unreachable_message(planted)


def test_control_duplicate_step_with_a_decoy_pin_is_refused():
    text = _real()
    step_start = re.search(r"^(\s*)- name: " + re.escape(_SMOKE_STEP) + r"\n", text, re.M)
    indent = step_start.group(1)
    decoy = (f"{indent}- name: {_SMOKE_STEP}\n{indent}  env:\n{indent}    PROXIMO_FINGERPRINT: "
             "${{ vars.PROXIMO_FINGERPRINT || '" + ":".join(["ab"] * 32) + "' }}\n")
    mutant = text[:step_start.start()] + decoy + text[step_start.start():]
    with pytest.raises(AssertionError, match="exactly once"):
        pin_default(mutant)
