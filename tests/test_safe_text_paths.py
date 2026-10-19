"""`safe_text(paths=True)` over every path shape an error message can carry.

THE RESIDUAL THIS CLOSES. The path rule matched a single-quoted POSIX path and a bare one of
two or more segments, which is what the lens of 2026-10-09 named as its gap: a path holding a
space, a Windows path, and a `~` path went out whole. The probe that opened this lane found one
more: `~john/.config/x` carried a USERNAME through, one of the four shapes this workspace
redacts by name.

DRIVEN, NOT TYPED. Where Python itself composes the message (`FileNotFoundError` quotes the
path with `repr`, which switches to double quotes when the path holds an apostrophe;
`PureWindowsPath` renders the backslashes) the fixture is that real text, so the test proves
the scrubber against what the interpreter writes, not against a string of ours. A planted
control asserts the fixture leaks before the scrub, so a Python that stops quoting paths turns
this file red instead of green for the wrong reason.

THE AXIS NOT VARIED. The same call must still leave `3/4`, `and/or`, a single-segment `/tmp`
and the default `paths=False` alone, keep `<url>` and `<redacted>`, and hold the bound.
"""
from __future__ import annotations

from pathlib import PureWindowsPath

import pytest

from proximo.core.secretfile import register_secret, safe_text

MARK = "zq9x-marker"          # rides in every path below; it must never reach the output


def _real_open_error(path: str) -> OSError:
    try:
        open(path, encoding="utf-8")   # noqa: SIM115 -- the raise is the fixture
    except OSError as exc:
        return exc
    raise AssertionError(f"{path!r} exists on this box; the fixture needs a missing file")


# --- the control: the fixtures leak before the scrub ----------------------------------------------

def test_the_control_proves_pythons_own_message_carries_the_quoted_path():
    """PLANTED CONTROL: the interpreter quotes the path with repr(), double quotes when the path
    holds an apostrophe. If that ever changes these tests pass for the wrong reason."""
    assert f"\"/opt/john's lab/{MARK}.key\"" in str(_real_open_error(f"/opt/john's lab/{MARK}.key"))
    assert f"'/opt/my lab/{MARK}.key'" in str(_real_open_error(f"/opt/my lab/{MARK}.key"))


# --- the shapes the lens named ----------------------------------------------------------------------

def test_a_double_quoted_path_with_a_space_goes_out_whole():
    out = safe_text(str(_real_open_error(f"/opt/john's lab/{MARK}.key")), paths=True)
    assert MARK not in out and "lab" not in out and "<path>" in out
    assert "No such file" in out                       # the reason stays, the locator goes


def test_a_single_quoted_path_with_a_space_still_goes_out_whole():
    out = safe_text(str(_real_open_error(f"/opt/my lab/{MARK}.key")), paths=True)
    assert MARK not in out and "lab" not in out and "<path>" in out


@pytest.mark.parametrize("raw", [
    str(PureWindowsPath(f"C:/Users/{MARK}/token.txt")),      # C:\Users\...\token.txt
    f"C:/Users/{MARK}/token.txt",
    f"d:\\lab\\{MARK}\\pve.token",
])
def test_a_windows_drive_path_goes_out_whole(raw):
    out = safe_text(f"cannot read {raw}: permission denied", paths=True)
    assert MARK not in out and "Users" not in out and "lab" not in out
    assert out == "cannot read <path>: permission denied"


def test_a_quoted_windows_path_goes_out_whole():
    """On this box `open("C:\\...")` raises with the path repr-quoted and the backslashes doubled;
    the quoted rules take a drive path as they take a POSIX one."""
    out = safe_text(str(_real_open_error(f"C:\\Users\\{MARK}\\token.txt")), paths=True)
    assert MARK not in out and "Users" not in out and "<path>" in out


def test_a_home_relative_path_goes_out_whole():
    out = safe_text(f"chmod 600 ~/.config/{MARK}/pve-token", paths=True)
    assert out == "chmod 600 <path>"


def test_a_home_relative_path_does_not_carry_the_username_through():
    """`~john/...` names a user: one of the four shapes this workspace redacts by name."""
    out = safe_text(f"chmod 600 ~{MARK}user/.config/pve-token", paths=True)
    assert MARK not in out and "user" not in out and out == "chmod 600 <path>"


def test_a_bare_path_with_a_space_does_not_leak_its_tail():
    """A bare path cut at the space left `lab/secret.key` standing beside `<path>`; a token with a
    slash right after a scrubbed path is that path's tail and folds into it."""
    out = safe_text(f"open failed: /opt/my lab/{MARK}.key and then", paths=True)
    assert MARK not in out and "lab" not in out and out == "open failed: <path> and then"


# --- the axis not varied --------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "ratio 3/4 and/or a/b path/like",
    "file /tmp refused",                       # one segment is a word, not a locator (by design)
    "note:/tmp and 12:30/40",                  # a colon before a slash is not a drive letter
    "trip at <path> (mode 600)",               # a tail fold needs a slash; prose stands
])
def test_prose_that_is_not_a_path_is_left_alone(body):
    assert safe_text(body, paths=True) == body


def test_the_default_leaves_paths_in_place():
    """0.44's callers compose their own messages around paths on purpose (`chmod 600 /x/y`) and
    keep the default; only `paths=True` takes them."""
    body = f"chmod 600 /opt/{MARK}/token"
    assert safe_text(body) == body


def test_the_other_locators_and_secrets_are_still_taken():
    register_secret(f"{MARK}-supersecretvalue")
    out = safe_text(f"see https://pve.invalid:8006/x and 192.0.2.10:8006 for {MARK}-supersecretvalue "
                    f"at '/opt/my lab/{MARK}.key'", paths=True)
    assert out == "see <url> and <addr> for <redacted> at <path>"


def test_the_bound_still_holds():
    assert len(safe_text("x" * 5000 + " '/opt/a b/c'", paths=True)) <= 400


# --- the lens fold (2026-10-09, four MAJOR) -------------------------------------------------------
# A path glued to a colon, a UNC or double-slash path, a bare spaced path whose filename carries no
# slash, and a single-quoted path cut early by an apostrophe each left a locator standing.

@pytest.mark.parametrize("raw", [f"file:/opt/{MARK}/key", f"at:/opt/{MARK}/key"])
def test_a_path_glued_to_a_colon_goes_out_whole(raw):
    out = safe_text(f"refused {raw} today", paths=True)
    assert MARK not in out and "opt" not in out and out.endswith(":<path> today")   # the label stays


@pytest.mark.parametrize("raw", [f"\\\\{MARK}srv\\share\\key", f"//{MARK}srv/share/key", f"/opt//{MARK}/key/"])
def test_a_unc_or_doubled_slash_path_goes_out_whole(raw):
    out = safe_text(f"refused {raw} today", paths=True)
    assert MARK not in out and "share" not in out and out == "refused <path> today"


def test_a_bare_spaced_path_does_not_leak_a_slashless_filename():
    out = safe_text(f"cannot read /home/{MARK}/my secret.key now", paths=True)
    assert MARK not in out and "secret" not in out and out == "cannot read <path> now"


def test_a_single_quoted_path_cut_by_an_apostrophe_leaves_no_residue():
    """`'/opt/a: it's b/c secret.key` cut at `it'`; the `s`, the `b/c` and the filename stood."""
    out = safe_text(f"'/opt/{MARK}: it's b/c secret.key failed", paths=True)
    assert MARK not in out and "secret" not in out and "b/c" not in out and out == "<path> failed"


@pytest.mark.parametrize("body", [
    "token <path>: permission denied",          # punctuation after a path is not residue
    "a 3.4 GB disk and v1.2 at e.g. noon",       # numbers and versions are not filenames
])
def test_the_fold_takes_residue_and_filenames_but_not_punctuation_or_numbers(body):
    assert safe_text(body, paths=True) == body


@pytest.mark.parametrize("raw", [
    f"/opt/{MARK}/a%20b/key", f"C:\\lab\\{MARK}%20x\\key", f"~{MARK}/a%2Fb/key", f"\\\\{MARK}srv\\sh%20are\\key",
])
def test_a_percent_in_a_bare_segment_goes_out_whole(raw):
    """A URL-escaped segment (`%20`, the shape a path carries after one trip through a URL) cut
    the bare rule at the `%` and the rest stood: `<path>%20b/c` (lens 2026-10-09, MINOR)."""
    out = safe_text(f"cannot read {raw} now", paths=True)
    assert MARK not in out and "%" not in out and out == "cannot read <path> now"


@pytest.mark.parametrize("body", [
    "load 80%/90%/95% of cpu",            # percentages between slashes are prose (lens 2026-10-16)
    "a 3%/4 share",
])
def test_a_bare_percent_is_not_an_escape_and_the_prose_stands(body):
    assert safe_text(body, paths=True) == body
