"""The base-image digest check has a control of its own (claims lens, 2026-09-04).

`scripts/base_image_digest_check.py` exists because the fold's "verified byte for byte
against the registry" was an ad hoc one-liner nobody could re-run. The script that fixed
that shipped with no test: its MATCH / BEHIND / DISAGREE / UNKNOWN branches were exercised
by hand during development, so the 0.39.1 CHANGELOG's "each proven on a control" named a
regression check that did not exist. This file is that control.

The registry is never reached here. `urlopen` is replaced per test, so each branch is
provoked deliberately and the suite stays offline.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import base_image_digest_check  # noqa: E402

PIN = "sha256:" + "9" * 64
OTHER = "sha256:" + "7" * 64


def _dockerfile(tmp_path: Path, *digests: str, tag: str = "3.13-slim") -> Path:
    """A synthetic Dockerfile pinning one FROM line per digest given."""
    body = "\n".join(f"FROM python:{tag}@{d} AS stage{i}" for i, d in enumerate(digests))
    p = tmp_path / "Dockerfile"
    p.write_text(body + "\n", encoding="utf-8")
    return p


def _registry_returns(monkeypatch, digest: str) -> None:
    def fake_urlopen(url, timeout=None):  # noqa: ARG001
        return io.StringIO(json.dumps({"digest": digest}))

    monkeypatch.setattr(base_image_digest_check.urllib.request, "urlopen", fake_urlopen)


def _registry_raises(monkeypatch, exc: Exception) -> None:
    def fake_urlopen(url, timeout=None):  # noqa: ARG001
        raise exc

    monkeypatch.setattr(base_image_digest_check.urllib.request, "urlopen", fake_urlopen)


def test_match_when_the_pin_is_the_tag_head(tmp_path, monkeypatch, capsys):
    _registry_returns(monkeypatch, PIN)
    rc = base_image_digest_check.main(["prog", str(_dockerfile(tmp_path, PIN, PIN))])
    assert rc == 0
    assert "MATCH" in capsys.readouterr().out


def test_behind_when_the_tag_has_moved_past_the_pin(tmp_path, monkeypatch, capsys):
    _registry_returns(monkeypatch, OTHER)
    rc = base_image_digest_check.main(["prog", str(_dockerfile(tmp_path, PIN, PIN))])
    assert rc == 1, "a pin behind the tag head must not exit 0"
    assert "BEHIND" in capsys.readouterr().out


def test_disagree_when_the_two_stages_pin_different_bases(tmp_path, monkeypatch, capsys):
    # The registry must never be consulted: disagreement is decided from the file alone.
    _registry_raises(monkeypatch, AssertionError("the registry must not be reached"))
    rc = base_image_digest_check.main(["prog", str(_dockerfile(tmp_path, PIN, OTHER))])
    assert rc == 1
    assert "DISAGREE" in capsys.readouterr().err


def test_disagree_when_the_stages_pin_different_tags(tmp_path, monkeypatch):
    _registry_raises(monkeypatch, AssertionError("the registry must not be reached"))
    body = f"FROM python:3.13-slim@{PIN} AS build\nFROM python:3.12-slim@{PIN} AS run\n"
    p = tmp_path / "Dockerfile"
    p.write_text(body, encoding="utf-8")
    assert base_image_digest_check.main(["prog", str(p)]) == 1


def test_unknown_when_the_registry_is_unreadable(tmp_path, monkeypatch, capsys):
    _registry_raises(monkeypatch, urllib.error.URLError("no route"))
    rc = base_image_digest_check.main(["prog", str(_dockerfile(tmp_path, PIN, PIN))])
    assert rc == 2, "an unreadable registry is UNKNOWN (2), never a silent pass"
    assert "UNKNOWN" in capsys.readouterr().err


def test_unknown_when_the_registry_answer_has_no_digest(tmp_path, monkeypatch, capsys):
    def fake_urlopen(url, timeout=None):  # noqa: ARG001
        return io.StringIO(json.dumps({"name": "3.13-slim"}))

    monkeypatch.setattr(base_image_digest_check.urllib.request, "urlopen", fake_urlopen)
    rc = base_image_digest_check.main(["prog", str(_dockerfile(tmp_path, PIN, PIN))])
    assert rc == 2
    assert "UNKNOWN" in capsys.readouterr().err


def test_an_unpinned_dockerfile_refuses(tmp_path, monkeypatch, capsys):
    _registry_raises(monkeypatch, AssertionError("the registry must not be reached"))
    p = tmp_path / "Dockerfile"
    p.write_text("FROM python:3.13-slim\n", encoding="utf-8")
    assert base_image_digest_check.main(["prog", str(p)]) == 1
    assert "no digest-pinned" in capsys.readouterr().err


@pytest.mark.parametrize("rc_name", ["MATCH", "BEHIND", "DISAGREE", "UNKNOWN"])
def test_every_documented_verdict_is_reachable(rc_name):
    """The docstring names four verdicts; each has a test above that provokes it."""
    src = Path(base_image_digest_check.__file__).read_text(encoding="utf-8")
    assert rc_name in src, f"{rc_name} is documented but no longer emitted by the script"
