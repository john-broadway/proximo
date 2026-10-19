"""
Structural tests for the README one-click install deeplinks (VS Code / Cursor).

The deeplinks are single-sourced from scripts/gen_deeplinks.py; these tests
pin two things:

1. The no-secret invariant — the field-standard MCP install deeplink prompts
   the user to paste the token SECRET into client config (the exact
   anti-pattern `proximo mint` exists to kill). Proximo's deeplink prompts for
   the token FILE PATH (PROXIMO_TOKEN_PATH) instead: no input may be a
   password prompt, and no env key may carry a TOKEN_VALUE/SECRET shape.
2. README <-> generator drift — the URLs embedded in README.md must be exactly
   the generator's current output, so editing either side alone fails CI.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
from urllib.parse import parse_qs, urlparse

_ROOT = pathlib.Path(__file__).parent.parent
_README = _ROOT / "README.md"
_SCRIPT = _ROOT / "scripts" / "gen_deeplinks.py"

_EXPECTED_ENV_KEYS = {"PROXIMO_API_BASE_URL", "PROXIMO_TOKEN_PATH"}
_FORBIDDEN_SHAPES = ("TOKEN_VALUE", "TOKEN_SECRET", "PROXIMO_TOKEN=", "PASSWORD")


def _mod():
    spec = importlib.util.spec_from_file_location("gen_deeplinks", _SCRIPT)
    assert spec is not None and spec.loader is not None, f"missing {_SCRIPT}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _vscode_params() -> dict:
    url = _mod().vscode_url()
    qs = parse_qs(urlparse(url).query)
    return {
        "name": qs["name"][0],
        "inputs": json.loads(qs["inputs"][0]),
        "config": json.loads(qs["config"][0]),
    }


def _cursor_config() -> dict:
    url = _mod().cursor_url()
    qs = parse_qs(urlparse(url).query)
    return json.loads(base64.b64decode(qs["config"][0]))


# ---------------------------------------------------------------- no-secret pin


def test_vscode_inputs_prompt_for_path_never_secret():
    """No VS Code input may be a password prompt, and the token input must be
    the file PATH — the deeplink never asks for the secret itself."""
    inputs = _vscode_params()["inputs"]
    ids = {i["id"] for i in inputs}
    assert "proximo_token_path" in ids, "the token input must be the PATH input"
    for i in inputs:
        assert not i.get("password"), (
            f"input {i['id']!r} is a password prompt — that is the paste-the-secret "
            "anti-pattern this deeplink exists to avoid; prompt for the token PATH"
        )
        assert "value" not in i["id"] and "secret" not in i["id"], (
            f"input id {i['id']!r} smells like a secret prompt"
        )


def test_vscode_config_is_by_reference():
    """The VS Code config wires exactly the three PROXIMO_* env vars, each by
    ${input:...} reference — no inline values, no secret-shaped keys."""
    cfg = _vscode_params()["config"]
    assert cfg["command"] == "uvx"
    assert cfg["args"] == ["proximo-proxmox"]
    assert set(cfg["env"]) == _EXPECTED_ENV_KEYS
    for key, val in cfg["env"].items():
        assert val.startswith("${input:") and val.endswith("}"), (
            f"env {key} must reference a prompt input, got {val!r}"
        )
    blob = json.dumps(cfg).upper()
    for shape in _FORBIDDEN_SHAPES:
        assert shape not in blob, f"secret-shaped key {shape!r} in VS Code config"


def test_cursor_config_is_placeholders_only():
    """Cursor deeplinks cannot prompt, so the config ships placeholder values —
    same three env keys, obviously-fake values, still no secret-shaped keys."""
    cfg = _cursor_config()
    assert cfg["command"] == "uvx"
    assert cfg["args"] == ["proximo-proxmox"]
    assert set(cfg["env"]) == _EXPECTED_ENV_KEYS
    assert cfg["env"]["PROXIMO_TOKEN_PATH"] == "/path/to/token-file", (
        "the Cursor placeholder must be the same token-file path the Quickstart "
        "teaches — a PATH, never a secret"
    )
    for val in cfg["env"].values():
        assert "your-" in val or val.startswith("/path/"), (
            f"Cursor placeholder {val!r} does not look like an obvious placeholder"
        )
    blob = json.dumps(cfg).upper()
    for shape in _FORBIDDEN_SHAPES:
        assert shape not in blob, f"secret-shaped key {shape!r} in Cursor config"


# ------------------------------------------------------------------- drift pin


def test_readme_carries_generator_vscode_url():
    """README must embed exactly the generator's VS Code URL (drift pin)."""
    assert _mod().vscode_url() in _README.read_text(encoding="utf-8"), (
        "README.md does not carry the current gen_deeplinks.py VS Code URL — "
        "rerun: uv run python scripts/gen_deeplinks.py"
    )


def test_readme_carries_generator_cursor_url():
    """README must embed exactly the generator's Cursor URL (drift pin)."""
    assert _mod().cursor_url() in _README.read_text(encoding="utf-8"), (
        "README.md does not carry the current gen_deeplinks.py Cursor URL — "
        "rerun: uv run python scripts/gen_deeplinks.py"
    )
