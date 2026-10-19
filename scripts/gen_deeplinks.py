#!/usr/bin/env python3
"""
Single source for the README one-click install deeplinks (VS Code / Cursor).

The field-standard MCP install deeplink prompts the user to paste the token
SECRET into client config — the exact anti-pattern `proximo mint` exists to
kill. Proximo's deeplinks prompt for the token FILE PATH instead
(PROXIMO_TOKEN_PATH): secrets-by-reference survives one-click convenience.

tests/test_deeplinks.py pins the no-secret invariant and pins README.md to
this script's exact output. To change the deeplinks: edit here, run

    uv run python scripts/gen_deeplinks.py

and paste the printed markdown over the README's install-buttons block.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

NAME = "proximo"

# VS Code prompts at install time — the token prompt asks for the PATH.
VSCODE_INPUTS = [
    {
        "id": "proximo_api_base_url",
        "type": "promptString",
        "description": "PVE API base URL, e.g. https://your-pve:8006/api2/json",
    },
    {
        "id": "proximo_token_path",
        "type": "promptString",
        "description": (
            "Path to your token FILE (USER@REALM!TOKENID=SECRET inside) — "
            "the secret itself is never entered here"
        ),
    },
]

VSCODE_CONFIG = {
    "command": "uvx",
    "args": ["proximo-proxmox"],
    "env": {
        "PROXIMO_API_BASE_URL": "${input:proximo_api_base_url}",
        "PROXIMO_TOKEN_PATH": "${input:proximo_token_path}",
    },
}

# Cursor deeplinks cannot prompt — ship obvious placeholders, same shape as
# the Quickstart block (a token-file PATH, never a secret).
CURSOR_CONFIG = {
    "command": "uvx",
    "args": ["proximo-proxmox"],
    "env": {
        "PROXIMO_API_BASE_URL": "https://your-pve:8006/api2/json",
        "PROXIMO_TOKEN_PATH": "/path/to/token-file",
    },
}


def _compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


def vscode_url() -> str:
    return (
        "https://insiders.vscode.dev/redirect/mcp/install"
        f"?name={NAME}"
        f"&inputs={quote(_compact(VSCODE_INPUTS), safe='')}"
        f"&config={quote(_compact(VSCODE_CONFIG), safe='')}"
    )


def cursor_url() -> str:
    b64 = base64.b64encode(_compact(CURSOR_CONFIG).encode()).decode()
    return f"https://cursor.com/install-mcp?name={NAME}&config={quote(b64, safe='')}"


def markdown() -> str:
    vscode_badge = (
        "https://img.shields.io/badge/VS_Code-Install_Proximo-0098FF"
        "?style=flat-square&logo=visualstudiocode&logoColor=white"
    )
    cursor_badge = "https://img.shields.io/badge/Cursor-Install_Proximo-000000?style=flat-square"
    return (
        f"[![Install in VS Code]({vscode_badge})]({vscode_url()})\n"
        f"[![Install in Cursor]({cursor_badge})]({cursor_url()})\n"
        "\n"
        "<sub>Both prompt for (or placeholder) the token file **path** — the secret "
        "itself never lands in client config. No token yet? `uvx proximo-proxmox mint` "
        "prints the least-privilege runbook.</sub>"
    )


if __name__ == "__main__":
    print(markdown())
