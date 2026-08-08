# llms-install.md — AI-agent install guide for Proximo

This file is for an AI agent (Cline, Claude, or any MCP-capable assistant) setting up
Proximo for a user. Follow it top to bottom. Every step is non-interactive except where
marked **ASK THE USER**.

Proximo is a Proxmox MCP server (PyPI package `proximo-proxmox`, command `proximo`).
It is read-only by default and safe to install before any credentials exist: the server
starts and serves its tool surface with no configuration at all.

## 1. Prerequisites

- Python 3.12+ available as `python3`, OR the `uv` tool (preferred — `uvx` runs the
  server with zero install).
- Network access to the user's Proxmox VE host on port 8006 (only needed at call time,
  not at setup time).

## 2. Install nothing — use uvx (preferred)

The recommended command is `uvx proximo-proxmox`: it fetches and runs the published
package on demand. There is nothing to clone and nothing to build. If `uv` is not
available, `pip install proximo-proxmox` provides the same `proximo` command.

Verify the server runs before configuring anything:

```bash
uvx proximo-proxmox --help
```

This prints usage and exits. (It must NOT start a server or bind a port — if it hangs,
the installed version predates 0.31.2; upgrade.)

## 3. Credentials — ASK THE USER

Proximo authenticates with a Proxmox API token, passed **by file reference, never as a
value**. Ask the user for three things:

1. **API base URL** — `https://<their-pve-host>:8006/api2/json`
2. **Default node name** — the Proxmox node to operate against (e.g. `pve`)
3. **Token file path** — a file on their machine containing one line:
   `USER@REALM!TOKENID=SECRET`, permissions `chmod 600`.

If the user has no token yet, run `uvx proximo-proxmox mint` — it prints a
least-privilege runbook for creating one (read-only to start). Do not paste token
secrets into config files, chat, or environment variable values; only the file path is
ever configured. Proximo refuses to start if the token file is group- or world-readable.

## 4. MCP client configuration

Add this to the MCP settings (for Cline: `cline_mcp_settings.json`; same shape for any
MCP client):

```json
{
  "mcpServers": {
    "proximo": {
      "command": "uvx",
      "args": ["proximo-proxmox"],
      "env": {
        "PROXIMO_API_BASE_URL": "https://your-pve:8006/api2/json",
        "PROXIMO_NODE": "your-node",
        "PROXIMO_TOKEN_PATH": "/path/to/token-file"
      }
    }
  }
}
```

Replace the three values with the user's answers from step 3.

## 5. Verify

1. Restart/reload the MCP client so it launches the server.
2. The server should list its doorway tools (`proximo_find_tools`, `proximo_call`,
   `proximo_tool_schema`, `audit_entries`, `audit_verify`, `proximo_recall`); the full
   catalog (900+ tools across Proxmox VE, Backup Server, Mail Gateway, and Datacenter
   Manager) is reachable through them by search.
3. Preflight the user's token (read-only, safe): call the `pve_doctor` tool via
   `proximo_call`, or run the doctor in a terminal with the same three values exported:

   ```bash
   PROXIMO_API_BASE_URL="https://your-pve:8006/api2/json" \
   PROXIMO_NODE="your-node" \
   PROXIMO_TOKEN_PATH="/path/to/token-file" \
   uvx proximo-proxmox doctor
   ```

   It reports exactly what the token can and cannot do.

## 6. What to tell the user when done

- Proximo is **read-only by default**. Mutations require a recorded PLAN first, then an
  explicit `confirm=true` call; every change lands in a tamper-evident audit ledger.
- In-container command execution is **off** unless they opt in (`PROXIMO_ENABLE_EXEC=1`
  plus a fail-closed container allowlist).
- Start with a read-only token; the server is useful long before write access exists.
- Full docs: `docs/SETUP.md` (token-first walkthrough) and `SECURITY.md` (what each
  control does and does not hold).

## Troubleshooting

- **Server won't start, complains about the token file**: the file is missing or its
  permissions are too open — `chmod 600` it.
- **`uvx: command not found`**: install uv (`pip install uv`) or fall back to
  `pip install proximo-proxmox` and use `"command": "proximo", "args": []` in the config.
- **Tools list but calls fail with 401/403**: the token lacks a role for that path —
  run the doctor preflight; its report names the missing privilege.
