"""Proximo — the ethical Proxmox MCP.

Proxmox REST API management + scoped in-container exec, behind clean native tools.
Exec off by default; bounded by the token you scope; every action audited; the PVE token is read
from its file only at call time, never logged or persisted.
"""

__version__ = "0.30.0"
