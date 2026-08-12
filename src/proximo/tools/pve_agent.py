"""qemu-agent read/mutation tools (pve_agent_exec itself stays in server.py — it gates before its own auto-undo).

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.backends import ProximoError
from proximo.qemu_agent import (
    _check_agent_fs_command,
    _check_agent_info_command,
    _check_file_path,
    _content_fingerprint,
    _password_fingerprint,
    plan_agent_file_write,
    plan_agent_fs,
    plan_agent_set_password,
)
from proximo.server import (
    _agent_gate,
    _audited,
    run_governed,
    tool,
)


@tool()
def pve_agent_info(
    vmid: Annotated[str, Field(description="Numeric VM ID of the guest to query via the qemu-agent.")],
    command: Annotated[str, Field(description="qemu-agent query: ping, info, get-fsinfo, get-host-name, get-osinfo, get-time, get-timezone, get-users, get-vcpus, network-get-interfaces, get-memory-blocks, fsfreeze-status, or exec-status.")] = "info",
    pid: Annotated[int | None, Field(description="Process id returned by pve_agent_exec; required only when command='exec-status'.")] = None,
    node: Annotated[str | None, Field(description="Proxmox node name hosting the guest; auto-detected if omitted.")] = None,
) -> dict:
    """READ-ONLY: query the qemu-agent on a guest (ping, osinfo, hostname, users, exec-status, …).

    Requires PROXIMO_ENABLE_AGENT=1, the VMID in PROXIMO_AGENT_ALLOWLIST, and a running guest agent
    inside the VM. No confirm needed — read-only. Returns a dict of the raw qemu-agent response
    fields for the chosen command; for command='exec-status', run pve_agent_exec first and pass its
    returned pid here to poll for completion.
    """
    cfg, api, _, _ = _proximo_server._svc()
    blocked = _agent_gate(cfg, "pve_agent_info", vmid, mutation=False)
    if blocked:
        return blocked

    _check_agent_info_command(command)

    if command == "exec-status":
        if pid is None:
            raise ProximoError("exec-status requires pid")
        return _audited("pve_agent_info", f"qemu/{vmid}",
                        lambda: api.agent_exec_status(vmid, node, pid))
    return _audited("pve_agent_info", f"qemu/{vmid}",
                    lambda: api.agent_simple(vmid, node, command))


@tool()
def pve_agent_file_read(
    vmid: Annotated[str, Field(description="Numeric VM ID of the guest to read from via the qemu-agent.")],
    file: Annotated[str, Field(description="Absolute path of the file to read inside the guest.")],
    node: Annotated[str | None, Field(description="Proxmox node name hosting the guest; auto-detected if omitted.")] = None,
) -> dict:
    """READ-ONLY: read a file from inside the guest via the qemu-agent.

    Requires PROXIMO_ENABLE_AGENT=1, the VMID in PROXIMO_AGENT_ALLOWLIST, and a running guest agent
    inside the VM. No confirm needed — read-only. File path must be absolute. To write instead use
    pve_agent_file_write. Returns {"bytes-read": int, "content": str} — text round-trips exactly;
    the ledger records only the file path, never the content.
    """
    cfg, api, _, _ = _proximo_server._svc()
    blocked = _agent_gate(cfg, "pve_agent_file_read", vmid, mutation=False)
    if blocked:
        return blocked

    _check_file_path(file)
    return _audited("pve_agent_file_read", f"qemu/{vmid}",
                    lambda: api.agent_file_read(vmid, node, file),
                    detail={"file": file})


@tool()
def pve_agent_file_write(
    vmid: Annotated[str, Field(description="Numeric VM ID of the guest to write to via the qemu-agent.")],
    file: Annotated[str, Field(description="Absolute path of the file to write inside the guest.")],
    content: Annotated[str, Field(description="File content to write; unconditionally redacted from the ledger (fingerprint only).")],
    node: Annotated[str | None, Field(description="Proxmox node name hosting the guest; auto-detected if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the write.")] = False,
) -> dict:
    """MUTATION: write a file inside the guest via the qemu-agent.

    Requires PROXIMO_ENABLE_AGENT=1, the VMID in PROXIMO_AGENT_ALLOWLIST, and a running guest agent
    inside the VM. Dry-run by default (returns a PLAN); confirm=True executes and returns
    {"status": "ok", "result": None}. File path must be absolute; content is UNCONDITIONALLY
    redacted from the ledger (fingerprint only). Overwrites the target file whole — irreversible,
    no undo primitive on this plane. To read a file instead use pve_agent_file_read; text content
    round-trips byte-identical, binary/encoded content is unconfirmed.
    """
    cfg, api, _, _ = _proximo_server._svc()
    blocked = _agent_gate(cfg, "pve_agent_file_write", vmid, mutation=True)
    if blocked:
        return blocked

    # UNCONDITIONAL: content fingerprint only, never the body.
    detail = {"file": file, **_content_fingerprint(content)}
    return run_governed(
        "pve_agent_file_write", f"qemu/{vmid}:{file}",
        plan=lambda: plan_agent_file_write(vmid, file, content, node),
        execute=lambda: api.agent_file_write(vmid, node, file, content),
        confirm=confirm, detail=detail)


@tool()
def pve_agent_fs(
    vmid: Annotated[str, Field(description="Numeric VM ID of the guest to operate on via the qemu-agent.")],
    command: Annotated[str, Field(description="Filesystem operation: fsfreeze-freeze, fsfreeze-thaw, or fstrim.")],
    node: Annotated[str | None, Field(description="Proxmox node name hosting the guest; auto-detected if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the command.")] = False,
) -> dict:
    """MUTATION: fsfreeze-freeze, fsfreeze-thaw, or fstrim inside the guest via the qemu-agent.

    Requires PROXIMO_ENABLE_AGENT=1, the VMID in PROXIMO_AGENT_ALLOWLIST, and a running guest agent
    inside the VM. Dry-run by default (returns a PLAN); confirm=True executes and returns
    {"status": "ok", "result": <raw qemu-agent response>}. command: fsfreeze-freeze | fsfreeze-thaw
    | fstrim — freeze stalls guest I/O until thawed, so always pair them. Irreversible; no undo
    primitive on this plane.
    """
    cfg, api, _, _ = _proximo_server._svc()
    blocked = _agent_gate(cfg, "pve_agent_fs", vmid, mutation=True)
    if blocked:
        return blocked

    _check_agent_fs_command(command)
    return run_governed(
        "pve_agent_fs", f"qemu/{vmid}:{command}",
        plan=lambda: plan_agent_fs(vmid, command, node),
        execute=lambda: api.agent_simple(vmid, node, command),
        confirm=confirm, detail={"command": command})


@tool()
def pve_agent_set_password(
    vmid: Annotated[str, Field(description="Numeric VM ID of the guest whose OS user password is being set.")],
    username: Annotated[str, Field(description="Guest OS username whose password will be changed.")],
    password: Annotated[str, Field(description="New password for the guest OS user; unconditionally redacted from the ledger.")],
    node: Annotated[str | None, Field(description="Proxmox node name hosting the guest; auto-detected if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the password change.")] = False,
) -> dict:
    """MUTATION: set a guest OS user's password via the qemu-agent.

    Requires PROXIMO_ENABLE_AGENT=1, the VMID in PROXIMO_AGENT_ALLOWLIST, and a running guest agent
    inside the VM. Dry-run by default (returns a PLAN); confirm=True executes and returns
    {"status": "ok", "result": None}. Password is UNCONDITIONALLY redacted from the ledger
    (fingerprint only — "[redacted]"). Irreversible without knowledge of the old password; no undo
    primitive on this plane.
    """
    cfg, api, _, _ = _proximo_server._svc()
    blocked = _agent_gate(cfg, "pve_agent_set_password", vmid, mutation=True)
    if blocked:
        return blocked

    # UNCONDITIONAL: password redacted always, regardless of cfg.redact_ledger.
    detail = {"username": username, **_password_fingerprint()}
    return run_governed(
        "pve_agent_set_password", f"qemu/{vmid}:{username}",
        plan=lambda: plan_agent_set_password(vmid, username, node),
        execute=lambda: api.agent_set_password(vmid, node, username, password),
        confirm=confirm, detail=detail)
