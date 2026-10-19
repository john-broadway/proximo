"""WHO ASKED: the name tag and the verified caller every ledger row carries.

Moved here from `proximo.principal` so the core's `_record` stamps the same principal the 0.44
rows carry, from ONE process global and ONE context variable: `proximo.principal` re-exports
these names rather than keeping a copy, because a face that set its face on one copy while the
core read the other would put a false access path in the tamper-evident log. The badge crypto
(the camera that verifies a caller) stays there; it needs the `cryptography` extra and this
module stays stdlib-only, inside the core's closure.

Identity, never authority: the Proxmox token and the spine decide WHAT; this names WHO.
"""
from __future__ import annotations

import contextvars
import os

_MAX_ID_LEN = 120

# Per-request verified caller (network faces). None => no verified caller in this context.
_active_caller: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "proximo_active_caller", default=None
)

_serving_face: str = "stdio"


def sanitize_id(raw: str) -> str:
    """Printable, single-line, length-capped — same posture as audit._sanitize_target."""
    cleaned = "".join(ch for ch in raw if ch.isprintable() and ch not in "\r\n")
    return cleaned.strip()[:_MAX_ID_LEN]


def process_principal() -> str | None:
    """The operator-declared name tag (``PROXIMO_PRINCIPAL``). None when unset/blank."""
    raw = os.environ.get("PROXIMO_PRINCIPAL", "")
    return sanitize_id(raw) or None


def set_serving_face(face: str) -> None:
    """Which door this process serves ("stdio" | "http" | "a2a" | ...). Set once per entrypoint."""
    global _serving_face
    _serving_face = sanitize_id(face) or "stdio"


def serving_face() -> str:
    return _serving_face


def set_active_caller(caller: str | None) -> contextvars.Token:
    return _active_caller.set(caller)


def reset_active_caller(token: contextvars.Token) -> None:
    _active_caller.reset(token)


def ledger_principal() -> dict | None:
    """The ``principal`` object for a PROVE entry — verified caller wins, else the name tag."""
    caller = _active_caller.get()
    if caller:
        return {"id": caller, "via": "verified", "face": _serving_face}
    tag = process_principal()
    if tag:
        return {"id": tag, "via": "spawn", "face": _serving_face}
    return None
