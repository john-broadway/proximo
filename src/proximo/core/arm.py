"""CONSENT -- the ARM predicate: is the token the box serves actually the WRITE token?

Armed  <=>  the served token's bytes equal the arm source's bytes. The inverse ("armed unless it
matches the read-only source") fails OPEN on a garbled, rotated or truncated token; equality with
the arm source fails CLOSED by construction and self-heals on rotation. `PROXIMO_READONLY_SOURCE`
is read for message quality only, never for enforcement. No token material leaves this module.

`cfg` is duck-typed: `token_path`, `arm_source`, `readonly_source`. The big package's
ProximoConfig carries them; a registry target carries them; the core needs no config type of its
own to ask the question. The full rationale (the ssh-path fail-open this closes, why equality and
not inequality) is in the ARM section of SECURITY.md.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .secretfile import register_secret

#: THE TICKET IS THE ARM (2026-11-05). A token is an identity (the vendor ships it with `expire` 0 and
#: means a standing credential with an ACL); a ticket is a session (`POST /access/ticket`, the vendor's
#: two hours, dead on its own). A person arms by logging in; the served file then holds the ticket, and
#: the predicate reads the ticket's OWN issue time: hex seconds in its text, signed by the vendor. A job
#: with nobody at a keyboard keeps the token pair below, unchanged.
TICKET_LIFETIME = 7200            # the vendor's ticket lifetime, seconds; not a knob of ours
TICKET_PREFIX = {"pve": "PVE", "pbs": "PBS", "pdm": "PDM"}   # the planes whose wire sends a ticket; PMG logs in itself
#: The vendor's ticket, exactly: PREFIX:user@realm:<8 hex>::<base64 signature>. A user with `!` is a token, not a
#: login; a `!tfa!` marker is a challenge, never a credential; any other byte (a newline that h11 then echoed with
#: the whole ticket, lens 2026-11-05) is not a ticket.
TICKET_RE = re.compile(r"^(PVE|PBS|PDM|PMG):([^:!\s@]+@[^:!\s@]+):([0-9A-Fa-f]{8})::([A-Za-z0-9+/=_-]+)$")
_PRINTABLE = re.compile(r"^[!-~]+$")

ARM_SOURCE_ENV = "PROXIMO_ARM_SOURCE"  # noqa: S105 -- env var NAME, not a secret value
READONLY_SOURCE_ENV = "PROXIMO_READONLY_SOURCE"  # noqa: S105 -- env var NAME
TOKEN_PATH_ENV = "PROXIMO_TOKEN_PATH"  # noqa: S105 -- env var NAME; shared with lease.py/arm.py
BASE_URL_ENV = "PROXIMO_API_BASE_URL"    # the env box's identity beside its token file


@dataclass(frozen=True)
class ArmGateState:
    """``enforced`` False => the operator does not use the arm pattern; ``armed`` is then moot.

    ``reason`` is a short, non-secret explanation for the ledger and the refusal text. It names
    file *conditions* only — never a path's contents.
    """

    enforced: bool
    armed: bool
    reason: str = ""


def _read_token(path: str) -> bytes | None:
    """Stripped bytes of a readable REGULAR file, else None (which always reads as NOT armed).

    A directory is rejected explicitly: ``open()`` on one raises IsADirectoryError (an OSError,
    so it would already fail closed) but naming it keeps the failure legible.
    """
    if not path:
        return None
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(path, "rb") as f:
            data = f.read().strip()
        register_secret(data.decode("utf-8", errors="replace"))  # the arm token is a token
        return data
    except OSError:
        return None


def served_credential(path: str) -> tuple[str, Any]:
    """What the served file holds: ("token", bytes), ("ticket", {ticket, csrf, box, prefix, user, issued}) or
    ("unreadable", why). THE ONE READER for the predicate and the wire, so they never disagree. A ticket file
    is JSON `{"ticket", "csrf", "box"}` written by `proximo-core arm`; `issued` is parsed from the ticket's
    own text (`PREFIX:user@realm:<hex seconds>::<sig>`), nothing of ours is stored. A TFA challenge
    (`PREFIX:!tfa!...`) is never a served credential."""
    raw = _read_token(path)
    if raw is None:
        return "unreadable", "the served credential is missing, unreadable, or not a regular file"
    return credential_from_bytes(raw)


def credential_from_bytes(raw: bytes) -> tuple[str, Any]:
    """`served_credential` on bytes already in hand: the verb reads the vendor's answer through this before it
    serves it, so what the file reader would refuse is never written."""
    if not raw:
        return "unreadable", "the served credential is empty"
    if raw[:1] != b"{":
        return "token", raw
    try:
        doc = json.loads(raw)
    except ValueError:
        return "unreadable", "the served ticket file is not JSON"
    if not isinstance(doc, dict):
        return "unreadable", "the served ticket file is not a JSON object"
    ticket, csrf, box = doc.get("ticket"), doc.get("csrf"), doc.get("box")
    if not (isinstance(ticket, str) and ticket and isinstance(csrf, str) and csrf and isinstance(box, str) and box):
        return "unreadable", "the served ticket file lacks ticket, csrf or box"
    fields = ticket_fields(ticket)
    if fields is None:
        return "unreadable", "the served ticket is not a vendor ticket"
    if not _PRINTABLE.match(csrf):
        return "unreadable", "the served CSRF token is not one a header can carry"
    if not _box_url(box):
        return "unreadable", "the served ticket names no box"
    register_secret(ticket)
    register_secret(csrf)
    prefix, user, issued = fields
    return "ticket", {"ticket": ticket, "csrf": csrf, "box": _box_url(box), "prefix": prefix, "user": user,
                      "issued": issued}


def ticket_fields(text: object) -> tuple[str, str, int] | None:
    """(prefix, user, issued) when `text` is exactly a vendor ticket, else None."""
    m = TICKET_RE.fullmatch(text) if isinstance(text, str) else None     # fullmatch: `$` forgives a trailing newline
    return (m.group(1), m.group(2), int(m.group(3), 16)) if m else None


def ticket_state(cred: dict[str, Any], product: str, box: str) -> ArmGateState:
    """The predicate for a served ticket: armed iff it is this product's ticket, for this box, and the vendor's
    two hours have not passed since its own issue time. Everything else is not armed and says why; nothing of
    ours extends it."""
    prefix = TICKET_PREFIX.get(product)
    if prefix is None:
        return ArmGateState(enforced=True, armed=False,
                            reason=f"a ticket file is not {product.upper()}'s credential: its wire logs in itself")
    if not _box_url(box):
        return ArmGateState(enforced=True, armed=False, reason="this plane names no box, so no ticket can be its own")
    if cred["prefix"] != prefix:
        return ArmGateState(enforced=True, armed=False,
                            reason=f"the served ticket is a {cred['prefix']} ticket and this box is {product}")
    if cred["box"] != _box_url(box):
        return ArmGateState(enforced=True, armed=False, reason="the served ticket is for another box")
    age = time.time() - cred["issued"]
    dies = datetime.fromtimestamp(cred["issued"] + TICKET_LIFETIME, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if age < 0:
        return ArmGateState(enforced=True, armed=False, reason="the served ticket is from the future; not trusted")
    if age >= TICKET_LIFETIME:
        return ArmGateState(enforced=True, armed=False,
                            reason=f"the ticket died at {dies} (the vendor's two hours); arm again")
    return ArmGateState(enforced=True, armed=True, reason=f"a ticket for {cred['user']}, armed until {dies}")


def raw_is_ticket_shaped(path: str) -> bool:
    """True when the served file starts like a ticket file (`{`): a malformed one fails closed with its own
    words instead of being compared as a token to the pair."""
    raw = _read_token(path)
    return raw is not None and raw[:1] == b"{"


def _box_url(value: object) -> str:
    """A base_url as a box identity: stripped, no trailing slash; "" when there is none to compare."""
    return value.strip().rstrip("/") if isinstance(value, str) else ""


def _same_path(a: str, b: str) -> bool:
    """True if two CONFIG VALUES name one file. Deliberately does NOT resolve symlinks or compare
    inodes: `test_a_symlinked_token_is_judged_by_its_TARGET` pins the symlink case as ARMED on
    purpose, and it is right to. `arm`/`disarm` install via temp+rename, which REPLACES a symlink
    at token_path with a regular file, so a symlink is transient and self-correcting. Two env
    vars set to the same path is neither: `disarm` would overwrite the arm source with the
    read-only token and the comparison could never mean anything again."""
    return os.path.normpath(os.path.abspath(a)) == os.path.normpath(os.path.abspath(b))


def arm_state(cfg: Any | None = None) -> ArmGateState:
    """Read fresh and decide whether live WRITE authority is being served. Never caches.

    ``cfg`` is the config of the box the command is actually aimed at. Pass it. Without it this
    grades the process env, which is right only for the env-configured box: proximo has a target
    registry, and ``packaging/targets.example.toml`` already promises that "arming stays
    out-of-band and per-target: it swaps the token at that target's token_path". Grading the env
    while ssh -> pct exec runs against a registry target meant ARMED HERE READ AS ARMED
    EVERYWHERE. envelope.py resolves the active target for exactly this reason.

    Precedence, and every branch of it fails closed:
      * no cfg                       -> the env pair (unchanged, and the common single-box case)
      * cfg IS the env box           -> the env pair may supply what cfg leaves unset
      * cfg is a different box       -> its OWN arm_source, or NOT ARMED with a reason naming it
    """
    env_arm = os.environ.get(ARM_SOURCE_ENV, "").strip()
    env_token = os.environ.get(TOKEN_PATH_ENV, "").strip()
    env_ro = os.environ.get(READONLY_SOURCE_ENV, "").strip()

    if conflict := getattr(cfg, "conflict", None):
        return ArmGateState(enforced=True, armed=False, reason=f"misconfigured: {conflict}")
    # A SERVED TICKET IS JUDGED FIRST, by its own clock; it needs no pair. The file is read once more below
    # for the token path, as it always was (the token branch is unchanged).
    served_path = env_token if cfg is None else (cfg.token_path or "").strip()
    kind, cred = served_credential(served_path) if served_path else ("unreadable", "no served path")
    if kind == "ticket" and isinstance(cred, dict):
        box = os.environ.get(BASE_URL_ENV, "") if cfg is None else \
            (getattr(cfg, "base_url", None) or getattr(cfg, "api_base_url", None) or "")
        return ticket_state(cred, "pve" if cfg is None else (getattr(cfg, "product", None) or "pve"), box)
    if kind == "unreadable" and served_path and raw_is_ticket_shaped(served_path):
        return ArmGateState(enforced=True, armed=False, reason=f"not armed: {cred}")
    if cfg is None:
        arm_source, token_path, readonly = env_arm, env_token, env_ro
    else:
        token_path = (cfg.token_path or "").strip()
        # Same token file AT the same base_url => this IS the env-configured box, however it was
        # constructed. Normalized, like the degenerate-config check below: two spellings of one
        # path are one box, and disagreeing with _same_path here would refuse the env box over a
        # trailing slash. The token file alone was the test until 2026-09-23 (lens 4): a registry
        # entry for ANOTHER host that named the env token file, with no arm pair of its own, read
        # as the env box and ran armed against a host the operator never armed. The box must be
        # AT the env's base_url; an env that names no base_url cannot prove any box is its own
        # (lens 5: "when set" fell back to the token file alone the moment it was unset).
        box_url = _box_url(getattr(cfg, "base_url", None) or getattr(cfg, "api_base_url", None))
        env_url = _box_url(os.environ.get(BASE_URL_ENV))
        # AND the box is PVE's: the env pair is PVE's pair. A pbs Plane at PVE's url with PVE's
        # token file (a copy-pasted env) matched on file + url alone and inherited PVE's arm
        # (lens 2026-09-28). The 0.44 config carries no product; it is the PVE box.
        product = getattr(cfg, "product", None)
        is_env_box = (product in (None, "pve")
                      and bool(token_path) and bool(env_token) and _same_path(token_path, env_token)
                      and bool(env_url) and box_url == env_url)
        arm_source = (cfg.arm_source or "").strip() or (env_arm if is_env_box else "")
        readonly = (cfg.readonly_source or "").strip() or (env_ro if is_env_box else "")
        if product == "pmg" and not getattr(cfg, "credential", False):
            # PASSWORD mode, on EVERY path, a registry target's arm_source included (lens
            # 2026-09-28): the reason is a fact about that login, not about where the config came
            # from. CREDENTIAL mode carries the user in the file and falls through to the pair.
            return ArmGateState(
                enforced=True, armed=False,
                reason="PMG in password mode has no arm pair: the username comes from config and "
                       "only the password from a file, so swapping the password cannot switch a "
                       "read-only user for a write one. Use PROXIMO_PMG_CREDENTIAL_PATH (a file of "
                       "two lines: user@realm, then the password) with PROXIMO_PMG_ARM_SOURCE and "
                       "_READONLY_SOURCE in the same form")
        if not arm_source and product in ("pbs", "pdm", "pmg") and not getattr(cfg, "name", None):
            return ArmGateState(
                enforced=True, armed=False,
                reason=f"this {product.upper()} box has no arm pair: set PROXIMO_{product.upper()}"
                       f"_ARM_SOURCE (and _READONLY_SOURCE); another plane's arm never authorizes it")
        if not arm_source and env_arm:
            # The operator DOES use the arm pattern, just not for this box. Silence must not
            # read as permission: refuse, and say exactly which knob is missing.
            return ArmGateState(
                enforced=True, armed=False,
                reason="this target has no arm_source configured — set arm_source on its registry "
                       "entry; the default box's arm never authorizes another box")

    if not arm_source:
        return ArmGateState(enforced=False, armed=False, reason="arm pattern not configured")

    # `x == x` is not authority: one path for both sides would report ARMED forever, silently.
    if token_path and _same_path(token_path, arm_source):
        return ArmGateState(enforced=True, armed=False,
                            reason="misconfigured: the served token and the arm source are the "
                                   "same file, so the check would compare it to itself")

    served = _read_token(token_path)
    if served is None:
        return ArmGateState(enforced=True, armed=False,
                            reason="the served token is missing, unreadable, or not a regular file")
    if not served:
        # b"" == b"" would otherwise call an empty token a match against an empty arm source.
        return ArmGateState(enforced=True, armed=False, reason="the served token is empty")

    expected = _read_token(arm_source)
    readonly_bytes = _read_token(readonly)
    if expected is not None and readonly_bytes is not None and expected == readonly_bytes:
        # TWO PATHS, ONE SECRET. The served token equals the arm source whenever it equals the
        # read-only one, so the gate would read ARMED forever. Only one path was refused before.
        return ArmGateState(enforced=True, armed=False,
                            reason="misconfigured: the arm source and the read-only source hold the "
                                   "same secret, so disarming could never change anything")
    if expected is None:
        return ArmGateState(enforced=True, armed=False,
                            reason="the arm source is missing, unreadable, or not a regular file")
    if served == expected:
        return ArmGateState(enforced=True, armed=True, reason="the served token is the arm source")

    # Enforcement is already decided. This only sharpens the message.
    if readonly_bytes is not None and served == readonly_bytes:
        return ArmGateState(enforced=True, armed=False, reason="disarmed (serving the read-only token)")
    return ArmGateState(enforced=True, armed=False,
                        reason="the served token matches neither the arm nor the read-only source")
