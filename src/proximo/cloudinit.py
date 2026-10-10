"""CLOUD-INIT & TEMPLATE pillar — read/set cloud-init config on QEMU VMs, convert to template.

Cloud-init is QEMU-only on Proxmox (LXC uses per-container OS tools, not a cloud-init drive).
Every function here raises ProximoError if called with kind != 'qemu'.

Following Proximo's module idiom exactly:
- Op functions build requests and return results; they do NOT self-gate.
  The server layer adds confirm-gating + audit before calling these.
- Plan functions read live state (one safe read) to surface facts.
- All path components validated before entering URLs.
- Secret fields (cipassword and similar) are NEVER echoed back in plans/results/ledger.
  _mask_secrets() runs on every dict that may contain secret values before it is returned
  or stored.

Hard rules:
- plan_template_convert carries RISK_HIGH and makes NO undo claim (one-way op).
- plan_cloudinit_set captures UNDO by storing prior field values via cloudinit_get.
  However, cipassword (and other secret fields) cannot be retrieved from PVE — if the live
  GET returns them masked/omitted, the UNDO snapshot for those fields is incomplete.
  This limitation is flagged in the plan; no false-recovery claim is made.

SHAPE-RISKS (unverified until live PVE smoke — document honestly, do not change):
  [SR-1] GET /nodes/{n}/qemu/{vmid}/config returns cloud-init keys inline alongside disk/net
         config. Key names assumed: ciuser, cipassword, sshkeys, ipconfig0..ipconfig<N>,
         nameserver, searchdomain, citype, cicustom. Exact set is live-unverified.
  [SR-2] cipassword: PVE may return it masked ("*****"), omitted, or (unlikely) cleartext.
         _mask_secrets() masks it regardless; UNDO snapshot for secret fields may be incomplete
         and is flagged in the plan.
  [SR-3] POST /nodes/{n}/qemu/{vmid}/config is synchronous and returns None (not a UPID).
         Mirror of backup_delete's honest "may return None" stance.
  [SR-4] sshkeys value may need URL-encoding when sent to PVE (newlines, spaces in the
         public-key blob). Encoding is the caller's responsibility; this module passes the
         value through.
  [SR-5] ipconfigN keys are accepted for N 0..31 (a liberal range; PVE may enforce a tighter
         bound at the API level).
  [SR-6] POST /nodes/{n}/qemu/{vmid}/template: body is empty (or accepts no params); return
         is None or a UPID string. We return raw and do not validate. True irreversibility
         (no un-template endpoint) assumed but live-unverified.
  [SR-7] The "similar secret fields" set beyond cipassword is a curated guess. Only
         cipassword is treated as secret here; extend _SECRET_KEYS if others are confirmed.
  [SR-8] LXC has /nodes/{n}/lxc/{vmid}/template but its semantics/params differ; it is
         out-of-scope and explicitly refused in plan_template_convert.
"""

from __future__ import annotations

import re

from .backends import ProximoError, _check_node, _check_vmid, guest_absent
from .planning import RISK_HIGH, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Cloud-init key allowlist
# ---------------------------------------------------------------------------

# Scalar cloud-init keys accepted by pve_cloudinit_set. (ipconfig<N> handled separately.)
# [SR-1]: Names derived from PVE docs; live verification required.
_SCALAR_CI_KEYS: frozenset[str] = frozenset({
    "ciuser",
    "cipassword",
    "sshkeys",
    "nameserver",
    "searchdomain",
    "citype",
    "cicustom",
})

# Indexed ipconfig pattern: ipconfig0 .. ipconfig31.  [SR-5]
_IPCONFIG_RE = re.compile(r"^ipconfig(?:[0-9]|[12][0-9]|3[01])$")

# Secret fields — NEVER echo back in plans, results, or ledger.  [SR-2]
_SECRET_KEYS: frozenset[str] = frozenset({"cipassword"})

_SECRET_MASK = "***"  # noqa: S105 — this is a mask string, not a password


def _is_allowed_ci_key(key: str) -> bool:
    return key in _SCALAR_CI_KEYS or bool(_IPCONFIG_RE.match(key))


def _check_ci_key(key: str) -> str:
    k = str(key).strip()
    if not _is_allowed_ci_key(k):
        raise ProximoError(
            f"unknown or unsupported cloud-init key: {key!r}. "
            f"Allowed scalar keys: {sorted(_SCALAR_CI_KEYS)}; indexed: ipconfigN (0-31)"
        )
    return k


def _mask_secrets(d: dict) -> dict:
    """Return a shallow copy of d with secret field values replaced by '***'.

    Runs before any dict is returned to the caller, stored in a plan, or recorded to the ledger.
    The mask is NOT reversible — the original value is not retained anywhere after masking.
    """
    return {k: (_SECRET_MASK if k in _SECRET_KEYS else v) for k, v in d.items()}


def _check_qemu_only(kind: str) -> str:
    """Cloud-init is QEMU-only on Proxmox. Raise ProximoError for LXC or other kinds."""
    if kind != "qemu":
        raise ProximoError(
            f"cloud-init is QEMU-only on Proxmox (kind={kind!r}). "
            "LXC containers do not use a cloud-init drive."
        )
    return kind


# ---------------------------------------------------------------------------
# Operations — each validates params, builds exact PVE URL, returns raw result
# ---------------------------------------------------------------------------

# Cloud-init key names as returned by PVE GET /config  [SR-1]
_CI_KEY_NAMES: frozenset[str] = _SCALAR_CI_KEYS | frozenset(
    f"ipconfig{i}" for i in range(32)
)


def cloudinit_get(
    api,
    vmid: str,
    node: str | None = None,
    kind: str = "qemu",
) -> dict:
    """Read cloud-init config from a QEMU VM's config endpoint.

    GET /nodes/{node}/qemu/{vmid}/config  (read-only, QEMU-only)

    Returns only the cloud-init-relevant fields from the full VM config, with secret
    fields masked. Non-cloud-init config keys (disk, net, cores, ...) are stripped.
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    _check_qemu_only(kind)
    n = node or api.config.node
    raw: dict = api._get(f"/nodes/{n}/qemu/{vmid}/config") or {}
    # Filter to only CI keys and mask secrets.  [SR-1, SR-2]
    ci = {k: v for k, v in raw.items() if k in _CI_KEY_NAMES}
    return _mask_secrets(ci)


def cloudinit_set(
    api,
    vmid: str,
    changes: dict,
    node: str | None = None,
    kind: str = "qemu",
):
    """Apply cloud-init config changes to a QEMU VM.

    POST /nodes/{node}/qemu/{vmid}/config  →  None (synchronous; [SR-3])

    Only allowed cloud-init keys are accepted; unknown keys raise ProximoError.
    The caller is responsible for URL-encoding sshkeys values if required by PVE. [SR-4]
    Changes take effect on next reboot + cloud-init regen — not live.

    Returns None or a UPID string (storage-backend-dependent; return raw).  [SR-3]
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    _check_qemu_only(kind)
    if not changes or not isinstance(changes, dict):
        raise ProximoError("changes must be a non-empty dict of cloud-init key/value pairs")
    validated: dict = {}
    for k, v in changes.items():
        validated[_check_ci_key(k)] = v
    n = node or api.config.node
    # MUTATION — confirm-gated + audited at the server layer.
    # [SR-3]: POST /config is synchronous; returns None in practice.
    return api._post(f"/nodes/{n}/qemu/{vmid}/config", validated)


def template_convert(
    api,
    vmid: str,
    node: str | None = None,
    kind: str = "qemu",
):
    """Convert a QEMU VM into a template.  IRREVERSIBLE.

    POST /nodes/{node}/qemu/{vmid}/template  →  None or UPID  [SR-6]

    LXC has a separate endpoint (/lxc/{vmid}/template) with different semantics
    and is out-of-scope; kind='lxc' is refused.  [SR-8]

    Converting to a template is effectively one-way: there is no "un-template"
    endpoint. This is stated clearly in plan_template_convert.
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    _check_qemu_only(kind)
    n = node or api.config.node
    # DESTRUCTIVE/IRREVERSIBLE MUTATION — confirm-gated + audited at the server layer.
    # [SR-6]: return value is raw; do not validate as UPID.
    return api._post(f"/nodes/{n}/qemu/{vmid}/template")


# ---------------------------------------------------------------------------
# UNDO capture — cloud-init-specific (separate from snapshot-based _auto_undo)
# ---------------------------------------------------------------------------

def capture_cloudinit_undo(
    api,
    vmid: str,
    node: str | None = None,
    kind: str = "qemu",
) -> dict:
    """Capture current cloud-init field values as an UNDO record before mutation.

    Reads the current cloud-init config via cloudinit_get (secret fields masked).
    Returns a dict with the prior values that can be passed back to cloudinit_set to revert.

    Important: secret fields (cipassword) are masked in the snapshot — PVE may return them
    omitted or pre-masked, so a true password revert is not possible from this snapshot alone.
    This limitation is disclosed and must NOT be papered over.  [SR-2]
    """
    prior = cloudinit_get(api, vmid, node=node, kind=kind)
    had_secrets = any(k in _SECRET_KEYS for k in prior)
    # Strip secret keys ENTIRELY (not just mask): a masked value like "*****" must never be
    # re-applied as a real password on revert. The undo record restores non-secret fields only.
    revertable = {k: v for k, v in prior.items() if k not in _SECRET_KEYS}
    note = None
    if had_secrets:
        note = (
            "secret fields (cipassword) are NOT captured here; reverting restores non-secret "
            "cloud-init fields only — re-supply the password manually to fully revert"
        )
    return {
        "prior_ci_config": revertable,
        "secret_undo_caveat": note,
        # [SR-3 / audit M-2] Reverting re-applies these prior fields via a bare set (no delete
        # param), so any cloud-init key this change ADDS (one absent beforehand) is NOT removed by
        # the revert — it persists. A full key-delete revert (cf. guest_config_revert) is not yet
        # implemented; disclose the gap rather than imply a clean round-trip.
        "additive_key_caveat": (
            "revert re-applies prior fields but does NOT delete keys this change adds; "
            "a key newly introduced by the change persists after revert"
        ),
    }


# ---------------------------------------------------------------------------
# Plan functions — each returns a Plan for caller inspection (PLAN pillar)
# ---------------------------------------------------------------------------

def plan_cloudinit_set(
    api,
    vmid: str,
    changes: dict,
    node: str | None = None,
    kind: str = "qemu",
) -> Plan:
    """Preview setting cloud-init config on a QEMU VM.

    Reads live config (one safe GET) to:
    - Validate that all change keys are allowed cloud-init keys.
    - Build a diff (current → new) for the blast radius, with secret fields masked.
    - Capture UNDO snapshot of current values (secret fields omitted per masking).

    Risk: RISK_MEDIUM — changes are staged; they apply on next reboot + cloud-init
    regen, not immediately. However, wrong sshkeys / network config can lock out
    access after the next reboot.

    If the live read fails, uncertainty is disclosed (same honesty as plan_restore):
    transient errors are NOT treated as "no current config exists".
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    _check_qemu_only(kind)

    # Validate keys before touching the API — reject unknown keys immediately.
    validated_changes: dict = {}
    for k, v in (changes or {}).items():
        validated_changes[_check_ci_key(k)] = v

    if not validated_changes:
        raise ProximoError("changes must be a non-empty dict of cloud-init key/value pairs")

    # One safe read to show what's being changed.
    # (UNDO capture is done by capture_cloudinit_undo at the server layer, not here.)
    current_ci: dict = {}
    check_failed = False
    try:
        current_ci = cloudinit_get(api, vmid, node=node, kind=kind)
    except Exception:
        check_failed = True

    # Build diff (masked). Secret values in changes are masked for the plan record.
    masked_changes = _mask_secrets(validated_changes)
    diff_lines: list[str] = []
    for k, new_v in masked_changes.items():
        old_v = current_ci.get(k, "<not set>")
        if k in _SECRET_KEYS:
            old_v = _SECRET_MASK
        diff_lines.append(f"  {k}: {old_v!r} → {new_v!r}")

    diff_text = "\n".join(diff_lines) if diff_lines else "(no displayable diff)"

    # Blast radius notes.
    blast: list[str] = []
    if check_failed:
        blast.append(
            f"could not read current cloud-init config for qemu/{vmid} — "
            "diff and UNDO snapshot unavailable; changes will be applied without baseline"
        )
    else:
        blast.append(
            f"sets {len(validated_changes)} cloud-init field(s) on qemu/{vmid}:\n{diff_text}"
        )
    blast.append(
        "changes are STAGED — they apply on the next reboot + cloud-init regen, not immediately"
    )
    blast.append(
        "wrong sshkeys / network config can lock out access to the VM after the next reboot"
    )

    # Secret fields in changes: note undo caveat.
    has_secret_changes = any(k in _SECRET_KEYS for k in validated_changes)
    if has_secret_changes:
        blast.append(
            "cipassword (and similar secrets) are masked here; "
            "the UNDO snapshot does NOT store the original password value — "
            "revert requires re-supplying it manually"
        )

    reasons: list[str] = ["staged cloud-init changes — apply on next reboot/regen, not live"]
    if check_failed:
        reasons.append(
            "live config read failed — UNDO snapshot unavailable; "
            "absence of HIGH flag is not a safety signal"
        )
    reasons.append(
        "incorrect network/ssh config can lock out access after reboot"
    )

    return Plan(
        action="pve_cloudinit_set",
        target=f"qemu/{vmid}",
        change=f"set cloud-init fields on qemu/{vmid}: {sorted(validated_changes)}",
        current=current_ci,  # already masked via cloudinit_get
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=reasons,
        note=(
            "undo_record available in result when confirm=True; "
            "secret fields cannot be reverted from the snapshot alone"
        ) if not check_failed else (
            "undo_record unavailable — live config read failed"
        ),
    )


def plan_template_convert(
    api,
    vmid: str,
    node: str | None = None,
    kind: str = "qemu",
) -> Plan:
    """Preview converting a QEMU VM into a template.

    Reads guest config (one safe GET) to name the VM being converted.
    RISK_HIGH — one-way op. There is no un-template endpoint on Proxmox.
    Makes NO undo claim.  [SR-6, SR-8]
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    _check_qemu_only(kind)

    current: dict = {}
    found = True
    check_failed = False
    n = node or api.config.node
    try:
        raw = api._get(f"/nodes/{n}/qemu/{vmid}/config") or {}
        current = {k: raw[k] for k in ("name", "template") if k in raw}
    except Exception as e:
        if guest_absent(e, api=api, vmid=vmid, kind=kind):  # 404, or 500 "not on this node" + empty cluster roster
            found = False
        else:
            check_failed = True

    name = current.get("name", vmid)
    already_template = bool(current.get("template"))

    if not found:
        blast = [
            f"convert will FAIL — qemu/{vmid} not found; nothing would be converted"
        ]
        reasons = [
            f"qemu/{vmid} not found — convert will be rejected by PVE",
            "RISK_HIGH maintained: not-found is a failure state, not a safety signal",
        ]
    elif already_template:
        blast = [
            f"qemu/{vmid} (name={name!r}) is ALREADY a template; "
            "convert may be a no-op or fail — PVE behavior unverified"
        ]
        reasons = [
            f"qemu/{vmid} already has template flag set",
            "RISK_HIGH maintained: PVE behavior for re-converting is unverified",
        ]
    elif check_failed:
        blast = [
            f"could NOT verify whether qemu/{vmid} exists; "
            "if it does, this IRREVERSIBLY converts it to a template"
        ]
        reasons = [
            "existence check failed — cannot confirm what (if anything) is converted",
            "RISK_HIGH maintained: uncertainty is not a safety signal",
        ]
    else:
        blast = [
            f"IRREVERSIBLY converts qemu/{vmid} (name={name!r}) to a template",
            "there is no 'un-template' endpoint on Proxmox — this is a one-way operation",
            "the VM will no longer be startable as a normal guest after conversion",
        ]
        reasons = [
            f"converts qemu/{vmid} (name={name!r}) to a template — one-way, no undo",
            "template conversion is irreversible: no un-template API exists on Proxmox",
        ]

    return Plan(
        action="pve_template_convert",
        target=f"qemu/{vmid}",
        change=f"convert qemu/{vmid} to template (IRREVERSIBLE)",
        current=current,
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=reasons,
        note=(
            "NO UNDO: converting a VM to a template is one-way. "
            "There is no un-template endpoint on Proxmox. "
            "Back up the VM before proceeding if you need to restore guest access."
        ),
    )
