"""GUEST CONFIG EDIT module — read + safe-edit + revert guest configuration.

Follows the exact same op+plan layering as provisioning.py and backup.py:
- Op functions (guest_config_get, guest_config_set, guest_config_revert) take `api` first,
  validate inputs, build the PVE URL, and execute. No confirm-gating or ledger calls here —
  those live in server.py (via _plan / _audited), exactly as the other modules.
- Plan functions (plan_config_get, plan_config_set, plan_config_revert) return a Plan
  for the caller to inspect; plan_config_set and plan_config_revert do a live read to
  capture current state for the diff.

PLAN→PROVE weld: the captured config snapshot is stored in Plan.current so that
_record_plan (server layer) writes it to the tamper-evident ledger.

UNDO: guest_config_set captures the pre-change config dict as "prior_config" in its result;
the caller can hand this to guest_config_revert / plan_config_revert to restore.

LXC vs QEMU:
- Both use the same GET /nodes/{node}/{kind}/{vmid}/config endpoint.
- Both use PUT /nodes/{node}/{kind}/{vmid}/config for synchronous writes (returns null).
  POST on the config endpoint is QEMU-only and asynchronous; PUT is the portable choice
  for both kinds. Verify this at live smoke — see SHAPE-RISKS at the bottom.
- PUT is NOT on ApiBackend (it only has _get/_post/_delete); we call api._client.request
  directly, mirroring how _delete does it.

Outcome: PUT config is SYNCHRONOUS on PVE (returns null, not a UPID). The server layer
must wire these with outcome="ok", NOT outcome="submitted".

SHAPE-RISKS (unverifiable without a live PVE call — verify at smoke):
1. Config GET path:  GET /nodes/{node}/{kind}/{vmid}/config  (assumed correct)
2. Config PUT path:  PUT /nodes/{node}/{kind}/{vmid}/config  (assumed; confirm 200/204 vs 405)
3. PUT vs POST:      QEMU also accepts POST /config (async); we use PUT (sync) for both kinds.
                     If QEMU requires POST for certain params, adjust and record "submitted".
4. Key deletion:     Unset a key by sending it in the "delete" param as a comma-separated string.
                     E.g. {"delete": "description,tags"}  This is the assumed Proxmox convention;
                     confirm the param name and separator at live smoke.
5. "digest" param:   PVE config GET returns a "digest" field; including it in PUT enables
                     optimistic-locking. We include it in plan/set flow. Confirm the field name.
6. Computed fields:  "digest", "lock", "lxc.X" (LXC raw params) are read-only; we strip known
                     computed keys from revert. The full list is PVE version-dependent.
7. Key formats:      net* values are complex strings (e.g. "virtio=...,bridge=vmbr0"); we allow
                     them by key-name prefix. The format is validated only by PVE at write time.
                     A value that attaches to a host bridge or passes a host device in is a
                     host-boundary crossing — plan_config_set escalates those to HIGH and names
                     the crossing (see _host_crossings), since the key-name allowlist alone does
                     not see the value.
8. QEMU-only keys:   serial*/parallel*/usb* are admitted only when kind="qemu" (host character/
                     USB devices — treated as a host crossing, above). Escape-prone keys like
                     args/cpu/machine/bios are NOT on the allowlist and are refused for both
                     kinds. This set is curated and may be incomplete.
"""

from __future__ import annotations

import re

from .backends import ProximoError, _check_kind, _check_node, _check_vmid
from .cloudinit import _mask_secrets
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Allowed config keys — conservative allowlist.
# Unknown or dangerous keys are REFUSED rather than passed through.
# ---------------------------------------------------------------------------

# Keys allowed for both LXC and QEMU. Indexed keys (net0, net1…) are matched by prefix below.
_SAFE_KEYS_COMMON = frozenset({
    "cores", "memory", "swap",
    "cpulimit", "cpuunits",
    "onboot", "startup",
    "description", "tags",
    "nameserver", "searchdomain",
    "protection",
})

# LXC-only safe keys (QEMU guests do NOT accept these).
_SAFE_KEYS_LXC = frozenset({
    "hostname",
    "ostype",
    "timezone",
})

# QEMU-only safe keys (LXC guests do NOT accept these).
_SAFE_KEYS_QEMU = frozenset({
    "name",
    "balloon",       # memory balloon target
    "agent",         # QEMU agent config
    "kvm",           # enable/disable KVM
    "numa",
    "ostype",        # overlaps but QEMU ostype values differ
    "scsihw",
    "boot",          # boot order (read back on plan; safe to re-set)
    "sockets",
})

# Key prefixes for indexed multi-valued keys (net0, net1, …). Each must match [prefix]\d+.
# We compile these once. Disk keys (scsi*, ide*, virtio*, sata*) and volume keys (rootfs, mp*)
# are intentionally NOT here — they carry data-loss risk and require separate workflows.
_INDEXED_PREFIXES_COMMON = re.compile(r"^net\d+\Z")
_INDEXED_PREFIXES_QEMU_ONLY = re.compile(r"^(serial|parallel|usb)\d+\Z")

# Computed / read-only keys that MUST be stripped from any write; we silently drop these in
# guest_config_revert rather than failing (PVE will 400 on them).
_COMPUTED_KEYS = frozenset({
    "digest", "lock",
})

# Keys whose change is likely to require a guest reboot to take effect. Shared by
# plan_config_set and plan_config_revert's reboot-hint check.
_REBOOT_KEYS = frozenset({
    "cores", "memory", "swap", "cpulimit", "sockets", "numa", "kvm", "scsihw", "ostype",
})

# LXC raw-config keys that are not settable via the API config endpoint.
_LXC_READONLY_PREFIX = re.compile(r"^lxc\.")

# Host-boundary crossings. The allowlist admits net/usb/serial/parallel keys by NAME, but the
# VALUE decides whether the edit crosses a host boundary: a NIC bound to a host bridge/VLAN
# (lateral network reach), a per-NIC firewall turned off, or a host character/USB device passed
# into the guest (host-resource grant). These are HIGH risk and the plan must name the crossing
# rather than fold it into a routine MEDIUM edit. Value validation is still PVE's at write time;
# this is plan-honesty, not enforcement.
_NET_KEY_RE = re.compile(r"^net\d+\Z")
_HOSTDEV_KEY_RE = re.compile(r"^(serial|parallel|usb)\d+\Z")
_BRIDGE_ATTACH_RE = re.compile(r"(?:^|,)bridge=([^,]+)", re.I)
_NIC_FIREWALL_OFF_RE = re.compile(r"(?:^|,)firewall=0(?:,|\Z)", re.I)
# `host=<id>` (direct), `mapping=<id>` (PVE resource-mapping — a first-class host-device
# passthrough form), or a bare `/dev/...` path all pass a host device into the guest.
_HOST_DEVICE_RE = re.compile(r"(?:(?:^|,)(?:host|mapping)=)|(?:^|[,=])/dev/", re.I)


def _host_crossings(to_set: dict) -> list[str]:
    """Return human-readable blast lines for any value that crosses a host boundary."""
    crossings: list[str] = []
    for k, v in to_set.items():
        val = str(v)
        if _NET_KEY_RE.match(k):
            m = _BRIDGE_ATTACH_RE.search(val)
            if m:
                crossings.append(
                    f"{k} attaches the guest NIC to host bridge {m.group(1)!r} "
                    "(network-boundary crossing — lateral reach onto that bridge/VLAN)"
                )
            if _NIC_FIREWALL_OFF_RE.search(val):
                crossings.append(f"{k} sets firewall=0 — disables the per-NIC firewall")
        elif _HOSTDEV_KEY_RE.match(k) and _HOST_DEVICE_RE.search(val):
            crossings.append(
                f"{k}={val!r} passes a HOST device into the guest (host-resource grant)"
            )
    return crossings


def _allowed_key(key: str, kind: str) -> bool:
    """Return True if key is on the safe allowlist for this guest kind."""
    if key in _SAFE_KEYS_COMMON:
        return True
    if _INDEXED_PREFIXES_COMMON.match(key):
        return True
    if kind == "lxc" and key in _SAFE_KEYS_LXC:
        return True
    if kind == "qemu":
        if key in _SAFE_KEYS_QEMU:
            return True
        if _INDEXED_PREFIXES_QEMU_ONLY.match(key):
            return True
    return False


def _check_changes(changes: dict, kind: str) -> dict:
    """Validate every key in `changes`.  Raises ProximoError for unknown/disallowed keys."""
    bad = [k for k in changes if not _allowed_key(k, kind)]
    if bad:
        raise ProximoError(
            f"refused: unknown or disallowed config key(s): {sorted(bad)!r}. "
            "Only a curated set of safe keys is accepted — use pve_guest_config_get to "
            "inspect the full current config and pve_guest_config_revert to undo a prior set."
        )
    return dict(changes)


def _strip_computed(cfg: dict) -> dict:
    """Return a copy of cfg with computed/read-only keys removed, ready for a write."""
    return {
        k: v for k, v in cfg.items()
        if k not in _COMPUTED_KEYS and not _LXC_READONLY_PREFIX.match(k)
    }


def _settable_prior(prior_config: dict, kind: str) -> tuple[dict, list[str]]:
    """Reduce a captured prior config to the keys a revert is ALLOWED to restore.

    Strips computed/PVE-managed keys (digest, lock, lxc.*) AND anything outside the safe SET
    allowlist — real QEMU configs carry auto-generated keys (meta, smbios1, vmgenid) that SET
    rightly refuses. Returns (settable, skipped). Revert mirrors set's scope: it restores only
    what set could change and never fails on a real-world config. Dropping a non-allowlisted key
    is safe — it is never written, so a malicious prior cannot smuggle e.g. hookscript into a revert.
    """
    writable = _strip_computed(prior_config)
    settable = {k: v for k, v in writable.items() if _allowed_key(k, kind)}
    skipped = sorted(k for k in writable if not _allowed_key(k, kind))
    return settable, skipped


# ---------------------------------------------------------------------------
# PUT helper — ApiBackend only exposes _get / _post / _delete
# ---------------------------------------------------------------------------

def _put_config(api, path: str, data: dict):
    """PUT {path} with {data}.  PVE config PUT returns null (sync).
    Routes through ApiBackend._put so the shared _form() bool->1/0 coercion applies — a native
    Python bool in {data} would otherwise reach PVE as 'True'/'False' and be rejected.
    SHAPE-RISK: confirm 200/204 vs 405 at live smoke; also confirm QEMU sync vs async.
    """
    return api._put(path, data)


def _safe_read_config(api, n: str, kind: str, vmid: str) -> tuple[dict, str | None]:
    """One safe GET of the guest config for a plan preview — never raises.

    Returns (config, read_error); read_error is the raising exception's class name,
    or None if the read succeeded. Shared by plan_config_set and plan_config_revert.
    """
    try:
        return api._get(f"/nodes/{n}/{kind}/{vmid}/config") or {}, None
    except Exception as e:
        return {}, type(e).__name__


# ---------------------------------------------------------------------------
# Op functions — validate, build URL, execute (no confirm-gating / ledger here)
# ---------------------------------------------------------------------------

def guest_config_get(api, vmid: str, kind: str = "lxc", node: str | None = None) -> dict:
    """Read the current config of a guest.  READ-ONLY.

    GET /nodes/{node}/{kind}/{vmid}/config
    Returns the raw config dict from PVE.
    SHAPE-RISK: verify field names match expectations at live smoke.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/{kind}/{vmid}/config") or {}


def guest_config_set(api, vmid: str, changes: dict, kind: str = "lxc",
                     node: str | None = None) -> dict:
    """Apply `changes` to a guest's config.  SYNCHRONOUS MUTATION.

    Two steps:
    1. GET current config (captures the "prior_config" snapshot for UNDO).
    2. Build the PUT body: changed keys + optional "delete" param for keys explicitly
       set to None (meaning: remove that key).  Includes the "digest" from the GET for
       optimistic-locking (confirm field name at live smoke).
    Returns {"prior_config": <snapshot>, "applied": <keys_set>, "deleted": <keys_removed>}.

    The server layer must wire this with outcome="ok" (sync, not a UPID).
    No confirm-gating or ledger calls here — those are in server.py.

    SHAPE-RISK: PUT vs POST; "delete" param name/format; digest field name.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    if not isinstance(changes, dict):
        raise ProximoError("changes must be a dict")
    # Separate: keys with None values mean "delete this key"; non-None keys are set.
    to_set = {k: v for k, v in changes.items() if v is not None}
    to_delete = [k for k, v in changes.items() if v is None]
    # Validate BOTH sets against the allowlist.
    _check_changes(to_set, kind)
    _check_changes({k: "" for k in to_delete}, kind)

    n = node or api.config.node
    path = f"/nodes/{n}/{kind}/{vmid}/config"

    # Capture current state FIRST — this is the UNDO snapshot.
    prior = api._get(path) or {}

    # Build PUT body.
    data: dict = dict(to_set)
    # Include digest for optimistic-locking (PVE rejects if another write raced us).
    if "digest" in prior:
        data["digest"] = prior["digest"]
    if to_delete:
        data["delete"] = ",".join(sorted(to_delete))

    # MUTATION — confirm-gated + audited at the server layer.
    _put_config(api, path, data)

    return {
        "prior_config": prior,
        "applied": sorted(to_set.keys()),
        "deleted": sorted(to_delete),
    }


def guest_config_revert(api, vmid: str, prior_config: dict, kind: str = "lxc",
                        node: str | None = None) -> dict:
    """Re-apply a previously captured config snapshot.  SYNCHRONOUS MUTATION — the UNDO op.

    Steps:
    1. GET current config so we can compute what changed since the snapshot.
    2. Build a PUT body from `prior_config` (stripped of computed/read-only keys).
       Keys present now but absent in `prior_config` are added to the "delete" param.
    Returns {"reverted_to_keys": <list>, "deleted": <list>}.

    SHAPE-RISK: "delete" param; digest; keys missing from prior that should be re-deleted.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    if not isinstance(prior_config, dict):
        raise ProximoError("prior_config must be a dict")

    n = node or api.config.node
    path = f"/nodes/{n}/{kind}/{vmid}/config"

    # Reduce the captured prior to the keys revert is ALLOWED to restore. Computed/PVE-managed
    # keys (meta, smbios1, vmgenid, digest, lock, lxc.*) and anything outside the SET allowlist
    # are SKIPPED — revert mirrors set's scope and never fails on a real config full of
    # auto-generated keys. Dropping a non-allowlisted key is safe: it is never written.
    writable_prior, skipped = _settable_prior(prior_config, kind)

    # Capture current config to detect keys that need to be deleted (present now, absent before).
    current = api._get(path) or {}
    current_writable = _strip_computed(current)

    # Keys that are in current but NOT in prior_config must be deleted.
    to_delete = sorted(
        k for k in current_writable
        if k not in writable_prior and _allowed_key(k, kind)
    )

    # Build PUT body.
    data: dict = dict(writable_prior)
    if "digest" in current:
        data["digest"] = current["digest"]
    if to_delete:
        data["delete"] = ",".join(to_delete)

    # MUTATION — confirm-gated + audited at the server layer.
    _put_config(api, path, data)

    return {
        "reverted_to_keys": sorted(writable_prior.keys()),
        "deleted": to_delete,
        "skipped_unsettable": skipped,
    }


# ---------------------------------------------------------------------------
# Plan functions — return a Plan for caller inspection.
# These do ONE safe read (GET config) to surface the live state.
# ---------------------------------------------------------------------------

def plan_config_get(vmid: str, kind: str = "lxc", node: str | None = None) -> Plan:
    """Preview a config read.  PURE — no API call.  Informational; read-only."""
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    return Plan(
        action="pve_guest_config_get",
        target=f"{kind}/{vmid}",
        change=f"read config of {kind} {vmid}",
        current={},
        blast_radius=["read-only: no changes made"],
        risk=RISK_LOW,
        risk_reasons=["reads the guest's current config; does not change state"],
    )


def plan_config_set(api, vmid: str, changes: dict, kind: str = "lxc",
                    node: str | None = None) -> Plan:
    """Preview a config change.  Reads current config (one safe GET) to show old→new diff.

    The diff is captured in Plan.current so _record_plan writes it to the ledger
    (PLAN→PROVE weld). The blast_radius notes whether a reboot is likely required.

    Raises ProximoError for disallowed keys (validation before any I/O).
    SHAPE-RISK: GET path, field names (see module docstring).
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    if not isinstance(changes, dict):
        raise ProximoError("changes must be a dict")

    to_set = {k: v for k, v in changes.items() if v is not None}
    to_delete = [k for k, v in changes.items() if v is None]
    _check_changes(to_set, kind)
    _check_changes({k: "" for k in to_delete}, kind)

    # One safe read to build the diff — from the SAME node the mutation will target,
    # so the recorded plan/PROVE snapshot matches what gets written (multi-node clusters).
    n = node or api.config.node
    current_cfg, read_error = _safe_read_config(api, n, kind, vmid)
    # PVE's config GET can return cloud-init secrets (e.g. cipassword) inline alongside
    # disk/net config (see cloudinit.py's SR-2). Mask them before they reach the diff or
    # Plan.current — the latter is written verbatim to the PROVE ledger on every call,
    # confirm=False dry-runs included. Changeable/deletable keys are always drawn from the
    # SET allowlist (_check_changes), which never includes a secret key, so masking here
    # cannot hide a real "from" value for any key actually being changed.
    current_cfg = _mask_secrets(current_cfg)

    # Build per-key diff for display in the plan.
    diff: dict = {}
    for k, v in to_set.items():
        diff[k] = {"from": current_cfg.get(k, "<unset>"), "to": v}
    for k in to_delete:
        diff[k] = {"from": current_cfg.get(k, "<unset>"), "to": "<deleted>"}

    # Determine if a reboot is expected for any changed key.
    needs_reboot = bool(
        (set(to_set) | set(to_delete)) & _REBOOT_KEYS
    )

    blast: list[str] = []
    if read_error:
        blast.append(
            f"live-config read failed ({read_error}) — diff is incomplete; "
            "changes will still be applied if confirmed"
        )
    blast.append(f"modifies config of {kind}/{vmid}: "
                 + ", ".join(f"{k}: {d['from']!r} → {d['to']!r}" for k, d in diff.items()))
    if needs_reboot:
        blast.append(
            "NOTE: one or more changed keys (cpu/memory/ostype/scsihw) "
            "require a guest REBOOT to take effect"
        )

    risk = RISK_MEDIUM
    reasons = ["modifies guest config; may require reboot for cpu/memory changes"]
    if needs_reboot:
        reasons.insert(0, "cpu/memory/ostype key change requires guest reboot to take effect")

    # A value that attaches to a host bridge or passes a host device in crosses a host boundary:
    # escalate to HIGH and name the crossing so a reviewer (or an agent) is not told MEDIUM for
    # what is really lateral network reach or a host-resource grant.
    crossings = _host_crossings(to_set)
    if crossings:
        risk = RISK_HIGH
        blast.extend(crossings)
        reasons.insert(0, "host-boundary crossing: guest gains a host device or attaches to a host bridge/VLAN")

    return Plan(
        action="pve_guest_config_set",
        target=f"{kind}/{vmid}",
        change=f"set config on {kind} {vmid}: "
               + ", ".join(f"{k}={v!r}" for k, v in to_set.items())
               + (f"; delete: {to_delete!r}" if to_delete else ""),
        current={"config": current_cfg, "diff": diff},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
    )


def plan_config_revert(api, vmid: str, prior_config: dict, kind: str = "lxc",
                       node: str | None = None) -> Plan:
    """Preview a config revert (UNDO).  Reads current config to show what changes back.

    Validates all keys in prior_config against the allowlist — revert is NOT exempt from
    key validation (a malicious prior_config could smuggle disallowed keys).
    RISK_MEDIUM: reverts a prior mutation; may require reboot.

    SHAPE-RISK: same as plan_config_set (GET path, delete param, digest).
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    if not isinstance(prior_config, dict):
        raise ProximoError("prior_config must be a dict")

    writable_prior, skipped = _settable_prior(prior_config, kind)

    # One safe read to build the diff — from the SAME node the revert will target.
    n = node or api.config.node
    current_cfg, read_error = _safe_read_config(api, n, kind, vmid)
    # See plan_config_set: mask cloud-init secrets (e.g. cipassword) that PVE's config GET
    # may return inline, before the snapshot reaches the diff or Plan.current (written
    # verbatim to the PROVE ledger). writable_prior/to_delete are always drawn from the
    # SET allowlist, which never includes a secret key, so masking here is safe.
    current_cfg = _mask_secrets(current_cfg)

    current_writable = _strip_computed(current_cfg)
    to_delete = sorted(
        k for k in current_writable
        if k not in writable_prior and _allowed_key(k, kind)
    )

    # Diff: what will change back.
    diff: dict = {}
    for k, v in writable_prior.items():
        current_val = current_cfg.get(k, "<unset>")
        if current_val != v:
            diff[k] = {"from": current_val, "to": v}
    for k in to_delete:
        diff[k] = {"from": current_cfg.get(k, "<unset>"), "to": "<deleted>"}

    blast: list[str] = []
    if read_error:
        blast.append(
            f"live-config read failed ({read_error}) — diff is incomplete; "
            "revert will still be applied if confirmed"
        )
    blast.append(
        f"reverts config of {kind}/{vmid} to prior snapshot: "
        + (", ".join(f"{k}: {d['from']!r} → {d['to']!r}" for k, d in diff.items())
           if diff else "no detected differences")
    )
    if to_delete:
        blast.append(f"will DELETE keys absent from prior snapshot: {to_delete!r}")
    if skipped:
        blast.append(
            f"NOTE: {len(skipped)} PVE-managed/non-settable key(s) left as-is (not reverted): "
            f"{skipped!r}"
        )

    needs_reboot = bool((set(writable_prior) | set(to_delete)) & _REBOOT_KEYS)
    if needs_reboot:
        blast.append(
            "NOTE: one or more reverted keys (cpu/memory/ostype/scsihw) "
            "require a guest REBOOT to take effect"
        )

    return Plan(
        action="pve_guest_config_revert",
        target=f"{kind}/{vmid}",
        change=f"revert config of {kind} {vmid} to prior snapshot "
               f"({len(writable_prior)} key(s))",
        current={"current_config": current_cfg, "prior_config": writable_prior, "diff": diff},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "reverts guest config to a previously captured snapshot; "
            "may require a reboot if cpu/memory keys are involved"
        ],
    )
