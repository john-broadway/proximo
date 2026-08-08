"""Blast-radius engine — compute the SPECIFIC downstream impact of a dangerous op.

The pure reasoning (compute_storage_blast and its helpers) takes already-fetched cluster
state and returns named, classified consequences — no api, no I/O, fully unit-testable.
gather_storage_dependents does the safe reads and CATCHES per-guest failures (turning them
into complete=False, never raising) so the plan always builds with an honest INCOMPLETE marker.

Honesty contract (mirrors the access-plane plan_*_delete idiom):
- An incomplete enumeration is rendered LOUDLY and never read as "nothing affected = safe".
- The engine never lowers a plan's risk; on uncertainty it forces max_severity="high".
- "found zero affected" is not a safety signal — orphaned/unreferenced volumes are out of v1 scope.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .cluster_ops import cluster_resources, ha_resources_list
from .config_edit import guest_config_get
from .planning import RISK_HIGH, RISK_MEDIUM, _max_risk
from .tasks_pools import pool_get, pools_list

# Config keys that hold a guest *data* volume. `netN` (NICs) and non-disk keys are excluded.
_DISK_KEY_RE = re.compile(r"^(?:rootfs|(?:efidisk|tpmstate|scsi|sata|ide|virtio|mp|unused)\d+)$")

# Boot-critical even when they are not the "boot disk": losing the UEFI variable store (efidisk0)
# or the TPM state (tpmstate0) prevents boot on UEFI / Secure-Boot / TPM-backed guests. Over-flag
# (treat their loss as won't-boot) rather than under-flag — these slots only exist when relevant.
_BOOT_CRITICAL = frozenset({"efidisk0", "tpmstate0"})


def _is_disk_key(key: str) -> bool:
    return bool(_DISK_KEY_RE.match(key))


def _fmt_bytes(n: int | None) -> str:
    """Human-readable bytes (binary units). 'unknown' for None."""
    if n is None:
        return "unknown"
    val = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(val) < 1024.0 or unit == "TiB":
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} TiB"


def _storage_of_volid(volval: str) -> str | None:
    """Storage name from a disk config value, or None if it names no storage volume.

    A PVE disk value looks like '<storage>:<rest>,opt=val,...' e.g.
    'nas:101/vm-101-disk-0.qcow2,size=32G' or 'local-lvm:vm-101-disk-0,size=8G'.
    Returns the storage segment; None for 'none', raw paths ('/dev/...'), or anything
    without a 'storage:volume' shape.
    """
    head = volval.split(",", 1)[0].strip()
    if ":" not in head:
        return None
    storage, _, rest = head.partition(":")
    storage, rest = storage.strip(), rest.strip()
    if not storage or not rest or "/" in storage:
        return None  # '/' in the storage segment => an absolute path, not 'storage:vol'
    return storage


def _disk_slots(config: dict) -> dict[str, str]:
    """{slot: storage} for every DATA-disk slot in a guest config. cdrom media is excluded
    (removable media is not guest data; deleting its storage breaks a mount, not the guest)."""
    return _disk_slots_split(config)[0]


def _disk_slots_split(config: dict) -> tuple[dict[str, str], list[str]]:
    """({slot: storage} for storage-backed data disks, [slot] for RAW/passthrough disks that name no
    PVE storage). cdrom media + non-disk keys are excluded from both. Used by the migrate class, where
    a raw `/dev/...` disk is the most un-migratable thing and must NOT be silently dropped."""
    backed: dict[str, str] = {}
    raw: list[str] = []
    for key, val in config.items():
        if not isinstance(val, str) or not _is_disk_key(key):
            continue
        if "media=cdrom" in val:
            continue
        storage = _storage_of_volid(val)
        if storage is not None:
            backed[key] = storage
        else:
            raw.append(key)
    return backed, sorted(raw)


def _boot_slot(config: dict, kind: str) -> str | None:
    """The slot holding the boot disk, or None if not determinable.
    LXC always boots from 'rootfs'. QEMU: prefer 'bootdisk', else first DISK in 'boot: order=...'.
    """
    if kind == "lxc":
        return "rootfs" if "rootfs" in config else None
    bootdisk = config.get("bootdisk")
    if isinstance(bootdisk, str) and bootdisk.strip():
        return bootdisk.strip()
    boot = config.get("boot")
    if isinstance(boot, str) and "order=" in boot:
        order = boot.split("order=", 1)[1]
        for tok in re.split(r"[;,]", order):
            tok = tok.strip()
            if _is_disk_key(tok):
                return tok
    return None


def _is_linked_clone_of(config: dict, template_vmid: str) -> bool:
    """True if any disk in `config` backs onto template `template_vmid`'s base volume.
    A linked clone's volid carries the template's base volume name: `base-<tmpl>-disk-N`."""
    needle = f"base-{template_vmid}-disk"
    for key, val in (config or {}).items():
        if _is_disk_key(key) and needle in str(val):
            return True
    return False


@dataclass
class BlastEntry:
    """One guest's loss if the target storage is removed/disabled."""

    resource: str          # "qemu/101" | "lxc/200"
    vmid: str
    name: str
    node: str
    via: list[str]         # data-disk slots on the target storage
    effect: str
    only_copy: bool        # every one of the guest's data disks is on the target storage
    running: bool
    severity: str          # "high" | "medium" | "unknown"

    def as_dict(self) -> dict:
        return {
            "resource": self.resource, "vmid": self.vmid, "name": self.name,
            "node": self.node, "via": self.via, "effect": self.effect,
            "only_copy": self.only_copy, "running": self.running, "severity": self.severity,
        }


def _classify_guest(storage: str, guest: dict, config: dict) -> BlastEntry | None:
    """Classify one guest's loss if `storage` is removed/disabled. None if it holds no data disk there."""
    slots = _disk_slots(config)                              # {slot: storage}
    on_s = sorted(slot for slot, st in slots.items() if st == storage)
    if not on_s:
        return None
    vmid = str(guest.get("vmid", ""))
    kind = guest.get("type", "qemu")                         # "qemu" | "lxc"
    node = str(guest.get("node", ""))
    name = str(guest.get("name", "") or "")
    running = guest.get("status") == "running"

    only_copy = len(on_s) == len(slots)                      # all data disks are on S
    boot = _boot_slot(config, kind)
    boot_on_s = boot is not None and slots.get(boot) == storage
    boot_critical_on_s = sorted(_BOOT_CRITICAL.intersection(on_s))
    # Boot disk indeterminable AND we lose disk(s) on S that are neither the only copy nor a
    # boot-critical slot: one of the lost disks MAY itself be the boot disk, so we cannot promise
    # the guest still boots. Over-flag as won't-boot rather than under-flag (the engine's doctrine)
    # — never falsely claim "boot disk is elsewhere" when we cannot see where it is.
    boot_indeterminate = boot is None and not only_copy and not boot_critical_on_s
    wont_boot = only_copy or boot_on_s or bool(boot_critical_on_s) or boot_indeterminate

    if only_copy:
        effect = f"will NOT boot — all data disks ({', '.join(on_s)}) are on this storage"
    elif boot_on_s:
        effect = f"will NOT boot — boot disk {boot} is on this storage"
    elif boot_critical_on_s:
        effect = (f"will NOT boot — loses UEFI/TPM state ({', '.join(boot_critical_on_s)}) on this "
                  "storage; UEFI / Secure-Boot / TPM-backed guests cannot boot without it")
    elif boot_indeterminate:
        effect = (f"may NOT boot — loses disk(s) ({', '.join(on_s)}) on this storage; the boot disk "
                  "could not be determined and may be among them")
    else:
        effect = f"degraded — loses disk(s) {', '.join(on_s)}; boot disk is elsewhere"
    if running:
        effect += " — RUNNING: losing the disk live may crash or corrupt the guest"

    return BlastEntry(
        resource=f"{kind}/{vmid}", vmid=vmid, name=name, node=node, via=on_s,
        effect=effect, only_copy=only_copy, running=running,
        severity="high" if wont_boot else "medium",
    )


@dataclass
class BlastResult:
    affected: list[BlastEntry]
    summary_lines: list[str]
    complete: bool
    max_severity: str          # "high" | "medium" | "none" — drives risk escalation, never lowers

    def affected_dicts(self) -> list[dict]:
        return [e.as_dict() for e in self.affected]


def _count_unread(guests: list[dict], configs: dict) -> int:
    """Count of guests in `guests` whose config in `configs` is missing/unread (not a dict)."""
    return sum(1 for g in guests if not isinstance(configs.get(str(g.get("vmid", ""))), dict))


def _blast_severity(complete: bool, affected: list[BlastEntry]) -> str:
    """Shared max_severity ladder: incomplete enumeration forces HIGH (never lowered); otherwise the
    highest severity among `affected`, or 'none' if nothing is affected."""
    if not complete:
        return "high"                                       # uncertainty is HIGH, never lowered
    if any(e.severity == "high" for e in affected):
        return "high"
    return "medium" if affected else "none"


def _incomplete_sentinel() -> BlastEntry:
    """The 'enumeration incomplete' sentinel appended to `affected` when complete=False."""
    return BlastEntry(
        resource="?", vmid="", name="", node="", via=[],
        effect="enumeration incomplete — one or more guests could not be read",
        only_copy=False, running=False, severity="unknown",
    )


def compute_storage_blast(storage: str, guests: list[dict], configs: dict,
                          complete: bool) -> BlastResult:
    """PURE. Given enumerated guests + their configs (vmid -> config dict, or None if the read
    failed), compute which guests lose volumes on `storage`. `complete=False` (partial enumeration)
    renders a loud INCOMPLETE marker, forces max_severity='high', and appends an 'unknown' sentinel."""
    affected: list[BlastEntry] = []
    for guest in guests:
        config = configs.get(str(guest.get("vmid", "")))
        if not isinstance(config, dict):
            continue                                        # unread guest — reflected via `complete`
        entry = _classify_guest(storage, guest, config)
        if entry is not None:
            affected.append(entry)
    affected.sort(key=lambda e: (0 if e.severity == "high" else 1, e.vmid))

    total = len(guests)
    failed = _count_unread(guests, configs)
    lines: list[str] = []
    if not complete:
        miss = str(failed) if failed else "some"
        lines.append(
            f"⚠ INCOMPLETE: could not enumerate {miss} of {total} guests cluster-wide — "
            "do NOT treat this list as exhaustive; absence of a guest here is not proof it is safe"
        )
    if affected:
        lines.append(f"ENUMERATED {len(affected)} guest(s) with data volumes on '{storage}':")
        for e in affected:
            label = e.resource + (f" ({e.name})" if e.name else "")
            lines.append(f"  {label} on {e.node}: {e.effect}")
    elif complete:
        lines.append(
            f"no guest config references storage '{storage}' — NOTE: orphaned/unreferenced "
            "volumes are not enumerated in v1; absence here is not proof the storage is unused"
        )

    max_severity = _blast_severity(complete, affected)
    if not complete:
        affected = affected + [_incomplete_sentinel()]
    return BlastResult(affected=affected, summary_lines=lines, complete=complete,
                       max_severity=max_severity)


def gather_storage_dependents(api, storage: str) -> tuple[list[dict], dict, bool]:
    """I/O: enumerate ALL guests cluster-wide + read each config. Returns (guests, configs, complete).
    A total cluster_resources failure -> ([], {}, False); a per-guest config failure ->
    configs[vmid]=None + complete=False. NEVER raises — the plan must always build.

    `storage` is unused here (enumeration is storage-agnostic; the filter happens in
    compute_storage_blast) but kept for a symmetric, future-proof signature.
    """
    try:
        rows = cluster_resources(api) or []
    except Exception:
        return [], {}, False
    guests = [r for r in rows if r.get("type") in ("qemu", "lxc")]
    configs: dict = {}
    complete = True
    for g in guests:
        vmid = str(g.get("vmid", ""))
        try:
            cfg = guest_config_get(api, vmid, str(g.get("type")), g.get("node"))
        except Exception:
            configs[vmid] = None
            complete = False
            continue
        # An enumerated guest with an empty/null config means we could NOT see its disks
        # (e.g. HTTP 200 with {"data": null}); a real guest config is never empty. Treat it as a
        # FAILED read (partial enumeration) — never as "no disks → not affected = safe".
        if not cfg:
            configs[vmid] = None
            complete = False
        else:
            configs[vmid] = cfg
    return guests, configs, complete


def storage_blast(api, storage: str) -> BlastResult:
    """Convenience: gather live cluster state then compute the pure blast result."""
    guests, configs, complete = gather_storage_dependents(api, storage)
    return compute_storage_blast(storage, guests, configs, complete)


def compute_storage_nodes_blast(storage: str, new_nodes: set[str], guests: list[dict],
                                configs: dict, complete: bool) -> BlastResult:
    """PURE. Restricting storage `storage` to be available only on `new_nodes` STRANDS any guest that
    has a data volume on `storage` AND sits on a node NOT in `new_nodes` (its node loses the storage).

    Invariant: a guest on a node in `new_nodes` keeps access — so the only error direction is OVER-flag
    (a guest already stranded by a prior misconfig), NEVER under-flag. Reuses `_classify_guest` (same
    won't-boot/degraded/running classification as the delete class), adding only the node filter.
    `complete=False` (partial enumeration) renders a loud INCOMPLETE marker, forces max_severity='high',
    and appends an 'unknown' sentinel — uncertainty is never read as "nothing stranded = safe".

    Scope: this is a PLAN-TIME residency check — it flags guests *currently* on an excluded node. It
    does NOT model future placement (e.g. an HA guest that later fails over onto a now-excluded node);
    that is a future-relocation effect, not immediate stranding. NOTE: an empty `new_nodes` here means
    "available on NO node → strand everyone" (the literal math); mapping the PVE string ``nodes=""`` to
    its real "clear restriction → all nodes" meaning is the caller's job (see `plan_storage_update`).
    """
    affected: list[BlastEntry] = []
    for guest in guests:
        config = configs.get(str(guest.get("vmid", "")))
        if not isinstance(config, dict):
            continue                                        # unread guest — reflected via `complete`
        entry = _classify_guest(storage, guest, config)
        if entry is not None and entry.node not in new_nodes:   # disk on S AND node excluded → stranded
            affected.append(entry)
    affected.sort(key=lambda e: (0 if e.severity == "high" else 1, e.vmid))

    nodes_label = ", ".join(sorted(new_nodes)) if new_nodes else "(none)"
    lines: list[str] = []
    if not complete:
        total = len(guests)
        failed = _count_unread(guests, configs)
        miss = str(failed) if failed else "some"
        lines.append(
            f"⚠ INCOMPLETE: could not enumerate {miss} of {total} guests cluster-wide — "
            "do NOT treat this list as exhaustive; absence of a guest here is not proof it is safe"
        )
    if affected:
        lines.append(
            f"restricting storage '{storage}' to nodes [{nodes_label}] STRANDS "
            f"{len(affected)} guest(s) on excluded nodes from their disk(s):"
        )
        for e in affected:
            label = e.resource + (f" ({e.name})" if e.name else "")
            lines.append(f"  {label} on {e.node}: {e.effect}")
    elif complete:
        lines.append(
            f"restricting storage '{storage}' to nodes [{nodes_label}] strands no guests — no "
            "enumerated guest with a disk on this storage sits on an excluded node (absence here is "
            "not proof of safety for orphaned/unreferenced volumes)"
        )

    max_severity = _blast_severity(complete, affected)
    if not complete:
        affected = affected + [_incomplete_sentinel()]
    return BlastResult(affected=affected, summary_lines=lines, complete=complete,
                       max_severity=max_severity)


# ===========================================================================
# Disk-move class — moving a disk ONTO a target storage consumes that storage's
# capacity, putting every co-tenant (a guest with a disk on the target) at risk if
# the target fills or the move won't fit. Unlike storage-delete (the storage GOES
# AWAY → name everyone), co-tenants are only AT RISK when capacity is threatened, so
# we name them only then (cry-wolf control). Soundness: the fit check uses the
# PROVISIONED disk size (worst case) → "won't fit / fills T" can only over-flag,
# never under-flag; capacity we cannot read is never read as "safe".
# ===========================================================================

_DISK_MOVE_TIGHT_FRACTION = 0.10   # post-move free < this fraction of total → "tight"
# Absolute safe-free floor: leaving less than this free is "tight" REGARDLESS of total — so a move
# stays sound even when total capacity is unreadable (no under-flag of tightness on a partial read).
_DISK_MOVE_MIN_FREE_BYTES = 10 * 1024 ** 3   # 10 GiB

_SEV_ORDER = {"high": 0, "medium": 1, "unknown": 2, "none": 3}


def _cotenants_on(target_storage: str, moved_resource: str, guests: list[dict],
                  configs: dict) -> list[BlastEntry]:
    """Guests (minus the one being moved) that hold a data disk on `target_storage`.
    Severity/effect are set by the caller per the capacity verdict; here we only enumerate."""
    out: list[BlastEntry] = []
    for guest in guests:
        config = configs.get(str(guest.get("vmid", "")))
        if not isinstance(config, dict):
            continue                                        # unread guest — reflected via `complete`
        vmid = str(guest.get("vmid", ""))
        kind = guest.get("type", "qemu")
        if f"{kind}/{vmid}" == moved_resource:
            continue                                        # the guest being moved is not its own co-tenant
        slots = _disk_slots(config)
        on_t = sorted(slot for slot, st in slots.items() if st == target_storage)
        if not on_t:
            continue
        out.append(BlastEntry(
            resource=f"{kind}/{vmid}", vmid=vmid, name=str(guest.get("name", "") or ""),
            node=str(guest.get("node", "")), via=on_t, effect="",
            only_copy=len(on_t) == len(slots), running=guest.get("status") == "running",
            severity="medium",
        ))
    return out


def _disk_move_capacity_verdict(
    disk_size_bytes: int | None, target_avail: int | None, target_total: int | None,
) -> tuple[str, str, str]:
    """(cap, cap_sev, co_sev) verdict ladder for fitting `disk_size_bytes` onto a target with
    `target_avail`/`target_total` free/total bytes:
    - size or avail unknown → cannot assess fit → 'unknown'/'high' — NEVER 'safe'.
    - size >= avail → 'wont_fit'/'high' (move fails / fills the storage).
    - post-move free < the absolute floor OR < 10% of total → 'tight'/'medium'.
    - total unreadable (won't-fit ruled out but fullness can't be assessed) → 'fits_total_unknown'.
    - fits comfortably → 'fits'/'none'.
    """
    if disk_size_bytes is None or target_avail is None:
        return "unknown", "high", "unknown"
    if disk_size_bytes >= target_avail:
        return "wont_fit", "high", "high"
    post = target_avail - disk_size_bytes
    tight_by_abs = post < _DISK_MOVE_MIN_FREE_BYTES                          # sound w/o total
    tight_by_pct = bool(target_total) and post < _DISK_MOVE_TIGHT_FRACTION * target_total
    if tight_by_abs or tight_by_pct:
        return "tight", "medium", "medium"
    if not target_total:
        # Won't-fit is ruled out, but without total we cannot assess post-move fullness —
        # disclose the unknown rather than reassure (capacity handled symmetrically: a missing
        # `avail` forced HIGH above, a missing `total` must not produce a clean all-clear).
        return "fits_total_unknown", "none", "none"
    return "fits", "none", "none"


def _disk_move_mark_cotenants(
    cotenants: list[BlastEntry], cap: str, co_sev: str, target_storage: str,
) -> list[BlastEntry]:
    """Set severity/effect on each co-tenant when capacity is at risk (won't-fit/tight/unknown);
    cry-wolf control — a comfortable fit leaves co-tenants unflagged (returns [])."""
    if cap not in ("wont_fit", "tight", "unknown"):
        return []
    for e in cotenants:
        e.severity = co_sev
        e.effect = (f"shares target storage '{target_storage}' (disk slot(s) {', '.join(e.via)})"
                    " — at risk if the move "
                    + ("exhausts it" if cap != "unknown" else "fills it (capacity unknown)"))
        if e.running:
            e.effect += " — RUNNING: allocation/write failure can crash or corrupt it"
    return list(cotenants)


def _disk_move_verdict_lines(
    cap: str, target_storage: str, disk_size_bytes: int | None, target_avail: int | None,
    target_total: int | None, n_co: int, complete: bool,
) -> list[str]:
    """The capacity-verdict summary line(s) — phrasing + co-tenant-count disclosure per verdict."""
    if cap == "unknown":
        lines = [
            f"could not assess target '{target_storage}' capacity (disk size or free space "
            "unreadable) — cannot confirm the move fits; uncertainty is NOT a safety signal"
        ]
        if n_co:
            lines.append(f"  {n_co} guest(s) share target '{target_storage}' — impact cannot be ruled out")
        return lines
    if cap == "wont_fit":
        lines = [
            f"WILL NOT FIT: disk ({_fmt_bytes(disk_size_bytes)}) ≥ free space on target "
            f"'{target_storage}' ({_fmt_bytes(target_avail)}) — the move fails or fills the storage"
        ]
        if n_co:
            lines.append(f"{n_co} co-tenant guest(s) share target '{target_storage}':")
        return lines
    if cap == "tight":
        post = target_avail - disk_size_bytes        # type: ignore[operator]
        if target_total:
            why = f"< {int(_DISK_MOVE_TIGHT_FRACTION * 100)}% of {_fmt_bytes(target_total)} total"
        else:
            why = "below the safe-free floor; total capacity unreadable"
        lines = [
            f"TIGHT: the move leaves only {_fmt_bytes(post)} free on target '{target_storage}' "
            f"({why}) — co-tenants risk allocation failure"
        ]
        if n_co:
            lines.append(f"{n_co} co-tenant guest(s) share target '{target_storage}':")
        return lines
    if cap == "fits_total_unknown":
        post = target_avail - disk_size_bytes        # type: ignore[operator]
        msg = (f"fits available space: target '{target_storage}' has {_fmt_bytes(target_avail)} free; "
               f"disk is {_fmt_bytes(disk_size_bytes)}; leaves {_fmt_bytes(post)} — but total capacity "
               "is unreadable, so whether this leaves the target near-full cannot be assessed")
        if n_co:
            msg += (f". {n_co} guest(s) share this target — if it is near capacity they risk "
                    "allocation pressure")
        return [msg]
    # cap == "fits"
    post = target_avail - disk_size_bytes        # type: ignore[operator]
    msg = (f"fits: target '{target_storage}' has {_fmt_bytes(target_avail)} free; disk is "
           f"{_fmt_bytes(disk_size_bytes)}; leaves {_fmt_bytes(post)} free")
    if n_co and complete:
        msg += f". {n_co} other guest(s) share this target, with headroom remaining"
    elif n_co:
        # complete=False → the count is a FLOOR, not exhaustive — never reassure on it.
        msg += (f". at least {n_co} co-tenant(s) share this target — co-tenant list INCOMPLETE, "
                "not proof of safety")
    return [msg]


def compute_disk_move_blast(target_storage: str, disk_size_bytes: int | None,
                            target_avail: int | None, target_total: int | None,
                            moved_resource: str, guests: list[dict], configs: dict,
                            complete: bool) -> BlastResult:
    """PURE. Moving a disk of `disk_size_bytes` (PROVISIONED — worst case) onto `target_storage`
    (which has `target_avail`/`target_total` free/total bytes) consumes capacity shared by every
    co-tenant guest with a disk on the target.

    Verdict ladder (the engine ESCALATES risk via max_severity; it never lowers the base plan risk):
    - size or avail unknown → cannot assess fit → max_severity='high', loud line, NEVER 'safe'.
    - size >= avail → WON'T FIT (move fails / fills the storage) → 'high'; co-tenants named.
    - post-move free < 10% of total → TIGHT → 'medium'; co-tenants named.
    - fits comfortably → 'none'; co-tenants NOT flagged (cry-wolf control), headroom stated plainly.
    `complete=False` (guest enumeration incomplete) → loud ⚠ INCOMPLETE, force 'high', append sentinel.
    """
    cotenants = _cotenants_on(target_storage, moved_resource, guests, configs)
    n_co = len(cotenants)
    cap, cap_sev, co_sev = _disk_move_capacity_verdict(disk_size_bytes, target_avail, target_total)
    affected = _disk_move_mark_cotenants(cotenants, cap, co_sev, target_storage)
    affected.sort(key=lambda e: (_SEV_ORDER.get(e.severity, 9), e.vmid))

    lines: list[str] = []
    if not complete:
        total = len(guests)
        failed = _count_unread(guests, configs)
        miss = str(failed) if failed else "some"
        lines.append(
            f"⚠ INCOMPLETE: could not enumerate {miss} of {total} guests cluster-wide — "
            "do NOT treat this co-tenant list as exhaustive; absence here is not proof of safety"
        )
    lines.extend(_disk_move_verdict_lines(
        cap, target_storage, disk_size_bytes, target_avail, target_total, n_co, complete,
    ))
    for e in affected:
        if e.severity == "unknown" and e.resource == "?":
            continue
        label = e.resource + (f" ({e.name})" if e.name else "")
        lines.append(f"  {label} on {e.node}: {e.effect}")

    max_severity = "high" if not complete else cap_sev   # ladder differs (folds in cap_sev); untouched
    if not complete:
        affected = affected + [_incomplete_sentinel()]
    return BlastResult(affected=affected, summary_lines=lines, complete=complete,
                       max_severity=max_severity)


def gather_disk_move_dependents(api, target_storage: str, vmid: str, disk: str, kind: str,
                                node: str | None) -> tuple[int | None, int | None, int | None,
                                                           list[dict], dict, bool]:
    """I/O, fail-closed (never raises). Returns
    (disk_size_bytes, target_avail, target_total, guests, configs, complete):
    - the PROVISIONED size of `disk` on the moved guest (None if unreadable/unparseable),
    - target storage free/total bytes (None on read failure),
    - the cluster guest list + configs (reused storage gather) and its completeness flag.
    """
    from .disk_ops import _parse_size_bytes
    from .storage import storage_status

    disk_size_bytes: int | None = None
    try:
        cfg = guest_config_get(api, vmid, kind, node)
        if isinstance(cfg, dict):
            entry = cfg.get(disk)
            if isinstance(entry, str):
                for part in entry.split(","):
                    part = part.strip()
                    if part.startswith("size="):
                        disk_size_bytes = _parse_size_bytes(part[5:])
                        break
    except Exception:
        disk_size_bytes = None

    target_avail: int | None = None
    target_total: int | None = None
    try:
        st = storage_status(api, target_storage, node)
        if isinstance(st, dict):
            av, tot = st.get("avail"), st.get("total")
            target_avail = int(av) if isinstance(av, (int, float)) else None
            target_total = int(tot) if isinstance(tot, (int, float)) else None
    except Exception:
        target_avail = target_total = None

    guests, configs, complete = gather_storage_dependents(api, target_storage)
    return disk_size_bytes, target_avail, target_total, guests, configs, complete


def disk_move_blast(api, vmid: str, disk: str, target_storage: str, kind: str,
                    node: str | None) -> BlastResult:
    """Convenience: gather live state then compute the pure disk-move blast result."""
    size, avail, total, guests, configs, complete = gather_disk_move_dependents(
        api, target_storage, vmid, disk, kind, node)
    return compute_disk_move_blast(target_storage, size, avail, total,
                                   f"{kind}/{vmid}", guests, configs, complete)


# ===========================================================================
# Storage content-delete class — deleting a volume that is an ACTIVE guest disk
# destroys that disk's data. Scans guest configs for the EXACT volid; names the
# owning guest (won't-boot if it's the boot disk / only copy / EFI-TPM). Uncertainty
# (incomplete enumeration) forces HIGH — never read as "not in use".
# ===========================================================================

def _guest_disks_matching_volid(config: dict, volid: str) -> list[str]:
    """Disk slots whose value references EXACTLY `volid` (head before the comma). Exact match so
    deleting 'vm-101-disk-0' does not match 'vm-101-disk-00'."""
    out: list[str] = []
    for key, val in config.items():
        if not isinstance(val, str) or not _is_disk_key(key):
            continue
        if "media=cdrom" in val:           # a mounted ISO is not the guest's data disk
            continue
        if val.split(",", 1)[0].strip() == volid:
            out.append(key)
    return sorted(out)


@dataclass
class ContentDeleteBlastResult:
    summary_lines: list[str]
    affected: list[dict]
    complete: bool
    max_severity: str          # "high" (in use / uncertain) | "none" — escalates, never lowers


def compute_content_delete_blast(volid: str, guests: list[dict], configs: dict,
                                 complete: bool) -> ContentDeleteBlastResult:
    """PURE. Names guests whose ACTIVE disk is `volid` — deleting it destroys their data.
    `complete=False` (some guest configs unread) → forced HIGH, never read as 'not in use'."""
    affected: list[dict] = []
    for g in guests:
        cfg = configs.get(str(g.get("vmid", "")))
        if not isinstance(cfg, dict):
            continue
        slots = _guest_disks_matching_volid(cfg, volid)
        if not slots:
            continue
        kind = g.get("type", "qemu")
        vmid = str(g.get("vmid", ""))
        boot = _boot_slot(cfg, kind)
        all_data = _disk_slots(cfg)
        wont_boot = (boot in slots) or bool(_BOOT_CRITICAL.intersection(slots)) \
            or (set(slots) == set(all_data))
        effect = (f"volume is an ACTIVE disk ({', '.join(slots)}) of this guest — deleting it DESTROYS "
                  "that disk's data")
        if wont_boot:
            effect += " — the guest will NOT boot"
        affected.append({"resource": f"{kind}/{vmid}", "vmid": vmid, "name": str(g.get("name", "") or ""),
                         "node": str(g.get("node", "")), "via": slots, "effect": effect, "severity": "high"})
    affected.sort(key=lambda a: a["vmid"])

    lines: list[str] = []
    if not complete:
        lines.append(
            f"⚠ INCOMPLETE: could not enumerate all guests — cannot confirm whether {volid!r} is an "
            "in-use disk (absence here is NOT proof it is unused)"
        )
    if affected:
        lines.append(
            f"{volid!r} is an ACTIVE disk of {len(affected)} guest(s) — deleting it destroys their data:"
        )
        for a in affected:
            label = a["resource"] + (f" ({a['name']})" if a["name"] else "")
            lines.append(f"  {label} on {a['node']}: {a['effect']}")
    elif complete:
        lines.append(
            f"no guest config references {volid!r} as a disk — not an in-use guest disk (an "
            "ISO/template/backup/orphan; absence here is not proof for any guest not enumerated)"
        )
    return ContentDeleteBlastResult(lines, affected, complete=complete,
                                    max_severity="high" if (affected or not complete) else "none")


def content_delete_blast(api, volid: str) -> ContentDeleteBlastResult:
    """Convenience: enumerate cluster guests then check whether `volid` is an in-use disk."""
    guests, configs, complete = gather_storage_dependents(api, "")
    return compute_content_delete_blast(volid, guests, configs, complete)


# ===========================================================================
# Access / ACL class — shadow/widen reasoning for an ACL grant/revoke.
# ===========================================================================

@dataclass
class AclBlastResult:
    summary_lines: list[str]
    risk: str
    risk_reasons: list[str]
    current: dict
    affected: list[dict] = field(default_factory=list)
    complete: bool = True


def _acl_split_direct_inherited(
    path: str, target: str, entries: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Partition the target's own ACL entries into (direct-at-path, inherited-from-an-ancestor).
    An entry counts as inherited only if it sits above `path` (trailing-slash boundary) AND
    propagates."""
    direct: list[dict] = []
    inherited: list[dict] = []
    for entry in entries:
        if entry.get("ugid", "") != target:
            continue
        entry_path = entry.get("path", "")
        if entry_path == path:
            direct.append(entry)
        elif path.startswith(entry_path.rstrip("/") + "/") and entry.get("propagate", True):
            inherited.append(entry)
    return direct, inherited


def _acl_group_inherited_roles(
    path: str,
    entries: list[dict],
    target_groups: list[str] | None,
    extra_inherited: dict[str, str] | None,
) -> dict[str, str]:
    """roleid -> via-label for roles the target inherits through ITS OWN group memberships
    (an ancestor, propagated group grant) — folded in with (privsep=0 token only) the owning
    user's direct propagated grants, passed in by the caller as `extra_inherited`.
    Empty if `target_groups` is None (group-membership resolution unavailable)."""
    group_inherited: dict[str, str] = {}
    if target_groups is not None:
        gset = set(target_groups)
        for entry in entries:
            if entry.get("type") != "group" or entry.get("ugid", "") not in gset:
                continue
            entry_path = entry.get("path", "")
            if path.startswith(entry_path.rstrip("/") + "/") and entry.get("propagate", True):
                group_inherited[entry.get("roleid", "")] = entry.get("ugid", "")
    if extra_inherited:
        group_inherited.update(extra_inherited)
    return group_inherited


def _acl_effective_change(
    new_roles: set[str], delete: bool, current_direct_roles: set[str], inherited_roles: set[str],
) -> tuple[bool, set[str], set[str]]:
    """(has_direct, shadowed_inherited, widened) for this grant/revoke, given the roles the target
    holds directly vs. by inheritance, before and after the change."""
    has_direct = bool(current_direct_roles)
    effective_before = current_direct_roles if has_direct else inherited_roles
    if not delete:
        effective_after = new_roles
    else:
        remaining_direct = current_direct_roles - new_roles
        effective_after = remaining_direct if remaining_direct else inherited_roles
    shadowed_inherited = inherited_roles - new_roles if not has_direct and not delete else set()
    widened = effective_after - effective_before
    return has_direct, shadowed_inherited, widened


def _acl_grant_lines(
    path: str, roles: str, target: str, shadowed_inherited: set[str], widened: set[str],
) -> tuple[list[str], list[str], str]:
    """blast lines + risk reasons + risk for a GRANT (delete=False)."""
    blast: list[str] = []
    reasons: list[str] = []
    risk = RISK_MEDIUM
    if shadowed_inherited:
        sr = ", ".join(sorted(shadowed_inherited))
        blast.append(
            f"SHADOW WARNING: granting {roles!r} at {path!r} will REPLACE {target!r}'s "
            f"INHERITED grants — the following inherited roles will NO LONGER apply at "
            f"{path!r}: {sr}. (The specific-path entry takes precedence over ancestor "
            "propagated grants.)"
        )
        reasons.append(
            "granting a specific-path ACL replaces ancestor inherited (propagated) grants — "
            f"inherited roles {{{sr}}} are shadowed (lost) at {path!r}"
        )
        risk = _max_risk(risk, RISK_HIGH)
    if widened:
        wr = ", ".join(sorted(widened))
        blast.append(f"NEW privileges at {path!r}: {target!r} gains {wr}")
        reasons.append(f"target gains new roles: {wr}")
    if not shadowed_inherited and not widened:
        blast.append(
            f"grants {roles!r} to {target!r} at {path!r} — "
            "no inherited grants detected to shadow; no new privileges detected"
        )
        reasons.append("no inherited grants to shadow; grant is additive at this path")
    return blast, reasons, risk


def _acl_revoke_lines(
    path: str, roles: str, target: str, widened: set[str],
) -> tuple[list[str], list[str], str]:
    """blast lines + risk reasons + risk for a REVOKE (delete=True)."""
    blast: list[str] = []
    reasons: list[str] = []
    risk = RISK_MEDIUM
    if widened:
        wr = ", ".join(sorted(widened))
        blast.append(
            f"WIDEN WARNING: revoking the specific entry at {path!r} for {target!r} "
            f"RESTORES inherited grants — {target!r} will gain back: {wr}"
        )
        reasons.append(
            "revoking a specific-path ACL restores inherited grants — "
            f"the following roles become effective again at {path!r}: {wr}"
        )
        risk = _max_risk(risk, RISK_HIGH)
    else:
        blast.append(
            f"revokes {roles!r} from {target!r} at {path!r} — no inherited grants detected "
            "that would widen access after revoke"
        )
        reasons.append("no inherited grants detected; revoke is straightforward")
    return blast, reasons, risk


def _acl_scope_escalation(new_roles: set[str], path: str) -> tuple[list[str], list[str], bool]:
    """Universal risk escalations independent of grant/revoke: Administrator is the widest possible
    role; '/' and '/storage' are cluster/storage-wide scopes. Returns (lines, reasons, escalate_hi)."""
    lines: list[str] = []
    reasons: list[str] = []
    escalate = False
    if "Administrator" in new_roles:
        lines.append("Administrator role grants ALL Proxmox privileges — this is the widest possible role")
        reasons.append("Administrator = super-role with full cluster privileges")
        escalate = True
    if path in ("/", "/storage"):
        lines.append(f"ACL at {path!r} affects ALL resources at that scope on the cluster")
        reasons.append(f"path {path!r} is a high-blast scope (root or storage-wide)")
        escalate = True
    return lines, reasons, escalate


def _acl_current_entry(current_direct_entries: list[dict]) -> dict:
    """The current-state summary dict: the target's first direct entry at this exact path, or {}."""
    if not current_direct_entries:
        return {}
    first = current_direct_entries[0]
    return {k: first[k] for k in ("path", "roleid", "ugid", "propagate") if k in first}


def _acl_affected_direct(
    target: str,
    kind: str,
    path: str,
    shadowed_inherited: set[str],
    group_inherited: dict[str, str],
    widened: set[str],
    sev: str,
) -> list[dict]:
    """affected entries for the TARGET's own gains/losses (never the who-else context rows)."""
    affected: list[dict] = []
    if shadowed_inherited:
        for role in sorted(shadowed_inherited):
            grp = group_inherited.get(role)
            via = f"inherited via group {grp}" if grp else "inherited (shadowed by the new direct entry)"
            affected.append({
                "principal": target, "kind": kind, "via": via,
                "change": "loses", "roles": [role], "at": path, "severity": "high",
            })
    if widened:
        affected.append({
            "principal": target, "kind": kind, "via": "direct",
            "change": "gains", "roles": sorted(widened), "at": path, "severity": sev,
        })
    return affected


def _acl_who_else_context(
    path: str, group_members: dict[str, list | None] | None,
) -> tuple[list[dict], list[str], bool]:
    """#2: who ELSE can reach this path (members of in-scope group ACL entries). CONTEXT only —
    their access is UNCHANGED by editing the target's entry. Returns (affected, lines, incomplete)."""
    affected: list[dict] = []
    lines: list[str] = []
    incomplete = False
    if not group_members:
        return affected, lines, incomplete
    named: list[str] = []
    for grp, members in group_members.items():
        if members is None:
            incomplete = True
            lines.append(
                f"could not enumerate members of group {grp!r} — "
                "who-else-can-reach is INCOMPLETE (not a safety signal)"
            )
            continue
        for m in members:
            affected.append({
                "principal": m, "kind": "group-member", "via": f"group {grp}",
                "change": "unchanged", "roles": [], "at": path, "severity": "medium",
            })
            named.append(m)
    if named:
        lines.append(
            f"also has access at this path — UNCHANGED by this change: {', '.join(named)} "
            "(via group membership; their access is computed independently of the target's entry)"
        )
    return affected, lines, incomplete


def compute_acl_blast(
    path: str,
    roles: str,
    target: str,
    kind: str,
    delete: bool,
    acl_entries: list[dict] | None,   # None => the ACL read FAILED (fail-closed branch)
    acl_error: str | None = None,
    target_groups: list[str] | None = None,   # the target's own group memberships; None => unresolved
    group_members: dict[str, list | None] | None = None,   # #2 in-scope group -> members (None=read failed)
    extra_inherited: dict[str, str] | None = None,   # privsep=0 token: owner's direct grants, role->via label
) -> AclBlastResult:
    """PURE shadow/widen analysis for an ACL grant/revoke. No API.

    `acl_entries` is the already-fetched current ACL; None means the read FAILED → a RISK_HIGH
    disclosure ("absence of a warning is not a safety signal"), never a clean "safe".

    THE PROXMOX GOTCHA: a specific-path ACL entry REPLACES (shadows) an ancestor's propagated
    grant rather than unioning with it. So granting at a deeper path can NARROW access (shadow),
    and revoking a specific entry can WIDEN it (the shadowed inherited grant returns.)
    """
    new_roles = {r.strip() for r in roles.split(",")}

    # Fail-closed keys on the DATA: acl_entries is None means the read failed, regardless of whether
    # a label was passed. Synthesize a generic message if acl_error is absent — never fall through
    # to a clean "additive / safe" plan on a failed read.
    check_error = (acl_error or "ACL read failed (no detail)") if acl_entries is None else None
    entries = acl_entries or []
    groups_resolved = target_groups is not None

    blast: list[str] = []
    reasons: list[str] = []
    risk = RISK_MEDIUM
    complete = True
    current_direct_entries: list[dict] = []
    shadowed_inherited: set[str] = set()
    widened: set[str] = set()
    group_inherited: dict[str, str] = {}

    if check_error is not None:
        blast.append(
            f"could NOT read current ACL ({check_error}) — cannot determine what privileges "
            "would be shadowed or widened; absence of a shadow/widen warning is NOT a safety signal"
        )
        reasons.append(
            "ACL read failed — shadow/widen analysis unavailable; absence of a warning is not a safety signal"
        )
        risk = _max_risk(risk, RISK_HIGH)
        complete = False
    else:
        current_direct_entries, inherited_entries = _acl_split_direct_inherited(path, target, entries)
        inherited_roles = {e.get("roleid", "") for e in inherited_entries}

        # #1: fold in roles the TARGET inherits via THEIR OWN group memberships (ancestor, propagated),
        # plus (privsep=0 token) the owning user's direct propagated grants.
        group_inherited = _acl_group_inherited_roles(path, entries, target_groups, extra_inherited)
        inherited_roles |= set(group_inherited)

        current_direct_roles = {e.get("roleid", "") for e in current_direct_entries}
        _has_direct, shadowed_inherited, widened = _acl_effective_change(
            new_roles, delete, current_direct_roles, inherited_roles,
        )

        group_entries_present = any(
            e.get("type") == "group" and (
                e.get("path") == path or path.startswith(e.get("path", "").rstrip("/") + "/")
            )
            for e in entries
        )
        if group_entries_present and not groups_resolved:
            complete = False
            blast.append(
                "UNCERTAINTY: group-type ACL entries exist at or above this path and group "
                "membership could not be resolved — shadow/widen analysis may be INCOMPLETE for "
                "users who are group members"
            )
            reasons.append(
                "group-based ACL grants exist and were not resolved; "
                "shadow analysis may miss group-inherited privileges"
            )
            # Honesty contract: uncertainty that could HIDE a widen/shadow forces risk UP (the
            # disclosure line alone under-reports via the structured risk field). Over-flag is safe.
            risk = _max_risk(risk, RISK_HIGH)

        change_lines, change_reasons, change_risk = (
            _acl_revoke_lines(path, roles, target, widened) if delete
            else _acl_grant_lines(path, roles, target, shadowed_inherited, widened)
        )
        blast.extend(change_lines)
        reasons.extend(change_reasons)
        risk = _max_risk(risk, change_risk)

    scope_lines, scope_reasons, scope_escalate = _acl_scope_escalation(new_roles, path)
    blast.extend(scope_lines)
    reasons.extend(scope_reasons)
    if scope_escalate:
        risk = _max_risk(risk, RISK_HIGH)

    current = _acl_current_entry(current_direct_entries)

    affected: list[dict] = []
    if check_error is None:
        sev = "high" if risk == RISK_HIGH else "medium"
        affected = _acl_affected_direct(
            target, kind, path, shadowed_inherited, group_inherited, widened, sev,
        )
        who_affected, who_lines, who_incomplete = _acl_who_else_context(path, group_members)
        affected.extend(who_affected)
        blast.extend(who_lines)
        if who_incomplete:
            complete = False

    return AclBlastResult(summary_lines=blast, risk=risk, risk_reasons=reasons,
                          current=current, affected=affected, complete=complete)


# ===========================================================================
# Firewall / network reach class.
#
# PER-RULE REACH, never "the cluster is exposed" as fact. A firewall rule's true
# effect depends on the whole ordered ruleset + default policy + enabled state; a
# single-rule classifier computes only what THIS rule permits/blocks IF it is the
# deciding match in an enforced, default-DROP firewall. Every line is phrased as a
# property of the RULE. Missing field => MAXIMAL, never benign (empty dport => ALL
# ports; empty source => anywhere; ipset/alias => unknown-conservative). enable=0 =>
# "staged, not active". Risk is only ever raised, never lowered.
# ===========================================================================

# Well-known admin/management ports -> service label. Used for sensitivity, NOT to
# narrow reach — an unrecognized port form is never downgraded to benign.
_SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH", 8006: "PVE API", 3389: "RDP", 23: "telnet", 3306: "MySQL",
    5432: "Postgres", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    2375: "Docker API", 2376: "Docker API (TLS)", 111: "rpcbind", 445: "SMB",
    135: "MSRPC", 139: "NetBIOS", 5985: "WinRM", 5986: "WinRM (TLS)",
    389: "LDAP", 636: "LDAPS",
}

# VNC display ports (5900-5999) are a remote-desktop admin surface — sensitive as a RANGE, not
# enumerable into the dict. Service NAMES PVE may carry as a dport (e.g. "ssh", "vnc") map to the
# same sensitivity; an UNRECOGNIZED name is NEVER downgraded to benign (spec honesty contract).
_VNC_LO, _VNC_HI = 5900, 5999
_SENSITIVE_SERVICE_NAMES: frozenset[str] = frozenset({
    "ssh", "vnc", "rdp", "ms-wbt-server", "telnet", "mysql", "postgres", "postgresql", "redis",
    "mongodb", "docker", "winrm", "smb", "microsoft-ds", "netbios-ssn", "rpcbind", "ldap", "ldaps",
    "elasticsearch",
})


def _is_vnc(port: int) -> bool:
    return _VNC_LO <= port <= _VNC_HI


# "Internal/private" by the SPEC's explicit RFC1918 / loopback / link-local list — NOT Python's
# broader ip.is_private (which also flags documentation/benchmark/reserved ranges like 203.0.113/24
# and 198.18/15). Classifying those as "internal" would UNDER-state the reach of a documentation /
# reserved source; treating a non-RFC1918 address as a concrete host/range is the conservative call.
_INTERNAL_NETS = [
    ipaddress.ip_network(c) for c in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",
        "fc00::/7", "fe80::/10", "::1/128",
    )
]


def _is_internal_net(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """True if `net` is wholly contained in an RFC1918 / loopback / link-local range."""
    return any(
        net.version == base.version and net.subnet_of(base)  # type: ignore[arg-type]
        for base in _INTERNAL_NETS
    )


def _source_breadth(source: str | None) -> tuple[str, str]:
    """(kind, human) for a rule source. kind in {anywhere, internal, host, range, named}.

    None/empty/0.0.0.0/0/::/0 => anywhere (widest). RFC1918/loopback/link-local =>
    internal. A concrete public host => host; a public CIDR => range. A non-IP token
    (ipset '+name' / alias 'dc/name' / bare alias) => named (unknown breadth — NEVER
    treated as narrow; the membership is not resolved in v1).
    """
    s = (source or "").strip()
    if s == "":
        # No source given => widest, family-agnostic. Lead with 0.0.0.0/0 but name ::/0 too so an
        # IPv6 reader is not misled into thinking only IPv4 is covered.
        return "anywhere", "0.0.0.0/0 + ::/0 (the entire internet/WAN — no source restriction)"
    if s in ("0.0.0.0/0", "::/0"):
        # Honest per-TOKEN label: never claim 0.0.0.0/0 when the source was ::/0, or vice versa.
        return "anywhere", f"{s} (the entire internet/WAN)"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return "named", f"{s} (named set/alias — membership not resolved)"
    if _is_internal_net(net):
        return "internal", f"{s} (internal/private)"
    if net.num_addresses == 1:
        return "host", f"{s} (a single host)"
    return "range", f"{s} (a public range)"


def _proto_suffix(proto: str | None) -> str:
    """The '/proto' suffix for a port label. tcp / unspecified => '/tcp' (the conventional default
    PVE rules carry); a named proto (udp, icmp, …) is reflected honestly so a udp rule is NOT
    narrated as '/tcp'. An 'any'/'all' proto drops the suffix (the port spans all protocols)."""
    p = (proto or "").strip().lower()
    if p in ("", "tcp"):
        return "/tcp"
    if p in ("any", "all"):
        return ""
    return f"/{p}"


def _port_label(dport: str | None, proto: str | None = None) -> str:
    """Human label for a dport. Empty => 'ALL ports' (maximal — NEVER benign). Recognizes a single
    well-known port; passes ranges/lists/service-names through verbatim (not downgraded). The
    protocol is reflected honestly (a udp rule is not narrated as '/tcp')."""
    d = (dport or "").strip()
    if not d:
        return "ALL ports"
    suffix = _proto_suffix(proto)
    if d.isdigit():
        n = int(d)
        svc = _SENSITIVE_PORTS.get(n) or ("VNC" if _is_vnc(n) else None)
        return f"{svc} ({d}{suffix})" if svc else f"port {d}{suffix}"
    return f"port(s) {d}" + (f" ({proto})" if suffix and proto and proto.strip().lower() != "tcp" else "")


def _port_is_sensitive(dport: str | None) -> bool:
    """True if the dport reaches a known mgmt/admin service — OVER-flag, never under-flag. Empty =>
    ALL ports => True. A single well-known port or a VNC display (5900-5999) => True. A range or
    comma-list => scan each member (a mgmt port hidden in '80,22' / '20:30' / a VNC range still
    trips). A service NAME maps via _SENSITIVE_SERVICE_NAMES; an UNRECOGNIZED non-numeric token is
    treated conservatively (True) — the spec forbids downgrading an unrecognized form to benign."""
    d = (dport or "").strip()
    if not d:
        return True   # ALL ports includes the sensitive ones
    if d.isdigit():
        n = int(d)
        return n in _SENSITIVE_PORTS or _is_vnc(n)
    unrecognized = False
    for member in d.split(","):
        member = member.strip()
        if not member:
            continue
        if member.isdigit():
            n = int(member)
            if n in _SENSITIVE_PORTS or _is_vnc(n):
                return True
            continue
        if ":" in member:
            # a range 'a:b' — flag if any sensitive port (or the VNC band) falls inside [a, b]
            lo, _, hi = member.partition(":")
            lo, hi = lo.strip(), hi.strip()
            if lo.isdigit() and hi.isdigit():
                a, b = int(lo), int(hi)
                if a <= b and (any(a <= p <= b for p in _SENSITIVE_PORTS) or (a <= _VNC_HI and b >= _VNC_LO)):
                    return True
            else:
                unrecognized = True  # malformed range — don't downgrade to benign
            continue
        # a service NAME token: known-sensitive => True; unknown => conservative (never benign)
        if member.lower() in _SENSITIVE_SERVICE_NAMES:
            return True
        unrecognized = True
    return unrecognized


@dataclass
class FirewallReachResult:
    """Per-rule reach classification. summary_lines are rule-scoped; affected is a list of dicts
    (effect/service/from/direction/scope/severity); risk is only ever raised, never lowered."""

    summary_lines: list[str]
    affected: list[dict]
    risk: str
    risk_reasons: list[str]
    complete: bool = True


# The standing framing disclaimer carried on every reach result. It is intentionally NOT a
# "this rule …" sentence; the per-rule-reach framing test treats it (any line containing
# "per-rule") as the one exception to the "every line starts with 'this rule'" rule.
_REACH_DISCLAIMER = (
    "PER-RULE REACH: this describes what THIS rule permits/blocks if it is the deciding match in "
    "an enforced, default-DROP firewall — NOT whether the cluster is actually exposed (that "
    "depends on the full ordered ruleset, the default policy, and whether the firewall is enabled "
    "for this scope)."
)


def compute_firewall_reach(
    action: str,
    direction: str,
    source: str | None,
    dport: str | None,
    proto: str | None,
    scope_label: str,
    enable: bool = True,
    mgmt_host: str | None = None,
) -> FirewallReachResult:
    """PURE per-rule reach classification. No API. See _REACH_DISCLAIMER for the framing contract.

    `proto`/`mgmt_host` are accepted for signature symmetry; an empty proto does NOT narrow reach
    (all protocols), and the mgmt_host self-lockout hint is a v1 nicety (may be None).
    """
    action = (action or "").upper()
    direction = (direction or "").lower()
    breadth, from_label = _source_breadth(source)
    service = _port_label(dport, proto)
    sensitive = _port_is_sensitive(dport)
    lines: list[str] = [_REACH_DISCLAIMER]
    reasons: list[str] = ["per-rule reach is heuristic; absence of HIGH is not a safety signal"]
    affected: list[dict] = []
    risk = RISK_MEDIUM

    # enable=0 — STAGED, not active. Never "permits"/"blocks"; risk floor only.
    if not enable:
        lines.append(
            f"this rule is DISABLED (enable=0) — STAGED, not active: it would "
            f"{action.lower() or 'apply'} {service} from {from_label} ({direction}) only once enabled"
        )
        affected.append({"effect": "staged", "service": service, "from": from_label,
                         "direction": direction, "scope": scope_label, "severity": "low"})
        return FirewallReachResult(summary_lines=lines, affected=affected, risk=risk,
                                   risk_reasons=reasons + ["rule is staged (enable=0)"])

    # Outbound — egress note, materially lower exposure than an inbound open. The engine only holds
    # `source`; an egress rule's DESTINATION is the rule's `dest` (not passed in v1), so do NOT
    # narrate the source as the destination — state the egress effect without a (false) target.
    if direction == "out":
        is_accept = action == "ACCEPT"
        verb = "PERMITS" if is_accept else "BLOCKS"
        lines.append(
            f"this rule {verb} OUTBOUND {service} (egress — lower exposure; the destination is the "
            "rule's dest, not classified in v1)"
        )
        affected.append({"effect": "permits" if is_accept else "blocks", "service": service,
                         "from": "(egress — dest not classified in v1)", "direction": "out",
                         "scope": scope_label, "severity": "low"})
        return FirewallReachResult(summary_lines=lines, affected=affected, risk=risk,
                                   risk_reasons=reasons)

    # Inbound.
    if action == "ACCEPT":
        if breadth == "anywhere":
            sev = "high"
        elif breadth in ("range", "named"):
            # public range or unresolved named set/alias — never "low"; HIGH if it reaches mgmt.
            sev = "high" if sensitive else "medium"
        elif breadth == "internal":
            sev = "medium"
        else:  # host
            sev = "medium" if sensitive else "low"
        lines.append(f"this rule PERMITS inbound {service} from {from_label} on {scope_label}")
        if sev == "high":
            lines.append(
                f"  -> reachable from {from_label}"
                + (" on a management/admin service" if sensitive else "")
            )
        affected.append({"effect": "permits", "service": service, "from": from_label,
                         "direction": "in", "scope": scope_label, "severity": sev})
        if sev == "high":
            risk = _max_risk(risk, RISK_HIGH)
    else:  # DROP / REJECT, inbound
        lockout = sensitive and breadth in ("anywhere", "range", "named", "internal")
        lines.append(f"this rule BLOCKS inbound {service} from {from_label} on {scope_label}")
        sev = "medium"
        if lockout:
            sev = "high"
            lines.append(
                "  -> LOCKOUT RISK: this rule blocks a management/admin port from a broad source; "
                "if it covers your access path you lose SSH/API (console to recover)"
            )
            risk = _max_risk(risk, RISK_HIGH)
        affected.append({"effect": "blocks", "service": service, "from": from_label,
                         "direction": "in", "scope": scope_label, "severity": sev})

    return FirewallReachResult(summary_lines=lines, affected=affected, risk=risk,
                               risk_reasons=reasons)


# ===========================================================================
# Network-apply lockout class — best-effort mgmt-interface naming on an UNCONDITIONAL HIGH.
#
# plan_network_apply is already RISK_HIGH unconditional, so naming the interface CANNOT under-flag;
# it only adds specificity. Non-identification (hostname mgmt_host, addressless ifaces, no match)
# => HIGH STANDS, never "no lockout". Risk is never lowered.
# ===========================================================================

@dataclass
class ApplyLockoutResult:
    summary_lines: list[str]
    affected: list[dict]
    risk: str
    risk_reasons: list[str]
    complete: bool = True


def _iface_holding_host(host: str | None, ifaces: list[dict]) -> str | None:
    """Best-effort: the iface whose address/cidr equals the mgmt host IP. None if host is not an IP,
    no iface matches, or addresses are absent (best-effort — caller keeps HIGH regardless)."""
    h = (host or "").strip()
    try:
        target = ipaddress.ip_address(h)
    except ValueError:
        return None
    for i in ifaces:
        for key in ("address", "cidr", "address6", "cidr6"):
            raw = i.get(key)
            if not raw:
                continue
            val = str(raw).split("/")[0].strip()
            if not val:
                continue
            try:
                if ipaddress.ip_address(val) == target:
                    return i.get("iface")
            except ValueError:
                continue
    return None


def compute_apply_lockout(pending_ifaces: list[str], mgmt_host: str | None,
                          ifaces: list[dict]) -> ApplyLockoutResult:
    """PURE. Best-effort naming on top of an UNCONDITIONAL HIGH (network apply is always RISK_HIGH).
    Names the pending iface that carries the mgmt host; non-identification => HIGH STANDS, never 'safe'.
    """
    mgmt_iface = _iface_holding_host(mgmt_host, ifaces)
    lines: list[str] = []
    affected: list[dict] = []
    reasons = ["network apply can lose connectivity; no automatic rollback (console to recover)"]
    if mgmt_iface and mgmt_iface in pending_ifaces:
        lines.append(
            f"LOCKOUT: this apply changes {mgmt_iface!r}, which holds the management host "
            f"{mgmt_host} — you will lose SSH/API access; recovery needs console/physical access"
        )
        affected.append({"iface": mgmt_iface, "effect": "management interface changing",
                         "holds": mgmt_host, "severity": "high"})
        reasons.append(f"pending change to {mgmt_iface} (management interface) — lockout")
    elif mgmt_iface:
        lines.append(
            f"management host {mgmt_host} is on {mgmt_iface!r}, which is NOT in the pending set — "
            "but apply is still RISK_HIGH (a dependent bond/VLAN under it may be affected, and the "
            "pending-change read may be incomplete)"
        )
        reasons.append(
            f"management host is on {mgmt_iface} (not pending) — HIGH stands; dependent layers may "
            "still be affected"
        )
    else:
        lines.append(
            f"could not identify the management interface (mgmt host {mgmt_host!r} is a hostname, is "
            "addressless on the read, or did not match any iface address) — RISK_HIGH STANDS; assume "
            "lockout risk"
        )
        reasons.append(
            "management interface not identified — RISK_HIGH stands; absence of a named lockout is "
            "NOT a safety signal"
        )
    return ApplyLockoutResult(summary_lines=lines, affected=affected, risk=RISK_HIGH,
                              risk_reasons=reasons)


# ===========================================================================
# Firewall-lockout class — enabling the firewall / setting policy_in=DROP under
# default-DROP locks out management on every node whose (datacenter ∪ node) ruleset
# lacks an inbound ACCEPT for SSH(22)/PVE(8006). Names the at-risk nodes on top of an
# UNCONDITIONAL HIGH (mirrors compute_apply_lockout): a rule counts as protective ONLY
# if ENABLED + inbound + ACCEPT + tcp-ish + covers 22/8006 — a disabled/udp/outbound/
# narrow-source rule is NEVER counted as blanket protection (no under-flag of a lockout).
# ===========================================================================

_MGMT_PORTS = (22, 8006)   # SSH, PVE API — the host-management surface a lockout kills
_BREADTH_RANK = {"anywhere": 3, "internal": 2, "host": 1, "range": 1, "named": 1}

_FW_LOCKOUT_DISCLAIMER = (
    "FIREWALL LOCKOUT: enabling the firewall / setting policy_in=DROP applies a default-DROP policy; "
    "a node keeps management access only if an ENABLED inbound ACCEPT for SSH(22)/PVE(8006) exists in "
    "its (datacenter + node) ruleset. This names nodes whose rules do NOT clearly grant that — rule "
    "order and your actual admin source still decide the outcome, so the change is RISK_HIGH regardless."
)


def _fw_covers_mgmt_port(dport: str | None) -> bool:
    """True if `dport` reaches SSH(22) or PVE(8006). Empty => ALL ports => True. Scans single port,
    comma-list, and 'a:b' ranges; the 'ssh' service name maps to 22. OVER-flag, never under-flag."""
    d = (dport or "").strip()
    if not d:
        return True
    for member in d.split(","):
        member = member.strip()
        if not member:
            continue
        if member.isdigit():
            if int(member) in _MGMT_PORTS:
                return True
            continue
        if ":" in member:
            lo, _, hi = member.partition(":")
            lo, hi = lo.strip(), hi.strip()
            if lo.isdigit() and hi.isdigit():
                a, b = int(lo), int(hi)
                if a <= b and any(a <= p <= b for p in _MGMT_PORTS):
                    return True
            continue
        if member.lower() == "ssh":
            return True
    return False


def _fw_proto_is_tcp_ish(proto: str | None) -> bool:
    """SSH/8006 are tcp. A rule protects them only if its proto is tcp / unspecified / any / all."""
    return (proto or "").strip().lower() in ("", "tcp", "any", "all")


def _fw_rule_protects_mgmt(rule: dict) -> bool:
    """A rule grants inbound management access iff: enabled (enable != 0) AND type=='in' AND
    action=='ACCEPT' AND proto is tcp-ish AND dport covers 22/8006. Conservative — anything that
    fails a clause is NOT counted as protection (so a lockout is never under-flagged)."""
    if str(rule.get("enable", 1)).strip().lower() in ("0", "false", "no"):
        return False
    if str(rule.get("type", "")).strip().lower() != "in":
        return False
    if str(rule.get("action", "")).strip().upper() != "ACCEPT":
        return False
    if not _fw_proto_is_tcp_ish(rule.get("proto")):
        return False
    return _fw_covers_mgmt_port(rule.get("dport"))


@dataclass
class FirewallLockoutResult:
    """Lockout naming on top of an unconditional RISK_HIGH. `affected` = the AT-RISK nodes
    (lockout / conditional / incomplete); open/internal-protected nodes appear only in summary_lines."""

    summary_lines: list[str]
    affected: list[dict]
    risk: str
    risk_reasons: list[str]
    complete: bool = True


def compute_firewall_lockout_blast(scope: str, nodes: list[str] | None,
                                   datacenter_rules: list[dict] | None,
                                   node_rules: dict) -> FirewallLockoutResult:
    """PURE. Names nodes that would lose management access when the firewall is enabled / policy_in
    goes DROP. Risk is RISK_HIGH unconditional; the engine only NAMES the at-risk nodes (it never
    lowers risk). `nodes`/`datacenter_rules`/a node's rules being None means that read FAILED →
    INCOMPLETE for the affected node(s), never read as 'safe'."""
    lines: list[str] = [_FW_LOCKOUT_DISCLAIMER]
    reasons = ["enabling default-DROP can instantly cut SSH/API; absence of a named node is not safety"]
    affected: list[dict] = []

    # `not nodes` covers both None (read failed) AND [] (degraded enumeration — a real cluster always
    # has ≥1 node, so an empty list is never legitimate). Both fail closed; never read as "nothing at risk".
    if not nodes:
        lines.append(
            "could not ENUMERATE the nodes in scope — enabling default-DROP can lock out management "
            "cluster-wide; RISK_HIGH stands (absence of a named node is NOT a safety signal)"
        )
        return FirewallLockoutResult(lines, affected, RISK_HIGH, reasons, complete=False)

    complete = True
    for node in nodes:
        node_specific = node_rules.get(node)
        if datacenter_rules is None or node_specific is None:
            complete = False
            affected.append({
                "node": node, "state": "incomplete", "severity": "unknown",
                "effect": "firewall rules unreadable — cannot confirm a management ACCEPT exists; "
                          "assume lockout risk",
            })
            lines.append(
                f"⚠ INCOMPLETE: could not read firewall rules for {node!r} — a lockout for this node "
                "cannot be ruled out (not a safety signal)"
            )
            continue

        protective = [r for r in (list(datacenter_rules) + list(node_specific))
                      if _fw_rule_protects_mgmt(r)]
        if not protective:
            affected.append({
                "node": node, "state": "lockout", "severity": "high",
                "effect": "no enabled inbound ACCEPT for SSH(22)/PVE(8006) — default-DROP blocks management",
            })
            lines.append(
                f"LOCKOUT: {node} has no enabled inbound management ACCEPT (SSH 22 / PVE 8006) — "
                "enabling default-DROP blocks SSH/API to it"
            )
            continue

        pairs = [_source_breadth(r.get("source")) for r in protective]
        breadths = [k for k, _ in pairs]
        widest = max(breadths, key=lambda k: _BREADTH_RANK.get(k, 1))
        if widest == "anywhere":
            lines.append(
                f"{node}: an OPEN inbound management ACCEPT exists — HIGH still stands (rule order / "
                "default policy decide the outcome), but the clearest lockout cause is absent"
            )
        elif widest == "internal":
            lines.append(
                f"{node}: inbound management ACCEPT restricted to INTERNAL/private sources — protective "
                "only if you manage from inside the private network"
            )
        else:
            srcs = sorted({label for k, label in pairs if k not in ("anywhere", "internal")})
            affected.append({
                "node": node, "state": "conditional", "severity": "high",
                "effect": f"management ACCEPT exists but SOURCE-RESTRICTED ({'; '.join(srcs)}) — if your "
                          "admin source is outside it, default-DROP locks you out",
            })
            lines.append(
                f"CONDITIONAL LOCKOUT: {node}'s only management ACCEPT is source-restricted — it locks "
                "out any admin source outside that set"
            )

    return FirewallLockoutResult(lines, affected, RISK_HIGH, reasons, complete=complete)


def gather_firewall_lockout_dependents(api, scope: str,
                                       node: str | None) -> tuple[list[str] | None,
                                                                  list[dict] | None, dict]:
    """I/O, fail-closed (never raises). Returns (nodes, datacenter_rules, node_rules):
    - datacenter_rules: cluster firewall rules (None on read failure);
    - nodes: cluster scope → every node name (None if enumeration fails); node scope → [node];
    - node_rules: {node: that node's rules (None on read failure)}.
    """
    from .firewall import firewall_rules_list

    try:
        datacenter_rules: list[dict] | None = firewall_rules_list(api, "cluster")
    except Exception:
        datacenter_rules = None

    nodes: list[str] | None
    if scope == "node" and node:
        nodes = [node]
    else:
        try:
            rows = cluster_resources(api, "node") or []
            nodes = [str(r.get("node")) for r in rows if r.get("node")]
        except Exception:
            nodes = None

    node_rules: dict = {}
    for n in (nodes or []):
        try:
            node_rules[n] = firewall_rules_list(api, "node", node=n)
        except Exception:
            node_rules[n] = None
    return nodes, datacenter_rules, node_rules


def firewall_lockout_blast(api, scope: str, node: str | None) -> FirewallLockoutResult:
    """Convenience: gather live firewall state then compute the pure lockout result."""
    nodes, dc_rules, node_rules = gather_firewall_lockout_dependents(api, scope, node)
    return compute_firewall_lockout_blast(scope, nodes, dc_rules, node_rules)


# ===========================================================================
# Network-iface attachment class — editing a bridge disrupts every guest with a NIC
# on it when the staged change is applied. Names the attached guests. The change is
# staged (reversible until network_apply, where compute_apply_lockout carries the HIGH
# mgmt-lockout) so risk is not escalated here; the value is naming the affected guests.
# ===========================================================================

_NET_KEY_RE = re.compile(r"^net\d+$")


def _guest_nics_on_bridge(config: dict, iface: str) -> list[str]:
    """netN slots whose `bridge=` token equals `iface` EXACTLY (token match, so 'vmbr1' does not
    match a guest on 'vmbr10')."""
    out: list[str] = []
    needle = f"bridge={iface}"
    for key, val in config.items():
        if _NET_KEY_RE.match(key) and isinstance(val, str):
            if any(tok.strip() == needle for tok in val.split(",")):
                out.append(key)
    return sorted(out)


@dataclass
class IfaceBlastResult:
    summary_lines: list[str]
    affected: list[dict]
    complete: bool
    max_severity: str          # "medium" (guests attached) | "none" — never escalates a staged edit


def compute_iface_blast(iface: str, guests: list[dict], configs: dict,
                        complete: bool) -> IfaceBlastResult:
    """PURE. Names guests with a NIC on bridge `iface` — disrupted when a staged iface change applies.
    `complete=False` (some guest configs unread) → loud INCOMPLETE; the attached list may be partial."""
    affected: list[dict] = []
    for g in guests:
        cfg = configs.get(str(g.get("vmid", "")))
        if not isinstance(cfg, dict):
            continue
        nics = _guest_nics_on_bridge(cfg, iface)
        if nics:
            affected.append({
                "resource": f"{g.get('type', 'qemu')}/{g.get('vmid', '')}",
                "vmid": str(g.get("vmid", "")), "name": str(g.get("name", "") or ""),
                "node": str(g.get("node", "")), "nics": nics,
                "effect": f"attached to bridge {iface!r} via {', '.join(nics)} — networking disrupted "
                          "when this staged change is applied",
                "severity": "medium",
            })
    affected.sort(key=lambda a: a["vmid"])

    lines: list[str] = []
    if not complete:
        lines.append(
            f"⚠ INCOMPLETE: could not enumerate all guests — the list attached to bridge {iface!r} may "
            "be partial (absence here is not proof a guest is unaffected)"
        )
    if affected:
        lines.append(
            f"{len(affected)} guest(s) are attached to bridge {iface!r} and have their networking "
            "disrupted when this staged change is applied:"
        )
        for a in affected:
            label = a["resource"] + (f" ({a['name']})" if a["name"] else "")
            lines.append(f"  {label} on {a['node']}: via {', '.join(a['nics'])}")
    elif complete:
        lines.append(
            f"no guest has a NIC on bridge {iface!r} — no guest networking is disrupted (absence here "
            "is not proof for any guest not enumerated)"
        )
    return IfaceBlastResult(lines, affected, complete=complete,
                            max_severity="medium" if affected else "none")


def iface_attachment_blast(api, iface: str) -> IfaceBlastResult:
    """Convenience: enumerate cluster guests (storage gather is guest-list-agnostic) then compute."""
    guests, configs, complete = gather_storage_dependents(api, "")
    return compute_iface_blast(iface, guests, configs, complete)


# ===========================================================================
# Guest-migrate disk-residency class — a guest's disks migrate cleanly ONLY if each
# sits on SHARED storage available on the target node. Local (shared=0) storage forces
# a copy (or fails); a nodes-restricted storage absent from the target can't place the
# disk. Names the BLOCKING disks. Honest framing: this is migration FEASIBILITY (the
# harm is mostly to the guest itself), not cross-resource naming. Risk only escalates.
# ===========================================================================

@dataclass
class MigrateBlastResult:
    summary_lines: list[str]
    affected: list[dict]
    complete: bool
    max_severity: str          # "high" | "none" — escalates the plan's base risk, never lowers it


def compute_migrate_blast(target: str, disk_slots: dict, storage_meta: dict,
                          config_complete: bool, online: bool, kind: str,
                          raw_slots: list[str] | None = None) -> MigrateBlastResult:
    """PURE. Given the guest's {slot: storage} disks and per-storage metadata
    ({storage: {"shared": bool, "nodes": set|None}}; a storage ABSENT from the map = metadata
    unreadable), decide whether each disk can migrate to `target`. A disk is OK (unflagged) ONLY when
    its storage is provably shared AND available on the target; local / unavailable / unknown all flag.
    `raw_slots` are passthrough/raw disks that name no PVE storage — they cannot follow the guest to
    another node, so each is flagged (never dropped). `config_complete=False` → loud INCOMPLETE, HIGH."""
    lines: list[str] = []
    affected: list[dict] = []

    if not config_complete:
        lines.append(
            "⚠ INCOMPLETE: could not read the guest config — cannot enumerate its disks; whether they "
            "can migrate to the target is UNKNOWN (not a safety signal)"
        )
        affected.append({"slot": "", "storage": "", "state": "incomplete", "severity": "unknown",
                         "effect": "guest config unreadable — disks could not be enumerated"})
        return MigrateBlastResult(lines, affected, complete=False, max_severity="high")

    complete = True
    for slot in sorted(disk_slots):
        storage = disk_slots[slot]
        meta = storage_meta.get(storage)
        if meta is None:
            complete = False
            affected.append({"slot": slot, "storage": storage, "state": "unknown", "severity": "unknown",
                             "effect": f"storage {storage!r} config unreadable — cannot confirm it is "
                                       "shared and available on the target; the disk may not migrate"})
            lines.append(
                f"⚠ INCOMPLETE: storage {storage!r} (disk {slot}) metadata unreadable — migration "
                "feasibility for this disk is UNKNOWN (not a safety signal)"
            )
            continue
        nodes = meta.get("nodes")
        if nodes is not None and target not in nodes:
            affected.append({"slot": slot, "storage": storage, "state": "unavailable", "severity": "high",
                             "effect": f"storage {storage!r} is restricted to {sorted(nodes)} and is NOT "
                                       f"available on target {target!r} — cannot place disk {slot}"})
            lines.append(
                f"FAILS: disk {slot} is on {storage!r}, not available on target {target!r} "
                f"(restricted to {sorted(nodes)}) — the migration cannot place it"
            )
            continue
        if not meta.get("shared"):
            live = online and kind == "qemu"
            extra = " a LIVE migration is NOT possible with a local disk" if live else ""
            affected.append({"slot": slot, "storage": storage, "state": "local", "severity": "high",
                             "effect": f"disk {slot} is on LOCAL/non-shared storage {storage!r} — migration "
                                       f"must COPY it to the target (needs with-local-disks); a plain "
                                       f"migrate FAILS.{extra}"})
            lines.append(
                f"LOCAL DISK: {slot} is on non-shared {storage!r} — migrating copies it (with-local-disks) "
                f"or FAILS;{extra}"
            )
            continue
        # shared AND available on the target → clean migrate, not flagged (no cry-wolf)

    for slot in sorted(raw_slots or []):
        affected.append({"slot": slot, "storage": "", "state": "raw", "severity": "high",
                         "effect": f"disk {slot} is a RAW/passthrough device (no PVE storage volume) — "
                                   "it cannot follow the guest to another node; migration cannot move it"})
        lines.append(
            f"RAW DISK: {slot} is a passthrough device (no PVE storage) — it cannot migrate to another node"
        )

    if affected:
        return MigrateBlastResult(lines, affected, complete=complete, max_severity="high")
    if disk_slots:
        lines.append(
            f"all {len(disk_slots)} disk(s) are on shared storage available on target {target!r} — "
            "no disk copy required for the migration"
        )
    else:
        lines.append("guest has no data disks to migrate")
    return MigrateBlastResult(lines, affected, complete=True, max_severity="none")


def gather_migrate_dependents(api, vmid: str, kind: str, node: str | None,
                              target: str) -> tuple[dict, list[str], dict, bool]:
    """I/O, fail-closed. Returns (disk_slots, raw_slots, storage_meta, config_complete):
    - disk_slots {slot: storage} + raw_slots [slot] (passthrough/no-storage) from the guest config
      (config_complete=False if unreadable/empty);
    - storage_meta {storage: {"shared": bool, "nodes": set[str]|None}} from the cluster storage.cfg
      (a storage absent from the map / a failed read = metadata unknown for that storage).
    """
    from .storage_admin import storage_config_list

    disk_slots: dict = {}
    raw_slots: list[str] = []
    config_complete = True
    try:
        cfg = guest_config_get(api, vmid, kind, node)
        if isinstance(cfg, dict) and cfg:
            disk_slots, raw_slots = _disk_slots_split(cfg)
        else:
            config_complete = False
    except Exception:
        config_complete = False

    storage_meta: dict = {}
    try:
        for s in (storage_config_list(api) or []):
            name = s.get("storage")
            if not name:
                continue
            nodes_raw = s.get("nodes")
            nodes = {n.strip() for n in str(nodes_raw).split(",") if n.strip()} if nodes_raw else None
            shared = str(s.get("shared", 0)).strip().lower() in ("1", "true", "yes")
            storage_meta[str(name)] = {"shared": shared, "nodes": nodes or None}
    except Exception:
        storage_meta = {}
    return disk_slots, raw_slots, storage_meta, config_complete


def migrate_blast(api, vmid: str, kind: str, node: str | None, target: str,
                  online: bool) -> MigrateBlastResult:
    """Convenience: gather live state then compute the pure migrate disk-residency result."""
    disk_slots, raw_slots, storage_meta, config_complete = gather_migrate_dependents(
        api, vmid, kind, node, target)
    return compute_migrate_blast(target, disk_slots, storage_meta, config_complete, online, kind,
                                 raw_slots=raw_slots)


# ===========================================================================
# Guest-destroy class — cascade what destroying a VM/CT actually does.
#
# Three outcome categories: WON'T PROCEED (PVE will refuse — protection=1,
# template-with-clones, running+force=False), REFERENCES (HA / replication /
# backup — each conditional on `purge`), INFORMATIONAL (disks, snapshots, pool).
# Risk is RISK_HIGH unconditional; only ever raised, never lowered.
# ===========================================================================

_GUEST_DESTROY_DISCLAIMER = (
    "GUEST-DESTROY CASCADE: computed at PLAN time against the cluster as currently read. "
    "Consequences are shown for THIS call's purge/force values — a different purge/force would "
    "change them. RISK is always HIGH for a destroy and is only ever raised, never lowered."
)


@dataclass(frozen=True)
class GuestDestroyInputs:
    """Everything compute_guest_destroy_blast needs — assembled by gather_guest_dependents.
    A None on any cluster-wide read means that read FAILED (not 'empty'); an empty list means
    the read succeeded and found nothing. guest_config None means the target's own config was
    unreadable."""
    vmid: str
    kind: str
    purge: bool
    force: bool
    guest_config: dict | None
    status: str
    ha_resources: list[dict] | None
    replication_jobs: list[dict] | None
    backup_jobs: list[dict] | None
    pools: list[dict] | None
    snapshots: list[dict] | None
    clone_configs: dict | None  # {vmid: config} of OTHER guests, for the template-clone scan


@dataclass(frozen=True)
class GuestDestroyBlastResult:
    summary_lines: list[str]
    affected: list[dict]
    risk: str
    risk_reasons: list[str]
    complete: bool = True


def _purge_effect(purge: bool, what: str) -> str:
    """Phrase a reference consequence conditional on purge — NEVER the opposite of what happens."""
    if purge:
        return f"PVE will REMOVE this {what} as part of purge=true"
    return f"left DANGLING (purge=false); remove this {what} manually after the destroy"


@dataclass
class _DestroyCheck:
    """One classification's contribution to the aggregate: entries to add to `affected`, lines to
    add to `summary`, risk-reason lines to add, and whether this check found the plan INCOMPLETE."""

    affected: list[dict] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    incomplete: bool = False


def _destroy_disk_summary(inp: GuestDestroyInputs, res: str) -> _DestroyCheck:
    """INFORMATIONAL: disks + storages freed (from the target's own config)."""
    if inp.guest_config is None:
        return _DestroyCheck(
            summary=[f"could NOT read {res} config — cannot enumerate its disks"], incomplete=True,
        )
    slots = _disk_slots(inp.guest_config)
    affected = []
    for st in sorted(set(slots.values())):
        via = sorted(s for s, sto in slots.items() if sto == st)
        affected.append({
            "category": "informational", "kind": "disk", "ref": st,
            "effect": f"frees disk(s) {', '.join(via)} on storage {st}",
            "severity": "info",
        })
    return _DestroyCheck(affected=affected)


def _destroy_protection_guard(inp: GuestDestroyInputs, res: str) -> _DestroyCheck:
    """WON'T PROCEED: protection=1 (force does NOT override)."""
    if inp.guest_config is None or str(inp.guest_config.get("protection", 0)) not in ("1", "True", "true"):
        return _DestroyCheck()
    return _DestroyCheck(
        affected=[{
            "category": "wont_proceed", "kind": "protection", "ref": res,
            "effect": "PVE will REFUSE: protection=1 is set; force does NOT override — "
                      "unset protection first",
            "severity": "high",
        }],
        reasons=["would be REFUSED: protection=1 (force does not override)"],
    )


def _destroy_running_guard(inp: GuestDestroyInputs, res: str) -> _DestroyCheck:
    """WON'T PROCEED: running + force=False (force=True overrides ONLY this guard). status="unknown"
    (the run-state re-read itself failed) with force=False is the ONE input that would otherwise
    silently read as safe — the running guard never fires, so flag it incomplete instead of a false
    "go". With force=True the running guard is overridden anyway, so an unknown status is moot."""
    if inp.status == "running" and not inp.force:
        return _DestroyCheck(
            affected=[{
                "category": "wont_proceed", "kind": "running", "ref": res,
                "effect": "PVE will REFUSE: the guest is running; re-call with force=true to "
                          "override the running guard (force does NOT override protection or "
                          "template-with-clones)",
                "severity": "high",
            }],
            reasons=["would be REFUSED: guest is running and force=false"],
        )
    if inp.status not in ("running", "stopped") and not inp.force:
        return _DestroyCheck(
            summary=[
                f"could NOT confirm run-state of {res} (got {inp.status!r}); if it is running and "
                "force=false, PVE will REFUSE the destroy."
            ],
            incomplete=True,
        )
    return _DestroyCheck()


def _destroy_template_clone_guard(inp: GuestDestroyInputs, res: str) -> _DestroyCheck:
    """WON'T PROCEED: template with linked clones (force does NOT override)."""
    if inp.guest_config is None or str(inp.guest_config.get("template", 0)) not in ("1", "True", "true"):
        return _DestroyCheck()
    if inp.clone_configs is None:
        return _DestroyCheck(
            summary=[
                f"{res} is a TEMPLATE but could NOT scan for linked clones — if any exist, "
                "the destroy will be REFUSED"
            ],
            incomplete=True,
        )
    affected: list[dict] = []
    reasons: list[str] = []
    clones = sorted(v for v, cfg in inp.clone_configs.items() if _is_linked_clone_of(cfg, str(inp.vmid)))
    if clones:
        affected.append({
            "category": "wont_proceed", "kind": "template_clones",
            "ref": ", ".join(clones),
            "effect": f"PVE will REFUSE: this template has {len(clones)} linked clone(s) "
                      f"({', '.join(clones)}); destroying it would corrupt them; force does "
                      "NOT override",
            "severity": "high",
        })
        reasons.append(f"would be REFUSED: template has linked clone(s) {', '.join(clones)}")
    # Even on a clean scan, name the blind spot: linked clones on directory/qcow2 storage record
    # their backing chain in the qcow2 file, NOT the PVE config, so they are invisible to a config
    # scan. Documented limitation (not a failed read) — caveat, never incomplete.
    summary = [
        f"{res} is a TEMPLATE — linked-clone detection is config-based (covers "
        "LVM-thin/ZFS/RBD backing); directory/qcow2 backing chains are not visible in "
        "config and are NOT detected."
    ]
    return _DestroyCheck(affected=affected, summary=summary, reasons=reasons)


def _destroy_ha_reference(inp: GuestDestroyInputs, sid: str) -> _DestroyCheck:
    """REFERENCE: HA resource (conditional on purge)."""
    if inp.ha_resources is None:
        return _DestroyCheck(
            summary=["could NOT read HA resources — cannot determine HA references"], incomplete=True,
        )
    affected = [
        {
            "category": "reference", "kind": "ha", "ref": sid,
            "effect": _purge_effect(inp.purge, "HA resource"),
            "severity": "info" if inp.purge else "medium",
        }
        for hr in inp.ha_resources if str(hr.get("sid")) == sid
    ]
    return _DestroyCheck(affected=affected)


def _destroy_replication_reference(inp: GuestDestroyInputs) -> _DestroyCheck:
    """REFERENCE: replication jobs (id == "<vmid>-N", exact vmid segment)."""
    if inp.replication_jobs is None:
        return _DestroyCheck(
            summary=["could NOT read replication jobs — cannot determine replication references"],
            incomplete=True,
        )
    affected: list[dict] = []
    for job in inp.replication_jobs:
        jid = str(job.get("id", ""))
        head, _, tail = jid.partition("-")
        if head == str(inp.vmid) and tail.isdigit():
            affected.append({
                "category": "reference", "kind": "replication", "ref": jid,
                "effect": _purge_effect(inp.purge, "replication job"),
                "severity": "info" if inp.purge else "medium",
            })
    return _DestroyCheck(affected=affected)


def _backup_job_coverage(job: dict, vmid: str, pools: list[dict] | None) -> bool | None:
    """Tri-state coverage of `vmid` by one backup job's selection: True=covered, False=not covered,
    None=unresolvable. PVE may serialize all=0/pool=""/exclude="" on explicit-vmid jobs; value-
    coercion (not key presence) is required to distinguish an active mode from a falsy default."""
    all_mode = str(job.get("all", 0)) in ("1", "True", "true")
    pool_val = str(job.get("pool", "")).strip()
    exclude_set = {v.strip() for v in str(job.get("exclude", "")).split(",") if v.strip()}
    vmid_set = {v.strip() for v in str(job.get("vmid", "")).split(",") if v.strip()}

    if all_mode:
        # all=1: every guest is covered UNLESS in the exclude list.
        return vmid not in exclude_set
    if pool_val:
        # pool=X: covered iff target is a member of that pool AND not excluded.
        if pools is None:
            return None  # pool data unreadable — cannot resolve
        target_pools = {
            str(p.get("poolid", ""))
            for p in pools
            if any(str(m.get("vmid")) == vmid for m in (p.get("members") or []))
        }
        return (pool_val in target_pools) and (vmid not in exclude_set)
    if vmid_set:
        # Explicit vmid list (all=0/falsy, no pool): direct membership check.
        return vmid in vmid_set
    return None  # unrecognizable selection (e.g. all=0, no pool, no vmid)


def _destroy_backup_reference(inp: GuestDestroyInputs) -> _DestroyCheck:
    """REFERENCE: backup jobs (resolved per selection mode; only an unresolvable selection stays
    incomplete)."""
    if inp.backup_jobs is None:
        return _DestroyCheck(
            summary=["could NOT read backup jobs — cannot determine backup-job references"],
            incomplete=True,
        )
    vmid = str(inp.vmid)
    affected: list[dict] = []
    summary: list[str] = []
    incomplete = False
    for job in inp.backup_jobs:
        jid = str(job.get("id", "?"))
        covered = _backup_job_coverage(job, vmid, inp.pools)
        if covered is None:
            incomplete = True
            summary.append(
                f"backup job {jid} uses an unresolvable selection — could NOT confirm whether "
                f"{vmid} is covered"
            )
        elif covered:
            affected.append({
                "category": "reference", "kind": "backup_job", "ref": jid,
                "effect": _purge_effect(inp.purge, "backup-job membership"),
                "severity": "info" if inp.purge else "medium",
            })
        # covered is False → resolved, not covered → no entry, no incomplete flag
    return _DestroyCheck(affected=affected, summary=summary, incomplete=incomplete)


def _destroy_snapshot_summary(inp: GuestDestroyInputs, res: str) -> _DestroyCheck:
    """INFORMATIONAL: snapshots removed with the guest. PVE's snapshot endpoint always includes a
    synthetic {"name": "current"} entry (the live state) — it is NOT a real snapshot and is excluded
    from the count/emit."""
    if inp.snapshots is None:
        return _DestroyCheck(
            summary=[f"could NOT read snapshots for {res} — cannot confirm what is removed"],
            incomplete=True,
        )
    real = [s for s in inp.snapshots if s.get("name") != "current"]
    if not real:
        return _DestroyCheck()
    return _DestroyCheck(affected=[{
        "category": "informational", "kind": "snapshots", "ref": str(len(real)),
        "effect": f"removes {len(real)} snapshot(s) with the guest",
        "severity": "info",
    }])


def _destroy_pool_summary(inp: GuestDestroyInputs, res: str) -> _DestroyCheck:
    """INFORMATIONAL: pool membership removed with the guest."""
    if inp.pools is None:
        return _DestroyCheck(
            summary=[f"could NOT read pools — cannot confirm {res} pool membership"], incomplete=True,
        )
    affected = []
    for p in inp.pools:
        members = p.get("members") or []
        if any(str(m.get("vmid")) == str(inp.vmid) for m in members):
            affected.append({
                "category": "informational", "kind": "pool", "ref": str(p.get("poolid", "")),
                "effect": f"removes {res} from pool {p.get('poolid')}",
                "severity": "info",
            })
    return _DestroyCheck(affected=affected)


def compute_guest_destroy_blast(inp: GuestDestroyInputs) -> GuestDestroyBlastResult:
    """Pure, no I/O. Classify what destroying inp.vmid does, conditional on purge/force.
    Risk is RISK_HIGH unconditional (destroy is irreversible) and only ever raised.

    Three outcome categories, each its own check below: WON'T PROCEED (PVE will refuse — protection,
    running+force=false, template-with-clones), REFERENCE (HA / replication / backup — conditional on
    purge), INFORMATIONAL (disks, snapshots, pool). Each check reports independently; this function
    only aggregates (never raises risk beyond the unconditional HIGH, never lowers `complete`)."""
    res = f"{inp.kind}/{inp.vmid}"
    sid = f"{'vm' if inp.kind == 'qemu' else 'ct'}:{inp.vmid}"
    affected: list[dict] = []
    summary: list[str] = [_GUEST_DESTROY_DISCLAIMER]
    reasons: list[str] = []
    complete = True

    for check in (
        _destroy_disk_summary(inp, res),
        _destroy_protection_guard(inp, res),
        _destroy_running_guard(inp, res),
        _destroy_template_clone_guard(inp, res),
        _destroy_ha_reference(inp, sid),
        _destroy_replication_reference(inp),
        _destroy_backup_reference(inp),
        _destroy_snapshot_summary(inp, res),
        _destroy_pool_summary(inp, res),
    ):
        affected.extend(check.affected)
        summary.extend(check.summary)
        reasons.extend(check.reasons)
        if check.incomplete:
            complete = False

    return GuestDestroyBlastResult(
        summary_lines=summary, affected=affected, risk=RISK_HIGH,
        risk_reasons=reasons, complete=complete,
    )


def _safe(fn, default=None):
    """Call fn(); on ANY exception return `default` (the 'read failed' sentinel)."""
    try:
        return fn()
    except Exception:
        return default


def _resolve_pool_members(api) -> list[dict]:
    """Resolve each pool's MEMBER list. pools_list returns only summaries (no members); membership
    lives in pool_get(api, poolid). Raises on ANY failure (pools_list OR a single pool_get) so the
    caller's _safe turns it into None == 'membership unknown' (never under-report by dropping a pool).
    """
    out: list[dict] = []
    for summary in pools_list(api) or []:
        pid = str(summary.get("poolid", ""))
        if not pid:
            continue
        out.append({"poolid": pid, "members": pool_get(api, pid).get("members") or []})
    return out


def gather_guest_dependents(api, vmid: str, kind: str, node: str | None,
                            purge: bool, force: bool) -> GuestDestroyInputs:
    """I/O: read everything compute needs. NEVER raises — a failed read becomes None so the
    honesty contract (None == unknown, [] == confirmed-empty) holds downstream."""
    cfg = _safe(lambda: guest_config_get(api, vmid, kind, node))
    # an empty dict from a 200 {"data": null} is an unreadable config, not 'no disks'
    if not cfg:
        cfg = None

    status = "unknown"
    gs = _safe(lambda: api.guest_status(vmid, kind, node))
    if isinstance(gs, dict) and gs.get("status"):
        status = str(gs["status"])

    # The peer-config clone scan is only needed (and only correct) when the TARGET is a template.
    # Decision table for clone_configs (the sentinel compute reads as 'could not scan'):
    #   - target cfg unreadable (cfg is None)  -> None  (template-ness unknown; stay incomplete)
    #   - target readable, NOT a template      -> {}    (compute's template branch won't use it)
    #   - target readable AND a template:
    #       - cluster_resources read failed     -> None
    #       - ANY peer config read failed/empty -> None  (a dropped peer may be a hidden clone)
    #       - else                              -> {peer_vmid: cfg, ...}
    clone_configs: dict | None
    is_template = cfg is not None and str(cfg.get("template", 0)) in ("1", "True", "true")
    if cfg is None:
        clone_configs = None
    elif not is_template:
        clone_configs = {}
    else:
        rows = _safe(lambda: cluster_resources(api))
        if rows is None:
            clone_configs = None
        else:
            scanned: dict = {}
            any_peer_failed = False
            for rrow in rows:
                if rrow.get("type") not in ("qemu", "lxc"):
                    continue
                rid = str(rrow.get("vmid", ""))
                if rid == str(vmid) or not rid:
                    continue
                ccfg = _safe(lambda rrow=rrow, rid=rid: guest_config_get(
                    api, rid, str(rrow.get("type")), rrow.get("node")))
                if ccfg:
                    scanned[rid] = ccfg
                else:
                    # A peer we could NOT read may itself be a linked clone we now cannot see.
                    # Dropping it silently would let compute find no clones -> false complete=True.
                    any_peer_failed = True
            clone_configs = None if any_peer_failed else scanned

    return GuestDestroyInputs(
        vmid=str(vmid), kind=str(kind), purge=purge, force=force,
        guest_config=cfg, status=status,
        ha_resources=_safe(lambda: ha_resources_list(api)),
        replication_jobs=_safe(lambda: api._get("/cluster/replication") or []),
        backup_jobs=_safe(lambda: api._get("/cluster/backup") or []),
        pools=_safe(lambda: _resolve_pool_members(api)),
        snapshots=_safe(lambda: api.snapshot_list(vmid, kind, node)),
        clone_configs=clone_configs,
    )


def guest_destroy_blast(api, vmid: str, kind: str, node: str | None,
                        purge: bool, force: bool) -> GuestDestroyBlastResult:
    """Convenience: gather (I/O, fail-closed) then compute (pure)."""
    return compute_guest_destroy_blast(
        gather_guest_dependents(api, vmid, kind, node, purge, force))
