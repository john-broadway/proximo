"""What a safety snapshot before a rollback can do on the storage a guest lives on (pure).

A rollback discards everything since the snapshot, and Proxmox publishes no read of a guest to
capture first, so the net is another snapshot (`records/undo.toml` [net]). Two different things
can stop it, judged on two different sets of volumes (read from the sources, 2026-10-25/26):

  1. THE NET WOULD BLOCK THE ROLLBACK. pve-guest-common `AbstractConfig::snapshot_rollback` runs
     `__snapshot_rollback_vol_possible` through `foreach_volume` over the TARGET SNAPSHOT's config
     (no `include_unused`; a VM's `vmstate` is handled apart, by `__snapshot_rollback_vm_start`; qemu
     skips CD-ROM drives; a VM's valid volume keys are its drive names, a container's are `rootfs`
     and `mp0..mp255`). So only the snapshot's own disks can refuse the rollback, and a volume the
     snapshot does not hold (an `unused0` that move-disk left behind, a disk added later, a
     vmstate) never can. The storage plugin refuses when a snapshot is newer than the target:
       zfspool, zfs   `volume_rollback_is_possible` dies "not most recent snapshot" (ZFSPlugin,
                      type `zfs`, inherits ZFSPoolPlugin and overrides nothing of it)   -> BLOCKS
       dir, nfs, cifs, glusterfs, cephfs, lvm
                      the same check, but ONLY with the storage's `snapshot-as-volume-chain`
                      (Plugin.pm returns 1 at once without it)                          -> BLOCKS with the flag
       lvmthin, btrfs never blocks (btrfs returns 1; thin LVM rolls back whatever is newer)
       rbd            never blocks: RBDPlugin overrides nothing, and its `options` do not list
                      `snapshot-as-volume-chain`, so it cannot be set and Plugin.pm's check
                      always returns 1                                                  -> NEVER
       anything else  not settled
  2. THE NET CANNOT BE TAKEN AT ALL. Taking it snapshots the CURRENT config's volumes (the same
     keys, no unused). `Plugin.pm volume_snapshot` dies "can't snapshot this image format" for a
     file-based volume that is not `.qcow2` (or `.qed` without the chain flag); thick LVM
     snapshots only as a `.qcow2` chain; a `.subvol` on a directory cannot. Then no safety
     snapshot is possible on this guest, and the plan and the receipt say so; none is taken.

An unreadable or unsettled storage takes the net: the rollback then refuses rather than reverts
without a way back, the fail-closed side. A storage whose chain flag cannot be read (the datacenter
manager's node storage list is a STATUS list, which never carries it) is unsettled for the
types that depend on that flag. Types, not names, are printed: the answer rides a receipt.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


class _Token:
    """A private sentinel. `execute` takes two fenced keywords, `judging` and `rate_prepaid`, and accepts
    only the object defined here for each: a boolean, a string, a number or a copy is refused, so the only
    way to pass one is to name it, and the names are pinned to the engine's own call sites
    (`tests/test_net_reads_taint_nothing.py`). A flag a caller could spell is a fence a caller could cross."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<{self.name}>"

    def __bool__(self) -> bool:
        raise TypeError(f"{self.name} is a sentinel, not a flag")


JUDGING = _Token("judging")          # the engine's own read for a judgement: marks nothing, keeps nothing
PREPAID = _Token("rate_prepaid")     # the safety snapshot's: its rate slots were taken with its act's

BLOCKS_ALWAYS = frozenset({"zfspool", "zfs"})
FILE_BASED = frozenset({"dir", "nfs", "cifs", "glusterfs", "cephfs"})
BLOCKS_WITH_CHAIN = FILE_BASED | {"lvm"}
ALWAYS_SNAPSHOTTABLE = frozenset({"zfspool", "zfs", "lvmthin", "btrfs", "rbd"})
NEVER_BLOCKS = frozenset({"lvmthin", "btrfs", "rbd"})
CHAIN_FLAG = "snapshot-as-volume-chain"

#: The config keys that name a volume the way PVE iterates them for a snapshot: a VM's drives (disks,
#: EFI and TPM state; a CD-ROM is skipped below) and a container's root and mount points. NOT the
#: unused volumes a detach left behind, and NOT a snapshot's `vmstate`.
_VOLUME_KEY = re.compile(r"^(?:(?:ide|sata|scsi|virtio|efidisk|tpmstate|mp)\d+|rootfs)$")
_VOLUME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*):([^,\s]+)")

BLOCKED_SENTENCE = ("on this storage a safety snapshot would block the rollback, so none is taken; "
                    "take a backup first if you need a way back")
IMPOSSIBLE_SENTENCE = ("no safety snapshot is possible on this guest, so none is taken; "
                       "take a backup first if you need a way back")


def truthy(value: Any) -> bool:
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value == 1) or \
        (isinstance(value, str) and value.strip().lower() in ("1", "true", "yes", "on"))


def volumes_of(config: Any) -> tuple[list[tuple[str, str]], int]:
    """([(storage id, volume name)], how many volume values could not be read) of a guest config
    (or a snapshot's), over the keys PVE iterates. A CD-ROM and `none` are no volume; a bind mount
    or a passthrough device has no storage and is counted as unread, not guessed at."""
    out: list[tuple[str, str]] = []
    unread = 0
    if not isinstance(config, Mapping):
        return out, unread
    for key, value in config.items():
        if not _VOLUME_KEY.match(str(key)) or not isinstance(value, str):
            continue
        if "media=cdrom" in value or value.strip() == "none":
            continue
        if m := _VOLUME.match(value):
            out.append((m.group(1), m.group(2)))
        else:
            unread += 1
    return out, unread


def device_mounts(config: Any) -> int:
    """How many of a config's volume values are a PATH, not a storage volume: an LXC bind or device
    mount, a qemu passthrough disk. PVE cannot snapshot a guest that has one (`has_feature` runs over
    every mount point or drive, and `volume_has_feature` answers undef for a path)."""
    if not isinstance(config, Mapping):
        return 0
    return sum(1 for key, value in config.items()
               if _VOLUME_KEY.match(str(key)) and isinstance(value, str) and value.lstrip().startswith("/")
               and "media=cdrom" not in value)


def storages_of(config: Any) -> set[str]:
    return {sid for sid, _ in volumes_of(config)[0]}


def blocks(stype: Any, chain: Any, visible: bool) -> bool | None:
    """True when a safety snapshot would block a rollback on this storage, False when it would not,
    None when that is not settled. `visible` is whether this plane can show the chain flag at all."""
    if stype in BLOCKS_ALWAYS:
        return True
    if stype in NEVER_BLOCKS:
        return False
    if stype in BLOCKS_WITH_CHAIN:
        return truthy(chain) if visible else None
    return None


def can_snapshot(stype: Any, volname: str) -> bool | None:
    """Whether this volume can be snapshotted at all (the safety snapshot snapshots the CURRENT
    config's volumes): True, False, or None when the storage type is not settled. File-based and
    thick LVM storage snapshot a `.qcow2` and nothing else: `Plugin.pm volume_has_feature` lists
    `snapshot` for qcow2 only, and the API asks it before `volume_snapshot` (a `.qed` is refused)."""
    if stype in ALWAYS_SNAPSHOTTABLE:
        return True
    if stype in FILE_BASED or stype == "lvm":
        return volname.endswith(".qcow2")
    return None


def _type_of(definition: Any) -> str | None:
    """The storage type of a definition, only if it is TEXT: the answer is the vendor's, and a list or
    a mapping where a type belongs (unhashable: it would crash a set test) is no type at all, which
    reads as unsettled."""
    stype = definition.get("type") if isinstance(definition, Mapping) else None
    return stype if isinstance(stype, str) and stype else None


JUDGEMENT_FAILED = "the storage judgement failed"


def judge_blocking(volumes: list[tuple[str, str]], definitions: Mapping[str, Mapping[str, Any]] | None,
                   visible: bool) -> dict[str, list[str]]:
    """{blocked: [types], unsettled: [reasons]} for the volumes a rollback would restore (the target
    snapshot's own)."""
    blocked: set[str] = set()
    unsettled: set[str] = set()
    for sid in sorted({s for s, _ in volumes}):
        d = (definitions or {}).get(sid)
        stype = _type_of(d)
        verdict = blocks(stype, d.get(CHAIN_FLAG) if isinstance(d, Mapping) else None, visible) if stype else None
        if verdict is True:
            blocked.add(str(stype))
        elif verdict is None:
            unsettled.add(_why_unsettled(stype, visible))
    return {"blocked": sorted(blocked), "unsettled": sorted(unsettled)}


DEVICE_REASON = "a bind mount or passthrough device that is not a storage volume"


def judge_snapshottable(volumes: list[tuple[str, str]], definitions: Mapping[str, Mapping[str, Any]] | None,
                        devices: int = 0) -> dict[str, list[str]]:
    """{cannot: [reasons], unsettled: [reasons]} for the volumes the safety snapshot would snapshot
    (the CURRENT config's), and `devices` path mounts among them."""
    cannot: set[str] = {DEVICE_REASON} if devices else set()
    unsettled: set[str] = set()
    for sid, vol in volumes:
        d = (definitions or {}).get(sid)
        stype = _type_of(d)
        verdict = can_snapshot(stype, vol) if stype else None
        if verdict is False:
            cannot.add(f"{stype}: a volume in a format that cannot be snapshotted")   # False only for FILE_BASED/lvm
        elif verdict is None:
            unsettled.add(_why_unsettled(stype, True))
    return {"cannot": sorted(cannot), "unsettled": sorted(unsettled)}


#: The storage types this module names. Anything else is printed as "other storage type": the
#: type string comes from a vendor answer and the answer reaches the caller, so what it says is
#: chosen from this closed set and never copied (the net's reads taint nothing, on that premise).
KNOWN_TYPES = (BLOCKS_ALWAYS | BLOCKS_WITH_CHAIN | NEVER_BLOCKS | ALWAYS_SNAPSHOTTABLE
               | frozenset({"iscsi", "iscsidirect", "pbs", "zfs", "lvm", "lvmthin", "dir", "nfs"}))


def _why_unsettled(stype: Any, visible: bool) -> str:
    if stype in BLOCKS_WITH_CHAIN and not visible:
        return f"{stype} (its snapshot-as-volume-chain setting is not readable here)"
    if not stype:
        return "unknown"
    return str(stype) if stype in KNOWN_TYPES else "other storage type"
