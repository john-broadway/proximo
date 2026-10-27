"""The estate model: what the vendor's own answers say is there, as plain records and the relations
between them. Pure: no I/O, no engine, no wire. A judge reads an `Estate`, never a vendor answer.

    answers (published GETs, read through engine.execute by consult)   ->   build()   ->   Estate
        /cluster/resources                       guests, nodes, storage (as the cluster sees it)
        /nodes/{node}/qemu|lxc/{vmid}/config     a guest's disks and NICs
        /storage                                 storage definitions (shared, content, nodes)
        /nodes/{node}/storage/{storage}/content  volumes (backups, images, ISOs)
        /cluster/backup                          backup jobs
        /pools                                   pools and their members
        /nodes/{node}/network                    a node's interfaces (bridges)

The relations are the edges a judge asks about: `guests_on_storage`, `guests_on_bridge`, `disks_of`,
`disks_using`, `backups_of`, `jobs_covering`, `guests_in_pool`.

A FIELD THE VENDOR OMITTED IS UNKNOWN, NOT ZERO. Every record field is `X | None`: a guest row with no
`status` is not stopped, a storage with no `shared` is not local, a pool listed without `members` is
not empty. A judge that reads None as false would call an unknown safe, which is the one thing the
consult seam (`proximo.core.consult`) exists not to do. Likewise a guest whose config was not read, or
came back empty, is in `Estate.unread`: a failed read, never "a guest with no disks" (0.44's rule in
`gather_storage_dependents`).

An answer of the WRONG SHAPE is not an empty one. A list source that answered something other than
a list, or a guest row in `/cluster/resources` with no vmid to key it by, lands in
`Estate.malformed` with the reason: "no guests listed" from a garbled answer is a failed read too.

A guest's config has two views, and the estate keeps every disk either names (the union). PVE's
`GET .../pending` ("the virtual machine configuration with both current and pending values") is a
list of rows `{key, value, pending, delete}`: `value` is what the guest runs with now, `pending`
what it takes at its next start, and `delete` marks a key a pending change removes. A disk named
in `value` is in use now, even when its key is marked for delete (a running guest without hotplug
still has it attached); a disk named only in `pending` is the guest's on its next start. A guest
read through more than one answer (a `/config` and a `/pending`) is the union of them all.

The disk-key and volid rules are 0.44's (`git show 2d87019^:src/proximo/blast.py`: `_DISK_KEY_RE`,
`_storage_of_volid`, `_boot_slot`, the cdrom exclusion, `_backup_job_coverage`), with two additions:
`vmstate` (a hibernated guest's saved memory, which `qm suspend --todisk` writes into the config)
is a disk key, and a volume is matched by its name's path COMPONENTS on the same storage
(`disks_using`), because a linked clone names its disk through its base and the vendor resolves
the short name to the same volume.

To feed a new source: add its published GET template to `SOURCES`, a constructor for its answer, and a
branch in `build`; `tests/test_estate.py` holds every source to a published GET.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple

# A guest config key that holds a DATA volume: never a NIC, a name, or a boot order (0.44 blast.py).
_DISK_KEY_RE = re.compile(r"^(?:rootfs|vmstate|(?:efidisk|tpmstate|scsi|sata|ide|virtio|mp|unused)\d+)$")
_NET_KEY_RE = re.compile(r"^net\d+$")
#: Boot-critical even when not the boot disk: the UEFI variable store and the TPM state (0.44's
#: doctrine: over-flag their loss as won't-boot rather than under-flag; the slots exist only when used),
#: and a hibernated guest's saved memory (`vmstate`: without it the guest cannot resume, and starts
#: only once its config is repaired by hand).
BOOT_CRITICAL = frozenset({"efidisk0", "tpmstate0", "vmstate"})
GUEST_KINDS = ("qemu", "lxc")

#: The sources whose answer is a list of rows; any other shape is malformed, never "no rows".
_PENDING = frozenset({"/nodes/{node}/qemu/{vmid}/pending", "/nodes/{node}/lxc/{vmid}/pending"})
_LIST_SOURCES = frozenset({"/cluster/resources", "/storage", "/nodes/{node}/storage/{storage}/content",
                           "/cluster/backup", "/pools", "/nodes/{node}/network"}) | _PENDING

#: The published GETs an estate is built from. `tests/test_estate.py` resolves each one on pve.
SOURCES = (
    "/cluster/resources",
    "/nodes/{node}/qemu/{vmid}/config",
    "/nodes/{node}/lxc/{vmid}/config",
    "/nodes/{node}/qemu/{vmid}/pending",
    "/nodes/{node}/lxc/{vmid}/pending",
    "/storage",
    "/nodes/{node}/storage/{storage}/content",
    "/cluster/backup",
    "/pools",
    "/nodes/{node}/network",
    "/access/permissions",
)


# ---- the vendor's spellings, read without guessing ---------------------------------------------------

def _str(v: Any) -> str | None:
    """A name or an id as a string; None when absent, empty or not a scalar."""
    if v is None or isinstance(v, (dict, list, tuple)):
        return None
    s = str(v).strip()
    return s or None


def _flag(v: Any) -> bool | None:
    """Proxmox's booleans (0/1, "0"/"1", true/false); None when absent or not one of them."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ("0", "1", "true", "false"):
        return v.strip().lower() in ("1", "true")
    return None


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


def _list(v: Any, sep: str = ",") -> tuple[str, ...] | None:
    """A comma (or other) separated vendor list; None when absent. An empty string is an empty list."""
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        return tuple(s for s in (_str(x) for x in v) if s)
    if not isinstance(v, str):
        return None
    return tuple(s.strip() for s in re.split(sep, v) if s.strip())


def is_disk_key(key: str) -> bool:
    return bool(_DISK_KEY_RE.match(key))


def storage_of_volid(value: str) -> str | None:
    """The storage a disk value names: `nas:101/vm-101-disk-0.qcow2,size=32G` -> `nas`. None for
    `none`, a raw path (`/dev/...`), or anything without a `storage:volume` shape (0.44)."""
    head = value.split(",", 1)[0].strip()
    if ":" not in head:
        return None
    storage, _, rest = head.partition(":")
    storage, rest = storage.strip(), rest.strip()
    if not storage or not rest or "/" in storage:
        return None
    return storage


def boot_slot(config: Mapping[str, Any], kind: str) -> str | None:
    """The slot holding the boot disk, or None when the config does not say (0.44): a container
    boots from `rootfs`; a VM from `bootdisk`, else the first disk in `boot: order=...`."""
    if kind == "lxc":
        return "rootfs" if "rootfs" in config else None
    bootdisk = config.get("bootdisk")
    if isinstance(bootdisk, str) and bootdisk.strip():
        return bootdisk.strip()
    boot = config.get("boot")
    if isinstance(boot, str) and "order=" in boot:
        for tok in re.split(r"[;,]", boot.split("order=", 1)[1]):
            if is_disk_key(tok.strip()):
                return tok.strip()
    return None


# ---- the records -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Guest:
    kind: str                     # "qemu" | "lxc"
    vmid: str
    node: str | None = None
    name: str | None = None       # guest-authored text: the session that read it is tainted already
    status: str | None = None
    template: bool | None = None
    pool: str | None = None
    tags: tuple[str, ...] | None = None
    boot: str | None = None       # the boot slot, from the config when it was read

    @property
    def key(self) -> str:
        return f"{self.kind}/{self.vmid}"

    @property
    def running(self) -> bool | None:
        return None if self.status is None else self.status == "running"


@dataclass(frozen=True)
class Node:
    name: str
    status: str | None = None


@dataclass(frozen=True)
class Storage:
    id: str
    node: str | None = None                       # set on a /cluster/resources row (one per node)
    type: str | None = None
    shared: bool | None = None
    content: tuple[str, ...] | None = None
    nodes: tuple[str, ...] | None = None          # the definition's node restriction; None: unknown or all
    disabled: bool | None = None
    status: str | None = None


@dataclass(frozen=True)
class Disk:
    guest: str                    # Guest.key
    slot: str
    value: str                    # the config value as the vendor wrote it
    volid: str | None             # `storage:volume`; None for a raw path or `none`
    storage: str | None
    cdrom: bool                   # removable media, not the guest's data


@dataclass(frozen=True)
class Nic:
    guest: str
    slot: str
    bridge: str | None


@dataclass(frozen=True)
class Pool:
    id: str
    members: tuple[str, ...] | None = None        # resource ids ("qemu/101"); None when not listed


@dataclass(frozen=True)
class BackupJob:
    id: str
    enabled: bool | None = None
    all: bool | None = None
    vmids: tuple[str, ...] | None = None
    pool: str | None = None
    exclude: tuple[str, ...] | None = None
    storage: str | None = None
    node: str | None = None
    schedule: str | None = None


@dataclass(frozen=True)
class Volume:
    volid: str
    storage: str | None = None
    content: str | None = None
    vmid: str | None = None
    size: int | None = None
    ctime: int | None = None
    format: str | None = None
    protected: bool | None = None


@dataclass(frozen=True)
class Iface:
    node: str
    iface: str
    type: str | None = None
    active: bool | None = None
    cidr: str | None = None
    ports: tuple[str, ...] | None = None


# ---- constructors: one vendor answer each ------------------------------------------------------------

def _rows(answer: Any) -> list[dict]:
    return [r for r in answer if isinstance(r, dict)] if isinstance(answer, list) else []


def _guest_vmid(r: Mapping[str, Any], kind: str) -> str | None:
    vmid = _str(r.get("vmid"))
    if vmid is None and isinstance(r.get("id"), str) and r["id"].startswith(f"{kind}/"):
        vmid = _str(r["id"].partition("/")[2])
    return vmid


def shape_problems(template: str, answer: Any) -> tuple[str, ...]:
    """Why an answer from `template` cannot be read whole: a list source that is not a list, and in
    `/cluster/resources` a row that is not a record or a guest row with no vmid to key it by. A
    constructor skips such rows; this names them, so a consult reads them as a gap."""
    if template == "/access/permissions":
        return () if permission_map(answer) is not None else (f"GET {template} answered no permission map",)
    if template not in _LIST_SOURCES:
        return ()
    if not isinstance(answer, list):
        return (f"GET {template} answered {type(answer).__name__}, not a list of rows",)
    if template in _PENDING:
        out, seen = [], set()
        for i, r in enumerate(answer):
            key = _pending_key(r)
            if key is None:
                out.append(f"GET {template} row {i} is not a {{key, value, pending}} record")
            elif key in seen:                   # two rows for one key: which one is the guest's is unknown
                out.append(f"GET {template} row {i} repeats the key {key}")
            elif any(f in r and r[f] is None for f in ("value", "pending")):
                # the vendor gives a value or leaves the field out: a null is not its row
                out.append(f"GET {template} row {i} ({key}) carries a null value")
            seen.add(key or "")
        return tuple(out)
    if template != "/cluster/resources":
        return ()
    out = []
    for i, r in enumerate(answer):
        if not isinstance(r, dict):
            out.append(f"GET {template} row {i} is {type(r).__name__}, not a record")
        elif r.get("type") in GUEST_KINDS and _guest_vmid(r, r["type"]) is None:
            out.append(f"GET {template} row {i} is a {r['type']} guest with no vmid")
    return tuple(out)


def guests_from_resources(rows: Any) -> tuple[Guest, ...]:
    out = []
    for r in _rows(rows):
        kind = r.get("type")
        if kind not in GUEST_KINDS:
            continue
        vmid = _guest_vmid(r, kind)
        if vmid is None:
            continue
        out.append(Guest(kind=kind, vmid=vmid, node=_str(r.get("node")), name=_str(r.get("name")),
                         status=_str(r.get("status")), template=_flag(r.get("template")),
                         pool=_str(r.get("pool")), tags=_list(r.get("tags"), r"[;,\s]")))
    return tuple(out)


def nodes_from_resources(rows: Any) -> tuple[Node, ...]:
    return tuple(Node(name=n, status=_str(r.get("status"))) for r in _rows(rows)
                 if r.get("type") == "node" and (n := _str(r.get("node"))))


def storages_from_resources(rows: Any) -> tuple[Storage, ...]:
    return tuple(Storage(id=s, node=_str(r.get("node")), type=_str(r.get("plugintype")),
                         shared=_flag(r.get("shared")), content=_list(r.get("content")),
                         status=_str(r.get("status")))
                 for r in _rows(rows) if r.get("type") == "storage" and (s := _str(r.get("storage"))))


def storages_from_config(rows: Any) -> tuple[Storage, ...]:
    """`GET /storage`: the definitions. `nodes` absent means every node, which the estate cannot
    tell from 'not reported', so it stays None."""
    return tuple(Storage(id=s, type=_str(r.get("type")), shared=_flag(r.get("shared")),
                         content=_list(r.get("content")), nodes=_list(r.get("nodes")),
                         disabled=_flag(r.get("disable")))
                 for r in _rows(rows) if (s := _str(r.get("storage"))))


def permission_map(perms: Any) -> dict[str, dict[str, bool]] | None:
    """{path: {privilege: propagate}} from the token's whole `GET /access/permissions`, or None when
    the answer is not a permission map (empty, not a map of maps, a value that is no 0/1 flag,
    a null included: the vendor writes 1 or 0, so anything else is not its map). A path that holds
    nothing is KEPT (`{"/vms/105": {}}`): a defined key decides its path alone, and an empty one
    there is a guest the token cannot see."""
    if not isinstance(perms, dict) or not perms or not all(isinstance(v, dict) for v in perms.values()):
        return None
    out: dict[str, dict[str, bool]] = {}
    for path, held in perms.items():
        out[str(path)] = {}
        for priv, propagate in held.items():
            if not (isinstance(propagate, bool) or (isinstance(propagate, int) and propagate in (0, 1))):
                return None
            out[str(path)][str(priv)] = bool(propagate)
    return out


def _pending_key(r: Any) -> str | None:
    """A pending row's option name: a non-empty string, or None (a number is no option name)."""
    key = r.get("key") if isinstance(r, dict) else None
    return (key.strip() or None) if isinstance(key, str) else None


def views_from_pending(rows: Any) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """`GET .../pending` as two configs: (current, next start). None when it is not a list. A key
    marked `delete` stays in the current view (still in use now) and leaves the next-start view; a
    key with `pending` takes that value at the next start."""
    if not isinstance(rows, list):
        return None
    current: dict[str, Any] = {}
    after: dict[str, Any] = {}
    for r in rows:
        key = _pending_key(r)
        if key is None:
            continue
        if "value" in r:
            current[key] = r["value"]
        if r.get("delete") not in (None, 0, "0", False):
            continue
        if "pending" in r:
            after[key] = r["pending"]
        elif "value" in r:
            after[key] = r["value"]
    return current, after


def disks_from_config(kind: str, vmid: str, config: Any) -> tuple[Disk, ...]:
    if not isinstance(config, Mapping):
        return ()
    out = []
    for key, val in config.items():
        if not isinstance(key, str) or not isinstance(val, str) or not is_disk_key(key):
            continue
        storage = storage_of_volid(val)
        out.append(Disk(guest=f"{kind}/{vmid}", slot=key, value=val,
                        volid=val.split(",", 1)[0].strip() if storage else None, storage=storage,
                        cdrom="media=cdrom" in val))
    return tuple(sorted(out, key=lambda d: d.slot))


def nics_from_config(kind: str, vmid: str, config: Any) -> tuple[Nic, ...]:
    """`netN` slots and the bridge each names, by TOKEN (`bridge=vmbr1` is not `bridge=vmbr10`)."""
    if not isinstance(config, Mapping):
        return ()
    out = []
    for key, val in config.items():
        if not isinstance(key, str) or not isinstance(val, str) or not _NET_KEY_RE.match(key):
            continue
        bridge = next((t.strip()[len("bridge="):] for t in val.split(",") if t.strip().startswith("bridge=")), "")
        out.append(Nic(guest=f"{kind}/{vmid}", slot=key, bridge=bridge.strip() or None))
    return tuple(sorted(out, key=lambda n: n.slot))


def volumes_from_content(storage: str, rows: Any) -> tuple[Volume, ...]:
    return tuple(Volume(volid=v, storage=storage, content=_str(r.get("content")), vmid=_str(r.get("vmid")),
                        size=_int(r.get("size")), ctime=_int(r.get("ctime")), format=_str(r.get("format")),
                        protected=_flag(r.get("protected")))
                 for r in _rows(rows) if (v := _str(r.get("volid"))))


def jobs_from_backup(rows: Any) -> tuple[BackupJob, ...]:
    return tuple(BackupJob(id=i, enabled=_flag(r.get("enabled")), all=_flag(r.get("all")),
                           vmids=_list(r.get("vmid")), pool=_str(r.get("pool")), exclude=_list(r.get("exclude")),
                           storage=_str(r.get("storage")), node=_str(r.get("node")),
                           schedule=_str(r.get("schedule")))
                 for r in _rows(rows) if (i := _str(r.get("id"))))


def pools_from_pools(rows: Any) -> tuple[Pool, ...]:
    out = []
    for r in _rows(rows):
        pid = _str(r.get("poolid"))
        if pid is None:
            continue
        members = r.get("members")
        ids = (tuple(m for m in (_str(x.get("id")) for x in members if isinstance(x, dict)) if m)
               if isinstance(members, list) else None)
        out.append(Pool(id=pid, members=ids))
    return tuple(out)


def ifaces_from_network(node: str, rows: Any) -> tuple[Iface, ...]:
    return tuple(Iface(node=node, iface=i, type=_str(r.get("type")), active=_flag(r.get("active")),
                       cidr=_str(r.get("cidr")), ports=_list(r.get("bridge_ports"), r"[\s,]"))
                 for r in _rows(rows) if (i := _str(r.get("iface"))))


# ---- the estate --------------------------------------------------------------------------------------

class Answer(NamedTuple):
    """One read's answer: the published GET template it came from, the values that filled the
    template's placeholders, and the vendor's data (unfenced, withheld as the door withholds it)."""

    template: str
    bound: Mapping[str, str]
    data: Any


@dataclass(frozen=True)
class Estate:
    guests: tuple[Guest, ...] = ()
    nodes: tuple[Node, ...] = ()
    storages: tuple[Storage, ...] = ()
    disks: tuple[Disk, ...] = ()
    nics: tuple[Nic, ...] = ()
    pools: tuple[Pool, ...] = ()
    jobs: tuple[BackupJob, ...] = ()
    volumes: tuple[Volume, ...] = ()
    ifaces: tuple[Iface, ...] = ()
    unread: frozenset[str] = frozenset()      # guests whose config is not known: never "no disks"
    read: frozenset[str] = frozenset()        # the SOURCES templates this estate was built from
    malformed: tuple[str, ...] = ()           # answers of the wrong shape: a failed read, never "none"
    permissions: Mapping[str, Mapping[str, bool]] | None = None   # the token's map, as permission_map reads it

    def sees_every(self, priv: str, base: str) -> bool | None:
        """Whether the token holds `priv` on every entry under `base` (VM.Audit under /vms: every
        guest), read from its whole permission map. PVE: a more specific ACL path replaces what is
        inherited there, so the MOST SPECIFIC DEFINED key on the way to `base` decides (`base`
        itself if defined, else its nearest defined ancestor, up to `/`), and must hold `priv`
        propagating; and every key defined below `base` must hold `priv` (one that lacks it is an
        entry the token cannot see; one that holds it, propagating or not, is seen). For guests a
        pool path counts too: PVE scopes a guest by its pool's ACL as well as its own path, and the
        map does not say who is in a pool, so `/pool` or `/pool/<id>` defined without `priv` may be
        the path that hides a member and reads as blind (the safe side). None when the map was not
        read. The token-sight check (`proximo.core.sight`) reads the same map; the two readings are
        to become one."""
        perms = self.permissions
        if perms is None:
            return None
        on_the_way = [base] + [base[:i] or "/" for i in range(len(base) - 1, -1, -1) if base[i] == "/"]
        decider = next((p for p in on_the_way if p in perms), None)
        if decider is None or perms[decider].get(priv) is not True:
            return False
        below = [base.rstrip("/") + "/"]
        if base == "/vms":
            below.append("/pool/")
        return all(priv in held for p, held in perms.items()
                   if any(p.startswith(b) for b in below) or (base == "/vms" and p == "/pool"))

    def guest(self, key: str) -> Guest | None:
        return next((g for g in self.guests if g.key == key), None)

    def disks_of(self, guest: str) -> tuple[Disk, ...]:
        return tuple(d for d in self.disks if d.guest == guest)

    def disks_using(self, volid: str) -> tuple[Disk, ...]:
        """The DATA disks that may BE `volid`: on the same storage, a disk whose volume name has the
        volid's last path component as one of its own components (`base-100-disk-0/vm-101-disk-0`
        is `vm-101-disk-0`, and it is built on `base-100-disk-0`; `100/base-100-disk-0.qcow2/101/
        vm-101-disk-0.qcow2` is `101/vm-101-disk-0.qcow2`). Whole components, so `vm-101-disk-00`
        is not `vm-101-disk-0`. This may over-match a spelling the vendor would tell apart (its
        `parse_volname` is not read here), which is the louder, safe side. A cdrom mount is not the
        guest's data (0.44)."""
        storage, _, name = volid.partition(":")
        want = name.rstrip("/").rpartition("/")[2]
        if not want:
            return ()
        return tuple(d for d in self.disks if not d.cdrom and d.volid and d.storage == storage
                     and want in d.volid.partition(":")[2].split("/"))

    def guests_on_storage(self, storage: str) -> tuple[Guest, ...]:
        on = {d.guest for d in self.disks if d.storage == storage and not d.cdrom}
        return tuple(g for g in self.guests if g.key in on)

    def guests_on_bridge(self, bridge: str) -> tuple[Guest, ...]:
        on = {n.guest for n in self.nics if n.bridge == bridge}
        return tuple(g for g in self.guests if g.key in on)

    def backups_of(self, vmid: str) -> tuple[Volume, ...]:
        return tuple(v for v in self.volumes if v.content == "backup" and v.vmid == str(vmid))

    def _in_pool(self, vmid: str, poolid: str) -> bool | None:
        pool = next((p for p in self.pools if p.id == poolid), None)
        if pool is not None and pool.members is not None:
            return any(m.rpartition("/")[2] == vmid for m in pool.members)
        guest = next((g for g in self.guests if g.vmid == vmid), None)
        if guest is not None and guest.pool is not None:
            return guest.pool == poolid
        return None

    def jobs_covering(self, vmid: str) -> tuple[tuple[BackupJob, bool | None], ...]:
        """Each backup job and whether its selection covers `vmid`: True, False, or None when it
        cannot be told (a pool job whose members were not read; a selection of no recognised shape).
        0.44's `_backup_job_coverage`, kept whole: all-mode minus excludes, pool membership minus
        excludes, an explicit vmid list."""
        vmid = str(vmid)
        out = []
        for j in self.jobs:
            excluded = vmid in (j.exclude or ())
            if j.all is True:
                covered: bool | None = not excluded
            elif j.pool:
                member = self._in_pool(vmid, j.pool)
                covered = None if member is None else member and not excluded
            elif j.vmids:
                covered = vmid in j.vmids
            else:
                covered = None
            out.append((j, covered))
        return tuple(out)

    def guests_in_pool(self, poolid: str) -> tuple[Guest, ...]:
        return tuple(g for g in self.guests if self._in_pool(g.vmid, poolid))


def build(answers: Iterable[Answer]) -> Estate:
    """An Estate from the answers a consult read (any subset of SOURCES, in any order). An answer
    from a template the estate does not read is refused (a judge declaring a read nothing consumes)."""
    guests: dict[str, Guest] = {}
    configs: dict[str, list[Any]] = {}
    parts: dict[str, list] = {k: [] for k in ("nodes", "storages", "pools", "jobs", "volumes", "ifaces")}
    read: set[str] = set()
    malformed: list[str] = []
    permissions = None
    for a in answers:
        if a.template not in SOURCES:
            raise ValueError(f"the estate is not built from {a.template}; it reads {', '.join(SOURCES)}")
        read.add(a.template)
        malformed += shape_problems(a.template, a.data)
        if a.template == "/cluster/resources":
            for g in guests_from_resources(a.data):
                guests.setdefault(g.key, g)
            parts["nodes"] += nodes_from_resources(a.data)
            parts["storages"] += storages_from_resources(a.data)
        elif a.template.endswith(("/config", "/pending")):
            kind = a.template.split("/")[3]
            vmid, node = str(a.bound.get("vmid", "")), _str(a.bound.get("node"))
            guests.setdefault(f"{kind}/{vmid}", Guest(kind=kind, vmid=vmid, node=node))
            # a pending answer that is not a list is no view at all (malformed above), never a config
            views = (views_from_pending(a.data) or ()) if a.template in _PENDING else (a.data,)
            configs.setdefault(f"{kind}/{vmid}", []).extend(views)
        elif a.template == "/storage":
            parts["storages"] += storages_from_config(a.data)
        elif a.template.endswith("/content"):
            parts["volumes"] += volumes_from_content(str(a.bound.get("storage", "")), a.data)
        elif a.template == "/cluster/backup":
            parts["jobs"] += jobs_from_backup(a.data)
        elif a.template == "/pools":
            parts["pools"] += pools_from_pools(a.data)
        elif a.template == "/access/permissions":
            permissions = permission_map(a.data)
        elif a.template.endswith("/network"):
            parts["ifaces"] += ifaces_from_network(str(a.bound.get("node", "")), a.data)
    disks, nics, unread, ordered = [], [], set(), []
    for key, g in guests.items():
        # An EMPTY config is a failed read: a real guest config is never empty (0.44).
        landed = [cfg for cfg in configs.get(key, ()) if isinstance(cfg, Mapping) and cfg]
        if not landed:
            unread.add(key)
            ordered.append(g)
            continue
        seen_disks: dict[tuple[str, str], Disk] = {}
        seen_nics: dict[tuple[str, str | None], Nic] = {}
        malformed += sorted({f"{key} {k} is a disk key whose value is {type(v).__name__}, not a volume"
                             for cfg in landed for k, v in cfg.items()
                             if isinstance(k, str) and is_disk_key(k) and v is not None and not isinstance(v, str)})
        for cfg in landed:           # the union of the views: a disk any view names is the guest's
            seen_disks.update(((d.slot, d.value), d) for d in disks_from_config(g.kind, g.vmid, cfg))
            seen_nics.update(((n.slot, n.bridge), n) for n in nics_from_config(g.kind, g.vmid, cfg))
        disks += sorted(seen_disks.values(), key=lambda d: (d.slot, d.value))
        nics += sorted(seen_nics.values(), key=lambda n: (n.slot, n.bridge or ""))
        boot = next((b for cfg in landed if (b := boot_slot(cfg, g.kind))), None)
        # the name the resources read was not asked for (consult keeps that read narrow so a big
        # estate fits the door's cap) comes from the guest's own config: guest-authored either way
        name = g.name or next((n for cfg in landed if (n := _str(cfg.get("name" if g.kind == "qemu"
                                                                         else "hostname")))), None)
        ordered.append(Guest(**{**g.__dict__, "boot": boot, "name": name}))
    return Estate(guests=tuple(ordered), nodes=tuple(parts["nodes"]), storages=tuple(parts["storages"]),
                  disks=tuple(disks), nics=tuple(nics), pools=tuple(parts["pools"]), jobs=tuple(parts["jobs"]),
                  volumes=tuple(parts["volumes"]), ifaces=tuple(parts["ifaces"]), unread=frozenset(unread),
                  read=frozenset(read), malformed=tuple(malformed), permissions=permissions)
