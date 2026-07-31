"""PLAN pillar — dry-run preview + honest, heuristic risk classification.

Pure functions (no I/O except the one safe read in plan_power, which calls the API's
guest_status to report live state). The classifiers are deliberately HEURISTIC tripwires,
not sandboxes: they err toward caution (over-flagging is fine), scan the WHOLE command/SQL
(not just the leading token), and never claim a change is "safe" — only that it does or does
not match a destructive pattern. This is the PROVE-redteam lesson applied: do not overclaim.

Two load-bearing principles (guard every path to LOW):
- LOW means "does not change state", NOT "safe" — a read can still exfiltrate (`cat /etc/shadow`).
  A command/statement is rated LOW only in a known read-only FORM, never as a guess.
- The absence of a HIGH flag is NOT a safety signal. HIGH signatures are curated, not exhaustive.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .backends import _check_kind, _check_vmid

# --- risk levels (plain strings, matching the codebase style) ---
RISK_NONE = "none"
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

_RISK_ORDER = {RISK_NONE: 0, RISK_LOW: 1, RISK_MEDIUM: 2, RISK_HIGH: 3}

_HEURISTIC_NOTE = (
    "heuristic classification — advisory only, not a guarantee. LOW means 'does not change state', "
    "NOT 'safe' (a read can still exfiltrate). The absence of a HIGH flag is not a safety signal. "
    "Review the change yourself."
)


def _max_risk(a: str, b: str) -> str:
    # Defensive: an unknown risk string sorts as lowest rather than raising KeyError.
    return a if _RISK_ORDER.get(a, 0) >= _RISK_ORDER.get(b, 0) else b


@dataclass
class Plan:
    """A previewed-but-not-executed change. Returned by the dry-run gate; recorded to the ledger."""

    action: str               # "pve_guest_power" | "ct_exec" | "ct_psql"
    target: str               # "lxc/1975" | "<ctid>"
    change: str               # human summary of what WOULD happen
    current: dict             # live facts (power); {} for exec/psql
    blast_radius: list[str]
    risk: str                 # one of RISK_*
    risk_reasons: list[str]
    to_proceed: str = "re-call with confirm=true"
    note: str = ""            # honesty disclaimer for heuristic classifications
    affected: list[dict] = field(default_factory=list)  # computed downstream impact (blast engine)
    complete: bool = True     # False => the blast computation was incomplete (a read failed) — honesty signal

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "change": self.change,
            "current": self.current,
            "blast_radius": self.blast_radius,
            "risk": self.risk,
            "risk_reasons": self.risk_reasons,
            "to_proceed": self.to_proceed,
            "note": self.note,
            "affected": self.affected,
            "complete": self.complete,
        }


# --- power planning -----------------------------------------------------------

def _fmt_uptime(secs) -> str:
    if not isinstance(secs, (int, float)) or not math.isfinite(secs) or secs <= 0:
        return ""
    secs = int(secs)
    if secs >= 86400:
        return f" (uptime {secs // 86400}d)"
    if secs >= 3600:
        return f" (uptime {secs // 3600}h)"
    return f" (uptime {secs // 60}m)"


def plan_power(api, vmid: str, action: str, kind: str = "lxc", node: str | None = None) -> Plan:
    """Preview a power action. Reads live guest_status (a safe read) for facts + no-op detection."""
    _check_vmid(vmid)
    _check_kind(kind)
    cur = api.guest_status(vmid, kind, node)
    status = str(cur.get("status", "unknown"))
    running = status == "running"
    current = {k: cur[k] for k in ("status", "name", "uptime", "cpu", "mem", "maxmem") if k in cur}
    change = f"{action} {kind} {vmid}"
    blast: list[str] = []
    reasons: list[str] = []

    if action == "start" and running:
        risk = RISK_NONE
        blast = ["no-op: already running"]
    elif action in ("stop", "shutdown") and not running:
        risk = RISK_NONE
        blast = [f"no-op: already {status}"]
    elif action == "start":
        risk = RISK_LOW
        reasons = ["bringing a guest up"]
    elif action == "shutdown":
        risk = RISK_MEDIUM
        reasons = ["graceful ACPI shutdown of a running guest"]
    elif action == "stop":
        risk = RISK_HIGH
        reasons = ["hard stop (power pull) of a running guest"]
    elif action == "reboot":
        risk = RISK_HIGH
        reasons = ["reboot (stop+start) of a running guest"]
    else:
        risk = RISK_MEDIUM
        reasons = [f"unrecognized action: {action}"]

    if running and action in ("stop", "shutdown", "reboot"):
        blast = [f"1 running guest will halt{_fmt_uptime(cur.get('uptime'))}"]

    return Plan(
        action="pve_guest_power", target=f"{kind}/{vmid}:{action}", change=change,
        current=current, blast_radius=blast, risk=risk, risk_reasons=reasons,
    )


# --- command classification ---------------------------------------------------

# First tokens that only read state, in ANY form. (Commands with mutating sub-forms — find, ip,
# mount, systemctl, env — are deliberately NOT here; they're handled conditionally below so a
# mutating form can never inherit a read pass. Guard every path to LOW.)
_READ_COMMANDS = frozenset({
    "cat", "ls", "grep", "egrep", "fgrep", "journalctl", "ps", "df", "free", "stat", "head", "tail",
    "echo", "pwd", "whoami", "id", "uptime", "date", "hostname", "uname", "printenv", "which",
    "wc", "du", "top", "ss", "netstat", "lsblk", "getent", "dmesg", "lscpu",
})
# systemctl is read-only ONLY for these subcommands; mask/unmask/kill are escalated to HIGH.
_SYSTEMCTL_READ = frozenset({
    "status", "is-active", "is-enabled", "is-failed", "show", "list-units", "list-unit-files",
    "cat", "get-default",
})
_SYSTEMCTL_HIGH = frozenset({"mask", "unmask", "kill"})
# Whitelisted-but-conditional: read-only EXCEPT when an argv token names a mutating sub-form.
_CONDITIONAL_READ: dict[str, frozenset[str]] = {
    "ip": frozenset({"add", "del", "delete", "set", "change", "replace", "flush", "append", "prepend"}),
    "find": frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir",
                       "-fprintf", "-fls", "-fprint", "-fprint0"}),
}

# Destructive patterns scanned over the WHOLE joined command (catches sh -c "..." wrappers too).
# Curated, NOT exhaustive — false-HIGH is safe; the absence of a HIGH flag is not a safety signal.
_DANGEROUS_CMD: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\b\s+(?:-\S+\s+)*-\S*r", re.I), "rm -rf"),
    (re.compile(r"\bdd\b\s+(?:if=|of=)", re.I), "dd"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", re.I), "mkfs"),
    (re.compile(r"\bwipefs\b", re.I), "wipefs"),
    (re.compile(r"\b(?:fdisk|parted|sgdisk|mkswap)\b", re.I), "disk partitioning"),
    (re.compile(r"\b(?:lvremove|vgremove|pvremove)\b", re.I), "LVM removal"),
    (re.compile(r"\bcryptsetup\b\s+(?:luks(?:format|erase)|erase)\b", re.I), "cryptsetup destructive"),
    (re.compile(r"\bshred\b", re.I), "shred"),
    (re.compile(r"\bfind\b.*\s-(?:delete|exec|execdir|ok|okdir)\b", re.I), "find -delete/-exec"),
    (re.compile(r":\(\)\s*\{", re.I), "fork bomb"),
    (re.compile(r">\s*/dev/", re.I), "redirect to /dev"),
    (re.compile(r">\s*/etc/", re.I), "overwrite under /etc"),
    (re.compile(r"\bch(?:mod|own)\b\s+(?:-\S+\s+)*-\S*r", re.I), "recursive chmod/chown"),
    (re.compile(r"\bchmod\b[^&|;]*(?:\+s|u\+s|g\+s|\b[0-7]?[4-7][0-7]{3}\b)", re.I), "chmod setuid/setgid"),
    (re.compile(r"\b(?:mv|cp|tee)\b[^&|;]*(?:/etc/|/dev/|\.ssh/)", re.I), "write to sensitive path"),
    (re.compile(r"\b(?:iptables|ip6tables)\b[^&|;]*-[FXZ]\b", re.I), "iptables flush"),
    (re.compile(r"\bnft\b[^&|;]*\bflush\b", re.I), "nft flush"),
    (re.compile(r"\buserdel\b", re.I), "userdel"),
    (re.compile(r"\buseradd\b[^&|;]*-[ou]\b", re.I), "useradd (override/uid)"),
    (re.compile(r"\bcrontab\b[^&|;]*-r\b", re.I), "crontab -r"),
    (re.compile(r"\bpasswd\b", re.I), "passwd change"),
    (re.compile(r"\bkill\b\s+(?:-\S+\s+)*1\b", re.I), "kill PID 1"),
    (re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b", re.I), "host/guest power-off"),
    (re.compile(r"\btruncate\b", re.I), "truncate"),
]


def classify_command(command: list[str]) -> tuple[str, list[str]]:
    """Heuristic read-vs-write classification of a container command. Advisory only.

    LOW is only ever returned for a command in a known read-only form — never as a guess.
    HIGH signatures are curated (not exhaustive); MEDIUM is the honest "modifies state / unknown" floor.
    """
    joined = " ".join(command)
    hits = [label for rx, label in _DANGEROUS_CMD if rx.search(joined)]
    if hits:
        return RISK_HIGH, [f"matches destructive pattern: {h}" for h in dict.fromkeys(hits)]

    if command:
        first = os.path.basename(command[0])
        rest = command[1:]
        if first == "systemctl":
            sub = rest[0] if rest else ""
            if sub in _SYSTEMCTL_HIGH:
                return RISK_HIGH, [f"systemctl {sub} (disables or kills a service)"]
            if sub in _SYSTEMCTL_READ:
                return RISK_LOW, ["looks read-only (systemctl query)"]
            return RISK_MEDIUM, ["may modify state (systemctl action)"]
        if first == "mount":
            if not rest:
                return RISK_LOW, ["looks read-only (mount listing)"]
            return RISK_MEDIUM, ["may modify state (mount)"]
        if first in _CONDITIONAL_READ:
            muts = sorted(_CONDITIONAL_READ[first].intersection(rest))
            if muts:
                return RISK_MEDIUM, [f"may modify state ({first} {' '.join(muts)})"]
            return RISK_LOW, ["looks read-only"]
        if first in _READ_COMMANDS:
            return RISK_LOW, ["looks read-only"]

    return RISK_MEDIUM, ["may modify state (unclassified)"]


# --- SQL classification -------------------------------------------------------

_SQL_READ = frozenset({"SELECT", "EXPLAIN", "SHOW", "VALUES", "TABLE"})
_SQL_DML = frozenset({"INSERT", "UPDATE", "DELETE", "MERGE", "COPY", "UPSERT"})
_SQL_DDL = frozenset({"DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE", "RENAME"})

_SQL_DDL_RE = re.compile(r"\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b")
_SQL_DML_RE = re.compile(r"\b(INSERT|UPDATE|DELETE|MERGE)\b")
_LEADING_WORD_RE = re.compile(r"\s*([A-Za-z]+)")

# `COPY ... TO/FROM PROGRAM 'cmd'` is OS command execution as the postgres user — RCE, not a write.
_SQL_COPY_PROGRAM_RE = re.compile(r"\bCOPY\b[\s\S]+\bPROGRAM\b", re.I)
# System functions that read/write the host filesystem, kill sessions, or drop replication slots —
# a `SELECT` carrying one of these is NOT a read. (Curated; not exhaustive.)
_SQL_HIGH_FN_RE = re.compile(
    r"\b(pg_terminate_backend|pg_drop_replication_slot"
    r"|pg_create_(?:physical|logical)_replication_slot|pg_read_file|pg_read_binary_file"
    r"|pg_write_file|pg_ls_dir|lo_import|lo_export|lo_unlink|dblink|pg_rotate_logfile)\s*\(",
    re.I,
)
_SQL_MED_FN_RE = re.compile(r"\b(pg_cancel_backend|pg_reload_conf)\s*\(", re.I)


def _strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", " ", sql)                # line comments
    prev = None                                        # peel nested /* ... */ from the inside out
    while prev != sql:
        prev = sql
        sql = re.sub(r"/\*[^*/]*\*/", " ", sql)
    return sql


def _classify_one_sql(stmt: str) -> tuple[str, list[str]]:
    upper = stmt.upper()
    m = _LEADING_WORD_RE.match(stmt)
    word = m.group(1).upper() if m else ""
    if word in _SQL_READ:
        risk, reasons = RISK_LOW, [f"read ({word})"]
    elif word in _SQL_DML:
        risk, reasons = RISK_MEDIUM, [f"write/DML ({word})"]
    elif word in _SQL_DDL:
        risk, reasons = RISK_HIGH, [f"schema/DDL ({word})"]
    else:
        risk, reasons = RISK_MEDIUM, [f"unclassified ({word or 'empty'})"]

    # Backstops — guard the path to LOW: a dangerous token ANYWHERE escalates and is named,
    # so a benign leading keyword (SELECT, WITH) can't smuggle a write past the classifier.
    if _SQL_COPY_PROGRAM_RE.search(stmt):
        risk = _max_risk(risk, RISK_HIGH)
        reasons.append("COPY ... PROGRAM (command execution)")
    if _SQL_HIGH_FN_RE.search(stmt):
        risk = _max_risk(risk, RISK_HIGH)
        reasons.append("dangerous system function")
    ddl = _SQL_DDL_RE.search(upper)
    if ddl:
        risk = _max_risk(risk, RISK_HIGH)
        if word not in _SQL_DDL:
            reasons.append(f"contains DDL keyword ({ddl.group(1)})")
    dml = _SQL_DML_RE.search(upper)
    if dml:
        risk = _max_risk(risk, RISK_MEDIUM)
        if word not in _SQL_DML:
            reasons.append(f"contains DML keyword ({dml.group(1)})")
    if _SQL_MED_FN_RE.search(stmt):
        risk = _max_risk(risk, RISK_MEDIUM)
        reasons.append("intrusive system function")
    return risk, reasons


def classify_sql(sql: str) -> tuple[str, list[str]]:
    """Heuristic read-vs-write classification of SQL. Multi-statement-aware; advisory only.

    LOW is only returned for a statement that leads with a read keyword AND carries no destructive
    keyword or dangerous function anywhere. HIGH signatures are curated, not exhaustive.
    """
    cleaned = _strip_sql_comments(sql).strip()
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    if not statements:
        return RISK_LOW, ["empty statement"]

    worst = RISK_NONE
    reasons: list[str] = []
    for stmt in statements:
        risk, rs = _classify_one_sql(stmt)
        worst = _max_risk(worst, risk)
        reasons.extend(rs)
    reasons = list(dict.fromkeys(reasons))
    if len(statements) > 1:
        reasons.append("multiple statements")
    return worst, reasons


# --- exec / psql plan wrappers ------------------------------------------------

def command_fingerprint(command: list[str]) -> dict:
    """Privacy-preserving fingerprint of a shell command for the audit ledger: proves WHICH command
    ran (sha256 over the joined argv) + its size and executable name, without persisting the args
    (which may carry secrets, e.g. `--password ...`). Used when PROXIMO_LEDGER_REDACT is set."""
    joined = shlex.join(command)
    return {
        "cmd_sha256": hashlib.sha256(joined.encode("utf-8")).hexdigest(),
        "cmd_kind": command[0] if command else "EMPTY",   # the executable; secrets live in the args
        "cmd_len": len(joined),
    }


def plan_exec(ctid: str, command: list[str], redact: bool = False) -> Plan:
    risk, reasons = classify_command(command)
    if redact:
        fp = command_fingerprint(command)
        shown = f"[redacted {fp['cmd_kind']}, {fp['cmd_len']} chars, sha256:{fp['cmd_sha256'][:12]}]"
    else:
        shown = shlex.join(command)
    return Plan(
        action="ct_exec", target=str(ctid),
        change=f"run in {ctid}: {shown}",
        current={}, blast_radius=[], risk=risk, risk_reasons=reasons, note=_HEURISTIC_NOTE,
    )


def _sql_kind(sql: str) -> str:
    """Coarse, human-readable statement kind (leading keyword) for a redacted ledger entry."""
    cleaned = _strip_sql_comments(sql).strip()
    if not cleaned:
        return "EMPTY"
    head = cleaned.split(None, 1)[0]
    return head.upper() if head.isalpha() else "OTHER"


def sql_fingerprint(sql: str) -> dict:
    """A privacy-preserving fingerprint of a SQL statement for the audit ledger: proves WHICH
    statement ran (sha256) and its size + coarse kind, without persisting the body (which may
    carry secrets/PII). Used unless PROXIMO_LEDGER_REDACT is turned off; fingerprinting is the default."""
    return {
        "sql_sha256": hashlib.sha256(sql.encode("utf-8")).hexdigest(),
        "sql_kind": _sql_kind(sql),
        "sql_len": len(sql),
    }


def plan_psql(ctid: str, sql: str, db: str = "postgres", redact: bool = False) -> Plan:
    risk, reasons = classify_sql(sql)
    if redact:
        fp = sql_fingerprint(sql)
        shown = f"[redacted {fp['sql_kind']}, {fp['sql_len']} chars, sha256:{fp['sql_sha256'][:12]}]"
    else:
        shown = sql
    return Plan(
        action="ct_psql", target=str(ctid),
        change=f"psql {db} in {ctid}: {shown}",
        current={}, blast_radius=[], risk=risk, risk_reasons=reasons, note=_HEURISTIC_NOTE,
    )


# --- UNDO pillar: snapshot plans ----------------------------------------------

def undo_snapname() -> str:
    """A snapshot-name-safe, collision-resistant label for an auto-undo point (leading letter, no
    separators PVE rejects; microsecond precision so back-to-back calls don't collide). <=40 chars."""
    return "proximo_undo_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + "Z"


def plan_rollback(api, vmid: str, snapname: str, kind: str = "lxc", node: str | None = None) -> Plan:
    """Preview a rollback. DESTRUCTIVE: discards everything since the snapshot. Reads the snapshot
    list (a safe read) to confirm the target exists and to surface when it was taken."""
    _check_vmid(vmid)
    _check_kind(kind)
    snaps = api.snapshot_list(vmid, kind, node) or []
    found = next((s for s in snaps if s.get("name") == snapname), None)
    current: dict = {}
    if found:
        current = {k: found[k] for k in ("name", "snaptime", "description") if k in found}
        blast = [
            f"DISCARDS all changes to {kind}/{vmid} since snapshot '{snapname}'",
            "NOTE: PVE does NOT snapshot a guest's 'description' or 'tags' — rollback will not "
            "revert those (use pve_guest_config_set / pve_guest_config_revert to change them).",
        ]
        reasons = ["rollback is destructive — every change after the snapshot is lost"]
    else:
        # No contradiction: if the snapshot isn't there, nothing gets discarded — the rollback fails.
        blast = [f"rollback will FAIL — snapshot '{snapname}' not found; no changes would be discarded"]
        reasons = [f"snapshot '{snapname}' not found in current list — rollback will fail"]
    return Plan(
        action="pve_rollback", target=f"{kind}/{vmid}:{snapname}",
        change=f"rollback {kind} {vmid} to snapshot {snapname}",
        current=current, blast_radius=blast, risk=RISK_HIGH, risk_reasons=reasons,
    )


def plan_snapshot_create(vmid: str, snapname: str, kind: str = "lxc") -> Plan:
    _check_vmid(vmid)
    _check_kind(kind)
    return Plan(
        action="pve_snapshot_create", target=f"{kind}/{vmid}:{snapname}",
        change=f"create snapshot {snapname} of {kind} {vmid}",
        current={}, blast_radius=["adds a restore point (non-destructive)"],
        risk=RISK_LOW, risk_reasons=["additive — creates a snapshot"],
        note=("requires snapshot-capable storage (ZFS/BTRFS/LVM-thin) — "
              "fails on directory or raw storage"),
    )


def plan_snapshot_delete(vmid: str, snapname: str, kind: str = "lxc") -> Plan:
    _check_vmid(vmid)
    _check_kind(kind)
    return Plan(
        action="pve_snapshot_delete", target=f"{kind}/{vmid}:{snapname}",
        change=f"delete snapshot {snapname} of {kind} {vmid}",
        current={}, blast_radius=[f"removes restore point '{snapname}' (you can't roll back to it after)"],
        risk=RISK_MEDIUM, risk_reasons=["removes a restore point"],
    )


# --- PDM fleet-control planners -----------------------------------------------
# These mirror the PVE planners' risk logic but read live state through the PDM
# proxy: pdm.guest_status(remote, kind, vmid) (remote-first signature) rather than
# the direct-PVE api.guest_status(vmid, kind, node). Target is remote-qualified so
# the ledger names which datacenter the guest lives in.


def _pdm_current(pdm, remote: str, kind: str, vmid: str) -> tuple[dict, bool]:
    """Read live guest state via the PDM proxy for a plan's `current` facts + running flag."""
    cur = pdm.guest_status(remote, kind, vmid) or {}
    status = str(cur.get("status", "unknown"))
    current: dict = {"status": status}
    for k in ("name", "uptime", "cpu", "mem", "maxmem"):
        if k in cur:
            current[k] = cur[k]
    return current, status == "running"


def plan_pdm_power(pdm, remote: str, kind: str, vmid: str, action: str) -> Plan:
    """Preview a proxied power action (no-op detection + risk by action)."""
    current, running = _pdm_current(pdm, remote, kind, vmid)
    blast: list[str] = []
    reasons: list[str] = []
    if action == "start" and running:
        risk = RISK_NONE
        blast = ["no-op: already running"]
    elif action in ("stop", "shutdown") and not running:
        risk = RISK_NONE
        blast = [f"no-op: already {current['status']}"]
    elif action == "start":
        risk = RISK_LOW
        reasons = ["bringing a guest up"]
    elif action == "resume" and kind == "qemu":
        risk = RISK_LOW
        reasons = ["resuming a paused VM"]
    elif action == "shutdown":
        risk = RISK_MEDIUM
        reasons = ["graceful ACPI shutdown of a running guest"]
    elif action == "stop":
        risk = RISK_HIGH
        reasons = ["hard stop (power pull) of a running guest"]
    else:
        # e.g. lxc+resume, or reboot/suspend — PDM proxies none of these; confirm will be
        # refused by _check_power_action, so the preview says so rather than looking normal.
        risk = RISK_MEDIUM
        reasons = [f"'{action}' is not a power action PDM proxies for {kind} — confirm will be refused"]
    if running and action in ("stop", "shutdown"):
        blast = [f"1 running guest on remote '{remote}' will halt"]
    return Plan(
        action="pdm_fleet_power", target=f"{remote}:{kind}/{vmid}:{action}",
        change=f"{action} {kind} {vmid} on remote {remote}",
        current=current, blast_radius=blast, risk=risk, risk_reasons=reasons,
    )


def plan_pdm_migrate(pdm, remote: str, kind: str, vmid: str, target: str, *,
                     cross_remote: bool = False, delete: bool = False, online: bool = False,
                     target_storage: str | None = None, target_bridge: str | None = None) -> Plan:
    """Preview an in-cluster or cross-remote migration."""
    current, running = _pdm_current(pdm, remote, kind, vmid)
    where = f"remote '{target}'" if cross_remote else f"node '{target}'"
    if cross_remote:
        risk = RISK_HIGH if delete else RISK_MEDIUM
        reasons = ["cross-remote (datacenter-to-datacenter) migration"]
        if delete:
            reasons.append("source guest is DELETED after a successful move")
    else:
        risk = RISK_MEDIUM
        reasons = ["in-cluster migration"]
    blast = [f"{kind} {vmid} relocates from '{remote}' to {where}"]
    maps = []
    if target_storage:
        maps.append(f"storage {target_storage}")
    if target_bridge:
        maps.append(f"bridge {target_bridge}")
    if maps:
        blast.append("mappings: " + ", ".join(maps))
    if cross_remote and delete:
        blast.append(f"source copy on '{remote}' is DELETED after a successful move (irreversible)")
    if running and not online:
        blast.append("running guest — an offline migrate interrupts it")
    if kind == "lxc" and online:
        blast.append(
            "lxc has no live migration — online=True is a restart-migration "
            "(stop, move, start): real downtime, not a true online move"
        )
    return Plan(
        action="pdm_fleet_migrate", target=f"{remote}:{kind}/{vmid}",
        change=f"migrate {kind} {vmid} from '{remote}' to {where}" + (" (online)" if online else ""),
        current=current, blast_radius=blast, risk=risk, risk_reasons=reasons,
    )


def plan_pdm_snapshot_create(pdm, remote: str, kind: str, vmid: str, snapname: str, *,
                             vmstate: bool = False) -> Plan:
    """Preview a snapshot create (additive)."""
    current, _ = _pdm_current(pdm, remote, kind, vmid)
    blast = [f"adds restore point '{snapname}'"]
    if vmstate:
        blast.append("includes RAM state (vmstate)")
    return Plan(
        action="pdm_fleet_snapshot_create", target=f"{remote}:{kind}/{vmid}:{snapname}",
        change=f"create snapshot '{snapname}' of {kind} {vmid} on remote {remote}",
        current=current, blast_radius=blast, risk=RISK_LOW,
        risk_reasons=["additive: creates a restore point"],
    )


def plan_pdm_snapshot_delete(pdm, remote: str, kind: str, vmid: str, snapname: str) -> Plan:
    """Preview a snapshot delete (irreversible loss of a restore point)."""
    current, _ = _pdm_current(pdm, remote, kind, vmid)
    return Plan(
        action="pdm_fleet_snapshot_delete", target=f"{remote}:{kind}/{vmid}:{snapname}",
        change=f"delete snapshot '{snapname}' of {kind} {vmid} on remote {remote}",
        current=current, blast_radius=[f"removes restore point '{snapname}' (irreversible)"],
        risk=RISK_MEDIUM, risk_reasons=["deletes a restore point — cannot be undone"],
    )


def plan_pdm_snapshot_rollback(pdm, remote: str, kind: str, vmid: str, snapname: str) -> Plan:
    """Preview a rollback. DESTRUCTIVE — the tool takes an auto safety-snapshot first."""
    current, running = _pdm_current(pdm, remote, kind, vmid)
    blast = [
        f"DISCARDS current state; reverts {kind}/{vmid} to snapshot '{snapname}'",
        "an auto safety-snapshot of the current state is taken first (fail-closed)",
    ]
    if running:
        blast.append("running guest will be reverted")
    return Plan(
        action="pdm_fleet_snapshot_rollback", target=f"{remote}:{kind}/{vmid}:{snapname}",
        change=f"rollback {kind} {vmid} on remote {remote} to snapshot '{snapname}'",
        current=current, blast_radius=blast, risk=RISK_HIGH,
        risk_reasons=["destructive: discards all changes since the snapshot"],
    )
