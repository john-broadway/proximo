"""Append-only, tamper-EVIDENT audit ledger — the PROVE pillar.

Every entry is hash-chained:
    entry_hash = H(prev_hash + canonical(body))
where `body` is the entry minus the chaining fields, and H is either SHA-256 or
HMAC-SHA256 under an operator key. Altering, inserting, reordering, or removing
any *interior* entry breaks the chain, and verify() pinpoints the first break. **Tail operations** —
deleting the last entry, appending a forged entry, or wiping the file — are NOT caught by a forward
walk alone; pass `verify(expected_head=...)` with a head() value you pinned off-box to detect them.
The pin is the operator's hand: copy head() somewhere this box cannot write (0.44's anchor sinks
went with it); the guarantee rests on the copy being off-box, not on code.

Keyed, always (0.45 retired the ``PROXIMO_AUDIT_KEYED`` opt-out; a door refuses while it is set off):
    With a key, entry_hash = HMAC-SHA256(key, prev_hash + canonical(body)) and each entry carries
    ``"alg": "hmac-sha256"``. An attacker who can write the log but cannot read the key cannot forge a
    valid forward rewrite. A keyed ledger **requires every entry to be keyed** — an unkeyed entry is
    treated as a downgrade and FAILS verification (the entry's own ``alg`` tag is never trusted; the
    ledger's key configuration is authoritative). You therefore cannot mix modes in one log.

    Key path: ``cfg.audit_key_path`` if set (``PROXIMO_AUDIT_KEY_PATH``); otherwise auto-generated at
    ``<audit-log-dir>/audit.key`` (0600). Key-gen failure fails closed — no silent downgrade.

    Seal-and-rotate: when ``open_ledger`` meets an existing *unkeyed* log (a 0.44 box that opted
    out, or a writer that bypassed the door), the old log is sealed with a terminal ``audit_rotate`` entry, archived as
    ``<log>.unkeyed-<UTCstamp>-<head8>`` (NEVER deleted), and a new keyed log is started that records
    ``prev_log`` / ``prev_head`` as an auditable custody seam.

    Honest threat model: a same-user attacker who can write the 0600 log can often read the 0600 key
    too — so keying is a *marginal* hardening, **not** a substitute for an off-box head() anchor, which
    remains the strong guarantee. Use both.

Tamper-EVIDENT, not tamper-PROOF: anyone with write access (and, in keyed mode, the key) can rewrite the
chain from a point forward. Detection is the guarantee, not prevention.

The PVE API token is never written here. Callers pass non-sensitive detail; an argument the
secrets record (`secrets.toml`) names, a container command's argv say, lands as a fingerprint
(sha256 + kind + length), never raw. There is no switch to record it in full.
"""

from __future__ import annotations

import fcntl
import glob
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import ProximoError
from .secretfile import register_secret

GENESIS_HASH = "0" * 64
_KEY_ALG = "hmac-sha256"

#: Where the instance ledger lives unless PROXIMO_AUDIT_LOG says otherwise. ONE copy: the big
#: package's ProximoConfig reads this constant rather than spelling the path a second time.
DEFAULT_AUDIT_LOG = os.path.expanduser("~/.local/state/proximo/audit.log")
# Fields excluded from the hashed `body`. `alg` is a transparency marker, NOT a trusted input: verify()
# decides keyed-vs-unkeyed from the ledger's own key, so a tampered `alg` can't downgrade the check.
_CHAIN_FIELDS = ("prev_hash", "entry_hash", "alg")
_HEAD_RE = re.compile(r"[0-9a-f]{64}")

# Audit-target sanitization: the `target` field is a human-readable label built from caller-supplied
# args *before* backend validation runs. A hostile caller can inject C0 control chars (newlines,
# NUL, TAB, etc.) to fragment or forge log entries when the raw string is later read by a log tool.
# Sanitize at the single record() chokepoint: this covers _audited, _plan/_record_plan, and the A2A
# executor, without touching any tool callsite or the HMAC chain (which covers the sanitized body).
_C0_RE = re.compile(r"[\x00-\x1f]")
_AUDIT_TARGET_MAX = 512


def _sanitize_target(raw: str) -> str:
    """Replace C0 control chars (U+0000–U+001F) with '?' and cap to _AUDIT_TARGET_MAX chars.

    Control chars (incl. NUL, TAB, CR, LF) allow a hostile caller to inject fake log entries or
    null-terminate the target string in log-scanning tools. Replacing with '?' makes the injection
    visible without silently discarding characters. Over-long targets are capped with a marker so
    the ledger stays scannable. Only the `target` field is sanitized; all other fields are unchanged.
    """
    sanitized = _C0_RE.sub("?", raw)
    if len(sanitized) > _AUDIT_TARGET_MAX:
        sanitized = sanitized[:_AUDIT_TARGET_MAX] + "…[truncated]"
    return sanitized


def looks_like_head(value: str) -> bool:
    """True if `value` has the shape of a head() hash: 64 lowercase hex chars.

    A SHA-256 / HMAC-SHA256 hexdigest (and GENESIS_HASH) match. This is the single
    shape rule for a pinned head — used to validate both PROXIMO_AUDIT_EXPECTED_HEAD
    (config) and a per-call expected_head, so a typo is rejected as a caller error
    rather than read as a tail-attack "head mismatch".
    """
    return bool(_HEAD_RE.fullmatch(value))


def _canonical(body: dict[str, Any]) -> bytes:
    # Deterministic, order-independent serialization for hashing.
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(body: dict[str, Any], prev_hash: str, key: bytes | None = None) -> str:
    msg = prev_hash.encode("ascii") + _canonical(body)
    if key is not None:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    # Identical bytes to the historical two-update form: sha256(prev || canonical(body)).
    return hashlib.sha256(msg).hexdigest()


def load_or_create_key(path: str) -> bytes:
    """Load the audit HMAC key from `path` (stored as hex), generating a 32-byte key at 0600 if absent.

    Fail-closed on an empty or non-hex key file. See the module docstring for the (honest, marginal)
    threat model — keying is not a substitute for an off-box head() anchor.
    """
    path = os.path.expanduser(path)
    directory = os.path.dirname(path) or "."
    if os.path.islink(directory):
        # A symlinked key directory could redirect the audit key (and its atomic-link publish) onto a
        # path chosen by whoever planted the link. O_NOFOLLOW on the file open only catches a symlinked
        # FILE, not a symlinked parent dir — refuse rather than create through it (mirrors
        # envelope._rate_reserve's reservation-dir guard).
        raise OSError(f"refusing to use a symlinked audit-key directory: {directory!r}")
    os.makedirs(directory, exist_ok=True)
    if not os.path.exists(path):
        # Generate + publish ATOMICALLY: write a 0600 temp in the same dir, then os.link it into place.
        # The key file is therefore never observable half-written/empty by a racing process — the loser
        # of the link race reads the winner's key (single-key guarantee).
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".audit-key-")
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (secrets.token_bytes(32).hex() + "\n").encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path)  # atomic; raises if another process already created the key
        except FileExistsError:
            pass
        finally:
            os.unlink(tmp)
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    register_secret(text)  # the HMAC key must never appear in an error either
    if not text:
        raise ValueError(f"audit key file {path} is empty — refusing an empty key (fail-closed)")
    try:
        key = bytes.fromhex(text)
    except ValueError as e:
        raise ValueError(f"audit key file {path} is not valid hex: {e}") from e
    if len(key) < 32:
        raise ValueError(f"audit key file {path} is too short ({len(key)} bytes; need >=32) — fail-closed")
    return key


def find_rotation_archive(log_path: str) -> str | None:
    """Return the newest sibling rotation archive (``*.unkeyed-*`` or ``*.keyed-*``), or None.

    Lets a caller tell a benign migration (unkeyed→keyed OR keyed→unkeyed, both of which rotate
    the head so a stale off-box pin reads as a "head mismatch") apart from a real tail attack —
    the archive is the migration's fingerprint. Path-only; does not read or trust the archive's
    contents.
    """
    matches = glob.glob(glob.escape(log_path) + ".unkeyed-*") + glob.glob(glob.escape(log_path) + ".keyed-*")
    # newest by the UTC stamp in the name, never by the whole name: "keyed" sorts before "unkeyed"
    return max(matches, key=lambda m: m.rsplit("-", 2)[-2]) if matches else None


def _algs(path: str) -> list[tuple[int, str]]:
    """(line, alg) for every parseable entry; alg is "sha256" for an unkeyed row."""
    out: list[tuple[int, str]] = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append((lineno, obj.get("alg") or "sha256"))
    return out


def detect_mode(path: str) -> str:
    """Inspect an on-disk ledger's chaining mode without trusting it for verification.

    Returns "empty" (absent / no parseable entries), "keyed" (every entry is HMAC-keyed),
    "unkeyed" (none is), or "mixed" (both kinds). Used ONLY to decide migration
    (seal-and-rotate); verify() still treats the ledger's key as authoritative, never the
    entry's `alg`.

    THE WHOLE FILE, NOT THE LAST ROW. Reading one row called the 09-21 chain -- 8,574 keyed
    rows with 25 unkeyed rows appended by a bypass -- "unkeyed", and the custody row written
    from that answer said `prev_alg: sha256` about a file that was 99.7% HMAC.
    """
    kinds = {alg for _, alg in _algs(path)}
    if not kinds:
        return "empty"
    if kinds == {_KEY_ALG}:
        return "keyed"
    if _KEY_ALG in kinds:
        return "mixed"
    return "unkeyed"


def seam_line(path: str) -> int | None:
    """The first line whose alg differs from the first entry's: where a mixed chain changed."""
    algs = _algs(path)
    return next((n for n, alg in algs if alg != algs[0][1]), None) if algs else None


def seal_and_rotate(log_path: str, key: bytes) -> tuple[str, str]:
    """Seal an existing UNKEYED ledger and start a fresh keyed one in its place.

    Under a sidecar `<log_path>.lock` (the log itself gets renamed, so we can't lock it):
    append a terminal `audit_rotate` entry to the old log, archive it untouched-as-a-chain
    to `<log>.unkeyed-<UTCstamp>-<head8>`, then start the new keyed log whose genesis records
    `prev_log`/`prev_head` — an auditable custody seam. No-op (returns ("", head)) if the log
    is not unkeyed once the lock is held (a racing process already rotated). NEVER deletes the
    old log.
    """
    lock_path = log_path + ".lock"
    # O_NOFOLLOW: a co-located writer that plants `<log>.lock` as a symlink must not have the
    # flock silently redirected onto (and, via O_CREAT, potentially create) an arbitrary target
    # path — that's a containment escape. Opening a symlinked lock path raises OSError (ELOOP).
    with open(lock_path, "a+", encoding="utf-8",
              opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            mode = detect_mode(log_path)
            if mode not in ("unkeyed", "mixed"):
                return "", AuditLedger(log_path, key=key).head()
            # A MIXED chain (keyed rows, then unkeyed rows from a bypass) has an unkeyed TAIL,
            # so an unkeyed seal is the only entry that can extend it; the custody row below
            # says "mixed" and names the seam, because "sha256" would be a lie about 99% of it.
            seam = seam_line(log_path) if mode == "mixed" else None
            old = AuditLedger(log_path)  # unkeyed writer: agrees with the tail in both cases
            # ledger-lifecycle housekeeping — intentionally no principal= (not a caller-attributable action)
            old.record("audit_rotate", target="ledger",
                       detail={"reason": "keyed-default upgrade", "sealed": True,
                               **({"seam_line": seam} if seam else {})})
            sealed_head = old.head()
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            archive_path = f"{log_path}.unkeyed-{stamp}-{sealed_head[:8]}"
            # Crash window: if the process dies after the rename but before the genesis record below,
            # the archive survives intact (non-destructive — it's a complete verifiable chain), but
            # the new log's prev_log/prev_head custody pointer is lost. Both logs still verify
            # independently; re-running open_ledger sees an empty new log and starts fresh.
            os.rename(log_path, archive_path)
            # Claim the new log path ATOMICALLY: write the keyed genesis to a temp file in the same
            # dir, then os.replace() it into place. record() and seal_and_rotate hold *different*
            # locks (the log inode vs the sidecar .lock), so a racer can create log_path in this
            # window; the atomic replace clobbers any such interloper file rather than letting the
            # genesis append after an unkeyed entry (which would make the live log fail verify()
            # forever — flock can't help, as it binds to the inode, not the freshly-created path).
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(log_path) or ".", prefix=".audit-new-")
            os.close(fd)
            # ledger-lifecycle housekeeping — intentionally no principal= (not a caller-attributable action)
            AuditLedger(tmp, key=key).record(
                "audit_rotate", target="ledger",
                detail={"prev_log": os.path.basename(archive_path),
                        "prev_head": sealed_head, "prev_alg": mode if seam else "sha256",
                        **({"seam_line": seam} if seam else {})})
            os.replace(tmp, log_path)
            return archive_path, sealed_head
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class LedgerVerification:
    ok: bool
    entries: int
    broken_at: int | None = None  # 1-based line number of the first bad entry
    reason: str | None = None
    # `verify_chain` only: (alg, rows) runs in file order, so a mixed archive shows its seam.
    segments: tuple[tuple[str, int], ...] = ()
    head: str | None = None


class AuditLedger:
    """Hash-chained, flock-guarded, append-only audit ledger (JSON lines).

    Pass `key` (bytes) to chain with HMAC-SHA256 instead of bare SHA-256 (`open_ledger` always passes one). A given
    log file must be all-keyed or all-unkeyed for its whole life — see the module docstring.
    """

    def __init__(self, path: str, *, key: bytes | None = None):
        self.path = path
        self.key = key
        self._refuse_if_symlinked_dir()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _refuse_if_symlinked_dir(self) -> None:
        # A symlinked ledger directory redirects every ledger write (or read) onto an
        # attacker-chosen path; the per-file O_NOFOLLOW on record()'s append can't catch a
        # symlinked PARENT. Refuse rather than write/read the tamper-evident ledger through it
        # (mirrors envelope._rate_reserve's reservation-dir guard). Re-checked on EVERY
        # record()/head()/verify() call, not just at construction — a long-lived AuditLedger
        # (the server's lru_cache'd instance ledger) must not have a mid-session directory
        # swap silently redirect it, the same way _rate_reserve re-validates on every call.
        directory = os.path.dirname(self.path)
        if directory and os.path.islink(directory):
            raise OSError(f"refusing to use a symlinked audit-ledger directory: {directory!r}")

    @property
    def keyed(self) -> bool:
        return self.key is not None

    @staticmethod
    def _last_entry(f) -> tuple[str, str | None]:
        """(head hash, the last entry's alg) -- `alg` is None for an unkeyed row and "" for an
        empty file, so a caller can tell "nothing to agree with" from "an unkeyed chain"."""
        # O(n) tail scan. Audit volume is low; optimize to a cached head if it ever isn't.
        prev, alg = GENESIS_HASH, ""
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            # A valid-JSON non-dict line (int/list/str) would raise TypeError on the
            # subscript below — guard it the same way verify() does, so a corrupt tail
            # line never crashes record() mid-mutation or DoSes audit_verify/head().
            # The entry_hash VALUE must also be a str: _hash() does prev_hash.encode("ascii"),
            # so a crafted {"entry_hash": 123} would set prev to a non-str and brick record().
            if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
                prev, alg = entry["entry_hash"], entry.get("alg")
        return prev, alg

    @classmethod
    def _last_hash(cls, f) -> str:
        return cls._last_entry(f)[0]

    def record(self, action: str, *, target: str, mutation: bool = False,
               outcome: str = "ok", detail: dict[str, Any] | None = None,
               remote: str | None = None, principal: dict[str, Any] | None = None) -> dict[str, Any]:
        self._refuse_if_symlinked_dir()
        target = _sanitize_target(target)
        body = {
            "ts": datetime.now(UTC).isoformat(),
            "action": action,
            "target": target,
            "mutation": mutation,
            "outcome": outcome,
            "detail": detail or {},
        }
        # Multi-target: the box this op hit (None => the default/env box). Omitted on the default
        # path so default-box entry bodies — and thus their hashes — are byte-identical to before.
        # verify() rehashes from all non-_CHAIN_FIELDS keys, so a present `remote` is covered.
        if remote is not None:
            body["remote"] = _sanitize_target(remote)
        # Principal (who asked): omitted when unconfigured so default-path entry bodies — and
        # their hashes — stay byte-identical to before (same contract as `remote` above).
        if principal is not None:
            body["principal"] = {
                "id": _sanitize_target(str(principal.get("id", ""))),
                "via": str(principal.get("via", "")),
                "face": str(principal.get("face", "")),
            }
        # Reject non-finite JSON (NaN/Infinity) at write time: they serialize to non-RFC8259 tokens
        # that strict external audit parsers (Go/Rust/jq) can't read. Caught loudly here rather than
        # silently corrupting the log; verify() stays lenient for any pre-existing entry.
        try:
            json.dumps(body, allow_nan=False)
        except ValueError as e:
            raise ValueError(f"audit detail must be JSON-finite (no NaN/Infinity): {e}") from e
        # Hold an exclusive lock across read-prev + append so the chain stays consistent under concurrency.
        # Owner-only on creation: entries carry command/SQL detail, so the umask default is too open.
        # (Applies at creation only — an existing file keeps whatever mode the operator set.)
        # O_NOFOLLOW: a co-located writer that plants the ledger path itself as a symlink must not
        # have appends silently redirected onto (and, via O_CREAT, potentially created at) an
        # arbitrary target the service can write — that's a containment escape on the PROVE
        # ledger. Opening a symlinked ledger path raises OSError (ELOOP) instead of following it.
        with open(self.path, "a+", encoding="utf-8",
                  opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                prev, last_alg = self._last_entry(f)
                # TOTAL OVER WHAT THE FILE ALREADY HOLDS. On 2026-09-21 a bare `AuditLedger(path)`
                # appended unkeyed rows to a chain that had been HMAC-keyed since June, and the
                # next keyed start sealed all 8,599 rows into an archive as if none had been
                # keyed. The writer never looked at what it was extending. Now it does, under the
                # same lock that protects the append: a writer whose algorithm disagrees with the
                # chain's last row refuses, and `open_ledger` -- the one door that migrates a
                # chain -- is named as the way in. A matching writer is untouched.
                if last_alg != "" and (last_alg == _KEY_ALG) != (self.key is not None):
                    raise ValueError(
                        f"refusing to append {'an unkeyed' if self.key is None else 'a keyed'} entry "
                        f"to {'a keyed' if last_alg == _KEY_ALG else 'an unkeyed'} chain at {self.path}: "
                        "open the ledger through open_ledger(), which migrates a chain instead of "
                        "corrupting it"
                    )
                entry = {**body, "prev_hash": prev, "entry_hash": _hash(body, prev, self.key)}
                if self.key is not None:
                    entry["alg"] = _KEY_ALG
                # Append-only newline guard: if a crash left the last line unterminated, start this
                # entry on a fresh line rather than gluing two JSON objects onto one physical line
                # (which the forward walk reads as one unparseable line, silently re-anchoring at
                # GENESIS). os.pread checks the last byte without text-decode/seek hazards.
                size = os.fstat(f.fileno()).st_size
                if size and os.pread(f.fileno(), 1, size - 1) != b"\n":
                    f.write("\n")
                f.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return entry

    def head(self) -> str:
        """Latest entry_hash (GENESIS if empty). Anchor this off-box for true tamper-resistance."""
        self._refuse_if_symlinked_dir()
        if not os.path.exists(self.path):
            return GENESIS_HASH
        with open(self.path, encoding="utf-8") as f:
            return self._last_hash(f)

    def verify(self, expected_head: str | None = None, pinned_row: str | None = None) -> LedgerVerification:
        """Walk the chain; report the first break.

        Catches interior alteration / insertion / removal / reorder on its own. A keyed ledger also
        catches a *downgrade* (a keyed entry rewritten without the HMAC), because keyed-vs-unkeyed is
        decided by this ledger's key — never by the entry's own `alg` tag. To also catch tail
        truncation, a forged tail-append, or a full file replacement, pass `expected_head` — the head()
        value you pinned off-box; verify fails if the chain's final hash doesn't match it.
        `pinned_row` is the weaker, standing form: a row hash the chain must still HOLD, so later
        rows pass and a cut below it or a replaced file fails; a row forged after it does not.
        """
        self._refuse_if_symlinked_dir()
        lines = _read_rows(self.path) if os.path.exists(self.path) else []
        return verify_lines(lines, self.key, expected_head, pinned_row)


def _rows_of(text: str) -> list[str]:
    r"""The file's rows, split the way the writer joined them: on `\n` ONLY. `str.splitlines`
    also splits on U+2028, U+2029 and U+0085, which `json.dumps(ensure_ascii=False)` leaves raw
    inside a string, so one genuine row (a pasted description) became two unparseable fragments
    and a clean ledger read as tampered (lens 3)."""
    return text.split("\n")


#: A row the writer cannot have produced: bytes that are not UTF-8 (read back as lone surrogates)
#: or an escaped lone surrogate, either of which leaves no canonical body to hash.
UNENCODABLE = "row holds characters the writer cannot produce (not UTF-8, or a lone surrogate)"


def _read_rows(path: str) -> list[str]:
    """The file's rows the way the WRITER joined them, for every check that gives a verdict.
    Text mode's universal newlines read a lone `\r` as a row break the writer never wrote, so
    Proximo's own check and a checker that splits on `\n` gave opposite answers on one file
    (lens 3a, 2026-10-24). `surrogateescape` turns a byte that is not UTF-8 into a broken ROW
    at its line, not a crash of the whole check."""
    with open(path, "rb") as f:
        return _rows_of(f.read().decode("utf-8", errors="surrogateescape"))


def _parse_row(raw: str) -> Any:
    """json.loads, with every way a planted row can make it RAISE read as unparseable: a 5,000
    digit int (ValueError) and deep nesting (RecursionError) crashed audit_verify (lens 3a)."""
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise json.JSONDecodeError("unparseable", raw, 0) from None


def verify_lines(lines: list[str], key: bytes | None, expected_head: str | None = None,
                 pinned_row: str | None = None) -> LedgerVerification:
    """`AuditLedger.verify` over lines already read: the one judgement, usable on the bytes a
    caller holds, so a restore verifies, finds and pairs within ONE read of a writable file
    (lens 2: three separate reads let a swap between them put a forged capture on the wire)."""
    prev = GENESIS_HASH
    count = 0
    sealed_seen = False
    held = pinned_row is None or pinned_row == GENESIS_HASH
    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        if sealed_seen:
            # A terminal seal (seal-and-rotate's audit_rotate{sealed:true}) must be the LAST
            # entry. Anything chained after it = a write to an archived/sealed log (e.g. a
            # stale fd held across rotation) — flag it (detection is the guarantee).
            return LedgerVerification(False, count, lineno, "entry recorded after ledger seal")
        try:
            entry = _parse_row(raw)
        except json.JSONDecodeError:
            return LedgerVerification(False, count, lineno, "unparseable line")
        if not isinstance(entry, dict):
            return LedgerVerification(False, count, lineno, "non-object line")
        if entry.get("prev_hash") != prev:
            return LedgerVerification(False, count, lineno,
                                      "prev_hash mismatch (entry inserted, removed, or reordered)")
        body = {k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}
        entry_alg = entry.get("alg")
        if key is not None:
            # Keyed ledger: EVERY entry must be keyed. A non-keyed entry is a downgrade — reject
            # it (do not let the attacker-controlled `alg` choose the algorithm).
            if entry_alg != _KEY_ALG:
                return LedgerVerification(False, count, lineno,
                                          "expected an HMAC-keyed entry but found none (possible downgrade)")
            try:
                expected = _hash(body, prev, key)
            except UnicodeEncodeError:
                return LedgerVerification(False, count, lineno, UNENCODABLE)
        else:
            # Unkeyed ledger: a keyed entry can't be verified without the key — say so.
            if entry_alg == _KEY_ALG:
                return LedgerVerification(False, count, lineno, "chain is HMAC-keyed but verify() has no key")
            if entry_alg is not None:
                return LedgerVerification(False, count, lineno, f"unknown chain alg {entry_alg!r}")
            try:
                expected = _hash(body, prev, None)
            except UnicodeEncodeError:
                return LedgerVerification(False, count, lineno, UNENCODABLE)
        found_hash = entry.get("entry_hash")
        if not isinstance(found_hash, str):
            # A truthy non-string entry_hash (42, [..], {..}) would crash compare_digest; treat
            # it as tamper, not an exception (a writer-with-access DoS on verify()).
            return LedgerVerification(False, count, lineno, "entry_hash missing or not a string")
        if not hmac.compare_digest(expected, found_hash):
            return LedgerVerification(False, count, lineno, "entry_hash mismatch (entry altered)")
        prev = entry["entry_hash"]
        held = held or prev == pinned_row
        count += 1
        detail = entry.get("detail")
        if entry.get("action") == "audit_rotate" and isinstance(detail, dict) and detail.get("sealed") is True:
            sealed_seen = True
    # Tail truncation / forged append / full wipe are invisible to a forward walk — only an
    # off-box anchor can catch them.
    if expected_head is not None and prev != expected_head:
        return LedgerVerification(False, count, None, "head mismatch (tail truncated/appended or file replaced)")
    if not held:
        return LedgerVerification(False, count, None,
                                  "pinned row not in the chain (truncated below the pin, or the file replaced)")
    return LedgerVerification(ok=True, entries=count)


@dataclass(frozen=True)
class LedgerConfig:
    """The two settings the instance ledger needs, and nothing a plane needs.

    `open_ledger` reads exactly these attributes, so any config carrying them (the big package's
    ProximoConfig included) opens the same ledger the same way. This is the core's own shape:
    a shell door on a box with no PVE triple configured still stands up its ledger.
    """

    audit_log_path: str = DEFAULT_AUDIT_LOG
    audit_key_path: str | None = None

    @classmethod
    def from_env(cls) -> LedgerConfig:
        return cls(
            audit_log_path=os.environ.get("PROXIMO_AUDIT_LOG", DEFAULT_AUDIT_LOG),
            audit_key_path=os.environ.get("PROXIMO_AUDIT_KEY_PATH") or None,
        )


def ledger_key(cfg: Any) -> bytes | None:
    """The key the ledger at `cfg` is signed with, READ, never minted: `open_ledger` is the
    writer's door and creates one as a side effect. None when the key file does not exist yet (a
    chain with no rows to verify)."""
    key_path = cfg.audit_key_path or os.path.join(os.path.dirname(cfg.audit_log_path) or ".", "audit.key")
    if not os.path.exists(key_path):
        return None
    with open(key_path, encoding="utf-8") as f:
        return bytes.fromhex(f.read().strip())


def read_log(log_path: str) -> list[str]:
    """The live log's lines, read ONCE. A missing log refuses: "no ledger" and "nothing happened"
    are different facts and only the first is knowable."""
    if not os.path.exists(log_path):
        raise ProximoError(f"no ledger at {log_path}; nothing can be found on it")
    return _read_rows(log_path)


def parse_lines(lines: list[str]) -> list[dict]:
    """The rows in `lines`, in order; a line that is not JSON is skipped here because
    `verify_lines` is what judges integrity."""
    out: list[dict] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def find_entry(entries: list[dict], ref: str, log_path: str) -> dict:
    """The ONE entry whose hash starts with `ref` (8 to 64 hex characters), as recorded. The id a
    mutation returns under `undo.id` and `read_entries` prints is the first 12. A prefix two
    rows share is refused for more characters, never resolved to the newer one."""
    if not re.fullmatch(r"[0-9a-f]{8,64}", ref or ""):
        raise ProximoError(f"a receipt id is at least 8 hex characters of the row's hash, not {ref!r}")
    found = [e for e in entries if str(e.get("entry_hash", "")).startswith(ref)]
    if not found:
        raise ProximoError(f"no capture {ref}: not in the live log at {log_path}; sealed archives beside it "
                           f"are not searched")
    if len(found) > 1:
        raise ProximoError(f"{ref} names {len(found)} receipts; give more characters of the id")
    return found[0]


def executing_for(entries: list[dict], capture: dict) -> dict | None:
    """The detail of the `executing` row written for `capture`: the row whose preview names the
    capture's own id (`undo.id`), or None (a process that died between the two). Pairing by
    intent mispaired interleaved twins at one path (lens 2). Its `args` name what the captured
    mutation itself sent, which is what a restore may remove again."""
    ref = str(capture.get("entry_hash", ""))[:12]
    for entry in entries:
        d = entry.get("detail") or {}
        if entry.get("outcome") == EXECUTING and ((d.get("undo") or {}).get("id") == ref):
            return d
    return None


def open_ledger(cfg: Any) -> AuditLedger:
    """Build the AuditLedger for `cfg`: keyed, with the key at `cfg.audit_key_path` if set, else
    `<logdir>/audit.key`. An existing UNKEYED or MIXED log is sealed-and-rotated first (archived,
    never deleted). Key-gen failure fails loud: there is no unkeyed fallback.
    """
    log = cfg.audit_log_path
    key_path = cfg.audit_key_path or os.path.join(os.path.dirname(log) or ".", "audit.key")
    try:
        key = load_or_create_key(key_path)
    except (OSError, ValueError) as e:
        raise RuntimeError(
            f"cannot create audit key at {key_path}: {e}; the ledger is keyed, always: "
            "fix the key path (PROXIMO_AUDIT_KEY_PATH) or its directory's permissions"
        ) from e
    mode = detect_mode(log)
    if mode in ("unkeyed", "mixed"):
        archive_path, sealed_head = seal_and_rotate(log, key)
        ledger = AuditLedger(log, key=key)
        # Only the migration WINNER warns. A concurrent-start loser gets ("", head) — the winner
        # already rotated — so it must not emit a warning reading "archived to <empty>".
        if archive_path:
            what = ("the prior MIXED log (keyed rows with unkeyed rows appended by a writer that "
                    "bypassed open_ledger)" if mode == "mixed" else "the prior unkeyed log")
            warnings.warn(
                f"PROVE ledger upgraded to keyed mode: {what} "
                f"(head {sealed_head[:12]}...) was sealed and archived to {archive_path}, and a new "
                f"keyed log was started (head {ledger.head()}). Verify the archive with "
                f"audit_verify(path=<its name>); if you pin PROXIMO_AUDIT_EXPECTED_HEAD, "
                f"re-pin it to this new head.",
                stacklevel=2,
            )
        return ledger
    return AuditLedger(log, key=key)


def verify_chain(path: str, key: bytes | None) -> LedgerVerification:
    """Walk a chain ROW BY ROW, each under the algorithm it declares. For ARCHIVES.

    `AuditLedger.verify` is the live log's check and is right to demand one algorithm for the
    whole file: on a live keyed chain an unkeyed row IS a downgrade. An archive is different.
    The estate's June-to-September history was sealed as one continuous chain of 8,574 keyed
    rows and 25 unkeyed ones, and "intact" was not "provable" until something could walk it.
    Each row's hash is checked with the algorithm the row carries; a keyed row with no key
    available, or an unknown algorithm, breaks the walk there. The result names the segments
    in file order so a reader can see exactly where the chain changed hands.
    """
    prev, count, segments, sealed_seen = GENESIS_HASH, 0, [], False
    if not os.path.exists(path):
        return LedgerVerification(False, 0, None, "no such file")
    for lineno, raw in enumerate(_read_rows(path), start=1):  # split as the writer joined it
        raw = raw.strip()
        if not raw:
            continue
        if sealed_seen:
            # THE SEAL IS TERMINAL, here as in verify(). A lens appended a valid row after
            # the archive's `audit_rotate{sealed:true}` and this walk said ok: the one
            # verifier built for sealed archives was not checking the seal held.
            return LedgerVerification(False, count, lineno, "entry recorded after ledger seal",
                                      tuple(segments))
        try:
            entry = _parse_row(raw)
        except json.JSONDecodeError:
            return LedgerVerification(False, count, lineno, "unparseable line", tuple(segments))
        if not isinstance(entry, dict):
            return LedgerVerification(False, count, lineno, "non-object line", tuple(segments))
        if entry.get("prev_hash") != prev:
            return LedgerVerification(False, count, lineno,
                                      "prev_hash mismatch (entry inserted, removed, or reordered)",
                                      tuple(segments))
        alg = entry.get("alg") or "sha256"
        if alg == _KEY_ALG and key is None:
            return LedgerVerification(False, count, lineno,
                                      "keyed entry but no key was given to verify it", tuple(segments))
        if alg not in (_KEY_ALG, "sha256"):
            return LedgerVerification(False, count, lineno, f"unknown chain alg {alg!r}", tuple(segments))
        body = {k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}
        try:
            expected = _hash(body, prev, key if alg == _KEY_ALG else None)
        except UnicodeEncodeError:
            return LedgerVerification(False, count, lineno, UNENCODABLE, tuple(segments))
        found = entry.get("entry_hash")
        if not isinstance(found, str) or not hmac.compare_digest(expected, found):
            return LedgerVerification(False, count, lineno, "entry_hash mismatch (entry altered)",
                                      tuple(segments))
        prev = found
        count += 1
        detail = entry.get("detail")
        if entry.get("action") == "audit_rotate" and isinstance(detail, dict) \
                and detail.get("sealed") is True:
            sealed_seen = True
        if segments and segments[-1][0] == alg:
            segments[-1] = (alg, segments[-1][1] + 1)
        else:
            segments.append((alg, 1))
    return LedgerVerification(True, count, None, None, tuple(segments), prev)


# --- crash forensics: which mutations were mid-flight when the process stopped. ---
# Mutations record an `executing` entry BEFORE the call and a terminal entry after, both carrying
# the same derived `intent` (server.intent_id). An `executing` with no terminal partner therefore
# means exactly one thing: that operation was running when this process stopped. Before this, a
# SIGKILL between the call and the outcome write left an executed mutation with no ledger trace at
# all — the L16 note in server.py documented the hole and deferred the fix.
#
# Pure and read-only: takes already-parsed entries so it can be run over an exported chain, a
# copy, or a live log without touching the ledger. Order matters (the chain is append-only), so a
# re-attempt of the same intent correctly re-opens the interval its predecessor closed.
EXECUTING = "executing"


def in_flight(entries: list[dict]) -> list[dict]:
    """The `executing` entries with no terminal entry for the same intent, oldest first.

    An entry with no `intent` in its detail is ignored rather than guessed at: pre-intent ledgers
    are still valid chains, and inventing pairings across them would report phantom crashes.

    intent_id hashes only action+target, so two IDENTICAL ops that overlap in time share one
    intent. A per-intent STACK (not a last-writer-wins dict) is required: each terminal closes the
    most-recent still-open executing for that intent, so N executing minus M terminals leaves the
    correct N-M open. The old dict overwrote the first executing with the second, then a single
    terminal cleared it — a genuinely stranded twin vanished from the forensic view.
    """
    open_by_intent: dict[str, list[tuple[int, dict]]] = {}
    for i, entry in enumerate(entries):
        intent = (entry.get("detail") or {}).get("intent")
        if not intent:
            continue
        if entry.get("outcome") == EXECUTING:
            open_by_intent.setdefault(intent, []).append((i, entry))
        elif entry.get("action") in ("core.undo_point", "core.task"):
            # Written BESIDE an executing pair, not closing it: the UNDO capture comes before
            # its own executing row and the wait's receipt after `submitted` already closed it.
            # Either one popped a TWIN's open executing (lens 5 and 6, 2026-09-30).
            continue
        else:
            stack = open_by_intent.get(intent)
            if stack:
                stack.pop()  # a terminal closes the most-recent open executing for this intent
    still_open = [pair for stack in open_by_intent.values() for pair in stack]
    still_open.sort(key=lambda p: p[0])  # oldest first by position in the append-only chain
    return [entry for _, entry in still_open]


def read_entries(limit: int = 20, target: str | None = None, action: str | None = None,
                 principal: str | None = None, mutations_only: bool = False,
                 path: str | None = None) -> dict:
    """Read the PROVE chain back — who did what, when, to which target.

    THE HALF THAT WAS MISSING. 0.29.0 records the principal on every entry, and until now
    nothing could read one: `audit_verify` returns ok/entries/head, so "who changed this
    guest" was unanswerable through Proximo even though the answer was on disk. Found on
    the real estate by a qwen3:8b, which read the catalog and correctly reported that no
    tool does this. We shipped the claim without the read path; this is that path.

    Newest first, bounded, and honest in three specific ways:

    * `matched` counts every entry passing the filters, `total` counts the whole ledger —
      a filtered view must never masquerade as the census (memory.py's law).
    * `truncated` says so out loud when `limit` cut rows; silently dropping them reads as
      "that was all of them" to a model that will not check.
    * an entry with no principal reports `null` PLUS a note. "No principal recorded" is a
      fact about the ledger; "nobody" or "anonymous" would be an inference about a person.

    A missing ledger REFUSES rather than returning an empty history — "no ledger here" and
    "nothing has happened" are different facts and only the first one is knowable.
    """
    log_path = path or os.environ.get("PROXIMO_AUDIT_LOG", DEFAULT_AUDIT_LOG)
    if not os.path.exists(log_path):
        raise ProximoError(
            f"no ledger at {log_path} — this is NOT a statement that nothing has happened; "
            "it is the absence of a log. Check PROXIMO_AUDIT_LOG points where the server writes.")
    rows: list[dict] = []
    total = 0
    with open(log_path, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue          # verify() is what judges integrity; this one only reads
            total += 1
            if target and target != entry.get("target"):
                continue
            if action and action != entry.get("action"):
                continue
            if mutations_only and not entry.get("mutation"):
                continue
            who = entry.get("principal")
            if principal and (who or {}).get("id") != principal:
                continue
            row = {"ts": entry.get("ts"), "id": str(entry.get("entry_hash") or "")[:12],
                   "action": entry.get("action"), "target": entry.get("target"),
                   "mutation": bool(entry.get("mutation")), "outcome": entry.get("outcome"),
                   "principal": who}
            if "remote" in entry:
                row["remote"] = entry["remote"]   # the box a registered target named; absent = the env box
            if not who:
                row["note"] = ("no principal recorded on this entry — the ledger did not "
                               "capture a caller identity here, which is not a claim that "
                               "nobody was responsible")
            rows.append(row)
    rows.reverse()
    return {"source": "ledger", "path": log_path, "total": total, "matched": len(rows),
            "truncated": len(rows) > limit, "entries": rows[:limit],
            "note": "matched counts entries passing the filters; total counts the WHOLE ledger. "
                    "This reads the chain, it does not verify it — call audit_verify for that."}
