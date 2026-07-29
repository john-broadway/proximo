"""Append-only, tamper-EVIDENT audit ledger — the PROVE pillar.

Every entry is hash-chained:
    entry_hash = H(prev_hash + canonical(body))
where `body` is the entry minus the chaining fields, and H is either SHA-256 or
HMAC-SHA256 under an operator key. Altering, inserting, reordering, or removing
any *interior* entry breaks the chain, and verify() pinpoints the first break. **Tail operations** —
deleting the last entry, appending a forged entry, or wiping the file — are NOT caught by a forward
walk alone; pass `verify(expected_head=...)` with a head() value you pinned off-box to detect them.
The off-box pin can be automated: see ``audit_anchor.py`` (the FileSink anchor auto-pins head() and
audit_verify() re-exports it), but the guarantee still rests on the sink being off-box, not the code.

Keyed mode (default — controlled by ``PROXIMO_AUDIT_KEYED``, opt out with ``off``/``0``/``false``/``no``):
    With a key, entry_hash = HMAC-SHA256(key, prev_hash + canonical(body)) and each entry carries
    ``"alg": "hmac-sha256"``. An attacker who can write the log but cannot read the key cannot forge a
    valid forward rewrite. A keyed ledger **requires every entry to be keyed** — an unkeyed entry is
    treated as a downgrade and FAILS verification (the entry's own ``alg`` tag is never trusted; the
    ledger's key configuration is authoritative). You therefore cannot mix modes in one log.

    Key path: ``cfg.audit_key_path`` if set (``PROXIMO_AUDIT_KEY_PATH``); otherwise auto-generated at
    ``<audit-log-dir>/audit.key`` (0600). Key-gen failure fails closed — no silent downgrade.

    Seal-and-rotate: when ``open_ledger`` is called in keyed mode against an existing *unkeyed* log,
    the old log is sealed with a terminal ``audit_rotate`` entry, archived as
    ``<log>.unkeyed-<UTCstamp>-<head8>`` (NEVER deleted), and a new keyed log is started that records
    ``prev_log`` / ``prev_head`` as an auditable custody seam.

    Honest threat model: a same-user attacker who can write the 0600 log can often read the 0600 key
    too — so keying is a *marginal* hardening, **not** a substitute for an off-box head() anchor, which
    remains the strong guarantee. Use both.

Tamper-EVIDENT, not tamper-PROOF: anyone with write access (and, in keyed mode, the key) can rewrite the
chain from a point forward. Detection is the guarantee, not prevention.

The PVE API token is never written here. Callers pass non-sensitive detail, with ONE documented
exception: ``ct_psql`` records the SQL body and ``ct_exec`` the command argv it runs (the operator's own
input, on a 0600 log) — set ``PROXIMO_LEDGER_REDACT=1`` for a fingerprint (sha256 + kind + length) instead.
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

GENESIS_HASH = "0" * 64
_KEY_ALG = "hmac-sha256"
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
    matches = sorted(
        glob.glob(glob.escape(log_path) + ".unkeyed-*")
        + glob.glob(glob.escape(log_path) + ".keyed-*")
    )
    return matches[-1] if matches else None


def detect_mode(path: str) -> str:
    """Inspect an on-disk ledger's chaining mode without trusting it for verification.

    Returns "empty" (absent / no parseable entries), "keyed" (last entry is HMAC-keyed),
    or "unkeyed". Used ONLY to decide migration (seal-and-rotate); verify() still treats
    the ledger's key as authoritative, never the entry's `alg`.
    """
    if not os.path.exists(path):
        return "empty"
    last: dict[str, Any] | None = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                last = obj
    if last is None:
        return "empty"
    return "keyed" if last.get("alg") == _KEY_ALG else "unkeyed"


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
            if detect_mode(log_path) != "unkeyed":
                return "", AuditLedger(log_path, key=key).head()
            old = AuditLedger(log_path)  # unkeyed
            old.record("audit_rotate", target="ledger",
                       detail={"reason": "keyed-default upgrade", "sealed": True})
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
            AuditLedger(tmp, key=key).record(
                "audit_rotate", target="ledger",
                detail={"prev_log": os.path.basename(archive_path),
                        "prev_head": sealed_head, "prev_alg": "sha256"})
            os.replace(tmp, log_path)
            return archive_path, sealed_head
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def seal_keyed_and_rotate(log_path: str) -> tuple[str, str]:
    """Archive an existing KEYED ledger and start a fresh unkeyed one in its place.

    Mirror of ``seal_and_rotate`` for the reverse direction: called when the operator sets
    ``PROXIMO_AUDIT_KEYED=off`` after a keyed run (keyed→unkeyed downgrade). Because the HMAC
    key is unavailable at this point, no terminal ``sealed:true`` entry can be appended to the
    keyed log — the keyed chain is archived intact and is still fully verifiable with the
    original key. The new unkeyed log records ``prev_log``/``prev_head``/``prev_alg`` as an
    auditable custody seam, analogous to the forward migration.

    Under a sidecar ``<log_path>.lock`` (the log itself gets renamed, so we can't lock it).
    No-op (returns ``("", head)``) if the log is not keyed once the lock is held — a racing
    process already handled it. NEVER deletes the old log.
    """
    lock_path = log_path + ".lock"
    # O_NOFOLLOW: a co-located writer that plants `<log>.lock` as a symlink must not have the
    # flock silently redirected onto (and, via O_CREAT, potentially create) an arbitrary target
    # path — that's a containment escape. Opening a symlinked lock path raises OSError (ELOOP).
    with open(lock_path, "a+", encoding="utf-8",
              opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            if detect_mode(log_path) != "keyed":
                return "", AuditLedger(log_path).head()
            # Read the stored head without HMAC verification — the key is unavailable here,
            # and we only need the value for the archive name and custody seam, not to verify.
            old_head = AuditLedger(log_path).head()
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            archive_path = f"{log_path}.keyed-{stamp}-{old_head[:8]}"
            # Archive the keyed log intact.  No terminal seal entry is possible without the key;
            # the archive is a complete, independently verifiable keyed chain.
            # Crash window: if the process dies after rename but before the genesis below, the
            # archive survives (non-destructive); re-running open_ledger sees an empty new log
            # and starts fresh with no custody seam — acceptable, as with seal_and_rotate.
            os.rename(log_path, archive_path)
            # Write the unkeyed genesis to a temp file, then os.replace() atomically — same
            # pattern as seal_and_rotate to prevent a racer from creating log_path in this window.
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(log_path) or ".", prefix=".audit-new-")
            os.close(fd)
            AuditLedger(tmp).record(
                "audit_rotate", target="ledger",
                detail={"prev_log": os.path.basename(archive_path),
                        "prev_head": old_head, "prev_alg": _KEY_ALG,
                        "reason": "keyed-to-unkeyed downgrade"})
            os.replace(tmp, log_path)
            return archive_path, old_head
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class LedgerVerification:
    ok: bool
    entries: int
    broken_at: int | None = None  # 1-based line number of the first bad entry
    reason: str | None = None


class AuditLedger:
    """Hash-chained, flock-guarded, append-only audit ledger (JSON lines).

    Pass `key` (bytes) to chain with HMAC-SHA256 instead of bare SHA-256 (opt-in keyed mode). A given
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
    def _last_hash(f) -> str:
        # O(n) tail scan. Audit volume is low; optimize to a cached head if it ever isn't.
        prev = GENESIS_HASH
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
                prev = entry["entry_hash"]
        return prev

    def record(self, action: str, *, target: str, mutation: bool = False,
               outcome: str = "ok", detail: dict[str, Any] | None = None,
               remote: str | None = None) -> dict[str, Any]:
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
                prev = self._last_hash(f)
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

    def verify(self, expected_head: str | None = None) -> LedgerVerification:
        """Walk the chain; report the first break.

        Catches interior alteration / insertion / removal / reorder on its own. A keyed ledger also
        catches a *downgrade* (a keyed entry rewritten without the HMAC), because keyed-vs-unkeyed is
        decided by this ledger's key — never by the entry's own `alg` tag. To also catch tail
        truncation, a forged tail-append, or a full file replacement, pass `expected_head` — the head()
        value you pinned off-box; verify fails if the chain's final hash doesn't match it.
        """
        self._refuse_if_symlinked_dir()
        prev = GENESIS_HASH
        count = 0
        sealed_seen = False
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                for lineno, raw in enumerate(f, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    if sealed_seen:
                        # A terminal seal (seal-and-rotate's audit_rotate{sealed:true}) must be the
                        # LAST entry. Anything chained after it = a write to an archived/sealed log
                        # (e.g. a stale fd held across rotation) — flag it (detection is the guarantee).
                        return LedgerVerification(
                            False, count, lineno, "entry recorded after ledger seal"
                        )
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        return LedgerVerification(False, count, lineno, "unparseable line")
                    if not isinstance(entry, dict):
                        return LedgerVerification(False, count, lineno, "non-object line")
                    if entry.get("prev_hash") != prev:
                        return LedgerVerification(
                            False, count, lineno, "prev_hash mismatch (entry inserted, removed, or reordered)"
                        )
                    body = {k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}
                    entry_alg = entry.get("alg")
                    if self.key is not None:
                        # Keyed ledger: EVERY entry must be keyed. A non-keyed entry is a downgrade —
                        # reject it (do not let the attacker-controlled `alg` choose the algorithm).
                        if entry_alg != _KEY_ALG:
                            return LedgerVerification(
                                False, count, lineno,
                                "expected an HMAC-keyed entry but found none (possible downgrade)",
                            )
                        expected = _hash(body, prev, self.key)
                    else:
                        # Unkeyed ledger: a keyed entry can't be verified without the key — say so.
                        if entry_alg == _KEY_ALG:
                            return LedgerVerification(
                                False, count, lineno, "chain is HMAC-keyed but verify() has no key"
                            )
                        if entry_alg is not None:
                            return LedgerVerification(
                                False, count, lineno, f"unknown chain alg {entry_alg!r}"
                            )
                        expected = _hash(body, prev, None)
                    found_hash = entry.get("entry_hash")
                    if not isinstance(found_hash, str):
                        # A truthy non-string entry_hash (42, [..], {..}) would crash compare_digest;
                        # treat it as tamper, not an exception (a writer-with-access DoS on verify()).
                        return LedgerVerification(False, count, lineno, "entry_hash missing or not a string")
                    if not hmac.compare_digest(expected, found_hash):
                        return LedgerVerification(False, count, lineno, "entry_hash mismatch (entry altered)")
                    prev = entry["entry_hash"]
                    count += 1
                    detail = entry.get("detail")
                    if entry.get("action") == "audit_rotate" and isinstance(detail, dict) \
                            and detail.get("sealed") is True:
                        sealed_seen = True
        # Tail truncation / forged append / full wipe are invisible to a forward walk — only an
        # off-box anchor can catch them.
        if expected_head is not None and prev != expected_head:
            return LedgerVerification(False, count, None, "head mismatch (tail truncated/appended or file replaced)")
        return LedgerVerification(ok=True, entries=count)


def open_ledger(cfg: Any) -> AuditLedger:
    """Build the AuditLedger for `cfg`, applying the keyed-default + seal-and-rotate policy.

    - keyed off (PROXIMO_AUDIT_KEYED=off) and no explicit key path -> unkeyed ledger.
    - else keyed: key at cfg.audit_key_path if set, else <logdir>/audit.key. An existing
      UNKEYED log is sealed-and-rotated first. Key-gen failure fails loud (no silent downgrade).
    """
    log = cfg.audit_log_path
    if cfg.audit_key_path:
        key_path = cfg.audit_key_path
        if not cfg.audit_keyed:
            warnings.warn(
                "PROXIMO_AUDIT_KEY_PATH is set, so the PROVE ledger is KEYED even though "
                "PROXIMO_AUDIT_KEYED is off — the explicit key path takes precedence.",
                stacklevel=2,
            )
    elif cfg.audit_keyed:
        key_path = os.path.join(os.path.dirname(log) or ".", "audit.key")
    else:
        # Keyed→unkeyed migration guard: if the existing log is keyed, seal-and-rotate it
        # (archive intact, start fresh unkeyed log, warn loudly) rather than silently appending
        # bare-SHA-256 entries onto an HMAC chain — which makes verify() fail forever with no
        # operator-readable migration guidance.  Mirrors the forward unkeyed→keyed path exactly.
        if detect_mode(log) == "keyed":
            archive_path, sealed_head = seal_keyed_and_rotate(log)
            ledger = AuditLedger(log)
            # Only the migration WINNER warns (same pattern as forward rotation).
            if archive_path:
                warnings.warn(
                    f"PROVE ledger DOWNGRADED to unkeyed mode: the prior keyed log "
                    f"(head {sealed_head[:12]}...) was archived to {archive_path} "
                    f"(verify it with its original HMAC key — no key was available here to "
                    f"add a terminal seal entry). A new unkeyed log was started "
                    f"(head {ledger.head()}). HMAC tamper-evidence is no longer active — "
                    f"re-enable PROXIMO_AUDIT_KEYED to restore it. "
                    f"If you pin PROXIMO_AUDIT_EXPECTED_HEAD, re-pin it to the new head.",
                    stacklevel=2,
                )
            return ledger
        return AuditLedger(log)  # unkeyed (opt-out)
    try:
        key = load_or_create_key(key_path)
    except (OSError, ValueError) as e:
        raise RuntimeError(
            f"cannot create audit key at {key_path}: {e}; "
            "set PROXIMO_AUDIT_KEYED=off to run an unkeyed ledger"
        ) from e
    if detect_mode(log) == "unkeyed":
        archive_path, sealed_head = seal_and_rotate(log, key)
        ledger = AuditLedger(log, key=key)
        # Only the migration WINNER warns. A concurrent-start loser gets ("", head) — the winner
        # already rotated — so it must not emit a warning reading "archived to <empty>".
        if archive_path:
            warnings.warn(
                f"PROVE ledger upgraded to keyed mode: the prior unkeyed log "
                f"(head {sealed_head[:12]}...) was sealed and archived to {archive_path}, and a new "
                f"keyed log was started (head {ledger.head()}). If you pin PROXIMO_AUDIT_EXPECTED_HEAD, "
                f"re-pin it to this new head.",
                stacklevel=2,
            )
        return ledger
    return AuditLedger(log, key=key)


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
    """
    open_by_intent: dict[str, dict] = {}
    for entry in entries:
        intent = (entry.get("detail") or {}).get("intent")
        if not intent:
            continue
        if entry.get("outcome") == EXECUTING:
            open_by_intent[intent] = entry
        else:
            open_by_intent.pop(intent, None)
    return list(open_by_intent.values())
