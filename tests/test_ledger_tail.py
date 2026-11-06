"""A receipt costs the same on a fresh ledger and a full one.

2026-10-31: every receipt ran `open_ledger`, which read the WHOLE ledger twice: `detect_mode` parsed every
row to say keyed / unkeyed / mixed, and `record` parsed every row forward to find the last hash. A
receipt cost 6 ms on a fresh ledger and 878 ms at 35,000 rows, so an operator's ledger, which only grows,
made every call slower than the last. The last entry is now read from the end, and the mode from the bytes
appended since this process last looked. Neither may change an answer: the backward read is held to the
forward walk on every shape a file can take, and the 09-21 law (THE WHOLE FILE, NOT THE LAST ROW) still
holds under the cache. Counted, never timed.
"""
from __future__ import annotations

import json
import os
import random

import pytest

from proximo.core import ledger as L
from proximo.core.ledger import GENESIS_HASH, AuditLedger, LedgerConfig, open_ledger


def _forward(path: str) -> tuple[str, str | None]:
    """The 0.50.1 walk, verbatim in behaviour: a text-mode read, every line, the last entry wins."""
    prev, alg = GENESIS_HASH, ""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
                prev, alg = entry["entry_hash"], entry.get("alg")
    return prev, alg


def _backward(path: str) -> tuple[str, str | None]:
    with open(path, encoding="utf-8") as f:
        return AuditLedger._last_entry(f)


class _Count:
    """json.loads, counted: what a receipt PARSES is the cost that grew with the ledger."""

    def __init__(self, monkeypatch):
        self.n, real = 0, json.loads

        def loads(s, *a, **k):
            self.n += 1
            return real(s, *a, **k)
        monkeypatch.setattr(L.json, "loads", loads)


def _entry(i: int, alg: str | None = "hmac-sha256") -> dict:
    e = {"ts": "t", "action": "a", "target": f"/t{i}", "entry_hash": f"{i:064x}", "prev_hash": "0" * 64}
    if alg:
        e["alg"] = alg
    return e


# --- the cost: a handful of parses per receipt, however long the ledger --------------------------

def test_a_receipt_on_a_long_ledger_parses_a_handful_of_lines(tmp_path, monkeypatch):
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    for i in range(5000):
        led.record("core.execute", target=f"/r{i}")
    open_ledger(cfg).record("core.execute", target="/warm")   # this process's first look reads it all, once
    count = _Count(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/last")   # what engine._record does for every receipt
    assert count.n <= 8, count.n          # the forward walks parsed 10,000 lines here
    count.n = 0
    assert L.detect_mode(cfg.audit_log_path) == "keyed"
    assert count.n <= 2, count.n          # only the row appended since the last look
    assert led.verify().ok


def test_a_fresh_process_reads_the_whole_file_once(tmp_path, monkeypatch):
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    for i in range(200):
        led.record("core.execute", target=f"/r{i}")
    monkeypatch.setattr(L, "_MODE_SEEN", {})      # what a new CLI process starts with
    count = _Count(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path) == "keyed"
    assert count.n == 200


# --- the answer: the backward read IS the forward walk -------------------------------------------

_JUNK = [b"", b"   ", b"not json", b"[1, 2]", b"42", b'"s"', b'{"entry_hash": 123}', b'{"no": "hash"}',
         b"{broken", "{\"x\": \"中é\U0001F600\"}".encode(), b"\xef\xbb\xbf{}", b"null"]
_ENDS = [b"\n", b"\r\n", b"\r", b"\n\n", b"\r\r\n"]


def _random_file(rng: random.Random) -> bytes:
    parts = []
    for i in range(rng.randint(0, 12)):
        kind = rng.random()
        if kind < 0.4:
            line = json.dumps(_entry(i, rng.choice(["hmac-sha256", None])), ensure_ascii=rng.random() < 0.5)
            parts.append(line.encode())
        elif kind < 0.5:
            # a line longer than a block, multibyte all the way, so blocks cut inside UTF-8 sequences
            e = _entry(i)
            e["detail"] = {"pad": "中" * rng.randint(30_000, 80_000)}
            parts.append(json.dumps(e, ensure_ascii=False).encode())
        else:
            parts.append(rng.choice(_JUNK))
        parts.append(rng.choice(_ENDS))
    if parts and rng.random() < 0.4:
        parts.pop()                                   # an unterminated last line
    return b"".join(parts)


@pytest.mark.parametrize("seed", range(120))
def test_the_backward_read_is_the_forward_walk(tmp_path, seed):
    path = tmp_path / "audit.log"
    path.write_bytes(_random_file(random.Random(seed)))  # noqa: S311 -- a seeded fuzz, not a secret
    assert _backward(str(path)) == _forward(str(path))


@pytest.mark.parametrize("tail", [
    b"x" * (3 * 64 * 1024),                           # megabytes of junk would do the same, slower
    ("中" * 50_000).encode(),                     # no line end, multibyte across every block edge
    b"\r" * 70_000,
    b'{"entry_hash": 123}\n' * 5000,
])
def test_a_tail_with_no_entry_is_read_back_to_the_last_real_one(tmp_path, tail):
    path = tmp_path / "audit.log"
    path.write_bytes(json.dumps(_entry(7)).encode() + b"\n" + tail)
    assert _backward(str(path)) == _forward(str(path)) == (f"{7:064x}", "hmac-sha256")


def test_an_empty_or_all_junk_file_is_genesis(tmp_path):
    path = tmp_path / "audit.log"
    for body in (b"", b"\n\n\r\n", b"junk\n[1]\n"):
        path.write_bytes(body)
        assert _backward(str(path)) == _forward(str(path)) == (GENESIS_HASH, "")


def test_head_and_record_extend_the_same_chain_as_before(tmp_path):
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    for i in range(300):
        led.record("core.execute", target=f"/r{i}", detail={"pad": "中" * (i * 37 % 3000)})
    assert led.head() == _forward(cfg.audit_log_path)[0]
    assert led.verify().ok


# --- the mode: the whole file, not the last row, under the cache ---------------------------------

def _keyed(tmp_path):
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    led.record("core.execute", target="/a", mutation=True)
    led.record("core.execute", target="/b", mutation=True)
    return cfg, led


def _forge_unkeyed(path: str, prev: str, n: int = 3) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for i in range(n):
            body = {"ts": "t", "action": "shell", "target": f"/u{i}", "mutation": True,
                    "outcome": "ok", "detail": {}}
            entry = {**body, "prev_hash": prev, "entry_hash": L._hash(body, prev, None)}
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            prev = entry["entry_hash"]


def test_unkeyed_rows_appended_after_a_cached_look_make_it_mixed(tmp_path):
    # the 09-21 bypass, AFTER this process has cached the chain as keyed
    cfg, led = _keyed(tmp_path)
    assert L.detect_mode(cfg.audit_log_path) == "keyed"
    _forge_unkeyed(cfg.audit_log_path, led.head())
    assert L.detect_mode(cfg.audit_log_path) == "mixed"


def test_a_keyed_row_after_an_unkeyed_tail_stays_mixed(tmp_path):
    # the kinds seen are kept: rows read before stay counted when only the newest bytes are read
    cfg, led = _keyed(tmp_path)
    _forge_unkeyed(cfg.audit_log_path, led.head(), 1)
    assert L.detect_mode(cfg.audit_log_path) == "mixed"
    with open(cfg.audit_log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(_entry(99)) + "\n")
    assert L.detect_mode(cfg.audit_log_path) == "mixed"


def test_a_rotated_or_remade_ledger_is_read_again_whole(tmp_path):
    path = str(tmp_path / "audit.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(_entry(i)) + "\n" for i in range(50)))
    assert L.detect_mode(path) == "keyed"
    os.rename(path, path + ".old")                       # a rotation: a new inode at the path
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(_entry(1, None)) + "\n")
    assert L.detect_mode(path) == "unkeyed"
    os.remove(path)
    assert L.detect_mode(path) == "empty"


def test_the_same_inode_with_a_different_head_is_read_again_whole(tmp_path):
    # a ledger deleted and made again can get the old inode number straight back (ext4); the same thing,
    # forced: one inode, rewritten from byte 0 and LONGER, so neither the inode nor the size gives it away
    path = str(tmp_path / "audit.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(_entry(i)) + "\n" for i in range(50)))
    ino = os.stat(path).st_ino
    assert L.detect_mode(path) == "keyed"
    with open(path, "r+", encoding="utf-8") as f:
        f.write("".join(json.dumps(_entry(i, None)) + "\n" for i in range(60)))
    assert os.stat(path).st_ino == ino
    assert L.detect_mode(path) == "unkeyed"


def test_a_partial_last_line_counts_and_is_read_again_when_it_ends(tmp_path):
    path = str(tmp_path / "audit.log")
    keyed = json.dumps(_entry(1)) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(keyed + json.dumps(_entry(2, None)))       # no line end yet: the walk reads it
    assert L.detect_mode(path) == "mixed"
    with open(path, "w", encoding="utf-8") as f:
        f.write(keyed + '{"entry_ha')                       # half a row, rewritten in place below
    assert L.detect_mode(path) == "keyed"
    with open(path, "a", encoding="utf-8") as f:
        f.write('sh": "x"}\n')
    assert L.detect_mode(path) == "mixed"                   # the row, whole now, is unkeyed


class _Split:
    """The line splitter, counted: the bytes it is handed are the work the backward read does."""

    def __init__(self, monkeypatch):
        self.n, real = 0, L._EOL
        outer = self

        class _Counted:
            def split(self, data):
                outer.n += len(data)
                return real.split(data)

            def finditer(self, data):
                return real.finditer(data)
        monkeypatch.setattr(L, "_EOL", _Counted())


def test_a_long_tail_with_no_line_end_is_split_once(tmp_path, monkeypatch):
    # the first backward read glued each block onto the carry and split it again: a 4 MiB tail with no
    # line end was about 130 MiB of splitting (64 blocks, each with every one after it), under the exclusive
    # lock every receipt waits on; the work grows with the square of the tail
    path = tmp_path / "audit.log"
    tail = b"x" * (4 * 1024 * 1024)
    path.write_bytes(json.dumps(_entry(3)).encode() + b"\n" + tail)
    split = _Split(monkeypatch)
    assert _backward(str(path)) == (f"{3:064x}", "hmac-sha256")
    assert split.n <= os.path.getsize(path), split.n


def test_a_ledger_cut_short_in_place_is_read_again_whole(tmp_path):
    # lens 10: without the size check, a warm cache on a file truncated on the same inode read a negative
    # length (ValueError) instead of reading the file again
    path = str(tmp_path / "audit.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(_entry(i)) + "\n" for i in range(200)))
    assert L.detect_mode(path) == "keyed"
    ino = os.stat(path).st_ino
    os.truncate(path, 8192)
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n" + json.dumps(_entry(999, None)) + "\n")
    assert os.stat(path).st_ino == ino and os.path.getsize(path) < 200 * 100
    assert L.detect_mode(path) == "mixed"


# --- the sidecar (2026-11-01): a new process starts where the last one ended, by the key's word only ---------

def _ledger(tmp_path, n: int):
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    for i in range(n):
        led.record("core.execute", target=f"/r{i}")
    open_ledger(cfg)            # the look that writes the sidecar, as engine._record does before a receipt
    return cfg, led


def _cold(monkeypatch):
    monkeypatch.setattr(L, "_MODE_SEEN", {})     # what a new CLI process starts with
    return _Count(monkeypatch)


def test_a_new_process_reads_only_what_was_appended_since_the_sidecar(tmp_path, monkeypatch):
    cfg, led = _ledger(tmp_path, 5000)
    assert os.path.exists(cfg.audit_log_path + ".mode")
    count = _cold(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/cold")
    assert count.n <= 8, count.n                   # the cold walk parsed 5,000 lines here
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed" and led.verify().ok


def test_the_0921_bypass_after_a_sidecar_is_still_mixed(tmp_path, monkeypatch):
    cfg, led = _ledger(tmp_path, 50)
    _forge_unkeyed(cfg.audit_log_path, led.head())
    _cold(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path, led.key) == "mixed"


@pytest.mark.parametrize("spoil", ["byte", "other_key", "deleted", "garbage", "huge", "done_past_end"])
def test_a_sidecar_the_key_did_not_sign_or_that_no_longer_fits_is_read_whole(tmp_path, monkeypatch, spoil):
    cfg, led = _ledger(tmp_path, 300)
    side = cfg.audit_log_path + ".mode"
    body = json.loads(open(side, encoding="utf-8").read())
    if spoil == "byte":
        body["kinds"] = []                         # claim nothing was seen: the MAC no longer matches
        open(side, "w", encoding="utf-8").write(json.dumps(body))
    elif spoil == "other_key":
        L._sidecar_write(cfg.audit_log_path, b"k" * 32, (body["dev"], body["ino"], body["head"], body["tail"]),
                         body["done"], frozenset())
    elif spoil == "deleted":
        os.remove(side)
    elif spoil == "garbage":
        open(side, "wb").write(b"\x00not json")
    elif spoil == "huge":
        open(side, "w", encoding="utf-8").write(" " * (L._SIDECAR_MAX + 10))
    elif spoil == "done_past_end":
        del body["mac"]
        body["done"] = 10 ** 9
        L._sidecar_write(cfg.audit_log_path, led.key, (body["dev"], body["ino"], body["head"], body["tail"]),
                         body["done"], frozenset(body["kinds"]))
    count = _cold(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed"
    assert count.n >= 300                          # read whole, never trusted
    count.n = 0
    monkeypatch.setattr(L, "_MODE_SEEN", {})
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed" and count.n <= 2   # and written afresh


def test_a_ledger_cut_and_grown_back_past_the_sidecar_is_read_whole(tmp_path, monkeypatch):
    # lens 11 MINOR-3, now for the next process too: same inode, the first 4 KiB unchanged, the size not
    # smaller than what was scanned; only the tail of the scanned region tells it apart
    cfg, led = _ledger(tmp_path, 400)
    path = cfg.audit_log_path
    done = json.loads(open(path + ".mode", encoding="utf-8").read())["done"]
    os.truncate(path, 8192)
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n")
        while os.path.getsize(path) < done:            # the unkeyed rows sit INSIDE what the sidecar says
            f.write(json.dumps(_entry(1, None)) + "\n")   # was scanned; everything after it is keyed
            f.flush()                                     # (unflushed, the size lags and they spill past it)
        for i in range(5):
            f.write(json.dumps(_entry(900 + i)) + "\n")
    _cold(monkeypatch)
    assert L.detect_mode(path, led.key) == "mixed"


def test_a_rotated_ledger_does_not_take_the_old_sidecar(tmp_path, monkeypatch):
    cfg, led = _ledger(tmp_path, 100)
    path = cfg.audit_log_path
    os.rename(path, path + ".old")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(_entry(i, None)) + "\n" for i in range(150)))
    _cold(monkeypatch)
    assert L.detect_mode(path, led.key) == "unkeyed"


def test_a_symlinked_sidecar_is_not_followed(tmp_path, monkeypatch):
    cfg, led = _ledger(tmp_path, 100)
    side = cfg.audit_log_path + ".mode"
    elsewhere = tmp_path / "elsewhere.json"
    os.rename(side, elsewhere)
    os.symlink(elsewhere, side)
    count = _cold(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed" and count.n >= 100   # not read through it
    assert not os.path.islink(side) and json.loads(open(elsewhere, encoding="utf-8").read())  # replaced, target kept


def test_without_the_key_the_sidecar_is_never_read(tmp_path, monkeypatch):
    cfg, _ = _ledger(tmp_path, 120)
    count = _cold(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path) == "keyed" and count.n >= 120   # doctor's path: as before


# --- lens 13 (2026-11-01): what is planted at the sidecar's name costs a whole read, never the receipt ---

@pytest.mark.parametrize("plant", ["fifo", "directory"])
def test_a_fifo_or_a_directory_at_the_sidecar_costs_only_a_whole_read(tmp_path, monkeypatch, plant):
    # b603bbd: a FIFO blocked every keyed open (no O_NONBLOCK, under the mode lock); a directory raised out
    cfg, led = _ledger(tmp_path, 50)
    side = cfg.audit_log_path + ".mode"
    os.remove(side)
    os.mkfifo(side) if plant == "fifo" else os.mkdir(side)
    _cold(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/after")      # must return, and receipt
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed" and led.verify().ok


def test_a_symlinked_ledger_directory_gets_no_sidecar_written_through_it(tmp_path, monkeypatch):
    # b603bbd: detect_mode ran before AuditLedger's directory refusal and wrote audit.log.mode through the link
    real, link = tmp_path / "elsewhere", tmp_path / "ledgerdir"
    real.mkdir()
    (real / "audit.log").write_text(json.dumps(_entry(1)) + "\n", encoding="utf-8")
    link.symlink_to(real)
    cfg = LedgerConfig(audit_log_path=str(link / "audit.log"), audit_key_path=str(tmp_path / "audit.key"))
    _cold(monkeypatch)
    with pytest.raises(OSError, match="symlinked"):
        open_ledger(cfg).record("core.execute", target="/x")
    assert sorted(os.listdir(real)) == ["audit.log"]


def test_a_cold_process_with_nothing_appended_leaves_the_sidecar_as_it_is(tmp_path, monkeypatch):
    cfg, led = _ledger(tmp_path, 50)
    side = cfg.audit_log_path + ".mode"
    before = os.stat(side).st_ino
    _cold(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed"
    assert os.stat(side).st_ino == before          # b603bbd rewrote it on every cold process


def test_a_sidecar_of_another_version_is_read_whole(tmp_path, monkeypatch):
    cfg, led = _ledger(tmp_path, 120)
    side = cfg.audit_log_path + ".mode"
    body = json.loads(open(side, encoding="utf-8").read())
    del body["mac"]
    body["v"] = 99
    body["mac"] = L._sidecar_mac(led.key, body)
    open(side, "w", encoding="utf-8").write(json.dumps(body))
    count = _cold(monkeypatch)
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed" and count.n >= 120


@pytest.mark.parametrize("alg", [5, 1.5, True, [1], {"a": 1}])
def test_a_bypass_row_whose_alg_is_not_text_is_sealed_never_a_stuck_ledger(tmp_path, monkeypatch, alg):
    # lens 14 (172a87c): "alg": 5 put a number among the kinds; sorting them for the sidecar raised on every
    # keyed open, the seal that would clear it included. main sealed it. ([1] and {"a": 1} raised on main too.)
    cfg, led = _ledger(tmp_path, 20)
    with open(cfg.audit_log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({**_entry(500), "alg": alg}) + "\n")
    _cold(monkeypatch)
    with pytest.warns(UserWarning, match="sealed and archived"):
        open_ledger(cfg).record("core.execute", target="/after")      # sealed once, as main does
    _cold(monkeypatch)
    fresh = open_ledger(cfg)                                          # and every open after receipts
    fresh.record("core.execute", target="/again")
    assert fresh.verify().ok and L.detect_mode(cfg.audit_log_path, fresh.key) == "keyed"
    assert any(n.startswith("audit.log.unkeyed-") for n in os.listdir(tmp_path))


@pytest.mark.parametrize("field,value", [("done", "Infinity"), ("done", "1e400"), ("dev", "-Infinity"),
                                         ("ino", "Infinity"), ("kinds", '"hmac-sha256"'), ("kinds", "[1]"),
                                         ("v", "true"), ("done", '"10"')])
def test_a_signed_sidecar_with_a_field_of_the_wrong_shape_costs_a_whole_read(tmp_path, monkeypatch, field, value):
    # lens 15 (21de491): a signed "done": Infinity raised OverflowError out of int() on every keyed open
    cfg, led = _ledger(tmp_path, 60)
    side = cfg.audit_log_path + ".mode"
    body = json.loads(open(side, encoding="utf-8").read())
    del body["mac"]
    raw = json.dumps(body, separators=(",", ":"))
    raw = raw.replace(f'"{field}":{json.dumps(body[field], separators=(",", ":"))}', f'"{field}":{value}', 1)
    signed = json.loads(raw)                                      # Python reads Infinity / 1e400 as floats
    mac = L._sidecar_mac(led.key, signed)
    open(side, "w", encoding="utf-8").write(raw[:-1] + f',"mac":"{mac}"}}')
    count = _cold(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/after")      # never raises
    assert count.n >= 60 and L.detect_mode(cfg.audit_log_path, led.key) == "keyed"


_NON_ASCII_MACS = [
    '{"mac":"\u00e9"}'.encode(),                       # raw é: compare_digest raised on it
    b'{"mac":"\\ud800"}',                              # pure-ASCII bytes, a lone surrogate once decoded
    ('{"mac":"' + "\u00e9" * 64 + '"}').encode(),      # the right length, the wrong characters
]


@pytest.mark.parametrize("planted", _NON_ASCII_MACS)
def test_a_planted_sidecar_with_a_mac_of_the_wrong_shape_costs_a_whole_read(tmp_path, monkeypatch, planted):
    # lens 16 (ddd608b), NO KEY NEEDED: compare_digest raises on a non-ASCII str, so {"mac":"\u00e9"} at the
    # sidecar's name stopped every receipt; main never read the name
    cfg, led = _ledger(tmp_path, 40)
    open(cfg.audit_log_path + ".mode", "wb").write(planted)
    count = _cold(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/after")
    assert count.n >= 40 and L.detect_mode(cfg.audit_log_path, led.key) == "keyed"


def test_a_signed_sidecar_that_stops_inside_a_character_reads_the_ledger_whole(tmp_path, monkeypatch):
    # lens 16 M1: a done of the right shape inside a multibyte character (rows carry raw UTF-8) raised
    # UnicodeDecodeError on every keyed open; now any failure reading on from a remembered point is main's read
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    for i in range(30):
        led.record("core.execute", target=f"/r{i}", detail={"n": "\u00e9\u4e2d" * 5})
    raw = open(cfg.audit_log_path, "rb").read()
    done = raw.index("\u4e2d".encode()) + 1                     # inside the three-byte character
    with open(cfg.audit_log_path, "rb") as f:
        ident = L._region_id(f, os.fstat(f.fileno()), done)
    L._sidecar_write(cfg.audit_log_path, led.key, ident, done, frozenset({"hmac-sha256"}))
    count = _cold(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/after")
    assert count.n >= 30 and L.detect_mode(cfg.audit_log_path, led.key) == "keyed" and led.verify().ok


def test_a_ledger_with_no_line_end_yet_keeps_its_sidecar_as_it_is(tmp_path, monkeypatch):
    # lens 17 m1: at_line_start seeked to -1 before testing 0, so a point of 0 never fitted and the sidecar
    # was rewritten on every open of a ledger whose only row has no line end yet
    path = tmp_path / "audit.log"
    path.write_text(json.dumps(_entry(1)), encoding="utf-8")
    key = b"k" * 32
    assert L.detect_mode(str(path), key) == "keyed"
    writes = []
    real_write = L._sidecar_write
    monkeypatch.setattr(L, "_sidecar_write", lambda *a: writes.append(a) or real_write(*a))
    for _ in range(3):                             # counted per open: an inode compare at the end can alternate
        _cold(monkeypatch)                         # back on some filesystems and pass on the old order (lens 18)
        assert L.detect_mode(str(path), key) == "keyed"
        assert writes == [], writes


def test_a_signed_point_of_zero_that_names_a_kind_is_refused(tmp_path, monkeypatch):
    # lens 18 (742da0e): with at_line_start(0) true, a signed {"done": 0, "kinds": ["sha256"]} fitted any
    # ledger on its inode and added its lie to the whole read's answer, so every receipt refused
    cfg, led = _ledger(tmp_path, 5)
    with open(cfg.audit_log_path, "rb") as f:
        ident = L._region_id(f, os.fstat(f.fileno()), 0)
    L._sidecar_write(cfg.audit_log_path, led.key, ident, 0, frozenset({"sha256"}))
    _cold(monkeypatch)
    open_ledger(cfg).record("core.execute", target="/after")
    assert L.detect_mode(cfg.audit_log_path, led.key) == "keyed"
