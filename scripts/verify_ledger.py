#!/usr/bin/env python3
"""Verify a Proximo audit ledger with nothing but Python's standard library.

    python3 verify_ledger.py audit.log --key audit.key [--expected-head HEX]

Format version: ledger: 1 (docs/ledger-format.md). This file imports no part of Proximo, so a
reader who was handed a log and its key can check it on any box with Python 3.

What it checks: every row parses as an object; each row's prev_hash is the previous row's
entry_hash (genesis is 64 zeros); each entry_hash is HMAC-SHA256(key, prev_hash || canonical
body), or plain SHA-256 of the same bytes for an unkeyed log; with a key, EVERY row must be keyed
(a row's own `alg` never chooses the check); nothing follows a sealing `audit_rotate`.

What it does not: a cut tail, a forged append or a replaced file are invisible to a forward walk;
pass --expected-head, the head pinned off-box, to catch them. A sealed archive that mixes keyed
and unkeyed rows needs `proximo.core.ledger.verify_chain`.

Exit 0: ok, prints `ok <rows> <head>`. Exit 1: broken, prints the first break. Exit 2: the check
could not run (usage, unreadable file, bad key, or no rows: an empty log proves nothing).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys

GENESIS = "0" * 64
KEYED = "hmac-sha256"
CHAIN_FIELDS = ("prev_hash", "entry_hash", "alg")
HEAD = re.compile(r"[0-9a-f]{64}")
UNENCODABLE = "row holds characters the writer cannot produce (not UTF-8, or a lone surrogate)"


class Refused(Exception):
    """The check could not run; exit 2."""


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(body: dict, prev: str, key: bytes | None) -> str:
    msg = prev.encode("ascii") + _canonical(body)
    return hmac.new(key, msg, hashlib.sha256).hexdigest() if key is not None else hashlib.sha256(msg).hexdigest()


def verify(lines: list[str], key: bytes | None,
           expected_head: str | None) -> tuple[bool, int, int | None, str | None, str]:
    """(ok, rows, broken line, reason, head). The reasons are the core's, word for word."""
    prev, count, sealed = GENESIS, 0, False
    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        if sealed:
            return False, count, lineno, "entry recorded after ledger seal", prev
        try:
            entry = json.loads(raw)
        except (ValueError, RecursionError):     # a 5,000-digit int or deep nesting raises, too
            return False, count, lineno, "unparseable line", prev
        if not isinstance(entry, dict):
            return False, count, lineno, "non-object line", prev
        if entry.get("prev_hash") != prev:
            return False, count, lineno, "prev_hash mismatch (entry inserted, removed, or reordered)", prev
        body = {k: v for k, v in entry.items() if k not in CHAIN_FIELDS}
        alg = entry.get("alg")
        if key is not None:
            if alg != KEYED:
                return False, count, lineno, "expected an HMAC-keyed entry but found none (possible downgrade)", prev
        elif alg == KEYED:
            return False, count, lineno, "chain is HMAC-keyed but verify() has no key", prev
        elif alg is not None:
            return False, count, lineno, f"unknown chain alg {alg!r}", prev
        found = entry.get("entry_hash")
        if not isinstance(found, str):
            return False, count, lineno, "entry_hash missing or not a string", prev
        try:
            expected = _hash(body, prev, key)
        except UnicodeEncodeError:
            return False, count, lineno, UNENCODABLE, prev
        if not hmac.compare_digest(expected, found):
            return False, count, lineno, "entry_hash mismatch (entry altered)", prev
        prev = found
        count += 1
        detail = entry.get("detail")
        sealed = entry.get("action") == "audit_rotate" and isinstance(detail, dict) and detail.get("sealed") is True
    if expected_head is not None and prev != expected_head:
        return False, count, None, "head mismatch (tail truncated/appended or file replaced)", prev
    return True, count, None, None, prev


def _load_key(path: str) -> bytes:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    except OSError as e:
        raise Refused(f"cannot read the key file: {e.strerror}") from None
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise Refused("the key file is not hex") from None
    if len(key) < 32:
        raise Refused(f"the key is {len(key)} bytes; a ledger key is at least 32")
    return key


def _load_lines(path: str) -> list[str]:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise Refused(f"cannot read the log: {e.strerror}") from None
    # A byte that is not UTF-8 is a broken ROW at its line (tamper or damage), never "could not
    # run": surrogateescape carries it to the hash step, which names it.
    text = raw.decode("utf-8", errors="surrogateescape")
    lines = text.split("\n")        # "\n" ONLY: U+2028 or a lone "\r" is not a row break
    if not any(x.strip() for x in lines):
        raise Refused("no rows: an empty ledger proves nothing")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a Proximo audit ledger (ledger: 1), stdlib only.")
    ap.add_argument("log")
    ap.add_argument("--key", help="the ledger's key file (hex); omit only for an unkeyed archive")
    ap.add_argument("--expected-head", help="the head pinned off-box; catches a cut or forged tail")
    args = ap.parse_args(argv)
    try:
        pin = args.expected_head.strip().lower() if args.expected_head is not None else None
        if pin is not None and not HEAD.fullmatch(pin):
            raise Refused("--expected-head is not 64 hex characters")
        if args.key is not None and not args.key.strip():
            raise Refused("--key is empty (an unset variable?); omit it only for an unkeyed archive")
        key = _load_key(args.key) if args.key is not None else None
        lines = _load_lines(args.log)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    ok, rows, line, reason, head = verify(lines, key, pin)
    if ok:
        print(f"ok {rows} {head}")
        return 0
    print(f"broken at line {line}: {reason}" if line is not None else f"broken: {reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
