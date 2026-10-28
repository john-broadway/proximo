# The Proximo audit ledger: its format

Format version: **ledger: 1**. This page is enough to check a Proximo ledger without Proximo:
it says what a row is, how the chain is built, and what a check can and cannot tell you. The
checker that follows it, `scripts/verify_ledger.py`, is one file of standard-library Python.

## Where it lives

One file, append-only, JSON Lines: `~/.local/state/proximo/audit.log` unless
`PROXIMO_AUDIT_LOG` names another. Its key is `audit.key` beside it (32 random bytes, written as
hex with a trailing newline, mode `0600`) unless `PROXIMO_AUDIT_KEY_PATH` names another. Proximo
writes every row under an exclusive lock and `fsync`s it.

## A row

Each line is one JSON object. Its **body** is these fields:

| field | what it holds |
|---|---|
| `ts` | when the row was written, ISO 8601 UTC |
| `action` | what happened, e.g. `core.execute`, `core.refuse`, `core.consent_spent`, `audit_rotate` |
| `target` | what it happened to, e.g. `pve:POST /nodes/pve1/qemu/101/snapshot`; control characters U+0000 to U+001F become `?`, and past 512 characters it is cut and ends `…[truncated]` |
| `mutation` | `true` if the address changes something |
| `outcome` | a short word: `ok`, `refused`, `rejected`, `error`, `submitted`, `incomplete`, `undo_point`, or `executing` (written before the wire, closed by a later row). The list is open; a checker must not reject a word it does not know |
| `detail` | an object; what the action recorded. A secret-named argument is a fingerprint, never raw |
| `remote` | present only when the call went to a named box rather than the default one; sanitized like `target` |
| `principal` | present only when the caller was identified: `{id, via, face}`; `id` sanitized like `target` |

Three more fields are the **chain**, and are not part of the body:

| field | what it holds |
|---|---|
| `prev_hash` | the previous row's `entry_hash`; the first row's is `0000000000000000000000000000000000000000000000000000000000000000` |
| `entry_hash` | this row's hash, 64 lowercase hex characters |
| `alg` | `hmac-sha256` on a keyed row; absent on an unkeyed one |

Rows are separated by `\n` and nothing else. A JSON string may hold U+2028, U+2029 or U+0085
unescaped, and a lone `\r` is not a break either: split the file's bytes on `\n`, never with a
"split lines" helper or a text-mode reader that translates newlines. Proximo's own checks read
the file this way too. Blank lines are skipped, and so is surrounding whitespace (the `\r` of a
`\r\n` from a copy through Windows included). The hash covers the canonical body, not the bytes:
JSON whitespace added inside a row changes no content and is not a break.

A row the writer cannot have produced is a break at its line, never a crash: bytes that are not
UTF-8, an escaped lone surrogate (`row holds characters the writer cannot produce`), and a number
or nesting too large for a JSON reader (`unparseable line`).

## The chain

For each row, in file order:

1. **body** = the row without `prev_hash`, `entry_hash` and `alg`.
2. **canonical** = `json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
   encoded as UTF-8.
3. **entry_hash** = `HMAC-SHA256(key, prev_hash as ASCII || canonical)`, hex. An unkeyed log uses
   plain `SHA-256` of the same bytes.
4. `prev_hash` must equal the previous row's `entry_hash`.

**The `alg` field is a marker and is never trusted.** Whether a check is keyed is decided by
whether the checker holds the key: with a key, every row must carry `hmac-sha256`, and a row
without it is a downgrade and a break. Without a key, a keyed row is a break too (it cannot be
checked), never a pass.

## Seals and rotation

An `audit_rotate` row whose `detail` has `"sealed": true` ends a log: any row after it is a break.
Proximo writes one when it moves aside an old log that is unkeyed, or mixed (keyed rows followed
by unkeyed ones). The old file keeps its name plus
`.unkeyed-<stamp>-<head8>`, and the new log's first row is an `audit_rotate` whose `detail`
carries `prev_log` (the archive's file name), `prev_head` (its last `entry_hash`) and `prev_alg`.
That is the custody seam between the two files. A keyed log is never rotated.

## Rows a reader meets most

| `action` | `detail` holds |
|---|---|
| `core.execute` | a mutation's `executing` row: `tier`, `args` (secrets fingerprinted), `consent_id`, `undo`, `intent`, `notes` (the plan notes whose condition the arguments met, as sentences) when any did, `risk_hint` (`reading` and `reasons`: the advisory read, write or destructive reading of an exec, psql or guest-agent command, a word and closed labels, never the command) on those rows, and `default_node` (the node `PROXIMO_NODE` filled into `{node}`) when it did; it is closed by a later `core.execute` row carrying `tier` and `params`, or by `core.error` if the wire failed. A read writes a `core.execute` row with `params` too |
| `core.refuse` | `reason`, `needs` (which gate), and that gate's own fields |
| `core.consent_spent` | `consent_id`, `grant: {inode, mtime_ns}`: one operator approval, used once |
| `core.undo_point` | the record read back before a change, so the change can be put back |
| `core.recall` | an answer served from what Proximo already holds, not the vendor: a `since=` recall of a list, or a memory verb (`target: memory where|uses|changed`; `learn` is reads, each its own `core.execute` row) with the caller's words capped (a long ask keeps a prefix, its length and a fingerprint) |
| `audit_rotate` | see above |

## What a check tells you, and what it does not

A forward walk catches any row altered, inserted, removed or reordered **inside** the log, and a
row written after a seal. It cannot see a **cut tail**, a **forged row appended** at the end, or a
**whole file replaced**: each of those leaves a chain that is consistent with itself. Only the
head, `entry_hash` of the last row, copied somewhere this box cannot write and compared later,
catches them. Pin it off-box.

The key sits beside the log. Someone who can write the log as Proximo's own user can usually read
the key too, and could rewrite the chain from any point forward. So the key is a marginal
hardening; the off-box head is the strong guarantee. Use both. The ledger is tamper-evident, not
tamper-proof.

## Checking a ledger without Proximo

The checker is `scripts/verify_ledger.py` in Proximo's source repository (it is not in the
installed package; copy the one file). It reads the whole log into memory, as Proximo's own check
does.

```sh
python3 scripts/verify_ledger.py audit.log --key audit.key --expected-head <the head you pinned>
```

- exit `0`, prints `ok <rows> <head>`: the chain holds (and ends at the pinned head, if given);
- exit `1`, prints `broken at line <n>: <reason>` or `broken: <reason>`: the first break, with
  the same reason Proximo's own check gives;
- exit `2`, prints `refused: <why>` on stderr: the check could not run. A missing or unreadable
  file, a key that is not hex or is under 32 bytes, an empty `--key` (an unset variable), and **a
  log with no rows** all refuse: an empty ledger proves nothing. A pin is read in either case.

Omit `--key` only for an unkeyed archive. The script checks a single-algorithm log; a sealed
archive that mixes keyed and unkeyed rows needs `proximo.core.ledger.verify_chain`. Its test suite
holds it to the core: every planted break is judged by both, and they must agree to the line.
