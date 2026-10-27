"""An ADVISORY reading of the command or SQL an exec, psql or guest-agent exec plan carries.

0.44 read a container command and a statement list as low, medium or high, and the plan showed it
beside the tier. The core tiers every command at one level (`records/tiers.toml` says it is a
heuristic that cannot see which command it is), so the person approving a plan lost the one word
that told `cat` from `rm -rf`. This module brings the reading back, and nothing else:

  * ADVISORY. It never lowers or raises the tier, never changes `allowed`, and never refuses.
    The authored tier is the floor the ladder reads; this is a sentence for the person.
  * "READ" IS AN ALLOWLIST. A command reads as read only when it is a known command, invoked by
    bare name or from a standard system directory, and every option it carries is on that
    command's list of options known to be read-only (exact spellings: a getopt abbreviation of a
    mutating option is not on the list, so it is not read). A statement reads as read only when it
    leads with SELECT, VALUES, TABLE, SHOW or EXPLAIN without ANALYZE, has no INTO, no row lock, no
    psql meta-command, and calls only functions on the read-only list. Everything else is write or
    destructive. The first version listed what mutates and called the rest a read; a lens
    found 100 ways that said "read" of a command that changes state.
  * LINEAR AND BOUNDED. The plan has no input cap of its own, so the classifier tokenizes once and
    never lets a pattern span the whole input, and input over a cap reads as a write ("too long
    to read").
  * IT NEVER QUOTES. The command and the SQL are secrets the ledger fingerprints
    (`records/secrets.toml`), so the hint is one word and a closed list of labels from this file,
    never a token of what was typed. A hint rides only a row whose argument the ledger
    fingerprints (`argument_of`), and `tests/test_risk_hint.py` plants a distinctive token and
    reads every byte of the ledger for it.
  * BAR 4. Proxmox runs the command and Postgres runs the SQL; neither says whether it writes.
    This is a curated heuristic, not a parser: the destructive patterns are not exhaustive, and
    the absence of "destructive" is not a safety signal. "read" is the only claim it stands behind.

Pure standard library: the shell door imports this through the engine, and its closure stays httpx.
"""
from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable, Mapping
from typing import Any

READ, WRITE, DESTRUCTIVE = "read", "write", "destructive"
_ORDER = {READ: 0, WRITE: 1, DESTRUCTIVE: 2}
#: Input over these reads as a write: the plan has no cap of its own, and a classifier is no place
#: to spend a request's time.
MAX_COMMAND_CHARS, MAX_COMMAND_ARGS, MAX_SQL_CHARS = 8192, 512, 16384
TOO_LONG = "too long to read"


def _worst(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


# --- commands -----------------------------------------------------------------------------------

#: Where a read command may live besides the bare name: a program NAMED `ls` in /tmp is not `ls`.
_STANDARD_DIRS = frozenset({"/usr/bin", "/bin", "/usr/sbin", "/sbin"})

#: Commands whose every option is read-only (they print, they do not change state).
_PLAIN = frozenset({"cat", "ls", "grep", "egrep", "fgrep", "ps", "df", "free", "stat", "head", "tail", "echo",
                    "pwd", "whoami", "id", "uptime", "uname", "printenv", "which", "wc", "du", "top",
                    "getent", "lsblk", "lscpu"})
_SYSTEMCTL_READ = frozenset({"status", "is-active", "is-enabled", "is-failed", "show", "list-units",
                             "list-unit-files", "cat", "get-default"})
_SYSTEMCTL_DESTRUCTIVE = frozenset({"mask", "unmask", "kill"})

#: Per command: options with no value, options that take a value (the next word, or `=value`),
#: options whose value is optional and attached, the letters a short cluster may hold, and whether a
#: bare word is allowed. Exact spellings only.
_SPECS: dict[str, dict[str, Any]] = {
    "journalctl": {
        "flags": frozenset({"-f", "-r", "-x", "-e", "-a", "-q", "-k", "-b", "-m", "--follow", "--reverse",
                            "--catalog", "--pager-end", "--all", "--quiet", "--dmesg", "--merge", "--no-pager",
                            "--no-hostname", "--utc", "--boot", "--list-boots", "--disk-usage", "--no-tail",
                            "--system", "--user", "--full", "--no-full"}),
        "valued": frozenset({"-u", "-n", "-o", "-p", "-S", "-U", "-t", "-g", "-c", "--unit", "--user-unit",
                             "--lines", "--output", "--priority", "--since", "--until", "--identifier",
                             "--grep", "--cursor", "--after-cursor", "--output-fields"}),
        "bare": True},
    "date": {
        "flags": frozenset({"-u", "-R", "--utc", "--universal", "--rfc-email", "--rfc-2822", "-I", "-Idate",
                            "-Ihours", "-Iminutes", "-Iseconds", "-Ins"}),
        "valued": frozenset({"-d", "--date", "-r", "--reference"}),
        "optional": frozenset({"--iso-8601", "--rfc-3339"}),
        "bare": False},                           # `date 1231235959` SETS the clock; only `+FORMAT` reads
    "hostname": {
        "flags": frozenset({"-f", "-s", "-i", "-I", "-d", "-a", "-A", "-y", "--fqdn", "--long", "--short",
                            "--ip-address", "--all-ip-addresses", "--domain", "--alias", "--yp", "--nis",
                            "--all-fqdns"}),
        "valued": frozenset(), "bare": False},
    "dmesg": {
        "flags": frozenset({"-T", "-H", "-x", "-k", "-u", "-w", "-t", "-r", "-P", "--ctime", "--human",
                            "--decode", "--kernel", "--userspace", "--follow", "--notime", "--raw", "--nopager"}),
        "valued": frozenset({"-l", "-f", "--level", "--facility"}),
        "optional": frozenset({"--color"}), "bare": False},
    "ss": {
        "letters": frozenset("tulnaoepsimrxwH46OE"),
        "flags": frozenset({"--tcp", "--udp", "--listening", "--numeric", "--all", "--processes", "--extended",
                            "--options", "--summary", "--info", "--memory", "--resolve", "--ipv4", "--ipv6",
                            "--no-header", "--unix", "--raw", "--oneline", "--events"}),
        "valued": frozenset({"-A"}), "bare": True},
    "netstat": {
        "letters": frozenset("tulnaoepsrigWvx46c"),
        "flags": frozenset({"--tcp", "--udp", "--listening", "--numeric", "--all", "--programs", "--extended",
                            "--route", "--interfaces", "--statistics", "--wide", "--verbose", "--timers"}),
        "valued": frozenset(), "bare": True},
    "find": {
        "flags": frozenset({"-print", "-print0", "-ls", "-empty", "-xdev", "-mount", "-depth", "-prune", "-o",
                            "-a", "-not", "-and", "-or", "-L", "-H", "-P", "-readable", "-writable",
                            "-executable", "-true", "-false", "-nouser", "-nogroup", "-follow", "-daystart",
                            "-noleaf"}),
        "valued": frozenset({"-name", "-iname", "-type", "-xtype", "-mtime", "-atime", "-ctime", "-mmin",
                             "-amin", "-cmin", "-size", "-maxdepth", "-mindepth", "-perm", "-user", "-group",
                             "-newer", "-path", "-ipath", "-regex", "-iregex", "-links", "-inum", "-uid",
                             "-gid", "-lname", "-samefile", "-wholename", "-iwholename"}),
        "bare": True, "numbers": True},
}
_IP_OPTIONS = frozenset({"-4", "-6", "-s", "-d", "-j", "-p", "-o", "-br", "-brief", "-c", "-stats", "-details",
                         "-json", "-oneline", "-color"})
_IP_OBJECTS = frozenset({"addr", "address", "link", "route", "neigh", "neighbor", "neighbour", "rule", "maddr",
                         "maddress"})
_IP_READ_VERBS = frozenset({"show", "list", "ls", "lst", "get"})
_NUMBER = re.compile(r"^[+-]?\d+[A-Za-z]?$")

_WORD_SPLIT = re.compile(r"[\s;&|()'\"`<>{}$]+")
_FORK_BOMB = re.compile(r":\(\)\s*\{")
_REDIRECT_DEV = re.compile(r">\s*/dev/")
_REDIRECT_ETC = re.compile(r">\s*/etc/")
_OCTAL_SETUID = re.compile(r"[0-7]?[4-7][0-7]{3}")
_LOOKAHEAD = 64          # words after a dangerous command that can still be its arguments


def _scan_options(rest: list[str], spec: Mapping[str, Any]) -> bool:
    """Whether every word of `rest` is an option on `spec`'s lists (or an allowed bare word)."""
    flags, valued = spec["flags"], spec["valued"]
    optional, letters = spec.get("optional", frozenset()), spec.get("letters", frozenset())
    skip = False
    for tok in rest:
        if skip:
            skip = False
        elif tok.startswith("--") and len(tok) > 2:
            name, eq, _ = tok.partition("=")
            if name in valued:
                skip = not eq
            elif name in optional:
                pass
            elif name not in flags or eq:
                return False
        elif tok.startswith("-") and len(tok) > 1:
            if tok in valued:
                skip = True
            elif tok in flags:
                pass
            elif letters and re.fullmatch(r"-[A-Za-z0-9]+", tok) and all(c in letters for c in tok[1:]):
                pass
            elif spec.get("numbers") and _NUMBER.match(tok):
                pass
            else:
                return False
        elif not (spec["bare"] or tok.startswith("+")):
            return False
    return True


def _ip_reads(rest: list[str]) -> bool:
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        if rest[i] not in _IP_OPTIONS:
            return False
        i += 1
    if i >= len(rest) or rest[i] not in _IP_OBJECTS:
        return False
    tail = rest[i + 1:]
    return not tail or tail[0] in _IP_READ_VERBS


#: Commands that are destructive by name alone.
_DESTRUCTIVE_NAMES = {"wipefs": "wipefs", "shred": "shred", "userdel": "userdel", "passwd": "passwd change",
                      "truncate": "truncate", "fdisk": "disk partitioning", "parted": "disk partitioning",
                      "sgdisk": "disk partitioning", "mkswap": "disk partitioning", "lvremove": "LVM removal",
                      "vgremove": "LVM removal", "pvremove": "LVM removal", "shutdown": "host/guest power-off",
                      "reboot": "host/guest power-off", "halt": "host/guest power-off",
                      "poweroff": "host/guest power-off"}


def _sensitive(after: list[str]) -> bool:
    return any(p in a for a in after for p in ("/etc/", "/dev/", ".ssh/"))


def _label_of(name: str, after: list[str]) -> str | None:
    """The destructive pattern a command word starts, from the words after it, or None."""
    recursive = any(a.startswith("-") and "r" in a[1:] for a in after)
    if name in _DESTRUCTIVE_NAMES:
        return _DESTRUCTIVE_NAMES[name]
    if name.startswith("mkfs"):
        return "mkfs"
    checks = (
        (name == "rm" and recursive, "rm -rf"),
        (name == "dd" and any(a.startswith(("if=", "of=")) for a in after), "dd"),
        (name == "cryptsetup" and any(a in ("luksformat", "lukserase", "erase") for a in after),
         "cryptsetup destructive"),
        (name == "find" and any(a in ("-delete", "-exec", "-execdir", "-ok", "-okdir") for a in after),
         "find -delete/-exec"),
        (name in ("chmod", "chown") and recursive, "recursive chmod/chown"),
        (name == "chmod" and any("+s" in a or _OCTAL_SETUID.fullmatch(a) for a in after), "chmod setuid/setgid"),
        (name in ("mv", "cp", "tee") and _sensitive(after), "write to sensitive path"),
        (name in ("iptables", "ip6tables") and any(a in ("-f", "-x", "-z") for a in after), "iptables flush"),
        (name == "nft" and "flush" in after, "nft flush"),
        (name == "useradd" and any(a in ("-o", "-u") for a in after), "useradd (override/uid)"),
        (name == "crontab" and "-r" in after, "crontab -r"),
        (name == "kill" and next((a for a in after if not a.startswith("-")), None) == "1", "kill PID 1"),
    )
    return next((label for hit, label in checks if hit), None)


#: Commands that only list or stat a path, never open it: `ls /dev/` and `stat /dev/watchdog` are reads.
_METADATA_ONLY = frozenset({"ls", "stat", "df", "du", "id", "whoami", "which", "pwd", "uname", "uptime", "free",
                            "lsblk", "lscpu", "echo", "printenv", "getent"})
_PROC_FD = re.compile(r"^proc/(?:\d+|self|thread-self)/(?:fd|fdinfo|mem|environ)\b")


def _device_path(arg: str) -> bool:
    """Whether an argument (or the value of `if=...`) names a device node or a process's file
    descriptors: the normalised path, so `dev/x`, `//dev/./x`, `/DEV/x` and `../dev/x` all count, and
    `/dev/null` and the directory `/dev` itself do not."""
    value = arg.rpartition("=")[2] if "=" in arg else arg
    parts = [p for p in posixpath.normpath(value.lower()).split("/") if p not in ("", ".", "..")]
    if not parts:
        return False
    if parts[0] == "dev":
        return len(parts) > 1 and parts[1:] != ["null"]
    return bool(_PROC_FD.match("/".join(parts)))


def _destructive_labels(command: list[str]) -> list[str]:
    """Labels of the destructive patterns in the command, found on words, never across the whole
    input at once. Curated, NOT exhaustive: a false "destructive" is safe, and the absence of one
    is not a safety signal. `sh -c "..."` wrappers are found because the words are split out of
    every argument."""
    joined = " ".join(command)
    words = [w.lower() for w in _WORD_SPLIT.split(joined) if w]
    hits = [h for i, w in enumerate(words)
            if (h := _label_of(w.rpartition("/")[2], words[i + 1:i + 1 + _LOOKAHEAD]))]
    for rx, label in ((_FORK_BOMB, "fork bomb"), (_REDIRECT_DEV, "redirect to /dev"),
                      (_REDIRECT_ETC, "overwrite under /etc")):
        if rx.search(joined):
            hits.append(label)
    return list(dict.fromkeys(hits))


def classify_command(command: list[str]) -> tuple[str, list[str]]:
    """(read | write | destructive, closed-vocabulary reasons) for an argv list. Advisory only."""
    if len(command) > MAX_COMMAND_ARGS or sum(len(a) + 1 for a in command) > MAX_COMMAND_CHARS:
        return WRITE, [TOO_LONG]
    if hits := _destructive_labels(command):
        return DESTRUCTIVE, [f"matches destructive pattern: {h}" for h in hits]
    if not command:
        return WRITE, ["may modify state (unclassified)"]
    directory, _, name = command[0].rpartition("/")
    if (directory and directory not in _STANDARD_DIRS) or not name:
        return WRITE, ["may modify state (unclassified)"]       # a program NAMED like a read command
    rest = command[1:]
    if name not in _METADATA_ONLY and any(_device_path(a) for a in rest):
        return WRITE, ["may modify state (a device node or a process's file descriptor is not a file: reading it "
                       "can act on the device or the process)"]
    if name == "systemctl":
        sub = rest[0] if rest else ""
        if sub in _SYSTEMCTL_DESTRUCTIVE:
            return DESTRUCTIVE, [f"systemctl {sub} (disables or kills a service)"]
        if sub in _SYSTEMCTL_READ:
            return READ, ["looks read-only (systemctl query)"]
        return WRITE, ["may modify state (systemctl action)"]
    if name == "mount":
        return (READ, ["looks read-only (mount listing)"]) if not rest else (WRITE, ["may modify state (mount)"])
    if name == "ip":
        return (READ, ["looks read-only"]) if _ip_reads(rest) else (WRITE, ["may modify state (ip)"])
    if name in _PLAIN:
        return READ, ["looks read-only"]
    if name in _SPECS:
        if _scan_options(rest, _SPECS[name]):
            return READ, ["looks read-only"]
        return WRITE, [f"may modify state ({name} with an option not known to be read-only)"]
    return WRITE, ["may modify state (unclassified)"]


# --- SQL ----------------------------------------------------------------------------------------

_SQL_READ_LEAD = frozenset({"select", "values", "table", "show"})
_SQL_DML = frozenset({"insert", "update", "delete", "merge", "copy", "upsert"})
_SQL_DDL_LEAD = frozenset({"drop", "truncate", "alter", "create", "grant", "revoke", "rename"})
_SQL_DDL_ANY = frozenset({"drop", "truncate", "alter", "grant", "revoke"})
_SQL_DML_ANY = frozenset({"insert", "update", "delete", "merge"})
#: System functions that read or write the host filesystem, kill sessions or drop replication
#: slots: a SELECT carrying one is not a read.
_SQL_HIGH_FN = frozenset({"pg_terminate_backend", "pg_drop_replication_slot", "pg_create_physical_replication_slot",
                          "pg_create_logical_replication_slot", "pg_read_file", "pg_read_binary_file",
                          "pg_write_file", "pg_ls_dir", "lo_import", "lo_export", "lo_unlink", "dblink",
                          "pg_rotate_logfile"})
_SQL_MED_FN = frozenset({"pg_cancel_backend", "pg_reload_conf"})
#: Functions known to read and only read. A call to any other function is not a read: the name tells
#: nothing about what it does (`nextval`, `set_config`, a user's own function).
_SQL_SAFE_FN = frozenset({
    "count", "sum", "avg", "min", "max", "coalesce", "nullif", "greatest", "least", "lower", "upper", "length",
    "char_length", "substr", "substring", "trim", "ltrim", "rtrim", "btrim", "concat", "concat_ws", "replace",
    "position", "left", "right", "split_part", "format", "initcap", "md5", "abs", "round", "floor", "ceil",
    "ceiling", "mod", "power", "sqrt", "cast", "date_trunc", "extract", "date_part", "to_char", "to_date",
    "to_timestamp", "to_number", "age", "now", "array_agg", "string_agg", "json_agg", "jsonb_agg",
    "json_build_object", "jsonb_build_object", "to_json", "to_jsonb", "jsonb_pretty", "row_number", "rank",
    "dense_rank", "lag", "lead", "first_value", "last_value", "ntile", "unnest", "array_length",
    "generate_series", "version", "current_database", "current_user", "current_setting", "pg_size_pretty",
    "pg_database_size", "pg_relation_size", "pg_total_relation_size", "pg_table_size", "pg_indexes_size",
    "pg_is_in_recovery", "pg_postmaster_start_time", "pg_backend_pid", "regexp_replace", "regexp_matches",
    "bool_and", "bool_or", "every", "stddev", "variance", "percentile_cont", "percentile_disc", "mode",
})
#: Words that precede a parenthesis without being a function call.
_SQL_SYNTAX = frozenset({
    "in", "exists", "any", "all", "some", "over", "filter", "and", "or", "not", "on", "using", "as", "from",
    "where", "when", "then", "else", "case", "between", "values", "select", "union", "intersect", "except",
    "join", "by", "distinct", "array", "row", "limit", "offset", "having", "order", "group", "partition",
    "within", "like", "ilike", "is", "table", "lateral", "rows", "range", "explain", "verbose", "show",
})
_SQL_WORD = re.compile(r"[^\W\d][\w$]*|\d[\w.]*")
_SQL_DOLLAR = re.compile(r"\$(?:[^\W\d]\w*)?\$")
Token = tuple[str, str]


def _skip_block_comment(sql: str, i: int) -> int | None:
    """The index after a (nested) block comment that starts at `i`, or None when it never closes."""
    depth, j, n = 1, i + 2, len(sql)
    while j < n and depth:
        if sql.startswith("/*", j):
            depth, j = depth + 1, j + 2
        elif sql.startswith("*/", j):
            depth, j = depth - 1, j + 2
        else:
            j += 1
    return None if depth else j


def _skip_string(sql: str, i: int, escaped: bool) -> int | None:
    """The index after the quoted string whose opening quote is at `i` ('' doubles a quote; a
    backslash escapes in an E'...' string), or None when it never closes."""
    j, n = i + 1, len(sql)
    while j < n:
        if escaped and sql[j] == "\\":
            j += 2
        elif sql[j] == "'":
            if not sql.startswith("''", j):
                return j + 1
            j += 2
        else:
            j += 1
    return None


def _skip_quoted_identifier(sql: str, i: int) -> tuple[str, int] | None:
    j, n = i + 1, len(sql)
    while j < n:
        if sql[j] == '"':
            if not sql.startswith('""', j):
                return sql[i + 1:j].replace('""', '"').lower(), j + 1
            j += 2
        else:
            j += 1
    return None


def _sql_tokens(sql: str) -> list[Token] | None:
    """One linear pass: words (lower case), quoted identifiers, string bodies dropped, comments
    dropped, punctuation, the backslash. A quote or comment that never closes is None: a statement
    that cannot be read to its end is not read."""
    toks: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        end: int | None = i + 1
        if c.isspace():
            pass
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            end = n if j < 0 else j + 1
        elif sql.startswith("/*", i):
            end = _skip_block_comment(sql, i)
        elif c == "'":
            escaped = bool(toks) and toks[-1] == ("w", "e") and i > 0 and sql[i - 1] in "eE"
            if escaped:
                toks.pop()
            end = _skip_string(sql, i, escaped)
            # a backslash in a plain string means one thing with standard_conforming_strings on and
            # another with it off (where `\'` does not close the string): marked, and not read
            toks.append(("s", "\\" if end is not None and not escaped and "\\" in sql[i:end] else ""))
        elif c == '"':
            got = _skip_quoted_identifier(sql, i)
            end = got[1] if got else None
            toks.append(("q", got[0] if got else ""))
        elif c == "$" and (m := _SQL_DOLLAR.match(sql, i)):
            close = sql.find(m.group(0), m.end())
            end = None if close < 0 else close + len(m.group(0))
            toks.append(("s", ""))
        elif c == "\\":
            toks.append(("\\", c))
        elif m := _SQL_WORD.match(sql, i):
            toks.append(("w", m.group(0).lower()))
            end = m.end()
        else:
            toks.append((c if c in "();,." else "o", c))
        if end is None:
            return None
        i = end
    return toks


def _explain_target(toks: list[Token]) -> bool:
    """Whether an EXPLAIN (no ANALYZE; the caller checked) explains a read: skip its options."""
    j = 1
    if j < len(toks) and toks[j][0] == "(":
        while j < len(toks) and toks[j][0] != ")":
            j += 1
        j += 1
    if j < len(toks) and toks[j] == ("w", "verbose"):
        j += 1
    return j < len(toks) and toks[j][0] == "w" and toks[j][1] in ("select", "values", "table")


def _qualified(toks: list[Token], i: int) -> bool:
    """Whether the function name at `i` is schema-qualified. `myschema.lower(x)` is not the
    allowlisted `lower`: only `pg_catalog.` borrows the trust of the built-in."""
    return i >= 2 and toks[i - 1][0] == "." and toks[i - 2] not in (("w", "pg_catalog"), ("q", "pg_catalog"))


def _classify_statement(toks: list[Token]) -> tuple[str, list[str]]:
    words = [t for k, t in toks if k == "w"]
    lead = toks[0][1] if toks[0][0] == "w" else ""
    worst, reasons, unknown_fn = READ, [], False
    for i, (kind, text) in enumerate(toks):
        if kind == "\\":
            shell = i + 1 < len(toks) and toks[i + 1][1] == "!"
            worst = _worst(worst, DESTRUCTIVE if shell else WRITE)
            reasons.append("psql shell escape (command execution)" if shell else "psql meta-command")
        elif kind == "s" and text:
            worst, unknown_fn = _worst(worst, WRITE), True
            reasons.append("string literal with a backslash (read differently under another server setting)")
        elif kind in ("w", "q") and i + 1 < len(toks) and toks[i + 1][0] == "(" and \
                not (kind == "w" and text in _SQL_SYNTAX):
            if text in _SQL_HIGH_FN or text.startswith("dblink"):
                worst, why = _worst(worst, DESTRUCTIVE), "dangerous system function"
            elif text in _SQL_MED_FN:
                worst, why = _worst(worst, WRITE), "intrusive system function"
            elif text in _SQL_SAFE_FN and kind == "w" and not _qualified(toks, i):
                continue
            else:
                worst, why, unknown_fn = _worst(worst, WRITE), "calls a function not known to be read-only", True
            reasons.append(why)
    if "copy" in words and "program" in words:
        worst = DESTRUCTIVE
        reasons.append("COPY ... PROGRAM (command execution)")
    for w in dict.fromkeys(words):
        if w in _SQL_DDL_ANY:
            worst = DESTRUCTIVE
            reasons.append(f"contains DDL keyword ({w.upper()})" if w != lead else f"schema/DDL ({w.upper()})")
        elif w in _SQL_DML_ANY:
            worst = _worst(worst, WRITE)
            reasons.append(f"contains DML keyword ({w.upper()})" if w != lead else f"write/DML ({w.upper()})")
    if lead in _SQL_DDL_LEAD and worst != DESTRUCTIVE:
        worst = DESTRUCTIVE
        reasons.append(f"schema/DDL ({lead.upper()})")
    if lead in ("copy", "upsert"):
        worst = _worst(worst, WRITE)
        reasons.append(f"write/DML ({lead.upper()})")
    reads = lead in _SQL_READ_LEAD or (lead == "explain" and not {"analyze", "analyse"} & set(words)
                                       and _explain_target(toks))
    if lead == "explain" and {"analyze", "analyse"} & set(words):
        reasons.append("EXPLAIN ANALYZE runs its statement")
    if "into" in words or ("for" in words and "share" in words):
        reads = False
        reasons.append("creates a table or takes row locks")
    if reads and worst == READ and not unknown_fn:
        return READ, [f"read ({lead.upper()})"]
    if worst == READ:
        worst = WRITE
        if not reasons:
            reasons.append("unclassified statement")        # never the word: it is what was typed
    return worst, reasons


def classify_sql(sql: str) -> tuple[str, list[str]]:
    """(read | write | destructive, closed-vocabulary reasons) for SQL, every statement counted."""
    if len(sql) > MAX_SQL_CHARS:
        return WRITE, [TOO_LONG]
    toks = _sql_tokens(sql)
    if toks is None:
        return WRITE, ["unreadable statement (a quote or comment never closes)"]
    statements: list[list[Token]] = [[]]
    for t in toks:
        if t[0] == ";":
            statements.append([])
        else:
            statements[-1].append(t)
    statements = [s for s in statements if s]
    if not statements:
        return WRITE, ["empty statement"]
    worst, reasons = READ, []
    for st in statements:
        risk, why = _classify_statement(st)
        worst, reasons = _worst(worst, risk), reasons + why
    reasons = list(dict.fromkeys(reasons))
    if len(statements) > 1:
        reasons.append("multiple statements")
    return worst, reasons


# --- the hint ----------------------------------------------------------------------------------

def _hint(reading: str, reasons: list[str], of: str) -> dict[str, Any]:
    return {"reading": reading, "reasons": reasons, "of": of, "advisory": True}


def command_reading(value: Any) -> dict[str, Any]:
    """The hint for a command argument as the shell door reads it: an argv list, or a JSON array
    in a string. Anything else is a command nobody can read, and reads as a write."""
    cmd = value
    if isinstance(cmd, str):
        try:
            cmd = json.loads(cmd)
        except ValueError:
            cmd = None
    if not isinstance(cmd, list) or not cmd or not all(isinstance(a, str) for a in cmd):
        return _hint(WRITE, ["unreadable command (not an argv list of strings)"], "command")
    return _hint(*classify_command(cmd), "command")


def sql_reading(value: Any) -> dict[str, Any]:
    """The hint for a SQL argument: a string with a statement in it, else a write."""
    if not isinstance(value, str) or not value.strip():
        return _hint(WRITE, ["unreadable statement (not text)"], "sql")
    return _hint(*classify_sql(value), "sql")


#: (parameter, published type, reader). The row's shape picks the reader, never its path string.
_READERS: tuple[tuple[str, str, Callable[[Any], dict[str, Any]]], ...] = (
    ("command", "array", command_reading),
    ("sql", "string", sql_reading),
)


def argument_of(row: Any) -> tuple[str, Callable[[Any], dict[str, Any]]] | None:
    """(the argument name, its reader) when this row runs a command or SQL the ledger fingerprints:
    a mutation on the ssh wire or the guest-agent lane, publishing the argument at the type the
    reader reads, and listing it among the row's arg-secrets. The last condition is the leak
    fence: a hint never rides a row whose text the ledger would write raw."""
    if row.access != "mutate" or not (row.wire == "ssh" or row.lane == "agent"):
        return None
    for name, kind, reader in _READERS:
        if row.params.get(name, {}).get("type") == kind and name in row.arg_secrets:
            return name, reader
    return None


def hint(row: Any, args: Mapping[str, Any]) -> dict[str, Any] | None:
    """The advisory reading of this call's command or SQL, or None when the row runs neither.
    A call that leaves the argument out reads as a write: the vendor will refuse it, but the
    reading never rests on a guess."""
    found = argument_of(row)
    if found is None:
        return None
    name, reader = found
    return reader(args.get(name))
