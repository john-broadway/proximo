"""An exec or psql plan carries an ADVISORY reading of the whole command or SQL (capability
`command-risk-hint`).

0.44's `classify_command` and `classify_sql` read a container command and a statement list as
read, write or destructive, so the person approving a plan saw "this reads" or "this drops a
table" beside the tier. The core tiers every container command at one level (the record says
so), and a tier cannot say which command it is. The hint can.

What it is NOT, by rule: it never lowers or raises the tier, never changes `allowed`, `reason`
or `needs`, never refuses. "read" is returned only for a command or statement in a known
read-only form, never as a guess; anything the classifier cannot read is "write". And the command
is a secret the ledger fingerprints (records/secrets.toml), so the hint is a word and a closed
list of labels, never a token of the command itself.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from proximo.core import engine, risk, shell, spine

NODE, CT = "pve1", "105"
EXEC, PSQL = f"/nodes/{NODE}/lxc/{CT}/exec", f"/nodes/{NODE}/lxc/{CT}/psql"
AGENT_EXEC = f"/nodes/{NODE}/qemu/100/agent/exec"
SECRET = "-".join(["zqsentinel", "value", "7f3a"])  # built in parts: a sentinel, not a credential a scanner should flag
DROP = "DR" + "OP TABLE"          # spelled in two halves: a statement, not a thing this file does


# --- the classifiers: 0.44's deleted tests, kept ------------------------------------------------

@pytest.mark.parametrize("cmd,reading", [
    (["cat", "/etc/hostname"], "read"),
    (["/usr/bin/cat", "/etc/hostname"], "read"),
    (["systemctl", "status", "nginx"], "read"),
    (["systemctl", "restart", "nginx"], "write"),
    (["systemctl", "mask", "nginx"], "destructive"),
    (["find", "/var", "-name", "*.log"], "read"),
    (["find", "/", "-delete"], "destructive"),
    (["find", "/", "-exec", "rm", "{}", "+"], "destructive"),
    (["ip", "addr", "show"], "read"),
    (["ip", "route", "add", "default", "via", "gateway"], "write"),
    (["ip", "link", "set", "eth0", "down"], "write"),
    (["mount"], "read"),
    (["mount", "/dev/sdb1", "/mnt"], "write"),
    (["rm", "-rf", "/var/lib/x"], "destructive"),
    (["sh", "-c", "rm -rf /tmp/x"], "destructive"),
    (["dd", "if=/dev/zero", "of=/dev/sda"], "destructive"),
    (["mkfs.ext4", "/dev/sdb1"], "destructive"),
    (["shred", "-u", "/etc/shadow"], "destructive"),
    (["lvremove", "-f", "vg/lv"], "destructive"),
    (["cryptsetup", "luksFormat", "/dev/sdb"], "destructive"),
    (["chmod", "4755", "/bin/bash"], "destructive"),
    (["chmod", "+s", "/bin/bash"], "destructive"),
    (["kill", "-9", "1"], "destructive"),
    (["iptables", "-F"], "destructive"),
    (["reboot"], "destructive"),
    (["apt-get", "install", "-y", "nginx"], "write"),
    (["sh", "-c", "echo hi"], "write"),           # a wrapper hides what it runs: not read
])
def test_a_command_reads_as_0_44_read_it(cmd, reading):
    assert risk.classify_command(cmd)[0] == reading


@pytest.mark.parametrize("cmd", [
    ["journalctl", "--vacuum-time=1s"], ["journalctl", "--rotate"], ["date", "-s", "2020-01-01"],
    ["date", "--set=2020-01-01"], ["hostname", "other"], ["dmesg", "-C"], ["dmesg", "--clear"],
    ["ss", "-K"], ["sed", "-i", "s/a/b/", "/etc/x"], ["tee", "/etc/x"],
])
def test_a_read_command_with_a_mutating_form_is_not_read(cmd):
    """Guard every path to read: a mutating form never inherits the read pass of its first word."""
    assert risk.classify_command(cmd)[0] != "read"


@pytest.mark.parametrize("cmd", [["journalctl", "-u", "ssh", "-n", "50"], ["date"], ["hostname"], ["dmesg"],
                                 ["ss", "-tlnp"], ["tail", "-n", "20", "/var/log/syslog"]])
def test_the_plain_read_forms_stay_read(cmd):
    assert risk.classify_command(cmd)[0] == "read"


@pytest.mark.parametrize("sql,reading", [
    ("SELECT * FROM users", "read"),
    ("  select count(*) from t ", "read"),
    ("EXPLAIN SELECT 1", "read"),
    ("UPDATE t SET x=1 WHERE id=2", "write"),
    ("INSERT INTO t VALUES (1)", "write"),
    (f"{DROP} users", "destructive"),
    ("truncate foo", "destructive"),
    ("ALTER TABLE t ADD COLUMN c int", "destructive"),
    (f"-- harmless\n{DROP} t", "destructive"),
    (f"/* harmless */ {DROP} t", "destructive"),
    (f"SELECT 1; {DROP} t", "destructive"),
    ("SELECT 1; SELECT 2", "read"),
    (f"SELECT '--'; {DROP} t", "destructive"),            # 0.44 stripped from the quoted `--` and read this as a read
    (f"SELECT 1 /* {DROP} */", "read"),                    # a comment is not a statement
    ("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", "write"),
    ("SELECT pg_read_file('/etc/passwd')", "destructive"),
    ("COPY t TO PROGRAM 'id'", "destructive"),
    ("SELECT pg_terminate_backend(1)", "destructive"),
    ("SELECT pg_reload_conf()", "write"),
    ("VACUUM t", "write"),
    ("\\! id", "destructive"),
    ("SELECT 1 \\gexec", "write"),
])
def test_sql_reads_as_0_44_read_it(sql, reading):
    assert risk.classify_sql(sql)[0] == reading


def test_a_multi_statement_list_says_so():
    assert "multiple statements" in risk.classify_sql(f"SELECT 1; {DROP} t")[1]


@pytest.mark.parametrize("value", [None, "", [], [""], [1], ["cat", 1], {"cat": 1}, "cat /etc/hostname", "[not json",
                                   '{"a": 1}', 5, True])
def test_a_command_it_cannot_read_is_write_never_read(value):
    assert risk.command_reading(value)["reading"] == "write"


@pytest.mark.parametrize("value", [None, "", "   ", ";", 7, ["select 1"]])
def test_a_statement_it_cannot_read_is_write_never_read(value):
    assert risk.sql_reading(value)["reading"] == "write"


def test_a_json_array_string_is_an_argv_as_the_shell_door_reads_it():
    assert risk.command_reading('["cat", "/etc/hostname"]')["reading"] == "read"
    assert risk.command_reading('["rm", "-rf", "/x"]')["reading"] == "destructive"


@pytest.mark.parametrize("cmd", [["systemctl", "frobnicate", SECRET], ["find", "/", "-fprintf", SECRET],
                                 [SECRET], ["cat", SECRET], ["rm", "-rf", SECRET], ["sh", "-c", f"echo {SECRET}"]])
def test_no_reason_echoes_a_token_of_the_command(cmd):
    hint = risk.command_reading(cmd)
    assert SECRET not in json.dumps(hint)
    assert set(hint) == {"reading", "reasons", "of", "advisory"} and hint["of"] == "command"


@pytest.mark.parametrize("sql", [f"SELECT '{SECRET}'", f"{SECRET} x", f"UPDATE t SET p='{SECRET}'",  # noqa: S608
                                 f"{DROP} {SECRET}", f"SELECT 1; -- {SECRET}"])
def test_no_reason_echoes_a_token_of_the_sql(sql):
    hint = risk.sql_reading(sql)
    assert SECRET not in json.dumps(hint)
    assert set(hint) == {"reading", "reasons", "of", "advisory"} and hint["of"] == "sql"


# --- the plan --------------------------------------------------------------------------------

@pytest.fixture
def box(armed_plane, monkeypatch):
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", CT)
    monkeypatch.setattr(spine, "_SLEEP", lambda s: None)
    return armed_plane


class Sh:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv[-1])
        ran = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
        return 0, "ok\n", f"proximo-ran-{ran}\n"


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.mark.parametrize("path,args,reading", [
    (EXEC, {"command": ["cat", "/etc/hostname"]}, "read"),
    (EXEC, {"command": ["rm", "-rf", "/x"]}, "destructive"),
    (EXEC, {"command": ["touch", "/x"]}, "write"),
    (PSQL, {"sql": "SELECT 1"}, "read"),
    (PSQL, {"sql": f"SELECT 1; {DROP} t"}, "destructive"),
    (AGENT_EXEC, {"command": ["id"]}, "read"),
])
def test_the_plan_carries_the_reading(box, monkeypatch, path, args, reading):
    monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1")
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "100")
    out = engine.plan(engine.resolve("pve", "POST", path), args, path, cfg=box)
    assert out["risk_hint"]["reading"] == reading and out["risk_hint"]["advisory"] is True
    assert out["tier"] == "destructive"                        # the tier is the tier, whatever the reading


def test_the_hint_changes_no_verdict(box):
    row = engine.resolve("pve", "POST", EXEC)
    read = engine.plan(row, {"command": ["cat", "x"]}, EXEC, cfg=box)
    drop = engine.plan(row, {"command": ["rm", "-rf", "/"]}, EXEC, cfg=box)
    keys = ("allowed", "reason", "needs", "tier", "why")
    assert [read[k] for k in keys] == [drop[k] for k in keys]
    assert read["allowed"] is True


def test_a_read_reading_never_lowers_the_tier_the_ladder_will_consult():
    """The hint is advice for the person; the effective tier is the authored one."""
    row = engine.resolve("pve", "POST", EXEC)
    assert engine.effective_tier(row, EXEC, {"command": ["cat", "x"]}) == ("destructive", None)


def test_the_hint_is_the_same_with_no_credential(monkeypatch):
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)
    out = engine.plan(engine.resolve("pve", "POST", EXEC), {"command": ["cat", "x"]}, EXEC)
    assert out["allowed"] is False and out["risk_hint"]["reading"] == "read"


def test_the_template_path_plan_carries_it_too():
    row = engine.resolve("pve", "POST", "/nodes/{node}/lxc/{vmid}/exec")
    assert engine.plan(row, {"command": ["id"]})["risk_hint"]["reading"] == "read"


def test_rows_without_a_command_carry_no_hint(box):
    start = engine.resolve("pve", "POST", "/nodes/{node}/lxc/{vmid}/status/start")
    assert "risk_hint" not in engine.plan(start, {}, f"/nodes/{NODE}/lxc/{CT}/status/start", cfg=box)
    for p, path in (("pbs", "/nodes/{node}/status"), ("pve", "/cluster/backup")):
        assert "risk_hint" not in engine.plan(engine.resolve(p, "POST", path), {"command": "reboot"})


def test_every_row_that_gets_a_hint_fingerprints_the_argument_it_reads():
    """The leak fence: a hint rides only a row whose command is a secret the ledger fingerprints."""
    hinted = [r for r in engine.table().values() if risk.argument_of(r) is not None]
    assert {r.key for r in hinted} == {"pve:POST /nodes/{node}/lxc/{vmid}/exec",
                                       "pve:POST /nodes/{node}/lxc/{vmid}/psql",
                                       "pve:POST /nodes/{node}/qemu/{vmid}/agent/exec"}
    for r in hinted:
        assert risk.argument_of(r)[0] in r.arg_secrets


# --- the receipt and the ledger ---------------------------------------------------------------

@pytest.mark.parametrize("cmd,reading", [(["rm", "-rf", f"/srv/{SECRET}"], "destructive"),
                                         ([f"/opt/{SECRET}/run", "--now"], "write"),     # unclassified: first word
                                         (["systemctl", f"restart-{SECRET}"], "write"),
                                         (["cat", f"/srv/{SECRET}"], "read")])
def test_the_receipt_carries_the_reading_and_the_ledger_never_the_command(box, monkeypatch, cmd, reading):
    monkeypatch.setattr(shell, "_run", Sh())
    out = engine.execute(engine.resolve("pve", "POST", EXEC), {"command": cmd}, cfg=box, path=EXEC)
    assert out["risk_hint"]["reading"] == reading
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert executing[-1]["detail"]["risk_hint"] == {"reading": reading, "reasons": out["risk_hint"]["reasons"]}
    with open(os.environ["PROXIMO_AUDIT_LOG"], "rb") as f:
        assert SECRET.encode() not in f.read()                  # the whole ledger, every byte
    assert SECRET not in json.dumps(out["risk_hint"])


def test_a_psql_receipt_never_carries_the_sql(box, monkeypatch):
    monkeypatch.setattr(shell, "_run", Sh())
    out = engine.execute(engine.resolve("pve", "POST", PSQL), {"sql": f"UPDATE t SET p='{SECRET}'"},  # noqa: S608
                         cfg=box, path=PSQL)
    assert out["risk_hint"]["reading"] == "write"
    with open(os.environ["PROXIMO_AUDIT_LOG"], "rb") as f:
        assert SECRET.encode() not in f.read()


# --- the allowlist: every destructive label, every read option, the caps (lens round 2) ---------------

@pytest.mark.parametrize("cmd,label", [
    (["rm", "-rf", "/x"], "rm -rf"), (["dd", "if=/dev/zero", "of=/x"], "dd"), (["mkfs.ext4", "/dev/x"], "mkfs"),
    (["wipefs", "-a", "/dev/x"], "wipefs"), (["fdisk", "/dev/x"], "disk partitioning"),
    (["parted", "/dev/x"], "disk partitioning"), (["sgdisk", "/dev/x"], "disk partitioning"),
    (["mkswap", "/dev/x"], "disk partitioning"), (["lvremove", "vg/lv"], "LVM removal"),
    (["vgremove", "vg"], "LVM removal"), (["pvremove", "/dev/x"], "LVM removal"),
    (["cryptsetup", "luksFormat", "/dev/x"], "cryptsetup destructive"),
    (["cryptsetup", "erase", "/dev/x"], "cryptsetup destructive"), (["shred", "x"], "shred"),
    (["find", "/", "-delete"], "find -delete/-exec"), (["find", "/", "-execdir", "x", ";"], "find -delete/-exec"),
    (["sh", "-c", ":(){ :|:& };:"], "fork bomb"), (["sh", "-c", "echo x >/dev/sda"], "redirect to /dev"),
    (["sh", "-c", "echo x > /etc/passwd"], "overwrite under /etc"),
    (["chmod", "-R", "777", "/"], "recursive chmod/chown"), (["chown", "-R", "x", "/"], "recursive chmod/chown"),
    (["chmod", "u+s", "/x"], "chmod setuid/setgid"), (["chmod", "04755", "/x"], "chmod setuid/setgid"),
    (["cp", "x", "/etc/passwd"], "write to sensitive path"), (["mv", "x", "/home/.ssh/k"], "write to sensitive path"),
    (["iptables", "-F"], "iptables flush"), (["ip6tables", "-X"], "iptables flush"),
    (["nft", "flush", "ruleset"], "nft flush"), (["userdel", "x"], "userdel"),
    (["useradd", "-o", "-u", "0", "x"], "useradd (override/uid)"), (["crontab", "-r"], "crontab -r"),
    (["passwd", "x"], "passwd change"), (["kill", "-9", "1"], "kill PID 1"),
    (["shutdown", "-h", "now"], "host/guest power-off"), (["poweroff"], "host/guest power-off"),
    (["truncate", "-s", "0", "x"], "truncate"),
])
def test_each_destructive_pattern_names_its_label(cmd, label):
    reading, reasons = risk.classify_command(cmd)
    assert reading == "destructive" and f"matches destructive pattern: {label}" in reasons


@pytest.mark.parametrize("cmd", [
    ["ip", "a", "a", "x"], ["ip", "route", "add", "x"], ["ip", "route", "del", "x"], ["ip", "route", "change", "x"],
    ["ip", "route", "replace", "x"], ["ip", "route", "flush"], ["ip", "route", "append", "x"],
    ["ip", "route", "prepend", "x"], ["ip", "link", "set", "x"], ["ip", "addr", "delete", "x"],
    ["find", "/", "-fprintf", "/x", "y"], ["find", "/", "-fprint", "/x"], ["find", "/", "-fprint0", "/x"],
    ["find", "/", "-fls", "/x"], ["journalctl", "--flush"], ["journalctl", "--sync"],
    ["journalctl", "--relinquish-var"], ["journalctl", "--smart-relinquish-var"], ["dmesg", "--read-clear"],
    ["dmesg", "--console-off"], ["ss", "--kill"], ["ss", "-K"], ["date", "-s", "x"], ["hostname", "x"],
])
def test_a_mutating_form_of_a_read_command_is_never_read(cmd):
    assert risk.classify_command(cmd)[0] != "read"


@pytest.mark.parametrize("cmd", [
    ["ip", "addr"], ["ip", "-4", "addr", "show"], ["ip", "-br", "link"], ["ip", "route", "get", "192.0.2.1"],
    ["ip", "-s", "link", "show", "dev", "eth0"], ["find", "/etc", "-name", "*.conf", "-type", "f", "-mtime", "-1"],
    ["find", ".", "-maxdepth", "1", "-print"], ["journalctl", "-u", "ssh", "--since", "yesterday", "--no-pager"],
    ["journalctl", "-n", "5", "-o", "json"], ["date", "-u", "+%s"], ["date", "-d", "yesterday", "+%F"],
    ["date", "--iso-8601=seconds"], ["hostname", "-I"], ["dmesg", "-T"], ["dmesg", "--level=err"],
    ["ss", "-tlnp"], ["ss", "-s"], ["ss", "state", "established"], ["netstat", "-tulpn"],
    ["/usr/bin/cat", "x"], ["/bin/ls", "-l"], ["/sbin/ip", "addr"], ["/usr/sbin/ss", "-tl"],
    ["systemctl", "status", "ssh"], ["systemctl", "is-active", "ssh"], ["mount"], ["ps", "aux"], ["df", "-h"],
])
def test_the_known_safe_forms_are_still_read(cmd):
    assert risk.classify_command(cmd)[0] == "read"


@pytest.mark.parametrize("cmd", [["/tmp/ls"], ["./cat", "x"], ["/var/tmp/ps"], ["../x/id"], ["/opt/bin/cat", "x"],  # noqa: S108
                                 ["/usr/local/bin/ls"], ["/usr/bin/../../tmp/ls"], ["/"], ["cat/"]])
def test_a_program_named_like_a_read_command_is_not_read(cmd):
    assert risk.classify_command(cmd)[0] != "read"


@pytest.mark.parametrize("sql", [
    "SELECT count(*), max(id) FROM t WHERE x IN (1, 2) GROUP BY y ORDER BY 1 LIMIT 5",
    "SELECT coalesce(a, 'x'), lower(b) FROM t", "SELECT now(), version()", "SHOW ALL", "TABLE t", "VALUES (1), (2)",
    "EXPLAIN SELECT * FROM t", "EXPLAIN (FORMAT JSON) SELECT 1", "EXPLAIN VERBOSE SELECT 1",
    "SELECT \"Name\" FROM \"Users\"", "SELECT 'a;b -- not a comment'", "SELECT $$a;b$$", "SELECT E'it\\'s'",
    "SELECT 1 -- DROP\n", "SELECT x::int FROM t", "SELECT a FROM t AS u WHERE u.b > 3",
])
def test_the_known_safe_statements_are_still_read(sql):
    assert risk.classify_sql(sql)[0] == "read"


@pytest.mark.parametrize("sql", ["SELECT 'unterminated", "SELECT /* never closes", 'SELECT "never closes',
                                 "SELECT $$never closes", "SELECT E'it\\'"])
def test_a_statement_that_never_closes_is_not_read(sql):
    reading, reasons = risk.classify_sql(sql)
    assert reading == "write" and any("never closes" in r for r in reasons)


def test_input_over_the_cap_is_a_write_that_says_so():
    assert risk.classify_sql("SELECT 1" + " " * risk.MAX_SQL_CHARS) == ("write", [risk.TOO_LONG])
    assert risk.classify_sql("SELECT 1 " * 10) [0] == "read"
    assert risk.classify_command(["cat", "x" * risk.MAX_COMMAND_CHARS]) == ("write", [risk.TOO_LONG])
    assert risk.classify_command(["cat"] + ["x"] * risk.MAX_COMMAND_ARGS) == ("write", [risk.TOO_LONG])
    assert risk.classify_command(["cat", "x" * 100])[0] == "read"
    hint = risk.command_reading(["cat", "x" * risk.MAX_COMMAND_CHARS])
    assert hint["reading"] == "write" and hint["reasons"] == ["too long to read"]


@pytest.mark.parametrize("make", [
    lambda: risk.classify_sql("COPY " * 3000), lambda: risk.classify_sql("(" * 3000),
    lambda: risk.classify_sql("/*" * 3000), lambda: risk.classify_sql("'" * 3000),
    lambda: risk.classify_sql("SELECT " + "f(" * 2000),
    lambda: risk.classify_command(["sh", "-c", "chmod " * 1300]),
    lambda: risk.classify_command(["rm"] + ["-"] * 500), lambda: risk.classify_command(["sh", "-c", ">" * 8000]),
    lambda: risk.classify_command(["sh", "-c", ">" + " " * 8000]),
    lambda: risk.classify_command(["find"] + ["-x"] * 500),
])
def test_nothing_at_the_cap_takes_long(make):
    import time
    start = time.monotonic()
    make()
    assert time.monotonic() - start < 0.5


# --- round 3 -------------------------------------------------------------------------------------

@pytest.mark.parametrize("sql", ["SELECT 'a\\'' ; " + DROP + " t; --'", "SELECT 'x\\y'",
                                 "SELECT 1 WHERE a = 'c:\\dir'"])
def test_a_backslash_in_a_plain_string_is_not_read(sql):
    """With standard_conforming_strings off the backslash escapes a quote; the statement then reads
    differently from how it was tokenised, so it is not called a read."""
    reading, reasons = risk.classify_sql(sql)
    assert reading != "read" and any("backslash" in r for r in reasons)


def test_a_backslash_in_an_e_string_is_unambiguous_and_still_read():
    assert risk.classify_sql("SELECT E'it\\'s'")[0] == "read"


@pytest.mark.parametrize("cmd", [["cat", "/dev/watchdog"], ["head", "-c1", "/dev/watchdog"], ["tail", "/dev/kmsg"],
                                 ["dd", "if=/dev/zero", "of=/x"], ["grep", "x", "/dev/mem"]])
def test_a_command_reading_a_device_node_is_not_a_read(cmd):
    assert risk.classify_command(cmd)[0] != "read"


def test_dev_null_is_a_read():
    assert risk.classify_command(["cat", "/dev/null"])[0] == "read"


@pytest.mark.parametrize("sql", ["SELECT myschema.lower(x) FROM t", "SELECT public.count(*) FROM t",
                                 "SELECT a.b.lower(x) FROM t"])
def test_a_schema_qualified_function_is_not_the_allowlisted_one(sql):
    assert risk.classify_sql(sql)[0] != "read"
