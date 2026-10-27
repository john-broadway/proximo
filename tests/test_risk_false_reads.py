"""LENS: every case below is a command or statement that CHANGES STATE (or runs arbitrary code) and
that risk.py reads as "read" today. "read" is the one claim the module stands behind, so each is a
failing assertion until the classifier stops saying it. Cases that really are reads are NOT here."""
# ruff: noqa: S108  (paths in /tmp are the data: the lookalike executables and files the commands name)
from __future__ import annotations

import pytest

from proximo.core import risk

FALSE_READ_COMMANDS = [
    # ip: abbreviated verbs, batch mode, netns exec, state-changing subcommands not in the verb list
    ["ip", "a", "a", "192.0.2.1/24", "dev", "eth0"],
    ["ip", "l", "s", "eth0", "down"],
    ["ip", "link", "s", "eth0", "up"],
    ["ip", "r", "d", "default"],
    ["ip", "-b", "/tmp/cmds"],
    ["ip", "-batch", "/tmp/cmds"],
    ["ip", "netns", "exec", "x", "sh"],
    ["ip", "route", "restore"],
    ["ip", "xfrm", "state", "allocspi"],
    # journalctl: options that write, and getopt_long abbreviations of the ones that are listed
    ["journalctl", "--setup-keys"],
    ["journalctl", "--update-catalog"],
    ["journalctl", "--rot"],
    ["journalctl", "--fl"],
    ["journalctl", "--relinq"],
    ["journalctl", "--cursor-file=/etc/cursor"],
    # date: a bare MMDDhhmm sets the clock; --set abbreviated
    ["date", "1231235959"],
    ["date", "--se=2020-01-01"],
    ["date", "--s", "2020-01-01"],
    # hostname: option forms that set the name
    ["hostname", "--file=/etc/hostname"],
    ["hostname", "-F/etc/hostname"],
    ["hostname", "-b"],
    ["hostname", "--boot"],
    # dmesg / ss abbreviated destructive options; ss -D dumps to a file
    ["dmesg", "--cl"],
    ["dmesg", "--read-c"],
    ["ss", "--ki"],
    ["ss", "-D", "/tmp/dump"],
    # a program that is only NAMED like a read command (basename() throws the directory away)
    ["/tmp/ls"],
    ["./cat", "x"],
    ["/var/tmp/ps"],
    ["../x/id"],
]


@pytest.mark.parametrize("cmd", FALSE_READ_COMMANDS, ids=lambda c: " ".join(c)[:50])
def test_command_that_changes_state_does_not_read_as_read(cmd):
    reading, _ = risk.classify_command(cmd)
    assert reading != "read"


FALSE_READ_SQL = [
    # state-changing functions behind SELECT / VALUES
    "SELECT set_config('statement_timeout','1',false)",
    "SELECT nextval('s')",
    "SELECT setval('s', 1)",
    "VALUES (nextval('s'))",
    "SELECT dblink_exec('c','x')",
    "SELECT dblink_connect('c','dbname=y')",
    "SELECT dblink_send_query('c','x')",
    "SELECT pg_advisory_lock(1)",
    "SELECT pg_advisory_xact_lock(1)",
    "SELECT pg_sleep(100000)",
    "SELECT pg_switch_wal()",
    "SELECT pg_create_restore_point('x')",
    "SELECT pg_promote()",
    "SELECT pg_backup_start('x')",
    "SELECT pg_stat_reset()",
    "SELECT pg_stat_statements_reset()",
    "SELECT pg_file_write('/tmp/x','y',true)",
    "SELECT pg_logical_emit_message(true,'a','b')",
    "SELECT pg_replication_origin_create('x')",
    "SELECT pg_wal_replay_pause()",
    "SELECT pg_notify('a','b')",
    "SELECT lo_create(0)",
    "SELECT lo_put(1,0,'x')",
    "SELECT lowrite(1,'x')",
    "SELECT lo_from_bytea(0,'x')",
    "SELECT pg_ls_logdir()",
    "SELECT pg_ls_waldir()",
    "SELECT pg_stat_file('/etc/passwd')",
    "SELECT pg_logdir_ls()",
    "SELECT my_function_that_writes(1)",
    # a quoted identifier defeats the \bname\s*\( function scan
    'SELECT "pg_terminate_backend"(1)',
    'SELECT public."pg_terminate_backend"(1)',
    'SELECT U&"pg_terminate_backend"(1)',
    # SELECT ... INTO creates a table
    "SELECT * INTO newtab FROM t",
    "SELECT * INTO TEMP newtab FROM t",
    "SELECT 1 UNION SELECT 2 INTO x",
    # EXPLAIN ANALYZE executes its statement; only DML/DDL-keyword statements are caught
    "EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1",
    "EXPLAIN (ANALYZE) SELECT * INTO x FROM t",
    "EXPLAIN ANALYZE SELECT nextval('s')",
    "EXPLAIN ANALYZE REFRESH MATERIALIZED VIEW v",
    "EXPLAIN ANALYZE EXECUTE p",
    # keyword assembled at run time
    "SELECT query_to_xml('DEL'||'ETE FROM t', true, true, '')",
]


@pytest.mark.parametrize("sql", FALSE_READ_SQL, ids=lambda s: s[:50])
def test_statement_that_changes_state_does_not_read_as_read(sql):
    reading, _ = risk.classify_sql(sql)
    assert reading != "read"
