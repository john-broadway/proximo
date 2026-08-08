"""PLAN pillar tests — the dry-run preview + honest risk classification.

Pure functions, no live Proxmox. plan_power uses a tiny fake api with guest_status().
Bypass cases (multi-statement SQL, sh -c wrappers) are tested up front: the classifier
must scan the whole command/SQL, not just the leading token.
"""

from __future__ import annotations

from proximo.planning import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    Plan,
    _fmt_uptime,
    _max_risk,
    classify_command,
    classify_sql,
    command_fingerprint,
    plan_exec,
    plan_power,
    plan_psql,
    plan_rollback,
    plan_snapshot_create,
    plan_snapshot_delete,
    sql_fingerprint,
    undo_snapname,
)


class _FakeApi:
    """Stands in for ApiBackend.guest_status during planning."""

    def __init__(self, status: dict):
        self._status = status
        self.calls: list[tuple] = []

    def guest_status(self, vmid, kind="lxc", node=None):
        self.calls.append((vmid, kind, node))
        return self._status


# --- Plan dataclass ---

def test_plan_as_dict_has_expected_shape():
    p = Plan(
        action="ct_exec", target="105", change="run in 105: true",
        current={}, blast_radius=[], risk=RISK_LOW, risk_reasons=["x"],
    )
    d = p.as_dict()
    assert d["action"] == "ct_exec"
    assert d["risk"] == RISK_LOW
    assert d["to_proceed"] == "re-call with confirm=true"
    assert "blast_radius" in d and "risk_reasons" in d


# --- power planning ---

def test_power_start_already_running_is_noop():
    api = _FakeApi({"status": "running", "name": "web", "uptime": 100})
    p = plan_power(api, "1975", "start")
    assert p.risk == RISK_NONE
    assert any("no-op" in b for b in p.blast_radius)


def test_power_stop_already_stopped_is_noop():
    api = _FakeApi({"status": "stopped", "name": "web"})
    p = plan_power(api, "1975", "stop")
    assert p.risk == RISK_NONE


def test_power_stop_running_is_high_and_warns_halt():
    api = _FakeApi({"status": "running", "name": "web", "uptime": 86400 * 12})
    p = plan_power(api, "1975", "stop")
    assert p.risk == RISK_HIGH
    assert any("halt" in b.lower() for b in p.blast_radius)
    assert p.change == "stop lxc 1975"


def test_power_shutdown_running_is_medium():
    api = _FakeApi({"status": "running", "name": "web", "uptime": 500})
    assert plan_power(api, "1975", "shutdown").risk == RISK_MEDIUM


def test_power_reboot_running_is_high():
    api = _FakeApi({"status": "running", "name": "web", "uptime": 500})
    assert plan_power(api, "1975", "reboot").risk == RISK_HIGH


def test_power_start_stopped_is_low():
    api = _FakeApi({"status": "stopped", "name": "web"})
    assert plan_power(api, "1975", "start").risk == RISK_LOW


def test_power_includes_live_state_in_current():
    api = _FakeApi({"status": "running", "name": "web", "uptime": 500})
    p = plan_power(api, "1975", "stop")
    assert p.current.get("status") == "running"
    assert api.calls == [("1975", "lxc", None)]


# --- command classification ---

def test_command_read_is_low():
    risk, reasons = classify_command(["cat", "/etc/hostname"])
    assert risk == RISK_LOW
    assert any("read" in r.lower() for r in reasons)


def test_command_rm_rf_is_high():
    risk, reasons = classify_command(["rm", "-rf", "/var/lib/x"])
    assert risk == RISK_HIGH
    assert any("rm -rf" in r for r in reasons)


def test_command_unknown_is_medium():
    risk, _ = classify_command(["systemctl", "restart", "nginx"])
    assert risk == RISK_MEDIUM


def test_command_systemctl_status_is_low():
    risk, _ = classify_command(["systemctl", "status", "nginx"])
    assert risk == RISK_LOW


def test_command_dangerous_inside_sh_c_is_high():
    # Bypass attempt: hide the destructive command inside a shell wrapper.
    risk, reasons = classify_command(["sh", "-c", "rm -rf /tmp/x"])
    assert risk == RISK_HIGH


def test_command_dd_and_mkfs_are_high():
    assert classify_command(["dd", "if=/dev/zero", "of=/dev/sda"])[0] == RISK_HIGH
    assert classify_command(["mkfs.ext4", "/dev/sdb1"])[0] == RISK_HIGH


# --- SQL classification ---

def test_sql_select_is_low():
    risk, reasons = classify_sql("SELECT * FROM users")
    assert risk == RISK_LOW
    assert any("read" in r.lower() for r in reasons)


def test_sql_select_case_insensitive():
    assert classify_sql("  select count(*) from t ")[0] == RISK_LOW


def test_sql_update_is_medium():
    assert classify_sql("UPDATE t SET x=1 WHERE id=2")[0] == RISK_MEDIUM


def test_sql_drop_is_high():
    risk, reasons = classify_sql("DROP TABLE users")
    assert risk == RISK_HIGH
    assert any("ddl" in r.lower() or "schema" in r.lower() for r in reasons)


def test_sql_truncate_is_high():
    assert classify_sql("truncate foo")[0] == RISK_HIGH


def test_sql_multistatement_takes_max_risk_and_flags():
    # Bypass attempt: lead with a harmless SELECT, smuggle a DROP after the semicolon.
    risk, reasons = classify_sql("SELECT 1; DROP TABLE t")
    assert risk == RISK_HIGH
    assert any("multiple statement" in r.lower() for r in reasons)


def test_sql_leading_comment_ignored():
    assert classify_sql("-- harmless\nDROP TABLE t")[0] == RISK_HIGH


# --- exec / psql plan wrappers carry the honesty note ---

def test_plan_exec_carries_heuristic_note():
    p = plan_exec("105", ["rm", "-rf", "/x"])
    assert p.risk == RISK_HIGH
    assert "heuristic" in p.note.lower()
    assert p.action == "ct_exec"


def test_plan_psql_carries_heuristic_note_and_classifies():
    p = plan_psql("105", "DROP TABLE t", db="appdb")
    assert p.risk == RISK_HIGH
    assert "heuristic" in p.note.lower()
    assert "appdb" in p.change


def test_sql_fingerprint_has_no_raw_sql():
    fp = sql_fingerprint("DROP TABLE secrets")
    assert "sql" not in fp                            # no raw-sql key
    assert "DROP TABLE secrets" not in str(fp)        # body appears nowhere
    assert len(fp["sql_sha256"]) == 64
    assert fp["sql_len"] == len("DROP TABLE secrets")


def test_sql_fingerprint_kind_is_leading_keyword():
    assert sql_fingerprint("select 1")["sql_kind"] == "SELECT"
    assert sql_fingerprint("  DROP TABLE t")["sql_kind"] == "DROP"


def test_plan_psql_keeps_sql_by_default():
    p = plan_psql("105", "DROP TABLE t", db="appdb")
    assert "DROP TABLE t" in p.change


def test_plan_psql_redacts_sql_when_asked():
    p = plan_psql("105", "DROP TABLE secrets", db="appdb", redact=True)
    assert "DROP TABLE secrets" not in p.change
    assert "sha256:" in p.change
    assert p.risk == RISK_HIGH   # classification stays honest even when the body is hidden


def test_command_fingerprint_has_no_raw_args():
    fp = command_fingerprint(["mysql", "--password", "hunter2"])
    assert "command" not in fp
    assert "hunter2" not in str(fp)             # secret arg appears nowhere
    assert len(fp["cmd_sha256"]) == 64
    assert fp["cmd_kind"] == "mysql"            # executable name is safe to show; secrets are in args


def test_plan_exec_keeps_command_by_default():
    p = plan_exec("105", ["rm", "-rf", "/x"])
    assert "rm" in p.change and "/x" in p.change


def test_plan_exec_redacts_command_when_asked():
    p = plan_exec("105", ["mysql", "--password", "hunter2"], redact=True)
    assert "hunter2" not in p.change
    assert "sha256:" in p.change


# --- L2: the CONSENT approver must be able to read what the redacted hash stands for ---

def test_redacted_plan_surfaces_operator_cleartext_for_approver():
    # The redacted `change` is a hash the approver can't read; the un-redacted command is surfaced
    # in as_dict (operator_cleartext) so they see WHAT they authorize.
    p = plan_exec("105", ["mysql", "--password", "hunter2"], redact=True)
    assert "hunter2" not in p.change                        # ledger-bound field stays redacted
    assert p.as_dict()["operator_cleartext"] == "mysql --password hunter2"


def test_unredacted_plan_omits_operator_cleartext():
    p = plan_exec("105", ["rm", "-rf", "/x"], redact=False)
    assert "operator_cleartext" not in p.as_dict()          # change already shows it; no duplicate


def test_psql_redacted_plan_surfaces_cleartext():
    p = plan_psql("105", "DROP TABLE secrets", db="appdb", redact=True)
    assert "DROP TABLE secrets" not in p.change
    assert "DROP TABLE secrets" in p.as_dict()["operator_cleartext"]


def test_operator_cleartext_excluded_from_consent_id():
    # The preview-only field must NOT enter the consent_id hash, or a grant for the redacted plan
    # would not match and the gate would break.
    from proximo.consent import consent_id_for
    a = plan_exec("105", ["mysql", "--password", "hunter2"], redact=True)
    b = plan_exec("105", ["mysql", "--password", "hunter2"], redact=True)
    b.operator_cleartext = ""                               # differ ONLY in the preview field
    assert consent_id_for(a) == consent_id_for(b)


# === Redteam regressions: guard every path to LOW ============================
# A destructive command/SQL must NEVER rate "low" ("looks read-only"). MEDIUM is the
# honest floor; HIGH is enrichment. These were confirmed bypasses (2026-06-07 redteam).

# --- whitelist audit: read-only commands with mutating FORMS must not rate low ---

def test_find_delete_is_not_read_only():
    risk, _ = classify_command(["find", "/", "-delete"])
    assert risk == RISK_HIGH  # was 'low: looks read-only'


def test_find_exec_rm_is_not_read_only():
    assert classify_command(["find", "/", "-exec", "rm", "{}", "+"])[0] == RISK_HIGH


def test_find_plain_search_is_low():
    assert classify_command(["find", "/var", "-name", "*.log"])[0] == RISK_LOW


def test_ip_route_add_is_not_read_only():
    risk, _ = classify_command(["ip", "route", "add", "default", "via", "10.0.0.1"])
    assert risk == RISK_MEDIUM  # was 'low: looks read-only'


def test_ip_link_set_down_is_not_read_only():
    assert classify_command(["ip", "link", "set", "eth0", "down"])[0] == RISK_MEDIUM


def test_ip_addr_show_is_low():
    assert classify_command(["ip", "addr", "show"])[0] == RISK_LOW


def test_mount_with_target_is_not_read_only():
    assert classify_command(["mount", "/dev/sdb1", "/mnt"])[0] == RISK_MEDIUM


def test_mount_bare_listing_is_low():
    assert classify_command(["mount"])[0] == RISK_LOW


# --- curated HIGH enrichment: catastrophic ops promoted from medium ---

def test_shred_is_high():
    assert classify_command(["shred", "-u", "/etc/shadow"])[0] == RISK_HIGH


def test_lvremove_is_high():
    assert classify_command(["lvremove", "-f", "vg/lv"])[0] == RISK_HIGH


def test_cryptsetup_luksformat_is_high():
    assert classify_command(["cryptsetup", "luksFormat", "/dev/sdb"])[0] == RISK_HIGH


def test_chmod_setuid_is_high():
    assert classify_command(["chmod", "4755", "/bin/bash"])[0] == RISK_HIGH
    assert classify_command(["chmod", "+s", "/bin/bash"])[0] == RISK_HIGH


def test_kill_pid1_is_high():
    assert classify_command(["kill", "-9", "1"])[0] == RISK_HIGH


def test_iptables_flush_is_high():
    assert classify_command(["iptables", "-F"])[0] == RISK_HIGH


def test_systemctl_mask_is_high():
    assert classify_command(["systemctl", "mask", "sshd"])[0] == RISK_HIGH


def test_tee_to_sensitive_path_is_high():
    assert classify_command(["tee", "/etc/passwd"])[0] == RISK_HIGH


def test_userdel_is_high():
    assert classify_command(["userdel", "-r", "root"])[0] == RISK_HIGH


# --- SQL: guard the path to LOW ---

def test_sql_copy_program_is_rce_high():
    risk, reasons = classify_sql("COPY t TO PROGRAM 'rm -rf /'")
    assert risk == RISK_HIGH  # was 'medium: write/DML (COPY)'
    assert any("program" in r.lower() for r in reasons)


def test_sql_select_dangerous_function_is_not_read():
    # SELECT carrying a dangerous system function is NOT a read.
    assert classify_sql("SELECT pg_terminate_backend(1234)")[0] == RISK_HIGH
    assert classify_sql("SELECT lo_import('/etc/passwd')")[0] == RISK_HIGH
    assert classify_sql("SELECT pg_drop_replication_slot('s')")[0] == RISK_HIGH


def test_sql_pg_read_file_is_not_read():
    assert classify_sql("SELECT pg_read_file('/etc/passwd')")[0] == RISK_HIGH


def test_sql_cte_smuggled_delete_names_the_keyword():
    # WITH ... DELETE is medium (DML) — and the reason must name the embedded write, not hide it.
    risk, reasons = classify_sql("WITH x AS (SELECT 1) DELETE FROM t")
    assert risk == RISK_MEDIUM
    assert any("delete" in r.lower() for r in reasons)


def test_sql_nested_block_comment_stripped():
    # Nested /* /* */ */ comments must not leave a destructive remnant unparsed.
    assert classify_sql("/* /* x */ */ SELECT version()")[0] == RISK_LOW


# --- helper hardening (latent defects) ---

def test_max_risk_tolerates_unknown_string():
    assert _max_risk("high", "definitely-not-a-tier") == "high"  # no KeyError


def test_fmt_uptime_tolerates_non_finite():
    assert _fmt_uptime(float("inf")) == ""   # no OverflowError
    assert _fmt_uptime(float("nan")) == ""   # no ValueError
    assert _fmt_uptime(-5) == ""


# === UNDO pillar: snapshot plans ============================================

class _SnapApi:
    def __init__(self, snaps):
        self._snaps = snaps

    def snapshot_list(self, vmid, kind="lxc", node=None):
        return self._snaps


def test_undo_snapname_prefix_and_valid():
    from proximo.backends import _SNAPNAME_RE
    n = undo_snapname()
    assert n.startswith("proximo_undo_")
    assert _SNAPNAME_RE.match(n)  # must be a valid PVE snapshot name


def test_plan_rollback_is_high_and_warns_discard():
    p = plan_rollback(_SnapApi([{"name": "before_x", "snaptime": 1700000000}]), "105", "before_x")
    assert p.risk == RISK_HIGH
    assert any("discard" in b.lower() for b in p.blast_radius)
    assert p.action == "pve_rollback"


def test_plan_rollback_notes_missing_snapshot():
    p = plan_rollback(_SnapApi([{"name": "other"}]), "105", "before_x")
    notes = p.risk_reasons + p.blast_radius
    assert any("not found" in n.lower() or "will fail" in n.lower() for n in notes)


def test_plan_rollback_blast_not_contradictory_when_missing():
    # When the snapshot is absent, blast_radius must NOT claim it "DISCARDS all changes" — nothing
    # gets discarded if the rollback will fail. The two fields must agree.
    p = plan_rollback(_SnapApi([{"name": "other"}]), "105", "before_x")
    assert not any("discards all" in b.lower() for b in p.blast_radius)


def test_plan_rollback_warns_description_and_tags_not_reverted():
    # PVE does NOT include 'description' or 'tags' in snapshots, so rollback never reverts them.
    # The PLAN must warn — a user rolling back expecting those to revert is otherwise surprised
    # (real dogfood finding 2026-06-24: a set description survived a rollback).
    p = plan_rollback(_SnapApi([{"name": "before_x", "snaptime": 1700000000}]), "105", "before_x")
    warn = next((b for b in p.blast_radius if "description" in b.lower()), "")
    assert "tags" in warn.lower()
    assert "not" in warn.lower() and "revert" in warn.lower()


def test_plan_snapshot_create_is_low():
    p = plan_snapshot_create("105", "before_x")
    assert p.risk == RISK_LOW
    assert p.action == "pve_snapshot_create"


def test_plan_snapshot_create_discloses_storage_dependency():
    p = plan_snapshot_create("105", "before_x")
    text = " ".join(p.blast_radius + [p.note]).lower()
    assert "storage" in text  # the storage caveat must be in the preview, not just the tool docstring


def test_undo_snapname_is_unique_across_calls():
    # Sequential calls must not collide (was second-resolution → duplicate name).
    assert undo_snapname() != undo_snapname()


def test_plan_snapshot_delete_is_medium():
    p = plan_snapshot_delete("105", "before_x")
    assert p.risk == RISK_MEDIUM
    assert p.action == "pve_snapshot_delete"


def test_plan_affected_defaults_empty_and_serializes():
    p = Plan(action="x", target="t", change="c", current={}, blast_radius=[],
             risk="high", risk_reasons=[])
    assert p.affected == []
    assert p.as_dict()["affected"] == []


def test_plan_affected_roundtrips_in_as_dict():
    entry = {"resource": "qemu/101", "severity": "high"}
    p = Plan(action="x", target="t", change="c", current={}, blast_radius=[],
             risk="high", risk_reasons=[], affected=[entry])
    assert p.as_dict()["affected"] == [entry]


def test_plan_complete_defaults_true_and_serializes():
    p = Plan(action="x", target="t", change="c", current={}, blast_radius=[],
             risk="high", risk_reasons=[])
    assert p.complete is True and p.as_dict()["complete"] is True
