"""Field projection — lean list responses (the response-payload half of the context-cost work).

Schema bloat wastes context; response bloat corrupts answers (a 12B model with the full
25-field guest list in context answered "19 guests" on a 28-guest cluster). List tools
therefore default to a curated lean field set, with `fields` as the escape hatch:
`fields="all"` returns the raw payload, a comma list projects custom fields, and a field
no row carries fails closed naming what IS available — same posture as the scoping layers.

Mirrors test_provisioning.py style: pure-logic tests first, then the server seam with a
fake api + real ledger via monkeypatched _svc.
"""

from __future__ import annotations

import pytest

from proximo.backends import ProximoError
from proximo.projection import envelope_rows, project_rows

# ---------------------------------------------------------------------------
# Pure logic — project_rows
# ---------------------------------------------------------------------------

LEAN = ("vmid", "name", "type", "status")

FAT_ROWS = [
    # modeled on the real /nodes/<n>/lxc shape: running guest, PSI metrics and all
    {"vmid": 100, "name": "web", "type": "lxc", "status": "running", "uptime": 12345,
     "pid": 4711, "cpu": 0.01, "cpus": 4, "mem": 1024, "maxmem": 2048, "swap": 0,
     "maxswap": 512, "disk": 10, "maxdisk": 20, "diskread": 1, "diskwrite": 2,
     "netin": 3, "netout": 4, "pressurecpusome": "0.00", "pressurecpufull": "0.00",
     "pressurememorysome": "0.00", "pressurememoryfull": "0.00",
     "pressureiosome": "0.00", "pressureiofull": "0.00", "tags": "prod;web"},
    # stopped guest: no pid, no pressure metrics — rows are shape-heterogeneous
    {"vmid": 101, "name": "db", "type": "qemu", "status": "stopped", "uptime": 0,
     "cpu": 0, "cpus": 2, "mem": 0, "maxmem": 4096, "disk": 0, "maxdisk": 30,
     "diskread": 0, "diskwrite": 0, "netin": 0, "netout": 0, "memhost": 0},
]


def test_default_projects_to_the_lean_set():
    out = project_rows(FAT_ROWS, None, LEAN)
    assert out == [
        {"vmid": 100, "name": "web", "type": "lxc", "status": "running"},
        {"vmid": 101, "name": "db", "type": "qemu", "status": "stopped"},
    ]


def test_lean_field_absent_from_a_row_is_omitted_not_none():
    # `tags` is lean-listed but only the first row carries it.
    out = project_rows(FAT_ROWS, None, LEAN + ("tags",))
    assert out[0]["tags"] == "prod;web"
    assert "tags" not in out[1]


def test_all_returns_rows_untouched():
    out = project_rows(FAT_ROWS, "all", LEAN)
    assert out == FAT_ROWS


def test_all_is_case_insensitive_and_stripped():
    assert project_rows(FAT_ROWS, "  ALL ", LEAN) == FAT_ROWS


def test_custom_fields_project_in_requested_order():
    out = project_rows(FAT_ROWS, "name, maxmem ,vmid", LEAN)
    assert out[0] == {"name": "web", "maxmem": 2048, "vmid": 100}
    assert list(out[0]) == ["name", "maxmem", "vmid"]


def test_custom_field_present_in_only_some_rows_is_kept_where_present():
    out = project_rows(FAT_ROWS, "vmid,pid", LEAN)
    assert out[0] == {"vmid": 100, "pid": 4711}
    assert out[1] == {"vmid": 101}


def test_unknown_field_fails_closed_naming_available_fields():
    with pytest.raises(ProximoError) as ei:
        project_rows(FAT_ROWS, "vmid,pressureio", LEAN)
    msg = str(ei.value)
    assert "pressureio" in msg
    # the error teaches: it names what IS available
    assert "pressureiosome" in msg


def test_blank_fields_is_an_error_not_a_silent_default():
    with pytest.raises(ProximoError):
        project_rows(FAT_ROWS, "  ", LEAN)
    with pytest.raises(ProximoError):
        project_rows(FAT_ROWS, " , ", LEAN)


def test_empty_rows_pass_through_without_validation():
    # Nothing to validate a custom list against — an empty estate is not a typo.
    assert project_rows([], "anything", LEAN) == []
    assert project_rows([], None, LEAN) == []


def test_non_dict_rows_pass_through_untouched():
    # Defensive: a backend that hands back strings must not crash the projector.
    rows = ["UPID:pve:0001", {"vmid": 100, "name": "web", "cpu": 0.1}]
    out = project_rows(rows, None, ("vmid", "name"))
    assert out[0] == "UPID:pve:0001"
    assert out[1] == {"vmid": 100, "name": "web"}


# ---------------------------------------------------------------------------
# Pure logic — envelope_rows
#
# Live-proven 2026-07-28 (mistral-nemo:12b, 16k ctx, the real 28-guest cluster): with lean
# rows alone the model counted "24 guests" every run; with {total, by_status, guests} it
# answered 28/18/10 three-for-three. Counting is the server's job, not the model's.
# ---------------------------------------------------------------------------

def test_envelope_counts_and_keys():
    out = envelope_rows(FAT_ROWS, project_rows(FAT_ROWS, None, LEAN), "guests", "status")
    assert out["total"] == 2
    assert out["by_status"] == {"running": 1, "stopped": 1}
    assert out["guests"] == project_rows(FAT_ROWS, None, LEAN)


def test_envelope_counts_come_from_raw_rows_even_when_projection_drops_the_axis():
    projected = project_rows(FAT_ROWS, "vmid,name", LEAN)  # no `status` in the rows
    out = envelope_rows(FAT_ROWS, projected, "guests", "status")
    assert out["by_status"] == {"running": 1, "stopped": 1}
    assert "status" not in out["guests"][0]


def test_envelope_on_empty_rows():
    out = envelope_rows([], [], "resources", "type")
    assert out == {"total": 0, "by_type": {}, "resources": []}


def test_envelope_rows_missing_the_axis_count_under_unknown():
    rows = [{"id": "a", "type": "node"}, {"id": "b"}]
    out = envelope_rows(rows, rows, "resources", "type")
    assert out["by_type"] == {"node": 1, "unknown": 1}


# ---------------------------------------------------------------------------
# Server seam — the tools apply projection + envelope by default
# ---------------------------------------------------------------------------

def _wire(monkeypatch, tmp_path, api_obj):
    import proximo.server as server
    from proximo.audit import AuditLedger
    from proximo.config import ProximoConfig

    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=str(tmp_path / "audit.log"))
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api_obj, None, ledger))
    return server


class _GuestApi:
    def list_guests(self, node=None):
        return [dict(r) for r in FAT_ROWS]


class _ResourcesApi:
    # cluster_ops.cluster_resources drives the raw REST read
    def _get(self, path):
        return [
            {"id": "lxc/100", "type": "lxc", "node": "pve", "status": "running",
             "name": "web", "vmid": 100, "cpu": 0.01, "maxcpu": 4, "mem": 1024,
             "maxmem": 2048, "disk": 10, "maxdisk": 20, "uptime": 12345,
             "netin": 3, "netout": 4, "diskread": 1, "diskwrite": 2,
             "template": 0, "hastate": ""},
            {"id": "storage/pve/local", "type": "storage", "node": "pve",
             "status": "available", "storage": "local", "disk": 5, "maxdisk": 100,
             "plugintype": "dir", "content": "iso,vztmpl", "shared": 0},
        ]


def test_pve_list_guests_is_a_counted_lean_envelope_by_default(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _GuestApi())
    out = server.pve_list_guests()
    # the counting is the server's job — a 12B model given raw rows counted 24 of 28
    assert out["total"] == 2
    assert out["by_status"] == {"running": 1, "stopped": 1}
    assert {"vmid", "name", "type", "status"} <= set(out["guests"][0])
    assert "pressurecpusome" not in out["guests"][0]
    assert "netin" not in out["guests"][0]


def test_pve_list_guests_fields_all_keeps_raw_rows_inside_the_envelope(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _GuestApi())
    out = server.pve_list_guests(fields="all")
    assert out["guests"] == FAT_ROWS
    assert out["total"] == 2


def test_pve_list_guests_custom_fields(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _GuestApi())
    out = server.pve_list_guests(fields="vmid,mem,maxmem")
    assert out["guests"][0] == {"vmid": 100, "mem": 1024, "maxmem": 2048}
    # counts survive a projection that drops the status column
    assert out["by_status"] == {"running": 1, "stopped": 1}


def test_pve_cluster_resources_is_a_counted_lean_envelope_by_default(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _ResourcesApi())
    out = server.pve_cluster_resources()
    assert out["total"] == 2
    assert out["by_type"] == {"lxc": 1, "storage": 1}
    vm, storage = out["resources"]
    assert vm["id"] == "lxc/100" and vm["status"] == "running"
    assert "netin" not in vm and "diskwrite" not in vm
    # mixed shapes: the storage row keeps its identity fields, sans usage counters
    assert storage["storage"] == "local"
    assert "plugintype" not in storage


def test_pve_cluster_resources_fields_all_keeps_raw_rows(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _ResourcesApi())
    out = server.pve_cluster_resources(fields="all")
    assert "plugintype" in out["resources"][1] and "netin" in out["resources"][0]


# ---------------------------------------------------------------------------
# cap_newest — the opt-in hazard-class cap (M4 option D, John 2026-08-11)
# ---------------------------------------------------------------------------
# Backup/snapshot/volume listings are ABSENCE-CHECK ground truth: a row missing from a
# capped slice must never read as "the backup failed". So the cap is opt-in (None =
# untouched passthrough, order included), newest-first when asked, and zero/negative is
# refused outright — never coerced to "all".

_CAP_ROWS = [
    {"volid": "old", "ctime": 100},
    {"volid": "new", "ctime": 300},
    {"volid": "mid", "ctime": 200},
    {"volid": "no-ts"},
]


def test_cap_newest_none_is_untouched_passthrough():
    from proximo.projection import cap_newest
    rows = [dict(r) for r in _CAP_ROWS]
    out = cap_newest(rows, None, "ctime")
    assert out == _CAP_ROWS          # same rows, same ORDER — the wire's promise intact


def test_cap_newest_returns_newest_first():
    from proximo.projection import cap_newest
    out = cap_newest([dict(r) for r in _CAP_ROWS], 2, "ctime")
    assert [r["volid"] for r in out] == ["new", "mid"]


def test_cap_newest_rows_missing_the_key_sort_oldest():
    from proximo.projection import cap_newest
    out = cap_newest([dict(r) for r in _CAP_ROWS], 4, "ctime")
    assert out[-1]["volid"] == "no-ts"


def test_cap_newest_limit_beyond_len_returns_all():
    from proximo.projection import cap_newest
    assert len(cap_newest([dict(r) for r in _CAP_ROWS], 99, "ctime")) == 4


def test_cap_newest_rejects_zero_and_negative():
    from proximo.projection import cap_newest
    for bad in (0, -1):
        with pytest.raises(ProximoError, match="positive"):
            cap_newest([dict(r) for r in _CAP_ROWS], bad, "ctime")


class _BackupApi:
    class config:  # backup_list/storage_content default the node from api.config
        node = "pve"

    def _get(self, path, params=None):
        return [
            {"volid": f"backup/vzdump-{i}", "ctime": i, "content": "backup"}
            for i in (5, 1, 3)
        ]


def test_pve_backup_list_limit_is_opt_in_and_newest_first(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _BackupApi())
    full = server.pve_backup_list(storage="local")
    assert [r["ctime"] for r in full] == [5, 1, 3]     # untouched without limit
    capped = server.pve_backup_list(storage="local", limit=2)
    assert [r["ctime"] for r in capped] == [5, 3]


def test_pve_storage_content_limit_is_opt_in_and_newest_first(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _BackupApi())
    full = server.pve_storage_content(storage="local")
    assert len(full) == 3
    capped = server.pve_storage_content(storage="local", limit=1)
    assert [r["ctime"] for r in capped] == [5]


def test_cap_newest_survives_string_timestamps_and_honors_numeric_ones():
    # A backend row carrying ctime as a numeric STRING must not crash sorted() with a
    # mixed int/str TypeError, and its value must still count as its timestamp; a
    # non-numeric string sorts oldest like a missing key (redteam finding, 2026-08-11).
    from proximo.projection import cap_newest
    rows = [
        {"volid": "int", "ctime": 200},
        {"volid": "numstr", "ctime": "300"},
        {"volid": "garbage", "ctime": "not-a-time"},
    ]
    out = cap_newest(rows, 3, "ctime")
    assert [r["volid"] for r in out] == ["numstr", "int", "garbage"]


def test_cap_newest_sorts_rfc3339_string_timestamps_by_value():
    # PMG's view of PBS snapshots types backup-time as an RFC 3339 STRING (documented
    # divergence, pmg.py) — float() fails on it, so without ISO support every row sorts
    # equal and "newest N" silently becomes "first N in API order" (scout finding,
    # 2026-08-11). The cap must order ISO strings by their actual instant.
    from proximo.projection import cap_newest
    rows = [
        {"id": "old", "backup-time": "2026-08-01T00:00:00Z"},
        {"id": "new", "backup-time": "2026-08-11T03:00:00Z"},
        {"id": "mid", "backup-time": "2026-08-05T12:00:00+00:00"},
    ]
    out = cap_newest(rows, 2, "backup-time")
    assert [r["id"] for r in out] == ["new", "mid"]


def test_cap_newest_mixed_epoch_and_iso_do_not_crash_and_order_sanely():
    from proximo.projection import cap_newest
    rows = [
        {"id": "epoch", "t": 1754900000},                      # 2025-08-11-ish epoch
        {"id": "iso", "t": "2026-08-11T00:00:00Z"},
        {"id": "none", "t": None},
    ]
    out = cap_newest(rows, 3, "t")
    assert out[-1]["id"] == "none"          # missing still sorts oldest
    assert {out[0]["id"], out[1]["id"]} == {"epoch", "iso"}


def test_cap_newest_naive_iso_is_deterministic_regardless_of_box_timezone(monkeypatch):
    # A timezone-NAIVE ISO string must not sort differently on differently-zoned boxes
    # (redteam, 2026-08-11): naive datetimes are pinned to UTC before .timestamp().
    import time

    from proximo.projection import cap_newest
    # Chosen to DISCRIMINATE: naive 03:00 read as UTC sorts BELOW aware 05:00Z, but read
    # in America/New_York (=07:00Z) it sorts ABOVE — an un-pinned implementation flips order.
    rows = [{"id": "naive", "t": "2026-08-11T03:00:00"}, {"id": "aware", "t": "2026-08-11T05:00:00Z"}]
    results = []
    for tz in ("UTC", "America/New_York"):
        monkeypatch.setenv("TZ", tz)
        time.tzset()
        out = cap_newest([dict(r) for r in rows], 2, "t")
        results.append([r["id"] for r in out])
    monkeypatch.delenv("TZ")
    time.tzset()
    assert results[0] == results[1] == ["aware", "naive"]   # naive pinned to UTC


# ---------------------------------------------------------------------------
# cap_top + envelope_capped — the estate-scale statistics envelope (0.32.0 Bucket 2)
# ---------------------------------------------------------------------------
# Per-correspondent statistics scale with the estate's mail history, not its config.
# The envelope's `total` is the complete count (the server's job); a capped row list is
# the top slice by a metric column, never the population — and never "newest", because
# these rows carry no timestamp.

_TOP_ROWS = [
    {"who": "a@x", "count": 5},
    {"who": "b@x", "count": 40},
    {"who": "c@x", "count": "12"},   # backend handing a numeric string still sorts by value
    {"who": "d@x"},                  # missing metric sorts last
]


def test_cap_top_returns_top_n_by_metric_descending():
    from proximo.projection import cap_top
    out = cap_top([dict(r) for r in _TOP_ROWS], 2, "count")
    assert [r["who"] for r in out] == ["b@x", "c@x"]


def test_cap_top_none_is_untouched_passthrough():
    from proximo.projection import cap_top
    rows = [dict(r) for r in _TOP_ROWS]
    assert cap_top(rows, None, "count") == _TOP_ROWS


def test_cap_top_zero_and_negative_are_refused_never_coerced():
    import pytest as _pytest

    from proximo.backends import ProximoError
    from proximo.projection import cap_top
    for bad in (0, -3):
        with _pytest.raises(ProximoError):
            cap_top([dict(r) for r in _TOP_ROWS], bad, "count")


def test_cap_top_missing_metric_sorts_last():
    from proximo.projection import cap_top
    out = cap_top([dict(r) for r in _TOP_ROWS], 4, "count")
    assert out[-1]["who"] == "d@x"


def test_envelope_capped_counts_raw_not_returned():
    from proximo.projection import envelope_capped
    capped = _TOP_ROWS[:2]
    out = envelope_capped(_TOP_ROWS, capped, "senders")
    assert out["total"] == 4
    assert out["returned"] == 2
    assert out["senders"] == capped


def test_envelope_capped_empty_rows():
    from proximo.projection import envelope_capped
    out = envelope_capped([], [], "receivers")
    assert out == {"total": 0, "returned": 0, "receivers": []}


# ---------------------------------------------------------------------------
# Server seam — the 0.32.0 Bucket-2 envelopes (estate-scale inventory + PMG statistics)
# ---------------------------------------------------------------------------
# Inventory tools envelope WITHOUT a cap (sibling parity with pve_list_guests /
# pve_cluster_resources; capping unordered inventory is the rosters dishonesty).
# Per-correspondent PMG statistics envelope WITH a default top-by-count cap — the
# context-blowup class the bucket exists for. limit=None (explicit) = all rows.

def _wire_pdm(monkeypatch, tmp_path, pdm_obj):
    from types import SimpleNamespace

    import proximo.server as server
    from proximo.audit import AuditLedger
    from proximo.config import ProximoConfig

    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=str(tmp_path / "audit.log"))
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, ledger))
    monkeypatch.setattr(server, "_pdm", lambda: (SimpleNamespace(), pdm_obj))
    monkeypatch.setattr(server, "_pmg", lambda: (SimpleNamespace(node="pmg"), pdm_obj))
    return server


class _PdmInventory:
    def resources_list(self):
        return [{"id": "qemu/100", "type": "qemu"}, {"id": "lxc/7", "type": "lxc"},
                {"id": "storage/s", "type": "storage"}, {"id": "qemu/101", "type": "qemu"}]

    def pve_resources(self, remote, kind=None):
        return [{"id": "qemu/100", "type": "qemu"}, {"id": "storage/s", "type": "storage"}]

    def pve_qemu_list(self, remote, node=None):
        return [{"vmid": 100, "status": "running"}, {"vmid": 101, "status": "stopped"},
                {"vmid": 102, "status": "running"}]

    def pve_lxc_list(self, remote, node=None):
        return [{"vmid": 7, "status": "running"}]


def test_pdm_resources_list_is_a_counted_envelope_by_type(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PdmInventory())
    out = server.pdm_resources_list()
    assert out["total"] == 4
    assert out["by_type"] == {"qemu": 2, "lxc": 1, "storage": 1}
    assert out["resources"][0]["id"] == "qemu/100"


def test_pdm_pve_resources_is_a_counted_envelope_by_type(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PdmInventory())
    out = server.pdm_pve_resources(remote="r1")
    assert out["total"] == 2
    assert out["by_type"] == {"qemu": 1, "storage": 1}


def test_pdm_pve_qemu_list_is_a_counted_envelope_by_status(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PdmInventory())
    out = server.pdm_pve_qemu_list(remote="r1")
    assert out["total"] == 3
    assert out["by_status"] == {"running": 2, "stopped": 1}
    assert [r["vmid"] for r in out["vms"]] == [100, 101, 102]


def test_pdm_pve_lxc_list_is_a_counted_envelope_by_status(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PdmInventory())
    out = server.pdm_pve_lxc_list(remote="r1")
    assert out["total"] == 1
    assert out["by_status"] == {"running": 1}
    assert out["containers"][0]["vmid"] == 7


class _HaApi:
    def _get(self, path):
        assert path == "/cluster/ha/resources"
        return [{"sid": "ct:7", "type": "ct", "state": "started"},
                {"sid": "vm:100", "type": "vm", "state": "started"},
                {"sid": "vm:101", "type": "vm", "state": "disabled"}]


def test_pve_ha_resources_list_is_a_counted_envelope_by_state(monkeypatch, tmp_path):
    server = _wire(monkeypatch, tmp_path, _HaApi())
    out = server.pve_ha_resources_list()
    assert out["total"] == 3
    assert out["by_state"] == {"started": 2, "disabled": 1}
    assert out["resources"][0]["sid"] == "ct:7"


class _PmgStats:
    def __init__(self):
        self.gets = []

    def _get(self, path, params=None):
        self.gets.append((path, params))
        if path.endswith("/detail"):
            return [{"time": 100, "sender": "a@x"}, {"time": 300, "sender": "b@x"},
                    {"time": 200, "sender": "c@x"}]
        return [{"who": "a@x", "count": 5}, {"who": "b@x", "count": 40},
                {"who": "c@x", "count": 12}]


def test_pmg_statistics_sender_default_is_top_100_envelope(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PmgStats())
    out = server.pmg_statistics_sender()
    assert out["total"] == 3 and out["returned"] == 3
    # under the default cap the rows come back top-by-count, count DESC
    assert [r["count"] for r in out["senders"]] == [40, 12, 5]


def test_pmg_statistics_sender_limit_caps_top_by_count(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PmgStats())
    out = server.pmg_statistics_sender(limit=2)
    assert out["total"] == 3 and out["returned"] == 2
    assert [r["who"] for r in out["senders"]] == ["b@x", "c@x"]


def test_pmg_statistics_sender_explicit_none_returns_all_rows_api_order(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PmgStats())
    out = server.pmg_statistics_sender(limit=None)
    assert out["returned"] == out["total"] == 3
    assert [r["who"] for r in out["senders"]] == ["a@x", "b@x", "c@x"]   # untouched


def test_pmg_statistics_sender_cap_is_client_side_never_an_api_param(monkeypatch, tmp_path):
    pmg = _PmgStats()
    server = _wire_pdm(monkeypatch, tmp_path, pmg)
    server.pmg_statistics_sender(limit=1)
    _, params = pmg.gets[-1]
    assert not params or "limit" not in params   # PMG's API has no such param; never leak it


def test_pmg_statistics_receiver_and_contact_envelope_keys(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PmgStats())
    assert server.pmg_statistics_receiver()["receivers"]
    assert server.pmg_statistics_contact()["contacts"]


def test_pmg_statistics_detail_default_caps_newest_by_time(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PmgStats())
    out = server.pmg_statistics_detail(address="a@x", type_="sender")
    assert out["total"] == 3
    # detail rows are per-message and DO carry time — newest first under the cap
    assert [r["time"] for r in out["messages"]] == [300, 200, 100]


def test_pmg_statistics_detail_limit_2_newest(monkeypatch, tmp_path):
    server = _wire_pdm(monkeypatch, tmp_path, _PmgStats())
    out = server.pmg_statistics_detail(address="a@x", type_="sender", limit=2)
    assert out["returned"] == 2
    assert [r["time"] for r in out["messages"]] == [300, 200]
