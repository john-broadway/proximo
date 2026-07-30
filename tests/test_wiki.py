"""The wiki seam, reader side — increment 1: the contract pin and the opt-in gate.

Design: docs/plans/internal/2026-07-29-wiki-seam-sketch.md. Proximo owns the reader; the
builder the OPERATOR runs writes this schema. The seam is a FILE CONTRACT, so the
version pin is the load-bearing part: a builder that drifts must be refused loudly and by
name, never guessed at. An index read with the wrong shape would answer Proxmox questions
from garbage, which is worse than answering nothing.

Rails under test here: opt-in (PROXIMO_WIKI unset => refuse, never touch a file); contract
version pinned both directions; a missing or malformed index refuses helpfully rather than
leaking a bare sqlite error.
"""

from __future__ import annotations

import sqlite3

import pytest

from proximo.backends import ProximoError
from proximo.wiki import (
    CONTRACT_VERSION,
    WIKI_SCHEMA,
    WikiIndex,
    wiki_enabled,
    wiki_path,
)

LONG_BODY = (
    "systemd-boot is used, unless Secure Boot is enabled. Then GRUB is used. "
    "The bootloader is installed by the installer onto every selected disk so the "
    "system still starts when one disk fails. Use proxmox-boot-tool to keep the ESPs "
    "synchronised after a kernel upgrade, and to list which disks are currently "
    "initialised for booting on this host."
)

SECTIONS = [
    ("a1", "refdocs", "Host Bootloader",
     "https://pve.proxmox.com/wiki/Host_Bootloader", "AGPL-3.0", LONG_BODY),
    ("b2", "forum", "ZFS pool will not import after reboot",
     "https://forum.proxmox.com/threads/1.1/", "forum-terms",
     "Import the pool by id and set the cachefile so it survives a reboot."),
    ("c3", "wiki", "PMG Cluster join",
     "https://pve.proxmox.com/wiki/PMG_Cluster", "AGPL-3.0",
     "Join a PMG cluster from the node that is NOT the master."),
]


def build_index(path: str, *, contract: str | int = CONTRACT_VERSION,
                harvested_at: float = 1_700_000_000.0,
                sections: list = SECTIONS) -> None:
    """Build a fixture index from the SAME schema text the reader pins, so a drift in
    WIKI_SCHEMA breaks these tests rather than silently passing against a stale fixture."""
    db = sqlite3.connect(path)
    db.executescript(WIKI_SCHEMA)
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('contract_version', ?)",
               (str(contract),))
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('harvested_at', ?)",
               (str(harvested_at),))
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('builder', ?)",
               ("fixture-builder/test",))
    db.executemany(
        "INSERT INTO sections (id, source, title, url, license, body)"
        " VALUES (?,?,?,?,?,?)", sections)
    db.execute("INSERT INTO sections_fts (rowid, title, body)"
               " SELECT rowid, title, body FROM sections")
    db.commit()
    db.close()


# --- the opt-in gate ------------------------------------------------------------------

def test_wiki_disabled_when_env_unset(monkeypatch):
    monkeypatch.delenv("PROXIMO_WIKI", raising=False)
    assert wiki_enabled() is False


def test_wiki_enabled_when_env_truthy(monkeypatch):
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    assert wiki_enabled() is True


def test_wiki_path_prefers_explicit_env(monkeypatch):
    monkeypatch.setenv("PROXIMO_WIKI_PATH", "/somewhere/custom.db")
    assert wiki_path() == "/somewhere/custom.db"


def test_wiki_path_defaults_beside_the_audit_log(monkeypatch):
    monkeypatch.delenv("PROXIMO_WIKI_PATH", raising=False)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", "/var/state/proximo/audit.log")
    assert wiki_path() == "/var/state/proximo/wiki.db"


# --- the contract pin -----------------------------------------------------------------

def test_opens_an_index_written_at_the_pinned_contract(tmp_path):
    p = str(tmp_path / "wiki.db")
    build_index(p)
    idx = WikiIndex(p)
    try:
        assert idx.harvested_at == 1_700_000_000.0
    finally:
        idx.close()


def test_refuses_a_newer_contract_by_name(tmp_path):
    p = str(tmp_path / "wiki.db")
    build_index(p, contract=CONTRACT_VERSION + 1)
    with pytest.raises(ProximoError) as e:
        WikiIndex(p)
    msg = str(e.value)
    assert str(CONTRACT_VERSION + 1) in msg and str(CONTRACT_VERSION) in msg


def test_refuses_an_older_contract_by_name(tmp_path):
    p = str(tmp_path / "wiki.db")
    build_index(p, contract=CONTRACT_VERSION - 1)
    with pytest.raises(ProximoError) as e:
        WikiIndex(p)
    assert str(CONTRACT_VERSION) in str(e.value)


def test_refuses_an_index_with_no_contract_row(tmp_path):
    """A db that is missing the pin entirely is NOT treated as the current version —
    fail-closed, the same posture the scoping layers take on an unknown field."""
    p = str(tmp_path / "wiki.db")
    db = sqlite3.connect(p)
    db.executescript(WIKI_SCHEMA)
    db.commit()
    db.close()
    with pytest.raises(ProximoError) as e:
        WikiIndex(p)
    assert "contract_version" in str(e.value)


def test_refuses_a_missing_file_helpfully(tmp_path):
    """Never a bare sqlite 'unable to open database file' — the message must name the path
    and say what builds one."""
    p = str(tmp_path / "absent.db")
    with pytest.raises(ProximoError) as e:
        WikiIndex(p)
    msg = str(e.value)
    assert "absent.db" in msg and "index" in msg.lower()


def test_no_refusal_names_a_tool_the_reader_does_not_ship(tmp_path):
    """REDTEAM (John's standing law: our code must not lie).

    Four refusals told the user to build the index with a private, unpublished builder tool
    that is not part of this package, so every public adopter was handed a remedy they cannot
    run. (The builder's name is deliberately absent from this file: it is an internal project
    name on the leak denylist, assembled below so the public tree never carries the literal.)
    A remedy naming an unreachable tool is worse than no remedy: it reads as "you are missing
    a step" when the truth is "you build this yourself, and here is the contract".

    The reader ships the contract, so the refusals must point at the documented contract instead.
    """
    paths = [str(tmp_path / "absent.db")]
    bad = tmp_path / "garbage.db"
    bad.write_text("not a sqlite database")
    paths.append(str(bad))

    messages = []
    for p in paths:
        with pytest.raises(ProximoError) as e:
            WikiIndex(p)
        messages.append(str(e.value))

    # And the two contract-drift refusals, built from the pinned schema.
    for version in ("2", None):
        db = tmp_path / f"drift-{version}.db"
        con = sqlite3.connect(str(db))
        con.executescript(WIKI_SCHEMA)
        if version is not None:
            con.execute("INSERT INTO meta (key, value) VALUES ('contract_version', ?)", (version,))
        con.commit()
        con.close()
        with pytest.raises(ProximoError) as e:
            WikiIndex(str(db))
        messages.append(str(e.value))

    # The private builder's name, assembled at runtime so the literal never sits in the
    # public tree (it is word-boundary-matched by the release leak-audit denylist).
    private_builder = "".join(("maxi", "mus"))
    for msg in messages:
        assert private_builder not in msg.lower(), msg
        assert "SETUP" in msg or "contract" in msg.lower(), msg


def test_refuses_a_file_that_is_not_an_index(tmp_path):
    p = str(tmp_path / "garbage.db")
    (tmp_path / "garbage.db").write_text("this is not a sqlite database at all")
    with pytest.raises(ProximoError):
        WikiIndex(p)


def test_refuses_a_directory_helpfully(tmp_path):
    """ARENA (pbs-only-walk.md #5, verdict 1.10b): PROXIMO_WIKI_PATH pointed at a directory
    (the exact typo a copy-paste of SETUP.md's own example path risks) must not leak a raw
    sqlite OperationalError — the existence check passes for a directory too, so this needs
    its own guard, in the same voice as the missing-file and bad-schema refusals above."""
    p = str(tmp_path)  # tmp_path IS a directory
    with pytest.raises(ProximoError) as e:
        WikiIndex(p)
    msg = str(e.value)
    assert "directory" in msg.lower()
    assert "PROXIMO_WIKI_PATH" in msg
    assert "OperationalError" not in msg


# --- increment 2: search — lean rows, counted envelope, age stamp ---------------------

def open_index(tmp_path, **kw) -> WikiIndex:
    p = str(tmp_path / "wiki.db")
    build_index(p, **kw)
    return WikiIndex(p)


NOW = 1_700_000_000.0 + 86_400 * 3  # 3 days after the fixture harvest


def test_search_hit_is_lean_and_never_carries_the_body(tmp_path):
    """The 0.26.0 lesson, paid twice live: a search hit that carried bodies would re-import
    the exact payload cost the counted envelope exists to remove. The hit is five fields,
    and the snippet is a capped excerpt — never the section."""
    from proximo.wiki import SNIPPET_MAX

    idx = open_index(tmp_path)
    try:
        out = idx.search("bootloader", now=NOW)
        hit = out["hits"][0]
        assert set(hit) == {"id", "title", "source", "score", "snippet"}
        assert len(hit["snippet"]) <= SNIPPET_MAX
        assert len(LONG_BODY) > SNIPPET_MAX      # the cap actually bites on this fixture
        assert hit["snippet"] != LONG_BODY
    finally:
        idx.close()


def test_search_counts_server_side_and_states_returned_of_matched(tmp_path):
    sections = SECTIONS + [
        (f"z{i}", "forum", f"ZFS thread {i}", f"https://forum.proxmox.com/threads/{i}/",
         "forum-terms", "zfs pool import trouble after reboot")
        for i in range(10)
    ]
    idx = open_index(tmp_path, sections=sections)
    try:
        out = idx.search("zfs", k=3, now=NOW)
        assert out["returned"] == 3
        assert out["matched"] == 11          # 10 synthetic + the original ZFS section
        assert len(out["hits"]) == 3
    finally:
        idx.close()


def test_search_is_age_stamped_and_source_named(tmp_path):
    idx = open_index(tmp_path)
    try:
        out = idx.search("bootloader", now=NOW)
        assert out["source"] == "wiki-index"
        assert out["harvested_at"] == 1_700_000_000.0
        assert out["age_days"] == 3.0
    finally:
        idx.close()


def test_search_can_filter_by_source(tmp_path):
    idx = open_index(tmp_path)
    try:
        out = idx.search("reboot OR bootloader OR cluster", source="forum", now=NOW)
        assert {h["source"] for h in out["hits"]} == {"forum"}
    finally:
        idx.close()


def test_search_refuses_an_unknown_source_naming_what_exists(tmp_path):
    """Fail-closed and teaching, exactly like the projection layer's unknown-field refusal."""
    idx = open_index(tmp_path)
    try:
        with pytest.raises(ProximoError) as e:
            idx.search("reboot", source="mailing-list", now=NOW)
        msg = str(e.value)
        assert "mailing-list" in msg
        assert "forum" in msg and "wiki" in msg and "refdocs" in msg
    finally:
        idx.close()


def test_search_refuses_a_blank_query(tmp_path):
    """"No filter" must never degrade into "the whole index" — lean.py's rule, same reason."""
    idx = open_index(tmp_path)
    try:
        with pytest.raises(ProximoError):
            idx.search("   ", now=NOW)
    finally:
        idx.close()


def test_search_ranks_the_better_match_first(tmp_path):
    idx = open_index(tmp_path)
    try:
        out = idx.search("secure boot bootloader", now=NOW)
        assert out["hits"][0]["id"] == "a1"
    finally:
        idx.close()


def test_search_survives_fts5_operator_characters_in_a_natural_query(tmp_path):
    """Models type prose. A bare quote or paren is an FTS5 syntax error, and a syntax error
    surfacing as a crash would make natural questions unanswerable."""
    idx = open_index(tmp_path)
    try:
        out = idx.search('what does "secure boot" do? (bootloader)', now=NOW)
        assert out["matched"] >= 1
    finally:
        idx.close()


def test_search_returns_an_honest_empty_envelope(tmp_path):
    idx = open_index(tmp_path)
    try:
        out = idx.search("kubernetes helm chart", now=NOW)
        assert out["returned"] == 0 and out["matched"] == 0
        assert out["hits"] == []
    finally:
        idx.close()


# --- increment 3: read — one full section, with provenance ---------------------------

def test_read_returns_the_full_section_with_provenance(tmp_path):
    """Search is lean on purpose; read is the escalation path, so it carries the WHOLE body
    plus everything needed to cite it: origin url, per-source license, and the age stamp."""
    idx = open_index(tmp_path)
    try:
        out = idx.read_section("a1", now=NOW)
        assert out["body"] == LONG_BODY
        assert out["url"] == "https://pve.proxmox.com/wiki/Host_Bootloader"
        assert out["license"] == "AGPL-3.0"
        assert out["title"] == "Host Bootloader"
        assert out["source_kind"] == "refdocs"
    finally:
        idx.close()


def test_read_is_age_stamped_and_source_named(tmp_path):
    """A cached doc must never masquerade as a live one — same contract as recall."""
    idx = open_index(tmp_path)
    try:
        out = idx.read_section("a1", now=NOW)
        assert out["source"] == "wiki-index"
        assert out["harvested_at"] == 1_700_000_000.0
        assert out["age_days"] == 3.0
    finally:
        idx.close()


def test_read_returns_exactly_one_section(tmp_path):
    idx = open_index(tmp_path)
    try:
        out = idx.read_section("b2", now=NOW)
        assert out["id"] == "b2"
        assert "Host Bootloader" not in str(out)
    finally:
        idx.close()


def test_read_refuses_an_unknown_id_by_name(tmp_path):
    """Fail-closed: a model that mistyped an id must get a recoverable error, never an
    empty section it would then narrate as fact."""
    idx = open_index(tmp_path)
    try:
        with pytest.raises(ProximoError) as e:
            idx.read_section("nope", now=NOW)
        msg = str(e.value)
        assert "nope" in msg
        assert "proximo_wiki" in msg          # points back at the search that yields ids
    finally:
        idx.close()


def test_read_refuses_a_blank_id(tmp_path):
    idx = open_index(tmp_path)
    try:
        with pytest.raises(ProximoError):
            idx.read_section("  ", now=NOW)
    finally:
        idx.close()


# --- increment 4: the module seams, registration, and the taint rail -----------------

def test_search_refuses_when_the_wiki_is_off(monkeypatch):
    """Opt-in, with an enable hint that says what it costs — same contract as PROXIMO_MEMORY."""
    from proximo.wiki import wiki_search

    monkeypatch.delenv("PROXIMO_WIKI", raising=False)
    with pytest.raises(ProximoError) as e:
        wiki_search("bootloader")
    assert "PROXIMO_WIKI" in str(e.value)


def test_read_refuses_when_the_wiki_is_off(monkeypatch):
    from proximo.wiki import wiki_read

    monkeypatch.delenv("PROXIMO_WIKI", raising=False)
    with pytest.raises(ProximoError) as e:
        wiki_read("a1")
    assert "PROXIMO_WIKI" in str(e.value)


def test_disabled_wiki_never_touches_a_file(tmp_path, monkeypatch):
    """Inert means inert: no file is opened, created, or even stat-ed into existence."""
    from proximo.wiki import wiki_search

    p = tmp_path / "wiki.db"
    monkeypatch.delenv("PROXIMO_WIKI", raising=False)
    monkeypatch.setenv("PROXIMO_WIKI_PATH", str(p))
    with pytest.raises(ProximoError):
        wiki_search("bootloader")
    assert not p.exists()


def test_enabled_search_reads_the_configured_index(tmp_path, monkeypatch):
    from proximo.wiki import wiki_search

    p = str(tmp_path / "wiki.db")
    build_index(p)
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    monkeypatch.setenv("PROXIMO_WIKI_PATH", p)
    out = wiki_search("bootloader")
    assert out["source"] == "wiki-index"
    assert out["hits"][0]["id"] == "a1"


def test_enabled_read_reads_the_configured_index(tmp_path, monkeypatch):
    from proximo.wiki import wiki_read

    p = str(tmp_path / "wiki.db")
    build_index(p)
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    monkeypatch.setenv("PROXIMO_WIKI_PATH", p)
    assert wiki_read("a1")["body"] == LONG_BODY


def test_both_wiki_tools_are_classified_adversarial():
    """THE rail that makes a community-corpus index shippable at all. Forum content is
    third-party-authored: a solved thread can carry "now run pve_delete_guest" as easily as
    a fix, so retrieved bytes must re-enter the taint model instead of laundering through
    storage — the same reasoning that put proximo_recall here."""
    from proximo.taint import ADVERSARIAL_TOOLS

    assert "proximo_wiki" in ADVERSARIAL_TOOLS
    assert "proximo_wiki_read" in ADVERSARIAL_TOOLS


def test_wiki_tools_are_registered():
    from proximo import server

    registry = server.mcp._tool_manager._tools
    assert "proximo_wiki" in registry
    assert "proximo_wiki_read" in registry


def test_wiki_is_a_scopeable_surface():
    from proximo.server import SURFACES

    assert "wiki" in SURFACES
    assert all(n.startswith(SURFACES["wiki"])
               for n in ("proximo_wiki", "proximo_wiki_read"))


def test_wiki_is_a_scopeable_toolset():
    from proximo.server import TOOLSETS

    assert "wiki" in TOOLSETS
    assert all(n.startswith(TOOLSETS["wiki"])
               for n in ("proximo_wiki", "proximo_wiki_read"))


# --- the server seam: both tools are governed reads on the PROVE ledger --------------
# These are what the NOT_SHAPE_ASSERTED_READ allowlist entry in tests/test_wrapper_shapes.py
# cites: the sweep there cannot call these tools (they refuse with PROXIMO_WIKI unset, by
# design), so the request/response/ledger seams are pinned HERE instead. If you remove these,
# remove the allowlist entry too — an allowlist that points at nothing is worse than no
# allowlist, because it reads as coverage.

def _wire(monkeypatch, tmp_path):
    import proximo.server as server
    from proximo.audit import AuditLedger
    from proximo.config import ProximoConfig

    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=str(tmp_path / "audit.log"))
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, ledger))
    return server


def _ledger_entries(tmp_path) -> list:
    import json

    with open(str(tmp_path / "audit.log"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_proximo_wiki_is_a_governed_read_on_the_ledger(monkeypatch, tmp_path):
    p = str(tmp_path / "wiki.db")
    build_index(p)
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    monkeypatch.setenv("PROXIMO_WIKI_PATH", p)
    server = _wire(monkeypatch, tmp_path)

    out = server.proximo_wiki(query="bootloader")
    assert out["source"] == "wiki-index" and out["returned"] >= 1
    assert any(e["action"] == "proximo_wiki" and e["mutation"] is False
               for e in _ledger_entries(tmp_path))


def test_proximo_wiki_read_is_a_governed_read_carrying_its_target(monkeypatch, tmp_path):
    """The ledger entry must carry the section id — a read of "some section" is not traceable."""
    p = str(tmp_path / "wiki.db")
    build_index(p)
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    monkeypatch.setenv("PROXIMO_WIKI_PATH", p)
    server = _wire(monkeypatch, tmp_path)

    out = server.proximo_wiki_read(section_id="a1")
    assert out["body"] == LONG_BODY
    assert any(e["action"] == "proximo_wiki_read" and e["target"] == "a1"
               and e["mutation"] is False for e in _ledger_entries(tmp_path))


def test_a_disabled_wiki_records_the_refusal_as_an_error_not_a_success(
        monkeypatch, tmp_path):
    """A refused call still lands on the PROVE ledger, marked `outcome: error` — the refusal
    is part of the record, not a gap in it.

    NOTE the shape: ledger entries carry `outcome`, NOT an `ok` boolean. The first version of
    this test asserted `not any(e.get("ok") ...)`, which passed for EVERY possible behaviour
    because the key does not exist — a vacuous green. Assert on `outcome` by value.
    """
    monkeypatch.delenv("PROXIMO_WIKI", raising=False)
    monkeypatch.setenv("PROXIMO_WIKI_PATH", str(tmp_path / "wiki.db"))
    server = _wire(monkeypatch, tmp_path)

    with pytest.raises(ProximoError):
        server.proximo_wiki(query="bootloader")

    mine = [e for e in _ledger_entries(tmp_path) if e.get("action") == "proximo_wiki"]
    assert len(mine) == 1, "the refused read must still be recorded exactly once"
    assert mine[0]["outcome"] == "error"
    assert mine[0]["mutation"] is False


# --- increment 5: match semantics — the counted number has to MEAN something ----------
# LIVE-CAUGHT 2026-07-29 against the real 13,639-thread harvest: OR-joining every term made
# `matched` 8,484-13,552 out of 13,639 on four natural questions — technically true, and
# useless. A model reading "5 of 13,552" is being told the whole corpus is relevant. The
# counted envelope exists to hand the model a number it can TRUST, so a meaningless count
# attacks the exact thing the feature is for. Measured on the same four queries: AND over
# content terms returned 7 / 24 / 53 / 55. That is a number worth printing.

def test_stopwords_do_not_drive_the_match(tmp_path):
    """"how do I join a PMG cluster?" must search join/pmg/cluster — not `a` and `how`,
    which appear in nearly every forum thread ever written."""
    from proximo.wiki import content_terms

    assert content_terms("how do I join a PMG cluster?") == ["join", "pmg", "cluster"]


def test_a_query_whose_terms_all_appear_in_one_section_matches_only_it(tmp_path):
    """All-terms first: precision before recall, so `matched` stays a usable number."""
    idx = open_index(tmp_path)
    try:
        out = idx.search("secure boot bootloader", now=NOW)
        assert out["match_mode"] == "all-terms"
        assert out["matched"] == 1
        assert out["hits"][0]["id"] == "a1"
    finally:
        idx.close()


def test_search_falls_back_to_any_term_and_says_so(tmp_path):
    """When no section carries every term, answering nothing would be worse than answering
    broadly — but the envelope must SAY the match was widened, or the count lies by omission."""
    idx = open_index(tmp_path)
    try:
        out = idx.search("bootloader cachefile", now=NOW)   # no section has both
        assert out["match_mode"] == "any-term"
        assert out["matched"] >= 2
    finally:
        idx.close()


def test_search_reports_the_terms_it_actually_searched(tmp_path):
    """Transparency: the model can see that stopwords were dropped, so a surprising count
    is explainable rather than mysterious."""
    idx = open_index(tmp_path)
    try:
        out = idx.search("what is the bootloader?", now=NOW)
        assert out["terms"] == ["bootloader"]
    finally:
        idx.close()


def test_an_all_stopword_query_refuses(tmp_path):
    """"how do I do this" carries no content term. Searching it would OR the whole corpus;
    refusing tells the caller to ask a real question."""
    idx = open_index(tmp_path)
    try:
        with pytest.raises(ProximoError):
            idx.search("how do I do this?", now=NOW)
    finally:
        idx.close()


def test_the_wiki_serves_on_a_box_with_no_pve_env_at_all(monkeypatch, tmp_path):
    """The reader is LOCAL — a PBS-only / pure-targets box with PROXIMO_WIKI=1 gets the
    wiki, not a PVE-shaped env error (ultra review 2026-07-30). Real _svc on purpose:
    every other test here mocks it, and that mock is exactly why the suite missed the
    wrapper's upfront _svc() call dying on Missing required Proximo env var."""
    import proximo.server as server

    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH",
                "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    db = str(tmp_path / "wiki.db")
    build_index(db)
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    monkeypatch.setenv("PROXIMO_WIKI_PATH", db)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    # The recommended posture; also keeps the redact advisory out of the suite.
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    server._svc_cache_clear()
    try:
        out = server.proximo_wiki(query="bootloader")
        assert out["matched"] >= 1
        section = server.proximo_wiki_read(section_id=out["hits"][0]["id"])
        assert section["title"] == "Host Bootloader"
    finally:
        server._svc_cache_clear()
