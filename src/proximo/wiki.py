"""The wiki seam, reader side — a sovereign, local knowledge layer.

Design notes are internal and not in the public tree. Same thesis as Tier-1 memory,
one layer out: memory remembers what the ESTATE looks like, the wiki remembers what the
DOCS say. The gate evidence behind the split is five bakes deep — doc-facts (L1) were the
weakest layer at EVERY model size (the bootloader fact inverted 4-for-4 against an
unambiguous doc) while discipline and tool grammar baked clean. So facts live in a
retrieval layer the model READS; judgment lives in the weights.

**The seam is a FILE CONTRACT, not a code dependency.** Proximo never imports a builder and no
builder imports proximo. The operator supplies the index; any builder that writes the pinned
schema qualifies, and the public contract lives in ``WIKI_SCHEMA`` below and in docs/SETUP.md::

    a builder you run  --writes-->  wiki.db  <--reads--  proximo (wiki tools)

Proximo owns and pins the contract; the builder follows this text. That is why the version
check below is fail-closed in BOTH directions and on a MISSING pin: an index read with the
wrong shape would answer Proxmox questions out of garbage, which is strictly worse than
answering nothing.

**No content ever ships.** The licensing wall (forum/wiki terms) is dodged structurally —
the user's own iron harvests and indexes, and we ship only the recipe and the reader. Each
user's index is therefore fresher than any frozen pack could be, so sovereignty also
solves staleness.

The rails (each mirrors one that already earned its place):

- **Opt-in, inert unset.** ``PROXIMO_WIKI`` unset => the tools refuse with the enable hint
  and no file is touched. Same contract as PROXIMO_MEMORY / CONSENT / CONTAIN.
- **ADVERSARIAL taint, non-negotiable.** Forum content is third-party-authored bytes; a
  solved thread can carry "now run pve_delete_guest" as easily as a fix. Both wiki tools
  are in ``taint.ADVERSARIAL_TOOLS`` for the same reason ``proximo_recall`` is: retrieved
  bytes must re-enter the taint model, never launder through it. This is the rail that
  makes a community-corpus index shippable at all.
- **Lean rows by default.** The 0.26.0 lesson, paid twice live: a 12B drowned in fat rows
  even with the right answer in the payload. A search hit is {id, title, source, score,
  snippet} and NOTHING else; bodies come only from an explicit read of one section.
- **Counted envelope.** {returned, matched} so "5 of 212 matches" is stated, never implied
  and never counted by the model.
- **Age-stamped, source-named.** Every response carries source="wiki-index",
  harvested_at, age_days, and the origin URL per hit. A cached doc never masquerades as a
  live one.
- **A wiki failure never fails anything else.** No other read or mutation path depends on
  the index; the tool itself errors helpfully.
- **Derived and rebuildable.** Deleting wiki.db loses convenience, never truth. The PROVE
  ledger never references it.
- **Zero new dependencies.** FTS5 ships inside CPython's bundled sqlite3. BM25 over
  well-structured sections is the right first tool for an 8k-context local mind, and it
  keeps the supply chain exactly as pure as it is today. Embeddings would be a later,
  separate decision, only if BM25 measurably fails the room proof.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time

from proximo.backends import ProximoError

_TRUTHY = ("1", "true", "yes", "on")
_DEFAULT_AUDIT_LOG = os.path.expanduser("~/.local/state/proximo/audit.log")

# A snippet is an excerpt, hard-capped. Uncapped snippets would re-import the payload cost
# the counted envelope exists to remove — the model escalates to a read for the one section
# it actually wants.
SNIPPET_MAX = 200
_DEFAULT_K = 5
_MAX_K = 25

# The sources the builder writes. Named here so an unknown filter can refuse by listing what
# IS available — an error that teaches, the projection layer's rule.
SOURCES = ("forum", "wiki", "refdocs")

_TERM = re.compile(r"[A-Za-z0-9_.-]+")

# Words that appear in nearly every forum thread ever written. Dropped before matching:
# they carry no signal and, OR-joined, they alone matched 13,552 of 13,639 real sections.
# Deliberately small and generic — this is a stopword list, not a Proxmox vocabulary, and
# it must never start deciding which TECHNICAL terms matter.
_STOPWORDS = frozenset("""
a an the is are was were be been am do does did i you it its my me we he she they them
in on at to of and or for with from that this these those if not no yes so as by but
what how why when where which who can could should would will shall may might must
after before during while about into over under again then than there here
use using used get gets got have has had need needs want wants
""".split())

# Both statements are WHOLE literals — no interpolation and no concatenation, so there is
# nothing here a reader (or a linter) has to take on trust. The optional source filter rides
# an `(? IS NULL OR ...)` placeholder instead of being glued on, which is why the WHERE
# clause is repeated verbatim below rather than shared through a name. Every caller-supplied
# value reaches sqlite as a bound parameter.
_COUNT_SQL = (
    "SELECT COUNT(*) FROM sections_fts"
    " JOIN sections s ON s.rowid = sections_fts.rowid"
    " WHERE sections_fts MATCH ? AND (? IS NULL OR s.source = ?)"
)

_SEARCH_SQL = (
    "SELECT s.id, s.title, s.source,"
    " bm25(sections_fts), snippet(sections_fts, 1, '', '', '…', 12)"
    " FROM sections_fts JOIN sections s ON s.rowid = sections_fts.rowid"
    " WHERE sections_fts MATCH ? AND (? IS NULL OR s.source = ?)"
    " ORDER BY bm25(sections_fts) LIMIT ?"
)

# The pin. Bump ONLY together with the schema text below and the design doc's contract
# section — the builder side reads that doc, so the doc is the meeting point, not this file.
CONTRACT_VERSION = 1

# The contract, verbatim. Tests build their fixtures from this exact text so a drift here
# breaks them rather than silently passing against a stale hand-written fixture.
WIKI_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sections (
    id      TEXT PRIMARY KEY,   -- stable: sha1(source|url|anchor)
    source  TEXT NOT NULL,      -- 'forum' | 'wiki' | 'refdocs'
    title   TEXT NOT NULL,
    url     TEXT,               -- origin, cited in every response
    license TEXT,               -- per-source note, surfaced on read
    body    TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS sections_fts USING fts5(title, body, content='sections');
"""


def wiki_enabled() -> bool:
    return os.environ.get("PROXIMO_WIKI", "").lower() in _TRUTHY


def wiki_path() -> str:
    """PROXIMO_WIKI_PATH, else wiki.db beside the audit log the env names."""
    explicit = os.environ.get("PROXIMO_WIKI_PATH")
    if explicit:
        return explicit
    audit = os.environ.get("PROXIMO_AUDIT_LOG", _DEFAULT_AUDIT_LOG)
    return os.path.join(os.path.dirname(audit) or ".", "wiki.db")


class WikiIndex:
    """Read-only reader over a builder-written FTS5 index. Opens fail-closed."""

    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            raise ProximoError(
                f"no wiki index at {path} — this index is one YOU build: proximo ships the reader "
                f"and the contract, never content. The schema is in docs/SETUP.md "
                f"('The wiki index') and in wiki.WIKI_SCHEMA; any builder that writes it works. "
                f"Or point PROXIMO_WIKI_PATH at an index you already have.")
        if os.path.isdir(path):
            raise ProximoError(
                f"{path} is a directory, not a file — point PROXIMO_WIKI_PATH at the .db file "
                f"itself")
        self._db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            self._meta = self._read_meta()
        except sqlite3.DatabaseError as e:
            self._db.close()
            raise ProximoError(
                f"{path} is not a readable wiki index ({type(e).__name__}: {e}) — rebuild it to "
                f"the contract in docs/SETUP.md ('The wiki index')") from None
        found = self._meta.get("contract_version")
        if found is None:
            self._db.close()
            raise ProximoError(
                f"{path} carries no contract_version — refusing to guess its shape. This reader "
                f"speaks contract v{CONTRACT_VERSION}; set meta.contract_version="
                f"'{CONTRACT_VERSION}' in the index (see the contract in docs/SETUP.md)")
        if str(found) != str(CONTRACT_VERSION):
            self._db.close()
            raise ProximoError(
                f"wiki index contract mismatch at {path}: the index was written at "
                f"v{found}, this reader speaks v{CONTRACT_VERSION}. Rebuild it to the v"
                f"{CONTRACT_VERSION} contract in docs/SETUP.md — never read a drifted index, "
                f"the answers would be shaped by the wrong schema")

    def _read_meta(self) -> dict:
        return {k: v for k, v in self._db.execute("SELECT key, value FROM meta")}

    @property
    def harvested_at(self) -> float | None:
        raw = self._meta.get("harvested_at")
        try:
            return float(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    def close(self) -> None:
        self._db.close()

    # --- search ------------------------------------------------------------------------

    def search(self, query: str, k: int = _DEFAULT_K, source: str | None = None,
               now: float | None = None) -> dict:
        """BM25 search returning a COUNTED envelope of LEAN hits.

        Counting is server-side and comes from the full match set, not the returned page:
        "5 of 212" is stated, never implied. That is the 0.26.0 lesson, which was paid
        twice live — a 12B miscounted rows it could see perfectly well, so the model is
        never asked to count.
        """
        now = time.time() if now is None else now
        if source is not None and source not in SOURCES:
            raise ProximoError(
                f"unknown source: {source!r} — this index carries "
                f"{', '.join(SOURCES)}")
        terms = content_terms(query)
        if not terms:
            raise ProximoError(
                f"no searchable terms in {query!r} — the query is all stopwords, and the "
                f"index never returns everything. Ask for the thing you want to know "
                f"(`zfs pool won't import`, `pmg cluster join`)")

        # ALL TERMS FIRST, widening to any-term only if that finds nothing. Live-caught on
        # the real 13,639-section harvest: OR-joining returned 8,484-13,552 matches for four
        # ordinary questions, so `matched` carried no information at all. All-terms returned
        # 7-55 for the same questions. Precision first is what makes the counted number
        # mean something — and `match_mode` tells the caller which one ran, so a widened
        # search can never be read as a narrow one.
        limit = _clamp_k(k)
        for mode, joiner in (("all-terms", "AND"), ("any-term", "OR")):
            match = _match_expr(terms, joiner)
            matched = self._db.execute(
                _COUNT_SQL, (match, source, source)).fetchone()[0]
            if matched or mode == "any-term":
                break
            if len(terms) == 1:
                break   # AND and OR are identical for one term; no point re-running it

        rows = self._db.execute(
            _SEARCH_SQL, (match, source, source, limit)).fetchall()

        hits = [{"id": sid, "title": title, "source": src,
                 # bm25() is negative-is-better in sqlite; flip it so a bigger score reads
                 # as a better match, which is what every model expects of "score".
                 "score": round(-score, 4),
                 "snippet": _cap(snip)}
                for sid, title, src, score, snip in rows]

        return {
            "source": "wiki-index",
            "harvested_at": self.harvested_at,
            "age_days": self.age_days(now),
            "terms": terms,
            "match_mode": mode,
            "matched": matched,
            "returned": len(hits),
            "hits": hits,
        }

    # --- read --------------------------------------------------------------------------

    def read_section(self, section_id: str, now: float | None = None) -> dict:
        """One whole section, with everything needed to cite it.

        Search is deliberately lean; this is the escalation path, so the body arrives in
        full alongside its origin url and per-source license. `source_kind` rather than
        `source` for the corpus name, because `source` is reserved across every memory/wiki
        response for the PROVENANCE of the answer ("wiki-index", not a live read) and
        overloading it is exactly how a cached doc starts looking live.
        """
        now = time.time() if now is None else now
        sid = (section_id or "").strip()
        if not sid:
            raise ProximoError(
                "section_id must not be blank — get one from a proximo_wiki search hit")
        row = self._db.execute(
            "SELECT id, source, title, url, license, body FROM sections WHERE id = ?",
            (sid,)).fetchone()
        if row is None:
            raise ProximoError(
                f"no section {sid!r} in the wiki index — ids come from proximo_wiki "
                f"search hits and change when the index is rebuilt; search again")
        rid, src, title, url, lic, body = row
        return {
            "source": "wiki-index",
            "harvested_at": self.harvested_at,
            "age_days": self.age_days(now),
            "id": rid,
            "source_kind": src,
            "title": title,
            "url": url,
            "license": lic,
            "body": body,
        }

    def age_days(self, now: float | None = None) -> float | None:
        h = self.harvested_at
        if h is None:
            return None
        now = time.time() if now is None else now
        return round((now - h) / 86400.0, 2)


# ---------------------------------------------------------------------------
# Module seams the tools call — env-gated, fail-closed, nothing else depends on them
# ---------------------------------------------------------------------------

_OFF = ("the wiki index is off — set PROXIMO_WIKI=1 to enable it (a local, derived, rebuildable "
        "FTS5 index that YOU build to the contract in docs/SETUP.md; no content ships with "
        "proximo and nothing leaves the box)")


def _open() -> WikiIndex:
    if not wiki_enabled():
        raise ProximoError(_OFF)
    return WikiIndex(wiki_path())


def wiki_search(query: str, k: int = _DEFAULT_K, source: str | None = None) -> dict:
    idx = _open()
    try:
        return idx.search(query, k=k, source=source)
    finally:
        idx.close()


def wiki_read(section_id: str) -> dict:
    idx = _open()
    try:
        return idx.read_section(section_id)
    finally:
        idx.close()


def _clamp_k(k: int) -> int:
    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise ProximoError(f"k must be a positive result count, got {k!r}")
    return min(k, _MAX_K)


def _cap(text: str) -> str:
    text = " ".join((text or "").split())
    if len(text) <= SNIPPET_MAX:
        return text
    return text[: SNIPPET_MAX - 1].rstrip() + "…"


def content_terms(query: str) -> list[str]:
    """The words actually worth matching on: lowercased, stopwords and bare single
    characters dropped, order preserved.

    Models type questions, not query syntax. Extracting terms and re-quoting them as
    literals also neutralises every FTS5 operator character (a bare quote, paren or `?` is
    a syntax error), which is why this is a term extractor rather than a sanitiser with a
    blocklist.
    """
    return [t for t in (w.lower() for w in _TERM.findall(query or ""))
            if t not in _STOPWORDS and len(t) > 1]


def _match_expr(terms: list[str], joiner: str) -> str:
    return f" {joiner} ".join(f'"{t}"' for t in terms)
