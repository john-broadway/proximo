"""Unit tests for scripts/reach.py's fetch layer (stubbed transport, no network).

The defect these pin: `_get_json` used to collapse every failure — rate limit,
network error, malformed JSON, genuine 404 — into a bare None, and the report
printed the single word "unavailable" for all of them. A rate-limited PyPI read
therefore looked identical to a surface that does not exist. These tests assert
the two states render differently, and that the transient one is retried.
"""
import json
import sys
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import reach  # noqa: E402


class _Resp:
    """Minimal urlopen context-manager double."""

    def __init__(self, body: bytes, status: int = 200):
        self._body, self.status = body, status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example.invalid", code, "boom", {}, None)


class _Transport:
    """One INTERLEAVED log of fetches and sleeps.

    Two separate lists cannot express ordering, so "sleep was called at some point"
    passes even when the retry fires first and sleeps afterwards. Backing off BEFORE
    the retry is the whole behaviour, so the log records the sequence.
    """

    def __init__(self):
        self.events: list[str] = []

    @property
    def calls(self) -> list[str]:
        return [e.removeprefix("GET ") for e in self.events if e.startswith("GET ")]


def _stub(monkeypatch, *outcomes) -> _Transport:
    """Queue one outcome per call: bytes for a 200 body, a _Resp, or an exception to raise."""
    queue, t = list(outcomes), _Transport()

    def fake_urlopen(req, timeout=None):
        t.events.append(f"GET {req.full_url}")
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome if isinstance(outcome, _Resp) else _Resp(outcome)

    monkeypatch.setattr(reach.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(reach.time, "sleep", lambda s: t.events.append(f"sleep {s}"))
    return t


# --- the failing cases first -------------------------------------------------

def test_rate_limit_is_retried_after_a_real_backoff(monkeypatch):
    t = _stub(monkeypatch, _http_error(429), _http_error(429))
    data, reason, status = reach._get_json("https://pypistats.org/api/x")
    assert data is None
    assert status == 429
    assert "429" in reason and "retryable" in reason
    # The literal 2.0 rules out BACKOFF_SECONDS being set to zero, and the ORDER rules
    # out sleeping after the retry instead of before it. Asserting `slept ==
    # [reach.BACKOFF_SECONDS]` proved neither: it compared the constant to itself.
    assert t.events == ["GET https://pypistats.org/api/x", "sleep 2.0",
                        "GET https://pypistats.org/api/x"], (
        "the retry must wait BEFORE re-firing: hitting a rate limiter instantly "
        "doubles the request rate against the limiter that blanked the gauge"
    )


def test_rate_limited_pypi_does_not_read_as_a_bare_unavailable(monkeypatch):
    _stub(monkeypatch, _http_error(429), _http_error(429))
    row = reach.pypi_reach()
    assert row["available"] is False
    assert row["http_status"] == 429
    rendered = reach.render_table([row])
    assert "429" in rendered, "the report must name why the gauge is blank"


def test_dockerhub_404_and_429_do_not_render_the_same(monkeypatch):
    _stub(monkeypatch, _http_error(404))
    absent = reach.dockerhub_reach()
    _stub(monkeypatch, _http_error(429), _http_error(429))
    throttled = reach.dockerhub_reach()

    absent_line = reach.render_table([absent])
    throttled_line = reach.render_table([throttled])
    assert "not yet mirrored" in absent_line
    assert "not yet mirrored" not in throttled_line, (
        "a rate limit must never be reported as a surface that does not exist"
    )
    assert "429" in throttled_line
    assert absent_line != throttled_line


def test_network_error_and_bad_json_carry_their_own_reasons(monkeypatch):
    _stub(monkeypatch, urllib.error.URLError("no route to host"))
    _, reason, status = reach._get_json("https://example.com/x")
    assert "network error" in reason and status is None

    _stub(monkeypatch, _Resp(b"{not json", status=200))
    _, reason, status = reach._get_json("https://example.com/x")
    assert "JSONDecodeError" in reason or "ValueError" in reason
    assert status == 200, (
        "the HTTP layer succeeded, so a malformed body must not report the same "
        "http_status as a DNS failure"
    )


def test_non_https_is_refused_without_a_request(monkeypatch):
    t = _stub(monkeypatch)
    data, reason, _ = reach._get_json("http://insecure.example.com/x")
    assert data is None and "non-https" in reason
    assert t.calls == [], "a refused URL must not be fetched"


# --- a 200 is not a measurement: unfamiliar bodies must not print confident zeros ---

def test_ok_response_with_an_unfamiliar_body_never_reports_counts(monkeypatch):
    _stub(monkeypatch, b'{"data": {}}')
    pypi = reach.pypi_reach()
    assert pypi["available"] is False, "three nulls are not three measurements"

    _stub(monkeypatch, b'{"detail": "gone"}')
    docker = reach.dockerhub_reach()
    assert docker["available"] is False
    assert "not yet mirrored" not in docker["note"], "a 200 is not a missing mirror"

    _stub(monkeypatch, b'{"data": [1, 2, 3]}')
    assert reach.pypi_reach()["available"] is False, "a list where a dict belongs must not crash"


def test_hf_dropped_expand_param_never_fabricates_a_zero_total(monkeypatch):
    # The real API shape when the expand[] params are lost: well-formed dicts that
    # carry `downloads` (default) but not `downloadsAllTime` (expand-only). The old
    # `.get(x) or 0` turned that into a plausible-looking row with one real number
    # and one fabricated zero, which is worse than an obviously broken one.
    _stub(monkeypatch, b'[{"id": "a", "downloads": 40}, {"id": "b", "downloads": 38}]')
    row = reach.hf_reach()
    assert "all_time" not in row, "a total the API never delivered must not be published"
    assert row["last_30d"] == 78, "the total it DID deliver still counts"
    assert row["repos"] == 2
    rendered = reach.render_table([row])
    assert "0 all-time" not in rendered
    assert "downloadsAllTime" in row["caveat"]


def test_hf_partial_delivery_is_not_summed_into_a_plausible_undercount(monkeypatch):
    # `any(field in m ...)` only caught absent-on-EVERY-member. Absent on SOME fell
    # through to .get(field, 0) and fabricated a zero per missing repo, summing to a
    # too-low total with nothing marking it: 5,000 presented as the all-time figure
    # across two repos when one was never delivered.
    _stub(monkeypatch, b'[{"downloadsAllTime": 5000, "downloads": 400}, {"downloads": 45}]')
    row = reach.hf_reach()
    assert "all_time" not in row, "one missing member makes the total unmeasurable"
    assert row["last_30d"] == 445, "the fully-delivered total still counts"
    assert "5,000" not in reach.render_table([row])


def test_hf_mixed_member_types_refuse_rather_than_reach_sum(monkeypatch):
    _stub(monkeypatch, b'[{"downloadsAllTime": 5000}, {"downloadsAllTime": "many"}]')
    row = reach.hf_reach()
    assert "all_time" not in row, "a string in one member must not reach sum()"
    reach.render_table([row])


def test_hf_present_and_zero_is_a_real_zero(monkeypatch):
    # The mirror case of the test above: the field is delivered and genuinely zero.
    # That IS a measurement and must publish, or the guard becomes its own fail-open.
    _stub(monkeypatch, b'[{"downloadsAllTime": 0, "downloads": 0}]')
    row = reach.hf_reach()
    assert row["all_time"] == 0 and row["last_30d"] == 0
    assert "caveat" not in row


def test_hf_empty_list_publishes_the_count_it_measured_and_nothing_else(monkeypatch):
    _stub(monkeypatch, b"[]")
    row = reach.hf_reach()
    assert row["repos"] == 0, "0 repos IS a measurement and publishes"
    assert "all_time" not in row and "last_30d" not in row, (
        "no downloads were measured, so none are reported"
    )
    assert "0 repos" in row["caveat"]
    assert "0 all-time" not in reach.render_table([row])


def test_hf_non_numeric_download_field_does_not_crash_the_whole_report(monkeypatch):
    _stub(monkeypatch, b'[{"downloadsAllTime": "many", "downloads": 1}]')
    row = reach.hf_reach()
    assert "all_time" not in row, "a string must not reach sum() and kill every surface"
    assert row["last_30d"] == 1
    reach.render_table([row])


def test_hf_failures_carry_their_reason(monkeypatch):
    _stub(monkeypatch, _http_error(503), _http_error(503))
    row = reach.hf_reach()
    assert row["available"] is False and row["http_status"] == 503
    assert "503" in reach.render_table([row])

    _stub(monkeypatch, b'[1, 2, 3]')
    assert reach.hf_reach()["available"] is False, "non-dict members must not be summed"


def test_hf_sums_downloads_and_flags_page_truncation(monkeypatch):
    _stub(monkeypatch, b'[{"downloadsAllTime": 5000, "downloads": 400},'
                       b' {"downloadsAllTime": 346, "downloads": 45}]')
    row = reach.hf_reach()
    assert (row["available"], row["repos"], row["all_time"], row["last_30d"]) == (True, 2, 5346, 445)
    assert row["truncated"] is False
    assert "5,346 all-time" in reach.render_table([row])

    # Sized from the constant, not from a literal 100: the request's limit and the
    # truncation comparison must be the same number or the flag drifts silently.
    t = _stub(monkeypatch, b"[" + b",".join(
        [b'{"downloadsAllTime": 1, "downloads": 1}'] * reach.HF_PAGE_SIZE) + b"]")
    truncated = reach.hf_reach()
    assert f"limit={reach.HF_PAGE_SIZE}" in t.calls[0], "the query must request the size it checks"
    assert truncated["truncated"] is True, "a full page may be hiding repos past the limit"
    assert "truncated" in reach.render_table([truncated])


# --- the stars leg: gross additions, and windows the feed cannot cover ---------

def _events(*specs: str) -> bytes:
    """specs are 'TYPE@ISO' pairs, e.g. 'WatchEvent@2026-08-12T00:00:00Z'.

    Every event gets a DISTINCT id derived from its own spec. Real GitHub pages share
    no ids, so a fixture reusing one models a feed the API cannot serve — and an
    earlier version of this file did exactly that, which made the suite reject a
    correct dedup fix. Pass 'TYPE@ISO#id' to force a shared id on purpose.
    """
    out = []
    for i, spec in enumerate(specs):
        body, _, forced = spec.partition("#")
        kind, _, ts = body.partition("@")
        eid = forced or f"e{i}-{kind}-{ts}"
        out.append(f'{{"id": "{eid}", "type": "{kind}", "created_at": "{ts}"}}')
    return ("[" + ",".join(out) + "]").encode()


# A fixed instant, never wall-clock: a window asserted against `now` would go red on a
# calendar boundary with no commit behind it.
NOW = datetime(2026, 8, 13, 0, 0, tzinfo=UTC)


def test_star_windows_are_gross_counts_and_ignore_other_event_types(monkeypatch):
    _stub(monkeypatch,
          b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z",    # inside 7d
                  "WatchEvent@2026-08-08T00:00:00Z",    # inside 7d
                  "PushEvent@2026-08-11T00:00:00Z",     # not a star
                  "WatchEvent@2026-08-02T00:00:00Z",    # inside 14d only
                  "ForkEvent@2026-07-20T00:00:00Z"))    # oldest, sets feed reach
    row = reach.github_reach(now=NOW)
    assert (row["stars"], row["forks"]) == (30, 3)
    assert row["star_windows"]["7"]["stars_added"] == 2, "a PushEvent is not a star"
    assert row["star_windows"]["14"]["stars_added"] == 3
    assert row["stars_per_day"]["2026-08-12"] == 1


def test_a_short_page_means_the_feed_is_exhausted_not_merely_shallow(monkeypatch):
    # A page that comes back SHORT is the end of the feed, so there is nothing older to
    # have missed and the window is complete even though the oldest event is recent.
    # Treating feed reach as the only signal marked such repos incomplete forever, so
    # the "≥" decorated instead of meaning something.
    _stub(monkeypatch,
          b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z", "WatchEvent@2026-08-10T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["feed_exhausted"] is True
    assert row["star_windows"]["7"]["complete"] is True
    assert row["star_windows"]["14"]["complete"] is True
    assert "≥" not in reach.render_table([row])


def test_a_full_feed_that_stops_short_of_the_window_is_a_floor(monkeypatch):
    # Verified live 2026-08-13: one page reached only to 08-02, so 14d read 11 against
    # an authoritative 13. Page 2 also came back full, which is why the fetch pages.
    # Each page carries DISTINCT events, as real pages do.
    monkeypatch.setattr(reach, "EVENTS_PAGE", 2)
    monkeypatch.setattr(reach, "EVENTS_MAX_PAGES", 2)
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z", "WatchEvent@2026-08-11T00:00:00Z"),
          _events("WatchEvent@2026-08-10T00:00:00Z", "WatchEvent@2026-08-09T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["feed_exhausted"] is False, "every page came back full: more events exist"
    assert row["feed_stopped_because"] == "page_cap"
    assert row["star_windows"]["14"]["complete"] is False
    rendered = reach.render_table([row])
    assert "≥+4/14d" in rendered, "an uncoverable window is not a total"
    assert "feed page cap" in rendered, "the table must say the read was cut short"


def test_a_re_served_event_is_not_counted_twice(monkeypatch):
    # Events pagination is offset-based, so a star arriving mid-walk shifts the window
    # and re-serves an event already held. Without dedup that star counts twice and the
    # row still claims complete. The shared id below is what a real overlap looks like.
    monkeypatch.setattr(reach, "EVENTS_PAGE", 2)
    monkeypatch.setattr(reach, "EVENTS_MAX_PAGES", 2)
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z#dup", "WatchEvent@2026-08-11T00:00:00Z"),
          _events("WatchEvent@2026-08-12T00:00:00Z#dup", "PushEvent@2026-06-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["star_windows"]["7"]["stars_added"] == 2, "the repeated event is one star"
    assert row["events_read"] == 3, "the duplicate is dropped, not stored twice"


def test_paging_stops_as_soon_as_the_longest_window_is_covered(monkeypatch):
    # Each request spends from an unauthenticated 60/hr budget, so the fetch must stop
    # at the first page that reaches past the oldest window rather than always paging.
    monkeypatch.setattr(reach, "EVENTS_PAGE", 2)
    monkeypatch.setattr(reach, "EVENTS_MAX_PAGES", 4)
    t = _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
              _events("WatchEvent@2026-08-12T00:00:00Z", "PushEvent@2026-07-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert len(t.calls) == 2, "one repo read, one events page, then stop"
    assert row["star_windows"]["14"]["complete"] is True


def test_an_undated_event_makes_a_window_incomplete_even_when_the_feed_is_deep(monkeypatch):
    # An undated event may itself be a star inside the window. Feed reach is not the
    # only way a count comes up short, and a dropped star inside a covered window would
    # otherwise print as a confident total.
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z",
                  "WatchEvent@not-a-timestamp",
                  "PushEvent@2026-07-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["undated_events"] == 1
    assert row["star_windows"]["7"]["complete"] is False, (
        "a dropped event might have been a star inside this window"
    )
    assert "≥+1/7d" in reach.render_table([row])


def test_an_undated_event_does_not_shift_stars_onto_other_events(monkeypatch):
    # The feed is NOT guaranteed to be uniformly dated. Filtering timestamps into their
    # own list and zipping it back against the unfiltered events misaligns every pair
    # after the first undated one: below, the real star at 08-01 would be dropped and
    # the PushEvent's 08-12 attributed to a star instead, turning a 14d-only star into
    # a fake 7d one. Pairing in a single pass makes that unrepresentable.
    _stub(monkeypatch,
          b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@not-a-timestamp",
                  "PushEvent@2026-08-12T00:00:00Z",
                  "WatchEvent@2026-08-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["stars_per_day"] == {"2026-08-01": 1}, "a star must keep its OWN timestamp"
    assert row["star_windows"]["7"]["stars_added"] == 0, "the 08-01 star is not inside 7 days"
    assert row["star_windows"]["14"]["stars_added"] == 1
    assert row["undated_events"] == 1, "dropped events are reported, not silently lost"
    assert row["star_windows"]["14"]["complete"] is False, "an undated event may be a star"


def test_a_naive_timestamp_is_treated_as_undated_not_a_crash(monkeypatch):
    # Comparing a naive datetime against an aware `now` raises TypeError, which would
    # kill main() and take PyPI, Docker Hub and HuggingFace down with it.
    _stub(monkeypatch,
          b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00", "WatchEvent@2026-08-12T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["star_windows"]["7"]["stars_added"] == 1
    assert row["undated_events"] == 1
    reach.render_table([row])


def test_github_counts_get_the_same_guard_as_every_other_surface(monkeypatch):
    # _is_count was added for PyPI/Docker/HF and then a FOURTH surface was written an
    # hour later using the bare isinstance(int) it replaced. bool subclasses int, so
    # a JSON true rendered as "1 stars · 1 forks": a fabricated number on a surface
    # whose own docstring promises none.
    _stub(monkeypatch, b'{"stargazers_count": true, "forks_count": true}')
    row = reach.github_reach(now=NOW)
    assert row["available"] is False
    assert "1 stars" not in reach.render_table([row])


def test_forks_is_validated_not_passed_through_raw(monkeypatch):
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": "3"}',
          _events("PushEvent@2026-07-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["forks"] is None, "an unvalidated string was published straight to --json"
    assert row["stars"] == 30, "the count that IS real still publishes"


def test_a_star_exactly_on_the_window_boundary_is_inside_it(monkeypatch):
    # Pins inclusivity: with no fixture on the edge, >= vs > is invisible.
    boundary = (NOW - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events(f"WatchEvent@{boundary}", "PushEvent@2026-07-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["star_windows"]["7"]["stars_added"] == 1


def test_the_histogram_spans_the_feed_and_does_not_compose_with_the_windows(monkeypatch):
    # Deliberate, documented divergence, pinned so it is not mistaken for an accident:
    # windows cut at an exact timestamp while the histogram buckets whole UTC days. A
    # star earlier on the cutoff's own day is in the histogram and outside the count.
    # Today's live numbers reconcile only because both 08-06 stars fall after the
    # cutoff; a reader summing the histogram to check a window would be misled.
    # A midday `now` is required: with a midnight one the cutoff sits on the day
    # boundary and the same-day-but-earlier region this pins does not exist.
    midday = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
    cutoff_day = (midday - timedelta(days=7)).date().isoformat()
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events(f"WatchEvent@{cutoff_day}T01:00:00Z",   # same day, BEFORE the cutoff
                  "PushEvent@2026-07-01T00:00:00Z"))
    row = reach.github_reach(now=midday)
    assert row["stars_per_day"][cutoff_day] == 1, "the histogram covers the whole feed"
    assert row["star_windows"]["7"]["stars_added"] == 0, "the window cuts at an instant"


def test_undated_events_counts_every_undated_event_not_only_stars(monkeypatch):
    # The count is a data-quality signal about the FEED, so a non-star with no date
    # counts too: it is still an event we could not place, and it still means a star
    # could be hiding among the ones we dropped.
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("PushEvent@no-date", "IssuesEvent@also-bad",
                  "WatchEvent@2026-08-12T00:00:00Z", "PushEvent@2026-07-01T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["undated_events"] == 2
    assert row["star_windows"]["7"]["complete"] is False


def test_the_histogram_ships_oldest_first(monkeypatch):
    # Regression, caught by the lens after I removed sorted() on its own bad advice:
    # per_day is built by iterating `stars`, and dict insertion order IS the --json key
    # order. Unsorted, the histogram shipped newest-first and a consumer plotting it in
    # key order got a reversed axis. The feed is not chronological, so the input order
    # below is deliberately scrambled.
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-10T00:00:00Z", "WatchEvent@2026-08-12T00:00:00Z",
                  "WatchEvent@2026-08-11T00:00:00Z", "PushEvent@2026-06-01T00:00:00Z"))
    keys = list(reach.github_reach(now=NOW)["stars_per_day"])
    assert keys == sorted(keys), "the histogram must ship in chronological key order"


def test_a_page_that_errors_mid_walk_is_reported_as_a_partial_read(monkeypatch):
    # Earlier pages stay usable, but "we stopped" has four meanings and reporting them
    # alike asserts a clean read that did not happen. The count stays honest either
    # way, since an uncovered window is already incomplete; the provenance is the gap.
    monkeypatch.setattr(reach, "EVENTS_PAGE", 2)
    monkeypatch.setattr(reach, "EVENTS_MAX_PAGES", 3)
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z", "WatchEvent@2026-08-11T00:00:00Z"),
          _http_error(422))
    row = reach.github_reach(now=NOW)
    assert row["feed_stopped_because"] == "error"
    assert row["feed_exhausted"] is False
    assert row["star_windows"]["14"]["complete"] is False
    assert "feed error" in reach.render_table([row]), "a partial read must be visible"


def test_the_shipped_page_cap_can_actually_cover_the_longest_window(monkeypatch):
    # Both paging tests patch EVENTS_MAX_PAGES, so the module value was exercised by
    # nothing: setting it to 1 reverted the whole pagination feature with a green suite.
    # Measured 2026-08-13: the endpoint serves 300 events over 3 pages and 422s past it.
    assert reach.EVENTS_MAX_PAGES == 3
    assert reach.EVENTS_MAX_PAGES * reach.EVENTS_PAGE == 300

    page = _events(*[f"PushEvent@2026-08-{12 - i:02d}T00:00:00Z" for i in range(3)])
    t = _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}', page, page, page)
    monkeypatch.setattr(reach, "EVENTS_PAGE", 3)
    reach.github_reach(now=NOW)
    assert len(t.calls) == 4, "one repo read plus every page the shipped cap allows"
    assert "page=3" in t.calls[-1], "the cap must be reachable, not one page short"


def test_the_histogram_spans_the_whole_feed_not_just_the_window(monkeypatch):
    # The other half of the documented property: window-aligning the histogram would
    # pass the day-vs-instant test but silently drop the older shape.
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z",     # inside 7d
                  "WatchEvent@2026-06-15T00:00:00Z"))    # far outside every window
    row = reach.github_reach(now=NOW)
    assert "2026-06-15" in row["stars_per_day"], "the histogram is not window-clipped"
    assert row["star_windows"]["14"]["stars_added"] == 1, "the window still excludes it"


def test_a_caveat_actually_reaches_the_printed_table(monkeypatch):
    # Every other render assertion here is NEGATIVE ("0 all-time" absent), and those
    # all pass when the caveat is dropped entirely. Deleting the renderer's caveat
    # branch left the suite green, so the caveat only ever existed in --json. John
    # reads the table.
    _stub(monkeypatch, b'[{"id": "a", "downloads": 40}]')
    rendered = reach.render_table([reach.hf_reach()])
    assert "downloadsAllTime" in rendered, "a caveat nobody prints is not a caveat"


def test_paging_does_not_stop_on_an_inversion_and_strand_in_window_stars(monkeypatch):
    # The feed is NOT chronological: inversions of ~14h were measured on the live feed.
    # Page 1 here dips just past the 14d boundary, so stopping on the bare boundary
    # would end the walk and strand the 08-01 star sitting on page 2.
    monkeypatch.setattr(reach, "EVENTS_PAGE", 2)
    monkeypatch.setattr(reach, "EVENTS_MAX_PAGES", 3)
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _events("WatchEvent@2026-08-12T00:00:00Z", "PushEvent@2026-07-29T12:00:00Z"),
          _events("WatchEvent@2026-08-01T00:00:00Z", "PushEvent@2026-07-20T00:00:00Z"))
    row = reach.github_reach(now=NOW)
    assert row["star_windows"]["14"]["stars_added"] == 2, (
        "an in-window star one page past an inversion must not be stranded"
    )


def test_github_reports_stars_even_when_the_events_feed_fails(monkeypatch):
    _stub(monkeypatch, b'{"stargazers_count": 30, "forks_count": 3}',
          _http_error(403), _http_error(403))
    row = reach.github_reach(now=NOW)
    assert row["available"] is True and row["stars"] == 30
    assert "403" in row["velocity_note"]
    assert "30 stars" in reach.render_table([row])


def test_github_rate_limit_reports_its_status_not_a_blank(monkeypatch):
    _stub(monkeypatch, _http_error(403))
    row = reach.github_reach(now=NOW)
    assert row["available"] is False and row["http_status"] == 403
    assert "403" in reach.render_table([row])


# --- the success path, so the failing cases above are meaningful --------------

def test_404_is_not_retried(monkeypatch):
    t = _stub(monkeypatch, _http_error(404))
    _, _, status = reach._get_json("https://example.com/x")
    assert status == 404
    assert len(t.calls) == 1, "a definitive status must not be retried"
    assert not [e for e in t.events if e.startswith("sleep")], (
        "a definitive status must not cost a backoff"
    )


def test_success_reports_the_transport_status_not_a_hardcoded_200(monkeypatch):
    # 203 is a real success the stub does not default to: if the code hardcoded 200,
    # this is the assertion that catches it.
    t = _stub(monkeypatch, _http_error(503), _Resp(b'{"data": {"last_month": 3250}}', status=203))
    data, reason, status = reach._get_json("https://pypistats.org/api/x")
    assert reason is None and status == 203
    assert data["data"]["last_month"] == 3250
    assert t.events[1] == "sleep 2.0" and len(t.calls) == 2


def test_pypi_row_reports_counts_when_the_fetch_succeeds(monkeypatch):
    _stub(monkeypatch, b'{"data": {"last_day": 257, "last_week": 1020, "last_month": 3250}}')
    row = reach.pypi_reach()
    assert row["available"] is True
    assert (row["last_day"], row["last_week"], row["last_month"]) == (257, 1020, 3250)
    assert "3,250/mo" in reach.render_table([row])


def test_a_json_true_is_not_a_count(monkeypatch):
    # bool subclasses int, and f"{True:,}" renders as "1". A guard that only checked
    # isinstance(v, int) would publish a fabricated 1 as a measured figure.
    _stub(monkeypatch, b'{"data": {"last_day": true, "last_week": true, "last_month": true}}')
    assert reach.pypi_reach()["available"] is False

    _stub(monkeypatch, b'{"pull_count": true}')
    row = reach.dockerhub_reach()
    assert row["available"] is False
    assert "1 pulls" not in reach.render_table([row])


def test_a_stringified_count_is_not_a_count(monkeypatch):
    _stub(monkeypatch, b'{"pull_count": "1372"}')
    assert reach.dockerhub_reach()["available"] is False, (
        "an available row that renders a dash is the defect this guard exists to stop"
    )
    _stub(monkeypatch, b'{"data": {"last_day": "257", "last_week": "1020", "last_month": "3250"}}')
    assert reach.pypi_reach()["available"] is False


def test_partial_pypi_data_publishes_what_was_measured_and_nulls_the_rest(monkeypatch):
    # Recorded policy, not an accident: one real count is enough to publish, and the
    # absent ones travel as explicit nulls rather than as zeros or as a dropped row.
    _stub(monkeypatch, b'{"data": {"last_day": 257, "last_week": null, "last_month": null}}')
    row = reach.pypi_reach()
    assert row["available"] is True
    assert (row["last_day"], row["last_week"], row["last_month"]) == (257, None, None)
    rendered = reach.render_table([row])
    assert "257/day" in rendered and "—/mo" in rendered


def test_json_output_is_well_formed_and_carries_http_status_on_every_surface(monkeypatch):
    _stub(monkeypatch, b'{"data": {"last_day": 1, "last_week": 2, "last_month": 3}}')
    rows = [reach.pypi_reach()]
    _stub(monkeypatch, b'{"pull_count": 7}')
    rows.append(reach.dockerhub_reach())
    _stub(monkeypatch, b'[{"downloadsAllTime": 1, "downloads": 1}]')
    rows.append(reach.hf_reach())
    _stub(monkeypatch, _http_error(429), _http_error(429))
    rows.append(reach.pypi_reach())

    for row in rows:
        assert "http_status" in row, (
            f"{row['surface']}: the --json contract must not be shaped by success"
        )
        json.loads(json.dumps(row))  # every state must serialise
