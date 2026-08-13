#!/usr/bin/env python3
"""Report Proximo's global install/download reach across every countable surface.

Turns the ad-hoc "what's our download count" question into one reproducible view:

    python scripts/reach.py            # human table
    python scripts/reach.py --json     # machine-readable

Surfaces:
  * GitHub (john-broadway/proximo) — stars/forks now, plus stars GAINED per window
    from the public events feed.
  * PyPI   (proximo-proxmox) — pypistats recent counts (last day/week/month).
  * Docker Hub (jebroadway/proximo) — pull_count. GHCR exposes no pull count, so
    the release pipeline mirrors the image here (see .github/workflows/dockerhub-mirror.yml);
    until the first mirror lands this reads "not yet mirrored".
  * HuggingFace (john-broadway RYS models) — all-time + last-30d downloads.

Honesty notes baked into the output:
  * PyPI/Docker counts include CI, mirrors, and bots — treat as reach, not humans.
  * GHCR pull counts are unmeasurable at the source; Docker Hub is the proxy.
  * Star counts per window are GROSS: WatchEvent fires on star and never on unstar.
    The events feed is paged back until it covers the longest window; anything still
    short of it, or holding an undated event that might itself be a star, prints "≥":
    a floor, not a total. Validated 2026-08-13 against the authoritative stargazer
    list — WatchEvent counts matched exactly at the feed boundary and over 7 days.
  * No surface ever publishes a number it did not measure: an absent count is
    omitted or null, never rendered as a zero.

Stdlib only — no deps, runs under any python3.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

PYPI_PACKAGE = "proximo-proxmox"
DOCKERHUB_REPO = "jebroadway/proximo"
HF_AUTHOR = "john-broadway"
GITHUB_REPO = "john-broadway/proximo"
STAR_WINDOWS_DAYS = (7, 14)
EVENTS_PAGE = 100
EVENTS_MAX_PAGES = 3  # measured: the events endpoint serves 300 max and 422s past it
EVENTS_ORDER_SLACK = timedelta(hours=36)  # feed is unordered; measured inversions ~14h
HF_PAGE_SIZE = 100  # interpolated into the query AND compared against: one constant, no drift

TIMEOUT = 15
RETRY_STATUSES = (429, 500, 502, 503, 504)
BACKOFF_SECONDS = 2.0


def _fetch(url: str) -> tuple[dict | list | None, str | None, int | None]:
    """One GET attempt. Returns (data, reason, http_status); reason is None on success."""
    if not url.startswith("https://"):  # only ever called with the fixed https constants above; enforce it
        return None, "refused: non-https URL", None
    req = urllib.request.Request(url, headers={"User-Agent": "proximo-reach/1.0"})  # noqa: S310 — https enforced above
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 — https enforced above
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as e:  # subclass of URLError — must be caught first
        retryable = " (retryable)" if e.code in RETRY_STATUSES else ""
        return None, f"HTTP {e.code}{retryable}", e.code
    except urllib.error.URLError as e:
        return None, f"network error: {e.reason}", None
    except TimeoutError as e:
        return None, f"TimeoutError: {e}", None
    try:
        return json.loads(body.decode("utf-8")), None, status
    except ValueError as e:  # JSONDecodeError and UnicodeDecodeError are both ValueError
        # The HTTP layer SUCCEEDED here. Keep its status, or a malformed body is
        # indistinguishable from a DNS failure to anything reading --json.
        return None, f"{type(e).__name__}: {e}", status


def _get_json(url: str) -> tuple[dict | list | None, str | None, int | None]:
    """GET with one retry on transient statuses. Returns (data, reason, http_status).

    The reason is load-bearing. A 429 says nothing about the surface and clears on
    its own; a 404 means the surface is genuinely absent. The earlier version
    collapsed both — plus network errors and malformed JSON — into a bare None, so
    the report printed "unavailable" for PyPI on a day it was serving thousands of
    downloads. A gauge that reads empty when it is merely rate-limited is worse
    than one that admits it failed.
    """
    data, reason, status = _fetch(url)
    if data is None and status in RETRY_STATUSES:
        time.sleep(BACKOFF_SECONDS)
        data, reason, status = _fetch(url)
    return data, reason, status


def _blank(surface: str, note: str, status: int | None, **extra) -> dict:
    """An unavailable row that always says WHY. Never prints a count it did not measure."""
    return {"surface": surface, "available": False, "note": note, "http_status": status, **extra}


def _is_count(v: object) -> bool:
    """A real count. bool is a subclass of int, and `f"{True:,}"` renders as "1",
    so a guard that only checks int would publish a fabricated 1 from a JSON true."""
    return isinstance(v, int) and not isinstance(v, bool)


def pypi_reach() -> dict:
    # pypistats /recent reports downloads WITHOUT mirrors (verified 2026-08-13 against
    # the /overall series: the without_mirrors sum for the same 30d window matches
    # last_month exactly, 3,250). Including mirrors would roughly triple the figure;
    # we report the lower, honest one.
    data, reason, status = _get_json(f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/recent")
    d = data.get("data") if isinstance(data, dict) else None
    counts = ({k: d.get(k) for k in ("last_day", "last_week", "last_month")}
              if isinstance(d, dict) else {})
    # Policy, recorded because it is a choice: a row publishes when AT LEAST ONE count
    # is real, carrying explicit nulls for the rest. Each present field is individually
    # honest, while an all-null row is not a measurement at all and must not read as one.
    if not any(_is_count(v) for v in counts.values()):
        return _blank("PyPI", reason or "unexpected response shape", status, package=PYPI_PACKAGE)
    return {"surface": "PyPI", "package": PYPI_PACKAGE, "available": True, "http_status": status,
            **{k: (v if _is_count(v) else None) for k, v in counts.items()}}


def dockerhub_reach() -> dict:
    data, reason, status = _get_json(f"https://hub.docker.com/v2/repositories/{DOCKERHUB_REPO}/")
    pulls = data.get("pull_count") if isinstance(data, dict) else None
    if not _is_count(pulls):
        # 404 until the first mirror runs: genuine absence, a distinct honest state.
        # Any other failure is the instrument, not the surface. Don't print them alike.
        note = ("not yet mirrored — run the dockerhub-mirror workflow" if status == 404
                else reason or "unexpected response shape")
        return _blank("Docker Hub", note, status, repo=DOCKERHUB_REPO)
    return {"surface": "Docker Hub", "repo": DOCKERHUB_REPO, "available": True,
            "http_status": status, "pull_count": pulls}


def _hf_total(members: list[dict], field: str) -> int | None:
    """Sum one expand-only field, or None if it was never delivered.

    `downloadsAllTime` arrives ONLY when its expand[] param does; `downloads` comes by
    default. So dropping a query param yields well-formed dicts missing one field, and
    `.get(field) or 0` would fabricate a zero for every repo while the other total
    stayed real: a row that looks plausible instead of obviously broken. Absent on ANY
    member makes the total unmeasurable. Present-and-zero is a genuine zero.
    """
    if not all(field in m for m in members):
        # `any` was not strict enough: a field absent on SOME members fell through to
        # .get(field, 0), fabricating a zero contribution each and summing to a
        # plausible, too-low total with nothing to mark it. Absent on any member means
        # the total is not measurable. Present-and-zero is still a genuine zero.
        return None
    values = [m[field] for m in members]
    return sum(values) if all(_is_count(v) for v in values) else None


def hf_reach() -> dict:
    url = (f"https://huggingface.co/api/models?author={HF_AUTHOR}"
           f"&expand[]=downloadsAllTime&expand[]=downloads&limit={HF_PAGE_SIZE}")
    data, reason, status = _get_json(url)
    if not isinstance(data, list) or not all(isinstance(m, dict) for m in data):
        return _blank("HuggingFace", reason or "unexpected response shape", status, author=HF_AUTHOR)
    row = {"surface": "HuggingFace", "author": HF_AUTHOR, "available": True,
           "http_status": status, "repos": len(data),
           # At exactly one full page the sums may be missing repos past the limit.
           "truncated": len(data) >= HF_PAGE_SIZE}
    if not data:
        # 0 repos is a real measurement, so the repo count publishes. The download
        # totals are NOT measured here, so they are omitted rather than sent as zeros.
        return row | {"caveat": f"API returned 0 repos for author '{HF_AUTHOR}'"}
    fields = (("all_time", "downloadsAllTime"), ("last_30d", "downloads"))
    totals = {key: _hf_total(data, api) for key, api in fields}
    # Name the API field, not our key: it is what a reader greps for to find the
    # dropped expand[] param.
    missing = [api for key, api in fields if totals[key] is None]
    if missing:
        row["caveat"] = f"not delivered by the API: {', '.join(missing)}"
    return row | {k: v for k, v in totals.items() if v is not None}


def _parse_ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A naive timestamp compared against an aware `now` raises TypeError and takes
    # down every surface, not just this one. Treat it as undated.
    return parsed if parsed.tzinfo else None


def _fetch_events(oldest_needed: datetime) -> tuple[list[dict], str | None, str]:
    """Page the events feed back past `oldest_needed`. Returns (events, reason, stop).

    One page was NOT enough: page 2 also returns a full 100 events (probed), so a
    single read stopped ~11 days back and made every longer window a floor.

    `stop` records WHY paging ended, because "we stopped" has four different meanings
    and reporting them alike hides whether the read was clean:
      exhausted  - a short page, i.e. the end of the feed itself
      covered    - we reached past the oldest window with room to spare
      page_cap   - we hit our own limit with the window still uncovered
      error      - a page failed; earlier pages are still usable but the read is partial

    Measured 2026-08-13: this endpoint serves at most 300 events (3 pages) and answers
    422 beyond that, never a short page. So a short page really is the feed's end, and
    asking for a 4th page is a guaranteed-wasted request against a 60/hr budget.

    Pagination is offset-based, so an event arriving mid-walk shifts the window and
    re-serves one we already hold. Dedup by event id or that star is counted twice.
    """
    events: list[dict] = []
    seen_ids: set[str] = set()
    stamps: list[datetime] = []
    for page in range(1, EVENTS_MAX_PAGES + 1):
        data, reason, _ = _get_json(f"https://api.github.com/repos/{GITHUB_REPO}"
                                    f"/events?per_page={EVENTS_PAGE}&page={page}")
        if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
            # Earlier pages stay usable, but the read is partial and must say so.
            return events, (reason or "events feed unavailable") if not events else None, "error"
        for e in data:
            eid = e.get("id")
            if isinstance(eid, str):
                if eid in seen_ids:
                    continue
                seen_ids.add(eid)
            events.append(e)
            if (t := _parse_ts(e.get("created_at"))):
                stamps.append(t)
        if len(data) < EVENTS_PAGE:
            return events, None, "exhausted"
        # The feed is NOT strictly ordered (inversions of ~14h measured), so stopping
        # the moment a page dips past the boundary can strand in-window events on the
        # next page. Require a margin, and judge on every stamp held, not this page's.
        if stamps and min(stamps) <= oldest_needed - EVENTS_ORDER_SLACK:
            return events, None, "covered"
    return events, None, "page_cap"


def _star_velocity(now: datetime) -> dict:
    """Gross star additions per window, from the public events feed.

    Honesty constraints, all load-bearing:
      * WatchEvent fires on star and NEVER on unstar, so these are additions, not net.
      * A window the feed does not reach back through is a FLOOR, not a total, and says
        so rather than presenting a confident number.
      * An undated event may itself be a star inside the window, so undated events make
        a window incomplete too. Feed reach is not the only way a count can be short.
      * An average over a window hides a spike, so the per-day shape ships in --json.

    `stars_per_day` spans the WHOLE feed and buckets by UTC calendar day, while the
    windows cut at an exact timestamp. The two therefore do NOT compose: a star earlier
    on the same day as a window's cutoff appears in the histogram and outside the count.
    The histogram answers "what is the shape", not "what is in the window"; only
    `star_windows` answers the latter.
    """
    oldest_needed = now - timedelta(days=max(STAR_WINDOWS_DAYS))
    data, reason, stop = _fetch_events(oldest_needed)
    if reason or not data:
        return {"velocity_note": reason or "events feed returned no events"}
    # Pair each event with its OWN timestamp in one pass. Filtering timestamps into a
    # separate list and zipping them back against the unfiltered events misaligns every
    # pair after the first undated event, silently attributing stars to other events.
    dated = [(e, t) for e in data if (t := _parse_ts(e.get("created_at")))]
    if not dated:
        return {"velocity_note": "events feed returned no dated events"}
    # sorted() is NOT dead work: per_day is built by iterating this, and dict
    # insertion order is the --json key order. Without it the histogram ships
    # newest-first, so a consumer plotting it in key order gets a reversed axis.
    stars = sorted(t for e, t in dated if e.get("type") == "WatchEvent")
    reaches_back_to = min(t for _, t in dated)
    undated = len(data) - len(dated)
    windows, per_day = {}, {}
    for days in STAR_WINDOWS_DAYS:
        start = now - timedelta(days=days)
        # An undated event could be a star inside this window, so it can only be called
        # complete when every event carried a date.
        windows[str(days)] = {
            "stars_added": sum(t >= start for t in stars),
            "complete": (stop == "exhausted" or reaches_back_to <= start) and not undated,
        }
    for t in stars:
        per_day[t.date().isoformat()] = per_day.get(t.date().isoformat(), 0) + 1
    return {"star_windows": windows, "stars_per_day": per_day,
            "feed_reaches_back_to": reaches_back_to.isoformat(),
            "feed_exhausted": stop == "exhausted", "feed_stopped_because": stop,
            "events_read": len(data),
            "undated_events": undated}


def github_reach(now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    data, reason, status = _get_json(f"https://api.github.com/repos/{GITHUB_REPO}")
    stars = data.get("stargazers_count") if isinstance(data, dict) else None
    forks = data.get("forks_count") if isinstance(data, dict) else None
    if not _is_count(stars):
        # Unauthenticated GitHub allows 60 requests/hour and answers 403 past it. That
        # window is an hour, so the 2s retry cannot clear it; the status is the answer.
        return _blank("GitHub", reason or "unexpected response shape", status, repo=GITHUB_REPO)
    return {"surface": "GitHub", "repo": GITHUB_REPO, "available": True,
            "http_status": status, "stars": stars,
            "forks": forks if _is_count(forks) else None,
            **_star_velocity(now)}


def _fmt(n: object) -> str:
    return f"{n:,}" if isinstance(n, int) else "—"


def render_table(surfaces: list[dict]) -> str:
    lines = ["", "Proximo — global reach", "=" * 48]
    for s in surfaces:
        if not s.get("available"):
            note = s.get("note", "unavailable")
            lines.append(f"{s['surface']:<14} {note}")
            continue
        if s["surface"] == "PyPI":
            lines.append(f"{'PyPI':<14} {_fmt(s['last_month'])}/mo  ·  "
                         f"{_fmt(s['last_week'])}/wk  ·  {_fmt(s['last_day'])}/day   ({s['package']})")
        elif s["surface"] == "Docker Hub":
            lines.append(f"{'Docker Hub':<14} {_fmt(s['pull_count'])} pulls (all-time)   ({s['repo']})")
        elif s["surface"] == "GitHub":
            head = f"{_fmt(s['stars'])} stars  ·  {_fmt(s['forks'])} forks"
            if s.get("velocity_note"):
                lines.append(f"{'GitHub':<14} {head}   (velocity: {s['velocity_note']})")
                continue
            # "+6/7d" is a count of stars gained, never a net figure: the events feed
            # has no unstar event. An incomplete window prints "≥" because the feed
            # did not reach back far enough to have seen the whole thing.
            spans = "  ·  ".join(
                f"{'' if w['complete'] else '≥'}+{w['stars_added']}/{d}d"
                for d, w in sorted(s["star_windows"].items(), key=lambda kv: int(kv[0]))
            )
            # "≥" alone cannot say WHY a window is a floor, and a partial read is
            # invisible without this. The table is what gets read; --json is not.
            why = []
            if s.get("undated_events"):
                why.append(f"{s['undated_events']} undated")
            if s.get("feed_stopped_because") in ("error", "page_cap"):
                why.append(f"feed {s['feed_stopped_because'].replace('_', ' ')}")
            tail = f" [{', '.join(why)}]" if why else ""
            lines.append(f"{'GitHub':<14} {head}  ·  {spans} gross{tail}   ({s['repo']})")
        elif s["surface"] == "HuggingFace":
            # Only totals the API actually delivered are printed; a missing one shows
            # its reason instead of a dash that would read as a measured zero.
            totals = "  ·  ".join(f"{_fmt(s[k])}{label}" for k, label in
                                  (("all_time", " all-time"), ("last_30d", "/30d")) if k in s)
            tail = f" [{s['caveat']}]" if s.get("caveat") else ""
            if s.get("truncated"):
                tail += " (truncated at the API page size)"
            head = f"{totals}   " if totals else ""
            lines.append(f"{'HuggingFace':<14} {head}({s['repos']} RYS repos){tail}")
    lines.append("-" * 48)
    lines.append("Counts include CI / mirrors / bots — reach, not humans.")
    lines.append("GHCR pull counts are unmeasurable at source; Docker Hub is the proxy.")
    lines.append("Stars gained are gross: the events feed has no unstar event.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Report Proximo's global download reach.")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    surfaces = [github_reach(), pypi_reach(), dockerhub_reach(), hf_reach()]

    if args.json:
        print(json.dumps({"surfaces": surfaces}, indent=2))
    else:
        print(render_table(surfaces))
    return 0


if __name__ == "__main__":
    sys.exit(main())
