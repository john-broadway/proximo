"""The Scorecard job holds only `uses` steps, and the publish is still checked.

OpenSSF's API verifies the workflow before it takes a result: the job that runs
`ossf/scorecard-action` with `publish_results: true` may hold no `run:` step. A check that the
score was published (added 2026-11-06 as a `run:` step in that same job) reached GitHub with
0.53.0 and was itself the reason the publish was refused: "workflow verification failed:
scorecard job must only have steps with `uses`", a 400 the action logs and survives, so the run
went red on our own check, on every push and every Monday. The check stays; it lives in a job of
its own that waits for the analysis.
"""
from __future__ import annotations

import re
from pathlib import Path

_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scorecard.yml"


def _jobs() -> dict[str, str]:
    """Each job's own lines, by name: the two-space-indented keys under `jobs:`, comments dropped."""
    body = _WORKFLOW.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    lines = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    jobs: dict[str, list[str]] = {}
    name = None
    for ln in lines:
        head = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", ln)
        if head:
            name = head.group(1)
            jobs[name] = []
        elif name is not None:
            jobs[name].append(ln)
    return {k: "\n".join(v) for k, v in jobs.items()}


def _publishing(jobs: dict[str, str]) -> str:
    (name,) = [k for k, v in jobs.items() if "ossf/scorecard-action@" in v]
    return name


def test_the_job_that_publishes_the_score_holds_no_run_step():
    jobs = _jobs()
    job = jobs[_publishing(jobs)]
    assert "publish_results: true" in job
    refused = "a `run:` step in the Scorecard job makes OpenSSF refuse the publish"
    assert not re.search(r"^\s+(- )?run:", job, re.M), refused


def test_the_publish_is_still_checked_in_a_job_that_waits_for_the_analysis():
    jobs = _jobs()
    publishing = _publishing(jobs)
    checkers = [k for k, v in jobs.items() if k != publishing and "api.scorecard.dev/projects/" in v]
    assert len(checkers) == 1, f"expected one job that asks the public API for this commit, found {checkers}"
    check = jobs[checkers[0]]
    assert re.search(rf"^\s+needs:\s*\[?\s*{re.escape(publishing)}\s*\]?\s*$", check, re.M)
    assert "exit 1" in check                       # a result for another commit, or none, is a red run
