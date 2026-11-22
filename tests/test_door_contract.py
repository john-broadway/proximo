"""The door contract: the interface a client builds against is the door that ships.

`docs/door-contract.json` is the six tools as `tools/list` hands them over and the shapes their
answers take. A client built against contract N must meet contract N, so a door that drifts is red
here until the change is made on purpose (`scripts/gen_door_contract.py --bump`), and a contract
the CHANGELOG does not announce is red too: the CHANGELOG is where a client learns the door moved.
"""
import json
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the [mcp] extra is not installed")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import gen_door_contract as g  # noqa: E402


@pytest.fixture(scope="module")
def served():
    return g.build()


def test_the_door_is_the_committed_contract(served):
    held = g.committed()
    assert held is not None, "docs/door-contract.json is missing: run scripts/gen_door_contract.py"
    drift = [k for k in served if held.get(k) != served[k]]
    assert not drift, (f"the door no longer matches door contract {held['contract']} in {drift}; if the "
                       "change is on purpose: scripts/gen_door_contract.py --bump, and a CHANGELOG line")


def test_the_changelog_announces_the_contract():
    n = g.committed()["contract"]
    assert re.search(rf"\bdoor contract {n}\b", (REPO_ROOT / "CHANGELOG.md").read_text()), \
        f"CHANGELOG.md never says 'door contract {n}': a client would not know the door moved"


def test_a_drifted_door_is_seen(served, tmp_path, monkeypatch):
    """THE CONTROL: one word of one description changed, and the generator refuses to call it the
    same contract; with --bump it writes contract + 1."""
    held = g.committed()
    moved = json.loads(json.dumps(served))
    moved["tools"][0]["description"] += " (moved)"
    out = tmp_path / "door-contract.json"
    out.write_text(g.render(held["contract"], served))
    monkeypatch.setattr(g, "OUT", out)
    monkeypatch.setattr(g, "build", lambda: moved)
    assert g.main([]) == 1
    assert g.main(["--bump"]) == 0 and json.loads(out.read_text())["contract"] == held["contract"] + 1


def test_the_contract_holds_what_a_client_acts_on(served):
    assert [t["name"] for t in served["tools"]] == ["proximo_find", "proximo_plan", "proximo_read",
                                                    "proximo_call", "audit_entries", "audit_verify"]
    assert {"arm", "tier", "arguments", "consent"} <= set(served["needs"])
    plan = next(a["answer"] for a in served["answers"] if a["tool"] == "proximo_plan")
    assert plan["needs"] == "arm" and plan["allowed"] is False and "why" in plan["keys"]
    assert "why" not in plan, "an authored value is content, not contract"


def test_a_call_that_runs_is_in_the_contract(served):
    """Lens 1 MAJOR 1: the answer a client gets when a call RUNS (its undo capture, its task) was
    never sampled, so renaming `undo` or `task` stayed green. The armed estate samples it."""
    ran = [a["answer"] for a in served["answers"] if "ARMED" in a["env"] and "keys" in a["answer"]]
    assert ran and all({"undo", "task", "intent"} <= set(r["keys"]) for r in ran)
    assert any(r["undo."]["keys"] != ["captured", "why"] for r in ran), "no sample captured a before-state"


def test_every_refusal_lane_sampled_says_its_own_words(served):
    """Lens 1 MAJOR 2: only two refusals' words were frozen. Each lane below refuses in the
    contract with its words; an authored sentence inside them is `<why>`, never the sentence."""
    said = " ".join(a["answer"]["refused"] for a in served["answers"] if "refused" in a["answer"])
    for words in ("not armed", "over the budget", "forbidden on this surface", "consent required",
                  "contained: mutation refused", "does not publish no-such-argument", "is held: <why>",
                  "the container shell lane is off", "pmg is not configured", "pve publishes no GET"):
        assert words in said, words
    assert "[Claude," not in said and "<scratch>" in said


def test_a_build_leaves_no_scratch_folder_behind(monkeypatch, tmp_path):
    # The builder once leaked one `door-contract-*` folder per run into /tmp (a memory-backed
    # tmpfs on the dev box: 1,028 had piled up). Point tempfile at an empty folder and count.
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    g.build()
    assert list(tmp_path.iterdir()) == []
