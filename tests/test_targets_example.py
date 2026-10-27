"""The shipped example registry documents only keys the core reads (issue #98).

`packaging/targets.example.toml` is the config shape README and SETUP point a stranger at.
It carried `ssh_target` and `node` on its targets: keys the loader the 0.45.0 cut removed had
read, and the core never has. 0.45.0 through 0.46.1 shipped it that way; an operator who set them
got nothing, silently, and #98 read the example as a promise the shell lane does not keep.
Drive the real loader: a key the core reads changes the Plane it builds, or refuses the change;
a key whose value can change without the Plane noticing is dead, and the example must not teach
it. (Removal is the wrong probe: the example sets `verify_tls = true`, the default, and removing
it changes nothing either.)
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from proximo.core import registry
from proximo.core.errors import ProximoError

EXAMPLE = Path(__file__).resolve().parents[1] / "packaging" / "targets.example.toml"


def _toml(targets: dict[str, dict]) -> str:
    def value(v: object) -> str:
        if isinstance(v, dict):
            return "{ " + ", ".join(f"{json.dumps(k)} = {value(x)}" for k, x in v.items()) + " }"
        return json.dumps(v)

    return "".join(f"[targets.{n}]\n" + "".join(f"{k} = {value(v)}\n" for k, v in t.items()) + "\n"
                   for n, t in targets.items())


def _other(v: object) -> object:
    if isinstance(v, bool):
        return not v
    if isinstance(v, int):
        return v + 1
    if isinstance(v, dict):
        return {k: _other(x) for k, x in v.items()}
    return f"{v}x"


def dead_keys(targets: dict[str, dict], monkeypatch, tmp_path) -> list[tuple[str, str]]:
    """Every (target, key) whose value can change with the core's Plane staying the same."""
    reg = tmp_path / "targets.toml"
    dead: list[tuple[str, str]] = []
    for name, fields in targets.items():
        reg.write_text(_toml(targets))
        monkeypatch.setenv(registry.ENV, str(reg))
        registry._parse_registry.cache_clear()
        whole = registry.plane(fields["kind"], name)
        for key, value in fields.items():
            altered = {n: ({**t, key: _other(value)} if n == name else t) for n, t in targets.items()}
            reg.write_text(_toml(altered))
            registry._parse_registry.cache_clear()
            try:
                if registry.plane(fields["kind"], name) == whole:
                    dead.append((name, key))
            except ProximoError:
                continue   # read, and held to a rule
    return dead


@pytest.fixture
def example() -> dict[str, dict]:
    with EXAMPLE.open("rb") as f:
        return tomllib.load(f)["targets"]


def test_the_example_documents_no_key_the_core_ignores(example, monkeypatch, tmp_path):
    assert dead_keys(example, monkeypatch, tmp_path) == []


def test_the_check_sees_a_dead_key_when_one_is_planted(example, monkeypatch, tmp_path):
    """The control: the two keys the cut orphaned, planted back, are named by target and key."""
    planted = {n: dict(t) for n, t in example.items()}
    planted["home-pve"]["ssh_target"] = "pve"
    planted["edge-pve"]["node"] = "edge"
    assert dead_keys(planted, monkeypatch, tmp_path) == [("home-pve", "ssh_target"), ("edge-pve", "node")]


@pytest.mark.parametrize("target,node,destination", [
    ("home-pve", "pve-01", "home-pve01"), ("home-pve", "pve-02", "home-pve02"),
    ("edge-pve", "edge-01", "root@edge-01.example.com"),
])
def test_each_example_node_destination_is_loaded(target, node, destination, example, monkeypatch, tmp_path):
    reg = tmp_path / "targets.toml"
    reg.write_text(_toml(example))
    monkeypatch.setenv(registry.ENV, str(reg))
    registry._parse_registry.cache_clear()
    before = registry.plane("pve", target)
    assert dict(before.nodes)[node] == destination
    changed = {name: dict(fields) for name, fields in example.items()}
    changed[target]["nodes"] = {**changed[target]["nodes"], node: destination + "-changed"}
    reg.write_text(_toml(changed))
    registry._parse_registry.cache_clear()
    after = registry.plane("pve", target)
    assert dict(after.nodes)[node] == destination + "-changed"
