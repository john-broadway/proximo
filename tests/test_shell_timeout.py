"""The shell lanes' wait is the operator's to set (issue #106): `PROXIMO_SHELL_TIMEOUT`, whole seconds from 1 to
600, unset is the 60 it always was. A value that is set and is not that refuses the shell call before anything
dials, naming the variable: a wait the operator did not mean is never guessed. No argument a model sends moves it."""

from __future__ import annotations

import subprocess

import pytest

from proximo.core import doctor, receipt, shell
from proximo.core.errors import ProximoError


@pytest.fixture
def recorded(monkeypatch):
    seen: list[int] = []

    def _run(argv, timeout):
        seen.append(timeout)
        raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr(shell, "_run", _run)
    monkeypatch.setenv(shell.TARGET_ENV, "pve1")
    return seen


def _dial():
    client = shell.client()
    with pytest.raises(ProximoError) as ei:
        client.call("POST", "/nodes/pve1/lxc/105/exec", {"command": ["uptime"]})
    return client, str(ei.value)


def test_unset_is_the_sixty_seconds_it_always_was(recorded, monkeypatch):
    monkeypatch.delenv(shell.TIMEOUT_ENV, raising=False)
    client, said = _dial()
    assert client.timeout == 60 and recorded == [60] and "within 60s" in said


@pytest.mark.parametrize("value,seconds", [("180", 180), (" 600 ", 600), ("1", 1)])
def test_a_set_value_is_the_wait_the_ssh_child_gets(recorded, monkeypatch, value, seconds):
    monkeypatch.setenv(shell.TIMEOUT_ENV, value)
    client, said = _dial()
    assert client.timeout == seconds and recorded == [seconds] and f"within {seconds}s" in said


@pytest.mark.parametrize("value", ["0", "601", "90000", "-5", "60.5", "1e3", "sixty", "60s", "١٢٠"])
def test_anything_else_refuses_before_anything_dials(recorded, monkeypatch, value):
    monkeypatch.setenv(shell.TIMEOUT_ENV, value)
    with pytest.raises(ProximoError) as ei:
        shell.client()
    said = str(ei.value)
    assert shell.TIMEOUT_ENV in said and "1 to 600" in said and recorded == []
    assert value.strip() not in said or value.strip() in ("0", "600")   # the bound is named, the junk is not echoed


def test_an_empty_value_is_unset(recorded, monkeypatch):
    monkeypatch.setenv(shell.TIMEOUT_ENV, "  ")
    assert shell.client().timeout == 60


def test_doctor_reports_the_effective_wait_and_a_garbled_one(monkeypatch):
    monkeypatch.setenv(shell.TIMEOUT_ENV, "240")
    rep = doctor.run()
    assert rep["pillars"]["DIAGNOSE"]["shell_timeout"] == 240
    assert receipt.allowed(rep)["pillars"]["DIAGNOSE"]["shell_timeout"] == 240
    monkeypatch.setenv(shell.TIMEOUT_ENV, "lots")
    rep = doctor.run()
    assert rep["pillars"]["DIAGNOSE"]["shell_timeout"] is None
    flags = [f for f in rep["flags"] if receipt.flag_code(f) == "shell-timeout-garbled"]
    assert len(flags) == 1 and "lots" not in flags[0]
