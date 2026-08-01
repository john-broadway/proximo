"""Shared pytest fixtures for the Proximo suite."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _no_real_proximo_env_file(tmp_path_factory):
    """Never let ``load_env_file()`` source the OPERATOR'S real ``~/.config/proximo/proximo.env``
    during tests. It is invoked by ``server.main()`` / ``proximo-a2a`` (exercised by
    ``test_main_module`` / ``test_doctor`` / ``test_a2a_entry``); on a real deployment box that file
    exists and carries this box's ``PROXIMO_*`` settings (e.g. ``PROXIMO_ENABLE_EXEC``), which would
    leak into ``os.environ`` and pollute every later test's config warnings.

    Point ``PROXIMO_ENV_FILE`` at a guaranteed-absent path. Managed via ``os.environ`` directly (NOT
    ``monkeypatch``) so this autouse fixture doesn't pull ``monkeypatch`` into every test's fixture
    graph and reorder it relative to other autouse fixtures. Tests that need a fixture env file
    override this with their own ``monkeypatch.setenv``."""
    absent = str(tmp_path_factory.getbasetemp() / "no_such_proximo.env")
    prev = os.environ.get("PROXIMO_ENV_FILE")
    os.environ["PROXIMO_ENV_FILE"] = absent
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("PROXIMO_ENV_FILE", None)
        else:
            os.environ["PROXIMO_ENV_FILE"] = prev


@pytest.fixture(autouse=True)
def _restore_the_shared_registry():
    """The 0.30 flip made the DEFAULT `_apply_surfaces` path prune the live registry — pre-flip,
    nothing-configured was a no-op, so entry-point tests (main(), the faces) could run it on the
    shared module singleton without a trace. The suite is many productions in one process:
    without restore, the first main()-shaped test narrows every later registry-wide structural
    test (tool counts, taint classification, wrapper sweeps) to the 4-tool facade. Snapshot the
    registry and the two catalog globals, restore after every test. Production narrows once per
    process BY DESIGN; that design assumption is exactly what a shared-process suite violates."""
    import proximo.server as _server
    tools = dict(_server.mcp._tool_manager._tools)
    lean_catalog = _server.LEAN_CATALOG
    full_catalog = _server.FULL_CATALOG
    try:
        yield
    finally:
        _server.mcp._tool_manager._tools.clear()
        _server.mcp._tool_manager._tools.update(tools)
        # apply_lean/_snapshot_full_catalog REBIND these module globals (not in-place mutation),
        # so restore is assignment of the saved reference, not .update() on a stale object.
        _server.LEAN_CATALOG = lean_catalog
        _server.FULL_CATALOG = full_catalog


@pytest.fixture(autouse=True)
def _memory_db_in_tmp(tmp_path):
    """Estate memory is DEFAULT-ON since the 0.30 flip, and its default db path sits beside the
    real audit log (``~/.local/state/proximo``). A suite running with that default would write
    real files on the dev box — which dogfoods Proximo, so it would write into the LIVE map.
    Point every test's memory at its own tmp file. Managed via ``os.environ`` directly for the
    same fixture-ordering reason as above; tests asserting path RESOLUTION or opt-in/out
    semantics override or delete this with their own ``monkeypatch``."""
    prev = os.environ.get("PROXIMO_MEMORY_PATH")
    os.environ["PROXIMO_MEMORY_PATH"] = str(tmp_path / "proximo-test-memory.db")
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("PROXIMO_MEMORY_PATH", None)
        else:
            os.environ["PROXIMO_MEMORY_PATH"] = prev
