"""Shared pytest fixtures for the Proximo suite."""

from __future__ import annotations

import functools
import importlib
import os

import pytest


@pytest.fixture(autouse=True)
def _no_real_proximo_env_file(tmp_path_factory):
    """Never let ``load_env_file()`` source the OPERATOR'S real ``~/.config/proximo/proximo.env``
    during tests. Every door's ``main`` sources it (exercised by ``test_core_envfile`` /
    ``test_entrypoint_help``); on a real deployment box that file
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
def _audit_log_in_tmp(tmp_path):
    """The PROVE ledger's default path is the REAL one (``~/.local/state/proximo/audit.log``), and
    every core door stamps its arrival there on start. Point every test's ledger at its own tmp
    file. Managed via ``os.environ`` directly (NOT ``monkeypatch``) for the same fixture-ordering
    reason as above; a test asserting path RESOLUTION overrides it with its own ``monkeypatch``."""
    prev = os.environ.get("PROXIMO_AUDIT_LOG")
    os.environ["PROXIMO_AUDIT_LOG"] = str(tmp_path / "proximo-test-audit.log")
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("PROXIMO_AUDIT_LOG", None)
        else:
            os.environ["PROXIMO_AUDIT_LOG"] = prev


@pytest.fixture(autouse=True)
def _clear_secret_registry():
    """The output scrubber's registry is process-wide (a fixture token read in one test would
    redact the same literal in a later test's error assertion, with no visible link between the
    two files). Start every test clean.

    Import lazily and tolerate absence: CI's requirements-drift job runs this tree's tests with
    `uv run --no-project` (no proximo installed) and a conftest that imports the package at
    collection time errors every test in that job before it starts (public PR #73 on the 0.43.0
    curated sha, 2026-09-20)."""
    try:
        from proximo.core import secretfile as _secretfile
    except ImportError:  # a no-project job (requirements-drift) has no registry to clear
        yield
        return
    _secretfile.clear_registered_secrets()
    yield
    _secretfile.clear_registered_secrets()


@pytest.fixture(autouse=True)
def _grants_are_written_by_another_user():
    """Every grant a test writes is owned by the suite's own uid, which is exactly the owner the
    CONSENT gate refuses (a grant owned by the agent's own user is the agent granting itself). So
    the suite plays the operator: `spine._euid` answers a uid no test file carries. A test of the
    owner check itself patches it back to `os.geteuid`. Same lazy import as above."""
    try:
        from proximo.core import spine as _spine
    except ImportError:
        yield
        return
    real = _spine._euid
    _spine._euid = lambda: os.geteuid() + 1
    try:
        yield
    finally:
        _spine._euid = real


@pytest.fixture
def armed_plane(monkeypatch, tmp_path):
    """An armed pve box with a token file, every pillar unset, receipts to the tmp ledger the
    autouse fixture points at; the test wires its own answers with `engine._client`. Shared by
    the core's seam tests (task wait, plan live state), which cannot import `tests.test_spine`
    because CI's bare pytest has no `tests.` package. Imports lazily for the no-project job."""
    from proximo.core import engine, wire
    tok = tmp_path / "token"
    tok.write_text("secret-token")
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))
    for var in ("PROXIMO_CONTAIN_TRIP_PATH", "PROXIMO_SCOPE_PATH", "PROXIMO_ARM_TTL",
                "PROXIMO_FORBID", "PROXIMO_CONSENT_DIR", "PROXIMO_CONSENT_TTL_SECONDS",
                "PROXIMO_RATE_MAX", "PROXIMO_RATE_WINDOW", "PROXIMO_UNDO",
                "PROXIMO_TAINT_TRACK", "PROXIMO_TAINT_FORBID", "PROXIMO_TAINT_REQUIRE_CONSENT",
                "PROXIMO_TAINT_FENCE", "PROXIMO_ENABLE_AGENT", "PROXIMO_AGENT_ALLOWLIST",
                "PROXIMO_ENABLE_EXEC", "PROXIMO_CT_ALLOWLIST", "PROXIMO_SSH_TARGET",
                "PROXIMO_ENABLE_NODE_SHELL", "PROXIMO_ENABLE_DOWNLOAD"):
        monkeypatch.delenv(var, raising=False)
    return wire.Plane("pve", "https://pve.invalid:8006/api2/json", str(tok))


# --- the perimeter has ONE caller, the core door ---------------------------------------------------

#: face name (a test module's `FACE`) -> the core door that mounts that perimeter. Each door's
#: `build_app(url, *, token, allowed_hosts, ...)` supplies its own dispatch, instance and recorder.
_DOORS = {
    "http": "proximo.core.doors.http",
    "mcp-http": "proximo.core.doors.mcphttp",
    "a2a": "proximo.core.doors.a2a",
}


@pytest.fixture
def build_app(request):
    """The core door's `build_app` for the face the module names in `FACE`. Until the cut
    (2026-10-18) this fixture ran every perimeter test twice, once with the 0.44 server behind the
    perimeter and once with the core door; the 0.44 caller went with the 0.44 server."""
    return importlib.import_module(_DOORS[request.module.FACE]).build_app


#: Every cache built from the one JSON, cleared together so a planted record reaches every reader.
_DATA_CACHES = (
    ("proximo.core.apitree", ("published", "raw_tree", "tree", "_rows")),
    ("proximo.core.engine", ("table", "untrusted_addresses")),
    ("proximo.core.search", ("descriptions", "_index", "synonyms", "_stopwords", "_known_words", "_lexical_index")),
    ("proximo.core.diagnose", ("subjects",)),
)


def _clear_data_caches():
    for mod, names in _DATA_CACHES:
        m = importlib.import_module(mod)
        for n in names:
            getattr(m, n).cache_clear()


@pytest.fixture
def records(monkeypatch):
    """Plant record text and serve what it builds, through the real build.

    `records(**{"tiers.toml": text})` builds the one JSON from the committed vendor rows and the
    committed records with the named ones replaced (`None` = absent), installs it as what the
    package's `proximo.json.gz` holds, and returns the engine's table. A record the build refuses
    raises exactly as `scripts/build_proximo_json.py` would. The real file comes back after.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import build_proximo_json as bj

    from proximo.core import apitree, engine

    def install(**texts):
        vendor, real, _ = bj.read_inputs()
        doc = bj.build(vendor, {**real, **texts})
        _clear_data_caches()
        monkeypatch.setattr(apitree, "published", functools.cache(lambda: doc))
        return engine.table()

    yield install
    monkeypatch.undo()
    _clear_data_caches()
