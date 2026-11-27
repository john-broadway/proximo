"""The operator's words on every door, and the wire with none of them set.

With neither variable set, what each door sends is what it sent before the words existed (the
build's first acceptance line). The goldens under `tests/data/words_unset_*.json` were captured at
`e6c6265` by running this file's own `mcp_surface`, `openapi_surface` and `card_surface` against
that tree, so the comparison is made by the code that made the capture. Proximo's own version is
replaced by a fixed word in each (it moves at every release and is not what this checks).

The MCP golden is the mcp 2.x wire (the file's name says so). On mcp 1.x the same test holds the
three facts the golden exists for and says which it checked: no instructions, the five prompts,
the six tools.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

pytest.importorskip("mcp", reason="the [mcp] extra is not installed")
pytest.importorskip("starlette", reason="the [mcp-http] extra is not installed")

from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

from proximo import __version__  # noqa: E402
from proximo.core import principal  # noqa: E402
from proximo.core.mcpcompat import MCP_MAJOR  # noqa: E402

BASE = "http://localhost"
TOKEN = "t0k"  # noqa: S105 -- a test bearer
BEARER = {"Authorization": f"Bearer {TOKEN}"}
DATA = Path(__file__).parent / "data"
FIVE = ["diagnose_cluster", "provision_container", "review_receipts", "safe_backup", "safe_migration"]
SIX = ["audit_entries", "audit_verify", "proximo_call", "proximo_find", "proximo_plan", "proximo_read"]
VERSION = "<proximo's version>"


def _unversioned(value: Any) -> Any:
    """`value` with Proximo's own version, wherever it stands as a whole string, made a fixed word."""
    if isinstance(value, dict):
        return {k: _unversioned(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unversioned(v) for v in value]
    return VERSION if value == __version__ else value


def _dump(model: Any) -> Any:
    return json.loads(model.model_dump_json(by_alias=True, exclude_none=True))


async def mcp_session(app: Any, headers: dict[str, str] | None = BEARER) -> dict[str, Any]:
    """`initialize`, `prompts/list` and `tools/list` as the official client reads them off the wire."""
    hx = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE, headers=headers, timeout=30)
    async with app.router.lifespan_context(app):
        async with streamable_http_client(f"{BASE}/mcp", http_client=hx) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                init = await session.initialize()
                prompts = (await session.list_prompts()).prompts
                tools = (await session.list_tools()).tools
    return {"initialize": _dump(init),
            "prompts": sorted((_dump(p) for p in prompts), key=lambda p: p["name"]),
            "tools": sorted((_dump(t) for t in tools), key=lambda t: t["name"])}


async def mcp_surface() -> Any:
    from proximo.core.doors import mcphttp
    return _unversioned(await mcp_session(mcphttp.build_app(token=TOKEN)))


def openapi_surface() -> Any:
    from starlette.testclient import TestClient

    from proximo.core.doors import http
    return _unversioned(TestClient(http.build_app(token=TOKEN), base_url=BASE).get("/openapi.json").json())


def card_surface() -> Any:
    from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
    from starlette.testclient import TestClient

    from proximo.core.doors import a2a
    app = a2a.build_app(token=TOKEN)
    return _unversioned(TestClient(app, base_url=BASE).get(AGENT_CARD_WELL_KNOWN_PATH).json())


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "state" / "audit.log"))
    yield tmp_path
    principal.set_serving_face("stdio")


def _golden(name: str) -> Any:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


# --- A1: nothing set, nothing moved ------------------------------------------------------------

async def test_with_no_words_set_the_mcp_wire_is_the_one_before_the_words(env):
    got = await mcp_surface()
    if MCP_MAJOR != 2:
        # The golden is the 2.x wire. On 1.x: the three facts it exists for, checked by name.
        assert "instructions" not in got["initialize"]
        assert [p["name"] for p in got["prompts"]] == FIVE
        assert [t["name"] for t in got["tools"]] == SIX
        return
    assert got == _golden("words_unset_mcp2.json")


def test_with_no_words_set_the_open_document_is_the_one_before_the_words(env):
    assert openapi_surface() == _golden("words_unset_openapi.json")


def test_with_no_words_set_the_agent_card_is_the_one_before_the_words(env):
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    assert card_surface() == _golden("words_unset_agent_card.json")


# --- the instructions, door by door (A2) ---------------------------------------------------------

RULES = "Every call names a target.\n"


@pytest.fixture
def rules(env, monkeypatch):
    folder = env / "words"
    folder.mkdir()
    (folder / "rules.md").write_text(RULES)
    monkeypatch.setenv("PROXIMO_INSTRUCTIONS", str(folder / "rules.md"))
    return folder / "rules.md"


async def test_mcp_http_with_a_bearer_carries_the_instructions(rules):
    from proximo.core.doors import mcphttp
    got = await mcp_session(mcphttp.build_app(token=TOKEN))
    assert got["initialize"]["instructions"] == RULES


async def test_mcp_http_with_no_bearer_carries_none_and_says_why_once(rules, capsys):
    from proximo.core.doors import mcphttp
    app = mcphttp.build_app(token=None)
    err = capsys.readouterr().err
    assert err.count("this door has no bearer token, so the operator's words are not served on it") == 1
    assert str(rules) not in err
    got = await mcp_session(app, headers=None)
    assert "instructions" not in got["initialize"]
    assert [p["name"] for p in got["prompts"]] == FIVE     # the door itself is whole


def test_a_bare_build_server_reads_no_environment(rules):
    """The words come down from the door's one read; a caller that hands none gets none, whatever is set."""
    from proximo.core import words
    from proximo.core.doors import mcp as door
    assert door.build_server().instructions is None
    assert door.build_server(words=words.Words(RULES, (), ())).instructions == RULES


def test_the_dispatch_hands_the_doors_words_to_the_one_server(rules):
    from proximo.core import words
    from proximo.core.doors.dispatch import Core
    assert Core().instance.instructions is None
    assert Core(words.Words(RULES, (), ())).instance.instructions == RULES


@pytest.mark.parametrize("token", [TOKEN, None])
def test_rest_and_a2a_read_at_build_and_their_open_documents_do_not_move(rules, capsys, token):
    """The read happens when the app is built (a refusal is said then, once, not on a first
    request), and the open documents do not move whatever is set."""
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    from starlette.testclient import TestClient

    from proximo.core.doors import a2a, http
    rules.write_bytes(b"\xff\xfe")
    for face in (http, a2a):
        app = face.build_app(token=token)
        err = capsys.readouterr().err
        expected = "PROXIMO_INSTRUCTIONS is not UTF-8 text" if token else "this door has no bearer token"
        assert err.count(expected) == 1 and err.count("\n") == 1
        TestClient(app, base_url=BASE).get("/healthz")
        assert capsys.readouterr().err == ""               # nothing more is said on a request
    rules.write_text(RULES)
    assert openapi_surface() == _golden("words_unset_openapi.json")
    assert card_surface() == _golden("words_unset_agent_card.json")
    assert RULES.strip() not in json.dumps([openapi_surface(), card_surface()])


# --- the runbooks, on the MCP wire -------------------------------------------------------------

BOOK = "# Drain a node\n\nplane: pve\n\n1. proximo_read pve GET /nodes/{node}/status.\n"


@pytest.fixture
def books(env, monkeypatch):
    folder = env / "runbooks"
    folder.mkdir()
    (folder / "drain_node.md").write_text(BOOK)
    (folder / "bad.md").write_text("# Bad\n\nplane: pve\n\nGET /nodes/{node}/nope\n")
    monkeypatch.setenv("PROXIMO_RUNBOOKS_DIR", str(folder))
    return folder


async def test_mcp_http_with_a_bearer_lists_the_sound_runbook_beside_the_five(books):
    from proximo.core.doors import mcphttp
    got = await mcp_session(mcphttp.build_app(token=TOKEN))
    assert [p["name"] for p in got["prompts"]] == sorted([*FIVE, "drain_node"])
    [mine] = [p for p in got["prompts"] if p["name"] == "drain_node"]
    assert mine["description"] == "Operator runbook (not Proximo's)." and not mine.get("arguments")
    assert [t["name"] for t in got["tools"]] == SIX
    if MCP_MAJOR == 2:
        golden = _golden("words_unset_mcp2.json")
        assert [p for p in got["prompts"] if p["name"] != "drain_node"] == golden["prompts"]   # the five: unmoved
        assert got["tools"] == golden["tools"]


async def test_mcp_http_with_no_bearer_lists_only_the_five(books, capsys):
    from proximo.core.doors import mcphttp
    app = mcphttp.build_app(token=None)
    assert capsys.readouterr().err.count("no bearer token") == 1
    got = await mcp_session(app, headers=None)
    assert [p["name"] for p in got["prompts"]] == FIVE


# --- the shell verbs, on both commands (A9) ------------------------------------------------------

def _shell(argv, capsys):
    from proximo.core.doors import cli
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def _listing(folder):
    return sorted((str(p.relative_to(folder)), p.stat().st_size) for p in folder.rglob("*"))


def test_the_shell_prints_exactly_what_mcp_serves_and_writes_nothing(rules, books, env, capsys):
    from proximo.core import words
    from proximo.core.doors import mcp as door
    served = words.at_start(bearer=True)
    capsys.readouterr()
    before = _listing(env)
    assert _shell(["instructions"], capsys) == (0, served.instructions, "")
    rc, out, err = _shell(["runbook", "list"], capsys)
    assert (rc, out) == (2, "drain_node\tpve\tDrain a node\n")   # the sound one still prints; `bad` is set and refused
    assert err == ("proximo-core: an operator runbook is not served: bad: it names an address pve does not "
                   "publish: GET /nodes/{node}/nope\n")
    assert _shell(["runbook", "show", "drain_node"], capsys) == (0, served.runbooks[0].text, "")
    assert served.runbooks[0].text.startswith("Operator runbook (not Proximo's): drain_node.\n\n")
    assert _listing(env) == before                         # no ledger row, no file, nothing grown
    assert door.main(["runbook", "show", "drain_node"]) == 0             # the same verb on `proximo`
    assert capsys.readouterr().out == served.runbooks[0].text
    assert door.main(["instructions"]) == 0 and capsys.readouterr().out == served.instructions


def test_the_shell_verbs_exit_3_for_the_callers_own_mistake(env, capsys):
    for argv in (["instructions"], ["runbook", "list"], ["runbook", "show", "drain_node"]):
        rc, out, err = _shell(argv, capsys)
        assert (rc, out) == (3, "") and "is not set" in err
    for argv in (["instructions", "extra"], ["runbook"], ["runbook", "show"], ["runbook", "run", "x"],
                 ["runbook", "list", "extra"], ["runbook", "show", "a", "b"]):
        rc, out, err = _shell(argv, capsys)
        assert (rc, out) == (3, "") and err.startswith("usage: proximo-core instructions | runbook list")


def test_the_shell_verbs_exit_3_for_an_unknown_name_and_never_echo_it(books, capsys):
    rc, out, err = _shell(["runbook", "show", "../../etc/shadow"], capsys)
    assert (rc, out) == (3, "") and "no operator runbook has that name" in err and "shadow" not in err


def test_the_shell_verbs_exit_2_for_words_set_and_refused(rules, books, capsys):
    rules.write_bytes(b"\xff\xfe")
    rc, out, err = _shell(["instructions"], capsys)
    assert (rc, out) == (2, "") and "PROXIMO_INSTRUCTIONS is not UTF-8 text" in err and str(rules) not in err
    rc, out, err = _shell(["runbook", "show", "bad"], capsys)
    assert (rc, out) == (2, "") and "an operator runbook is not served: bad: " in err
    for path in books.iterdir():
        path.unlink()
    books.rmdir()
    for argv in (["runbook", "list"], ["runbook", "show", "drain_node"]):
        rc, out, err = _shell(argv, capsys)
        assert (rc, out) == (2, "") and "PROXIMO_RUNBOOKS_DIR does not name a folder" in err and str(books) not in err


def test_the_shell_verbs_run_past_a_retired_switch_like_doctor(rules, monkeypatch, capsys):
    monkeypatch.setenv("PROXIMO_SURFACES", "pve")
    assert _shell(["instructions"], capsys)[:2] == (0, RULES)


def test_the_usage_of_the_proximo_command_names_the_verbs(capsys):
    """`proximo-core --help` is argparse's and lists no verb (not `learn`, not `doctor`): its verbs
    are named by its module's account and by the usage line a bad argument earns, tested above."""
    from proximo.core.doors import cli
    from proximo.core.doors import mcp as door
    assert door.main(["--help"]) == 0
    assert "mint|doctor|badge|arm|disarm|instructions|runbook" in capsys.readouterr().out
    assert "proximo-core runbook show drain_node" in (cli.__doc__ or "")


# --- REST: behind the bearer or not at all (A12) -------------------------------------------------

def _rest(token):
    from starlette.testclient import TestClient

    from proximo.core.doors import http
    return TestClient(http.build_app(token=token), base_url=BASE)


ROUTES = ("/instructions", "/runbooks", "/runbooks/drain_node")


def test_rest_with_the_bearer_serves_the_words(rules, books):
    from proximo.core import words
    served = words.at_start(bearer=True)
    client = _rest(TOKEN)
    got = client.get("/instructions", headers=BEARER)
    assert (got.status_code, got.text) == (200, RULES)
    assert got.headers["content-type"] == "text/plain; charset=utf-8"
    listed = client.get("/runbooks", headers=BEARER)
    assert listed.status_code == 200
    assert listed.json() == [{"name": "drain_node", "title": "Drain a node", "plane": "pve"}]
    one = client.get("/runbooks/drain_node", headers=BEARER)
    assert (one.status_code, one.text) == (200, served.runbooks[0].text)
    assert one.headers["content-type"] == "text/plain; charset=utf-8"
    for unknown in ("/runbooks/bad", "/runbooks/nope", "/runbooks/drain_node/more", "/instructions/x"):
        missing = client.get(unknown, headers=BEARER)
        assert missing.status_code == 404 and "nope" not in missing.text and "bad" not in missing.text


@pytest.mark.parametrize("headers", [None, {"Authorization": "Bearer wrong"}])
def test_rest_without_the_bearer_is_401_and_says_nothing(rules, books, headers):
    client = _rest(TOKEN)
    for route in (*ROUTES, "/runbooks/nope"):
        got = client.get(route, headers=headers)
        assert got.status_code == 401 and RULES.strip() not in got.text and "Drain" not in got.text


def test_rest_with_no_token_configured_has_no_such_routes(rules, books):
    client = _rest(None)
    for route in ROUTES:
        got = client.get(route)
        assert got.status_code == 404 and RULES.strip() not in got.text and "Drain" not in got.text


def test_rest_with_a_token_and_no_words_is_the_old_wire_to_whoever_holds_the_bearer(env):
    """With the bearer and nothing to serve, each of the three paths answers what any unknown path
    answers, byte for byte (the app's own 404, as before the words). Without the bearer they are
    401, words or none, so the door does not say which: the one stated change on this wire."""
    client = _rest(TOKEN)
    unknown = client.get("/no-such-path", headers=BEARER)
    assert unknown.status_code == 404
    for route in ROUTES:
        for method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
            got = client.request(method, route, headers=BEARER)
            old = client.request(method, "/no-such-path", headers=BEARER)
            assert (got.status_code, got.content, got.headers.get("content-type")) == (
                old.status_code, old.content, old.headers.get("content-type")), (method, route)
        assert unknown.status_code == 404 and client.get(route).status_code == 401


@pytest.mark.parametrize("token", [TOKEN, None])
def test_the_open_document_is_the_same_bytes_whatever_is_set(rules, books, token):
    from starlette.testclient import TestClient

    from proximo.core.doors import http
    with_words = TestClient(http.build_app(token=token), base_url=BASE).get("/openapi.json").content
    for name in ("PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        os.environ.pop(name)
    assert TestClient(http.build_app(token=token), base_url=BASE).get("/openapi.json").content == with_words
    assert b"runbook" not in with_words and b"/instructions" not in with_words


def test_a_page_in_a_browser_cannot_read_the_words(rules, books):
    """The cross-origin guard is for POSTs (a forged mutation). A GET of the words is kept from a
    web page by the two things checked here: it cannot be asked for without the bearer, which a
    cross-site page cannot attach without a preflight, and no answer carries a CORS grant."""
    client = _rest(TOKEN)
    cross = {"sec-fetch-site": "cross-site", "origin": "https://evil.example"}
    for route in ROUTES:
        assert client.get(route, headers=cross).status_code == 401
        assert client.options(route, headers={**cross, "access-control-request-headers": "authorization"}
                              ).headers.get("access-control-allow-origin") is None
        assert client.get(route, headers={**BEARER, **cross}).headers.get("access-control-allow-origin") is None


def test_the_perimeter_itself_serves_no_words_without_a_token_whoever_hands_them_in(env):
    """The door reads nothing for a door with no token; this is the second line. An embedder that
    hands the perimeter words and no token gets no words routes: with no bearer check in front of
    them they would be open to anyone who reaches the port."""
    from starlette.testclient import TestClient

    from proximo.core import runbooks, words
    from proximo.core.doors.dispatch import Core
    from proximo.core.doors.network import recorder
    from proximo.core.perimeter import rest
    book = runbooks.check("drain_node", BOOK)
    handed = words.Words(RULES, (book,), ())
    open_app = rest.build_app(token=None, dispatch=Core(), record=recorder("test"), words=handed)
    client = TestClient(open_app, base_url=BASE)
    for route in ROUTES:
        got = client.get(route)
        assert got.status_code == 404 and RULES.strip() not in got.text and "Drain" not in got.text
    held_app = rest.build_app(token=TOKEN, dispatch=Core(), record=recorder("test"), words=handed)
    held = TestClient(held_app, base_url=BASE)
    assert held.get("/instructions", headers=BEARER).text == RULES       # the control: with a token they are served


def test_rest_with_only_one_half_set_serves_that_half_and_the_other_is_the_old_404(rules, env):
    client = _rest(TOKEN)
    assert client.get("/instructions", headers=BEARER).text == RULES
    old = client.get("/no-such-path", headers=BEARER)
    for route in ("/runbooks", "/runbooks/drain_node"):
        got = client.get(route, headers=BEARER)
        assert (got.status_code, got.content) == (old.status_code, old.content)


@pytest.mark.parametrize("words_set", [True, False])
def test_without_the_bearer_nothing_under_the_words_paths_tells_set_from_unset(env, monkeypatch, words_set):
    """Lens 2: a trailing slash reached the router before the bearer, and the router's redirect
    said whether instructions were set. Everything under the three paths meets the bearer first."""
    if words_set:
        folder = env / "w"
        folder.mkdir()
        (folder / "rules.md").write_text(RULES)
        (folder / "drain_node.md").write_text(BOOK)
        monkeypatch.setenv("PROXIMO_INSTRUCTIONS", str(folder / "rules.md"))
        monkeypatch.setenv("PROXIMO_RUNBOOKS_DIR", str(folder))
    client = _rest(TOKEN)
    for path in ("/instructions", "/instructions/", "/instructions%2F", "/instructions/x", "/runbooks", "/runbooks/",
                 "/runbooks/drain_node", "/runbooks/drain_node/", "/runbooks/nope"):
        for method in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"):
            got = client.request(method, path, follow_redirects=False)
            assert got.status_code == 401, (method, path, got.status_code)
            assert "location" not in got.headers and RULES.strip() not in got.text


# --- words only: who may know of them (A13), and the example in the docs ---------------------------

WORDS_MODULES = {"proximo.core.words", "proximo.core.instructions", "proximo.core.runbooks"}


def _knows_the_words(source: str, package: str) -> bool:
    """Does this module import the words, in any form: absolute, relative, aliased, one name from
    one of them, inside a function, over several lines, or by `importlib` with the name written?"""
    import ast
    import re
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import) and any(a.name in WORDS_MODULES for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom):
            base = package.rsplit(".", node.level - 1)[0] if node.level else ""
            module = ".".join(x for x in (base, node.module or "") if x)
            if module in WORDS_MODULES or any(f"{module}.{a.name}" in WORDS_MODULES for a in node.names):
                return True
    return bool(re.search(r"import_module\([^)]*\b(words|instructions|runbooks)\b", source))


@pytest.mark.parametrize("source", [
    "from proximo.core import words", "from proximo.core import engine, runbooks as r",
    "import proximo.core.instructions",
    "from proximo.core.runbooks import check", "from proximo.core.words import NONE as X",
    "from proximo.core import (\n    engine,\n    words,\n)", "from .words import at_start",
    "from . import instructions", "def f():\n    from proximo.core.runbooks import load\n",
    "import importlib\nimportlib.import_module('proximo.core.words')",
])
def test_the_scan_sees_every_way_a_module_can_reach_the_words(source):
    assert _knows_the_words(source, "proximo.core")


def test_the_scan_does_not_cry_at_a_module_that_only_says_the_word():
    plain = "from proximo.core import engine\nwords = 'instructions and runbooks'\n"
    assert not _knows_the_words(plain, "proximo.core")
    assert not _knows_the_words("from proximo.core.wordsfile import read\n", "proximo.core")


def test_only_the_doors_and_doctor_know_the_words_exist():
    """Goal 3: nothing in Proximo reads the words to decide anything. Held structurally: no module
    of the core but the ones that carry or report the words imports them. The engine, the spine and
    the ledger are named so a rename cannot hollow this out."""
    core = Path(__file__).parent.parent / "src" / "proximo" / "core"
    may = {"words.py", "instructions.py", "runbooks.py", "doctor.py", "prompts.py", "perimeter/rest.py"} | {
        f"doors/{p.name}" for p in (core / "doors").glob("*.py")}
    found = set()
    for path in core.rglob("*.py"):
        rel = path.relative_to(core)
        package = ".".join(("proximo", "core", *rel.parts[:-1]))
        if _knows_the_words(path.read_text(encoding="utf-8"), package):
            found.add(str(rel))
    assert found - may == set(), found - may
    assert {"doors/mcp.py", "doors/http.py", "doors/cli.py", "doctor.py", "words.py"} <= found   # the scan sees
    for name in ("engine.py", "spine.py", "ledger.py"):
        assert (core / name).exists() and name not in found


def test_the_runbook_in_the_setup_guide_is_one_proximo_would_serve():
    import re

    from proximo.core import runbooks
    setup = (Path(__file__).parent.parent / "docs" / "SETUP.md").read_text(encoding="utf-8")
    [example] = re.findall(r"```markdown\n(# .*?)```", setup, re.S)
    book = runbooks.check("drain_node", example)
    assert book.plane == "pve" and book.title == "Drain a node before maintenance"


# --- A2A: the words in the authenticated extended card, a runbook by its skill --------------------
#
# The open card is the same bytes whether an operator has words or not (John: "zerotrust"), so the
# flag that announces an extended card is on for every door with a token. Cards are compared byte
# for byte only with no signing key: two signatures of one card are never the same bytes.

A2A_RPC = {"A2A-Version": "1.0", "Content-Type": "application/json"}
LABEL = "Operator instructions (not Proximo's):"


def _a2a(token=TOKEN, key=None, url: str | None = f"{BASE}/"):
    """The door's app. `url=None` is the door's own default address, the one the goldens were taken at."""
    from proximo.core.doors import a2a
    return a2a.build_app(url, token=token, signing_key=key)


def _open_card(app) -> Any:
    from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
    from starlette.testclient import TestClient
    return _unversioned(TestClient(app, base_url=BASE).get(AGENT_CARD_WELL_KNOWN_PATH).json())


def _rpc(app, method: str, headers: dict[str, str] | None = None):
    from starlette.testclient import TestClient
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}
    return TestClient(app, base_url=BASE).post("/", headers={**A2A_RPC, **(headers or {})}, json=body)


def _hx(app, headers):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE, headers=headers, timeout=20)


async def _cards(app, verifier=None, headers=BEARER):
    """(the open card, the extended card) as the OFFICIAL client reads them, the second with the bearer."""
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import GetExtendedAgentCardRequest
    async with _hx(app, headers) as hx:
        card = await A2ACardResolver(hx, BASE).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=False)).create(card)
        extended = await client.get_extended_agent_card(GetExtendedAgentCardRequest(), signature_verifier=verifier)
        return card, extended


async def _ask(app, payload: dict, headers=BEARER):
    """Send one skill call with the official client: (final state, artifacts by name, every text said)."""
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.helpers.proto_helpers import new_data_message
    from a2a.types.a2a_pb2 import SendMessageRequest
    async with _hx(app, headers) as hx:
        card = await A2ACardResolver(hx, BASE).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=False)).create(card)
        state, artifacts, said = None, [], []
        async for resp in client.send_message(SendMessageRequest(message=new_data_message(payload))):
            if resp.HasField("task"):
                artifacts += list(resp.task.artifacts)
                state = resp.task.status.state
                said += [part.text for part in resp.task.status.message.parts if part.text]
            if resp.HasField("artifact_update"):
                artifacts.append(resp.artifact_update.artifact)
            if resp.HasField("status_update"):
                state = resp.status_update.status.state
                said += [part.text for part in resp.status_update.status.message.parts if part.text]
        return state, {a.name: [part.text for part in a.parts if part.text] for a in artifacts}, " ".join(said)


def _dict(card) -> Any:
    from google.protobuf.json_format import MessageToDict
    return MessageToDict(card)


@pytest.fixture
def a2a_words(env, monkeypatch):
    """Instructions, one sound runbook and one refused, for the tests that want all three."""
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    folder = env / "a2a-words"
    folder.mkdir()
    (folder / "rules.md").write_text(RULES)
    books = folder / "runbooks"
    books.mkdir()
    (books / "drain_node.md").write_text(BOOK)
    (books / "bad.md").write_text("# Bad\n\nplane: pve\n\nGET /nodes/{node}/nope\n")
    monkeypatch.setenv("PROXIMO_INSTRUCTIONS", str(folder / "rules.md"))
    monkeypatch.setenv("PROXIMO_RUNBOOKS_DIR", str(books))
    return books


def test_b1_a_door_with_no_token_is_todays_door_words_or_none(a2a_words, monkeypatch):
    with_words = _a2a(token=None, url=None)
    assert _open_card(with_words) == _golden("words_unset_agent_card_no_token.json")
    refused = _rpc(with_words, "GetExtendedAgentCard").json()
    assert "does not support authenticated extended cards" in refused["error"]["message"]
    for name in ("PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(name)
    none = _a2a(token=None, url=None)
    assert _open_card(none) == _golden("words_unset_agent_card_no_token.json")
    assert _rpc(none, "GetExtendedAgentCard").json() == refused
    assert RULES.strip() not in json.dumps([_open_card(with_words), refused])


def test_b2_the_open_card_of_a_door_with_a_token_is_the_same_bytes_words_or_none(a2a_words, monkeypatch):
    from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
    from starlette.testclient import TestClient

    def raw():
        return TestClient(_a2a(url=None), base_url=BASE).get(AGENT_CARD_WELL_KNOWN_PATH).content
    with_words = raw()
    assert _open_card(_a2a(url=None)) == _golden("words_unset_agent_card.json")
    assert json.loads(with_words)["capabilities"]["extendedAgentCard"] is True
    assert b"Drain" not in with_words and RULES.strip().encode() not in with_words and b"runbook" not in with_words
    for name in ("PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(name)
    assert raw() == with_words


@pytest.mark.parametrize("headers", [None, {"Authorization": "Bearer wrong"}])
def test_b3_without_the_bearer_the_rpc_path_is_401_words_or_none(a2a_words, monkeypatch, headers):
    def answers():
        app = _a2a()
        asked = (_rpc(app, "GetExtendedAgentCard", headers), _rpc(app, "SendMessage", headers))
        return [(r.status_code, r.json()) for r in asked]
    with_words = answers()
    assert with_words == [(401, _golden("a2a_unauthorized_body.json"))] * 2
    for name in ("PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(name)
    assert answers() == with_words


async def test_b4_with_the_bearer_and_no_words_the_extended_card_is_the_open_card(env):
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    card, extended = await _cards(_a2a())
    assert _dict(extended) == _dict(card) and len(extended.skills) == 6


async def test_b5_the_instructions_follow_proximos_own_description_under_one_fixed_line(a2a_words, monkeypatch):
    card, extended = await _cards(_a2a())
    assert extended.description == f"{card.description}\n\n{LABEL}\n{RULES}"
    assert card.description and LABEL not in card.description
    monkeypatch.delenv("PROXIMO_INSTRUCTIONS")
    card, runbooks_only = await _cards(_a2a())
    assert runbooks_only.description == card.description         # no label with nothing under it
    assert [s.id for s in runbooks_only.skills][6:] == ["runbook.drain_node"]


async def test_b5_instructions_alone_are_words_too(a2a_words, monkeypatch):
    """The lens on 9ff8239b: with instructions and NO runbooks the copy was only ever tested by
    accident. One half of the words is words."""
    monkeypatch.delenv("PROXIMO_RUNBOOKS_DIR")
    card, extended = await _cards(_a2a())
    assert extended.description == f"{card.description}\n\n{LABEL}\n{RULES}"
    assert len(extended.skills) == 6


def _key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from proximo.core.perimeter.a2a.signing import load_operator_key
    pem = tmp_path / "a2a-signing.pem"
    pem.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pem.chmod(0o600)
    return load_operator_key(pem)


def _jku(card) -> str:
    import base64
    protected = card.signatures[0].protected
    return json.loads(base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4)))["jku"]


async def test_b6_a_signed_door_signs_the_extended_card_again_with_the_same_key(a2a_words, tmp_path, monkeypatch):
    from proximo.core.perimeter.a2a.signing import make_verifier
    key = _key(tmp_path)
    verify = make_verifier(key)
    card, extended = await _cards(_a2a(key=key), verifier=verify)
    verify(card)
    verify(extended)                                             # and the client's own check passed above
    assert _jku(extended) == _jku(card)
    assert extended.signatures[0].signature != card.signatures[0].signature
    extended.description += "!"
    with pytest.raises(Exception, match="(?i)signature"):
        verify(extended)
    for name in ("PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(name)
    card, same = await _cards(_a2a(key=key), verifier=verify)
    assert _dict(same) == _dict(card)                            # no words: the open card itself, seal included


async def test_b7_each_served_runbook_is_one_more_skill_after_the_six(a2a_words):
    (a2a_words / "aaa_first.md").write_text("# First things\n\nplane: pbs\n\nGET /version\n")
    (a2a_words / "proximo_call.md").write_text("# Named like a tool\n\nplane: pve\n\nGET /version\n")
    card, extended = await _cards(_a2a())
    assert [s.id for s in card.skills] == [s.id for s in extended.skills][:6] and len(card.skills) == 6
    mine = list(extended.skills)[6:]
    assert [s.id for s in mine] == ["runbook.aaa_first", "runbook.drain_node", "runbook.proximo_call"]   # by name
    assert [(s.name, list(s.tags)) for s in mine] == [
        ("First things", ["runbook", "pbs"]), ("Drain a node", ["runbook", "pve"]),
        ("Named like a tool", ["runbook", "pve"])]
    assert {s.description for s in mine} == {"Operator runbook (not Proximo's)."}
    assert "runbook.bad" not in [s.id for s in extended.skills]             # the refused one is nowhere
    assert len({s.id for s in extended.skills}) == len(extended.skills)
    state, artifacts, said = await _ask(_a2a(), {"skill": "proximo_call", "params": {}})
    assert "runbook" not in artifacts and "Named like a tool" not in said   # the tool, not the runbook of that name


async def test_b8_calling_a_runbooks_skill_returns_the_text_mcp_serves_and_touches_nothing(a2a_words, env, monkeypatch):
    from a2a.types.a2a_pb2 import TaskState

    from proximo.core import words
    from proximo.core.doors import mcp as door
    from proximo.core.doors.dispatch import Core
    served = words.at_start(bearer=True)
    prompt = (await door.build_server(words=served).get_prompt("drain_node", {})).messages[0].content.text
    calls: list[str] = []
    real = Core.call

    async def spy(self, name, arguments):
        calls.append(name)
        return await real(self, name, arguments)
    monkeypatch.setattr(Core, "call", spy)
    app = _a2a()
    before = _listing(env)
    for payload in ({"skill": "runbook.drain_node"}, {"tool": "runbook.drain_node", "params": {}}):
        state, artifacts, said = await _ask(app, payload)
        assert state == TaskState.TASK_STATE_COMPLETED
        assert artifacts == {"runbook": [prompt]}
        assert prompt.startswith("Operator runbook (not Proximo's): drain_node.\n\n")
    assert calls == []                                           # never the dispatch: words, not a tool
    assert _listing(env) == before                               # no ledger row, no file
    await _ask(app, {"skill": "audit_verify", "params": {}})
    assert calls == ["audit_verify"]                             # the control: the spy sees a real tool call


async def test_b9_a_runbook_takes_no_arguments_and_an_unknown_one_is_an_unknown_tool(a2a_words, env):
    from a2a.types.a2a_pb2 import TaskState
    app = _a2a()
    # Anything but absent or {} is an argument: the empty and the false ones too (the lens on 9ff8239b).
    sent = ({"node": "pve1"}, ["x"], "x", 1, [], 0, "", False)
    for params in sent:
        state, artifacts, said = await _ask(app, {"skill": "runbook.drain_node", "params": params})
        assert state == TaskState.TASK_STATE_FAILED and "runbook" not in artifacts, params
        assert "an operator runbook takes no arguments" in said and "Drain a node" not in said
    rows = (env / "state" / "audit.log").read_text()
    assert rows.count("a2a_rejected") == len(sent) and "an operator runbook takes no arguments" in rows
    for name in ("runbook.nope", "runbook.", "runbook.bad", "runbook", "RUNBOOK.drain_node"):
        state, artifacts, said = await _ask(app, {"skill": name})
        assert state == TaskState.TASK_STATE_FAILED and artifacts == {} and "unknown tool" in said, name
        assert "Drain a node" not in said


async def test_b9_a_door_with_no_token_has_no_runbook_skill_though_words_are_set(a2a_words):
    from a2a.types.a2a_pb2 import TaskState
    state, artifacts, said = await _ask(_a2a(token=None), {"skill": "runbook.drain_node"}, headers=None)
    assert state == TaskState.TASK_STATE_FAILED and artifacts == {} and "unknown tool" in said


async def test_the_a2a_perimeter_itself_serves_no_words_without_a_token_whoever_hands_them_in(env):
    """The door reads nothing for a door with no token; this is the second line, as on REST."""
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    from a2a.types.a2a_pb2 import TaskState

    from proximo.core import runbooks, words
    from proximo.core.doors.dispatch import Core
    from proximo.core.doors.network import recorder
    from proximo.core.perimeter.a2a import app as perimeter
    handed = words.Words(RULES, (runbooks.check("drain_node", BOOK),), ())
    default = perimeter.build_app(token=None, dispatch=Core(), record=recorder("test"), words=handed)
    assert _open_card(default) == _golden("words_unset_agent_card_no_token.json")
    open_app = perimeter.build_app(f"{BASE}/", token=None, dispatch=Core(), record=recorder("test"), words=handed)
    assert "does not support" in _rpc(open_app, "GetExtendedAgentCard").json()["error"]["message"]
    state, artifacts, said = await _ask(open_app, {"skill": "runbook.drain_node"}, headers=None)
    assert state == TaskState.TASK_STATE_FAILED and artifacts == {} and "unknown tool" in said
    held = perimeter.build_app(f"{BASE}/", token=TOKEN, dispatch=Core(), record=recorder("test"), words=handed)
    _card, extended = await _cards(held)
    assert RULES in extended.description                          # the control: with a token they are served


def test_runbook_list_exits_2_only_while_a_file_is_refused(env, monkeypatch, capsys):
    """#142 item 30 (kevwillow): a folder whose only file was refused listed nothing and exited 0, while
    `show` and SETUP said 2. A folder of sound files, or an empty one, is still 0."""
    folder = env / "runbooks"
    folder.mkdir()
    monkeypatch.setenv("PROXIMO_RUNBOOKS_DIR", str(folder))
    assert _shell(["runbook", "list"], capsys) == (0, "", "")
    (folder / "bad.md").write_text("# Bad\n\nplane: pve\n\nGET /nodes/{node}/nope\n")
    rc, out, err = _shell(["runbook", "list"], capsys)
    assert (rc, out) == (2, "") and "bad: it names an address pve does not publish" in err
    (folder / "bad.md").unlink()
    (folder / "drain_node.md").write_text(BOOK)
    assert _shell(["runbook", "list"], capsys) == (0, "drain_node\tpve\tDrain a node\n", "")
    # a file the folder IGNORES is not a refusal: a wrong extension, a capital, a subfolder
    (folder / "notes.txt").write_text("x")
    (folder / "Misnamed.md").write_text(BOOK)
    (folder / "sub").mkdir()
    assert _shell(["runbook", "list"], capsys) == (0, "drain_node\tpve\tDrain a node\n", "")
