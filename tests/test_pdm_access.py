"""The PDM identity core: users, tokens, ACL, permissions, driven through the shared
proxmox-access helpers with a PdmBackend. Path/verb/payload per op, plane-correct action and
target names, PLAN-by-default through the real funnel with a real ledger, secrets never in the
ledger, and a control that the PBS names did not move."""

from __future__ import annotations

import io
import json
import pathlib
import re
import tokenize
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo import pbs_access
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.config import ProximoConfig
from proximo.pdm import PdmBackend


class _FakePdm:
    """PDM-shaped: _get(path, params), _post(path, data, params), _put(path, data), _delete(path, params)."""

    def __init__(self, get_return=None):
        self.calls: list = []
        self._get_return = get_return

    def _get(self, path, params=None):
        self.calls.append(("GET", path, params))
        return self._get_return

    def _post(self, path, data=None, params=None):
        self.calls.append(("POST", path, data))
        return {"tokenid": "svc@pdm!ci", "value": "FAKE-PDM-SECRET-sentinel"}

    def _put(self, path, data=None):
        self.calls.append(("PUT", path, data))
        return {"secret": "FAKE-REGEN-sentinel"} if (data or {}).get("regenerate") else None

    def _delete(self, path, params=None):
        self.calls.append(("DELETE", path, params))
        return None


# make the duck-typing real: the plane is read off the class name
_FakePdm.__name__ = "PdmBackend"


def _wire(tmp_path, monkeypatch, pdm=None):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="x1", token_path="/run/x", audit_log_path=log)
    ledger = AuditLedger(log)
    pdm = pdm or _FakePdm()
    monkeypatch.setattr(server, "_svc", lambda: (cfg, SimpleNamespace(), SimpleNamespace(), ledger))
    monkeypatch.setattr(server, "_pdm", lambda: (SimpleNamespace(), pdm))
    return pdm, log


def _entries(log):
    return [json.loads(line) for line in open(log)]


# --- plane naming -----------------------------------------------------------------------------


def test_plane_is_read_off_the_backend_class_and_the_pbs_names_did_not_move():
    assert pbs_access._plane(_FakePdm()) == "pdm"
    assert pbs_access._plane(SimpleNamespace()) == "pbs"
    assert pbs_access._plane(PdmBackend.__new__(PdmBackend)) == "pdm"
    assert pbs_access.plan_user_create("a@pdm").action == "pbs_user_create"  # default plane, the control
    assert pbs_access.plan_token_delete("a@pdm", "t").target == "pbs/access/users/a@pdm/token/t"


def test_pure_plan_factories_take_the_plane():
    p = pbs_access.plan_user_create("a@pdm", plane="pdm")
    assert (p.action, p.target) == ("pdm_user_create", "pdm/access/users/a@pdm")
    p = pbs_access.plan_token_create("a@pdm", "t", plane="pdm")
    assert (p.action, p.target) == ("pdm_token_create", "pdm/access/users/a@pdm/token/t")
    p = pbs_access.plan_token_update("a@pdm", "t", regenerate=True, plane="pdm")
    assert p.action == "pdm_token_update"
    p = pbs_access.plan_token_delete("a@pdm", "t", plane="pdm")
    assert p.action == "pdm_token_delete"


def test_api_bearing_plan_factories_derive_the_plane():
    pdm = _FakePdm(get_return=[])
    assert pbs_access.plan_acl_update(pdm, "/", "Auditor", auth_id="a@pdm").action == "pdm_acl_update"
    pdm = _FakePdm(get_return={"userid": "a@pdm"})
    assert pbs_access.plan_user_delete(pdm, "a@pdm").target == "pdm/access/users/a@pdm"
    assert pbs_access.plan_user_update(pdm, "a@pdm", comment="x").action == "pdm_user_update"


# --- wire shape per op, through the tools with confirm=True -----------------------------------


def test_user_create_posts_json_shaped_body_and_redacts_the_password(tmp_path, monkeypatch):
    pdm, log = _wire(tmp_path, monkeypatch)
    out = server.pdm_user_create("svc@pdm", comment="ci", enable=True, password="hunter2hunter2", confirm=True)
    assert out["status"] == "ok"
    assert pdm.calls == [
        ("POST", "/access/users", {"userid": "svc@pdm", "comment": "ci", "enable": True, "password": "hunter2hunter2"})
    ]
    e = [x for x in _entries(log) if x["action"] == "pdm_user_create"][-1]
    assert e["target"] == "pdm/access/users/svc@pdm" and e["outcome"] == "ok"
    assert "hunter2hunter2" not in json.dumps(e)


def test_user_update_puts_and_delete_deletes_with_digest(tmp_path, monkeypatch):
    pdm, _ = _wire(tmp_path, monkeypatch, _FakePdm(get_return={"userid": "svc@pdm", "comment": "old"}))
    # PDM types `delete` as an array; PBS (form-encoded) takes the comma list. The first fixture
    # asserted the PBS shape here and was green: an invented fixture tests your memory.
    server.pdm_user_update("svc@pdm", enable=False, delete_props=["comment"], digest="ab" * 32, confirm=True)
    assert pdm.calls[-1] == (
        "PUT",
        "/access/users/svc@pdm",
        {"enable": False, "delete": ["comment"], "digest": "ab" * 32},
    )
    server.pdm_user_delete("svc@pdm", digest="ab" * 32, confirm=True)
    assert pdm.calls[-1] == ("DELETE", "/access/users/svc@pdm", {"digest": "ab" * 32})


def test_token_create_returns_the_secret_once_and_never_ledgers_it(tmp_path, monkeypatch):
    pdm, log = _wire(tmp_path, monkeypatch)
    out = server.pdm_token_create("svc@pdm", "ci", comment="runner", expire=4102444800, confirm=True)
    assert out["result"]["value"] == "FAKE-PDM-SECRET-sentinel"
    assert pdm.calls == [("POST", "/access/users/svc@pdm/token/ci", {"comment": "runner", "expire": 4102444800})]
    assert "FAKE-PDM-SECRET-sentinel" not in open(log).read()


def test_token_update_regenerate_and_delete(tmp_path, monkeypatch):
    pdm, log = _wire(tmp_path, monkeypatch)
    out = server.pdm_token_update("svc@pdm", "ci", regenerate=True, confirm=True)
    assert out["result"] == {"secret": "FAKE-REGEN-sentinel"}
    assert pdm.calls[-1] == ("PUT", "/access/users/svc@pdm/token/ci", {"regenerate": True})
    assert "FAKE-REGEN-sentinel" not in open(log).read()
    server.pdm_token_delete("svc@pdm", "ci", confirm=True)
    assert pdm.calls[-1] == ("DELETE", "/access/users/svc@pdm/token/ci", None)


def test_acl_update_grants_and_revokes_one_role_for_one_principal(tmp_path, monkeypatch):
    pdm, log = _wire(tmp_path, monkeypatch, _FakePdm(get_return=[]))
    server.pdm_acl_update("/resource/lab", "Auditor", auth_id="svc@pdm!ci", propagate=False, confirm=True)
    assert pdm.calls[-1] == (
        "PUT",
        "/access/acl",
        {"path": "/resource/lab", "role": "Auditor", "auth-id": "svc@pdm!ci", "propagate": False},
    )
    server.pdm_acl_update("/resource/lab", "Auditor", group="ops", delete=True, confirm=True)
    assert pdm.calls[-1] == (
        "PUT",
        "/access/acl",
        {"path": "/resource/lab", "role": "Auditor", "group": "ops", "delete": True},
    )
    e = [x for x in _entries(log) if x["action"] == "pdm_acl_update" and x["outcome"] == "ok"]
    assert [x["target"] for x in e] == [
        "pdm/access/acl:/resource/lab:svc@pdm!ci",
        "pdm/access/acl:/resource/lab:group:ops",
    ]
    with pytest.raises(ProximoError):
        server.pdm_acl_update("/", "Auditor", auth_id="a@pdm", group="g", confirm=True)  # both principals


def test_reads_hit_their_paths_and_ledger_as_reads(tmp_path, monkeypatch):
    pdm, log = _wire(tmp_path, monkeypatch, _FakePdm(get_return={"x": 1}))
    server.pdm_user_get("svc@pdm")
    server.pdm_user_tokens_list("svc@pdm")
    server.pdm_user_token_get("svc@pdm", "ci")
    server.pdm_permissions_get(auth_id="svc@pdm!ci", path="/")
    assert [c[1] for c in pdm.calls] == [
        "/access/users/svc@pdm",
        "/access/users/svc@pdm/token",
        "/access/users/svc@pdm/token/ci",
        "/access/permissions",
    ]
    assert pdm.calls[-1][2] == {"auth-id": "svc@pdm!ci", "path": "/"}
    acts = [x["action"] for x in _entries(log)]
    assert acts == ["pdm_user_get", "pdm_user_tokens_list", "pdm_user_token_get", "pdm_permissions_get"]
    assert all(not x.get("mutation") for x in _entries(log))


# --- PLAN by default, every mutation --------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "kwargs", "action"),
    [
        ("pdm_user_create", {"userid": "a@pdm"}, "pdm_user_create"),
        ("pdm_user_update", {"userid": "a@pdm", "comment": "x"}, "pdm_user_update"),
        ("pdm_user_delete", {"userid": "a@pdm"}, "pdm_user_delete"),
        ("pdm_token_create", {"userid": "a@pdm", "token_name": "t"}, "pdm_token_create"),
        ("pdm_token_update", {"userid": "a@pdm", "token_name": "t", "comment": "x"}, "pdm_token_update"),
        ("pdm_token_delete", {"userid": "a@pdm", "token_name": "t"}, "pdm_token_delete"),
        ("pdm_acl_update", {"path": "/", "role": "Auditor", "auth_id": "a@pdm"}, "pdm_acl_update"),
    ],
)
def test_every_mutation_plans_by_default_and_touches_no_write(tmp_path, monkeypatch, name, kwargs, action):
    pdm, log = _wire(tmp_path, monkeypatch, _FakePdm(get_return={"userid": "a@pdm"}))
    out = getattr(server, name)(**kwargs)
    assert out["status"] == "plan" and out["action"] == action
    assert not [c for c in pdm.calls if c[0] != "GET"]


def test_delete_props_take_the_wire_shape_of_the_backend():
    assert pbs_access._delete_props_wire(_FakePdm(), ["comment", "email"]) == ["comment", "email"]
    assert pbs_access._delete_props_wire(SimpleNamespace(), ["comment", "email"]) == "comment,email"


def test_a_subclass_of_the_backend_is_still_the_plane():
    class Wrapped(PdmBackend):
        pass

    assert pbs_access._plane(Wrapped.__new__(Wrapped)) == "pdm"


@pytest.mark.parametrize(
    ("plan", "kwargs"),
    [
        (pbs_access.plan_user_create, {"userid": "a@pdm", "plane": "pdm"}),
        (pbs_access.plan_token_create, {"userid": "a@pdm", "token_name": "t", "plane": "pdm"}),
        (pbs_access.plan_token_delete, {"userid": "a@pdm", "token_name": "t", "plane": "pdm"}),
    ],
)
def test_pure_pdm_plan_text_names_pdm_not_pbs(plan, kwargs):
    d = plan(**kwargs).as_dict()
    text = " ".join(str(d.get(k)) for k in ("change", "blast_radius", "risk_reasons", "note"))
    assert "PBS" not in text and "pbs_" not in text, text
    assert "PDM" in text or "pdm_" in text, text


def test_api_bearing_pdm_plan_text_names_pdm_and_the_pbs_control_still_says_pbs():
    for d in (
        pbs_access.plan_acl_update(_FakePdm(get_return=[]), "/", "Auditor", auth_id="a@pdm").as_dict(),
        pbs_access.plan_user_delete(_FakePdm(get_return={"userid": "a@pdm"}), "a@pdm").as_dict(),
        pbs_access.plan_user_update(_FakePdm(get_return={"userid": "a@pdm"}), "a@pdm", comment="x").as_dict(),
    ):
        text = " ".join(str(d.get(k)) for k in ("change", "blast_radius", "risk_reasons", "note"))
        assert "PBS" not in text and "pbs_" not in text, text
    control = pbs_access.plan_user_create("a@pbs").as_dict()
    assert "create PBS user" in control["change"]  # the PBS side did not move


def test_pdm_backend_put_sends_json(monkeypatch):
    seen = {}

    class _Client:
        def put(self, path, headers=None, json=None):
            seen.update(path=path, json=json)
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"data": None})

    pdm = PdmBackend.__new__(PdmBackend)
    pdm._client = _Client()
    monkeypatch.setattr(PdmBackend, "_auth_header", lambda self: {})
    pdm._put("/access/acl", {"enable": True})
    assert seen == {"path": "/access/acl", "json": {"enable": True}}


# --- plan text, both planes: no stray literal (live-proof 2026-09-19 on pdm-test read
# "delete PDM user 'x'f" and "(grant<->revoke).f" — a scripted plane= edit had put the f-string
# prefix INSIDE twelve closing quotes; every text-blind test stayed green) ---------------------

# Rendered-text detector: punctuation glued to a lone f, a fake inner f'…', or f glued to a
# capital. A glued f that merges into a real word ("be f"+"recovered") is invisible here by
# construction — the lens's catch — so that shape is pinned by exact tails below and caught at the
# SOURCE by test_no_fstring_segment_ends_in_a_glued_f (tokenize, before literals merge).
_STRAY_F = re.compile(r"(?<=[.)'}\]])f(?=[\s,]|$)|\bf'|\bf[A-Z]")


def _plan_texts(plane: str) -> list[tuple[str, str]]:
    api = _FakePdm(get_return={"userid": f"a@{plane}"}) if plane == "pdm" else _FakePbsGet({"userid": "a@pbs"})
    plans = [
        pbs_access.plan_user_create(f"a@{plane}", comment="x", plane=plane),
        pbs_access.plan_user_create(f"a@{plane}", plane=plane),
        pbs_access.plan_user_update(api, f"a@{plane}", comment="x"),
        pbs_access.plan_user_delete(api, f"a@{plane}"),
        pbs_access.plan_token_create(f"a@{plane}", "t", plane=plane),
        pbs_access.plan_token_create(f"a@{plane}", "t", expire=3600, plane=plane),
        pbs_access.plan_token_update(f"a@{plane}", "t", regenerate=True, plane=plane),
        pbs_access.plan_token_delete(f"a@{plane}", "t", plane=plane),
        pbs_access.plan_acl_update(
            _FakePdm(get_return=[]) if plane == "pdm" else _FakePbsGet([]), "/", "Auditor", auth_id=f"a@{plane}"
        ),
    ]
    out = []
    for p in plans:
        d = p.as_dict()
        for k in ("change", "note"):
            out.append((f"{p.action}.{k}", str(d.get(k) or "")))
        for k in ("blast_radius", "risk_reasons"):
            out.extend((f"{p.action}.{k}", str(x)) for x in (d.get(k) or []))
    return out


class _FakePbsGet:
    def __init__(self, get_return):
        self._get_return = get_return

    def _get(self, path, params=None):
        return self._get_return


@pytest.mark.parametrize("plane", ["pbs", "pdm"])
def test_plan_text_carries_no_stray_f_on_either_plane(plane):
    bad = [(k, t) for k, t in _plan_texts(plane) if _STRAY_F.search(t)]
    assert not bad, bad
    # the control: the detector sees the shape the lab read back
    assert _STRAY_F.search("delete PDM user 'a@pdm'f") and _STRAY_F.search("(grant<->revoke).f")
    assert _STRAY_F.search("as fABSOLUTE") and not _STRAY_F.search("tokens cannot be frecovered")  # the limit
    assert not _STRAY_F.search("half of the users, and a proof of it, will no longer be forwarded")


@pytest.mark.parametrize("plane,P", [("pbs", "PBS"), ("pdm", "PDM")])
def test_plan_text_exact_tails(plane, P):
    t: dict[str, str] = {}
    for k, x in _plan_texts(plane):
        t.setdefault(k, x)  # first plan of each action wins (user_create is built twice)
    assert t[f"{plane}_user_create.change"] == f"create {P} user 'a@{plane}': {{'comment': 'x'}}"
    assert t[f"{plane}_user_delete.change"] == f"delete {P} user 'a@{plane}'"
    assert t[f"{plane}_user_delete.note"].startswith(
        f"irreversible; no {P} snapshot primitive applies to access-control state."
    )
    assert t[f"{plane}_acl_update.note"].startswith(
        f"no rollback primitive — revert with a second {plane}_acl_update call (grant<->revoke)."
    )
    texts = [x for k, x in _plan_texts(plane)]
    assert any(x.endswith("(tokens cannot be recovered; new ones must be reissued)") for x in texts), texts
    assert any("treats it as an ABSOLUTE UNIX timestamp" in x for x in texts), texts
    assert any("(no optional fields set)" in x and not x.endswith("f") for x in texts), texts


@pytest.mark.parametrize("plane", ["pbs", "pdm"])
def test_token_create_plan_says_the_owner_bounds_the_token(plane):
    """Live-proven 2026-09-19 on pdm-test (PDM 1.1.4): a token granted Auditor at '/' resolved to
    NO privileges until its owning user held Auditor too; revoking the owner's grant emptied the
    token again. proxmox-access-control acl.rs lookup_privs_details: `privs &= owner_privs`
    ("limit privs to that of owning user") — one crate, both planes."""
    texts = [x for _, x in _plan_texts(plane) if x]
    assert any("owning user" in x and "never more than" in x for x in texts), texts


def _glued_f_segments(source: bytes) -> list[tuple[int, str]]:
    """(line, segment) for every f-string literal segment that closes on a lone glued 'f' or
    carries a fake inner f-prefix (=f'/ (f'/ ,f'). Token-level, so 'cannot be f' + 'recovered'
    is seen as WRITTEN, before Python merges the two literals into innocent prose."""
    toks = list(tokenize.tokenize(io.BytesIO(source).readline))
    names = [tokenize.tok_name[t.type] for t in toks]
    out = []
    for i, tok in enumerate(toks):
        if names[i] != "FSTRING_MIDDLE":
            continue
        text = tok.string
        if re.search(r"[=(,]\s*f['\"]", text):
            out.append((tok.start[0], text))
            continue
        j = i + 1
        while j < len(toks) and names[j] in ("COMMENT", "NL"):
            j += 1
        if j < len(toks) and names[j] == "FSTRING_END" and re.search(r"(?:^|[)}'.\] ])f$", text):
            out.append((tok.start[0], text))
    return out


def test_no_fstring_segment_ends_in_a_glued_f():
    """The 2026-09-19 plane refactor left twelve f-strings with the prefix inside the closing
    quote; rendered-text tests cannot see the two that merged into real words. This reads the
    SOURCE. Control first: the planted shapes must be found."""
    planted = b'x = f"delete {P} user {u!r}f"\ny = f"cannot be f" "recovered"\nz = f"auth_id=f\'{u}\'"\nw = f"{n}f"\n'
    assert [ln for ln, _ in _glued_f_segments(planted)] == [1, 2, 3, 4]
    assert _glued_f_segments(b'a = f"half of {n}"\nb = f"{x} proof"\n') == []
    root = pathlib.Path(pbs_access.__file__).parent
    struct_codes = {root / "vectors.py"}  # struct.pack(f"{dim}f"): 'f' IS the float format code
    hits = {
        f"{p.relative_to(root)}:{ln}": seg
        for p in sorted(root.rglob("*.py"))
        if p not in struct_codes
        for ln, seg in _glued_f_segments(p.read_bytes())
    }
    assert not hits, hits
