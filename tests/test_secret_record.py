"""The SECRET record: `src/proximo/core/secrets.toml`, what a door withholds from a read.

The 0.44 wrappers stripped credentials from a read before the model saw it (a PBS remote's
password, a fetchmail pass, an SDN lock token, an ACME plugin's DNS keys). The door served the
same addresses raw: the governed engine and the raw GET door handed back every field the vendor
sent. The record moves those strips to the address, both doors read it, and these tests hold
it: its shape, its totality over the strips the backends still carry, and the behaviour on each
door with a control that must go red.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import tomllib
from dataclasses import dataclass

import pytest

from proximo.core import engine, wire
from proximo.core.errors import ProximoError

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "proximo"
RECORD = SRC / "core" / "secrets.toml"

#: pve 21 · pbs 17 · pmg 16 · pdm 14. 61 on 2026-09-24 (the wrappers' strips + the vendor schemas +
#: lens 1); +6 on 2026-09-28, the strips 0.44 kept in shapes the scan could not see (STRIPS_044);
#: +1 the same day, the quarantine link 0.44's docstring told the model was a password (bearer).
#: 68 until 2026-10-04; lenses 1+2 added 13 lines on a mutation's own answer (bearer mints, echo drops) and
#: 1 GET drop; the 4 tfa lines carry `args` too and count among the 11 arg lines, not here.
EXACT_LINES = 86

#: A stripping backend whose address is NOT a line, and why. Each is a judgement, not a gap.
NOT_A_CREDENTIAL = {
    "pdm:GET /access/users": "pdm's substring strip catches the WORD token in `tokens`, which is "
                             "token metadata (tokenid, comment, expiry), never a secret",
}


def _record() -> dict:
    return tomllib.loads(RECORD.read_text())["secret"]


def _read_lines() -> dict:
    # the READ strips; the arg-secret lines (B5: a mutation's own argv/content) carry `args`
    # instead of drop/userinfo/rows/text/bearer and are guarded by their own test below.
    return {k: v for k, v in _record().items() if "args" not in v}


def test_the_record_is_exact_and_names_only_addresses_the_door_serves():
    """A line lives on a read the door serves or on a mutation it may open (a token mint's
    one-time answer, lens 1 B1); never on a tunnel or a hard-gated byte stream."""
    live = {r.key: r for r in engine.table().values()}
    keys = list(_read_lines())
    assert not (set(keys) - set(live)), sorted(set(keys) - set(live))[:5]
    assert not [k for k in keys if live[k].excluded or (live[k].gate and engine.opt_in_lane(live[k]) is None)
                or (live[k].method != "GET" and live[k].access != "mutate")]
    assert len(keys) == EXACT_LINES, f"the record holds {len(keys)} lines, the pin says {EXACT_LINES}"


def test_every_line_is_a_sentence_and_names_a_field():
    bad = [(k, v) for k, v in _read_lines().items()
           if len(v.get("why", "").split()) < 3
           or not (v.get("drop") or v.get("userinfo") or v.get("rows") or v.get("text") is True
                   or v.get("bearer") is True)]
    assert not bad, bad[:3]


def test_the_arg_secret_lines_name_mutations_and_fingerprint_their_args():
    # B5: a mutation's own arguments (a guest exec's argv and stdin, a file-write's content) are
    # fingerprinted in the ledger. Each line is keyed on a live mutating address, carries a
    # non-empty `args` list of field names and a why.
    live = {r.key: r for r in engine.table().values()}
    arg_lines = {k: v for k, v in _record().items() if "args" in v}
    # +2 otel-headers (lens 1 N7), +4 a second factor's value (lens 2 N6)
    assert len(arg_lines) == 11, sorted(arg_lines)
    for k, v in arg_lines.items():
        assert k in live and live[k].access == "mutate" and not live[k].excluded, k
        assert isinstance(v["args"], list) and v["args"] and all(isinstance(a, str) and a for a in v["args"])
        assert len(v.get("why", "").split()) >= 3, k


# ---- totality: every strip a backend still carries has its line ------------------------------

_STRIPPERS = re.compile(r"^_strip_\w*(secret|password|key|token|fields)\w*$|^_redact_\w+$")
#: a comprehension that drops a credential-named key inline: `{k: v ... if k != "secret-key"}`,
#: `if k not in _SECRET_KEYS`. 0.44 stripped seven reads this way and the name scan saw none of them.
#: KEY only as a whole word (`key`, `client-key`, `_LOCK_TOKEN_KEY`): `_COMPUTED_KEYS` is not a credential.
_CRED = re.compile(r"secret|passw|token|(^|[-_])key$|^pass$", re.I)


def _plane(path: pathlib.Path) -> str:
    stem = path.stem
    return next((p for p in ("pmg", "pbs", "pdm") if stem.startswith(p)), "pve")


def _path_of(arg: ast.AST, fn: ast.FunctionDef) -> str | None:
    """The literal a `_get(...)` reaches, `{}` for every interpolation; a `{}` glued to the end of
    a literal is a query builder (`{_sdn_get_query(...)}`), not a segment, and is dropped."""
    if isinstance(arg, ast.Name):
        arg = next((a.value for a in ast.walk(fn) if isinstance(a, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == arg.id for t in a.targets)), None)
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.JoinedStr):
        s = "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in arg.values)
        return re.sub(r"(?<=[^/])\{\}$", "", s)
    return None


def _names_a_credential(c: ast.Compare) -> bool:
    return any(isinstance(r, ast.Constant) and isinstance(r.value, str) and _CRED.search(r.value)
               or isinstance(r, ast.Name) and _CRED.search(r.id) for r in c.comparators)


def _drops_inline(fn: ast.FunctionDef) -> bool:
    """A comprehension that DROPS a credential-named key (`if k != "secret-key"`, `if k not in
    _SECRET_KEYS`) or MASKS its value (`MASK if k in _SECRET_KEYS else v`: cloudinit's shape)."""
    for comp in ast.walk(fn):
        if isinstance(comp, (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            for c in ast.walk(comp):
                if isinstance(c, ast.Compare) and any(isinstance(o, (ast.NotEq, ast.NotIn)) for o in c.ops) \
                        and _names_a_credential(c):
                    return True
                if isinstance(c, ast.IfExp) and isinstance(c.test, ast.Compare) \
                        and any(isinstance(o, (ast.Eq, ast.In)) for o in c.test.ops) and _names_a_credential(c.test):
                    return True
    return False


def _norm(key: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", key)


# ---- parity: every strip 0.44 carried, whether or not its backend survives -------------------

STRIPS_044 = pathlib.Path(__file__).resolve().parent / "fixtures" / "strips-0.44.json"


def test_every_strip_044_carried_has_its_line():
    """The totality scan above sees only the backends still in the tree; the cut deletes them,
    and a deleted backend takes its strip out of the scan's sight while the door keeps serving
    the address. So the list is pinned from the v0.44.0 source (`_stripping_reads` run over that
    tree; see the fixture's header) and held to the record whatever the tree carries today."""
    pinned = json.loads(STRIPS_044.read_text())
    assert pinned["source"].startswith("v0.44.0") and len(pinned["reads"]) == 37, pinned["source"]
    lines = {_norm(k) for k in _record()} | {_norm(k) for k in NOT_A_CREDENTIAL}
    missing = sorted(k for k in pinned["reads"] if _norm(k) not in lines)
    assert not missing, missing


# ---- totality over the vendor's schemas (source 2) ---------------------------------------------

VENDOR = pathlib.Path(__file__).resolve().parent / "fixtures" / "vendor-secret-returns.json"

#: A credential-SHAPED field name that is not a credential, anywhere it appears.
NOT_A_CREDENTIAL_FIELD = {
    "tokens": "a user's token METADATA (tokenid, comment, expiry), never the secret",
    "tokenid": "a token's id, not its secret",
    "token-name": "a token's name, not its secret",
    "authorized-tokens": "token IDs allowed to fetch an answer file, not secrets",
    "public_key": "a public key", "root-ssh-keys": "public SSH keys", "ssh-public-host-keys": "public host keys",
    "Key": "an apt repository option's NAME (Options[].Key), not a key",
    "full-tokenid": "a token's full id (user@realm!name), not its value",
    "recovery-bytes-sec": "a ceph recovery rate",
    "medium-passes": "a tape pass counter", "beginning-of-medium-passes": "a tape pass counter",
    "middle-of-tape-passes": "a tape pass counter",
    # Surfaced 2026-10-05 when the scanner first walked PBS's nested allOf return schemas (B19):
    "limit-passive-requests": "an S3 request rate limit (#/s)",
    "active-encryption-key": "a sync job's encryption key ID ('ID to uniquely identify'), not key material",
    "associated-key": "the IDs of keys associated with a sync job, not key material",
}
#: The same, where the reason belongs to one address.
NOT_A_CREDENTIAL_AT = {
    ("pdm:GET /subscriptions/keys", "key"): "the pool key is the resource's own name, in its own path",
    ("pdm:GET /subscriptions/keys/{key}", "key"): "the pool key is the resource's own name, in its own path",
    ("pve:GET /nodes/{node}/lxc/{vmid}/pending", "key"): "a pending row's OPTION NAME; no LXC option holds a secret",
    ("pve:GET /nodes/{node}/lxc/{vmid}/pending", "value"): "a pending row's VALUE; no LXC option holds a secret",
    ("pve:GET /nodes/{node}/storage/{storage}/import-metadata", "key"): "a warning's option name",
    ("pdm:POST /auto-install/prepared", "token"): "the minted token's record; `secret` is the credential (bearer)",
    ("pdm:PUT /auto-install/prepared/{id}", "token"): "the minted token's record; `secret` is the credential (bearer)",
    # `value` (a candidate since 2026-10-04, for the token mints) where it is a row's or a metric's value
    ("pve:GET /cluster/metrics/export", "value"): "a metric sample",
    ("pve:GET /cluster/notifications/matcher-field-values", "value"): "a notification field value",
    ("pbs:GET /config/notifications/matcher-field-values", "value"): "a notification field value",
    ("pve:GET /cluster/ceph/flags", "value"): "a ceph flag's state",
    ("pdm:GET /ceph/clusters/{cluster}/flags", "value"): "a ceph flag's state",
    ("pve:GET /nodes/{node}/ceph/cfg/db", "value"): "a ceph config value (`mask` is a field name there, see above)",
    ("pve:GET /nodes/{node}/storage/{storage}/import-metadata", "value"): "a warning's value",
    ("pbs:GET /nodes/{node}/disks/smart", "value"): "a SMART attribute value",
    ("pbs:GET /tape/drive/{drive}/cartridge-memory", "value"): "a cartridge-memory attribute value",
    # The S3 ACCESS key is the identifier half of the pair; the secret half (`secret-key`) is
    # dropped by this address's own line. Surfaced by the allOf walk, 2026-10-05.
    ("pbs:GET /config/s3", "access-key"): "the S3 key ID; its secret-key is dropped on this line",
    ("pbs:GET /config/s3/{id}", "access-key"): "the S3 key ID; its secret-key is dropped on this line",
}


def _uncovered(vendor: dict[str, list[str]]) -> list[str]:
    """Every vendor candidate the record neither withholds nor names as no credential. A
    mutation's answer is governed by its OWN line merged with its read twin's (`engine.secret_rule`),
    a bearer line serves it whole and labelled, and a HELD, excluded or hard-gated address never
    answers at all (two lenses, 2026-10-04: the guard had read GETs alone)."""
    out = []
    live = {r.key: r for r in engine.table().values()}
    for addr, fields in vendor.items():
        row = live.get(addr)
        if row is not None and (row.held or row.excluded or (row.gate and engine.opt_in_lane(row) is None)):
            continue
        plane, rest = addr.split(":", 1)
        twin = f"{plane}:GET {rest.split(' ', 1)[1]}"
        lines = [_record().get(addr, {})] + ([_record().get(twin, {})] if twin != addr else [])
        for f in fields:
            leaf = f.split(".")[-1].lstrip("[]")
            covered = lines[0].get("bearer") is True or any(
                leaf in ln.get("drop", ()) or leaf in ln.get("userinfo", ())
                or (leaf in ("key", "value") and ln.get("rows")) for ln in lines)
            if not covered and leaf not in NOT_A_CREDENTIAL_FIELD and (addr, leaf) not in NOT_A_CREDENTIAL_AT:
                out.append(f"{addr} {f}")
    return out


def test_every_credential_the_vendor_schema_declares_is_withheld_or_named():
    """scripts/secret_returns.py writes the candidates from the published api-viewer; the record
    must answer each one. pdm's node-status keys and an answer file's subscription-key were the
    two a hand pass missed (lens 1, 2026-09-24)."""
    vendor = json.loads(VENDOR.read_text())
    assert len(vendor) >= 50, f"{len(vendor)} candidate addresses: the fixture has gone thin"
    assert not _uncovered(vendor), _uncovered(vendor)


def test_the_vendor_guard_sees_a_credential_it_was_never_shown():
    planted = {"pmg:GET /config/planted": ["[]password"], "pdm:GET /subscriptions/node-status": ["[]current-key"],
               "pve:POST /planted/mint": ["value"], "pve:POST /access/ticket": ["ticket"]}    # the last is HELD
    assert _uncovered(planted) == ["pmg:GET /config/planted []password", "pve:POST /planted/mint value"]


# ---- the loader fails closed -------------------------------------------------------------------

@pytest.mark.parametrize("body,match", [
    (None, "cannot be read"),
    (b"[secret]\n\"pve:GET /x\" = { drop = [\"a\"] }\n\"pve:GET /x\" = { drop = [\"b\"] }\n", "cannot be read"),
    (b"[secret]\n\"pve:GET /nodes/{node}/subscription\" = { drop = [\"key\"], why = \"\" }\n", "without a why"),
    (b"[secret]\n\"pve:GET /nodes/{node}/subscription\" = { why = \"the key\" }\n", "without a why or a field"),
    (b"[secret]\n\"pmg:GET /quarantine/link\" = { bearer = \"yes\", why = \"a link\" }\n", "without a why or a field"),
    (b"[other]\n", "non-empty table"),
])
def test_a_record_that_cannot_be_read_refuses_by_name(monkeypatch, body, match):
    class _File:
        def joinpath(self, _name):
            return self

        def read_bytes(self):
            if body is None:
                raise FileNotFoundError("secrets.toml")
            return body

    monkeypatch.setattr(engine.resources, "files", lambda _pkg: _File())
    engine._secrets.cache_clear()
    try:
        with pytest.raises(ProximoError, match=match):
            engine._secrets()
    finally:
        engine._secrets.cache_clear()


def test_a_line_for_an_address_the_door_never_serves_is_refused(monkeypatch):
    engine._secrets.cache_clear()
    monkeypatch.setattr(engine, "_secrets",
                        lambda: {"pmg:GET /config/ldap/{section}/config": (frozenset({"bindpw"}), frozenset())})
    with pytest.raises(ProximoError, match="match no address the door answers"):
        engine._refuse_inert_secrets(dict(engine.table()))


# ---- the behaviour, on both doors --------------------------------------------------------------

@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None
    audit_keyed: bool = True


class _Wire:
    def __init__(self, body):
        self.body, self.calls = body, []

    def call(self, method, path, params=None):
        self.calls.append((method, path))
        return json.loads(json.dumps(self.body))


PBS_REMOTES = [{"remote": "offsite", "server": "pbs.example", "datastore": "main",
                "password": "hunter2", "encryption-key": "ENCKEY", "master-pubkey": "PUB"}]


@pytest.fixture
def cfg(tmp_path):
    return _Cfg("pmg", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                audit_log_path=str(tmp_path / "audit.log"))


def test_the_governed_door_withholds_the_fields_and_says_which(monkeypatch, cfg):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(PBS_REMOTES))
    row = engine.resolve("pmg", "GET", "/nodes/{node}/pbs")
    out = engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pmg1/pbs")
    assert out["data"] == [{"remote": "offsite", "server": "pbs.example", "datastore": "main",
                            "master-pubkey": "PUB"}]
    assert out["withheld"] == ["encryption-key", "password"]
    assert "hunter2" not in json.dumps(out) and "ENCKEY" not in json.dumps(out)


def test_the_control_an_unrecorded_read_passes_every_byte(monkeypatch, cfg):
    """The same bytes on an address the record does not name come back whole, no `withheld`:
    the rule is the record, not a name heuristic."""
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(PBS_REMOTES))
    row = engine.resolve("pmg", "GET", "/nodes/{node}/status")
    out = engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pmg1/status")
    assert out["data"] == PBS_REMOTES and "withheld" not in out


LINK = "https://pmg.example:8006/quarantine?ticket=PMGQUAR%3Aalice%3ASECRET"


def test_a_bearer_read_is_served_whole_and_says_it_is_a_credential(monkeypatch, cfg):
    """0.44's pmg_quarantine_link_get told the model, in its docstring, that the link is a
    password. The door has no docstring per address; the record carries the sentence and the
    envelope says it, on both doors. The link itself is the answer, so it is not withheld."""
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(LINK))
    row = engine.resolve("pmg", "GET", "/quarantine/link")
    out = engine.execute(row, {"mail": "alice@example"}, cfg=cfg, ledger_cfg=cfg, path="/quarantine/link")
    assert out["data"] == LINK
    assert "bearer credential" in out["bearer_credential"] and "password" in out["bearer_credential"]
    assert "SECRET" not in pathlib.Path(cfg.audit_log_path).read_text()   # the ledger never holds it


def test_a_bearer_value_never_reaches_a_receipt_raw():
    """The ledger's scrub, not only the envelope: an UNDO capture or a mutation's args under a
    bearer line are fingerprinted whole (lens 2026-09-28: `ledgered` read only drop and userinfo)."""
    rule = engine.secret_rule(engine.resolve("pmg", "GET", "/quarantine/link"))
    assert rule[4]
    assert engine.ledgered(LINK, rule=rule).startswith("[redacted sha256:")
    assert "SECRET" not in json.dumps(engine.ledgered({"link": LINK, "mail": "a@b"}, rule=rule))
    assert engine.ledgered(LINK) == LINK            # the control: no line, no fingerprint


def test_an_own_line_merges_with_the_read_twins_never_replaces_it(monkeypatch):
    """Lens 2 N1: an own bearer line replaced the twin's `password` drop wholesale. The rule is
    the union: the twin's drops still withhold a mutation's echo, bearer comes from the own line."""
    row = engine.resolve("pbs", "PUT", "/config/remote/{name}")
    twin = engine._secrets()["pbs:GET /config/remote/{name}"]
    assert "password" in twin[0] and engine.secret_rule(row) == twin        # no own line: the twin's
    own = {**engine._secrets(), row.key: (frozenset(), frozenset(), frozenset(), False, "a credential")}
    monkeypatch.setattr(engine, "_secrets", lambda: own)
    merged = engine.secret_rule(row)
    assert "password" in merged[0] and merged[4] == "a credential"
    out = engine._envelope(row, row.path, {"host": "h", "password": "HUNTER2"})
    assert out["withheld"] == ["password"] and "HUNTER2" not in repr(out) and out["bearer_credential"]


def test_the_control_no_other_read_claims_to_be_a_credential(monkeypatch, cfg):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(LINK))
    row = engine.resolve("pmg", "GET", "/nodes/{node}/status")
    out = engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pmg1/status")
    assert "bearer_credential" not in out
    # the one bearer READ; a token mint's own line (a mutation) is the other bearer shape, pinned
    # in tests/test_arena.py
    assert [k for k, v in _record().items() if v.get("bearer") and ":GET " in k] == ["pmg:GET /quarantine/link"]


def test_userinfo_is_masked_to_the_host_and_named(monkeypatch, cfg):
    body = {"http-proxy": "proxyuser:p@ss@proxy.example:3128", "email-from": "a@b"}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(body))
    row = engine.resolve("pbs", "GET", "/nodes/{node}/config")
    out = engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/nodes/pbs1/config")
    assert out["data"] == {"http-proxy": "[redacted]@proxy.example:3128", "email-from": "a@b"}
    assert out["withheld"] == ["http-proxy"]


def test_a_nested_field_is_withheld_at_any_depth():
    data, withheld = engine.withhold("pve:GET /cluster/sdn/fabrics/all",
                                     {"fabrics": [{"id": "f1", "lock-token": "L"}], "nodes": [{"lock-token": "M"}]})
    assert data == {"fabrics": [{"id": "f1"}], "nodes": [{}]} and withheld == ["lock-token"]


def test_the_ledger_fingerprints_the_record_fields_a_name_rule_cannot_see(monkeypatch, cfg):
    """A mutation's UNDO read-back and its arguments land in the ledger, which audit_entries
    hands the model. An ACME plugin's `data` is its DNS provider's API keys and is named like
    nothing secret: the name rule passed it raw on both halves until the record reached them."""
    from proximo.core import arm as ag
    monkeypatch.setattr(ag, "arm_state", lambda cfg=None: ag.ArmGateState(True, True, None))
    assert engine.ledgered({"data": "CF_Token=OLD"}) == {"data": "CF_Token=OLD"}   # the name rule alone
    before = {"plugin": "cf", "api": "cf", "data": "CF_Token=OLD"}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(before))
    row = engine.Row(**{**engine.resolve("pmg", "PUT", "/config/acme/plugins/{id}").__dict__, "tier": "restorable"})
    engine.execute(row, {"data": "CF_Token=NEW", "validation-delay": 30}, cfg=cfg, ledger_cfg=cfg,
                   path="/config/acme/plugins/cf")
    rows = [json.loads(line) for line in open(cfg.audit_log_path)]
    ledger = json.dumps(rows)
    assert "CF_Token" not in ledger
    undo = next(r for r in rows if r["action"] == "core.undo_point")["detail"]["before"]
    args = next(r for r in rows if r["outcome"] == "executing")["detail"]["args"]
    assert undo["api"] == "cf" and undo["data"].startswith("[redacted sha256:")   # the before-image IS there
    assert args["validation-delay"] == 30 and args["data"].startswith("[redacted sha256:")


def test_a_key_value_row_is_withheld_by_its_option_name():
    rows = [{"key": "cores", "value": "4"}, {"key": "cipassword", "value": "S3cr3t", "pending": "N3w"}]
    data, withheld = engine.withhold("pve:GET /nodes/{node}/qemu/{vmid}/pending", rows)
    assert data == [{"key": "cores", "value": "4"},
                    {"key": "cipassword", "value": "[withheld]", "pending": "[withheld]"}]
    assert withheld == ["cipassword"]
    assert engine.withhold("pve:GET /nodes/{node}/status", rows) == (rows, [])   # the control: no line, no change


def test_the_rendered_cloud_init_hides_its_password_lines_and_keeps_the_rest():
    body = ("#cloud-config\nuser: admin\npassword: S3cr3t\nchpasswd:\n  expire: False\n"
            "ssh_authorized_keys:\n  - ssh-ed25519 AAAA\n")
    data, withheld = engine.withhold("pve:GET /nodes/{node}/qemu/{vmid}/cloudinit/dump", body)
    assert "S3cr3t" not in data and "password: [withheld]" in data and withheld == ["password"]
    assert data.replace("password: [withheld]", "password: S3cr3t") == body


def test_a_mutation_that_echoes_its_resource_is_withheld_by_its_read(monkeypatch, tmp_path):
    """PBS's PUT of an OpenID realm returns the realm config, client-key included (lens 1): the
    mutation's own response goes through its READ's line."""
    from proximo.core import arm as ag
    monkeypatch.setattr(ag, "arm_state", lambda cfg=None: ag.ArmGateState(True, True, None))
    cfg = _Cfg("pbs", "https://unreachable.invalid:8007/api2/json", "/dev/null",
               audit_log_path=str(tmp_path / "audit.log"))
    echo = {"realm": "corp", "client-id": "proximo", "client-key": "OIDC-SECRET"}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(echo))
    put = engine.resolve("pbs", "PUT", "/config/access/openid/{realm}")
    row = engine.Row(**{**put.__dict__, "tier": "disruptive"})
    out = engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path="/config/access/openid/corp")
    assert out["data"] == {"realm": "corp", "client-id": "proximo"} and out["withheld"] == ["client-key"]
    assert "OIDC-SECRET" not in json.dumps(out) and "OIDC-SECRET" not in open(cfg.audit_log_path).read()


# ---- the ledger's masker, split at the LAST @ --------------------------------------------------

@pytest.mark.parametrize("text,want", [
    ("http://user:p@ss@host:3128/x", "http://[redacted]@host:3128/x"),
    ("user:pw@host:3128", "[redacted]@host:3128"),
    ("alice@pam", "alice@pam"),
    ("https://host/path@x", "https://host/path@x"),
])
def test_mask_userinfo_splits_at_the_last_at(text, want):
    assert engine._mask_userinfo(text) == want
