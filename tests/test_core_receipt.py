"""The doctor's receipt: ONE pasteable, estate-redacted artifact with a fingerprint, and nothing sent.

A doctor report is made of what an operator must not publish (hosts, nodes, guests, storage,
addresses, users, token ids, paths). The tests that matter are not about formatting: the module
cannot reach the network, every planted identifier of every kind is gone from the rendered text
(and the same report is a control that proves the test could see them), and the diagnosis
survives. Fixtures are reserved documentation values (RFC 5737 / 3849, the `.invalid` and
`.example` TLDs), never an address from a real estate.
"""
from __future__ import annotations

import ast
import copy
import inspect
import json
import pathlib

import pytest

from proximo.core import doctor, receipt
from proximo.core.doors import cli

# One identifier of every kind a support thread must not carry. Each is asserted ABSENT from
# the output and PRESENT in the unredacted report (the control).
PLANTED = {
    "hostname": "gw-lab7.zq.invalid",
    "bare host label": "gw-lab7",
    "node name": "hv-zq",
    "guest id": "4711",
    "guest name": "web-zq",
    "storage name": "tank-zq",
    "ipv4": "192.0.2.44",
    "cidr": "198.51.100.0/24",
    "ipv6": "2001:db8::7",
    "url": "https://gw-lab7.zq.invalid:8006/api2/json",
    "username": "ops@corp.example",
    "realm user": "ops@pve",
    "token id": "ops@pve!proximo-write",
    "target name": "east-annex",
    "secret file": "/srv/secrets/zq-pmg.cred",
    "path in prose": "/srv/secrets/zq-audit.key",
    "cert fingerprint": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
    "uuid": "123e4567-e89b-12d3-a456-426614174000",
}


def _report() -> dict:
    """The doctor's own shape (core/doctor.py `run`), with the estate planted in every place it
    could ride: structured fields, ACL path samples, vendor error text and the flags."""
    return {
        "doctor": "proximo-core",
        "record": {"rows": 1580, "mutations": 612, "tiered": 592, "held": 20, "creates": 5, "untrusted": 40},
        "planes": {
            "pve": {"configured": True, "base_url": PLANTED["url"], "verify_tls": True,
                    "fingerprint_pinned": True, "tls_strict": True,
                    "arm": {"enforced": True, "armed": False, "reason": "not armed"},
                    "reach": {"version": "9.2.2",
                              "permissions": {"paths": 3, "sample": ["/", "/vms/4711", "/storage/tank-zq",
                                                                     "/nodes/hv-zq"]}}},
            "pbs": {"configured": False, "missing": ["PROXIMO_PBS_BASE_URL", "PROXIMO_PBS_TOKEN_PATH"]},
            "pmg": {"configured": True, "credential_file": PLANTED["secret file"],
                    "reach": {"version": {"error": "unreachable", "tls": "pin mismatch",
                                          "observed": PLANTED["cert fingerprint"], "pinned": PLANTED["uuid"]}}},
        },
        "guests": [{"vmid": 4711, "name": "web-zq"}],
        "targets": {"configured": True, "count": 1, "names": [PLANTED["target name"]]},
        "ledger": {"keyed": True, "mode": "keyed", "key_readable": True, "rows": 31, "chain": "ok",
                   "in_flight": 0},
        "pillars": {"PLAN": {"standing": True}, "PROVE": {"standing": True},
                    "CONSENT": {"standing": False}, "CONTAIN": {"standing": False}},
        "retired": [],
        "flags": [
            "pmg: no reach: GET /version failed (connect to 192.0.2.44 and 2001:db8::7, "
            "net 198.51.100.0/24, host gw-lab7.zq.invalid, as ops@pve!proximo-write)",
            f"guest {PLANTED['guest name']} (vmid {PLANTED['guest id']}) on {PLANTED['node name']} "
            f"in storage {PLANTED['storage name']} is read by {PLANTED['username']} and {PLANTED['realm user']}",
            "the audit key cannot be read (/srv/secrets/zq-audit.key); GET /access/permissions failed",
            "CONSENT is inert: a plan says so, and any armed caller may mutate without a second party",
        ],
        "complete": False,
    }


def _render(report=None, **kw) -> str:
    return receipt.render(_report() if report is None else report, version="0.48.1",
                          generated_at="2026-10-25T00:00:00Z", **kw)


# --- the control: the planted report really carries every identifier ----------------------------

def test_the_planted_report_carries_every_identifier_unredacted():
    raw = json.dumps(_report())
    for kind, value in PLANTED.items():
        assert value in raw, f"the fixture does not carry the {kind}; the test below would prove nothing"


# --- nothing transmits ---------------------------------------------------------------------------

#: A receipt is built from the report in hand with the standard library's text tools alone.
ALLOWED_IMPORTS = {"__future__", "hashlib", "json", "re", "typing"}


def test_the_module_imports_no_network_no_process_no_filesystem():
    """Read the real import statements (the AST), not the text: a docstring that says it imports
    no subprocess must not fail this, and `import subprocess` inside a string must not pass it.
    Stated positively: only these names may ever appear."""
    tree = ast.parse(pathlib.Path(receipt.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= ALLOWED_IMPORTS, f"receipt.py reached for {sorted(imported - ALLOWED_IMPORTS)}"
    assert "re" in imported and "hashlib" in imported, "the probe read nothing"


def test_render_takes_no_handle_to_anything():
    params = inspect.signature(receipt.render).parameters
    for banned in ("api", "transport", "client", "session", "cfg", "plane"):
        assert banned not in params


# --- the allowlist: every kind of identifier is gone ----------------------------------------------

@pytest.mark.parametrize("kind", sorted(PLANTED))
def test_each_kind_of_estate_identifier_is_gone_from_the_receipt(kind):
    assert PLANTED[kind] not in _render(), f"the {kind} survived into the receipt"


def test_no_planted_identifier_survives_in_any_case():
    body = _render().lower()
    for kind, value in PLANTED.items():
        assert value.lower() not in body, kind


def test_a_key_the_schema_does_not_name_is_dropped_with_its_value():
    """A pool, a node, a user under any key at any depth: the schema lists what may appear and
    nothing else gets in, whatever it looks like. Two earlier misses were exactly this."""
    rep = {"pool": "tank-zq", "pools": ["mail"], "node": "mail", "nodes": [{"node": "hv-zq", "vmid": 102}],
           "cluster": "office", "planes": {"pve": {"configured": True, "node": "hv-zq", "pool": "mail",
                                                   "storage": "tank-zq", "token": "ops@pve!x"}},
           "ledger": {"rows": 3, "ledger": "/var/zq/audit.log", "user": "alice"}}
    out = receipt.redact_structure(rep)
    assert out == {"planes": {"pve": {"configured": True}}, "ledger": {"rows": 3}}


def test_an_unknown_plane_pillar_or_lane_name_is_dropped():
    rep = {"planes": {"pve": {"configured": True}, "east-annex": {"configured": True}},
           "pillars": {"PLAN": {"standing": True}, "zq-pillar": {"standing": True},
                       "DIAGNOSE": {"lanes": {"agent": {"open": True}, "zq-lane": {"open": True}}}}}
    out = receipt.redact_structure(rep)
    assert set(out["planes"]) == {"pve"} and set(out["pillars"]) == {"PLAN", "DIAGNOSE"}
    assert set(out["pillars"]["DIAGNOSE"]["lanes"]) == {"agent"}


def test_a_value_of_the_wrong_kind_is_not_shown():
    rep = {"record": {"rows": "alice-zq", "mutations": True},
           "ledger": {"mode": "acme-mode", "chain": "broken at 7: acme"},
           "planes": {"pve": {"configured": "yes-zq", "reach": {"version": "9.2.2-acme.zq"}}}}
    out = json.dumps(receipt.redact_structure(rep))
    assert "alice" not in out and "acme-mode" not in out and "acme" not in out and "yes-zq" not in out
    assert receipt.redact_structure(rep)["ledger"]["chain"] == "broken"


def test_free_text_becomes_a_placeholder_and_its_presence_is_kept():
    out = receipt.redact_structure({
        "targets": {"error": "PROXIMO_TARGETS: target 'east-annex' has unknown kind"},
        "pillars": {"CONTAIN": {"trip": {"tripped": True, "reason": "alice: hv-zq on fire"}}}})
    assert out["targets"]["error"] == "[text]"
    assert out["pillars"]["CONTAIN"]["trip"] == {"tripped": True, "reason": "[text]"}


def test_the_missing_env_var_names_are_the_diagnosis_and_stay_but_only_as_env_names():
    out = receipt.redact_structure({"planes": {"pbs": {"configured": False,
                                                       "missing": ["PROXIMO_PBS_BASE_URL", "east-annex-zq"]}}})
    assert out["planes"]["pbs"]["missing"] == ["PROXIMO_PBS_BASE_URL", "[text]"]


def test_the_vocabularies_are_held_to_the_core():
    from proximo.core import spine, wire
    assert receipt.LANES == frozenset(spine._LANES)
    assert receipt.PRODUCTS == frozenset(wire.PRODUCTS)


# --- flags are codes: the fixed head only, whatever the doctor interpolated ----------------------

def test_a_flag_is_rendered_by_its_code_and_none_of_its_tail():
    sentence = "pmg: no reach: GET /version failed (ConnectError for acme.cloud); check base URL"
    assert receipt.flag_code(sentence) == "no-reach:pmg"
    tripped = "CONTAIN is tripped: every mutation is refused (alice: hv-zq on fire)"
    assert receipt.flag_code(tripped) == "contain-tripped"
    assert receipt.flag_code("the target registry is set and unreadable: target 'east-annex' has unknown kind") \
        == "registry-unreadable"
    assert receipt.flag_code("guest web-zq is on fire") == "unrecognised"
    assert receipt.flag_code(["not", "a", "string"]) == "unrecognised"


def test_every_flag_the_live_doctor_writes_has_a_code():
    """Run against the doctor's own words, not a copy typed here: the source's flag f-strings."""
    import pathlib
    import re
    src = pathlib.Path(doctor.__file__).read_text(encoding="utf-8")
    heads = set()
    for m in re.finditer(r"flags(?:\.append\(| \+= \[)\s*\(?\s*f?\"([^\"{]{6,})", src):
        heads.add(m.group(1))
    assert len(heads) >= 15, heads
    unknown = sorted(h for h in heads if receipt.flag_code(h.replace("{product}", "pve")) == "unrecognised"
                     and not h.startswith(("{", " ")))
    assert not unknown, unknown


# --- the second line: patterns over what the allowlist let through -------------------------------

def test_a_url_is_redacted_whole_not_mangled():
    out = receipt.redact("api_base_url: https://192.0.2.10:8006/api2/json")
    assert "192.0.2.10" not in out and "8006" not in out and "api2" not in out and "]]" not in out


def test_a_url_is_one_marker():
    assert receipt.redact("https://zq.example:8006/x?y=1") == "[redacted-url]"


def test_the_url_host_is_scrubbed_inside_prose_and_after_punctuation():
    for text in ("see (https://zq.example/x) now", "u=https://zq.example", "at:https://zq.test:8006/"):
        assert "zq" not in receipt.redact(text), text


@pytest.mark.parametrize("name", ["acme.cloud", "hv.acme.co.uk", "node1.acme.dev", "a.b.c.d.example",
                                  "mail.acme.xyz", "ACME.IO"])
def test_any_dotted_name_with_an_alphabetic_last_label_is_a_host(name):
    out = receipt.redact(f"failed to reach {name} twice")
    assert "[redacted-host]" in out and "twice" in out and name.lower() not in out.lower()


@pytest.mark.parametrize("text", ["path=/srv/zq/key", "file:/srv/zq/key", "(/srv/zq/key)", "zq/rel/key", "./zq/key",
                                  "C:\\Users\\zq\\key.pem", "\\\\fileserver\\zq\\share", "k=/zq"])
def test_paths_in_any_spelling_are_redacted(text):
    assert "zq" not in receipt.redact(text), text


def test_a_slash_alone_and_a_version_are_not_paths_or_hosts():
    assert receipt.redact("version 9.2.2 and 1.1.4-2") == "version 9.2.2 and 1.1.4-2"
    assert receipt.redact("a / b") == "a / b"


def test_a_base64_or_long_token_is_a_secret():
    for blob in ("c2VjcmV0LXRva2VuLWJ5dGVzLWFyZS1oZXJlLXp6enp6enp6", "A" * 40 + "==", "sk_live_" + "x" * 30):
        assert blob not in receipt.redact(f"token {blob} end"), blob


def test_the_scrub_is_linear_on_a_dotted_blob():
    import time
    for blob in ("a." * 20000, "a" * 40000, "/" * 40000, "a@" * 20000, "1:" * 20000):
        t0 = time.perf_counter()
        receipt.redact(blob)
        assert time.perf_counter() - t0 < 2.0, blob[:4]


def test_denylist_treats_dash_dot_underscore_as_separators_but_not_letters():
    deny = receipt.compile_denylist(["acme"])
    for hit in ("acme-prod", "prod-acme", "acme.prod", "acme_prod", "prod_acme", "ACME", "(acme)"):
        assert "acme" not in receipt.redact(f"on {hit} now", deny).lower(), hit
    for keep in ("acmetool", "myacme", "acme2", "2acme"):
        assert keep in receipt.redact(f"on {keep} now", deny), keep


def test_denylist_reaches_the_header_and_empty_is_inert():
    deny = receipt.compile_denylist(["acme"])
    assert "acme" not in receipt.render({}, version="acme-1", generated_at="t", deny=deny)
    assert receipt.compile_denylist([" ", ""]) is None


# --- the diagnosis survives (an artifact redacted into uselessness helps nobody) -----------------

def test_versions_counts_pillars_and_flag_codes_survive():
    body = _render()
    for kept in ("9.2.2", "1580", "612", "592", "PLAN", "CONSENT", "CONTAIN", "standing: True",
                 "standing: False", "consent-inert", "no-reach:pmg", "audit-key-unreadable", "0.48.1",
                 "pin mismatch", "PROXIMO_PBS_BASE_URL", "unrecognised"):
        assert kept in body, f"the receipt dropped the diagnosis: {kept!r}"


def test_the_pins_and_counts_the_doctor_reports_stay_numbers():
    out = receipt.redact_structure({"ledger": {"rows": 31, "in_flight": 0}, "targets": {"count": 2},
                                    "planes": {"pve": {"reach": {"permissions": {"paths": 9, "sample": ["/vms/1"]}}}}})
    assert out["ledger"] == {"rows": 31, "in_flight": 0} and out["targets"] == {"count": 2}
    assert out["planes"]["pve"]["reach"]["permissions"] == {"paths": 9}


# --- the fingerprint: the defect's shape, nothing else -------------------------------------------

def test_the_same_defect_on_two_different_estates_has_one_fingerprint():
    """Every name, count and version differs between the two estates; the defect does not."""
    swap = {"gw-lab7.zq.invalid": "other.zq.invalid", "gw-lab7": "other", "hv-zq": "hv-b", "4711": "9021",
            "web-zq": "db-b", "tank-zq": "pool-b", "192.0.2.44": "192.0.2.99", "east-annex": "west-annex"}
    raw = json.dumps(_report())
    for old, new in swap.items():
        raw = raw.replace(old, new)
    b = json.loads(raw)
    b["record"]["rows"] = 7
    b["planes"]["pve"]["reach"]["version"] = "8.4.1"
    b["ledger"]["rows"] = 999
    assert b != _report() and "hv-zq" not in raw
    assert receipt.fingerprint(_report()) == receipt.fingerprint(b)


def test_the_fingerprint_moves_when_a_pillar_or_a_flag_moves():
    a = _report()
    b = copy.deepcopy(a)
    b["pillars"]["CONSENT"]["standing"] = True
    c = copy.deepcopy(a)
    c["flags"].append("UNDO is off: no mutation captures a before-state")
    assert len({receipt.fingerprint(a), receipt.fingerprint(b), receipt.fingerprint(c)}) == 3


def test_counts_and_versions_do_not_move_the_fingerprint():
    a = _report()
    b = copy.deepcopy(a)
    b["record"]["rows"] += 1
    b["planes"]["pve"]["reach"]["version"] = "9.9.9"
    assert receipt.fingerprint(a) == receipt.fingerprint(b)


def test_the_header_fingerprint_is_the_shape_hash():
    assert f"fingerprint  {receipt.fingerprint(_report())}" in _render()
    assert len(receipt.fingerprint(_report())) == 12


# --- where it can go, and the human's choice -----------------------------------------------------

def test_the_receipt_names_where_it_can_go_and_says_nothing_was_sent():
    body = _render()
    assert receipt.WHERE in body, "the redactor ate the destination"
    assert "github.com" in body
    assert "nothing was transmitted" in body.lower()


def test_the_issue_template_it_names_is_tracked():
    import subprocess
    repo = pathlib.Path(__file__).resolve().parents[1]
    name = receipt.WHERE.rsplit("template=", 1)[1]
    rel = f".github/ISSUE_TEMPLATE/{name}"
    done = subprocess.run(["git", "ls-files", "--error-unmatch", rel], cwd=repo,  # noqa: S603, S607
                          capture_output=True, text=True, check=False)
    if done.returncode != 0 and not (repo / ".git").exists():
        pytest.skip("not a git checkout")
    assert (repo / rel).is_file(), f"{rel} does not exist: every receipt would point at a 404"


# --- the verb: `proximo-core doctor --receipt` ---------------------------------------------------

def test_the_verb_prints_the_receipt_and_keeps_the_doctors_exit(monkeypatch, capsys):
    report = {**_report(), "exit": 4}
    monkeypatch.setattr(doctor, "run", lambda *a, **k: dict(report))
    code = cli.doctor_main(["--receipt"])
    out = capsys.readouterr().out
    assert code == 4
    assert out.startswith("proximo receipt\n")
    for kind, value in PLANTED.items():
        assert value not in out, kind
    assert "9.2.2" in out and receipt.WHERE in out
    assert '"doctor"' not in out, "the JSON report leaked beside the receipt"


def test_the_verb_takes_a_denylist(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run", lambda *a, **k: {**_report(), "exit": 0})
    cli.doctor_main(["--receipt", "--deny", "boot-zq"])
    monkeypatch.setattr(doctor, "run", lambda *a, **k: {"flags": ["boot-zq failed"], "exit": 0})
    capsys.readouterr()
    cli.doctor_main(["--receipt", "--deny", "boot-zq"])
    assert "boot-zq" not in capsys.readouterr().out


def test_the_plain_doctor_is_unchanged_and_deny_alone_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run", lambda *a, **k: {**_report(), "exit": 0})
    assert cli.doctor_main([]) == 0
    assert json.loads(capsys.readouterr().out)["doctor"] == "proximo-core"
    assert cli.doctor_main(["--deny", "x"]) == cli.EXIT_USAGE
    assert cli.doctor_main(["--bogus"]) == cli.EXIT_USAGE
    assert cli.doctor_main(["--receipt", "--deny"]) == cli.EXIT_USAGE


def test_the_real_doctor_through_the_verb_leaks_nothing(monkeypatch, capsys, tmp_path):
    """Not a planted dict: the live `doctor.run` against a plane whose host and token path carry
    markers, its read answered by a stand-in wire that fails with the host in the text."""
    from proximo.core import engine
    tok = tmp_path / "zq-token-file"
    tok.write_text("zq-secret-bytes")
    tok.chmod(0o600)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://gw-lab7.zq.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    for var in ("PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL", "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)

    class Down:
        def call(self, method, path, params=None):
            raise RuntimeError("connect to gw-lab7.zq.invalid (192.0.2.44) failed as ops@pve!proximo-write")

    monkeypatch.setattr(engine, "_client", lambda product, c=None: Down())
    code = cli.doctor_main(["--receipt"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_VENDOR
    for leaked in ("gw-lab7", "192.0.2.44", "proximo-write", "zq-token-file", "zq-secret-bytes", str(tmp_path)):
        assert leaked not in out, leaked
    assert "proximo receipt" in out and "fingerprint" in out


# --- the fold after the second lens ---------------------------------------------------------------

@pytest.mark.parametrize("bare", ["zqmark", "ZQ-MARK", "zqmark.example", "9.2.2.zqmark", "192.168.1", "172.16.1",
                                  "10.1.2", "256.1.1", "999.1", "9"])
def test_a_version_that_is_not_a_vendor_version_renders_as_text(bare):
    out = receipt.redact_structure({"planes": {"pve": {"reach": {"version": bare}}}})
    assert out["planes"]["pve"]["reach"]["version"] == "[text]", bare


@pytest.mark.parametrize("real", ["9.2.2", "8.4", "3.4.1-2", "1.1.4", "0.9.1", "7.4-17"])
def test_a_vendor_version_survives(real):
    assert receipt.redact_structure({"planes": {"pbs": {"reach": {"version": real}}}}
                                    )["planes"]["pbs"]["reach"]["version"] == real


def test_the_header_clock_and_version_render_intact():
    body = receipt.render({}, version="0.48.1", generated_at="2026-10-25T17:38:43Z")
    assert "generated    2026-10-25T17:38:43Z\n" in body and "version      0.48.1\n" in body


def test_a_header_value_that_is_not_a_clock_or_a_version_is_still_scrubbed():
    body = receipt.render({}, version="gw-lab7.zq.invalid", generated_at="ops@pve!tok 192.0.2.44")
    assert "gw-lab7" not in body and "ops@pve" not in body and "192.0.2.44" not in body


def test_a_pmg_either_or_missing_pair_keeps_both_env_names():
    pair = "PROXIMO_PMG_CREDENTIAL_PATH (or PROXIMO_PMG_PASSWORD_PATH)"
    out = receipt.redact_structure({"planes": {"pmg": {"configured": False, "missing": [pair]}}})
    assert out["planes"]["pmg"]["missing"] == [pair]
    for bad in ("PROXIMO_PMG_X (or east-annex)", "east-annex (or PROXIMO_PMG_X)", "PROXIMO_A (or PROXIMO_B) zq"):
        shown = receipt.redact_structure({"planes": {"pmg": {"missing": [bad]}}})
        assert shown["planes"]["pmg"]["missing"] == ["[text]"]


def test_the_second_line_catches_what_a_loose_first_line_lets_through(monkeypatch):
    """The allowlist makes the pattern scrub look redundant; this plants a schema that trusts a
    string field, and only the second line stands between it and the page. Without the scrub this
    is red (checked by neutering `_second_line`)."""
    monkeypatch.setitem(receipt.SCHEMA, "targets", {"error": lambda v: v})
    leaky = "reach https://zq.example/x as ops@pve!tok at 192.0.2.44 via /srv/zq/key and gw-lab7.zq.invalid"
    body = receipt.render({"targets": {"error": leaky}}, version="1.0", generated_at="t")
    for gone in ("zq.example", "ops@pve", "192.0.2.44", "/srv/zq", "gw-lab7"):
        assert gone not in body, gone
    assert "[redacted-" in body
