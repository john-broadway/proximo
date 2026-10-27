"""WHICH ARGUMENT NAMES THE DOOR FINGERPRINTS, as a decision (lens 5, 2026-10-26).

`engine._SECRET_NAME` hides a mutation's argument by its NAME. A name only sounds secret in places: `tokens` on
an ACL entry are token IDs (which token got the role), `sshkeys` are public keys, `limit-passive-requests` has
`pass` inside `passive`. `records/secrets.toml` carries the authored judgement, per address and with a why
(`public = [...]`); everything else the rule matches stays a fingerprint, in the model's plan, the operator's
view and the receipt alike. The list the rule still hides is PINNED here, so a new hide is a visible decision.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

from proximo.core import engine
from proximo.core.errors import ProximoError

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import build_proximo_json as bj  # noqa: E402

#: every mutation parameter name the door fingerprints, with the planes that publish it
HIDDEN = {
    "bindpw": ["pmg"], "cipassword": ["pve"], "client-key": ["pbs", "pdm", "pmg", "pve"], "command": ["pve"],
    "confirmation-password": ["pbs", "pve"], "content": ["pve"], "crypt_pass": ["pmg"],
    "data": ["pbs", "pdm", "pmg", "pve"], "decryption-keys": ["pbs"], "eab-hmac-key": ["pmg", "pve"],
    "eab-kid": ["pmg"], "eab_hmac_key": ["pbs", "pdm"], "encryption-key": ["pbs", "pmg", "pve"],
    "generate-password": ["pve"], "input-data": ["pve"], "key": ["pbs", "pdm", "pmg", "pve"],
    "keyring": ["pve"], "keys": ["pdm", "pmg", "pve"], "lock-token": ["pve"], "new-password": ["pbs"],
    "otel-headers": ["pve"], "otp": ["pmg", "pve"], "pass": ["pmg"], "password": ["pbs", "pdm", "pmg", "pve"],
    "root-password": ["pdm"], "root-password-hashed": ["pdm"], "secret": ["pbs", "pve"], "secret-key": ["pbs"],
    "sql": ["pve"], "subscription-key": ["pdm"], "token": ["pbs", "pdm", "pve"],
    "totp": ["pbs", "pdm", "pmg", "pve"], "value": ["pbs", "pdm", "pmg", "pve"],
}


def _hidden_names() -> dict[str, list[str]]:
    out: dict[str, set[str]] = {}
    for r in engine.table().values():
        if r.method == "GET":
            continue
        for n in r.params:
            if n not in r.arg_public and (n in r.arg_secrets or n in r.secret[0] or engine.name_looks_secret(n)):
                out.setdefault(n, set()).add(r.product)
    return {k: sorted(v) for k, v in sorted(out.items())}


def test_the_list_of_names_the_door_still_fingerprints_is_pinned():
    assert _hidden_names() == HIDDEN


@pytest.mark.parametrize("name", ["tokens", "authorized-tokens", "create-token", "delete-token", "regenerate-secret",
                                  "sshkeys", "root-ssh-keys", "access-key",
                                  "active-encryption-key", "associated-key", "certkey"])
def test_the_names_the_lens_found_are_shown_where_the_record_says_so(name):
    lines = [r for r in engine.table().values() if name in r.arg_public]
    assert lines, f"no address judges {name} public"
    for r in lines:
        assert name in r.params and r.method != "GET"
        assert engine.ledgered({name: "u@pve!t"}, rule=engine.arg_rule(r)) == {name: "u@pve!t"}
        # the same name on an address that does NOT judge it public is still fingerprinted when the rule matches
    other = next((r for r in engine.table().values() if name in r.params and r.method != "GET"
                  and name not in r.arg_public and engine.name_looks_secret(name)), None)
    if other is not None:
        assert engine.ledgered({name: "x"}, rule=engine.arg_rule(other))[name].startswith("[redacted sha256:")


def test_which_token_got_the_role_is_in_the_plan_the_receipt_and_the_operators_view(armed_plane, capsys):
    from proximo.core.doors import cli
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/access/acl").__dict__, "tier": "destructive"})
    args = {"path": "/", "roles": "Administrator", "tokens": "svc@pve!ci"}
    plan = engine.plan(row, args, "/access/acl", cfg=armed_plane)
    assert plan["arguments"]["tokens"] == "svc@pve!ci"
    assert engine.ledgered(args, rule=engine.arg_rule(row))["tokens"] == "svc@pve!ci"
    code = cli.main(["pve", "PUT", "/access/acl", "path=/", "roles=Administrator", "tokens=svc@pve!ci", "--plan"])
    assert code in (cli.EXIT_OK, cli.EXIT_REFUSED)
    assert json.loads(capsys.readouterr().out)["arguments"]["tokens"] == "svc@pve!ci"


def test_true_secrets_stay_fingerprinted_in_every_view(armed_plane, capsys):
    from proximo.core.doors import cli
    row = engine.Row(**{**engine.resolve("pve", "POST", "/access/users").__dict__, "tier": "destructive"})
    plan = engine.plan(row, {"userid": "bob@pve", "password": "hunter2hunter2"}, "/access/users", cfg=armed_plane)
    assert "hunter2" not in json.dumps(plan) and plan["arguments"]["password"].startswith("[redacted sha256:")
    assert engine.ledgered({"password": "hunter2"}, rule=engine.arg_rule(row))["password"].startswith("[redacted")
    cli.main(["pve", "POST", "/access/users", "userid=bob@pve", "password=hunter2hunter2", "--plan"])
    out = capsys.readouterr().out
    assert "hunter2" not in out and "[redacted sha256:" in out


@pytest.mark.parametrize(("name", "secret"), [
    ("pass", True), ("crypt_pass", True), ("root-pass", True), ("password", True), ("cipassword", True),
    ("passphrase", True), ("passwd", True), ("limit-passive-requests", False), ("bypass", False),
    ("compass", False), ("passive", False), ("pubkey", False), ("ssh-pubkeys", False), ("comment", False)])
def test_pass_is_matched_as_a_word_not_inside_another_word(name, secret):
    assert engine.name_looks_secret(name) is secret


def test_the_name_rule_is_ascii_only():
    assert engine.name_looks_secret("paｓsword") is False        # fullwidth `s`: not the word


def test_a_public_line_that_does_nothing_is_refused_by_the_build():
    rows = dict(engine.table())
    with pytest.raises(ProximoError, match="do nothing"):
        bj.refuse_inert_public(rows, {"pve:PUT /access/acl": ["comment"]})            # the rule never hid it
    with pytest.raises(ProximoError, match="do nothing"):
        bj.refuse_inert_public(rows, {"pve:PUT /access/acl": ["sshkeys"]})            # not a parameter there
    with pytest.raises(ProximoError, match="do nothing"):
        bj.refuse_inert_public(rows, {"pve:GET /version": ["tokens"]})                # not a live mutation
    bj.refuse_inert_public(rows, {"pve:PUT /access/acl": ["tokens"]})


def test_a_public_line_needs_names_and_a_why():
    base = '[secret]\n"pve:PUT /access/acl" = { public = ["tokens"] }\n'
    with pytest.raises(ProximoError, match="without a why"):
        bj.arg_public(base)
    assert bj.arg_public('[secret]\n"pve:PUT /access/acl" = { public = ["tokens"], public_why = "ids" }\n') == {
        "pve:PUT /access/acl": ["tokens"]}


def test_every_public_line_in_the_record_is_live_and_has_a_why():
    text = bj.read_inputs()[1]["secrets.toml"]
    public = bj.arg_public(text)
    assert public and all(isinstance(v, list) and v for v in public.values())
    bj.refuse_inert_public(dict(engine.table()), public)


def test_limit_passive_requests_is_not_hidden_by_the_rule_at_all():
    r = engine.resolve("pbs", "POST", "/config/s3")
    assert "limit-passive-requests" in r.params and not engine.name_looks_secret("limit-passive-requests")
    assert engine.ledgered({"limit-passive-requests": 5}, rule=engine.arg_rule(r)) == {"limit-passive-requests": 5}
