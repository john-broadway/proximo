"""Tests for src/proximo/_validate.py — the plane-neutral shared validators.

The per-module `_check_digest` aliases are exercised where they live (each plane's own
test file keeps its TestCheckDigest class against the module attribute the tools call);
this file pins the shared core itself, strict no-strip included.
"""

from __future__ import annotations

import pytest

from proximo._validate import DIGEST_RE, check_digest, redact_secrets
from proximo.backends import ProximoError


class TestCheckDigest:
    def test_none_passes_through(self):
        assert check_digest(None) is None

    def test_accepts_valid_sha256_hex(self):
        d = "0123456789abcdef" * 4
        assert check_digest(d) == d

    def test_rejects_wrong_length(self):
        with pytest.raises(ProximoError):
            check_digest("a" * 63)
        with pytest.raises(ProximoError):
            check_digest("a" * 65)

    def test_rejects_uppercase_hex(self):
        with pytest.raises(ProximoError):
            check_digest("A" * 64)

    def test_rejects_non_hex(self):
        with pytest.raises(ProximoError):
            check_digest("z" * 64)

    def test_rejects_trailing_newline_no_strip(self):
        # The load-bearing choice: strict no-strip. Stripping before matching would
        # re-admit the trailing newline the \Z anchor exists to refuse.
        with pytest.raises(ProximoError):
            check_digest("a" * 64 + "\n")

    def test_rejects_surrounding_whitespace(self):
        with pytest.raises(ProximoError):
            check_digest(" " + "a" * 64)
        with pytest.raises(ProximoError):
            check_digest("a" * 64 + " ")

    def test_regex_is_fullmatch_anchored(self):
        # \Z, not $ — $ would tolerate a trailing newline on its own.
        assert DIGEST_RE.pattern.endswith(r"\Z")


class TestRedactSecrets:
    def test_masks_only_the_named_keys(self):
        d = {"token": "s3cret", "host": "pbs.example"}
        assert redact_secrets(d, frozenset({"token"})) == {
            "token": "[redacted]",
            "host": "pbs.example",
        }

    def test_whole_value_swap_regardless_of_shape(self):
        # The contract the seven docstrings all stated: list-of-dicts secrets are swapped
        # whole, never partially redacted.
        d = {"secret": [{"name": "n", "value": "djNjcmV0"}]}
        assert redact_secrets(d, frozenset({"secret"}))["secret"] == "[redacted]"

    def test_does_not_mutate_the_input(self):
        d = {"password": "hunter-two"}
        redact_secrets(d, frozenset({"password"}))
        assert d["password"] == "hunter-two"

    def test_empty_keys_is_a_passthrough(self):
        d = {"token": "s3cret"}
        assert redact_secrets(d, frozenset()) == d


class TestModuleAliases:
    def test_all_eleven_modules_alias_the_shared_check(self):
        # The consolidation's whole point: one function, eleven doors. A module that
        # regrows its own copy silently forks the semantics again.
        import importlib

        for name in (
            "pbs_access",
            "pbs_acme",
            "pbs_admin",
            "pbs_metrics",
            "pbs_node",
            "pbs_notifications",
            "pbs_s3",
            "pbs_tape_config",
            "pbs_tape_jobs",
            "pbs_tape_media",
            "pmg_identity",
        ):
            mod = importlib.import_module(f"proximo.{name}")
            assert mod._check_digest is check_digest, f"{name} forked _check_digest"

    def test_pbs_apt_digest_aliases_the_shared_check(self):
        # The 12th copy, caught by the lens: PBS's APT digest is the standard strict
        # 64-hex ConfigDigest, not a divergent APT shape like PVE/PMG's.
        from proximo import pbs

        assert pbs._check_pbs_apt_digest is check_digest
