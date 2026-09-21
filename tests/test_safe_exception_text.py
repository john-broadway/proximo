"""safe_exception_text — exception text that can be handed to a model.

THE LEAK THIS CLOSES. httpx builds its error message from the REQUEST URL, so on this
product `str(exc)` reads:

    Client error '403 Forbidden' for url 'https://<internal-ip>:8006/api2/json/nodes/...'

Any tool that formats `f"{type(e).__name__}: {e}"` into a response therefore hands the
caller the estate's internal address. `redact()` does not catch it: that function hides
REGISTERED SECRET LITERALS and four auth-header shapes, and an internal IP is neither.

NOT NOVEL TO ONE FILE. The same `type(e).__name__: {e}` shape appears across the tree
(diagnose, memory, network, ceph, file_restore, pmg_node, pmg_welcomelist, wiki, vectors).
This helper lives in the scrubbing module rather than in its first caller so the class has
one place to be fixed, not ten.

WHY NOT JUST THE TYPE NAME. `_audited_run` drops the message entirely, which is right for a
durable log nobody reads under pressure. A model answering "why could you not read this
storage?" needs `403 Forbidden` to say something useful. So the locator is removed and the
reason is kept.
"""
from __future__ import annotations

import httpx

from proximo._secretfile import register_secret, safe_exception_text


# Fixture addresses are RFC 5737 TEST-NET-1 (192.0.2.0/24) and RFC 2606 (.invalid), both reserved for documentation.
# An RFC1918 literal here would be flagged by the repo's own leak audit -- which it was, on the
# first run of these very tests. A test that proves we do not leak addresses should not ship an
# address shape the audit has to forgive.
def _real_http_error(url: str) -> httpx.HTTPStatusError:
    """A genuine httpx error, raised the way httpx raises it (NOT hand-written).

    Constructing HTTPStatusError with a message of our own would test our own string, not
    httpx's, and httpx's is the thing that leaks.
    """
    req = httpx.Request("GET", url)
    try:
        httpx.Response(403, request=req).raise_for_status()
    except httpx.HTTPStatusError as exc:
        return exc
    raise AssertionError("raise_for_status did not raise")


def test_the_internal_address_does_not_survive():
    exc = _real_http_error("https://192.0.2.10:8006/api2/json/nodes/n1/storage/lab/status")
    assert "192.0.2.10" not in (out := safe_exception_text(exc))
    assert "8006" not in out


def test_the_path_does_not_survive():
    exc = _real_http_error("https://192.0.2.10:8006/api2/json/nodes/n1/storage/lab/status")
    assert "/api2/json/" not in safe_exception_text(exc)


def test_the_control_proves_the_fixture_actually_leaks():
    """PLANTED CONTROL. If httpx ever stops embedding the URL, these tests would pass for
    the wrong reason and this one goes red to say so."""
    exc = _real_http_error("https://192.0.2.10:8006/api2/json/nodes/n1/storage/lab/status")
    assert "192.0.2.10:8006" in str(exc), "fixture no longer reproduces the leak"


def test_the_actionable_reason_is_kept():
    out = safe_exception_text(_real_http_error("https://192.0.2.10:8006/x"))
    assert "403" in out and "Forbidden" in out


def test_the_type_is_named():
    assert safe_exception_text(_real_http_error("https://192.0.2.10:8006/x")).startswith(
        "HTTPStatusError")


def test_a_hostname_url_is_scrubbed_too():
    """Not only dotted quads: an internal FQDN is topology just the same."""
    out = safe_exception_text(_real_http_error("https://pve-01.example.invalid:8006/x"))
    assert "pve-01" not in out and "example.invalid" not in out


def test_a_registered_secret_is_still_redacted():
    register_secret("supersecrettokenvalue")
    assert "supersecrettokenvalue" not in safe_exception_text(
        RuntimeError("auth failed for supersecrettokenvalue"))


def test_a_plain_exception_keeps_its_message():
    assert "storage is offline" in safe_exception_text(RuntimeError("storage is offline"))


def test_bare_host_port_is_scrubbed():
    assert "192.0.2.10" not in safe_exception_text(
        OSError("connection refused to 192.0.2.10:8006"))


def test_output_is_bounded():
    assert len(safe_exception_text(RuntimeError("x" * 5000))) <= 400


def test_no_exception_text_is_not_a_crash():
    assert safe_exception_text(RuntimeError()) == "RuntimeError"
