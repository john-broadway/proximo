"""The receipt: a pasteable artifact the OPERATOR chooses to share.

A Proxmox doctor report is *made of* the things an operator must not publish, so the tests that
matter are not about formatting. They are:

  1. it cannot reach the network (no client imported, no api handle in the signature)
  2. it redacts the whole STRUCTURE, keys as well as values, before rendering
  3. the diagnosis survives, or the artifact wastes the goodwill of whoever sent it
  4. it is a LOOP — the destination is in the artifact and actually exists

Fixtures use reserved documentation values (RFC 5737 TEST-NET, `example` TLD) and never a real
address from this estate. That rule was earned on 2026-07-27, on the Pacioli side of this same
feature, when the pre-push leak guard refused to build a public tree because the test proving
redaction had been written using a real internal IP.
"""
import inspect

from proximo.receipt import WHERE, fingerprint, redact, redact_structure, render

# --- 1. it cannot phone home ---------------------------------------------------------------------

def test_module_imports_no_network_or_shell():
    """Parse the real import statements rather than grepping the source text.

    The first version of this test grepped for the banned words and failed on the module's own
    DOCSTRING, which says it imports no subprocess. Source text is a stand-in for imports; the AST
    is the thing. A grep would also have been fooled the other way, by `import subprocess` written
    inside a string.
    """
    import ast

    import proximo.receipt as mod

    tree = ast.parse(open(mod.__file__, encoding="utf-8").read())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    banned = {"urllib", "socket", "http", "requests", "httpx", "subprocess", "proxmoxer", "os"}
    assert not (imported & banned), f"receipt.py must not import {imported & banned}"


def test_render_takes_no_api_handle():
    params = inspect.signature(render).parameters
    for banned in ("api", "transport", "client", "session"):
        assert banned not in params


# --- 2. redaction of the whole structure ---------------------------------------------------------

def test_ipv4_and_cidr_are_redacted():
    assert "192.0.2.10" not in redact("quorum lost to 192.0.2.10")
    assert "198.51.100.0/24" not in redact("migration network 198.51.100.0/24")


def test_pve_api_token_id_is_redacted():
    out = redact("token proximo@pve!operator failed to authenticate")
    assert "proximo@pve!operator" not in out
    assert "[redacted-token-id]" in out


def test_realm_user_is_redacted():
    assert "root@pam" not in redact("running as root@pam")


def test_certificate_fingerprint_is_redacted():
    fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    assert fp not in redact(f"cert fingerprint {fp}")


def test_identifying_KEYS_are_redacted_even_when_the_value_is_an_ordinary_word():
    """A node named `mail` or `backup` matches no pattern and is not a secret-looking string.
    Only the KEY knows it names someone's machine. This is why value-regex alone is not enough."""
    out = redact_structure({"node": "mail", "cluster": "office", "storage": "tank"})
    assert out == {"node": "[redacted-id]", "cluster": "[redacted-id]", "storage": "[redacted-id]"}


def test_a_vmid_is_an_identifier_not_a_count():
    out = redact_structure({"vmid": 1971, "guests_total": 42})
    assert out["vmid"] == "[redacted-id]"
    assert out["guests_total"] == 42, "counts are the diagnosis and must survive"


def test_redaction_reaches_nested_structures():
    report = {"cluster": {"nodes": [{"node": "pve01", "ip": "192.0.2.10"}]}}
    out = redact_structure(report)
    flat = str(out)
    assert "pve01" not in flat and "192.0.2.10" not in flat


def test_redaction_survives_into_the_rendered_receipt():
    """End-to-end. Redaction that only works on the helper is not redaction."""
    body = render({"nodes": [{"node": "pve01", "ip": "192.0.2.10"}]},
                  version="0.25.0", generated_at="2026-07-28T00:00:00Z")
    assert "pve01" not in body and "192.0.2.10" not in body


# --- 3. the artifact stays USEFUL ----------------------------------------------------------------

def test_the_diagnosis_survives():
    body = render(
        {"privileges": ["VM.Allocate", "Datastore.Audit"], "token_is_root": True, "guests": 12},
        version="0.25.0", generated_at="2026-07-28T00:00:00Z")
    assert "VM.Allocate" in body, "privilege names are the diagnosis"
    assert "Datastore.Audit" in body
    assert "True" in body
    assert "12" in body


def test_version_is_in_the_receipt():
    body = render({"a": 1}, version="0.25.0", generated_at="2026-07-28T00:00:00Z")
    assert "0.25.0" in body


def test_receipt_states_that_the_human_chose_to_share_it():
    body = render({"a": 1}, version="0.25.0", generated_at="2026-07-28T00:00:00Z")
    assert "nothing was transmitted" in body.lower() or "chose to share" in body.lower()


# --- 4. the fingerprint --------------------------------------------------------------------------

def test_fingerprint_is_stable():
    r = {"a": 1, "node": "pve01"}
    assert fingerprint(dict(r)) == fingerprint(dict(r))


def test_fingerprint_is_the_SAME_across_two_different_clusters():
    """Two operators with the identical defect must produce the identical fingerprint, or the id
    meant to group reports instead leaks which estate it came from."""
    a = fingerprint({"fault": "quorum lost", "node": "pve01", "ip": "192.0.2.10"})
    b = fingerprint({"fault": "quorum lost", "node": "hv-a", "ip": "198.51.100.7"})
    assert a == b


def test_fingerprint_changes_when_the_DEFECT_changes():
    a = fingerprint({"fault": "quorum lost"})
    b = fingerprint({"fault": "storage offline"})
    assert a != b


# --- 5. it is a LOOP, not a dead end -------------------------------------------------------------

def test_receipt_names_where_it_can_go():
    body = render({"a": 1}, version="0.25.0", generated_at="2026-07-28T00:00:00Z")
    assert WHERE in body


def test_the_destination_survives_its_own_redactor():
    """Our URL contains a hostname. If the redactor eats it the loop dies silently, with every
    other test above still green."""
    body = render({"a": 1}, version="0.25.0", generated_at="2026-07-28T00:00:00Z")
    assert "github.com" in body, "the redactor ate the destination"


def test_the_issue_template_reaches_the_repo():
    """Checked on 2026-07-27 in Pacioli: asserting the file merely EXISTS on disk passed while the
    template was untracked and absent from the published tree, so every receipt pointed at a 404.
    Existing locally is a stand-in for being shipped. Assert the real thing: git tracks it."""
    import subprocess
    from pathlib import Path
    repo = Path(__file__).resolve().parents[1]
    rel = ".github/ISSUE_TEMPLATE/receipt.yml"
    assert "template=" + Path(rel).name in WHERE
    # S603/S607 suppressed deliberately: the argv is a fixed literal with no interpolation and no
    # shell, and `git` on PATH is the only way to ask the real question — "is this tracked?" —
    # without reimplementing index parsing, which would itself be a stand-in for git's answer.
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", rel],  # noqa: S603, S607
                             cwd=repo, capture_output=True, text=True, check=False)
    assert tracked.returncode == 0, f"{rel} is not tracked by git — it cannot reach the mirror"


# --- 6. found by running it as an end user, not by a green test ----------------------------------

def test_absolute_filesystem_paths_are_redacted():
    """Caught 2026-07-28 in a REAL receipt off the live PVE: `ca_bundle` emitted an absolute path
    under the operator's home directory whose FILENAME embedded their hardware model. Nineteen
    tests were green at the time; only running the command as an operator would surfaced it.

    The fixtures below deliberately avoid the literal shapes this repo's leak-audit denies — the
    first draft of this docstring quoted the offending path verbatim and tripped that audit, which
    is the same mistake one level up: documenting a leak by reproducing it."""
    out = redact("ca_bundle: /home/operator/.config/app/node-leaf.pem")
    assert "/home/operator" not in out
    assert "[redacted-path]" in out
    assert "/etc/pve/local/pve-ssl.pem" not in redact("cert /etc/pve/local/pve-ssl.pem")


def test_a_url_is_redacted_whole_not_mangled():
    """Also from that real receipt: the address rule fired BEFORE the url rule, rewriting the host
    first, so the url rule then matched only a fragment and emitted `https://[redacted-host]]:8006`
    — a mangled string that still leaked the port and path. Order matters, so it is pinned."""
    out = redact("api_base_url: https://192.0.2.10:8006/api2/json")
    assert "192.0.2.10" not in out
    assert "8006" not in out, "the port and path must go with the host"
    assert "]]" not in out, "rule ordering produced a mangled marker"


def test_path_bearing_keys_are_redacted_by_key_too():
    out = redact_structure({"ca_bundle": "/some/where/leaf.pem", "audit_log": "/var/log/x.jsonl"})
    assert out == {"ca_bundle": "[redacted-id]", "audit_log": "[redacted-id]"}
