# Verify Proximo — don't trust it

Proximo hands an AI agent the keys to your Proxmox cluster. That's a large ask.
So the design rule is the opposite of "trust us": **every claim on this project
should be checkable by you, against the artifacts, without our word for any of it.**

This page pairs each claim with the command that proves it. Run them. If one doesn't
do what it says, that's a bug — [open an issue](https://github.com/john-broadway/proximo/issues).

And the wider point, because it outlives this project: **these checks work on any
tool, from any vendor.** A provenance attestation, a tamper-evident log, a greppable
egress surface, a published SBOM — you can demand all of it everywhere. Verifiability
is not a favor a maintainer does you. It's the floor. Hold every tool to it.

> These proofs run against the **trust core**, which is local and file-based — no live
> Proxmox needed for most of them. Clone the repo and run `uv sync --extra dev` first.

---

## 1. The tool count is real (904) — introspect it, don't read it

Claims of "N tools" are cheap. Ask the server itself, cold:

```bash
uv run python -c "import asyncio; from proximo import server; \
print(len(asyncio.run(server.mcp.list_tools())))"
# => 904
```

That number is the count of `@mcp.tool()` definitions the FastMCP server actually
registers at startup — not a figure typed into a README.

## 2. The audit ledger is tamper-evident (PROVE) — forge a byte, watch it refuse

Every mutation lands in a hash-chained ledger. Change one field of one past entry and
the chain breaks — `verify()` names where:

```python
import tempfile
from pathlib import Path
from proximo.audit import AuditLedger

with tempfile.TemporaryDirectory() as d:
    led = AuditLedger(str(Path(d) / "audit.log"))
    led.record("guest_power", target="vm/100", mutation=True)
    led.record("snapshot_create", target="vm/100", mutation=True)
    print("clean: ", led.verify().ok)                     # => True

    p = Path(led.path)                                     # now forge history:
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace('"vm/100"', '"vm/999"')
    p.write_text("\n".join(lines) + "\n")

    v = led.verify()
    print("forged:", v.ok, "| broken_at:", v.broken_at, "|", v.reason)
    # => forged: False | broken_at: 1 | entry_hash mismatch (entry altered)
```

With keyed chaining on (the default) an attacker can't recompute the chain without the
HMAC key, and `audit_verify(expected_head=...)` catches truncation of the *tail* by
pinning the head off-box. Tamper-evident, not just tamper-logged.

## 3. No phone-home — the entire outbound surface is greppable

Proximo talks to exactly one place: the Proxmox endpoint **you** configure. There is no
telemetry, no analytics, no "anonymous usage" beacon. Prove it by listing every URL
literal in the shipped source:

```bash
grep -rEoh 'https?://[a-zA-Z0-9._~:/?#@!$&*+,;=-]+' src/proximo --include='*.py' | sort -u
```

Everything it prints is one of: an **`example.*` placeholder or `localhost` doc example**
in a docstring or config sample, a **loopback bind default** (`127.0.0.1`) for the
optional A2A, HTTP, and MCP-over-streamable-HTTP network faces, or the **print-only**
`hello` links. Those are
never fetched — `hello.py` builds URLs as *strings it prints*, and says so in its own
docstring ("print-only; sends nothing"). Nothing here calls out to us.

## 4. The container image is signed at the source (SLSA provenance)

The GHCR image carries a sigstore keyless **build-provenance attestation** — cryptographic
proof of *which workflow at which commit* built it. Verify it yourself:

```bash
gh attestation verify oci://ghcr.io/john-broadway/proximo:latest --owner john-broadway
# exit 0 = verified. add --format json to read the provenance:
```

```jsonc
// the attestation ties the image to the real repo + release workflow:
"predicateType": "https://slsa.dev/provenance/v1"
"sourceRepositoryURI": "https://github.com/john-broadway/proximo"
"buildSignerURI": ".github/workflows/release.yml@refs/tags/v0.29.0"
```

The image also ships an **SPDX SBOM** (`release.yml`, `sbom: true`). Inspect it on any
Docker host with `docker buildx imagetools inspect ghcr.io/john-broadway/proximo:latest
--format '{{ json .SBOM }}'` — verify the dependency tree against your own policy.

## 5. The PyPI artifacts carry publish provenance (PEP 740)

Published tokenlessly via GitHub OIDC Trusted Publishing — no long-lived API token exists
in the release path to steal. Each artifact has an attached provenance attestation:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/proximo-proxmox/0.29.0/proximo_proxmox-0.29.0-py3-none-any.whl/provenance
# => 200   (the signed provenance PyPI generated at publish time)
```

## 6. Independent security posture — OpenSSF Scorecard

An automated third party grades the repo weekly. It's linked from the README badge and
lives here, updated without our involvement:

```
https://scorecard.dev/viewer/?uri=github.com/john-broadway/proximo
```

We don't set that score; OpenSSF does. Read the failing checks, not just the number.

---

## What we *don't* claim

Honesty is part of the verification. Risk ratings are an **advisory heuristic, not a
sandbox** — `LOW` means "no state change," not "safe." UNDO covers the snapshottable
surface (guests, container exec), **not** firewall/SDN/ACL/token planes, which have no
Proxmox rollback primitive. The opt-in controls (CONSENT, CONTAIN, taint-tracking) only
become a real boundary when their state lives outside the agent's own write reach — see
[`SECURITY.md`](./SECURITY.md), "the two-deployment trust model." We'd rather you find
the edges here than be surprised by them in production.

Other Proxmox tools are converging on these ideas — some ship an HMAC audit chain, risk
gates, or undo tokens too, and that's good for everyone who runs an agent on infra. Credit
where due. The bar isn't "only Proximo does this." The bar is: **whatever you run, make it
prove itself. That's what keeps you free.**
