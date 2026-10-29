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

> These proofs run against the **core**, which is local and file-based — no live
> Proxmox needed for most of them. Clone the repo and run `uv sync --extra dev` first.

---

## 1. The tool count is real (six) — introspect it, don't read it

Claims of "N tools" are cheap. Ask the door itself, cold:

```bash
uv run python -c "import asyncio; from proximo.core.doors.mcp import build_server; \
print(len(asyncio.run(build_server().list_tools())))"
# => 6
```

That number is what the MCP door registers at startup — not a figure typed into a
README. The six are `proximo_find`, `proximo_plan`, `proximo_read`, `proximo_call`,
`audit_entries`, `audit_verify`. Everything else is an address the vendor publishes,
reached through them; the count of those is generated from the vendor's own schema into
[`docs/arena.md`](docs/arena.md), and a stale copy fails the test suite.

## 2. The audit ledger is tamper-evident (PROVE) — forge a byte, watch it refuse

Every mutation lands in a keyed, hash-chained ledger. Change one field of one past entry
and the chain breaks — `verify()` names where:

```python
import tempfile
from pathlib import Path
from proximo.core.ledger import LedgerConfig, open_ledger

with tempfile.TemporaryDirectory() as d:
    path = Path(d) / "audit.log"
    led = open_ledger(LedgerConfig(audit_log_path=str(path)))   # keyed, always; the key is minted beside it
    led.record("core.execute", target="pve:POST /nodes/pve1/qemu/100/status/start", mutation=True)
    led.record("core.execute", target="pve:POST /nodes/pve1/qemu/100/snapshot", mutation=True)
    print("clean: ", led.verify().ok)                      # => True

    lines = path.read_text().splitlines()                   # now forge history:
    lines[0] = lines[0].replace("qemu/100", "qemu/999")
    path.write_text("\n".join(lines) + "\n")

    v = led.verify()
    print("forged:", v.ok, "| broken_at:", v.broken_at, "|", v.reason)
    # => forged: False | broken_at: 1 | entry_hash mismatch (entry altered)
```

The chain is keyed (HMAC-SHA256) with no unkeyed mode: an attacker can't recompute it
without the key, and `audit_verify(expected_head=...)` catches truncation of the *tail*
by pinning the head off-box. Tamper-evident, not just tamper-logged.

**Without Proximo installed.** The format is written down in
[`docs/ledger-format.md`](docs/ledger-format.md), and `scripts/verify_ledger.py` checks a log
from it with the standard library alone, so whoever you hand the log and its key to can run:

```sh
python3 scripts/verify_ledger.py audit.log --key audit.key
# => ok 2 <head>
```

## 3. No phone-home — the entire outbound surface is greppable

Proximo talks to exactly one place: the Proxmox endpoint **you** configure. There is no
telemetry, no analytics, no "anonymous usage" beacon. Prove it by listing every URL
literal in the shipped source:

```bash
grep -rEoh 'https?://[a-zA-Z0-9._~:/?#@!$&*+,;=-]+' src/proximo --include='*.py' | sort -u
```

Everything it prints is one of: a **placeholder** in a docstring or config sample
(`example.*`, `localhost`, or a URL-shape stand-in like `http://user:pass@host:port`), a
**loopback literal** (`127.0.0.1`, `::1`) used as a bind default for the optional A2A,
HTTP, and MCP-over-streamable-HTTP doors or as a parsing counter-example, or an
**upstream Proxmox documentation citation** in a docstring recording where an API shape
was checked. None of them is ever fetched. Nothing here calls out to us.

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
"buildSignerURI": ".github/workflows/release.yml@refs/tags/v0.50.1"
```

The image also ships an **SPDX SBOM** (`release.yml`, `sbom: true`). Inspect it on any
Docker host with `docker buildx imagetools inspect ghcr.io/john-broadway/proximo:latest
--format '{{ json .SBOM }}'` — verify the dependency tree against your own policy.

## 5. The PyPI artifacts carry publish provenance (PEP 740)

Published tokenlessly via GitHub OIDC Trusted Publishing — no long-lived API token exists
in the release path to steal. Each artifact has an attached provenance attestation:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/proximo-proxmox/0.50.1/proximo_proxmox-0.50.1-py3-none-any.whl/provenance
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

## 7. Disarmed means refused (ARM) — try the write, watch it refuse

Unlike §1–6 this needs your own server and token (it proves *your* boundary, not our
artifact). Armed means one thing: **the token the door serves is byte-for-byte the write
token** (`PROXIMO_ARM_SOURCE`; `PROXIMO_READONLY_SOURCE` improves the refusal message but
never enforces). While **disarmed**, any `proximo_call` of a mutation with `confirm=true`
is refused before the wire, and the receipt says so: `needs: "arm"`. Run `proximo
doctor` disarmed and read the plane's `arm` field (`armed: false`, with the reason); arm from
your shell (`proximo arm`), the same doctor read changes; `proximo disarm` and it changes back. The shell door is the same
engine: `proximo-core pve POST /nodes/pve1/qemu/100/status/stop` exits 2 (refused by the
spine) while disarmed.

Honesty about what this proves: "the agent cannot arm itself" holds only in the
two-deployment shape where the write token sits on ground the agent cannot read or write.
On a single-uid co-located box, anyone who can run `proximo arm` can copy the source into
place, and the gate is a discipline, not a wall (`SECURITY.md`'s ARM section says exactly
this, and `arm` prints which one you have). The refusal-when-disarmed is what this section
proves; the boundary strength is your deployment's. If a disarmed confirmed mutation ever
executes, that's a report (see `SECURITY.md` → Reporting).

## 8. An unjudged mutation is refused, armed or not

Also needs your server. Governance here is derived from the vendor's own schema: the HTTP
method decides read or write, total over every published address. The one human-authored
column is the blast-radius **tier**, and an address with no tier is refused for mutation
even when the operator is armed — an untiered address is not "probably fine", it is
unjudged. Pick any published mutation, ask for its plan, and read the verdict:

```bash
proximo-core pve POST /nodes/pve1/qemu/100/status/start --plan
```

Disarmed, the plan answers `needs: "arm"` first; armed, it names the tier it found, or
`needs: "tier"` if there is none. The 20 addresses
held on purpose (a login ticket, the node's `execute`, the cluster join) answer
`needs: "held"` with the sentence that says why, and nothing you set opens them: that
line moves only by a change to `tiers.toml` in a release. The full record, by class and
by product, is [`docs/arena.md`](docs/arena.md).

---

## What we *don't* claim

Honesty is part of the verification. Tiers are an **advisory blast-radius judgement, not a
sandbox** — a low tier means "small blast radius", not "safe." UNDO covers what the vendor
publishes a write to put back; a delete, a collection, or a path with no PUT gets a
sentence, not a guessed reverse call. The opt-in controls (CONSENT, CONTAIN, TAINT, the
envelope) only become a real boundary when their state lives outside the agent's own write
reach — see [`SECURITY.md`](./SECURITY.md), "the two-deployment trust model." We'd rather
you find the edges here than be surprised by them in production.

Other Proxmox tools are converging on these ideas — some ship an HMAC audit chain, risk
gates, or undo tokens too, and that's good for everyone who runs an agent on infra. Credit
where due. The bar isn't "only Proximo does this." The bar is: **whatever you run, make it
prove itself. That's what keeps you free.**
