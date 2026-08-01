#!/usr/bin/env python3
"""Proximo demo driver — "Hand the keys." A narrated, RECORDABLE walk through the trust spine.

The whole point of this demo is that it is REAL: every line below calls Proximo's actual code and
prints its actual output. Nothing is faked — which is the entire pitch.

Two modes:
  --local   (default)  Self-contained. The PROVE pillar end-to-end against a throwaway keyed ledger
                       in a temp dir. Needs nothing but `pip install proximo-proxmox` — runs anywhere,
                       reproducible by anyone. This is the differentiator: a tamper-evident receipt.
  --live               The full PLAN -> UNDO -> PROVE arc against a REAL Proxmox host and a THROWAWAY
                       guest. Requires the PROXIMO_* env (see scripts/live-smoke/README.md) and
                       SMOKE_VMID set to a throwaway guest the token is scoped to. Self-cleaning.

Pacing (for recording):
  default     pause for <Enter> between beats — you drive the tempo while recording.
  --auto N    no prompts; sleep N seconds between beats (good for asciinema/unattended). N default 3.

Examples:
  uv run python scripts/demo/hand_the_keys.py                 # local, you press Enter to advance
  uv run python scripts/demo/hand_the_keys.py --auto 3        # local, hands-free, 3s/beat
  set -a; . /path/to/proximo.env; set +a
  SMOKE_VMID=931 uv run python scripts/demo/hand_the_keys.py --live
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time

# --- tiny terminal theater -------------------------------------------------------------------------
_C = sys.stdout.isatty()
def _c(s: str, code: str) -> str: return f"\033[{code}m{s}\033[0m" if _C else s
def dim(s): return _c(s, "2")
def bold(s): return _c(s, "1")
def red(s): return _c(s, "1;31")
def grn(s): return _c(s, "1;32")
def cyn(s): return _c(s, "1;36")
def yel(s): return _c(s, "1;33")

_AUTO: float | None = None

def _breathe(secs: float) -> None:
    # tiny pacing so a recording reads at human speed; interactive (Enter-paced) runs skip it
    if _AUTO is not None:
        time.sleep(secs)

def beat(title: str) -> None:
    print("\n" + cyn("━" * 64))
    print(cyn(f"  {title}"))
    print(cyn("━" * 64))
    _breathe(0.8)

def caption(s: str) -> None:   # the voiceover / on-screen caption
    print(bold(f"\n  ▸ {s}"))
    _breathe(1.2)

def agent(s: str) -> None:     # "the AI agent asks"
    print(f"\n  {yel('AI agent ▸')} {s}")
    _breathe(1.2)

def shows(label: str, obj) -> None:   # Proximo's real output
    body = json.dumps(obj, indent=2, ensure_ascii=False) if not isinstance(obj, str) else obj
    print(dim(f"  proximo ▸ {label}"))
    for line in body.splitlines():
        print("    " + line, flush=True)
        _breathe(0.12)

def pause() -> None:
    if _AUTO is not None:
        time.sleep(_AUTO)
    else:
        try:
            input(dim("\n    [Enter] →"))
        except EOFError:
            pass


# --- LOCAL: the PROVE pillar, self-contained ------------------------------------------------------
def demo_local() -> int:
    from proximo.audit import AuditLedger, load_or_create_key

    d = tempfile.mkdtemp(prefix="proximo-demo-")
    log = os.path.join(d, "audit.log")
    key = load_or_create_key(os.path.join(d, "audit.key"))  # real 0600 HMAC key (keyed by default)
    led = AuditLedger(log, key=key)

    beat("Hand an AI agent the keys to your cluster.")
    caption("Every move it makes lands in a tamper-evident ledger — keyed, hash-chained, by default.")
    caption("Watch three things an agent did get written down, then watch the record defend itself.")
    pause()

    beat("1 / The agent acts. Proximo writes it down.")
    # These detail dicts are the REAL shapes `_audited()` writes, captured from a live ledger
    # write against each tool (2026-08-01) and kept in sync deliberately. The previous versions
    # were hand-invented — `{"op","why"}`, `{"name"}`, `{"argv"}` — and none of those keys exists
    # anywhere in the product, so the demo taught adopters field names they could not find.
    #
    # The ct_exec entry matters most: it used to show the raw argv, which is exactly what
    # PROXIMO_LEDGER_REDACT (default ON since 0.29.0) exists to keep OUT of a durable file,
    # because a command line routinely carries a secret. Showing the pre-0.29.0 behaviour
    # advertised the vulnerability we fixed. The fingerprint below is what a real box records.
    for action, target, detail in [
        ("pve_guest_power",     "lxc/931", {
            "change": "stop lxc 931", "risk": "high",
            "risk_reasons": ["hard stop (power pull) of a running guest"],
            "blast_radius": ["1 running guest will halt (uptime 1d)"]}),
        ("pve_snapshot_create", "lxc/931", {
            "change": "create snapshot pre-deploy of lxc 931", "risk": "low",
            "risk_reasons": ["additive — creates a snapshot"],
            "blast_radius": ["adds a restore point (non-destructive)"]}),
        ("ct_exec",             "lxc/931", {
            "change": "run in 931: [redacted apt, 19 chars, sha256:2aabcc03b444]",
            "risk": "medium", "cmd_kind": "apt", "cmd_len": 19,
            "cmd_sha256": "2aabcc03b44475014399e2e18d2aac30da0abd33d417b445edf976b2de1e658a"}),
    ]:
        led.record(action, target=target, mutation=True, detail=detail)
        agent(f"{action}  {dim(json.dumps(detail))}")
    v = led.verify()
    head = led.head()
    shows("audit_verify()", {"ok": v.ok, "entries": v.entries, "keyed": led.keyed, "head": head[:24] + "…"})
    caption(f"Three actions, hash-chained. {grn('ok=True')}, keyed=True. This is the receipt.")
    pause()

    beat("2 / Someone edits the log to hide a move.")
    caption("An attacker (or a careless cleanup) rewrites one entry's detail, in place.")
    lines = open(log).read().splitlines()
    objs = [json.loads(x) for x in lines]
    objs[1]["detail"] = {"name": "pre-deploy", "note": "nothing to see here"}   # tamper the middle entry
    tampered = os.path.join(d, "audit.tampered.log")
    open(tampered, "w").write("\n".join(json.dumps(o) for o in objs) + "\n")
    tv = AuditLedger(tampered, key=key).verify()
    shows("audit_verify()  (on the edited copy)",
          {"ok": tv.ok, "broken_at_line": tv.broken_at, "reason": tv.reason})
    caption(f"{red('ok=False')} — caught at line {tv.broken_at}. You can't edit the past without breaking the chain.")
    pause()

    beat("3 / Someone deletes the tail to erase the last move.")
    caption("The sneakiest attack: just truncate the file. A forward walk alone can't see what's gone —")
    caption("so you pin the head off-box. Proximo checks the live chain against the head you trust.")
    truncated = os.path.join(d, "audit.truncated.log")
    open(truncated, "w").write("\n".join(lines[:-1]) + "\n")    # drop the last (real) entry
    led_trunc = AuditLedger(truncated, key=key)
    naive = led_trunc.verify()                                  # forward walk only — looks fine
    pinned = led_trunc.verify(expected_head=head)               # vs the off-box-pinned head
    shows("forward walk alone", {"ok": naive.ok, "reason": naive.reason})
    shows("verify(expected_head=…)  the off-box anchor",
          {"ok": pinned.ok, "reason": pinned.reason})
    caption(f"Forward walk says ok — but pinned against the trusted head: {red('ok=False, head mismatch')}.")
    caption("Tamper-EVIDENT, by construction. Hand over the keys; keep the receipts.")
    print(grn("\n  Strength and honor.\n"))
    return 0


# --- LIVE: PLAN -> UNDO -> PROVE against a real host + throwaway guest -----------------------------
def demo_live() -> int:
    vmid = os.environ.get("SMOKE_VMID", "").strip()
    if not vmid:
        print(red("  --live needs SMOKE_VMID set to a THROWAWAY guest the token is scoped to."))
        print(dim("  (and the PROXIMO_* env — see scripts/live-smoke/README.md). Refusing to guess."))
        return 2
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)  # keep API URLs off camera (same as demo.py)
    from proximo.audit import AuditLedger
    from proximo.server import (
        _svc,
        audit_verify,
        pve_delete_guest,
        pve_snapshot_create,
        pve_snapshot_delete,
    )
    kind = os.environ.get("SMOKE_KIND", "lxc")
    snap = "proximo_handthekeys_demo"
    _, api, _, ledger = _svc()

    def snaps():
        return {s.get("name", "") for s in api.snapshot_list(vmid, kind, None)}
    def wait(pred, t=90):
        t0 = time.monotonic()
        while time.monotonic() - t0 < t and not pred():
            time.sleep(2)
        return pred()

    beat("Hand an AI agent the keys to a REAL cluster.")
    caption(f"Target: throwaway {kind}/{vmid} on your live Proxmox. Everything below is real.")
    pause()

    beat("1 / PLAN — the agent tries to destroy the guest.")
    agent(f"pve_delete_guest({vmid}, purge=True)   # 'clean it up'")
    plan = pve_delete_guest(vmid, kind=kind, confirm=False)     # confirm=False => dry-run, NO mutation
    shows("pve_delete_guest(confirm=False)", plan)
    caption(f"status={plan.get('status')} — it shows the blast radius and {red('does NOT execute')}.")
    caption("An agent cannot fumble into an irreversible wipe. A plan is mandatory; confirm is yours.")
    pause()

    beat("2 / UNDO — a reversible change snapshots FIRST.")
    n0 = audit_verify()["entries"]
    agent(f"pve_snapshot_create({vmid}, '{snap}')")
    dry = pve_snapshot_create(vmid, snap, kind, confirm=False)
    shows("confirm=False (plan)", {"status": dry.get("status")})
    pve_snapshot_create(vmid, snap, kind, confirm=True)         # real, ledgered
    created = wait(lambda: snap in snaps())
    caption(f"Safety net taken before any change: snapshot present = {grn(str(created))}.")
    pause()

    beat("3 / PROVE — the receipt, and it defends itself.")
    v1 = audit_verify()
    shows("audit_verify()", {"ok": v1["ok"], "entries": v1["entries"],
                             "keyed": v1["keyed"], "head": (v1["head"] or "")[:24] + "…"})
    caption(f"The two real ops are chained in: entries {n0}→{v1['entries']}, {grn('ok=True')}.")
    # tamper a COPY only — never the real ledger
    lines = open(ledger.path).read().splitlines()
    objs = [json.loads(x) for x in lines]
    mid = max(0, len(objs) // 2)
    objs[mid]["target"] = str(objs[mid].get("target", "")) + "_TAMPERED"
    tmp = os.path.join(tempfile.mkdtemp(prefix="proximo-demo-"), "tampered.log")
    open(tmp, "w").write("\n".join(json.dumps(o) for o in objs) + "\n")
    tv = AuditLedger(tmp, key=ledger.key).verify()
    shows("audit_verify()  (edited copy)", {"ok": tv.ok, "broken_at_line": tv.broken_at, "reason": tv.reason})
    caption(f"Edit the record and it breaks: {red('ok=False')} at line {tv.broken_at}.")

    # cleanup — also ledgered (confirm=True)
    if snap in snaps():
        print(dim(f"\n  [cleanup] pve_snapshot_delete {snap} ..."))
        try:
            pve_snapshot_delete(vmid, snap, kind, confirm=True)
            wait(lambda: snap not in snaps())
        except Exception as e:
            print(red(f"  [cleanup] FAILED: {e!r} — MANUAL: pct/qm delsnapshot {vmid} {snap}"))
    caption("Plan it. Undo it. Prove it. Hand over the keys; keep the receipts.")
    print(grn("\n  Strength and honor.\n"))
    return 0


def main() -> int:
    global _AUTO
    ap = argparse.ArgumentParser(description="Proximo 'Hand the keys' demo")
    ap.add_argument("--live", action="store_true",
                    help="full PLAN/UNDO/PROVE vs a real host (needs SMOKE_VMID + PROXIMO_* env)")
    ap.add_argument("--auto", nargs="?", type=float, const=3.0, default=None,
                    help="hands-free: sleep N seconds between beats instead of waiting for Enter (default 3)")
    a = ap.parse_args()
    _AUTO = a.auto
    try:
        return demo_live() if a.live else demo_local()
    except KeyboardInterrupt:
        print("\n(interrupted)")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
