#!/usr/bin/env python3
"""Live-smoke orchestrator — the durable "what runs, in what order, needing what" map plus a runner.

Phases escalate by blast radius:
  read     — pure reads (node/storage/backup/audit). Needs only a READ token.
  plan     — PLAN/blast previews; reads + computes, mutates nothing. Read token suffices.
  mutate   — reversible mutate→verify on a PERSISTENT throwaway VM (power/snapshot/disk/backup/…).
  destroy  — create→destroy (clone/template-convert/container). One-shot per ACL grant: destroying
             a guest strips its /vms/<id> ACL, so the grant must be re-applied before each run.

Mutate/destroy need a scoped CI token bound to a throwaway VMID range + an isolated test storage
(provably NOT prod) — see the live-CI scope. **Advisory by design:** prints a per-smoke PASS/FAIL/SKIP
summary and exits non-zero if any RUN smoke failed, but whether that gates anything is the caller's
call (recommended: notify-and-triage, not a blocking gate, until green is boring).

A smoke whose required env is unset is SKIPPED (not failed), so a partial-env run is clean.

Usage:
  python scripts/live-smoke/run-all.py --list                 # the registry
  python scripts/live-smoke/run-all.py --dry-run --phase all  # what WOULD run, with env readiness
  python scripts/live-smoke/run-all.py --phase read,plan      # run the credential-free slice
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
PHASES = ("read", "plan", "mutate", "destroy", "pbs", "access", "storage")

# Base-env TIERS. A smoke's `base` selects which connection env must be present:
#   pve — the Proxmox VE API + a token (the original tier)
#   pbs — the Proxmox Backup Server API + a PBS token (the backup plane)
# A smoke whose tier env is unset is SKIPPED (not failed), so a PVE-only or PBS-only runner is clean
# and a fully-unconfigured runner is obviously all-skipped (never a false green).
BASE_ENV = {
    "pve": {"all": ("PROXIMO_API_BASE_URL", "PROXIMO_NODE"),
            "any": ("PROXIMO_TOKEN_PATH", "PROXIMO_TOKEN_FILE")},
    "pbs": {"all": ("PROXIMO_PBS_BASE_URL", "PROXIMO_PBS_TOKEN_PATH"),
            "any": ()},
}

# A CA bundle names a FILE, and the variable being set says nothing about the file being there.
# The live-smoke workflow's PBS precheck bails with a bare `exit 0` BEFORE writing pbs-ca.pem when
# the test box is down — its own comment says the tier "must SKIP cleanly ... not red" — but the
# bail ends only that STEP, so the smoke step still ran with the path set and the file absent and
# all five PBS smokes FAILED. Diagnosed 2026-09-04 from 65 straight nightly reds. A tier whose
# bundle is set but names nothing cannot connect, so it is NOT ready: skip it, with the reason.
# An UNSET bundle stays ready — that is a deployment verifying by fingerprint or system CAs.
# Env vars that name a FILE. The variable being set says nothing about the file being there, and
# the live-smoke workflow sets all four unconditionally while writing them only on a success path:
# a bailed precheck leaves the path set and the file absent, the tier read as READY, and the
# smokes FAILED where the workflow's own comment says they SKIP. Diagnosed 2026-09-04 from 65
# straight nightly reds. An UNSET var stays ready — that is a deployment configured another way.
# NOTE, honestly: for PBS a missing CA bundle is evidence the precheck did not finish, NOT proof
# the tier cannot connect. PbsBackend returns inside `if config.fingerprint:` before it ever reads
# ca_bundle (src/proximo/pbs.py), so with a fingerprint pinned the bundle is unused. The workflow
# now also DECLARES the skip by clearing PROXIMO_PBS_BASE_URL, which is the real mechanism; this
# check is the backstop for a path that goes missing some other way.
BASE_FILES = {
    "pve": ("PROXIMO_CA_BUNDLE", "PROXIMO_TOKEN_PATH"),
    "pbs": ("PROXIMO_PBS_CA_BUNDLE", "PROXIMO_PBS_TOKEN_PATH"),
}


@dataclass(frozen=True)
class Smoke:
    name: str
    script: str                       # filename in this directory
    phase: str                        # one of PHASES
    needs: tuple[str, ...] = ()        # env vars required beyond the base tier
    one_shot_regrant: bool = False     # destroy strips /vms/<id> ACL → re-grant before each run
    base: str = "pve"                  # env tier: 'pve' or 'pbs'
    note: str = ""


REGISTRY: tuple[Smoke, ...] = (
    Smoke("readonly", "readonly-smoke.py", "read", note="node/storage/backup/audit reads"),
    Smoke("fw-reach", "fw-reach-smoke.py", "plan", needs=(), note="firewall reach PLAN (FW_* have defaults)"),
    Smoke("storage-blast", "blast-smoke.py", "plan", needs=("PROXIMO_STORAGE",), note="storage blast PLAN"),
    Smoke("acl-blast", "acl-blast-smoke.py", "plan",
          needs=("PROXIMO_ACL_PATH", "PROXIMO_ACL_TARGET"), note="ACL shadow/widen PLAN"),
    # blast-radius coverage (op-classes #6-15) — drives each engine against the real cluster + the
    # sandbox VMs, PLAN ONLY (no confirm ever passed). Read-only, but it REQUIRES the sandbox-identity
    # fixtures (refuse to guess) so a cluster without them SKIPs instead of false-redding on drift.
    Smoke("coverage-blast", "coverage-blast-smoke.py", "plan",
          needs=("SMOKE_VMID", "PROXIMO_SMOKE_TEST_VMIDS", "SMOKE_STORE", "SMOKE_POOL"),
          note="blast-radius PLAN verification (op-classes #6-15) vs the sandbox VMs — read-only"),
    # mutate smokes self-guard (default-deny allowlist) — they REQUIRE the allowlist env so the
    # orchestrator SKIPs (not hard-fails on the guard) when it isn't provisioned.
    Smoke("guest-lifecycle", "guest-lifecycle-smoke.py", "mutate",
          needs=("SMOKE_VMID", "PROXIMO_SMOKE_TEST_VMIDS"),
          note="power+snapshot+rollback on a PERSISTENT stopped VM (no destroy → no ACL strip)"),
    Smoke("disk-resize", "disk-resize-smoke.py", "mutate",
          needs=("SMOKE_VMID", "SMOKE_STORE", "PROXIMO_SMOKE_TEST_VMIDS", "PROXIMO_SMOKE_TEST_STORAGES"),
          note="grow + grow-only guard"),
    Smoke("content-delete", "content-delete-smoke.py", "mutate",
          needs=("SMOKE_VMID", "SMOKE_STORE", "PROXIMO_SMOKE_TEST_VMIDS", "PROXIMO_SMOKE_TEST_STORAGES"),
          note="in-use detection + real volume delete"),
    Smoke("backup", "backup-smoke.py", "mutate",
          needs=("SMOKE_VMID", "SMOKE_STORE", "PROXIMO_SMOKE_TEST_VMIDS", "PROXIMO_SMOKE_TEST_STORAGES"),
          note="backup + backup_delete"),
    Smoke("prove", "prove-smoke.py", "mutate", needs=("SMOKE_VMID",),
          note="PROVE ledger + confirm-gate via the real pve_* tools + tamper detection"),
    Smoke("envelope", "envelope-smoke.py", "mutate", needs=("SMOKE_VMID",),
          note="autonomy-envelope FORBID block + concurrent RATE-budget barrier vs live PVE"),
    # cluster-level (firewall/HA) — need privs the VM/Datastore-scoped CI token does NOT carry; gated
    # behind SMOKE_CLUSTER_OPS so the default nightly (scoped token) SKIPs them instead of 403-failing.
    Smoke("fwobjects", "fwobjects-smoke.sh", "mutate", needs=("SMOKE_CLUSTER_OPS",),
          note="firewall object CRUD (firewall stays DISABLED) — needs cluster-priv token"),
    Smoke("sdn", "sdn-smoke.py", "mutate", needs=("SMOKE_SDN_ZONE", "SMOKE_SDN_VNET", "SMOKE_SDN_CIDR"),
          note="SDN pending CRUD — sdn_apply NEVER fired — needs cluster-priv token"),
    Smoke("ha-rules", "harules-smoke.py", "mutate", needs=("SMOKE_CLUSTER_OPS",),
          note="HA rule CRUD — HA state ignored (CRM never starts it) — needs cluster-priv token"),
    Smoke("clone", "clone-smoke.py", "destroy",
          needs=("SMOKE_SRC_VMID", "SMOKE_NEW_VMID", "SMOKE_STORE"), one_shot_regrant=True,
          note="full clone (target storage) + purge — UNGUARDED + new-VMID grant unresolved: dispatch-only"),
    Smoke("template-convert", "template-convert-smoke.py", "destroy",
          needs=("SMOKE_SRC_VMID", "SMOKE_TPL_VMID", "SMOKE_STORE"), one_shot_regrant=True,
          note="irreversible convert (disposable SMOKE_TPL_VMID clone first; distinct id): dispatch-only"),
    Smoke("create-container", "create-container-smoke.py", "destroy",
          needs=("SMOKE_VMID", "SMOKE_STORE", "SMOKE_TEMPLATE"), one_shot_regrant=True,
          note="LXC create + purge: dispatch-only"),
    # PBS plane (base='pbs') — self-seeding + guarded (PROXIMO_SMOKE_PBS_HOSTS default-deny allowlist).
    Smoke("pbs-namespace", "pbs-namespace-smoke.py", "pbs", base="pbs",
          needs=("PROXIMO_SMOKE_PBS_HOSTS",), note="namespace create + delete"),
    Smoke("pbs-snapshot-delete", "pbs-snapshot-delete-smoke.py", "pbs", base="pbs",
          needs=("PROXIMO_SMOKE_PBS_HOSTS",), note="seed -> snapshot_delete -> gone"),
    Smoke("pbs-prune", "pbs-prune-smoke.py", "pbs", base="pbs",
          needs=("PROXIMO_SMOKE_PBS_HOSTS",), note="seed x2 -> prune keep-last=1 -> one kept"),
    Smoke("pbs-gc", "pbs-gc-smoke.py", "pbs", base="pbs",
          needs=("PROXIMO_SMOKE_PBS_HOSTS",), note="gc_start -> task OK + status readable"),
    Smoke("pbs-verify", "pbs-verify-smoke.py", "pbs", base="pbs",
          needs=("PROXIMO_SMOKE_PBS_HOSTS",), note="seed target+decoy -> scoped verify -> state ok"),
    # access-CRUD plane (base='pve') — needs an access-MGMT token (Realm.AllocateUser/User.Modify/
    # Permissions.Modify) + the identity allowlist (its SOLE guard, since access privs can't be scoped
    # to test identities). DISPATCH-ONLY: that token is powerful (can touch ANY user/role) — never nightly.
    Smoke("access-crud", "access-crud-smoke.py", "access", base="pve",
          needs=("PROXIMO_SMOKE_IDENTITY_PREFIXES",),
          note="user/role/token create+delete + the token_revoke path-traversal fix — needs access-mgmt token"),
    # storage-admin plane (base='pve') — storage create/delete mutates CLUSTER config; needs
    # Datastore.Allocate at the /storage ROOT (can't be scoped to test storages) + the name allowlist
    # (sole guard). DISPATCH-ONLY: that priv can delete ANY storage (stranding prod guests).
    Smoke("storage-admin", "storage-admin-smoke.py", "storage", base="pve",
          needs=("PROXIMO_SMOKE_IDENTITY_PREFIXES",),
          note="storage create + plan-delete + delete — needs a storage-admin token (Datastore.Allocate @ /storage)"),
)


def _validate_registry() -> list[str]:
    """Self-check: phases valid, names unique, every script file present. Returns problems."""
    problems: list[str] = []
    seen: set[str] = set()
    for s in REGISTRY:
        if s.phase not in PHASES:
            problems.append(f"{s.name}: bad phase {s.phase!r}")
        if s.name in seen:
            problems.append(f"duplicate smoke name {s.name!r}")
        seen.add(s.name)
        if not os.path.exists(os.path.join(HERE, s.script)):
            problems.append(f"{s.name}: script {s.script!r} not found")
    return problems


def _base_env_ready(base: str) -> list[str]:
    """Missing base-env vars for a tier ('pve'|'pbs'). Empty list = that tier's connection is set."""
    tier = BASE_ENV[base]
    missing = [v for v in tier["all"] if not os.environ.get(v)]
    if tier["any"] and not any(os.environ.get(v) for v in tier["any"]):
        missing.append("(" + " | ".join(tier["any"]) + ")")
    for var in BASE_FILES.get(base, ()):
        if (path := os.environ.get(var)) and not os.path.isfile(path):
            missing.append(f"{var} (set, but names no file)")
    return missing


def _smoke_missing_env(s: Smoke) -> list[str]:
    return [v for v in s.needs if not os.environ.get(v)]


def _skip_reason(s: Smoke) -> list[str]:
    """Why a smoke would be skipped: its base-env tier unmet and/or its `needs` unset. Empty = ready."""
    return _base_env_ready(s.base) + _smoke_missing_env(s)


def _selected(phase_arg: str) -> list[Smoke]:
    if phase_arg == "all":
        wanted = set(PHASES)
    else:
        wanted = {p.strip() for p in phase_arg.split(",")}
        bad = wanted - set(PHASES)
        if bad:
            sys.exit(f"unknown phase(s): {', '.join(sorted(bad))}; valid: {', '.join(PHASES)}")
    order = {p: i for i, p in enumerate(PHASES)}
    return sorted([s for s in REGISTRY if s.phase in wanted], key=lambda s: order[s.phase])


def _runner(script: str) -> list[str]:
    return ["bash", script] if script.endswith(".sh") else [sys.executable, script]


def cmd_list() -> int:
    for p in PHASES:
        print(f"\n[{p}]")
        for s in (x for x in REGISTRY if x.phase == p):
            tag = " (one-shot re-grant)" if s.one_shot_regrant else ""
            needs = f"  needs: {' '.join(s.needs)}" if s.needs else ""
            print(f"  {s.name:18} {s.script:28}{tag}\n      {s.note}{needs}")
    return 0


def cmd_dry_run(phase_arg: str) -> int:
    selected = _selected(phase_arg)
    for t in sorted({s.base for s in selected}):
        bm = _base_env_ready(t)
        print(f"{t} base env: {'READY' if not bm else 'MISSING ' + ', '.join(bm)}")
    for s in selected:
        miss = _skip_reason(s)
        state = "ready" if not miss else "SKIP (missing: " + ", ".join(miss) + ")"
        print(f"  [{s.phase}/{s.base}] {s.name:18} -> {state}")
    return 0


def _verdict(results: list[tuple[str, str, float]]) -> tuple[int, str]:
    """The run's exit code and its summary line. Pure, so it is testable without live infra.

    `ran == 0` is REFUSED (rc 2). A run that proved nothing is not a pass, and before this the
    exit was `1 if failed else 0` with `ran` computed and never used: a night with the lab off
    skipped every smoke and exited 0, so CI read GREEN on zero evidence. An adversarial lens
    caught it in the commit that introduced the skip, which had traded a true red for a false
    green — the one outcome this workflow's header forbids.

    A PARTIAL run still passes. The lab is off unless someone is testing, so a nightly that
    proves the PVE tier and skips the lab tier is a real pass for what it ran; the skips stay
    named in the summary above. Only proving NOTHING is refused.
    """
    failed = sum(1 for _, state, _ in results if state.startswith("FAIL"))
    ran = sum(1 for _, state, _ in results if state != "SKIP")
    line = f"{failed} failed / {ran} run / {len(results) - ran} skipped / {len(results)} total"
    if failed:
        return 1, line
    if ran == 0:
        return 2, line + "\n  REFUSED: this run ran nothing — 0 run is not a pass, it is no evidence."
    return 0, line


def cmd_run(phase_arg: str) -> int:
    selected = _selected(phase_arg)
    # Per-tier readiness banner: a tier with no env makes its smokes SKIP, so an unconfigured runner
    # is OBVIOUSLY all-skipped (never a silent 0-run green).
    for t in sorted({s.base for s in selected}):
        bm = _base_env_ready(t)
        if bm:
            print(f"NOTE: {t!r} base env not configured ({', '.join(bm)}) — its smokes will SKIP")
    results: list[tuple[str, str, float]] = []
    for s in selected:
        miss = _skip_reason(s)
        if miss:
            print(f"SKIP {s.name} [{s.phase}/{s.base}] (missing {', '.join(miss)})")
            results.append((s.name, "SKIP", 0.0))
            continue
        print(f"\n==> {s.name} [{s.phase}/{s.base}] {s.script}")
        t0 = time.monotonic()
        rc = subprocess.run(_runner(s.script), cwd=HERE).returncode
        dt = time.monotonic() - t0
        results.append((s.name, "PASS" if rc == 0 else f"FAIL(rc={rc})", dt))

    print("\n" + "=" * 56 + "\nSUMMARY")
    for name, state, dt in results:
        print(f"  {state:12} {name:18} {dt:6.1f}s")
    rc, note = _verdict(results)
    print(note)
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="print the registry and exit")
    ap.add_argument("--dry-run", action="store_true", help="resolve env + show what would run, run nothing")
    ap.add_argument("--phase", default="read,plan",
                    help="comma list of read/plan/mutate/destroy/pbs, or 'all' (default: read,plan)")
    args = ap.parse_args()

    problems = _validate_registry()
    if problems:
        sys.exit("registry invalid:\n  - " + "\n  - ".join(problems))

    if args.list:
        return cmd_list()
    if args.dry_run:
        return cmd_dry_run(args.phase)
    return cmd_run(args.phase)


if __name__ == "__main__":
    raise SystemExit(main())
