#!/usr/bin/env python3
"""Proximo HA-RULES-PLANE full-chain mutation smoke (ha_rule create / update / delete).

PVE rejects HA rules over UNMANAGED resources, and rejects HA-managing a non-existent guest.
So a real end-to-end prove stands up a throwaway guest, HA-manages it, exercises the rule CRUD,
then tears the whole thing down (self-cleaning, reverse order):

  create minimal empty VM -> wait -> HA-manage (state=ignored) -> rule create/read/update/delete
  -> remove HA resource -> delete VM

The VM is empty (1 GB disk on local-lvm, no OS) and HA state=ignored, so the CRM never starts it.

Environment (set by the wrapper):
  PROXIMO_API_BASE_URL  PROXIMO_NODE  PROXIMO_TOKEN_PATH  PROXIMO_VERIFY_TLS
  SMOKE_HA_RULE  (default proximo-smoke-rule)   SMOKE_VMID (default 9999)
"""
from __future__ import annotations

import os

import proximo.server as server

RULE: str = os.environ.get("SMOKE_HA_RULE", "proximo-smoke-rule")
VMID: str = os.environ.get("SMOKE_VMID", "9999")
NODE: str = os.environ.get("PROXIMO_NODE", "your-node")
SID: str = f"vm:{VMID}"


def hr(title: str) -> None:
    print(f"\n=== {title} ===")


def _upid(res) -> str | None:
    if isinstance(res, dict):
        for k in ("task", "upid", "data", "result"):
            v = res.get(k)
            if isinstance(v, str) and v.startswith("UPID"):
                return v
    if isinstance(res, str) and res.startswith("UPID"):
        return res
    return None


def wait(api, res) -> None:
    upid = _upid(res)
    if upid:
        server._wait_task(api, upid, node=NODE)


def find_rule(name: str) -> dict | None:
    for r in server.pve_ha_rules_list():
        if r.get("rule") == name or r.get("id") == name:
            return r
    return None


def rule_exists(name: str) -> bool:
    try:
        return find_rule(name) is not None
    except Exception as e:  # noqa: BLE001
        print(f"  (ha-rules read failed: {type(e).__name__}: {e})")
        return True


def ha_managed(sid: str) -> bool:
    try:
        return any(r.get("sid") == sid
                   for r in server.pve_ha_resources_list()["resources"])
    except Exception as e:  # noqa: BLE001
        print(f"  (ha-resources read failed: {type(e).__name__}: {e})")
        return True


def vm_present(api) -> bool:
    try:
        return any(str(g.get("vmid")) == str(VMID) for g in server.pve_list_guests(node=NODE))
    except Exception as e:  # noqa: BLE001
        print(f"  (guest-list read failed: {type(e).__name__}: {e})")
        return True


def main() -> int:
    cfg, api, _, _ = server._svc()
    print(f"node={cfg.node}  url={cfg.api_base_url}")
    print(f"throwaway: vm={SID}  rule={RULE!r}  node-affinity->{NODE!r}")

    vm_created = ha = rule = False
    try:
        hr("prep — create a minimal empty throwaway VM + HA-manage it")
        r = server.pve_create_vm(
            VMID, node=NODE,
            options={"cores": 1, "memory": 512, "scsi0": "local-lvm:1",
                     "ostype": "l26", "name": "proximo-smoke"},
            confirm=True,
        )
        wait(api, r)
        vm_created = vm_present(api)
        print(f"  create_vm {SID}: present? {vm_created}")
        server.pve_ha_resource_add(VMID, kind="qemu", state="ignored", confirm=True)
        ha = True
        print(f"  ha_resource_add {SID} (state=ignored): managed? {ha_managed(SID)}")

        hr("ha_rule — create node-affinity / read / update / delete")
        c = server.pve_ha_rule_create(RULE, "node-affinity", SID, nodes=NODE,
                                      comment="proximo smoke", confirm=True)
        rule = True
        print("  create:", c.get("status", c))
        got = find_rule(RULE)
        print(f"  read-back: type={got and got.get('type')}  resources={got and got.get('resources')}")
        u = server.pve_ha_rule_update(RULE, comment="proximo smoke (updated)", confirm=True)
        got2 = find_rule(RULE)
        print(f"  update: {u.get('status', u)}  comment-now={got2 and got2.get('comment')!r}")
        server.pve_ha_rule_delete(RULE, confirm=True)
        rule = rule_exists(RULE)
        print(f"  delete; gone? {not rule}")

    finally:
        hr("cleanup (guaranteed, reverse order)")
        if rule_exists(RULE):
            try:
                server.pve_ha_rule_delete(RULE, confirm=True)
                print(f"  removed leftover HA rule ({RULE!r})")
            except Exception as e:  # noqa: BLE001
                print(f"  !!! could not remove rule {RULE!r}: {e}")
        if ha and ha_managed(SID):
            try:
                server.pve_ha_resource_remove(VMID, kind="qemu", confirm=True)
                print(f"  removed HA resource {SID}")
            except Exception as e:  # noqa: BLE001
                print(f"  !!! could not remove HA resource {SID}: {e}")
        if vm_created and vm_present(api):
            try:
                dr = server.pve_delete_guest(VMID, kind="qemu", confirm=True)
                wait(api, dr)
                print(f"  deleted VM {SID}; gone? {not vm_present(api)}")
            except Exception as e:  # noqa: BLE001
                print(f"  !!! could not delete VM {SID}: {e} — manual: pvesh delete /nodes/{NODE}/qemu/{VMID}")
        residue = []
        if rule_exists(RULE):
            residue.append(f"ha rule {RULE!r}")
        if ha_managed(SID):
            residue.append(f"ha resource {SID}")
        if vm_present(api):
            residue.append(f"vm {VMID}")
        print("  residue:", residue or "none — clean")

    v = server.audit_verify()
    print("\nledger verify:", {"ok": v.get("ok"), "entries": v.get("entries")})
    print("HA-RULES-PLANE FULL-CHAIN SMOKE COMPLETE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
