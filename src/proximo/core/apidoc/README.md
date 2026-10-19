# Vendored Proxmox API operation lists

One file per product: every `(path, method)` pair in the official api-viewer tree,
parsed from `apidoc.js` by `scripts/api_coverage.py fetch` (which is the only
thing that writes here). Denominators for the coverage receipt and the whitelist of the raw GET door (`proximo.rawdoor`).

| file | source | fetched |
|---|---|---|
| `pve.ops.json` | https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js | 2026-09-19 (Last-Modified 2026-09-18) |
| `pbs.ops.json` | https://pbs.proxmox.com/docs/api-viewer/apidoc.js | 2026-09-19 |
| `pmg.ops.json` | https://pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js | 2026-09-19 |
| `pdm.ops.json` | https://pdm.proxmox.com/docs/api-viewer/apidoc.js | 2026-09-19 |

The published trees track the current release; a live host of an older version
has fewer operations. Re-fetch when the products move (`api_coverage.py fetch`)
and commit the diff, so the receipt is dated by this table, not by memory.
