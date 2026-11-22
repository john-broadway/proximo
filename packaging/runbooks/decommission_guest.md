# Remove a guest for good

plane: pve

Show each plan, wait for a yes. Tasks need task.succeeded=true. Failed or cut read, failed write, timeout: stop. Paths say qemu; a container uses lxc.

1. The operator names {node} and {vmid}. GET /nodes/{node}/qemu/{vmid}/pending with fields=key. GET /nodes/{node}/qemu/{vmid}/config with fields=name (hostname for lxc), digest, and each of protection, lock, template only if the key list has it (missing: 0 or none; never name it). The operator confirms the name; it and digest are its identity. Stop if protection is 1, lock is set, or template is 1 (clones may use it).
2. GET /nodes/{node}/storage with content=backup (fields=storage,active); inactive: unread. For each active {storage}: GET /nodes/{node}/storage/{storage}/content with content=backup and the vmid (fields=volid,ctime). Report the newest (listed, not tested). None or any unread: go on only on the operator's yes.
3. GET /nodes/{node}/qemu/{vmid}/snapshot (fields=name): these go with it. GET /cluster/ha/resources, GET /cluster/backup, GET /cluster/replication, plain: report entries naming it; purge removes them. Jobs by all or pool remain.
4. GET /nodes/{node}/qemu/{vmid}/status/current (fields=status). Running: re-read step 1's fields, stop unless unchanged, POST /nodes/{node}/qemu/{vmid}/status/shutdown with timeout=120. Failed or still running: stop; a forced stop is the operator's call.
5. On a separate yes: re-read step 1's fields; stop unless unchanged. DELETE /nodes/{node}/qemu/{vmid} with purge=1. GET /cluster/resources with type=vm, plain (empty: gone), else fields=vmid: it must be gone.

Report name, newest backup (kept, untested), what went with it, gone or not. Backups and disks it did not reference stay.
