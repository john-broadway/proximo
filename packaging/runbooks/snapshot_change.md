# Change a VM with a snapshot to fall back on

plane: pve

Show each plan, wait for a yes. Tasks need task.succeeded=true. Failed or cut read, failed write, timeout: stop.

1. GET /nodes/{node}/qemu/{vmid}/status/current with fields=name,status. The operator confirms the name. GET /nodes/{node}/qemu/{vmid}/pending with fields=key: stop if empty or it has lock. Note which keys to change are absent (fields refuses those). GET /nodes/{node}/qemu/{vmid}/config with fields naming the others; note values. If running and a file will prove it, the operator opens the agent lane; GET /nodes/{node}/qemu/{vmid}/agent/file-read and note it.
2. GET /nodes/{node}/qemu/{vmid}/snapshot with fields=name. Pick a unique new name. POST /nodes/{node}/qemu/{vmid}/snapshot with snapname, vmstate=0.
3. List with fields=name,parent. Change nothing unless the row named current has that name as parent.
4. Make only the agreed change, then repeat step 1's reads. The operator says keep or roll back.
5. Keep: on a separate yes DELETE /nodes/{node}/qemu/{vmid}/snapshot/{snapname}, then list names: it must be gone.
6. Roll back: list as in 3; stop unless current's parent is still that name. Say what is lost (disk and config changes since) and kept (description, tags). On a separate yes POST /nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback.
7. After a rollback the VM is stopped. If it was running, POST /nodes/{node}/qemu/{vmid}/status/start; on a lock error retry for a minute. Repeat step 1's reads until they answer, five minutes at most. The rollback is proven only if all equal the notes.

Report what was compared, the result, power state and snapshots left (Proximo adds a proximo_ one per rollback). The operator closes the agent lane.
