# Prove a container backup by restoring a copy

plane: pve

Never write to the original: check each write's id is step 2's. Show each plan, wait for a yes. A task must end succeeded=true or exitstatus WARNINGS: n (report). Failed write or timeout: stop.

1. GET /nodes/{node}/storage/{storage}/content with content=backup and the original vmid. The operator picks the volid and a known-text file outside system temp dirs (not backed up).
2. GET /cluster/nextid for an id the operator accepts; they open its lane.
3. POST /nodes/{node}/lxc with that vmid, ostemplate=volid, restore=1, storage, pool, unique=1. Never force or start.
4. GET /nodes/{node}/lxc/{vmid}/pending with fields=key. Stop if failed, empty, cut, or it has devN, lxc or hookscript.
5. Isolate it. GET /nodes/{node}/lxc/{vmid}/config with fields naming only every netN and mpN. Stop if failed, cut, missing, or an mpN starts with / (host path). PUT /nodes/{node}/lxc/{vmid}/config with onboot=0, protection=0 and each netN's own value with link_down=1 (replacing any). Read them back, same stops.
6. Only if step 5 read back link_down=1 on each netN and both flags 0: POST /nodes/{node}/lxc/{vmid}/status/start, then GET /nodes/{node}/lxc/{vmid}/status/current with fields=status until running, 1 min max; else start unproven, skip to 8.
7. POST /nodes/{node}/lxc/{vmid}/exec with command ["cat", the file]; need returncode 0, stdout exactly the text, else (a failed exec too): data not proven.
8. Re-read step 5's read-back fields: stop unless unchanged. If running, POST /nodes/{node}/lxc/{vmid}/status/stop; on a separate yes re-read, then DELETE /nodes/{node}/lxc/{vmid} with purge=1. Keep the backup.

Report volid, file, result, copy gone or not. Operator closes the lane.
