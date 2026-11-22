# Prove a VM backup by restoring a copy

plane: pve

Never write to the original: check each write's id is step 2's. Show each plan, wait for a yes. Tasks need task.succeeded=true. Failed write or timeout: stop.

1. GET /nodes/{node}/storage/{storage}/content with content=backup and the original vmid. The operator picks the volid and a file of known text.
2. GET /cluster/nextid for an id the operator accepts; they open its agent lane.
3. POST /nodes/{node}/qemu with that vmid, archive=volid, storage, pool, unique=1. Never force, start or live-restore.
4. GET /nodes/{node}/qemu/{vmid}/pending with fields=key. Stop if failed, empty, cut, or it has hostpci, usb, virtiofs, parallel, args or hookscript.
5. Isolate it. GET /nodes/{node}/qemu/{vmid}/config with fields naming only every netN, serialN and ide, sata, scsi, virtio key. Stop if failed, cut, any is missing, a serial isn't socket, or a disk starts with / (host device). PUT /nodes/{node}/qemu/{vmid}/config with onboot=0, protection=0 and each netN's own value with link_down=1 (replacing any). Read those plus both flags back, same stops.
6. Only if step 5 read back link_down=1 on each netN and both flags 0: POST /nodes/{node}/qemu/{vmid}/status/start, then GET /nodes/{node}/qemu/{vmid}/agent/get-host-name up to 5 minutes. No hostname: boot not proven, skip to 8.
7. GET /nodes/{node}/qemu/{vmid}/agent/file-read with that file; compare exactly. Failed, empty or cut: report boot proven, data not.
8. Re-read step 5's read-back fields: stop unless unchanged. POST /nodes/{node}/qemu/{vmid}/status/stop, on a separate yes re-read, then DELETE /nodes/{node}/qemu/{vmid} with purge=1. Keep the backup.

Report volid, file, result, copy gone or not. Operator closes the agent lane.
