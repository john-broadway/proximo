# Build a dev VM from a template

plane: pve

Show each plan, wait for a yes. Tasks need task.succeeded=true. Failed or cut read, failed write, timeout: stop.

1. In steps 1-3 {vmid} is the template. GET /nodes/{node}/qemu/{vmid}/pending with fields=key. GET /nodes/{node}/qemu/{vmid}/config with fields=name,template and each ide, sata, scsi, virtio key in that list (only those): stop unless template is 1, one is cloudinit and net0 is listed. Operator: confirm its name; give new name, id, pool, storage, memory, address, user, key.
2. GET /cluster/nextid with vmid=the new id: refused means in use. GET /cluster/resources with type=vm, fields=name: the name must be absent.
3. POST /nodes/{node}/qemu/{vmid}/clone with newid, name, pool, storage, full=1. Now {vmid} is the new id. GET /nodes/{node}/qemu/{vmid}/config with fields=name,smbios1,vmgenid,net0: the name must match. Its identity.
4. PUT /nodes/{node}/qemu/{vmid}/config with ciuser, sshkeys (URL-encoded, %20 = space), ipconfig0 (ip=addr/prefix,gw=gw, or ip=dhcp), memory, onboot=0. Read back: each must match.
5. Its network is up. The operator opens its agent lane. POST /nodes/{node}/qemu/{vmid}/status/start. Repeat GET /nodes/{node}/qemu/{vmid}/agent/get-host-name (retry failures) until it answers the new name, up to 5 min. Never read its address list (Proximo cuts it): with DHCP the operator matches net0's MAC to a lease.
6. If a step after 3 failed, report it. On a separate yes, before POST /nodes/{node}/qemu/{vmid}/status/stop and again before DELETE /nodes/{node}/qemu/{vmid} with purge=1, re-read step 3's fields: stop unless unchanged.

Report id, name, address (or net0's MAC), user. Address, user and key stay unproven until an ssh login. Operator closes the lane.
