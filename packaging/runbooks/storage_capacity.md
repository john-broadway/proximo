# Check storage that is nearly full or overcommitted

plane: pve

Reads only: never write. Lists: read plain first, and an empty list ends there (fields= on an empty list is refused). Otherwise read again with the fields named. An answer that fails, is refused, or is cut (truncated, or summarized with no data) is unread.

1. GET /nodes (fields=node,status). Each offline node is unread.
2. For each online {node}: GET /nodes/{node}/storage (fields=storage,type,active,shared,total,used). Inactive: unread. Shared: count once.
3. Flag used / total above the operator's limit (85% if none given), with the percent.
4. GET /nodes/{node}/disks/lvmthin (fields=lv,vg,lv_size,used,metadata_size,metadata_used). Flag data or metadata above the limit: a full thin pool's metadata can corrupt every volume on it.
5. For each lvmthin {storage}: GET /nodes/{node}/storage/{storage}/content (fields=volid,size); cut: read once per guest, vmid from GET /cluster/resources with type=vm (fields=vmid,node). The sum of size is what was promised; above the pool's total it is overcommitted: give the ratio. Unread or refused (Proxmox lists disks only with VM.Config.Disk on the guest or Datastore.Allocate here): promised is unknown.

Report per node: storages flagged in 3, thin pools flagged in 4, overcommitted pools with ratio, and what was unread. Overcommit is allowed by design; it is a risk to report, not an error. Freeing or growing space is the operator's.
