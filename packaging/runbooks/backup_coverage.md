# Check which guests have no recent backup

plane: pve

Reads only: never write. Lists: read plain first, and an empty list ends there (fields= on an empty list is refused). Otherwise read again with the fields named. An answer that fails, is refused, or is cut (truncated, or summarized with no data) is unread.

1. GET /cluster/backup-info/not-backed-up (fields=vmid). Unread: stop. These guests are selected by no backup job (whether jobs are enabled is not checked). Drop templates the operator does not count.
2. GET /cluster/resources with type=vm (fields=vmid,template; more fields can cut it). Unread: stop. Templates count only if the operator says so.
3. GET /nodes (fields=node,status). Each offline node is unread. For each online {node}: GET /nodes/{node}/storage with content=backup (fields=storage,active); each inactive one is unread.
4. For each active {storage}: GET /nodes/{node}/storage/{storage}/content with content=backup (fields=vmid,ctime); cut: read once per guest with its vmid. An unread storage is unread, never empty.
5. For each guest from step 2, take its newest ctime across all storages. None, or older than the operator's limit (7 days if none given): flag it, with its age. While any node or storage is unread, none or too old is unknown.

Report three lists: guests in no job (step 1), guests flagged in step 5, nodes or storages unread. Say "every guest has a recent backup and a job" only when all three are empty and every read answered whole.
