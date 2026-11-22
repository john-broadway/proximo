# Find old and leftover snapshots

plane: pve

Reads, then deletes only what the operator picks. Show each plan, wait for a yes. Tasks need task.succeeded=true. Failed write or timeout: stop. Lists: read plain first, and an empty list ends there (fields= on an empty list is refused). Otherwise read again with the fields named. An answer that fails, is refused, or is cut (truncated, or summarized with no data) is unread.

1. GET /cluster/resources with type=vm (fields=vmid,name,node,type,template). Unread: stop. For each node: GET /nodes/{node}/time (fields=time) for its now.
2. For each guest: GET /nodes/{node}/qemu/{vmid}/snapshot, or GET /nodes/{node}/lxc/{vmid}/snapshot for a container (fields=name,snaptime,parent). Unread: that guest is unknown. Skip current: it is the running state.
3. Flag a snapshot older than the operator's age (30 days if none given), and any named proximo_ (Proximo's safety snapshots, kept after its rollbacks; one under a day old may be a change still under way: say so).
4. Report per guest, by vmid and name: each flagged snapshot, its age and why, and the guests unread. The operator picks any to delete; nothing is deleted unpicked.
5. For each pick, on its own yes: re-read step 2 for that guest; stop unless it is still there with the same snaptime. DELETE /nodes/{node}/qemu/{vmid}/snapshot/{snapname}, or DELETE /nodes/{node}/lxc/{vmid}/snapshot/{snapname} for a container. Read step 2 again: it must be gone.

Report what was deleted and what is left flagged.
