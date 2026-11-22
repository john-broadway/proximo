# Check recent backups that failed or warned

plane: pve

Reads only: never write. Lists: read plain first, and an empty list ends there (fields= on an empty list is refused). Otherwise read again with the fields named. An answer that fails, is refused, or is cut (truncated, or summarized with no data) is unread.

1. GET /nodes (fields=node,status). Each offline node is unread.
2. For each online {node}: GET /nodes/{node}/time (fields=time) for now. GET /nodes/{node}/tasks with typefilter=vzdump, since=now minus the operator's window (7 days if none given), limit=4, start=0 (fields=upid,id,status,starttime); then start=4, 8 and on until a page has fewer than 4. Any page unread: that node's backups are unknown.
3. Sort each task by status: OK is good. Exactly WARNINGS: and a number finished with warnings. No status yet: still running. Anything else failed.
4. A job run covers many guests and has no id. Read the log of each failed or warned job run, and of each guest's newest failed or warned task (count its older ones): GET /nodes/{node}/tasks/{upid}/log with limit=5, start=0 (fields=t), then start=5, 10 and on until a page has fewer than 5. Note each line with ERROR or WARN, and the guest it names.
5. GET /cluster/backup. A job has a node key only if pinned to one. An enabled job with no task in the window on its node (or any, if not pinned): list it as no run seen, with its schedule and next-run. That is not a failure: it may not have been due.

Report per node: failed backups (guest, when, the error line), warned backups (guest, warning), still running, jobs with no run seen, nodes or logs unread. Say "every backup in the window succeeded" only when nothing failed, warned or runs, and every read answered whole.
