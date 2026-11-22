# Check that a node can get updates

plane: pve

Reads only: never write, and never refresh the package index here. Lists: read plain first, and an empty list ends there (fields= on an empty list is refused). Otherwise read again with the fields named. An answer that fails, is refused, or is cut (truncated, or summarized with no data) is unread.

1. GET /nodes/{node}/subscription with fields=status. Unread: stop.
2. GET /nodes/{node}/tasks with typefilter=aptupdate and limit=3 (fields=status,endtime). Unread: stop. Empty: no recorded refresh, freshness unknown. The newest status is not OK: the last recorded refresh failed; give that status and when it ran. Older failures that later runs fixed are history.
3. GET /nodes/{node}/apt/repositories with fields=errors,infos. Unread: say so. Report every error, and every info whose kind is warning.
4. GET /nodes/{node}/apt/update (fields=Package,Version; new packages have no OldVersion). Unread: report the total if given. Empty: none pending, but only if step 2's newest run was OK; else unknown.

Report: subscription status, when the index was last refreshed and whether that worked, repository errors, and the pending updates with their versions. If step 2's newest run failed and the subscription is not active, say the node may be using a paid repository without a subscription. Upgrades and repository changes are the operator's, on the node.
