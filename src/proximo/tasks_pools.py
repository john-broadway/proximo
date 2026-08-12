"""TASK CONTROL + RESOURCE POOLS pillar — task list/log/stop and pool CRUD.

Trust thesis applies in two complementary lanes:

TASK LANE — the blast-radius honesty lives here:
  Stopping a task is RISK_HIGH because it can interrupt a backup, restore, migration,
  or clone MID-FLIGHT, potentially leaving the target in an inconsistent or partial state.
  There is NO undo for an interrupted task. This is the headline honesty of this lane.

POOL LANE — pool membership shapes ACL scope:
  Moving a guest in or out of a pool can change who has access (ACL grants on
  /pool/{poolid} apply to all members). pool_delete orphans those ACLs. pool_update
  changes which guests/storage fall under the pool's permission scope.

Key structural notes:
- Task ops (tasks_list, task_log, task_stop) are node-scoped: /nodes/{node}/tasks/...
- Pool ops (pools_list, pool_get, pool_create, pool_update, pool_delete) are cluster-scoped:
  /pools — NO /nodes/ prefix.
- api._get(path) takes NO params kwarg — query params are built inline in the path string.
- UPIDs contain colons (e.g. UPID:pve:00001:0:0:0:vmstart:100:root@pam:). Colon is a
  valid pchar (RFC 3986 §3.3); do NOT url-encode it. Smoke-confirm the PVE router
  handles raw colons in task-path segments the same way it handles /cluster/ha/resources/vm:100.
- task_stop DELETE returns null (synchronous cancellation signal, not a UPID).

Endpoint-shape risks flagged throughout with "Smoke-confirm:" comments.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from urllib.parse import urlencode

from .backends import ProximoError, _check_node, _check_upid
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Local validators
# ---------------------------------------------------------------------------

# Pool ID: letters/digits/hyphen/underscore; must start with alnum; length cap 40.
# Colons and slashes are explicitly excluded — a colon would break path construction,
# a slash would break URL routing. Dot is also excluded (pool names are identifiers,
# not DNS names). \Z (not $) blocks embedded-newline bypass.
_POOLID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")


def _check_poolid(poolid: str) -> str:
    """Validate a PVE pool ID.

    Allowed: letters, digits, hyphen, underscore. Must start with alnum. Max 40 chars.
    Rejects: empty, leading hyphen/underscore, slash, colon, dot, newline (\\Z guard),
    over-length (>40 chars including the first).
    """
    p = str(poolid).strip()
    if not _POOLID_RE.match(p):
        raise ProximoError(
            f"invalid pool ID: {poolid!r} "
            "(letters/digits/_/- only, must start with alnum, <=40, no slash/colon/dot/newline)"
        )
    return p


# ---------------------------------------------------------------------------
# READ operations — no confirm, no plan; audited by the server layer
# ---------------------------------------------------------------------------

def tasks_list(
    api,
    node: str | None = None,
    limit: int = 50,
    errors: bool = False,
    vmid: str | None = None,
    typefilter: str | None = None,
    statusfilter: str | None = None,
) -> list[dict]:
    """List recent tasks on a node.

    GET /nodes/{node}/tasks[?limit=N&errors=1&vmid=N&typefilter=X&statusfilter=X]

    node:         target node (defaults to api.config.node).
    limit:        max records to return; must be 1-1000 (positive, capped at 1000).
    errors:       if True, sends errors=1 to filter for errored tasks only.
    vmid:         optional VMID filter (PVE accepts a numeric string).
    typefilter:   optional task-type filter (e.g. 'vzstart', 'qmcreate').
    statusfilter: optional status filter — live-proven values: 'ok' / 'error' / 'warning';
                  by_outcome words ('warnings', 'failed') and task-status words
                  ('running', 'stopped') are rejected with a 400.

    Returns a list of task dicts (or [] on null).

    Smoke-confirm: verify all query param names against live PVE:
      - 'errors' (bool → integer 1)
      - 'vmid', 'typefilter', 'statusfilter' (exact names in PVE API viewer)
      - whether limit=0 is accepted by PVE or treated as unlimited (here we enforce >=1)
    """
    _check_node(node)
    n = node or api.config.node

    # Validate limit: positive required (reject <=0); cap at 1000 (clamp, not reject).
    limit = int(limit)
    if limit <= 0:
        raise ProximoError(f"limit must be a positive integer, got {limit!r}")
    if limit > 1000:
        limit = 1000

    params: dict = {"limit": limit}
    if errors:
        params["errors"] = 1  # PVE expects integer 1, not True
    if vmid is not None:
        params["vmid"] = vmid
    if typefilter is not None:
        params["typefilter"] = typefilter
    if statusfilter is not None:
        params["statusfilter"] = statusfilter

    qs = urlencode(params)
    return api._get(f"/nodes/{n}/tasks?{qs}") or []


def task_log(
    api,
    upid: str,
    node: str | None = None,
    start: int = 0,
    limit: int = 50,
) -> list[dict]:
    """Retrieve the log lines for a task.

    GET /nodes/{node}/tasks/{upid}/log?start=N&limit=N

    upid:  the task UPID (validated via _check_upid). UPIDs contain colons — colon is a
           valid pchar (RFC 3986 §3.3); do NOT url-encode the UPID in the path.
           Smoke-confirm: verify PVE's router handles raw colons in this segment the same
           way it does for /cluster/ha/resources/vm:100 and /nodes/{node}/tasks/{upid}/status.
    node:  target node (defaults to api.config.node).
    start: log line offset (0-based). Always sent, even when 0.
    limit: max log lines to return (1-1000, capped).

    Returns a list of log-line dicts (or [] on null).

    Smoke-confirm: verify PVE API param names for log pagination: 'start' and 'limit' —
    some PVE versions use 'since'/'max' — confirm against the API viewer.
    """
    upid = _check_upid(upid)
    _check_node(node)
    n = node or api.config.node

    limit = int(limit)
    if limit <= 0:
        raise ProximoError(f"limit must be a positive integer, got {limit!r}")
    if limit > 1000:
        limit = 1000

    start = int(start)
    if start < 0:
        raise ProximoError(f"start must be a non-negative integer (0-based offset), got {start!r}")

    params: dict = {"start": start, "limit": limit}
    qs = urlencode(params)
    # Raw UPID in path — colons are pchar-valid; do NOT url-encode.
    return api._get(f"/nodes/{n}/tasks/{upid}/log?{qs}") or []


def wait_for_task(
    fetch_status: Callable[[], dict],
    *,
    timeout: int = 120,
    interval: int = 2,
    sleep: Callable[[float], object] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict:
    """Poll ``fetch_status()`` until the task is terminal (PVE ``status == "stopped"``) or ``timeout``
    seconds elapse. Returns a structured result and NEVER raises on the task's own outcome — a failed
    or timed-out task is a *result*, not an exception. (A genuine API error from ``fetch_status`` still
    propagates.)

    ``succeeded`` is fail-closed: a stopped task whose ``exitstatus`` is missing or != ``"OK"`` is NOT
    a success — mirrors the internal ``_wait_task`` contract that guards the auto-undo path.
    ``sleep``/``monotonic`` are injected so callers (and tests) control timing deterministically.
    Bounding ``timeout``/``interval`` is the caller's responsibility — this primitive does not validate
    them; the ``pve_task_wait`` tool clamps to [1, 600]s / [1, 60]s.

    Returns ``{finished, succeeded, status, exitstatus, timed_out, polls}``.
    """
    deadline = monotonic() + timeout
    polls = 0
    while True:
        st = fetch_status() or {}
        polls += 1
        if st.get("status") == "stopped":
            exit_ = st.get("exitstatus")
            return {
                "finished": True,
                "succeeded": exit_ == "OK",
                "status": "stopped",
                "exitstatus": exit_,
                "timed_out": False,
                "polls": polls,
            }
        if monotonic() >= deadline:
            return {
                "finished": False,
                "succeeded": False,
                "status": st.get("status"),
                "exitstatus": st.get("exitstatus"),
                "timed_out": True,
                "polls": polls,
            }
        sleep(interval)


def pools_list(api) -> list[dict]:
    """List all resource pools (cluster-scoped, no node prefix).

    GET /pools
    Returns a list of pool summary dicts (poolid, comment, ...) or [].

    Smoke-confirm: verify returned fields — expected {poolid, comment} with optional member
    summary. The full member list is only in pool_get (GET /pools/{poolid}).
    """
    return api._get("/pools") or []


def pool_get(api, poolid: str) -> dict:
    """Get a specific pool's config and member list.

    GET /pools/{poolid}
    Returns a dict with pool config + members (vms, storage).

    Smoke-confirm: verify the response shape — expected {poolid, comment, members: [{vmid,
    type, ...}], storage: [{storage, ...}]} but field names may vary by PVE version.
    """
    poolid = _check_poolid(poolid)
    return api._get(f"/pools/{poolid}") or {}


# ---------------------------------------------------------------------------
# MUTATION operations — each is confirm-gated + plan-first at the server layer
# ---------------------------------------------------------------------------

def task_stop(api, upid: str, node: str | None = None) -> object:
    """Stop (cancel) a running task.

    DELETE /nodes/{node}/tasks/{upid}

    Returns null (PVE sends a synchronous cancellation signal; the task may still run briefly
    before it sees the signal). This is NOT a UPID — do NOT validate the return as one.

    Raw UPID in path — colons are pchar-valid; do NOT url-encode.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify DELETE /nodes/{node}/tasks/{upid} returns null on success;
    verify PVE's error response when the UPID does not correspond to a running task
    (404? 500? field in response?); verify whether a non-running (finished/errored) task
    DELETE is accepted silently or returns an error.
    """
    upid = _check_upid(upid)
    _check_node(node)
    n = node or api.config.node
    # Raw UPID — colons are pchar-valid; do NOT url-encode.
    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/nodes/{n}/tasks/{upid}")


def pool_create(api, poolid: str, comment: str | None = None) -> object:
    """Create a new resource pool.

    POST /pools
    Body: {poolid, comment?}

    poolid is sent in the request body (not the path) — this is the create endpoint.
    Returns the PVE response (typically null — synchronous config write).

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify PVE returns null on successful pool creation; verify 'comment'
    param name is correct (PVE API viewer); verify whether creating a duplicate pool ID
    returns a 4xx error or is silently accepted.
    """
    poolid = _check_poolid(poolid)
    data: dict = {"poolid": poolid}
    if comment is not None:
        data["comment"] = str(comment)
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post("/pools", data)


def pool_update(
    api,
    poolid: str,
    vms: str | None = None,
    storage: str | None = None,
    delete: bool = False,
) -> object:
    """Add or remove members from a resource pool.

    PUT /pools/{poolid}
    Body: {vms?, storage?, delete?}

    delete=False (default): ADD the listed vms/storage to the pool.
    delete=True:            REMOVE the listed vms/storage from the pool.

    vms:     comma-separated VMID string (e.g. "100,200,300"). Smoke-confirm: verify PVE
             accepts the comma-separated form (vs JSON array) and the exact param name.
    storage: comma-separated storage ID string. Smoke-confirm: verify param name.

    Note: changing pool membership changes ACL scope — any ACL granted on /pool/{poolid}
    applies to all members; adding or removing guests changes who has access.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify 'delete' param semantics (integer 1 vs boolean string) and that
    it removes listed members rather than clearing all members; verify comma-separated string
    format for vms/storage vs repeated params; verify PVE returns null on success.
    """
    poolid = _check_poolid(poolid)
    # delete=True with no members is a footgun: PVE's behavior for `{delete:1}` with no
    # vms/storage is undefined (could clear all members or error). Refuse it explicitly
    # rather than send an ambiguous request.
    if delete and vms is None and storage is None:
        raise ProximoError(
            "pool_update(delete=True) requires at least one of vms/storage to remove; "
            "refusing to send an ambiguous delete with no members"
        )
    data: dict = {}
    if vms is not None:
        data["vms"] = str(vms)
    if storage is not None:
        data["storage"] = str(storage)
    if delete:
        data["delete"] = 1  # PVE expects integer 1, not True
    # MUTATION — confirm-gated + audited at the server layer.
    return api._put(f"/pools/{poolid}", data)


def pool_delete(api, poolid: str) -> object:
    """Delete a resource pool.

    DELETE /pools/{poolid}

    PVE requires the pool to be empty before deletion — attempting to delete a non-empty
    pool will be refused by PVE (members must be removed first via pool_update). This does
    NOT cascade-delete member guests or storage; it only removes the pool grouping.

    Returns null on success (synchronous config write).

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify PVE returns null on success; verify the exact error (4xx/5xx)
    when attempting to delete a non-empty pool; verify whether PVE accepts pool deletion
    with an empty member list vs requiring explicit member-removal calls first.
    """
    poolid = _check_poolid(poolid)
    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/pools/{poolid}")


# ---------------------------------------------------------------------------
# PLAN functions — pure factories; no API call; the PLAN pillar
# ---------------------------------------------------------------------------

def plan_task_stop(upid: str, node: str | None = None) -> Plan:
    """Preview stopping (cancelling) a running task.  PURE — no API call.

    RISK_HIGH — headline honesty for this lane:
    Stopping a running task can interrupt a backup, restore, migration, or clone
    MID-FLIGHT, potentially leaving the target in an inconsistent or partial state.
    There is NO undo for an interrupted task. The task may not stop immediately —
    PVE sends a cancellation signal; the task sees it at its next checkpoint.

    UNDO: not available. An interrupted task leaves whatever it was doing mid-operation.
    To recover: inspect the guest state manually (check disk integrity, re-run the op).
    """
    upid = _check_upid(upid)
    _check_node(node)

    node_note = f" on node {node!r}" if node else " (node from api.config.node at call time)"

    return Plan(
        action="pve_task_stop",
        target=upid,
        change=f"stop (cancel) task {upid}{node_note}",
        current={},
        blast_radius=[
            f"sends a cancellation signal to task {upid}",
            "if this task is a backup, restore, migration, or clone: it is interrupted MID-FLIGHT — "
            "the target may be left in an inconsistent or partial state",
            "CANNOT be automatically undone — there is NO undo for an interrupted task",
            "recovery requires manual inspection of the affected guest and potentially re-running the operation",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "stopping a running task can interrupt a backup/restore/migration/clone mid-flight",
            "the target may be left in an inconsistent or partial state with no automatic rollback",
            "no undo path exists for a task that was already partially completed",
        ],
        note=(
            "task_stop is a cancellation signal — the task may still run briefly before "
            "it sees the signal. task_stop DELETE returns null (not a UPID). "
            "Smoke-confirm: verify the DELETE path and null-return on live PVE."
        ),
    )


def plan_pool_create(poolid: str, comment: str | None = None) -> Plan:
    """Preview creating a resource pool.  PURE — no API call.

    RISK_LOW: additive operation — creates an empty grouping with no members.
    No guests, storage, or ACLs are changed; the pool has no members until pool_update
    is called. Reversible via pool_delete (empty pool — no member-removal needed).
    """
    poolid = _check_poolid(poolid)
    comment_note = f" (comment: {comment!r})" if comment else ""

    return Plan(
        action="pve_pool_create",
        target=poolid,
        change=f"create resource pool {poolid!r}{comment_note}",
        current={},
        blast_radius=[
            f"creates a new empty resource pool {poolid!r}{comment_note}",
            "additive — no guests, storage, or ACLs are modified",
            "to undo: pool_delete (pool is empty, so no member-removal needed first)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "creates an empty grouping — no state is removed or reassigned",
            "additive operation; reversible via pool_delete IF the create succeeds and the "
            "pool ID is new (if PVE silently accepts a duplicate, the pool pre-existed and "
            "deleting it would remove someone else's pool — not a true reversal)",
        ],
        note=(
            "Smoke-confirm: verify POST /pools returns null on success; verify duplicate "
            "pool ID behavior (4xx vs silent accept) — reversibility depends on it."
        ),
    )


def plan_pool_update(
    poolid: str,
    vms: str | None = None,
    storage: str | None = None,
    delete: bool = False,
) -> Plan:
    """Preview adding or removing members from a resource pool.  PURE — no API call.

    RISK_MEDIUM: re-scopes pool membership.

    ACL SCOPE NOTE: any ACL granted on /pool/{poolid} applies to ALL pool members.
    Adding a guest to a pool means anyone with an ACL on the pool gains access to that
    guest. Removing a guest means the pool's ACLs no longer cover it.
    This is a permission-surface change — review pool ACLs before adding sensitive guests.

    delete=False (default): ADD members.
    delete=True:            REMOVE members from the pool (does not delete the guests/storage).

    Smoke-confirm: vms/storage are comma-separated strings; delete=1 removes listed members.
    """
    poolid = _check_poolid(poolid)
    # Mirror the op-layer guard so the dry-run surfaces the footgun too (the server _plan
    # gate audits this planning error and re-raises — the bad combo never reaches a mutation).
    if delete and vms is None and storage is None:
        raise ProximoError(
            "pool_update(delete=True) requires at least one of vms/storage to remove; "
            "refusing to plan an ambiguous delete with no members"
        )
    op = "REMOVE from" if delete else "ADD to"
    members = []
    if vms is not None:
        members.append(f"vms={vms!r}")
    if storage is not None:
        members.append(f"storage={storage!r}")
    members_note = (", ".join(members)) if members else "(no members specified)"

    return Plan(
        action="pve_pool_update",
        target=poolid,
        change=f"{op} pool {poolid!r}: {members_note}",
        current={},
        blast_radius=[
            f"{op} pool {poolid!r}: {members_note}",
            "pool membership changes ACL scope — any ACL on /pool/{poolid} applies to ALL members; "
            "adding/removing guests changes who has access to those guests via the pool's permissions",
            "the guests and storage themselves are NOT deleted or modified — only their pool membership changes",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "re-scopes pool membership, which changes the ACL coverage for affected guests/storage",
            "adding a guest to a pool extends that pool's permission grants to the guest",
            "removing a guest means pool ACLs no longer cover it (may break access for pool-scoped users)",
        ],
        note=(
            "Smoke-confirm: verify 'delete=1' removes listed members (not all members); "
            "verify vms/storage are comma-separated strings vs repeated params; "
            "verify PUT /pools/{poolid} returns null on success."
        ),
    )


def plan_pool_delete(api, poolid: str) -> Plan:
    """Preview deleting a resource pool.

    Reads the ACL (and the pool's members) to NAME the principals that lose access when grants on
    /pool/{poolid} orphan, and to surface that PVE refuses a non-empty pool. Risk: MEDIUM by default,
    escalated to HIGH when real ACL grants would break (a silent permission loss) or a read fails.
    """
    poolid = _check_poolid(poolid)
    pool_path = f"/pool/{poolid}"

    blast = [
        f"deletes pool {poolid!r} — the pool grouping is permanently removed",
        "PREREQUISITE: PVE requires the pool to be empty first — remove all members via "
        "pool_update before calling pool_delete, or PVE will refuse the deletion",
        "does NOT delete member guests or storage — only the pool grouping is removed",
    ]
    reasons = [
        "deletes the pool grouping and permanently orphans all ACLs granted on it",
        "PVE refuses deletion of a non-empty pool — must empty it first",
    ]
    affected: list[dict] = []
    complete = True

    # Blast radius: read the ACL → principals whose access is granted on the pool path.
    try:
        acl_entries = api._get("/access/acl") or []
        grants = [e for e in acl_entries
                  if e.get("path") == pool_path or str(e.get("path", "")).startswith(pool_path + "/")]
        for e in grants:
            affected.append({"principal": str(e.get("ugid", "")), "path": str(e.get("path", "")),
                             "roleid": str(e.get("roleid", "")), "change": "orphaned", "severity": "high"})
        if grants:
            named = ", ".join(sorted(f"{e.get('ugid', '')} ({e.get('roleid', '')})" for e in grants))
            blast.append(
                f"ACL ORPHAN: {len(grants)} grant(s) on {pool_path} break silently — these principals "
                f"lose pool-derived access: {named}"
            )
            reasons.append(f"{len(grants)} ACL grant(s) on {pool_path} break — silent permission loss")
        else:
            blast.append(f"no ACL grants currently target {pool_path} — no principal loses pool access")
    except Exception as exc:
        complete = False
        check_error = "404" if getattr(getattr(exc, "response", None), "status_code", None) == 404 \
            else type(exc).__name__
        blast.append(
            f"could NOT read the ACL ({check_error}) — cannot name which grants on {pool_path} orphan; "
            "absence of a list is NOT a safety signal"
        )
        reasons.append(f"ACL read failed ({check_error}) — orphaned-grants list unknown")

    # Members: PVE refuses a non-empty pool — surface that the delete would be rejected.
    try:
        members = (pool_get(api, poolid) or {}).get("members") or []
        if isinstance(members, list) and members:
            blast.append(
                f"pool currently has {len(members)} member(s) — PVE will REFUSE the delete until they "
                "are removed (pool_update)"
            )
            reasons.append(f"{len(members)} member(s) present — delete refused until emptied")
    except Exception:
        complete = False
        blast.append("could NOT read pool members — cannot confirm the pool is empty (delete may be refused)")

    blast.append("to undo: recreate the pool via pool_create and re-add members, then re-grant lost ACLs")

    risk = RISK_HIGH if (affected or not complete) else RISK_MEDIUM
    return Plan(
        action="pve_pool_delete",
        target=poolid,
        change=f"delete resource pool {poolid!r}",
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        affected=affected,
        complete=complete,
        note=(
            "Smoke-confirm: verify DELETE /pools/{poolid} returns null on success; "
            "verify PVE error (4xx/5xx) when deleting a non-empty pool (does NOT cascade). "
            "Pool delete is a synchronous config write — no UPID returned."
        ),
    )
