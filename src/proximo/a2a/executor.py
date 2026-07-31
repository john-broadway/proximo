"""ProximoAgentExecutor — the A2A transport over the governed core.

Every inbound A2A call routes through ``governed.call_governed`` — the same spine path (PLAN,
PROVE, UNDO, the gates, the token scope) an MCP client takes. The A2A face exposes the FULL tool
surface, not a curated slice: a transport carries the surface, it does not curate it, so it never
decides the surface or re-invents safety. No second mutate path.

Message convention
------------------
The inbound ``Message`` must contain a ``DataPart`` whose ``.data`` is a JSON object shaped::

    {"tool": "<tool-name>", "params": {<arg-dict>}}

``"skill"`` is accepted as an alias for ``"tool"`` (backward-compatible with the earlier slice
wire format). ``params`` may be absent/null (an empty object). Any other shape produces a clean
failed-task response.
"""

from __future__ import annotations

import warnings

from a2a.helpers.proto_helpers import get_data_parts, new_data_part, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.utils.errors import UnsupportedOperationError

from .. import server
from ..governed import GovernedError, call_governed
from ..principal import ledger_principal


class ProximoAgentExecutor(AgentExecutor):
    """Stateless A2A executor — parses, routes through the governed core, replies."""

    async def _fail(self, updater: TaskUpdater, message: str) -> None:
        """Wrap `message` in a TaskUpdater failed-message — the shared 'fail the task' tail."""
        await updater.failed(updater.new_agent_message([new_text_part(message)]))

    def _audit_rejection(self, tool_name: str | None, reason: str) -> None:
        """Best-effort PROVE trace for a REJECTED A2A call (unknown tool / bad params / no tool).

        The failed-task returned to the caller is the primary guarantee; this records the rejection
        to the same tamper-evident ledger the tools use, so hostile enumeration isn't invisible.
        Uses the tolerant ``server._ledger()`` (not ``_svc()``, which raises when the PVE triple is
        unset — that would blackhole the trace during exactly the enumeration it exists to catch).
        Only the reason + tool name are recorded — never raw params or secrets.
        """
        try:
            server._ledger().record("a2a_rejected", target=str(tool_name or "<none>"),
                                    mutation=False, outcome="rejected", detail={"reason": reason},
                                    principal=ledger_principal())
        except Exception as exc:  # noqa: BLE001 — supplementary audit; never break the rejection path
            warnings.warn(f"A2A rejection audit failed to record: {type(exc).__name__}", stacklevel=2)

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Parse the inbound message, route to the governed core, publish result or failure."""
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")

        tool_name: str | None = None
        params: dict | None = None
        message = context.message
        if message is not None:
            for payload in get_data_parts(message.parts):
                if isinstance(payload, dict) and ("tool" in payload or "skill" in payload):
                    tool_name = payload.get("tool", payload.get("skill"))
                    raw = payload.get("params")
                    params = raw if isinstance(raw, dict) else {}
                    break

        if tool_name is None:
            self._audit_rejection(None, "no tool in inbound message")
            await self._fail(
                updater,
                'Expected a DataPart with shape {"tool": "<name>", "params": {...}}.'
                " No such part found in the inbound message.",
            )
            return

        try:
            result = await call_governed(tool_name, params or {})
        except GovernedError as exc:
            if exc.status in (400, 404):
                self._audit_rejection(tool_name, exc.message)
            await self._fail(updater, exc.message)
            return
        except Exception as exc:  # noqa: BLE001 -- last-resort sanitize; never leak a traceback
            await self._fail(updater, f"tool '{tool_name}' failed: {type(exc).__name__}")
            return

        await updater.add_artifact(parts=[new_data_part(result)], name="result")
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise UnsupportedOperationError()
