"""ProximoAgentExecutor — the A2A transport over the governed core.

Every inbound A2A call routes through the caller's ``dispatch`` (0.44: ``governed.Dispatch``; the
core door: its own), the same spine path (PLAN, PROVE, UNDO, the gates, the token scope) an MCP
client takes. The A2A face exposes the FULL tool
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

from a2a.helpers.proto_helpers import get_data_parts, new_data_part, new_task, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types.a2a_pb2 import TaskState
from a2a.utils.errors import UnsupportedOperationError

from ...doors.dispatch import DispatchError


class ProximoAgentExecutor(AgentExecutor):
    """Stateless A2A executor — parses, routes through the governed core, replies.

    ``dispatch`` is what a call runs on: the core's A2A door passes a ``dispatch.Core`` (the six
    core tools). ``record`` is how a rejection row is written: the core door's own
    (``network.recorder``), or an embedder's. Both are required: this module
    reaches nothing of the 0.44 server itself.
    """

    def __init__(self, *, dispatch, record) -> None:
        super().__init__()
        self._dispatch = dispatch
        self._record = record

    async def _fail(self, updater: TaskUpdater, message: str) -> None:
        """Wrap `message` in a TaskUpdater failed-message — the shared 'fail the task' tail."""
        await updater.failed(updater.new_agent_message([new_text_part(message)]))

    def _audit_rejection(self, tool_name: str | None, reason: str) -> None:
        """Best-effort PROVE trace for a REJECTED A2A call (unknown tool / bad params / no tool).

        The failed-task returned to the caller is the primary guarantee; this records the rejection
        to the same tamper-evident ledger the tools use, so hostile enumeration isn't invisible.
        Written through ``record``. Only the reason + tool name are recorded, never raw params or
        secrets.
        """
        target = str(tool_name or "<none>")
        try:
            self._record("a2a_rejected", target=target, outcome="rejected", detail={"reason": reason})
        except Exception as exc:  # noqa: BLE001 — supplementary audit; never break the rejection path
            warnings.warn(f"A2A rejection audit failed to record: {type(exc).__name__}", stacklevel=2)

    async def _call(self, tool_name: str, params: dict) -> dict:
        return await self._dispatch.call(tool_name, params)

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Parse the inbound message, route to the governed core, publish result or failure."""
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        if context.current_task is None:
            # THE TASK FIRST. The SDK refuses a status event on a task it has not seen
            # (`InvalidAgentResponseError: Agent should enqueue Task before ...`), and every failure
            # below is a status event (so is `updater.submit()`). An artifact creates the task on
            # its own, which is why the success path worked while every refusal, unknown tool and
            # malformed message crashed the request instead of failing the task. Found driving the
            # core's door with the real client, 2026-10-04; the old tests used a queue that ran no
            # ordering check.
            await event_queue.enqueue_event(new_task(
                context.task_id or "", context.context_id or "", TaskState.TASK_STATE_SUBMITTED,
                history=[context.message] if context.message is not None else None))

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
            result = await self._call(tool_name, params or {})
        except DispatchError as exc:
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
