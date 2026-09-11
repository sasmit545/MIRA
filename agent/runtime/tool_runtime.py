"""Tool runtime over the existing MCP client."""

import inspect
from collections.abc import Callable
from typing import Any, List

from ..contracts.tool import ToolCall, ToolResult, ToolSpec


class ToolRuntime:
    """Thin wrapper over the MCP client. No exception crosses this boundary."""

    def __init__(
        self,
        available_tools: List[ToolSpec],
        executor: Callable[[str, dict[str, Any]], Any] | None = None,
    ):
        self.available_tools = {tool.name: tool for tool in available_tools}
        self._executor = executor

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute one tool call, returning failures as observable results.

        The executor is the transport boundary: it receives a capability name
        and its arguments, and may be sync or async.
        """
        if tool_call.name not in self.available_tools:
            return ToolResult(
                tool_call_id=tool_call.tool_call_id,
                success=False,
                error=f"Unknown tool: {tool_call.name}",
            )

        if self._executor is None:
            return ToolResult(
                tool_call_id=tool_call.tool_call_id,
                success=False,
                error="No tool executor is configured",
            )

        try:
            result = self._executor(tool_call.name, tool_call.arguments)
            if inspect.isawaitable(result):
                result = await result
        except Exception as error:
            return ToolResult(
                tool_call_id=tool_call.tool_call_id,
                success=False,
                error=f"Tool execution failed: {error}",
            )

        failure = _envelope_error(result)
        if failure:
            return ToolResult(
                tool_call_id=tool_call.tool_call_id,
                success=False,
                error=failure,
            )

        return ToolResult(tool_call_id=tool_call.tool_call_id, success=True, output=result)


def _envelope_error(result: Any) -> str | None:
    """Surface a capability's own error envelope as a failed result.

    Transport success is not tool success: capabilities report their own
    failures in the payload, and a model shown those as successes will
    happily retry the same broken call forever.
    """
    if not isinstance(result, dict):
        return None
    status = result.get("status")
    if status is None or status == "ok":
        return None
    error = result.get("error") or {}
    code = error.get("code") or status
    message = error.get("message") or status
    return f"{code}: {message}"
