"""Tool runtime over MCP client."""

import asyncio
import inspect
from collections.abc import Callable
from typing import Any, List

from ..contracts.tool import ToolCall, ToolResult, ToolSpec


class ToolRuntime:
    """Thin wrapper over the existing MCP client."""

    def __init__(
        self,
        available_tools: List[ToolSpec],
        executor: Callable[[str, dict[str, Any]], Any] | None = None,
    ):
        self.available_tools = {tool.name: tool for tool in available_tools}
        self._executor = executor

    def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a tool call and return a ToolResult.
        The executor is the runtime's MCP transport boundary. It receives a
        capability name and its validated arguments.
        """
        # Step 1: Validate
        tool_spec = self.available_tools.get(tool_call.name)
        if tool_spec is None:
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
            # If the executor returned a coroutine, run it
            if inspect.iscoroutine(result):
                try:
                    raw_result = asyncio.run(result)
                except RuntimeError:
                    # If there is already a running loop, we cannot use asyncio.run.
                    # In that case, we assume the executor is sync and just use the result.
                    raw_result = result
            else:
                raw_result = result
        except Exception as error:
            return ToolResult(
                tool_call_id=tool_call.tool_call_id,
                success=False,
                error=f"Tool execution failed: {error}",
            )
        return ToolResult(
            tool_call_id=tool_call.tool_call_id,
            success=True,
            output=raw_result,
        )
