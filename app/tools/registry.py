import logging
from typing import Dict, Any, Optional
from app.tools.base import BaseTool
from app.tools.discover_http_surface import DiscoverHttpSurfaceTool
from app.tools.send_http_request import SendHttpRequestTool
from app.tools.inspect_http_response import InspectHttpResponseTool
from app.tools.manage_test_session import ManageTestSessionTool
from app.tools.run_browser import RunBrowserTool
from app.tools.inspect_page import InspectPageTool
from app.tools.compare_responses import CompareResponsesTool
from app.tools.measure_baseline import MeasureBaselineTool
from app.tools.pressure_test import PressureTestTool
from app.tools.concurrency_test import ConcurrencyTestTool
from app.tools.test_idempotency import TestIdempotencyTool
from app.tools.inject_failure import InjectFailureTool
from app.tools.record_evidence import RecordEvidenceTool
from app.tools.finish_audit import FinishAuditTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.target import TargetBoundaryViolation

logger = logging.getLogger("stressx.tools")


class ToolRegistry:
    """Manages the lifecycle, schema exposure, and boundary enforcement of audit tools."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        tools = [
            DiscoverHttpSurfaceTool(),
            SendHttpRequestTool(),
            InspectHttpResponseTool(),
            ManageTestSessionTool(),
            RunBrowserTool(),
            InspectPageTool(),
            CompareResponsesTool(),
            MeasureBaselineTool(),
            PressureTestTool(),
            ConcurrencyTestTool(),
            TestIdempotencyTool(),
            InjectFailureTool(),
            RecordEvidenceTool(),
            FinishAuditTool()
        ]
        for t in tools:
            self._tools[t.name] = t

    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def get_tools_prompt_description(self) -> str:
        """Returns formatted tool descriptions and parameter schemas for LLM prompts."""
        lines = []
        for name, tool in self._tools.items():
            lines.append(f"Tool: {name}")
            lines.append(f"Description: {tool.description}")
            lines.append(f"Parameters Schema: {tool.parameters_schema}")
            lines.append("-" * 40)
        return "\n".join(lines)

    async def execute_tool(self, tool_name: str, session: AuditSession, arguments: dict[str, Any]) -> Observation:
        """Executes a tool with boundary checking and exception isolation."""
        tool = self.get_tool(tool_name)
        if not tool:
            logger.error(f"Unknown tool requested: {tool_name}")
            return Observation(
                step=session.step_count,
                tool=tool_name,
                target=session.target.base_url,
                summary=f"Execution rejected: Unknown tool '{tool_name}'",
                key_insights=[f"Tool '{tool_name}' does not exist in registry."],
                raw_data={"error": f"Tool '{tool_name}' not registered"}
            )

        try:
            return await tool.execute(session, **arguments)
        except TargetBoundaryViolation as e:
            logger.warning(f"Target boundary violation: {e}")
            return Observation(
                step=session.step_count,
                tool=tool_name,
                target=session.target.base_url,
                summary=f"TOOL EXECUTION BLOCKED: Target boundary violation ({str(e)})",
                key_insights=["Execution blocked because target violates authorized assessment scope."],
                raw_data={"error": "TargetBoundaryViolation", "details": str(e)}
            )
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}", exc_info=True)
            return Observation(
                step=session.step_count,
                tool=tool_name,
                target=session.target.base_url,
                summary=f"Error executing {tool_name}: {type(e).__name__} ({str(e)})",
                key_insights=[f"Tool error: {str(e)}"],
                raw_data={"error": str(e)}
            )
