from typing import Any
from app.tools.base import BaseTool
from app.models.session import AuditSession, SessionStatus
from app.models.observation import Observation


class FinishAuditTool(BaseTool):
    """Tool for concluding the autonomous security audit session."""

    name = "finish_audit"
    description = (
        "Concludes the active security testing session, closes network connections, "
        "and aggregates all empirical observations into the final audit assessment report."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "High-level summary of audit conclusion"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        conclusion_notes = kwargs.get("summary", "Autonomous audit finalized.")
        session.complete(SessionStatus.COMPLETED)

        from app.models.metrics import AuditMetrics
        metrics = AuditMetrics.calculate_from_session(session)

        # Print concise metrics summary as required
        print(
            f"\n## Audit completed\n\n"
            f"Duration: {metrics.duration_seconds:.1f}s\n"
            f"Steps: {metrics.total_steps}\n"
            f"Reconnaissance steps: {metrics.reconnaissance_steps}\n"
            f"Active test steps: {metrics.active_test_steps}\n"
            f"Endpoints discovered: {metrics.total_endpoints_discovered}\n"
            f"Unique endpoints tested: {metrics.unique_endpoints_tested}\n"
            f"HTTP requests: {metrics.total_http_requests}\n"
            f"Hypotheses: {metrics.total_hypotheses}\n"
            f"Confirmed findings: {metrics.confirmed_findings}\n"
            f"Evidence records: {metrics.evidence_records}\n"
            f"Verification attempts: {metrics.verification_attempts}\n"
            f"Repeated actions prevented: {metrics.repeated_actions_prevented}\n"
            f"Tool calls: {metrics.tool_calls}\n\n"
            f"Report location: audit_reports/{session.id}/\n"
        )

        insights = [
            f"Audit finished with status: {session.status.value}",
            f"Duration: {metrics.duration_seconds:.1f}s",
            f"Steps: {metrics.total_steps}",
            f"Reconnaissance steps: {metrics.reconnaissance_steps}",
            f"Active test steps: {metrics.active_test_steps}",
            f"Endpoints discovered: {metrics.total_endpoints_discovered}",
            f"HTTP requests: {metrics.total_http_requests}",
            f"Hypotheses: {metrics.total_hypotheses}",
            f"Confirmed findings: {metrics.confirmed_findings}",
            f"Evidence records: {metrics.evidence_records}",
            f"Repeated actions prevented: {metrics.repeated_actions_prevented}",
            f"Tool calls: {metrics.tool_calls}",
            f"Report location: audit_reports/{session.id}/"
        ]

        summary = (
            f"Audit completed against {session.target.base_url}. "
            f"Identified {metrics.confirmed_findings} confirmed security findings. {conclusion_notes}"
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=session.target.base_url,
            summary=summary,
            key_insights=insights,
            raw_data=metrics.model_dump()
        )
