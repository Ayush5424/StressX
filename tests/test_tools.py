import pytest
from app.models.target import Target
from app.models.session import AuditSession
from app.tools.registry import ToolRegistry
from app.tools.discover_http_surface import DiscoverHttpSurfaceTool
from app.tools.record_evidence import RecordEvidenceTool


@pytest.mark.asyncio
async def test_tool_registry_registration():
    registry = ToolRegistry()
    tool_names = registry.list_tool_names()
    assert "discover_http_surface" in tool_names
    assert "send_http_request" in tool_names
    assert "inspect_http_response" in tool_names
    assert "manage_test_session" in tool_names
    assert "compare_responses" in tool_names
    assert "record_evidence" in tool_names
    assert "finish_audit" in tool_names


@pytest.mark.asyncio
async def test_tool_boundary_blocking():
    registry = ToolRegistry()
    target = Target(base_url="http://127.0.0.1:8088", allowed_hosts=["127.0.0.1"])
    session = AuditSession(target=target)

    # Attempt to send request to external attacker/disallowed host
    obs = await registry.execute_tool(
        "send_http_request",
        session,
        {"method": "GET", "path": "http://evil-external-site.com/exploit"}
    )
    assert "Target boundary violation" in obs.summary
    assert "TargetBoundaryViolation" in obs.raw_data.get("error", "")


@pytest.mark.asyncio
async def test_record_evidence_tool():
    target = Target(base_url="http://127.0.0.1:8088")
    session = AuditSession(target=target)
    registry = ToolRegistry()

    obs = await registry.execute_tool(
        "record_evidence",
        session,
        {
            "title": "Information Disclosure in Debug Route",
            "category": "INFORMATION_DISCLOSURE",
            "severity": "HIGH",
            "confidence": "HIGH",
            "endpoint": "/api/v1/debug/env",
            "description": "Environment variables leaked in response",
            "impact": "Credentials exposed",
            "remediation": "Disable debug routes"
        }
    )

    assert "Confirmed and recorded finding" in obs.summary
    assert len(session.findings) == 1
    finding = session.findings[0]
    assert finding.title == "Information Disclosure in Debug Route"
    assert len(finding.evidence) >= 1
    assert finding.evidence[0].verified is True
