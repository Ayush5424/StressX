import pytest
import asyncio
from app.models.target import Target
from app.models.session import SessionStatus
from app.agent.controller import AgentController
from app.target.runner import TargetRunner


@pytest.mark.asyncio
async def test_agent_autonomous_audit_loop():
    """Runs an autonomous audit loop with the controller against the controlled target."""
    runner = TargetRunner(port=8089, use_docker=False)
    target = runner.start()

    try:
        from app.models.adapter import AutonomousSecurityReasoningEngine
        model = AutonomousSecurityReasoningEngine()
        controller = AgentController(target=target, model=model, max_steps=18)
        session = await controller.run_audit()

        assert session.status == SessionStatus.COMPLETED
        assert session.step_count > 0

        # Verify hypotheses were formed
        assert len(session.hypotheses) > 0

        # Verify findings were confirmed and backed by evidence
        assert len(session.findings) >= 3
        
        # Verify findings have actual empirical evidence
        for finding in session.findings:
            assert len(finding.evidence) >= 1
            assert finding.evidence[0].verified is True
            assert finding.reproduction_steps is not None
            assert len(finding.reproduction_steps) >= 3

        # Check for specific vulnerability types tested
        categories = [f.category.value for f in session.findings]
        assert "INFORMATION_DISCLOSURE" in categories
        assert "UNSAFE_INPUT_HANDLING" in categories

    finally:
        runner.stop()
