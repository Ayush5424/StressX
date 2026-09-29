import asyncio
from typing import Optional, Dict
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from app.models.target import Target
from app.models.session import AuditSession
from app.agent.controller import AgentController
from app.evidence.store import EvidenceStore

api_app = FastAPI(
    title="StressX AI Autonomous Security Audit Engine",
    description="API for managing autonomous security audit sessions and retrieving empirical findings.",
    version="0.1.0"
)

# In-memory session registry for active/completed audits
SESSIONS: Dict[str, AuditSession] = {}
EVIDENCE_STORE = EvidenceStore()


class StartAuditRequest(BaseModel):
    base_url: str
    allowed_hosts: Optional[list[str]] = None
    allowed_ports: Optional[list[int]] = None
    name: Optional[str] = "Target Application"
    max_steps: int = 25


class AuditSessionResponse(BaseModel):
    session_id: str
    status: str
    target_url: str
    step_count: int
    max_steps: int
    findings_count: int
    start_time: str
    end_time: Optional[str] = None


async def run_audit_background(controller: AgentController):
    session = await controller.run_audit()
    EVIDENCE_STORE.save_session_dossier(session)
    EVIDENCE_STORE.generate_markdown_report(session)


@api_app.post("/api/sessions", response_model=AuditSessionResponse)
async def create_audit_session(req: StartAuditRequest, background_tasks: BackgroundTasks):
    """Initializes and begins an asynchronous autonomous security audit."""
    target = Target(
        base_url=req.base_url,
        allowed_hosts=req.allowed_hosts or [],
        allowed_ports=req.allowed_ports or [],
        name=req.name or "Target"
    )

    controller = AgentController(target=target, max_steps=req.max_steps)
    session = controller.session
    SESSIONS[session.id] = session

    # Run in background
    background_tasks.add_task(run_audit_background, controller)

    return AuditSessionResponse(
        session_id=session.id,
        status=session.status.value,
        target_url=target.base_url,
        step_count=session.step_count,
        max_steps=session.max_steps,
        findings_count=len(session.findings),
        start_time=session.start_time
    )


@api_app.get("/api/sessions/{session_id}", response_model=AuditSessionResponse)
async def get_session_status(session_id: str):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found")

    return AuditSessionResponse(
        session_id=session.id,
        status=session.status.value,
        target_url=session.target.base_url,
        step_count=session.step_count,
        max_steps=session.max_steps,
        findings_count=len(session.findings),
        start_time=session.start_time,
        end_time=session.end_time
    )


@api_app.get("/api/sessions/{session_id}/findings")
async def get_session_findings(session_id: str):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found")

    return {
        "session_id": session.id,
        "total_findings": len(session.findings),
        "findings": [f.model_dump() for f in session.findings]
    }


@api_app.get("/api/sessions/{session_id}/trace")
async def get_session_trace(session_id: str):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found")

    return {
        "session_id": session.id,
        "step_count": session.step_count,
        "status": session.status.value,
        "attempts": [a.model_dump() for a in session.attack_attempts],
        "observations": [o.model_dump() for o in session.observations],
        "hypotheses": [h.model_dump() for h in session.hypotheses]
    }
