import os
import json
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.models.target import Target
from app.models.session import AuditSession
from app.models.config import AuditConfig, TargetComplexity, AuditStatus
from app.agent.controller import AgentController
from app.evidence.store import EvidenceStore
from app.api.events import EVENT_MANAGER, AuditEventType, AuditEvent
from app.api.manager import AUDIT_MANAGER

api_app = FastAPI(
    title="StressX Autonomous AI Security Audit Engine",
    description="Creator-style autonomous security audit and resilience testing dashboard and control plane.",
    version="0.2.0"
)

STATIC_DIR = Path(__file__).parent.parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_DIR = STATIC_DIR / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

# Mount production compiled React static assets
api_app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

# Request / Response Schemas
class AnalyzeProjectRequest(BaseModel):
    project_path: str


class CreateAuditRequest(BaseModel):
    project_path: str
    selected_steps: Optional[int] = None
    name: Optional[str] = None
    audit_name: Optional[str] = None



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


# Dashboard Web App Entrypoint
@api_app.get("/")
async def get_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "StressX Autonomous Security Testing Dashboard API"}


# Modern Audit Control & Complexity Endpoints
@api_app.post("/api/projects/analyze")
async def analyze_project(req: AnalyzeProjectRequest):
    """Inspects a local codebase, identifies architectural components, and computes deterministic complexity."""
    try:
        return AUDIT_MANAGER.analyze_project(req.project_path)
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=404, detail=str(fnf))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Analysis failed: {e}")


@api_app.post("/api/audits", response_model=AuditConfig)
async def create_audit(req: CreateAuditRequest):
    """Registers an audit session with calculated complexity and recommended/selected step budget."""
    try:
        return AUDIT_MANAGER.create_audit(
            project_path=req.project_path,
            selected_steps=req.selected_steps,
            name=req.name,
            audit_name=req.audit_name
        )
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=404, detail=str(fnf))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create audit: {e}")


@api_app.post("/api/audits/{audit_id}/start", response_model=AuditConfig)
async def start_audit(audit_id: str):
    """Deploys the target inside an isolated sandbox and launches autonomous attack testing."""
    try:
        return await AUDIT_MANAGER.start_audit(audit_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit not found")
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to launch audit: {e}")


@api_app.post("/api/audits/{audit_id}/stop")
async def stop_audit(audit_id: str):
    """Signals active controller to stop gracefully, preserving evidence, partial report, and teardown."""
    success = await AUDIT_MANAGER.stop_audit(audit_id)
    if not success:
        raise HTTPException(status_code=404, detail="Active audit not found or already stopped")
    return {"status": "STOPPING", "audit_id": audit_id, "message": "Graceful stop requested."}


@api_app.get("/api/audits/{audit_id}", response_model=AuditConfig)
async def get_audit(audit_id: str):
    """Returns configuration and current status of an audit."""
    config = AUDIT_MANAGER.get_audit(audit_id)
    if not config:
        raise HTTPException(status_code=404, detail="Audit not found")
    return config


@api_app.get("/api/audits/{audit_id}/events")
async def stream_audit_events(audit_id: str):
    """Server-Sent Events (SSE) stream for real-time live dashboard monitoring with history replay."""
    async def event_generator():
        try:
            async for event in EVENT_MANAGER.subscribe(audit_id):
                yield f"data: {event.model_dump_json()}\n\n"
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@api_app.websocket("/ws/audits/{audit_id}")
async def websocket_audit_events(websocket: WebSocket, audit_id: str):
    """WebSocket stream for low-latency live audit events."""
    await websocket.accept()
    try:
        async for event in EVENT_MANAGER.subscribe(audit_id):
            await websocket.send_text(event.model_dump_json())
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass


@api_app.get("/api/audits/{audit_id}/surface")
async def get_audit_surface(audit_id: str):
    """Returns categorized attack surfaces: discovered, testing, tested, invalid, blocked."""
    return AUDIT_MANAGER.get_surface(audit_id)


@api_app.get("/api/audits/{audit_id}/activity")
async def get_audit_activity(audit_id: str):
    """Returns real-time AI reasoning, current tool, hypothesis, and next decision."""
    return AUDIT_MANAGER.get_activity(audit_id)


@api_app.get("/api/audits/{audit_id}/findings")
async def get_audit_findings(audit_id: str):
    """Returns confirmed findings with full empirical evidence items and reproduction steps."""
    findings = AUDIT_MANAGER.get_findings(audit_id)
    return {"audit_id": audit_id, "total": len(findings), "findings": findings}


@api_app.get("/api/reports")
async def list_reports():
    """Lists historical audit reports found in the audit_reports/ directory."""
    return AUDIT_MANAGER.list_reports()


@api_app.get("/api/reports/{audit_id}")
async def get_report_details(audit_id: str):
    """Returns complete audit dossier for report viewer: markdown, metrics, findings, actions, evidence."""
    try:
        return AUDIT_MANAGER.get_report_details(audit_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Audit report not found")


@api_app.get("/api/stats")
async def get_stats():
    """Returns global metrics for the dashboard overview cards."""
    return AUDIT_MANAGER.get_global_stats()


# Legacy API Compatibility Endpoints
@api_app.post("/api/sessions", response_model=AuditSessionResponse)
async def legacy_create_session(req: StartAuditRequest, background_tasks: BackgroundTasks):
    target = Target(
        base_url=req.base_url,
        allowed_hosts=req.allowed_hosts or [],
        allowed_ports=req.allowed_ports or [],
        name=req.name or "Target"
    )
    controller = AgentController(target=target, max_steps=req.max_steps)
    session = controller.session
    AUDIT_MANAGER.controllers[session.id] = controller

    background_tasks.add_task(controller.run_audit)

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
async def legacy_get_session(session_id: str):
    controller = AUDIT_MANAGER.controllers.get(session_id)
    if not controller:
        raise HTTPException(status_code=404, detail="Audit session not found")
    session = controller.session
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
async def legacy_get_findings(session_id: str):
    controller = AUDIT_MANAGER.controllers.get(session_id)
    if not controller:
        raise HTTPException(status_code=404, detail="Audit session not found")
    return {
        "session_id": session_id,
        "total_findings": len(controller.session.findings),
        "findings": [f.model_dump() for f in controller.session.findings]
    }


@api_app.get("/api/sessions/{session_id}/trace")
async def legacy_get_trace(session_id: str):
    controller = AUDIT_MANAGER.controllers.get(session_id)
    if not controller:
        raise HTTPException(status_code=404, detail="Audit session not found")
    session = controller.session
    return {
        "session_id": session.id,
        "step_count": session.step_count,
        "status": session.status.value,
        "attempts": [a.model_dump() for a in session.attack_attempts],
        "observations": [o.model_dump() for o in session.observations],
        "hypotheses": [h.model_dump() for h in session.hypotheses]
    }


# React SPA Catch-All Route (Fallback for Client-Side Routing)
@api_app.get("/{full_path:path}")
async def serve_spa_fallback(full_path: str):
    """Serves the canonical React index.html for client-side routing, while preserving 404s for API/asset misses."""
    if full_path.startswith("api/") or full_path.startswith("assets/") or full_path.startswith("ws/"):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "StressX Autonomous Security Testing Dashboard API"}

