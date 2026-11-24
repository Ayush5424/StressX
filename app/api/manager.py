import os
import json
import uuid
import logging
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from app.models.config import AuditConfig, TargetComplexity, AuditStatus, ComplexityLevel
from app.models.target import Target
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.finding import Finding
from app.target.detector import ProjectDetector, ProjectInfo, ProjectType
from app.target.complexity import ComplexityAnalyzer
from app.target.sandbox import DockerProjectSandbox
from app.target.compose_sandbox import ComposeProjectSandbox
from app.target.runner import TargetRunner
from app.agent.controller import AgentController
from app.api.events import EVENT_MANAGER, AuditEventType
from app.evidence.store import EvidenceStore

logger = logging.getLogger("stressx.api.manager")


class AuditManager:
    """Central orchestrator managing targets, sandboxes, controllers, and reports."""

    def __init__(self, reports_dir: Optional[str] = None):
        self.reports_dir = Path(reports_dir or "audit_reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.detector = ProjectDetector()
        self.analyzer = ComplexityAnalyzer()
        self.evidence_store = EvidenceStore(export_dir=str(self.reports_dir))

        self.audits: Dict[str, AuditConfig] = {}
        self.controllers: Dict[str, AgentController] = {}
        self.sandboxes: Dict[str, Any] = {}
        self.tasks: Dict[str, asyncio.Task] = {}

    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """Analyzes target directory structure, detects architecture, and calculates deterministic complexity."""
        target_p = Path(project_path).resolve()
        if not target_p.exists():
            raise FileNotFoundError(f"Target project path does not exist: {project_path}")

        project_info: ProjectInfo = self.detector.detect(str(target_p))
        complexity: TargetComplexity = self.analyzer.analyze(str(target_p), project_info)

        return {
            "project": {
                "name": project_info.description or target_p.name,
                "path": str(target_p),
                "type": project_info.project_type.value,
                "framework": project_info.description,
                "build_tool": project_info.build_file,
                "detected_port": project_info.detected_port,
                "is_multi_service": project_info.is_multi_service,
                "services": list(project_info.services),
                "primary_service": project_info.primary_service,
                "dockerfile": (target_p / "Dockerfile").exists(),
                "compose_file": bool(project_info.compose_file),
                "service_types": project_info.service_types
            },
            "complexity": complexity.model_dump()
        }

    def create_audit(
        self,
        project_path: Optional[str] = None,
        target_url: Optional[str] = None,
        selected_steps: Optional[int] = None,
        name: Optional[str] = None,
        audit_name: Optional[str] = None,
        user_id: str = "default"
    ) -> AuditConfig:
        """Inspects target or accepts running URL, registering a new audit session with explicit audit_name."""
        audit_id = f"audit_{uuid.uuid4().hex[:8]}"
        
        # If auditing a live running URL directly:
        if target_url and target_url.strip():
            url = target_url.strip().rstrip("/")
            from urllib.parse import urlparse
            parsed = urlparse(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            proj_name = name or f"Live Target ({parsed.netloc})"
            user_audit_name = (audit_name or "").strip() or f"{proj_name} Security Audit"
            effective_steps = selected_steps or 20
            
            complexity = TargetComplexity(
                level=ComplexityLevel.MEDIUM,
                score=50,
                recommended_steps=20,
                reasons=["Live running application URL direct audit"]
            )
            config = AuditConfig(
                audit_id=audit_id,
                user_id=user_id,
                audit_name=user_audit_name,
                target_name=proj_name,
                target_url=url,
                target_type="LIVE_URL",
                project_name=proj_name,
                complexity=complexity,
                recommended_steps=20,
                selected_steps=effective_steps,
                max_steps=effective_steps,
                step_budget=effective_steps,
                status=AuditStatus.CONFIGURED
            )
            self.audits[audit_id] = config
            logger.info(f"Created direct live URL audit configuration {audit_id} for {url} (user: {user_id})")
            return config

        if not project_path:
            raise ValueError("Either project_path or target_url must be provided.")

        target_p = Path(project_path)
        if not target_p.exists():
            raise FileNotFoundError(f"Target project path does not exist: {project_path}")

        analysis = self.analyze_project(str(target_p))
        comp_dict = analysis["complexity"]
        complexity = TargetComplexity(**comp_dict)

        project_target_name = analysis["project"]["name"] or target_p.name
        user_audit_name = (audit_name or "").strip() or (name or "").strip() or f"{project_target_name} Security Audit"

        effective_steps = selected_steps or complexity.recommended_steps
        if effective_steps < 5:
            effective_steps = 5

        config = AuditConfig(
            audit_id=audit_id,
            user_id=user_id,
            audit_name=user_audit_name,
            target_name=project_target_name,
            target_path=str(target_p),
            target_type="DIRECTORY",
            project_name=project_target_name,
            complexity=complexity,
            recommended_steps=complexity.recommended_steps,
            selected_steps=effective_steps,
            max_steps=effective_steps,
            step_budget=effective_steps,
            status=AuditStatus.CONFIGURED
        )

        self.audits[audit_id] = config

        asyncio.create_task(
            EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.COMPLEXITY_CALCULATED,
                data={
                    "audit_id": audit_id,
                    "audit_name": user_audit_name,
                    "complexity_score": complexity.score,
                    "level": complexity.level.value,
                    "recommended_steps": complexity.recommended_steps,
                    "selected_steps": effective_steps
                },
                summary=f"Calculated {complexity.level.value} complexity (score {complexity.score}). Recommended budget: {complexity.recommended_steps} steps."
            )
        )

        logger.info(f"Created audit configuration {audit_id} ('{user_audit_name}') for {project_target_name} with budget {effective_steps} steps")
        return config

    async def start_audit(self, audit_id: str, user_id: Optional[str] = None) -> AuditConfig:
        """Initializes and begins asynchronous sandbox preparation and autonomous agent controller."""
        config = self.get_audit(audit_id, user_id=user_id)
        if not config:
            raise KeyError(f"Audit {audit_id} not found or access denied")

        if config.status != AuditStatus.CONFIGURED:
            raise ValueError(f"Audit {audit_id} is already in state {config.status.value}")

        config.status = AuditStatus.INITIALIZING
        config.started_at = datetime.now(timezone.utc).isoformat()

        # Emit immediate start event so frontend renders immediately
        await EVENT_MANAGER.emit(
            audit_id=audit_id,
            event_type=AuditEventType.AUDIT_STARTED,
            data={
                "audit_id": audit_id,
                "audit_name": config.audit_name,
                "target_name": config.target_name,
                "status": "INITIALIZING"
            },
            summary=f"Audit '{config.audit_name}' initialized. Preparing target environment..."
        )

        # Launch sandbox preparation and attack loop asynchronously in background task
        task = asyncio.create_task(self._run_sandbox_and_audit(audit_id, config))
        self.tasks[audit_id] = task

        return config

    async def _run_sandbox_and_audit(self, audit_id: str, config: AuditConfig) -> None:
        """Background worker that handles asynchronous sandbox preparation, startup, and the audit loop."""
        sandbox = None
        target: Optional[Target] = None

        try:
            # Handle direct Live URL audit
            if config.target_url:
                from urllib.parse import urlparse
                parsed = urlparse(config.target_url)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                hostname = parsed.hostname or "127.0.0.1"
                target = Target(
                    base_url=config.target_url,
                    allowed_hosts=[hostname, "127.0.0.1", "localhost"],
                    allowed_ports=[port],
                    name=config.project_name
                )
                config.target_url = target.base_url
                config.status = AuditStatus.RUNNING
                config.phase = "RECON"
                
                await EVENT_MANAGER.emit(
                    audit_id=audit_id,
                    event_type=AuditEventType.SANDBOX_STARTED,
                    data={"base_url": target.base_url, "stage": "READY", "progress_pct": 100},
                    summary=f"Connected directly to live target application at {target.base_url}."
                )
                await EVENT_MANAGER.emit(
                    audit_id=audit_id,
                    event_type=AuditEventType.STATUS_CHANGED,
                    data={"status": "RUNNING"},
                    summary="Audit status transitioned to RUNNING."
                )
                
                controller = AgentController(
                    target=target,
                    max_steps=config.selected_steps or config.max_steps,
                    evidence_store=self.evidence_store,
                    config=config
                )
                controller.session.user_id = config.user_id
                controller.session.audit_name = config.audit_name
                controller.session.target_name = config.target_name
                controller.session.context_data["audit_name"] = config.audit_name
                controller.session.context_data["target_name"] = config.target_name
                self.controllers[audit_id] = controller
                
                await self._run_audit_loop(audit_id, controller, None)
                return

            # Stage 1: Inspect target project
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.SANDBOX_PROGRESS,
                data={
                    "stage": "PREPARING_TARGET",
                    "progress_pct": 15,
                    "detail": "Inspecting project structure and dependencies"
                },
                summary="Inspecting project structure..."
            )
            project_info = await asyncio.to_thread(self.detector.detect, config.target_path)

            # Stage 2: Building target sandbox
            config.status = AuditStatus.SANDBOXING
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.STATUS_CHANGED,
                data={"status": "SANDBOXING"},
                summary="Audit status transitioned to SANDBOXING."
            )
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.SANDBOX_PROGRESS,
                data={
                    "stage": "BUILDING_APPLICATION",
                    "progress_pct": 40,
                    "detail": f"Deploying isolated environment for {project_info.description}"
                },
                summary="Building target application sandbox..."
            )

            if project_info.compose_file:
                logger.info(f"Deploying ComposeProjectSandbox for {config.target_path}")
                sandbox = ComposeProjectSandbox(
                    project_info=project_info,
                    cpu_limit=1.0,
                    memory_limit_mb=1024,
                    startup_timeout_seconds=90.0
                )
                target = await asyncio.to_thread(sandbox.build_and_start)
            elif (Path(config.target_path) / "Dockerfile").exists() or project_info.project_type == ProjectType.DOCKERFILE:
                logger.info(f"Deploying DockerProjectSandbox for {config.target_path}")
                sandbox = DockerProjectSandbox(
                    project_info=project_info,
                    cpu_limit=1.0,
                    memory_limit_mb=1024,
                    startup_timeout_seconds=60.0
                )
                target = await asyncio.to_thread(sandbox.build_and_start)
            else:
                port = project_info.detected_port or 8080
                target = Target(
                    base_url=f"http://127.0.0.1:{port}",
                    allowed_hosts=["127.0.0.1", "localhost"],
                    allowed_ports=[port],
                    name=config.project_name
                )

            # Stage 3: Checking readiness
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.SANDBOX_PROGRESS,
                data={
                    "stage": "CHECKING_READINESS",
                    "progress_pct": 85,
                    "detail": f"Target active at {target.base_url}"
                },
                summary="Checking application readiness..."
            )

            if sandbox:
                self.sandboxes[audit_id] = sandbox

            config.target_url = target.base_url
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.SANDBOX_STARTED,
                data={
                    "base_url": target.base_url,
                    "is_multi_service": getattr(target, "is_multi_service", False),
                    "services": getattr(target, "services", []),
                    "stage": "READY",
                    "progress_pct": 100
                },
                summary=f"Isolated sandbox deployed at {target.base_url}."
            )

            # Stage 4: Launch AgentController
            config.status = AuditStatus.RUNNING
            config.phase = "RECON"
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.STATUS_CHANGED,
                data={"status": "RUNNING"},
                summary="Audit status transitioned to RUNNING."
            )

            controller = AgentController(
                target=target,
                max_steps=config.selected_steps or config.max_steps,
                evidence_store=self.evidence_store,
                config=config
            )
            controller.session.user_id = config.user_id
            controller.session.audit_name = config.audit_name
            controller.session.target_name = config.target_name
            controller.session.context_data["audit_name"] = config.audit_name
            controller.session.context_data["target_name"] = config.target_name

            self.controllers[audit_id] = controller

            await self._run_audit_loop(audit_id, controller, sandbox)

        except Exception as sb_err:
            logger.error(f"Sandbox / audit launch failed for {audit_id}: {sb_err}", exc_info=True)
            config.status = AuditStatus.FAILED
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.AUDIT_FAILED,
                data={"error": str(sb_err), "stage": "SANDBOX_FAILED"},
                summary=f"Audit execution aborted: {sb_err}"
            )
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.STATUS_CHANGED,
                data={"status": "FAILED"},
                summary="Audit status transitioned to FAILED."
            )
            if sandbox:
                try:
                    await asyncio.to_thread(sandbox.cleanup)
                except Exception:
                    pass

    async def _run_audit_loop(
        self,
        audit_id: str,
        controller: AgentController,
        sandbox: Optional[Any] = None
    ) -> None:
        """Executes the controller and guarantees proper sandbox cleanup and state finalization."""
        config = self.audits.get(audit_id)
        try:
            session = await controller.run_audit()
            if config:
                config.steps_completed = session.step_count
                config.findings_count = len(session.findings)
                config.completed_at = session.end_time or datetime.now(timezone.utc).isoformat()
                if config.started_at and config.completed_at:
                    try:
                        s_dt = datetime.fromisoformat(config.started_at.replace("Z", "+00:00"))
                        e_dt = datetime.fromisoformat(config.completed_at.replace("Z", "+00:00"))
                        d_sec = max(0.0, (e_dt - s_dt).total_seconds())
                        config.duration_seconds = d_sec
                        dm = int(d_sec // 60)
                        ds = int(d_sec % 60)
                        config.duration = f"{dm}m {ds}s" if dm > 0 else f"{ds}s"
                    except Exception:
                        pass
                sev_counts = self.evidence_store._get_severity_counts(session)
                config.severity_breakdown = sev_counts
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    if sev_counts.get(s, 0) > 0:
                        config.highest_severity = s
                        break

                if session.context_data.get("stop_reason") == "USER_STOP_REQUESTED":
                    config.status = AuditStatus.STOPPED
                elif session.status == SessionStatus.COMPLETED or session.status == SessionStatus.TIMED_OUT:
                    config.status = AuditStatus.COMPLETED
                else:
                    config.status = AuditStatus.FAILED

                await EVENT_MANAGER.emit(
                    audit_id=audit_id,
                    event_type=AuditEventType.STATUS_CHANGED,
                    data={"status": config.status.value},
                    summary=f"Audit completed with status {config.status.value}."
                )
        except Exception as e:
            logger.error(f"Audit loop exception for {audit_id}: {e}", exc_info=True)
            if config:
                config.status = AuditStatus.FAILED
                await EVENT_MANAGER.emit(
                    audit_id=audit_id,
                    event_type=AuditEventType.STATUS_CHANGED,
                    data={"status": "FAILED"},
                    summary="Audit status transitioned to FAILED."
                )
        finally:
            if sandbox:
                try:
                    logger.info(f"Cleaning up sandbox for audit {audit_id}...")
                    await asyncio.to_thread(sandbox.cleanup)
                    await EVENT_MANAGER.emit(
                        audit_id=audit_id,
                        event_type=AuditEventType.SANDBOX_CLEANED,
                        data={"audit_id": audit_id},
                        summary="Sandbox resources and containers cleaned up."
                    )
                except Exception as clean_err:
                    logger.warning(f"Error during sandbox cleanup for {audit_id}: {clean_err}")

    async def stop_audit(self, audit_id: str, user_id: Optional[str] = None) -> bool:
        """Triggers graceful stop of active audit controller and sandbox teardown."""
        config = self.get_audit(audit_id, user_id=user_id)
        if not config:
            return False

        controller = self.controllers.get(audit_id)

        if controller:
            controller.request_stop()
            config.status = AuditStatus.STOPPING
            await EVENT_MANAGER.emit(
                audit_id=audit_id,
                event_type=AuditEventType.STATUS_CHANGED,
                data={"status": "STOPPING"},
                summary="Audit status transitioned to STOPPING."
            )
            logger.info(f"Stop signal sent to controller for audit {audit_id}")
            return True
        return False

    def get_audit(self, audit_id: str, user_id: Optional[str] = None) -> Optional[AuditConfig]:
        config = self.audits.get(audit_id)
        if not config:
            return None
        if user_id and config.user_id != user_id:
            logger.warning(f"Access denied: user '{user_id}' requested audit {audit_id} owned by '{config.user_id}'")
            raise PermissionError(f"Access denied: Audit '{audit_id}' belongs to another user.")
        return config

    def get_surface(self, audit_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns the classified attack surface status for the UI panels."""
        if not self.get_audit(audit_id, user_id=user_id):
            return {"total": 0, "endpoints": []}

        controller = self.controllers.get(audit_id)
        if not controller:
            return {"total": 0, "endpoints": []}

        session = controller.session
        discovered: List[str] = session.context_data.get("discovered_endpoints", [])
        invalid: List[str] = session.context_data.get("disallowed_or_404_paths", [])

        # Categorize endpoints
        tested_paths = set()
        for att in session.attack_attempts:
            if att.target:
                tested_paths.add(str(att.target))
        for hyp in session.hypotheses:
            if hyp.target_endpoint:
                tested_paths.add(str(hyp.target_endpoint))

        current_hyp = session.get_current_hypothesis()
        active_target = str(current_hyp.target_endpoint) if current_hyp and current_hyp.target_endpoint else None

        classified = []
        for ep in discovered:
            ep_str = str(ep)
            if any(inv in ep_str for inv in invalid):
                status = "invalid"
            elif active_target and active_target in ep_str:
                status = "testing"
            elif any(t in ep_str for t in tested_paths):
                status = "tested"
            else:
                status = "discovered"

            classified.append({
                "endpoint": ep_str,
                "status": status,
                "method": "ANY",
                "last_tested": next((att.timestamp for att in reversed(session.attack_attempts) if att.target and ep_str in str(att.target)), None)
            })

        return {
            "audit_id": audit_id,
            "total": len(classified),
            "discovered_count": sum(1 for c in classified if c["status"] == "discovered"),
            "testing_count": sum(1 for c in classified if c["status"] == "testing"),
            "tested_count": sum(1 for c in classified if c["status"] == "tested"),
            "invalid_count": sum(1 for c in classified if c["status"] == "invalid"),
            "endpoints": classified
        }

    def get_activity(self, audit_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Provides real-time AI reasoning, current tool, hypothesis, and decision data."""
        self.get_audit(audit_id, user_id=user_id)
        controller = self.controllers.get(audit_id)
        if not controller:
            return {"active": False}

        session = controller.session
        current_hyp = session.get_current_hypothesis()
        last_obs = session.observations[-1] if session.observations else None

        return {
            "active": session.status not in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.TIMED_OUT),
            "audit_id": audit_id,
            "step": session.step_count,
            "max_steps": session.max_steps,
            "phase": session.current_phase.value,
            "current_hypothesis": {
                "id": current_hyp.id,
                "category": current_hyp.category.value,
                "target_endpoint": current_hyp.target_endpoint,
                "description": current_hyp.description,
                "confidence": current_hyp.confidence.value,
                "status": current_hyp.status.value,
                "security_question": current_hyp.security_question
            } if current_hyp else None,
            "last_tool": last_obs.tool if last_obs else None,
            "last_target": last_obs.target if last_obs else None,
            "last_summary": last_obs.summary if last_obs else None,
            "insights": last_obs.key_insights if last_obs else [],
            "repetition_prevented": session.repeated_actions_prevented,
            "total_hypotheses": len(session.hypotheses),
            "total_findings": len(session.findings)
        }

    def get_findings(self, audit_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns confirmed findings with full empirical evidence items and reproduction steps."""
        if audit_id in self.audits:
            cfg = self.audits[audit_id]
            if user_id and cfg.user_id != user_id:
                raise PermissionError(f"Access denied: Audit '{audit_id}' belongs to another user.")
            controller = self.controllers.get(audit_id)
            if controller:
                return [f.model_dump() for f in controller.session.findings]

        rep_dir = self.reports_dir / audit_id
        rep_file = rep_dir / "report.json"
        find_file = rep_dir / "findings.json"

        if rep_file.exists():
            try:
                with open(rep_file, "r", encoding="utf-8") as f:
                    rep_data = json.load(f)
                    f_uid = rep_data.get("user_id")
                    if user_id and f_uid and f_uid != user_id:
                        raise PermissionError(f"Access denied: Audit report '{audit_id}' belongs to another user.")
            except PermissionError:
                raise
            except Exception:
                pass

        if find_file.exists():
            try:
                with open(find_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def list_reports(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scans the audit_reports directory and returns metadata summaries for past audits."""
        reports = []
        seen_audit_ids = set()
        if not self.reports_dir.exists():
            return []

        for p in self.reports_dir.iterdir():
            if p.is_dir():
                rep_json = p / "report.json"
                met_json = p / "metrics.json"
                find_json = p / "findings.json"

                audit_id = p.name
                rep_user_id = None
                data: Dict[str, Any] = {
                    "audit_id": audit_id,
                    "user_id": "default",
                    "audit_name": "Security Audit",
                    "target_name": "Target Application",
                    "target": "Unknown Target",
                    "timestamp": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
                    "status": "COMPLETED",
                    "total_steps": 0,
                    "duration": "0s",
                    "duration_seconds": 0.0,
                    "findings_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "highest_severity": "INFO",
                    "has_markdown": (p / "report.md").exists()
                }

                if rep_json.exists():
                    try:
                        with open(rep_json, "r", encoding="utf-8") as f:
                            rep = json.load(f)
                            rep_user_id = rep.get("user_id")
                            data["user_id"] = rep_user_id or "default"
                            data["audit_name"] = rep.get("audit_name") or rep.get("name") or data["audit_name"]
                            data["target_name"] = rep.get("target_name") or (rep.get("target") or {}).get("name") or data["target_name"]
                            data["target"] = (rep.get("target") or {}).get("base_url", data["target"])
                            data["timestamp"] = rep.get("start_time", data["timestamp"])
                            data["status"] = rep.get("status", data["status"])
                            data["total_steps"] = rep.get("step_count", rep.get("total_steps", 0))
                            data["duration_seconds"] = rep.get("duration_seconds", 0.0)
                            data["duration"] = rep.get("duration", data["duration"])
                            data["highest_severity"] = rep.get("highest_severity", data["highest_severity"])
                            if "severity_breakdown" in rep:
                                sb = rep["severity_breakdown"]
                                data["critical_count"] = sb.get("CRITICAL", 0)
                                data["high_count"] = sb.get("HIGH", 0)
                                data["medium_count"] = sb.get("MEDIUM", 0)
                                data["low_count"] = sb.get("LOW", 0)
                    except Exception:
                        pass

                # Enforce tenant isolation filter:
                if user_id:
                    if rep_user_id and rep_user_id != user_id:
                        continue
                    if not rep_user_id and user_id != "default":
                        continue

                seen_audit_ids.add(audit_id)

                if met_json.exists():
                    try:
                        with open(met_json, "r", encoding="utf-8") as f:
                            met = json.load(f)
                            if data["duration_seconds"] == 0.0:
                                dur_s = met.get("duration_seconds", 0.0)
                                data["duration_seconds"] = dur_s
                                dm = int(dur_s // 60)
                                ds = int(dur_s % 60)
                                data["duration"] = f"{dm}m {ds}s" if dm > 0 else f"{ds}s"
                            data["total_steps"] = met.get("total_steps", data["total_steps"])
                            if data["target"] == "Unknown Target":
                                data["target"] = met.get("target_base_url", data["target"])
                    except Exception:
                        pass

                if find_json.exists():
                    try:
                        with open(find_json, "r", encoding="utf-8") as f:
                            findings = json.load(f)
                            data["findings_count"] = len(findings)
                            data["critical_count"] = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                            data["high_count"] = sum(1 for f in findings if f.get("severity") == "HIGH")
                            data["medium_count"] = sum(1 for f in findings if f.get("severity") == "MEDIUM")
                            data["low_count"] = sum(1 for f in findings if f.get("severity") == "LOW")
                            if data["critical_count"] > 0:
                                data["highest_severity"] = "CRITICAL"
                            elif data["high_count"] > 0:
                                data["highest_severity"] = "HIGH"
                            elif data["medium_count"] > 0:
                                data["highest_severity"] = "MEDIUM"
                            elif data["low_count"] > 0:
                                data["highest_severity"] = "LOW"
                    except Exception:
                        pass

                reports.append(data)

        # Merge active / configured in-memory audits not yet persisted to disk
        for a_id, cfg in self.audits.items():
            if user_id and cfg.user_id != user_id:
                continue
            if a_id not in seen_audit_ids:
                reports.append({
                    "audit_id": a_id,
                    "user_id": cfg.user_id,
                    "audit_name": cfg.audit_name,
                    "target_name": cfg.target_name,
                    "target": cfg.target_url or cfg.target_path or "Target Application",
                    "timestamp": cfg.started_at or cfg.created_at,
                    "status": cfg.status.value,
                    "total_steps": cfg.steps_completed,
                    "duration": cfg.duration or "In Progress",
                    "duration_seconds": cfg.duration_seconds,
                    "findings_count": cfg.findings_count,
                    "critical_count": cfg.severity_breakdown.get("CRITICAL", 0),
                    "high_count": cfg.severity_breakdown.get("HIGH", 0),
                    "medium_count": cfg.severity_breakdown.get("MEDIUM", 0),
                    "low_count": cfg.severity_breakdown.get("LOW", 0),
                    "highest_severity": cfg.highest_severity or "INFO",
                    "has_markdown": False
                })

        reports.sort(key=lambda r: str(r.get("timestamp", "")), reverse=True)
        return reports

    def get_report_details(self, audit_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Loads complete dossier for an audit report including markdown, metrics, findings, actions, and evidence."""
        rep_dir = self.reports_dir / audit_id
        if not rep_dir.exists():
            cfg = self.audits.get(audit_id)
            if not cfg:
                raise FileNotFoundError(f"Report dossier not found for {audit_id}")
            if user_id and cfg.user_id != user_id:
                raise PermissionError(f"Access denied: Audit '{audit_id}' belongs to another user.")
            ctrl = self.controllers.get(audit_id)
            if ctrl:
                sess = ctrl.session
                return {
                    "audit_id": audit_id,
                    "user_id": cfg.user_id,
                    "audit_name": cfg.audit_name,
                    "target_name": cfg.target_name,
                    "duration": cfg.duration or "In Progress",
                    "status": cfg.status.value,
                    "findings": [f.model_dump() for f in sess.findings],
                    "actions": [a.model_dump() for a in sess.attack_attempts],
                    "report": {
                        "audit_id": audit_id,
                        "user_id": cfg.user_id,
                        "audit_name": cfg.audit_name,
                        "target_name": cfg.target_name,
                        "status": cfg.status.value,
                        "step_count": sess.step_count,
                        "findings_count": len(sess.findings),
                        "duration": cfg.duration or "In Progress",
                        "severity_breakdown": cfg.severity_breakdown
                    }
                }
            raise FileNotFoundError(f"Report dossier not found for {audit_id}")

        rep_file = rep_dir / "report.json"
        if rep_file.exists():
            try:
                with open(rep_file, "r", encoding="utf-8") as rf:
                    rep_data = json.load(rf)
                    f_uid = rep_data.get("user_id")
                    if user_id and f_uid and f_uid != user_id:
                        raise PermissionError(f"Access denied: Audit report '{audit_id}' belongs to another user.")
            except PermissionError:
                raise
            except Exception:
                pass
        elif audit_id in self.audits:
            cfg = self.audits[audit_id]
            if user_id and cfg.user_id != user_id:
                raise PermissionError(f"Access denied: Audit '{audit_id}' belongs to another user.")

        result: Dict[str, Any] = {"audit_id": audit_id}

        files_map = {
            "report": ("report.json", True),
            "metrics": ("metrics.json", True),
            "findings": ("findings.json", True),
            "evidence": ("evidence.json", True),
            "actions": ("actions.jsonl", False),
            "markdown": ("report.md", False)
        }

        for key, (filename, is_json) in files_map.items():
            fpath = rep_dir / filename
            if fpath.exists():
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        if is_json:
                            result[key] = json.load(f)
                        elif key == "actions":
                            lines = [json.loads(line.strip()) for line in f if line.strip()]
                            result[key] = lines
                        else:
                            result[key] = f.read()
                except Exception as e:
                    logger.warning(f"Error loading {filename} for {audit_id}: {e}")
                    result[key] = None
            else:
                result[key] = None

        if result.get("report"):
            rep = result["report"]
            result["user_id"] = rep.get("user_id", "default")
            result["audit_name"] = rep.get("audit_name", "Security Audit")
            result["target_name"] = rep.get("target_name", "Target Application")
            result["duration"] = rep.get("duration", "")
            result["status"] = rep.get("status", "COMPLETED")
        elif audit_id in self.audits:
            cfg = self.audits[audit_id]
            result["user_id"] = cfg.user_id
            result["audit_name"] = cfg.audit_name
            result["target_name"] = cfg.target_name
            result["duration"] = cfg.duration or ""
            result["status"] = cfg.status.value

        return result

    def get_global_stats(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Computes summary statistics across active audits and past reports."""
        reports = self.list_reports(user_id=user_id)
        total_reports = len(reports)
        total_findings = sum(r.get("findings_count", 0) for r in reports)
        critical_findings = sum(r.get("critical_count", 0) for r in reports)

        active_count = sum(
            1 for a in self.audits.values()
            if a.status in (AuditStatus.RUNNING, AuditStatus.STOPPING)
            and (not user_id or a.user_id == user_id)
        )

        unique_targets = set(r.get("target") for r in reports if r.get("target"))

        return {
            "active_audits": active_count,
            "total_audits": total_reports,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "unique_projects_tested": len(unique_targets)
        }
        total_reports = len(reports)
        total_findings = sum(r.get("findings_count", 0) for r in reports)
        critical_findings = sum(r.get("critical_count", 0) for r in reports)

        active_count = sum(
            1 for a in self.audits.values() if a.status in (AuditStatus.RUNNING, AuditStatus.STOPPING)
        )

        unique_targets = set(r.get("target") for r in reports if r.get("target"))

        return {
            "active_audits": active_count,
            "total_audits": total_reports,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "unique_projects_tested": len(unique_targets)
        }


# Singleton audit manager
AUDIT_MANAGER = AuditManager()
