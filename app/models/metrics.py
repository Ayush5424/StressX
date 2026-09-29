from datetime import datetime, timezone
from typing import Optional, Any
from pydantic import BaseModel, Field

from app.models.finding import FindingStatus, Severity, FindingCategory
from app.models.hypothesis import HypothesisStatus
from app.models.session import AuditSession


class ActionRecord(BaseModel):
    """Immutable record of an individual autonomous security testing action."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_id: str
    step: int
    tool: str
    intent: str
    target: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    hypothesis_id: Optional[str] = None
    outcome: str = "SUCCESS"
    success: bool = True
    summary: str


class AuditMetrics(BaseModel):
    """Verifiable numeric metrics derived from actual runtime observations of an audit."""
    audit_id: str
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    audit_duration: float = 0.0
    target: str
    project_type: str = "BENCHMARK"
    
    total_steps: int = 0
    reconnaissance_steps: int = 0
    active_test_steps: int = 0
    unique_endpoints_tested: int = 0
    testing_actions: int = 0
    total_http_requests: int = 0
    total_endpoints_discovered: int = 0
    
    total_hypotheses: int = 0
    hypotheses_created: int = 0
    hypotheses_supported: int = 0
    hypotheses_rejected: int = 0
    hypotheses_inconclusive: int = 0
    
    total_findings: int = 0
    confirmed_findings: int = 0
    likely_findings: int = 0
    inconclusive_findings: int = 0
    not_confirmed_findings: int = 0
    
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    
    evidence_records: int = 0
    verification_attempts: int = 0
    repeated_actions_prevented: int = 0
    tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    model_decisions: int = 0
    
    sandbox_deployments: int = 0
    sandbox_cleanup_success: int = 0
    
    authentication_tests: int = 0
    authorization_tests: int = 0
    injection_tests: int = 0
    information_disclosure_tests: int = 0
    other_security_tests: int = 0
    
    average_http_latency_ms: float = 0.0
    total_http_latency_ms: float = 0.0

    @classmethod
    def calculate_from_session(cls, session: AuditSession, project_type: Optional[str] = None) -> "AuditMetrics":
        """Calculates exact verified metrics from actual recorded session events."""
        # 1. Duration calculation
        duration_s = 0.0
        if session.start_time:
            t0 = datetime.fromisoformat(session.start_time)
            t1 = datetime.fromisoformat(session.end_time) if session.end_time else datetime.now(timezone.utc)
            duration_s = round(max((t1 - t0).total_seconds(), 0.0), 2)

        # 2. Endpoints discovered
        endpoints_count = len(session.context_data.get("discovered_endpoints", []))

        # 3. HTTP requests & Latency
        # Count actual HTTP requests sent across attempts and tools
        http_requests = 0
        total_latency = 0.0

        for att in session.attack_attempts:
            http_requests += 1
            # Extract latency if present in request/response
            if "latency_ms" in att.request_data:
                total_latency += float(att.request_data["latency_ms"])
            elif "elapsed_ms" in att.request_data:
                total_latency += float(att.request_data["elapsed_ms"])

        # Also account for discovery probes that made HTTP requests
        for obs in session.observations:
            raw = obs.raw_data
            if raw and "elapsed_ms" in raw and isinstance(raw["elapsed_ms"], (int, float)):
                total_latency += float(raw["elapsed_ms"])
            if obs.tool == "discover_http_surface" and "endpoints" in raw:
                # Add probe requests executed during surface discovery
                probes_count = len(raw.get("endpoints", []))
                if probes_count > 0 and http_requests < probes_count:
                    http_requests += probes_count

        avg_latency = round(total_latency / http_requests, 2) if http_requests > 0 else 0.0
        total_latency = round(total_latency, 2)

        # 4. Hypotheses breakdown
        total_hypo = len(session.hypotheses)
        hypo_supp = sum(1 for h in session.hypotheses if h.status == HypothesisStatus.SUPPORTED)
        hypo_rej = sum(1 for h in session.hypotheses if h.status == HypothesisStatus.REJECTED)
        hypo_inconc = sum(1 for h in session.hypotheses if h.status in (HypothesisStatus.INCONCLUSIVE, HypothesisStatus.TESTING, HypothesisStatus.FORMULATED))

        # 5. Findings breakdown by status
        total_find = len(session.findings)
        conf_find = sum(1 for f in session.findings if f.status == FindingStatus.CONFIRMED)
        likely_find = sum(1 for f in session.findings if f.status == FindingStatus.LIKELY)
        inconc_find = sum(1 for f in session.findings if f.status == FindingStatus.INCONCLUSIVE)
        not_conf_find = sum(1 for f in session.findings if f.status == FindingStatus.NOT_CONFIRMED)

        # 6. Findings breakdown by severity
        crit_find = sum(1 for f in session.findings if f.severity == Severity.CRITICAL)
        high_find = sum(1 for f in session.findings if f.severity == Severity.HIGH)
        med_find = sum(1 for f in session.findings if f.severity == Severity.MEDIUM)
        low_find = sum(1 for f in session.findings if f.severity == Severity.LOW)
        info_find = sum(1 for f in session.findings if f.severity == Severity.INFO)

        # 7. Tool calls and success
        total_tools = len(session.observations)
        failed_tools = sum(
            1 for o in session.observations
            if "error" in o.raw_data or "Error" in o.summary or "BLOCKED" in o.summary
        )
        succ_tools = max(total_tools - failed_tools, 0)

        # 8. Reconnaissance vs Active Testing Steps
        recon_tools = {"discover_http_surface", "inspect_http_response", "inspect_page"}
        active_tools = {"send_http_request", "manage_test_session", "compare_responses", "run_browser", "record_evidence"}
        
        recon_steps = 0
        active_steps = 0
        verification_attempts = 0
        unique_endpoints_tested_set = set()

        for obs in session.observations:
            if obs.tool in recon_tools:
                recon_steps += 1
            elif obs.tool in active_tools:
                active_steps += 1
            if obs.tool == "compare_responses":
                verification_attempts += 1
            if obs.tool in active_tools and obs.target:
                from urllib.parse import urlparse
                parsed = urlparse(obs.target)
                path = parsed.path or obs.target
                if path and path != session.target.base_url:
                    unique_endpoints_tested_set.add(path)

        for att in session.attack_attempts:
            if att.target:
                from urllib.parse import urlparse
                parsed = urlparse(att.target)
                path = parsed.path or att.target
                if path and path != session.target.base_url:
                    unique_endpoints_tested_set.add(path)
            action_lower = (att.action_summary or "").lower()
            if "verify" in action_lower or "confirm" in action_lower or "boolean" in action_lower or "diff" in action_lower:
                verification_attempts += 1

        testing_actions = max(active_steps, len(session.attack_attempts))

        # 9. Test classification
        authn_tests = 0
        authz_tests = 0
        inj_tests = 0
        info_tests = 0
        other_tests = 0

        for att in session.attack_attempts:
            target_str = (att.target or "").lower()
            action_str = (att.action_summary or "").lower()
            tool_str = (att.tool or "").lower()

            if "login" in target_str or "auth" in target_str or tool_str == "manage_test_session":
                authn_tests += 1
            elif "user" in target_str or "profile" in target_str or "admin" in target_str or "role" in action_str:
                authz_tests += 1
            elif "search" in target_str or "sql" in action_str or "'" in action_str or "inject" in action_str:
                inj_tests += 1
            elif "debug" in target_str or "env" in target_str or "leak" in action_str:
                info_tests += 1
            else:
                other_tests += 1

        resolved_project_type = project_type or session.context_data.get("project_type", "BENCHMARK")

        # Measured strictly from actual runtime sandbox lifecycle events
        # Zero fabrication or inference from project_type
        sandbox_dep = session.sandbox_deployments
        if sandbox_dep == 0 and session.target and getattr(session.target, "sandbox_deployment_success", False):
            sandbox_dep = 1

        sandbox_clean = session.sandbox_cleanup_success
        if sandbox_clean == 0 and session.target and getattr(session.target, "sandbox_cleanup_success", False):
            sandbox_clean = 1

        return cls(
            audit_id=session.id,
            start_time=session.start_time,
            end_time=session.end_time,
            duration_seconds=duration_s,
            audit_duration=duration_s,
            target=session.target.base_url,
            project_type=str(resolved_project_type),
            total_steps=session.step_count,
            reconnaissance_steps=recon_steps,
            active_test_steps=active_steps,
            unique_endpoints_tested=len(unique_endpoints_tested_set),
            testing_actions=testing_actions,
            total_http_requests=http_requests,
            total_endpoints_discovered=endpoints_count,
            total_hypotheses=total_hypo,
            hypotheses_created=total_hypo,
            hypotheses_supported=hypo_supp,
            hypotheses_rejected=hypo_rej,
            hypotheses_inconclusive=hypo_inconc,
            total_findings=total_find,
            confirmed_findings=conf_find,
            likely_findings=likely_find,
            inconclusive_findings=inconc_find,
            not_confirmed_findings=not_conf_find,
            critical_findings=crit_find,
            high_findings=high_find,
            medium_findings=med_find,
            low_findings=low_find,
            info_findings=info_find,
            evidence_records=len(session.evidence_store),
            verification_attempts=verification_attempts,
            repeated_actions_prevented=session.repeated_actions_prevented,
            tool_calls=total_tools,
            successful_tool_calls=succ_tools,
            failed_tool_calls=failed_tools,
            model_decisions=session.step_count,
            sandbox_deployments=sandbox_dep,
            sandbox_cleanup_success=sandbox_clean,
            authentication_tests=authn_tests,
            authorization_tests=authz_tests,
            injection_tests=inj_tests,
            information_disclosure_tests=info_tests,
            other_security_tests=other_tests,
            average_http_latency_ms=avg_latency,
            total_http_latency_ms=total_latency
        )


class AggregateMetrics(BaseModel):
    """Cumulative verified metrics aggregated across all completed StressX audits."""
    total_audits: int = 0
    total_targets: int = 0
    total_steps: int = 0
    total_reconnaissance_steps: int = 0
    total_active_test_steps: int = 0
    total_unique_endpoints_tested: int = 0
    total_http_requests: int = 0
    total_endpoints: int = 0
    total_hypotheses: int = 0
    total_confirmed_findings: int = 0
    total_evidence_records: int = 0
    total_verification_attempts: int = 0
    total_repeated_actions_prevented: int = 0
    total_sandbox_deployments: int = 0
    total_successful_sandbox_cleanups: int = 0
    total_tool_calls: int = 0
    audited_ids: list[str] = Field(default_factory=list)
    unique_targets: list[str] = Field(default_factory=list)
    audited_runs: dict[str, dict[str, Any]] = Field(default_factory=dict)

    def add_audit_metrics(self, m: AuditMetrics) -> bool:
        """Incorporates an audit's metrics idempotently, tracking deltas for post-cleanup updates."""
        if m.audit_id not in self.audited_ids:
            self.total_audits += 1
            self.audited_ids.append(m.audit_id)

            if m.target and m.target not in self.unique_targets:
                self.unique_targets.append(m.target)
            self.total_targets = len(self.unique_targets)

            self.total_steps += m.total_steps
            self.total_reconnaissance_steps += m.reconnaissance_steps
            self.total_active_test_steps += m.active_test_steps
            self.total_unique_endpoints_tested += m.unique_endpoints_tested
            self.total_http_requests += m.total_http_requests
            self.total_endpoints += m.total_endpoints_discovered
            self.total_hypotheses += m.total_hypotheses
            self.total_confirmed_findings += m.confirmed_findings
            self.total_evidence_records += m.evidence_records
            self.total_verification_attempts += m.verification_attempts
            self.total_repeated_actions_prevented += m.repeated_actions_prevented
            self.total_sandbox_deployments += m.sandbox_deployments
            self.total_successful_sandbox_cleanups += m.sandbox_cleanup_success
            self.total_tool_calls += m.tool_calls
            self.audited_runs[m.audit_id] = m.model_dump()
            return True

        prev = self.audited_runs.get(m.audit_id)
        if prev is None:
            delta_deployments = m.sandbox_deployments
            delta_cleanups = m.sandbox_cleanup_success
            self.total_sandbox_deployments += delta_deployments
            self.total_successful_sandbox_cleanups += delta_cleanups
            self.audited_runs[m.audit_id] = m.model_dump()
            return (delta_deployments > 0 or delta_cleanups > 0)

        delta_deployments = m.sandbox_deployments - prev.get("sandbox_deployments", 0)
        delta_cleanups = m.sandbox_cleanup_success - prev.get("sandbox_cleanup_success", 0)
        delta_steps = m.total_steps - prev.get("total_steps", 0)

        if delta_deployments == 0 and delta_cleanups == 0 and delta_steps == 0:
            return False

        self.total_sandbox_deployments += delta_deployments
        self.total_successful_sandbox_cleanups += delta_cleanups
        self.total_steps += delta_steps
        self.audited_runs[m.audit_id] = m.model_dump()
        return True
