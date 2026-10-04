import json
import os
from pathlib import Path
from typing import Optional, Any
from app.models.session import AuditSession
from app.models.metrics import ActionRecord, AuditMetrics, AggregateMetrics
from app.evidence.redact import redact_sensitive_text, redact_dict


class EvidenceStore:
    """Manages the persistence, formatting, action logging, and metrics export of audit dossiers."""

    def __init__(self, export_dir: str = "audit_reports"):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def get_audit_dir(self, audit_id: str) -> Path:
        """Returns and creates the dedicated directory for an individual audit."""
        audit_dir = self.export_dir / audit_id
        audit_dir.mkdir(parents=True, exist_ok=True)
        return audit_dir

    def log_action(self, action: ActionRecord) -> None:
        """Appends an individual action record to the audit's append-only actions.jsonl log."""
        audit_dir = self.get_audit_dir(action.audit_id)
        action_file = audit_dir / "actions.jsonl"

        # Scrub sensitive data before persistence
        action_dict = action.model_dump()
        action_dict["summary"] = redact_sensitive_text(action_dict.get("summary", ""))
        action_dict["intent"] = redact_sensitive_text(action_dict.get("intent", ""))
        if action_dict.get("target"):
            action_dict["target"] = redact_sensitive_text(action_dict["target"])

        with open(action_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(action_dict) + "\n")

    def save_audit_dossier(self, session: AuditSession, project_type: Optional[str] = None) -> tuple[Path, AuditMetrics]:
        """Saves metrics.json, actions.jsonl, findings.json, evidence.json, and report.json in audit_reports/<audit_id>/."""
        audit_dir = self.get_audit_dir(session.id)

        # 1. Calculate and save metrics.json
        metrics = AuditMetrics.calculate_from_session(session, project_type=project_type)
        metrics_file = audit_dir / "metrics.json"
        with open(metrics_file, "w", encoding="utf-8") as f:
            json.dump(metrics.model_dump(), f, indent=2)

        # 2. Save findings.json
        findings_file = audit_dir / "findings.json"
        sanitized_findings = [redact_dict(f.model_dump()) for f in session.findings]
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(sanitized_findings, f, indent=2)

        # 3. Save evidence.json
        evidence_file = audit_dir / "evidence.json"
        sanitized_evidence = {k: redact_dict(v.model_dump()) for k, v in session.evidence_store.items()}
        with open(evidence_file, "w", encoding="utf-8") as f:
            json.dump(sanitized_evidence, f, indent=2)

        # 4. Save report.json (complete summary report)
        multi_service_meta = None
        if getattr(session.target, "is_multi_service", False) or session.context_data.get("services_deployed"):
            multi_service_meta = {
                "services": session.context_data.get("services_deployed", getattr(session.target, "services", [])),
                "service_types": session.context_data.get("service_types", {}),
                "primary_target_service": session.context_data.get("primary_target_service", getattr(session.target, "primary_service", None)),
                "exposed_application_port": session.target.allowed_ports[0] if session.target.allowed_ports else None,
                "deployment_status": "SUCCESS" if session.sandbox_deployments > 0 else "FAILED",
                "cleanup_status": "SUCCESS" if session.sandbox_cleanup_success > 0 else "PENDING_OR_FAILED",
                "deployment_duration": getattr(session, "deployment_duration", 0.0)
            }

        audit_name = getattr(session, "audit_name", None) or session.context_data.get("audit_name", "Security Audit")
        target_name = getattr(session, "target_name", None) or getattr(session.target, "name", "Target Application")
        sev_counts = self._get_severity_counts(session)
        highest_sev = "INFO"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev_counts.get(s, 0) > 0:
                highest_sev = s
                break

        dur_secs = metrics.duration_seconds
        dur_mins = int(dur_secs // 60)
        dur_rem = int(dur_secs % 60)
        duration_str = f"{dur_mins}m {dur_rem}s" if dur_mins > 0 else f"{dur_rem}s"

        report_file = audit_dir / "report.json"
        report_data = {
            "audit_id": session.id,
            "audit_name": audit_name,
            "target_name": target_name,
            "target": redact_dict(session.target.model_dump()),
            "status": session.status.value,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "duration": duration_str,
            "duration_seconds": dur_secs,
            "step_count": session.step_count,
            "total_steps": session.step_count,
            "metrics": metrics.model_dump(),
            "multi_service": multi_service_meta,
            "findings_count": len(session.findings),
            "highest_severity": highest_sev,
            "severity_breakdown": sev_counts,
            "findings": sanitized_findings,
            "hypotheses": [redact_dict(h.model_dump()) for h in session.hypotheses]
        }
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # 5. Save human-readable report.md inside audit dir
        self.generate_markdown_report(session, target_dir=audit_dir)

        # 6. Update aggregate_metrics.json (idempotent across runs)
        self.update_aggregate_metrics(metrics)

        # 7. Also maintain backwards compatibility top-level dossier if needed
        self.save_session_dossier(session)

        return audit_dir, metrics

    def update_aggregate_metrics(self, metrics: AuditMetrics) -> AggregateMetrics:
        """Loads and updates cumulative metrics in audit_reports/aggregate_metrics.json."""
        aggregate_file = self.export_dir / "aggregate_metrics.json"

        aggregate = AggregateMetrics()
        if aggregate_file.exists():
            try:
                with open(aggregate_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    aggregate = AggregateMetrics.model_validate(data)
            except Exception:
                pass

        # Idempotently add metrics for this audit
        aggregate.add_audit_metrics(metrics)

        with open(aggregate_file, "w", encoding="utf-8") as f:
            json.dump(aggregate.model_dump(), f, indent=2)

        return aggregate

    def get_aggregate_metrics(self) -> AggregateMetrics:
        """Retrieves top-level aggregate metrics across all audits."""
        aggregate_file = self.export_dir / "aggregate_metrics.json"
        if aggregate_file.exists():
            try:
                with open(aggregate_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return AggregateMetrics.model_validate(data)
            except Exception:
                pass
        return AggregateMetrics()

    def save_session_dossier(self, session: AuditSession, filename: Optional[str] = None) -> str:
        """Maintains backward compatibility for tests expecting root session json."""
        name = filename or f"audit_dossier_{session.id}.json"
        target_path = self.export_dir / name

        data = {
            "session_id": session.id,
            "target": redact_dict(session.target.model_dump()),
            "status": session.status.value,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "step_count": session.step_count,
            "summary": {
                "total_findings": len(session.findings),
                "severity_breakdown": self._get_severity_counts(session),
                "total_attempts": len(session.attack_attempts),
                "total_evidence_artifacts": len(session.evidence_store)
            },
            "findings": [redact_dict(f.model_dump()) for f in session.findings],
            "hypotheses": [redact_dict(h.model_dump()) for h in session.hypotheses],
            "attack_attempts": [redact_dict(a.model_dump()) for a in session.attack_attempts],
            "observations": [redact_dict(o.model_dump()) for o in session.observations]
        }

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return str(target_path)

    def generate_markdown_report(
        self,
        session: AuditSession,
        filename: Optional[str] = None,
        target_dir: Optional[Path] = None
    ) -> str:
        """Generates an executive technical security report in Markdown."""
        base_dir = target_dir or self.export_dir
        name = filename or (f"security_report_{session.id}.md" if target_dir is None else "report.md")
        target_path = base_dir / name

        audit_name = getattr(session, "audit_name", None) or session.context_data.get("audit_name", "Security Assessment")
        target_name = getattr(session, "target_name", None) or getattr(session.target, "name", "Target Application")

        lines = [
            f"# {audit_name}",
            "### StressX Autonomous Security Assessment Report",
            f"**Audit ID:** `{session.id}`  ",
            f"**Target:** {target_name} (`{session.target.base_url}`)  ",
            f"**Audit Status:** `{session.status.value}`  ",
            f"**Execution Steps:** {session.step_count}  ",
            f"**Report Generated:** {session.end_time or session.start_time}  ",
            "",
            "## 1. Executive Summary",
            f"StressX completed an autonomous, empirical security evaluation of **{target_name}** (`{session.target.base_url}`). "
            f"A total of **{len(session.findings)}** vulnerability findings were discovered, tested, and empirically confirmed.",
            "",
            "### Finding Breakdown by Severity",
            "| Severity | Count |",
            "| :--- | :--- |",
        ]

        sev_counts = self._get_severity_counts(session)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| **{sev}** | {sev_counts.get(sev, 0)} |")

        if getattr(session.target, "is_multi_service", False):
            srv_list = ", ".join(getattr(session.target, "services", []))
            lines.extend([
                "",
                "### Multi-Service Compose Architecture",
                f"- **Primary Application Target:** `{session.target.primary_service}`",
                f"- **Services in Stack:** `{srv_list}`",
                f"- **Network Boundary:** Dedicated isolated network with unexposed internal data stores (PostgreSQL/Redis)."
            ])

        lines.extend([
            "",
            "## 2. Verified Vulnerability Findings & Empirical Evidence",
            ""
        ])

        if not session.findings:
            lines.append("*No confirmed vulnerabilities detected during this assessment session.*")
        else:
            for idx, finding in enumerate(session.findings, 1):
                lines.extend([
                    f"### {idx}. [{finding.severity.value}] {redact_sensitive_text(finding.title)}",
                    f"- **Category:** {finding.category.value}",
                    f"- **Status:** {finding.status.value}",
                    f"- **Confidence:** {finding.confidence.value}",
                    f"- **Affected Endpoint:** `{finding.affected_endpoint}`",
                    "",
                    f"**Description:**",
                    f"{redact_sensitive_text(finding.description)}",
                    "",
                    f"**Impact:**",
                    f"{redact_sensitive_text(finding.impact)}",
                    "",
                    "**Reproduction Runbook:**"
                ])
                for step in finding.reproduction_steps:
                    redacted_step = redact_sensitive_text(step)
                    lines.append(f"```bash\n{redacted_step}\n```" if "curl" in step else f"- {redacted_step}")

                if finding.evidence:
                    lines.append("\n**Verified Runtime Evidence:**")
                    for ev in finding.evidence:
                        lines.append(f"- **Evidence ID:** `{ev.id}` ({ev.evidence_type})")
                        lines.append(f"  - Request: `{redact_sensitive_text(ev.request_summary)}`")
                        lines.append(f"  - Response: `{redact_sensitive_text(ev.response_summary)}`")
                        if ev.curl_command:
                            lines.append(f"  - Exact Curl: `{redact_sensitive_text(ev.curl_command)}`")

                if finding.remediation:
                    lines.extend([
                        "",
                        f"**Actionable Remediation:**",
                        f"> {redact_sensitive_text(finding.remediation)}",
                        ""
                    ])
                lines.append("---")

        lines.extend([
            "",
            "## 3. Discovered Attack Surface",
            f"Endpoints detected: {', '.join(session.context_data.get('discovered_endpoints', []))}",
            "",
            "## 4. Assessment Limitations",
            "- This assessment was executed in an isolated test sandbox.",
            "- Only bounded, non-destructive security probes were dispatched.",
            "- Finding coverage is constrained to observable runtime behaviors."
        ])

        with open(target_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(target_path)

    def _get_severity_counts(self, session: AuditSession) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in session.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
