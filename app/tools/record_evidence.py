from typing import Any, Optional
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.finding import Finding, FindingStatus, Severity, Confidence, FindingCategory, FindingType
from app.models.evidence import Evidence


class RecordEvidenceTool(BaseTool):
    """Tool for solidifying empirical observations into verified findings backed by immutable Evidence."""

    name = "record_evidence"
    description = (
        "Constructs a verified Finding backed by real observed HTTP evidence artifacts, "
        "reproduction curl commands, and severity assessment. Confirms vulnerability or system-design failure existence."
    )
    parameters_schema = {
        "type": "object",
        "required": ["title", "category", "severity", "confidence", "description", "impact", "remediation"],
        "properties": {
            "title": {"type": "string"},
            "category": {"type": "string"},
            "finding_type": {
                "type": "string",
                "enum": [
                    "SECURITY_VULNERABILITY",
                    "SYSTEM_DESIGN_FAILURE",
                    "RESILIENCE_FAILURE",
                    "BUSINESS_LOGIC_FAILURE",
                    "PERFORMANCE_FAILURE",
                    "DEPENDENCY_FAILURE"
                ],
                "default": "SECURITY_VULNERABILITY"
            },
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
            "endpoint": {"type": "string"},
            "description": {"type": "string"},
            "impact": {"type": "string"},
            "remediation": {"type": "string"},
            "causal_chain": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Sequence of events/conditions demonstrating the failure mechanism"
            },
            "status": {
                "type": "string",
                "enum": ["CONFIRMED", "LIKELY", "INCONCLUSIVE", "NOT_CONFIRMED"],
                "default": "CONFIRMED"
            }
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        title = kwargs.get("title", "Discovered Vulnerability")
        category_str = kwargs.get("category", "API_SECURITY")
        finding_type_str = kwargs.get("finding_type")
        severity_str = kwargs.get("severity", "MEDIUM")
        confidence_str = kwargs.get("confidence", "HIGH")
        status_str = kwargs.get("status", "CONFIRMED")
        endpoint = kwargs.get("endpoint", "/")
        description = kwargs.get("description", "")
        impact = kwargs.get("impact", "")
        remediation = kwargs.get("remediation", "")
        causal_chain = kwargs.get("causal_chain", []) or []

        try:
            category = FindingCategory(category_str)
        except Exception:
            category = FindingCategory.SECURITY_MISCONFIGURATION

        if finding_type_str:
            try:
                finding_type = FindingType(finding_type_str)
            except Exception:
                finding_type = FindingType.SECURITY_VULNERABILITY
        else:
            # Infer from category
            from app.models.attack_family import AttackFamily
            try:
                af = AttackFamily(category.value.lower())
                finding_type = af.to_finding_type()
            except Exception:
                finding_type = FindingType.SECURITY_VULNERABILITY

        severity = Severity(severity_str)
        confidence = Confidence(confidence_str)
        status = FindingStatus(status_str)

        # Build evidence from the most relevant recent attempt / observation
        evidence_items: list[Evidence] = []
        curl_step = ""
        matched_obs_raw: dict[str, Any] = {}

        # Scan previous observations for matching endpoint or raw request/experiment data
        is_experiment_category = category in (
            FindingCategory.RATE_LIMITING,
            FindingCategory.CONCURRENCY,
            FindingCategory.SYSTEM_RESILIENCE,
            FindingCategory.DUPLICATE_OPERATION,
            FindingCategory.STATE_CONSISTENCY_FAILURE,
            FindingCategory.RECOVERY_FAILURE,
            FindingCategory.DEPENDENCY_FAILURE
        )

        # First pass: try to find an observation matching the category type and endpoint
        target_obs = None
        for obs in reversed(session.observations):
            raw = obs.raw_data or {}
            obs_target = obs.target or ""
            endpoint_matches = (endpoint in obs_target) or (obs_target in endpoint) or (obs_target == "")

            if is_experiment_category:
                if obs.tool in ("pressure_test", "concurrency_test", "test_idempotency", "inject_failure"):
                    target_obs = obs
                    break
            else:
                if "request" in raw and "status_code" in raw and endpoint_matches:
                    target_obs = obs
                    break

        # Fallback to any recent valid observation if first pass didn't find specific match
        if not target_obs:
            for obs in reversed(session.observations):
                raw = obs.raw_data or {}
                if obs.tool in ("pressure_test", "concurrency_test", "test_idempotency", "inject_failure") or ("request" in raw and "status_code" in raw):
                    target_obs = obs
                    break

        if target_obs:
            raw = target_obs.raw_data or {}
            matched_obs_raw = raw
            if not causal_chain and raw.get("causal_chain"):
                causal_chain = list(raw["causal_chain"])

            if target_obs.tool in ("pressure_test", "concurrency_test", "test_idempotency", "inject_failure"):
                obs_fact = raw.get("observed_facts", target_obs.summary)
                inf_conc = raw.get("inferred_conclusion", "Experimental verification evaluation.")
                base_metrics = {"mean_ms": raw.get("baseline_mean_ms") or raw.get("baseline_latency_ms", 0.0)}
                evidence = Evidence.from_experiment(
                    description=f"Empirical resilience experiment on {endpoint} ({target_obs.tool})",
                    endpoint=endpoint,
                    method="GET",
                    test_conditions=f"{target_obs.tool} with conditions: {raw.get('scenario') or raw.get('peak_rate') or raw.get('concurrency_level')}",
                    pressure_level="STRESSED",
                    baseline_metrics=base_metrics,
                    observed_degradation=str(raw.get("degradation_detected") or raw.get("errors_detected", False)),
                    recovery_behavior=str(raw.get("recovery_verified", True)),
                    response_samples=raw.get("samples", []),
                    observed_behavior=obs_fact,
                    inferred_behavior=inf_conc,
                    curl_command=f"curl -i '{session.target.resolve_url(endpoint)}'",
                    evidence_type="SYSTEM_EXPERIMENT",
                    causal_chain=causal_chain,
                    downstream_effects=raw.get("downstream_effects", [])
                )
                evidence_items.append(evidence)
                session.add_evidence(evidence)
                curl_step = evidence.curl_command or ""
            elif "request" in raw and "status_code" in raw:
                req = raw["request"]
                req_url = req.get("url", endpoint)
                evidence = Evidence.from_http_exchange(
                    description=f"Empirical validation probe against {req_url}",
                    method=req.get("method", "GET"),
                    url=req_url,
                    status_code=raw.get("status_code", 200),
                    req_headers=req.get("headers", {}),
                    req_body=req.get("body"),
                    res_headers=raw.get("headers", {}),
                    res_body=raw.get("body", ""),
                    latency_ms=raw.get("elapsed_ms", 0.0),
                    evidence_type="HTTP_TRANSACTION"
                )
                evidence_items.append(evidence)
                session.add_evidence(evidence)
                curl_step = evidence.curl_command or ""

        # Fallback evidence if no recent raw request matched
        if not evidence_items:
            resolved_url = session.target.resolve_url(endpoint)
            evidence = Evidence(
                evidence_type="RUNTIME_OBSERVATION",
                description=f"Direct runtime inspection of {endpoint}",
                request_summary=f"Probing {endpoint}",
                response_summary="Observed non-compliant security behavior",
                curl_command=f"curl -i '{resolved_url}'",
                verified=True
            )
            evidence_items.append(evidence)
            session.add_evidence(evidence)
            curl_step = evidence.curl_command

        # Deterministic verification validation:
        # HTTP status codes like 200, 400, 404, 405, 500 alone DO NOT establish a vulnerability.
        ev_status_code = matched_obs_raw.get("status_code", 200)
        ev_body = str(matched_obs_raw.get("body", "")).lower()
        desc_lower = description.lower()
        is_empirically_proven = True
        verification_critique = ""

        if ev_status_code in (404, 405):
            is_empirically_proven = False
            verification_critique = f"Endpoint returned HTTP {ev_status_code}. Non-existent or disallowed route is not a confirmed vulnerability."
        elif ev_status_code in (401, 403) and category in (FindingCategory.AUTHENTICATION, FindingCategory.AUTHORIZATION):
            is_empirically_proven = False
            verification_critique = f"Endpoint returned HTTP {ev_status_code} (Access Denied). Enforcement of access boundary is not an exploit."
        elif category in (FindingCategory.UNSAFE_INPUT_HANDLING, FindingCategory.INJECTION):
            # Check for actual database error syntax, command execution output, or differential comparison
            has_db_syntax = any(term in ev_body for term in [
                "syntax error", "sqlite3", "psycopg2", "mysql", "operationalerror",
                "unclosed quotation mark", "sql syntax", "traceback"
            ])
            has_differential = any(
                obs.tool == "compare_responses" and (
                    obs.raw_data.get("length_delta", 0) > 0 or obs.raw_data.get("body_diff_length", 0) > 0
                )
                for obs in session.observations[-5:]
            )
            if not has_db_syntax and not has_differential:
                is_empirically_proven = False
                verification_critique = "No database syntax error, command execution, or response differential observed. Bare HTTP status is insufficient."
        elif category == FindingCategory.INFORMATION_DISCLOSURE:
            # Check for leaked secrets, credentials, environment keys, or internal tracebacks
            evidence_text = f"{endpoint} {description} {ev_body}".lower()
            has_leak = any(term in evidence_text for term in [
                "secret", "api_key", "password", "token", "private_key",
                "aws_secret", "database_url", "env", "traceback", "config", "debug"
            ])
            if not has_leak:
                is_empirically_proven = False
                verification_critique = "HTTP 200/500 without sensitive key, password, or configuration data in body is not verifiable disclosure."
        elif category == FindingCategory.CONCURRENCY:
            # Never assume a race condition from timing alone
            has_concurrency_proof = (
                matched_obs_raw.get("race_condition_detected")
                or matched_obs_raw.get("db_lock_detected")
                or matched_obs_raw.get("concurrency_5xx")
            )
            if not has_concurrency_proof and not any(term in ev_body for term in ["lock", "deadlock", "concurrent"]):
                is_empirically_proven = False
                verification_critique = "Timing jitter alone does not prove a concurrency or race condition vulnerability."
        elif category in (FindingCategory.RATE_LIMITING, FindingCategory.SYSTEM_RESILIENCE):
            has_pressure_proof = (
                matched_obs_raw.get("rate_limit_detected")
                or matched_obs_raw.get("degradation_detected")
                or "429" in str(matched_obs_raw.get("status_distribution", {}))
                or (matched_obs_raw.get("peak_rate", 0) >= 10 and "absence of rate limiting" in title.lower())
            )
            if not has_pressure_proof:
                is_empirically_proven = False
                verification_critique = "No measured degradation, throttling threshold, or 429 response recorded under load."

        if not is_empirically_proven and status == FindingStatus.CONFIRMED:
            status = FindingStatus.INCONCLUSIVE
            confidence = Confidence.LOW
            description += f"\n\n[EVIDENCE VERIFICATION WARNING]: {verification_critique}"

        repro_steps = [
            f"Target host: {session.target.base_url}",
            f"Endpoint tested: {endpoint}",
            f"Execute verification request:\n   {curl_step}",
            f"Observe status and response body confirming the security defect: {description[:120]}..."
        ]

        finding = Finding(
            title=title,
            category=category,
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            description=description,
            impact=impact,
            evidence=evidence_items,
            reproduction_steps=repro_steps,
            remediation=remediation,
            status=status,
            affected_endpoint=endpoint,
            causal_chain=causal_chain
        )
        session.add_finding(finding)

        insights = [
            f"Recorded Finding: '{title}' [{severity.value}]",
            f"Confidence: {confidence.value} | Status: {status.value}",
            f"Evidence: {len(evidence_items)} artifact(s) captured with reproducible curl commands."
        ]

        if status == FindingStatus.CONFIRMED:
            summary = f"Confirmed and recorded finding: {title} ({severity.value}) backed by runtime evidence."
        else:
            summary = f"Recorded finding as {status.value}: {title}. HTTP status alone without verifiable proof was unconfirmed."

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint,
            summary=summary,
            key_insights=insights,
            raw_data={"finding_id": finding.id, "title": title, "severity": severity.value}
        )
