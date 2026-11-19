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

        # 1. Validation of Title specificity
        VAGUE_TITLES = {
            "potential security vulnerability",
            "vulnerable http endpoint",
            "discovered vulnerability",
            "security issue",
            "potential issue",
            "system vulnerability",
            "unspecified flaw",
            "http vulnerability",
            "test vulnerability",
            "security misconfiguration",
            "vulnerability",
            "issue"
        }
        clean_title = title.strip().lower()
        if clean_title in VAGUE_TITLES or len(title.strip()) < 8:
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=endpoint,
                summary=f"EVIDENCE REJECTED: Title is too vague ('{title}'). Specify the exact vulnerability, e.g. 'Broken Object Level Authorization (IDOR) on /api/orders/{{id}}' or 'Spring Boot Actuator Env Endpoint Exposed'.",
                key_insights=[
                    "Vague titles like 'Potential Security Vulnerability' are rejected.",
                    "Identify the explicit vulnerability type, affected parameter, and failure mechanism."
                ],
                raw_data={"rejected": True, "reason": "vague_title"}
            )

        # 2. Validation of Impact specificity
        clean_impact = impact.strip().lower()
        if clean_impact in ("unspecified", "none", "n/a", "high", "medium", "low", "unknown", "") or len(impact.strip()) < 8:
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=endpoint,
                summary="EVIDENCE REJECTED: Impact description is missing or generic. State the explicit security and business risk.",
                key_insights=[
                    "Generic impact values like 'Unspecified' or 'High' are prohibited.",
                    "Describe what an attacker can access, alter, steal, or disrupt."
                ],
                raw_data={"rejected": True, "reason": "vague_impact"}
            )

        # 3. Validation of Remediation specificity
        clean_remed = remediation.strip().lower()
        if clean_remed in ("further investigation and validation", "investigate", "fix it", "patch", "unknown", "none", "further investigation", "") or len(remediation.strip()) < 12:
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=endpoint,
                summary="EVIDENCE REJECTED: Remediation must provide actionable architectural or code-level guidance.",
                key_insights=[
                    "Placeholder remedies like 'Further investigation' are prohibited.",
                    "Specify exact code annotations, parameterization, or authorization checks required."
                ],
                raw_data={"rejected": True, "reason": "vague_remediation"}
            )

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
            from app.models.attack_family import AttackFamily
            try:
                af = AttackFamily(category.value.lower())
                finding_type = af.to_finding_type()
            except Exception:
                finding_type = FindingType.SECURITY_VULNERABILITY

        severity = Severity(severity_str)
        confidence = Confidence(confidence_str)
        status = FindingStatus(status_str)

        # 4. Strict filter for previous observations: Guardrail blocks cannot be used as evidence!
        def is_valid_observation(o: Observation) -> bool:
            if not o.raw_data:
                return False
            r = o.raw_data
            if r.get("repetition_prevented") or r.get("unverified_endpoint_blocked") or r.get("guard_blocked") or r.get("rejected"):
                return False
            if "UNVERIFIED ENDPOINT BLOCKED" in str(o.summary) or "REPETITION PREVENTED" in str(o.summary) or "INVALID TARGET BLOCKED" in str(o.summary):
                return False
            if "request" in r and "status_code" in r:
                return True
            if o.tool in ("pressure_test", "concurrency_test", "test_idempotency", "inject_failure") and (r.get("samples") or r.get("baseline_latency_ms") or r.get("status_distribution")):
                return True
            return False

        target_obs = None
        for obs in reversed(session.observations):
            if is_valid_observation(obs):
                obs_target = obs.target or ""
                if (endpoint in obs_target) or (obs_target in endpoint) or (obs_target == ""):
                    target_obs = obs
                    break

        if not target_obs:
            for obs in reversed(session.observations):
                if is_valid_observation(obs):
                    target_obs = obs
                    break

        if not target_obs:
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=endpoint,
                summary=f"EVIDENCE REJECTED: No verified runtime HTTP exchange found for endpoint '{endpoint}'. You must test the endpoint first with send_http_request.",
                key_insights=[
                    "Findings must be preceded by a real HTTP exchange showing the flaw.",
                    "Internal controller guard messages cannot be recorded as vulnerabilities."
                ],
                raw_data={"rejected": True, "reason": "no_valid_runtime_exchange"}
            )

        evidence_items: list[Evidence] = []
        curl_step = ""
        matched_obs_raw: dict[str, Any] = target_obs.raw_data or {}
        if not causal_chain and matched_obs_raw.get("causal_chain"):
            causal_chain = list(matched_obs_raw["causal_chain"])

        if target_obs.tool in ("pressure_test", "concurrency_test", "test_idempotency", "inject_failure"):
            obs_fact = matched_obs_raw.get("observed_facts", target_obs.summary)
            inf_conc = matched_obs_raw.get("inferred_conclusion", "Experimental verification evaluation.")
            base_metrics = {"mean_ms": matched_obs_raw.get("baseline_mean_ms") or matched_obs_raw.get("baseline_latency_ms", 0.0)}
            evidence = Evidence.from_experiment(
                description=f"Empirical resilience experiment on {endpoint} ({target_obs.tool})",
                endpoint=endpoint,
                method="GET",
                test_conditions=f"{target_obs.tool} with conditions: {matched_obs_raw.get('scenario') or matched_obs_raw.get('peak_rate') or matched_obs_raw.get('concurrency_level')}",
                pressure_level="STRESSED",
                baseline_metrics=base_metrics,
                observed_degradation=str(matched_obs_raw.get("degradation_detected") or matched_obs_raw.get("errors_detected", False)),
                recovery_behavior=str(matched_obs_raw.get("recovery_verified", True)),
                response_samples=matched_obs_raw.get("samples", []),
                observed_behavior=obs_fact,
                inferred_behavior=inf_conc,
                curl_command=f"curl -i '{session.target.resolve_url(endpoint)}'",
                evidence_type="SYSTEM_EXPERIMENT",
                causal_chain=causal_chain,
                downstream_effects=matched_obs_raw.get("downstream_effects", [])
            )
            evidence_items.append(evidence)
            session.add_evidence(evidence)
            curl_step = evidence.curl_command or ""
        elif "request" in matched_obs_raw and "status_code" in matched_obs_raw:
            req = matched_obs_raw["request"]
            req_url = req.get("url", endpoint)
            evidence = Evidence.from_http_exchange(
                description=f"Empirical validation probe against {req_url}",
                method=req.get("method", "GET"),
                url=req_url,
                status_code=matched_obs_raw.get("status_code", 200),
                req_headers=req.get("headers", {}),
                req_body=req.get("body"),
                res_headers=matched_obs_raw.get("headers", {}),
                res_body=matched_obs_raw.get("body", ""),
                latency_ms=matched_obs_raw.get("elapsed_ms", 0.0),
                evidence_type="HTTP_TRANSACTION"
            )
            evidence_items.append(evidence)
            session.add_evidence(evidence)
            curl_step = evidence.curl_command or ""

        # 5. Deterministic verification criteria:
        ev_status_code = matched_obs_raw.get("status_code", 200)
        ev_body = str(matched_obs_raw.get("body", "")).lower()
        is_empirically_proven = True
        verification_critique = ""

        # Reject normal HTML on root '/'
        if endpoint in ("/", "") and ev_status_code == 200 and ("<!doctype html" in ev_body or "<html" in ev_body):
            has_secret = any(k in ev_body for k in ("password", "private_key", "secret_key", "aws_access_key", "traceback"))
            if not has_secret:
                return Observation(
                    step=session.step_count,
                    tool=self.name,
                    target=endpoint,
                    summary="EVIDENCE REJECTED: The application homepage ('/') returning HTTP 200 HTML is standard web behavior, NOT a security vulnerability.",
                    key_insights=[
                        "An application serving its HTML landing page or single-page app is not vulnerable.",
                        "Target specific backend API endpoints with payloads, auth headers, or parameter fuzzing."
                    ],
                    raw_data={"rejected": True, "reason": "normal_homepage_not_vulnerable"}
                )

        if ev_status_code in (404, 405):
            is_empirically_proven = False
            verification_critique = f"Endpoint returned HTTP {ev_status_code}. Non-existent or disallowed route is not a confirmed vulnerability."
        elif ev_status_code in (401, 403) and category in (FindingCategory.AUTHENTICATION, FindingCategory.AUTHORIZATION):
            is_empirically_proven = False
            verification_critique = f"Endpoint returned HTTP {ev_status_code} (Access Denied). Enforcement of access boundary is not an exploit."
        elif category in (FindingCategory.UNSAFE_INPUT_HANDLING, FindingCategory.INJECTION, FindingCategory.SQL_INJECTION, FindingCategory.COMMAND_INJECTION):
            has_db_syntax = any(term in ev_body for term in [
                "syntax error", "sqlite3", "psycopg2", "mysql", "operationalerror",
                "unclosed quotation mark", "sql syntax", "traceback", "badsqlgrammar",
                "org.springframework.dao", "hibernate", "jpa", "jdbc"
            ])
            has_differential = any(
                obs.tool == "compare_responses" and (
                    obs.raw_data.get("length_delta", 0) > 0 or obs.raw_data.get("body_diff_length", 0) > 0
                )
                for obs in session.observations[-5:]
            )
            if not has_db_syntax and not has_differential:
                is_empirically_proven = False
                verification_critique = "No database error, command execution signature, or response differential observed. Bare HTTP status is insufficient."
        elif category == FindingCategory.INFORMATION_DISCLOSURE:
            evidence_text = f"{endpoint} {description} {ev_body}".lower()
            has_leak = any(term in evidence_text for term in [
                "secret", "api_key", "password", "token", "private_key",
                "aws_secret", "database_url", "env", "traceback", "config", "debug",
                "org.springframework", "java.lang.nullpointerexception", "stacktrace"
            ])
            if not has_leak:
                is_empirically_proven = False
                verification_critique = "HTTP 200/500 without sensitive key, password, or configuration data in body is not verifiable disclosure."
        elif category == FindingCategory.SECURITY_MISCONFIGURATION:
            has_actuator_misconfig = (
                any(t in endpoint.lower() for t in ("/actuator", "/env", "/mappings", "/beans", "/heapdump", "/configprops"))
                and ev_status_code == 200
                and any(term in ev_body for term in ("contexts", "profiles", "beans", "properties", "systemenvironment", "spring"))
            ) or any(term in ev_body for term in ("whitelabel error page", "stacktrace", "exception in thread"))
            if not has_actuator_misconfig and ev_status_code not in (500,):
                is_empirically_proven = False
                verification_critique = "No exposed actuator configuration, dangerous unprotected management endpoint, or unhandled stack trace observed."
        elif category in (FindingCategory.IDOR_BOLA, FindingCategory.AUTHORIZATION):
            if ev_status_code != 200:
                is_empirically_proven = False
                verification_critique = f"Endpoint returned HTTP {ev_status_code}. BOLA/IDOR requires successful 200 retrieval of another user's unauthorized record."
        elif category == FindingCategory.CONCURRENCY:
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

        if not is_empirically_proven:
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=endpoint,
                summary=f"EVIDENCE REJECTED: Finding not empirically confirmed. {verification_critique}",
                key_insights=[
                    verification_critique,
                    "StressX strictly requires reproducible, verifiable runtime proof before confirming a security finding.",
                    "Continue testing with modified payloads, auth tokens, or injection sequences."
                ],
                raw_data={"rejected": True, "reason": verification_critique}
            )

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
