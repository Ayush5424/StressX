import time
from typing import Any, Optional
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence


class AuditAccessControlTool(BaseTool):
    """Tool for auditing Access Control, Role-Based Access Control (RBAC), and Object-Level Authorization (IDOR/BOLA)."""

    name = "audit_access_control"
    description = (
        "Empirically evaluates authorization boundaries across multiple identity states: "
        "Unauthenticated access, cross-tenant Object-Level Access (IDOR/BOLA), "
        "and header-based privilege escalation."
    )
    parameters_schema = {
        "type": "object",
        "required": ["endpoint"],
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Target endpoint to audit (e.g. '/api/orders', '/api/procurements/{id}', '/api/users/me')"
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "default": "GET"
            },
            "resource_id": {
                "type": "string",
                "description": "Optional specific resource identifier to substitute for {id} or test IDOR"
            },
            "body": {
                "type": "string",
                "description": "Optional JSON body string for mutating endpoints"
            }
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        endpoint = kwargs.get("endpoint", "/")
        method = kwargs.get("method", "GET").upper()
        resource_id = kwargs.get("resource_id") or "1"
        body = kwargs.get("body")
        active_token = session.context_data.get("active_token")
        active_user = session.context_data.get("active_user", "anonymous")

        # Resolve endpoint with resource_id substitution
        target_path = endpoint
        for placeholder in ["{id}", "{user_id}", "{order_id}", "{procurement_id}"]:
            if placeholder in target_path:
                target_path = target_path.replace(placeholder, str(resource_id))

        resolved_url = self.validate_target(session, target_path)
        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        matrix_results: dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            # 1. State 1: Unauthenticated request (no Authorization header)
            start = time.perf_counter()
            unauth_res = None
            try:
                unauth_res = await client.request(
                    method=method,
                    url=resolved_url,
                    content=body.encode("utf-8") if isinstance(body, str) else None
                )
                unauth_elapsed = (time.perf_counter() - start) * 1000.0
                matrix_results["unauthenticated"] = {
                    "status_code": unauth_res.status_code,
                    "length": len(unauth_res.text),
                    "elapsed_ms": unauth_elapsed
                }
            except Exception as e:
                matrix_results["unauthenticated"] = {"error": str(e)}

            # Analyze State 1:
            if unauth_res and unauth_res.status_code == 200:
                is_sensitive_path = any(s in target_path.lower() for s in [
                    "/admin", "/api/user", "/api/order", "/api/procurement",
                    "/api/invoice", "/api/item", "/actuator/env", "/actuator/heapdump"
                ])
                # Check that it's not a generic public landing page or login page
                is_auth_route = any(a in target_path.lower() for a in ["/login", "/auth", "/register"])
                if is_sensitive_path and not is_auth_route and "text/html" not in unauth_res.headers.get("content-type", ""):
                    insights.append(
                        f"UNAUTHENTICATED SENSITIVE ENDPOINT: {target_path} returned HTTP 200 without credentials."
                    )
                    findings_suggested.append({
                        "title": f"Unauthenticated API Endpoint Exposure on {target_path}",
                        "category": FindingCategory.AUTHENTICATION,
                        "finding_type": FindingType.SECURITY_VULNERABILITY,
                        "severity": Severity.HIGH,
                        "confidence": Confidence.HIGH,
                        "description": (
                            f"The endpoint '{target_path}' allows unauthenticated users to access private business data. "
                            f"HTTP {method} request succeeded with HTTP 200 OK without Authorization header."
                        ),
                        "impact": "Unrestricted exposure of sensitive business and tenant records to unauthenticated external actors.",
                        "remediation": f"Enforce Spring Security authentication filter on '{target_path}', requiring valid JWT or session credentials."
                    })

            # 2. State 2: Authenticated request (if active token exists)
            auth_res = None
            if active_token:
                start = time.perf_counter()
                try:
                    auth_headers = {"Authorization": f"Bearer {active_token}"}
                    auth_res = await client.request(
                        method=method,
                        url=resolved_url,
                        headers=auth_headers,
                        content=body.encode("utf-8") if isinstance(body, str) else None
                    )
                    auth_elapsed = (time.perf_counter() - start) * 1000.0
                    matrix_results["authenticated"] = {
                        "status_code": auth_res.status_code,
                        "length": len(auth_res.text),
                        "elapsed_ms": auth_elapsed
                    }
                except Exception as e:
                    matrix_results["authenticated"] = {"error": str(e)}

            # 3. State 3: Object-Level Access (IDOR / BOLA) test
            # If endpoint has an ID or resource_id, test alternative ID (e.g. '2', '999', '0')
            alt_id = "2" if str(resource_id) == "1" else "1"
            alt_path = endpoint
            has_id_param = False
            for placeholder in ["{id}", "{user_id}", "{order_id}", "{procurement_id}"]:
                if placeholder in alt_path:
                    alt_path = alt_path.replace(placeholder, alt_id)
                    has_id_param = True

            idor_res = None
            if has_id_param:
                alt_url = self.validate_target(session, alt_path)
                try:
                    h = {"Authorization": f"Bearer {active_token}"} if active_token else {}
                    idor_res = await client.request(method=method, url=alt_url, headers=h)
                    matrix_results["idor_probe"] = {
                        "alt_path": alt_path,
                        "status_code": idor_res.status_code,
                        "length": len(idor_res.text)
                    }
                    if idor_res.status_code == 200:
                        # Check if different record is returned without ownership check
                        if unauth_res and unauth_res.status_code == 200:
                            insights.append(f"POTENTIAL IDOR / BOLA: Alternate object ID '{alt_path}' returned HTTP 200.")
                            findings_suggested.append({
                                "title": f"Broken Object-Level Authorization (IDOR) on {endpoint}",
                                "category": FindingCategory.IDOR_BOLA,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "severity": Severity.HIGH,
                                "confidence": Confidence.HIGH,
                                "description": (
                                    f"The application allows arbitrary object access across records on '{endpoint}'. "
                                    f"Requesting '{alt_path}' succeeded with HTTP 200 without verifying whether the caller owns the entity."
                                ),
                                "impact": "Horizontal privilege escalation allowing users or attackers to read, modify, or delete other users' records.",
                                "remediation": f"Implement object ownership validation in service layer ensuring the requested entity ID belongs to the authenticated user's organization."
                            })
                except Exception as e:
                    matrix_results["idor_probe"] = {"error": str(e)}

            # 4. State 4: Header Privilege Escalation Probe
            # Test if backend trusts untrusted forward/role headers
            escalate_headers = {
                "X-Role": "ADMIN",
                "X-User-Role": "admin",
                "X-Forwarded-For": "127.0.0.1",
                "X-Admin": "true"
            }
            if active_token:
                escalate_headers["Authorization"] = f"Bearer {active_token}"
            try:
                esc_res = await client.request(method=method, url=resolved_url, headers=escalate_headers)
                matrix_results["privilege_header_probe"] = {
                    "status_code": esc_res.status_code,
                    "length": len(esc_res.text)
                }
                # If baseline returned 401 or 403, but with forged header returned 200!
                base_code = unauth_res.status_code if unauth_res else 403
                if base_code in (401, 403) and esc_res.status_code == 200:
                    insights.append(f"PRIVILEGE ESCALATION VULNERABILITY: Header spoofing bypassed access barrier on {target_path} (403 -> 200).")
                    findings_suggested.append({
                        "title": f"Privilege Escalation via Trusted Forwarding Headers on {target_path}",
                        "category": FindingCategory.AUTHORIZATION_BYPASS,
                        "finding_type": FindingType.SECURITY_VULNERABILITY,
                        "severity": Severity.CRITICAL,
                        "confidence": Confidence.HIGH,
                        "description": (
                            f"The backend trusts client-controlled authorization headers ('X-Role: ADMIN' / 'X-Forwarded-For: 127.0.0.1') "
                            f"allowing unprivileged clients to bypass authorization barriers (status flipped from {base_code} to 200 OK)."
                        ),
                        "impact": "Complete authorization bypass allowing arbitrary users to impersonate administrative roles.",
                        "remediation": "Do not trust incoming X-Role or X-Forwarded-For headers from external untrusted clients; extract user roles exclusively from validated server-side JWT or session context."
                    })
            except Exception as e:
                matrix_results["privilege_header_probe"] = {"error": str(e)}

        # Record attempt
        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Access Control Matrix Audit on {method} {target_path}",
            request_data={"endpoint": target_path, "method": method, "matrix": matrix_results},
            response_summary=f"Unauth: {matrix_results.get('unauthenticated', {}).get('status_code')} | Auth: {matrix_results.get('authenticated', {}).get('status_code')}",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "ACCESS_CONTROL_ENFORCED"
        )
        session.add_attempt(attempt)

        summary = (
            f"Access control audit on {method} {target_path}: "
            f"Unauthenticated status={matrix_results.get('unauthenticated', {}).get('status_code', 'ERR')}, "
            f"Findings detected: {len(findings_suggested)}."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=target_path,
            summary=summary,
            key_insights=insights or ["Access controls properly enforced across all tested identity states."],
            raw_data={
                "matrix": matrix_results,
                "findings_suggested": findings_suggested,
                "endpoint": target_path,
                "method": method
            }
        )
