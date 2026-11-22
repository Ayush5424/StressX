import re
import time
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence
from app.models.attack_family import AttackFamily


class ScanSensitiveDataTool(BaseTool):
    """Tool for detecting leaked credentials, API tokens, internal network topology, stack traces, and PII."""

    name = "scan_sensitive_data"
    description = (
        "Inspects HTTP responses, configuration endpoints, and debug surfaces for exposed secrets "
        "(AWS, GitHub, Stripe, database connection strings), internal private IP addresses, "
        "verbose framework stack traces, and unmasked credential fields."
    )
    parameters_schema = {
        "type": "object",
        "required": ["endpoint"],
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Target endpoint to audit (e.g. '/api/users/1', '/actuator/env', '/.env', '/debug')"
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST"],
                "default": "GET"
            },
            "probe_debug_paths": {
                "type": "boolean",
                "default": False,
                "description": "Whether to also probe common sensitive debug paths (e.g. /.env, /actuator/env, /debug/vars)."
            },
            "body": {
                "type": "string",
                "description": "Optional body for POST requests"
            }
        }
    }

    # High-fidelity regex patterns for sensitive data exposure
    SECRET_PATTERNS: list[dict[str, Any]] = [
        {
            "name": "AWS Access Key ID",
            "regex": re.compile(r"\b((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Hardcoded or dynamically leaked AWS Access Key ID detected in response.",
            "impact": "Unrestricted access to AWS cloud infrastructure and hosted resources.",
            "remediation": "Revoke the exposed AWS credential immediately via IAM and migrate to IAM roles or Secrets Manager."
        },
        {
            "name": "RSA / OpenSSH Private Key",
            "regex": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Server response exposes an unencrypted private cryptographic key.",
            "impact": "Complete compromise of server identity, decryption of traffic, or unauthorized SSH access.",
            "remediation": "Revoke and rotate the exposed private key and remove key files from web-accessible directories."
        },
        {
            "name": "Database Connection String with Credentials",
            "regex": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^:\s\/]+:[^@\s\/]+@[^\s\/]+", re.IGNORECASE),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Database connection URI containing plaintext username and password exposed.",
            "impact": "Direct unauthorized access to production database, data exfiltration, or database destruction.",
            "remediation": "Store connection strings in secure environment variables or vault and redact database URLs in API outputs."
        },
        {
            "name": "Stripe Secret / Restricted Key",
            "regex": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Live Stripe Secret Key exposed in API response.",
            "impact": "Unauthorized financial charges, customer account manipulation, and balance transfers.",
            "remediation": "Roll the compromised Stripe secret key in the Stripe Dashboard immediately."
        },
        {
            "name": "GitHub Personal Access Token",
            "regex": re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})\b"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "GitHub Personal Access Token or OAuth token exposed in HTTP response.",
            "impact": "Unauthorized source code repository read/write access and CI/CD secret theft.",
            "remediation": "Revoke the token in GitHub Settings and inspect git audit logs for suspicious activity."
        },
        {
            "name": "Google API Key",
            "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            "severity": Severity.HIGH,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Google Cloud API key leaked in response body.",
            "impact": "Potential quota theft, unauthorized access to cloud services, and cloud billing inflation.",
            "remediation": "Restrict API key in Google Cloud Console with HTTP referrers or API restrictions."
        },
        {
            "name": "Plaintext Password or Secret in JSON",
            "regex": re.compile(r'"(?:password|passwd|user_password|api_secret|client_secret)"\s*:\s*"([^"]{4,})"', re.IGNORECASE),
            "severity": Severity.HIGH,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Plaintext user password or API client secret returned in JSON serialization.",
            "impact": "Immediate credential theft of user accounts or service accounts.",
            "remediation": "Filter sensitive fields (e.g., password, secret) in DTOs and serializers using field exclusion."
        },
        {
            "name": "Verbose Python Traceback",
            "regex": re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "category": FindingCategory.ERROR_DISCLOSURE,
            "description": "Uncaught Python application exception exposing full file system paths and stack traces.",
            "impact": "Provides attackers detailed insight into backend architecture, framework versions, and source code paths.",
            "remediation": "Configure global error handling middleware to mask internal exceptions in production."
        },
        {
            "name": "Verbose Java / Spring Stack Trace",
            "regex": re.compile(r"\b(?:at [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+:[0-9]+\)|org\.springframework\.|java\.lang\.\w+Exception)"),
            "severity": Severity.MEDIUM,
            "category": FindingCategory.ERROR_DISCLOSURE,
            "description": "Uncaught Java/Spring framework stack trace returned to caller.",
            "impact": "Aids vulnerability discovery by leaking internal package names, library versions, and query lines.",
            "remediation": "Set server.error.include-stacktrace=never in application.properties or application.yml."
        },
        {
            "name": "Internal Private IP Disclosure (RFC 1918)",
            "regex": re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
            "severity": Severity.LOW,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Internal network IP address exposed in response headers or payload.",
            "impact": "Facilitates internal network reconnaissance and SSRF target mapping.",
            "remediation": "Sanitize internal hostnames and IP addresses before returning responses to external clients."
        }
    ]

    DEBUG_PATHS = [
        "/.env",
        "/actuator/env",
        "/actuator/metrics",
        "/debug/vars",
        "/api/config",
        "/server-status"
    ]

    @staticmethod
    def _redact_secret(match_str: str) -> str:
        """Redacts sensitive value keeping only first 3 and last 2 characters."""
        if len(match_str) <= 6:
            return "***"
        return f"{match_str[:3]}***{match_str[-2:]}"

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        endpoint = kwargs.get("endpoint", "/")
        method = kwargs.get("method", "GET").upper()
        probe_debug_paths = kwargs.get("probe_debug_paths", False)
        body = kwargs.get("body")

        paths_to_test = [endpoint]
        if probe_debug_paths:
            for dp in self.DEBUG_PATHS:
                if dp not in paths_to_test:
                    paths_to_test.append(dp)

        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        causal_chain: list[str] = []
        scanned_details: dict[str, Any] = {}

        auth_headers = {}
        if "active_token" in session.context_data:
            auth_headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False, verify=False) as client:
            for path in paths_to_test:
                resolved_url = self.validate_target(session, path)
                try:
                    resp = await client.request(
                        method=method,
                        url=resolved_url,
                        headers=auth_headers,
                        content=body.encode("utf-8") if isinstance(body, str) else None
                    )
                    resp_text = resp.text
                    status_code = resp.status_code
                except Exception as e:
                    scanned_details[path] = {"error": str(e)}
                    continue

                path_findings = []
                for pattern in self.SECRET_PATTERNS:
                    matches = pattern["regex"].findall(resp_text)
                    if matches:
                        # Normalize match result
                        first_match = matches[0]
                        if isinstance(first_match, tuple):
                            first_match = next((m for m in first_match if m), "")
                        redacted = self._redact_secret(first_match)

                        path_findings.append({
                            "pattern_name": pattern["name"],
                            "match_sample": redacted,
                            "severity": pattern["severity"].value
                        })

                        insights.append(
                            f"EXPOSURE DETECTED on {path}: Found {pattern['name']} (Sample: '{redacted}')."
                        )
                        causal_chain.append(
                            f"Queried {method} {path} (HTTP {status_code}): response body matched pattern '{pattern['name']}'"
                        )

                        findings_suggested.append({
                            "title": f"Sensitive Data Exposure: {pattern['name']} on {path}",
                            "category": pattern["category"],
                            "finding_type": FindingType.SECURITY_VULNERABILITY,
                            "attack_family": AttackFamily.INFORMATION_DISCLOSURE.value,
                            "severity": pattern["severity"],
                            "confidence": Confidence.HIGH,
                            "description": f"{pattern['description']} (Pattern matched on endpoint {path}).",
                            "impact": pattern["impact"],
                            "remediation": pattern["remediation"],
                            "causal_chain": list(causal_chain)
                        })

                # Check if debug route returned HTTP 200 with JSON configuration
                if path in self.DEBUG_PATHS and status_code == 200 and not path_findings:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or "text/plain" in content_type:
                        if len(resp_text) > 100 and "<html>" not in resp_text.lower():
                            insights.append(f"UNPROTECTED CONFIG ENDPOINT: {path} returned HTTP 200 with configuration data.")
                            findings_suggested.append({
                                "title": f"Unprotected Debug / Environment Endpoint Exposed at {path}",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.HIGH,
                                "confidence": Confidence.HIGH,
                                "description": f"The administrative debug endpoint '{path}' is publicly accessible without authentication, exposing internal runtime metrics or configuration properties.",
                                "impact": "Information disclosure facilitating targeted exploits and infrastructure mapping.",
                                "remediation": "Restrict access to debug and actuator endpoints via IP filtering, reverse proxy rules, or strong authentication."
                            })

                scanned_details[path] = {
                    "status_code": status_code,
                    "findings_count": len(path_findings),
                    "matches": path_findings
                }

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=session.target.resolve_url(endpoint),
            action_summary=f"Sensitive Data & Secret Exposure Scan on {endpoint} (Paths tested: {len(paths_to_test)})",
            request_data={"endpoint": endpoint, "paths_tested": paths_to_test, "method": method},
            response_summary=f"Discovered {len(findings_suggested)} exposed secret/stack trace findings.",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "NO_SECRETS_EXPOSED"
        )
        session.add_attempt(attempt)

        summary = (
            f"Sensitive data scan on {endpoint} across {len(paths_to_test)} path(s): "
            f"{len(findings_suggested)} security finding(s) detected."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint,
            summary=summary,
            key_insights=insights or ["No sensitive credentials, API tokens, internal IPs, or stack traces detected."],
            raw_data={
                "endpoint": endpoint,
                "paths_scanned": scanned_details,
                "findings_suggested": findings_suggested,
                "causal_chain": causal_chain
            }
        )
