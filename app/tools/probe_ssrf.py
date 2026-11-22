import json
import time
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence
from app.models.attack_family import AttackFamily


class ProbeSsrfTool(BaseTool):
    """Tool for auditing Server-Side Request Forgery (SSRF) vulnerabilities."""

    name = "probe_ssrf"
    description = (
        "Empirically tests endpoints accepting URLs, webhooks, or export targets against cloud metadata services "
        "(AWS 169.254.169.254, GCP metadata.google.internal, Azure), internal loopback interfaces "
        "(127.0.0.1, localhost, [::1], decimal/hex encodings), and detects response reflection or blind SSRF."
    )
    parameters_schema = {
        "type": "object",
        "required": ["endpoint", "parameter_name"],
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Target endpoint to probe (e.g. '/api/preview', '/api/webhook', '/api/fetch-url')"
            },
            "parameter_name": {
                "type": "string",
                "description": "Name of parameter accepting URL or destination (e.g. 'url', 'webhook_url', 'target', 'dest', 'callback')"
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT"],
                "default": "POST"
            },
            "param_location": {
                "type": "string",
                "enum": ["body_json", "query", "body_form"],
                "default": "body_json"
            },
            "base_body": {
                "type": "string",
                "description": "Optional baseline JSON body to merge parameter into"
            }
        }
    }

    # Controlled SSRF payloads targeting cloud metadata and loopback surfaces
    SSRF_TARGETS: list[dict[str, Any]] = [
        {
            "name": "AWS Metadata Service (IMDSv1)",
            "url": "http://169.254.169.254/latest/meta-data/",
            "signatures": ["ami-id", "instance-id", "security-credentials", "local-ipv4", "iam"],
            "severity": Severity.CRITICAL,
            "cloud": "AWS"
        },
        {
            "name": "Google Cloud Metadata Service",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "signatures": ["Metadata-Flavor", "project-id", "instance-id", "service-accounts"],
            "severity": Severity.CRITICAL,
            "cloud": "GCP"
        },
        {
            "name": "Azure Instance Metadata Service",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "signatures": ["compute", "vmId", "subscriptionId", "resourceGroupName"],
            "severity": Severity.CRITICAL,
            "cloud": "Azure"
        },
        {
            "name": "Internal Loopback IPv4",
            "url": "http://127.0.0.1:80/",
            "signatures": ["nginx", "apache", "docker", "redis", "swagger", "html"],
            "severity": Severity.HIGH,
            "cloud": "Local"
        },
        {
            "name": "Decimal Encoded Localhost (2130706433)",
            "url": "http://2130706433:80/",
            "signatures": ["nginx", "apache", "docker", "redis", "swagger", "html"],
            "severity": Severity.HIGH,
            "cloud": "Local (Bypass)"
        },
        {
            "name": "IPv6 Loopback ([::1])",
            "url": "http://[::1]:80/",
            "signatures": ["nginx", "apache", "docker", "redis", "swagger", "html"],
            "severity": Severity.HIGH,
            "cloud": "Local (IPv6)"
        }
    ]

    def _build_request_kwargs(
        self,
        method: str,
        param_location: str,
        param_name: str,
        payload_url: str,
        base_body: Optional[str]
    ) -> dict[str, Any]:
        """Constructs params or body payload depending on specified location."""
        req_kwargs: dict[str, Any] = {}
        if param_location == "query" or method == "GET":
            req_kwargs["params"] = {param_name: payload_url}
        elif param_location == "body_json":
            body_dict = {}
            if base_body:
                try:
                    body_dict = json.loads(base_body)
                except Exception:
                    body_dict = {}
            body_dict[param_name] = payload_url
            req_kwargs["json"] = body_dict
        elif param_location == "body_form":
            req_kwargs["data"] = {param_name: payload_url}
        return req_kwargs

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        endpoint = kwargs.get("endpoint", "/")
        param_name = kwargs.get("parameter_name", "url")
        method = kwargs.get("method", "POST").upper()
        param_location = kwargs.get("param_location", "body_json")
        base_body = kwargs.get("base_body")

        resolved_url = self.validate_target(session, endpoint)
        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        causal_chain: list[str] = []
        probe_results: dict[str, Any] = {}

        auth_headers = {}
        if "active_token" in session.context_data:
            auth_headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        async with httpx.AsyncClient(timeout=7.0, follow_redirects=False, verify=False) as client:
            # 1. Baseline request with safe external URL or dummy host
            baseline_url = "http://example.invalid-stressx-probe/"
            base_kwargs = self._build_request_kwargs(method, param_location, param_name, baseline_url, base_body)
            base_kwargs["headers"] = auth_headers
            try:
                base_resp = await client.request(method=method, url=resolved_url, **base_kwargs)
                base_status = base_resp.status_code
                base_len = len(base_resp.text)
            except Exception as e:
                base_status = 0
                base_len = 0

            # 2. Probe SSRF targets
            for target in self.SSRF_TARGETS:
                probe_url = target["url"]
                req_kwargs = self._build_request_kwargs(method, param_location, param_name, probe_url, base_body)
                req_kwargs["headers"] = auth_headers

                t0 = time.perf_counter()
                try:
                    resp = await client.request(method=method, url=resolved_url, **req_kwargs)
                    elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
                    resp_text = resp.text
                    status_code = resp.status_code

                    probe_results[target["name"]] = {
                        "status_code": status_code,
                        "elapsed_ms": elapsed,
                        "length": len(resp_text)
                    }

                    # Check for direct metadata or internal banner reflection
                    matched_signatures = [sig for sig in target["signatures"] if sig.lower() in resp_text.lower()]
                    if matched_signatures and status_code == 200:
                        sig_str = ", ".join(matched_signatures)
                        insights.append(
                            f"CRITICAL SSRF CONFIRMED on {endpoint} via parameter '{param_name}': "
                            f"Target reflected {target['name']} signatures: [{sig_str}]!"
                        )
                        causal_chain.append(
                            f"Supplied '{probe_url}' in parameter '{param_name}' to {method} {endpoint}: "
                            f"backend dispatched request and returned {target['name']} response with signatures [{sig_str}]"
                        )
                        findings_suggested.append({
                            "title": f"Server-Side Request Forgery (SSRF) to {target['name']} on {endpoint}",
                            "category": FindingCategory.SSRF,
                            "finding_type": FindingType.SECURITY_VULNERABILITY,
                            "attack_family": AttackFamily.SSRF.value,
                            "severity": target["severity"],
                            "confidence": Confidence.HIGH,
                            "description": (
                                f"The endpoint '{endpoint}' accepts user-controlled URLs in parameter '{param_name}' "
                                f"and fetches them server-side without verifying destination host IP boundaries. "
                                f"Requests to '{probe_url}' successfully reflected internal signatures: [{sig_str}]."
                            ),
                            "impact": (
                                "Severe unauthorized access to cloud instance metadata, IAM credentials, "
                                "and internal network services inaccessible from the public internet."
                            ),
                            "remediation": (
                                "Enforce a strict whitelist of allowed destination domains/protocols, "
                                "resolve hostnames before connecting, and reject private RFC 1918 / 169.254.0.0/16 IP ranges."
                            ),
                            "causal_chain": list(causal_chain)
                        })
                        break

                    # Check for differential behavioral response (Blind SSRF indicator)
                    # If baseline returns 400 Bad Request, but querying 127.0.0.1 or 169.254.169.254 returns 200, 502 Bad Gateway, or 504 Gateway Timeout
                    if base_status in (400, 422) and status_code in (200, 502, 504):
                        insights.append(
                            f"POTENTIAL BLIND SSRF on {endpoint}: Status changed from {base_status} (baseline) to {status_code} when querying '{probe_url}'."
                        )
                        findings_suggested.append({
                            "title": f"Potential Blind SSRF / Internal Port Scanning on {endpoint}",
                            "category": FindingCategory.SSRF,
                            "finding_type": FindingType.SECURITY_VULNERABILITY,
                            "attack_family": AttackFamily.SSRF.value,
                            "severity": Severity.MEDIUM,
                            "confidence": Confidence.MEDIUM,
                            "description": (
                                f"Parameter '{param_name}' on {endpoint} exhibited differential response codes "
                                f"(baseline HTTP {base_status} vs target HTTP {status_code}) when targeting internal interface '{probe_url}'."
                            ),
                            "impact": "Facilitates internal network port scanning and reconnaissance of backend service infrastructure.",
                            "remediation": "Validate destination URLs against an allowlist and block connections to localhost and private subnets."
                        })
                except Exception as e:
                    probe_results[target["name"]] = {"error": str(e)}

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"SSRF Audit on {method} {endpoint} (Param: {param_name})",
            request_data={"endpoint": endpoint, "param": param_name, "method": method, "location": param_location},
            response_summary=f"Discovered {len(findings_suggested)} SSRF vulnerabilities.",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "NO_SSRF_DETECTED"
        )
        session.add_attempt(attempt)

        summary = (
            f"SSRF audit on {method} {endpoint} (param '{param_name}'): "
            f"{len(findings_suggested)} finding(s) detected across {len(self.SSRF_TARGETS)} probes."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint,
            summary=summary,
            key_insights=insights or ["No Server-Side Request Forgery vulnerabilities detected; internal destinations safely handled."],
            raw_data={
                "endpoint": endpoint,
                "param_name": param_name,
                "findings_suggested": findings_suggested,
                "probe_results": probe_results,
                "causal_chain": causal_chain
            }
        )
