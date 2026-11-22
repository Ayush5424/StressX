import re
import json
import urllib.parse
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence
from app.models.attack_family import AttackFamily


class AuditFrontendAssetsTool(BaseTool):
    """Tool for auditing client-side frontend HTML, scripts, bundles, and source maps for exposed credentials."""

    name = "audit_frontend_assets"
    description = (
        "Audits client-side HTML, JavaScript bundles, inline scripts, and production source maps (.js.map) "
        "for inadvertently exposed credentials (API keys, hardcoded JWTs, cloud tokens, database URIs), "
        "and provides actionable remediation instructions to remove and rotate them."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "default": "/",
                "description": "Frontend entry path to audit (e.g. '/', '/index.html', '/app', '/login')"
            },
            "scan_scripts": {
                "type": "boolean",
                "default": True,
                "description": "Whether to fetch and audit external JavaScript bundles referenced in the HTML."
            },
            "check_source_maps": {
                "type": "boolean",
                "default": True,
                "description": "Whether to check if production source map files (.js.map) are publicly accessible."
            },
            "max_scripts_to_scan": {
                "type": "integer",
                "default": 10,
                "description": "Maximum number of linked script bundles to download and inspect."
            }
        }
    }

    # Patterns for high-risk credentials commonly leaked into frontend builds
    FRONTEND_SECRET_PATTERNS: list[dict[str, Any]] = [
        {
            "name": "Hardcoded JWT Token",
            "regex": re.compile(r"\b(eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})\b"),
            "severity": Severity.HIGH,
            "category": FindingCategory.SESSION_TOKEN_ABUSE,
            "description": "Hardcoded JSON Web Token (JWT) embedded directly in frontend client bundle.",
            "impact": "Exposes static authentication tokens or developer test sessions to any website visitor.",
            "remediation": "Remove hardcoded JWTs from frontend code. Authentication tokens should only be obtained dynamically via authentication endpoints and stored securely in HttpOnly cookies."
        },
        {
            "name": "Stripe Live Secret Key",
            "regex": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Stripe Live Secret Key bundled into client-side JavaScript instead of public publishable key.",
            "impact": "Allows attackers to make unauthorized charges, view customer records, and manipulate billing data.",
            "remediation": "Immediately revoke and roll this Stripe key in the Stripe Dashboard. In frontend code, use only publishable keys ('pk_live_...'), keeping secret keys strictly on backend servers."
        },
        {
            "name": "AWS Access Key ID",
            "regex": re.compile(r"\b((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "AWS IAM Access Key ID exposed in client-side code.",
            "impact": "Allows unauthorized callers to access hosted AWS resources, S3 buckets, and infrastructure.",
            "remediation": "Revoke the exposed key in AWS IAM immediately. Use temporary credentials via AWS Cognito or proxy requests through a secure backend API instead of embedding AWS keys in frontend code."
        },
        {
            "name": "GitHub Personal Access Token",
            "regex": re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})\b"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "GitHub Personal Access Token exposed in client-accessible frontend files.",
            "impact": "Grants unauthorized access to source code repositories, CI/CD pipelines, and private packages.",
            "remediation": "Revoke the token immediately in GitHub Settings -> Developer settings -> Personal access tokens, and check repository access logs for unauthorized activity."
        },
        {
            "name": "Google / Firebase API Key",
            "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            "severity": Severity.HIGH,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Google API key or Firebase web credential detected in client code.",
            "impact": "May allow unauthorized quota consumption or API access if key restrictions are not configured.",
            "remediation": "Ensure this API key is restricted by HTTP Referrer in the Google Cloud Console, and ensure no administrative service account keys are bundled into frontend assets."
        },
        {
            "name": "Database Connection String",
            "regex": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s\/]+:[^@\s\/]+@[^\s\/]+", re.IGNORECASE),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Database connection URI with plaintext credentials embedded in frontend bundle.",
            "impact": "Direct, unauthenticated database connection capability from any client machine.",
            "remediation": "Remove the database connection string from client assets immediately. Production databases must never be connected directly from client-side JavaScript; proxy all database queries through backend API endpoints."
        },
        {
            "name": "Private Cryptographic Key",
            "regex": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
            "severity": Severity.CRITICAL,
            "category": FindingCategory.INFORMATION_DISCLOSURE,
            "description": "Private key file contents embedded in client-side bundle or static directory.",
            "impact": "Compromises cryptographic identity, TLS encryption, or SSH server access.",
            "remediation": "Revoke and regenerate the private key immediately. Store private keys strictly in server-side secret management systems."
        }
    ]

    @staticmethod
    def _redact_value(val: str) -> str:
        """Redacts sensitive value keeping only first 3 and last 2 characters."""
        if len(val) <= 6:
            return "***"
        return f"{val[:3]}***{val[-2:]}"

    def _extract_script_urls(self, html: str, base_url: str) -> list[str]:
        """Extracts script source URLs from HTML script and modulepreload tags."""
        script_srcs: list[str] = []

        # Find <script src="...">
        for match in re.finditer(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1).strip()
            if src and not src.startswith("data:"):
                resolved = urllib.parse.urljoin(base_url, src)
                if resolved not in script_srcs:
                    script_srcs.append(resolved)

        # Find <link rel="modulepreload" href="...">
        for match in re.finditer(r'<link\b[^>]*\brel=["\']modulepreload["\'][^>]*\bhref=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = match.group(1).strip()
            if href:
                resolved = urllib.parse.urljoin(base_url, href)
                if resolved not in script_srcs:
                    script_srcs.append(resolved)

        return script_srcs

    def _scan_text_for_secrets(self, text: str, source_label: str) -> list[dict[str, Any]]:
        """Scans arbitrary text (HTML or JS) against secret patterns."""
        detected = []
        for pattern in self.FRONTEND_SECRET_PATTERNS:
            matches = pattern["regex"].findall(text)
            if matches:
                sample = matches[0]
                if isinstance(sample, tuple):
                    sample = next((m for m in sample if m), "")
                redacted = self._redact_value(sample)
                detected.append({
                    "name": pattern["name"],
                    "category": pattern["category"],
                    "severity": pattern["severity"],
                    "sample": redacted,
                    "source": source_label,
                    "description": pattern["description"],
                    "impact": pattern["impact"],
                    "remediation": pattern["remediation"]
                })
        return detected

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        scan_scripts = kwargs.get("scan_scripts", True)
        check_source_maps = kwargs.get("check_source_maps", True)
        max_scripts = max(1, min(int(kwargs.get("max_scripts_to_scan", 10)), 25))

        resolved_url = self.validate_target(session, path)
        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        causal_chain: list[str] = []
        scanned_assets: dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
            # 1. Fetch frontend HTML root
            try:
                html_resp = await client.get(resolved_url)
                html_text = html_resp.text
                html_status = html_resp.status_code
            except Exception as e:
                return Observation(
                    step=session.step_count,
                    tool=self.name,
                    target=path,
                    summary=f"Failed to fetch frontend page at {path}: {str(e)}",
                    key_insights=[f"Error accessing frontend asset: {str(e)}"],
                    raw_data={"error": str(e)}
                )

            # 2. Check HTML for inline secrets or sensitive config dumps (window.__ENV__, etc.)
            html_secrets = self._scan_text_for_secrets(html_text, f"HTML Page ({path})")
            scanned_assets[path] = {
                "type": "html",
                "status_code": html_status,
                "secrets_found": len(html_secrets)
            }

            for sec in html_secrets:
                insights.append(
                    f"EXPOSED CREDENTIAL in {sec['source']}: {sec['name']} detected (Sample: '{sec['sample']}'). REMOVAL REQUIRED."
                )
                causal_chain.append(
                    f"Fetched {path}: HTML response contained {sec['name']} (Sample: '{sec['sample']}')"
                )
                findings_suggested.append({
                    "title": f"Exposed {sec['name']} in Frontend HTML at {path}",
                    "category": sec["category"],
                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                    "attack_family": AttackFamily.INFORMATION_DISCLOSURE.value,
                    "severity": sec["severity"],
                    "confidence": Confidence.HIGH,
                    "description": f"{sec['description']} Found in HTML page '{path}'.",
                    "impact": sec["impact"],
                    "remediation": f"ACTION REQUIRED: Remove credential from frontend source. {sec['remediation']}",
                    "causal_chain": list(causal_chain)
                })

            # Check for window.__ENV__ or window.__INITIAL_STATE__ leaking credentials
            env_dump_match = re.search(r'window\.(?:__ENV__|__INITIAL_STATE__|config|env)\s*=\s*(\{.*?\});', html_text, re.DOTALL)
            if env_dump_match:
                try:
                    env_raw = env_dump_match.group(1)
                    parsed_env = json.loads(env_raw)
                    sensitive_keys = [k for k in parsed_env.keys() if any(s in k.lower() for s in ["secret", "key", "token", "password", "db", "uri", "auth"])]
                    if sensitive_keys:
                        insights.append(
                            f"EXPOSED RUNTIME CONFIG: Global config window.__ENV__ exposes sensitive keys: {', '.join(sensitive_keys[:5])}."
                        )
                        findings_suggested.append({
                            "title": f"Sensitive Runtime Environment Variables Exposed in Frontend at {path}",
                            "category": FindingCategory.SECURITY_MISCONFIGURATION,
                            "finding_type": FindingType.SECURITY_VULNERABILITY,
                            "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                            "severity": Severity.HIGH,
                            "confidence": Confidence.HIGH,
                            "description": (
                                f"The HTML page '{path}' embeds environment properties into global state (window.__ENV__) "
                                f"containing sensitive keys: {', '.join(sensitive_keys[:5])}."
                            ),
                            "impact": "Exposes backend service configurations, secrets, and connection parameters to all users.",
                            "remediation": "ACTION REQUIRED: Filter environment variables injected into frontend templates so that only public, non-sensitive variables (e.g. VITE_PUBLIC_*) are exposed.",
                            "causal_chain": list(causal_chain)
                        })
                except Exception:
                    pass

            # 3. Extract and scan referenced JavaScript bundles
            script_urls = self._extract_script_urls(html_text, resolved_url)
            scripts_to_scan = script_urls[:max_scripts]

            for script_url in scripts_to_scan:
                script_path = urllib.parse.urlparse(script_url).path
                try:
                    s_resp = await client.get(script_url)
                    s_text = s_resp.text
                    s_status = s_resp.status_code
                except Exception as e:
                    scanned_assets[script_path] = {"error": str(e)}
                    continue

                bundle_secrets = self._scan_text_for_secrets(s_text, f"JS Bundle ({script_path})")
                scanned_assets[script_path] = {
                    "type": "javascript",
                    "status_code": s_status,
                    "length": len(s_text),
                    "secrets_found": len(bundle_secrets)
                }

                for sec in bundle_secrets:
                    insights.append(
                        f"EXPOSED CREDENTIAL in {script_path}: {sec['name']} detected (Sample: '{sec['sample']}'). REMOVAL REQUIRED."
                    )
                    causal_chain.append(
                        f"Downloaded client script {script_path}: bundle text matched {sec['name']} (Sample: '{sec['sample']}')"
                    )
                    findings_suggested.append({
                        "title": f"Exposed {sec['name']} in Client-Side JavaScript Bundle ({script_path})",
                        "category": sec["category"],
                        "finding_type": FindingType.SECURITY_VULNERABILITY,
                        "attack_family": AttackFamily.INFORMATION_DISCLOSURE.value,
                        "severity": sec["severity"],
                        "confidence": Confidence.HIGH,
                        "description": f"{sec['description']} Discovered in bundle '{script_path}'.",
                        "impact": sec["impact"],
                        "remediation": f"ACTION REQUIRED: Remove this credential immediately from source code and bundle configs. {sec['remediation']}",
                        "causal_chain": list(causal_chain)
                    })

                # 4. Check for Public Source Map (.map) exposure
                if check_source_maps:
                    map_url = None
                    # Check for //# sourceMappingURL= comment
                    map_comment = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', s_text)
                    if map_comment:
                        map_ref = map_comment.group(1).strip()
                        map_url = urllib.parse.urljoin(script_url, map_ref)
                    else:
                        map_url = f"{script_url}.map"

                    if map_url:
                        try:
                            map_resp = await client.get(map_url)
                            if map_resp.status_code == 200 and ("\"sources\"" in map_resp.text or "\"mappings\"" in map_resp.text):
                                map_path = urllib.parse.urlparse(map_url).path
                                insights.append(
                                    f"PRODUCTION ARTIFACT LEAK: Public source map file '{map_path}' is accessible (HTTP 200). REMOVAL REQUIRED."
                                )
                                causal_chain.append(
                                    f"Queried source map URL {map_path}: server returned full source map JSON (length {len(map_resp.text)})"
                                )
                                findings_suggested.append({
                                    "title": f"Public Production Source Map (.map) Exposure on {map_path}",
                                    "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                                    "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                    "severity": Severity.MEDIUM,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The production JavaScript source map '{map_path}' is publicly served. "
                                        f"Source maps reconstruct the complete original, unminified source code, "
                                        f"including internal variable names, directory paths, and developer comments."
                                    ),
                                    "impact": "Assists external actors in understanding internal system logic and locating application weaknesses.",
                                    "remediation": "ACTION REQUIRED: Disable source maps in production build configurations (e.g., set 'sourcemap: false' in vite.config.js / webpack.config.js) or block access to .map files via web server configuration.",
                                    "causal_chain": list(causal_chain)
                                })
                        except Exception:
                            pass

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Frontend Client Asset & Secret Audit on {path} ({len(scanned_assets)} assets scanned)",
            request_data={"path": path, "scripts_scanned": len(scanned_assets), "check_source_maps": check_source_maps},
            response_summary=f"Discovered {len(findings_suggested)} exposed credential / asset misconfigurations.",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "NO_SECRETS_EXPOSED"
        )
        session.add_attempt(attempt)

        summary = (
            f"Frontend asset audit on {path}: Scanned {len(scanned_assets)} asset(s). "
            f"Detected {len(findings_suggested)} credential/source map finding(s)."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=path,
            summary=summary,
            key_insights=insights or ["No exposed credentials, API keys, tokens, or public source maps detected in client assets."],
            raw_data={
                "path": path,
                "assets_scanned": scanned_assets,
                "findings_suggested": findings_suggested,
                "causal_chain": causal_chain
            }
        )
