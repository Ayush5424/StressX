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


class AuditGraphqlWebsocketTool(BaseTool):
    """Tool for auditing GraphQL and WebSocket endpoints for security misconfigurations and DoS risks."""

    name = "audit_graphql_websocket"
    description = (
        "Audits GraphQL services for enabled introspection queries, field suggestion information leaks, "
        "query depth and recursion limit exhaustion, and query batching abuse. Also evaluates WebSocket "
        "endpoints for Cross-Site WebSocket Hijacking (CSWSH) and unauthenticated handshake acceptance."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "target_type": {
                "type": "string",
                "enum": ["graphql", "websocket", "auto"],
                "default": "auto",
                "description": "Protocol to audit: 'graphql', 'websocket', or 'auto' (probes both)."
            },
            "endpoint": {
                "type": "string",
                "description": "Optional specific path (e.g. '/graphql', '/api/graphql', '/ws', '/socket.io'). If omitted, common paths are probed."
            },
            "run_introspection": {
                "type": "boolean",
                "default": True,
                "description": "Whether to probe for GraphQL schema introspection."
            },
            "run_depth_test": {
                "type": "boolean",
                "default": True,
                "description": "Whether to test GraphQL query depth & recursive complexity exhaustion."
            },
            "run_field_suggestions": {
                "type": "boolean",
                "default": True,
                "description": "Whether to test for GraphQL field suggestion information leaks."
            },
            "run_batching_test": {
                "type": "boolean",
                "default": True,
                "description": "Whether to test GraphQL query batching / request amplification."
            },
            "run_websocket_origin_check": {
                "type": "boolean",
                "default": True,
                "description": "Whether to test WebSocket handshakes with malicious Origin headers (CSWSH)."
            }
        }
    }

    GRAPHQL_COMMON_PATHS = [
        "/graphql",
        "/api/graphql",
        "/query",
        "/v1/graphql"
    ]

    WEBSOCKET_COMMON_PATHS = [
        "/ws",
        "/websocket",
        "/socket.io/",
        "/api/ws"
    ]

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        target_type = kwargs.get("target_type", "auto").lower()
        endpoint = kwargs.get("endpoint")
        run_introspection = kwargs.get("run_introspection", True)
        run_depth_test = kwargs.get("run_depth_test", True)
        run_field_suggestions = kwargs.get("run_field_suggestions", True)
        run_batching_test = kwargs.get("run_batching_test", True)
        run_ws_origin = kwargs.get("run_websocket_origin_check", True)

        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        causal_chain: list[str] = []
        graphql_results: dict[str, Any] = {}
        websocket_results: dict[str, Any] = {}

        auth_headers = {}
        if "active_token" in session.context_data:
            auth_headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
            # =========================================================================
            # 1. GRAPHQL AUDIT SUITE
            # =========================================================================
            if target_type in ("graphql", "auto"):
                gql_paths = [endpoint] if endpoint and target_type == "graphql" else (
                    [endpoint] if endpoint and "ws" not in endpoint else self.GRAPHQL_COMMON_PATHS
                )

                active_gql_path = None
                for gp in gql_paths:
                    resolved_url = self.validate_target(session, gp)
                    try:
                        probe_resp = await client.post(
                            resolved_url,
                            headers=dict(auth_headers, **{"Content-Type": "application/json"}),
                            json={"query": "{ __typename }"}
                        )
                        if probe_resp.status_code in (200, 400) and ("data" in probe_resp.text or "errors" in probe_resp.text):
                            active_gql_path = gp
                            graphql_results["active_path"] = gp
                            insights.append(f"GraphQL surface detected at {gp} (HTTP {probe_resp.status_code}).")
                            break
                    except Exception:
                        continue

                if active_gql_path:
                    gql_target_url = self.validate_target(session, active_gql_path)

                    # 1a. Introspection Query Probe
                    if run_introspection:
                        intro_query = {
                            "query": (
                                "query IntrospectionCheck { "
                                "__schema { types { name kind fields { name } } } "
                                "}"
                            )
                        }
                        try:
                            intro_resp = await client.post(
                                gql_target_url,
                                headers=dict(auth_headers, **{"Content-Type": "application/json"}),
                                json=intro_query
                            )
                            graphql_results["introspection_status"] = intro_resp.status_code
                            if intro_resp.status_code == 200 and "__schema" in intro_resp.text:
                                insights.append(
                                    f"CRITICAL GRAPHQL MISCONFIGURATION: Introspection query enabled in production on {active_gql_path}."
                                )
                                causal_chain.append(
                                    f"Dispatched GraphQL introspection query to {active_gql_path}: "
                                    f"server returned full schema definition (HTTP 200, length {len(intro_resp.text)})"
                                )
                                findings_suggested.append({
                                    "title": f"GraphQL Schema Introspection Enabled in Production on {active_gql_path}",
                                    "category": FindingCategory.INFORMATION_DISCLOSURE,
                                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                                    "attack_family": AttackFamily.INFORMATION_DISCLOSURE.value,
                                    "severity": Severity.HIGH,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The GraphQL endpoint '{active_gql_path}' allows full schema introspection. "
                                        f"External actors can enumerate all internal types, queries, mutations, "
                                        f"and sensitive database fields."
                                    ),
                                    "impact": "Exposes complete API surface and hidden endpoints for targeted exploitation.",
                                    "remediation": "Disable introspection queries in production configurations (e.g. Apollo Server `introspection: false`).",
                                    "causal_chain": list(causal_chain)
                                })
                        except Exception as e:
                            graphql_results["introspection_error"] = str(e)

                    # 1b. Field Suggestion Leakage Probe
                    if run_field_suggestions:
                        misspelled_query = {"query": "{ __unknownFieldTestStressX { id } }"}
                        try:
                            sugg_resp = await client.post(
                                gql_target_url,
                                headers=dict(auth_headers, **{"Content-Type": "application/json"}),
                                json=misspelled_query
                            )
                            if "did you mean" in sugg_resp.text.lower():
                                insights.append(
                                    f"INFORMATION LEAK: GraphQL field suggestion enabled on {active_gql_path}."
                                )
                                findings_suggested.append({
                                    "title": f"GraphQL Field Suggestion Information Leakage on {active_gql_path}",
                                    "category": FindingCategory.INFORMATION_DISCLOSURE,
                                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                                    "attack_family": AttackFamily.INFORMATION_DISCLOSURE.value,
                                    "severity": Severity.LOW,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The GraphQL server on '{active_gql_path}' returns 'Did you mean ...?' suggestions "
                                        f"when invalid fields are submitted, permitting automated schema reconstruction."
                                    ),
                                    "impact": "Facilitates brute-force discovery of private fields and unreleased features.",
                                    "remediation": "Mask suggestion errors in production error formatting handlers."
                                })
                        except Exception:
                            pass

                    # 1c. Query Depth & Complexity Exhaustion Probe
                    if run_depth_test:
                        # Construct a deeply nested query (Depth 12)
                        nested_q = "id"
                        for i in range(12):
                            nested_q = f"node {{ child {{ {nested_q} }} }}"
                        depth_payload = {"query": f"query DepthTest {{ {nested_q} }}"}

                        try:
                            t0 = time.perf_counter()
                            depth_resp = await client.post(
                                gql_target_url,
                                headers=dict(auth_headers, **{"Content-Type": "application/json"}),
                                json=depth_payload
                            )
                            depth_time = round((time.perf_counter() - t0) * 1000.0, 2)
                            graphql_results["depth_status"] = depth_resp.status_code
                            graphql_results["depth_time_ms"] = depth_time

                            # If server returned 500 internal server error or accepted depth > 10 without validation error
                            if depth_resp.status_code == 500:
                                insights.append(
                                    f"RESILIENCE DEFECT: Deeply nested GraphQL query caused HTTP 500 Internal Server Error on {active_gql_path}."
                                )
                                causal_chain.append(f"Sent 12-level nested recursive query to {active_gql_path}: caused server 500 crash")
                                findings_suggested.append({
                                    "title": f"Unhandled Server Crash on Deeply Nested GraphQL Query on {active_gql_path}",
                                    "category": FindingCategory.RESOURCE_EXHAUSTION,
                                    "finding_type": FindingType.RESILIENCE_FAILURE,
                                    "attack_family": AttackFamily.RESOURCE_EXHAUSTION.value,
                                    "severity": Severity.HIGH,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The GraphQL engine on '{active_gql_path}' crashed with HTTP 500 when processing "
                                        f"a 12-level nested recursive query, demonstrating absence of depth limiting."
                                    ),
                                    "impact": "Application Denial of Service (DoS) and worker thread starvation.",
                                    "remediation": "Implement query depth limiting plugins (e.g. graphql-depth-limit) to reject queries exceeding safe depth.",
                                    "causal_chain": list(causal_chain)
                                })
                        except Exception as e:
                            graphql_results["depth_error"] = str(e)

                    # 1d. Batching / Query Amplification Probe
                    if run_batching_test:
                        batch_payload = [{"query": "{ __typename }"} for _ in range(25)]
                        try:
                            batch_resp = await client.post(
                                gql_target_url,
                                headers=dict(auth_headers, **{"Content-Type": "application/json"}),
                                json=batch_payload
                            )
                            if batch_resp.status_code == 200 and isinstance(batch_resp.json(), list) and len(batch_resp.json()) == 25:
                                insights.append(
                                    f"GRAPHQL BATCHING PERMITTED: Server processed 25 batched queries in a single HTTP request on {active_gql_path}."
                                )
                                findings_suggested.append({
                                    "title": f"Unrestricted GraphQL Batching / Query Amplification on {active_gql_path}",
                                    "category": FindingCategory.API_SECURITY,
                                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                                    "attack_family": AttackFamily.RESOURCE_EXHAUSTION.value,
                                    "severity": Severity.MEDIUM,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The GraphQL endpoint on '{active_gql_path}' allows arbitrary query batching without rate limiting, "
                                        f"permitting brute-force amplification and rate limit evasion."
                                    ),
                                    "impact": "Bypasses external WAF rate limits and amplifies brute-force or credential-stuffing attacks.",
                                    "remediation": "Disable batching or enforce strict batch request limits (e.g., maximum 5 queries per request)."
                                })
                        except Exception:
                            pass

            # =========================================================================
            # 2. WEBSOCKET AUDIT SUITE
            # =========================================================================
            if target_type in ("websocket", "auto"):
                ws_paths = [endpoint] if endpoint and target_type == "websocket" else (
                    [endpoint] if endpoint and "graphql" not in endpoint else self.WEBSOCKET_COMMON_PATHS
                )

                for wsp in ws_paths:
                    resolved_ws_url = self.validate_target(session, wsp)
                    # Handshake request headers
                    ws_handshake_headers = {
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": "https://evil-attacker.example.com"
                    }
                    try:
                        ws_resp = await client.get(resolved_ws_url, headers=ws_handshake_headers)
                        websocket_results[wsp] = {
                            "status_code": ws_resp.status_code,
                            "headers": dict(ws_resp.headers)
                        }

                        # 101 Switching Protocols indicates handshake accepted
                        if ws_resp.status_code == 101:
                            if run_ws_origin:
                                insights.append(
                                    f"CRITICAL WEBSOCKET FLAW: Endpoint {wsp} accepted WebSocket handshake with untrusted Origin 'https://evil-attacker.example.com' (CSWSH)!"
                                )
                                causal_chain.append(
                                    f"Sent WebSocket Upgrade request with Origin 'https://evil-attacker.example.com' to {wsp}: "
                                    f"server accepted handshake with HTTP 101 Switching Protocols without origin validation"
                                )
                                findings_suggested.append({
                                    "title": f"Cross-Site WebSocket Hijacking (CSWSH) on {wsp}",
                                    "category": FindingCategory.SECURITY_MISCONFIGURATION,
                                    "finding_type": FindingType.SECURITY_VULNERABILITY,
                                    "attack_family": AttackFamily.SECURITY_MISCONFIGURATION.value,
                                    "severity": Severity.HIGH,
                                    "confidence": Confidence.HIGH,
                                    "description": (
                                        f"The WebSocket server at '{wsp}' accepts connection upgrade handshakes with "
                                        f"arbitrary third-party Origin headers. Attackers can hijack authenticated sessions "
                                        f"via malicious web pages."
                                    ),
                                    "impact": "Unauthorized bidirectional communication and data theft across origins.",
                                    "remediation": "Validate the 'Origin' request header against an explicit whitelist of authorized domains during the WebSocket handshake.",
                                    "causal_chain": list(causal_chain)
                                })
                        elif ws_resp.status_code in (400, 403, 401):
                            websocket_results[wsp]["rejected"] = True
                    except Exception as e:
                        websocket_results[wsp] = {"error": str(e)}

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=session.target.base_url,
            action_summary=f"GraphQL & WebSocket Security Audit (Target type: {target_type})",
            request_data={"target_type": target_type, "endpoint": endpoint},
            response_summary=f"Findings detected: {len(findings_suggested)}",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "SERVICES_SECURED"
        )
        session.add_attempt(attempt)

        summary = (
            f"GraphQL/WebSocket audit ({target_type}): "
            f"{len(findings_suggested)} finding(s) detected. "
            f"GraphQL active={bool(graphql_results.get('active_path'))}, "
            f"WebSocket paths checked={len(websocket_results)}."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint or "auto",
            summary=summary,
            key_insights=insights or ["No GraphQL introspection, depth issues, or WebSocket handshake vulnerabilities detected."],
            raw_data={
                "target_type": target_type,
                "graphql": graphql_results,
                "websocket": websocket_results,
                "findings_suggested": findings_suggested,
                "causal_chain": causal_chain
            }
        )
