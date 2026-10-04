import re
from typing import Any
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation


class DiscoverHttpSurfaceTool(BaseTool):
    """Tool for actively discovering the HTTP surface, API definitions, and endpoints."""

    name = "discover_http_surface"
    description = (
        "Actively probes the target web application to discover exposed endpoints, "
        "API specifications (OpenAPI/Swagger), debug routes, and authentication portals."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "scan_depth": {
                "type": "string",
                "enum": ["fast", "standard", "thorough"],
                "default": "standard",
                "description": "Thoroughness of endpoint discovery"
            }
        }
    }

    COMMON_PATHS = [
        "/",
        "/api",
        "/api/v1",
        "/docs",
        "/openapi.json",
        "/swagger.json",
        "/robots.txt",
        "/health",
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
        "/actuator/metrics",
        "/status",
        "/info",
        "/login",
        "/auth",
        "/auth/login",
        "/api/auth/login",
        "/api/v1/auth/login",
        "/users",
        "/api/users",
        "/api/v1/users",
        "/search",
        "/api/search",
        "/api/v1/search",
        "/admin",
        "/admin/config",
        "/api/admin/config",
        "/api/v1/admin/system-config",
        "/debug",
        "/api/debug",
        "/api/v1/debug/env",
        "/api/v1/reports/export",
        "/admin",
        "/debug"
    ]

    OPENAPI_SPEC_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/v1/openapi.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json"
    ]

    @staticmethod
    def parse_openapi_spec(spec: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        """Extracts routes, supported methods, summaries, and parameters dynamically from OpenAPI/Swagger JSON."""
        routes: list[dict[str, Any]] = []
        discovered_params: list[str] = []
        paths = spec.get("paths", {})
        valid_methods = {"get", "post", "put", "delete", "patch", "options", "head"}

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method_name, op in path_item.items():
                if method_name.lower() not in valid_methods or not isinstance(op, dict):
                    continue
                
                # Extract parameters
                param_names = []
                for param in op.get("parameters", []):
                    if isinstance(param, dict) and "name" in param:
                        p_name = param["name"]
                        param_names.append(p_name)
                        if p_name not in discovered_params:
                            discovered_params.append(p_name)
                
                # Extract JSON body schema properties if present
                req_body = op.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for media_type, schema_obj in content.items():
                        if "json" in media_type and isinstance(schema_obj, dict):
                            schema = schema_obj.get("schema", {})
                            props = schema.get("properties", {})
                            if isinstance(props, dict):
                                for prop_name in props.keys():
                                    if prop_name not in discovered_params:
                                        discovered_params.append(prop_name)

                route_info = {
                    "path": path,
                    "method": method_name.upper(),
                    "source": "openapi",
                    "status_code": 200,
                    "summary": op.get("summary", ""),
                    "parameters": param_names
                }
                routes.append(route_info)

        return routes, discovered_params

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        discovered_routes: list[dict[str, Any]] = []
        insights: list[str] = []
        all_params: list[str] = list(session.context_data.get("interesting_parameters", []))

        async with httpx.AsyncClient(timeout=4.0) as client:
            # 1. Probe for OpenAPI / Swagger specs dynamically
            for spec_path in self.OPENAPI_SPEC_PATHS:
                spec_url = self.validate_target(session, spec_path)
                try:
                    res = await client.get(spec_url)
                    if res.status_code == 200 and ("json" in res.headers.get("content-type", "") or res.text.strip().startswith("{")):
                        spec = res.json()
                        spec_routes, spec_params = self.parse_openapi_spec(spec)
                        if spec_routes:
                            insights.append(f"Discovered OpenAPI specification at {spec_path} with {len(spec_routes)} endpoints and {len(spec_params)} parameters.")
                            for r in spec_routes:
                                if not any(existing["path"] == r["path"] and existing["method"] == r["method"] for existing in discovered_routes):
                                    discovered_routes.append(r)
                            for p in spec_params:
                                if p not in all_params:
                                    all_params.append(p)
                            break
                except Exception:
                    pass

            # 2. Probe common path dictionary
            for path in self.COMMON_PATHS:
                url = self.validate_target(session, path)
                try:
                    res = await client.get(url, follow_redirects=False)
                    if res.status_code in (200, 201, 301, 302, 401, 403, 405):
                        allow_hdr = res.headers.get("allow", "").upper()
                        rec_method = "GET"
                        if res.status_code == 405:
                            rec_method = "POST" if ("POST" in allow_hdr or not allow_hdr) else (allow_hdr.split(",")[0].strip() or "POST")
                            insights.append(f"Mutation route found (HTTP 405 on GET): {path} -> requires {rec_method}")

                        route_info = {
                            "path": path,
                            "method": rec_method,
                            "source": "probe",
                            "status_code": res.status_code,
                            "content_type": res.headers.get("content-type", "").split(";")[0]
                        }
                        # Add if not already found in openapi
                        if not any(r["path"] == path for r in discovered_routes):
                            discovered_routes.append(route_info)
                            
                        if res.status_code == 200:
                            insights.append(f"Accessible endpoint found: {path} (HTTP {res.status_code})")
                            # Extract links from JSON or HATEOAS responses (e.g. Actuator, HAL, REST index)
                            try:
                                if "application/json" in res.headers.get("content-type", "") or res.text.strip().startswith(("{", "[")):
                                    hrefs = re.findall(r'"href"\s*:\s*"([^"]+)"', res.text)
                                    for h in hrefs:
                                        p_match = re.search(r'(https?://[^/]+)?(/[^"?#]+)', h)
                                        if p_match:
                                            sub_path = p_match.group(2)
                                            if not any(r["path"] == sub_path for r in discovered_routes):
                                                discovered_routes.append({
                                                    "path": sub_path,
                                                    "method": "GET",
                                                    "source": "link_discovery",
                                                    "status_code": 200,
                                                    "content_type": "application/json"
                                                })
                                                insights.append(f"Discovered linked resource from {path}: {sub_path}")
                            except Exception:
                                pass
                        elif res.status_code in (401, 403):
                            insights.append(f"Protected endpoint found: {path} (HTTP {res.status_code})")
                except Exception:
                    continue

        # Update session context
        endpoint_paths = [r["path"] for r in discovered_routes]
        endpoint_methods = {r["path"]: r.get("method", "GET") for r in discovered_routes}
        session.context_data["discovered_endpoints"] = endpoint_paths
        session.context_data["endpoint_methods"] = endpoint_methods
        session.context_data["interesting_parameters"] = all_params
        session.context_data["discovered_routes_detailed"] = discovered_routes
        
        summary = (
            f"Discovered {len(discovered_routes)} HTTP endpoints on target {session.target.base_url}. "
            f"Key surfaces: {', '.join(endpoint_paths[:6])}"
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=session.target.base_url,
            summary=summary,
            key_insights=insights,
            raw_data={"endpoints": discovered_routes}
        )
