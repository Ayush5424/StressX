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
        "/login",
        "/api/v1/auth/login",
        "/api/v1/users",
        "/api/v1/users/user_101/profile",
        "/api/v1/users/user_102/profile",
        "/api/v1/search",
        "/api/v1/admin/system-config",
        "/api/v1/debug/env",
        "/api/v1/reports/export",
        "/admin",
        "/debug"
    ]

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        discovered_routes: list[dict[str, Any]] = []
        insights: list[str] = []

        async with httpx.AsyncClient(timeout=4.0) as client:
            # 1. First probe for OpenAPI / Swagger specs
            for spec_path in ["/openapi.json", "/swagger.json", "/api/openapi.json"]:
                spec_url = self.validate_target(session, spec_path)
                try:
                    res = await client.get(spec_url)
                    if res.status_code == 200 and "application/json" in res.headers.get("content-type", ""):
                        spec = res.json()
                        paths = spec.get("paths", {})
                        insights.append(f"Discovered OpenAPI specification at {spec_path} with {len(paths)} endpoints.")
                        for path, methods in paths.items():
                            for method in methods.keys():
                                route_info = {
                                    "path": path,
                                    "method": method.upper(),
                                    "source": "openapi",
                                    "status_code": 200,
                                    "summary": methods[method].get("summary", "")
                                }
                                if route_info not in discovered_routes:
                                    discovered_routes.append(route_info)
                        break
                except Exception:
                    pass

            # 2. Probe common path dictionary
            for path in self.COMMON_PATHS:
                url = self.validate_target(session, path)
                try:
                    res = await client.get(url, follow_redirects=False)
                    if res.status_code in (200, 201, 301, 302, 401, 403, 405):
                        route_info = {
                            "path": path,
                            "method": "GET",
                            "source": "probe",
                            "status_code": res.status_code,
                            "content_type": res.headers.get("content-type", "").split(";")[0]
                        }
                        # Add if not already found in openapi
                        if not any(r["path"] == path for r in discovered_routes):
                            discovered_routes.append(route_info)
                            
                        if res.status_code == 200:
                            insights.append(f"Accessible endpoint found: {path} (HTTP {res.status_code})")
                        elif res.status_code in (401, 403):
                            insights.append(f"Protected endpoint found: {path} (HTTP {res.status_code})")
                except Exception:
                    continue

        # Update session context
        endpoint_paths = [r["path"] for r in discovered_routes]
        session.context_data["discovered_endpoints"] = endpoint_paths
        
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
