import re
from typing import Any
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation


class InspectPageTool(BaseTool):
    """Tool for analyzing HTML structure, input forms, script tags, and hidden form fields."""

    name = "inspect_page"
    description = (
        "Extracts form fields, input parameters, script references, and hidden inputs "
        "from an HTML page to identify potential input injection and CSRF vectors."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "description": "Page path to inspect"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        target_url = self.validate_target(session, path)

        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(target_url)
            html = res.text

        insights: list[str] = []
        forms = re.findall(r'<form\b[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        inputs = re.findall(r'<input\b[^>]*>', html, re.IGNORECASE)
        scripts = re.findall(r'<script\b[^>]*src=["\'](.*?)["\']', html, re.IGNORECASE)

        has_csrf_token = any("csrf" in inp.lower() for inp in inputs)
        if forms and not has_csrf_token:
            insights.append(f"Detected {len(forms)} form(s) without anti-CSRF token fields.")

        insights.append(f"Discovered {len(inputs)} input fields and {len(scripts)} script references.")

        summary = f"Page {path} inspection: {len(forms)} forms, {len(inputs)} inputs found."

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=target_url,
            summary=summary,
            key_insights=insights,
            raw_data={
                "form_count": len(forms),
                "input_count": len(inputs),
                "scripts": scripts[:10],
                "csrf_protected": has_csrf_token
            }
        )
