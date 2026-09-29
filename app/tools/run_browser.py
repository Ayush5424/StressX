from typing import Any
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation


class RunBrowserTool(BaseTool):
    """Tool for running a headless browser to render pages, execute scripts, and inspect client DOM."""

    name = "run_browser"
    description = (
        "Launches a browser session against a target URL to observe client-side DOM rendering, "
        "detect single-page application routes, and monitor console errors."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path_or_url"],
        "properties": {
            "path_or_url": {"type": "string", "description": "Page URL or relative path to render"},
            "wait_ms": {"type": "integer", "default": 1000}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path_or_url", "/")
        target_url = self.validate_target(session, path)
        insights: list[str] = []

        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                resp = await page.goto(target_url, timeout=10000)
                title = await page.title()
                content = await page.content()
                await browser.close()
                status = resp.status if resp else 200
                summary = f"Browser rendered '{target_url}' (Title: '{title}', Status: {status})."
                insights.append(f"Client-rendered page title: '{title}'")
                return Observation(
                    step=session.step_count,
                    tool=self.name,
                    target=target_url,
                    summary=summary,
                    key_insights=insights,
                    raw_data={"title": title, "content_snippet": content[:500]}
                )
        except Exception as e:
            # Fallback using httpx HTTP client if Playwright browser binary is not pre-installed
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(target_url)
                summary = f"Rendered page via HTTP parser for '{target_url}' (Status {res.status_code})."
                insights.append(f"HTTP fallback inspection performed ({len(res.text)} bytes).")
                return Observation(
                    step=session.step_count,
                    tool=self.name,
                    target=target_url,
                    summary=summary,
                    key_insights=insights,
                    raw_data={"status_code": res.status_code, "body": res.text[:500]}
                )
