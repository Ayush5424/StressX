from typing import Any
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation


class ManageTestSessionTool(BaseTool):
    """Tool for managing test sessions, authentication contexts, cookies, and tokens."""

    name = "manage_test_session"
    description = (
        "Manages session state, logs in to obtain authentication tokens, stores user contexts, "
        "and switches between identities (e.g. standard user vs admin) to test authorization boundaries."
    )
    parameters_schema = {
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {"type": "string", "enum": ["login", "set_token", "clear_session", "get_status"]},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "token": {"type": "string"},
            "login_endpoint": {"type": "string", "default": "/api/v1/auth/login"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        action = kwargs.get("action", "get_status")
        insights: list[str] = []

        if action == "login":
            username = kwargs.get("username", "alice")
            password = kwargs.get("password", "password123")
            login_endpoint = kwargs.get("login_endpoint", "/api/v1/auth/login")
            login_url = self.validate_target(session, login_endpoint)

            async with httpx.AsyncClient(timeout=5.0) as client:
                try:
                    res = await client.post(login_url, json={"username": username, "password": password})
                    if res.status_code == 200:
                        data = res.json()
                        token = data.get("access_token") or data.get("token")
                        session.context_data["active_token"] = token
                        session.context_data["active_user"] = username
                        session.context_data["tokens"][username] = token
                        insights.append(f"Successfully authenticated as '{username}'. Token captured.")
                        summary = f"Logged in as '{username}'. Session token acquired and activated."
                    else:
                        insights.append(f"Login failed for '{username}' with HTTP {res.status_code}.")
                        summary = f"Authentication attempt for '{username}' returned HTTP {res.status_code}."
                except Exception as e:
                    insights.append(f"Login request error: {str(e)}")
                    summary = f"Authentication failed with error: {str(e)}"

        elif action == "set_token":
            token = kwargs.get("token", "")
            session.context_data["active_token"] = token
            summary = "Direct authentication token configured in session context."
            insights.append("Active bearer token updated.")

        elif action == "clear_session":
            session.context_data.pop("active_token", None)
            session.context_data.pop("active_user", None)
            summary = "Session context cleared. Subsequent requests will be unauthenticated."
            insights.append("Session state reset to anonymous.")

        else:
            active_user = session.context_data.get("active_user", "anonymous")
            has_token = bool(session.context_data.get("active_token"))
            summary = f"Active session state: User='{active_user}', HasToken={has_token}."

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=session.target.base_url,
            summary=summary,
            key_insights=insights,
            raw_data={"context": session.context_data}
        )
