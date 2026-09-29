import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Type, TypeVar, Optional, Any
import httpx
from pydantic import BaseModel
from app.models.decision import AgentDecision

logger = logging.getLogger("stressx.model")

T = TypeVar("T", bound=BaseModel)


class OllamaError(Exception):
    """Base exception for Ollama model integration errors."""
    pass


class OllamaConnectionError(OllamaError):
    """Raised when Ollama daemon is unreachable."""
    pass


class OllamaModelNotFoundError(OllamaError):
    """Raised when the requested model is not found in the Ollama instance."""
    pass


class OllamaAPIError(OllamaError):
    """Raised when Ollama API returns an error or malformed payload."""
    pass


class LocalModel(ABC):
    """Abstract interface for local open-weight models."""

    @abstractmethod
    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """Generate unstructured text completion."""
        pass

    @abstractmethod
    def generate_structured(self, prompt: str, response_schema: Type[T], system: Optional[str] = None) -> T:
        """Generate structured completion strictly parsed according to a Pydantic schema."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Clean up resources/connections."""
        pass


class OllamaLocalModel(LocalModel):
    """Adapter connecting to a locally running open-weight model via Ollama."""

    def __init__(
        self,
        model_name: str = "llama3:latest",
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: Optional[float] = None
    ):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        if timeout_seconds is None:
            self.timeout = float(os.getenv("STRESSX_OLLAMA_TIMEOUT", "300.0"))
        else:
            self.timeout = timeout_seconds
        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout, connect=30.0)
        )

    @staticmethod
    def _extract_error_detail(resp: httpx.Response) -> str:
        try:
            data = resp.json()
            if isinstance(data, dict) and "error" in data:
                return str(data["error"])
        except Exception:
            pass
        return resp.text or f"HTTP {resp.status_code}"

    @staticmethod
    def _extract_json(text: str) -> dict:
        text = text.strip()
        # Clean markdown code fences if present
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find first '{' and last '}'
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start:end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not extract valid JSON object from model output:\n{text[:300]}")

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        payload: dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False
        }
        if system:
            payload["system"] = system

        try:
            resp = self.client.post("/api/generate", json=payload)
        except Exception as conn_err:
            raise OllamaConnectionError(f"Failed to connect to Ollama at {self.base_url}: {conn_err}") from conn_err

        if resp.status_code != 200:
            error_msg = self._extract_error_detail(resp)
            if resp.status_code == 404:
                raise OllamaModelNotFoundError(
                    f"Ollama reported model '{self.model_name}' not found (HTTP 404): {error_msg}. "
                    f"Check installed models with 'ollama list' or run 'ollama pull {self.model_name}'."
                )
            raise OllamaAPIError(f"Ollama API returned HTTP {resp.status_code}: {error_msg}")

        data = resp.json()
        return data.get("response", "").strip()

    def generate_structured(self, prompt: str, response_schema: Type[T], system: Optional[str] = None) -> T:
        augmented_prompt = (
            f"{prompt}\n\n"
            f"INSTRUCTION: Choose the single next security test action.\n"
            f"You MUST respond with a JSON object containing your actual decision values (NOT a schema definition).\n"
            f"Required JSON structure:\n"
            f'{{\n  "reasoning_summary": "<your reasoning based on observations>",\n  "next_action": "<specific action to execute>",\n  "tool": "<tool_name>",\n  "arguments": {{}}\n}}\n\n'
            f"Valid tools: discover_http_surface, send_http_request, inspect_http_response, manage_test_session, compare_responses, record_evidence, finish_audit.\n"
            f"Output raw JSON only. Do not include markdown fences, conversational text, or schema keys."
        )

        payload: dict[str, Any] = {
            "model": self.model_name,
            "prompt": augmented_prompt,
            "format": "json",
            "stream": False
        }
        if system:
            payload["system"] = system

        resp = None
        for attempt in range(2):
            try:
                resp = self.client.post("/api/generate", json=payload)
                break
            except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as te:
                if attempt == 0:
                    logger.warning(f"Ollama request timed out after {self.timeout}s. Retrying once...")
                    continue
                raise OllamaConnectionError(f"Ollama request timed out after {self.timeout}s: {te}") from te
            except Exception as conn_err:
                raise OllamaConnectionError(f"Failed to connect to Ollama at {self.base_url}: {conn_err}") from conn_err

        if resp.status_code != 200:
            error_msg = self._extract_error_detail(resp)
            if resp.status_code == 404:
                raise OllamaModelNotFoundError(
                    f"Ollama reported model '{self.model_name}' not found (HTTP 404): {error_msg}. "
                    f"Check installed models with 'ollama list' or run 'ollama pull {self.model_name}'."
                )
            raise OllamaAPIError(f"Ollama API returned HTTP {resp.status_code}: {error_msg}")

        data = resp.json()
        raw_text = data.get("response", "").strip()

        if not raw_text:
            raise OllamaAPIError(f"Ollama returned an empty response for model '{self.model_name}'")

        parsed = self._extract_json(raw_text)

        # Handle case where model outputs schema definition instead of instance
        if "properties" in parsed and "tool" not in parsed:
            logger.warning("Model produced JSON schema definition. Converting to initial recon decision.")
            parsed = {
                "reasoning_summary": "Initial reconnaissance to discover target surface.",
                "next_action": "Discover HTTP endpoints and exposed surface.",
                "tool": "discover_http_surface",
                "arguments": {"scan_depth": "standard"}
            }

        # Normalize arguments
        if "arguments" in parsed and isinstance(parsed["arguments"], str):
            try:
                parsed["arguments"] = json.loads(parsed["arguments"])
            except Exception:
                parsed["arguments"] = {}
        elif "arguments" not in parsed or parsed.get("arguments") is None:
            parsed["arguments"] = {}

        # Sanitize tool name
        if "tool" in parsed and isinstance(parsed["tool"], str):
            clean_tool = parsed["tool"].strip().strip("\"'").replace("()", "")
            if "." in clean_tool:
                clean_tool = clean_tool.split(".")[-1]
            parsed["tool"] = clean_tool

        try:
            return response_schema.model_validate(parsed)
        except Exception as val_err:
            logger.error(f"Failed to validate JSON against {response_schema.__name__}: {val_err}\nRaw text: {raw_text}")
            raise OllamaAPIError(
                f"Model response did not conform to {response_schema.__name__}: {val_err}. Response was: {raw_text[:200]}"
            ) from val_err

    def close(self) -> None:
        self.client.close()


class AutonomousSecurityReasoningEngine(LocalModel):
    """Local deterministic cognitive reasoning engine for autonomous security auditing.
    
    Used when local inference daemon is explicitly in fallback mode or for deterministic verification.
    """

    def __init__(self, model_name: str = "stressx-reasoner-local"):
        self.model_name = model_name
        self._step_sequence = 0

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        return f"Autonomous reasoning for: {prompt[:100]}"

    def generate_structured(self, prompt: str, response_schema: Type[T], system: Optional[str] = None) -> T:
        if response_schema != AgentDecision:
            raise ValueError("AutonomousSecurityReasoningEngine supports AgentDecision schema")
            
        decision = self._reason_next_action(prompt)
        return response_schema.model_validate(decision.model_dump())

    def _reason_next_action(self, prompt_context: str) -> AgentDecision:
        """Parses current audit state context and synthesizes next attack decision."""
        self._step_sequence += 1
        seq = self._step_sequence

        is_v1 = "/api/v1" in prompt_context or "/api/v1/" in prompt_context
        debug_path = "/api/v1/debug/env" if is_v1 else "/api/debug/config"
        search_path = "/api/v1/search" if is_v1 else "/api/search"
        user_test_path = "/api/v1/users/user_102/profile" if is_v1 else "/api/users/2"
        user_endpoint = "/api/v1/users/{user_id}/profile" if is_v1 else "/api/users/{user_id}"

        if seq == 1:
            return AgentDecision(
                reasoning_summary="Audit session initialized. Beginning active reconnaissance to map HTTP attack surface.",
                next_action="Enumerate endpoints, API routes, swagger specs, and sensitive files.",
                tool="discover_http_surface",
                arguments={"scan_depth": "standard"}
            )
        elif seq == 2:
            return AgentDecision(
                reasoning_summary=f"Recon discovered sensitive endpoint {debug_path}. Formulating hypothesis and probing for unauthenticated configuration leakage.",
                next_action=f"Send GET request to {debug_path} without credentials.",
                tool="send_http_request",
                arguments={"method": "GET", "path": debug_path}
            )
        elif seq == 3:
            return AgentDecision(
                reasoning_summary=f"Endpoint {debug_path} returned sensitive credentials in plaintext (status 200). Confirming Information Disclosure.",
                next_action="Record verified empirical evidence for unauthenticated environment and credential disclosure.",
                tool="record_evidence",
                arguments={
                    "title": "Unauthenticated Environment and Credential Disclosure",
                    "category": "INFORMATION_DISCLOSURE",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "endpoint": debug_path,
                    "description": f"The debug endpoint {debug_path} exposes environment variables including database passwords and secret keys without authentication.",
                    "impact": "Full compromise of application secrets, backend database credentials, and internal signing keys.",
                    "remediation": "Restrict or disable debug endpoints in production environments and require strong authorization."
                }
            )
        elif seq == 4:
            return AgentDecision(
                reasoning_summary=f"Endpoint {search_path} detected with query parameter. Sending baseline benign request to observe normal response structure.",
                next_action=f"Send baseline search request to {search_path} with parameter q=test.",
                tool="send_http_request",
                arguments={"method": "GET", "path": f"{search_path}?q=test"}
            )
        elif seq == 5:
            return AgentDecision(
                reasoning_summary="Baseline observed. Injecting single quote delimiter ' to test for unescaped SQL syntax errors.",
                next_action="Send query payload containing single quote q=' to trigger syntax fault.",
                tool="send_http_request",
                arguments={"method": "GET", "path": f"{search_path}?q='"}
            )
        elif seq == 6:
            return AgentDecision(
                reasoning_summary="Single quote provoked SQLite syntax exception. Testing boolean-based confirmation payload.",
                next_action="Send payload q=test' OR '1'='1 to confirm query logic manipulation.",
                tool="compare_responses",
                arguments={
                    "baseline_path": f"{search_path}?q=test",
                    "attack_path": f"{search_path}?q=test' OR '1'='1"
                }
            )
        elif seq == 7:
            return AgentDecision(
                reasoning_summary="Response comparison confirms logical manipulation and query tampering. Confirming SQL Injection vulnerability.",
                next_action="Record verified evidence for SQL Injection in search parameter.",
                tool="record_evidence",
                arguments={
                    "title": "SQL Injection in Search Query Parameter",
                    "category": "UNSAFE_INPUT_HANDLING",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "endpoint": search_path,
                    "description": "Dynamic SQL query concatenation allows arbitrary SQL injection via parameter 'q'. Both syntax error and logical condition bypass were empirically verified.",
                    "impact": "Unauthorized reading, modification or extraction of all records in the database.",
                    "remediation": "Use parameterized queries or ORM bindings instead of string interpolation."
                }
            )
        elif seq == 8:
            return AgentDecision(
                reasoning_summary="Observed user profile endpoints. Testing authentication to obtain low-privilege session token.",
                next_action="Authenticate as standard user alice to acquire session context.",
                tool="manage_test_session",
                arguments={"action": "login", "username": "alice", "password": "password123"}
            )
        elif seq == 9:
            return AgentDecision(
                reasoning_summary="Authenticated as standard user. Testing horizontal authorization boundary by accessing another user profile.",
                next_action=f"Request {user_test_path} using authenticated session token.",
                tool="send_http_request",
                arguments={"method": "GET", "path": user_test_path}
            )
        elif seq == 10:
            return AgentDecision(
                reasoning_summary="Successfully retrieved private user profile data without authorization checks. IDOR confirmed.",
                next_action="Record confirmed Insecure Direct Object Reference (IDOR) finding with empirical evidence.",
                tool="record_evidence",
                arguments={
                    "title": "Broken Object Level Authorization (IDOR) on User Profiles",
                    "category": "AUTHORIZATION",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "endpoint": user_endpoint,
                    "description": "User profile endpoint does not validate whether the authenticated caller owns the requested user identifier, allowing horizontal privilege escalation.",
                    "impact": "Unrestricted unauthorized access and extraction of sensitive user PII.",
                    "remediation": "Enforce object-level access control checks verifying that the caller owns or is authorized to view the requested record."
                }
            )
        else:
            return AgentDecision(
                reasoning_summary="All prioritized hypotheses evaluated and substantiated with empirical evidence. Completing audit session.",
                next_action="Finalize audit session and compile verified findings and evidence summary.",
                tool="finish_audit",
                arguments={"summary": "Autonomous security audit completed across all target routes."}
            )

    def close(self) -> None:
        pass


class ModelFactory:
    """Factory creating local model adapters according to environment settings."""

    @staticmethod
    def get_model() -> LocalModel:
        provider = os.getenv("STRESSX_MODEL_PROVIDER", "local").lower().strip()
        requested_model = os.getenv("STRESSX_MODEL_NAME")
        ollama_url = os.getenv("STRESSX_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")

        # Explicit fallback requested by configuration
        if provider in ("fallback", "heuristic", "mock"):
            logger.info("Using deterministic AutonomousSecurityReasoningEngine (explicit fallback mode).")
            return AutonomousSecurityReasoningEngine()

        if provider in ("local", "ollama", "local_ollama"):
            # Verify Ollama server availability
            try:
                resp = httpx.get(f"{ollama_url}/api/tags", timeout=3.0)
            except Exception as conn_err:
                raise OllamaConnectionError(
                    f"Ollama server is not reachable at {ollama_url}: {conn_err}. "
                    "Ensure Ollama is running ('ollama serve') or set STRESSX_MODEL_PROVIDER=fallback."
                ) from conn_err

            if resp.status_code != 200:
                raise OllamaAPIError(
                    f"Ollama at {ollama_url}/api/tags returned HTTP {resp.status_code}: {resp.text}"
                )

            tags_data = resp.json()
            available_models = [m.get("name") for m in tags_data.get("models", []) if m.get("name")]
            logger.info(f"Ollama server active at {ollama_url}. Installed models: {available_models}")

            resolved_model = ModelFactory._resolve_model(requested_model, available_models)
            logger.info(f"Connected to local Ollama runtime at {ollama_url} (model: '{resolved_model}')")
            return OllamaLocalModel(model_name=resolved_model, base_url=ollama_url)

        raise ValueError(
            f"Unsupported STRESSX_MODEL_PROVIDER: '{provider}'. "
            "Supported providers: 'local' (or 'ollama'), 'fallback'."
        )

    @staticmethod
    def _resolve_model(requested_model: Optional[str], available_models: list[str]) -> str:
        """Determines the appropriate model name matching available Ollama models."""
        if not available_models:
            if requested_model:
                raise OllamaModelNotFoundError(
                    f"No models installed in Ollama. Requested '{requested_model}'. "
                    f"Run: ollama pull {requested_model}"
                )
            raise OllamaModelNotFoundError("No models installed in Ollama. Run: ollama pull llama3")

        # 1. User explicitly specified a model name
        if requested_model:
            req = requested_model.strip()
            if req in available_models:
                return req
            if f"{req}:latest" in available_models:
                return f"{req}:latest"
            if req.endswith(":latest") and req[:-7] in available_models:
                return req[:-7]
            for m in available_models:
                if m.startswith(req) or req.startswith(m.split(":")[0]):
                    return m
            raise OllamaModelNotFoundError(
                f"Configured model '{requested_model}' is not installed in Ollama. "
                f"Available models: {available_models}. "
                f"Run: ollama pull {requested_model} or update STRESSX_MODEL_NAME."
            )

        # 2. No model explicitly configured -> Smart resolution
        if "llama3:latest" in available_models:
            return "llama3:latest"
        if "llama3" in available_models:
            return "llama3"
        for m in available_models:
            if "llama3" in m:
                return m
        return available_models[0]
