import json
import pytest
import httpx
from app.models.decision import AgentDecision
from app.models.adapter import (
    OllamaLocalModel,
    CloudAPIModel,
    ModelFactory,
    OllamaModelNotFoundError,
    OllamaAPIError,
    OllamaConnectionError,
    AutonomousSecurityReasoningEngine
)


def test_model_resolution_exact_and_suffix():
    available = ["llama3:latest", "mistral:latest"]

    # Exact match
    assert ModelFactory._resolve_model("llama3:latest", available) == "llama3:latest"

    # Match without :latest suffix
    assert ModelFactory._resolve_model("llama3", available) == "llama3:latest"

    # Smart default when no model requested
    assert ModelFactory._resolve_model(None, available) == "llama3:latest"


def test_model_resolution_not_found():
    available = ["llama3:latest"]

    with pytest.raises(OllamaModelNotFoundError) as exc:
        ModelFactory._resolve_model("nonexistent_model:7b", available)
    assert "nonexistent_model:7b" in str(exc.value)
    assert "llama3:latest" in str(exc.value)


def test_model_resolution_empty_models():
    with pytest.raises(OllamaModelNotFoundError):
        ModelFactory._resolve_model(None, [])


def test_ollama_structured_generation_success():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/generate"
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["model"] == "llama3:latest"
        assert payload["format"] == "json"

        response_json = {
            "model": "llama3:latest",
            "response": json.dumps({
                "reasoning_summary": "Reconnaissance complete. Probing debug endpoint.",
                "next_action": "Send GET to /api/v1/debug/env",
                "tool": "send_http_request",
                "arguments": {"method": "GET", "path": "/api/v1/debug/env"}
            }),
            "done": True
        }
        return httpx.Response(200, json=response_json)

    transport = httpx.MockTransport(mock_handler)
    model = OllamaLocalModel(model_name="llama3:latest", base_url="http://127.0.0.1:11434")
    model.client = httpx.Client(base_url="http://127.0.0.1:11434", transport=transport)

    decision = model.generate_structured("Analyze target state", AgentDecision)
    assert isinstance(decision, AgentDecision)
    assert decision.tool == "send_http_request"
    assert decision.arguments.get("path") == "/api/v1/debug/env"


def test_ollama_structured_generation_with_markdown_fences():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raw_output = """```json
{
  "reasoning_summary": "Testing SQL injection",
  "next_action": "Send probe with single quote",
  "tool": "send_http_request",
  "arguments": {"path": "/api/v1/search?q='"}
}
```"""
        return httpx.Response(200, json={"model": "llama3:latest", "response": raw_output, "done": True})

    transport = httpx.MockTransport(mock_handler)
    model = OllamaLocalModel(model_name="llama3:latest", base_url="http://127.0.0.1:11434")
    model.client = httpx.Client(base_url="http://127.0.0.1:11434", transport=transport)

    decision = model.generate_structured("Analyze state", AgentDecision)
    assert decision.tool == "send_http_request"
    assert decision.arguments["path"] == "/api/v1/search?q='"


def test_ollama_404_model_not_found_handling():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'llama3.1:8b' not found, try pulling it first"})

    transport = httpx.MockTransport(mock_handler)
    model = OllamaLocalModel(model_name="llama3.1:8b", base_url="http://127.0.0.1:11434")
    model.client = httpx.Client(base_url="http://127.0.0.1:11434", transport=transport)

    with pytest.raises(OllamaModelNotFoundError) as exc:
        model.generate_structured("Prompt", AgentDecision)
    assert "Ollama reported model 'llama3.1:8b' not found" in str(exc.value)


def test_model_factory_no_silent_fallback_when_server_down(monkeypatch):
    monkeypatch.setenv("STRESSX_MODEL_PROVIDER", "local")
    monkeypatch.setenv("STRESSX_OLLAMA_URL", "http://127.0.0.1:59999")  # Non-existent port

    with pytest.raises(OllamaConnectionError) as exc:
        ModelFactory.get_model()
    assert "Ollama server is not reachable" in str(exc.value)


def test_model_factory_explicit_fallback_mode(monkeypatch):
    monkeypatch.setenv("STRESSX_MODEL_PROVIDER", "fallback")
    engine = ModelFactory.get_model()
    assert isinstance(engine, AutonomousSecurityReasoningEngine)


def test_cloud_api_model_generate_structured():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        assert request.headers.get("Authorization") == "Bearer sk-test-fake-key"
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["model"] == "gpt-4o-mini"
        assert payload["response_format"] == {"type": "json_object"}

        response_json = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "reasoning_summary": "Cloud reasoning: checking for exposed endpoints.",
                        "next_action": "Probe auth endpoint",
                        "tool": "send_http_request",
                        "arguments": {"method": "GET", "path": "/api/v1/auth/status"}
                    })
                }
            }]
        }
        return httpx.Response(200, json=response_json)

    transport = httpx.MockTransport(mock_handler)
    model = CloudAPIModel(api_key="sk-test-fake-key", model_name="gpt-4o-mini", base_url="https://api.openai.com/v1")
    model.client = httpx.Client(base_url="https://api.openai.com/v1", transport=transport)

    decision = model.generate_structured("Analyze state", AgentDecision)
    assert isinstance(decision, AgentDecision)
    assert decision.tool == "send_http_request"
    assert decision.arguments.get("path") == "/api/v1/auth/status"


def test_model_factory_cloud_openai_mode(monkeypatch):
    monkeypatch.setenv("STRESSX_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-sample-key")
    monkeypatch.setenv("STRESSX_MODEL_NAME", "gpt-4o-mini")

    model = ModelFactory.get_model()
    assert isinstance(model, CloudAPIModel)
    assert model.model_name == "gpt-4o-mini"


def test_model_factory_cloud_missing_key_raises(monkeypatch):
    monkeypatch.setenv("STRESSX_MODEL_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("STRESSX_API_KEY", raising=False)

    with pytest.raises(ValueError) as exc:
        ModelFactory.get_model()
    assert "requires OPENAI_API_KEY or STRESSX_API_KEY" in str(exc.value)

