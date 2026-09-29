import re
from typing import Any

# Regular expression patterns for common sensitive values
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_BEARER_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9_\-\.]{8,})", re.IGNORECASE)
_DB_URL_PATTERN = re.compile(r"(postgres(?:ql)?|mysql|mongodb|redis)://([^:]+):([^@]+)@", re.IGNORECASE)
_AWS_KEY_PATTERN = re.compile(r"(AKIA[A-Z0-9]{16})")
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL)
_JSON_CREDENTIAL_PATTERN = re.compile(
    r'("(?:password|secret|token|access_token|key|api_key|apiKey)"\s*:\s*")([^"]+)(")',
    re.IGNORECASE
)
_URL_PARAM_CREDENTIAL_PATTERN = re.compile(
    r"((?:password|secret|token|api_key|apiKey)=)([^&\s]+)",
    re.IGNORECASE
)


def redact_sensitive_text(text: str) -> str:
    """Masks secrets, passwords, JWTs, API keys, and connection credentials from strings."""
    if not isinstance(text, str) or not text:
        return ""

    # 1. Private keys
    text = _PRIVATE_KEY_PATTERN.sub("-----BEGIN [REDACTED PRIVATE KEY]-----", text)

    # 2. Database connection credentials
    text = _DB_URL_PATTERN.sub(r"\1://\2:[REDACTED]@", text)

    # 3. JWTs
    text = _JWT_PATTERN.sub("[REDACTED_JWT]", text)

    # 4. Bearer tokens
    text = _BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", text)

    # 5. AWS Access Keys
    text = _AWS_KEY_PATTERN.sub("AKIA****************", text)

    # 6. JSON credential fields
    text = _JSON_CREDENTIAL_PATTERN.sub(r'\1[REDACTED]\3', text)

    # 7. URL query parameter credentials
    text = _URL_PARAM_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]", text)

    return text


def redact_dict(data: Any) -> Any:
    """Recursively redacts dictionary keys containing passwords, tokens, or credentials."""
    sensitive_keys = {
        "password", "secret", "token", "access_token", "jwt_secret",
        "api_key", "apikey", "private_key", "secret_key", "authorization",
        "confidential_data", "secret_notes", "secret_data"
    }

    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if k.lower() in sensitive_keys and isinstance(v, (str, int, float)):
                cleaned[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                cleaned[k] = redact_dict(v)
            elif isinstance(v, str):
                cleaned[k] = redact_sensitive_text(v)
            else:
                cleaned[k] = v
        return cleaned
    elif isinstance(data, list):
        return [redact_dict(item) for item in data]
    elif isinstance(data, str):
        return redact_sensitive_text(data)
    return data
