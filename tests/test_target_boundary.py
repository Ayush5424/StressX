import pytest
from app.models.target import Target, TargetBoundaryViolation


def test_target_boundary_allowance():
    target = Target(base_url="http://127.0.0.1:8088")
    
    # Allowed local URLs
    assert target.is_url_allowed("http://127.0.0.1:8088/api/v1/search")
    assert target.is_url_allowed("http://localhost:8088/health")
    assert target.is_url_allowed("/api/v1/users")

    # Disallowed external / out-of-scope URLs
    assert not target.is_url_allowed("http://example.com/api")
    assert not target.is_url_allowed("https://google.com")
    assert not target.is_url_allowed("http://127.0.0.1:9099/unauthorized")


def test_target_boundary_violation_raised():
    target = Target(base_url="http://127.0.0.1:8088")
    
    with pytest.raises(TargetBoundaryViolation) as exc:
        target.resolve_url("http://attacker.com/evil")
    assert "violates assessment boundaries" in str(exc.value)


def test_target_path_resolution():
    target = Target(base_url="http://127.0.0.1:8088")
    resolved = target.resolve_url("/api/v1/debug")
    assert resolved == "http://127.0.0.1:8088/api/v1/debug"
