import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import yaml

from app.models.target import Target
from app.models.session import AuditSession
from app.models.metrics import AuditMetrics, AggregateMetrics
from app.target.detector import ProjectDetector, ProjectInfo, ProjectType, ProjectDetectionError
from app.target.compose_sandbox import ComposeProjectSandbox, ComposeSandboxError
from app.evidence.store import EvidenceStore


def test_compose_file_detection_all_variants(tmp_path):
    """Verify that all standard compose filenames are detected as DOCKER_COMPOSE."""
    compose_names = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml"
    ]
    sample_yaml = {
        "services": {
            "web": {
                "image": "python:3.13-slim",
                "ports": ["8000:8000"]
            }
        }
    }

    for name in compose_names:
        proj_dir = tmp_path / f"proj_{name.replace('.', '_')}"
        proj_dir.mkdir(parents=True, exist_ok=True)
        compose_file = proj_dir / name
        compose_file.write_text(yaml.dump(sample_yaml), encoding="utf-8")

        info = ProjectDetector.detect(proj_dir)
        assert info.project_type == ProjectType.DOCKER_COMPOSE
        assert info.compose_file == name
        assert "web" in info.services
        assert info.detected_port == 8000


def test_invalid_compose_projects(tmp_path):
    """Verify that empty, malformed, or missing-services compose files raise ProjectDetectionError."""
    # 1. Empty compose file
    empty_dir = tmp_path / "empty_compose"
    empty_dir.mkdir()
    (empty_dir / "compose.yaml").write_text("", encoding="utf-8")
    with pytest.raises(ProjectDetectionError, match="is empty"):
        ProjectDetector.detect(empty_dir)

    # 2. Corrupt YAML
    corrupt_dir = tmp_path / "corrupt_compose"
    corrupt_dir.mkdir()
    (corrupt_dir / "docker-compose.yml").write_text("services: [unbalanced", encoding="utf-8")
    with pytest.raises(ProjectDetectionError, match="Failed to parse"):
        ProjectDetector.detect(corrupt_dir)

    # 3. Missing services section
    no_services_dir = tmp_path / "no_services"
    no_services_dir.mkdir()
    (no_services_dir / "compose.yml").write_text("version: '3.8'\nnetworks:\n  default:\n", encoding="utf-8")
    with pytest.raises(ProjectDetectionError, match="No 'services' section found"):
        ProjectDetector.detect(no_services_dir)


def test_multi_service_project_detection(tmp_path):
    """Verify multi-service classification for app + postgres + redis."""
    proj_dir = tmp_path / "multi_service"
    proj_dir.mkdir()
    compose_yaml = {
        "services": {
            "web": {
                "build": ".",
                "ports": ["8080:8080"],
                "depends_on": ["db", "cache"]
            },
            "db": {
                "image": "postgres:16-alpine",
                "ports": ["5432:5432"]
            },
            "cache": {
                "image": "redis:7-alpine",
                "ports": ["6379:6379"]
            }
        }
    }
    (proj_dir / "docker-compose.yml").write_text(yaml.dump(compose_yaml), encoding="utf-8")

    info = ProjectDetector.detect(proj_dir)
    assert info.project_type == ProjectType.DOCKER_COMPOSE
    assert info.is_multi_service is True
    assert set(info.services) == {"web", "db", "cache"}
    assert info.primary_service == "web"
    assert info.detected_port == 8080

    assert info.service_types["web"] == "application"
    assert info.service_types["db"] == "database"
    assert info.service_types["cache"] == "cache"


def test_internal_database_service_handling(tmp_path):
    """Verify that the sandbox strips external host ports from database and cache services."""
    proj_dir = tmp_path / "port_strip_test"
    proj_dir.mkdir()
    compose_yaml = {
        "services": {
            "api": {
                "build": ".",
                "ports": ["8000:8000"]
            },
            "postgres": {
                "image": "postgres:15",
                "ports": ["5432:5432"]
            },
            "redis": {
                "image": "redis:alpine",
                "ports": ["6379:6379"]
            }
        }
    }
    (proj_dir / "docker-compose.yml").write_text(yaml.dump(compose_yaml), encoding="utf-8")
    info = ProjectDetector.detect(proj_dir)

    sandbox = ComposeProjectSandbox(project_info=info, target_service="api", target_port=8000)
    sandbox.temp_dir = tmp_path / "scratch_test"
    sandbox.temp_dir.mkdir()
    sandbox.scratch_compose_file = sandbox.temp_dir / "docker-compose.yml"
    sandbox.scratch_compose_file.write_text(yaml.dump(compose_yaml), encoding="utf-8")

    sandbox._sanitize_and_write_compose_file()

    # Re-read sanitized compose file
    with open(sandbox.scratch_compose_file, "r", encoding="utf-8") as f:
        sanitized = yaml.safe_load(f)

    # API must expose host port strictly on 127.0.0.1
    assert "ports" in sanitized["services"]["api"]
    api_port_entry = sanitized["services"]["api"]["ports"][0]
    assert api_port_entry.startswith("127.0.0.1:")
    assert api_port_entry.endswith(":8000")

    # Postgres must NOT expose host ports
    assert "ports" not in sanitized["services"]["postgres"]
    assert 5432 in sanitized["services"]["postgres"].get("expose", [])

    # Redis must NOT expose host ports
    assert "ports" not in sanitized["services"]["redis"]
    assert 6379 in sanitized["services"]["redis"].get("expose", [])


def test_ambiguous_exposed_services_and_explicit_override(tmp_path):
    """Verify that multiple application candidates can be explicitly selected via target_service."""
    proj_dir = tmp_path / "ambiguous_app"
    proj_dir.mkdir()
    compose_yaml = {
        "services": {
            "frontend": {
                "build": "./frontend",
                "ports": ["3000:3000"]
            },
            "backend": {
                "build": "./backend",
                "ports": ["8000:8000"]
            }
        }
    }
    (proj_dir / "compose.yaml").write_text(yaml.dump(compose_yaml), encoding="utf-8")
    info = ProjectDetector.detect(proj_dir)

    # Explicit override selecting backend
    sandbox = ComposeProjectSandbox(
        project_info=info,
        target_service="backend",
        target_port=8000
    )
    assert sandbox.primary_service == "backend"
    assert sandbox.container_port == 8000
    assert sandbox.target.primary_service == "backend"


def test_compose_lifecycle_mocked(tmp_path):
    """Verify build_and_start and cleanup lifecycle with mocked docker compose commands."""
    proj_dir = tmp_path / "lifecycle_proj"
    proj_dir.mkdir()
    compose_yaml = {
        "services": {
            "web": {
                "image": "python:3.13-slim",
                "ports": ["8000:8000"]
            }
        }
    }
    (proj_dir / "compose.yaml").write_text(yaml.dump(compose_yaml), encoding="utf-8")
    info = ProjectDetector.detect(proj_dir)

    sandbox = ComposeProjectSandbox(project_info=info)

    mock_run = MagicMock()
    mock_run.return_value = MagicMock(returncode=0, stdout="Container started", stderr="")

    with patch("subprocess.run", mock_run), \
         patch.object(sandbox, "_check_docker_compose_cli"), \
         patch.object(sandbox, "wait_until_ready", return_value=True):
        target = sandbox.build_and_start()

        assert sandbox.deployment_succeeded is True
        assert target.sandbox_deployment_success is True
        assert target.is_multi_service is True
        assert target.primary_service == "web"
        assert sandbox.deployment_duration > 0.0

        # Test cleanup
        cleaned = sandbox.cleanup()
        assert cleaned is True
        assert sandbox.cleanup_succeeded is True
        assert target.sandbox_cleanup_success is True


def test_compose_failed_deployment_mocked(tmp_path):
    """Verify that build or startup failure aborts and does not mark deployment as succeeded."""
    proj_dir = tmp_path / "fail_proj"
    proj_dir.mkdir()
    (proj_dir / "compose.yaml").write_text("services:\n  app:\n    image: broken:tag\n", encoding="utf-8")
    info = ProjectDetector.detect(proj_dir)

    sandbox = ComposeProjectSandbox(project_info=info)

    mock_run = MagicMock()
    # Simulate compose up failure
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error: broken image")

    with patch("subprocess.run", mock_run), \
         patch.object(sandbox, "_check_docker_compose_cli"):
        with pytest.raises(ComposeSandboxError, match="Docker Compose failed"):
            sandbox.build_and_start()

    assert sandbox.deployment_succeeded is False
    assert sandbox.target.sandbox_deployment_success is False


def test_compose_metrics_integration(tmp_path):
    """Verify that AuditMetrics accurately records multi-service deployment metadata."""
    target = Target(
        base_url="http://127.0.0.1:9250",
        is_sandboxed=True,
        sandbox_deployment_success=True,
        sandbox_cleanup_success=True,
        is_multi_service=True,
        primary_service="web_api",
        services=["web_api", "postgres", "redis"],
        deployment_duration=4.75
    )
    session = AuditSession(target=target)
    session.record_multi_service_deployment(
        success=True,
        services=["web_api", "postgres", "redis"],
        primary_service="web_api",
        duration=4.75
    )
    session.record_sandbox_cleanup(True)

    metrics = AuditMetrics.calculate_from_session(session, project_type="DOCKER_COMPOSE")
    assert metrics.sandbox_deployments == 1
    assert metrics.successful_deployments == 1
    assert metrics.deployment_failures == 0
    assert metrics.sandbox_cleanup_success == 1
    assert metrics.successful_cleanups == 1
    assert metrics.cleanup_failures == 0
    assert metrics.services_deployed == 3
    assert metrics.primary_target_service == "web_api"
    assert metrics.deployment_duration == 4.75

    # Aggregate test
    store = EvidenceStore(export_dir=str(tmp_path))
    store.save_audit_dossier(session, project_type="DOCKER_COMPOSE")

    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 1
    assert agg.total_sandbox_deployments == 1
    assert agg.total_successful_sandbox_cleanups == 1
    assert agg.total_services_deployed == 3


def test_isolation_guarantees_user_directory_untouched(tmp_path):
    """Verify that sandbox operates strictly in scratch directory and never mutates user files."""
    user_proj = tmp_path / "user_original_project"
    user_proj.mkdir()
    compose_yaml = {
        "services": {
            "app": {
                "image": "python:3.13-slim",
                "ports": ["8000:8000"]
            }
        }
    }
    compose_path = user_proj / "docker-compose.yml"
    compose_path.write_text(yaml.dump(compose_yaml), encoding="utf-8")
    marker_file = user_proj / "secret_source.txt"
    marker_content = "ORIGINAL_UNTOUCHED_CONTENT_12345"
    marker_file.write_text(marker_content, encoding="utf-8")

    info = ProjectDetector.detect(user_proj)
    sandbox = ComposeProjectSandbox(project_info=info)

    # Prepare scratch workspace
    sandbox.temp_dir = tmp_path / "scratch_work"
    sandbox.temp_dir.mkdir()
    sandbox._prepare_scratch_workspace()
    sandbox._sanitize_and_write_compose_file()

    # Verify user project directory is completely unchanged
    assert marker_file.read_text(encoding="utf-8") == marker_content
    # The original compose file must still have original content (not modified with 127.0.0.1)
    original_compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert original_compose["services"]["app"]["ports"] == ["8000:8000"]


def test_existing_single_container_behavior_remains_unchanged(tmp_path):
    """Verify that non-compose projects continue to be detected and handled by single-container sandbox."""
    python_proj = tmp_path / "single_py"
    python_proj.mkdir()
    (python_proj / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (python_proj / "app.py").write_text("import fastapi\n", encoding="utf-8")

    info = ProjectDetector.detect(python_proj)
    assert info.project_type == ProjectType.PYTHON
    assert info.compose_file is None
    assert info.is_multi_service is False


def test_sample_compose_postgres_app_structure():
    """Verify that the actual sample_projects/compose_postgres_app directory is detected accurately."""
    sample_path = Path("sample_projects/compose_postgres_app")
    assert sample_path.exists()
    assert (sample_path / "docker-compose.yml").exists()
    assert (sample_path / "Dockerfile").exists()
    assert (sample_path / "app.py").exists()

    info = ProjectDetector.detect(sample_path)
    assert info.project_type == ProjectType.DOCKER_COMPOSE
    assert info.is_multi_service is True
    assert "web" in info.services
    assert "db" in info.services
    assert info.primary_service == "web"
    assert info.service_types["web"] == "application"
    assert info.service_types["db"] == "database"
    assert info.detected_port == 8000

