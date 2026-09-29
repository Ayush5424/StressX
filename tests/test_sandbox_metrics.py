import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import json

from app.models.target import Target
from app.models.session import AuditSession, SessionStatus
from app.models.metrics import AuditMetrics, AggregateMetrics
from app.evidence.store import EvidenceStore
from app.target.sandbox import DockerProjectSandbox, DockerSandboxError
from app.target.runner import TargetRunner
from app.target.detector import ProjectInfo, ProjectType


def test_successful_sandbox_deployment_increments_count():
    """Verify successful sandbox deployment sets deployment count to 1."""
    target = Target(
        base_url="http://127.0.0.1:9123",
        is_sandboxed=True,
        sandbox_deployment_success=True
    )
    session = AuditSession(target=target)
    assert session.sandbox_deployments == 1

    metrics = AuditMetrics.calculate_from_session(session, project_type="PYTHON")
    assert metrics.sandbox_deployments == 1


def test_failed_deployment_does_not_increment_count():
    """Verify failed sandbox deployment keeps deployment count at 0 even for non-benchmark projects."""
    target = Target(
        base_url="http://127.0.0.1:9123",
        is_sandboxed=True,
        sandbox_deployment_success=False
    )
    session = AuditSession(target=target)
    assert session.sandbox_deployments == 0

    # Ensure no fabrication even when project_type is a user project
    metrics = AuditMetrics.calculate_from_session(session, project_type="SPRING_BOOT_MAVEN")
    assert metrics.sandbox_deployments == 0


def test_successful_cleanup_increments_count():
    """Verify successful sandbox container cleanup sets cleanup count to 1."""
    target = Target(
        base_url="http://127.0.0.1:9123",
        is_sandboxed=True,
        sandbox_deployment_success=True
    )
    session = AuditSession(target=target)
    session.record_sandbox_cleanup(success=True)

    assert session.sandbox_cleanup_success == 1
    metrics = AuditMetrics.calculate_from_session(session)
    assert metrics.sandbox_cleanup_success == 1


def test_failed_cleanup_does_not_increment_count():
    """Verify failed cleanup leaves cleanup count at 0."""
    target = Target(
        base_url="http://127.0.0.1:9123",
        is_sandboxed=True,
        sandbox_deployment_success=True
    )
    session = AuditSession(target=target)
    session.record_sandbox_cleanup(success=False)

    assert session.sandbox_cleanup_success == 0
    metrics = AuditMetrics.calculate_from_session(session)
    assert metrics.sandbox_cleanup_success == 0


def test_docker_project_sandbox_lifecycle_mocked():
    """Test DockerProjectSandbox lifecycle sets flags accurately on build success and failure."""
    project_info = ProjectInfo(
        project_path="sample_projects/python_api",
        project_type=ProjectType.PYTHON,
        detected_port=8000,
        description="Python FastAPI Sample"
    )

    sandbox = DockerProjectSandbox(project_info=project_info)
    assert sandbox.deployment_succeeded is False
    assert sandbox.cleanup_succeeded is False
    assert sandbox.target.is_sandboxed is True
    assert sandbox.target.sandbox_deployment_success is False

    # Simulate successful container run & readiness
    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "mock_container_12345"
    mock_docker.containers.run.return_value = mock_container
    mock_docker.containers.get.return_value = mock_container
    sandbox.docker_client = mock_docker

    with patch.object(sandbox, "_prepare_build_context"), \
         patch.object(sandbox, "wait_until_ready", return_value=True):
        mock_docker.images.build.return_value = (MagicMock(), [])
        mock_docker.networks.get.return_value = MagicMock()

        target = sandbox.build_and_start()
        assert sandbox.deployment_succeeded is True
        assert target.sandbox_deployment_success is True

    # Test cleanup
    cleaned = sandbox.cleanup()
    assert cleaned is True
    assert sandbox.cleanup_succeeded is True
    assert target.sandbox_cleanup_success is True
    mock_container.stop.assert_called_once()
    mock_container.remove.assert_called_once()


def test_docker_project_sandbox_failed_deployment_mocked():
    """Test DockerProjectSandbox build failure does not mark deployment as succeeded."""
    project_info = ProjectInfo(
        project_path="sample_projects/python_api",
        project_type=ProjectType.PYTHON,
        detected_port=8000,
        description="Python FastAPI Sample"
    )

    sandbox = DockerProjectSandbox(project_info=project_info)
    mock_docker = MagicMock()
    mock_docker.images.build.side_effect = Exception("Docker daemon error")
    sandbox.docker_client = mock_docker

    with patch.object(sandbox, "_prepare_build_context"):
        with pytest.raises(DockerSandboxError):
            sandbox.build_and_start()

    assert sandbox.deployment_succeeded is False
    assert sandbox.target.sandbox_deployment_success is False
    assert sandbox.cleanup_succeeded is False


def test_target_runner_docker_lifecycle_mocked():
    """Verify TargetRunner with use_docker=True tracks deployment and cleanup."""
    runner = TargetRunner(port=8088, use_docker=True)
    assert runner.is_sandboxed is True
    assert runner.deployment_succeeded is False
    assert runner.cleanup_succeeded is False

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "mock_runner_container_999"
    mock_docker.containers.run.return_value = mock_container
    mock_docker.containers.get.return_value = mock_container

    with patch.object(runner, "_is_docker_available", return_value=True), \
         patch("docker.from_env", return_value=mock_docker), \
         patch.object(runner, "wait_until_healthy", return_value=True):
        target = runner.start()
        assert runner.deployment_succeeded is True
        assert target.is_sandboxed is True
        assert target.sandbox_deployment_success is True

    cleaned = runner.stop()
    assert cleaned is True
    assert runner.cleanup_succeeded is True
    assert target.sandbox_cleanup_success is True


def test_no_fabrication_from_project_type_matrix():
    """Verify that project_type alone never fabricates sandbox deployments or cleanups."""
    for ptype in ["PYTHON", "SPRING_BOOT_MAVEN", "SPRING_BOOT_GRADLE", "NODE_JS", "BENCHMARK"]:
        target = Target(base_url="http://127.0.0.1:8088", is_sandboxed=False)
        session = AuditSession(target=target)
        metrics = AuditMetrics.calculate_from_session(session, project_type=ptype)
        assert metrics.sandbox_deployments == 0, f"Fabricated deployment for {ptype}"
        assert metrics.sandbox_cleanup_success == 0, f"Fabricated cleanup for {ptype}"



def test_aggregate_metrics_accumulates_sandbox_metrics_across_runs(tmp_path):
    """Verify aggregate metrics accurately accumulates sandbox deployments and cleanups across multiple runs."""
    store = EvidenceStore(export_dir=str(tmp_path))

    # Run 1: Sandboxed target deployed and cleaned up
    t1 = Target(base_url="http://127.0.0.1:9001", is_sandboxed=True, sandbox_deployment_success=True)
    s1 = AuditSession(target=t1)
    s1.record_sandbox_cleanup(True)
    store.save_audit_dossier(s1, project_type="PYTHON")

    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 1
    assert agg.total_sandbox_deployments == 1
    assert agg.total_successful_sandbox_cleanups == 1

    # Run 2: Another sandboxed target deployed and cleaned up
    t2 = Target(base_url="http://127.0.0.1:9002", is_sandboxed=True, sandbox_deployment_success=True)
    s2 = AuditSession(target=t2)
    s2.record_sandbox_cleanup(True)
    store.save_audit_dossier(s2, project_type="SPRING_BOOT_MAVEN")

    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 2
    assert agg.total_sandbox_deployments == 2
    assert agg.total_successful_sandbox_cleanups == 2

    # Run 3: Non-sandboxed benchmark target (no sandbox deployment, no cleanup)
    t3 = Target(base_url="http://127.0.0.1:8088", is_sandboxed=False)
    s3 = AuditSession(target=t3)
    store.save_audit_dossier(s3, project_type="BENCHMARK")

    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 3
    assert agg.total_sandbox_deployments == 2
    assert agg.total_successful_sandbox_cleanups == 2


def test_aggregate_metrics_strictly_idempotent_on_rerun(tmp_path):
    """Verify aggregate metrics remain strictly idempotent when re-saving or re-running."""
    store = EvidenceStore(export_dir=str(tmp_path))

    t1 = Target(base_url="http://127.0.0.1:9001", is_sandboxed=True, sandbox_deployment_success=True)
    s1 = AuditSession(target=t1)
    s1.step_count = 5

    # 1. Initial save prior to cleanup (e.g. report generation)
    store.save_audit_dossier(s1, project_type="PYTHON")
    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 1
    assert agg.total_sandbox_deployments == 1
    assert agg.total_successful_sandbox_cleanups == 0

    # 2. Re-save identical session before cleanup: must NOT double count
    store.save_audit_dossier(s1, project_type="PYTHON")
    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 1
    assert agg.total_sandbox_deployments == 1
    assert agg.total_successful_sandbox_cleanups == 0

    # 3. Post-cleanup save: sandbox cleanup recorded
    s1.record_sandbox_cleanup(True)
    store.save_audit_dossier(s1, project_type="PYTHON")
    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 1
    assert agg.total_sandbox_deployments == 1
    assert agg.total_successful_sandbox_cleanups == 1

    # 4. Re-save post-cleanup: must remain strictly idempotent
    store.save_audit_dossier(s1, project_type="PYTHON")
    agg = store.get_aggregate_metrics()
    assert agg.total_audits == 1
    assert agg.total_sandbox_deployments == 1
    assert agg.total_successful_sandbox_cleanups == 1
