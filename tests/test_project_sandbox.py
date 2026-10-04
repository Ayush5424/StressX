import os
import shutil
import tempfile
from pathlib import Path
import pytest
import httpx

from app.target.detector import ProjectDetector, ProjectInfo, ProjectType, ProjectDetectionError
from app.target.sandbox import DockerProjectSandbox, DockerSandboxError
from app.models.target import TargetBoundaryViolation


def test_folder_validation(tmp_path):
    # 1. Empty string
    with pytest.raises(ProjectDetectionError) as exc:
        ProjectDetector.validate_folder("")
    assert "cannot be empty" in str(exc.value)

    # 2. Non-existent path
    non_existent = tmp_path / "does_not_exist"
    with pytest.raises(ProjectDetectionError) as exc:
        ProjectDetector.validate_folder(str(non_existent))
    assert "does not exist" in str(exc.value)

    # 3. Path is a file, not a directory
    file_path = tmp_path / "regular_file.txt"
    file_path.write_text("hello", encoding="utf-8")
    with pytest.raises(ProjectDetectionError) as exc:
        ProjectDetector.validate_folder(str(file_path))
    assert "not a directory" in str(exc.value)

    # 4. Empty directory
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    with pytest.raises(ProjectDetectionError) as exc:
        ProjectDetector.validate_folder(str(empty_dir))
    assert "directory is empty" in str(exc.value)

    # 5. Valid directory with files
    non_empty = tmp_path / "valid_project"
    non_empty.mkdir()
    (non_empty / "app.py").write_text("print('test')", encoding="utf-8")
    validated = ProjectDetector.validate_folder(str(non_empty))
    assert validated.resolve() == non_empty.resolve()


def test_project_type_detection_spring_boot_maven(tmp_path):
    project_dir = tmp_path / "spring_maven"
    project_dir.mkdir()
    (project_dir / "pom.xml").write_text("<project><dependencies><dependency><groupId>org.springframework.boot</groupId></dependency></dependencies></project>", encoding="utf-8")
    
    # application.properties with custom port
    res_dir = project_dir / "src" / "main" / "resources"
    res_dir.mkdir(parents=True)
    (res_dir / "application.properties").write_text("server.port=8082\nspring.application.name=demo", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    assert info.project_type == ProjectType.SPRING_BOOT_MAVEN
    assert info.detected_port == 8082
    assert info.build_file == "pom.xml"


def test_project_type_detection_spring_boot_gradle(tmp_path):
    project_dir = tmp_path / "spring_gradle"
    project_dir.mkdir()
    (project_dir / "build.gradle").write_text("plugins { id 'org.springframework.boot' version '3.2.0' }", encoding="utf-8")

    res_dir = project_dir / "src" / "main" / "resources"
    res_dir.mkdir(parents=True)
    (res_dir / "application.yml").write_text("server:\n  port: 8090", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    assert info.project_type == ProjectType.SPRING_BOOT_GRADLE
    assert info.detected_port == 8090
    assert info.build_file == "build.gradle"


def test_project_type_detection_node_js(tmp_path):
    project_dir = tmp_path / "node_app"
    project_dir.mkdir()
    (project_dir / "package.json").write_text('{"name": "test-app", "scripts": {"start": "node server.js"}}', encoding="utf-8")
    (project_dir / "server.js").write_text("const app = express(); app.listen(4000);", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    assert info.project_type == ProjectType.NODE_JS
    assert info.detected_port == 4000
    assert info.entrypoint_hint == "server.js"


def test_project_type_detection_python(tmp_path):
    project_dir = tmp_path / "python_app"
    project_dir.mkdir()
    (project_dir / "requirements.txt").write_text("fastapi>=0.100\nuvicorn", encoding="utf-8")
    (project_dir / "app.py").write_text("import uvicorn\nuvicorn.run(port=8005)", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    assert info.project_type == ProjectType.PYTHON
    assert info.detected_port == 8005
    assert info.entrypoint_hint == "app.py"


def test_sample_project_folder_detection():
    # Test path in stressx-ai
    sample_dir = Path(__file__).resolve().parent.parent / "sample_projects" / "python_api"
    assert sample_dir.exists(), f"Sample project directory must exist at {sample_dir}"
    info = ProjectDetector.detect(sample_dir)
    assert info.project_type == ProjectType.PYTHON
    assert info.detected_port == 8000
    assert info.entrypoint_hint == "app.py"


@pytest.mark.asyncio
async def test_sample_project_endpoints():
    import sys
    sample_dir = Path(__file__).resolve().parent.parent / "sample_projects" / "python_api"
    sys.path.insert(0, str(sample_dir))
    from sample_projects.python_api.app import app as sample_app
    from httpx import ASGITransport

    transport = ASGITransport(app=sample_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health
        h = await client.get("/health")
        assert h.status_code == 200
        assert h.json()["status"] == "healthy"

        # 2. Debug config
        d = await client.get("/api/debug/config")
        assert d.status_code == 200
        assert "DATABASE_URL" in d.json()

        # 3. Auth login
        l = await client.post("/api/auth/login", json={"username": "alice", "password": "password123"})
        assert l.status_code == 200
        token = l.json()["token"]

        # 4. IDOR user profile
        u = await client.get("/api/users/user_102", headers={"Authorization": f"Bearer {token}"})
        assert u.status_code == 200
        assert u.json()["username"] == "bob"

        # 5. SQL injection search
        s_err = await client.get("/api/search?q='")
        assert s_err.status_code == 500
        s_ok = await client.get("/api/search?q=' OR 1=1 --")
        assert s_ok.status_code == 200
        assert s_ok.json()["count"] == 3

        # 6. Admin config privilege escalation
        a_denied = await client.get("/api/admin/config")
        assert a_denied.status_code == 403
        a_ok = await client.get("/api/admin/config", headers={"X-Original-Role": "admin"})
        assert a_ok.status_code == 200


def test_project_type_detection_unknown(tmp_path):
    project_dir = tmp_path / "unknown_app"
    project_dir.mkdir()
    (project_dir / "README.md").write_text("Just documentation", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    assert info.project_type == ProjectType.UNKNOWN


def test_sandbox_configuration_and_dockerfile_generation(tmp_path):
    project_dir = tmp_path / "python_proj"
    project_dir.mkdir()
    (project_dir / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (project_dir / "main.py").write_text("print('hello')", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    sandbox = DockerProjectSandbox(
        project_info=info,
        target_port=8000,
        cpu_limit=1.0,
        memory_limit_mb=512,
        network_name="test-net"
    )

    assert sandbox.cpu_limit == 1.0
    assert sandbox.memory_limit_mb == 512
    assert sandbox.container_port == 8000
    assert sandbox.network_name == "test-net"

    # Test Dockerfile generation
    dockerfile = sandbox._generate_dockerfile()
    assert "FROM python:3.13-slim" in dockerfile
    assert "EXPOSE 8000" in dockerfile
    assert "CMD [\"python\", \"main.py\"]" in dockerfile


def test_sandbox_target_boundary_enforcement(tmp_path):
    project_dir = tmp_path / "bounded_app"
    project_dir.mkdir()
    (project_dir / "app.py").write_text("print('test')", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    sandbox = DockerProjectSandbox(project_info=info, target_port=8080)
    target = sandbox.target

    # Permitted local requests on mapped port
    assert target.is_url_allowed(f"http://127.0.0.1:{sandbox.host_port}/api")
    assert target.is_url_allowed(f"http://localhost:{sandbox.host_port}/health")

    # Rejected requests to other ports or external hosts
    assert not target.is_url_allowed("http://127.0.0.1:22/ssh")
    assert not target.is_url_allowed("https://external-bank.com")
    
    with pytest.raises(TargetBoundaryViolation):
        target.resolve_url("http://malicious-external-host.com/exploit")


def test_sandbox_cleanup_on_failure(tmp_path):
    project_dir = tmp_path / "cleanup_test"
    project_dir.mkdir()
    (project_dir / "app.py").write_text("print('clean')", encoding="utf-8")

    info = ProjectDetector.detect(project_dir)
    sandbox = DockerProjectSandbox(project_info=info)

    # Simulate temporary build dir creation
    sandbox.temp_build_dir = Path(tempfile.mkdtemp(prefix="stressx_test_clean_"))
    assert sandbox.temp_build_dir.exists()

    # Call cleanup
    sandbox.cleanup()
    assert sandbox.temp_build_dir is None
