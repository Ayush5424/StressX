import os
import shutil
import tempfile
import time
import uuid
import logging
from pathlib import Path
from typing import Optional
import httpx
from app.models.target import Target
from app.target.detector import ProjectInfo, ProjectType, ProjectDetectionError
from app.target.runner import find_free_port

logger = logging.getLogger("stressx.target.sandbox")


class DockerSandboxError(Exception):
    """Raised when container sandbox build, startup, or health checking fails."""
    pass


class DockerProjectSandbox:
    """Orchestrates an isolated, resource-bounded Docker sandbox for arbitrary user projects."""

    def __init__(
        self,
        project_info: ProjectInfo,
        target_port: Optional[int] = None,
        cpu_limit: float = 1.0,
        memory_limit_mb: int = 1024,
        startup_timeout_seconds: float = 90.0,
        network_name: str = "stressx-sandbox-net"
    ):
        self.project_info = project_info
        self.container_port = target_port or project_info.detected_port or 8080
        self.host_port = find_free_port(9000)
        self.cpu_limit = cpu_limit
        self.memory_limit_mb = memory_limit_mb
        self.startup_timeout = startup_timeout_seconds
        self.network_name = network_name

        self.session_id = uuid.uuid4().hex[:8]
        self.image_tag = f"stressx-target-{self.session_id}:latest"
        self.container_name = f"stressx-box-{self.session_id}"
        self.temp_build_dir: Optional[Path] = None
        self.container_id: Optional[str] = None
        self.docker_client = None

        self.deployment_succeeded = False
        self.cleanup_succeeded = False
        self.base_url = f"http://127.0.0.1:{self.host_port}"
        self.target = Target(
            base_url=self.base_url,
            allowed_hosts=["127.0.0.1", "localhost"],
            allowed_ports=[self.host_port],
            name=f"Sandboxed: {self.project_info.description}",
            is_sandboxed=True
        )

    def _get_docker(self):
        if self.docker_client is None:
            try:
                import docker
                client = docker.from_env()
                client.ping()
                self.docker_client = client
            except Exception as e:
                raise DockerSandboxError(
                    f"Docker is required to safely sandbox user projects without host execution: {e}. "
                    "Please ensure Docker Desktop / Docker Engine is running."
                ) from e
        return self.docker_client

    def build_and_start(self) -> Target:
        """Copies project into a scratch build context, builds image, and launches container."""
        if self.project_info.project_type == ProjectType.UNKNOWN:
            raise DockerSandboxError(
                f"Cannot sandbox project: Unrecognized or unsupported project type in {self.project_info.project_path}"
            )

        client = self._get_docker()
        logger.info(f"Preparing Docker build context for {self.project_info.description}...")

        # 1. Create temporary isolated build context (avoid touching user directory)
        self.temp_build_dir = Path(tempfile.mkdtemp(prefix="stressx_build_"))
        self._prepare_build_context()

        # 2. Build Docker Image
        logger.info(f"Building Docker container image '{self.image_tag}'...")
        try:
            image, build_logs = client.images.build(
                path=str(self.temp_build_dir),
                tag=self.image_tag,
                rm=True,
                forcerm=True
            )
        except Exception as e:
            self.cleanup()
            raise DockerSandboxError(f"Failed to build project Docker image: {e}") from e

        # 3. Ensure isolated Docker network exists
        try:
            client.networks.get(self.network_name)
        except Exception:
            client.networks.create(self.network_name, driver="bridge")

        # 4. Launch Container with strict resource limits
        logger.info(
            f"Launching container '{self.container_name}' with CPU={self.cpu_limit}, "
            f"Memory={self.memory_limit_mb}MB, Port {self.container_port}->{self.host_port}..."
        )
        try:
            container = client.containers.run(
                image=self.image_tag,
                name=self.container_name,
                detach=True,
                ports={f"{self.container_port}/tcp": ("127.0.0.1", self.host_port)},
                nano_cpus=int(self.cpu_limit * 1e9),
                mem_limit=f"{self.memory_limit_mb}m",
                network=self.network_name,
                restart_policy={"Name": "no"}
            )
            self.container_id = container.id
        except Exception as e:
            self.cleanup()
            raise DockerSandboxError(f"Failed to start Docker container: {e}") from e

        # 5. Wait for readiness
        logger.info(f"Waiting for target application readiness at {self.base_url} (timeout: {self.startup_timeout}s)...")
        if not self.wait_until_ready():
            logs = self._get_container_logs()
            self.cleanup()
            raise DockerSandboxError(
                f"Target application failed to become responsive at {self.base_url} within {self.startup_timeout}s.\n"
                f"Container logs:\n{logs[-1000:]}"
            )

        self.deployment_succeeded = True
        self.target.sandbox_deployment_success = True
        logger.info(f"[+] Target application verified ready and bounded at {self.base_url}")
        return self.target

    def _prepare_build_context(self) -> None:
        """Copies project files and ensures an appropriate Dockerfile exists."""
        src_path = Path(self.project_info.project_path)
        dest_path = self.temp_build_dir / "src"

        # Copy files excluding giant or unnecessary folders
        def ignore_patterns(folder, contents):
            ignored = set()
            for c in contents:
                if c in (".git", "node_modules", "target", "build", ".gradle", "__pycache__", ".venv", "venv"):
                    ignored.add(c)
            return ignored

        shutil.copytree(src_path, dest_path, ignore=ignore_patterns, dirs_exist_ok=True)

        # Generate Dockerfile in build root
        dockerfile_path = self.temp_build_dir / "Dockerfile"
        existing_dockerfile = src_path / "Dockerfile"

        if existing_dockerfile.exists():
            # Use user's own Dockerfile if provided
            shutil.copy2(existing_dockerfile, dockerfile_path)
        else:
            dockerfile_content = self._generate_dockerfile()
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(dockerfile_content)

    def _generate_dockerfile(self) -> str:
        ptype = self.project_info.project_type
        port = self.container_port

        if ptype == ProjectType.SPRING_BOOT_MAVEN:
            return f"""FROM maven:3.9-eclipse-temurin-21-alpine AS builder
WORKDIR /build
COPY src/ /build/
RUN mvn clean package -DskipTests --batch-mode

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /build/target/*.jar /app/app.jar
EXPOSE {port}
CMD ["java", "-jar", "/app/app.jar"]
"""
        elif ptype == ProjectType.SPRING_BOOT_GRADLE:
            return f"""FROM gradle:8.5-jdk21-alpine AS builder
WORKDIR /build
COPY src/ /build/
RUN gradle bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /build/build/libs/*.jar /app/app.jar
EXPOSE {port}
CMD ["java", "-jar", "/app/app.jar"]
"""
        elif ptype == ProjectType.NODE_JS:
            entry = self.project_info.entrypoint_hint or "index.js"
            return f"""FROM node:20-alpine
WORKDIR /app
COPY src/package*.json ./
RUN npm install --production || npm install
COPY src/ ./
EXPOSE {port}
CMD ["npm", "start"]
"""
        elif ptype == ProjectType.PYTHON:
            entry = self.project_info.entrypoint_hint or "app.py"
            return f"""FROM python:3.13-slim
WORKDIR /app
COPY src/requirements.txt* ./
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
COPY src/ ./
EXPOSE {port}
CMD ["python", "{entry}"]
"""
        raise ValueError(f"No Dockerfile template for project type {ptype}")

    def wait_until_ready(self) -> bool:
        """Polls common HTTP routes until application responds."""
        start_time = time.time()
        probes = ["/", "/health", "/api", "/actuator/health", "/api/v1/health"]

        with httpx.Client(timeout=2.0) as client:
            while time.time() - start_time < self.startup_timeout:
                # Check if container died prematurely
                if self.container_id:
                    try:
                        container = self.docker_client.containers.get(self.container_id)
                        if container.status == "exited":
                            logger.error("Sandbox container stopped unexpectedly.")
                            return False
                    except Exception:
                        pass

                for path in probes:
                    url = f"{self.base_url}{path}"
                    try:
                        resp = client.get(url, follow_redirects=False)
                        # Any valid HTTP response indicates server socket is accepting connections
                        if resp.status_code in (200, 201, 301, 302, 401, 403, 404, 405):
                            return True
                    except Exception:
                        continue
                time.sleep(1.0)
        return False

    def _get_container_logs(self) -> str:
        if self.container_id and self.docker_client:
            try:
                container = self.docker_client.containers.get(self.container_id)
                return container.logs(tail=100).decode("utf-8", errors="ignore")
            except Exception:
                pass
        return "[No container logs available]"

    def cleanup(self) -> bool:
        """Guarantees complete removal of containers, images, and temporary build context."""
        logger.info("Cleaning up Docker sandbox environment...")
        container_cleaned = False

        if self.container_id and self.docker_client:
            try:
                container = self.docker_client.containers.get(self.container_id)
                container.stop(timeout=2)
                container.remove(force=True)
                logger.info(f"Container '{self.container_name}' removed.")
                container_cleaned = True
            except Exception as e:
                logger.warning(f"Error removing container: {e}")
                try:
                    self.docker_client.containers.get(self.container_id)
                except Exception:
                    container_cleaned = True
            self.container_id = None

        if self.image_tag and self.docker_client:
            try:
                self.docker_client.images.remove(image=self.image_tag, force=True)
                logger.info(f"Ephemeral image '{self.image_tag}' removed.")
            except Exception:
                pass

        if self.temp_build_dir and self.temp_build_dir.exists():
            try:
                shutil.rmtree(self.temp_build_dir, ignore_errors=True)
                logger.info("Temporary build context purged.")
            except Exception:
                pass
            self.temp_build_dir = None

        if container_cleaned:
            self.cleanup_succeeded = True
            self.target.sandbox_cleanup_success = True
            return True
        return False
