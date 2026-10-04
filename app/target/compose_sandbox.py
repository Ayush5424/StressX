import os
import shutil
import tempfile
import time
import uuid
import logging
import subprocess
from pathlib import Path
from typing import Optional, Any
import httpx
import yaml

from app.models.target import Target
from app.target.detector import ProjectInfo, ProjectType, ProjectDetectionError
from app.target.runner import find_free_port

logger = logging.getLogger("stressx.target.compose_sandbox")


class ComposeSandboxError(Exception):
    """Raised when multi-service Docker Compose build, startup, readiness, or teardown fails."""
    pass


class ComposeProjectSandbox:
    """Orchestrates an isolated, resource-bounded multi-service Docker Compose sandbox."""

    def __init__(
        self,
        project_info: ProjectInfo,
        target_service: Optional[str] = None,
        target_port: Optional[int] = None,
        cpu_limit: float = 1.0,
        memory_limit_mb: int = 1024,
        startup_timeout_seconds: float = 90.0,
        isolated_network: Optional[str] = None
    ):
        self.project_info = project_info
        self.cpu_limit = cpu_limit
        self.memory_limit_mb = memory_limit_mb
        self.startup_timeout = startup_timeout_seconds

        self.session_id = uuid.uuid4().hex[:8]
        self.project_name = f"stressx_cmp_{self.session_id}"
        self.network_name = isolated_network or f"stressx_net_{self.session_id}"

        # Resolve primary service and port
        self.primary_service = target_service or project_info.primary_service or (
            project_info.services[0] if project_info.services else "app"
        )
        self.container_port = target_port or project_info.detected_port or 8080
        self.host_port = find_free_port(9200)

        self.temp_dir: Optional[Path] = None
        self.scratch_compose_file: Optional[Path] = None
        self.deployment_succeeded: bool = False
        self.cleanup_succeeded: bool = False
        self.deployment_duration: float = 0.0

        self.base_url = f"http://127.0.0.1:{self.host_port}"
        self.target = Target(
            base_url=self.base_url,
            allowed_hosts=["127.0.0.1", "localhost"],
            allowed_ports=[self.host_port],
            name=f"Compose Stack: {self.project_info.description}",
            is_sandboxed=True,
            is_multi_service=True,
            primary_service=self.primary_service,
            services=list(self.project_info.services)
        )

    def _check_docker_compose_cli(self) -> None:
        """Verifies that docker and docker compose are operational."""
        try:
            res = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            if res.returncode != 0:
                raise ComposeSandboxError(f"Docker Compose CLI check failed: {res.stderr.strip()}")
        except FileNotFoundError as e:
            raise ComposeSandboxError(
                "Docker / Docker Compose CLI is not installed or not available in PATH. "
                "Please verify Docker Desktop is running."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise ComposeSandboxError("Docker Compose CLI check timed out.") from e

    def build_and_start(self) -> Target:
        """Copies project into isolated scratch directory, sanitizes compose file, and launches stack."""
        if self.project_info.project_type != ProjectType.DOCKER_COMPOSE:
            raise ComposeSandboxError(
                f"Cannot launch compose sandbox: Project type is {self.project_info.project_type}, "
                "expected DOCKER_COMPOSE."
            )

        if not self.project_info.compose_file:
            raise ComposeSandboxError("ProjectInfo does not define a compose_file.")

        self._check_docker_compose_cli()
        start_time = time.time()
        logger.info(f"Preparing isolated Docker Compose scratch environment for '{self.project_name}'...")

        # 1. Create temporary scratch directory and copy source (protects user's original directory)
        self.temp_dir = Path(tempfile.mkdtemp(prefix="stressx_cmp_"))
        self._prepare_scratch_workspace()

        # 2. Modify and sanitize Docker Compose configuration
        self._sanitize_and_write_compose_file()

        # 3. Launch Docker Compose stack
        logger.info(
            f"Launching Docker Compose stack '{self.project_name}' (Target: {self.primary_service} "
            f"on 127.0.0.1:{self.host_port}->{self.container_port})..."
        )
        cmd = [
            "docker", "compose",
            "-p", self.project_name,
            "-f", str(self.scratch_compose_file),
            "up", "-d", "--build"
        ]
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.temp_dir),
                capture_output=True,
                text=True,
                check=False,
                timeout=180
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() or proc.stdout.strip()
                self.cleanup()
                raise ComposeSandboxError(f"Docker Compose failed to start stack '{self.project_name}': {err}")
        except subprocess.TimeoutExpired as te:
            self.cleanup()
            raise ComposeSandboxError(f"Docker Compose startup timed out after 180s: {te}") from te

        # 4. Wait for readiness of the primary target application
        logger.info(f"Waiting for target service '{self.primary_service}' readiness at {self.base_url} (timeout: {self.startup_timeout}s)...")
        if not self.wait_until_ready():
            logs = self.get_service_logs(tail=150)
            self.cleanup()
            raise ComposeSandboxError(
                f"Primary service '{self.primary_service}' failed to become ready at {self.base_url} "
                f"within {self.startup_timeout}s.\nService Logs:\n{logs[-2000:]}"
            )

        # 5. Mark verified deployment success
        self.deployment_duration = round(max(time.time() - start_time, 0.1), 2)
        self.deployment_succeeded = True
        self.target.sandbox_deployment_success = True
        self.target.deployment_duration = self.deployment_duration

        logger.info(f"[+] Multi-service Docker Compose stack verified ready at {self.base_url} in {self.deployment_duration}s")
        return self.target

    def _prepare_scratch_workspace(self) -> None:
        """Deep copies user project files to scratch directory excluding heavy/sensitive folders."""
        src_path = Path(self.project_info.project_path)

        def ignore_patterns(folder, contents):
            ignored = set()
            for c in contents:
                if c in (".git", "node_modules", "target", "build", ".gradle", "__pycache__", ".venv", "venv", ".pytest_cache"):
                    ignored.add(c)
            return ignored

        shutil.copytree(src_path, self.temp_dir, ignore=ignore_patterns, dirs_exist_ok=True)
        self.scratch_compose_file = self.temp_dir / self.project_info.compose_file

    def _sanitize_and_write_compose_file(self) -> None:
        """Modifies Compose file to enforce isolation, single 127.0.0.1 port exposure, and resource limits."""
        if not self.scratch_compose_file or not self.scratch_compose_file.exists():
            raise ComposeSandboxError(f"Scratch compose file not found: {self.scratch_compose_file}")

        try:
            with open(self.scratch_compose_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise ComposeSandboxError(f"Error parsing scratch compose YAML: {e}") from e

        if not isinstance(data, dict) or "services" not in data or not isinstance(data["services"], dict):
            raise ComposeSandboxError("Invalid Docker Compose structure: 'services' dictionary is required.")

        services = data["services"]
        if self.primary_service not in services:
            # Fall back to first service if named primary service was not found
            self.primary_service = next(iter(services.keys()))
            self.target.primary_service = self.primary_service

        # 1. Enforce dedicated network
        custom_net_key = "stressx_isolated_net"
        if "networks" not in data or not isinstance(data["networks"], dict):
            data["networks"] = {}
        data["networks"][custom_net_key] = {
            "name": self.network_name,
            "driver": "bridge"
        }

        # 2. Iterate each service to enforce security and port rules
        for sname, sspec in services.items():
            if not isinstance(sspec, dict):
                continue

            # Attach dedicated network
            sspec["networks"] = [custom_net_key]

            # Enforce CPU & Memory limits
            if "deploy" not in sspec:
                sspec["deploy"] = {}
            if "resources" not in sspec["deploy"]:
                sspec["deploy"]["resources"] = {}
            if "limits" not in sspec["deploy"]["resources"]:
                sspec["deploy"]["resources"]["limits"] = {
                    "cpus": str(self.cpu_limit),
                    "memory": f"{self.memory_limit_mb}m"
                }

            # Sanitize host volume mounts: strip sensitive/dangerous host mounts (e.g. docker.sock)
            if "volumes" in sspec and isinstance(sspec["volumes"], list):
                sanitized_vols = []
                for v in sspec["volumes"]:
                    v_str = str(v)
                    # Disallow host docker daemon socket mounting
                    if "docker.sock" in v_str:
                        logger.warning(f"Stripped dangerous host volume mount from service '{sname}': {v_str}")
                        continue
                    sanitized_vols.append(v)
                sspec["volumes"] = sanitized_vols

            # 3. Port exposure isolation:
            # Primary service gets ONLY 127.0.0.1 host binding
            if sname == self.primary_service:
                sspec["ports"] = [f"127.0.0.1:{self.host_port}:{self.container_port}"]
            else:
                # Internal services (Postgres, Redis, DBs, etc.):
                # STRIP all external host port bindings to ensure they are never exposed to the host machine!
                existing_ports = sspec.pop("ports", None)
                if existing_ports:
                    # Retain internal container port reachability for sibling services via 'expose'
                    if "expose" not in sspec:
                        sspec["expose"] = []
                    for p in (existing_ports if isinstance(existing_ports, list) else [existing_ports]):
                        # Extract container-side port
                        parts = str(p).split(":")
                        c_port = parts[-1].split("/")[0]
                        if c_port.isdigit():
                            sspec["expose"].append(int(c_port))

        with open(self.scratch_compose_file, "w", encoding="utf-8") as f:
            yaml.dump(data, f, sort_keys=False)

    def wait_until_ready(self) -> bool:
        """Polls common HTTP routes on 127.0.0.1 until the application responds."""
        start_time = time.time()
        probes = ["/", "/health", "/api", "/actuator/health", "/api/v1/health", "/ping"]

        with httpx.Client(timeout=2.0) as client:
            while time.time() - start_time < self.startup_timeout:
                # Check if services exited prematurely
                status = self.get_service_status()
                prim_status = status.get(self.primary_service, "").lower()
                if "exited" in prim_status or "dead" in prim_status:
                    logger.error(f"Primary service '{self.primary_service}' exited unexpectedly ({prim_status}).")
                    return False

                for path in probes:
                    url = f"{self.base_url}{path}"
                    try:
                        resp = client.get(url, follow_redirects=False)
                        if resp.status_code in (200, 201, 301, 302, 401, 403, 404, 405):
                            return True
                    except Exception:
                        continue
                time.sleep(1.0)
        return False

    def get_service_status(self) -> dict[str, str]:
        """Queries Docker Compose ps to inspect container statuses."""
        if not self.scratch_compose_file or not self.scratch_compose_file.exists():
            return {}
        try:
            cmd = [
                "docker", "compose",
                "-p", self.project_name,
                "-f", str(self.scratch_compose_file),
                "ps", "--format", "{{.Service}}:{{.State}}"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
            status_map = {}
            if res.returncode == 0:
                for line in res.stdout.strip().split("\n"):
                    if ":" in line:
                        sname, sstate = line.split(":", 1)
                        status_map[sname.strip()] = sstate.strip()
            return status_map
        except Exception:
            return {}

    def get_service_logs(self, tail: int = 100) -> str:
        """Collects combined logs from all services in the stack for debugging."""
        if not self.scratch_compose_file or not self.scratch_compose_file.exists():
            return "[No compose scratch file available for logs]"
        try:
            cmd = [
                "docker", "compose",
                "-p", self.project_name,
                "-f", str(self.scratch_compose_file),
                "logs", "--tail", str(tail)
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
            return res.stdout or res.stderr or "[No logs available]"
        except Exception as e:
            return f"[Failed to retrieve compose logs: {e}]"

    def cleanup(self) -> bool:
        """Guarantees complete removal of containers, volumes, networks, and scratch workspace."""
        logger.info(f"Tearing down Docker Compose sandbox '{self.project_name}'...")
        stack_cleaned = False

        if self.scratch_compose_file and self.scratch_compose_file.exists():
            try:
                cmd = [
                    "docker", "compose",
                    "-p", self.project_name,
                    "-f", str(self.scratch_compose_file),
                    "down", "--volumes", "--remove-orphans"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
                if res.returncode == 0:
                    stack_cleaned = True
                    logger.info(f"Docker Compose stack '{self.project_name}' destroyed.")
                else:
                    logger.warning(f"Warning during compose down: {res.stderr.strip()}")
                    # Verify if containers are still running
                    status = self.get_service_status()
                    if not status:
                        stack_cleaned = True
            except Exception as e:
                logger.warning(f"Error executing docker compose down: {e}")

        # Purge temporary scratch workspace
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.info("Scratch compose workspace purged.")
            except Exception:
                pass
            self.temp_dir = None

        if stack_cleaned:
            self.cleanup_succeeded = True
            self.target.sandbox_cleanup_success = True
            return True
        return False
