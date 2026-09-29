import os
import sys
import time
import socket
import logging
import subprocess
from typing import Optional
import httpx
from app.models.target import Target

logger = logging.getLogger("stressx.target.runner")


def find_free_port(start_port: int = 8088) -> int:
    for port in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


class TargetRunner:
    """Manages the lifecycle of the controlled vulnerable test target.
    
    Supports Docker container deployment with resource limits (CPU/Memory/Network isolation)
    and graceful fallback to managed isolated subprocess execution.
    """

    def __init__(
        self,
        port: Optional[int] = None,
        use_docker: bool = False,
        cpu_limit: float = 1.0,
        memory_limit_mb: int = 512,
        network_name: str = "stressx-isolated-net"
    ):
        self.port = port or find_free_port(8088)
        self.use_docker = use_docker
        self.is_sandboxed = use_docker
        self.cpu_limit = cpu_limit
        self.memory_limit = memory_limit_mb
        self.network_name = network_name
        self.container_id: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None
        self.deployment_succeeded: bool = False
        self.cleanup_succeeded: bool = False
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.target = Target(
            base_url=self.base_url,
            allowed_hosts=["127.0.0.1", "localhost"],
            allowed_ports=[self.port],
            name="StressX Vulnerable Benchmark Target",
            is_sandboxed=self.use_docker
        )

    def start(self) -> Target:
        """Starts the vulnerable target and verifies health."""
        if self.use_docker and self._is_docker_available():
            self._start_docker()
            self.target.is_sandboxed = True
        else:
            self._start_subprocess()

        if not self.wait_until_healthy(timeout=10.0):
            self.stop()
            raise RuntimeError(f"Target failed to become healthy at {self.base_url} within 10s.")

        if self.use_docker and self.container_id:
            self.deployment_succeeded = True
            self.target.sandbox_deployment_success = True

        logger.info(f"Target application active and bounded at {self.base_url}")
        return self.target

    def _is_docker_available(self) -> bool:
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False

    def _start_docker(self) -> None:
        """Runs the target inside Docker with strict CPU and Memory boundaries."""
        import docker
        client = docker.from_env()
        
        # Ensure isolated network exists
        try:
            client.networks.get(self.network_name)
        except Exception:
            client.networks.create(self.network_name, driver="bridge")

        image_tag = "stressx-vulnerable-target:latest"
        logger.info(f"Launching Docker container for target on port {self.port} with CPU={self.cpu_limit} Mem={self.memory_limit}MB")
        container = client.containers.run(
            image=image_tag,
            detach=True,
            ports={"8000/tcp": ("127.0.0.1", self.port)},
            nano_cpus=int(self.cpu_limit * 1e9),
            mem_limit=f"{self.memory_limit}m",
            network=self.network_name,
            remove=True
        )
        self.container_id = container.id

    def _start_subprocess(self) -> None:
        """Runs target locally via uvicorn in an isolated process with controlled port."""
        logger.info(f"Starting target as managed local process on 127.0.0.1:{self.port}")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "app.target.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "warning"
        ]
        
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )

    def wait_until_healthy(self, timeout: float = 10.0) -> bool:
        """Polls health endpoint until active or timeout."""
        start_time = time.time()
        health_url = f"{self.base_url}/health"
        
        while time.time() - start_time < timeout:
            try:
                with httpx.Client(timeout=1.0) as client:
                    resp = client.get(health_url)
                    if resp.status_code == 200:
                        return True
            except Exception:
                time.sleep(0.2)
        return False

    def stop(self) -> bool:
        """Cleans up the container or process environment. Returns True if sandbox container was cleanly stopped."""
        container_cleaned = False
        if self.container_id:
            try:
                import docker
                client = docker.from_env()
                container = client.containers.get(self.container_id)
                container.stop(timeout=2)
                logger.info(f"Stopped and removed Docker container {self.container_id}")
                container_cleaned = True
            except Exception as e:
                logger.warning(f"Error stopping container: {e}")
                try:
                    import docker
                    client = docker.from_env()
                    client.containers.get(self.container_id)
                except Exception:
                    container_cleaned = True
            self.container_id = None

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                self.process.kill()
            logger.info("Terminated target subprocess.")
            self.process = None

        if container_cleaned:
            self.cleanup_succeeded = True
            self.target.sandbox_cleanup_success = True
            return True
        return False
