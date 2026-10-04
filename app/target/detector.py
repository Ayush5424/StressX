import os
import re
from enum import Enum
from pathlib import Path
from typing import Optional
import yaml
from pydantic import BaseModel, Field


class ProjectType(str, Enum):
    DOCKER_COMPOSE = "DOCKER_COMPOSE"
    SPRING_BOOT_MAVEN = "SPRING_BOOT_MAVEN"
    SPRING_BOOT_GRADLE = "SPRING_BOOT_GRADLE"
    NODE_JS = "NODE_JS"
    PYTHON = "PYTHON"
    DOCKERFILE = "DOCKERFILE"
    UNKNOWN = "UNKNOWN"


class ProjectInfo(BaseModel):
    project_path: str
    project_type: ProjectType
    detected_port: Optional[int] = None
    build_file: Optional[str] = None
    entrypoint_hint: Optional[str] = None
    description: str = ""
    compose_file: Optional[str] = None
    services: list[str] = Field(default_factory=list)
    primary_service: Optional[str] = None
    service_types: dict[str, str] = Field(default_factory=dict)
    is_multi_service: bool = False


class ProjectDetectionError(Exception):
    """Raised when project path or configuration cannot be validated or detected."""
    pass


class ProjectDetector:
    """Inspects a user-supplied project directory to determine runtime type and port."""

    INFRASTRUCTURE_PATTERNS = {
        "database": [
            "postgres", "postgresql", "pgsql", "mysql", "mariadb",
            "mongo", "mongodb", "cockroach", "cassandra", "couchdb", "sqlite"
        ],
        "cache": [
            "redis", "memcached", "valkey"
        ],
        "queue": [
            "rabbitmq", "kafka", "activemq", "nats", "sqs"
        ],
        "infra": [
            "elasticsearch", "opensearch", "solr", "zookeeper",
            "etcd", "consul", "vault", "localstack", "prometheus",
            "grafana", "jaeger", "minio", "mailhog", "smtp"
        ]
    }

    @classmethod
    def _find_compose_file(cls, root: Path) -> Optional[Path]:
        candidates = [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml"
        ]
        for name in candidates:
            target = root / name
            if target.exists() and target.is_file():
                # Ignore shell scripts masquerading as yaml
                try:
                    with open(target, "r", encoding="utf-8", errors="ignore") as f:
                        first_line = f.readline()
                        if first_line.startswith("#!"):
                            continue
                except Exception:
                    pass
                return target
        return None

    @classmethod
    def _classify_service(cls, name: str, spec: dict) -> str:
        name_lower = name.lower()
        image = str(spec.get("image", "") if isinstance(spec, dict) else "").lower()

        for category, patterns in cls.INFRASTRUCTURE_PATTERNS.items():
            for pat in patterns:
                if pat in name_lower or pat in image:
                    return category
        return "application"

    @classmethod
    def _extract_service_port(cls, spec: dict) -> Optional[int]:
        if not isinstance(spec, dict):
            return None
        ports = spec.get("ports", [])
        if isinstance(ports, list):
            for p in ports:
                if isinstance(p, (int, str)):
                    parts = str(p).split(":")
                    target = parts[-1].split("/")[0]
                    if target.isdigit():
                        return int(target)
                elif isinstance(p, dict):
                    target = p.get("target") or p.get("published")
                    if target and str(target).isdigit():
                        return int(target)
        expose = spec.get("expose", [])
        if isinstance(expose, list):
            for e in expose:
                if str(e).isdigit():
                    return int(e)
        return None

    @classmethod
    def _select_primary_service(
        cls,
        services: dict[str, dict],
        service_types: dict[str, str]
    ) -> tuple[Optional[str], Optional[int]]:
        """Selects the primary HTTP application service and its internal listening port."""
        app_candidates = [s for s, t in service_types.items() if t == "application"]

        if not app_candidates:
            for s, spec in services.items():
                port = cls._extract_service_port(spec)
                if port:
                    return s, port
            first = next(iter(services.keys())) if services else None
            return first, cls._extract_service_port(services[first]) if first and isinstance(services.get(first), dict) else None

        if len(app_candidates) == 1:
            primary = app_candidates[0]
            port = cls._extract_service_port(services.get(primary, {})) or 8080
            return primary, port

        def score(s: str) -> int:
            spec = services.get(s, {}) or {}
            pts = 0
            if "build" in spec:
                pts += 10
            s_low = s.lower()
            if s_low in ("app", "web", "api", "backend", "server"):
                pts += 8
            elif any(k in s_low for k in ("web", "api", "app", "server", "backend")):
                pts += 5
            port = cls._extract_service_port(spec)
            if port in (80, 8080, 8000, 3000, 5000, 4000, 8088, 9000):
                pts += 5
            elif port:
                pts += 2
            return pts

        sorted_candidates = sorted(app_candidates, key=score, reverse=True)
        primary = sorted_candidates[0]
        port = cls._extract_service_port(services.get(primary, {})) or 8080
        return primary, port

    @classmethod
    def _inspect_compose_project(cls, root: Path, compose_file: Path) -> ProjectInfo:
        content = cls._read_file_safe(compose_file)
        if not content.strip():
            raise ProjectDetectionError(f"Docker Compose file '{compose_file.name}' is empty.")

        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise ProjectDetectionError(f"Failed to parse Docker Compose file '{compose_file.name}': {e}") from e

        if not isinstance(data, dict):
            raise ProjectDetectionError(f"Invalid Docker Compose file '{compose_file.name}': Top-level structure must be a mapping.")

        services = data.get("services")
        if not services or not isinstance(services, dict):
            raise ProjectDetectionError(f"Invalid Docker Compose file '{compose_file.name}': No 'services' section found.")

        service_names = list(services.keys())
        service_types = {s: cls._classify_service(s, services.get(s) or {}) for s in service_names}
        primary, port = cls._select_primary_service(services, service_types)

        desc = f"Docker Compose Multi-Service Stack ({len(service_names)} services: {', '.join(service_names)})"

        return ProjectInfo(
            project_path=str(root),
            project_type=ProjectType.DOCKER_COMPOSE,
            detected_port=port,
            build_file=compose_file.name,
            description=desc,
            compose_file=compose_file.name,
            services=service_names,
            primary_service=primary,
            service_types=service_types,
            is_multi_service=(len(service_names) > 1)
        )

    @staticmethod
    def validate_folder(folder_path_str: str) -> Path:
        """Validates that a path string is safe, exists, and is a directory."""
        if not folder_path_str or not folder_path_str.strip():
            raise ProjectDetectionError("Project folder path cannot be empty.")

        clean_path = folder_path_str.strip().strip("\"'")
        p = Path(clean_path).resolve()

        if not p.exists():
            raise ProjectDetectionError(f"Directory does not exist: '{p}'")

        if not p.is_dir():
            raise ProjectDetectionError(f"Path is not a directory: '{p}'")

        try:
            entries = list(p.iterdir())
            if not entries:
                raise ProjectDetectionError(f"Project directory is empty: '{p}'")
        except PermissionError as e:
            raise ProjectDetectionError(f"Permission denied accessing directory '{p}': {e}")

        return p

    @classmethod
    def _detect_single_dir(cls, p: Path) -> ProjectInfo:
        # 1. Docker Compose (Priority multi-service detection)
        compose_file = cls._find_compose_file(p)
        if compose_file:
            return cls._inspect_compose_project(p, compose_file)

        # 2. Java / Spring Boot (Maven)
        pom_file = p / "pom.xml"
        if pom_file.exists():
            content = cls._read_file_safe(pom_file)
            is_spring = "spring-boot" in content or "org.springframework" in content
            port = cls._detect_spring_port(p) or 8080
            return ProjectInfo(
                project_path=str(p),
                project_type=ProjectType.SPRING_BOOT_MAVEN,
                detected_port=port,
                build_file="pom.xml",
                description="Spring Boot (Maven)" if is_spring else "Java / Maven Application"
            )

        # 3. Java / Spring Boot (Gradle)
        gradle_file = p / "build.gradle"
        gradle_kts = p / "build.gradle.kts"
        if gradle_file.exists() or gradle_kts.exists():
            target_build = "build.gradle" if gradle_file.exists() else "build.gradle.kts"
            content = cls._read_file_safe(p / target_build)
            is_spring = "spring-boot" in content or "org.springframework" in content
            port = cls._detect_spring_port(p) or 8080
            return ProjectInfo(
                project_path=str(p),
                project_type=ProjectType.SPRING_BOOT_GRADLE,
                detected_port=port,
                build_file=target_build,
                description="Spring Boot (Gradle)" if is_spring else "Java / Gradle Application"
            )

        # 4. Node.js
        pkg_file = p / "package.json"
        if pkg_file.exists():
            port = cls._detect_node_port(p) or 3000
            entrypoint = cls._detect_node_entrypoint(p)
            return ProjectInfo(
                project_path=str(p),
                project_type=ProjectType.NODE_JS,
                detected_port=port,
                build_file="package.json",
                entrypoint_hint=entrypoint,
                description="Node.js Web Application"
            )

        # 5. Python
        req_file = p / "requirements.txt"
        pyproject = p / "pyproject.toml"
        python_files = list(p.glob("*.py"))
        if req_file.exists() or pyproject.exists() or python_files:
            port = cls._detect_python_port(p) or 8000
            entrypoint = cls._detect_python_entrypoint(p)
            return ProjectInfo(
                project_path=str(p),
                project_type=ProjectType.PYTHON,
                detected_port=port,
                build_file="requirements.txt" if req_file.exists() else "pyproject.toml" if pyproject.exists() else None,
                entrypoint_hint=entrypoint,
                description="Python Web Application"
            )

        # 6. Standalone Dockerfile
        dockerfile = p / "Dockerfile"
        if dockerfile.exists():
            port = 8080
            content = cls._read_file_safe(dockerfile)
            m = re.search(r"EXPOSE\s+(\d+)", content, re.IGNORECASE)
            if m:
                port = int(m.group(1))
            return ProjectInfo(
                project_path=str(p),
                project_type=ProjectType.DOCKERFILE,
                detected_port=port,
                build_file="Dockerfile",
                description="Containerized Application (Dockerfile)"
            )

        return ProjectInfo(
            project_path=str(p),
            project_type=ProjectType.UNKNOWN,
            description="Unsupported or unrecognized project type"
        )

    @classmethod
    def detect(cls, folder_path: Path) -> ProjectInfo:
        """Detects the framework, build system, and listening port of the project."""
        p = Path(folder_path).resolve()
        info = cls._detect_single_dir(p)
        if info.project_type != ProjectType.UNKNOWN:
            return info

        # If not found directly at root, check immediate subdirectories
        ignored_dirs = {".git", ".idea", ".vscode", "target", "build", "data", "dist", "node_modules", "vendor", "test", "tests"}
        for entry in p.iterdir():
            if entry.is_dir() and not entry.name.startswith((".", "_")) and entry.name.lower() not in ignored_dirs:
                try:
                    sub_info = cls._detect_single_dir(entry)
                    if sub_info.project_type != ProjectType.UNKNOWN:
                        return sub_info
                except Exception:
                    continue

        return info

    @staticmethod
    def _read_file_safe(file_path: Path, max_bytes: int = 50000) -> str:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(max_bytes)
        except Exception:
            return ""

    @classmethod
    def _detect_spring_port(cls, root: Path) -> Optional[int]:
        """Inspects application.properties or application.yml for server.port."""
        candidates = [
            root / "src" / "main" / "resources" / "application.properties",
            root / "src" / "main" / "resources" / "application.yml",
            root / "src" / "main" / "resources" / "application.yaml",
            root / "application.properties",
            root / "application.yml"
        ]
        for f in candidates:
            if f.exists():
                text = cls._read_file_safe(f)
                # server.port=8081 or server.port: 8081
                m = re.search(r"server\.port\s*[:=]\s*(\d+)", text)
                if m:
                    return int(m.group(1))
                # yml format server:\n  port: 8081
                m_yml = re.search(r"server:\s*\n\s+port:\s*(\d+)", text)
                if m_yml:
                    return int(m_yml.group(1))
        return None

    @classmethod
    def _detect_node_port(cls, root: Path) -> Optional[int]:
        """Inspects .env or package.json scripts or common source files for PORT."""
        env_file = root / ".env"
        if env_file.exists():
            text = cls._read_file_safe(env_file)
            m = re.search(r"PORT\s*=\s*(\d+)", text, re.IGNORECASE)
            if m:
                return int(m.group(1))

        for filename in ["server.js", "app.js", "index.js", "main.js"]:
            src = root / filename
            if src.exists():
                text = cls._read_file_safe(src)
                m = re.search(r"\.listen\(\s*(\d+)", text)
                if m:
                    return int(m.group(1))
        return None

    @classmethod
    def _detect_node_entrypoint(cls, root: Path) -> Optional[str]:
        for candidate in ["server.js", "app.js", "index.js", "main.js", "src/index.js", "src/server.js"]:
            if (root / candidate).exists():
                return candidate
        return None

    @classmethod
    def _detect_python_port(cls, root: Path) -> Optional[int]:
        """Inspects Python source files for uvicorn, flask, or fastapi port declarations."""
        for candidate in ["main.py", "app.py", "run.py", "server.py"]:
            src = root / candidate
            if src.exists():
                text = cls._read_file_safe(src)
                # uvicorn.run(..., port=8080)
                m = re.search(r"port\s*=\s*(\d+)", text)
                if m:
                    return int(m.group(1))
                if "flask" in text.lower():
                    return 5000
                if "uvicorn" in text.lower() or "fastapi" in text.lower():
                    return 8000
        return None

    @classmethod
    def _detect_python_entrypoint(cls, root: Path) -> Optional[str]:
        for candidate in ["main.py", "app.py", "run.py", "server.py", "manage.py"]:
            if (root / candidate).exists():
                return candidate
        return None
