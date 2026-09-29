import os
import re
from enum import Enum
from pathlib import Path
from typing import Optional
from pydantic import BaseModel


class ProjectType(str, Enum):
    SPRING_BOOT_MAVEN = "SPRING_BOOT_MAVEN"
    SPRING_BOOT_GRADLE = "SPRING_BOOT_GRADLE"
    NODE_JS = "NODE_JS"
    PYTHON = "PYTHON"
    UNKNOWN = "UNKNOWN"


class ProjectInfo(BaseModel):
    project_path: str
    project_type: ProjectType
    detected_port: Optional[int] = None
    build_file: Optional[str] = None
    entrypoint_hint: Optional[str] = None
    description: str = ""


class ProjectDetectionError(Exception):
    """Raised when project path or configuration cannot be validated or detected."""
    pass


class ProjectDetector:
    """Inspects a user-supplied project directory to determine runtime type and port."""

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

        # Basic check to ensure directory is not empty
        try:
            entries = list(p.iterdir())
            if not entries:
                raise ProjectDetectionError(f"Project directory is empty: '{p}'")
        except PermissionError as e:
            raise ProjectDetectionError(f"Permission denied accessing directory '{p}': {e}")

        return p

    @classmethod
    def detect(cls, folder_path: Path) -> ProjectInfo:
        """Detects the framework, build system, and listening port of the project."""
        p = folder_path.resolve()

        # 1. Java / Spring Boot (Maven)
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

        # 2. Java / Spring Boot (Gradle)
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

        # 3. Node.js
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

        # 4. Python
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

        return ProjectInfo(
            project_path=str(p),
            project_type=ProjectType.UNKNOWN,
            description="Unsupported or unrecognized project type"
        )

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
