import os
import re
from pathlib import Path
from typing import Optional

from app.models.config import TargetComplexity, ComplexityLevel
from app.target.detector import ProjectDetector, ProjectInfo, ProjectType


class ComplexityAnalyzer:
    """Calculates deterministic, explainable architectural complexity profiles and step budgets."""

    @classmethod
    def analyze(cls, project_path: str, project_info: Optional[ProjectInfo] = None) -> TargetComplexity:
        path = Path(project_path).resolve()
        if not path.exists() or not path.is_dir():
            return TargetComplexity(
                level=ComplexityLevel.LOW,
                score=5,
                recommended_steps=10,
                reasons=["Target path does not exist or is not a directory; standard baseline budget applied."]
            )

        if not project_info:
            try:
                project_info = ProjectDetector.detect(path)
            except Exception:
                project_info = None

        score = 0
        reasons: list[str] = []

        controllers_count = 0
        endpoints_count = 0
        mutation_routes_count = 0
        workers_count = 0
        services_count = len(project_info.services) if project_info and project_info.is_multi_service else 1

        databases: set[str] = set()
        caches: set[str] = set()
        queues: set[str] = set()

        has_compose = bool(project_info and project_info.project_type == ProjectType.DOCKER_COMPOSE)
        has_auth_surface = False
        has_operator_surface = False

        # 1. Scan build files for dependencies
        cls._scan_dependencies(path, databases, caches, queues)

        # 2. Scan source files for routes, controllers, and workers
        cls._scan_source_code(
            path,
            controllers_count_ref=[controllers_count],
            endpoints_count_ref=[endpoints_count],
            mutation_routes_ref=[mutation_routes_count],
            workers_count_ref=[workers_count],
            flags_ref={"auth": has_auth_surface, "operator": has_operator_surface}
        )

        controllers_count = max(controllers_count, 1)
        endpoints_count = max(endpoints_count, 4)
        mutation_routes_count = max(mutation_routes_count, 1)

        # Multi-service bonus
        if has_compose and project_info:
            score += 5 + (len(project_info.services) * 2)
            reasons.append(f"Docker Compose multi-service architecture with {len(project_info.services)} containers ({', '.join(project_info.services)})")

        # Endpoints contribution
        endpoint_pts = min(endpoints_count, 15)
        score += endpoint_pts
        reasons.append(f"Detected estimated {endpoints_count} HTTP endpoints across application controllers")

        # Mutation routes (POST, PUT, DELETE)
        mutation_pts = min(mutation_routes_count * 2, 10)
        score += mutation_pts
        if mutation_routes_count > 0:
            reasons.append(f"{mutation_routes_count} mutation routes requiring idempotency, replay, and concurrency validation")

        # Database dependencies
        if databases:
            db_list = sorted(list(databases))
            score += len(databases) * 3
            reasons.append(f"Persistent database storage detected: {', '.join(db_list)}")

        # Cache dependencies
        if caches:
            c_list = sorted(list(caches))
            score += len(caches) * 2
            reasons.append(f"In-memory caching layer detected: {', '.join(c_list)}")

        # Message queues
        if queues:
            q_list = sorted(list(queues))
            score += len(queues) * 3
            reasons.append(f"Asynchronous messaging broker detected: {', '.join(q_list)}")

        # Workers / Dispatchers
        if workers_count > 0 or any("worker" in s.lower() for s in (project_info.services if project_info else [])):
            w_num = max(workers_count, 1)
            score += w_num * 2
            reasons.append(f"{w_num} background worker or task dispatcher component(s) detected")

        # Auth and operator surfaces
        if cls._scan_auth_operator(path):
            score += 4
            has_auth_surface = True
            has_operator_surface = True
            reasons.append("Administrative, diagnostics, or authentication surface detected")

        # Deterministic Complexity Level and Step Budget mapping
        if score < 12:
            level = ComplexityLevel.LOW
            recommended = 10
            min_steps = 5
            max_steps_allowed = 20
        elif score < 24:
            level = ComplexityLevel.MEDIUM
            recommended = 15
            min_steps = 8
            max_steps_allowed = 30
        elif score < 36:
            level = ComplexityLevel.HIGH
            recommended = 18
            min_steps = 10
            max_steps_allowed = 40
        else:
            level = ComplexityLevel.VERY_HIGH
            recommended = 25
            min_steps = 15
            max_steps_allowed = 50

        return TargetComplexity(
            level=level,
            score=score,
            recommended_steps=recommended,
            min_steps=min_steps,
            max_steps_allowed=max_steps_allowed,
            endpoints_estimated=endpoints_count,
            mutation_routes_estimated=mutation_routes_count,
            controllers_count=controllers_count,
            services_count=services_count,
            workers_count=workers_count,
            databases_detected=sorted(list(databases)),
            caches_detected=sorted(list(caches)),
            queues_detected=sorted(list(queues)),
            has_compose=has_compose,
            has_auth_surface=has_auth_surface,
            has_operator_surface=has_operator_surface,
            reasons=reasons
        )

    @classmethod
    def _scan_dependencies(cls, root: Path, databases: set[str], caches: set[str], queues: set[str]) -> None:
        """Inspects build descriptors recursively (pom.xml, build.gradle, requirements.txt, package.json, docker-compose.yml)."""
        patterns = {
            "postgres": databases,
            "postgresql": databases,
            "mysql": databases,
            "mariadb": databases,
            "mongodb": databases,
            "sqlite": databases,
            "h2": databases,
            "redis": caches,
            "memcached": caches,
            "kafka": queues,
            "rabbitmq": queues,
            "activemq": queues,
        }

        build_names = {"pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "package.json", "docker-compose.yml", "compose.yaml"}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "target", "build", "dist", ".venv", "venv")]
            for f in filenames:
                if f.lower() in build_names:
                    p = Path(dirpath) / f
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore").lower()
                        for term, target_set in patterns.items():
                            if term in text:
                                target_set.add(term.capitalize())
                    except Exception:
                        pass

    @classmethod
    def _scan_source_code(
        cls,
        root: Path,
        controllers_count_ref: list[int],
        endpoints_count_ref: list[int],
        mutation_routes_ref: list[int],
        workers_count_ref: list[int],
        flags_ref: dict[str, bool]
    ) -> None:
        """Heuristically walks source files to count routes and identify workers."""
        exts = {".java", ".py", ".js", ".ts", ".go", ".cs"}
        max_files = 250
        files_checked = 0

        for dirpath, dirnames, filenames in os.walk(root):
            # Skip hidden dirs, target, node_modules, build
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "target", "build", "dist", ".venv", "venv")]
            for f in filenames:
                path = Path(dirpath) / f
                if path.suffix.lower() in exts:
                    files_checked += 1
                    if files_checked > max_files:
                        return

                    try:
                        content = path.read_text(encoding="utf-8", errors="ignore")
                        # Java / Spring annotations
                        if "@RestController" in content or "@Controller" in content:
                            controllers_count_ref[0] += 1
                        
                        # Route mappings
                        matches = re.findall(r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\b', content)
                        if matches:
                            endpoints_count_ref[0] += len(matches)
                            for m in matches:
                                if m in ("PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"):
                                    mutation_routes_ref[0] += 1

                        # Python / FastAPI / Flask routes
                        py_routes = re.findall(r'@(?:app|router)\.(get|post|put|delete|patch)\b', content, re.IGNORECASE)
                        if py_routes:
                            endpoints_count_ref[0] += len(py_routes)
                            for r in py_routes:
                                if r.lower() in ("post", "put", "delete", "patch"):
                                    mutation_routes_ref[0] += 1

                        # Workers / task dispatchers
                        if any(w in f.lower() for w in ["worker", "dispatcher", "consumer", "task"]):
                            workers_count_ref[0] += 1
                        elif "@Scheduled" in content or "@Async" in content:
                            workers_count_ref[0] += 1

                    except Exception:
                        pass

    @classmethod
    def _scan_auth_operator(cls, root: Path) -> bool:
        """Checks for auth, login, operator, admin routes in code or directory names."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "target", "build", ".venv")]
            for f in filenames:
                f_lower = f.lower()
                if any(k in f_lower for k in ["auth", "login", "operator", "admin", "diagnostics"]):
                    return True
        return False
