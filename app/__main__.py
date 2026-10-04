import asyncio
import os
import sys
import logging
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.models.target import Target
from app.models.decision import AgentDecision
from app.models.observation import Observation
from app.models.session import SessionStatus
from app.target.runner import TargetRunner
from app.target.detector import ProjectDetector, ProjectType, ProjectDetectionError
from app.target.sandbox import DockerProjectSandbox, DockerSandboxError
from app.target.compose_sandbox import ComposeProjectSandbox, ComposeSandboxError
from app.agent.controller import AgentController
from app.evidence.store import EvidenceStore

console = Console()
logging.basicConfig(level=logging.WARNING)


def render_step_callback(step: int, decision: AgentDecision, observation: Observation):
    """Real-time CLI visualization of autonomous agent reasoning and tool executions."""
    header = f"[bold cyan]Step {step}[/bold cyan] | Tool: [bold yellow]{decision.tool}[/bold yellow]"
    
    body = Text()
    body.append("Intent:    ", style="bold green")
    body.append(f"{decision.next_action}\n")
    body.append("Reasoning: ", style="bold magenta")
    body.append(f"{decision.reasoning_summary}\n")
    body.append("Outcome:   ", style="bold white")
    body.append(f"{observation.summary}\n")
    
    if observation.key_insights:
        body.append("\nKey Insights:\n", style="bold red")
        for insight in observation.key_insights:
            body.append(f"  - {insight}\n", style="yellow")

    console.print(Panel(body, title=header, border_style="blue", expand=False))


async def main():
    if any(arg in sys.argv for arg in ("--web", "--dashboard", "serve", "-w")):
        import uvicorn
        port = 8585
        for arg in sys.argv:
            if arg.startswith("--port="):
                try:
                    port = int(arg.split("=")[1])
                except Exception:
                    pass
        console.print(f"[bold cyan]Launching StressX Web Dashboard on http://127.0.0.1:{port} ...[/bold cyan]")
        config = uvicorn.Config("app.api.server:api_app", host="127.0.0.1", port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()
        return

    console.print(Panel.fit(
        "[bold red]StressX[/bold red] - [bold white]Autonomous AI Security Testing Agent[/bold white]\n"
        "[italic cyan]Empirical Closed-Loop Security Auditing for Software Projects[/italic cyan]",
        border_style="red"
    ))

    # 1. Project Selection (CLI argument, environment variable, or interactive)
    user_input = ""
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        user_input = sys.argv[1].strip()
    elif os.environ.get("STRESSX_TARGET_DIR"):
        user_input = os.environ.get("STRESSX_TARGET_DIR", "").strip()
    else:
        console.print("\n[bold yellow]Enter the path to the project folder you want StressX to audit:[/bold yellow]")
        console.print("[dim]Example: C:\\Projects\\MyProject or ./sample_projects/python_api[/dim]")
        console.print("[dim](Or press Enter to test the built-in vulnerable benchmark target):[/dim] ", end="")
        try:
            user_input = input().strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Audit canceled by user.[/yellow]")
            return

    runner: TargetRunner | None = None
    sandbox: DockerProjectSandbox | None = None
    compose_sandbox: ComposeProjectSandbox | None = None
    session = None
    store = None
    resolved_proj = "BENCHMARK"

    try:
        if not user_input or user_input.lower() in ("benchmark", "demo", "default"):
            # Fallback / benchmark mode
            console.print("\n[bold yellow][*] Initializing controlled vulnerable benchmark target...[/bold yellow]")
            runner = TargetRunner(port=8088, use_docker=False)
            target = runner.start()
            console.print(f"[bold green][+] Target active and isolated at {target.base_url}[/bold green]")
        else:
            # User-supplied project folder mode
            try:
                folder_path = ProjectDetector.validate_folder(user_input)
            except ProjectDetectionError as pe:
                console.print(Panel(f"[bold red]Invalid Project Path:[/bold red]\n{pe}", border_style="red"))
                return

            console.print(f"\n[cyan][*] Inspecting project at:[/cyan] {folder_path}")
            project_info = ProjectDetector.detect(folder_path)

            if project_info.project_type == ProjectType.UNKNOWN:
                console.print(Panel(
                    f"[bold red]Unsupported Project Type:[/bold red]\n"
                    f"Could not identify a supported project structure in '{folder_path}'.\n\n"
                    f"[yellow]Currently supported project types for Docker sandboxing:[/yellow]\n"
                    f"  - Docker Compose (compose.yaml / docker-compose.yml)\n"
                    f"  - Spring Boot / Maven (pom.xml)\n"
                    f"  - Spring Boot / Gradle (build.gradle / build.gradle.kts)\n"
                    f"  - Node.js (package.json)\n"
                    f"  - Python web applications (requirements.txt / pyproject.toml / main.py)",
                    title="Detection Error",
                    border_style="red"
                ))
                return

            console.print(f"[bold green][+] Detected Project Type:[/bold green] {project_info.description}")
            if project_info.build_file:
                console.print(f"[dim]    Build descriptor: {project_info.build_file}[/dim]")

            # 2. Build and launch isolated Docker sandbox (Multi-Service or Single Container)
            if project_info.project_type == ProjectType.DOCKER_COMPOSE:
                console.print(f"\n[bold cyan][*] Multi-Service Docker Compose Stack Detected:[/bold cyan]")
                for s in project_info.services:
                    stype = project_info.service_types.get(s, "application")
                    is_prim = " [bold green](Primary Target)[/bold green]" if s == project_info.primary_service else " [dim](Internal Dependency)[/dim]"
                    console.print(f"    - [yellow]{s}[/yellow] [{stype}]{is_prim}")

                target_service = project_info.primary_service
                target_port = project_info.detected_port or 8080

                console.print(f"\n[bold yellow][*] Building and starting isolated Docker Compose sandbox...[/bold yellow]")
                console.print(f"[dim]    Isolating stack: Service '{target_service}' mapped to 127.0.0.1. Internal services unexposed.[/dim]")
                compose_sandbox = ComposeProjectSandbox(
                    project_info=project_info,
                    target_service=target_service,
                    target_port=target_port,
                    cpu_limit=1.0,
                    memory_limit_mb=1024
                )
                target = compose_sandbox.build_and_start()
            else:
                # Port detection for single container
                target_port = project_info.detected_port
                if target_port:
                    console.print(f"[bold green][+] Detected listening port:[/bold green] {target_port}")
                else:
                    console.print("[yellow][!] Could not automatically detect listening port.[/yellow]")
                    console.print("Enter the application listening port [default: 8080]: ", end="")
                    try:
                        port_str = input().strip()
                        target_port = int(port_str) if port_str.isdigit() else 8080
                    except Exception:
                        target_port = 8080

                console.print(f"\n[bold yellow][*] Building and starting isolated Docker sandbox...[/bold yellow]")
                console.print(f"[dim]    Resource boundaries: CPU=1.0, Memory=1024MB, Network=stressx-sandbox-net[/dim]")
                sandbox = DockerProjectSandbox(
                    project_info=project_info,
                    target_port=target_port,
                    cpu_limit=1.0,
                    memory_limit_mb=1024
                )
                target = sandbox.build_and_start()

        console.print(f"[dim]    Target Boundary Enforcement: Permitted hosts = {target.allowed_hosts}, Ports = {target.allowed_ports}[/dim]\n")

        # 3. Launch Autonomous Security Agent with Dynamic Step Budget
        from app.target.complexity import ComplexityAnalyzer
        complexity = None
        if user_input and Path(user_input).exists():
            try:
                complexity = ComplexityAnalyzer.analyze(user_input, project_info if 'project_info' in locals() else None)
            except Exception:
                pass

        max_steps = complexity.recommended_steps if complexity else 25
        if os.environ.get("STRESSX_MAX_STEPS"):
            try:
                max_steps = int(os.environ.get("STRESSX_MAX_STEPS"))
            except Exception:
                pass

        if complexity:
            console.print(f"[bold cyan][*] Target Complexity: {complexity.level.value} (Score: {complexity.score}/100) | Recommended Steps: {complexity.recommended_steps}[/bold cyan]")
        console.print(f"[bold yellow][*] Launching StressX Autonomous Agent Controller (Budget: {max_steps} steps)...[/bold yellow]\n")
        controller = AgentController(
            target=target,
            max_steps=max_steps,
            step_callback=render_step_callback
        )

        # Record project type into session context
        resolved_proj = project_info.project_type.value if 'project_info' in locals() and project_info else "BENCHMARK"
        controller.session.context_data["project_type"] = resolved_proj

        session = await controller.run_audit()

        if session.status == SessionStatus.FAILED:
            err_msg = session.context_data.get("error_message", "Unknown model inference error.")
            console.print(Panel(
                f"[bold red]Audit Terminated Due to Model Execution Error:[/bold red]\n{err_msg}\n\n"
                f"[yellow]The local AI model was reached but could not execute or validate decisions.[/yellow]\n"
                f"[dim]Please check: ollama list, ollama run llama3[/dim]",
                title="[bold red]StressX Audit Execution Aborted[/bold red]",
                border_style="red"
            ))
            return

        # 4. Export Evidence Dossier & Reports
        store = EvidenceStore()
        audit_dir, metrics = store.save_audit_dossier(session, project_type=resolved_proj)
        report_file = audit_dir / "report.md"
        dossier_file = store.export_dir / f"audit_dossier_{session.id}.json"

        # 5. Display Findings Table
        console.print("\n" + "=" * 70)
        console.print("[bold red]STRESSX EMPIRICALLY CONFIRMED VULNERABILITY FINDINGS[/bold red]")
        console.print("=" * 70)

        table = Table(title="Verified Security Findings", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Category", width=22)
        table.add_column("Title", width=36)
        table.add_column("Affected Endpoint", width=24)
        table.add_column("Evidence", width=10)

        sev_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "white"
        }

        for f in session.findings:
            color = sev_colors.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value}[/{color}]",
                f.category.value,
                f.title,
                f.affected_endpoint or "/",
                f"{len(f.evidence)} items"
            )

        console.print(table)

        # 6. Display Evidence Runbook for first finding if available
        if session.findings:
            f = session.findings[0]
            console.print(Panel(
                f"[bold]Finding:[/bold] {f.title}\n"
                f"[bold]Description:[/bold] {f.description}\n\n"
                f"[bold]Reproduction Runbook:[/bold]\n" + "\n".join([f"  {s}" for s in f.reproduction_steps]),
                title="Sample Verifiable Evidence Dossier",
                border_style="green"
            ))

        console.print(f"\n[bold green][+] Audit metrics saved to:[/bold green] {audit_dir / 'metrics.json'}")
        console.print(f"[bold green][+] Action log saved to:[/bold green] {audit_dir / 'actions.jsonl'}")
        console.print(f"[bold green][+] Findings dossier saved to:[/bold green] {audit_dir / 'findings.json'}")
        console.print(f"[bold green][+] Complete audit folder:[/bold green] {audit_dir}")
        console.print(f"[bold cyan][+] Cumulative metrics updated at:[/bold cyan] {store.export_dir / 'aggregate_metrics.json'}")
        console.print(f"[bold cyan][+] Total Verified Findings: {len(session.findings)}[/bold cyan]")

    except (DockerSandboxError, ComposeSandboxError) as de:
        console.print(Panel(
            f"[bold red]Docker Sandbox Deployment Failed:[/bold red]\n{de}",
            title="Sandbox Error",
            border_style="red"
        ))
    finally:
        # Guarantee cleanup of target environment
        cleaned_up = False
        is_sandboxed_target = False

        if runner:
            console.print("\n[yellow][*] Tearing down benchmark target...[/yellow]")
            cleaned_up = runner.stop()
            is_sandboxed_target = getattr(runner, "use_docker", False)
            console.print("[green][+] Benchmark target cleanly stopped.[/green]")
        if sandbox:
            console.print("\n[yellow][*] Destroying isolated Docker sandbox...[/yellow]")
            cleaned_up = sandbox.cleanup()
            is_sandboxed_target = True
            console.print("[green][+] Sandbox container and artifacts destroyed.[/green]")
        if compose_sandbox:
            console.print("\n[yellow][*] Tearing down multi-service Docker Compose stack...[/yellow]")
            cleaned_up = compose_sandbox.cleanup()
            is_sandboxed_target = True
            console.print("[green][+] Multi-service sandbox destroyed.[/green]")

        if session is not None and is_sandboxed_target:
            session.record_sandbox_cleanup(cleaned_up)
            if store is not None:
                store.save_audit_dossier(session, project_type=resolved_proj)


if __name__ == "__main__":
    asyncio.run(main())
