# StressX — Autonomous AI Security Testing System

[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6.svg)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Sandboxed-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!WARNING]
> **AUTHORIZED TESTING AND EVALUATION USE ONLY**  
> StressX is an autonomous security auditing and adversarial experimentation system designed strictly for authorized penetration testing, vulnerability assessment, and resilience evaluation against applications you own or have explicit, documented authorization to test. Testing against unauthorized infrastructure is strictly prohibited.

---

## What It Does

**StressX** is an AI-driven autonomous security testing system. It is **not** a passive vulnerability scanner or static linter. StressX actively and safely tests target applications through an adaptive empirical loop:

- **Discovers the Target:** Maps endpoints, HTTP methods, OpenAPI/Swagger schemas, input fields, and parameters dynamically.
- **Builds & Isolates Applications:** Automatically containerizes projects into isolated Docker single-container or multi-service bridge sandboxes with strict CPU, memory, and network boundaries.
- **Reasons About Weaknesses:** Synthesizes structured security hypotheses covering authorization flaws, injection vulnerabilities, race conditions, and resilience boundaries.
- **Performs Controlled Attacks:** Dispatches active probes, payload mutations, concurrency bursts, and failure simulations.
- **Observes Runtime Behavior:** Measures latency inflation, HTTP status codes, error messages, and state mutations.
- **Adapts Subsequent Tests:** Evaluates test feedback in real time, abandons unproductive avenues, prevents repetitive loops, and pivots toward unverified surfaces.
- **Verifies Findings Empirically:** Confirms vulnerabilities only when reproducible evidence proves the flaw. Fabricated or speculative findings are strictly rejected.
- **Collects Evidence:** Automatically captures full HTTP request/response exchanges, calculates causal failure mechanisms, and constructs verifiable `curl` reproduction commands.
- **Produces Understandable Reports:** Generates executive summaries for stakeholders and expandable technical dossiers with reproduction runbooks for developers.

---

## Architecture

StressX is organized as a decoupled, layered platform:

```text
React + TypeScript + Vite (Control Dashboard)
                  ↓ [REST API & SSE Telemetry]
FastAPI Control Plane (Session Orchestration & State)
                  ↓
AI Agent / Controller (Autonomous Reasoning & Anti-Repetition Loop)
                  ↓
Controlled Testing Tools (Target-Bounded HTTP & Resilience Execution)
                  ↓
Isolated Sandbox (Docker Single-Container or Multi-Service Compose Bridge)
                  ↓
Authorized Target Application
```

### Component Breakdown
1. **Frontend (`frontend/`):** A clean, responsive React + TypeScript dashboard built with Vite, Tailwind CSS, and Lucide icons. Communicates with the backend via REST endpoints and a real-time Server-Sent Events (SSE) telemetry stream.
2. **Control Plane (`app/api/`):** FastAPI application managing project analysis, sandbox deployment lifecycle, live event publishing, and report dossier retrieval. Serves the compiled production React frontend from `app/static/`.
3. **AI Agent Controller (`app/agent/`):** Drives the multi-phase autonomous attack cycle, manages hypothesis lifecycle, tracks tested endpoints, enforces anti-repetition rules, and triggers pivots when hypotheses stagnate.
4. **Testing Tools (`app/tools/`):** Sandboxed security experimentation tools enforcing strict network boundaries.
5. **Target Sandboxing (`app/target/`):** Ephemeral Docker environments enforcing network isolation, port remapping, and memory/CPU limits.

---

## Attack Capabilities & Test Families

StressX tests real-world application security and system design integrity across diverse attack families:

- **Authentication & Authorization Testing:** Probes for missing access controls, unauthenticated administrative routes, token flaws, and Insecure Direct Object References (BOLA/IDOR).
- **Injection Testing:** Injects targeted SQL syntax delimiters and boolean logic payloads; verifies query tampering via differential response analysis.
- **Rate-Limit & Abuse Testing:** Deploys adaptive pressure testing to determine throttling thresholds (HTTP 429), measure degradation curves, and verify post-burst recovery.
- **Idempotency Testing:** Replays mutation requests sequentially and concurrently with identical `Idempotency-Key` headers to detect duplicate database state or unhandled 500 exceptions.
- **Concurrency & Race Condition Testing:** Dispatches simultaneous concurrent requests against mutation endpoints to observe database lock contention, thread starvation, and state inconsistencies.
- **Pressure & Load Testing:** Measures baseline latency distributions and escalates request rates to measure response time degradation and server backpressure.
- **System Resilience & Failure Injection:** Where simulation or control endpoints exist, introduces controlled failure states, assesses downstream health, and verifies automated recovery and rollback.
- **Worker & Resource Exhaustion Testing:** Evaluates memory, CPU, and worker dispatch behaviors under large payload or batch export operations.
- **Evidence-Based Verification:** Demands empirical runtime divergence before confirming any finding. No finding is reported without reproducible proof.

---

## Autonomous AI Reasoning Loop

The StressX agent executes an autonomous feedback loop:

```text
Discover → Hypothesize → Test → Observe → Reason → Adapt → Verify → Record Evidence → Pivot or Complete
```

1. **Discover:** Enumerate available routes, documentation, and query surfaces.
2. **Hypothesize:** Formulate testable assertions with specific security questions and expected indicators.
3. **Test:** Execute bounded probes using specialized tools.
4. **Observe:** Capture response status, latency, headers, and body previews.
5. **Reason:** Evaluate whether the observation supports, contradicts, or leaves the hypothesis inconclusive.
6. **Adapt:** If an endpoint is non-existent (404) or disallowed (405), immediately drop it and pivot to untested attack surface.
7. **Verify:** Confirm with follow-up validation or response comparisons.
8. **Record Evidence:** Persist verified evidence, reproducible `curl` commands, causal failure chains, and remediation guidance.
9. **Pivot or Complete:** Continue testing until the budgeted steps are exhausted, then conclude and compile the final report.

---

## Creator Dashboard

StressX includes a creator-style web dashboard:

- **Target Project Selection:** Select local project directories or test the built-in vulnerable benchmark.
- **Architectural Complexity Analysis:** Automatically inspects target endpoints, mutation routes, background workers, and multi-service compose topologies to calculate an architectural complexity score (0–100).
- **Dynamic Step Budgeting:** Recommends an optimal attack-step budget based on target complexity, with an interactive slider override.
- **Explicit Audit Naming:** Assign custom audit names (with automatic suggestions) to organize and track assessments without silent renaming.
- **Asynchronous Sandbox Deployment:** Launches container builds asynchronously in the background with real-time stage tracking (`PREPARING_TARGET`, `BUILDING_APPLICATION`, `STARTING_SERVICES`, `CHECKING_READINESS`, `READY`) without freezing the browser.
- **Real-Time Live Monitor:** Watch the AI agent formulate hypotheses, execute tools, and discover attack surfaces incrementally via live SSE events.
- **Structured Reports View:** Features an executive summary card, plain-English summary, structured finding cards (What Happened, Impact, Verification, Remediation), and an expandable technical evidence accordion with 1-click `curl` reproduction commands.
- **Dossier Export:** Export complete structured JSON or Markdown reports.

---

## Safety & Sandboxing

- **Strict Network Boundaries:** All requests are validated against allowed hostnames and IP addresses. Outbound requests to external networks are blocked at the transport layer.
- **Ephemeral Sandbox Isolation:** Target projects are copied into dedicated scratch contexts before execution. Original source code is never modified.
- **Resource Constraints:** Containers run with hard limits on CPU cores and memory allocations to protect the host machine.
- **Sensitive Data Redaction:** All persisted logs and reports automatically redact passwords, API tokens, JWTs, and private keys.
- **Automatic Failure Rollback:** Fault injection tools automatically execute reset actions to restore normal operation.

---

## Setup & Installation

### Prerequisites
- **Python:** 3.13 or newer
- **Node.js:** 18 or newer (with npm)
- **Docker:** Docker Desktop running with Compose support (for sandbox testing)
- **OS:** Windows 10/11, Linux, or macOS

### Windows Setup Instructions

Open PowerShell and execute:

```powershell
# 1. Clone the repository
git clone https://github.com/Ayush5424/StressX.git
cd StressX

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Build the React frontend
cd frontend
npm install
npm run build
cd ..

# 5. Launch the Web Dashboard
python -m app --web
```

The web dashboard is available at:
```text
http://127.0.0.1:8585
```

---

## AI Model Integration

StressX is designed for local, private open-weight model execution via [Ollama](https://ollama.com/):

### 1. Install & Start Ollama
1. Download Ollama from [ollama.com](https://ollama.com/).
2. Pull the recommended security reasoning model:
   ```powershell
   ollama pull llama3:8b
   ```
3. Ensure the Ollama server is running (defaults to `http://127.0.0.1:11434`).

### 2. Autonomous Fallback Engine
If Ollama is not running, StressX automatically activates its built-in **Deterministic Autonomous Security Reasoning Engine**, enabling full end-to-end testing, surface mapping, and report generation without requiring a running model daemon.

---

## Development Mode

To run the frontend and backend in active development mode:

### Backend Development Server
```powershell
.venv\Scripts\Activate.ps1
uvicorn app.api.server:api_app --host 127.0.0.1 --port 8000 --reload
```

### Frontend Hot-Reload Server
In a separate terminal:
```powershell
cd frontend
npm run dev
```

The Vite dev server proxies API requests directly to the FastAPI backend.

---

## Running Tests

Execute the comprehensive test suite:

```powershell
python -m pytest -q
```

---

## Repository Structure

```text
StressX/
├── frontend/                  # React 18 + TypeScript + Vite frontend
│   ├── src/
│   │   ├── components/        # Dashboard, ActiveAudit, NewAudit, Reports, Evidence views
│   │   ├── services/          # API client and Server-Sent Events (SSE) connector
│   │   ├── types/             # Domain TypeScript interfaces
│   │   └── App.tsx            # Root application component
│   ├── package.json           # Frontend dependencies and build scripts
│   └── vite.config.ts         # Vite build configuration (outputs to app/static/)
├── app/
│   ├── agent/                 # Autonomous agent controller and prompt synthesizers
│   ├── tools/                 # Sandboxed attack, concurrency, and measurement tools
│   ├── target/                # Sandbox engines, complexity analyzer, and benchmark runner
│   ├── evidence/              # Evidence store, redaction engine, and dossier export
│   ├── models/                # Pydantic schemas (config, session, finding, evidence)
│   ├── api/                   # FastAPI routes, event manager, and audit manager
│   ├── static/                # Production compiled React bundle served by FastAPI
│   └── __main__.py            # CLI entry point supporting both terminal and --web modes
├── sample_projects/           # Target applications for testing and benchmarking
│   ├── python_api/            # Standalone API sample project
│   └── compose_postgres_app/  # Multi-service Compose application
├── tests/                     # Unit, integration, and security test suites
├── audit_reports/             # Local output folder for generated dossiers (.gitkeep preserved)
├── .env.example               # Safe environment variable configuration template
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

---

## Configuration

Copy `.env.example` to `.env` to configure optional environment variables:

```bash
# AI Engine / Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434
STRESSX_MODEL=llama3:8b

# Server / Web Dashboard Configuration
STRESSX_WEB_HOST=127.0.0.1
STRESSX_WEB_PORT=8000

# Logging & Storage
STRESSX_LOG_LEVEL=INFO
STRESSX_REPORTS_DIR=audit_reports
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
