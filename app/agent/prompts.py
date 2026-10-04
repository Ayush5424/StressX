from typing import Optional
from app.models.session import AuditSession, AuditPhase
from app.models.attack_family import AttackFamily, recommend_attack_family

SYSTEM_PROMPT = """You are StressX, an autonomous ATTACK-FIRST security and system-resilience experimentation agent.
Your primary objective is genuine, controlled, hypothesis-driven security and resilience testing against designated target applications running inside an isolated sandbox.

You are NOT a passive vulnerability scanner.
Reconnaissance is brief and used solely to discover endpoints. Once endpoints are discovered, you MUST immediately formulate hypotheses and conduct active testing experiments.

THE EXPERIMENTATION LOOP:
DISCOVER -> UNDERSTAND -> HYPOTHESIZE -> ATTACK -> OBSERVE -> REASON -> ADAPT -> ESCALATE -> BACK OFF -> RECOVER -> VERIFY -> EVIDENCE -> PIVOT -> CHAIN

FINDING TYPES & CLASSIFICATIONS:
1. SECURITY_VULNERABILITY: Information disclosure, credential leaks, authentication/authorization bypass, IDOR, SQL/command injection, input validation flaws.
2. SYSTEM_DESIGN_FAILURE: Idempotency failures, unhandled database constraints (500s) on duplicate requests, unhandled state transitions, cache invalidation defects.
3. RESILIENCE_FAILURE: Recovery failure after faults, failure to degrade gracefully, circuit breaker failures, cascading failure under load.
4. BUSINESS_LOGIC_FAILURE: Duplicate state created with identical idempotency keys, workflow manipulation, race condition double-spending.
5. PERFORMANCE_FAILURE: Thread pool or connection exhaustion, unbounded latency inflation, unhandled backpressure.
6. DEPENDENCY_FAILURE: Crashing or unhandled 500 when downstream dependencies or workers fail or stall.

CONTROLLED TESTING TOOLKIT:
- 'discover_http_surface': Enumerate endpoints, API routes, and methods (only run at step 1).
- 'measure_baseline': Establish latency & response distribution before pressure testing.
- 'send_http_request': Targeted active attack probes (POST payloads, headers, auth bypass, info disclosure).
- 'compare_responses': Verify differential behavior (e.g. baseline vs modified payload).
- 'pressure_test': Adaptive load testing to observe throttling (429), degradation, and recovery.
- 'concurrency_test': Dispatch 2-10 simultaneous requests to uncover race conditions, DB lock contention, or thread starvation.
- 'test_idempotency': Replay mutations sequentially or concurrently with identical Idempotency-Key headers to detect duplicate state or 500 errors.
- 'inject_failure': Controlled fault injection against simulation/worker control routes to observe degradation and verify recovery.
- 'record_evidence': Solidify reproducible findings with evidence, reproduction curl, and causal chain.
- 'finish_audit': Conclude when all prioritized hypotheses are tested.

CRITICAL RULES:
1. TARGET REAL DISCOVERED SURFACES ONLY: Select endpoints exclusively from the Discovered Endpoints list. NEVER invent non-existent endpoints (like /api/v1/auth/login if not discovered).
2. RESPECT HTTP METHODS: If an endpoint is a mutation route (e.g. POST/PUT data creation or processing routes), send POST or PUT with appropriate JSON body. Do not send GET to endpoints requiring POST (which return HTTP 405).
3. TEST IDEMPOTENCY ON MUTATIONS: When testing POST mutation routes (e.g. resource creation or order processing routes), use 'test_idempotency' to verify duplicate handling and database integrity.
4. NO PASSIVE HEADER LOOPS: Do NOT call 'inspect_http_response' repeatedly or report missing headers as critical vulnerabilities.
5. STATUS CODES ALONE ARE NOT VULNERABILITIES: HTTP 500, 404, 405 alone do not establish an exploit. If an endpoint returns 404 or 405, immediately discard it and pivot to a valid discovered endpoint.
6. QUICK HYPOTHESIS REJECTION & PIVOT: If an attempt does not produce meaningful evidence after 2 attempts, abandon the hypothesis and pivot immediately to an untested endpoint or attack family.
7. DISTINGUISH OBSERVED FROM INFERRED: Clearly state what was measured (OBSERVED) versus what was deduced (INFERRED).

STRUCTURED OUTPUT FORMAT:
You must respond with a JSON object strictly matching this schema:
{
    "reasoning_summary": "<Concise 1-2 sentence explanation of your security hypothesis and reasoning>",
    "next_action": "<Description of the specific active probe or verification experiment>",
    "tool": "<tool_name>",
    "arguments": { <tool arguments> }
}
"""


def build_audit_prompt(
    session: AuditSession,
    tools_description: str,
    repetition_warning: Optional[str] = None,
    untested_endpoints: Optional[list[str]] = None
) -> str:
    """Builds a rich context prompt representing the active state of the audit session."""
    discovered = session.context_data.get("discovered_endpoints", [])
    endpoint_methods = session.context_data.get("endpoint_methods", {})
    active_token = bool(session.context_data.get("active_token"))
    active_user = session.context_data.get("active_user", "anonymous")
    baselines = session.context_data.get("baselines", {})

    # Format recent observations (last 3 for context)
    obs_lines = []
    for obs in session.observations[-3:]:
        obs_lines.append(f"[Step {obs.step}] Tool '{obs.tool}' on '{obs.target}':")
        obs_lines.append(f"  Summary: {obs.summary}")
        if obs.key_insights:
            obs_lines.append(f"  Insights: {'; '.join(obs.key_insights[:3])}")

    recent_obs_str = "\n".join(obs_lines) if obs_lines else "No observations yet."

    # Format recent actions performed to discourage repetition
    recent_actions = []
    for att in session.attack_attempts[-4:]:
        recent_actions.append(f"- Step {att.step}: {att.tool} -> {att.target} ({att.action_summary}) => {att.result}")
    actions_str = "\n".join(recent_actions) if recent_actions else "No attack attempts logged yet."

    # Baselines summary
    baseline_lines = []
    for p, b in baselines.items():
        baseline_lines.append(f"- {p}: Mean {b.get('mean_latency_ms', 0)}ms, Status: {b.get('status_distribution', {})}")
    baselines_str = "\n".join(baseline_lines) if baseline_lines else "None established yet. Consider 'measure_baseline' before pressure or injection tests."

    # Current hypothesis
    current_hypo = session.get_current_hypothesis()
    if current_hypo:
        hypo_details = (
            f"ID: {current_hypo.id}\n"
            f"  Category: {current_hypo.category.value}\n"
            f"  Target: {current_hypo.target_endpoint}\n"
            f"  Status: {current_hypo.status.value}\n"
            f"  Confidence: {current_hypo.confidence.value}\n"
            f"  Description: {current_hypo.description}\n"
            f"  Security Question: {current_hypo.security_question or 'N/A'}\n"
            f"  Attempts/Stagnation: {current_hypo.attempts_count} total attempts ({current_hypo.stagnation_count}/{current_hypo.max_stagnant_attempts} stagnant)\n"
            f"  Prior Observations: {', '.join(current_hypo.previous_observations) if current_hypo.previous_observations else 'None'}"
        )
    else:
        hypo_details = "None active. Formulate a new hypothesis on an untested endpoint or attack family."

    # Active hypotheses summary
    hypo_summary_lines = []
    for h in session.hypotheses:
        hypo_summary_lines.append(f"- [{h.status.value}] {h.category.value} on {h.target_endpoint}: {h.description}")
    hypo_summary_str = "\n".join(hypo_summary_lines) if hypo_summary_lines else "None currently registered."

    # Confirmed findings
    finding_lines = []
    for f in session.findings:
        finding_lines.append(f"- [{f.finding_type.value if hasattr(f, 'finding_type') else 'VULNERABILITY'}] [{f.severity.value}] {f.title} ({f.affected_endpoint}) - Status: {f.status.value} (Evidence: {len(f.evidence)})")
    findings_str = "\n".join(finding_lines) if finding_lines else "No findings confirmed yet."

    # Repetition alert
    rep_alert = ""
    if repetition_warning:
        rep_alert = f"\n⚠️ REPETITION / PIVOT ALERT:\n{repetition_warning}\nChoose a DIFFERENT tool, a different endpoint, or a different experiment.\n"
    elif session.repeated_actions_prevented > 0:
        rep_alert = f"\n⚠️ NOTE: {session.repeated_actions_prevented} duplicate actions have been blocked. Ensure your next action is unique.\n"

    # Untested endpoints and recommended attack families
    untested_str = ""
    if untested_endpoints:
        recs = []
        for ep in untested_endpoints[:5]:
            method = endpoint_methods.get(ep, "GET")
            families = [f.value for f in recommend_attack_family(ep)[:3]]
            recs.append(f"{method} {ep} [Recommended attacks: {', '.join(families)}]")
        untested_str = f"- Untested Candidate Surfaces & Vectors:\n  " + "\n  ".join(recs) + "\n"

    # Format discovered list with methods
    discovered_list_str = ""
    if discovered:
        disc_items = []
        for ep in discovered[:15]:
            m = endpoint_methods.get(ep, "GET")
            disc_items.append(f"{m} {ep}")
        discovered_list_str = ", ".join(disc_items)
    else:
        discovered_list_str = "NONE (Run discover_http_surface first)"

    # Phase-specific guidance
    phase_guidance = ""
    if session.current_phase == AuditPhase.RECON:
        if discovered:
            phase_guidance = "Surface already discovered. Advance immediately to HYPOTHESIS/TEST. Do not call discover_http_surface again."
        else:
            phase_guidance = "Call 'discover_http_surface' to identify application routes."
    elif session.current_phase in (AuditPhase.HYPOTHESIS, AuditPhase.TEST):
        if untested_endpoints:
            first_untested = untested_endpoints[0]
            first_m = endpoint_methods.get(first_untested, "GET")
            phase_guidance = (
                f"Target an untested candidate surface (e.g. {first_m} {first_untested}) using an active test tool "
                "(test_idempotency for mutations, concurrency_test for shared state, inject_failure for simulation/worker routes, "
                "or measure_baseline/send_http_request)."
            )
        else:
            phase_guidance = (
                "Select an active testing probe (test_idempotency, concurrency_test, inject_failure, "
                "measure_baseline, send_http_request, pressure_test) against a target endpoint to test the hypothesis."
            )
    elif session.current_phase == AuditPhase.VERIFY:
        phase_guidance = "An anomaly or degradation was detected! Verify whether this is a genuine reproducible finding using compare_responses, verification requests, or recovery checks."
    elif session.current_phase == AuditPhase.EVIDENCE:
        phase_guidance = "Vulnerability or resilience defect empirically verified! Call 'record_evidence' with title, finding_type, category, severity, description, causal_chain, and remediation."
    else:
        phase_guidance = "Proceed with active testing or invoke 'finish_audit' if all interesting surfaces have been evaluated."

    prompt = f"""
AUDIT SESSION STATE:
- Session ID: {session.id}
- Target Base URL: {session.target.base_url}
- Permitted Hosts: {session.target.allowed_hosts}
- Current Phase: {session.current_phase.value}
- Step: {session.step_count} / {session.max_steps}
- Active User Context: {active_user} (HasToken: {active_token})
- Discovered Endpoints & Methods ({len(discovered)}):
  {discovered_list_str}
{untested_str}{rep_alert}
CURRENT ACTIVE HYPOTHESIS:
{hypo_details}

ACTIVE HYPOTHESES LIST:
{hypo_summary_str}

ESTABLISHED BASELINES:
{baselines_str}

RECENT ACTIONS LOGGED:
{actions_str}

RECENT OBSERVATIONS:
{recent_obs_str}

CONFIRMED FINDINGS SO FAR:
{findings_str}

PHASE GUIDANCE:
{phase_guidance}

AVAILABLE TOOLS:
{tools_description}

Based on the evidence, current hypothesis, and phase guidance, decide your next action in structured JSON format.
Select endpoints exclusively from Discovered Endpoints list.
"""
    return prompt.strip()
