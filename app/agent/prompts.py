from typing import Optional
from app.models.session import AuditSession, AuditPhase

SYSTEM_PROMPT = """You are StressX, an autonomous ATTACK-FIRST security testing agent.
Your primary objective is active, empirical, hypothesis-driven security testing against a designated target application.

You are NOT a passive vulnerability scanner. Passive inspection is minimal.
Reconnaissance is brief and used solely to discover endpoints. Once endpoints are discovered, you MUST immediately formulate hypotheses and conduct active testing probes.

AUDIT PHASES:
1. RECON: Discover HTTP endpoints. (Brief, 1 step only).
2. HYPOTHESIS: Identify high-value surfaces (e.g. debug leaks, user IDOR, SQL injection, auth endpoints) and formulate testable hypotheses.
3. TEST: Dispatch active, controlled probes using send_http_request or manage_test_session.
4. OBSERVE: Analyze the runtime response (status code, timing, error messages, diffs).
5. VERIFY: When an anomaly or potential weakness is spotted, verify it with a secondary probe (e.g., boolean payload, altered ID, compare_responses).
6. EVIDENCE: If empirically confirmed, invoke 'record_evidence' with exact reproducible details.
7. NEXT HYPOTHESIS / COMPLETE: Pivot to the next endpoint or call 'finish_audit'.

CORE RULES:
1. ACTIVE OVER PASSIVE: Prefer active testing (send_http_request with crafted probes, compare_responses, manage_test_session) over passive inspection.
2. NO REPEATED RECON: Never call 'discover_http_surface' if endpoints are already known.
3. NO PASSIVE LOOPS: Never repeatedly call 'inspect_http_response'. Missing security headers alone are NOT a confirmed vulnerability and do not require repeated probing.
4. REPETITION IS STRICTLY FORBIDDEN: Never send the exact same request with the exact same payload twice. If an attempt is inconclusive or denied (e.g. 401/403), adapt your strategy: authenticate with test credentials, change parameter values, or test a different endpoint.
5. CONFIRMATION REQUIRES RUNTIME EVIDENCE: Every confirmed finding must show real observable behavior (e.g., leaked secrets, database error/manipulation, or unauthorized data access).
6. TARGET BOUNDARIES: Only interact with authorized target routes. Out-of-bounds requests will be rejected.

STRUCTURED OUTPUT FORMAT:
You must respond with a JSON object strictly matching this schema:
{
    "reasoning_summary": "<Concise 1-2 sentence explanation of your security hypothesis and reasoning>",
    "next_action": "<Description of the specific active probe or verification attack>",
    "tool": "<tool_name>",
    "arguments": { <tool arguments> }
}
"""


def build_audit_prompt(
    session: AuditSession,
    tools_description: str,
    repetition_warning: Optional[str] = None
) -> str:
    """Builds a rich context prompt representing the active state of the audit session."""
    discovered = session.context_data.get("discovered_endpoints", [])
    active_token = bool(session.context_data.get("active_token"))
    active_user = session.context_data.get("active_user", "anonymous")

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
            f"  Prior Observations: {', '.join(current_hypo.previous_observations) if current_hypo.previous_observations else 'None'}"
        )
    else:
        hypo_details = "None active. Formulate a new hypothesis on an untested endpoint."

    # Active hypotheses summary
    hypo_summary_lines = []
    for h in session.hypotheses:
        hypo_summary_lines.append(f"- [{h.status.value}] {h.category.value} on {h.target_endpoint}: {h.description}")
    hypo_summary_str = "\n".join(hypo_summary_lines) if hypo_summary_lines else "None currently registered."

    # Confirmed findings
    finding_lines = []
    for f in session.findings:
        finding_lines.append(f"- [{f.severity.value}] {f.title} ({f.affected_endpoint}) - Evidence count: {len(f.evidence)}")
    findings_str = "\n".join(finding_lines) if finding_lines else "No findings confirmed yet."

    # Repetition alert
    rep_alert = ""
    if repetition_warning:
        rep_alert = f"\n⚠️ REPETITION ALERT:\n{repetition_warning}\nChoose a DIFFERENT tool, a different endpoint, or a different probe payload.\n"
    elif session.repeated_actions_prevented > 0:
        rep_alert = f"\n⚠️ NOTE: {session.repeated_actions_prevented} duplicate actions have been blocked. Ensure your next action is unique.\n"

    # Phase-specific guidance
    phase_guidance = ""
    if session.current_phase == AuditPhase.RECON:
        if discovered:
            phase_guidance = "Surface already discovered. Advance immediately to HYPOTHESIS/TEST. Do not call discover_http_surface again."
        else:
            phase_guidance = "Call 'discover_http_surface' to identify application routes."
    elif session.current_phase in (AuditPhase.HYPOTHESIS, AuditPhase.TEST):
        phase_guidance = "Select an active testing probe (send_http_request, manage_test_session) against a target endpoint to test the hypothesis."
    elif session.current_phase == AuditPhase.VERIFY:
        phase_guidance = "An anomaly was detected! Verify whether this is a genuine reproducible vulnerability using compare_responses or a confirmation payload."
    elif session.current_phase == AuditPhase.EVIDENCE:
        phase_guidance = "Vulnerability empirically verified! Call 'record_evidence' with title, severity, category, description, and remediation."
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
- Discovered Endpoints ({len(discovered)}): {', '.join(discovered[:12]) if discovered else 'NONE'}
{rep_alert}
CURRENT ACTIVE HYPOTHESIS:
{hypo_details}

ACTIVE HYPOTHESES LIST:
{hypo_summary_str}

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
"""
    return prompt.strip()
