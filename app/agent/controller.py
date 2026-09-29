import logging
import json
from typing import Callable, Optional, Any
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.target import Target
from app.models.decision import AgentDecision
from app.models.adapter import LocalModel, ModelFactory
from app.models.hypothesis import Hypothesis, HypothesisStatus
from app.models.finding import FindingCategory, Confidence
from app.models.observation import Observation
from app.tools.registry import ToolRegistry
from app.agent.prompts import SYSTEM_PROMPT, build_audit_prompt

from app.evidence.store import EvidenceStore
from app.models.metrics import ActionRecord, AuditMetrics

logger = logging.getLogger("stressx.agent.controller")


class AgentController:
    """Orchestrates an autonomous security audit session through dynamic reasoning loops."""

    def __init__(
        self,
        target: Target,
        model: Optional[LocalModel] = None,
        tool_registry: Optional[ToolRegistry] = None,
        max_steps: int = 30,
        step_callback: Optional[Callable[[int, AgentDecision, Any], None]] = None,
        evidence_store: Optional[EvidenceStore] = None
    ):
        self.session = AuditSession(target=target, max_steps=max_steps)
        self.model = model or ModelFactory.get_model()
        self.tools = tool_registry or ToolRegistry()
        self.step_callback = step_callback
        self.evidence_store = evidence_store or EvidenceStore()
        self._executed_actions: dict[str, str] = {}
        self._repetition_warning: Optional[str] = None

    async def run_audit(self) -> AuditSession:
        """Executes the autonomous audit feedback loop to completion."""
        logger.info(f"Starting StressX autonomous security audit against {self.session.target.base_url}")
        self.session.status = SessionStatus.RECON
        self.session.set_phase(AuditPhase.RECON)

        while self.session.status not in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.TIMED_OUT):
            if self.session.step_count >= self.session.max_steps:
                logger.warning(f"Reached max steps limit ({self.session.max_steps}). Finalizing session.")
                self.session.complete(SessionStatus.TIMED_OUT)
                break

            self.session.step_count += 1
            step_idx = self.session.step_count

            # 1. Synthesize context prompt with current phase and repetition alerts
            tools_desc = self.tools.get_tools_prompt_description()
            state_prompt = build_audit_prompt(
                self.session,
                tools_desc,
                repetition_warning=self._repetition_warning
            )

            # 2. Query model for structured decision
            try:
                decision: AgentDecision = self.model.generate_structured(
                    prompt=state_prompt,
                    response_schema=AgentDecision,
                    system=SYSTEM_PROMPT
                )
            except Exception as e:
                logger.error(f"Failed to generate structured decision at step {step_idx}: {e}")
                self.session.context_data["error_message"] = str(e)
                self.session.complete(SessionStatus.FAILED)
                break

            logger.info(
                f"[Step {step_idx} | Phase: {self.session.current_phase.value}] "
                f"Tool: '{decision.tool}' | Intent: {decision.next_action} | "
                f"Reasoning: {decision.reasoning_summary}"
            )

            # 3. Dynamic hypothesis registration if reasoning implies new hypothesis
            self._update_hypotheses_from_decision(decision)

            # 4. Check for and prevent repetitive actions
            is_repetition, blocked_observation = self._check_and_prevent_repetition(decision, step_idx)

            if is_repetition and blocked_observation:
                observation = blocked_observation
            else:
                # Execute tool
                observation = await self.tools.execute_tool(
                    tool_name=decision.tool,
                    session=self.session,
                    arguments=decision.arguments
                )
                # Store observation fingerprint
                fp = self._compute_action_fingerprint(decision.tool, decision.arguments)
                self._executed_actions[fp] = observation.summary

            # 5. Record observation
            self.session.add_observation(observation)

            # 6. Advance hypothesis lifecycle and audit phase
            self._advance_phase_and_hypothesis(decision, observation)

            # 7. Action-level logging to actions.jsonl
            try:
                target_val = (
                    decision.arguments.get("path")
                    or decision.arguments.get("endpoint")
                    or decision.arguments.get("url")
                    or observation.target
                    or self.session.target.base_url
                )
                method_val = decision.arguments.get("method") or observation.raw_data.get("method")
                status_code_val = observation.raw_data.get("status_code")
                latency_val = observation.raw_data.get("elapsed_ms") or observation.raw_data.get("latency_ms")
                is_failed = "error" in observation.raw_data or observation.summary.startswith("Execution Error") or "BLOCKED" in observation.summary

                # Find associated hypothesis if any
                hypo_id = None
                for h in self.session.hypotheses:
                    if h.target_endpoint and target_val and h.target_endpoint in str(target_val):
                        hypo_id = h.id
                        break

                action = ActionRecord(
                    audit_id=self.session.id,
                    step=step_idx,
                    tool=decision.tool,
                    intent=decision.next_action,
                    target=str(target_val) if target_val else None,
                    method=str(method_val).upper() if method_val else None,
                    status_code=int(status_code_val) if status_code_val is not None else None,
                    latency_ms=float(latency_val) if latency_val is not None else None,
                    hypothesis_id=hypo_id,
                    outcome="FAILED" if is_failed else "SUCCESS",
                    success=not is_failed,
                    summary=observation.summary
                )
                self.evidence_store.log_action(action)
            except Exception as act_err:
                logger.debug(f"Action logging error: {act_err}")

            # 8. Notify callback (CLI / API streaming)
            if self.step_callback:
                try:
                    self.step_callback(step_idx, decision, observation)
                except Exception as cb_err:
                    logger.debug(f"Step callback error: {cb_err}")

            # 9. Check if audit concluded
            if decision.tool == "finish_audit" or self.session.status == SessionStatus.COMPLETED:
                self.session.complete(SessionStatus.COMPLETED)
                break

        # Ensure session completion timestamp is recorded
        if not self.session.end_time:
            self.session.complete(
                self.session.status
                if self.session.status in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.TIMED_OUT)
                else SessionStatus.COMPLETED
            )

        # Save complete audit dossier (metrics.json, actions.jsonl, findings.json, evidence.json, report.json, report.md)
        try:
            self.evidence_store.save_audit_dossier(self.session)
        except Exception as save_err:
            logger.error(f"Error persisting audit dossier: {save_err}")

        logger.info(
            f"Audit finished. Total findings: {len(self.session.findings)} | "
            f"Attempts: {len(self.session.attack_attempts)} | "
            f"Repetitions prevented: {self.session.repeated_actions_prevented}"
        )
        return self.session

    def _compute_action_fingerprint(self, tool: str, arguments: dict[str, Any]) -> str:
        """Generates a normalized signature for tool actions to detect identical repetitions."""
        tool_clean = tool.strip().lower()
        target_val = (
            arguments.get("path")
            or arguments.get("endpoint")
            or arguments.get("url")
            or arguments.get("target_endpoint")
            or ""
        )
        target_norm = str(target_val).strip().lower()
        method = str(arguments.get("method") or "GET").upper()

        stable_args = {
            k: v for k, v in sorted(arguments.items())
            if k not in ("summary", "rationale", "reasoning", "description")
        }
        args_json = json.dumps(stable_args, sort_keys=True)
        return f"{tool_clean}|{method}|{target_norm}|{args_json}"

    def _check_and_prevent_repetition(self, decision: AgentDecision, step_idx: int) -> tuple[bool, Optional[Observation]]:
        """Prevents the agent from executing identical actions repeatedly."""
        tool = decision.tool
        target_val = (
            decision.arguments.get("path")
            or decision.arguments.get("endpoint")
            or decision.arguments.get("url")
            or decision.arguments.get("target_endpoint")
            or ""
        )

        # 1. Prevent repeat reconnaissance if surface is already known
        discovered = self.session.context_data.get("discovered_endpoints", [])
        if tool == "discover_http_surface" and len(discovered) > 0:
            self.session.repeated_actions_prevented += 1
            obs = Observation(
                step=step_idx,
                tool=tool,
                target=self.session.target.base_url,
                summary="REPETITION PREVENTED: Reconnaissance already complete. Attack surface is known. You must advance to active testing.",
                key_insights=[
                    "Surface is already mapped.",
                    "Select an active test action (send_http_request, manage_test_session) against a discovered endpoint."
                ],
                raw_data={"repetition_prevented": True, "duplicate_tool": tool}
            )
            self._repetition_warning = "Reconnaissance already finished. Do NOT call discover_http_surface again. Formulate a hypothesis and test an endpoint."
            self.session.set_phase(AuditPhase.HYPOTHESIS)
            return True, obs

        # 2. Prevent repeated identical tool calls
        fp = self._compute_action_fingerprint(tool, decision.arguments)
        if fp in self._executed_actions:
            self.session.repeated_actions_prevented += 1
            obs = Observation(
                step=step_idx,
                tool=tool,
                target=str(target_val) if target_val else self.session.target.base_url,
                summary=(
                    f"REPETITION PREVENTED: Action '{tool}' on '{target_val}' with identical arguments was already executed. "
                    "Repeating this action yields no new information."
                ),
                key_insights=[
                    f"Duplicate '{tool}' call blocked by repetition guard.",
                    "Select a different active testing probe, update hypothesis, test another endpoint, or record evidence."
                ],
                raw_data={"repetition_prevented": True, "duplicate_tool": tool, "target": str(target_val)}
            )
            self._repetition_warning = (
                f"Action '{tool}' on '{target_val}' was blocked due to identical repetition. "
                "Choose a DIFFERENT active probe, test another endpoint, or advance to verify/evidence."
            )
            if tool == "inspect_http_response":
                self.session.set_phase(AuditPhase.HYPOTHESIS)
            return True, obs

        self._repetition_warning = None
        return False, None

    def _advance_phase_and_hypothesis(self, decision: AgentDecision, observation: Observation) -> None:
        """Progresses audit phases and updates hypothesis status based on runtime perception."""
        tool = decision.tool
        raw = observation.raw_data or {}
        summary_lower = observation.summary.lower()
        target_str = str(observation.target or "").lower()

        # Phase 1: RECON completion
        if self.session.current_phase == AuditPhase.RECON:
            endpoints = self.session.context_data.get("discovered_endpoints", [])
            if endpoints or tool == "discover_http_surface":
                self.session.set_phase(AuditPhase.HYPOTHESIS)
            return

        current_hypo = self.session.get_current_hypothesis()
        if current_hypo:
            current_hypo.add_observation(f"Step {observation.step} ({tool}): {observation.summary}")

        # Phase 6: EVIDENCE completion
        if tool == "record_evidence":
            if current_hypo:
                current_hypo.update_status(HypothesisStatus.SUPPORTED, "Empirical evidence recorded.")
            # Move to formulate next hypothesis or complete
            self.session.set_phase(AuditPhase.HYPOTHESIS)
            return

        # Phase 3-5: Active testing & verification
        if tool in ("send_http_request", "manage_test_session", "compare_responses", "inspect_http_response"):
            has_anomaly = (
                "sql" in summary_lower or "syntax error" in summary_lower
                or "disclosed" in summary_lower or "leaked" in summary_lower or "leak" in summary_lower
                or "idor" in summary_lower or "unauthorized access" in summary_lower or "bypass" in summary_lower
                or "anomaly" in summary_lower or "different" in summary_lower
                or raw.get("status_code") == 500
                or (raw.get("status_code") == 200 and ("env" in target_str or "debug" in target_str))
            )

            if tool == "compare_responses" and (raw.get("status_diff") or raw.get("body_diff_length", 0) > 0 or has_anomaly):
                self.session.set_phase(AuditPhase.EVIDENCE)
                if current_hypo:
                    current_hypo.confidence = Confidence.HIGH
                    current_hypo.update_status(HypothesisStatus.TESTING, "Differential comparison confirmed vulnerability.")
            elif has_anomaly:
                # Anomaly detected -> advance to VERIFY
                self.session.set_phase(AuditPhase.VERIFY)
                if current_hypo:
                    current_hypo.update_status(HypothesisStatus.TESTING, "Observed anomalous response. Verification required.")
            else:
                if "404" in summary_lower or "not found" in summary_lower:
                    if current_hypo:
                        current_hypo.update_status(HypothesisStatus.REJECTED, "Target endpoint returned 404.")
                    self.session.set_phase(AuditPhase.HYPOTHESIS)
                else:
                    self.session.set_phase(AuditPhase.TEST)

    def _update_hypotheses_from_decision(self, decision: AgentDecision) -> None:
        """Derives and tracks test hypotheses based on agent intent."""
        action_lower = decision.next_action.lower()
        reasoning_lower = decision.reasoning_summary.lower()

        category = None
        if "sql" in action_lower or "sql" in reasoning_lower or "injection" in action_lower:
            category = FindingCategory.UNSAFE_INPUT_HANDLING
        elif "idor" in action_lower or "authorization" in reasoning_lower or "horizontal" in reasoning_lower or "profile" in action_lower:
            category = FindingCategory.AUTHORIZATION
        elif "debug" in action_lower or "leak" in reasoning_lower or "credential" in reasoning_lower or "env" in action_lower:
            category = FindingCategory.INFORMATION_DISCLOSURE
        elif "admin" in action_lower or "privilege" in reasoning_lower:
            category = FindingCategory.AUTHORIZATION
        elif "resource" in action_lower or "exhaustion" in reasoning_lower or "batch" in action_lower:
            category = FindingCategory.RESOURCE_EXHAUSTION
        elif "auth" in action_lower or "login" in action_lower:
            category = FindingCategory.AUTHENTICATION

        if category:
            target_val = decision.arguments.get("path") or decision.arguments.get("endpoint") or "/unknown"
            from urllib.parse import urlparse
            endpoint = urlparse(str(target_val)).path or str(target_val)
            exists = any(h.category == category and h.target_endpoint == endpoint for h in self.session.hypotheses)
            if not exists:
                hypo = Hypothesis(
                    category=category,
                    description=decision.next_action,
                    target_endpoint=endpoint,
                    status=HypothesisStatus.FORMULATED,
                    rationale=decision.reasoning_summary,
                    confidence=Confidence.LOW
                )
                self.session.add_hypothesis(hypo)
