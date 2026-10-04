import logging
import json
from typing import Callable, Optional, Any
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.target import Target
from app.models.decision import AgentDecision
from app.models.adapter import LocalModel, ModelFactory
from app.models.hypothesis import Hypothesis, HypothesisStatus
from app.models.finding import FindingCategory, Confidence, FindingStatus
from app.models.observation import Observation
from app.tools.registry import ToolRegistry
from app.agent.prompts import SYSTEM_PROMPT, build_audit_prompt

from app.evidence.store import EvidenceStore
from app.models.metrics import ActionRecord, AuditMetrics
from app.models.config import AuditConfig
from app.api.events import EVENT_MANAGER, AuditEventType

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
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[AuditConfig] = None
    ):
        self.config = config
        effective_steps = max_steps
        if config:
            effective_steps = config.selected_steps or config.max_steps

        self.session = AuditSession(target=target, max_steps=effective_steps)
        if config and config.audit_id:
            self.session.id = config.audit_id

        self.model = model or ModelFactory.get_model()
        self.tools = tool_registry or ToolRegistry()
        self.step_callback = step_callback
        self.evidence_store = evidence_store or EvidenceStore()
        self._executed_actions: dict[str, str] = {}
        self._repetition_warning: Optional[str] = None
        self._stop_requested: bool = False
        self._known_endpoints: set[str] = set()
        self._known_findings: set[str] = set()

    def request_stop(self) -> None:
        """Signals the controller to gracefully stop after completing the current step."""
        logger.info(f"Stop requested for audit session {self.session.id}")
        self._stop_requested = True

    async def run_audit(self) -> AuditSession:
        """Executes the autonomous audit feedback loop to completion."""
        logger.info(f"Starting StressX autonomous security audit against {self.session.target.base_url}")
        self.session.status = SessionStatus.RECON
        self.session.set_phase(AuditPhase.RECON)

        await EVENT_MANAGER.emit(
            audit_id=self.session.id,
            event_type=AuditEventType.AUDIT_STARTED,
            data={
                "audit_id": self.session.id,
                "target": self.session.target.base_url,
                "max_steps": self.session.max_steps,
                "phase": self.session.current_phase.value
            },
            summary=f"Audit initiated against {self.session.target.base_url} with max budget {self.session.max_steps} steps."
        )

        while self.session.status not in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.TIMED_OUT):
            if self._stop_requested:
                logger.info(f"Graceful stop requested for session {self.session.id}. Completing audit.")
                self.session.context_data["stop_reason"] = "USER_STOP_REQUESTED"
                self.session.complete(SessionStatus.COMPLETED)
                await EVENT_MANAGER.emit(
                    audit_id=self.session.id,
                    event_type=AuditEventType.AUDIT_STOPPED,
                    data={
                        "step": self.session.step_count,
                        "findings_count": len(self.session.findings),
                        "reason": "USER_STOP_REQUESTED"
                    },
                    summary="Audit stopped gracefully by user request."
                )
                break

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
                repetition_warning=self._repetition_warning,
                untested_endpoints=self.get_untested_endpoints()
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

            # Emit tool started event
            await EVENT_MANAGER.emit(
                audit_id=self.session.id,
                event_type=AuditEventType.TOOL_STARTED,
                data={
                    "step": step_idx,
                    "tool": decision.tool,
                    "intent": decision.next_action,
                    "arguments": decision.arguments,
                    "reasoning_summary": decision.reasoning_summary,
                    "phase": self.session.current_phase.value
                },
                summary=f"Step {step_idx}: AI launching '{decision.tool}' — {decision.next_action}"
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

            # Emit tool completed event
            await EVENT_MANAGER.emit(
                audit_id=self.session.id,
                event_type=AuditEventType.TOOL_COMPLETED,
                data={
                    "step": step_idx,
                    "tool": decision.tool,
                    "summary": observation.summary,
                    "status_code": observation.raw_data.get("status_code"),
                    "key_insights": observation.key_insights,
                    "target": observation.target
                },
                summary=f"Step {step_idx}: Completed '{decision.tool}' -> {observation.summary[:120]}"
            )

            # 6. Advance hypothesis lifecycle and audit phase
            prev_phase = self.session.current_phase
            self._advance_phase_and_hypothesis(decision, observation)
            if self.session.current_phase != prev_phase:
                await EVENT_MANAGER.emit(
                    audit_id=self.session.id,
                    event_type=AuditEventType.PHASE_CHANGED,
                    data={"from_phase": prev_phase.value, "to_phase": self.session.current_phase.value},
                    summary=f"Audit phase changed to {self.session.current_phase.value}"
                )

            # Check for newly discovered endpoints
            current_discovered = set(self.session.context_data.get("discovered_endpoints", []))
            new_endpoints = current_discovered - self._known_endpoints
            if new_endpoints:
                self._known_endpoints.update(new_endpoints)
                await EVENT_MANAGER.emit(
                    audit_id=self.session.id,
                    event_type=AuditEventType.ENDPOINT_DISCOVERED,
                    data={
                        "new_endpoints": list(new_endpoints),
                        "total_endpoints": len(self._known_endpoints)
                    },
                    summary=f"Discovered {len(new_endpoints)} new attack surface endpoint(s)."
                )

            # Check for newly confirmed findings
            for finding in self.session.findings:
                if finding.id not in self._known_findings:
                    self._known_findings.add(finding.id)
                    if finding.status == FindingStatus.CONFIRMED:
                        await EVENT_MANAGER.emit(
                            audit_id=self.session.id,
                            event_type=AuditEventType.FINDING_CONFIRMED,
                            data={
                                "id": finding.id,
                                "title": finding.title,
                                "severity": finding.severity.value,
                                "confidence": finding.confidence.value,
                                "affected_endpoint": finding.affected_endpoint,
                                "description": finding.description,
                                "impact": finding.impact,
                                "remediation": finding.remediation,
                                "causal_chain": finding.causal_chain,
                                "evidence_count": len(finding.evidence)
                            },
                            summary=f"Confirmed finding: [{finding.severity.value}] {finding.title}"
                        )

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

            # Emit step completed event
            await EVENT_MANAGER.emit(
                audit_id=self.session.id,
                event_type=AuditEventType.STEP_COMPLETED,
                data={
                    "step": step_idx,
                    "max_steps": self.session.max_steps,
                    "phase": self.session.current_phase.value,
                    "findings_count": len(self.session.findings),
                    "hypotheses_count": len(self.session.hypotheses)
                },
                summary=f"Step {step_idx}/{self.session.max_steps} completed."
            )

            # 8. Notify callback (CLI / API streaming)
            if self.step_callback:
                try:
                    self.step_callback(step_idx, decision, observation)
                except Exception as cb_err:
                    logger.debug(f"Step callback error: {cb_err}")

            # 9. Check if user requested stop after step execution
            if self._stop_requested:
                logger.info(f"Stop requested for audit session {self.session.id}. Gracefully completing.")
                self.session.context_data["stop_reason"] = "USER_STOP_REQUESTED"
                self.session.complete(SessionStatus.COMPLETED)
                await EVENT_MANAGER.emit(
                    audit_id=self.session.id,
                    event_type=AuditEventType.AUDIT_STOPPED,
                    data={
                        "step": step_idx,
                        "findings_count": len(self.session.findings),
                        "reason": "USER_STOP_REQUESTED"
                    },
                    summary="Audit stopped gracefully by user request."
                )
                break

            # 10. Early completion check: if surfaces evaluated and no hypotheses active
            untested_eps = self.get_untested_endpoints()
            active_hypos = [h for h in self.session.hypotheses if h.status in (HypothesisStatus.FORMULATED, HypothesisStatus.TESTING)]
            if step_idx >= 5 and not untested_eps and not active_hypos and len(self._known_endpoints) > 0:
                logger.info(f"Early completion for session {self.session.id}: all discovered surfaces tested and hypotheses resolved.")
                self.session.complete(SessionStatus.COMPLETED)
                break

            # 11. Check if audit concluded explicitly
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

        # Emit audit completed event
        await EVENT_MANAGER.emit(
            audit_id=self.session.id,
            event_type=AuditEventType.AUDIT_COMPLETED,
            data={
                "audit_id": self.session.id,
                "status": self.session.status.value,
                "total_steps": self.session.step_count,
                "findings_count": len(self.session.findings),
                "duration_seconds": self.session.duration_seconds
            },
            summary=f"Audit completed with {len(self.session.findings)} finding(s) across {self.session.step_count} step(s)."
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

        # 2. Prevent repeated passive inspect_http_response on the same endpoint
        if tool == "inspect_http_response":
            inspected_targets = [
                str(att.target).lower() for att in self.session.attack_attempts if att.tool == "inspect_http_response"
            ]
            if str(target_val).lower() in inspected_targets:
                self.session.repeated_actions_prevented += 1
                obs = Observation(
                    step=step_idx,
                    tool=tool,
                    target=str(target_val),
                    summary=f"PASSIVE INSPECTION LOOP PREVENTED: Header inspection of '{target_val}' already performed. Advance to active attack testing.",
                    key_insights=["Do not perform repeated passive inspections."],
                    raw_data={"repetition_prevented": True, "duplicate_tool": tool}
                )
                self._repetition_warning = f"Endpoint '{target_val}' was already inspected. Select an active test probe (send_http_request, test_idempotency, concurrency_test)."
                self.session.set_phase(AuditPhase.HYPOTHESIS)
                return True, obs

        # 3. Prevent retrying paths previously discovered to be 404 or 405
        bad_paths = self.session.context_data.get("disallowed_or_404_paths", [])
        if target_val and any(bp == str(target_val) for bp in bad_paths):
            self.session.repeated_actions_prevented += 1
            obs = Observation(
                step=step_idx,
                tool=tool,
                target=str(target_val),
                summary=f"INVALID TARGET BLOCKED: Endpoint '{target_val}' returned 404 Not Found or 405 Method Not Allowed in prior attempts.",
                key_insights=[f"'{target_val}' is not a viable attack target.", "Pivot to a valid discovered surface."],
                raw_data={"repetition_prevented": True, "duplicate_tool": tool}
            )
            self._repetition_warning = f"Target '{target_val}' is invalid (404/405). Pivot to a discovered endpoint."
            self.session.set_phase(AuditPhase.HYPOTHESIS)
            return True, obs

        # 4. Prevent repeated identical tool calls
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

    def get_untested_endpoints(self) -> list[str]:
        """Identifies discovered endpoints that have not yet been evaluated, prioritized by attack value."""
        all_discovered = self.session.context_data.get("discovered_endpoints", [])
        from urllib.parse import urlparse
        
        tested_paths = set()
        for att in self.session.attack_attempts:
            path = urlparse(str(att.target)).path
            if path:
                tested_paths.add(path)
                
        for h in self.session.hypotheses:
            if h.target_endpoint:
                tested_paths.add(urlparse(str(h.target_endpoint)).path)
                
        untested = [ep for ep in all_discovered if ep not in tested_paths and urlparse(ep).path not in tested_paths]
        
        def priority_score(ep: str) -> int:
            ep_l = ep.lower()
            # Mutation / business logic / worker surfaces
            if any(k in ep_l for k in ["tasks", "workers", "operator", "failures", "simulate", "cache"]):
                return 10
            if any(k in ep_l for k in ["debug", "env", "config", "diagnostics"]):
                return 8
            if any(k in ep_l for k in ["auth", "login", "token", "session"]):
                return 7
            if any(k in ep_l for k in ["user", "profile", "account", "roles"]):
                return 6
            if any(k in ep_l for k in ["search", "query", "filter"]):
                return 5
            if any(k in ep_l for k in ["status", "info", "health", "metrics"]):
                return 3
            return 1

        untested.sort(key=priority_score, reverse=True)
        return untested

    def _advance_phase_and_hypothesis(self, decision: AgentDecision, observation: Observation) -> None:
        """Progresses audit phases and updates hypothesis status based on runtime perception."""
        tool = decision.tool
        raw = observation.raw_data or {}
        summary_lower = observation.summary.lower()
        target_str = str(observation.target or "").lower()
        body_str = str(raw.get("body", "")).lower()
        status_code = raw.get("status_code")

        # Phase 1: RECON completion
        if self.session.current_phase == AuditPhase.RECON:
            endpoints = self.session.context_data.get("discovered_endpoints", [])
            if endpoints or tool == "discover_http_surface":
                self.session.set_phase(AuditPhase.HYPOTHESIS)
            if tool == "discover_http_surface":
                return

        current_hypo = self.session.get_current_hypothesis()
        if current_hypo:
            current_hypo.add_observation(f"Step {observation.step} ({tool}): {observation.summary}")

        # Phase 6: EVIDENCE completion
        if tool == "record_evidence":
            if current_hypo:
                if "confirmed" in observation.summary.lower() or raw.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                    current_hypo.update_status(HypothesisStatus.SUPPORTED, "Empirical evidence recorded.")
                else:
                    current_hypo.update_status(HypothesisStatus.INCONCLUSIVE, "Recorded evidence was unconfirmed/inconclusive.")
                self.session.current_hypothesis_id = None
            # Move to formulate next hypothesis or complete
            self.session.set_phase(AuditPhase.HYPOTHESIS)
            return

        # Phase 3-5: Active testing & verification
        active_eval_tools = (
            "send_http_request", "manage_test_session", "compare_responses",
            "inspect_http_response", "measure_baseline", "pressure_test", "concurrency_test",
            "test_idempotency", "inject_failure"
        )
        if tool in active_eval_tools:
            # Check for non-existent or disallowed routes (404/405)
            if status_code in (404, 405) or "404" in summary_lower or "not found" in summary_lower:
                target_val = decision.arguments.get("path") or decision.arguments.get("endpoint") or observation.target
                if target_val:
                    bad = self.session.context_data.setdefault("disallowed_or_404_paths", [])
                    if str(target_val) not in bad:
                        bad.append(str(target_val))

                if current_hypo:
                    current_hypo.record_attempt(
                        attempt_id=f"step_{observation.step}",
                        produced_evidence=False,
                        summary=observation.summary,
                        status_code=status_code
                    )
                    self.session.current_hypothesis_id = None
                self.session.set_phase(AuditPhase.HYPOTHESIS)
                untested = self.get_untested_endpoints()
                candidate_str = f" Try: {untested[0]}" if untested else ""
                self._repetition_warning = f"Endpoint returned HTTP {status_code or 404}. PIVOTING: Formulate hypothesis on a valid surface.{candidate_str}"
                return

            # Check for actual security evidence (HTTP status alone does NOT establish a vulnerability)
            has_db_syntax = any(sig in body_str for sig in [
                "syntax error", "sqlite3", "psycopg2", "mysql", "operationalerror",
                "traceback (most recent call last)", "unclosed quotation mark", "sql syntax"
            ])
            has_secret_leak = (
                (status_code == 200 and ("env" in target_str or "debug" in target_str or "diagnostics" in target_str))
                or any(sig in body_str for sig in ["secret_key", "db_password", "database_url", "aws_secret", "private_key"])
            )
            has_auth_anomaly = (
                "idor" in summary_lower
                or "unauthorized access" in summary_lower
                or "bypass" in summary_lower
                or ("profile" in target_str and status_code == 200 and "alice" not in body_str and "bob" in body_str)
            )
            has_differential = (
                tool == "compare_responses"
                and (raw.get("status_diff") or raw.get("body_diff_length", 0) > 0)
            )
            has_idempotency_finding = bool(raw.get("findings_suggested"))
            has_resilience_anomaly = (
                (tool in ("pressure_test", "concurrency_test") and (raw.get("degradation_detected") or raw.get("race_condition_detected") or raw.get("rate_limit_detected")))
                or (tool in ("test_idempotency", "inject_failure") and has_idempotency_finding)
            )

            has_genuine_anomaly = has_db_syntax or has_secret_leak or has_auth_anomaly or has_differential or has_resilience_anomaly

            # Stagnation tracking: Does this attempt provide new security evidence?
            if current_hypo:
                is_stagnant = current_hypo.record_attempt(
                    attempt_id=f"step_{observation.step}",
                    produced_evidence=has_genuine_anomaly or tool == "measure_baseline",
                    summary=f"Step {observation.step} ({tool}): {observation.summary}",
                    status_code=status_code
                )
                if is_stagnant:
                    current_hypo.terminate(
                        HypothesisStatus.INCONCLUSIVE,
                        f"Stagnation detected: {current_hypo.stagnation_count} attempts failed to yield new security evidence."
                    )
                    self.session.current_hypothesis_id = None
                    self.session.set_phase(AuditPhase.HYPOTHESIS)
                    untested = self.get_untested_endpoints()
                    candidate_hint = f" Pivot to: {untested[0]}." if untested else " Pivot to next untested attack surface."
                    self._repetition_warning = (
                        f"Hypothesis on '{current_hypo.target_endpoint}' STAGNATED after {current_hypo.max_stagnant_attempts} attempts without proof. "
                        f"PIVOTING: Select a different endpoint or attack vector.{candidate_hint}"
                    )
                    return

            if has_differential or has_resilience_anomaly:
                self.session.set_phase(AuditPhase.EVIDENCE)
                if current_hypo:
                    current_hypo.confidence = Confidence.HIGH
                    current_hypo.update_status(HypothesisStatus.TESTING, "Observed verified behavioral divergence / resilience condition.")
            elif has_genuine_anomaly:
                self.session.set_phase(AuditPhase.VERIFY)
                if current_hypo:
                    current_hypo.update_status(HypothesisStatus.TESTING, "Observed genuine security anomaly. Verification required.")
            else:
                self.session.set_phase(AuditPhase.TEST)

    def _update_hypotheses_from_decision(self, decision: AgentDecision) -> None:
        """Derives and tracks test hypotheses based on agent intent."""
        action_lower = decision.next_action.lower()
        reasoning_lower = decision.reasoning_summary.lower()

        category = None
        if "idempotency" in action_lower or "idempotency" in reasoning_lower or "duplicate" in action_lower or decision.tool == "test_idempotency":
            category = FindingCategory.DUPLICATE_OPERATION
        elif "fault" in action_lower or "failure" in action_lower or "recovery" in action_lower or decision.tool == "inject_failure":
            category = FindingCategory.RECOVERY_FAILURE
        elif "sql" in action_lower or "sql" in reasoning_lower or "injection" in action_lower or "inject" in action_lower:
            category = FindingCategory.INJECTION
        elif "rate" in action_lower or "rate" in reasoning_lower or "pressure" in action_lower or "throttle" in action_lower or decision.tool == "pressure_test":
            category = FindingCategory.RATE_LIMITING
        elif "concurren" in action_lower or "race" in action_lower or "deadlock" in action_lower or decision.tool == "concurrency_test":
            category = FindingCategory.CONCURRENCY
        elif "idor" in action_lower or "authorization" in reasoning_lower or "horizontal" in reasoning_lower or "profile" in action_lower or "role" in action_lower:
            category = FindingCategory.AUTHORIZATION
        elif "debug" in action_lower or "leak" in reasoning_lower or "credential" in reasoning_lower or "env" in action_lower or "diagnostics" in action_lower:
            category = FindingCategory.INFORMATION_DISCLOSURE
        elif "admin" in action_lower or "privilege" in reasoning_lower:
            category = FindingCategory.AUTHORIZATION
        elif "validation" in action_lower or "malformed" in action_lower or "boundary" in action_lower:
            category = FindingCategory.INPUT_VALIDATION
        elif "resource" in action_lower or "exhaustion" in reasoning_lower or "payload" in action_lower:
            category = FindingCategory.RESOURCE_EXHAUSTION
        elif "auth" in action_lower or "login" in action_lower:
            category = FindingCategory.AUTHENTICATION
        elif "baseline" in action_lower or decision.tool == "measure_baseline":
            category = FindingCategory.SYSTEM_RESILIENCE
        elif decision.tool in ("send_http_request", "manage_test_session", "compare_responses"):
            category = FindingCategory.API_SECURITY

        if category:
            target_val = decision.arguments.get("path") or decision.arguments.get("endpoint") or "/unknown"
            from urllib.parse import urlparse
            endpoint = urlparse(str(target_val)).path or str(target_val)
            existing = next((h for h in self.session.hypotheses if h.category == category and h.target_endpoint == endpoint), None)
            if not existing:
                hypo = Hypothesis(
                    category=category,
                    description=decision.next_action,
                    target_endpoint=endpoint,
                    status=HypothesisStatus.FORMULATED,
                    rationale=decision.reasoning_summary,
                    confidence=Confidence.LOW,
                    security_question=f"Does {endpoint} expose vulnerabilities under {category.value}?",
                    expected_signal="Observable data disclosure, database syntax error, or authorization difference."
                )
                self.session.add_hypothesis(hypo)
            elif existing.status in (HypothesisStatus.FORMULATED, HypothesisStatus.TESTING):
                self.session.current_hypothesis_id = existing.id
