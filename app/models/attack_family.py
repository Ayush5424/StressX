from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.models.finding import FindingCategory, FindingType


class AttackFamily(str, Enum):
    """Structured and extensible 63-family attack taxonomy for StressX autonomous agent."""

    # 1. SECURITY ATTACKS (1 - 20)
    INFORMATION_DISCLOSURE = "information_disclosure"
    AUTHENTICATION = "authentication"
    CREDENTIAL_ABUSE = "credential_abuse"
    SESSION_TOKEN_ABUSE = "session_token_abuse"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    IDOR_BOLA = "idor_bola"
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    MALFORMED_INPUT = "malformed_input"
    TYPE_CONFUSION = "type_confusion"
    OVERSIZED_INPUT = "oversized_input"
    FILE_UPLOAD_ABUSE = "file_upload_abuse"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    ERROR_DISCLOSURE = "error_disclosure"

    # Backward compatibility aliases
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    INPUT_VALIDATION = "input_validation"
    ERROR_HANDLING = "error_handling"

    # 2. APPLICATION ABUSE ATTACKS (21 - 29)
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    BRUTE_FORCE_SENSITIVITY = "brute_force_sensitivity"
    REPLAY_ATTACK = "replay_attack"
    IDEMPOTENCY_ABUSE = "idempotency_abuse"
    BUSINESS_LOGIC_ABUSE = "business_logic_abuse"
    INVALID_STATE_TRANSITION = "invalid_state_transition"
    DUPLICATE_OPERATION = "duplicate_operation"
    OBJECT_OWNERSHIP_MANIPULATION = "object_ownership_manipulation"
    WORKFLOW_MANIPULATION = "workflow_manipulation"
    RATE_LIMITING = "rate_limiting"

    # 3. SYSTEM AND RESILIENCE ATTACKS (30 - 63)
    CONCURRENCY_RACE = "concurrency_race"
    CONCURRENCY = "concurrency"
    TOCTOU = "toctou"
    DEADLOCK = "deadlock"
    LOCK_CONTENTION = "lock_contention"
    WORKER_SATURATION = "worker_saturation"
    THREAD_POOL_EXHAUSTION = "thread_pool_exhaustion"
    CONNECTION_POOL_EXHAUSTION = "connection_pool_exhaustion"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CPU_EXHAUSTION = "cpu_exhaustion"
    QUEUE_SATURATION = "queue_saturation"
    CONSUMER_LAG = "consumer_lag"
    BACKPRESSURE_FAILURE = "backpressure_failure"
    RETRY_STORM = "retry_storm"
    TIMEOUT_CASCADE = "timeout_cascade"
    TIMEOUT_BEHAVIOR = "timeout_behavior"
    DEPENDENCY_FAILURE = "dependency_failure"
    CASCADING_FAILURE = "cascading_failure"
    FAILURE_AMPLIFICATION = "failure_amplification"
    CACHE_STAMPEDE = "cache_stampede"
    CACHE_AVALANCHE = "cache_avalanche"
    CACHE_INVALIDATION_FAILURE = "cache_invalidation_failure"
    LOAD_BALANCING_FAILURE = "load_balancing_failure"
    STATE_CONSISTENCY_FAILURE = "state_consistency_failure"
    MESSAGE_DUPLICATION = "message_duplication"
    MESSAGE_LOSS = "message_loss"
    POISON_MESSAGE = "poison_message"
    DLQ_FAILURE = "dlq_failure"
    WORKER_RESTART_FAILURE = "worker_restart_failure"
    RECOVERY_FAILURE = "recovery_failure"
    GRACEFUL_DEGRADATION_FAILURE = "graceful_degradation_failure"
    THUNDERING_HERD = "thundering_herd"
    RESOURCE_LEAK = "resource_leak"
    CONNECTION_LEAK = "connection_leak"
    UNBOUNDED_QUEUE_GROWTH = "unbounded_queue_growth"
    DEPENDENCY_SATURATION = "dependency_saturation"
    SYSTEM_RESILIENCE = "system_resilience"

    def to_finding_category(self) -> FindingCategory:
        mapping = {
            AttackFamily.INFORMATION_DISCLOSURE: FindingCategory.INFORMATION_DISCLOSURE,
            AttackFamily.AUTHENTICATION: FindingCategory.AUTHENTICATION,
            AttackFamily.CREDENTIAL_ABUSE: FindingCategory.CREDENTIAL_ABUSE,
            AttackFamily.SESSION_TOKEN_ABUSE: FindingCategory.SESSION_TOKEN_ABUSE,
            AttackFamily.AUTHORIZATION: FindingCategory.AUTHORIZATION,
            AttackFamily.AUTHORIZATION_BYPASS: FindingCategory.AUTHORIZATION_BYPASS,
            AttackFamily.IDOR_BOLA: FindingCategory.IDOR_BOLA,
            AttackFamily.INJECTION: FindingCategory.INJECTION,
            AttackFamily.SQL_INJECTION: FindingCategory.SQL_INJECTION,
            AttackFamily.NOSQL_INJECTION: FindingCategory.NOSQL_INJECTION,
            AttackFamily.COMMAND_INJECTION: FindingCategory.COMMAND_INJECTION,
            AttackFamily.TEMPLATE_INJECTION: FindingCategory.TEMPLATE_INJECTION,
            AttackFamily.PATH_TRAVERSAL: FindingCategory.PATH_TRAVERSAL,
            AttackFamily.SSRF: FindingCategory.SSRF,
            AttackFamily.XXE: FindingCategory.XXE,
            AttackFamily.UNSAFE_DESERIALIZATION: FindingCategory.UNSAFE_DESERIALIZATION,
            AttackFamily.INPUT_VALIDATION: FindingCategory.INPUT_VALIDATION,
            AttackFamily.MALFORMED_INPUT: FindingCategory.MALFORMED_INPUT,
            AttackFamily.TYPE_CONFUSION: FindingCategory.TYPE_CONFUSION,
            AttackFamily.OVERSIZED_INPUT: FindingCategory.OVERSIZED_INPUT,
            AttackFamily.FILE_UPLOAD_ABUSE: FindingCategory.FILE_UPLOAD_ABUSE,
            AttackFamily.SECURITY_MISCONFIGURATION: FindingCategory.SECURITY_MISCONFIGURATION,
            AttackFamily.ERROR_DISCLOSURE: FindingCategory.ERROR_DISCLOSURE,
            AttackFamily.ERROR_HANDLING: FindingCategory.ERROR_HANDLING,
            AttackFamily.RATE_LIMIT_BYPASS: FindingCategory.RATE_LIMIT_BYPASS,
            AttackFamily.RATE_LIMITING: FindingCategory.RATE_LIMITING,
            AttackFamily.BRUTE_FORCE_SENSITIVITY: FindingCategory.BRUTE_FORCE_SENSITIVITY,
            AttackFamily.REPLAY_ATTACK: FindingCategory.REPLAY_ATTACK,
            AttackFamily.IDEMPOTENCY_ABUSE: FindingCategory.IDEMPOTENCY_ABUSE,
            AttackFamily.BUSINESS_LOGIC_ABUSE: FindingCategory.BUSINESS_LOGIC_ABUSE,
            AttackFamily.INVALID_STATE_TRANSITION: FindingCategory.INVALID_STATE_TRANSITION,
            AttackFamily.DUPLICATE_OPERATION: FindingCategory.DUPLICATE_OPERATION,
            AttackFamily.OBJECT_OWNERSHIP_MANIPULATION: FindingCategory.OBJECT_OWNERSHIP_MANIPULATION,
            AttackFamily.WORKFLOW_MANIPULATION: FindingCategory.WORKFLOW_MANIPULATION,
            AttackFamily.CONCURRENCY: FindingCategory.CONCURRENCY,
            AttackFamily.CONCURRENCY_RACE: FindingCategory.CONCURRENCY_RACE,
            AttackFamily.TOCTOU: FindingCategory.TOCTOU,
            AttackFamily.DEADLOCK: FindingCategory.DEADLOCK,
            AttackFamily.LOCK_CONTENTION: FindingCategory.LOCK_CONTENTION,
            AttackFamily.WORKER_SATURATION: FindingCategory.WORKER_SATURATION,
            AttackFamily.THREAD_POOL_EXHAUSTION: FindingCategory.THREAD_POOL_EXHAUSTION,
            AttackFamily.CONNECTION_POOL_EXHAUSTION: FindingCategory.CONNECTION_POOL_EXHAUSTION,
            AttackFamily.RESOURCE_EXHAUSTION: FindingCategory.RESOURCE_EXHAUSTION,
            AttackFamily.CPU_EXHAUSTION: FindingCategory.CPU_EXHAUSTION,
            AttackFamily.MEMORY_EXHAUSTION: FindingCategory.MEMORY_EXHAUSTION,
            AttackFamily.QUEUE_SATURATION: FindingCategory.QUEUE_SATURATION,
            AttackFamily.CONSUMER_LAG: FindingCategory.CONSUMER_LAG,
            AttackFamily.BACKPRESSURE_FAILURE: FindingCategory.BACKPRESSURE_FAILURE,
            AttackFamily.RETRY_STORM: FindingCategory.RETRY_STORM,
            AttackFamily.TIMEOUT_CASCADE: FindingCategory.TIMEOUT_CASCADE,
            AttackFamily.TIMEOUT_BEHAVIOR: FindingCategory.TIMEOUT_BEHAVIOR,
            AttackFamily.DEPENDENCY_FAILURE: FindingCategory.DEPENDENCY_FAILURE,
            AttackFamily.CASCADING_FAILURE: FindingCategory.CASCADING_FAILURE,
            AttackFamily.FAILURE_AMPLIFICATION: FindingCategory.FAILURE_AMPLIFICATION,
            AttackFamily.CACHE_STAMPEDE: FindingCategory.CACHE_STAMPEDE,
            AttackFamily.CACHE_AVALANCHE: FindingCategory.CACHE_AVALANCHE,
            AttackFamily.CACHE_INVALIDATION_FAILURE: FindingCategory.CACHE_INVALIDATION_FAILURE,
            AttackFamily.LOAD_BALANCING_FAILURE: FindingCategory.LOAD_BALANCING_FAILURE,
            AttackFamily.STATE_CONSISTENCY_FAILURE: FindingCategory.STATE_CONSISTENCY_FAILURE,
            AttackFamily.MESSAGE_DUPLICATION: FindingCategory.MESSAGE_DUPLICATION,
            AttackFamily.MESSAGE_LOSS: FindingCategory.MESSAGE_LOSS,
            AttackFamily.POISON_MESSAGE: FindingCategory.POISON_MESSAGE,
            AttackFamily.DLQ_FAILURE: FindingCategory.DLQ_FAILURE,
            AttackFamily.WORKER_RESTART_FAILURE: FindingCategory.WORKER_RESTART_FAILURE,
            AttackFamily.RECOVERY_FAILURE: FindingCategory.RECOVERY_FAILURE,
            AttackFamily.GRACEFUL_DEGRADATION_FAILURE: FindingCategory.GRACEFUL_DEGRADATION_FAILURE,
            AttackFamily.THUNDERING_HERD: FindingCategory.THUNDERING_HERD,
            AttackFamily.RESOURCE_LEAK: FindingCategory.RESOURCE_LEAK,
            AttackFamily.CONNECTION_LEAK: FindingCategory.CONNECTION_LEAK,
            AttackFamily.UNBOUNDED_QUEUE_GROWTH: FindingCategory.UNBOUNDED_QUEUE_GROWTH,
            AttackFamily.DEPENDENCY_SATURATION: FindingCategory.DEPENDENCY_SATURATION,
            AttackFamily.SYSTEM_RESILIENCE: FindingCategory.SYSTEM_RESILIENCE,
        }
        return mapping.get(self, FindingCategory.SECURITY_MISCONFIGURATION)

    def to_finding_type(self) -> FindingType:
        if self in (
            AttackFamily.INFORMATION_DISCLOSURE, AttackFamily.AUTHENTICATION, AttackFamily.CREDENTIAL_ABUSE,
            AttackFamily.SESSION_TOKEN_ABUSE, AttackFamily.AUTHORIZATION, AttackFamily.AUTHORIZATION_BYPASS,
            AttackFamily.IDOR_BOLA, AttackFamily.INJECTION, AttackFamily.SQL_INJECTION, AttackFamily.NOSQL_INJECTION,
            AttackFamily.COMMAND_INJECTION, AttackFamily.TEMPLATE_INJECTION, AttackFamily.PATH_TRAVERSAL,
            AttackFamily.SSRF, AttackFamily.XXE, AttackFamily.UNSAFE_DESERIALIZATION, AttackFamily.SECURITY_MISCONFIGURATION,
            AttackFamily.ERROR_DISCLOSURE, AttackFamily.ERROR_HANDLING, AttackFamily.INPUT_VALIDATION,
            AttackFamily.MALFORMED_INPUT, AttackFamily.TYPE_CONFUSION, AttackFamily.FILE_UPLOAD_ABUSE
        ):
            return FindingType.SECURITY_VULNERABILITY

        if self in (
            AttackFamily.RATE_LIMIT_BYPASS, AttackFamily.RATE_LIMITING, AttackFamily.BRUTE_FORCE_SENSITIVITY,
            AttackFamily.REPLAY_ATTACK, AttackFamily.IDEMPOTENCY_ABUSE, AttackFamily.BUSINESS_LOGIC_ABUSE,
            AttackFamily.INVALID_STATE_TRANSITION, AttackFamily.DUPLICATE_OPERATION,
            AttackFamily.OBJECT_OWNERSHIP_MANIPULATION, AttackFamily.WORKFLOW_MANIPULATION
        ):
            return FindingType.BUSINESS_LOGIC_FAILURE

        if self in (
            AttackFamily.DEPENDENCY_FAILURE, AttackFamily.CASCADING_FAILURE,
            AttackFamily.FAILURE_AMPLIFICATION, AttackFamily.DEPENDENCY_SATURATION
        ):
            return FindingType.DEPENDENCY_FAILURE

        if self in (
            AttackFamily.CPU_EXHAUSTION, AttackFamily.MEMORY_EXHAUSTION, AttackFamily.RESOURCE_EXHAUSTION,
            AttackFamily.OVERSIZED_INPUT, AttackFamily.THREAD_POOL_EXHAUSTION, AttackFamily.CONNECTION_POOL_EXHAUSTION
        ):
            return FindingType.PERFORMANCE_FAILURE

        if self in (
            AttackFamily.RECOVERY_FAILURE, AttackFamily.GRACEFUL_DEGRADATION_FAILURE, AttackFamily.RETRY_STORM,
            AttackFamily.BACKPRESSURE_FAILURE, AttackFamily.WORKER_RESTART_FAILURE, AttackFamily.DLQ_FAILURE,
            AttackFamily.SYSTEM_RESILIENCE, AttackFamily.THUNDERING_HERD
        ):
            return FindingType.RESILIENCE_FAILURE

        return FindingType.SYSTEM_DESIGN_FAILURE


class AttackCapability(BaseModel):
    """Metadata describing how an attack family is applied by the autonomous agent."""
    family: AttackFamily
    description: str
    recommended_tools: list[str]
    expected_signals: list[str]
    finding_type: FindingType = FindingType.SECURITY_VULNERABILITY
    requires_baseline: bool = True
    safety_notes: str
    causal_parent: Optional[str] = None


ATTACK_CAPABILITIES: dict[AttackFamily, AttackCapability] = {
    # 1. Security Attacks
    AttackFamily.INFORMATION_DISCLOSURE: AttackCapability(
        family=AttackFamily.INFORMATION_DISCLOSURE,
        description="Inspect response bodies, headers, debug routes, and configuration leaks for credentials or internal secrets.",
        recommended_tools=["send_http_request", "inspect_http_response"],
        expected_signals=["API keys", "passwords", "database URLs", "stack traces", "environment secrets"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=False,
        safety_notes="Do not classify arbitrary strings or UUIDs as secrets."
    ),
    AttackFamily.AUTHENTICATION: AttackCapability(
        family=AttackFamily.AUTHENTICATION,
        description="Test missing credentials, invalid credentials, malformed tokens, and test credentials to verify access gates.",
        recommended_tools=["send_http_request", "manage_test_session"],
        expected_signals=["HTTP 401/403 vs 200", "token validation difference", "credential acceptance"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Controlled credential attempts without lockout of administrative users."
    ),
    AttackFamily.AUTHORIZATION: AttackCapability(
        family=AttackFamily.AUTHORIZATION,
        description="Reason about object ownership (identity A accessing object B vs object A) to verify privilege bypass.",
        recommended_tools=["compare_responses", "send_http_request", "manage_test_session"],
        expected_signals=["Cross-user data access", "role escalation", "IDOR reflection"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Confirm authorization boundary was actually bypassed."
    ),
    AttackFamily.AUTHORIZATION_BYPASS: AttackCapability(
        family=AttackFamily.AUTHORIZATION_BYPASS,
        description="Test unauthenticated access to privileged administrative or operator endpoints.",
        recommended_tools=["send_http_request", "compare_responses"],
        expected_signals=["HTTP 200 on administrative route without token", "role override headers accepted"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Confirm privileged action executed without authentication."
    ),
    AttackFamily.IDOR_BOLA: AttackCapability(
        family=AttackFamily.IDOR_BOLA,
        description="Manipulate object identifiers to access resources owned by other tenants or identities.",
        recommended_tools=["compare_responses", "send_http_request"],
        expected_signals=["Access to peer resource", "IDOR reflection", "missing tenancy gate"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Test known IDs sequentially or concurrently without data corruption."
    ),
    AttackFamily.INJECTION: AttackCapability(
        family=AttackFamily.INJECTION,
        description="Dynamically test query, path, and body parameters with controlled variations against a baseline.",
        recommended_tools=["measure_baseline", "compare_responses", "send_http_request"],
        expected_signals=["SQL/DB dialect errors", "boolean differential", "syntax exceptions", "data structure shift"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="HTTP 500 alone is NOT a vulnerability. Must demonstrate syntax or logic reflection."
    ),
    AttackFamily.SQL_INJECTION: AttackCapability(
        family=AttackFamily.SQL_INJECTION,
        description="Test for SQL injection syntax errors, quote breaking, and boolean evaluation differences.",
        recommended_tools=["measure_baseline", "compare_responses", "send_http_request"],
        expected_signals=["sqlite3 / psycopg2 / syntax error", "query response differential", "data extraction"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Do not execute drop/truncate/alter payloads."
    ),
    AttackFamily.INPUT_VALIDATION: AttackCapability(
        family=AttackFamily.INPUT_VALIDATION,
        description="Evaluate boundary values, unexpected types, and malformed inputs to test robust schema validation.",
        recommended_tools=["compare_responses", "send_http_request"],
        expected_signals=["HTTP 422/400 graceful handling vs 500 crash", "type confusion", "unhandled exceptions"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Probe edge cases cleanly within HTTP bounds."
    ),
    AttackFamily.ERROR_HANDLING: AttackCapability(
        family=AttackFamily.ERROR_HANDLING,
        description="Analyze error formatting, verbosity, stack traces, and unhandled exceptions across malformed requests.",
        recommended_tools=["send_http_request", "compare_responses"],
        expected_signals=["StackTrace disclosure", "internal framework paths", "dialect signatures in 5xx"],
        finding_type=FindingType.SECURITY_VULNERABILITY,
        requires_baseline=True,
        safety_notes="Inspect error responses for sensitive debug disclosures."
    ),

    # 2. Application Abuse & Idempotency
    AttackFamily.RATE_LIMITING: AttackCapability(
        family=AttackFamily.RATE_LIMITING,
        description="Apply bounded adaptive pressure to detect throttling thresholds, 429 status codes, and backpressure behavior.",
        recommended_tools=["measure_baseline", "pressure_test"],
        expected_signals=["HTTP 429 Too Many Requests", "Retry-After headers", "unthrottled degradation"],
        finding_type=FindingType.BUSINESS_LOGIC_FAILURE,
        requires_baseline=True,
        safety_notes="Escalate gradually, back off on degradation, and verify recovery."
    ),
    AttackFamily.RATE_LIMIT_BYPASS: AttackCapability(
        family=AttackFamily.RATE_LIMIT_BYPASS,
        description="Test whether rate limiting can be bypassed using headers (X-Forwarded-For) or path variations.",
        recommended_tools=["measure_baseline", "pressure_test"],
        expected_signals=["Bypassed 429 limit", "unlimited request execution"],
        finding_type=FindingType.BUSINESS_LOGIC_FAILURE,
        requires_baseline=True,
        safety_notes="Strictly bounded within sandbox limits."
    ),
    AttackFamily.IDEMPOTENCY_ABUSE: AttackCapability(
        family=AttackFamily.IDEMPOTENCY_ABUSE,
        description="Test repeat and concurrent submissions with identical idempotency keys to detect duplicate task creation or 500 crashes.",
        recommended_tools=["measure_baseline", "test_idempotency", "concurrency_test"],
        expected_signals=["Duplicate task/resource creation", "HTTP 500 DataIntegrityViolationException", "missing idempotency enforcement"],
        finding_type=FindingType.BUSINESS_LOGIC_FAILURE,
        requires_baseline=True,
        safety_notes="Verify whether repeated operations return cached result or produce side effects."
    ),
    AttackFamily.DUPLICATE_OPERATION: AttackCapability(
        family=AttackFamily.DUPLICATE_OPERATION,
        description="Test whether non-idempotent operations permit double-spending or duplicate execution when dispatched simultaneously.",
        recommended_tools=["test_idempotency", "concurrency_test"],
        expected_signals=["Multiple successful 201/200 creations", "state duplication"],
        finding_type=FindingType.BUSINESS_LOGIC_FAILURE,
        requires_baseline=True,
        safety_notes="Detect duplicate side effects without corrupting test targets."
    ),
    AttackFamily.REPLAY_ATTACK: AttackCapability(
        family=AttackFamily.REPLAY_ATTACK,
        description="Replay previously executed operations to determine whether replay causes unintended duplicate side effects.",
        recommended_tools=["test_idempotency", "send_http_request"],
        expected_signals=["Duplicate execution", "unhandled replay"],
        finding_type=FindingType.BUSINESS_LOGIC_FAILURE,
        requires_baseline=True,
        safety_notes="Check state before and after replay."
    ),

    # 3. System & Resilience
    AttackFamily.CONCURRENCY: AttackCapability(
        family=AttackFamily.CONCURRENCY,
        description="Dispatch controlled simultaneous requests to detect race conditions, state collisions, or connection exhaustion.",
        recommended_tools=["measure_baseline", "concurrency_test"],
        expected_signals=["Duplicate creation", "state inconsistency", "connection pool exhaustion", "5xx under load"],
        finding_type=FindingType.SYSTEM_DESIGN_FAILURE,
        requires_baseline=True,
        safety_notes="Never assume race from timing alone; verify response states and database effects."
    ),
    AttackFamily.CONCURRENCY_RACE: AttackCapability(
        family=AttackFamily.CONCURRENCY_RACE,
        description="Simultaneously race requests to exploit TOCTOU check-then-act gaps or unhandled database locking.",
        recommended_tools=["concurrency_test", "test_idempotency"],
        expected_signals=["Database is locked", "deadlock detected", "state corruption", "double creation"],
        finding_type=FindingType.SYSTEM_DESIGN_FAILURE,
        requires_baseline=True,
        safety_notes="Observe concrete error signatures or conflicting state records."
    ),
    AttackFamily.WORKER_SATURATION: AttackCapability(
        family=AttackFamily.WORKER_SATURATION,
        description="Gradually increase task workload until worker pool capacity is constrained; observe queuing and crash loops.",
        recommended_tools=["measure_baseline", "pressure_test", "concurrency_test"],
        expected_signals=["Worker OUT_OF_SERVICE", "restart budget exhausted", "backlog exceeds batch", "degraded diagnostics"],
        finding_type=FindingType.SYSTEM_DESIGN_FAILURE,
        requires_baseline=True,
        safety_notes="Monitor worker status during and after pressure."
    ),
    AttackFamily.QUEUE_SATURATION: AttackCapability(
        family=AttackFamily.QUEUE_SATURATION,
        description="Submit task bursts to observe queue growth, consumer processing lag, and queue backpressure enforcement.",
        recommended_tools=["measure_baseline", "pressure_test"],
        expected_signals=["Unbounded queue depth", "throttled recovery", "ACCEPTED status backlog"],
        finding_type=FindingType.SYSTEM_DESIGN_FAILURE,
        requires_baseline=True,
        safety_notes="Observe queue depth and age metrics via diagnostics endpoints."
    ),
    AttackFamily.BACKPRESSURE_FAILURE: AttackCapability(
        family=AttackFamily.BACKPRESSURE_FAILURE,
        description="Determine whether the application accepts work when background workers or queues are already overwhelmed.",
        recommended_tools=["pressure_test", "test_idempotency"],
        expected_signals=["Acceptance of work without worker capacity", "excessive lag", "HTTP 500 crash under load"],
        finding_type=FindingType.RESILIENCE_FAILURE,
        requires_baseline=True,
        safety_notes="Compare ingestion acceptance with processing rate."
    ),
    AttackFamily.DEPENDENCY_FAILURE: AttackCapability(
        family=AttackFamily.DEPENDENCY_FAILURE,
        description="Test controlled dependency unavailability or simulated downstream failure to evaluate fault tolerance.",
        recommended_tools=["inject_failure", "send_http_request"],
        expected_signals=["Cascading 500 errors", "stale data fallback", "unhandled connection exception"],
        finding_type=FindingType.DEPENDENCY_FAILURE,
        requires_baseline=True,
        safety_notes="Use authorized sandbox failure simulator; always reset to normal."
    ),
    AttackFamily.CASCADING_FAILURE: AttackCapability(
        family=AttackFamily.CASCADING_FAILURE,
        description="Determine whether failure of one worker or dependency cascades into unhandled failures across independent endpoints.",
        recommended_tools=["inject_failure", "send_http_request"],
        expected_signals=["Unrelated route failures", "unhandled circuit breaker", "platform-wide outage"],
        finding_type=FindingType.DEPENDENCY_FAILURE,
        requires_baseline=True,
        safety_notes="Track root trigger and downstream affected endpoints."
    ),
    AttackFamily.RECOVERY_FAILURE: AttackCapability(
        family=AttackFamily.RECOVERY_FAILURE,
        description="Verify whether the target returns to healthy baseline status and latency after pressure or failure ceases.",
        recommended_tools=["measure_baseline", "pressure_test", "inject_failure"],
        expected_signals=["Stuck in degraded state", "permanent worker crash loop", "unrecovered connection pool"],
        finding_type=FindingType.RESILIENCE_FAILURE,
        requires_baseline=True,
        safety_notes="Measure baseline -> apply stress -> back off -> verify recovery."
    ),
    AttackFamily.WORKER_RESTART_FAILURE: AttackCapability(
        family=AttackFamily.WORKER_RESTART_FAILURE,
        description="Evaluate worker restart budget exhaustion, crash loops, and transition to OUT_OF_SERVICE.",
        recommended_tools=["inject_failure", "send_http_request"],
        expected_signals=["Worker OUT_OF_SERVICE", "exhausted restart budget", "failed task recovery"],
        finding_type=FindingType.RESILIENCE_FAILURE,
        requires_baseline=True,
        safety_notes="Observe worker health lifecycle."
    ),
    AttackFamily.CACHE_INVALIDATION_FAILURE: AttackCapability(
        family=AttackFamily.CACHE_INVALIDATION_FAILURE,
        description="Evaluate cache staleness, cache disagreement with source data, and cache refresh behavior.",
        recommended_tools=["send_http_request", "compare_responses", "inject_failure"],
        expected_signals=["Disagreement between cached and source values", "stale data served without indication"],
        finding_type=FindingType.SYSTEM_DESIGN_FAILURE,
        requires_baseline=True,
        safety_notes="Inspect cache state and validation endpoints."
    ),
    AttackFamily.SYSTEM_RESILIENCE: AttackCapability(
        family=AttackFamily.SYSTEM_RESILIENCE,
        description="Conduct holistic system-design analysis (baseline -> stress -> degradation -> recovery) to identify architectural bottlenecks.",
        recommended_tools=["measure_baseline", "pressure_test", "concurrency_test", "test_idempotency", "inject_failure"],
        expected_signals=["Worker saturation", "connection pool starvation", "inadequate backpressure", "recovery failure"],
        finding_type=FindingType.SYSTEM_DESIGN_FAILURE,
        requires_baseline=True,
        safety_notes="Clearly distinguish OBSERVED metric changes from INFERRED architectural conclusions."
    )
}


def recommend_attack_family(endpoint: str, method: str = "GET", headers: Optional[dict] = None) -> list[AttackFamily]:
    """Suggests prioritized attack families based on endpoint naming, method, and characteristics."""
    ep_lower = endpoint.lower()
    method_upper = method.upper()
    families = []

    # Tasks / Jobs / Mutation
    if any(k in ep_lower for k in ["tasks", "jobs", "orders", "events", "dispatch"]):
        if method_upper in ("POST", "PUT"):
            families.append(AttackFamily.IDEMPOTENCY_ABUSE)
            families.append(AttackFamily.DUPLICATE_OPERATION)
            families.append(AttackFamily.CONCURRENCY_RACE)
            families.append(AttackFamily.INPUT_VALIDATION)
        else:
            families.append(AttackFamily.QUEUE_SATURATION)
            families.append(AttackFamily.CONCURRENCY)
        families.append(AttackFamily.BACKPRESSURE_FAILURE)
        families.append(AttackFamily.WORKER_SATURATION)

    # Workers / Cluster
    if any(k in ep_lower for k in ["workers", "cluster", "nodes"]):
        families.append(AttackFamily.WORKER_SATURATION)
        families.append(AttackFamily.WORKER_RESTART_FAILURE)
        families.append(AttackFamily.AUTHORIZATION_BYPASS)
        families.append(AttackFamily.CONCURRENCY)

    # Operator / Admin / Diagnostics
    if any(k in ep_lower for k in ["operator", "admin", "diagnostics", "control", "simulate"]):
        families.append(AttackFamily.AUTHORIZATION_BYPASS)
        families.append(AttackFamily.SECURITY_MISCONFIGURATION)
        families.append(AttackFamily.DEPENDENCY_FAILURE)
        families.append(AttackFamily.CASCADING_FAILURE)
        families.append(AttackFamily.INFORMATION_DISCLOSURE)

    # Cache
    if "cache" in ep_lower:
        families.append(AttackFamily.CACHE_INVALIDATION_FAILURE)
        families.append(AttackFamily.CACHE_STAMPEDE)

    # Debug / Env / Config
    if any(k in ep_lower for k in ["debug", "env", "config", "info"]):
        families.append(AttackFamily.INFORMATION_DISCLOSURE)
        families.append(AttackFamily.ERROR_HANDLING)

    # Auth
    if any(k in ep_lower for k in ["auth", "login", "token", "session"]):
        families.append(AttackFamily.AUTHENTICATION)
        families.append(AttackFamily.RATE_LIMITING)
        families.append(AttackFamily.BRUTE_FORCE_SENSITIVITY)

    # ID / Object
    if any(k in ep_lower for k in ["{user_id}", "{id}", "user", "profile", "account"]):
        families.append(AttackFamily.IDOR_BOLA)
        families.append(AttackFamily.AUTHORIZATION)
        families.append(AttackFamily.CONCURRENCY_RACE)

    # Search / Parameters
    if any(k in ep_lower for k in ["search", "query", "filter", "find"]):
        families.append(AttackFamily.INJECTION)
        families.append(AttackFamily.SQL_INJECTION)
        families.append(AttackFamily.INPUT_VALIDATION)
        families.append(AttackFamily.RESOURCE_EXHAUSTION)

    # General resilience applies to all primary endpoints
    families.append(AttackFamily.SYSTEM_RESILIENCE)
    families.append(AttackFamily.RATE_LIMITING)
    families.append(AttackFamily.RECOVERY_FAILURE)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for f in families:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result
