import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.models.evidence import Evidence


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_CONFIRMED = "NOT_CONFIRMED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingType(str, Enum):
    SECURITY_VULNERABILITY = "SECURITY_VULNERABILITY"
    SYSTEM_DESIGN_FAILURE = "SYSTEM_DESIGN_FAILURE"
    RESILIENCE_FAILURE = "RESILIENCE_FAILURE"
    BUSINESS_LOGIC_FAILURE = "BUSINESS_LOGIC_FAILURE"
    PERFORMANCE_FAILURE = "PERFORMANCE_FAILURE"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"


class FindingCategory(str, Enum):
    # Security
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    AUTHENTICATION = "AUTHENTICATION"
    CREDENTIAL_ABUSE = "CREDENTIAL_ABUSE"
    SESSION_TOKEN_ABUSE = "SESSION_TOKEN_ABUSE"
    AUTHORIZATION = "AUTHORIZATION"
    AUTHORIZATION_BYPASS = "AUTHORIZATION_BYPASS"
    IDOR_BOLA = "IDOR_BOLA"
    INJECTION = "INJECTION"
    SQL_INJECTION = "SQL_INJECTION"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    TEMPLATE_INJECTION = "TEMPLATE_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XXE = "XXE"
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    TYPE_CONFUSION = "TYPE_CONFUSION"
    OVERSIZED_INPUT = "OVERSIZED_INPUT"
    FILE_UPLOAD_ABUSE = "FILE_UPLOAD_ABUSE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    ERROR_DISCLOSURE = "ERROR_DISCLOSURE"
    ERROR_HANDLING = "ERROR_HANDLING"
    UNSAFE_INPUT_HANDLING = "UNSAFE_INPUT_HANDLING"
    API_SECURITY = "API_SECURITY"
    CONFIGURATION = "CONFIGURATION"

    # Application Abuse
    RATE_LIMIT_BYPASS = "RATE_LIMIT_BYPASS"
    RATE_LIMITING = "RATE_LIMITING"
    BRUTE_FORCE_SENSITIVITY = "BRUTE_FORCE_SENSITIVITY"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    IDEMPOTENCY_ABUSE = "IDEMPOTENCY_ABUSE"
    BUSINESS_LOGIC_ABUSE = "BUSINESS_LOGIC_ABUSE"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    DUPLICATE_OPERATION = "DUPLICATE_OPERATION"
    OBJECT_OWNERSHIP_MANIPULATION = "OBJECT_OWNERSHIP_MANIPULATION"
    WORKFLOW_MANIPULATION = "WORKFLOW_MANIPULATION"

    # System & Resilience
    CONCURRENCY = "CONCURRENCY"
    CONCURRENCY_RACE = "CONCURRENCY_RACE"
    TOCTOU = "TOCTOU"
    DEADLOCK = "DEADLOCK"
    LOCK_CONTENTION = "LOCK_CONTENTION"
    WORKER_SATURATION = "WORKER_SATURATION"
    THREAD_POOL_EXHAUSTION = "THREAD_POOL_EXHAUSTION"
    CONNECTION_POOL_EXHAUSTION = "CONNECTION_POOL_EXHAUSTION"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    CPU_EXHAUSTION = "CPU_EXHAUSTION"
    MEMORY_EXHAUSTION = "MEMORY_EXHAUSTION"
    QUEUE_SATURATION = "QUEUE_SATURATION"
    CONSUMER_LAG = "CONSUMER_LAG"
    BACKPRESSURE_FAILURE = "BACKPRESSURE_FAILURE"
    RETRY_STORM = "RETRY_STORM"
    TIMEOUT_CASCADE = "TIMEOUT_CASCADE"
    TIMEOUT_BEHAVIOR = "TIMEOUT_BEHAVIOR"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    CASCADING_FAILURE = "CASCADING_FAILURE"
    FAILURE_AMPLIFICATION = "FAILURE_AMPLIFICATION"
    CACHE_STAMPEDE = "CACHE_STAMPEDE"
    CACHE_AVALANCHE = "CACHE_AVALANCHE"
    CACHE_INVALIDATION_FAILURE = "CACHE_INVALIDATION_FAILURE"
    LOAD_BALANCING_FAILURE = "LOAD_BALANCING_FAILURE"
    STATE_CONSISTENCY_FAILURE = "STATE_CONSISTENCY_FAILURE"
    MESSAGE_DUPLICATION = "MESSAGE_DUPLICATION"
    MESSAGE_LOSS = "MESSAGE_LOSS"
    POISON_MESSAGE = "POISON_MESSAGE"
    DLQ_FAILURE = "DLQ_FAILURE"
    WORKER_RESTART_FAILURE = "WORKER_RESTART_FAILURE"
    RECOVERY_FAILURE = "RECOVERY_FAILURE"
    GRACEFUL_DEGRADATION_FAILURE = "GRACEFUL_DEGRADATION_FAILURE"
    THUNDERING_HERD = "THUNDERING_HERD"
    RESOURCE_LEAK = "RESOURCE_LEAK"
    CONNECTION_LEAK = "CONNECTION_LEAK"
    UNBOUNDED_QUEUE_GROWTH = "UNBOUNDED_QUEUE_GROWTH"
    DEPENDENCY_SATURATION = "DEPENDENCY_SATURATION"
    SYSTEM_RESILIENCE = "SYSTEM_RESILIENCE"


def generate_finding_id() -> str:
    return f"find_{uuid.uuid4().hex[:8]}"


class Finding(BaseModel):
    """An autonomous security finding backed by verified empirical evidence."""
    id: str = Field(default_factory=generate_finding_id)
    title: str = Field(..., description="Short descriptive title of the finding")
    category: FindingCategory = Field(..., description="Vulnerability category")
    finding_type: FindingType = Field(default=FindingType.SECURITY_VULNERABILITY, description="Classification of failure type")
    severity: Severity = Field(..., description="Assessed impact severity")
    confidence: Confidence = Field(..., description="Confidence level based on runtime validation")
    description: str = Field(..., description="Technical explanation of the security issue")
    impact: str = Field(..., description="Consequences of potential exploitation")
    evidence: list[Evidence] = Field(default_factory=list, description="Verified runtime evidence artifacts")
    reproduction_steps: list[str] = Field(default_factory=list, description="Step-by-step reproduction instructions")
    remediation: Optional[str] = Field(default=None, description="Actionable fix recommendations")
    status: FindingStatus = Field(default=FindingStatus.CONFIRMED, description="Validation status")
    affected_endpoint: Optional[str] = Field(default=None, description="Target endpoint or URI affected")
    causal_chain: list[str] = Field(default_factory=list, description="Identified causal sequence of linked events")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add_evidence(self, item: Evidence) -> None:
        item.finding_id = self.id
        self.evidence.append(item)
