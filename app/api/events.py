import asyncio
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    AUDIT_STARTED = "AUDIT_STARTED"
    PROJECT_ANALYZED = "PROJECT_ANALYZED"
    COMPLEXITY_CALCULATED = "COMPLEXITY_CALCULATED"
    SANDBOX_STARTED = "SANDBOX_STARTED"
    ENDPOINT_DISCOVERED = "ENDPOINT_DISCOVERED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    TOOL_STARTED = "TOOL_STARTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    OBSERVATION_CREATED = "OBSERVATION_CREATED"
    FINDING_CONFIRMED = "FINDING_CONFIRMED"
    FINDING_UPDATED = "FINDING_UPDATED"
    PHASE_CHANGED = "PHASE_CHANGED"
    STEP_COMPLETED = "STEP_COMPLETED"
    AUDIT_COMPLETED = "AUDIT_COMPLETED"
    AUDIT_STOPPED = "AUDIT_STOPPED"
    AUDIT_FAILED = "AUDIT_FAILED"
    STATUS_CHANGED = "STATUS_CHANGED"
    SANDBOX_PROGRESS = "SANDBOX_PROGRESS"
    SANDBOX_CLEANED = "SANDBOX_CLEANED"


class AuditEvent(BaseModel):
    audit_id: str
    event_type: AuditEventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class AuditEventManager:
    """Manages real-time event streaming, history buffering, and SSE/WebSocket subscriptions."""

    def __init__(self):
        self._history: Dict[str, List[AuditEvent]] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def emit(
        self,
        audit_id: str,
        event_type: AuditEventType,
        data: Optional[Dict[str, Any]] = None,
        summary: str = ""
    ) -> AuditEvent:
        event = AuditEvent(
            audit_id=audit_id,
            event_type=event_type,
            data=data or {},
            summary=summary
        )

        async with self._lock:
            if audit_id not in self._history:
                self._history[audit_id] = []
            self._history[audit_id].append(event)

            # Fan out to all active subscriber queues
            queues = list(self._subscribers.get(audit_id, []))

        for q in queues:
            try:
                q.put_nowait(event)
            except Exception:
                pass

        return event

    def emit_sync(
        self,
        audit_id: str,
        event_type: AuditEventType,
        data: Optional[Dict[str, Any]] = None,
        summary: str = ""
    ) -> AuditEvent:
        """Synchronous emit helper for worker threads or sync callbacks."""
        event = AuditEvent(
            audit_id=audit_id,
            event_type=event_type,
            data=data or {},
            summary=summary
        )
        if audit_id not in self._history:
            self._history[audit_id] = []
        self._history[audit_id].append(event)

        queues = list(self._subscribers.get(audit_id, []))
        for q in queues:
            try:
                q.put_nowait(event)
            except Exception:
                pass
        return event

    async def subscribe(self, audit_id: str) -> AsyncGenerator[AuditEvent, None]:
        """Async generator yielding past events then live events as SSE or WebSocket items."""
        q = asyncio.Queue()

        async with self._lock:
            if audit_id not in self._subscribers:
                self._subscribers[audit_id] = []
            self._subscribers[audit_id].append(q)

            # Send historical events first
            past_events = list(self._history.get(audit_id, []))

        for past in past_events:
            yield past

        try:
            while True:
                ev = await q.get()
                yield ev
        finally:
            async with self._lock:
                if audit_id in self._subscribers and q in self._subscribers[audit_id]:
                    self._subscribers[audit_id].remove(q)

    def get_events(self, audit_id: str) -> List[AuditEvent]:
        return list(self._history.get(audit_id, []))


# Global singleton
EVENT_MANAGER = AuditEventManager()
