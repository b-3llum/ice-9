"""Real-time event bus for ice_9 observability."""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


class EventType(str, Enum):
    """Event types emitted during operations."""

    # Tool events
    TOOL_START = "tool_start"
    TOOL_OUTPUT = "tool_output"
    TOOL_COMPLETE = "tool_complete"
    TOOL_ERROR = "tool_error"

    # Phase events
    PHASE_START = "phase_start"
    PHASE_PLAN = "phase_plan"
    PHASE_TASK_START = "phase_task_start"
    PHASE_TASK_COMPLETE = "phase_task_complete"
    PHASE_COMPLETE = "phase_complete"

    # AI events
    AI_REQUEST = "ai_request"
    AI_CHUNK = "ai_chunk"
    AI_RESPONSE = "ai_response"

    # Autopilot events
    AUTO_PHASE_SELECT = "auto_phase_select"
    AUTO_COMPLETE = "auto_complete"

    # Finding events
    FINDING_NEW = "finding_new"


@dataclass
class Event:
    """A single observable event."""

    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    campaign_id: Optional[str] = None
    phase_id: Optional[str] = None
    timestamp: str = field(default="")

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "timestamp": self.timestamp,
            "campaign_id": self.campaign_id,
            "phase_id": self.phase_id,
            "data": self.data,
        }

    def to_sse(self) -> str:
        """Format as Server-Sent Event."""
        return f"event: {self.type.value}\ndata: {json.dumps(self.to_dict())}\n\n"


class EventBus:
    """Thread-safe in-process event bus with bounded history.

    Usage:
        from ice_9.core.events import event_bus, Event, EventType

        # Emit
        event_bus.emit(Event(type=EventType.TOOL_START, data={"tool": "nmap"}))

        # Subscribe
        unsub = event_bus.subscribe(lambda e: print(e))
        unsub()  # unsubscribe

        # History
        recent = event_bus.history(limit=50)
    """

    def __init__(self, max_history: int = 200) -> None:
        self._subscribers: list[Callable[[Event], None]] = []
        self._history: deque[Event] = deque(maxlen=max_history)
        self._lock = threading.Lock()

    def emit(self, event: Event) -> None:
        """Emit an event to all subscribers and append to history."""
        with self._lock:
            self._history.append(event)
            subscribers = list(self._subscribers)

        for callback in subscribers:
            try:
                callback(event)
            except Exception:
                pass  # Never let a bad subscriber break the emitter

    def subscribe(self, callback: Callable[[Event], None]) -> Callable[[], None]:
        """Subscribe to events. Returns an unsubscribe function."""
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                try:
                    self._subscribers.remove(callback)
                except ValueError:
                    pass

        return unsubscribe

    def history(
        self,
        limit: int = 50,
        campaign_id: Optional[str] = None,
        types: Optional[list[EventType]] = None,
    ) -> list[Event]:
        """Get recent events from history buffer."""
        with self._lock:
            events = list(self._history)

        if campaign_id:
            events = [e for e in events if e.campaign_id is None or e.campaign_id == campaign_id]
        if types:
            events = [e for e in events if e.type in types]

        return events[-limit:]

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# Module-level singleton
event_bus = EventBus()
