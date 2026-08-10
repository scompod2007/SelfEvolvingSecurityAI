"""
============================================================
Self-Evolving Security AI
Master Filter Dispatcher Models
Version : 1.1

Part 2.12
Dispatcher Models

Responsibilities
----------------
• Define the request object passed into the dispatcher
• Define the structured response object returned by the
  dispatcher

NO dispatch or filtering logic belongs here.

============================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ============================================================
# DISPATCH REQUEST
# ============================================================


@dataclass(slots=True)
class DispatchRequest:
    """
    Represents an inbound telemetry event submitted to the
    MasterFilterDispatcher.
    """

    event: dict[str, Any]

    correlation_id: str | None = None

    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# DISPATCH RESPONSE
# ============================================================


@dataclass(slots=True)
class DispatchResponse:
    """
    Standard structured response returned by every dispatch call.

    Example
    -------
    response = DispatchResponse(
        accepted=True,
        event_type="PROCESS_CREATE",
        filter_name="ProcessFilter",
        correlation_id="1c1b6b8e-6b8e-4b8e-8b8e-1c1b6b8e6b8e",
        execution_time_ms=1.42,
    )
    """

    accepted: bool

    event_type: str

    filter_name: str

    correlation_id: str

    execution_time_ms: float

    result: Any | None = None

    error: str | None = None

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_success(self) -> bool:
        """
        Return True only when the event was accepted and no error
        occurred.
        """

        return self.accepted is True and self.error is None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert DispatchResponse to a fully serializable dictionary.

        Useful for logging, API responses, and downstream AI
        processing.
        """

        result_value = self.result
        if hasattr(result_value, "to_dict") and callable(
            getattr(result_value, "to_dict")
        ):
            result_value = result_value.to_dict()

        return {
            "accepted": self.accepted,
            "event_type": self.event_type,
            "filter_name": self.filter_name,
            "correlation_id": self.correlation_id,
            "execution_time_ms": self.execution_time_ms,
            "result": result_value,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }
