"""
============================================================
Self-Evolving Security AI
Master Filter Dispatcher
Version : 1.1

Part 2.12
Master Filter Dispatcher

Responsibilities
----------------
• Provide a stable public dispatch API for telemetry events
• Route events through the existing FilterEngine
• Normalize event types
• Generate correlation IDs when missing
• Capture execution time
• Return a structured DispatchResponse
• Never raise exceptions outward

NO filtering logic belongs here. All filtering decisions are
delegated to the existing FilterEngine.

============================================================
"""

from __future__ import annotations

import copy
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from engine.filter_engine import FilterEngine

from dispatcher.models import DispatchResponse

logger = logging.getLogger(__name__)


class MasterFilterDispatcher:
    """
    Stable public dispatch API sitting above the FilterEngine.

    Stateless per request. A single instance is safe to share across
    multiple threads.
    """

    def __init__(self) -> None:
        """
        Initialize the Master Filter Dispatcher.
        """
        self.logger = logger
        self._engine = FilterEngine()
        self._lock = threading.Lock()

        self._routing_metadata: dict[str, dict[str, str]] = {
            "PROCESS": {
                "prefix": "PROCESS_",
                "filter_name": "ProcessFilter",
                "default_event_type": "PROCESS_CREATE",
            },
            "FILE": {
                "prefix": "FILE_",
                "filter_name": "FileFilter",
                "default_event_type": "FILE_CREATE",
            },
            "NETWORK": {
                "prefix": "NETWORK_",
                "filter_name": "NetworkFilter",
                "default_event_type": "NETWORK_CONNECT",
            },
            "REGISTRY": {
                "prefix": "REGISTRY_",
                "filter_name": "RegistryFilter",
                "default_event_type": "REGISTRY_MODIFY",
            },
        }

        self.logger.info("MasterFilterDispatcher initialized.")

    # ========================================================
    # PRIVATE HELPERS
    # ========================================================

    def _generate_correlation_id(self) -> str:
        """
        Generate a unique correlation ID as a UUID4 string.
        """

        return str(uuid.uuid4())

    def _normalize_event_type(self, event_type: Any) -> str:
        """
        Normalize a raw event_type value into an uppercase, trimmed
        string.

        Returns an empty string when the value is missing, empty, or
        not a string.
        """

        if not isinstance(event_type, str):
            return ""

        return event_type.strip().upper()

    def _resolve_filter_name(self, event_type: str) -> str:
        """
        Resolve the human-readable sub-filter name responsible for a
        normalized event type, based on routing metadata prefixes.
        """

        for metadata in self._routing_metadata.values():
            if event_type.startswith(metadata["prefix"]):
                return metadata["filter_name"]

        return "UnknownFilter"

    def _error_response(
        self,
        *,
        event_type: str,
        correlation_id: str,
        error: str,
        execution_time_ms: float,
    ) -> DispatchResponse:
        """
        Build a structured DispatchResponse representing a dispatch
        failure. Used to ensure dispatch() never raises outward.
        """

        return DispatchResponse(
            accepted=False,
            event_type=event_type,
            filter_name="N/A",
            correlation_id=correlation_id,
            execution_time_ms=round(execution_time_ms, 3),
            result=None,
            error=error,
        )

    def _inject_default_event_type(
        self, event: Any, category: str
    ) -> Any:
        """
        Return a copy of the event with a category-specific default
        event_type injected when missing or empty, without mutating
        the caller's original event dictionary.
        """

        if not isinstance(event, dict):
            return event

        working_event = copy.deepcopy(event)
        raw_event_type = working_event.get("event_type")

        if not isinstance(raw_event_type, str) or not raw_event_type.strip():
            working_event["event_type"] = self._routing_metadata[category][
                "default_event_type"
            ]

        return working_event

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def dispatch(self, event: dict[str, Any]) -> DispatchResponse:
        """
        Dispatch a single telemetry event through the FilterEngine.

        Parameters
        ----------
        event : dict

            Raw telemetry event. Expected to contain at least
            'event_type'.

        Returns
        -------
        DispatchResponse

        Never raises. All failures are captured and returned as a
        DispatchResponse with accepted=False and a populated error
        field.
        """
        start_time = time.perf_counter()
        correlation_id: str | None = None

        try:
            if not isinstance(event, dict):
                correlation_id = self._generate_correlation_id()
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return self._error_response(
                    event_type="UNKNOWN",
                    correlation_id=correlation_id,
                    error="Invalid event: expected a dictionary.",
                    execution_time_ms=elapsed_ms,
                )

            # Deep copy to guarantee the caller's original event is never
            # mutated, including any nested structures.
            event_copy = copy.deepcopy(event)

            raw_event_type = event_copy.get("event_type")
            if not isinstance(raw_event_type, str):
                correlation_id = self._generate_correlation_id()
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return self._error_response(
                    event_type="UNKNOWN",
                    correlation_id=correlation_id,
                    error="Invalid event: 'event_type' is missing or not a string.",
                    execution_time_ms=elapsed_ms,
                )

            normalized_event_type = self._normalize_event_type(raw_event_type)

            raw_correlation_id = event_copy.get("correlation_id")
            if isinstance(raw_correlation_id, str) and raw_correlation_id.strip():
                correlation_id = raw_correlation_id.strip()
            else:
                correlation_id = self._generate_correlation_id()

            if not normalized_event_type:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return self._error_response(
                    event_type="UNKNOWN",
                    correlation_id=correlation_id,
                    error=(
                        "Invalid event: 'event_type' is empty or "
                        "whitespace-only after normalization."
                    ),
                    execution_time_ms=elapsed_ms,
                )

            event_copy["event_type"] = normalized_event_type
            event_copy["correlation_id"] = correlation_id

            filter_name = self._resolve_filter_name(normalized_event_type)

            with self._lock:
                result = self._engine.filter_event(event_copy)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            accepted = bool(getattr(result, "accepted", False))

            result_payload: Any = result
            if hasattr(result, "to_dict") and callable(getattr(result, "to_dict")):
                result_payload = result.to_dict()

            self.logger.info(
                "MasterFilterDispatcher dispatched event.",
                extra={
                    "correlation_id": correlation_id,
                    "event_type": normalized_event_type,
                    "filter_name": filter_name,
                    "accepted": accepted,
                    "elapsed_ms": f"{elapsed_ms:.4f}",
                },
            )

            return DispatchResponse(
                accepted=accepted,
                event_type=normalized_event_type,
                filter_name=filter_name,
                correlation_id=correlation_id,
                execution_time_ms=round(elapsed_ms, 3),
                result=result_payload,
                error=None,
            )

        except Exception as exc:
            fallback_correlation_id = (
                correlation_id or self._generate_correlation_id()
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            self.logger.exception(
                "MasterFilterDispatcher failed to dispatch event.",
                extra={
                    "correlation_id": fallback_correlation_id,
                    "event_type": "UNKNOWN",
                },
            )
            return self._error_response(
                event_type="UNKNOWN",
                correlation_id=fallback_correlation_id,
                error=f"Unexpected dispatch error: {exc}",
                execution_time_ms=elapsed_ms,
            )

    # ========================================================
    # CONVENIENCE METHODS
    # ========================================================

    def filter_process(self, event: dict[str, Any]) -> DispatchResponse:
        """
        Dispatch a process telemetry event, injecting PROCESS_CREATE as
        the default event_type when missing.
        """

        return self.dispatch(self._inject_default_event_type(event, "PROCESS"))

    def filter_file(self, event: dict[str, Any]) -> DispatchResponse:
        """
        Dispatch a file telemetry event, injecting FILE_CREATE as the
        default event_type when missing.
        """

        return self.dispatch(self._inject_default_event_type(event, "FILE"))

    def filter_network(self, event: dict[str, Any]) -> DispatchResponse:
        """
        Dispatch a network telemetry event, injecting NETWORK_CONNECT as
        the default event_type when missing.
        """

        return self.dispatch(self._inject_default_event_type(event, "NETWORK"))

    def filter_registry(self, event: dict[str, Any]) -> DispatchResponse:
        """
        Dispatch a registry telemetry event, injecting REGISTRY_MODIFY as
        the default event_type when missing.
        """

        return self.dispatch(self._inject_default_event_type(event, "REGISTRY"))

    # ========================================================
    # HEALTH CHECK
    # ========================================================

    def health_check(self) -> dict[str, Any]:
        """
        Return a lightweight health status for the dispatcher.
        """

        return {
            "status": "healthy",
            "dispatcher": self.__class__.__name__,
            "thread_safe": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
