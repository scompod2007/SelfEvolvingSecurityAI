"""
============================================================
Self-Evolving Security AI
Process Monitor Integration
Version : 1.0

Part 4.2
Process Monitor Integration

Responsibilities
----------------
• Connect collectors/process_monitor.py output to the
  MasterFilterDispatcher
• Preserve correlation_id
• Preserve timestamps
• Preserve parent PID information
• Preserve command line information
• Preserve executable path information
• Log accepted vs filtered decisions
• Forward accepted events to the next pipeline stage
• Track integration-level metrics

NO filtering logic belongs here. All filtering decisions are
delegated to the existing MasterFilterDispatcher / FilterEngine.

============================================================
"""

from __future__ import annotations

import copy
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

logger = logging.getLogger(__name__)

DownstreamHandler = Callable[[dict[str, Any]], None]


class ProcessMonitorIntegration:
    """
    Integration layer connecting the process monitor collector to the
    MasterFilterDispatcher and downstream pipeline.

    Stateless per request except for internal metrics, which are
    updated under a threading lock and safe to share across multiple
    threads.
    """

    def __init__(
        self,
        downstream_handler: DownstreamHandler | None = None,
        dispatcher: MasterFilterDispatcher | None = None,
    ) -> None:
        """
        Initialize the Process Monitor Integration.
        """
        self.logger = logger
        self.dispatcher = (
            dispatcher if dispatcher is not None else MasterFilterDispatcher()
        )
        self.downstream_handler: DownstreamHandler | None = downstream_handler

        self._lock = threading.Lock()

        self._metrics: dict[str, Any] = {
            "total_events": 0,
            "accepted_events": 0,
            "filtered_events": 0,
            "forwarded_events": 0,
            "error_events": 0,
            "last_processed_at": None,
        }

        self.logger.info("ProcessMonitorIntegration initialized.")

    # ========================================================
    # PUBLIC CONFIGURATION
    # ========================================================

    def set_downstream_handler(self, handler: DownstreamHandler | None) -> None:
        """
        Register, or clear, the downstream handler invoked for accepted
        events.
        """

        self.downstream_handler = handler

    # ========================================================
    # PRIVATE HELPERS
    # ========================================================

    def _build_result(
        self,
        *,
        accepted: bool,
        correlation_id: str,
        event_type: str,
        filter_name: str,
        execution_time_ms: float,
        forwarded: bool,
        error: str | None,
    ) -> dict[str, Any]:
        """
        Build the structured result dictionary returned by
        process_event().
        """

        return {
            "accepted": accepted,
            "correlation_id": correlation_id,
            "event_type": event_type,
            "filter_name": filter_name,
            "execution_time_ms": execution_time_ms,
            "forwarded": forwarded,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _update_metrics_locked(
        self, *, accepted: bool, forwarded: bool, error: bool
    ) -> None:
        """
        Update internal metrics. Must be called while holding
        self._lock.
        """

        self._metrics["total_events"] += 1

        if error:
            self._metrics["error_events"] += 1
        elif accepted:
            self._metrics["accepted_events"] += 1
        else:
            self._metrics["filtered_events"] += 1

        if forwarded:
            self._metrics["forwarded_events"] += 1

        self._metrics["last_processed_at"] = datetime.now(timezone.utc).isoformat()

    def _forward_downstream(
        self, event: dict[str, Any], *, correlation_id: str, event_type: str
    ) -> bool:
        """
        Forward an accepted event to the registered downstream handler,
        if any. Never raises outward.
        """

        if self.downstream_handler is None:
            return False

        try:
            self.downstream_handler(event)
            return True
        except Exception:
            self.logger.exception(
                "ProcessMonitorIntegration downstream handler failed.",
                extra={
                    "correlation_id": correlation_id,
                    "event_type": event_type,
                },
            )
            return False

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Process a single process telemetry event through the dispatcher
        and forward accepted events downstream.

        Parameters
        ----------
        event : dict

            Raw process telemetry event, typically produced by
            collectors/process_monitor.py. Expected fields include
            pid, ppid / parent_pid, parent_process_name, process_name,
            process_path / executable_path / exe, command_line /
            cmdline, and timestamp.

        Returns
        -------
        dict

            Structured result containing at least: accepted,
            correlation_id, event_type, filter_name,
            execution_time_ms, forwarded, error, timestamp.

        Never raises. All failures are captured and returned as a
        structured result dictionary with accepted=False and a
        populated error field.
        """

        try:
            if not isinstance(event, dict):
                result = self._build_result(
                    accepted=False,
                    correlation_id="",
                    event_type="UNKNOWN",
                    filter_name="N/A",
                    execution_time_ms=0.0,
                    forwarded=False,
                    error="Invalid event: expected a dictionary.",
                )
                with self._lock:
                    self._update_metrics_locked(
                        accepted=False, forwarded=False, error=True
                    )
                return result

            # Deep copy so the caller's original event is never mutated,
            # including any nested structures. This also preserves the
            # existing pid, ppid, parent_pid, parent_process_name,
            # process_name, process_path, executable_path, exe,
            # command_line, and cmdline fields untouched.
            event_copy = copy.deepcopy(event)

            # Preserve an existing timestamp; otherwise inject a UTC ISO one
            if not event_copy.get("timestamp"):
                event_copy["timestamp"] = datetime.now(timezone.utc).isoformat()

            # Default event_type to PROCESS_CREATE when absent or empty
            raw_event_type = event_copy.get("event_type")
            if not isinstance(raw_event_type, str) or not raw_event_type.strip():
                event_copy["event_type"] = "PROCESS_CREATE"

            response = self.dispatcher.filter_process(event_copy)

            accepted = bool(getattr(response, "accepted", False))
            correlation_id = str(getattr(response, "correlation_id", "") or "")
            event_type = str(getattr(response, "event_type", "") or "")
            filter_name = str(getattr(response, "filter_name", "") or "")
            execution_time_ms = float(
                getattr(response, "execution_time_ms", 0.0) or 0.0
            )
            dispatch_error = getattr(response, "error", None)

            forwarded = False
            if accepted:
                forwarded = self._forward_downstream(
                    event_copy,
                    correlation_id=correlation_id,
                    event_type=event_type,
                )

            if accepted:
                self.logger.info(
                    "ProcessMonitorIntegration accepted event.",
                    extra={
                        "correlation_id": correlation_id,
                        "event_type": event_type,
                        "filter_name": filter_name,
                        "forwarded": forwarded,
                    },
                )
            else:
                self.logger.info(
                    "ProcessMonitorIntegration filtered event.",
                    extra={
                        "correlation_id": correlation_id,
                        "event_type": event_type,
                        "filter_name": filter_name,
                        "reason": dispatch_error,
                    },
                )

            with self._lock:
                self._update_metrics_locked(
                    accepted=accepted, forwarded=forwarded, error=False
                )

            return self._build_result(
                accepted=accepted,
                correlation_id=correlation_id,
                event_type=event_type,
                filter_name=filter_name,
                execution_time_ms=execution_time_ms,
                forwarded=forwarded,
                error=dispatch_error,
            )

        except Exception as exc:
            self.logger.exception(
                "ProcessMonitorIntegration failed to process event."
            )
            with self._lock:
                self._update_metrics_locked(
                    accepted=False, forwarded=False, error=True
                )
            return self._build_result(
                accepted=False,
                correlation_id="",
                event_type="UNKNOWN",
                filter_name="N/A",
                execution_time_ms=0.0,
                forwarded=False,
                error=f"Unexpected integration error: {exc}",
            )

    def process_batch(
        self, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Process a batch of process telemetry events independently,
        preserving input order and continuing after individual
        failures.

        Never raises outward.
        """

        results: list[dict[str, Any]] = []

        if not isinstance(events, list):
            return results

        for event in events:
            results.append(self.process_event(event))

        return results

    # ========================================================
    # METRICS
    # ========================================================

    def get_metrics(self) -> dict[str, Any]:
        """
        Return a snapshot of the current integration metrics.
        """

        with self._lock:
            return dict(self._metrics)

    def reset_metrics(self) -> None:
        """
        Reset all integration metrics to their initial state.
        """

        with self._lock:
            self._metrics = {
                "total_events": 0,
                "accepted_events": 0,
                "filtered_events": 0,
                "forwarded_events": 0,
                "error_events": 0,
                "last_processed_at": None,
            }

    # ========================================================
    # HEALTH CHECK
    # ========================================================

    def health_check(self) -> dict[str, Any]:
        """
        Return a lightweight health status for the integration layer.
        """

        return {
            "status": "healthy",
            "component": self.__class__.__name__,
            "dispatcher_available": self.dispatcher is not None,
            "downstream_configured": self.downstream_handler is not None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
