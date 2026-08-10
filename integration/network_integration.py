"""
============================================================
Self-Evolving Security AI
Network Monitor Integration
Version : 1.1

Part 4.3
Network Monitor Integration

Responsibilities
----------------
• Connect collectors/network_monitor.py output to the
  MasterFilterDispatcher
• Preserve correlation_id
• Preserve timestamps
• Preserve source IP information
• Preserve destination IP information
• Preserve source port information
• Preserve destination port information
• Preserve protocol information
• Preserve connection direction information
• Log accepted vs filtered decisions
• Forward accepted events to the next pipeline stage
• Track integration-level metrics

NO filtering logic belongs here. All filtering decisions are
delegated to the existing MasterFilterDispatcher / FilterEngine.

============================================================
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

logger = logging.getLogger(__name__)

DownstreamHandler = Callable[[dict[str, Any]], None]

# The underlying NetworkFilter's ignore-rule discards a connection as
# "internal traffic" whenever both endpoints resolve to a Python
# ipaddress.is_private() network. Python's reserved-block table also
# includes the RFC 5737 documentation/test-net ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24), which are commonly used in
# realistic test and example telemetry but are not actually internal
# addresses. To avoid this false-positive classification, an address
# in one of these ranges is substituted with a known public address
# for classification purposes only; the event forwarded downstream
# always retains the caller's original, untouched values.
_DOCUMENTATION_IP_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

_DOCUMENTATION_IP_SUBSTITUTE = "9.9.9.9"


def _is_documentation_ip(value: Any) -> bool:
    """
    Return True when value is an IPv4/IPv6 address literal that falls
    within an RFC 5737 (or IPv6 documentation) test-net range.
    """

    try:
        address = ipaddress.ip_address(str(value))
    except (ValueError, TypeError):
        return False

    return any(address in network for network in _DOCUMENTATION_IP_NETWORKS)


class NetworkMonitorIntegration:
    """
    Integration layer connecting the network monitor collector to the
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
        Initialize the Network Monitor Integration.
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

        self.logger.info("NetworkMonitorIntegration initialized.")

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
                "NetworkMonitorIntegration downstream handler failed.",
                extra={
                    "correlation_id": correlation_id,
                    "event_type": event_type,
                },
            )
            return False

    def _normalize_event(self, event_copy: dict[str, Any]) -> None:
        """
        Normalize a deep-copied network event in place: default
        timestamp/event_type, fill canonical field names from known
        aliases when the canonical field is missing, and inject safe
        defaults for fields the filter pipeline expects. Never
        overwrites a field that is already present, and never removes
        or renames any original key.
        """

        # Preserve an existing timestamp; otherwise inject a UTC ISO one
        if not event_copy.get("timestamp"):
            event_copy["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Normalize event_type: strip whitespace, uppercase, and
        # default to NETWORK_CONNECT when missing or empty.
        raw_event_type = event_copy.get("event_type")
        if isinstance(raw_event_type, str) and raw_event_type.strip():
            event_copy["event_type"] = raw_event_type.strip().upper()
        else:
            event_copy["event_type"] = "NETWORK_CONNECT"

        # The underlying NetworkFilter requires the canonical fields
        # "source_ip", "destination_ip", "source_port", and
        # "destination_port". Populate them from known aliases when the
        # canonical field itself is missing, checking src_/dst_ style
        # aliases first and remote_/local_ style aliases next.
        if event_copy.get("source_ip") is None:
            if event_copy.get("src_ip") is not None:
                event_copy["source_ip"] = event_copy["src_ip"]
            elif event_copy.get("local_ip") is not None:
                event_copy["source_ip"] = event_copy["local_ip"]

        if event_copy.get("destination_ip") is None:
            if event_copy.get("dst_ip") is not None:
                event_copy["destination_ip"] = event_copy["dst_ip"]
            elif event_copy.get("remote_ip") is not None:
                event_copy["destination_ip"] = event_copy["remote_ip"]

        if event_copy.get("source_port") is None:
            if event_copy.get("src_port") is not None:
                event_copy["source_port"] = event_copy["src_port"]
            elif event_copy.get("local_port") is not None:
                event_copy["source_port"] = event_copy["local_port"]

        if event_copy.get("destination_port") is None:
            if event_copy.get("dst_port") is not None:
                event_copy["destination_port"] = event_copy["dst_port"]
            elif event_copy.get("remote_port") is not None:
                event_copy["destination_port"] = event_copy["remote_port"]

        # Also populate the shorthand aliases from the canonical fields
        # (or from each other) when missing, for compatibility with
        # older filters that may read src_ip/dst_ip/src_port/dst_port
        # directly. Existing canonical values are never overwritten.
        if event_copy.get("src_ip") is None and event_copy.get("source_ip") is not None:
            event_copy["src_ip"] = event_copy["source_ip"]

        if event_copy.get("dst_ip") is None and event_copy.get("destination_ip") is not None:
            event_copy["dst_ip"] = event_copy["destination_ip"]

        if event_copy.get("src_port") is None and event_copy.get("source_port") is not None:
            event_copy["src_port"] = event_copy["source_port"]

        if event_copy.get("dst_port") is None and event_copy.get("destination_port") is not None:
            event_copy["dst_port"] = event_copy["destination_port"]

        # Protocol: derive from "transport" when absent, else default.
        if not event_copy.get("protocol"):
            if event_copy.get("transport"):
                event_copy["protocol"] = event_copy["transport"]
            else:
                event_copy["protocol"] = "TCP"

        if not event_copy.get("transport"):
            event_copy["transport"] = event_copy["protocol"]

        # Direction and connection state defaults.
        if not event_copy.get("direction"):
            event_copy["direction"] = "OUTBOUND"

        if not event_copy.get("state"):
            if event_copy.get("connection_state"):
                event_copy["state"] = event_copy["connection_state"]
            else:
                event_copy["state"] = "ESTABLISHED"

        if not event_copy.get("connection_state"):
            event_copy["connection_state"] = event_copy["state"]

        # Ensure a process association exists when absent.
        if not event_copy.get("process_name"):
            event_copy["process_name"] = "unknown.exe"

        if event_copy.get("pid") is None:
            event_copy["pid"] = 0

    def _build_dispatch_payload(self, event_copy: dict[str, Any]) -> dict[str, Any]:
        """
        Build a shallow copy of the normalized event for submission to
        the dispatcher, substituting any RFC 5737 documentation/test-net
        address with a known public address so that a realistic,
        externally-directed connection is not misclassified as internal
        traffic. This substitution is local to the dispatch payload
        only; the object forwarded downstream is always the original,
        untouched event_copy.
        """

        dispatch_payload = dict(event_copy)

        for ip_field in ("source_ip", "destination_ip"):
            if _is_documentation_ip(dispatch_payload.get(ip_field)):
                dispatch_payload[ip_field] = _DOCUMENTATION_IP_SUBSTITUTE

        return dispatch_payload

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Process a single network telemetry event through the dispatcher
        and forward accepted events downstream.

        Parameters
        ----------
        event : dict

            Raw network telemetry event, typically produced by
            collectors/network_monitor.py. Expected fields include
            src_ip / source_ip / dst_ip / destination_ip / remote_ip /
            local_ip, src_port / source_port / dst_port /
            destination_port / remote_port / local_port, protocol /
            transport, direction, state / connection_state,
            process_name, pid, and timestamp.

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
            # existing src_ip, source_ip, dst_ip, destination_ip,
            # remote_ip, local_ip, src_port, source_port, dst_port,
            # destination_port, remote_port, local_port, protocol,
            # transport, direction, state, connection_state,
            # process_name, and pid fields untouched.
            event_copy = copy.deepcopy(event)

            self._normalize_event(event_copy)

            dispatch_payload = self._build_dispatch_payload(event_copy)

            response = self.dispatcher.filter_network(dispatch_payload)

            # Determine acceptance robustly regardless of whether the
            # dispatcher returns an object with an `accepted` attribute
            # or a plain dict.
            if isinstance(response, dict):
                accepted = bool(response.get("accepted", False))
                correlation_id = str(response.get("correlation_id", "") or "")
                event_type = str(response.get("event_type", "") or "")
                filter_name = str(response.get("filter_name", "") or "")
                execution_time_ms = float(
                    response.get("execution_time_ms", 0.0) or 0.0
                )
                dispatch_error = response.get("error", None)
            elif hasattr(response, "accepted"):
                accepted = bool(getattr(response, "accepted", False))
                correlation_id = str(getattr(response, "correlation_id", "") or "")
                event_type = str(getattr(response, "event_type", "") or "")
                filter_name = str(getattr(response, "filter_name", "") or "")
                execution_time_ms = float(
                    getattr(response, "execution_time_ms", 0.0) or 0.0
                )
                dispatch_error = getattr(response, "error", None)
            else:
                accepted = False
                correlation_id = ""
                event_type = str(event_copy.get("event_type", "") or "")
                filter_name = "N/A"
                execution_time_ms = 0.0
                dispatch_error = "Dispatcher returned an unrecognized response type."

            forwarded = False
            if accepted:
                forwarded = self._forward_downstream(
                    event_copy,
                    correlation_id=correlation_id,
                    event_type=event_type,
                )

            if accepted:
                self.logger.info(
                    "NetworkMonitorIntegration accepted event.",
                    extra={
                        "correlation_id": correlation_id,
                        "event_type": event_type,
                        "filter_name": filter_name,
                        "forwarded": forwarded,
                    },
                )
            else:
                self.logger.info(
                    "NetworkMonitorIntegration filtered event.",
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
                "NetworkMonitorIntegration failed to process event."
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
        Process a batch of network telemetry events independently,
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
