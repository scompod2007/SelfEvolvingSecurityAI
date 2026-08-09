"""Dataclasses shared by the statistics engine subsystem."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class CounterSnapshot:
    """Immutable snapshot of the statistics engine's event counters.

    Attributes:
        total_events: Total number of events observed.
        accepted_events: Events that passed duplicate and noise checks.
        filtered_events: Events suppressed by noise reduction.
        duplicate_events: Events identified as duplicates.
        suppressed_events: Events rejected for any reason (filtered
            or duplicate) combined.
        process_events: Events classified as process events.
        file_events: Events classified as file events.
        network_events: Events classified as network events.
        registry_events: Events classified as registry events.
        unknown_events: Events that could not be classified.
        timestamp: UTC timestamp the snapshot was produced.
    """

    total_events: int
    accepted_events: int
    filtered_events: int
    duplicate_events: int
    suppressed_events: int
    process_events: int
    file_events: int
    network_events: int
    registry_events: int
    unknown_events: int
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Returns a JSON-serializable dictionary representation."""
        return {
            "total_events": self.total_events,
            "accepted_events": self.accepted_events,
            "filtered_events": self.filtered_events,
            "duplicate_events": self.duplicate_events,
            "suppressed_events": self.suppressed_events,
            "process_events": self.process_events,
            "file_events": self.file_events,
            "network_events": self.network_events,
            "registry_events": self.registry_events,
            "unknown_events": self.unknown_events,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True)
class RuntimeSnapshot:
    """Immutable snapshot of runtime performance metrics.

    Attributes:
        total_processed: Total number of recorded processing durations.
        total_processing_time_ms: Sum of all recorded durations, in milliseconds.
        average_latency_ms: Mean processing duration, in milliseconds.
        min_latency_ms: Minimum recorded duration, in milliseconds.
        max_latency_ms: Maximum recorded duration, in milliseconds.
        throughput_eps: Events processed per second since start or last reset.
        uptime_seconds: Elapsed seconds since start or last reset.
        last_event_timestamp: UTC timestamp of the most recently recorded event.
        timestamp: UTC timestamp the snapshot was produced.
    """

    total_processed: int
    total_processing_time_ms: float
    average_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    throughput_eps: float
    uptime_seconds: float
    last_event_timestamp: datetime | None
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Returns a JSON-serializable dictionary representation."""
        return {
            "total_processed": self.total_processed,
            "total_processing_time_ms": self.total_processing_time_ms,
            "average_latency_ms": self.average_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "throughput_eps": self.throughput_eps,
            "uptime_seconds": self.uptime_seconds,
            "last_event_timestamp": (
                self.last_event_timestamp.isoformat()
                if self.last_event_timestamp is not None
                else None
            ),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True)
class NoiseReductionResult:
    """Outcome of evaluating a single event against noise reduction rules.

    Attributes:
        event_key: Stable key derived from the event's identifying fields.
        suppressed: Whether the event should be suppressed.
        reason: Human-readable explanation, or None when not suppressed.
        occurrences_in_window: Count of events sharing this key within the
            current sliding window, including the evaluated event.
        is_burst: Whether the event was part of a detected burst.
        is_rate_limited: Whether the event exceeded the configured rate cap.
        timestamp: UTC timestamp the evaluation was performed.
    """

    event_key: str
    suppressed: bool
    reason: str | None
    occurrences_in_window: int
    is_burst: bool
    is_rate_limited: bool
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Returns a JSON-serializable dictionary representation."""
        return {
            "event_key": self.event_key,
            "suppressed": self.suppressed,
            "reason": self.reason,
            "occurrences_in_window": self.occurrences_in_window,
            "is_burst": self.is_burst,
            "is_rate_limited": self.is_rate_limited,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True)
class DuplicateCheckResult:
    """Outcome of checking a single event for duplication.

    Attributes:
        fingerprint: SHA-256 hex digest identifying the event's content.
        is_duplicate: Whether the fingerprint was already seen within the
            retention window.
        total_duplicates: Cumulative count of duplicate events observed.
        unique_events: Cumulative count of unique fingerprints observed.
        duplicate_ratio: Ratio of duplicates to total checked events, in
            the range [0.0, 1.0].
        timestamp: UTC timestamp the check was performed.
    """

    fingerprint: str
    is_duplicate: bool
    total_duplicates: int
    unique_events: int
    duplicate_ratio: float
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Returns a JSON-serializable dictionary representation."""
        return {
            "fingerprint": self.fingerprint,
            "is_duplicate": self.is_duplicate,
            "total_duplicates": self.total_duplicates,
            "unique_events": self.unique_events,
            "duplicate_ratio": self.duplicate_ratio,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True)
class StatisticsResult:
    """Outcome of processing a single event through the statistics engine.

    Attributes:
        accepted: Whether the event was accepted (not filtered or a
            duplicate).
        category: Classified event category (e.g. "process", "file",
            "network", "registry", "unknown").
        duplicate_check: The duplicate-detection outcome for this event.
        noise_reduction: The noise-reduction outcome for this event.
        counters: The counter snapshot taken after processing this event.
        runtime: The runtime snapshot taken after processing this event.
        timestamp: UTC timestamp the result was produced.
    """

    accepted: bool
    category: str
    duplicate_check: DuplicateCheckResult
    noise_reduction: NoiseReductionResult
    counters: CounterSnapshot
    runtime: RuntimeSnapshot
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Returns a JSON-serializable dictionary representation."""
        return {
            "accepted": self.accepted,
            "category": self.category,
            "duplicate_check": self.duplicate_check.to_dict(),
            "noise_reduction": self.noise_reduction.to_dict(),
            "counters": self.counters.to_dict(),
            "runtime": self.runtime.to_dict(),
            "timestamp": self.timestamp.isoformat(),
        }
