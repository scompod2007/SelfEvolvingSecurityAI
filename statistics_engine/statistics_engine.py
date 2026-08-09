"""Main statistics engine coordinator."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from .duplicate_counter import DuplicateCounter
from .models import (
    CounterSnapshot,
    DuplicateCheckResult,
    NoiseReductionResult,
    StatisticsResult,
)
from .noise_reduction import NoiseReductionEngine
from .runtime_metrics import RuntimeMetrics

_CATEGORY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("PROCESS_", "process"),
    ("FILE_", "file"),
    ("NETWORK_", "network"),
    ("REGISTRY_", "registry"),
)


class StatisticsEngine:
    """Coordinates runtime metrics, noise reduction, and duplicate detection
    for generic telemetry event dictionaries.

    The engine is independent from any specific collector implementation:
    it accepts plain event dictionaries and classifies them by the
    ``event_type`` field prefix. It is safe to share a single instance
    across multiple threads.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_events_per_key: int = 20,
        burst_threshold: int = 10,
        duplicate_retention_seconds: float = 300.0,
    ) -> None:
        """Initializes the statistics engine and its subsystems.

        Args:
            window_seconds: Sliding window width, in seconds, used by the
                noise reduction engine.
            max_events_per_key: Rate limit per event key used by the noise
                reduction engine.
            burst_threshold: Burst detection threshold used by the noise
                reduction engine.
            duplicate_retention_seconds: Retention window, in seconds, used
                by the duplicate counter.
        """
        self._runtime_metrics = RuntimeMetrics()
        self._noise_reduction = NoiseReductionEngine(
            window_seconds=window_seconds,
            max_events_per_key=max_events_per_key,
            burst_threshold=burst_threshold,
        )
        self._duplicate_counter = DuplicateCounter(
            retention_seconds=duplicate_retention_seconds
        )

        self._lock = threading.Lock()
        self._total_events: int = 0
        self._accepted_events: int = 0
        self._filtered_events: int = 0
        self._duplicate_events: int = 0
        self._suppressed_events: int = 0
        self._process_events: int = 0
        self._file_events: int = 0
        self._network_events: int = 0
        self._registry_events: int = 0
        self._unknown_events: int = 0

    def _classify(self, event: dict[str, Any]) -> str:
        """Classifies an event into a category from its ``event_type`` prefix.

        Args:
            event: The raw event dictionary.

        Returns:
            str: One of "process", "file", "network", "registry", or
            "unknown".
        """
        try:
            event_type = event.get("event_type")
        except AttributeError:
            return "unknown"

        if not isinstance(event_type, str):
            return "unknown"

        normalized = event_type.strip().upper()
        for prefix, category in _CATEGORY_PREFIXES:
            if normalized.startswith(prefix):
                return category
        return "unknown"

    def _increment_category_locked(self, category: str) -> None:
        """Increments the counter for a classified category.

        Must be called while holding ``self._lock``.

        Args:
            category: The classified event category.
        """
        if category == "process":
            self._process_events += 1
        elif category == "file":
            self._file_events += 1
        elif category == "network":
            self._network_events += 1
        elif category == "registry":
            self._registry_events += 1
        else:
            self._unknown_events += 1

    def process_event(
        self, event: dict[str, Any], processing_time_ms: float | None = None
    ) -> StatisticsResult:
        """Processes a single telemetry event through the full statistics
        pipeline.

        The processing flow is: update total counters, classify the event,
        check for duplicates, apply noise reduction, update
        accepted/filtered counters, record runtime metrics, and return a
        combined result. Malformed events are treated as unknown events
        rather than raising an exception.

        Args:
            event: The raw event dictionary to process.
            processing_time_ms: Optional externally measured processing
                duration, in milliseconds, to record against runtime
                metrics. When omitted, the duration of this method's own
                internal work is measured and recorded instead.

        Returns:
            StatisticsResult: The combined outcome of processing this
            event, including duplicate, noise reduction, counter, and
            runtime information.
        """
        start = time.perf_counter()

        try:
            safe_event: dict[str, Any] = event if isinstance(event, dict) else {}

            category = self._classify(safe_event)

            try:
                duplicate_result = self._duplicate_counter.check(safe_event)
            except Exception:
                duplicate_result = DuplicateCheckResult(
                    fingerprint="",
                    is_duplicate=False,
                    total_duplicates=0,
                    unique_events=0,
                    duplicate_ratio=0.0,
                    timestamp=datetime.now(timezone.utc),
                )

            if duplicate_result.is_duplicate:
                noise_result = NoiseReductionResult(
                    event_key="",
                    suppressed=False,
                    reason=None,
                    occurrences_in_window=0,
                    is_burst=False,
                    is_rate_limited=False,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                try:
                    noise_result = self._noise_reduction.evaluate(safe_event)
                except Exception:
                    noise_result = NoiseReductionResult(
                        event_key="",
                        suppressed=False,
                        reason=None,
                        occurrences_in_window=0,
                        is_burst=False,
                        is_rate_limited=False,
                        timestamp=datetime.now(timezone.utc),
                    )

            is_suppressed = duplicate_result.is_duplicate or noise_result.suppressed

            with self._lock:
                self._total_events += 1
                self._increment_category_locked(category)

                if duplicate_result.is_duplicate:
                    self._duplicate_events += 1
                if noise_result.suppressed:
                    self._filtered_events += 1
                if is_suppressed:
                    self._suppressed_events += 1
                    accepted = False
                else:
                    self._accepted_events += 1
                    accepted = True

                counters = self._build_counter_snapshot_locked()

            if processing_time_ms is not None:
                self._runtime_metrics.record(processing_time_ms)
            else:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                self._runtime_metrics.record(elapsed_ms)

            runtime = self._runtime_metrics.snapshot()

            return StatisticsResult(
                accepted=accepted,
                category=category,
                duplicate_check=duplicate_result,
                noise_reduction=noise_result,
                counters=counters,
                runtime=runtime,
                timestamp=datetime.now(timezone.utc),
            )

        except Exception:
            return self._build_fallback_unknown_result()

    def _build_fallback_unknown_result(self) -> StatisticsResult:
        """Builds a safe fallback result for a malformed or unprocessable
        event, counting it as an unknown, suppressed event.

        Returns:
            StatisticsResult: A best-effort result reflecting the fallback
            classification.
        """
        now_dt = datetime.now(timezone.utc)

        with self._lock:
            self._total_events += 1
            self._unknown_events += 1
            self._suppressed_events += 1
            counters = self._build_counter_snapshot_locked()

        self._runtime_metrics.record(0.0)
        runtime = self._runtime_metrics.snapshot()

        duplicate_result = DuplicateCheckResult(
            fingerprint="",
            is_duplicate=False,
            total_duplicates=0,
            unique_events=0,
            duplicate_ratio=0.0,
            timestamp=now_dt,
        )
        noise_result = NoiseReductionResult(
            event_key="",
            suppressed=False,
            reason=None,
            occurrences_in_window=0,
            is_burst=False,
            is_rate_limited=False,
            timestamp=now_dt,
        )

        return StatisticsResult(
            accepted=False,
            category="unknown",
            duplicate_check=duplicate_result,
            noise_reduction=noise_result,
            counters=counters,
            runtime=runtime,
            timestamp=now_dt,
        )

    def _build_counter_snapshot_locked(self) -> CounterSnapshot:
        """Builds a counter snapshot from current totals.

        Must be called while holding ``self._lock``.

        Returns:
            CounterSnapshot: The current counter values.
        """
        return CounterSnapshot(
            total_events=self._total_events,
            accepted_events=self._accepted_events,
            filtered_events=self._filtered_events,
            duplicate_events=self._duplicate_events,
            suppressed_events=self._suppressed_events,
            process_events=self._process_events,
            file_events=self._file_events,
            network_events=self._network_events,
            registry_events=self._registry_events,
            unknown_events=self._unknown_events,
            timestamp=datetime.now(timezone.utc),
        )

    def snapshot(self) -> StatisticsResult:
        """Returns a point-in-time statistics result reflecting cumulative
        engine state, without processing a new event.

        The ``duplicate_check`` and ``noise_reduction`` fields reflect
        aggregate totals rather than a specific event's evaluation, since
        no event is being evaluated.

        Returns:
            StatisticsResult: The current aggregate statistics.
        """
        with self._lock:
            counters = self._build_counter_snapshot_locked()
            total_duplicates = self._duplicate_events
            total_checked = self._total_events

        runtime = self._runtime_metrics.snapshot()
        now_dt = datetime.now(timezone.utc)

        unique_events = max(total_checked - total_duplicates, 0)
        duplicate_ratio = (
            total_duplicates / total_checked if total_checked > 0 else 0.0
        )

        duplicate_result = DuplicateCheckResult(
            fingerprint="",
            is_duplicate=False,
            total_duplicates=total_duplicates,
            unique_events=unique_events,
            duplicate_ratio=duplicate_ratio,
            timestamp=now_dt,
        )
        noise_result = NoiseReductionResult(
            event_key="",
            suppressed=False,
            reason=None,
            occurrences_in_window=0,
            is_burst=False,
            is_rate_limited=False,
            timestamp=now_dt,
        )

        return StatisticsResult(
            accepted=True,
            category="unknown",
            duplicate_check=duplicate_result,
            noise_reduction=noise_result,
            counters=counters,
            runtime=runtime,
            timestamp=now_dt,
        )

    def reset(self) -> None:
        """Resets all counters and underlying subsystems to their initial
        state."""
        with self._lock:
            self._total_events = 0
            self._accepted_events = 0
            self._filtered_events = 0
            self._duplicate_events = 0
            self._suppressed_events = 0
            self._process_events = 0
            self._file_events = 0
            self._network_events = 0
            self._registry_events = 0
            self._unknown_events = 0

        self._runtime_metrics.reset()
        self._noise_reduction.reset()
        self._duplicate_counter.reset()