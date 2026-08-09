"""Thread-safe runtime performance metric tracking."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from .models import RuntimeSnapshot


class RuntimeMetrics:
    """Tracks processing latency, throughput, and uptime in a thread-safe
    manner.

    Durations are recorded in milliseconds. Uptime and throughput are
    computed relative to the last time the tracker was started or reset,
    using ``time.perf_counter()`` for monotonic timing.
    """

    def __init__(self) -> None:
        """Initializes counters and starts the uptime clock."""
        self._lock = threading.Lock()
        self._total_processed: int = 0
        self._total_processing_time_ms: float = 0.0
        self._min_latency_ms: float | None = None
        self._max_latency_ms: float | None = None
        self._last_event_timestamp: datetime | None = None
        self._start_perf_counter: float = time.perf_counter()

    def record(self, duration_ms: float) -> None:
        """Records a single processing duration.

        Args:
            duration_ms: Duration of the processing operation, in
                milliseconds. Negative values are ignored.
        """
        if duration_ms < 0:
            return

        with self._lock:
            self._total_processed += 1
            self._total_processing_time_ms += duration_ms

            if self._min_latency_ms is None or duration_ms < self._min_latency_ms:
                self._min_latency_ms = duration_ms
            if self._max_latency_ms is None or duration_ms > self._max_latency_ms:
                self._max_latency_ms = duration_ms

            self._last_event_timestamp = datetime.now(timezone.utc)

    def snapshot(self) -> RuntimeSnapshot:
        """Computes and returns a point-in-time snapshot of runtime metrics.

        Returns:
            RuntimeSnapshot: The current runtime metrics.
        """
        with self._lock:
            total_processed = self._total_processed
            total_processing_time_ms = self._total_processing_time_ms
            min_latency_ms = self._min_latency_ms if self._min_latency_ms is not None else 0.0
            max_latency_ms = self._max_latency_ms if self._max_latency_ms is not None else 0.0
            last_event_timestamp = self._last_event_timestamp
            elapsed_seconds = max(time.perf_counter() - self._start_perf_counter, 0.0)

        average_latency_ms = (
            total_processing_time_ms / total_processed if total_processed > 0 else 0.0
        )
        throughput_eps = (
            total_processed / elapsed_seconds if elapsed_seconds > 0 else 0.0
        )

        return RuntimeSnapshot(
            total_processed=total_processed,
            total_processing_time_ms=total_processing_time_ms,
            average_latency_ms=average_latency_ms,
            min_latency_ms=min_latency_ms,
            max_latency_ms=max_latency_ms,
            throughput_eps=throughput_eps,
            uptime_seconds=elapsed_seconds,
            last_event_timestamp=last_event_timestamp,
            timestamp=datetime.now(timezone.utc),
        )

    def reset(self) -> None:
        """Resets all counters and restarts the uptime clock."""
        with self._lock:
            self._total_processed = 0
            self._total_processing_time_ms = 0.0
            self._min_latency_ms = None
            self._max_latency_ms = None
            self._last_event_timestamp = None
            self._start_perf_counter = time.perf_counter()
