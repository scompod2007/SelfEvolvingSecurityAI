"""Thread-safe noise reduction and repetitive event suppression."""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque

from .models import NoiseReductionResult

_UNKNOWN_FIELD_PLACEHOLDER: str = "-"


class NoiseReductionEngine:
    """Suppresses repetitive, bursty, or rate-exceeding telemetry events.

    Events are grouped into sliding time windows keyed by a stable
    signature derived from ``event_type``, ``process_name``, ``file_path``,
    ``destination_ip``, and ``registry_key``. Within each window, an event
    is flagged as a burst when its occurrence count reaches
    ``burst_threshold`` and as rate-limited when the count exceeds
    ``max_events_per_key``.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_events_per_key: int = 20,
        burst_threshold: int = 10,
    ) -> None:
        """Initializes the noise reduction engine.

        Args:
            window_seconds: Width of the sliding window, in seconds, used
                to count occurrences per event key.
            max_events_per_key: Maximum number of events allowed for a
                single key within the window before suppression as
                rate-limited.
            burst_threshold: Minimum number of events for a single key
                within the window to be classified as a burst.
        """
        self._window_seconds: float = window_seconds
        self._max_events_per_key: int = max_events_per_key
        self._burst_threshold: int = burst_threshold
        self._lock = threading.Lock()
        self._windows: dict[str, Deque[float]] = {}

    def _extract_field(self, event: dict[str, Any], key: str) -> str:
        """Safely extracts and stringifies a field from an event dictionary.

        Args:
            event: The raw event dictionary.
            key: The field name to extract.

        Returns:
            str: The stringified field value, or a placeholder when absent.
        """
        try:
            value = event.get(key)
        except AttributeError:
            return _UNKNOWN_FIELD_PLACEHOLDER
        if value is None:
            return _UNKNOWN_FIELD_PLACEHOLDER
        return str(value)

    def _make_event_key(self, event: dict[str, Any]) -> str:
        """Builds a stable event key from identifying fields.

        Args:
            event: The raw event dictionary.

        Returns:
            str: A stable, delimiter-joined key.
        """
        event_type = self._extract_field(event, "event_type")
        process_name = self._extract_field(event, "process_name")
        file_path = self._extract_field(event, "file_path")
        destination_ip = self._extract_field(event, "destination_ip")
        registry_key = self._extract_field(event, "registry_key")
        return "|".join(
            (event_type, process_name, file_path, destination_ip, registry_key)
        )

    def _prune_window(self, window: Deque[float], now: float) -> None:
        """Removes entries older than the configured window from a deque.

        Args:
            window: The deque of monotonic-like epoch timestamps for a key.
            now: The current epoch timestamp.
        """
        cutoff = now - self._window_seconds
        while window and window[0] < cutoff:
            window.popleft()

    def evaluate(self, event: dict[str, Any]) -> NoiseReductionResult:
        """Evaluates a single event against noise reduction rules.

        Args:
            event: The raw event dictionary to evaluate.

        Returns:
            NoiseReductionResult: The suppression decision and supporting
            counts for this event.
        """
        if not isinstance(event, dict):
            event = {}

        now_dt = datetime.now(timezone.utc)
        now = now_dt.timestamp()
        event_key = self._make_event_key(event)

        with self._lock:
            window = self._windows.setdefault(event_key, deque())
            self._prune_window(window, now)
            window.append(now)
            occurrences_in_window = len(window)

        is_burst = occurrences_in_window >= self._burst_threshold
        is_rate_limited = occurrences_in_window > self._max_events_per_key
        suppressed = is_burst or is_rate_limited

        reason: str | None = None
        if is_rate_limited:
            reason = (
                f"Rate limit exceeded: {occurrences_in_window} events for key "
                f"'{event_key}' within {self._window_seconds}s window "
                f"(limit {self._max_events_per_key})."
            )
        elif is_burst:
            reason = (
                f"Burst detected: {occurrences_in_window} events for key "
                f"'{event_key}' within {self._window_seconds}s window "
                f"(threshold {self._burst_threshold})."
            )

        return NoiseReductionResult(
            event_key=event_key,
            suppressed=suppressed,
            reason=reason,
            occurrences_in_window=occurrences_in_window,
            is_burst=is_burst,
            is_rate_limited=is_rate_limited,
            timestamp=now_dt,
        )

    def reset(self) -> None:
        """Clears all sliding windows and suppression state."""
        with self._lock:
            self._windows.clear()
