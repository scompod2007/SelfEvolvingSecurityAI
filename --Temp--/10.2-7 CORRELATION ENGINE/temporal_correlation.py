"""
============================================================
Self-Evolving Security AI
Part 2.10.5 - Temporal Correlation Engine
============================================================

This module correlates events based on time proximity using
sliding and rolling windows. It supports delayed matching,
burst detection, out-of-order event handling, timestamp
normalization, and clock skew tolerance.

It is completely independent from confidence scoring, risk
scoring, and severity calculation.
"""

import bisect
import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
DETERMINISTIC_ID_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "self-evolving-security-ai.temporal-correlation"
)

DEFAULT_WINDOW_SECONDS: float = 30.0
DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS: float = 2.0
DEFAULT_BURST_THRESHOLD_COUNT: int = 5
DEFAULT_BURST_WINDOW_SECONDS: float = 10.0


# ============================================================
# CONFIGURATION DATACLASS
# ============================================================
@dataclass(slots=True)
class TemporalConfig:
    """
    Configuration controlling temporal correlation behavior.

    Attributes:
        window_seconds (float): Width of the sliding/rolling correlation window.
        rolling_window (bool): When True, uses a fixed-origin rolling window;
            when False, uses a sliding window centered/anchored on each event.
        clock_skew_tolerance_seconds (float): Extra allowance applied to
            window boundaries to tolerate minor clock skew between sources.
        burst_threshold_count (int): Minimum number of events within
            burst_window_seconds to classify as a burst.
        burst_window_seconds (float): Width of the window used for burst
            detection.
        max_delayed_match_seconds (float): Maximum allowed delay for a
            late-arriving event to still be matched against an earlier window.
    """
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    rolling_window: bool = False
    clock_skew_tolerance_seconds: float = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS
    burst_threshold_count: int = DEFAULT_BURST_THRESHOLD_COUNT
    burst_window_seconds: float = DEFAULT_BURST_WINDOW_SECONDS
    max_delayed_match_seconds: float = 300.0


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class TemporalResult:
    """
    Represents the outcome of temporal correlation for a single event
    against a batch or stream of other events.

    Attributes:
        event_id (str): Identifier of the event being correlated.
        correlated_event_ids (list[str]): Identifiers of events found within
            the configured temporal window.
        is_burst (bool): Whether this event is part of a detected burst.
        burst_event_count (int): Number of events in the burst window, if any.
        temporal_confidence (float): Confidence score based on time proximity,
            in the range [0.0, 1.0].
        proximity_scores (dict[str, float]): Per-correlated-event proximity
            scores, keyed by event ID.
        reasons (list[str]): Human-readable explanations for the correlation.
        metadata (dict[str, Any]): Additional structured context.
        timestamp (datetime): UTC timestamp of when this result was computed.
    """
    event_id: str
    correlated_event_ids: list[str]
    is_burst: bool
    burst_event_count: int
    temporal_confidence: float
    proximity_scores: dict[str, float]
    reasons: list[str]
    metadata: dict[str, Any]
    timestamp: datetime


# ============================================================
# TEMPORAL CORRELATION ENGINE
# ============================================================
class TemporalCorrelationEngine:
    """
    A thread-safe engine that correlates events based on time proximity.
    Maintains an internally sorted timestamp index (via bisect) to enable
    O(log n) window lookups even across out-of-order event arrival,
    scaling efficiently to 100,000+ events.
    """

    def __init__(self, config: TemporalConfig | None = None) -> None:
        """
        Initializes the engine with an optional configuration.

        Args:
            config (TemporalConfig | None): Engine configuration. Uses
                defaults when omitted.
        """
        self._config: TemporalConfig = config or TemporalConfig()
        self._lock = threading.RLock()
        self._event_ids: list[str] = []
        self._timestamps: list[float] = []
        self._events_by_id: dict[str, Mapping[str, Any]] = {}

    # ------------------------------------------------------------
    # NORMALIZATION HELPERS
    # ------------------------------------------------------------
    def _normalize_str(self, value: Any) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned.lower() if cleaned else None

    def _extract_event_id(self, event: Mapping[str, Any]) -> str:
        for key in ("event_id", "id", "uuid"):
            normalized = self._normalize_str(event.get(key))
            if normalized:
                return normalized
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, repr(sorted(event.items(), key=lambda kv: str(kv[0])))))

    def _normalize_timestamp(self, event: Mapping[str, Any]) -> datetime:
        """
        Normalizes an event's timestamp field into a timezone-aware UTC
        datetime, tolerating naive datetimes, ISO-formatted strings, and
        missing values.

        Args:
            event (Mapping[str, Any]): The event to extract a timestamp from.

        Returns:
            datetime: A timezone-aware UTC datetime.
        """
        raw = event.get("timestamp")
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning("Unable to parse timestamp string '%s'; falling back to current time.", raw)
        elif isinstance(raw, (int, float)):
            try:
                return datetime.fromtimestamp(float(raw), tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                logger.warning("Unable to parse numeric timestamp '%s'; falling back to current time.", raw)
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------
    # INDEX CONSTRUCTION
    # ------------------------------------------------------------
    def build_index(self, events: Sequence[Mapping[str, Any]]) -> None:
        """
        Builds (or rebuilds) the internal sorted-timestamp index from a
        batch of events, tolerating out-of-order arrival by sorting during
        construction.

        Args:
            events (Sequence[Mapping[str, Any]]): The events to index.
        """
        if not isinstance(events, Sequence):
            logger.warning("build_index received a non-sequence input; no index built.")
            events = []

        entries: list[tuple[float, str, Mapping[str, Any]]] = []
        for raw_event in events:
            if not isinstance(raw_event, Mapping):
                continue
            event_id = self._extract_event_id(raw_event)
            ts = self._normalize_timestamp(raw_event).timestamp()
            entries.append((ts, event_id, raw_event))

        entries.sort(key=lambda e: e[0])

        with self._lock:
            self._timestamps = [e[0] for e in entries]
            self._event_ids = [e[1] for e in entries]
            self._events_by_id = {e[1]: e[2] for e in entries}

        logger.info("TemporalCorrelationEngine indexed %d events.", len(entries))

    def insert_event(self, event: Mapping[str, Any]) -> str:
        """
        Inserts a single event into the sorted index in its correct
        chronological position, supporting out-of-order streaming ingestion.

        Args:
            event (Mapping[str, Any]): The event to insert.

        Returns:
            str: The normalized event ID that was inserted.
        """
        event_id = self._extract_event_id(event)
        ts = self._normalize_timestamp(event).timestamp()

        with self._lock:
            position = bisect.bisect_left(self._timestamps, ts)
            self._timestamps.insert(position, ts)
            self._event_ids.insert(position, event_id)
            self._events_by_id[event_id] = event

        return event_id

    # ------------------------------------------------------------
    # WINDOW LOOKUP
    # ------------------------------------------------------------
    def _window_bounds(self, center_ts: float) -> tuple[float, float]:
        half_window = self._config.window_seconds if self._config.rolling_window else self._config.window_seconds / 2.0
        skew = self._config.clock_skew_tolerance_seconds
        if self._config.rolling_window:
            return center_ts - skew, center_ts + half_window + skew
        return center_ts - half_window - skew, center_ts + half_window + skew

    def _events_in_window(self, center_ts: float) -> list[tuple[str, float]]:
        """
        Retrieves all indexed events within the configured window around a
        center timestamp using O(log n) binary search boundaries.

        Args:
            center_ts (float): The POSIX timestamp to center the window on.

        Returns:
            list[tuple[str, float]]: (event_id, timestamp) pairs within window.
        """
        lower, upper = self._window_bounds(center_ts)
        left = bisect.bisect_left(self._timestamps, lower)
        right = bisect.bisect_right(self._timestamps, upper)
        return list(zip(self._event_ids[left:right], self._timestamps[left:right]))

    def _proximity_score(self, delta_seconds: float) -> float:
        """
        Converts a time delta into a proximity score in [0.0, 1.0], where
        0 seconds apart scores 1.0 and events at the edge of the window
        score close to 0.0.

        Args:
            delta_seconds (float): Absolute time difference in seconds.

        Returns:
            float: The proximity score.
        """
        window = max(self._config.window_seconds, 1e-6)
        score = 1.0 - (abs(delta_seconds) / window)
        return round(max(min(score, 1.0), 0.0), 4)

    # ------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------
    def correlate(self, event: Mapping[str, Any]) -> TemporalResult:
        """
        Correlates a single event against the currently indexed events based
        on time proximity, detecting bursts and computing per-neighbor
        proximity scores.

        Args:
            event (Mapping[str, Any]): The event to correlate. Does not need
                to have been previously indexed; delayed/late-arriving
                events are supported up to max_delayed_match_seconds.

        Returns:
            TemporalResult: The temporal correlation outcome for this event.
        """
        if not isinstance(event, Mapping):
            logger.warning("correlate received a non-mapping event; returning a safe default result.")
            now = datetime.now(timezone.utc)
            return TemporalResult(
                event_id="",
                correlated_event_ids=[],
                is_burst=False,
                burst_event_count=0,
                temporal_confidence=0.0,
                proximity_scores={},
                reasons=["Invalid event input; expected a mapping."],
                metadata={},
                timestamp=now
            )

        try:
            with self._lock:
                event_id = self._extract_event_id(event)
                event_ts = self._normalize_timestamp(event).timestamp()

                neighbors = [(eid, ts) for eid, ts in self._events_in_window(event_ts) if eid != event_id]

                proximity_scores: dict[str, float] = {}
                for eid, ts in neighbors:
                    proximity_scores[eid] = self._proximity_score(ts - event_ts)

                burst_lower, burst_upper = event_ts - self._config.burst_window_seconds, event_ts + self._config.burst_window_seconds
                burst_left = bisect.bisect_left(self._timestamps, burst_lower)
                burst_right = bisect.bisect_right(self._timestamps, burst_upper)
                burst_event_count = burst_right - burst_left
                is_burst = burst_event_count >= self._config.burst_threshold_count

                if proximity_scores:
                    temporal_confidence = round(sum(proximity_scores.values()) / len(proximity_scores), 4)
                else:
                    temporal_confidence = 0.0

                reasons = [
                    f"Found {len(neighbors)} event(s) within a {self._config.window_seconds}s window "
                    f"(clock skew tolerance {self._config.clock_skew_tolerance_seconds}s)."
                ]
                if is_burst:
                    reasons.append(f"Detected burst: {burst_event_count} events within {self._config.burst_window_seconds}s.")

                return TemporalResult(
                    event_id=event_id,
                    correlated_event_ids=[eid for eid, _ in neighbors],
                    is_burst=is_burst,
                    burst_event_count=burst_event_count,
                    temporal_confidence=temporal_confidence,
                    proximity_scores=proximity_scores,
                    reasons=reasons,
                    metadata={"rolling_window": self._config.rolling_window},
                    timestamp=datetime.now(timezone.utc)
                )

        except Exception as e:
            logger.exception("Unexpected error in TemporalCorrelationEngine.correlate: %s", e)
            now = datetime.now(timezone.utc)
            return TemporalResult(
                event_id="",
                correlated_event_ids=[],
                is_burst=False,
                burst_event_count=0,
                temporal_confidence=0.0,
                proximity_scores={},
                reasons=["Engine encountered an unexpected error and returned a default empty result."],
                metadata={},
                timestamp=now
            )

    def correlate_all(self, events: Sequence[Mapping[str, Any]]) -> list[TemporalResult]:
        """
        Builds the internal index from the given events and returns a
        TemporalResult for every event in the batch.

        Args:
            events (Sequence[Mapping[str, Any]]): The full event batch.

        Returns:
            list[TemporalResult]: One result per input event.
        """
        self.build_index(events)
        return [self.correlate(event) for event in events if isinstance(event, Mapping)]
