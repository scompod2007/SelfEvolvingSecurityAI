"""Thread-safe duplicate event detection via SHA-256 fingerprinting."""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from typing import Any

from .models import DuplicateCheckResult

_UNKNOWN_FIELD_PLACEHOLDER: str = "-"


class DuplicateCounter:
    """Detects duplicate telemetry events using SHA-256 content fingerprints.

    A fingerprint is derived from ``event_type``, ``process_id``,
    ``file_path``, ``destination_ip``, ``registry_key``, and the event's
    timestamp rounded to the nearest second. Fingerprints are retained for
    a configurable window; a fingerprint seen again within that window is
    considered a duplicate.
    """

    def __init__(self, retention_seconds: float = 300.0) -> None:
        """Initializes the duplicate counter.

        Args:
            retention_seconds: Number of seconds a fingerprint is retained
                and treated as still "seen" for duplicate detection.
        """
        self._retention_seconds: float = retention_seconds
        self._lock = threading.Lock()
        self._fingerprints: dict[str, float] = {}
        self._total_duplicates: int = 0
        self._unique_events: int = 0

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

    def _extract_rounded_timestamp(self, event: dict[str, Any]) -> str:
        """Extracts the event timestamp, rounded to the nearest second.

        Supports ISO-8601 strings, ``datetime`` instances, and numeric
        epoch values. Falls back to a placeholder when absent or invalid.

        Args:
            event: The raw event dictionary.

        Returns:
            str: The rounded timestamp as an integer-second epoch string.
        """
        try:
            raw = event.get("timestamp")
        except AttributeError:
            return _UNKNOWN_FIELD_PLACEHOLDER

        if raw is None:
            return _UNKNOWN_FIELD_PLACEHOLDER

        parsed: datetime | None = None
        if isinstance(raw, datetime):
            parsed = raw
        elif isinstance(raw, (int, float)):
            try:
                parsed = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                parsed = None
        elif isinstance(raw, str):
            candidate = raw.strip()
            if candidate.endswith("Z"):
                candidate = candidate[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(candidate)
            except ValueError:
                parsed = None

        if parsed is None:
            return _UNKNOWN_FIELD_PLACEHOLDER

        return str(round(parsed.timestamp()))

    def _make_fingerprint(self, event: dict[str, Any]) -> str:
        """Computes a SHA-256 fingerprint from an event's identifying fields.

        Args:
            event: The raw event dictionary.

        Returns:
            str: A hex-encoded SHA-256 digest.
        """
        parts = (
            self._extract_field(event, "event_type"),
            self._extract_field(event, "process_id"),
            self._extract_field(event, "file_path"),
            self._extract_field(event, "destination_ip"),
            self._extract_field(event, "registry_key"),
            self._extract_rounded_timestamp(event),
        )
        payload = "|".join(parts).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _prune_expired_locked(self, now: float) -> None:
        """Removes fingerprints older than the retention window.

        Must be called while holding ``self._lock``.

        Args:
            now: The current epoch timestamp.
        """
        cutoff = now - self._retention_seconds
        expired = [
            fingerprint
            for fingerprint, seen_at in self._fingerprints.items()
            if seen_at < cutoff
        ]
        for fingerprint in expired:
            del self._fingerprints[fingerprint]

    def check(self, event: dict[str, Any]) -> DuplicateCheckResult:
        """Checks whether an event is a duplicate within the retention window.

        Args:
            event: The raw event dictionary to check.

        Returns:
            DuplicateCheckResult: The duplicate determination and running
            totals.
        """
        if not isinstance(event, dict):
            event = {}

        now_dt = datetime.now(timezone.utc)
        now = now_dt.timestamp()
        fingerprint = self._make_fingerprint(event)

        with self._lock:
            self._prune_expired_locked(now)

            is_duplicate = fingerprint in self._fingerprints
            self._fingerprints[fingerprint] = now

            if is_duplicate:
                self._total_duplicates += 1
            else:
                self._unique_events += 1

            total_duplicates = self._total_duplicates
            unique_events = self._unique_events

        total_checked = total_duplicates + unique_events
        duplicate_ratio = (
            total_duplicates / total_checked if total_checked > 0 else 0.0
        )

        return DuplicateCheckResult(
            fingerprint=fingerprint,
            is_duplicate=is_duplicate,
            total_duplicates=total_duplicates,
            unique_events=unique_events,
            duplicate_ratio=duplicate_ratio,
            timestamp=now_dt,
        )

    def cleanup(self) -> None:
        """Removes all fingerprints older than the retention window."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            self._prune_expired_locked(now)

    def reset(self) -> None:
        """Clears all fingerprints and resets duplicate/unique totals."""
        with self._lock:
            self._fingerprints.clear()
            self._total_duplicates = 0
            self._unique_events = 0
