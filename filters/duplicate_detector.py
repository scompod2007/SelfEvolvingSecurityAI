import threading
from dataclasses import dataclass
from typing import Any, Dict

try:
    from filters.filter_config import FILTER_CONFIG
except ImportError:
    from filter_config import FILTER_CONFIG

from filters.event_fingerprint import EventFingerprint
from filters.duplicate_cache import DuplicateCache


@dataclass(slots=True)
class DuplicateStatistics:
    """
    Runtime statistics for the duplicate detection engine.
    """
    total_events: int = 0
    total_duplicates: int = 0
    total_unique: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


@dataclass(slots=True)
class DuplicateDecision:
    is_duplicate: bool
    fingerprint: str
    reason: str
    duplicate_count: int


class DuplicateDetector:
    def __init__(self, config=FILTER_CONFIG):
        self.config = config
        self.cache: DuplicateCache = DuplicateCache(config=self.config)
        self.statistics: DuplicateStatistics = DuplicateStatistics()
        self._stats_lock = threading.Lock()

    def _record_unique(self) -> None:
        """Record statistics for a unique event."""
        with self._stats_lock:
            self.statistics.total_events += 1
            self.statistics.total_unique += 1
            self.statistics.cache_misses += 1

    def _record_duplicate(self) -> None:
        """Record statistics for a duplicate event."""
        with self._stats_lock:
            self.statistics.total_events += 1
            self.statistics.total_duplicates += 1
            self.statistics.cache_hits += 1

    def check(self, event: Dict[str, Any]) -> DuplicateDecision:
        if not isinstance(event, dict):
            self._record_unique()
            return DuplicateDecision(
                is_duplicate=False,
                fingerprint="",
                reason="Invalid event object",
                duplicate_count=0
            )

        if not event:
            self._record_unique()
            return DuplicateDecision(
                is_duplicate=False,
                fingerprint="",
                reason="Empty event",
                duplicate_count=0
            )

        if not getattr(self.config, "ENABLE_DUPLICATE_FILTER", True):
            self._record_unique()
            return DuplicateDecision(
                is_duplicate=False,
                fingerprint="",
                reason="Duplicate filtering disabled",
                duplicate_count=0
            )

        fingerprint = EventFingerprint.generate_fingerprint(event)
        
        self.cache.cleanup()

        if self.cache.contains(fingerprint):
            count = self.cache.increment(fingerprint)
            self._record_duplicate()
            return DuplicateDecision(
                is_duplicate=True,
                fingerprint=fingerprint,
                reason="Exact duplicate detected within time window",
                duplicate_count=count
            )
        
        self.cache.add(fingerprint)
        
        self._record_unique()
            
        return DuplicateDecision(
            is_duplicate=False,
            fingerprint=fingerprint,
            reason="First occurrence",
            duplicate_count=1
        )

    def reset_statistics(self) -> None:
        """
        Reset all duplicate engine statistics to zero.
        """
        with self._stats_lock:
            self.statistics: DuplicateStatistics = DuplicateStatistics()

    def duplicate_rate(self) -> float:
        """
        Calculate the percentage of duplicate events.
        
        Returns:
            float: The duplicate rate rounded to 2 decimal places.
        """
        with self._stats_lock:
            total = self.statistics.total_events
            dupes = self.statistics.total_duplicates
            
        if total == 0:
            return 0.0
        return round((dupes / total) * 100.0, 2)

    def cache_hit_ratio(self) -> float:
        """
        Calculate the cache hit ratio percentage.
        
        Returns:
            float: The cache hit ratio rounded to 2 decimal places.
        """
        with self._stats_lock:
            hits = self.statistics.cache_hits
            misses = self.statistics.cache_misses
            
        total = hits + misses
        if total == 0:
            return 0.0
        return round((hits / total) * 100.0, 2)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Retrieve a dictionary of all duplicate engine statistics.
        
        Returns:
            Dict[str, Any]: The current statistics including calculated rates.
        """
        with self._stats_lock:
            total_events = self.statistics.total_events
            total_duplicates = self.statistics.total_duplicates
            total_unique = self.statistics.total_unique
            cache_hits = self.statistics.cache_hits
            cache_misses = self.statistics.cache_misses

        return {
            "total_events": total_events,
            "total_duplicates": total_duplicates,
            "total_unique": total_unique,
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "duplicate_rate": self.duplicate_rate(),
            "cache_hit_ratio": self.cache_hit_ratio()
        }