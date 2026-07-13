import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple, Any

try:
    from filters.filter_config import FILTER_CONFIG
except ImportError:
    from filter_config import FILTER_CONFIG

class DuplicateCache:
    def __init__(self, config=FILTER_CONFIG):
        self.config = config
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add(self, hash_key: str) -> None:
        with self._lock:
            if hash_key not in self._cache:
                self._cache[hash_key] = {"timestamp": datetime.now(timezone.utc), "count": 1}

    def increment(self, hash_key: str) -> int:
        with self._lock:
            now = datetime.now(timezone.utc)
            if hash_key in self._cache:
                self._cache[hash_key]["count"] += 1
                self._cache[hash_key]["timestamp"] = now
                return self._cache[hash_key]["count"]
            self._cache[hash_key] = {"timestamp": now, "count": 1}
            return 1

    def contains(self, hash_key: str) -> bool:
        with self._lock:
            return hash_key in self._cache

    def remove(self, hash_key: str) -> None:
        with self._lock:
            if hash_key in self._cache:
                del self._cache[hash_key]

    def cleanup(self) -> Tuple[int, int]:
        """
        Removes expired cache entries and enforces the maximum cache size limit.
        
        Returns:
            Tuple[int, int]: A tuple containing:
                - The number of expired entries removed.
                - The number of entries removed due to cache size constraints.
        """
        expired_removed = 0
        overflow_removed = 0
        
        with self._lock:
            now = datetime.now(timezone.utc)
            ttl = getattr(self.config, "DUPLICATE_TTL_SECONDS", 60)
            max_size = getattr(
                self.config, 
                "MAX_EVENT_CACHE", 
                getattr(self.config, "MAX_DUPLICATE_CACHE_SIZE", 100000)
            )

            # 1. Expired Entry Removal
            expired_keys = [
                key for key, data in self._cache.items()
                if (now - data["timestamp"]).total_seconds() > ttl
            ]
            
            for key in expired_keys:
                del self._cache[key]
                expired_removed += 1

            # 2. Cache Size Control
            current_size = len(self._cache)
            if current_size > max_size:
                overflow_removed = current_size - max_size
                # Sort entries by timestamp to find the oldest
                sorted_entries = sorted(self._cache.items(), key=lambda item: item[1]["timestamp"])
                
                for i in range(overflow_removed):
                    del self._cache[sorted_entries[i][0]]

        return expired_removed, overflow_removed

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def get_entry(self, hash_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._cache.get(hash_key)
            return dict(entry) if entry else None

    def is_empty(self) -> bool:
        """
        Checks whether the duplicate cache is currently empty.
        
        Returns:
            bool: True if the cache is empty, False otherwise.
        """
        with self._lock:
            return not self._cache

    def cache_usage(self) -> Dict[str, Any]:
        """
        Calculates current cache memory usage metrics.
        
        Returns:
            Dict[str, Any]: A dictionary containing the current number of entries, 
                            the configured maximum size, and the usage percentage.
        """
        with self._lock:
            entries = len(self._cache)
            max_size = getattr(
                self.config, 
                "MAX_EVENT_CACHE", 
                getattr(self.config, "MAX_DUPLICATE_CACHE_SIZE", 100000)
            )
            usage_percent = (entries / max_size * 100.0) if max_size > 0 else 0.0
            
            return {
                "entries": entries,
                "max_size": max_size,
                "usage_percent": round(usage_percent, 2)
            }