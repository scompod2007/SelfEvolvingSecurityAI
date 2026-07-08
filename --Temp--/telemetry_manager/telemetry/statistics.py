"""
Runtime statistics for the Telemetry Manager.

Uptime, restart counts, and health-check counts are tracked
in-memory as they happen (cheap, no DB involved). Per-collector
event counts are the only thing that requires a database read, and
per the spec, statistics must never poll the database every second.
So event counts are refreshed on their own background timer
(default every `stats_refresh_interval` seconds) and served from an
in-memory cache the rest of the time -- callers never hit the
database directly.
"""

import logging
import threading
import time
from typing import Dict, Optional

from database.db import get_connection, close_connection


# Collector key -> the events table that collector writes into.
EVENT_TABLES: Dict[str, str] = {
    "process": "process_events",
    "file": "file_events",
    "registry": "registry_events",
    "network": "network_events",
}


class Statistics:
    """Thread-safe runtime statistics with cached DB-derived event counts."""

    def __init__(self, refresh_interval: float = 10.0, logger: Optional[logging.Logger] = None):

        self.refresh_interval = refresh_interval

        self.logger = logger or logging.getLogger("telemetry_manager")

        self._lock = threading.Lock()

        self._start_time = time.time()

        self._collectors_restarted = 0

        self._health_checks = 0

        self._event_counts: Dict[str, int] = {key: 0 for key in EVENT_TABLES}

        self._running = False

        self._thread: Optional[threading.Thread] = None

    # ---------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------

    def start(self) -> None:
        """Start the background cache-refresh timer."""

        if self._running:

            return

        self._running = True

        self._thread = threading.Thread(target=self._refresh_loop, daemon=True, name="statistics-refresh")

        self._thread.start()

    def stop(self) -> None:
        """Stop the background cache-refresh timer."""

        self._running = False

        if self._thread is not None:

            self._thread.join(timeout=self.refresh_interval + 5)

    # ---------------------------------------------------
    # In-memory counters
    # ---------------------------------------------------

    def record_restart(self) -> None:

        with self._lock:

            self._collectors_restarted += 1

    def record_health_check(self) -> None:

        with self._lock:

            self._health_checks += 1

    # ---------------------------------------------------
    # Cached DB-derived event counts
    # ---------------------------------------------------

    def _refresh_loop(self) -> None:

        # Populate the cache immediately instead of showing zeros
        # for the first `refresh_interval` seconds after startup.

        self._refresh_counts()

        while self._running:

            slept = 0.0

            while slept < self.refresh_interval:

                if not self._running:

                    return

                time.sleep(0.1)

                slept += 0.1

            self._refresh_counts()

    def _refresh_counts(self) -> None:

        conn = None

        try:

            conn = get_connection()

            cursor = conn.cursor()

            counts: Dict[str, int] = {}

            for key, table in EVENT_TABLES.items():

                try:

                    cursor.execute(f"SELECT COUNT(*) FROM {table}")

                    counts[key] = cursor.fetchone()[0]

                except Exception:

                    # Table may not exist yet (collector never
                    # started, or DB not initialized). Keep the
                    # last known value rather than treating this
                    # as a fatal error.

                    counts[key] = self._event_counts.get(key, 0)

            with self._lock:

                self._event_counts.update(counts)

        except Exception as e:

            self.logger.warning("Statistics: failed to refresh event counts (%s).", e)

        finally:

            if conn is not None:

                close_connection(conn)

    # ---------------------------------------------------
    # Snapshot
    # ---------------------------------------------------

    def uptime_seconds(self) -> float:

        return time.time() - self._start_time

    def snapshot(self) -> Dict[str, object]:
        """Return a thread-safe, point-in-time copy of all statistics."""

        with self._lock:

            return {
                "uptime_seconds": self.uptime_seconds(),
                "collectors_restarted": self._collectors_restarted,
                "health_checks": self._health_checks,
                "event_counts": dict(self._event_counts),
            }
