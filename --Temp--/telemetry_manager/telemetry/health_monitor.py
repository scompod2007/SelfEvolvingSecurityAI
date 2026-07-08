"""
Background health-check timer for the Telemetry Manager.

Runs on its own thread, separate from every collector thread, and
invokes a callback at a fixed interval. All health-check *decision*
logic (is a collector alive, should it be restarted) lives in
TelemetryManager.check_health -- this class owns only the timing.
"""

import logging
import threading
import time
from typing import Callable, Optional


class HealthMonitor:
    """Periodically invokes a health-check callback on its own thread."""

    def __init__(
        self,
        interval: float,
        check_callback: Callable[[], None],
        logger: Optional[logging.Logger] = None,
    ):

        self.interval = interval

        self.check_callback = check_callback

        self.logger = logger or logging.getLogger("telemetry_manager")

        self._running = False

        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:

        if self._running:

            return

        self._running = True

        self._thread = threading.Thread(target=self._loop, daemon=True, name="health-monitor")

        self._thread.start()

        self.logger.info("Health monitor started (interval=%ss).", self.interval)

    def stop(self) -> None:

        self._running = False

        if self._thread is not None:

            self._thread.join(timeout=self.interval + 5)

        self.logger.info("Health monitor stopped.")

    def _loop(self) -> None:

        while self._running:

            slept = 0.0

            while slept < self.interval:

                if not self._running:

                    return

                time.sleep(0.1)

                slept += 0.1

            if not self._running:

                return

            try:

                self.check_callback()

            except Exception as e:

                self.logger.error("Health monitor callback failed: %s", e)
