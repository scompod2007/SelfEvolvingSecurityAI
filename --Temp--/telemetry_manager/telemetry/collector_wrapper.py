"""
Adapter that lets the Telemetry Manager treat all four collectors
uniformly, despite their differing constructors and entry points:

    ProcessMonitor   -- constructor takes `interval`; blocking entry
                         point is `monitor()`; has no stop() method,
                         just a public `running` flag checked at the
                         top of its loop.

    FileMonitor      -- constructor takes `watch_path` (currently
                         unused by the implementation, which auto-
                         discovers every mounted drive instead);
                         blocking entry point is `start()`; has a
                         real `stop()`.

    RegistryMonitor  -- constructor takes no args (it's event-driven
                         via RegNotifyChangeKeyValue, not polling);
                         blocking entry point is `start()`; has a
                         real `stop()`.

    NetworkMonitor   -- constructor takes `interval`; blocking entry
                         point is `start()`; has a real `stop()`.

Every collector's blocking entry point already contains its own
`while self.running:` loop and already spawns whatever internal
threads it needs. The wrapper's only job is to run that blocking
call on a dedicated manager-owned thread and to signal it to stop --
never to duplicate or reimplement any collection logic.

Note on Ctrl+C: because each collector's entry point now runs on a
background thread instead of the main thread, KeyboardInterrupt is
never delivered to it directly (Python only raises SIGINT-based
KeyboardInterrupt on the main thread). That's intentional -- the
Telemetry Manager's main thread is the only place Ctrl+C is caught,
and shutdown() stops every collector explicitly and deterministically
rather than relying on each collector's own (now-unreachable)
`except KeyboardInterrupt` handler.
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class CollectorSpec:
    """Static description of how to build and drive one collector."""

    key: str                       # short key, e.g. "process"
    display_name: str              # e.g. "Process"
    factory: Callable[[], Any]     # zero-arg callable returning a fresh instance
    entry_method: str              # name of the blocking method to invoke
    has_stop_method: bool = True   # False for ProcessMonitor


class CollectorWrapper:
    """
    Runs one collector's blocking entry point on a dedicated thread
    and exposes a uniform start / stop / restart / is_alive interface
    to the Telemetry Manager.
    """

    def __init__(self, spec: CollectorSpec, logger: Optional[logging.Logger] = None):

        self.spec = spec

        self.logger = logger or logging.getLogger("telemetry_manager")

        self.instance: Optional[Any] = None

        self.thread: Optional[threading.Thread] = None

        self.restarts = 0

        self.last_error: Optional[str] = None

        self.started_at: Optional[float] = None

        self._crashed = threading.Event()

    # ---------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------

    def start(self) -> None:
        """Instantiate a fresh collector and run its entry point in a thread."""

        self._crashed.clear()

        self.instance = self.spec.factory()

        self.thread = threading.Thread(
            target=self._run,
            name=f"collector-{self.spec.key}",
            daemon=True,
        )

        self.started_at = time.time()

        self.thread.start()

    def _run(self) -> None:

        entry = getattr(self.instance, self.spec.entry_method, None)

        if entry is None:

            self.last_error = (
                f"{self.spec.display_name} monitor has no "
                f"'{self.spec.entry_method}' method."
            )

            self.logger.error(self.last_error)

            self._crashed.set()

            return

        try:

            entry()

        except Exception as e:

            self.last_error = str(e)

            self.logger.error("%s monitor crashed: %s", self.spec.display_name, e)

            self._crashed.set()

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the collector to stop and wait for its thread to exit."""

        if self.instance is None:

            return

        try:

            if self.spec.has_stop_method and hasattr(self.instance, "stop"):

                self.instance.stop()

            else:

                # ProcessMonitor: no stop() method, just a public
                # `running` flag checked at the top of monitor()'s loop.

                setattr(self.instance, "running", False)

        except Exception as e:

            self.logger.error(
                "Error while stopping %s monitor: %s", self.spec.display_name, e
            )

        if self.thread is not None:

            self.thread.join(timeout=timeout)

            if self.thread.is_alive():

                self.logger.warning(
                    "%s monitor thread did not exit within %ss.",
                    self.spec.display_name, timeout,
                )

    def restart(self) -> None:
        """Stop (if running) and start a brand-new collector instance."""

        self.stop()

        self.restarts += 1

        self.start()

    # ---------------------------------------------------
    # Health
    # ---------------------------------------------------

    def is_alive(self) -> bool:

        if self.thread is None:

            return False

        return self.thread.is_alive() and not self._crashed.is_set()

    def status(self) -> str:

        return "RUNNING" if self.is_alive() else "STOPPED"
