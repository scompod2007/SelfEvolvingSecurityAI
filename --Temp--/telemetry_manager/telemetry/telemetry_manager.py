"""
TelemetryManager -- central coordinator of the telemetry layer.

Responsible ONLY for orchestration: loading configuration, creating
and starting/stopping the four collectors, monitoring their health
and restarting crashed ones, tracking runtime statistics, and
central logging. It never inspects or parses telemetry content, and
never performs detection or AI logic -- that belongs to later stages
of the pipeline (Correlation Engine, Feature Extractor, AI Detection,
Self-Evolution Engine).
"""

import logging
import threading
import time
from typing import Dict, Optional

from telemetry.config_loader import ConfigLoader
from telemetry.logger import setup_logger
from telemetry.statistics import Statistics
from telemetry.health_monitor import HealthMonitor
from telemetry.collector_wrapper import CollectorWrapper, CollectorSpec


class TelemetryManager:
    """Coordinates all telemetry collectors. Does not analyze telemetry."""

    # Single place that lists every known collector key/order. Adding
    # a future collector (Memory, Driver, USB, ...) means adding one
    # entry here plus one _build_*_spec method -- nothing else in
    # this class needs to change.
    COLLECTOR_ORDER = ("process", "file", "registry", "network")

    def __init__(self, config_path: str = "config.json", log_dir: str = "logs"):

        self.logger: logging.Logger = setup_logger(log_dir=log_dir)

        self.config_path = config_path

        self.config: Dict[str, object] = {}

        self.collectors: Dict[str, CollectorWrapper] = {}

        self.statistics: Optional[Statistics] = None

        self.health_monitor: Optional[HealthMonitor] = None

        self._shutdown_event = threading.Event()

        self._status_lock = threading.Lock()

    # ======================================================
    # 1. Configuration
    # ======================================================

    def load_config(self) -> None:

        loader = ConfigLoader(self.config_path, logger=self.logger)

        self.config = loader.load()

        self.logger.info("Configuration loaded: %s", self.config)

    # ======================================================
    # 2. Collector creation
    # ======================================================

    def initialize_collectors(self) -> None:
        """
        Build a CollectorWrapper for every collector enabled in the
        config whose module can actually be imported/instantiated in
        this environment (e.g. RegistryMonitor requires Windows and
        FileMonitor requires the `watchdog` package). A collector
        that can't be built is logged and skipped rather than
        crashing manager startup entirely.
        """

        builders = {
            "process": self._build_process_spec,
            "file": self._build_file_spec,
            "registry": self._build_registry_spec,
            "network": self._build_network_spec,
        }

        for key in self.COLLECTOR_ORDER:

            config_flag = f"{key}_monitor"

            if not self.config.get(config_flag, False):

                self.logger.info("%s monitor disabled in config, skipping.", key.capitalize())

                continue

            try:

                spec = builders[key]()

            except Exception as e:

                self.logger.error(
                    "%s monitor unavailable in this environment (%s). Skipping.",
                    key.capitalize(), e,
                )

                continue

            self.collectors[key] = CollectorWrapper(spec, logger=self.logger)

            self.logger.info("%s monitor initialized.", spec.display_name)

    def _build_process_spec(self) -> CollectorSpec:

        from collectors.process_monitor import ProcessMonitor

        interval = self.config.get("process_interval", 2)

        return CollectorSpec(
            key="process",
            display_name="Process",
            factory=lambda: ProcessMonitor(interval=interval),
            entry_method="monitor",
            has_stop_method=False,
        )

    def _build_file_spec(self) -> CollectorSpec:

        from collectors.file_monitor import FileMonitor

        watch_path = self.config.get("file_watch_path")

        # The current FileMonitor implementation ignores watch_path
        # (it auto-discovers every mounted drive via
        # get_watch_directories()) but it's passed through anyway so
        # a future revision that does honor it works unchanged.

        return CollectorSpec(
            key="file",
            display_name="File",
            factory=lambda: FileMonitor(watch_path),
            entry_method="start",
            has_stop_method=True,
        )

    def _build_registry_spec(self) -> CollectorSpec:

        from collectors.registry_monitor import RegistryMonitor

        # RegistryMonitor is event-driven (RegNotifyChangeKeyValue),
        # not polling, so it takes no interval argument.
        # registry_interval in config.json is kept only for forward
        # compatibility with a possible future polling implementation
        # and is intentionally unused here.

        return CollectorSpec(
            key="registry",
            display_name="Registry",
            factory=lambda: RegistryMonitor(),
            entry_method="start",
            has_stop_method=True,
        )

    def _build_network_spec(self) -> CollectorSpec:

        from collectors.network_monitor import NetworkMonitor

        interval = self.config.get("network_interval", 1)

        return CollectorSpec(
            key="network",
            display_name="Network",
            factory=lambda: NetworkMonitor(interval=interval),
            entry_method="start",
            has_stop_method=True,
        )

    # ======================================================
    # 3. Start collectors / 5. Stop collectors
    # ======================================================

    def start_collectors(self) -> None:

        for wrapper in self.collectors.values():

            try:

                wrapper.start()

                self.logger.info("%s monitor started.", wrapper.spec.display_name)

            except Exception as e:

                self.logger.error(
                    "Failed to start %s monitor: %s", wrapper.spec.display_name, e
                )

    def stop_collectors(self) -> None:

        for wrapper in self.collectors.values():

            try:

                wrapper.stop()

                self.logger.info("%s monitor stopped.", wrapper.spec.display_name)

            except Exception as e:

                self.logger.error(
                    "Error stopping %s monitor: %s", wrapper.spec.display_name, e
                )

    # ======================================================
    # 4. Health monitoring / restart
    # ======================================================

    def check_health(self) -> None:
        """Called by HealthMonitor on its fixed interval."""

        self.statistics.record_health_check()

        with self._status_lock:

            for key, wrapper in self.collectors.items():

                if not wrapper.is_alive():

                    self.logger.warning(
                        "%s monitor is not running. Restarting...",
                        wrapper.spec.display_name,
                    )

                    self.restart_collector(key)

    def restart_collector(self, key: str) -> None:

        wrapper = self.collectors.get(key)

        if wrapper is None:

            return

        try:

            wrapper.restart()

            self.statistics.record_restart()

            self.logger.info(
                "%s monitor restarted (restart #%d).",
                wrapper.spec.display_name, wrapper.restarts,
            )

        except Exception as e:

            self.logger.error(
                "Failed to restart %s monitor: %s", wrapper.spec.display_name, e
            )

    # ======================================================
    # 6/7. Status & statistics
    # ======================================================

    def update_statistics(self) -> Dict[str, object]:
        """
        Return the current cached statistics snapshot. The cache is
        refreshed on its own background timer (see
        telemetry.statistics.Statistics), so this call is always
        cheap and never touches the database directly.
        """

        return self.statistics.snapshot()

    def print_status(self) -> None:

        stats = self.update_statistics()

        uptime = self._format_uptime(stats["uptime_seconds"])

        running_count = sum(1 for w in self.collectors.values() if w.is_alive())

        total_count = len(self.collectors)

        event_counts = stats["event_counts"]

        lines = []

        lines.append("=" * 60)
        lines.append(" Self-Evolving Security AI - Telemetry Manager Status")
        lines.append("=" * 60)
        lines.append(f" Uptime               : {uptime}")
        lines.append(f" Collectors Running   : {running_count} / {total_count}")
        lines.append(f" Collectors Restarted : {stats['collectors_restarted']}")
        lines.append(f" Health Checks        : {stats['health_checks']}")
        lines.append("-" * 60)
        lines.append(f" {'Collector':<12}{'Status':<12}{'Restarts':<12}{'Events':<10}")
        lines.append("-" * 60)

        for key in self.COLLECTOR_ORDER:

            wrapper = self.collectors.get(key)

            if wrapper is None:

                lines.append(f" {key.capitalize():<12}{'DISABLED':<12}{'-':<12}{'-':<10}")

                continue

            lines.append(
                f" {wrapper.spec.display_name:<12}"
                f"{wrapper.status():<12}"
                f"{wrapper.restarts:<12}"
                f"{event_counts.get(key, 0):<10}"
            )

        lines.append("=" * 60)

        status_text = "\n".join(lines)

        print(status_text)

        self.logger.info("Status printed:\n%s", status_text)

    @staticmethod
    def _format_uptime(seconds: float) -> str:

        seconds = int(seconds)

        hours, remainder = divmod(seconds, 3600)

        minutes, secs = divmod(remainder, 60)

        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    # ======================================================
    # Runtime flow
    # ======================================================

    def run(self) -> None:
        """
        Full runtime flow: load config -> create logger (done in
        __init__) -> initialize collectors -> start collectors ->
        start health monitor -> block until Ctrl+C -> shutdown.
        """

        self.logger.info("=" * 60)
        self.logger.info("Self-Evolving Security AI - Telemetry Manager starting up.")
        self.logger.info("=" * 60)

        self.load_config()

        self.statistics = Statistics(
            refresh_interval=self.config.get("stats_refresh_interval", 10),
            logger=self.logger,
        )

        self.statistics.start()

        self.initialize_collectors()

        if not self.collectors:

            self.logger.error("No collectors could be initialized. Nothing to run. Exiting.")

            self.statistics.stop()

            return

        self.start_collectors()

        self.health_monitor = HealthMonitor(
            interval=self.config.get("health_check_interval", 5),
            check_callback=self.check_health,
            logger=self.logger,
        )

        self.health_monitor.start()

        self.logger.info("Telemetry Manager running. Press Ctrl+C to stop.")

        try:

            while not self._shutdown_event.is_set():

                time.sleep(1)

        except KeyboardInterrupt:

            self.logger.info("Shutdown requested (Ctrl+C).")

        finally:

            self.shutdown()

    def shutdown(self) -> None:
        """Stop everything in an orderly fashion and exit cleanly."""

        self.logger.info("Shutting down Telemetry Manager...")

        self._shutdown_event.set()

        if self.health_monitor is not None:

            self.health_monitor.stop()

        self.stop_collectors()

        if self.statistics is not None:

            self.print_status()

            self.statistics.stop()

        self.logger.info("Telemetry Manager shutdown complete.")
