import logging
import threading
import time

from filters.filter_config import FILTER_CONFIG
import filters.filter_rules as filter_rules

from filters.filters import (
    FileFilter,
    FilterResult,
    FilterStatistics,
    NetworkFilter,
    ProcessFilter,
    RegistryFilter,
)
import filters.whitelist as whitelist

logger = logging.getLogger(__name__)


class FilterEngine:

    def __init__(self):
        self.config = FILTER_CONFIG
        self.statistics = FilterStatistics()
        self.whitelist = whitelist
        self.rules = filter_rules
        self.logger = logger

        self.stats_lock = threading.Lock()

        self.global_stats = {
            "total": 0,
            "accepted": 0,
            "filtered": 0,
            "ignored": 0,
            "duplicates": 0,
        }

        self.filter_stats = {
            "PROCESS": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
            "NETWORK": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
            "REGISTRY": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
            "FILE": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
        }

        try:
            self.file_filter = FileFilter(self)
            self.process_filter = ProcessFilter(self)
            self.network_filter = NetworkFilter(self)
            self.registry_filter = RegistryFilter(self)

        except Exception as e:
            self.logger.critical(
                f"Failed to initialize a sub-filter: {e}", exc_info=True
            )
            raise RuntimeError(
                "FilterEngine failed to initialize sub-filters."
            ) from e

        self.dispatch_table = {
            # Process
            "PROCESS_CREATE": self.process_filter,
            "PROCESS_TERMINATE": self.process_filter,
            "PROCESS_START": self.process_filter,
            "PROCESS_EXIT": self.process_filter,
            # Network
            "NETWORK_CONNECT": self.network_filter,
            "NETWORK_DISCONNECT": self.network_filter,
            "NETWORK_LISTEN": self.network_filter,
            "NETWORK_ACCEPT": self.network_filter,
            # Registry
            "REGISTRY_CREATE": self.registry_filter,
            "REGISTRY_MODIFY": self.registry_filter,
            "REGISTRY_DELETE": self.registry_filter,
            "REGISTRY_RENAME": self.registry_filter,
            "REGISTRY_READ": self.registry_filter,
            # File
            "FILE_CREATE": self.file_filter,
            "FILE_MODIFY": self.file_filter,
            "FILE_DELETE": self.file_filter,
            "FILE_RENAME": self.file_filter,
            "FILE_MOVE": self.file_filter,
            "FILE_COPY": self.file_filter,
        }

        self.logger.info("Filter Engine and all sub-filters initialized.")

    def _filtered_result(self, reason: str) -> FilterResult:
        """Creates and returns a standard FilterResult object marked as filtered."""
        result = FilterResult()
        result.mark_filtered(reason)
        return result

    def _update_statistics(self, result: FilterResult):
        """Updates global and per-filter statistics based on a FilterResult."""
        if not isinstance(result, FilterResult):
            return

        filter_category = getattr(result, "collector", None)

        with self.stats_lock:
            self.global_stats["total"] += 1

            if result.accepted:
                self.global_stats["accepted"] += 1
            if result.filtered:
                self.global_stats["filtered"] += 1
            if result.duplicate:
                self.global_stats["duplicates"] += 1
            # Ignored is a subset of filtered, counted separately
            if (
                result.filtered
                and not result.whitelisted
                and not result.duplicate
            ):
                self.global_stats["ignored"] += 1

            if filter_category and filter_category in self.filter_stats:
                stats = self.filter_stats[filter_category]
                stats["total"] += 1
                if result.accepted:
                    stats["accepted"] += 1
                if result.filtered:
                    stats["filtered"] += 1
                if result.duplicate:
                    stats["duplicates"] += 1
                if (
                    result.filtered
                    and not result.whitelisted
                    and not result.duplicate
                ):
                    stats["ignored"] += 1

    def filter_event(self, event: dict) -> FilterResult:
        """Orchestrates the filtering of a single telemetry event by routing it
        to the appropriate specialized filter.
        """
        start_time = time.perf_counter()
        result: FilterResult | None = None
        normalized_event_type = "UNKNOWN"
        filter_name = "N/A"

        try:
            if not isinstance(event, dict):
                result = self._filtered_result(
                    "Invalid event object: not a dictionary"
                )
                return result

            event_type_raw = event.get("event_type")
            if not isinstance(event_type_raw, str):
                result = self._filtered_result(
                    "Unsupported event type: missing or not a string"
                )
                return result

            normalized_event_type = event_type_raw.strip().upper()
            if not normalized_event_type:
                result = self._filtered_result(
                    "Unsupported event type: empty or whitespace"
                )
                return result

            target_filter = self.dispatch_table.get(normalized_event_type)

            if not target_filter:
                result = self._filtered_result(
                    f"Unsupported event type: {normalized_event_type}"
                )
                return result

            filter_name = target_filter.__class__.__name__
            if not callable(getattr(target_filter, "filter_event", None)):
                self.logger.critical(
                    "Dispatch target is invalid: 'filter_event' method not found or not callable.",
                    extra={
                        "filter_name": filter_name,
                        "event_type": normalized_event_type,
                    },
                )
                result = self._filtered_result(
                    f"Internal configuration error for filter: {filter_name}"
                )
                return result

            result = target_filter.filter_event(event)
            return result

        except (KeyError, TypeError, ValueError, RuntimeError):
            self.logger.exception(
                "A predictable error occurred during event processing.",
                extra={
                    "filter_name": filter_name,
                    "event_type": normalized_event_type,
                    "correlation_id": (
                        event.get("correlation_id", "N/A")
                        if isinstance(event, dict)
                        else "N/A"
                    ),
                },
            )
            result = self._filtered_result(
                f"Internal error in {filter_name} filter"
            )
            return result

        except Exception:
            self.logger.exception(
                "An unexpected error occurred during event processing.",
                extra={
                    "filter_name": filter_name,
                    "event_type": normalized_event_type,
                    "correlation_id": (
                        event.get("correlation_id", "N/A")
                        if isinstance(event, dict)
                        else "N/A"
                    ),
                },
            )
            result = self._filtered_result(
                f"Unexpected internal error in {filter_name} filter"
            )
            return result

        finally:
            if result:
                self._update_statistics(result)

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            log_extra = {
                "event_type": normalized_event_type,
                "elapsed_ms": f"{elapsed_ms:.4f}",
            }
            if result:
                log_extra["accepted"] = result.accepted
                log_extra["reason"] = result.reason

            self.logger.debug("FilterEngine processed event.", extra=log_extra)