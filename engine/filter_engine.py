import threading
import time
import logging

from filters.filter_config import FILTER_CONFIG

import filters.whitelist as whitelist
import filters.filter_rules as filter_rules

from filters.filters import (
    FilterResult,
    FilterStatistics,
    FileFilter,
    ProcessFilter,
    NetworkFilter,
    RegistryFilter,
)

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
            "Process": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
            "Network": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
            "Registry": {
                "total": 0,
                "accepted": 0,
                "filtered": 0,
                "ignored": 0,
                "duplicates": 0,
            },
            "File": {
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
                f"Failed to initialize a sub-filter: {e}"
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

            # File
            "FILE_CREATE": self.file_filter,
            "FILE_MODIFY": self.file_filter,
            "FILE_DELETE": self.file_filter,
            "FILE_RENAME": self.file_filter,
            "FILE_MOVE": self.file_filter,
            "FILE_COPY": self.file_filter,
        }

        self.logger.info(
            "Filter Engine and all sub-filters initialized."
        )

    def _update_statistics(
        self,
        result,
        filter_category=None,
    ):
        is_accepted = getattr(result, "accepted", False)
        is_filtered = getattr(result, "filtered", False)
        is_ignored = getattr(
            result,
            "ignored",
            getattr(result, "is_ignored", False),
        )
        is_duplicate = getattr(
            result,
            "duplicate",
            getattr(result, "is_duplicate", False),
        )

        with self.stats_lock:

            if is_accepted:
                self.global_stats["accepted"] += 1

            if is_filtered:
                self.global_stats["filtered"] += 1

            if is_ignored:
                self.global_stats["ignored"] += 1

            if is_duplicate:
                self.global_stats["duplicates"] += 1

            if (
                filter_category
                and filter_category in self.filter_stats
            ):
                stats = self.filter_stats[filter_category]

                stats["total"] += 1

                if is_accepted:
                    stats["accepted"] += 1

                if is_filtered:
                    stats["filtered"] += 1

                if is_ignored:
                    stats["ignored"] += 1

                if is_duplicate:
                    stats["duplicates"] += 1


    def filter_event(self, event: dict) -> FilterResult:
        start_time = time.perf_counter()
        
        event_type = event.get("event_type", "UNKNOWN") if isinstance(event, dict) else "UNKNOWN"
        self.logger.info(f"[PIPELINE] Received event: {event_type}")

        with self.stats_lock:
            self.global_stats["total"] += 1

        if not isinstance(event, dict):
            self.logger.error("[PIPELINE] Invalid event object: not a dictionary")
            result = FilterResult()
            result.mark_filtered("Invalid event object: not a dictionary")
            result = self._standardize_result(result)
            self._update_statistics(result)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            self.logger.info(f"[PERFORMANCE]\nEvent:\nUNKNOWN\nProcessing Time:\n{processing_time:.2f} ms")
            return result

        event_type = event.get("event_type")
        if not event_type or not isinstance(event_type, str):
            self.logger.error("[PIPELINE] Unsupported event type: missing or invalid")
            result = FilterResult()
            result.mark_filtered("Unsupported event type: missing or invalid")
            result = self._standardize_result(result)
            self._update_statistics(result)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            self.logger.info(f"[PERFORMANCE]\nEvent:\nUNKNOWN\nProcessing Time:\n{processing_time:.2f} ms")
            return result

        event_type_upper = event_type.upper()
        self.logger.info(f"[PIPELINE] Event type detected: {event_type_upper}")
        target_filter = self.dispatch_table.get(event_type_upper)

        if not target_filter:
            self.logger.warning(f"[PIPELINE] Routing failed. Unsupported event type: {event_type_upper}")
            result = FilterResult()
            result.mark_filtered(f"Unsupported event type: {event_type}")
            result = self._standardize_result(result)
            self._update_statistics(result)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            self.logger.info(f"[PERFORMANCE]\nEvent:\n{event_type_upper}\nProcessing Time:\n{processing_time:.2f} ms")
            return result

        filter_category = event_type_upper.split('_')[0].capitalize()
        filter_name = target_filter.__class__.__name__

        self.logger.info(f"[PIPELINE] Routing -> {filter_name}")

        try:
            self.logger.info(f"[FILTER] {filter_name} started")
            result = target_filter.filter_event(event)
            self.logger.info(f"[FILTER] {filter_name} finished")
            
            if not isinstance(result, FilterResult):
                self.logger.error("[PIPELINE] Filter pipeline returned invalid result object")
                
            result = self._standardize_result(result)
            self._update_statistics(result, filter_category)
            
            if result.accepted:
                self.logger.info("[FILTER] Result = Accepted")
            elif result.filtered:
                self.logger.info("[FILTER] Result = Filtered")
            else:
                self.logger.info("[FILTER] Result = Unknown")
                
            self.logger.info("[PIPELINE] Completed successfully")
            
            processing_time = (time.perf_counter() - start_time) * 1000
            self.logger.info(f"[PERFORMANCE]\nEvent:\n{event_type_upper}\nProcessing Time:\n{processing_time:.2f} ms")
            return result
            
        except Exception as e:
            self.logger.error(f"[ERROR] Exception during filtering event of type {event_type_upper} in {filter_name}: {e}", exc_info=True)
            safe_result = FilterResult()
            safe_result.mark_filtered("Internal filter error during processing")
            safe_result = self._standardize_result(safe_result)
            self._update_statistics(safe_result, filter_category)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            self.logger.info(f"[PERFORMANCE]\nEvent:\n{event_type_upper}\nProcessing Time:\n{processing_time:.2f} ms")
            return safe_result


    def _standardize_result(self, result) -> FilterResult:
        """
        Ensure every filter returns a complete FilterResult object
        with all required fields populated.
        """
        if not isinstance(result, FilterResult):
            safe_result = FilterResult()
            safe_result.mark_filtered(
                "Filter pipeline returned invalid result object"
            )
            result = safe_result

        defaults = {
            "accepted": False,
            "filtered": True,
            "ignored": False,
            "duplicate": False,
            "whitelisted": False,
            "suspicious": False,
            "severity": "INFO",
            "confidence": 100.0,
            "reason": "No reason provided",
            "correlation_id": "",
            "event_hash": "",
        }

        for attr, default_value in defaults.items():
            current = getattr(result, attr, None)

            if current is None:
                setattr(result, attr, default_value)

        if getattr(result, "reason", "") == "":
            result.reason = "No reason provided"

        return result