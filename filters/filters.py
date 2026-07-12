"""
============================================================
Self-Evolving Security AI
Core Filter Engine
Version : 1.0

Part 2.1
Imports & Initialization

Responsibilities
----------------
• Load configuration
• Load whitelist
• Load filter rules
• Initialize statistics
• Initialize duplicate cache
• Initialize event cache
• Initialize correlation ID generator

NO FILTERING LOGIC BELONGS HERE.

============================================================
"""

from __future__ import annotations
import ipaddress
import hashlib
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import count
from pathlib import Path
from typing import Any

# ============================================================
# IMPORT CONFIGURATION
# ============================================================

from filters.filter_config import FILTER_CONFIG

# ============================================================
# IMPORT WHITELIST
# ============================================================

import filters.whitelist as whitelist

# ============================================================
# IMPORT FILTER RULES
# ============================================================

import filters.filter_rules as filter_rules

# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger(__name__)

# ============================================================
# FILTER STATISTICS
# ============================================================


@dataclass(slots=True)
class FilterStatistics:
    """
    Runtime statistics for the filter engine.
    """

    files_seen: int = 0
    files_filtered: int = 0
    files_stored: int = 0

    processes_seen: int = 0
    processes_filtered: int = 0
    processes_stored: int = 0

    network_seen: int = 0
    network_filtered: int = 0
    network_stored: int = 0

    registry_seen: int = 0
    registry_filtered: int = 0
    registry_stored: int = 0

    duplicates_removed: int = 0

    ignored_events: int = 0

    total_events: int = 0

    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

# ============================================================
# FILTER RESULT
# ============================================================

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class FilterResult:
    """
    Standard result returned by every filter.

    Every collector (File, Process, Network, Registry)
    must return this object.

    This keeps the entire Security AI pipeline
    consistent.

    Example
    -------
    result = FilterResult(
        accepted=True,
        severity="HIGH",
        confidence=92.5
    )
    """

    # ========================================================
    # FILTER DECISION
    # ========================================================

    accepted: bool = True

    filtered: bool = False

    reason: str = "Accepted"

    # ========================================================
    # AI METADATA
    # ========================================================

    severity: str = "INFO"

    confidence: float = 100.0

    correlation_id: str = ""

    # ========================================================
    # FILTER FLAGS
    # ========================================================

    duplicate: bool = False

    ignored: bool = False

    whitelisted: bool = False

    suspicious: bool = False

    # ========================================================
    # EVENT INFORMATION
    # ========================================================

    event_hash: str = ""

    event_type: str = ""

    collector: str = ""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ========================================================
    # EXTRA DATA
    # ========================================================

    metadata: dict[str, Any] = field(default_factory=dict)

    # ========================================================
    # HELPER METHODS
    # ========================================================

    def mark_filtered(self, reason: str) -> None:
        """
        Mark event as filtered.
        """

        self.accepted = False
        self.filtered = True
        self.reason = reason

    def mark_duplicate(self) -> None:
        """
        Mark event as duplicate.
        """

        self.duplicate = True
    
    def mark_ignored(self, reason: str) -> None:
        self.accepted = False
        self.filtered = True
        self.ignored = True
        self.reason = reason

    def mark_whitelisted(self) -> None:
        """
        Mark event as whitelisted.
        """

        self.whitelisted = True

    def mark_suspicious(self) -> None:
        """
        Mark event as suspicious.
        """

        self.suspicious = True

    def set_severity(self, severity: str) -> None:
        """
        Set event severity.
        """

        self.severity = severity.upper()

    def set_confidence(self, confidence: float) -> None:
        """
        Set AI confidence score.

        Value is automatically limited to
        0–100.
        """

        confidence = max(0.0, min(100.0, confidence))

        self.confidence = round(confidence, 2)

    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to the event.
        """

        self.metadata[key] = value

    def to_dict(self) -> dict[str, Any]:
        """
        Convert FilterResult to dictionary.

        Useful for database insertion,
        logging, and AI processing.
        """

        return {

            "accepted": self.accepted,

            "filtered": self.filtered,

            "reason": self.reason,

            "severity": self.severity,

            "confidence": self.confidence,

            "correlation_id": self.correlation_id,

            "duplicate": self.duplicate,

            "whitelisted": self.whitelisted,

            "suspicious": self.suspicious,

            "event_hash": self.event_hash,

            "event_type": self.event_type,

            "collector": self.collector,

            "timestamp": self.timestamp,

            "metadata": self.metadata,

            "ignored": self.ignored

        }

# ============================================================
# DUPLICATE CACHE
# ============================================================

#
# event_hash
#
# {
#     timestamp,
#     count
# }
#

_duplicate_cache: dict[str, dict[str, Any]] = {}

_duplicate_lock = threading.Lock()

_last_cache_cleanup_time = datetime.now(timezone.utc)


# ============================================================
# EVENT CACHE
# ============================================================

#
# Temporary runtime cache
#
# Used later for
#
# • duplicate suppression
# • correlation
# • burst detection
#

_event_cache: dict[str, Any] = {}

_event_lock = threading.Lock()

# ============================================================
# CORRELATION ID GENERATOR
# ============================================================

_correlation_counter = count(1)

_correlation_lock = threading.Lock()


def generate_correlation_id() -> str:
    """
    Generates unique correlation IDs.

    Example

    CID-20260709-000001
    """

    with _correlation_lock:

        value = next(_correlation_counter)

    return (
        f"CID-"
        f"{datetime.now(timezone.utc):%Y%m%d}-"
        f"{value:06d}"
    )


# ============================================================
# FILTER ENGINE
# ============================================================


class FilterEngine:
    """
    Main filtering engine.

    Filtering methods are implemented in later sections.

    Current responsibilities:

    • Load configuration
    • Hold runtime caches
    • Hold statistics
    """

    def __init__(self):

        self.config = FILTER_CONFIG

        self.statistics = FilterStatistics()

        self.whitelist = whitelist

        self.rules = filter_rules

        self.logger = logger

        self.logger.info("Filter Engine initialized.")
# ============================================================
# FILE FILTER
# ============================================================

# ============================================================
# FILE FILTER
# ============================================================

class FileFilter:
    """
    File filtering engine.

    Responsibilities
    ----------------
    • Filter unwanted file events
    • Apply whitelist rules
    • Apply ignore rules
    • Detect duplicate events
    • Assign severity
    • Assign confidence
    • Generate correlation IDs
    • Update statistics

    NOTE:
    This class does NOT monitor files.
    It only evaluates file events received
    from the File Monitor.
    """

    def __init__(self, engine: "FilterEngine") -> None:
        """
        Initialize the File Filter.
        """
        self.engine = engine
        self.config = engine.config
        self.stats = engine.statistics
        self.logger = engine.logger

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def filter_event(self, event: dict) -> FilterResult:
        """
        Evaluate a single file event.

        Parameters
        ----------
        event : dict

            Expected fields:

                file_path
                event_type
                process_name
                timestamp
                user
                extension
                size

        Returns
        -------
        FilterResult
        """
        # Create a mutable copy to avoid side effects on the original event object
        event_copy = event.copy() if isinstance(event, dict) else event

        # 2.3.2 Validate event
        result = self._validate_event(event_copy)
        if not result.accepted:
            self._update_statistics(result)
            return result

        self.stats.total_events += 1
        self.stats.files_seen += 1

        # 2.3.6 Duplicate Detection
        if self._check_duplicate(event_copy, result):
            self._update_statistics(result)
            return result

        # 2.3.7 Severity Scoring (Runs before Whitelist)
        self._calculate_severity(event_copy, result)

        # 2.3.5 Whitelist Integration
        if self._check_whitelist(event_copy, result):
            self._update_statistics(result)
            return result

        # 2.3.3 Ignore Rules & 2.3.4 Dangerous Extension Rules
        if self._check_ignore_rules(event_copy, result):
            self._update_statistics(result)
            return result

        # 2.3.8 Confidence Scoring
        self._calculate_confidence(event_copy, result)

        # 2.3.10 & 2.3.11 Final result and statistics
        self._update_statistics(result)
        return result

    # ========================================================
    # FILE VALIDATION
    # ========================================================

    def _validate_event(
        self,
        event: dict,
    ) -> FilterResult:
        """
        Validate a file event before filtering.

        This function ONLY validates the event.

        It does NOT:
            • Apply filters
            • Check whitelist
            • Detect duplicates
            • Calculate severity

        Returns
        -------
        FilterResult

            accepted=True  -> Event is valid
            accepted=False -> Invalid event
        """
        result = FilterResult()
        result.collector = "FILE"

        # Event must be a dictionary (checked first to prevent crashes)
        if not isinstance(event, dict):
            result.mark_filtered("Invalid event object")
            return result

        result.event_type = event.get("event_type", "")

        # Correlation ID
        if self.config.ENABLE_CORRELATION_ID:
            result.correlation_id = generate_correlation_id()

        # Required fields
        required_fields = ("file_path", "event_type")
        for field in required_fields:
            value = event.get(field)
            if value is None:
                result.mark_filtered(f"Missing required field: {field}")
                return result
            if isinstance(value, str) and not value.strip():
                result.mark_filtered(f"Empty required field: {field}")
                return result

        # Normalize values
        event["file_path"] = str(event["file_path"]).strip()
        event["event_type"] = str(event["event_type"]).upper()

        # Optional values
        event.setdefault("process_name", "")
        event.setdefault("process_path", "")
        event.setdefault("publisher", "")
        event.setdefault("user", "")
        event.setdefault("extension", "")
        event.setdefault("filename", Path(event["file_path"]).name)
        event.setdefault("size", 0)
        event.setdefault("timestamp", datetime.now(timezone.utc))

        result.accepted = True
        result.filtered = False
        # The reason defaults to "Accepted" and is only changed if filtered.

        return result

    # ========================================================
    # IGNORE RULES
    # ========================================================

    def _check_ignore_rules(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Apply ignore rules from filter_rules.py.

        This method also contains the override logic for
        dangerous extensions. If an ignore rule matches BUT
        the extension is dangerous, the ignore is cancelled.

        Returns
        -------
        bool
            True if the event was filtered, False otherwise.
        """
        if not self.config.ENABLE_FILTERS:
            return False

        file_path = event.get("file_path", "")
        filename = event.get("filename", "")
        extension = event.get("extension", "")
        user = event.get("user", "")

        is_dangerous = self.engine.rules.is_dangerous_extension(extension)
        if is_dangerous:
            self.engine.rules.record_dangerous_hit()

        # Rule checks
        if self.engine.rules.is_ignored_path(file_path):
            self.engine.rules.record_path_hit()
            if not is_dangerous:
                result.mark_filtered("Ignored path")
                return True

        if self.engine.rules.is_ignored_file(filename):
            self.engine.rules.record_file_hit()
            if not is_dangerous:
                result.mark_filtered("Ignored file")
                return True

        if self.engine.rules.is_ignored_extension(extension):
            self.engine.rules.record_extension_hit()
            if not is_dangerous:
                result.mark_filtered("Ignored extension")
                return True

        if self.engine.rules.is_ignored_user(user):
            self.engine.rules.record_user_hit()
            if not is_dangerous:
                result.mark_filtered("Ignored user")
                return True

        return False

    # ========================================================
    # WHITELIST
    # ========================================================

    def _check_whitelist(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Apply whitelist rules from whitelist.py.

        Returns
        -------
        bool
            True if the event was filtered, False otherwise.
        """
        if not self.config.ENABLE_WHITELIST:
            return False

        # If severity analysis already marked the event as suspicious,
        # the whitelist must not apply.
        if result.suspicious:
            return False

        if self.engine.whitelist.is_trusted_process(event.get("process_name")):
            result.mark_whitelisted()
            result.mark_filtered("Whitelisted process")
            return True

        if self.engine.whitelist.is_trusted_folder(event.get("file_path")):
            result.mark_whitelisted()
            result.mark_filtered("Whitelisted folder")
            return True

        if self.engine.whitelist.is_trusted_publisher(event.get("publisher")):
            result.mark_whitelisted()
            result.mark_filtered("Whitelisted publisher")
            return True

        return False

    # ========================================================
    # DUPLICATES
    # ========================================================

    def _generate_event_hash(self, event: dict) -> str:
            """
            Generate a consistent hash for a given registry event.
            """
            payload = (
                f"{event.get('event_type', '')}|"
                f"{event.get('hive', '')}|"
                f"{event.get('registry_key', '')}|"
                f"{event.get('value_name', '')}|"
                f"{event.get('operation', '')}|"
                f"{event.get('process_name', '')}"
            )
            return hashlib.sha256(payload.encode()).hexdigest()

    def _check_duplicate(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Check for and handle duplicate registry events.
        """
        if not self.config.ENABLE_DUPLICATE_FILTER:
            return False

        event_hash = self._generate_event_hash(event)
        result.event_hash = event_hash
        now = datetime.now(timezone.utc)

        global _last_cache_cleanup_time

        with _duplicate_lock:
            # Check if cache cleanup is needed to prevent memory leak
            if (now - _last_cache_cleanup_time).total_seconds() > self.config.CACHE_CLEANUP_INTERVAL:
                expiration_window = self.config.DUPLICATE_WINDOW_SECONDS * 2
                keys_to_delete = [
                    key for key, cache_entry in _duplicate_cache.items()
                    if (now - cache_entry["timestamp"]).total_seconds() > expiration_window
                ]
                for key in keys_to_delete:
                    del _duplicate_cache[key]
                _last_cache_cleanup_time = now

            if event_hash in _duplicate_cache:
                last_seen = _duplicate_cache[event_hash]["timestamp"]
                delta = (now - last_seen).total_seconds()

                if delta < self.config.DUPLICATE_WINDOW_SECONDS:
                    _duplicate_cache[event_hash]["count"] += 1
                    result.mark_duplicate()
                    result.mark_filtered("Duplicate event")
                    self.stats.duplicates_removed += 1
                    return True

            # Record new event
            _duplicate_cache[event_hash] = {"timestamp": now, "count": 1}

        return False

    # ========================================================
    # SEVERITY & CONFIDENCE
    # ========================================================

    def _calculate_severity(
        self,
        event: dict,
        result: FilterResult,
    ) -> None:
        """
        Calculate event severity based on its properties.
        """
        if not self.config.ENABLE_SEVERITY_ENGINE:
            return

        extension = event.get("extension", "").lower()
        event_type = event.get("event_type", "")
        file_path_lower = event.get("file_path", "").lower()

        # Highest priority: critical system files
        if (
            event_type in ("FILE_CREATE", "FILE_DELETE", "FILE_MODIFY")
            and "system32" in file_path_lower
        ):
            result.set_severity("CRITICAL")
            result.mark_suspicious()
            return

        # Second priority: dangerous extensions
        if self.engine.rules.is_dangerous_extension(extension):
            result.set_severity("HIGH")
            result.mark_suspicious()
            return

        # Medium priority
        if event_type == "FILE_RENAME":
            result.set_severity("MEDIUM")
            return

        # Default
        result.set_severity("INFO")

    def _calculate_confidence(
        self,
        event: dict,
        result: FilterResult,
    ) -> None:
        """
        Calculate AI confidence score based on event properties.
        """
        if not self.config.ENABLE_CONFIDENCE_ENGINE:
            return

        score = 100.0

        if event.get("user") == "SYSTEM":
            score -= 10.0

        if self.engine.whitelist.is_trusted_process_path(event.get("process_path")):
            score -= 20.0

        if result.severity == "CRITICAL":
            score = 100.0
        elif result.severity == "HIGH":
            score = min(100.0, score + 15.0)

        result.set_confidence(score)

    # ========================================================
    # STATISTICS
    # ========================================================

    def _update_statistics(
        self,
        result: FilterResult,
    ) -> None:
        """
        Update file-specific and global statistics.
        """
        if not self.config.ENABLE_STATISTICS:
            return

        if result.filtered:
            self.stats.files_filtered += 1
            if not result.duplicate and not result.whitelisted:
                self.stats.ignored_events += 1
                self.engine.rules.record_ignored_event()
        else:
            self.stats.files_stored += 1
    # ========================================================
    # FILE VALIDATION
    # ========================================================

    def _validate_event(
        self,
        event: dict,
    ) -> FilterResult:
        """
        Validate a file event before filtering.

        This function ONLY validates the event.

        It does NOT:
            • Apply filters
            • Check whitelist
            • Detect duplicates
            • Calculate severity

        Returns
        -------
        FilterResult

            accepted=True  -> Event is valid
            accepted=False -> Invalid event
        """

        result = FilterResult()
        result.collector = "FILE"

        # ----------------------------------------------------
        # Event must be a dictionary
        # ----------------------------------------------------
        if not isinstance(event, dict):
            result.mark_filtered("Invalid event object")
            return result
        
        result.event_type = event.get("event_type", "")

        # 2.3.9 Correlation ID
        if self.config.ENABLE_CORRELATION_ID:
            result.correlation_id = generate_correlation_id()

        # ----------------------------------------------------
        # Required fields
        # ----------------------------------------------------

        required_fields = (

            "file_path",
            "event_type",

        )

        for field in required_fields:

            value = event.get(field)

            if value is None:

                result.mark_filtered(
                    f"Missing required field: {field}"
                )

                return result

            if isinstance(value, str) and not value.strip():

                result.mark_filtered(
                    f"Empty required field: {field}"
                )

                return result

        # ----------------------------------------------------
        # Normalize values
        # ----------------------------------------------------

        event["file_path"] = str(event["file_path"]).strip()

        event["event_type"] = str(
            event["event_type"]
        ).upper()

        # Optional values

        event.setdefault("process_name", "")
        event.setdefault("process_path", "")
        event.setdefault("publisher", "")
        event.setdefault("user", "")
        event.setdefault("extension", "")
        event.setdefault("filename", Path(event["file_path"]).name)
        event.setdefault("size", 0)
        event.setdefault("timestamp", datetime.now(timezone.utc))

        result.accepted = True
        result.filtered = False
        result.reason = "Valid event"

        return result
    
class ProcessFilter:
    """
    Process filtering engine.

    Responsibilities
    ----------------
    • Filter unwanted process events
    • Apply whitelist rules
    • Apply ignore rules
    • Detect duplicate events
    • Assign severity
    • Assign confidence
    • Generate correlation IDs
    • Update statistics

    NOTE:
    This class does NOT monitor processes.
    It only evaluates process events received
    from the Process Monitor.
    """

    def __init__(self, engine: "FilterEngine") -> None:
        """
        Initialize the Process Filter.
        """
        self.engine = engine
        self.config = engine.config
        self.stats = engine.statistics
        self.logger = engine.logger

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def filter_event(self, event: dict) -> FilterResult:
        """
        Evaluate a single process event.

        Parameters
        ----------
        event : dict

            Expected fields:

                process_name
                process_path
                pid
                event_type
                timestamp

        Returns
        -------
        FilterResult
        """
        # Create a mutable copy to avoid side effects on the original event object
        event_copy = event.copy() if isinstance(event, dict) else event

        # Validate event
        result = self._validate_event(event_copy)
        if not result.accepted:
            self._update_statistics(result)
            return result

        self.stats.total_events += 1
        self.stats.processes_seen += 1

        # Duplicate Detection
        if self._check_duplicate(event_copy, result):
            self._update_statistics(result)
            return result

        # Severity Scoring (Runs before Whitelist)
        self._calculate_severity(event_copy, result)

        # Whitelist Integration
        if self._check_whitelist(event_copy, result):
            self._update_statistics(result)
            return result

        # Ignore Rules
        if self._check_ignore_rules(event_copy, result):
            self._update_statistics(result)
            return result

        # Confidence Scoring
        self._calculate_confidence(event_copy, result)

        # Final result and statistics
        self._update_statistics(result)
        return result

    # ========================================================
    # PROCESS VALIDATION
    # ========================================================

    def _validate_event(
            self,
            event: dict,
        ) -> FilterResult:
            """
            Validate a process event before filtering.
            """
            result = FilterResult()
            result.collector = "PROCESS"

            # Event must be a dictionary
            if not isinstance(event, dict):
                result.mark_filtered("Invalid event object")
                return result

            result.event_type = event.get("event_type", "")

            # Correlation ID
            if self.config.ENABLE_CORRELATION_ID:
                result.correlation_id = generate_correlation_id()

            # Required fields
            required_fields = ("process_name", "process_path", "pid", "event_type")
            for field in required_fields:
                value = event.get(field)
                if value is None:
                    result.mark_filtered(f"Missing required field: {field}")
                    return result
                if isinstance(value, str) and not value.strip():
                    result.mark_filtered(f"Empty required field: {field}")
                    return result
            
            pid_value = event.get("pid")
            if not isinstance(pid_value, int) or pid_value < 0:
                result.mark_filtered(f"Invalid pid value: {pid_value}")
                return result

            # Normalize values
            event["process_name"] = str(event["process_name"]).strip()
            event["process_path"] = str(event["process_path"]).strip()
            event["event_type"] = str(event["event_type"]).upper()

            # Optional values
            event.setdefault("command_line", "")
            event.setdefault("parent_process", "")
            event.setdefault("parent_pid", 0)
            event.setdefault("publisher", "")
            event.setdefault("signature", "unsigned")
            event.setdefault("user", "")
            event.setdefault("integrity_level", "unknown")
            event.setdefault("timestamp", datetime.now(timezone.utc))

            result.accepted = True
            result.filtered = False

            return result

    # ========================================================
    # IGNORE RULES
    # ========================================================

    def _check_ignore_rules(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply process-specific ignore rules from filter_rules.py.

            Returns
            -------
            bool
                True if the event was filtered, False otherwise.
            """
            if not self.config.ENABLE_FILTERS:
                return False

            user = event.get("user", "")
            process_name = event.get("process_name", "")

            # Ignore events from configured noisy user accounts (e.g., SYSTEM)
            if self.engine.rules.is_ignored_user(user):
                self.engine.rules.record_user_hit()
                result.mark_filtered("Ignored user")
                return True

            # Ignore events from configured noisy system services
            if self.engine.rules.is_ignored_service(process_name):
                self.engine.rules.record_service_hit()
                result.mark_filtered("Ignored service")
                return True

            return False

    # ========================================================
    # WHITELIST
    # ========================================================

    def _check_whitelist(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Apply process-specific whitelist rules from whitelist.py.

        Returns
        -------
        bool
            True if the event was filtered, False otherwise.
        """
        if not self.config.ENABLE_WHITELIST:
            return False

        # If severity analysis already marked the event as suspicious,
        # the whitelist must not apply.
        if result.suspicious:
            return False

        # 1. Trusted Process
        if self.engine.whitelist.is_trusted_process(event.get("process_name")):
            result.mark_whitelisted()
            result.mark_filtered("Whitelisted process")
            return True

        # 2. Trusted Publisher
        if self.engine.whitelist.is_trusted_publisher(event.get("publisher")):
            result.mark_whitelisted()
            result.mark_filtered("Whitelisted publisher")
            return True

        # 3. Trusted Installation Path
        if self.engine.whitelist.is_trusted_process_path(event.get("process_path")):
            result.mark_whitelisted()
            result.mark_filtered("Whitelisted process path")
            return True

        return False

    # ========================================================
    # DUPLICATES
    # ========================================================

    def _generate_event_hash(self, event: dict) -> str:
            """
            Generate a consistent hash for a given process event.
            """
            payload = (
                f"{event.get('event_type', '')}|"
                f"{event.get('process_name', '')}|"
                f"{event.get('process_path', '')}|"
                f"{event.get('pid', 0)}|"
                f"{event.get('parent_pid', 0)}"
            )
            return hashlib.sha256(payload.encode()).hexdigest()

    def _check_duplicate(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Check for and handle duplicate process events.
        """
        if not self.config.ENABLE_DUPLICATE_FILTER:
            return False

        event_hash = self._generate_event_hash(event)
        result.event_hash = event_hash
        now = datetime.now(timezone.utc)

        global _last_cache_cleanup_time

        with _duplicate_lock:
            # Check if cache cleanup is needed to prevent memory leak
            if (now - _last_cache_cleanup_time).total_seconds() > self.config.CACHE_CLEANUP_INTERVAL:
                expiration_window = self.config.DUPLICATE_WINDOW_SECONDS * 2
                keys_to_delete = [
                    key for key, cache_entry in _duplicate_cache.items()
                    if (now - cache_entry["timestamp"]).total_seconds() > expiration_window
                ]
                for key in keys_to_delete:
                    del _duplicate_cache[key]
                _last_cache_cleanup_time = now

            if event_hash in _duplicate_cache:
                last_seen = _duplicate_cache[event_hash]["timestamp"]
                delta = (now - last_seen).total_seconds()

                if delta < self.config.DUPLICATE_WINDOW_SECONDS:
                    _duplicate_cache[event_hash]["count"] += 1
                    result.mark_duplicate()
                    result.mark_filtered("Duplicate event")
                    self.stats.duplicates_removed += 1
                    return True

            # Record new event
            _duplicate_cache[event_hash] = {"timestamp": now, "count": 1}

        return False
    # ========================================================
    # SEVERITY & CONFIDENCE
    # ========================================================

    def _calculate_severity(
        self,
        event: dict,
        result: FilterResult,
    ) -> None:
        """
        Calculate process event severity based on its properties.
        """
        if not self.config.ENABLE_SEVERITY_ENGINE:
            return

        # Extract and normalize data for analysis
        process_name = event.get("process_name", "")
        process_path = event.get("process_path", "")
        process_path_lower = process_path.lower()
        parent_process = event.get("parent_process", "")
        command_line_lower = event.get("command_line", "").lower()
        publisher = event.get("publisher", "")
        signature = event.get("signature", "unsigned").lower()
        integrity_level = event.get("integrity_level", "unknown").lower()
        event_type = event.get("event_type", "")
        extension = Path(process_path).suffix.lower()

        # ================================================
        # CRITICAL
        # ================================================

        # Untrusted process running from a critical system directory
        if (
            "system32" in process_path_lower or "syswow64" in process_path_lower
        ) and not self.engine.whitelist.is_trusted_process(process_name):
            result.set_severity("CRITICAL")
            result.mark_suspicious()
            return

        # Unsigned AND UNTRUSTED executable launched from a core Windows directory
        if (
            signature == "unsigned"
            and self.engine.whitelist.is_trusted_process_path(process_path)
            and not self.engine.whitelist.is_trusted_process(process_name)
            and extension in (".exe", ".dll", ".sys")
        ):
            result.set_severity("CRITICAL")
            result.mark_suspicious()
            return

        # Termination of a critical Windows process
        critical_procs_to_monitor = {"lsass.exe", "winlogon.exe", "csrss.exe"}
        if (
            event_type == "PROCESS_TERMINATE"
            and process_name.lower() in critical_procs_to_monitor
        ):
            result.set_severity("CRITICAL")
            result.mark_suspicious()
            return

        # TODO: Implement self.engine.rules.is_dangerous_process()
        # if self.engine.rules.is_dangerous_process(process_name):
        #     result.set_severity("CRITICAL")
        #     result.mark_suspicious()
        #     return

        # ================================================
        # HIGH
        # ================================================

        # Process launched from a Temp or Downloads folder
        if self.engine.rules.is_ignored_path(process_path) or "\\downloads\\" in process_path_lower:
            result.set_severity("HIGH")
            result.mark_suspicious()
            return

        # PowerShell or CMD executing a suspicious command
        if process_name.lower() in ("powershell.exe", "cmd.exe"):
            suspicious_args = ["-enc", "invoke-expression", "iex", "-w hidden"]
            if any(arg in command_line_lower for arg in suspicious_args):
                result.set_severity("HIGH")
                result.mark_suspicious()
                return

        # Process has an invalid signature
        if signature == "invalid":
            result.set_severity("HIGH")
            result.mark_suspicious()
            return

        # Process is running with elevated privileges and is not trusted
        if integrity_level in ("high", "system") and not self.engine.whitelist.is_trusted_process(process_name):
            result.set_severity("HIGH")
            result.mark_suspicious()
            return

        # ================================================
        # MEDIUM
        # ================================================

        # Uncommon parent-child process relationship (e.g., Office app spawning cmd)
        uncommon_children = {
            "winword.exe": "cmd.exe",
            "excel.exe": "powershell.exe",
            "outlook.exe": "mshta.exe",
        }
        if uncommon_children.get(parent_process.lower()) == process_name.lower():
            result.set_severity("MEDIUM")
            return

        if event_type == "PROCESS_RENAME":
            result.set_severity("MEDIUM")
            return

        # ================================================
        # INFO
        # ================================================

        result.set_severity("INFO")


    def _calculate_confidence(
            self,
            event: dict,
            result: FilterResult,
        ) -> None:
            """
            Calculate AI confidence score for a process event.
            """
            if not self.config.ENABLE_CONFIDENCE_ENGINE:
                return

            score = 100.0

            # Extract data for analysis
            publisher = event.get("publisher", "")
            signature = event.get("signature", "unsigned").lower()
            integrity_level = event.get("integrity_level", "unknown").lower()
            parent_process = event.get("parent_process", "")
            command_line = event.get("command_line", "")
            process_path = event.get("process_path", "")
            user = event.get("user", "")
            process_name = event.get("process_name", "")

            # ================================================
            # Reduce confidence based on missing/uncertain info
            # ================================================

            if not publisher:
                score -= 10
            if signature == "unsigned":
                score -= 15
            if integrity_level == "unknown":
                score -= 5
            if not parent_process:
                score -= 5
            if not command_line:
                score -= 5
            if not process_path:
                score -= 20
            if not user:
                score -= 5
            if signature == "invalid":
                score -= 20

            # ================================================
            # Increase confidence based on trustworthy indicators
            # ================================================

            if self.engine.whitelist.is_trusted_publisher(publisher):
                score += 10
            if self.engine.whitelist.is_trusted_process(process_name):
                score += 10
            if signature == "valid":
                score += 10
            if self.engine.whitelist.is_trusted_process_path(process_path):
                score += 5
            if parent_process:
                score += 5

            # ================================================
            # Adjust confidence based on severity/suspicion
            # ================================================

            if result.suspicious:
                score += 10
            if result.severity == "CRITICAL":
                score += 10

            # ================================================
            # Clamp result and assign
            # ================================================

            final_score = max(0.0, min(score, 100.0))
            result.set_confidence(final_score)

    # ========================================================
    # STATISTICS
    # ========================================================

    def _update_statistics(
            self,
            result: FilterResult,
        ) -> None:
            """
            Update process-specific and global statistics.
            """
            if not self.config.ENABLE_STATISTICS:
                return

            if result.filtered:
                self.stats.processes_filtered += 1
                # An "ignored" event is one filtered by an ignore rule, not by
                # the whitelist or duplicate detection.
                if not result.duplicate and not result.whitelisted:
                    self.stats.ignored_events += 1
                    self.engine.rules.record_ignored_event()
            else:
                self.stats.processes_stored += 1

class NetworkFilter:
    """
    Network filtering engine.

    Responsibilities
    ----------------
    • Filter unwanted network events
    • Apply whitelist rules
    • Apply ignore rules
    • Detect duplicate events
    • Assign severity
    • Assign confidence
    • Generate correlation IDs
    • Update statistics

    NOTE:
    This class does NOT monitor network traffic.
    It only evaluates network events received
    from the Network Monitor.
    """

    def __init__(self, engine: "FilterEngine") -> None:
        """
        Initialize the Network Filter.
        """
        self.engine = engine
        self.config = engine.config
        self.stats = engine.statistics
        self.logger = engine.logger

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def filter_event(self, event: dict) -> FilterResult:
            """
            Evaluate a single network event.
            """
            # Create a mutable copy to avoid side effects on the original event object
            event_copy = event.copy() if isinstance(event, dict) else event

            # Validate event
            result = self._validate_event(event_copy)
            if not result.accepted:
                self._update_statistics(result)
                return result

            self.stats.total_events += 1
            self.stats.network_seen += 1

            # Duplicate Detection
            if self._check_duplicate(event_copy, result):
                self._update_statistics(result)
                return result

            # Severity Scoring (Runs before Whitelist)
            self._calculate_severity(event_copy, result)

            # Whitelist Integration
            if self._check_whitelist(event_copy, result):
                self._update_statistics(result)
                return result

            # Ignore Rules
            if self._check_ignore_rules(event_copy, result):
                self._update_statistics(result)
                return result

            # Confidence Scoring
            self._calculate_confidence(event_copy, result)

            # Final result and statistics
            self._update_statistics(result)
            return result
    # ========================================================
    # PLACEHOLDER IMPLEMENTATIONS
    # ========================================================

    def _validate_event(
            self,
            event: dict,
        ) -> FilterResult:
            """
            Validate a network event before filtering.
            """
            # Assumes 'import ipaddress' exists at the top of the file.
            result = FilterResult()
            result.collector = "NETWORK"

            # 1. Verify the input is a dictionary.
            if not isinstance(event, dict):
                result.mark_filtered("Invalid event object")
                return result

            result.event_type = event.get("event_type", "")

            # 2. Generate a correlation ID.
            if self.config.ENABLE_CORRELATION_ID:
                result.correlation_id = generate_correlation_id()

            # 3. Validate required string fields.
            required_str_fields = ("source_ip", "destination_ip", "protocol", "direction", "event_type")
            for field in required_str_fields:
                value = event.get(field)
                if value is None:
                    result.mark_filtered(f"Missing required field: {field}")
                    return result
                if isinstance(value, str) and not value.strip():
                    result.mark_filtered(f"Empty required field: {field}")
                    return result

            # 4. Validate ports.
            required_port_fields = ("source_port", "destination_port")
            for field in required_port_fields:
                port_value = event.get(field)
                if port_value is None:
                    result.mark_filtered(f"Missing required field: {field}")
                    return result
                if not isinstance(port_value, int) or not (0 <= port_value <= 65535):
                    result.mark_filtered(f"Invalid port value for {field}: {port_value}")
                    return result
            
            # 5. Validate IP addresses.
            ip_fields = ("source_ip", "destination_ip")
            for field in ip_fields:
                try:
                    ipaddress.ip_address(event.get(field))
                except ValueError:
                    result.mark_filtered(f"Invalid IP address for {field}: {event.get(field)}")
                    return result

            # 6. Normalize fields.
            event["protocol"] = str(event["protocol"]).upper()
            event["direction"] = str(event["direction"]).upper()
            event["event_type"] = str(event["event_type"]).upper()

            # 7. Set defaults for optional fields.
            event.setdefault("hostname", "")
            event.setdefault("domain", "")
            event.setdefault("process_name", "")
            event.setdefault("process_path", "")
            event.setdefault("pid", 0)
            event.setdefault("user", "")
            event.setdefault("interface", "")
            event.setdefault("bytes_sent", 0)
            event.setdefault("bytes_received", 0)

            # 8. Add timestamp only if missing.
            event.setdefault("timestamp", datetime.now(timezone.utc))

            # 9. If validation succeeds:
            result.accepted = True
            result.filtered = False

            return result

    def _check_ignore_rules(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply network-specific ignore rules from filter_rules.py.

            Returns
            -------
            bool
                True if the event was filtered, False otherwise.
            """
            if not self.config.ENABLE_FILTERS:
                return False

            source_ip = event.get("source_ip", "")
            destination_ip = event.get("destination_ip", "")
            source_port = event.get("source_port")
            destination_port = event.get("destination_port")

            try:
                src_addr = ipaddress.ip_address(source_ip)
                dst_addr = ipaddress.ip_address(destination_ip)
            except ValueError:
                # This should not be reached if validation is correct, but provides safety.
                return False

            # 1. Ignore localhost traffic
            if src_addr.is_loopback or dst_addr.is_loopback:
                self.engine.rules.record_ip_hit()
                result.mark_filtered("Ignored localhost traffic")
                return True

            # 3. Ignore configured IP addresses
            if self.engine.rules.is_ignored_ip(source_ip) or self.engine.rules.is_ignored_ip(destination_ip):
                self.engine.rules.record_ip_hit()
                result.mark_filtered("Ignored IP address")
                return True

            # 4. Ignore configured ports
            if self.engine.rules.is_ignored_port(source_port) or self.engine.rules.is_ignored_port(destination_port):
                self.engine.rules.record_port_hit()
                result.mark_filtered("Ignored port")
                return True

            # 2. Ignore internal/private network traffic (if both ends are private)
            if src_addr.is_private and dst_addr.is_private:
                self.engine.rules.record_ip_hit()
                result.mark_filtered("Ignored internal network traffic")
                return True

            return False

    def _check_whitelist(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply network-specific whitelist rules from whitelist.py.

            Returns
            -------
            bool
                True if the event was filtered, False otherwise.
            """
            if not self.config.ENABLE_WHITELIST:
                return False

            # If severity analysis already marked the event as suspicious,
            # the whitelist must not apply.
            if result.suspicious:
                return False

            source_ip = event.get("source_ip", "")
            destination_ip = event.get("destination_ip", "")
            domain = event.get("domain", "") or event.get("hostname", "")
            source_port = event.get("source_port")
            destination_port = event.get("destination_port")

            # 1. Trusted Source IP
            if self.engine.whitelist.is_trusted_ip(source_ip):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted source IP")
                return True

            # 2. Trusted Destination IP
            if self.engine.whitelist.is_trusted_ip(destination_ip):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted destination IP")
                return True

            # 3. Trusted Domain
            if self.engine.whitelist.is_trusted_domain(domain):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted domain")
                return True

            # 4. Trusted Port
            if self.engine.whitelist.is_trusted_port(source_port) or self.engine.whitelist.is_trusted_port(destination_port):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted port")
                return True

            # 5. Trusted Network
            if self.engine.whitelist.is_trusted_network(source_ip) or self.engine.whitelist.is_trusted_network(destination_ip):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted network")
                return True

            return False

    def _generate_event_hash(self, event: dict) -> str:
            """
            Generate a consistent hash for a given network event.
            """
            payload = (
                f"{event.get('event_type', '')}|"
                f"{event.get('direction', '')}|"
                f"{event.get('protocol', '')}|"
                f"{event.get('source_ip', '')}|"
                f"{event.get('source_port', 0)}|"
                f"{event.get('destination_ip', '')}|"
                f"{event.get('destination_port', 0)}"
            )
            return hashlib.sha256(payload.encode()).hexdigest()

    def _check_duplicate(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Check for and handle duplicate network events.
        """
        if not self.config.ENABLE_DUPLICATE_FILTER:
            return False

        event_hash = self._generate_event_hash(event)
        result.event_hash = event_hash
        now = datetime.now(timezone.utc)

        global _last_cache_cleanup_time

        with _duplicate_lock:
            # Check if cache cleanup is needed to prevent memory leak
            if (now - _last_cache_cleanup_time).total_seconds() > self.config.CACHE_CLEANUP_INTERVAL:
                expiration_window = self.config.DUPLICATE_WINDOW_SECONDS * 2
                keys_to_delete = [
                    key for key, cache_entry in _duplicate_cache.items()
                    if (now - cache_entry["timestamp"]).total_seconds() > expiration_window
                ]
                for key in keys_to_delete:
                    del _duplicate_cache[key]
                _last_cache_cleanup_time = now

            if event_hash in _duplicate_cache:
                last_seen = _duplicate_cache[event_hash]["timestamp"]
                delta = (now - last_seen).total_seconds()

                if delta < self.config.DUPLICATE_WINDOW_SECONDS:
                    _duplicate_cache[event_hash]["count"] += 1
                    result.mark_duplicate()
                    result.mark_filtered("Duplicate event")
                    self.stats.duplicates_removed += 1
                    return True

            # Record new event
            _duplicate_cache[event_hash] = {"timestamp": now, "count": 1}

        return False

    def _calculate_severity(
            self,
            event: dict,
            result: FilterResult,
        ) -> None:
            """
            Calculate network event severity based on its properties.
            """
            if not self.config.ENABLE_SEVERITY_ENGINE:
                return

            # Extract data for analysis
            source_ip = event.get("source_ip", "")
            destination_ip = event.get("destination_ip", "")
            destination_port = event.get("destination_port")
            protocol = event.get("protocol", "")
            direction = event.get("direction", "")
            bytes_sent = event.get("bytes_sent", 0)

            try:
                dst_addr = ipaddress.ip_address(destination_ip)
            except ValueError:
                # Should not happen with validation, but provides safety
                result.set_severity("INFO")
                return

            # ================================================
            # CRITICAL
            # ================================================

            # TODO: Implement self.engine.rules.is_malicious_ip(...)
            # if self.engine.rules.is_malicious_ip(destination_ip):
            #     result.set_severity("CRITICAL")
            #     result.mark_suspicious()
            #     return

            # TODO: Implement self.engine.rules.is_blocked_port(...)
            # if self.engine.rules.is_blocked_port(destination_port):
            #     result.set_severity("CRITICAL")
            #     result.mark_suspicious()
            #     return

            # Outbound connection to a public IP on a dangerous, non-standard web port
            dangerous_ports = {21, 22, 23, 139, 445, 3389} # FTP, SSH, Telnet, NetBIOS, SMB, RDP
            if (
                direction == "OUTBOUND"
                and not dst_addr.is_private
                and destination_port in dangerous_ports
            ):
                result.set_severity("CRITICAL")
                result.mark_suspicious()
                return

            # ================================================
            # HIGH
            # ================================================

            # Connection using a risky protocol that is not on a standard port
            risky_protocols = {"RDP", "SMB", "SSH", "FTP", "TELNET"}
            if protocol in risky_protocols:
                result.set_severity("HIGH")
                result.mark_suspicious()
                return
            
            # TODO: Implement self.engine.rules.is_suspicious_protocol(...)
            # if self.engine.rules.is_suspicious_protocol(protocol):
            #     result.set_severity("HIGH")
            #     result.mark_suspicious()
            #     return

            # ================================================
            # MEDIUM
            # ================================================

            # Large outbound data transfer to a public IP
            large_transfer_threshold = 10 * 1024 * 1024  # 10 MB
            if (
                direction == "OUTBOUND"
                and not dst_addr.is_private
                and bytes_sent > large_transfer_threshold
            ):
                result.set_severity("MEDIUM")
                return

            # Connection to a non-standard, high-numbered port
            if destination_port > 49151: # Ephemeral ports
                result.set_severity("MEDIUM")
                return

            # ================================================
            # INFO
            # ================================================

            result.set_severity("INFO")

    def _calculate_confidence(
            self,
            event: dict,
            result: FilterResult,
        ) -> None:
            """
            Calculate AI confidence score for a network event.
            """
            if not self.config.ENABLE_CONFIDENCE_ENGINE:
                return

            score = 100.0

            # Extract data for analysis
            source_ip = event.get("source_ip")
            destination_ip = event.get("destination_ip")
            protocol = event.get("protocol")
            direction = event.get("direction")
            source_port = event.get("source_port")
            destination_port = event.get("destination_port")
            domain = event.get("domain") or event.get("hostname")

            # ================================================
            # Reduce confidence based on missing/uncertain info
            # ================================================

            if not source_ip:
                score -= 20
            if not destination_ip:
                score -= 20
            if not protocol or protocol == "UNKNOWN":
                score -= 10
            if not direction:
                score -= 5
            if source_port is None:
                score -= 5
            if destination_port is None:
                score -= 5
            if not domain:
                score -= 5
            
            # TODO: Implement a concept of a "known network" beyond just private/public
            # if not self.engine.rules.is_known_network(destination_ip):
            #     score -= 5

            # ================================================
            # Increase confidence based on trustworthy indicators
            # ================================================

            if self.engine.whitelist.is_trusted_ip(source_ip):
                score += 10
            if self.engine.whitelist.is_trusted_ip(destination_ip):
                score += 10
            if self.engine.whitelist.is_trusted_domain(domain):
                score += 10
            if self.engine.whitelist.is_trusted_network(source_ip) or self.engine.whitelist.is_trusted_network(destination_ip):
                score += 5
            if self.engine.whitelist.is_trusted_port(source_port) or self.engine.whitelist.is_trusted_port(destination_port):
                score += 5

            # ================================================
            # Adjust confidence based on severity/suspicion
            # ================================================

            if result.suspicious:
                score += 10
            if result.severity == "CRITICAL":
                score += 10

            # ================================================
            # Clamp result and assign
            # ================================================

            final_score = max(0.0, min(score, 100.0))
            result.set_confidence(final_score)

    def _update_statistics(
            self,
            result: FilterResult,
        ) -> None:
            """
            Update network-specific and global statistics.
            """
            if not self.config.ENABLE_STATISTICS:
                return

            if result.filtered:
                self.stats.network_filtered += 1
                # An "ignored" event is one filtered by an ignore rule, not by
                # the whitelist or duplicate detection.
                if not result.duplicate and not result.whitelisted:
                    self.stats.ignored_events += 1
                    self.engine.rules.record_ignored_event()
            else:
                self.stats.network_stored += 1
class RegistryFilter:
    """
    Registry filtering engine.

    Responsibilities
    ----------------
    • Filter unwanted registry events
    • Apply whitelist rules
    • Apply ignore rules
    • Detect duplicate events
    • Assign severity
    • Assign confidence
    • Generate correlation IDs
    • Update statistics

    NOTE:
    This class does NOT monitor the registry.
    It only evaluates registry events received
    from the Registry Monitor.
    """

    def __init__(self, engine: "FilterEngine") -> None:
        """
        Initialize the Registry Filter.
        """
        self.engine = engine
        self.config = engine.config
        self.stats = engine.statistics
        self.logger = engine.logger

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def filter_event(self, event: dict) -> FilterResult:
            """
            Evaluate a single registry event.
            """
            # Create a mutable copy to avoid side effects on the original event object
            event_copy = event.copy() if isinstance(event, dict) else event

            # Validate event
            result = self._validate_event(event_copy)
            if not result.accepted:
                self._update_statistics(result)
                return result

            self.stats.total_events += 1
            self.stats.registry_seen += 1

            # Duplicate Detection
            if self._check_duplicate(event_copy, result):
                self._update_statistics(result)
                return result

            # Severity Scoring (Runs before Whitelist)
            self._calculate_severity(event_copy, result)

            # Whitelist Integration
            if self._check_whitelist(event_copy, result):
                self._update_statistics(result)
                return result

            # Ignore Rules
            if self._check_ignore_rules(event_copy, result):
                self._update_statistics(result)
                return result

            # Confidence Scoring
            self._calculate_confidence(event_copy, result)

            # Final result and statistics
            self._update_statistics(result)
            return result

    # ========================================================
    # PLACEHOLDER IMPLEMENTATIONS
    # ========================================================

    def _validate_event(
            self,
            event: dict,
        ) -> FilterResult:
            """
            Validate a registry event before filtering.
            """
            result = FilterResult()
            result.collector = "REGISTRY"

            # Verify the input is a dictionary before accessing any keys.
            if not isinstance(event, dict):
                result.mark_filtered("Invalid event object")
                return result

            result.event_type = event.get("event_type", "")

            # Generate a correlation ID if enabled.
            if self.config.ENABLE_CORRELATION_ID:
                result.correlation_id = generate_correlation_id()

            # Validate required fields.
            # Note: value_name can be an empty string for the (Default) value, so it's not in this list.
            # Note: value_data can be None, so it's not in this list.
            required_str_fields = ("registry_key", "hive", "operation", "event_type", "process_name")
            for field in required_str_fields:
                value = event.get(field)
                if value is None:
                    result.mark_filtered(f"Missing required field: {field}")
                    return result
                if isinstance(value, str) and not value.strip():
                    result.mark_filtered(f"Empty required field: {field}")
                    return result
            
            # Check for existence of fields that can be empty or None
            if "value_name" not in event:
                result.mark_filtered("Missing required field: value_name")
                return result
            if "value_data" not in event:
                result.mark_filtered("Missing required field: value_data")
                return result

            # Registry Hive Validation
            valid_hives = {"HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU", "HKEY_CLASSES_ROOT", "HKCR", "HKEY_USERS", "HKU", "HKEY_CURRENT_CONFIG", "HKCC"}
            hive_upper = str(event.get("hive")).upper()
            if hive_upper not in valid_hives:
                result.mark_filtered(f"Invalid registry hive: {event.get('hive')}")
                return result

            # Operation Validation
            valid_operations = {"CREATE", "MODIFY", "DELETE", "RENAME", "READ"}
            operation_upper = str(event.get("operation")).upper()
            if operation_upper not in valid_operations:
                result.mark_filtered(f"Invalid operation: {event.get('operation')}")
                return result

            # Event Type Validation
            valid_event_types = {"REGISTRY_CREATE", "REGISTRY_MODIFY", "REGISTRY_DELETE", "REGISTRY_RENAME", "REGISTRY_READ"}
            event_type_upper = str(event.get("event_type")).upper()
            if event_type_upper not in valid_event_types:
                result.mark_filtered(f"Invalid event type: {event.get('event_type')}")
                return result

            # Normalization
            event["registry_key"] = str(event["registry_key"]).strip()
            event["value_name"] = str(event["value_name"]).strip()
            # value_data is not modified
            event["hive"] = hive_upper
            event["operation"] = operation_upper
            event["event_type"] = event_type_upper
            event["process_name"] = str(event["process_name"]).strip()

            # Set defaults for optional fields
            event.setdefault("process_path", "")
            event.setdefault("pid", 0)
            event.setdefault("user", "")
            event.setdefault("timestamp", datetime.now(timezone.utc))

            # If validation succeeds
            result.accepted = True
            result.filtered = False

            return result

    def _check_ignore_rules(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply registry-specific ignore rules from filter_rules.py.

            Returns
            -------
            bool
                True if the event was filtered, False otherwise.
            """
            if not self.config.ENABLE_FILTERS:
                return False

            registry_key = event.get("registry_key", "")
            process_name = event.get("process_name", "")
            value_name = event.get("value_name", "")

            # A "never ignore" rule for registry keys acts as an override for any ignore rule.
            is_never_ignore = self.engine.rules.is_never_ignore_registry(registry_key)
            if is_never_ignore:
                self.engine.rules.record_never_ignore_registry_hit()

            # Ignore Rule 1 & 2: Ignored/Temporary Registry Keys/Paths
            if self.engine.rules.is_ignored_registry(registry_key):
                self.engine.rules.record_registry_hit()
                if not is_never_ignore:
                    result.mark_filtered("Ignored registry key")
                    return True

            # Ignore Rule 3: Ignored Processes
            # Using is_ignored_service as it contains common noisy system processes.
            if self.engine.rules.is_ignored_service(process_name):
                self.engine.rules.record_service_hit()
                if not is_never_ignore:
                    result.mark_filtered("Ignored process")
                    return True

            # Ignore Rule 4: Ignored Registry Values
            # TODO: Move this list to filter_rules.py and create is_ignored_registry_value()
            ignored_value_names = {
                "lastvisitedpidlmru",
                "mrulist",
                "recentdocs",
                "iconstreams",
                "pasticonsstream",
            }
            if value_name.lower() in ignored_value_names:
                # TODO: Create and call self.engine.rules.record_registry_value_hit()
                if not is_never_ignore:
                    result.mark_filtered("Ignored registry value")
                    return True

            return False

    def _check_whitelist(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply registry-specific whitelist rules from whitelist.py.

            Returns
            -------
            bool
                True if the event was filtered, False otherwise.
            """
            if not self.config.ENABLE_WHITELIST:
                return False

            registry_key = event.get("registry_key", "")
            process_name = event.get("process_name", "")
            value_name = event.get("value_name", "")

            # Exception: A trusted process modifying a trusted key should always be
            # whitelisted, even if a broad severity rule flagged it as suspicious.
            if self.engine.whitelist.is_trusted_process(process_name) and self.engine.whitelist.is_trusted_registry_key(registry_key):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted operation by trusted process on trusted key")
                result.set_severity("INFO")
                result.suspicious = False
                return True

            # If severity analysis already marked the event as suspicious,
            # the whitelist must not apply.
            if result.suspicious:
                return False

            # Whitelist Rule 3: Trusted Processes (if not caught by the exception above)
            if self.engine.whitelist.is_trusted_process(process_name):
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted process")
                result.set_severity("INFO")
                result.suspicious = False
                return True

            # Whitelist Rule 4: Trusted Registry Values
            # TODO: Move this list to whitelist.py and create is_trusted_registry_value()
            trusted_value_names = {
                "(default)",
                "programfilesdir",
                "commonfilesdir",
                "devicepath",
            }
            if value_name.lower() in trusted_value_names:
                # TODO: Create and call a statistics recorder for this hit.
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted registry value")
                result.set_severity("INFO")
                result.suspicious = False
                return True

            return False

    def _generate_event_hash(self, event: dict) -> str:
            """
            Generate a consistent hash for a given registry event.
            """
            payload = (
                f"{event.get('event_type', '')}|"
                f"{event.get('hive', '')}|"
                f"{event.get('registry_key', '')}|"
                f"{event.get('value_name', '')}|"
                f"{event.get('operation', '')}|"
                f"{event.get('process_name', '')}"
            )
            return hashlib.sha256(payload.encode()).hexdigest()

    def _generate_event_hash(self, event: dict) -> str:
            """
            Generate a consistent hash for a given registry event.
            """
            payload = (
                f"{event.get('event_type', '')}|"
                f"{event.get('hive', '')}|"
                f"{event.get('registry_key', '')}|"
                f"{event.get('value_name', '')}|"
                f"{event.get('operation', '')}|"
                f"{event.get('process_name', '')}"
            )
            return hashlib.sha256(payload.encode()).hexdigest()

    def _check_duplicate(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Check for and handle duplicate registry events.
        """
        if not self.config.ENABLE_DUPLICATE_FILTER:
            return False

        event_hash = self._generate_event_hash(event)
        result.event_hash = event_hash
        now = datetime.now(timezone.utc)

        global _last_cache_cleanup_time

        with _duplicate_lock:
            # Check if cache cleanup is needed to prevent memory leak
            if (now - _last_cache_cleanup_time).total_seconds() > self.config.CACHE_CLEANUP_INTERVAL:
                expiration_window = self.config.DUPLICATE_WINDOW_SECONDS * 2
                keys_to_delete = [
                    key for key, cache_entry in _duplicate_cache.items()
                    if (now - cache_entry["timestamp"]).total_seconds() > expiration_window
                ]
                for key in keys_to_delete:
                    del _duplicate_cache[key]
                _last_cache_cleanup_time = now

            if event_hash in _duplicate_cache:
                last_seen = _duplicate_cache[event_hash]["timestamp"]
                delta = (now - last_seen).total_seconds()

                if delta < self.config.DUPLICATE_WINDOW_SECONDS:
                    _duplicate_cache[event_hash]["count"] += 1
                    result.mark_duplicate()
                    result.mark_filtered("Duplicate event")
                    self.stats.duplicates_removed += 1
                    return True

            # Record new event
            _duplicate_cache[event_hash] = {"timestamp": now, "count": 1}

        return False

    def _calculate_severity(
            self,
            event: dict,
            result: FilterResult,
        ) -> None:
            """
            Calculate registry event severity based on its properties.
            """
            if not self.config.ENABLE_SEVERITY_ENGINE:
                return

            # Extract data for analysis
            registry_key = event.get("registry_key", "")
            operation = event.get("operation", "")

            # ================================================
            # CRITICAL
            # ================================================
            # Use the existing helper which checks for persistence keys like Run, Services, Winlogon, etc.
            if self.engine.rules.is_never_ignore_registry(registry_key):
                result.set_severity("CRITICAL")
                result.mark_suspicious()
                return

            # TODO: Implement a specific helper for IFEO, AppInit_DLLs, etc. if not covered.
            # For now, we can add a simple check.
            critical_keywords = {
                "image file execution options",
                "appinit_dlls",
                "bootexecute",
                "knowndlls",
            }
            key_lower = registry_key.lower()
            if any(keyword in key_lower for keyword in critical_keywords):
                result.set_severity("CRITICAL")
                result.mark_suspicious()
                return

            # ================================================
            # HIGH
            # ================================================
            # Check for other important configuration areas.
            high_risk_keywords = {
                "software\\microsoft",
                "software\\classes",
                "firewall",
                "startupapproved",
                "shell extensions",
                "browser helper objects",
            }
            if any(keyword in key_lower for keyword in high_risk_keywords):
                result.set_severity("HIGH")
                result.mark_suspicious()
                return

            # ================================================
            # MEDIUM
            # ================================================
            # Any modification operation not caught by higher-risk rules is Medium.
            if operation in ("CREATE", "MODIFY", "DELETE", "RENAME"):
                result.set_severity("MEDIUM")
                return

            # ================================================
            # INFO
            # ================================================
            # Default for non-modifying operations like READ.
            result.set_severity("INFO")

    def _calculate_confidence(
        self,
        event: dict,
        result: FilterResult,
    ) -> None:
        """
        Calculate AI confidence score for a registry event.
        """
        if not self.config.ENABLE_CONFIDENCE_ENGINE:
            return

        score = 100.0

        # Extract data for analysis
        process_name = event.get("process_name")
        value_name = event.get("value_name")
        value_data = event.get("value_data")
        hive = event.get("hive")
        operation = event.get("operation")
        registry_key = event.get("registry_key")
        user = event.get("user")
        process_path = event.get("process_path")

        # ================================================
        # Reduce confidence based on missing/uncertain info
        # ================================================

        if not process_name:
            score -= 10
        if value_name is None:  # Empty string is valid for (Default)
            score -= 5
        if value_data is None:  # Empty string is a valid data type
            score -= 5
        if not hive:
            score -= 20
        if not operation:
            score -= 15
        if not registry_key:
            score -= 20
        if not user:
            score -= 5
        if not process_path:
            score -= 5

        # ================================================
        # Increase confidence based on trustworthy indicators
        # ================================================

        if self.engine.whitelist.is_trusted_registry_key(registry_key):
            score += 10
        if self.engine.whitelist.is_trusted_process(process_name):
            score += 10
        if hive:
            score += 5
        
        # TODO: Implement self.engine.whitelist.is_trusted_registry_value()
        # if self.engine.whitelist.is_trusted_registry_value(value_name):
        #     score += 5
        
        # TODO: Implement self.engine.whitelist.is_trusted_registry_path()
        # if self.engine.whitelist.is_trusted_registry_path(registry_key):
        #     score += 10

        # ================================================
        # Adjust confidence based on severity/suspicion
        # ================================================

        if result.suspicious:
            score += 10
        if result.severity == "CRITICAL":
            score += 10

        # ================================================
        # Clamp result and assign
        # ================================================

        final_score = max(0.0, min(score, 100.0))
        result.set_confidence(final_score)
    
    def _update_statistics(
        self,
        result: FilterResult,
    ) -> None:
        """
        Update registry-specific and global statistics.
        """
        if not self.config.ENABLE_STATISTICS:
            return

        if result.filtered:
            self.stats.registry_filtered += 1
            # An "ignored" event is one filtered by an ignore rule, not by
            # the whitelist or duplicate detection.
            if not result.duplicate and not result.whitelisted:
                self.stats.ignored_events += 1
                self.engine.rules.record_ignored_event()
        else:
            self.stats.registry_stored += 1

class FileFilter:
    """
    File filtering engine.

    Responsibilities
    ----------------
    • Filter unwanted file events
    • Apply whitelist rules
    • Apply ignore rules
    • Detect duplicate events
    • Assign severity
    • Assign confidence
    • Generate correlation IDs
    • Update statistics

    NOTE:
    This class does NOT monitor files.
    It only evaluates file events received
    from the File Monitor.
    """

    def __init__(self, engine: "FilterEngine") -> None:
        """
        Initialize the File Filter.
        """
        self.engine = engine
        self.config = engine.config
        self.stats = engine.statistics
        self.logger = engine.logger

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def filter_event(self, event: dict) -> FilterResult:
            """
            Evaluate a single file event.
            """
            # Create a mutable copy to avoid side effects on the original event object
            event_copy = event.copy() if isinstance(event, dict) else event

            # Validate event
            result = self._validate_event(event_copy)
            if not result.accepted:
                self._update_statistics(result)
                return result

            self.stats.total_events += 1
            self.stats.files_seen += 1

            # Duplicate Detection
            if self._check_duplicate(event_copy, result):
                self._update_statistics(result)
                return result

            # Severity Scoring (Runs before Whitelist)
            self._calculate_severity(event_copy, result)

            # Whitelist Integration
            if self._check_whitelist(event_copy, result):
                self._update_statistics(result)
                return result

            # Ignore Rules
            if self._check_ignore_rules(event_copy, result):
                self._update_statistics(result)
                return result

            # Confidence Scoring
            self._calculate_confidence(event_copy, result)

            # Final result and statistics
            self._update_statistics(result)
            return result

    # ========================================================
    # PLACEHOLDER IMPLEMENTATIONS
    # ========================================================

    def _validate_event(
            self,
            event: dict,
        ) -> FilterResult:
            """
            Validate a file event before filtering.
            """
            result = FilterResult()
            result.collector = "FILE"

            # Generate a Correlation ID for every event, including invalid ones.
            if self.config.ENABLE_CORRELATION_ID:
                result.correlation_id = generate_correlation_id()

            # Verify the input is a dictionary before accessing any keys.
            if not isinstance(event, dict):
                result.mark_filtered("Invalid event object")
                return result

            # --- Field Existence, Type, and Content Validation ---
            required_fields = {
                "file_path": str,
                "file_name": str,
                "extension": str,
                "operation": str,
                "process_name": str,
                "file_size": (int, float),
                "timestamp": datetime,
                "event_type": str,
            }

            for field, expected_type in required_fields.items():
                value = event.get(field)
                if value is None:
                    result.mark_filtered(f"Missing required field: {field}")
                    return result
                if not isinstance(value, expected_type):
                    result.mark_filtered(f"Invalid data type for {field}: expected {expected_type.__name__}, got {type(value).__name__}")
                    return result
                
                if isinstance(value, str):
                    stripped_value = value.strip()
                    if not stripped_value:
                        result.mark_filtered(f"Empty required field: {field}")
                        return result
                    event[field] = stripped_value

            # --- Specific Value Validation ---

            if event["file_size"] < 0:
                result.mark_filtered(f"Invalid file size: {event['file_size']}")
                return result

            if not event["extension"].startswith('.'):
                result.mark_filtered(f"Invalid extension format: {event['extension']}")
                return result

            event["operation"] = event["operation"].upper()
            valid_operations = {"CREATE", "MODIFY", "DELETE", "RENAME", "MOVE", "COPY"}
            if event["operation"] not in valid_operations:
                result.mark_filtered(f"Invalid operation: {event['operation']}")
                return result

            event["event_type"] = event["event_type"].upper()
            valid_event_types = {"FILE_CREATE", "FILE_MODIFY", "FILE_DELETE", "FILE_RENAME", "FILE_MOVE", "FILE_COPY"}
            if event["event_type"] not in valid_event_types:
                result.mark_filtered(f"Invalid event type: {event['event_type']}")
                return result

            # --- Success ---
            result.accepted = True
            result.filtered = False

            return result

    def _check_ignore_rules(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply file-specific ignore rules from filter_rules.py.
            """
            if not self.config.ENABLE_FILTERS:
                return False

            # Extract data for analysis
            file_path = event.get("file_path", "")
            file_name = event.get("file_name", "")
            extension = event.get("extension", "")
            process_name = event.get("process_name", "")

            # Dangerous extensions must never be ignored. This acts as an override.
            is_dangerous = self.engine.rules.is_dangerous_extension(extension)
            if is_dangerous:
                self.engine.rules.record_dangerous_hit()

            # 1 & 2. Ignore Temporary/Configured Folders
            if self.engine.rules.is_ignored_path(file_path):
                self.engine.rules.record_path_hit()
                if not is_dangerous:
                    result.mark_filtered("Ignored configured folder")
                    return True

            # Ignore specific temporary file patterns (e.g., ~$* for Office)
            # TODO: The is_ignored_pattern helper should be implemented in filter_rules.py
            # For now, we add a simple check for this common case.
            if file_name.startswith("~$"):
                # TODO: Add a specific statistics recorder for this pattern hit.
                if not is_dangerous:
                    result.mark_filtered("Ignored temporary file")
                    return True

            # 3. Ignore Configured File Extensions
            if self.engine.rules.is_ignored_extension(extension):
                self.engine.rules.record_extension_hit()
                if not is_dangerous:
                    result.mark_filtered("Ignored configured extension")
                    return True

            # 4. Ignore Configured Processes
            # Using is_trusted_process as it contains common noisy system processes.
            if self.engine.whitelist.is_trusted_process(process_name):
                # TODO: Add a specific statistics recorder for ignored process hits.
                if not is_dangerous:
                    result.mark_filtered("Ignored configured process")
                    return True

            return False

    def _check_whitelist(
            self,
            event: dict,
            result: FilterResult,
        ) -> bool:
            """
            Apply file-specific whitelist rules from whitelist.py.
            """
            if not self.config.ENABLE_WHITELIST:
                return False

            # Extract data for analysis
            file_path = event.get("file_path", "")
            file_name = event.get("file_name", "")
            process_name = event.get("process_name", "")
            extension = event.get("extension", "")

            # Calculate all trust indicators up front.
            is_proc_trusted = self.engine.whitelist.is_trusted_process(process_name)
            is_file_trusted = self.engine.whitelist.is_trusted_process(file_name)
            is_folder_trusted = self.engine.whitelist.is_trusted_folder(file_path)
            is_ext_trusted = self.engine.whitelist.is_trusted_extension(extension)

            # --- Override Path for Extremely High Trust Scenarios ---
            # This combination is strong enough to override a 'suspicious' flag from a broad severity rule.
            # This handles TEST 2: a trusted process (svchost.exe) modifying a trusted file (kernel32.dll).
            if is_proc_trusted and is_file_trusted:
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted trusted process on trusted file")
                result.set_severity("INFO")
                result.suspicious = False
                result.set_confidence(100.0)
                return True

            # --- Standard Security Gate ---
            # If the event did not meet the high bar for an override, and it was
            # flagged as suspicious by the severity engine, it must not be whitelisted.
            # This handles TEST 5: a non-trusted process creating a malicious file in a trusted folder.
            if result.suspicious:
                return False

            # --- Standard Benign Whitelist Path (for non-suspicious events) ---
            # These weaker conditions are safe only because we already know the event is not suspicious.

            # A trusted process performing a non-suspicious action.
            if is_proc_trusted:
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted trusted process")
                result.set_severity("INFO")
                result.suspicious = False
                result.set_confidence(100.0)
                return True

            # A non-suspicious action on a file with a benign, trusted extension.
            if is_ext_trusted:
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted trusted extension")
                result.set_severity("INFO")
                result.suspicious = False
                result.set_confidence(100.0)
                return True
            
            # A non-suspicious action inside a trusted folder.
            if is_folder_trusted:
                result.mark_whitelisted()
                result.mark_filtered("Whitelisted trusted folder")
                result.set_severity("INFO")
                result.suspicious = False
                result.set_confidence(100.0)
                return True

            return False

    def _generate_event_hash(self, event: dict) -> str:
        """
        Generate a consistent hash for a given file event.
        """
        payload = (
            f"{event.get('event_type', '')}|"
            f"{event.get('file_path', '')}|"
            f"{event.get('operation', '')}|"
            f"{event.get('process_name', '')}|"
            f"{event.get('extension', '')}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _check_duplicate(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Check for and handle duplicate file events.
        """
        if not self.config.ENABLE_DUPLICATE_FILTER:
            return False

        event_hash = self._generate_event_hash(event)
        result.event_hash = event_hash
        now = datetime.now(timezone.utc)

        global _last_cache_cleanup_time

        with _duplicate_lock:
            # Check if cache cleanup is needed to prevent memory leak
            if (now - _last_cache_cleanup_time).total_seconds() > self.config.CACHE_CLEANUP_INTERVAL:
                expiration_window = self.config.DUPLICATE_WINDOW_SECONDS * 2
                keys_to_delete = [
                    key for key, cache_entry in _duplicate_cache.items()
                    if (now - cache_entry["timestamp"]).total_seconds() > expiration_window
                ]
                for key in keys_to_delete:
                    del _duplicate_cache[key]
                _last_cache_cleanup_time = now

            if event_hash in _duplicate_cache:
                last_seen = _duplicate_cache[event_hash]["timestamp"]
                delta = (now - last_seen).total_seconds()

                if delta < self.config.DUPLICATE_WINDOW_SECONDS:
                    _duplicate_cache[event_hash]["count"] += 1
                    result.mark_duplicate()
                    result.mark_filtered("Duplicate event")
                    self.stats.duplicates_removed += 1
                    return True

            # Record new event
            _duplicate_cache[event_hash] = {"timestamp": now, "count": 1}

        return False


    def _calculate_severity(
            self,
            event: dict,
            result: FilterResult,
        ) -> None:
            """
            Calculate event severity based on its properties.
            """
            if not self.config.ENABLE_SEVERITY_ENGINE:
                return

            # Extract data for analysis
            file_path = event.get("file_path", "")
            file_path_lower = file_path.lower()
            extension = event.get("extension", "")
            operation = event.get("operation", "")
            process_name = event.get("process_name", "")
            event_type = event.get("event_type", "")

            is_dangerous_ext = self.engine.rules.is_dangerous_extension(extension)

            # ================================================
            # CRITICAL
            # ================================================

            # Executable or script dropped/modified in a critical system directory
            if (
                operation in ("CREATE", "MODIFY")
                and is_dangerous_ext
                and ("system32" in file_path_lower or "syswow64" in file_path_lower)
            ):
                result.set_severity("CRITICAL")
                result.mark_suspicious()
                return

            # Modification of startup persistence locations
            # TODO: Expand this list into a helper function in filter_rules.py
            startup_folders = {
                "\\start menu\\programs\\startup",
                "\\common startup\\",
            }
            if (
                operation in ("CREATE", "MODIFY")
                and is_dangerous_ext
                and any(folder in file_path_lower for folder in startup_folders)
            ):
                result.set_severity("CRITICAL")
                result.mark_suspicious()
                return

            # Ransomware-like activity: renaming files to suspicious extensions
            # TODO: Expand this list into a helper function in filter_rules.py
            ransomware_extensions = {".locked", ".encrypted", ".kraken", ".darkside"}
            if operation == "RENAME" and extension in ransomware_extensions:
                result.set_severity("CRITICAL")
                result.mark_suspicious()
                return

            # ================================================
            # HIGH
            # ================================================

            # Executable or script created outside of standard trusted installation folders
            if (
                operation == "CREATE"
                and is_dangerous_ext
                and not self.engine.whitelist.is_trusted_folder(file_path)
            ):
                result.set_severity("HIGH")
                result.mark_suspicious()
                return

            # Suspicious extension created by a non-trusted process
            # TODO: Implement a list of suspicious (but not strictly dangerous) extensions
            suspicious_extensions = {".hta", ".pif", ".url"}
            if (
                operation == "CREATE"
                and extension in suspicious_extensions
                and not self.engine.whitelist.is_trusted_process(process_name)
            ):
                result.set_severity("HIGH")
                result.mark_suspicious()
                return

            # ================================================
            # MEDIUM
            # ================================================

            # Renaming or deleting any executable file
            if operation in ("RENAME", "DELETE") and is_dangerous_ext:
                result.set_severity("MEDIUM")
                return

            # Modification of important user files (e.g., in Documents)
            if (
                operation == "MODIFY"
                and not is_dangerous_ext
                and "\\documents\\" in file_path_lower
            ):
                result.set_severity("MEDIUM")
                return

            # ================================================
            # INFO
            # ================================================

            result.set_severity("INFO")

    def _calculate_confidence(
            self,
            event: dict,
            result: FilterResult,
        ) -> None:
            """
            Calculate AI confidence score based on event properties.
            """
            if not self.config.ENABLE_CONFIDENCE_ENGINE:
                return

            # Handle terminal states with 100% confidence
            if result.duplicate or result.whitelisted or not result.accepted:
                result.set_confidence(100.0)
                return

            # Set base confidence from severity
            severity_map = {
                "CRITICAL": 90.0,
                "HIGH": 80.0,
                "MEDIUM": 65.0,
                "INFO": 50.0,
            }
            score = severity_map.get(result.severity, 50.0)

            # Extract data for analysis
            process_name = event.get("process_name", "")
            file_path = event.get("file_path", "")
            extension = event.get("extension", "")
            operation = event.get("operation", "")

            # ================================================
            # Decrease confidence for trusted indicators
            # ================================================
            if self.engine.whitelist.is_trusted_process(process_name):
                score -= 15
            if self.engine.whitelist.is_trusted_folder(file_path):
                score -= 10
            if self.engine.whitelist.is_trusted_extension(extension):
                score -= 5

            # ================================================
            # Increase confidence for suspicious indicators
            # ================================================
            if result.suspicious:
                score += 10

            is_dangerous_ext = self.engine.rules.is_dangerous_extension(extension)
            if is_dangerous_ext:
                score += 5

            # TODO: Implement is_unsigned_executable helper
            # if is_unsigned_executable(file_path):
            #     score += 5

            if operation in ("CREATE", "MODIFY", "DELETE"):
                score += 5

            # Multiple indicators agreeing strongly increases confidence
            if is_dangerous_ext and operation == "CREATE" and not self.engine.whitelist.is_trusted_folder(file_path):
                score += 15

            # ================================================
            # Clamp result and assign
            # ================================================
            final_score = max(0.0, min(score, 100.0))
            result.set_confidence(final_score)

    def _update_statistics(
            self,
            result: FilterResult,
        ) -> None:
            """
            Update file-specific and global statistics.
            """
            if not self.config.ENABLE_STATISTICS:
                return

            if result.filtered:
                self.stats.files_filtered += 1
                # An "ignored" event is one filtered by an ignore rule, not by
                # validation, the whitelist, or duplicate detection.
                if not result.duplicate and not result.whitelisted and result.reason not in ("Invalid event object", "Missing required field", "Empty required field"):
                    self.stats.ignored_events += 1
                    self.engine.rules.record_ignored_event()
            else:
                self.stats.files_stored += 1

# ============================================================
# GLOBAL ENGINE
# ============================================================

FILTER_ENGINE = FilterEngine()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("Filter Engine Initialized")
    print("=" * 60)

    print()

    print("Correlation ID Example")
    print(generate_correlation_id())

    print()

    print("Statistics")
    print(FILTER_ENGINE.statistics)