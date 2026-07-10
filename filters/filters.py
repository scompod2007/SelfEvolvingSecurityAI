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

import hashlib
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
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

    start_time: datetime = field(default_factory=datetime.utcnow)

# ============================================================
# FILTER RESULT
# ============================================================

from dataclasses import dataclass, field
from datetime import datetime
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

    whitelisted: bool = False

    suspicious: bool = False

    # ========================================================
    # EVENT INFORMATION
    # ========================================================

    event_hash: str = ""

    event_type: str = ""

    collector: str = ""

    timestamp: datetime = field(default_factory=datetime.utcnow)

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

_last_cache_cleanup_time = datetime.utcnow()


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
        f"{datetime.utcnow():%Y%m%d}-"
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
        event.setdefault("timestamp", datetime.utcnow())

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
        Generate a consistent hash for a given event.
        """
        payload = (
            f"{event.get('event_type', '')}|"
            f"{event.get('file_path', '')}|"
            f"{event.get('process_name', '')}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _check_duplicate(
        self,
        event: dict,
        result: FilterResult,
    ) -> bool:
        """
        Check for and handle duplicate events.

        Returns
        -------
        bool
            True if the event was filtered as a duplicate,
            False otherwise.
        """
        if not self.config.ENABLE_DUPLICATE_FILTER:
            return False

        event_hash = self._generate_event_hash(event)
        result.event_hash = event_hash
        now = datetime.utcnow()

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
        event.setdefault("timestamp", datetime.utcnow())

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

            # 1. Validate that the input is a dictionary before accessing any keys.
            if not isinstance(event, dict):
                result.mark_filtered("Invalid event object")
                return result

            result.event_type = event.get("event_type", "")

            # 4. Generate a correlation ID if correlation IDs are enabled.
            if self.config.ENABLE_CORRELATION_ID:
                result.correlation_id = generate_correlation_id()

            # 5. Validate the required fields.
            required_str_fields = ("process_name", "process_path", "event_type")
            for field in required_str_fields:
                value = event.get(field)
                if value is None:
                    result.mark_filtered(f"Missing required field: {field}")
                    return result
                if isinstance(value, str) and not value.strip():
                    result.mark_filtered(f"Empty required field: {field}")
                    return result

            # Specific validation for 'pid'
            pid_value = event.get("pid")
            if pid_value is None:
                result.mark_filtered("Missing required field: pid")
                return result
            if not isinstance(pid_value, int) or pid_value < 0:
                result.mark_filtered(f"Invalid pid value: {pid_value}")
                return result
        
            # The 'timestamp' field is handled by setdefault below.

            # 6. Normalize the event.
            event["process_name"] = str(event["process_name"]).strip()
            event["process_path"] = str(event["process_path"]).strip()
            event["event_type"] = str(event["event_type"]).upper()

            # Set defaults for optional fields.
            event.setdefault("command_line", "")
            event.setdefault("parent_process", "")
            event.setdefault("parent_pid", 0)
            event.setdefault("publisher", "")
            event.setdefault("signature", "unsigned")
            event.setdefault("user", "")
            event.setdefault("integrity_level", "unknown")
        
            # 7. Add timestamp only if missing.
            event.setdefault("timestamp", datetime.utcnow())

            # 11. If validation succeeds:
            result.accepted = True
            result.filtered = False
            # result.reason defaults to "Accepted"

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
            now = datetime.utcnow()

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

        cmd_line = event.get("command_line", "").lower()
        process_path = event.get("process_path", "")
        process_name = event.get("process_name", "")
        parent_process = event.get("parent_process", "")

        # CRITICAL: System process running from a non-standard path
        if (
            self.engine.whitelist.is_trusted_process(process_name) and
            not self.engine.whitelist.is_trusted_process_path(process_path)
        ):
            result.set_severity("CRITICAL")
            result.mark_suspicious()
            return

        # HIGH: Suspicious command line arguments or running from temp folders
        suspicious_keywords = ["-enc", "powershell -w hidden", "invoke-expression"]
        if any(keyword in cmd_line for keyword in suspicious_keywords):
            result.set_severity("HIGH")
            result.mark_suspicious()
            return

        if self.engine.rules.is_ignored_path(process_path): # e.g., Temp folders
            result.set_severity("HIGH")
            result.mark_suspicious()
            return

        # MEDIUM: Unusual parent-child relationships
        if process_name == "svchost.exe" and parent_process != "services.exe":
            result.set_severity("MEDIUM")
            result.mark_suspicious()
            return

        # Default
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

        if event.get("signature", "unsigned").lower() == "unsigned":
            score -= 25.0

        if event.get("user") == "SYSTEM":
            score -= 10.0

        if result.severity == "CRITICAL":
            score = 100.0
        elif result.severity == "HIGH":
            score = min(100.0, score + 20.0)
        elif result.severity == "MEDIUM":
            score = min(100.0, score + 5.0)

        result.set_confidence(score)

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
            if not result.duplicate and not result.whitelisted:
                self.stats.ignored_events += 1
                self.engine.rules.record_ignored_event()
        else:
            self.stats.processes_stored += 1

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