"""
============================================================
Self-Evolving Security AI
Part 2.10.2 - Event Relationship Engine
============================================================

This module identifies relationships between telemetry events
produced by the process, file, network, and registry collectors.
It performs parent-child process correlation, file-to-process,
network-to-process, and registry-to-process correlation, as well
as multi-source association via shared correlation identifiers.

It is completely independent from confidence scoring, risk
scoring, and severity calculation.
"""

import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
DETERMINISTIC_ID_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "self-evolving-security-ai.event-relationship"
)

PARENT_CHILD_CONFIDENCE: float = 0.95
FILE_TO_PROCESS_CONFIDENCE: float = 0.85
NETWORK_TO_PROCESS_CONFIDENCE: float = 0.85
REGISTRY_TO_PROCESS_CONFIDENCE: float = 0.85
CORRELATION_ID_CONFIDENCE: float = 0.90
OPERATION_ID_CONFIDENCE: float = 0.80
CONNECTION_ID_CONFIDENCE: float = 0.80
PROCESS_NAME_HEURISTIC_CONFIDENCE: float = 0.55


# ============================================================
# ENUMS
# ============================================================
class RelationshipType(Enum):
    """Enumerates the supported types of event relationships."""
    PARENT_CHILD_PROCESS = "parent_child_process"
    FILE_TO_PROCESS = "file_to_process"
    NETWORK_TO_PROCESS = "network_to_process"
    REGISTRY_TO_PROCESS = "registry_to_process"
    CORRELATION_ID_MATCH = "correlation_id_match"
    OPERATION_ID_MATCH = "operation_id_match"
    CONNECTION_ID_MATCH = "connection_id_match"
    MULTI_SOURCE = "multi_source"
    PROCESS_NAME_HEURISTIC = "process_name_heuristic"
    UNKNOWN = "unknown"


# ============================================================
# CONFIGURATION DATACLASS
# ============================================================
@dataclass(slots=True)
class RelationshipConfig:
    """
    Configuration controlling which correlation strategies the
    EventRelationshipEngine applies and their minimum confidence.

    Attributes:
        enable_parent_child (bool): Enable PID/PPID process-tree correlation.
        enable_file_to_process (bool): Enable file event to process correlation via PID.
        enable_network_to_process (bool): Enable network event to process correlation via PID.
        enable_registry_to_process (bool): Enable registry event to process correlation via PID.
        enable_correlation_id (bool): Enable correlation via shared correlation_id.
        enable_operation_id (bool): Enable correlation via shared operation_id.
        enable_connection_id (bool): Enable correlation via shared connection_id.
        enable_process_name_heuristic (bool): Enable weak process-name based correlation.
        min_confidence (float): Minimum relationship confidence to retain a result.
        max_relationships_per_event (int): Cap on relationships returned for a single event.
    """
    enable_parent_child: bool = True
    enable_file_to_process: bool = True
    enable_network_to_process: bool = True
    enable_registry_to_process: bool = True
    enable_correlation_id: bool = True
    enable_operation_id: bool = True
    enable_connection_id: bool = True
    enable_process_name_heuristic: bool = False
    min_confidence: float = 0.0
    max_relationships_per_event: int = 50


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class RelationshipResult:
    """
    Represents a single discovered relationship between two events.

    Attributes:
        relationship_id (str): Deterministic UUID identifying this relationship.
        relationship_type (RelationshipType): The kind of relationship discovered.
        source_event_id (str): Normalized identifier of the source event.
        target_event_id (str): Normalized identifier of the target event.
        confidence (float): Confidence score in the range [0.0, 1.0].
        reasons (list[str]): Human-readable explanations for the relationship.
        metadata (dict[str, Any]): Additional structured context about the relationship.
        timestamp (datetime): UTC timestamp of when the relationship was computed.
    """
    relationship_id: str
    relationship_type: RelationshipType
    source_event_id: str
    target_event_id: str
    confidence: float
    reasons: list[str]
    metadata: dict[str, Any]
    timestamp: datetime


# ============================================================
# EVENT RELATIONSHIP ENGINE
# ============================================================
class EventRelationshipEngine:
    """
    A thread-safe engine that identifies relationships between telemetry
    events using internal O(1) indexes. Designed to scale to 100,000+
    events by indexing on PID, parent PID, correlation ID, operation ID,
    and connection ID rather than performing pairwise comparisons.
    """

    def __init__(self, config: RelationshipConfig | None = None) -> None:
        """
        Initializes the engine with an optional configuration.

        Args:
            config (RelationshipConfig | None): Engine configuration. Uses
                defaults when omitted.
        """
        self._config: RelationshipConfig = config or RelationshipConfig()
        self._lock = threading.RLock()
        self._events_by_id: dict[str, Mapping[str, Any]] = {}
        self._pid_index: dict[int, list[str]] = {}
        self._process_events_by_pid: dict[int, list[str]] = {}
        self._correlation_index: dict[str, list[str]] = {}
        self._operation_index: dict[str, list[str]] = {}
        self._connection_index: dict[str, list[str]] = {}
        self._process_name_index: dict[str, list[str]] = {}

    # ------------------------------------------------------------
    # NORMALIZATION HELPERS
    # ------------------------------------------------------------
    def _normalize_str(self, value: Any) -> str | None:
        """
        Safely normalizes an arbitrary value into a stripped, lowercase string.

        Args:
            value (Any): The raw value.

        Returns:
            str | None: The normalized string, or None if empty/invalid.
        """
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned.lower() if cleaned else None

    def _normalize_int(self, value: Any) -> int | None:
        """
        Safely normalizes an arbitrary value into an integer.

        Args:
            value (Any): The raw value.

        Returns:
            int | None: The parsed integer, or None if invalid.
        """
        if value is None or isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _extract_event_id(self, event: Mapping[str, Any]) -> str:
        """
        Extracts (or synthesizes) a stable identifier for an event.

        Args:
            event (Mapping[str, Any]): The raw event.

        Returns:
            str: A stable string identifier for the event.
        """
        for key in ("event_id", "id", "uuid"):
            raw = event.get(key) if isinstance(event, Mapping) else None
            normalized = self._normalize_str(raw)
            if normalized:
                return normalized
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, repr(sorted(event.items(), key=lambda kv: str(kv[0])))))

    def _extract_pid(self, event: Mapping[str, Any]) -> int | None:
        for key in ("pid", "process_id"):
            pid = self._normalize_int(event.get(key))
            if pid is not None:
                return pid
        return None

    def _extract_ppid(self, event: Mapping[str, Any]) -> int | None:
        for key in ("ppid", "parent_pid", "parent_process_id"):
            ppid = self._normalize_int(event.get(key))
            if ppid is not None:
                return ppid
        return None

    def _extract_process_name(self, event: Mapping[str, Any]) -> str | None:
        for key in ("process_name", "image_name", "executable"):
            name = self._normalize_str(event.get(key))
            if name:
                return name
        return None

    def _extract_correlation_id(self, event: Mapping[str, Any]) -> str | None:
        return self._normalize_str(event.get("correlation_id"))

    def _extract_operation_id(self, event: Mapping[str, Any]) -> str | None:
        return self._normalize_str(event.get("operation_id"))

    def _extract_connection_id(self, event: Mapping[str, Any]) -> str | None:
        return self._normalize_str(event.get("connection_id"))

    def _extract_collector(self, event: Mapping[str, Any]) -> str | None:
        return self._normalize_str(event.get("collector") or event.get("source"))

    # ------------------------------------------------------------
    # INDEX CONSTRUCTION
    # ------------------------------------------------------------
    def build_indexes(self, events: Sequence[Mapping[str, Any]]) -> None:
        """
        Builds (or rebuilds) the internal O(1) lookup indexes from a batch
        of events. Thread-safe: existing indexes are atomically replaced.

        Args:
            events (Sequence[Mapping[str, Any]]): The events to index.
        """
        events_by_id: dict[str, Mapping[str, Any]] = {}
        pid_index: dict[int, list[str]] = {}
        process_events_by_pid: dict[int, list[str]] = {}
        correlation_index: dict[str, list[str]] = {}
        operation_index: dict[str, list[str]] = {}
        connection_index: dict[str, list[str]] = {}
        process_name_index: dict[str, list[str]] = {}

        if not isinstance(events, Sequence):
            logger.warning("build_indexes received a non-sequence input; no indexes built.")
            events = []

        for raw_event in events:
            if not isinstance(raw_event, Mapping):
                continue

            event_id = self._extract_event_id(raw_event)
            events_by_id[event_id] = raw_event

            pid = self._extract_pid(raw_event)
            if pid is not None:
                pid_index.setdefault(pid, []).append(event_id)
                collector = self._extract_collector(raw_event)
                if collector == "process" or "process_name" in raw_event:
                    process_events_by_pid.setdefault(pid, []).append(event_id)

            correlation_id = self._extract_correlation_id(raw_event)
            if correlation_id:
                correlation_index.setdefault(correlation_id, []).append(event_id)

            operation_id = self._extract_operation_id(raw_event)
            if operation_id:
                operation_index.setdefault(operation_id, []).append(event_id)

            connection_id = self._extract_connection_id(raw_event)
            if connection_id:
                connection_index.setdefault(connection_id, []).append(event_id)

            process_name = self._extract_process_name(raw_event)
            if process_name:
                process_name_index.setdefault(process_name, []).append(event_id)

        with self._lock:
            self._events_by_id = events_by_id
            self._pid_index = pid_index
            self._process_events_by_pid = process_events_by_pid
            self._correlation_index = correlation_index
            self._operation_index = operation_index
            self._connection_index = connection_index
            self._process_name_index = process_name_index

        logger.info("EventRelationshipEngine indexed %d events.", len(events_by_id))

    # ------------------------------------------------------------
    # RELATIONSHIP ID
    # ------------------------------------------------------------
    def _make_relationship_id(self, source_event_id: str, target_event_id: str, relationship_type: RelationshipType) -> str:
        """
        Computes a deterministic UUID for a relationship so identical
        relationships discovered across runs produce the same ID.

        Args:
            source_event_id (str): The source event identifier.
            target_event_id (str): The target event identifier.
            relationship_type (RelationshipType): The relationship type.

        Returns:
            str: A deterministic UUID string.
        """
        key = f"{relationship_type.value}:{source_event_id}:{target_event_id}"
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, key))

    def _make_result(
        self,
        source_event_id: str,
        target_event_id: str,
        relationship_type: RelationshipType,
        confidence: float,
        reasons: list[str],
        metadata: dict[str, Any]
    ) -> RelationshipResult:
        return RelationshipResult(
            relationship_id=self._make_relationship_id(source_event_id, target_event_id, relationship_type),
            relationship_type=relationship_type,
            source_event_id=source_event_id,
            target_event_id=target_event_id,
            confidence=round(min(max(confidence, 0.0), 1.0), 4),
            reasons=reasons,
            metadata=metadata,
            timestamp=datetime.now(timezone.utc)
        )

    # ------------------------------------------------------------
    # RELATIONSHIP DISCOVERY
    # ------------------------------------------------------------
    def _find_parent_child(self, event: Mapping[str, Any], event_id: str) -> list[RelationshipResult]:
        results: list[RelationshipResult] = []
        if not self._config.enable_parent_child:
            return results

        ppid = self._extract_ppid(event)
        if ppid is None:
            return results

        for parent_event_id in self._process_events_by_pid.get(ppid, []):
            if parent_event_id == event_id:
                continue
            results.append(self._make_result(
                source_event_id=parent_event_id,
                target_event_id=event_id,
                relationship_type=RelationshipType.PARENT_CHILD_PROCESS,
                confidence=PARENT_CHILD_CONFIDENCE,
                reasons=[f"Process event's parent PID {ppid} matches an indexed parent process event."],
                metadata={"ppid": ppid}
            ))
        return results

    def _find_pid_based(
        self,
        event: Mapping[str, Any],
        event_id: str,
        relationship_type: RelationshipType,
        enabled: bool
    ) -> list[RelationshipResult]:
        results: list[RelationshipResult] = []
        if not enabled:
            return results

        expected_collector = {
            RelationshipType.FILE_TO_PROCESS: "file",
            RelationshipType.NETWORK_TO_PROCESS: "network",
            RelationshipType.REGISTRY_TO_PROCESS: "registry",
        }.get(relationship_type)

        if expected_collector is not None and self._extract_collector(event) != expected_collector:
            return results

        pid = self._extract_pid(event)
        if pid is None:
            return results

        confidence_map = {
            RelationshipType.FILE_TO_PROCESS: FILE_TO_PROCESS_CONFIDENCE,
            RelationshipType.NETWORK_TO_PROCESS: NETWORK_TO_PROCESS_CONFIDENCE,
            RelationshipType.REGISTRY_TO_PROCESS: REGISTRY_TO_PROCESS_CONFIDENCE,
        }

        for process_event_id in self._process_events_by_pid.get(pid, []):
            if process_event_id == event_id:
                continue
            results.append(self._make_result(
                source_event_id=process_event_id,
                target_event_id=event_id,
                relationship_type=relationship_type,
                confidence=confidence_map.get(relationship_type, 0.5),
                reasons=[f"Event's PID {pid} matches an indexed process event."],
                metadata={"pid": pid}
            ))
        return results

    def _find_shared_identifier(
        self,
        event_id: str,
        identifier: str | None,
        index: Mapping[str, list[str]],
        relationship_type: RelationshipType,
        confidence: float,
        enabled: bool,
        label: str
    ) -> list[RelationshipResult]:
        results: list[RelationshipResult] = []
        if not enabled or not identifier:
            return results

        for other_event_id in index.get(identifier, []):
            if other_event_id == event_id:
                continue
            results.append(self._make_result(
                source_event_id=other_event_id,
                target_event_id=event_id,
                relationship_type=relationship_type,
                confidence=confidence,
                reasons=[f"Events share the same {label}: '{identifier}'."],
                metadata={label: identifier}
            ))
        return results

    def _find_process_name_heuristic(self, event: Mapping[str, Any], event_id: str) -> list[RelationshipResult]:
        results: list[RelationshipResult] = []
        if not self._config.enable_process_name_heuristic:
            return results

        process_name = self._extract_process_name(event)
        if not process_name:
            return results

        for other_event_id in self._process_name_index.get(process_name, []):
            if other_event_id == event_id:
                continue
            results.append(self._make_result(
                source_event_id=other_event_id,
                target_event_id=event_id,
                relationship_type=RelationshipType.PROCESS_NAME_HEURISTIC,
                confidence=PROCESS_NAME_HEURISTIC_CONFIDENCE,
                reasons=[f"Events share the same process name '{process_name}' (weak heuristic, no shared PID)."],
                metadata={"process_name": process_name}
            ))
        return results

    def find_relationships(self, event: Mapping[str, Any]) -> list[RelationshipResult]:
        """
        Finds all relationships between the given event and previously
        indexed events, using O(1) index lookups.

        Args:
            event (Mapping[str, Any]): The event to correlate. Must have
                previously been included in a call to build_indexes for
                full cross-referencing, though correlation against the
                already-built indexes still occurs otherwise.

        Returns:
            list[RelationshipResult]: All discovered relationships, sorted
            by descending confidence and truncated to
            config.max_relationships_per_event.
        """
        if not isinstance(event, Mapping):
            logger.warning("find_relationships received a non-mapping event; returning no relationships.")
            return []

        try:
            with self._lock:
                event_id = self._extract_event_id(event)
                results: list[RelationshipResult] = []
                results.extend(self._find_parent_child(event, event_id))
                results.extend(self._find_pid_based(event, event_id, RelationshipType.FILE_TO_PROCESS, self._config.enable_file_to_process))
                results.extend(self._find_pid_based(event, event_id, RelationshipType.NETWORK_TO_PROCESS, self._config.enable_network_to_process))
                results.extend(self._find_pid_based(event, event_id, RelationshipType.REGISTRY_TO_PROCESS, self._config.enable_registry_to_process))
                results.extend(self._find_shared_identifier(
                    event_id, self._extract_correlation_id(event), self._correlation_index,
                    RelationshipType.CORRELATION_ID_MATCH, CORRELATION_ID_CONFIDENCE,
                    self._config.enable_correlation_id, "correlation_id"
                ))
                results.extend(self._find_shared_identifier(
                    event_id, self._extract_operation_id(event), self._operation_index,
                    RelationshipType.OPERATION_ID_MATCH, OPERATION_ID_CONFIDENCE,
                    self._config.enable_operation_id, "operation_id"
                ))
                results.extend(self._find_shared_identifier(
                    event_id, self._extract_connection_id(event), self._connection_index,
                    RelationshipType.CONNECTION_ID_MATCH, CONNECTION_ID_CONFIDENCE,
                    self._config.enable_connection_id, "connection_id"
                ))
                results.extend(self._find_process_name_heuristic(event, event_id))

            deduped: dict[str, RelationshipResult] = {}
            for result in results:
                if result.confidence >= self._config.min_confidence:
                    deduped[result.relationship_id] = result

            ordered = sorted(deduped.values(), key=lambda r: r.confidence, reverse=True)
            return ordered[: self._config.max_relationships_per_event]

        except Exception as e:
            logger.exception("Unexpected error in EventRelationshipEngine.find_relationships: %s", e)
            return []

    def find_all_relationships(self, events: Sequence[Mapping[str, Any]]) -> list[RelationshipResult]:
        """
        Builds indexes from the given events and returns every discovered
        relationship across the entire batch. Suitable for offline/batch
        correlation of 100,000+ events.

        Args:
            events (Sequence[Mapping[str, Any]]): The full event batch.

        Returns:
            list[RelationshipResult]: All discovered relationships across
            the batch, deduplicated by relationship_id.
        """
        self.build_indexes(events)
        all_results: dict[str, RelationshipResult] = {}

        for raw_event in events:
            if not isinstance(raw_event, Mapping):
                continue
            for result in self.find_relationships(raw_event):
                all_results[result.relationship_id] = result

        return sorted(all_results.values(), key=lambda r: r.confidence, reverse=True)
