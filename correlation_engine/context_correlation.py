"""
============================================================
Self-Evolving Security AI
Part 2.10.6 - Context Correlation Engine
============================================================

This module correlates events based on shared contextual
attributes: PID, user, host, IP, hash, command line, parent
process, executable, publisher, domain, registry path, and
environment. It is independent from temporal correlation and
from confidence, risk, and severity scoring.
"""

import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
DETERMINISTIC_ID_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "self-evolving-security-ai.context-correlation"
)

# Per-attribute contribution weights used to compute aggregate context
# confidence. Higher-specificity attributes (hash, pid) weigh more than
# broad attributes (host, environment).
ATTRIBUTE_WEIGHTS: dict[str, float] = {
    "pid": 0.9,
    "hash": 0.95,
    "command_line": 0.7,
    "parent_process": 0.75,
    "executable": 0.6,
    "publisher": 0.55,
    "registry_path": 0.65,
    "ip": 0.6,
    "domain": 0.6,
    "user": 0.4,
    "host": 0.3,
    "environment": 0.25,
}


# ============================================================
# CONFIGURATION DATACLASS
# ============================================================
@dataclass(slots=True)
class ContextConfig:
    """
    Configuration controlling which contextual attributes the
    ContextCorrelationEngine considers and their relative weighting.

    Attributes:
        enabled_attributes (frozenset[str]): The set of attribute names
            (keys of ATTRIBUTE_WEIGHTS) to evaluate.
        min_shared_attributes (int): Minimum number of shared attributes
            required before two events are considered contextually related.
        min_confidence (float): Minimum aggregate context confidence required
            to retain a result.
    """
    enabled_attributes: frozenset[str] = field(default_factory=lambda: frozenset(ATTRIBUTE_WEIGHTS.keys()))
    min_shared_attributes: int = 1
    min_confidence: float = 0.0


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class ContextResult:
    """
    Represents the outcome of context correlation between two events.

    Attributes:
        source_event_id (str): Identifier of the source event.
        target_event_id (str): Identifier of the target event.
        shared_attributes (dict[str, str]): Attribute name to shared value
            for every matched contextual attribute.
        context_confidence (float): Aggregate confidence, in [0.0, 1.0],
            derived from the weights of the shared attributes.
        reasons (list[str]): Human-readable explanations for the correlation.
        metadata (dict[str, Any]): Additional structured context.
        timestamp (datetime): UTC timestamp of when this result was computed.
    """
    source_event_id: str
    target_event_id: str
    shared_attributes: dict[str, str]
    context_confidence: float
    reasons: list[str]
    metadata: dict[str, Any]
    timestamp: datetime


# ============================================================
# CONTEXT CORRELATION ENGINE
# ============================================================
class ContextCorrelationEngine:
    """
    A thread-safe engine that correlates events sharing contextual
    attributes. Maintains per-attribute O(1) indexes (attribute value ->
    event IDs) to scale efficiently to 100,000+ events.
    """

    def __init__(self, config: ContextConfig | None = None) -> None:
        """
        Initializes the engine with an optional configuration.

        Args:
            config (ContextConfig | None): Engine configuration. Uses
                defaults when omitted.
        """
        self._config: ContextConfig = config or ContextConfig()
        self._lock = threading.RLock()
        self._events_by_id: dict[str, Mapping[str, Any]] = {}
        self._attribute_index: dict[str, dict[str, list[str]]] = {attr: {} for attr in ATTRIBUTE_WEIGHTS}

    # ------------------------------------------------------------
    # NORMALIZATION HELPERS
    # ------------------------------------------------------------
    def _normalize_str(self, value: Any) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(str(value).split()).lower()
        return cleaned if cleaned else None

    def _extract_event_id(self, event: Mapping[str, Any]) -> str:
        for key in ("event_id", "id", "uuid"):
            normalized = self._normalize_str(event.get(key))
            if normalized:
                return normalized
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, repr(sorted(event.items(), key=lambda kv: str(kv[0])))))

    def _extract_attribute(self, event: Mapping[str, Any], attribute: str) -> str | None:
        """
        Extracts and normalizes a single contextual attribute from an event,
        trying multiple plausible field-name aliases.

        Args:
            event (Mapping[str, Any]): The source event.
            attribute (str): The logical attribute name (e.g. 'pid', 'ip').

        Returns:
            str | None: The normalized attribute value, or None if absent.
        """
        alias_map: dict[str, tuple[str, ...]] = {
            "pid": ("pid", "process_id"),
            "hash": ("sha256", "sha1", "md5", "file_hash", "hash"),
            "command_line": ("command_line", "cmdline"),
            "parent_process": ("parent_process", "parent_process_name"),
            "executable": ("executable", "process_name", "image_name"),
            "publisher": ("publisher", "signer"),
            "registry_path": ("registry_path", "key_path"),
            "ip": ("remote_ip", "local_ip", "source_ip", "destination_ip", "ip"),
            "domain": ("destination_domain", "domain", "url"),
            "user": ("user", "username"),
            "host": ("host", "hostname"),
            "environment": ("environment", "env"),
        }
        for key in alias_map.get(attribute, (attribute,)):
            value = event.get(key)
            normalized = self._normalize_str(value)
            if normalized:
                return normalized
        return None

    # ------------------------------------------------------------
    # INDEX CONSTRUCTION
    # ------------------------------------------------------------
    def build_index(self, events: Sequence[Mapping[str, Any]]) -> None:
        """
        Builds (or rebuilds) the internal per-attribute indexes from a
        batch of events.

        Args:
            events (Sequence[Mapping[str, Any]]): The events to index.
        """
        if not isinstance(events, Sequence):
            logger.warning("build_index received a non-sequence input; no index built.")
            events = []

        events_by_id: dict[str, Mapping[str, Any]] = {}
        attribute_index: dict[str, dict[str, list[str]]] = {attr: {} for attr in ATTRIBUTE_WEIGHTS}

        for raw_event in events:
            if not isinstance(raw_event, Mapping):
                continue
            event_id = self._extract_event_id(raw_event)
            events_by_id[event_id] = raw_event

            for attribute in self._config.enabled_attributes:
                value = self._extract_attribute(raw_event, attribute)
                if value:
                    attribute_index.setdefault(attribute, {}).setdefault(value, []).append(event_id)

        with self._lock:
            self._events_by_id = events_by_id
            self._attribute_index = attribute_index

        logger.info("ContextCorrelationEngine indexed %d events.", len(events_by_id))

    # ------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------
    def correlate(self, event: Mapping[str, Any]) -> list[ContextResult]:
        """
        Finds all previously indexed events sharing contextual attributes
        with the given event.

        Args:
            event (Mapping[str, Any]): The event to correlate.

        Returns:
            list[ContextResult]: Results for every other event meeting the
            configured minimum shared-attribute count and confidence,
            sorted by descending context confidence.
        """
        if not isinstance(event, Mapping):
            logger.warning("correlate received a non-mapping event; returning no results.")
            return []

        try:
            with self._lock:
                event_id = self._extract_event_id(event)
                matches: dict[str, dict[str, str]] = {}

                for attribute in self._config.enabled_attributes:
                    value = self._extract_attribute(event, attribute)
                    if not value:
                        continue
                    for other_event_id in self._attribute_index.get(attribute, {}).get(value, []):
                        if other_event_id == event_id:
                            continue
                        matches.setdefault(other_event_id, {})[attribute] = value

                results: list[ContextResult] = []
                for other_event_id, shared_attributes in matches.items():
                    if len(shared_attributes) < self._config.min_shared_attributes:
                        continue

                    total_weight = sum(ATTRIBUTE_WEIGHTS.get(attr, 0.3) for attr in shared_attributes)
                    max_possible = sum(ATTRIBUTE_WEIGHTS.get(attr, 0.3) for attr in self._config.enabled_attributes) or 1.0
                    confidence = round(min(total_weight / max_possible, 1.0), 4)

                    if confidence < self._config.min_confidence:
                        continue

                    reasons = [f"Shared attribute '{attr}': '{value}'." for attr, value in shared_attributes.items()]

                    results.append(ContextResult(
                        source_event_id=other_event_id,
                        target_event_id=event_id,
                        shared_attributes=shared_attributes,
                        context_confidence=confidence,
                        reasons=reasons,
                        metadata={"shared_attribute_count": len(shared_attributes)},
                        timestamp=datetime.now(timezone.utc)
                    ))

                return sorted(results, key=lambda r: r.context_confidence, reverse=True)

        except Exception as e:
            logger.exception("Unexpected error in ContextCorrelationEngine.correlate: %s", e)
            return []

    def correlate_all(self, events: Sequence[Mapping[str, Any]]) -> list[ContextResult]:
        """
        Builds the internal index from the given events and returns every
        discovered contextual relationship across the batch.

        Args:
            events (Sequence[Mapping[str, Any]]): The full event batch.

        Returns:
            list[ContextResult]: All discovered contextual relationships,
            deduplicated by (source_event_id, target_event_id) pair.
        """
        self.build_index(events)
        seen: set[tuple[str, str]] = set()
        all_results: list[ContextResult] = []

        for raw_event in events:
            if not isinstance(raw_event, Mapping):
                continue
            for result in self.correlate(raw_event):
                pair = tuple(sorted((result.source_event_id, result.target_event_id)))
                if pair in seen:
                    continue
                seen.add(pair)
                all_results.append(result)

        return sorted(all_results, key=lambda r: r.context_confidence, reverse=True)
