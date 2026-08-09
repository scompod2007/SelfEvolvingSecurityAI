"""
============================================================
Self-Evolving Security AI
Part 2.10.7 - Cross-Source Correlation Engine
============================================================

This module aggregates multi-source evidence (process, file,
network, registry) into constructed Incidents. It builds an
evidence graph, an incident timeline, and a human-readable
incident summary from previously discovered context and
relationship correlations.

It is completely independent from confidence scoring, risk
scoring, and severity calculation. It consumes ContextResult
and RelationshipResult objects produced by Parts 2.10.2 and
2.10.6 rather than duplicating correlation discovery.
"""

import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from correlation_engine.context_correlation import ContextResult
from correlation_engine.event_relationship import RelationshipResult

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
DETERMINISTIC_ID_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "self-evolving-security-ai.cross-source-correlation"
)

SOURCE_PAIR_LABELS: dict[frozenset[str], str] = {
    frozenset({"process", "file"}): "Process + File",
    frozenset({"process", "registry"}): "Process + Registry",
    frozenset({"process", "network"}): "Process + Network",
    frozenset({"file", "network"}): "File + Network",
    frozenset({"registry", "network"}): "Registry + Network",
    frozenset({"registry", "file"}): "Registry + File",
}


# ============================================================
# CONFIGURATION DATACLASS
# ============================================================
@dataclass(slots=True)
class CrossSourceConfig:
    """
    Configuration controlling cross-source incident construction.

    Attributes:
        min_sources (int): Minimum number of distinct collector sources
            required for a group of correlated events to be constructed
            into an Incident.
        min_evidence_confidence (float): Minimum confidence for a piece of
            evidence (context or relationship result) to be included.
        min_incident_confidence (float): Minimum aggregate confidence for an
            Incident to be reported.
    """
    min_sources: int = 2
    min_evidence_confidence: float = 0.0
    min_incident_confidence: float = 0.0


# ============================================================
# INCIDENT DATACLASS
# ============================================================
@dataclass(slots=True)
class Incident:
    """
    Represents a constructed multi-source incident.

    Attributes:
        incident_id (str): Deterministic UUID identifying this incident.
        event_ids (list[str]): All event identifiers included as evidence.
        sources (list[str]): Distinct collector sources represented.
        source_pair_label (str): Human-readable label for the source
            combination (e.g. "Process + Network").
        evidence_graph (dict[str, list[str]]): Adjacency mapping of event ID
            to the event IDs it is directly connected to via evidence.
        timeline (list[tuple[str, str]]): Chronologically ordered
            (event_id, description) entries.
        summary (str): A human-readable one-line incident summary.
        confidence (float): Aggregate incident confidence, in [0.0, 1.0].
        metadata (dict[str, Any]): Additional structured context.
        timestamp (datetime): UTC timestamp of incident construction.
    """
    incident_id: str
    event_ids: list[str]
    sources: list[str]
    source_pair_label: str
    evidence_graph: dict[str, list[str]]
    timeline: list[tuple[str, str]]
    summary: str
    confidence: float
    metadata: dict[str, Any]
    timestamp: datetime


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class IncidentResult:
    """
    Represents the outcome of cross-source correlation over a batch of
    evidence.

    Attributes:
        incidents (list[Incident]): All constructed incidents meeting the
            configured minimum source and confidence thresholds.
        total_evidence_considered (int): Number of evidence items (context
            and relationship results combined) evaluated.
        reasons (list[str]): Human-readable summary explanations.
        timestamp (datetime): UTC timestamp of when correlation completed.
    """
    incidents: list[Incident]
    total_evidence_considered: int
    reasons: list[str]
    timestamp: datetime


# ============================================================
# UNION-FIND HELPER (INTERNAL)
# ============================================================
class _UnionFind:
    """A minimal union-find structure used to group connected evidence."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self._parent.setdefault(item, item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_a] = root_b


# ============================================================
# CROSS-SOURCE CORRELATION ENGINE
# ============================================================
class CrossSourceCorrelationEngine:
    """
    A thread-safe engine that aggregates multi-source evidence into
    constructed Incidents. Uses a union-find structure to group connected
    evidence in near O(n alpha(n)) time, avoiding pairwise comparisons even
    across 100,000+ events.
    """

    def __init__(self, config: CrossSourceConfig | None = None) -> None:
        """
        Initializes the engine with an optional configuration.

        Args:
            config (CrossSourceConfig | None): Engine configuration. Uses
                defaults when omitted.
        """
        self._config: CrossSourceConfig = config or CrossSourceConfig()
        self._lock = threading.RLock()

    # ------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------
    def _normalize_str(self, value: Any) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip().lower()
        return cleaned if cleaned else None

    def _extract_source(self, event: Mapping[str, Any]) -> str:
        return self._normalize_str(event.get("collector") or event.get("source")) or "unknown"

    def _make_incident_id(self, event_ids: Sequence[str]) -> str:
        key = ":".join(sorted(event_ids))
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, key))

    def _source_pair_label(self, sources: set[str]) -> str:
        for pair, label in SOURCE_PAIR_LABELS.items():
            if pair.issubset(sources):
                return label
        return " + ".join(sorted(s.title() for s in sources)) if sources else "Unknown"

    # ------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------
    def correlate(
        self,
        context_results: Sequence[ContextResult] | None = None,
        relationship_results: Sequence[RelationshipResult] | None = None,
        events: Sequence[Mapping[str, Any]] | None = None
    ) -> IncidentResult:
        """
        Constructs multi-source incidents by grouping connected evidence
        (context correlations and event relationships) and aggregating
        their evidence into a single Incident per connected component.

        Args:
            context_results (Sequence[ContextResult] | None): Context
                correlation evidence from Part 2.10.6.
            relationship_results (Sequence[RelationshipResult] | None):
                Relationship evidence from Part 2.10.2.
            events (Sequence[Mapping[str, Any]] | None): The original raw
                events, used to determine collector source per event for
                source-pair labeling. Optional; defaults to "unknown".

        Returns:
            IncidentResult: All constructed incidents meeting the configured
            minimum source and confidence thresholds.
        """
        context_results = context_results or []
        relationship_results = relationship_results or []

        if not isinstance(context_results, Sequence) or not isinstance(relationship_results, Sequence):
            logger.warning("correlate received non-sequence evidence input; returning an empty result.")
            return IncidentResult(
                incidents=[],
                total_evidence_considered=0,
                reasons=["Invalid evidence input; expected sequences."],
                timestamp=datetime.now(timezone.utc)
            )

        try:
            with self._lock:
                events_by_id: dict[str, Mapping[str, Any]] = {}
                if events:
                    for raw_event in events:
                        if not isinstance(raw_event, Mapping):
                            continue
                        for key in ("event_id", "id", "uuid"):
                            eid = raw_event.get(key)
                            if eid:
                                events_by_id[str(eid).strip().lower()] = raw_event
                                break

                union_find = _UnionFind()
                edge_confidence: dict[tuple[str, str], float] = {}
                edge_labels: dict[tuple[str, str], str] = {}
                timeline_events: dict[str, list[str]] = {}

                total_evidence = 0

                for context_result in context_results:
                    if context_result.context_confidence < self._config.min_evidence_confidence:
                        continue
                    total_evidence += 1
                    union_find.union(context_result.source_event_id, context_result.target_event_id)
                    key = tuple(sorted((context_result.source_event_id, context_result.target_event_id)))
                    edge_confidence[key] = max(edge_confidence.get(key, 0.0), context_result.context_confidence)
                    edge_labels[key] = "context correlation (" + ", ".join(context_result.shared_attributes.keys()) + ")"
                    timeline_events.setdefault(context_result.target_event_id, []).append(
                        f"Correlated with {context_result.source_event_id} via {', '.join(context_result.shared_attributes.keys())}."
                    )

                for relationship_result in relationship_results:
                    if relationship_result.confidence < self._config.min_evidence_confidence:
                        continue
                    total_evidence += 1
                    union_find.union(relationship_result.source_event_id, relationship_result.target_event_id)
                    key = tuple(sorted((relationship_result.source_event_id, relationship_result.target_event_id)))
                    edge_confidence[key] = max(edge_confidence.get(key, 0.0), relationship_result.confidence)
                    edge_labels[key] = f"relationship ({relationship_result.relationship_type.value})"
                    timeline_events.setdefault(relationship_result.target_event_id, []).append(
                        f"Linked to {relationship_result.source_event_id} via {relationship_result.relationship_type.value}."
                    )

                groups: dict[str, set[str]] = {}
                for event_id in {eid for pair in edge_confidence.keys() for eid in pair}:
                    root = union_find.find(event_id)
                    groups.setdefault(root, set()).add(event_id)

                incidents: list[Incident] = []
                for group_event_ids in groups.values():
                    sources = {self._extract_source(events_by_id[eid]) for eid in group_event_ids if eid in events_by_id}
                    if not sources:
                        sources = {"unknown"}

                    if len(sources) < self._config.min_sources:
                        continue

                    evidence_graph: dict[str, list[str]] = {eid: [] for eid in group_event_ids}
                    relevant_edges = [
                        (pair, conf) for pair, conf in edge_confidence.items()
                        if pair[0] in group_event_ids and pair[1] in group_event_ids
                    ]
                    for (a, b), _ in relevant_edges:
                        evidence_graph.setdefault(a, []).append(b)
                        evidence_graph.setdefault(b, []).append(a)

                    if relevant_edges:
                        aggregate_confidence = round(sum(conf for _, conf in relevant_edges) / len(relevant_edges), 4)
                    else:
                        aggregate_confidence = 0.0

                    if aggregate_confidence < self._config.min_incident_confidence:
                        continue

                    timeline: list[tuple[str, str]] = []
                    for eid in group_event_ids:
                        for description in timeline_events.get(eid, []):
                            timeline.append((eid, description))
                    timeline.sort(key=lambda entry: entry[0])

                    source_label = self._source_pair_label(sources)
                    summary = (
                        f"Incident spanning {len(group_event_ids)} event(s) across {len(sources)} source(s) "
                        f"({source_label}), aggregate confidence {aggregate_confidence}."
                    )

                    sorted_event_ids = sorted(group_event_ids)
                    incidents.append(Incident(
                        incident_id=self._make_incident_id(sorted_event_ids),
                        event_ids=sorted_event_ids,
                        sources=sorted(sources),
                        source_pair_label=source_label,
                        evidence_graph=evidence_graph,
                        timeline=timeline,
                        summary=summary,
                        confidence=aggregate_confidence,
                        metadata={"evidence_edge_count": len(relevant_edges)},
                        timestamp=datetime.now(timezone.utc)
                    ))

                reasons = [f"Constructed {len(incidents)} incident(s) from {total_evidence} evidence item(s)."]

                return IncidentResult(
                    incidents=sorted(incidents, key=lambda i: i.confidence, reverse=True),
                    total_evidence_considered=total_evidence,
                    reasons=reasons,
                    timestamp=datetime.now(timezone.utc)
                )

        except Exception as e:
            logger.exception("Unexpected error in CrossSourceCorrelationEngine.correlate: %s", e)
            return IncidentResult(
                incidents=[],
                total_evidence_considered=0,
                reasons=["Engine encountered an unexpected error and returned a default empty result."],
                timestamp=datetime.now(timezone.utc)
            )
