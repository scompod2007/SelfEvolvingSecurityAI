"""
============================================================
Self-Evolving Security AI
Part 2.10.4 - Attack Chain Correlator
============================================================

This module reconstructs multi-stage attack chains from previously
discovered event relationships. It performs sequential event
linking, kill-chain stage classification, and attack path/graph
reconstruction for persistence, lateral movement, privilege
escalation, and payload execution chains.

It is completely independent from confidence scoring, risk
scoring, and severity calculation. It consumes RelationshipResult
objects produced by the Event Relationship Engine (Part 2.10.2)
rather than duplicating relationship discovery.
"""

import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from correlation_engine.event_relationship import RelationshipResult, RelationshipType

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
DETERMINISTIC_ID_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "self-evolving-security-ai.attack-chain"
)

MIN_STAGE_CONFIDENCE: float = 0.0
MIN_CHAIN_LENGTH: int = 2


# ============================================================
# ENUMS
# ============================================================
class AttackStageType(Enum):
    """Enumerates the recognized kill-chain stage categories."""
    PAYLOAD_EXECUTION = "payload_execution"
    PROCESS_ANCESTRY = "process_ancestry"
    REGISTRY_PERSISTENCE = "registry_persistence"
    NETWORK_BEACONING = "network_beaconing"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXECUTION_CHAIN = "execution_chain"
    UNKNOWN = "unknown"


# ============================================================
# CONFIGURATION DATACLASS
# ============================================================
@dataclass(slots=True)
class AttackChainConfig:
    """
    Configuration controlling attack chain reconstruction.

    Attributes:
        min_chain_length (int): Minimum number of stages required for a
            sequence of relationships to be reported as an attack chain.
        min_stage_confidence (float): Minimum relationship confidence for a
            relationship to be considered as a candidate chain link.
        max_chain_depth (int): Maximum number of stages to follow when
            walking a chain of relationships.
        network_ports_of_interest (frozenset[int]): Remote ports treated as
            indicative of beaconing/C2 activity when present in metadata.
    """
    min_chain_length: int = MIN_CHAIN_LENGTH
    min_stage_confidence: float = 0.5
    max_chain_depth: int = 50
    network_ports_of_interest: frozenset[int] = field(
        default_factory=lambda: frozenset({4444, 8080, 8443, 6667, 1337})
    )


# ============================================================
# STAGE DATACLASS
# ============================================================
@dataclass(slots=True)
class AttackStage:
    """
    Represents a single stage within a reconstructed attack chain.

    Attributes:
        stage_id (str): Deterministic UUID identifying this stage.
        stage_type (AttackStageType): The kill-chain category of this stage.
        event_id (str): The event identifier this stage represents.
        relationship_id (str | None): The relationship that linked this
            stage to the previous stage, if any.
        confidence (float): Confidence that this stage is a genuine part of
            the attack chain.
        reasons (list[str]): Human-readable explanations for this stage's
            classification.
        metadata (dict[str, Any]): Additional structured context.
        timestamp (datetime): UTC timestamp of stage construction.
    """
    stage_id: str
    stage_type: AttackStageType
    event_id: str
    relationship_id: str | None
    confidence: float
    reasons: list[str]
    metadata: dict[str, Any]
    timestamp: datetime


# ============================================================
# ATTACK CHAIN DATACLASS
# ============================================================
@dataclass(slots=True)
class AttackChain:
    """
    Represents a complete reconstructed attack chain.

    Attributes:
        attack_id (str): Deterministic UUID identifying this attack chain.
        stages (list[AttackStage]): The ordered stages composing this chain.
        stage_types (list[AttackStageType]): Convenience list of stage types
            in chain order.
        confidence (float): Aggregate confidence across all stages.
        start_time (datetime): Timestamp of the earliest stage.
        end_time (datetime): Timestamp of the latest stage.
        metadata (dict[str, Any]): Additional structured context.
    """
    attack_id: str
    stages: list[AttackStage]
    stage_types: list[AttackStageType]
    confidence: float
    start_time: datetime
    end_time: datetime
    metadata: dict[str, Any]


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class AttackChainResult:
    """
    Represents the outcome of attack chain reconstruction over a batch of
    relationships.

    Attributes:
        attack_chains (list[AttackChain]): All reconstructed chains meeting
            the configured minimum length and confidence thresholds.
        total_relationships_considered (int): Number of relationships
            evaluated as candidate chain links.
        total_stages (int): Total number of stages across all chains.
        reasons (list[str]): Human-readable summary explanations.
        timestamp (datetime): UTC timestamp of when reconstruction completed.
    """
    attack_chains: list[AttackChain]
    total_relationships_considered: int
    total_stages: int
    reasons: list[str]
    timestamp: datetime


# ============================================================
# ATTACK CHAIN CORRELATOR
# ============================================================
class AttackChainCorrelator:
    """
    A thread-safe correlator that reconstructs multi-stage attack chains
    from a batch of previously discovered event relationships. Builds a
    directed graph indexed by source/target event ID for O(1) traversal.
    """

    def __init__(self, config: AttackChainConfig | None = None) -> None:
        """
        Initializes the correlator with an optional configuration.

        Args:
            config (AttackChainConfig | None): Correlator configuration.
                Uses defaults when omitted.
        """
        self._config: AttackChainConfig = config or AttackChainConfig()
        self._lock = threading.RLock()

    # ------------------------------------------------------------
    # STAGE CLASSIFICATION
    # ------------------------------------------------------------
    def _classify_stage(self, relationship: RelationshipResult, event: Mapping[str, Any] | None) -> AttackStageType:
        """
        Classifies a relationship/event pair into a kill-chain stage type
        using the relationship type and, when available, event metadata.

        Args:
            relationship (RelationshipResult): The relationship linking two events.
            event (Mapping[str, Any] | None): The target event, if available.

        Returns:
            AttackStageType: The inferred kill-chain stage category.
        """
        if relationship.relationship_type == RelationshipType.PARENT_CHILD_PROCESS:
            return AttackStageType.PROCESS_ANCESTRY

        if relationship.relationship_type == RelationshipType.REGISTRY_TO_PROCESS:
            return AttackStageType.REGISTRY_PERSISTENCE

        if relationship.relationship_type == RelationshipType.NETWORK_TO_PROCESS:
            if event is not None:
                remote_port = event.get("remote_port") or event.get("destination_port")
                try:
                    remote_port_int = int(remote_port) if remote_port is not None else None
                except (TypeError, ValueError):
                    remote_port_int = None
                if remote_port_int in self._config.network_ports_of_interest:
                    return AttackStageType.NETWORK_BEACONING
                remote_host = str(event.get("remote_ip") or event.get("destination_ip") or "")
                local_host = str(event.get("local_ip") or event.get("source_ip") or "")
                if remote_host and local_host and remote_host != local_host:
                    return AttackStageType.LATERAL_MOVEMENT
            return AttackStageType.NETWORK_BEACONING

        if relationship.relationship_type == RelationshipType.FILE_TO_PROCESS:
            return AttackStageType.PAYLOAD_EXECUTION

        if relationship.relationship_type in (
            RelationshipType.CORRELATION_ID_MATCH,
            RelationshipType.OPERATION_ID_MATCH,
            RelationshipType.CONNECTION_ID_MATCH,
        ):
            return AttackStageType.EXECUTION_CHAIN

        return AttackStageType.UNKNOWN

    def _detect_privilege_escalation(self, source_event: Mapping[str, Any] | None, target_event: Mapping[str, Any] | None) -> bool:
        """
        Heuristically detects privilege escalation by comparing user context
        between a source and target event.

        Args:
            source_event (Mapping[str, Any] | None): The upstream event.
            target_event (Mapping[str, Any] | None): The downstream event.

        Returns:
            bool: True if the target event appears to run with elevated
            privileges relative to the source event.
        """
        if not source_event or not target_event:
            return False

        source_user = str(source_event.get("user") or source_event.get("username") or "").strip().lower()
        target_user = str(target_event.get("user") or target_event.get("username") or "").strip().lower()
        elevated_markers = {"system", "root", "administrator", "trustedinstaller"}

        if not source_user or not target_user or source_user == target_user:
            return False

        return target_user in elevated_markers and source_user not in elevated_markers

    def _make_stage_id(self, event_id: str, relationship_id: str | None) -> str:
        key = f"{event_id}:{relationship_id or ''}"
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, key))

    def _make_attack_id(self, stage_ids: Sequence[str]) -> str:
        key = ":".join(stage_ids)
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, key))

    # ------------------------------------------------------------
    # GRAPH CONSTRUCTION AND TRAVERSAL
    # ------------------------------------------------------------
    def _build_graph(self, relationships: Sequence[RelationshipResult]) -> dict[str, list[RelationshipResult]]:
        """
        Builds a directed adjacency index (source_event_id -> outgoing
        relationships) for O(1) chain traversal.

        Args:
            relationships (Sequence[RelationshipResult]): The relationships
                to index.

        Returns:
            dict[str, list[RelationshipResult]]: The adjacency index.
        """
        graph: dict[str, list[RelationshipResult]] = {}
        for relationship in relationships:
            if relationship.confidence < self._config.min_stage_confidence:
                continue
            graph.setdefault(relationship.source_event_id, []).append(relationship)
        return graph

    def _walk_chain(
        self,
        start_event_id: str,
        graph: Mapping[str, list[RelationshipResult]],
        events_by_id: Mapping[str, Mapping[str, Any]],
        visited_edges: set[tuple[str, str]]
    ) -> list[AttackStage]:
        """
        Walks a single chain of relationships starting from an event,
        following the highest-confidence outgoing edge at each step, and
        classifying each visited event into a kill-chain stage.

        Args:
            start_event_id (str): The event to begin walking from.
            graph (Mapping[str, list[RelationshipResult]]): The relationship
                adjacency index.
            events_by_id (Mapping[str, Mapping[str, Any]]): Lookup of raw
                events by event ID, for stage classification context.
            visited_edges (set[tuple[str, str]]): Edges already consumed by
                a previous chain, to avoid duplicate/overlapping chains.

        Returns:
            list[AttackStage]: The ordered stages discovered in this walk.
        """
        stages: list[AttackStage] = []
        current_event_id = start_event_id
        depth = 0

        while depth < self._config.max_chain_depth:
            outgoing = sorted(graph.get(current_event_id, []), key=lambda r: r.confidence, reverse=True)
            next_edge: RelationshipResult | None = None
            for edge in outgoing:
                edge_key = (edge.source_event_id, edge.target_event_id)
                if edge_key not in visited_edges:
                    next_edge = edge
                    break

            if next_edge is None:
                break

            visited_edges.add((next_edge.source_event_id, next_edge.target_event_id))

            source_event = events_by_id.get(next_edge.source_event_id)
            target_event = events_by_id.get(next_edge.target_event_id)

            stage_type = self._classify_stage(next_edge, target_event)
            if self._detect_privilege_escalation(source_event, target_event):
                stage_type = AttackStageType.PRIVILEGE_ESCALATION

            stage_confidence = next_edge.confidence
            reasons = [f"Linked via {next_edge.relationship_type.value} relationship (confidence {next_edge.confidence})."]

            stages.append(AttackStage(
                stage_id=self._make_stage_id(next_edge.target_event_id, next_edge.relationship_id),
                stage_type=stage_type,
                event_id=next_edge.target_event_id,
                relationship_id=next_edge.relationship_id,
                confidence=round(stage_confidence, 4),
                reasons=reasons,
                metadata=dict(next_edge.metadata),
                timestamp=datetime.now(timezone.utc)
            ))

            current_event_id = next_edge.target_event_id
            depth += 1

        return stages

    # ------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------
    def correlate(
        self,
        relationships: Sequence[RelationshipResult],
        events: Sequence[Mapping[str, Any]] | None = None
    ) -> AttackChainResult:
        """
        Reconstructs multi-stage attack chains from a batch of previously
        discovered event relationships.

        Args:
            relationships (Sequence[RelationshipResult]): Relationships
                produced by EventRelationshipEngine.
            events (Sequence[Mapping[str, Any]] | None): The original raw
                events, used to enrich stage classification (e.g. network
                ports, user context). Optional; classification degrades
                gracefully without it.

        Returns:
            AttackChainResult: All reconstructed attack chains meeting the
            configured minimum length and confidence thresholds.
        """
        if not isinstance(relationships, Sequence):
            logger.warning("correlate received a non-sequence relationships input; returning an empty result.")
            return AttackChainResult(
                attack_chains=[],
                total_relationships_considered=0,
                total_stages=0,
                reasons=["Invalid relationships input; expected a sequence."],
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

                graph = self._build_graph(relationships)

                all_source_ids = {r.source_event_id for r in relationships}
                all_target_ids = {r.target_event_id for r in relationships}
                root_event_ids = [eid for eid in all_source_ids if eid not in all_target_ids] or list(all_source_ids)

                visited_edges: set[tuple[str, str]] = set()
                chains: list[AttackChain] = []

                for root_event_id in root_event_ids:
                    stages = self._walk_chain(root_event_id, graph, events_by_id, visited_edges)
                    if len(stages) + 1 < self._config.min_chain_length:
                        continue

                    root_stage = AttackStage(
                        stage_id=self._make_stage_id(root_event_id, None),
                        stage_type=AttackStageType.EXECUTION_CHAIN,
                        event_id=root_event_id,
                        relationship_id=None,
                        confidence=1.0,
                        reasons=["Root event of the reconstructed attack chain."],
                        metadata={},
                        timestamp=datetime.now(timezone.utc)
                    )
                    full_stages = [root_stage] + stages

                    stage_ids = [s.stage_id for s in full_stages]
                    aggregate_confidence = round(sum(s.confidence for s in full_stages) / len(full_stages), 4)

                    chains.append(AttackChain(
                        attack_id=self._make_attack_id(stage_ids),
                        stages=full_stages,
                        stage_types=[s.stage_type for s in full_stages],
                        confidence=aggregate_confidence,
                        start_time=min(s.timestamp for s in full_stages),
                        end_time=max(s.timestamp for s in full_stages),
                        metadata={"stage_count": len(full_stages)}
                    ))

                total_stages = sum(len(c.stages) for c in chains)
                reasons = [f"Reconstructed {len(chains)} attack chain(s) from {len(relationships)} relationship(s)."]

                return AttackChainResult(
                    attack_chains=chains,
                    total_relationships_considered=len(relationships),
                    total_stages=total_stages,
                    reasons=reasons,
                    timestamp=datetime.now(timezone.utc)
                )

        except Exception as e:
            logger.exception("Unexpected error in AttackChainCorrelator.correlate: %s", e)
            return AttackChainResult(
                attack_chains=[],
                total_relationships_considered=0,
                total_stages=0,
                reasons=["Correlator encountered an unexpected error and returned a default empty result."],
                timestamp=datetime.now(timezone.utc)
            )
