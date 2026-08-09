# __init__.py
"""
Correlation Engine package initialization.
Exports the public APIs of Part 2.10 - Correlation Engine.
"""

from .event_relationship import (
    EventRelationshipEngine,
    RelationshipResult,
    RelationshipType,
    RelationshipConfig,
)
from .session_grouping import (
    SessionGroupingEngine,
    Session,
    SessionResult,
    SessionType,
    SessionConfig,
)
from .attack_chain import (
    AttackChainCorrelator,
    AttackChain,
    AttackStage,
    AttackChainResult,
    AttackChainConfig,
    AttackStageType,
)
from .temporal_correlation import (
    TemporalCorrelationEngine,
    TemporalResult,
    TemporalConfig,
)
from .context_correlation import (
    ContextCorrelationEngine,
    ContextResult,
    ContextConfig,
)
from .cross_source_correlation import (
    CrossSourceCorrelationEngine,
    Incident,
    IncidentResult,
    CrossSourceConfig,
)

__all__ = [
    "EventRelationshipEngine",
    "RelationshipResult",
    "RelationshipType",
    "RelationshipConfig",
    "SessionGroupingEngine",
    "Session",
    "SessionResult",
    "SessionType",
    "SessionConfig",
    "AttackChainCorrelator",
    "AttackChain",
    "AttackStage",
    "AttackChainResult",
    "AttackChainConfig",
    "AttackStageType",
    "TemporalCorrelationEngine",
    "TemporalResult",
    "TemporalConfig",
    "ContextCorrelationEngine",
    "ContextResult",
    "ContextConfig",
    "CrossSourceCorrelationEngine",
    "Incident",
    "IncidentResult",
    "CrossSourceConfig",
]
