"""
Import and smoke-test suite for the ``correlation_engine`` package.

This module verifies, for each of the six correlation_engine submodules,
that:

1. The module imports successfully.
2. Its expected public engine class is exposed.
3. The engine can be instantiated with default configuration.
4. Its primary public API can be invoked with minimal, realistic
   telemetry events without raising, and returns a non-None result.

The tests validate only observable public behavior (return types and
the absence of exceptions) and make no assumptions about internal
implementation details.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Module import tests
# ---------------------------------------------------------------------------


def test_import_event_relationship_module() -> None:
    """The event_relationship module must import without error."""
    import correlation_engine.event_relationship as module

    assert module is not None


def test_import_session_grouping_module() -> None:
    """The session_grouping module must import without error."""
    import correlation_engine.session_grouping as module

    assert module is not None


def test_import_attack_chain_module() -> None:
    """The attack_chain module must import without error."""
    import correlation_engine.attack_chain as module

    assert module is not None


def test_import_temporal_correlation_module() -> None:
    """The temporal_correlation module must import without error."""
    import correlation_engine.temporal_correlation as module

    assert module is not None


def test_import_context_correlation_module() -> None:
    """The context_correlation module must import without error."""
    import correlation_engine.context_correlation as module

    assert module is not None


def test_import_cross_source_correlation_module() -> None:
    """The cross_source_correlation module must import without error."""
    import correlation_engine.cross_source_correlation as module

    assert module is not None


# ---------------------------------------------------------------------------
# Public class availability tests
# ---------------------------------------------------------------------------


def test_event_relationship_engine_class_available() -> None:
    """EventRelationshipEngine must be exposed by event_relationship."""
    import correlation_engine.event_relationship as module

    assert hasattr(module, "EventRelationshipEngine"), (
        "correlation_engine.event_relationship is missing the expected "
        "public class 'EventRelationshipEngine'."
    )


def test_session_grouping_engine_class_available() -> None:
    """SessionGroupingEngine must be exposed by session_grouping."""
    import correlation_engine.session_grouping as module

    assert hasattr(module, "SessionGroupingEngine"), (
        "correlation_engine.session_grouping is missing the expected "
        "public class 'SessionGroupingEngine'."
    )


def test_attack_chain_correlator_class_available() -> None:
    """AttackChainCorrelator must be exposed by attack_chain."""
    import correlation_engine.attack_chain as module

    assert hasattr(module, "AttackChainCorrelator"), (
        "correlation_engine.attack_chain is missing the expected "
        "public class 'AttackChainCorrelator'."
    )


def test_temporal_correlation_engine_class_available() -> None:
    """TemporalCorrelationEngine must be exposed by temporal_correlation."""
    import correlation_engine.temporal_correlation as module

    assert hasattr(module, "TemporalCorrelationEngine"), (
        "correlation_engine.temporal_correlation is missing the expected "
        "public class 'TemporalCorrelationEngine'."
    )


def test_context_correlation_engine_class_available() -> None:
    """ContextCorrelationEngine must be exposed by context_correlation."""
    import correlation_engine.context_correlation as module

    assert hasattr(module, "ContextCorrelationEngine"), (
        "correlation_engine.context_correlation is missing the expected "
        "public class 'ContextCorrelationEngine'."
    )


def test_cross_source_correlation_engine_class_available() -> None:
    """CrossSourceCorrelationEngine must be exposed by cross_source_correlation."""
    import correlation_engine.cross_source_correlation as module

    assert hasattr(module, "CrossSourceCorrelationEngine"), (
        "correlation_engine.cross_source_correlation is missing the "
        "expected public class 'CrossSourceCorrelationEngine'."
    )


# ---------------------------------------------------------------------------
# Sample event helpers
# ---------------------------------------------------------------------------


def _make_process_event(
    *,
    event_id: str,
    pid: int,
    parent_pid: int | None = None,
    process_name: str = "explorer.exe",
    user: str = "alice",
    host: str = "workstation-01",
    command_line: str = "explorer.exe /startup",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Builds a minimal, realistic process telemetry event."""
    return {
        "event_id": event_id,
        "collector": "process",
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "pid": pid,
        "parent_pid": parent_pid,
        "process_name": process_name,
        "user": user,
        "host": host,
        "command_line": command_line,
    }


def _make_file_event(
    *,
    event_id: str,
    pid: int,
    file_path: str = r"C:\Users\alice\Downloads\payload.exe",
    user: str = "alice",
    host: str = "workstation-01",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Builds a minimal, realistic file telemetry event."""
    return {
        "event_id": event_id,
        "collector": "file",
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "pid": pid,
        "file_path": file_path,
        "user": user,
        "host": host,
    }


def _make_network_event(
    *,
    event_id: str,
    pid: int,
    destination_ip: str = "203.0.113.10",
    user: str = "alice",
    host: str = "workstation-01",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Builds a minimal, realistic network telemetry event."""
    return {
        "event_id": event_id,
        "collector": "network",
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "pid": pid,
        "destination_ip": destination_ip,
        "user": user,
        "host": host,
    }


def _make_registry_event(
    *,
    event_id: str,
    pid: int,
    registry_path: str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    user: str = "alice",
    host: str = "workstation-01",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Builds a minimal, realistic registry telemetry event."""
    return {
        "event_id": event_id,
        "collector": "registry",
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "pid": pid,
        "registry_path": registry_path,
        "user": user,
        "host": host,
    }


def _new_id(prefix: str) -> str:
    """Generates a unique, deterministic-looking event id for a test."""
    return f"{prefix}-{uuid.uuid4()}"


# ---------------------------------------------------------------------------
# Engine instantiation tests
# ---------------------------------------------------------------------------


def test_event_relationship_engine_instantiates() -> None:
    """EventRelationshipEngine must be constructible with defaults."""
    from correlation_engine.event_relationship import EventRelationshipEngine

    engine = EventRelationshipEngine()

    assert engine is not None


def test_session_grouping_engine_instantiates() -> None:
    """SessionGroupingEngine must be constructible with defaults."""
    from correlation_engine.session_grouping import SessionGroupingEngine

    engine = SessionGroupingEngine()

    assert engine is not None


def test_attack_chain_correlator_instantiates() -> None:
    """AttackChainCorrelator must be constructible with defaults."""
    from correlation_engine.attack_chain import AttackChainCorrelator

    correlator = AttackChainCorrelator()

    assert correlator is not None


def test_temporal_correlation_engine_instantiates() -> None:
    """TemporalCorrelationEngine must be constructible with defaults."""
    from correlation_engine.temporal_correlation import TemporalCorrelationEngine

    engine = TemporalCorrelationEngine()

    assert engine is not None


def test_context_correlation_engine_instantiates() -> None:
    """ContextCorrelationEngine must be constructible with defaults."""
    from correlation_engine.context_correlation import ContextCorrelationEngine

    engine = ContextCorrelationEngine()

    assert engine is not None


def test_cross_source_correlation_engine_instantiates() -> None:
    """CrossSourceCorrelationEngine must be constructible with defaults."""
    from correlation_engine.cross_source_correlation import (
        CrossSourceCorrelationEngine,
    )

    engine = CrossSourceCorrelationEngine()

    assert engine is not None


# ---------------------------------------------------------------------------
# Relationship smoke test
# ---------------------------------------------------------------------------


def test_event_relationship_engine_finds_parent_child_relationship() -> None:
    """Two process events with matching parent/child PIDs must yield a
    relationship result object."""
    from correlation_engine.event_relationship import (
        EventRelationshipEngine,
        RelationshipResult,
    )

    engine = EventRelationshipEngine()
    parent = _make_process_event(
        event_id=_new_id("proc-parent"), pid=1000, parent_pid=None
    )
    child = _make_process_event(
        event_id=_new_id("proc-child"), pid=1001, parent_pid=1000
    )

    results = engine.find_all_relationships([parent, child])

    assert results is not None
    assert len(results) >= 1
    assert all(isinstance(result, RelationshipResult) for result in results)


# ---------------------------------------------------------------------------
# Session smoke test
# ---------------------------------------------------------------------------


def test_session_grouping_engine_processes_event() -> None:
    """Processing a single process event must return a session result
    object."""
    from correlation_engine.session_grouping import (
        SessionGroupingEngine,
        SessionResult,
    )

    engine = SessionGroupingEngine()
    event = _make_process_event(event_id=_new_id("proc"), pid=2000)

    result = engine.process_event(event)

    assert result is not None
    assert isinstance(result, SessionResult)


# ---------------------------------------------------------------------------
# Attack chain smoke test
# ---------------------------------------------------------------------------


def test_attack_chain_correlator_reconstructs_chain_from_events() -> None:
    """A small ordered list of related events must produce an attack-chain
    result object without raising."""
    from correlation_engine.attack_chain import (
        AttackChainCorrelator,
        AttackChainResult,
    )
    from correlation_engine.event_relationship import EventRelationshipEngine

    base_time = datetime.now(timezone.utc)
    parent = _make_process_event(
        event_id=_new_id("proc-parent"),
        pid=3000,
        parent_pid=None,
        timestamp=base_time,
    )
    child = _make_process_event(
        event_id=_new_id("proc-child"),
        pid=3001,
        parent_pid=3000,
        timestamp=base_time + timedelta(seconds=1),
    )
    dropped_file = _make_file_event(
        event_id=_new_id("file"),
        pid=3001,
        timestamp=base_time + timedelta(seconds=2),
    )
    events = [parent, child, dropped_file]

    relationship_engine = EventRelationshipEngine()
    relationships = relationship_engine.find_all_relationships(events)

    correlator = AttackChainCorrelator()
    result = correlator.correlate(relationships, events=events)

    assert result is not None
    assert isinstance(result, AttackChainResult)


# ---------------------------------------------------------------------------
# Temporal smoke test
# ---------------------------------------------------------------------------


def test_temporal_correlation_engine_correlates_close_timestamps() -> None:
    """Two events with close timestamps must produce a temporal result
    object."""
    from correlation_engine.temporal_correlation import (
        TemporalCorrelationEngine,
        TemporalResult,
    )

    base_time = datetime.now(timezone.utc)
    first = _make_process_event(
        event_id=_new_id("proc-a"), pid=4000, timestamp=base_time
    )
    second = _make_process_event(
        event_id=_new_id("proc-b"),
        pid=4001,
        timestamp=base_time + timedelta(seconds=2),
    )

    engine = TemporalCorrelationEngine()
    engine.build_index([first, second])
    result = engine.correlate(second)

    assert result is not None
    assert isinstance(result, TemporalResult)


# ---------------------------------------------------------------------------
# Context smoke test
# ---------------------------------------------------------------------------


def test_context_correlation_engine_correlates_shared_pid() -> None:
    """Two events sharing a PID must produce at least one context result
    object."""
    from correlation_engine.context_correlation import (
        ContextCorrelationEngine,
        ContextResult,
    )

    process_event = _make_process_event(event_id=_new_id("proc"), pid=5000)
    file_event = _make_file_event(event_id=_new_id("file"), pid=5000)

    engine = ContextCorrelationEngine()
    engine.build_index([process_event])
    results = engine.correlate(file_event)

    assert results is not None
    assert len(results) >= 1
    assert all(isinstance(result, ContextResult) for result in results)


# ---------------------------------------------------------------------------
# Cross-source smoke test
# ---------------------------------------------------------------------------


def test_cross_source_correlation_engine_builds_incident_from_process_and_file() -> None:
    """A process event and a file event sharing a PID must produce an
    incident/correlation result object."""
    from correlation_engine.context_correlation import ContextCorrelationEngine
    from correlation_engine.cross_source_correlation import (
        CrossSourceCorrelationEngine,
        IncidentResult,
    )

    process_event = _make_process_event(event_id=_new_id("proc"), pid=6000)
    file_event = _make_file_event(event_id=_new_id("file"), pid=6000)
    events = [process_event, file_event]

    context_engine = ContextCorrelationEngine()
    context_results = context_engine.correlate_all(events)

    cross_source_engine = CrossSourceCorrelationEngine(
        config=None
    )
    result = cross_source_engine.correlate(
        context_results=context_results,
        relationship_results=[],
        events=events,
    )

    assert result is not None
    assert isinstance(result, IncidentResult)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))