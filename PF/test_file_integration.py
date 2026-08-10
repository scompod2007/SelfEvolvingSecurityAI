"""Import and smoke-test suite for the integration.file_integration module.

This module verifies that FileMonitorIntegration can be imported and
instantiated, that it correctly bridges file telemetry events to the
MasterFilterDispatcher, that it preserves correlation_id and timestamp
fields, that it never mutates caller input, that it forwards accepted
events to a registered downstream handler, that its metrics behave
correctly, and that it is safe under concurrent use.
"""

from __future__ import annotations

import importlib
import threading
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

import pytest

import uuid


def _make_unique_file_event() -> dict[str, Any]:
    """Builds a fresh, non-whitelisted file event with a unique file path.

    The underlying FileFilter maintains a process-wide duplicate-event
    cache, so tests must use distinct file paths to avoid colliding with
    events processed by other tests in this suite.
    """
    unique_name = f"test_{uuid.uuid4().hex}.dat"
    return {
        "event_type": "FILE_CREATE",
        "file_path": f"/tmp/{unique_name}",
        "file_name": unique_name,
        "extension": ".dat",
        "operation": "CREATE",
        "process_name": "custom_test_tool.exe",
        "file_size": 128,
        "timestamp": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------


def test_import_file_integration_module() -> None:
    """The integration.file_integration module must import cleanly."""
    module: ModuleType = importlib.import_module("integration.file_integration")
    assert module is not None


def test_file_monitor_integration_class_available() -> None:
    """FileMonitorIntegration must be exposed by integration.file_integration."""
    module = importlib.import_module("integration.file_integration")
    assert hasattr(module, "FileMonitorIntegration")


# ---------------------------------------------------------------------------
# Instantiation test
# ---------------------------------------------------------------------------


def test_file_monitor_integration_instantiates() -> None:
    """FileMonitorIntegration must be constructible with no arguments."""
    from integration.file_integration import FileMonitorIntegration

    instance = FileMonitorIntegration()
    assert instance is not None


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def test_process_event_smoke() -> None:
    """process_event must return a structured result dict with the
    expected keys."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    event = _make_unique_file_event()

    result = integration.process_event(event)

    assert isinstance(result, dict)
    assert "accepted" in result
    assert result["correlation_id"]
    assert isinstance(result["execution_time_ms"], (int, float))


# ---------------------------------------------------------------------------
# Correlation preservation
# ---------------------------------------------------------------------------


def test_correlation_id_preserved() -> None:
    """A caller-supplied correlation_id must be preserved unchanged."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    event = _make_unique_file_event()
    event["correlation_id"] = "CID-FIXED-000123"

    result = integration.process_event(event)

    assert result["correlation_id"] == "CID-FIXED-000123"


# ---------------------------------------------------------------------------
# Timestamp preservation
# ---------------------------------------------------------------------------


def test_timestamp_preserved_on_forwarded_event() -> None:
    """A caller-supplied timestamp must be preserved unchanged on the
    event forwarded downstream."""
    from integration.file_integration import FileMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = FileMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    fixed_timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event = _make_unique_file_event()
    event["timestamp"] = fixed_timestamp

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["timestamp"] == fixed_timestamp


# ---------------------------------------------------------------------------
# Default event type injection
# ---------------------------------------------------------------------------


def test_default_event_type_injected() -> None:
    """process_event must inject FILE_CREATE when event_type is missing."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    event = {
        "file_path": "/tmp/no_type.txt",
        "file_name": "no_type.txt",
        "process_name": "explorer.exe",
    }

    result = integration.process_event(event)

    assert result["event_type"] == "FILE_CREATE"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_process_event_none_rejected() -> None:
    """process_event(None) must return accepted=False."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    result = integration.process_event(None)  # type: ignore[arg-type]
    assert result["accepted"] is False


def test_process_event_invalid_string_rejected() -> None:
    """process_event('invalid') must return accepted=False."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    result = integration.process_event("invalid")  # type: ignore[arg-type]
    assert result["accepted"] is False


def test_process_event_invalid_int_rejected() -> None:
    """process_event(123) must return accepted=False."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    result = integration.process_event(123)  # type: ignore[arg-type]
    assert result["accepted"] is False


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------


def test_process_batch_result_count_matches_input() -> None:
    """process_batch must return one result per input event, in order,
    even when some events are malformed."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    events: list[Any] = [_make_unique_file_event(), None, "invalid", {}]

    results = integration.process_batch(events)

    assert len(results) == len(events)
    assert all(isinstance(result, dict) for result in results)


# ---------------------------------------------------------------------------
# Downstream forwarding
# ---------------------------------------------------------------------------


def test_accepted_event_forwarded_downstream() -> None:
    """An accepted event must be forwarded to the registered downstream
    handler."""
    from integration.file_integration import FileMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = FileMonitorIntegration()
    integration.set_downstream_handler(forwarded_events.append)

    event = _make_unique_file_event()
    result = integration.process_event(event)

    assert result["accepted"] is True
    assert result["forwarded"] is True
    assert len(forwarded_events) == 1


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------


def test_metrics_increase_after_processing() -> None:
    """Metrics counters must increase correctly after processing events."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()

    integration.process_event(_make_unique_file_event())
    integration.process_event(None)  # type: ignore[arg-type]

    metrics = integration.get_metrics()

    assert metrics["total_events"] == 2
    assert metrics["error_events"] == 1
    assert metrics["accepted_events"] + metrics["filtered_events"] == 1
    assert metrics["last_processed_at"] is not None


# ---------------------------------------------------------------------------
# Reset metrics test
# ---------------------------------------------------------------------------


def test_reset_metrics_zeroes_counters() -> None:
    """reset_metrics must zero all counters and clear last_processed_at."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    integration.process_event(_make_unique_file_event())

    integration.reset_metrics()
    metrics = integration.get_metrics()

    assert metrics["total_events"] == 0
    assert metrics["accepted_events"] == 0
    assert metrics["filtered_events"] == 0
    assert metrics["forwarded_events"] == 0
    assert metrics["error_events"] == 0
    assert metrics["last_processed_at"] is None


# ---------------------------------------------------------------------------
# Health check test
# ---------------------------------------------------------------------------


def test_health_check_status_healthy() -> None:
    """health_check must report status 'healthy'."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    health = integration.health_check()
    assert health["status"] == "healthy"


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------


def test_process_event_thread_safety_smoke() -> None:
    """Concurrently processing events from multiple threads must not
    raise any exceptions."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker() -> None:
        try:
            for _ in range(10):
                integration.process_event(_make_unique_file_event())
        except BaseException as exc:  # noqa: BLE001 - capture for assertion
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []


# ---------------------------------------------------------------------------
# Original event immutability
# ---------------------------------------------------------------------------


def test_original_event_not_mutated() -> None:
    """The caller's original event dictionary must be unchanged after
    processing."""
    from integration.file_integration import FileMonitorIntegration

    integration = FileMonitorIntegration()
    event = _make_unique_file_event()
    original_event = dict(event)

    integration.process_event(event)

    assert event == original_event


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
