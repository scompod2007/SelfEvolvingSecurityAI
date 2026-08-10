"""Import and smoke-test suite for the integration.process_integration module.

This module verifies that ProcessMonitorIntegration can be imported and
instantiated, that it correctly bridges process telemetry events to the
MasterFilterDispatcher, that it preserves correlation_id, timestamp,
parent PID, command line, and executable path fields, that it never
mutates caller input, that it forwards accepted events to a registered
downstream handler, that its metrics behave correctly, and that it is
safe under concurrent use.
"""

from __future__ import annotations

import importlib
import threading
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

import pytest

import itertools
import uuid

_pid_counter = itertools.count(10_000)
_pid_counter_lock = threading.Lock()


def _next_pid() -> int:
    """Returns a fresh, process-wide unique PID for use in test events."""
    with _pid_counter_lock:
        return next(_pid_counter)


def _make_unique_process_event() -> dict[str, Any]:
    """Builds a fresh, non-whitelisted process event with a unique pid.

    The underlying ProcessFilter maintains a process-wide duplicate-event
    cache, so tests must use distinct pid / command line combinations to
    avoid colliding with events processed by other tests in this suite.
    """
    pid = _next_pid()
    unique_name = f"test_{uuid.uuid4().hex}.exe"
    return {
        "event_type": "PROCESS_CREATE",
        "pid": pid,
        "ppid": pid - 1,
        "parent_pid": pid - 1,
        "parent_process_name": "custom_parent_tool.exe",
        "process_name": unique_name,
        "process_path": f"C:\\Tools\\{unique_name}",
        "executable_path": f"C:\\Tools\\{unique_name}",
        "exe": f"C:\\Tools\\{unique_name}",
        "command_line": f"{unique_name} --scan --mode=custom",
        "cmdline": [unique_name, "--scan", "--mode=custom"],
        "timestamp": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------


def test_import_process_integration_module() -> None:
    """The integration.process_integration module must import cleanly."""
    module: ModuleType = importlib.import_module("integration.process_integration")
    assert module is not None


def test_process_monitor_integration_class_available() -> None:
    """ProcessMonitorIntegration must be exposed by
    integration.process_integration."""
    module = importlib.import_module("integration.process_integration")
    assert hasattr(module, "ProcessMonitorIntegration")


# ---------------------------------------------------------------------------
# Instantiation test
# ---------------------------------------------------------------------------


def test_process_monitor_integration_instantiates() -> None:
    """ProcessMonitorIntegration must be constructible with no arguments."""
    from integration.process_integration import ProcessMonitorIntegration

    instance = ProcessMonitorIntegration()
    assert instance is not None


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def test_process_event_smoke() -> None:
    """process_event must return a structured result dict with the
    expected keys."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    event = _make_unique_process_event()

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
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    event = _make_unique_process_event()
    event["correlation_id"] = "CID-PROCESS-FIXED-000123"

    result = integration.process_event(event)

    assert result["correlation_id"] == "CID-PROCESS-FIXED-000123"


# ---------------------------------------------------------------------------
# Timestamp preservation
# ---------------------------------------------------------------------------


def test_timestamp_preserved_on_forwarded_event() -> None:
    """A caller-supplied timestamp must be preserved unchanged on the
    event forwarded downstream."""
    from integration.process_integration import ProcessMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = ProcessMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    fixed_timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event = _make_unique_process_event()
    event["timestamp"] = fixed_timestamp

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["timestamp"] == fixed_timestamp


# ---------------------------------------------------------------------------
# Parent PID preservation
# ---------------------------------------------------------------------------


def test_parent_pid_preserved_on_forwarded_event() -> None:
    """A caller-supplied ppid and parent_pid must be preserved unchanged
    on the event forwarded downstream."""
    from integration.process_integration import ProcessMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = ProcessMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_process_event()
    expected_ppid = event["ppid"]
    expected_parent_pid = event["parent_pid"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["ppid"] == expected_ppid
    assert forwarded_events[0]["parent_pid"] == expected_parent_pid


# ---------------------------------------------------------------------------
# Command line preservation
# ---------------------------------------------------------------------------


def test_command_line_preserved_on_forwarded_event() -> None:
    """A caller-supplied command_line and cmdline must be preserved
    unchanged on the event forwarded downstream."""
    from integration.process_integration import ProcessMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = ProcessMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_process_event()
    expected_command_line = event["command_line"]
    expected_cmdline = event["cmdline"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["command_line"] == expected_command_line
    assert forwarded_events[0]["cmdline"] == expected_cmdline


# ---------------------------------------------------------------------------
# Executable path preservation
# ---------------------------------------------------------------------------


def test_executable_path_preserved_on_forwarded_event() -> None:
    """A caller-supplied process_path, executable_path, and exe must be
    preserved unchanged on the event forwarded downstream."""
    from integration.process_integration import ProcessMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = ProcessMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_process_event()
    expected_process_path = event["process_path"]
    expected_executable_path = event["executable_path"]
    expected_exe = event["exe"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["process_path"] == expected_process_path
    assert forwarded_events[0]["executable_path"] == expected_executable_path
    assert forwarded_events[0]["exe"] == expected_exe


# ---------------------------------------------------------------------------
# Default event type injection
# ---------------------------------------------------------------------------


def test_default_event_type_injected() -> None:
    """process_event must inject PROCESS_CREATE when event_type is
    missing."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    pid = _next_pid()
    event = {
        "pid": pid,
        "ppid": pid - 1,
        "process_name": f"test_{uuid.uuid4().hex}.exe",
        "process_path": "C:\\Tools\\no_type.exe",
    }

    result = integration.process_event(event)

    assert result["event_type"] == "PROCESS_CREATE"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_process_event_none_rejected() -> None:
    """process_event(None) must return accepted=False."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    result = integration.process_event(None)  # type: ignore[arg-type]
    assert result["accepted"] is False


def test_process_event_invalid_string_rejected() -> None:
    """process_event('invalid') must return accepted=False."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    result = integration.process_event("invalid")  # type: ignore[arg-type]
    assert result["accepted"] is False


def test_process_event_invalid_int_rejected() -> None:
    """process_event(123) must return accepted=False."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    result = integration.process_event(123)  # type: ignore[arg-type]
    assert result["accepted"] is False


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------


def test_process_batch_result_count_matches_input() -> None:
    """process_batch must return one result per input event, in order,
    even when some events are malformed."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    events: list[Any] = [_make_unique_process_event(), None, "invalid", {}]

    results = integration.process_batch(events)

    assert len(results) == len(events)
    assert all(isinstance(result, dict) for result in results)


# ---------------------------------------------------------------------------
# Downstream forwarding
# ---------------------------------------------------------------------------


def test_accepted_event_forwarded_downstream() -> None:
    """An accepted event must be forwarded to the registered downstream
    handler."""
    from integration.process_integration import ProcessMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = ProcessMonitorIntegration()
    integration.set_downstream_handler(forwarded_events.append)

    event = _make_unique_process_event()
    result = integration.process_event(event)

    assert result["accepted"] is True
    assert result["forwarded"] is True
    assert len(forwarded_events) == 1


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------


def test_metrics_increase_after_processing() -> None:
    """Metrics counters must increase correctly after processing events."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()

    integration.process_event(_make_unique_process_event())
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
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    integration.process_event(_make_unique_process_event())

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
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    health = integration.health_check()
    assert health["status"] == "healthy"


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------


def test_process_event_thread_safety_smoke() -> None:
    """Concurrently processing events from multiple threads must not
    raise any exceptions."""
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker() -> None:
        try:
            for _ in range(10):
                integration.process_event(_make_unique_process_event())
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
    from integration.process_integration import ProcessMonitorIntegration

    integration = ProcessMonitorIntegration()
    event = _make_unique_process_event()
    original_event = dict(event)

    integration.process_event(event)

    assert event == original_event


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
