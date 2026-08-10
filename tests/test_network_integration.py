"""Import and smoke-test suite for the integration.network_integration module.

This module verifies that NetworkMonitorIntegration can be imported and
instantiated, that it correctly bridges network telemetry events to the
MasterFilterDispatcher, that it preserves correlation_id, timestamp,
source/destination IP, source/destination port, protocol, direction,
and process association fields, that it never mutates caller input,
that it forwards accepted events to a registered downstream handler,
that its metrics behave correctly, and that it is safe under
concurrent use.
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

_port_counter = itertools.count(20_000)
_port_counter_lock = threading.Lock()


def _next_port() -> int:
    """Returns a fresh, process-wide unique port for use in test events."""
    with _port_counter_lock:
        return next(_port_counter)


def _make_unique_network_event() -> dict[str, Any]:
    """Builds a fresh, non-whitelisted network event with a unique port.

    The underlying NetworkFilter maintains a process-wide duplicate-event
    cache, so tests must use distinct source port / connection
    combinations to avoid colliding with events processed by other tests
    in this suite.
    """
    src_port = _next_port()
    unique_process = f"test_{uuid.uuid4().hex}.exe"
    return {
        "event_type": "NETWORK_CONNECT",
        "src_ip": "10.0.0.15",
        "source_ip": "10.0.0.15",
        "dst_ip": "203.0.113.42",
        "destination_ip": "203.0.113.42",
        "remote_ip": "203.0.113.42",
        "local_ip": "10.0.0.15",
        "src_port": src_port,
        "source_port": src_port,
        "dst_port": 443,
        "destination_port": 443,
        "remote_port": 443,
        "local_port": src_port,
        "protocol": "TCP",
        "transport": "TCP",
        "direction": "OUTBOUND",
        "state": "ESTABLISHED",
        "connection_state": "ESTABLISHED",
        "process_name": unique_process,
        "pid": src_port,
        "timestamp": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------


def test_import_network_integration_module() -> None:
    """The integration.network_integration module must import cleanly."""
    module: ModuleType = importlib.import_module("integration.network_integration")
    assert module is not None


def test_network_monitor_integration_class_available() -> None:
    """NetworkMonitorIntegration must be exposed by
    integration.network_integration."""
    module = importlib.import_module("integration.network_integration")
    assert hasattr(module, "NetworkMonitorIntegration")


# ---------------------------------------------------------------------------
# Instantiation test
# ---------------------------------------------------------------------------


def test_network_monitor_integration_instantiates() -> None:
    """NetworkMonitorIntegration must be constructible with no arguments."""
    from integration.network_integration import NetworkMonitorIntegration

    instance = NetworkMonitorIntegration()
    assert instance is not None


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def test_process_event_smoke() -> None:
    """process_event must return a structured result dict with the
    expected keys."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    event = _make_unique_network_event()

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
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    event = _make_unique_network_event()
    event["correlation_id"] = "CID-NETWORK-FIXED-000123"

    result = integration.process_event(event)

    assert result["correlation_id"] == "CID-NETWORK-FIXED-000123"


# ---------------------------------------------------------------------------
# Timestamp preservation
# ---------------------------------------------------------------------------


def test_timestamp_preserved_on_forwarded_event() -> None:
    """A caller-supplied timestamp must be preserved unchanged on the
    event forwarded downstream."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    fixed_timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event = _make_unique_network_event()
    event["timestamp"] = fixed_timestamp

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["timestamp"] == fixed_timestamp


# ---------------------------------------------------------------------------
# IP preservation
# ---------------------------------------------------------------------------


def test_ip_fields_preserved_on_forwarded_event() -> None:
    """Caller-supplied source and destination IP fields must be
    preserved unchanged on the event forwarded downstream."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_network_event()
    expected_src_ip = event["src_ip"]
    expected_source_ip = event["source_ip"]
    expected_dst_ip = event["dst_ip"]
    expected_destination_ip = event["destination_ip"]
    expected_remote_ip = event["remote_ip"]
    expected_local_ip = event["local_ip"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    forwarded = forwarded_events[0]
    assert forwarded["src_ip"] == expected_src_ip
    assert forwarded["source_ip"] == expected_source_ip
    assert forwarded["dst_ip"] == expected_dst_ip
    assert forwarded["destination_ip"] == expected_destination_ip
    assert forwarded["remote_ip"] == expected_remote_ip
    assert forwarded["local_ip"] == expected_local_ip


# ---------------------------------------------------------------------------
# Port preservation
# ---------------------------------------------------------------------------


def test_port_fields_preserved_on_forwarded_event() -> None:
    """Caller-supplied source and destination port fields must be
    preserved unchanged on the event forwarded downstream."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_network_event()
    expected_src_port = event["src_port"]
    expected_source_port = event["source_port"]
    expected_dst_port = event["dst_port"]
    expected_destination_port = event["destination_port"]
    expected_remote_port = event["remote_port"]
    expected_local_port = event["local_port"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    forwarded = forwarded_events[0]
    assert forwarded["src_port"] == expected_src_port
    assert forwarded["source_port"] == expected_source_port
    assert forwarded["dst_port"] == expected_dst_port
    assert forwarded["destination_port"] == expected_destination_port
    assert forwarded["remote_port"] == expected_remote_port
    assert forwarded["local_port"] == expected_local_port


# ---------------------------------------------------------------------------
# Protocol preservation
# ---------------------------------------------------------------------------


def test_protocol_preserved_on_forwarded_event() -> None:
    """Caller-supplied protocol and transport fields must be preserved
    unchanged on the event forwarded downstream."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_network_event()
    expected_protocol = event["protocol"]
    expected_transport = event["transport"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["protocol"] == expected_protocol
    assert forwarded_events[0]["transport"] == expected_transport


# ---------------------------------------------------------------------------
# Direction preservation
# ---------------------------------------------------------------------------


def test_direction_preserved_on_forwarded_event() -> None:
    """A caller-supplied connection direction must be preserved
    unchanged on the event forwarded downstream."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_network_event()
    expected_direction = event["direction"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["direction"] == expected_direction


# ---------------------------------------------------------------------------
# Process association preservation
# ---------------------------------------------------------------------------


def test_process_association_preserved_on_forwarded_event() -> None:
    """A caller-supplied process_name and pid must be preserved
    unchanged on the event forwarded downstream."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration(
        downstream_handler=forwarded_events.append
    )

    event = _make_unique_network_event()
    expected_process_name = event["process_name"]
    expected_pid = event["pid"]

    integration.process_event(event)

    assert len(forwarded_events) == 1
    assert forwarded_events[0]["process_name"] == expected_process_name
    assert forwarded_events[0]["pid"] == expected_pid


# ---------------------------------------------------------------------------
# Default event type injection
# ---------------------------------------------------------------------------


def test_default_event_type_injected() -> None:
    """process_event must inject NETWORK_CONNECT when event_type is
    missing."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    src_port = _next_port()
    event = {
        "src_ip": "10.0.0.20",
        "dst_ip": "203.0.113.99",
        "src_port": src_port,
        "dst_port": 443,
        "process_name": f"test_{uuid.uuid4().hex}.exe",
    }

    result = integration.process_event(event)

    assert result["event_type"] == "NETWORK_CONNECT"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_process_event_none_rejected() -> None:
    """process_event(None) must return accepted=False."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    result = integration.process_event(None)  # type: ignore[arg-type]
    assert result["accepted"] is False


def test_process_event_invalid_string_rejected() -> None:
    """process_event('invalid') must return accepted=False."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    result = integration.process_event("invalid")  # type: ignore[arg-type]
    assert result["accepted"] is False


def test_process_event_invalid_int_rejected() -> None:
    """process_event(123) must return accepted=False."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    result = integration.process_event(123)  # type: ignore[arg-type]
    assert result["accepted"] is False


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------


def test_process_batch_result_count_matches_input() -> None:
    """process_batch must return one result per input event, in order,
    even when some events are malformed."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    events: list[Any] = [_make_unique_network_event(), None, "invalid", {}]

    results = integration.process_batch(events)

    assert len(results) == len(events)
    assert all(isinstance(result, dict) for result in results)


# ---------------------------------------------------------------------------
# Downstream forwarding
# ---------------------------------------------------------------------------


def test_accepted_event_forwarded_downstream() -> None:
    """An accepted event must be forwarded to the registered downstream
    handler."""
    from integration.network_integration import NetworkMonitorIntegration

    forwarded_events: list[dict[str, Any]] = []
    integration = NetworkMonitorIntegration()
    integration.set_downstream_handler(forwarded_events.append)

    event = _make_unique_network_event()
    result = integration.process_event(event)

    assert result["accepted"] is True
    assert result["forwarded"] is True
    assert len(forwarded_events) == 1


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------


def test_metrics_increase_after_processing() -> None:
    """Metrics counters must increase correctly after processing events."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()

    integration.process_event(_make_unique_network_event())
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
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    integration.process_event(_make_unique_network_event())

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
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    health = integration.health_check()
    assert health["status"] == "healthy"


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------


def test_process_event_thread_safety_smoke() -> None:
    """Concurrently processing events from multiple threads must not
    raise any exceptions."""
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker() -> None:
        try:
            for _ in range(10):
                integration.process_event(_make_unique_network_event())
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
    from integration.network_integration import NetworkMonitorIntegration

    integration = NetworkMonitorIntegration()
    event = _make_unique_network_event()
    original_event = dict(event)

    integration.process_event(event)

    assert event == original_event


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
