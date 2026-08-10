"""Import and smoke-test suite for the dispatcher package.

This module verifies that the dispatcher package's modules import
cleanly, that the expected public classes are exposed, that those
classes can be instantiated, and that MasterFilterDispatcher's public
dispatch API behaves correctly for valid events, malformed input, and
concurrent access.

All tests validate only observable public behavior and make no
assumptions about internal implementation details of the underlying
FilterEngine.
"""

from __future__ import annotations

import importlib
import threading
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

import pytest

sample_process_event: dict[str, Any] = {
    "event_type": "PROCESS_CREATE",
    "process_name": "cmd.exe",
    "process_path": "C:\\Windows\\System32\\cmd.exe",
    "pid": 4321,
}

sample_file_event: dict[str, Any] = {
    "event_type": "FILE_CREATE",
    "file_path": "/tmp/test.txt",
    "file_name": "test.txt",
    "extension": ".txt",
    "operation": "CREATE",
    "process_name": "explorer.exe",
    "file_size": 128,
    "timestamp": datetime.now(timezone.utc),
}

sample_network_event: dict[str, Any] = {
    "event_type": "NETWORK_CONNECT",
    "source_ip": "127.0.0.1",
    "destination_ip": "127.0.0.1",
    "protocol": "TCP",
    "direction": "OUTBOUND",
    "source_port": 51000,
    "destination_port": 443,
}

sample_registry_event: dict[str, Any] = {
    "event_type": "REGISTRY_MODIFY",
    "registry_key": "SOFTWARE\\Test",
    "hive": "HKLM",
    "operation": "MODIFY",
    "process_name": "regedit.exe",
    "value_name": "TestValue",
    "value_data": "1",
}


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------


def test_import_dispatcher_models_module() -> None:
    """The dispatcher.models module must import cleanly."""
    module: ModuleType = importlib.import_module("dispatcher.models")
    assert module is not None


def test_import_master_filter_dispatcher_module() -> None:
    """The dispatcher.master_filter_dispatcher module must import cleanly."""
    module: ModuleType = importlib.import_module(
        "dispatcher.master_filter_dispatcher"
    )
    assert module is not None


# ---------------------------------------------------------------------------
# Public class availability tests
# ---------------------------------------------------------------------------


def test_dispatch_request_class_available() -> None:
    """DispatchRequest must be exposed by dispatcher.models."""
    module = importlib.import_module("dispatcher.models")
    assert hasattr(module, "DispatchRequest")


def test_dispatch_response_class_available() -> None:
    """DispatchResponse must be exposed by dispatcher.models."""
    module = importlib.import_module("dispatcher.models")
    assert hasattr(module, "DispatchResponse")


def test_master_filter_dispatcher_class_available() -> None:
    """MasterFilterDispatcher must be exposed by
    dispatcher.master_filter_dispatcher."""
    module = importlib.import_module("dispatcher.master_filter_dispatcher")
    assert hasattr(module, "MasterFilterDispatcher")


# ---------------------------------------------------------------------------
# Instantiation tests
# ---------------------------------------------------------------------------


def test_dispatch_request_instantiates() -> None:
    """DispatchRequest must be constructible with an event dict."""
    from dispatcher.models import DispatchRequest

    instance = DispatchRequest(event={"event_type": "PROCESS_CREATE"})
    assert instance is not None


def test_dispatch_response_instantiates() -> None:
    """DispatchResponse must be constructible with its required fields."""
    from dispatcher.models import DispatchResponse

    instance = DispatchResponse(
        accepted=True,
        event_type="PROCESS_CREATE",
        filter_name="ProcessFilter",
        correlation_id="CID-TEST-000001",
        execution_time_ms=0.5,
        result=None,
        error=None,
    )
    assert instance is not None


def test_master_filter_dispatcher_instantiates() -> None:
    """MasterFilterDispatcher must be constructible with no arguments."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    instance = MasterFilterDispatcher()
    assert instance is not None


# ---------------------------------------------------------------------------
# DispatchResponse behavior tests
# ---------------------------------------------------------------------------


def test_dispatch_response_is_success_true() -> None:
    """is_success must return True when accepted is True and error is None."""
    from dispatcher.models import DispatchResponse

    response = DispatchResponse(
        accepted=True,
        event_type="PROCESS_CREATE",
        filter_name="ProcessFilter",
        correlation_id="CID-TEST-000002",
        execution_time_ms=0.5,
        result=None,
        error=None,
    )
    assert response.is_success() is True


def test_dispatch_response_is_success_false() -> None:
    """is_success must return False when accepted is False or error is set."""
    from dispatcher.models import DispatchResponse

    response = DispatchResponse(
        accepted=False,
        event_type="UNKNOWN",
        filter_name="N/A",
        correlation_id="CID-TEST-000003",
        execution_time_ms=0.5,
        result=None,
        error="Invalid event.",
    )
    assert response.is_success() is False


def test_dispatch_response_to_dict_returns_dict() -> None:
    """to_dict must return a dictionary representation of the response."""
    from dispatcher.models import DispatchResponse

    response = DispatchResponse(
        accepted=True,
        event_type="PROCESS_CREATE",
        filter_name="ProcessFilter",
        correlation_id="CID-TEST-000004",
        execution_time_ms=0.5,
        result=None,
        error=None,
    )
    result_dict = response.to_dict()
    assert isinstance(result_dict, dict)
    assert result_dict["correlation_id"] == "CID-TEST-000004"


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def _assert_valid_dispatch_smoke(
    dispatcher: Any, event: dict[str, Any]
) -> None:
    """Shared assertions for a successful dispatch smoke test."""
    from dispatcher.models import DispatchResponse

    original_event = dict(event)
    response = dispatcher.dispatch(event)

    assert isinstance(response, DispatchResponse)
    assert response.correlation_id
    assert response.execution_time_ms >= 0
    assert event == original_event


def test_dispatch_process_event_smoke() -> None:
    """Dispatching a process event must succeed without mutating the
    original event."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    _assert_valid_dispatch_smoke(dispatcher, dict(sample_process_event))


def test_dispatch_file_event_smoke() -> None:
    """Dispatching a file event must succeed without mutating the
    original event."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    _assert_valid_dispatch_smoke(dispatcher, dict(sample_file_event))


def test_dispatch_network_event_smoke() -> None:
    """Dispatching a network event must succeed without mutating the
    original event."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    _assert_valid_dispatch_smoke(dispatcher, dict(sample_network_event))


def test_dispatch_registry_event_smoke() -> None:
    """Dispatching a registry event must succeed without mutating the
    original event."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    _assert_valid_dispatch_smoke(dispatcher, dict(sample_registry_event))


# ---------------------------------------------------------------------------
# Convenience method tests
# ---------------------------------------------------------------------------


def test_filter_process_convenience_method() -> None:
    """filter_process must inject PROCESS_CREATE when event_type is
    missing and return a DispatchResponse."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher
    from dispatcher.models import DispatchResponse

    dispatcher = MasterFilterDispatcher()
    event: dict[str, Any] = {
        "process_name": "cmd.exe",
        "process_path": "C:\\Windows\\System32\\cmd.exe",
        "pid": 111,
    }
    original_event = dict(event)

    response = dispatcher.filter_process(event)

    assert isinstance(response, DispatchResponse)
    assert response.event_type == "PROCESS_CREATE"
    assert event == original_event


def test_filter_file_convenience_method() -> None:
    """filter_file must inject FILE_CREATE when event_type is missing
    and return a DispatchResponse."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher
    from dispatcher.models import DispatchResponse

    dispatcher = MasterFilterDispatcher()
    event: dict[str, Any] = {
        "file_path": "/tmp/other.txt",
        "file_name": "other.txt",
    }
    original_event = dict(event)

    response = dispatcher.filter_file(event)

    assert isinstance(response, DispatchResponse)
    assert response.event_type == "FILE_CREATE"
    assert event == original_event


def test_filter_network_convenience_method() -> None:
    """filter_network must inject NETWORK_CONNECT when event_type is
    missing and return a DispatchResponse."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher
    from dispatcher.models import DispatchResponse

    dispatcher = MasterFilterDispatcher()
    event: dict[str, Any] = {
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
    }
    original_event = dict(event)

    response = dispatcher.filter_network(event)

    assert isinstance(response, DispatchResponse)
    assert response.event_type == "NETWORK_CONNECT"
    assert event == original_event


def test_filter_registry_convenience_method() -> None:
    """filter_registry must inject REGISTRY_MODIFY when event_type is
    missing and return a DispatchResponse."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher
    from dispatcher.models import DispatchResponse

    dispatcher = MasterFilterDispatcher()
    event: dict[str, Any] = {
        "registry_key": "SOFTWARE\\Other",
        "hive": "HKCU",
    }
    original_event = dict(event)

    response = dispatcher.filter_registry(event)

    assert isinstance(response, DispatchResponse)
    assert response.event_type == "REGISTRY_MODIFY"
    assert event == original_event


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


def test_dispatch_none_rejected() -> None:
    """dispatch(None) must return accepted=False."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    response = dispatcher.dispatch(None)  # type: ignore[arg-type]
    assert response.accepted is False


def test_dispatch_invalid_string_rejected() -> None:
    """dispatch('invalid') must return accepted=False."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    response = dispatcher.dispatch("invalid")  # type: ignore[arg-type]
    assert response.accepted is False


def test_dispatch_empty_dict_rejected() -> None:
    """dispatch({}) must return accepted=False."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    response = dispatcher.dispatch({})
    assert response.accepted is False


def test_dispatch_whitespace_event_type_rejected() -> None:
    """dispatch({'event_type': '   '}) must return accepted=False."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    response = dispatcher.dispatch({"event_type": "   "})
    assert response.accepted is False


# ---------------------------------------------------------------------------
# Health check test
# ---------------------------------------------------------------------------


def test_health_check_status_healthy() -> None:
    """health_check must report status 'healthy'."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    health = dispatcher.health_check()
    assert health["status"] == "healthy"


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------


def test_dispatch_thread_safety_smoke() -> None:
    """Concurrently dispatching events from multiple threads must not
    raise any exceptions."""
    from dispatcher.master_filter_dispatcher import MasterFilterDispatcher

    dispatcher = MasterFilterDispatcher()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    events = (
        sample_process_event,
        sample_file_event,
        sample_network_event,
        sample_registry_event,
    )

    def worker() -> None:
        try:
            for i in range(20):
                event = dict(events[i % len(events)])
                dispatcher.dispatch(event)
        except BaseException as exc:  # noqa: BLE001 - capture for assertion
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
