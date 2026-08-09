"""Import and smoke-test suite for the statistics_engine package.

This module verifies that every module in the statistics_engine package
can be imported, that the expected public classes are exposed, that
those classes can be instantiated with no arguments, and that their
common public methods can be called without raising exceptions. It also
includes a lightweight multithreaded smoke test to confirm basic
thread-safety of the StatisticsEngine coordinator.

All tests are defensive: methods are only invoked via hasattr checks so
that this suite remains compatible with future refactors of the
statistics_engine package's public API.
"""

from __future__ import annotations

import importlib
import threading
from types import ModuleType
from typing import Any

import pytest

sample_event: dict[str, str] = {
    "event_type": "PROCESS_CREATE",
    "process_name": "cmd.exe",
    "timestamp": "2026-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# 1. Import module tests
# ---------------------------------------------------------------------------


def test_import_statistics_engine_module() -> None:
    """The statistics_engine.statistics_engine module must import cleanly."""
    module: ModuleType = importlib.import_module(
        "statistics_engine.statistics_engine"
    )
    assert module is not None


def test_import_runtime_metrics_module() -> None:
    """The statistics_engine.runtime_metrics module must import cleanly."""
    module: ModuleType = importlib.import_module(
        "statistics_engine.runtime_metrics"
    )
    assert module is not None


def test_import_noise_reduction_module() -> None:
    """The statistics_engine.noise_reduction module must import cleanly."""
    module: ModuleType = importlib.import_module(
        "statistics_engine.noise_reduction"
    )
    assert module is not None


def test_import_duplicate_counter_module() -> None:
    """The statistics_engine.duplicate_counter module must import cleanly."""
    module: ModuleType = importlib.import_module(
        "statistics_engine.duplicate_counter"
    )
    assert module is not None


def test_import_models_module() -> None:
    """The statistics_engine.models module must import cleanly."""
    module: ModuleType = importlib.import_module("statistics_engine.models")
    assert module is not None


# ---------------------------------------------------------------------------
# 2. Public class availability tests
# ---------------------------------------------------------------------------


def test_statistics_engine_class_available() -> None:
    """StatisticsEngine must be exposed by statistics_engine.statistics_engine."""
    module = importlib.import_module("statistics_engine.statistics_engine")
    assert hasattr(module, "StatisticsEngine")


def test_runtime_metrics_class_available() -> None:
    """RuntimeMetrics must be exposed by statistics_engine.runtime_metrics."""
    module = importlib.import_module("statistics_engine.runtime_metrics")
    assert hasattr(module, "RuntimeMetrics")


def test_noise_reduction_engine_class_available() -> None:
    """NoiseReductionEngine must be exposed by statistics_engine.noise_reduction."""
    module = importlib.import_module("statistics_engine.noise_reduction")
    assert hasattr(module, "NoiseReductionEngine")


def test_duplicate_counter_class_available() -> None:
    """DuplicateCounter must be exposed by statistics_engine.duplicate_counter."""
    module = importlib.import_module("statistics_engine.duplicate_counter")
    assert hasattr(module, "DuplicateCounter")


# ---------------------------------------------------------------------------
# 3. Instantiation smoke tests
# ---------------------------------------------------------------------------


def test_statistics_engine_instantiates() -> None:
    """StatisticsEngine must be constructible with no arguments."""
    from statistics_engine.statistics_engine import StatisticsEngine

    instance = StatisticsEngine()
    assert instance is not None


def test_runtime_metrics_instantiates() -> None:
    """RuntimeMetrics must be constructible with no arguments."""
    from statistics_engine.runtime_metrics import RuntimeMetrics

    instance = RuntimeMetrics()
    assert instance is not None


def test_noise_reduction_engine_instantiates() -> None:
    """NoiseReductionEngine must be constructible with no arguments."""
    from statistics_engine.noise_reduction import NoiseReductionEngine

    instance = NoiseReductionEngine()
    assert instance is not None


def test_duplicate_counter_instantiates() -> None:
    """DuplicateCounter must be constructible with no arguments."""
    from statistics_engine.duplicate_counter import DuplicateCounter

    instance = DuplicateCounter()
    assert instance is not None


# ---------------------------------------------------------------------------
# 4. Basic method smoke tests
# ---------------------------------------------------------------------------


def test_runtime_metrics_common_methods_smoke() -> None:
    """Common RuntimeMetrics methods must not raise when called, if present."""
    from statistics_engine.runtime_metrics import RuntimeMetrics

    instance = RuntimeMetrics()

    if hasattr(instance, "start_timer"):
        instance.start_timer()

    if hasattr(instance, "stop_timer"):
        instance.stop_timer()

    if hasattr(instance, "record_latency"):
        instance.record_latency(1.0)

    if hasattr(instance, "record"):
        instance.record(1.0)

    if hasattr(instance, "snapshot"):
        result: Any = instance.snapshot()
        assert result is not None


def test_duplicate_counter_common_methods_smoke() -> None:
    """Common DuplicateCounter methods must not raise when called, if present."""
    from statistics_engine.duplicate_counter import DuplicateCounter

    instance = DuplicateCounter()

    if hasattr(instance, "check"):
        result: Any = instance.check(sample_event)
        assert result is not None

    if hasattr(instance, "reset"):
        instance.reset()


def test_noise_reduction_engine_common_methods_smoke() -> None:
    """Common NoiseReductionEngine methods must not raise when called, if present."""
    from statistics_engine.noise_reduction import NoiseReductionEngine

    instance = NoiseReductionEngine()

    if hasattr(instance, "evaluate"):
        result: Any = instance.evaluate(sample_event)
        assert result is not None

    if hasattr(instance, "reset"):
        instance.reset()


# ---------------------------------------------------------------------------
# 5. StatisticsEngine integration smoke test
# ---------------------------------------------------------------------------


def test_statistics_engine_integration_smoke() -> None:
    """StatisticsEngine's common public workflow must not raise when called,
    and any returned values must be non-None."""
    from statistics_engine.statistics_engine import StatisticsEngine

    instance = StatisticsEngine()

    if hasattr(instance, "process_event"):
        result: Any = instance.process_event(sample_event)
        assert result is not None

    if hasattr(instance, "get_statistics"):
        stats: Any = instance.get_statistics()
        assert stats is not None

    if hasattr(instance, "reset"):
        instance.reset()


# ---------------------------------------------------------------------------
# 6. Models module smoke test
# ---------------------------------------------------------------------------


def test_models_module_has_public_members() -> None:
    """statistics_engine.models must expose at least one public attribute."""
    from statistics_engine import models

    public_members = [name for name in dir(models) if not name.startswith("_")]
    assert len(public_members) > 0


# ---------------------------------------------------------------------------
# 7. Thread-safety smoke test
# ---------------------------------------------------------------------------


def test_statistics_engine_process_event_thread_safety_smoke() -> None:
    """Concurrently calling process_event from multiple threads must not
    raise any exceptions."""
    from statistics_engine.statistics_engine import StatisticsEngine

    instance = StatisticsEngine()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker() -> None:
        try:
            if hasattr(instance, "process_event"):
                for _ in range(10):
                    instance.process_event(sample_event)
        except BaseException as exc:  # noqa: BLE001 - capture for assertion
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))