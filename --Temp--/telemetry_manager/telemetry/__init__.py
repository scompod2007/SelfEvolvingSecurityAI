"""
Telemetry layer package - Self-Evolving Security AI.

Exposes TelemetryManager, the central coordinator that starts,
stops, health-checks, and reports on the four telemetry collectors
(process, file, registry, network). This package performs
orchestration ONLY: it never parses telemetry, never detects
attacks, and never runs any AI/ML logic.
"""

from telemetry.telemetry_manager import TelemetryManager

__all__ = ["TelemetryManager"]
