"""
============================================================
Self-Evolving Security AI
Part 2.9.x - Integrated Confidence Engine Testing
============================================================

This module is a standalone, research-grade integration testing
framework designed to validate the entire confidence scoring pipeline.
        
1. ConfidenceEngine
2. RuleWeightingEngine
3. WhitelistAdjustmentEngine
4. AIAdjustmentSupportEngine

It strictly uses public APIs, avoids pipeline assumptions,
enforces performance and memory constraints, and provides
comprehensive reporting (Console, JSON, CSV).

IMPORTANT (black-box testing policy):
- This framework validates only DOCUMENTED PUBLIC API behavior.
- It never assumes confidence values, whitelist contents, execution
  order, internal flags, or internal metadata.
- Diagnostic/internal/optional fields are never required to exist.
- Any chaining between engines below is a TEST-HARNESS CONVENIENCE,
  clearly isolated in `OrchestrationPolicy`, and is NOT an assertion
  about actual production orchestration.
"""

import argparse
import csv
import json
import logging
import math
import random
import sys
import time
import tracemalloc
from dataclasses import dataclass, asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any

# ============================================================
# PROJECT IMPORTS
# ============================================================
try:
    from confidence_engine.confidence_engine import (
        ConfidenceEngine,
        ConfidenceResult
    )
    from confidence_engine.rule_weighting import (
        RuleWeightingEngine,
        RuleWeightResult
    )
    from confidence_engine.whitelist_adjustment import (
        WhitelistAdjustmentEngine,
        WhitelistAdjustmentResult
    )
    from ai.ai_adjustment_support import (
        AIAdjustmentSupportEngine,
        AIAdjustmentResult
    )
except ImportError as e:
    print(f"CRITICAL ERROR: Production engines not found. Details: {e}")
    print("Please ensure the 'confidence_engine' package is in the PYTHONPATH.")
    sys.exit(1)

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger("confidence_pipeline_test")

# ============================================================
# CONSTANTS & LIMITS
# ============================================================
DEFAULT_MAX_SCENARIO_TIME_MS: float = 50.0
DEFAULT_MAX_STRESS_TEST_TIME_S: float = 15.0
DEFAULT_MAX_PEAK_MEMORY_MB: float = 50.0


class TestCategory(Enum):
    """Categories for grouping test scenarios."""
    CONFIDENCE_ENGINE = "Confidence Engine"
    RULE_WEIGHTING = "Rule Weighting"
    WHITELIST = "Whitelist"
    AI_ADJUSTMENT = "AI Adjustment"
    METADATA = "Metadata"
    MALFORMED_INPUTS = "Malformed Inputs"
    STRESS_TESTS = "Stress Tests"
    NORMALIZATION_TESTS = "Normalization Tests"
    BOUNDARY_TESTS = "Boundary Tests"


# ============================================================
# DATACLASSES
# ============================================================

@dataclass(slots=True)
class ScenarioInput:
    """Defines the input parameters for a single test scenario."""
    name: str
    category: TestCategory
    raw_evidence: Any
    matched_rules: Any
    telemetry: Any
    ai_data: Any


@dataclass(slots=True)
class PipelineResult:
    """Stores the original production results and test metadata.

    Computed properties below (final_confidence, adjustment_type,
    adjustment_reason) are SAFE, NEVER-CRASHING derived views used only
    for reporting (CSV/JSON). They never assume a field exists on the
    underlying production result objects.
    """
    scenario_name: str
    category: TestCategory
    conf_result: ConfidenceResult | None
    weight_result: RuleWeightResult | None
    whitelist_result: WhitelistAdjustmentResult | None
    ai_result: AIAdjustmentResult | None
    passed: bool
    failure_reasons: list[str]
    execution_time_ms: float

    @property
    def final_confidence(self) -> float:
        """Safely derives a reportable final confidence value, if any exists."""
        if self.ai_result is not None and hasattr(self.ai_result, "adjusted_confidence"):
            val = getattr(self.ai_result, "adjusted_confidence")
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                if not (isinstance(val, float) and (math.isnan(val) or math.isinf(val))):
                    return float(val)
        return 0.0

    @property
    def adjustment_type(self) -> str:
        """Safely derives a reportable adjustment type, if any exists."""
        if self.ai_result is not None and hasattr(self.ai_result, "adjustment_type"):
            val = getattr(self.ai_result, "adjustment_type")
            if isinstance(val, str):
                return val
        return "N/A"

    @property
    def adjustment_reason(self) -> str:
        """Safely derives a reportable adjustment reason, if any exists."""
        if self.ai_result is not None and hasattr(self.ai_result, "adjustment_reason"):
            val = getattr(self.ai_result, "adjustment_reason")
            if isinstance(val, str):
                return val
        return "N/A"


# ============================================================
# UTILITIES
# ============================================================

class SafeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to safely serialize dataclasses, enums, and sets."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                return str(obj)
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def print_banner(title: str) -> None:
    """Prints a formatted banner to the console."""
    print(f"\n{'=' * 80}\n {title}\n{'=' * 80}")


def extract_engine_metadata() -> dict[str, str]:
    """Extracts available metadata from the production modules."""
    metadata = {}
    modules = [
        ("ConfidenceEngine", sys.modules.get("confidence_engine.confidence_engine")),
        ("RuleWeighting", sys.modules.get("confidence_engine.rule_weighting")),
        ("Whitelist", sys.modules.get("confidence_engine.whitelist_adjustment")),
        ("AIAdjustment", sys.modules.get("confidence_engine.ai_adjustment_support"))
    ]
    for name, mod in modules:
        if mod:
            version = getattr(mod, "__version__", "Unknown")
            author = getattr(mod, "__author__", "Unknown")
            metadata[name] = f"v{version} (Author: {author})"
    return metadata


def _make_nested_dict(depth: int) -> dict:
    """Builds a deeply nested (non-cyclic) dictionary for stress testing."""
    d: dict = {"leaf": True}
    for _ in range(depth):
        d = {"nested": d}
    return d


def _make_nested_list(depth: int) -> list:
    """Builds a deeply nested (non-cyclic) list for stress testing."""
    lst: list = ["leaf"]
    for _ in range(depth):
        lst = [lst]
    return lst


# ============================================================
# ORCHESTRATION POLICY (ISOLATION BOUNDARY)
# ============================================================

class OrchestrationPolicy:
    """
    ISOLATION BOUNDARY FOR ASSUMED ENGINE CHAINING.

    The production API does not currently expose an official orchestrator
    that combines ConfidenceEngine, RuleWeightingEngine,
    WhitelistAdjustmentEngine, and AIAdjustmentSupportEngine into a single
    pipeline. Any chaining performed here is a TEST-HARNESS CONVENIENCE
    ONLY. It is NOT a documented production behavior and MUST NOT be
    treated as an assertion about how production actually combines these
    engines.

    If production later exposes an official pipeline/orchestrator, replace
    the logic below with a direct call into that orchestrator.

    Failure handling policy: engine failures are treated NEUTRALLY. No
    fallback confidence value (e.g. 0.0) is ever fabricated. If an engine
    fails or produces no usable output, downstream engines that would
    require its output are simply not invoked, and the omission is
    recorded transparently rather than papered over.
    """

    def resolve_whitelist_input(
        self,
        conf_result: ConfidenceResult | None,
        conf_engine_failed: bool,
        errors: list[str]
    ) -> float | None:
        """Returns a confidence value to feed WhitelistAdjustmentEngine, or None."""
        if conf_engine_failed or conf_result is None:
            errors.append(
                "WhitelistAdjustmentEngine skipped: no valid confidence value "
                "available (ConfidenceEngine did not produce one). No fallback "
                "confidence was fabricated."
            )
            return None

        if not hasattr(conf_result, "confidence"):
            errors.append(
                "WhitelistAdjustmentEngine skipped: ConfidenceResult exposes no "
                "'confidence' attribute in this production build."
            )
            return None

        val = getattr(conf_result, "confidence")
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            errors.append(
                "WhitelistAdjustmentEngine skipped: ConfidenceResult.confidence "
                "is not numeric."
            )
            return None

        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            errors.append(
                "WhitelistAdjustmentEngine skipped: ConfidenceResult.confidence "
                "is not finite."
            )
            return None

        return float(val)

    def resolve_ai_input(
        self,
        whitelist_result: WhitelistAdjustmentResult | None,
        whitelist_engine_failed: bool,
        whitelist_skipped: bool,
        errors: list[str]
    ) -> float | None:
        """Returns a confidence value to feed AIAdjustmentSupportEngine, or None."""
        if whitelist_engine_failed or whitelist_skipped or whitelist_result is None:
            errors.append(
                "AIAdjustmentSupportEngine skipped: no valid confidence value "
                "available from WhitelistAdjustmentEngine. No fallback confidence "
                "was fabricated."
            )
            return None

        if not hasattr(whitelist_result, "adjusted_confidence"):
            errors.append(
                "AIAdjustmentSupportEngine skipped: WhitelistAdjustmentResult "
                "exposes no 'adjusted_confidence' attribute in this production build."
            )
            return None

        val = getattr(whitelist_result, "adjusted_confidence")
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            errors.append(
                "AIAdjustmentSupportEngine skipped: adjusted_confidence is not numeric."
            )
            return None

        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            errors.append(
                "AIAdjustmentSupportEngine skipped: adjusted_confidence is not finite."
            )
            return None

        return float(val)


# ============================================================
# PIPELINE ADAPTER
# ============================================================

class PipelineAdapter:
    """
    Encapsulates the execution of the production engines.
    Strictly uses public APIs and avoids assumptions about internal behavior.
    Orchestration/chaining decisions are fully delegated to an injectable
    OrchestrationPolicy so the harness can be adapted quickly if production
    orchestration changes.
    """

    def __init__(self, orchestration_policy: OrchestrationPolicy | None = None) -> None:
        self.conf_engine = ConfidenceEngine()
        self.weight_engine = RuleWeightingEngine()
        self.whitelist_engine = WhitelistAdjustmentEngine()
        self.ai_engine = AIAdjustmentSupportEngine()
        self.orchestration = orchestration_policy or OrchestrationPolicy()

    def execute(
        self, scenario: ScenarioInput
    ) -> tuple[
        ConfidenceResult | None,
        RuleWeightResult | None,
        WhitelistAdjustmentResult | None,
        AIAdjustmentResult | None,
        list[str]
    ]:
        """
        Executes each engine using only public APIs. Chaining between engines
        is isolated in `self.orchestration` and is a test-harness convenience,
        not a production assertion.

        Args:
            scenario (ScenarioInput): The input data for the pipeline.

        Returns:
            tuple: The exact result objects returned by the four production
            engines (or None if not invoked/failed), and any recorded errors
            or skip notices.
        """
        errors: list[str] = []
        conf_result: ConfidenceResult | None = None
        weight_result: RuleWeightResult | None = None
        whitelist_result: WhitelistAdjustmentResult | None = None
        ai_result: AIAdjustmentResult | None = None

        conf_failed = False
        whitelist_failed = False

        try:
            conf_result = self.conf_engine.calculate(scenario.raw_evidence)
        except Exception as e:
            errors.append(f"ConfidenceEngine raised exception: {e}")
            conf_failed = True

        try:
            weight_result = self.weight_engine.calculate(scenario.matched_rules)
        except Exception as e:
            errors.append(f"RuleWeightingEngine raised exception: {e}")

        whitelist_input = self.orchestration.resolve_whitelist_input(
            conf_result, conf_failed, errors
        )

        whitelist_skipped = whitelist_input is None
        if not whitelist_skipped:
            try:
                whitelist_result = self.whitelist_engine.adjust(
                    whitelist_input, scenario.telemetry
                )
            except Exception as e:
                errors.append(f"WhitelistAdjustmentEngine raised exception: {e}")
                whitelist_failed = True

        ai_input = self.orchestration.resolve_ai_input(
            whitelist_result, whitelist_failed, whitelist_skipped, errors
        )

        if ai_input is not None:
            try:
                ai_result = self.ai_engine.adjust(ai_input, scenario.ai_data)
            except Exception as e:
                errors.append(f"AIAdjustmentSupportEngine raised exception: {e}")

        return conf_result, weight_result, whitelist_result, ai_result, errors


# ============================================================
# TEST ORCHESTRATOR
# ============================================================

class ConfidencePipelineTester:
    """
    Orchestrates the execution of test scenarios, validates assertions,
    and tracks performance and memory metrics.
    """

    # ------------------------------------------------------------
    # Declarative field specs per result type.
    #
    # CORE fields are the minimal, stable public contract: if present,
    # they are type/bounds validated; if genuinely required for the
    # object to be meaningful (e.g. a confidence value), their absence
    # is flagged. Everything else is OPTIONAL: validated only if present,
    # NEVER required. Fields considered diagnostic/internal telemetry
    # (per project policy) are intentionally excluded entirely and never
    # touched by validation.
    # ------------------------------------------------------------
    CONFIDENCE_CORE = [
        ("confidence", float, (0.0, 100.0)),
    ]
    CONFIDENCE_OPTIONAL = [
        ("confidence_level", str, None),
        ("matched_rule_count", int, None),
        ("matched_indicator_count", int, None),
        ("total_unique_evidence", int, None),
        ("reasons", list, None),
        ("timestamp", datetime, None),
    ]

    RULEWEIGHT_CORE: list[tuple[str, type, tuple[float, float] | None]] = []
    RULEWEIGHT_OPTIONAL = [
        ("weighted_confidence", float, None),
        ("matched_rule_count", int, None),
        ("recognized_rule_count", int, None),
        ("unknown_rule_count", int, None),
        ("recognized_rules", list, None),
        ("unknown_rules", list, None),
        ("rule_weights", dict, None),
        ("reasons", list, None),
        ("timestamp", datetime, None),
    ]

    WHITELIST_CORE = [
        ("original_confidence", float, (0.0, 100.0)),
        ("adjusted_confidence", float, (0.0, 100.0)),
    ]
    # NOTE: publisher_reduction, certificate_reduction, ip_reduction are
    # diagnostic/internal telemetry fields and are intentionally excluded.
    WHITELIST_OPTIONAL = [
        ("confidence_reduction", float, None),
        ("process_reduction", float, None),
        ("domain_reduction", float, None),
        ("trusted_process_detected", bool, None),
        ("trusted_domain_detected", bool, None),
        ("trusted_ip_detected", bool, None),
        ("trusted_certificate_detected", bool, None),
        ("trusted_publisher_detected", bool, None),
        ("matched_process", str, None),
        ("matched_domain", str, None),
        ("matched_ip", str, None),
        ("matched_certificate", str, None),
        ("matched_publisher", str, None),
        ("matched_categories", list, None),
        ("reasons", list, None),
        ("timestamp", datetime, None),
    ]

    AI_CORE = [
        ("original_confidence", float, (0.0, 100.0)),
        ("adjusted_confidence", float, (0.0, 100.0)),
    ]
    # NOTE: adjustment_type_internal, ignored_duplicate_metadata,
    # ignored_duplicate_adjustments, ignored_extra_fields, override_origin
    # are diagnostic/internal telemetry fields and are intentionally excluded.
    AI_OPTIONAL = [
        ("confidence_change", float, None),
        ("adjustment_applied", bool, None),
        ("adjustment_source", str, None),
        ("adjustment_type", str, None),
        ("adjustment_reason", str, None),
        ("model_name", str, None),
        ("model_version", str, None),
        ("analyst_override_used", bool, None),
        ("ai_adjustment_used", bool, None),
        ("ml_adjustment_used", bool, None),
        ("threat_intelligence_used", bool, None),
        ("behavior_adjustment_used", bool, None),
        ("override_used", bool, None),
        ("final_adjustment_value", float, None),
        ("ignored_invalid_adjustments", int, None),
        ("source_consistency", bool, None),
        ("extra_metadata", dict, None),
        ("reasons", list, None),
        ("timestamp", datetime, None),
    ]

    def __init__(self, max_scenario_ms: float, max_stress_s: float, max_memory_mb: float) -> None:
        self.adapter = PipelineAdapter()
        self.max_scenario_ms = max_scenario_ms
        self.max_stress_s = max_stress_s
        self.max_memory_mb = max_memory_mb

    def _validate_type(self, obj: Any, expected_type: type, field_name: str, errors: list[str]) -> bool:
        if not isinstance(obj, expected_type):
            errors.append(f"Field '{field_name}' expected {expected_type.__name__}, got {type(obj).__name__}")
            return False
        return True

    def _validate_float_bounds(self, val: float, min_val: float, max_val: float, field_name: str, errors: list[str]) -> None:
        if math.isnan(val) or math.isinf(val):
            errors.append(f"Field '{field_name}' is not finite: {val}")
        elif not (min_val <= val <= max_val):
            errors.append(f"Field '{field_name}' out of bounds [{min_val}, {max_val}]: {val}")

 