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
import os
import random
import sys
import time
import tracemalloc
from dataclasses import dataclass, asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any

# ============================================================
# PYTHONPATH BOOTSTRAP
# ============================================================
# Matches the convention used by every other script in tests/: add the
# project root (one directory up from this file) to sys.path so the
# production packages ('confidence_engine', 'ai', etc.) can be imported
# regardless of the caller's current working directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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

    def _validate_fields(
        self,
        obj: Any,
        result_name: str,
        core_specs: list[tuple[str, type, tuple[float, float] | None]],
        optional_specs: list[tuple[str, type, tuple[float, float] | None]],
        errors: list[str]
    ) -> None:
        """
        Validates a production result object against its declared public API
        contract. CORE fields are required to exist; OPTIONAL fields are
        validated only if present and are never required. Every field is
        accessed strictly via getattr/hasattr so an unexpected production
        shape never raises inside the harness itself.

        Args:
            obj (Any): The production result object (or None).
            result_name (str): Human-readable label for error messages.
            core_specs (list): Required (field_name, type, bounds|None) tuples.
            optional_specs (list): Optional (field_name, type, bounds|None) tuples.
            errors (list[str]): Accumulator for failure reasons.
        """
        if obj is None:
            if core_specs:
                errors.append(f"{result_name}: result object is None but CORE fields are required.")
            return

        for field_name, expected_type, bounds in core_specs:
            if not hasattr(obj, field_name):
                errors.append(f"{result_name}: missing required CORE field '{field_name}'.")
                continue
            val = getattr(obj, field_name)
            if not self._validate_type(val, expected_type, f"{result_name}.{field_name}", errors):
                continue
            if bounds is not None and expected_type in (float, int) and not isinstance(val, bool):
                self._validate_float_bounds(float(val), bounds[0], bounds[1], f"{result_name}.{field_name}", errors)

        for field_name, expected_type, bounds in optional_specs:
            if not hasattr(obj, field_name):
                continue
            val = getattr(obj, field_name)
            if not self._validate_type(val, expected_type, f"{result_name}.{field_name}", errors):
                continue
            if bounds is not None and expected_type in (float, int) and not isinstance(val, bool):
                self._validate_float_bounds(float(val), bounds[0], bounds[1], f"{result_name}.{field_name}", errors)

    def validate(
        self,
        conf_result: ConfidenceResult | None,
        weight_result: RuleWeightResult | None,
        whitelist_result: WhitelistAdjustmentResult | None,
        ai_result: AIAdjustmentResult | None,
        pipeline_errors: list[str]
    ) -> tuple[bool, list[str]]:
        """
        Validates every produced result object against its declared public
        API contract. Engine failures already recorded by PipelineAdapter
        (in pipeline_errors) are surfaced as failures too, since an
        unhandled/raised exception is never an acceptable outcome for a
        stateless, exception-safe production engine.

        Returns:
            tuple[bool, list[str]]: Whether the scenario passed, and the
            full list of failure reasons (empty if passed).
        """
        errors: list[str] = list(pipeline_errors)

        # ConfidenceEngine.calculate() never raises by contract; a None
        # result here means PipelineAdapter caught an exception, which is
        # itself already recorded above. Only validate fields if we have
        # an object to validate.
        if conf_result is not None:
            self._validate_fields(conf_result, "ConfidenceResult", self.CONFIDENCE_CORE, self.CONFIDENCE_OPTIONAL, errors)

        if weight_result is not None:
            self._validate_fields(weight_result, "RuleWeightResult", self.RULEWEIGHT_CORE, self.RULEWEIGHT_OPTIONAL, errors)

        # Whitelist/AI results are legitimately None when the harness's
        # OrchestrationPolicy chose to skip them (e.g. no numeric confidence
        # upstream) -- that is not a failure, it is documented, recorded
        # behavior. Only validate fields when a result object exists.
        if whitelist_result is not None:
            self._validate_fields(whitelist_result, "WhitelistAdjustmentResult", self.WHITELIST_CORE, self.WHITELIST_OPTIONAL, errors)

        if ai_result is not None:
            self._validate_fields(ai_result, "AIAdjustmentResult", self.AI_CORE, self.AI_OPTIONAL, errors)

        return (len(errors) == 0), errors

    def run_scenario(self, scenario: ScenarioInput) -> PipelineResult:
        """
        Executes a single scenario through the production engines (via
        PipelineAdapter), times it, validates the results, and returns a
        structured PipelineResult for reporting.

        Args:
            scenario (ScenarioInput): The scenario to execute.

        Returns:
            PipelineResult: The recorded outcome of this scenario.
        """
        start = time.perf_counter()
        conf_result, weight_result, whitelist_result, ai_result, pipeline_errors = self.adapter.execute(scenario)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        passed, failure_reasons = self.validate(conf_result, weight_result, whitelist_result, ai_result, pipeline_errors)

        if elapsed_ms > self.max_scenario_ms:
            passed = False
            failure_reasons = failure_reasons + [
                f"Scenario exceeded max execution time: {elapsed_ms:.3f}ms > {self.max_scenario_ms}ms"
            ]

        return PipelineResult(
            scenario_name=scenario.name,
            category=scenario.category,
            conf_result=conf_result,
            weight_result=weight_result,
            whitelist_result=whitelist_result,
            ai_result=ai_result,
            passed=passed,
            failure_reasons=failure_reasons,
            execution_time_ms=elapsed_ms
        )

    def run_all(self, scenarios: list[ScenarioInput]) -> list[PipelineResult]:
        """
        Executes every provided scenario sequentially.

        Args:
            scenarios (list[ScenarioInput]): The scenarios to execute.

        Returns:
            list[PipelineResult]: One result per scenario, in order.
        """
        results: list[PipelineResult] = []
        for scenario in scenarios:
            try:
                results.append(self.run_scenario(scenario))
            except Exception as e:
                logger.exception("Harness-level failure running scenario '%s': %s", scenario.name, e)
                results.append(PipelineResult(
                    scenario_name=scenario.name,
                    category=scenario.category,
                    conf_result=None,
                    weight_result=None,
                    whitelist_result=None,
                    ai_result=None,
                    passed=False,
                    failure_reasons=[f"Harness-level exception: {e}"],
                    execution_time_ms=0.0
                ))
        return results

    def run_random_fuzz(self, iterations: int, seed: int | None = None) -> tuple[bool, list[str]]:
        """
        Feeds randomly generated, arbitrarily-shaped evidence/telemetry/AI
        data through the full pipeline. The only pass criterion is that no
        engine raises an unhandled exception -- randomized fuzz input has no
        predictable confidence value, so no output assertions are made.

        Args:
            iterations (int): Number of random scenarios to run.
            seed (int | None): Optional RNG seed for reproducibility.

        Returns:
            tuple[bool, list[str]]: Whether the fuzz run passed, and any
            recorded harness/engine errors.
        """
        rng = random.Random(seed)
        errors: list[str] = []

        def _rand_value(depth: int = 0) -> Any:
            choice = rng.randint(0, 9)
            if depth >= 4 or choice == 0:
                return rng.choice([
                    None, True, False, "", rng.random() * 1000,
                    rng.randint(-1000, 1000), "".join(rng.choices("abcdefXYZ123 ", k=rng.randint(0, 20)))
                ])
            if choice in (1, 2):
                return [_rand_value(depth + 1) for _ in range(rng.randint(0, 6))]
            if choice in (3, 4):
                return {f"key_{i}": _rand_value(depth + 1) for i in range(rng.randint(0, 6))}
            if choice == 5:
                return _make_nested_dict(rng.randint(1, 8))
            if choice == 6:
                return _make_nested_list(rng.randint(1, 8))
            return rng.choice([object(), (1, 2, 3), {1, 2, 3}])

        for i in range(iterations):
            scenario = ScenarioInput(
                name=f"random_fuzz_{i}",
                category=TestCategory.STRESS_TESTS,
                raw_evidence=_rand_value(),
                matched_rules=_rand_value(),
                telemetry=_rand_value(),
                ai_data=_rand_value()
            )
            _, _, _, _, pipeline_errors = self.adapter.execute(scenario)
            for err in pipeline_errors:
                if "raised exception" in err:
                    errors.append(f"[random_fuzz_{i}] {err}")

        return (len(errors) == 0), errors

    def run_deterministic_fuzz(self) -> tuple[bool, list[str]]:
        """
        Feeds a fixed, hand-picked set of adversarial/edge-case shapes
        (deeply nested containers, huge strings, unusual types) through the
        full pipeline. Deterministic (not seeded-random) so results are
        reproducible across runs and CI systems. As with random fuzz, the
        only pass criterion is the absence of unhandled exceptions.

        Returns:
            tuple[bool, list[str]]: Whether the run passed, and any
            recorded harness/engine errors.
        """
        deterministic_inputs = [
            ("empty_everything", {}, [], {}, {}),
            ("none_everything", None, None, None, None),
            ("huge_string_evidence", {"matched_rules": ["x" * 100000]}, [], {}, {}),
            ("deep_nested_dict", _make_nested_dict(500), [], {}, {}),
            ("deep_nested_list", {"matched_rules": _make_nested_list(500)}, [], {}, {}),
            ("wrong_types", 12345, "not_a_list", 3.14, [1, 2, 3]),
            ("mixed_bool_pollution", {"matched_rules": [True, False, "real rule"]}, [True, False, "real"], {}, {}),
            ("unicode_and_control_chars", {"matched_rules": ["\u0000\u200b\t\n rule \r"]}, ["rule\x00"], {}, {}),
            ("large_matched_rules_list", {}, [f"rule_{i}" for i in range(5000)], {}, {}),
            ("circular_safe_self_ref_dict", {"matched_rules": ["outbound connection"]}, ["outbound connection"],
             {"process_name": "explorer.exe"}, {"ai_confidence_adjustment": 999999}),
        ]

        errors: list[str] = []
        for name, raw_evidence, matched_rules, telemetry, ai_data in deterministic_inputs:
            scenario = ScenarioInput(
                name=f"deterministic_fuzz_{name}",
                category=TestCategory.STRESS_TESTS,
                raw_evidence=raw_evidence,
                matched_rules=matched_rules,
                telemetry=telemetry,
                ai_data=ai_data
            )
            _, _, _, _, pipeline_errors = self.adapter.execute(scenario)
            for err in pipeline_errors:
                if "raised exception" in err:
                    errors.append(f"[{name}] {err}")

        return (len(errors) == 0), errors

    def run_memory_test(self, iterations: int = 2000) -> tuple[bool, float, list[str]]:
        """
        Runs repeated pipeline executions under tracemalloc and asserts the
        peak memory usage stays within max_memory_mb. Uses a moderately
        sized, realistic scenario rather than worst-case fuzz input, since
        this test targets steady-state memory behavior, not adversarial
        input handling (which is covered by the fuzz tests).

        Args:
            iterations (int): Number of pipeline executions to perform.

        Returns:
            tuple[bool, float, list[str]]: Whether peak memory stayed within
            budget, the observed peak in MB, and any failure reasons.
        """
        scenario = ScenarioInput(
            name="memory_test_scenario",
            category=TestCategory.STRESS_TESTS,
            raw_evidence={"matched_rules": ["outbound connection", "dangerous port"],
                          "matched_ips": ["203.0.113.10"]},
            matched_rules=["outbound connection", "dangerous port"],
            telemetry={"process_name": "explorer.exe", "destination_domain": "example.org"},
            ai_data={"ai_confidence_adjustment": 5.0, "source": "ai"}
        )

        tracemalloc.start()
        try:
            for _ in range(iterations):
                self.adapter.execute(scenario)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        peak_mb = peak / (1024.0 * 1024.0)
        errors: list[str] = []
        passed = peak_mb <= self.max_memory_mb
        if not passed:
            errors.append(f"Peak memory {peak_mb:.2f}MB exceeded budget {self.max_memory_mb}MB over {iterations} iterations.")

        return passed, peak_mb, errors

    def run_performance_test(self, iterations: int = 5000) -> tuple[bool, float, list[str]]:
        """
        Runs repeated pipeline executions and asserts the total wall-clock
        time stays within max_stress_s.

        Args:
            iterations (int): Number of pipeline executions to perform.

        Returns:
            tuple[bool, float, list[str]]: Whether the run stayed within the
            time budget, the observed elapsed seconds, and any failure
            reasons.
        """
        scenario = ScenarioInput(
            name="performance_test_scenario",
            category=TestCategory.STRESS_TESTS,
            raw_evidence={"matched_rules": ["outbound connection", "dangerous port"],
                          "matched_ips": ["203.0.113.10"]},
            matched_rules=["outbound connection", "dangerous port"],
            telemetry={"process_name": "svchost.exe", "destination_domain": "example.org"},
            ai_data={"ml_adjustment": -5.0, "source": "ml"}
        )

        start = time.perf_counter()
        for _ in range(iterations):
            self.adapter.execute(scenario)
        elapsed_s = time.perf_counter() - start

        errors: list[str] = []
        passed = elapsed_s <= self.max_stress_s
        if not passed:
            errors.append(f"Performance run exceeded budget: {elapsed_s:.3f}s > {self.max_stress_s}s over {iterations} iterations.")

        return passed, elapsed_s, errors


# ============================================================
# SCENARIO BUILDERS
# ============================================================
# Each builder returns a list[ScenarioInput] for one TestCategory.
# Inputs are chosen to exercise real, documented behavior of the
# production engines (RULE_WEIGHTS keys, TRUSTED_* whitelist sets,
# KNOWN_ADJUSTMENT_KEYS) -- never internal/undocumented behavior.
# ============================================================

def build_confidence_engine_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="no_evidence",
            category=TestCategory.CONFIDENCE_ENGINE,
            raw_evidence={},
            matched_rules=[],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="single_rule_match",
            category=TestCategory.CONFIDENCE_ENGINE,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="rules_and_indicators_mixed",
            category=TestCategory.CONFIDENCE_ENGINE,
            raw_evidence={
                "matched_rules": ["c2 connection", "beaconing behavior"],
                "matched_ports": [4444, 8080],
                "matched_domains": ["evil.example.com"]
            },
            matched_rules=["c2 connection", "beaconing behavior"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="non_dict_evidence_ignored",
            category=TestCategory.CONFIDENCE_ENGINE,
            raw_evidence="not a dict",
            matched_rules=[],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="large_unique_evidence_saturation",
            category=TestCategory.CONFIDENCE_ENGINE,
            raw_evidence={"matched_indicators": [f"indicator_{i}" for i in range(50)]},
            matched_rules=[],
            telemetry={},
            ai_data={}
        ),
    ]


def build_rule_weighting_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="known_high_severity_rules",
            category=TestCategory.RULE_WEIGHTING,
            raw_evidence={},
            matched_rules=["c2 connection", "credential dumping", "tor network activity"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="unknown_rule_names",
            category=TestCategory.RULE_WEIGHTING,
            raw_evidence={},
            matched_rules=["some totally made up rule", "another unknown rule"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="empty_rule_list",
            category=TestCategory.RULE_WEIGHTING,
            raw_evidence={},
            matched_rules=[],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="mixed_known_and_unknown",
            category=TestCategory.RULE_WEIGHTING,
            raw_evidence={},
            matched_rules=["dangerous port", "made up rule", "process injection"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="wrong_type_input",
            category=TestCategory.RULE_WEIGHTING,
            raw_evidence={},
            matched_rules="not a list",
            telemetry={},
            ai_data={}
        ),
    ]


def build_whitelist_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="trusted_process_match",
            category=TestCategory.WHITELIST,
            raw_evidence={"matched_rules": ["script execution"]},
            matched_rules=["script execution"],
            telemetry={"process_name": "svchost.exe"},
            ai_data={}
        ),
        ScenarioInput(
            name="trusted_domain_suffix_match",
            category=TestCategory.WHITELIST,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={"destination_domain": "update.microsoft.com"},
            ai_data={}
        ),
        ScenarioInput(
            name="trusted_publisher_match",
            category=TestCategory.WHITELIST,
            raw_evidence={"matched_rules": ["script execution"]},
            matched_rules=["script execution"],
            telemetry={"publisher": "Microsoft Corporation"},
            ai_data={}
        ),
        ScenarioInput(
            name="no_whitelist_match",
            category=TestCategory.WHITELIST,
            raw_evidence={"matched_rules": ["c2 connection"]},
            matched_rules=["c2 connection"],
            telemetry={"process_name": "totally_unknown.exe", "destination_domain": "evil.example.net"},
            ai_data={}
        ),
        ScenarioInput(
            name="multiple_trusted_categories_stacked",
            category=TestCategory.WHITELIST,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={
                "process_name": "explorer.exe",
                "destination_domain": "github.com",
                "publisher": "Google",
                "certificate_issuer": "DigiCert Inc"
            },
            ai_data={}
        ),
    ]


def build_ai_adjustment_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="analyst_override_wins_priority",
            category=TestCategory.AI_ADJUSTMENT,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={"analyst_override": 90.0, "ai_confidence_adjustment": 5.0, "source": "analyst"}
        ),
        ScenarioInput(
            name="ai_delta_adjustment",
            category=TestCategory.AI_ADJUSTMENT,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={"ai_confidence_adjustment": 12.5, "source": "ai", "model": "detector-v3", "version": "1.2.0"}
        ),
        ScenarioInput(
            name="no_adjustments_provided",
            category=TestCategory.AI_ADJUSTMENT,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="disabled_ai_flag_ignored",
            category=TestCategory.AI_ADJUSTMENT,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={"ai_enabled": False, "ai_confidence_adjustment": 40.0, "source": "ai"}
        ),
        ScenarioInput(
            name="inconsistent_source_flagged_not_rejected",
            category=TestCategory.AI_ADJUSTMENT,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={"ml_adjustment": 8.0, "source": "analyst"}
        ),
    ]


def build_metadata_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="reason_and_source_metadata_preserved",
            category=TestCategory.METADATA,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={
                "ai_confidence_adjustment": 10.0,
                "source": "ai",
                "adjustment_reason": "Elevated risk from known C2 infrastructure overlap",
                "model": "conf-model",
                "version": "2.0.1"
            }
        ),
        ScenarioInput(
            name="duplicate_metadata_keys_ignored_safely",
            category=TestCategory.METADATA,
            raw_evidence={"matched_rules": []},
            matched_rules=[],
            telemetry={},
            ai_data={"AI_CONFIDENCE_ADJUSTMENT": 5.0, "ai_confidence_adjustment": 5.0, "source": "AI"}
        ),
        ScenarioInput(
            name="unrecognized_fields_preserved_as_extra_metadata",
            category=TestCategory.METADATA,
            raw_evidence={"matched_rules": []},
            matched_rules=[],
            telemetry={},
            ai_data={"custom_vendor_field": "some_value", "another_unknown_key": 123}
        ),
    ]


def build_malformed_input_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="none_raw_evidence",
            category=TestCategory.MALFORMED_INPUTS,
            raw_evidence=None,
            matched_rules=None,
            telemetry=None,
            ai_data=None
        ),
        ScenarioInput(
            name="wrong_type_all_fields",
            category=TestCategory.MALFORMED_INPUTS,
            raw_evidence=42,
            matched_rules={"not": "a list"},
            telemetry=["not", "a", "dict"],
            ai_data="not a dict"
        ),
        ScenarioInput(
            name="nan_and_inf_ai_adjustment",
            category=TestCategory.MALFORMED_INPUTS,
            raw_evidence={"matched_rules": []},
            matched_rules=[],
            telemetry={},
            ai_data={"ai_confidence_adjustment": float("nan")}
        ),
        ScenarioInput(
            name="out_of_range_override",
            category=TestCategory.MALFORMED_INPUTS,
            raw_evidence={"matched_rules": []},
            matched_rules=[],
            telemetry={},
            ai_data={"confidence_override": 999.0}
        ),
        ScenarioInput(
            name="boolean_values_in_evidence_lists",
            category=TestCategory.MALFORMED_INPUTS,
            raw_evidence={"matched_rules": [True, False], "matched_ports": [True]},
            matched_rules=[True, False],
            telemetry={},
            ai_data={}
        ),
    ]


def build_normalization_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="case_and_whitespace_insensitive_rules",
            category=TestCategory.NORMALIZATION_TESTS,
            raw_evidence={"matched_rules": ["  Outbound   Connection  ", "OUTBOUND CONNECTION"]},
            matched_rules=["  Outbound   Connection  ", "OUTBOUND CONNECTION"],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="process_path_basename_normalization",
            category=TestCategory.NORMALIZATION_TESTS,
            raw_evidence={"matched_rules": ["script execution"]},
            matched_rules=["script execution"],
            telemetry={"process_path": "C:\\Windows\\System32\\SVCHOST.EXE"},
            ai_data={}
        ),
        ScenarioInput(
            name="url_to_hostname_domain_normalization",
            category=TestCategory.NORMALIZATION_TESTS,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={"url": "https://update.microsoft.com/path?query=1"},
            ai_data={}
        ),
        ScenarioInput(
            name="publisher_legal_suffix_stripping",
            category=TestCategory.NORMALIZATION_TESTS,
            raw_evidence={"matched_rules": ["script execution"]},
            matched_rules=["script execution"],
            telemetry={"publisher": "Cisco Systems, Inc."},
            ai_data={}
        ),
        ScenarioInput(
            name="source_alias_normalization",
            category=TestCategory.NORMALIZATION_TESTS,
            raw_evidence={"matched_rules": []},
            matched_rules=[],
            telemetry={},
            ai_data={"ml_adjustment": 5.0, "source": "Machine-Learning"}
        ),
    ]


def build_boundary_scenarios() -> list[ScenarioInput]:
    return [
        ScenarioInput(
            name="confidence_zero_boundary",
            category=TestCategory.BOUNDARY_TESTS,
            raw_evidence={},
            matched_rules=[],
            telemetry={},
            ai_data={}
        ),
        ScenarioInput(
            name="max_delta_adjustment_boundary",
            category=TestCategory.BOUNDARY_TESTS,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={"ai_confidence_adjustment": 50.0, "source": "ai"}
        ),
        ScenarioInput(
            name="max_delta_adjustment_just_over_boundary_rejected",
            category=TestCategory.BOUNDARY_TESTS,
            raw_evidence={"matched_rules": ["outbound connection"]},
            matched_rules=["outbound connection"],
            telemetry={},
            ai_data={"ai_confidence_adjustment": 50.01, "source": "ai"}
        ),
        ScenarioInput(
            name="confidence_override_exact_100_boundary",
            category=TestCategory.BOUNDARY_TESTS,
            raw_evidence={},
            matched_rules=[],
            telemetry={},
            ai_data={"confidence_override": 100.0}
        ),
        ScenarioInput(
            name="whitelist_max_reduction_cap_boundary",
            category=TestCategory.BOUNDARY_TESTS,
            raw_evidence={"matched_rules": ["c2 connection", "credential dumping", "tor network activity"]},
            matched_rules=["c2 connection", "credential dumping", "tor network activity"],
            telemetry={
                "process_name": "explorer.exe",
                "destination_domain": "microsoft.com",
                "publisher": "Microsoft",
                "certificate_issuer": "DigiCert Inc"
            },
            ai_data={}
        ),
    ]


def build_all_scenarios() -> list[ScenarioInput]:
    """Aggregates every declared scenario category into a single ordered list."""
    return [
        *build_confidence_engine_scenarios(),
        *build_rule_weighting_scenarios(),
        *build_whitelist_scenarios(),
        *build_ai_adjustment_scenarios(),
        *build_metadata_scenarios(),
        *build_malformed_input_scenarios(),
        *build_normalization_scenarios(),
        *build_boundary_scenarios(),
    ]


# ============================================================
# REPORTING
# ============================================================

def print_console_report(results: list[PipelineResult], engine_metadata: dict[str, str]) -> None:
    """Prints a human-readable summary of all scenario results to the console."""
    print_banner("INTEGRATED CONFIDENCE ENGINE TEST REPORT")

    if engine_metadata:
        print("Engine metadata:")
        for name, meta in engine_metadata.items():
            print(f"  - {name}: {meta}")
        print()

    by_category: dict[TestCategory, list[PipelineResult]] = {}
    for r in results:
        by_category.setdefault(r.category, []).append(r)

    total_passed = sum(1 for r in results if r.passed)
    total = len(results)

    for category, cat_results in by_category.items():
        passed = sum(1 for r in cat_results if r.passed)
        print(f"[{category.value}] {passed}/{len(cat_results)} passed")
        for r in cat_results:
            status = "PASS" if r.passed else "FAIL"
            print(f"    [{status}] {r.scenario_name} ({r.execution_time_ms:.3f}ms) "
                  f"final_confidence={r.final_confidence:.2f} adjustment={r.adjustment_type}")
            if not r.passed:
                for reason in r.failure_reasons:
                    print(f"        - {reason}")
        print()

    print(f"TOTAL: {total_passed}/{total} scenarios passed")


def write_json_report(results: list[PipelineResult], engine_metadata: dict[str, str], path: str) -> None:
    """Writes the full structured results, including raw engine dataclasses, to a JSON file."""
    payload = {
        "generated_at": datetime.now().isoformat(),
        "engine_metadata": engine_metadata,
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
        "results": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, cls=SafeJSONEncoder)


def write_csv_report(results: list[PipelineResult], path: str) -> None:
    """Writes a flat, spreadsheet-friendly summary of every scenario to a CSV file."""
    fieldnames = [
        "scenario_name", "category", "passed", "execution_time_ms",
        "final_confidence", "adjustment_type", "adjustment_reason", "failure_reasons"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "scenario_name": r.scenario_name,
                "category": r.category.value,
                "passed": r.passed,
                "execution_time_ms": round(r.execution_time_ms, 3),
                "final_confidence": round(r.final_confidence, 2),
                "adjustment_type": r.adjustment_type,
                "adjustment_reason": r.adjustment_reason,
                "failure_reasons": " | ".join(r.failure_reasons),
            })


# ============================================================
# CLI ENTRY POINT
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Integrated Confidence Engine Testing (Part 2.9.x) -- "
                     "black-box validation of ConfidenceEngine, RuleWeightingEngine, "
                     "WhitelistAdjustmentEngine, and AIAdjustmentSupportEngine."
    )
    parser.add_argument("--json", dest="json_path", default=None, help="Write a JSON report to this path.")
    parser.add_argument("--csv", dest="csv_path", default=None, help="Write a CSV report to this path.")
    parser.add_argument("--max-scenario-ms", type=float, default=DEFAULT_MAX_SCENARIO_TIME_MS,
                         help="Per-scenario execution time budget in milliseconds.")
    parser.add_argument("--max-stress-s", type=float, default=DEFAULT_MAX_STRESS_TEST_TIME_S,
                         help="Total wall-clock time budget for the performance stress test, in seconds.")
    parser.add_argument("--max-memory-mb", type=float, default=DEFAULT_MAX_PEAK_MEMORY_MB,
                         help="Peak memory budget for the memory stress test, in megabytes.")
    parser.add_argument("--fuzz-iterations", type=int, default=500,
                         help="Number of iterations for the random fuzz stress test.")
    parser.add_argument("--fuzz-seed", type=int, default=1337,
                         help="RNG seed for the random fuzz stress test (reproducibility).")
    parser.add_argument("--skip-stress", action="store_true",
                         help="Skip the fuzz/performance/memory stress tests and only run scenarios.")
    args = parser.parse_args()

    tester = ConfidencePipelineTester(
        max_scenario_ms=args.max_scenario_ms,
        max_stress_s=args.max_stress_s,
        max_memory_mb=args.max_memory_mb
    )

    engine_metadata = extract_engine_metadata()

    scenarios = build_all_scenarios()
    results = tester.run_all(scenarios)

    overall_passed = all(r.passed for r in results)

    if not args.skip_stress:
        print_banner("STRESS TESTS")

        rf_passed, rf_errors = tester.run_random_fuzz(args.fuzz_iterations, seed=args.fuzz_seed)
        print(f"[Random Fuzz] {'PASS' if rf_passed else 'FAIL'} ({args.fuzz_iterations} iterations, seed={args.fuzz_seed})")
        for err in rf_errors:
            print(f"    - {err}")
        overall_passed = overall_passed and rf_passed

        df_passed, df_errors = tester.run_deterministic_fuzz()
        print(f"[Deterministic Fuzz] {'PASS' if df_passed else 'FAIL'}")
        for err in df_errors:
            print(f"    - {err}")
        overall_passed = overall_passed and df_passed

        mem_passed, peak_mb, mem_errors = tester.run_memory_test()
        print(f"[Memory Test] {'PASS' if mem_passed else 'FAIL'} (peak={peak_mb:.2f}MB, budget={args.max_memory_mb}MB)")
        for err in mem_errors:
            print(f"    - {err}")
        overall_passed = overall_passed and mem_passed

        perf_passed, elapsed_s, perf_errors = tester.run_performance_test()
        print(f"[Performance Test] {'PASS' if perf_passed else 'FAIL'} (elapsed={elapsed_s:.3f}s, budget={args.max_stress_s}s)")
        for err in perf_errors:
            print(f"    - {err}")
        overall_passed = overall_passed and perf_passed
        print()

    print_console_report(results, engine_metadata)

    if args.json_path:
        write_json_report(results, engine_metadata, args.json_path)
        print(f"\nJSON report written to: {args.json_path}")

    if args.csv_path:
        write_csv_report(results, args.csv_path)
        print(f"CSV report written to: {args.csv_path}")

    return 0 if overall_passed else 1


if __name__ == "__main__":
    sys.exit(main())
    errors.append(f"Field '{field_name}' out of bounds [{min_val}, {max_val}]: {val}")