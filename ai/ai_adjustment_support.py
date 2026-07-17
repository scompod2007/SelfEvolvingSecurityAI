"""
============================================================
Self-Evolving Security AI
Part 2.9.4 – AI Adjustment Support
============================================================

This module provides a compatibility layer for receiving and safely
applying confidence adjustment recommendations from external AI, ML,
Threat Intelligence, or Analyst systems.
"""

import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS & CONFIGURATION
# ============================================================
MIN_CONFIDENCE: float = 0.0
MAX_CONFIDENCE: float = 100.0
MAX_DELTA_ADJUSTMENT: float = 50.0

KEY_AI_ADJUSTMENT: str = "ai_confidence_adjustment"
KEY_ADJUSTMENT_REASON: str = "adjustment_reason"
KEY_TI_ADJUSTMENT: str = "threat_intelligence_adjustment"
KEY_ML_ADJUSTMENT: str = "ml_adjustment"
KEY_ANALYST_ADJUSTMENT: str = "analyst_adjustment"
KEY_ANALYST_OVERRIDE: str = "analyst_override"
KEY_AI_ENABLED: str = "ai_enabled"
KEY_ML_ENABLED: str = "ml_enabled"
KEY_TI_ENABLED: str = "threat_intelligence_enabled"
KEY_FEEDBACK_ENABLED: str = "feedback_enabled"
KEY_CONFIDENCE_DELTA: str = "confidence_delta"
KEY_CONFIDENCE_OVERRIDE: str = "confidence_override"
KEY_BEHAVIOR_ADJUSTMENT: str = "behavior_adjustment"
KEY_SOURCE: str = "source"
KEY_MODEL: str = "model"
KEY_VERSION: str = "version"
KEY_CONFIDENCE_SCORE: str = "confidence_score"

KNOWN_ADJUSTMENT_KEYS: frozenset[str] = frozenset([
    KEY_AI_ADJUSTMENT,
    KEY_ADJUSTMENT_REASON,
    KEY_TI_ADJUSTMENT,
    KEY_ML_ADJUSTMENT,
    KEY_ANALYST_ADJUSTMENT,
    KEY_ANALYST_OVERRIDE,
    KEY_AI_ENABLED,
    KEY_ML_ENABLED,
    KEY_TI_ENABLED,
    KEY_FEEDBACK_ENABLED,
    KEY_CONFIDENCE_DELTA,
    KEY_CONFIDENCE_OVERRIDE,
    KEY_BEHAVIOR_ADJUSTMENT,
    KEY_SOURCE,
    KEY_MODEL,
    KEY_VERSION,
    KEY_CONFIDENCE_SCORE
])

ADJUSTMENT_PRIORITY: tuple[str, ...] = (
    KEY_ANALYST_OVERRIDE,
    KEY_CONFIDENCE_OVERRIDE,
    KEY_ANALYST_ADJUSTMENT,
    KEY_AI_ADJUSTMENT,
    KEY_ML_ADJUSTMENT,
    KEY_TI_ADJUSTMENT,
    KEY_BEHAVIOR_ADJUSTMENT,
    KEY_CONFIDENCE_DELTA
)

OVERRIDE_KEYS: frozenset[str] = frozenset([
    KEY_ANALYST_OVERRIDE,
    KEY_CONFIDENCE_OVERRIDE
])

DISPLAY_NAMES: dict[str, str] = {
    KEY_ANALYST_OVERRIDE: "Analyst Override",
    KEY_CONFIDENCE_OVERRIDE: "Confidence Override",
    KEY_ANALYST_ADJUSTMENT: "Analyst Adjustment",
    KEY_AI_ADJUSTMENT: "AI Adjustment",
    KEY_ML_ADJUSTMENT: "ML Adjustment",
    KEY_TI_ADJUSTMENT: "Threat Intelligence Adjustment",
    KEY_BEHAVIOR_ADJUSTMENT: "Behavior Adjustment",
    KEY_CONFIDENCE_DELTA: "Confidence Delta",
    "none": "None"
}


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class AIAdjustmentResult:
    """
    Represents the result of applying an external AI or Analyst adjustment
    to an existing confidence score.

    Attributes:
        original_confidence (float): The confidence score before adjustment.
        adjusted_confidence (float): The final confidence score after adjustment.
        confidence_change (float): The mathematical difference applied.
        adjustment_applied (bool): Whether any adjustment was actually applied.
        adjustment_source (str): The reported source of the adjustment.
        adjustment_type (str): The human-readable category of adjustment applied.
        adjustment_type_internal (str): The internal key of the adjustment applied.
        adjustment_reason (str): The provided reason for the adjustment.
        model_name (str): The name of the model that provided the adjustment.
        model_version (str): The version of the model that provided the adjustment.
        analyst_override_used (bool): True if an analyst override was applied.
        ai_adjustment_used (bool): True if an AI delta was applied.
        ml_adjustment_used (bool): True if an ML delta was applied.
        threat_intelligence_used (bool): True if a TI delta was applied.
        behavior_adjustment_used (bool): True if a behavior delta was applied.
        override_used (bool): True if an absolute override was applied.
        final_adjustment_value (float): The raw value of the applied adjustment.
        ignored_invalid_adjustments (int): Count of invalid adjustment values ignored.
        ignored_extra_fields (int): Count of unrecognized fields ignored.
        ignored_duplicate_adjustments (int): Count of duplicate adjustment keys ignored.
        ignored_duplicate_metadata (int): Count of duplicate metadata keys ignored.
        override_origin (str): The original key used for the override.
        source_consistency (bool): True if the source matches the adjustment type.
        extra_metadata (dict[str, Any]): Unrecognized metadata fields preserved for future use.
        reasons (list[str]): Human-readable explanations of the engine's decisions.
        timestamp (datetime): The UTC timestamp of the evaluation.
    """
    original_confidence: float
    adjusted_confidence: float
    confidence_change: float
    adjustment_applied: bool
    adjustment_source: str
    adjustment_type: str
    adjustment_type_internal: str
    adjustment_reason: str
    model_name: str
    model_version: str
    analyst_override_used: bool
    ai_adjustment_used: bool
    ml_adjustment_used: bool
    threat_intelligence_used: bool
    behavior_adjustment_used: bool
    override_used: bool
    final_adjustment_value: float
    ignored_invalid_adjustments: int
    ignored_extra_fields: int
    ignored_duplicate_adjustments: int
    ignored_duplicate_metadata: int
    override_origin: str
    source_consistency: bool
    extra_metadata: dict[str, Any]
    reasons: list[str]
    timestamp: datetime


# ============================================================
# COMPATIBILITY & SUPPORT ENGINE
# ============================================================
class AIAdjustmentSupportEngine:
    """
    Stateless, thread-safe engine for safely applying external confidence
    adjustments based on a strict priority hierarchy.
    """

    def _validate_confidence(self, conf: Any) -> float:
        """
        Validates and sanitizes a confidence score.

        Args:
            conf (Any): The raw confidence score.

        Returns:
            float: A safe, clamped float rounded to two decimal places.
        """
        try:
            val = float(conf)
            if math.isnan(val) or math.isinf(val):
                return MIN_CONFIDENCE
            return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, val)), 2)
        except (ValueError, TypeError):
            return MIN_CONFIDENCE

    def _validate_adjustments(self, ai_data: Any) -> dict[str, Any]:
        """
        Ensures the incoming adjustment data is a valid dictionary.

        Args:
            ai_data (Any): The raw adjustment data.

        Returns:
            dict[str, Any]: A valid dictionary, empty if input was invalid.
        """
        if isinstance(ai_data, Mapping):
            return dict(ai_data)
        return {}

    def _parse_bool(self, val: Any) -> bool:
        """
        Safely parses various representations of boolean values.
        Defaults to True for unknown values to fail open.

        Args:
            val (Any): The value to parse.

        Returns:
            bool: The parsed boolean value.
        """
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return val != 0
        if isinstance(val, str):
            norm = val.strip().lower()
            if norm in ("false", "no", "0", "off"):
                return False
            if norm in ("true", "yes", "1", "on"):
                return True
            logger.debug("Unknown boolean value encountered: %s. Defaulting to True.", val)
        return True

    def _normalize_source(self, source: str) -> str:
        """
        Normalizes the source string to a known set of values.

        Args:
            source (str): The raw source string.

        Returns:
            str: The normalized source string.
        """
        if not source:
            return "Unknown"
            
        norm = str(source).lower().replace("-", " ").replace("_", " ")
        norm = " ".join(norm.split())
        
        if norm in ("ai", "artificial intelligence"):
            return "AI"
        if norm in ("ml", "machine learning"):
            return "ML"
        if norm in ("threatintel", "threat intelligence", "threat feed", "ti", "ti feed"):
            return "Threat Intelligence"
        if norm in ("behavior", "behaviour", "behavioral", "behavioural"):
            return "Behavior"
        if norm == "analyst":
            return "Analyst"
        if norm == "cloud":
            return "Cloud"
        if norm == "vendor":
            return "Vendor"
        if norm == "unknown":
            return "Unknown"
            
        return " ".join(str(source).split()).title()

    def _normalize_metadata(self, key: str, val: Any) -> str:
        """
        Normalizes metadata strings, collapsing whitespace while preserving formatting.

        Args:
            key (str): The metadata key.
            val (Any): The raw metadata value.

        Returns:
            str: The normalized metadata string.
        """
        if val is None:
            return ""
        return " ".join(str(val).split())

    def _get_display_name(self, adjustment_type: str) -> str:
        """
        Retrieves the human-readable display name for an adjustment type.

        Args:
            adjustment_type (str): The internal adjustment key.

        Returns:
            str: The display name.
        """
        if adjustment_type == "none":
            return "None"
        return DISPLAY_NAMES.get(adjustment_type, adjustment_type)

    def _extract_adjustments(self, valid_data: dict[str, Any]) -> tuple[dict[str, float], dict[str, str], int, int, int, int, dict[str, Any], str]:
        """
        Extracts valid numerical adjustments and metadata strings, counting ignored fields.
        Respects enable/disable flags and preserves the first valid metadata value.

        Args:
            valid_data (dict[str, Any]): The validated input dictionary.

        Returns:
            tuple: Extracted numerical adjustments, extracted strings, invalid value count, 
                   extra field count, duplicate count, duplicate metadata count, 
                   extra metadata, override origin.
        """
        adjustments: dict[str, float] = {}
        metadata: dict[str, str] = {}
        extra_metadata: dict[str, Any] = {}
        invalid_count = 0
        extra_count = 0
        dup_count = 0
        dup_meta_count = 0
        disabled_count = 0
        override_origin = ""
        seen_keys = set()

        ai_enabled = True
        ml_enabled = True
        ti_enabled = True
        feedback_enabled = True
        
        for k, v in valid_data.items():
            nk = str(k).strip().lower()
            if nk == KEY_AI_ENABLED:
                ai_enabled = self._parse_bool(v)
            elif nk == KEY_ML_ENABLED:
                ml_enabled = self._parse_bool(v)
            elif nk == KEY_TI_ENABLED:
                ti_enabled = self._parse_bool(v)
            elif nk == KEY_FEEDBACK_ENABLED:
                feedback_enabled = self._parse_bool(v)

        for key, value in valid_data.items():
            normalized_key = str(key).strip().lower()

            if normalized_key.endswith("enabled"):
                continue

            if normalized_key in seen_keys:
                if normalized_key in (KEY_ADJUSTMENT_REASON, KEY_SOURCE, KEY_MODEL, KEY_VERSION):
                    dup_meta_count += 1
                else:
                    dup_count += 1
                continue
            seen_keys.add(normalized_key)

            if normalized_key not in KNOWN_ADJUSTMENT_KEYS:
                extra_metadata[key] = value
                extra_count += 1
                continue

            if value is None:
                continue

            if normalized_key in (KEY_ADJUSTMENT_REASON, KEY_SOURCE, KEY_MODEL, KEY_VERSION):
                metadata[normalized_key] = self._normalize_metadata(normalized_key, value)
                continue

            if normalized_key == KEY_AI_ADJUSTMENT and not ai_enabled:
                disabled_count += 1
                continue
            if normalized_key == KEY_ML_ADJUSTMENT and not ml_enabled:
                disabled_count += 1
                continue
            if normalized_key == KEY_TI_ADJUSTMENT and not ti_enabled:
                disabled_count += 1
                continue
            if normalized_key in (KEY_ANALYST_ADJUSTMENT, KEY_BEHAVIOR_ADJUSTMENT) and not feedback_enabled:
                disabled_count += 1
                continue

            try:
                float_val = float(value)
                if math.isnan(float_val) or math.isinf(float_val):
                    invalid_count += 1
                    continue

                if normalized_key in OVERRIDE_KEYS or normalized_key == KEY_CONFIDENCE_SCORE:
                    if float_val < MIN_CONFIDENCE or float_val > MAX_CONFIDENCE:
                        invalid_count += 1
                        continue
                else:
                    if float_val < -MAX_DELTA_ADJUSTMENT or float_val > MAX_DELTA_ADJUSTMENT:
                        invalid_count += 1
                        continue

                adjustments[normalized_key] = round(float_val, 2)
            except (ValueError, TypeError):
                invalid_count += 1

        if KEY_CONFIDENCE_SCORE in adjustments:
            if KEY_CONFIDENCE_OVERRIDE not in adjustments:
                adjustments[KEY_CONFIDENCE_OVERRIDE] = adjustments[KEY_CONFIDENCE_SCORE]
                override_origin = "confidence_score (alias)"
            del adjustments[KEY_CONFIDENCE_SCORE]

        if KEY_CONFIDENCE_OVERRIDE in adjustments and not override_origin:
            override_origin = "confidence_override"

        if invalid_count > 0:
            logger.debug("Ignored %d invalid adjustment(s).", invalid_count)
        if dup_count > 0:
            logger.debug("Ignored %d duplicate adjustment(s).", dup_count)
        if dup_meta_count > 0:
            logger.debug("Ignored %d duplicate metadata field(s).", dup_meta_count)
        if disabled_count > 0:
            logger.debug("Ignored %d disabled adjustment(s).", disabled_count)
        if extra_count > 0:
            logger.debug("Ignored %d extra field(s).", extra_count)

        return adjustments, metadata, invalid_count, extra_count, dup_count, dup_meta_count, extra_metadata, override_origin

    def _determine_adjustment_type(self, adjustments: dict[str, float]) -> tuple[str, float, bool]:
        """
        Determines the highest priority adjustment to apply.

        Args:
            adjustments (dict[str, float]): The extracted valid numerical adjustments.

        Returns:
            tuple[str, float, bool]: The adjustment type, the value, and whether it is an override.
        """
        for key in ADJUSTMENT_PRIORITY:
            if key in adjustments:
                is_override = key in OVERRIDE_KEYS
                return key, adjustments[key], is_override
                
        return "none", 0.0, False

    def _check_source_consistency(self, adj_type: str, source_str: str) -> bool:
        """
        Validates that the adjustment type logically matches the reported source.

        Args:
            adj_type (str): The applied adjustment type.
            source_str (str): The normalized source string.

        Returns:
            bool: True if consistent or generic, False if explicitly inconsistent.
        """
        if adj_type == "none" or source_str in ("Unknown", "Vendor", "Cloud"):
            return True
            
        expected_source = ""
        if adj_type == KEY_AI_ADJUSTMENT:
            expected_source = "AI"
        elif adj_type == KEY_ML_ADJUSTMENT:
            expected_source = "ML"
        elif adj_type == KEY_TI_ADJUSTMENT:
            expected_source = "Threat Intelligence"
        elif adj_type == KEY_BEHAVIOR_ADJUSTMENT:
            expected_source = "Behavior"
        elif adj_type in (KEY_ANALYST_OVERRIDE, KEY_ANALYST_ADJUSTMENT):
            expected_source = "Analyst"
            
        if expected_source and source_str != expected_source:
            return False
            
        return True

    def _clamp_confidence(self, conf: float) -> float:
        """
        Clamps a confidence score strictly between MIN_CONFIDENCE and MAX_CONFIDENCE.

        Args:
            conf (float): The calculated confidence score.

        Returns:
            float: The clamped score rounded to two decimal places.
        """
        return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, conf)), 2)

    def _apply_override(self, override_value: float) -> float:
        """
        Applies an absolute override to the confidence score.

        Args:
            override_value (float): The absolute value to set.

        Returns:
            float: The clamped new confidence score.
        """
        return self._clamp_confidence(override_value)

    def _apply_delta(self, current_confidence: float, delta_value: float) -> float:
        """
        Applies a relative delta to the current confidence score.

        Args:
            current_confidence (float): The existing confidence score.
            delta_value (float): The relative change to apply.

        Returns:
            float: The clamped new confidence score.
        """
        return self._clamp_confidence(current_confidence + delta_value)

    def _build_reasons(
        self,
        original: float,
        adjusted: float,
        adj_type: str,
        adj_value: float,
        is_override: bool,
        reason_str: str,
        source_str: str,
        is_consistent: bool,
        invalid_count: int,
        extra_count: int,
        dup_count: int,
        dup_meta_count: int
    ) -> list[str]:
        """
        Constructs human-readable explanations for the adjustment process.

        Args:
            original (float): Original confidence score.
            adjusted (float): Adjusted confidence score.
            adj_type (str): The type of adjustment applied.
            adj_value (float): The raw value of the adjustment.
            is_override (bool): Whether the adjustment was an absolute override.
            reason_str (str): The externally provided reason.
            source_str (str): The externally provided source.
            is_consistent (bool): Whether the source matches the adjustment type.
            invalid_count (int): Number of invalid adjustments ignored.
            extra_count (int): Number of extra fields ignored.
            dup_count (int): Number of duplicate adjustment keys ignored.
            dup_meta_count (int): Number of duplicate metadata keys ignored.

        Returns:
            list[str]: A list of structured reason strings.
        """
        reasons = []
        
        if adj_type == "none":
            reasons.append("No valid AI or Analyst adjustments were provided. Confidence remains unchanged.")
        else:
            action = "Overrode" if is_override else "Adjusted"
            display_type = self._get_display_name(adj_type)
            reasons.append(f"{action} confidence from {original:.2f} to {adjusted:.2f}.")
            reasons.append(f"Applied highest priority adjustment: {display_type} ({adj_value:.2f}).")
            
            if source_str:
                reasons.append(f"Adjustment source: {source_str}.")
            if not is_consistent:
                reasons.append("Adjustment type does not match reported source.")
            if reason_str:
                reasons.append(f"Provided reason: {reason_str}.")

        if invalid_count > 0:
            reasons.append(f"Safely ignored {invalid_count} invalid numerical adjustment(s).")
        if extra_count > 0:
            reasons.append(f"Safely ignored {extra_count} unrecognized field(s).")
        if dup_count > 0:
            reasons.append(f"Safely ignored {dup_count} duplicate adjustment key(s).")
        if dup_meta_count > 0:
            reasons.append(f"Safely ignored {dup_meta_count} duplicate metadata field(s).")

        return reasons

    def _generate_output(
        self,
        original: float,
        adjusted: float,
        adj_type: str,
        adj_value: float,
        is_override: bool,
        metadata: dict[str, str],
        invalid_count: int,
        extra_count: int,
        dup_count: int,
        dup_meta_count: int,
        extra_metadata: dict[str, Any],
        override_origin: str,
        is_consistent: bool,
        reasons: list[str]
    ) -> AIAdjustmentResult:
        """
        Constructs the final AIAdjustmentResult dataclass.

        Args:
            original (float): Original confidence score.
            adjusted (float): Adjusted confidence score.
            adj_type (str): The type of adjustment applied.
            adj_value (float): The raw value of the adjustment.
            is_override (bool): Whether the adjustment was an absolute override.
            metadata (dict[str, str]): Extracted metadata strings.
            invalid_count (int): Number of invalid adjustments ignored.
            extra_count (int): Number of extra fields ignored.
            dup_count (int): Number of duplicate adjustment keys ignored.
            dup_meta_count (int): Number of duplicate metadata keys ignored.
            extra_metadata (dict[str, Any]): Unrecognized metadata fields preserved.
            override_origin (str): The original key used for the override.
            is_consistent (bool): Whether the source matches the adjustment type.
            reasons (list[str]): Explanations of the engine's decisions.

        Returns:
            AIAdjustmentResult: The populated result object.
        """
        change = round(adjusted - original, 2)
        applied = adj_type != "none"
        source = self._normalize_source(metadata.get(KEY_SOURCE, ""))
        display_type = self._get_display_name(adj_type)

        return AIAdjustmentResult(
            original_confidence=original,
            adjusted_confidence=adjusted,
            confidence_change=change,
            adjustment_applied=applied,
            adjustment_source=source,
            adjustment_type=display_type,
            adjustment_type_internal=adj_type,
            adjustment_reason=metadata.get(KEY_ADJUSTMENT_REASON, "No reason provided"),
            model_name=metadata.get(KEY_MODEL, "Unknown"),
            model_version=metadata.get(KEY_VERSION, "Unknown"),
            analyst_override_used=(adj_type == KEY_ANALYST_OVERRIDE),
            ai_adjustment_used=(adj_type == KEY_AI_ADJUSTMENT),
            ml_adjustment_used=(adj_type == KEY_ML_ADJUSTMENT),
            threat_intelligence_used=(adj_type == KEY_TI_ADJUSTMENT),
            behavior_adjustment_used=(adj_type == KEY_BEHAVIOR_ADJUSTMENT),
            override_used=is_override,
            final_adjustment_value=adj_value,
            ignored_invalid_adjustments=invalid_count,
            ignored_extra_fields=extra_count,
            ignored_duplicate_adjustments=dup_count,
            ignored_duplicate_metadata=dup_meta_count,
            override_origin=override_origin,
            source_consistency=is_consistent,
            extra_metadata=extra_metadata,
            reasons=reasons,
            timestamp=datetime.now(timezone.utc)
        )

    def adjust(self, current_confidence: float, ai_data: dict[str, Any]) -> AIAdjustmentResult:
        """
        Evaluates external adjustment recommendations and safely applies the highest
        priority valid adjustment to the confidence score.

        Args:
            current_confidence (float): The previously calculated confidence score.
            ai_data (dict[str, Any]): The dictionary containing optional adjustments.

        Returns:
            AIAdjustmentResult: The result containing the adjusted confidence and metadata.
        """
        try:
            original_conf = self._validate_confidence(current_confidence)
            valid_data = self._validate_adjustments(ai_data)
            
            (adjustments, metadata, invalid_count, extra_count, 
             dup_count, dup_meta_count, extra_metadata, override_origin) = self._extract_adjustments(valid_data)
            
            adj_type, adj_value, is_override = self._determine_adjustment_type(adjustments)

            if adj_type == "none":
                adjusted_conf = original_conf
            elif is_override:
                adjusted_conf = self._apply_override(adj_value)
            else:
                adjusted_conf = self._apply_delta(original_conf, adj_value)

            source_str = self._normalize_source(metadata.get(KEY_SOURCE, ""))
            is_consistent = self._check_source_consistency(adj_type, source_str)

            reasons = self._build_reasons(
                original=original_conf,
                adjusted=adjusted_conf,
                adj_type=adj_type,
                adj_value=adj_value,
                is_override=is_override,
                reason_str=metadata.get(KEY_ADJUSTMENT_REASON, ""),
                source_str=source_str,
                is_consistent=is_consistent,
                invalid_count=invalid_count,
                extra_count=extra_count,
                dup_count=dup_count,
                dup_meta_count=dup_meta_count
            )

            return self._generate_output(
                original=original_conf,
                adjusted=adjusted_conf,
                adj_type=adj_type,
                adj_value=adj_value,
                is_override=is_override,
                metadata=metadata,
                invalid_count=invalid_count,
                extra_count=extra_count,
                dup_count=dup_count,
                dup_meta_count=dup_meta_count,
                extra_metadata=extra_metadata,
                override_origin=override_origin,
                is_consistent=is_consistent,
                reasons=reasons
            )

        except Exception as e:
            logger.exception("Unexpected error in AIAdjustmentSupportEngine: %s", e)
            safe_conf = self._validate_confidence(current_confidence)
            return self._generate_output(
                original=safe_conf,
                adjusted=safe_conf,
                adj_type="none",
                adj_value=0.0,
                is_override=False,
                metadata={KEY_ADJUSTMENT_REASON: "Engine encountered an internal error."},
                invalid_count=0,
                extra_count=0,
                dup_count=0,
                dup_meta_count=0,
                extra_metadata={},
                override_origin="",
                is_consistent=True,
                reasons=["AI Adjustment failed due to an internal error. Confidence unchanged."]
            )