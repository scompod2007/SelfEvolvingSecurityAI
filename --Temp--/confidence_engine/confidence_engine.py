import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
"""
============================================================
LOGGING CONFIGURATION
============================================================
"""
logger = logging.getLogger(__name__)
"""
============================================================
CONSTANTS
============================================================
"""
MIN_CONFIDENCE: float = 0.0
MAX_CONFIDENCE: float = 100.0

# Mathematical constant for diminishing returns curve.
# Designed such that 1 piece of evidence is ~20%, 3 is ~49%, 10 is ~90%.
EVIDENCE_MULTIPLIER: float = 0.22314

# Confidence Level Thresholds
LEVEL_NONE: str = "None"
LEVEL_VERY_LOW: str = "Very Low"
LEVEL_LOW: str = "Low"
LEVEL_MEDIUM: str = "Medium"
LEVEL_HIGH: str = "High"
LEVEL_VERY_HIGH: str = "Very High"

"""
============================================================
OUTPUT DATACLASS
============================================================
"""
@dataclass(slots=True)
class ConfidenceResult:
    """
    Represents the calculated confidence of a detection event.
    """
    confidence: float
    confidence_level: str
    matched_rule_count: int
    matched_indicator_count: int
    total_unique_evidence: int
    reasons: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

"""
============================================================
CONFIDENCE ENGINE
============================================================
"""
class ConfidenceEngine:
    """
    A stateless, thread-safe engine to calculate confidence percentages
    based strictly on the volume of unique evidence, completely decoupled
    from risk and severity concepts.
    """

    def _extract_values(self, val: Any) -> list[Any]:
        """
        Extracts non-boolean values from a given input, handling lists, sets, and tuples.
        Ignores boolean flags to prevent evidence inflation from derived state.

        Args:
            val (Any): The raw value from an evidence field.

        Returns:
            list[Any]: A list of extracted, non-boolean evidence items.
        """
        extracted = []
        if val is None or val == "" or val == [] or val == {}:
            return extracted
            
        if isinstance(val, (list, set, tuple)):
            for item in val:
                if not isinstance(item, bool) and item is not None and item != "":
                    extracted.append(item)
        elif not isinstance(val, bool):
            extracted.append(val)
            
        return extracted

    def _validate_input(self, raw_evidence: Any) -> tuple[list[Any], list[Any]]:
        """
        Parses raw evidence dictionaries to extract rules and indicators
        from explicitly allowed fields only. Ignores boolean flags and unknown keys.

        Args:
            raw_evidence (Any): The raw evidence data, ideally a dict of detections.

        Returns:
            tuple[list[Any], list[Any]]: A tuple of (rules, indicators).
        """
        rules: list[Any] = []
        indicators: list[Any] = []

        if not isinstance(raw_evidence, dict):
            logger.debug("Input to ConfidenceEngine is not a dictionary. Returning empty evidence.")
            return rules, indicators

        rule_fields = ("matched_rules",)
        
        indicator_fields = (
            "matched_ports",
            "matched_protocols",
            "matched_extensions",
            "matched_registry_keys",
            "matched_processes",
            "matched_hashes",
            "matched_domains",
            "matched_ips",
            "matched_indicators",
        )

        for field_name in rule_fields:
            if field_name in raw_evidence:
                rules.extend(self._extract_values(raw_evidence[field_name]))

        for field_name in indicator_fields:
            if field_name in raw_evidence:
                indicators.extend(self._extract_values(raw_evidence[field_name]))

        return rules, indicators

    def _remove_duplicates(self, items: list[Any]) -> list[str]:
        """
        Removes duplicates from a list of evidence items by standardizing them.

        Args:
            items (list[Any]): A list of potentially duplicate items.

        Returns:
            list[str]: A deduplicated list of standardized string items.
        """
        unique_items = set()
        for item in items:
            try:
                standardized = str(item).strip().lower()
                if standardized:
                    unique_items.add(standardized)
            except (ValueError, TypeError):
                continue

        return sorted(list(unique_items))

    def _count_unique_rules(self, rules: list[str]) -> int:
        """
        Counts the number of unique matched rules.

        Args:
            rules (list[str]): A deduplicated list of rules.

        Returns:
            int: The count of rules.
        """
        return len(rules)

    def _count_unique_indicators(self, indicators: list[str]) -> int:
        """
        Counts the number of unique matched indicators.

        Args:
            indicators (list[str]): A deduplicated list of indicators.

        Returns:
            int: The count of indicators.
        """
        return len(indicators)

    def _calculate_confidence(self, total_evidence: int) -> float:
        """
        Calculates the numerical confidence score using a diminishing returns curve.
        Never exceeds MAX_CONFIDENCE or falls below MIN_CONFIDENCE.

        Args:
            total_evidence (int): The total count of unique rules and indicators.

        Returns:
            float: A confidence percentage clamped between 0.0 and 100.0.
        """
        if total_evidence <= 0:
            return MIN_CONFIDENCE

        try:
            # Formula: 100 * (1 - e^(-k * x))
            raw_confidence = MAX_CONFIDENCE * (1.0 - math.exp(-EVIDENCE_MULTIPLIER * total_evidence))
            clamped_confidence = max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, raw_confidence))
            return float(round(clamped_confidence, 2))
        except (ValueError, TypeError, OverflowError) as e:
            logger.error(f"Error calculating confidence: {e}. Defaulting to MIN_CONFIDENCE.")
            return MIN_CONFIDENCE

    def _get_confidence_level(self, confidence: float) -> str:
        """
        Maps a numerical confidence percentage to a human-readable string level.

        Args:
            confidence (float): The calculated confidence percentage.

        Returns:
            str: The mapped confidence level.
        """
        if confidence <= 0.0:
            return LEVEL_NONE
        if confidence <= 20.0:
            return LEVEL_VERY_LOW
        if confidence <= 40.0:
            return LEVEL_LOW
        if confidence <= 60.0:
            return LEVEL_MEDIUM
        if confidence <= 80.0:
            return LEVEL_HIGH
        return LEVEL_VERY_HIGH

    def calculate(self, raw_evidence: dict[str, Any]) -> ConfidenceResult:
        """
        Orchestrates the confidence calculation pipeline. 
        Extracts, deduplicates, counts evidence, and generates the final result.

        Args:
            raw_evidence (dict[str, Any]): A dictionary containing arbitrary detection data.

        Returns:
            ConfidenceResult: A structured dataclass containing the calculated confidence.
        """
        try:
            raw_rules, raw_indicators = self._validate_input(raw_evidence)

            unique_rules = self._remove_duplicates(raw_rules)
            unique_indicators = self._remove_duplicates(raw_indicators)

            # Global deduplication to ensure indicators do not overlap with rules
            global_indicators = [ind for ind in unique_indicators if ind not in unique_rules]

            rule_count = self._count_unique_rules(unique_rules)
            indicator_count = self._count_unique_indicators(global_indicators)

            total_evidence = rule_count + indicator_count
            confidence_score = self._calculate_confidence(total_evidence)
            confidence_level = self._get_confidence_level(confidence_score)

            reasons: list[str] = []
            if total_evidence > 0:
                reasons.append(
                    f"Confidence evaluated to {confidence_level} ({confidence_score}%) "
                    f"based on {total_evidence} total piece(s) of unique evidence."
                )
                reasons.append(f"Unique rules matched: {rule_count}")
                reasons.append(f"Unique indicators matched: {indicator_count}")
            else:
                reasons.append("Confidence is None (0.0%) due to lack of distinct evidence.")

            return ConfidenceResult(
                confidence=confidence_score,
                confidence_level=confidence_level,
                matched_rule_count=rule_count,
                matched_indicator_count=indicator_count,
                total_unique_evidence=total_evidence,
                reasons=reasons,
                timestamp=datetime.now(timezone.utc)
            )

        except Exception as e:
            logger.exception(f"Unexpected failure during confidence calculation: {e}")
            return ConfidenceResult(
                confidence=MIN_CONFIDENCE,
                confidence_level=LEVEL_NONE,
                matched_rule_count=0,
                matched_indicator_count=0,
                total_unique_evidence=0,
                reasons=["Confidence calculation failed due to an internal error."],
                timestamp=datetime.now(timezone.utc)
            )