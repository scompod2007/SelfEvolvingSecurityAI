"""
============================================================
Self-Evolving Security AI
Part 2.8.7 - Final Severity Decision
============================================================

This module converts a final accumulated risk score into a 
standardized security severity level. It acts strictly as a 
classification engine and does not perform threat detection or 
risk weighting.

It is designed to be highly performant (O(1) classification), 
stateless, thread-safe, and robust against malformed inputs.
Future AI learning hooks are included as placeholders for 
subsequent architectural phases.
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# ENGINE METADATA
# ============================================================
MODULE_NAME = "SeverityDecisionEngine"
ENGINE_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"


# ============================================================
# SEVERITY LEVELS
# ============================================================
class SeverityLevel(IntEnum):
    """
    Standardized security severity levels.
    Implemented as an IntEnum to allow easy comparative logic
    (e.g., SeverityLevel.CRITICAL > SeverityLevel.HIGH).
    """
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    def __str__(self) -> str:
        return self.name


# ============================================================
# IMMUTABLE CONFIGURATIONS
# ============================================================
@dataclass(slots=True, frozen=True)
class SeverityThresholds:
    """
    Immutable configuration defining the minimum risk score 
    required to achieve each severity level.
    """
    info: float = 0.0
    low: float = 10.0
    medium: float = 25.0
    high: float = 50.0
    critical: float = 75.0


@dataclass(slots=True, frozen=True)
class SeverityConfidenceConfig:
    """
    Immutable configuration defining the baseline confidence 
    associated with each severity classification decision.
    """
    info: float = 99.0
    low: float = 95.0
    medium: float = 90.0
    high: float = 85.0
    critical: float = 80.0


# ============================================================
# RESULT OBJECT
# ============================================================
@dataclass(slots=True)
class SeverityDecisionResult:
    """
    Represents the final classification of an event's severity.
    Designed to be future-proof and compatible with downstream 
    incident response orchestration.
    """
    severity: SeverityLevel
    risk_score: float
    threshold_used: float
    reason: str
    confidence: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    module_name: str = MODULE_NAME
    engine_version: str = ENGINE_VERSION
    rule_version: str = RULE_VERSION


# ============================================================
# ENGINE
# ============================================================
class SeverityDecisionEngine:
    """
    Stateless, thread-safe engine for converting numerical risk 
    scores into categorical severity levels.

    This engine operates in O(1) time and is built to handle 
    millions of telemetry events safely without memory leaks 
    or unexpected exceptions.
    """

    def __init__(
        self, 
        thresholds: SeverityThresholds | None = None,
        confidence_config: SeverityConfidenceConfig | None = None
    ) -> None:
        """
        Initializes the SeverityDecisionEngine with optional custom configurations.

        Args:
            thresholds (SeverityThresholds | None): Custom threshold boundaries.
            confidence_config (SeverityConfidenceConfig | None): Custom confidence baselines.
        """
        self.thresholds = thresholds or SeverityThresholds()
        self.confidence_config = confidence_config or SeverityConfidenceConfig()

    def _validate_score(self, score: Any) -> float | None:
        """
        Validates the input score, ensuring it is a finite number.
        Safely handles invalid types, negative numbers, NaNs, and Infinities.

        Args:
            score (Any): The raw risk score input.

        Returns:
            float | None: A validated float clamped at a minimum of 0.0, 
                          or None if the input is completely invalid.
        """
        if score is None:
            logger.debug("Received None as risk score.")
            return None

        try:
            parsed_score = float(score)
        except (ValueError, TypeError):
            logger.debug(f"Received invalid type for risk score: {type(score)}")
            return None

        if math.isnan(parsed_score) or math.isinf(parsed_score):
            logger.debug(f"Received non-finite risk score: {parsed_score}")
            return None

        # Clamp negative values to 0.0 as risk scores cannot be negative
        if parsed_score < 0.0:
            logger.debug(f"Received negative risk score ({parsed_score}). Clamping to 0.0.")
            return 0.0

        return parsed_score

    def _evaluate_threshold(
        self, 
        score: float
    ) -> tuple[SeverityLevel, float, str, float]:
        """
        Classifies the valid score against configured thresholds.
        Evaluates from highest to lowest to ensure O(1) short-circuiting.

        Args:
            score (float): The validated, finite risk score.

        Returns:
            tuple: (SeverityLevel, threshold_used, reason, confidence)
        """
        if score >= self.thresholds.critical:
            return (
                SeverityLevel.CRITICAL,
                self.thresholds.critical,
                f"Risk score ({score:.2f}) exceeds CRITICAL threshold ({self.thresholds.critical}).",
                self.confidence_config.critical
            )
            
        if score >= self.thresholds.high:
            return (
                SeverityLevel.HIGH,
                self.thresholds.high,
                f"Risk score ({score:.2f}) exceeds HIGH threshold ({self.thresholds.high}).",
                self.confidence_config.high
            )
            
        if score >= self.thresholds.medium:
            return (
                SeverityLevel.MEDIUM,
                self.thresholds.medium,
                f"Risk score ({score:.2f}) exceeds MEDIUM threshold ({self.thresholds.medium}).",
                self.confidence_config.medium
            )
            
        if score >= self.thresholds.low:
            return (
                SeverityLevel.LOW,
                self.thresholds.low,
                f"Risk score ({score:.2f}) exceeds LOW threshold ({self.thresholds.low}).",
                self.confidence_config.low
            )

        return (
            SeverityLevel.INFO,
            self.thresholds.info,
            f"Risk score ({score:.2f}) is below all alert thresholds.",
            self.confidence_config.info
        )

    # ============================================================
    # FUTURE AI EXTENSION HOOKS
    # ============================================================

    def _adjust_thresholds(self) -> SeverityThresholds:
        """
        Placeholder for future dynamic threshold tuning.
        
        TODO: Implement AI-driven threshold adjustment based on global 
        alert volume, analyst fatigue indicators, and false-positive rates.
        """
        return self.thresholds

    def _apply_adaptive_model(self, score: float, context: dict[str, Any]) -> float:
        """
        Placeholder for future adaptive score weighting.
        
        TODO: Implement machine learning model to adjust the risk score 
        based on real-time event context and historical analyst feedback.
        """
        return score

    def _apply_behavior_profile(self, score: float, user_entity: str) -> float:
        """
        Placeholder for future User and Entity Behavior Analytics (UEBA).
        
        TODO: Implement deviation checks against behavioral baselines 
        to raise or lower the severity based on historical norms.
        """
        return score

    def _apply_environment_profile(self, score: float, asset_criticality: str) -> float:
        """
        Placeholder for future environmental context integration.
        
        TODO: Implement asset-based risk scaling (e.g., automatically 
        escalating severity if the target is a Domain Controller or VIP).
        """
        return score

    # ============================================================
    # MAIN EVALUATION API
    # ============================================================

    def evaluate(self, risk_score: Any) -> SeverityDecisionResult:
        """
        Evaluates a raw risk score and classifies it into a final security severity.

        Args:
            risk_score (Any): The numerical risk score to classify.

        Returns:
            SeverityDecisionResult: The final structured decision outcome.
        """
        # Validate Input
        valid_score = self._validate_score(risk_score)
        
        # Handle Fail-Safe Conditions
        if valid_score is None:
            logger.warning(
                "Invalid risk score provided to SeverityDecisionEngine. Defaulting to INFO."
            )
            return SeverityDecisionResult(
                severity=SeverityLevel.INFO,
                risk_score=0.0,
                threshold_used=self.thresholds.info,
                reason="Defaulted to INFO due to malformed, missing, or invalid risk score.",
                confidence=self.confidence_config.info
            )

        # AI Hooks (Currently passthrough placeholders)
        # In the future, these would modify the score based on telemetry context
        # adjusted_score = self._apply_adaptive_model(valid_score, context={})
        
        # Core Classification Logic
        severity, threshold_used, reason, confidence = self._evaluate_threshold(valid_score)

        return SeverityDecisionResult(
            severity=severity,
            risk_score=valid_score,
            threshold_used=threshold_used,
            reason=reason,
            confidence=confidence
        )