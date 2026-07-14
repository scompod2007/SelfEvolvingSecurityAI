"""
============================================================
Self-Evolving Security AI
Part 2.8.8 - Severity Metadata
============================================================

This module is responsible for aggregating, organizing, and 
structuring the outputs from all previous detection and scoring 
engines into a final, standardized metadata object.

It performs no threat detection, risk calculation, or severity 
assignment. It strictly adheres to the Single Responsibility Principle,
acting as the final reporting layer before the data is consumed by 
incident response pipelines, dashboards, alerting systems, and 
downstream AI learning models.

Designed to be highly performant, stateless, thread-safe, and 
resilient against malformed telemetry.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# ENGINE METADATA CONSTANTS
# ============================================================
MODULE_NAME = "SeverityMetadataBuilder"
ENGINE_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"
METADATA_VERSION = "1.0.0"


# ============================================================
# METADATA RESULT OBJECT
# ============================================================
@dataclass(slots=True)
class SeverityMetadata:
    """
    Standardized metadata object containing the complete, 
    aggregated context of a security severity decision.
    
    This object is the universal contract between the detection 
    engines and downstream consumers (SIEM, AI, Dashboards).
    """
    # Core Fields
    severity: str
    risk_score: float
    confidence: float
    
    # Context & Explanations
    reasons: list[str]
    matched_indicators: list[str]
    matched_rules: list[str]
    severity_reason: str
    summary: str
    
    # Event Identifiers
    event_type: str
    event_id: str
    telemetry_source: str
    timestamp: datetime
    
    # Risk Distribution
    base_risk: float
    event_weight: float  # Synonymous with weight_added
    final_risk: float
    severity_threshold: float
    
    # Indicator Statistics
    total_indicator_count: int
    total_rule_count: int
    highest_indicator_score: float
    highest_indicator_name: str
    
    # Classification Metadata
    classification_method: str
    decision_source: str
    pipeline_stage: str
    analysis_duration_ms: float
    
    # Engine & Versioning Context
    module_name: str
    engine_version: str
    rule_version: str
    metadata_version: str
    analysis_id: str


# ============================================================
# METADATA BUILDER ENGINE
# ============================================================
class SeverityMetadataBuilder:
    """
    Stateless, high-performance engine for constructing standardized 
    SeverityMetadata objects from disparate detection outputs.
    
    Operates in O(n) time where n is the number of indicators/rules.
    Guarantees no exceptions are raised during the building process.
    """

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Safely extracts a float value."""
        if value is None:
            return default
        try:
            val = float(value)
            return val if not (val != val or val == float('inf') or val == float('-inf')) else default
        except (ValueError, TypeError):
            return default

    def _safe_string(self, value: Any, default: str = "UNKNOWN") -> str:
        """Safely extracts a string value."""
        if not value:
            return default
        return str(value).strip()

    def _deduplicate_list(self, items: Sequence[Any] | None) -> list[str]:
        """
        Safely converts an iterable to a list of strings, removing 
        duplicates and empty values while preserving order (O(n)).
        """
        if not items:
            return []
        return list(dict.fromkeys(str(i).strip() for i in items if i))

    def _extract_highest_indicator(
        self, 
        indicators: Mapping[str, float] | Sequence[str] | None
    ) -> tuple[list[str], str, float]:
        """
        Extracts indicator names, the highest scoring indicator, and its score.
        Supports both dicts (name -> score) and flat lists.
        """
        if not indicators:
            return [], "None", 0.0

        if isinstance(indicators, dict):
            if not indicators:
                return [], "None", 0.0
            
            # Find the indicator with the highest score
            highest_name = max(indicators, key=lambda k: self._safe_float(indicators[k]))
            highest_score = self._safe_float(indicators[highest_name])
            
            names_list = self._deduplicate_list(list(indicators.keys()))
            return names_list, str(highest_name).strip(), highest_score

        # Fallback if a flat list is provided instead of a scoring mapping
        names_list = self._deduplicate_list(indicators)
        highest_name = names_list[0] if names_list else "None"
        return names_list, highest_name, 0.0

    def _generate_summary(self, severity: str, indicators: list[str]) -> str:
        """
        Automatically generates a human-readable summary narrative 
        explaining the severity decision context.
        """
        if not indicators:
            return (
                f"{severity.capitalize()} severity assigned based on base risk "
                "and event weighting, with no specific high-risk indicators flagged."
            )

        # Select top indicators for the narrative (up to 3)
        top_indicators = [ind.lower() for ind in indicators[:3]]
        
        if len(top_indicators) == 1:
            ind_text = top_indicators[0]
        elif len(top_indicators) == 2:
            ind_text = f"{top_indicators[0]} and {top_indicators[1]}"
        else:
            ind_text = f"{top_indicators[0]}, {top_indicators[1]}, and {top_indicators[2]}"
            
        suffix = " among other factors" if len(indicators) > 3 else ""

        return (
            f"{severity.capitalize()} severity assigned because the event contains "
            f"high-risk indicators including {ind_text}{suffix}."
        )

    # ============================================================
    # FUTURE AI EXTENSION HOOKS
    # ============================================================

    def _prepare_training_metadata(self, metadata: SeverityMetadata) -> dict[str, Any]:
        """
        Placeholder hook.
        TODO: Format and anonymize the metadata object specifically for 
        ingestion into the AI model training pipeline.
        """
        return {}

    def _prepare_feedback_metadata(self, metadata: SeverityMetadata) -> dict[str, Any]:
        """
        Placeholder hook.
        TODO: Prepare structure for SOC analysts to provide reinforcement 
        learning feedback (e.g., True Positive / False Positive tags).
        """
        return {}

    def _prepare_explanation(self, metadata: SeverityMetadata) -> dict[str, Any]:
        """
        Placeholder hook.
        TODO: Generate SHAP/LIME style explainability metrics mapping 
        which exact features drove the severity classification.
        """
        return {}

    def _prepare_dashboard_metadata(self, metadata: SeverityMetadata) -> dict[str, Any]:
        """
        Placeholder hook.
        TODO: Extract time-series and categorical aggregates formatted 
        optimally for ELK, Splunk, or Grafana ingestion.
        """
        return {}

    # ============================================================
    # MAIN METADATA BUILDER API
    # ============================================================

    def build(
        self,
        severity: Any,
        risk_score: Any,
        confidence: Any,
        base_risk: Any,
        event_weight: Any,
        final_risk: Any,
        severity_threshold: Any,
        severity_reason: Any,
        event_type: Any,
        reasons: Sequence[Any] | None = None,
        matched_rules: Sequence[Any] | None = None,
        matched_indicators: Mapping[str, float] | Sequence[str] | None = None,
        event_id: Any = None,
        telemetry_source: Any = None,
        timestamp: datetime | None = None,
        classification_method: str = "Deterministic Heuristics",
        decision_source: str = "SeverityDecisionEngine",
        pipeline_stage: str = "Finalization",
        analysis_duration_ms: Any = 0.0,
    ) -> SeverityMetadata:
        """
        Aggregates outputs from detection and scoring modules into a 
        standardized SeverityMetadata object.

        Args:
            severity: Final severity string or Enum.
            risk_score: Final calculated risk score.
            confidence: Classification confidence (0-100).
            base_risk: Base risk prior to contextual weighting.
            event_weight: Additional risk assigned based on event type.
            final_risk: Total risk before threshold clamping.
            severity_threshold: The numeric threshold that triggered the severity.
            severity_reason: Explanation from the Severity Decision Engine.
            event_type: Type of telemetry (e.g., NETWORK, FILE, REGISTRY).
            reasons: List of strings detailing individual risk factors.
            matched_rules: List of rule names triggered across all engines.
            matched_indicators: Dictionary of indicator names to their risk scores, 
                                or a simple list of indicator names.
            event_id: Unique identifier for the source event.
            telemetry_source: Source of the event (e.g., Sysmon, EDR).
            timestamp: Processing timestamp.
            classification_method: Descriptor for the decision logic used.
            decision_source: The engine that finalized the severity.
            pipeline_stage: Current stage in the data pipeline.
            analysis_duration_ms: Total time taken by the detection engines.

        Returns:
            SeverityMetadata: The finalized, structured metadata object.
        """
        try:
            # 1. Clean and Deduplicate Lists
            clean_reasons = self._deduplicate_list(reasons)
            clean_rules = self._deduplicate_list(matched_rules)
            
            # 2. Process Indicators and Statistics
            indicator_names, top_ind_name, top_ind_score = self._extract_highest_indicator(matched_indicators)
            
            # 3. Safely Parse Numeric Values
            safe_severity = self._safe_string(severity, "INFO").upper()
            safe_risk_score = self._safe_float(risk_score)
            
            # 4. Generate Narrative Summary
            summary_text = self._generate_summary(safe_severity, indicator_names)
            
            # 5. Construct Result Object
            metadata = SeverityMetadata(
                # Core Fields
                severity=safe_severity,
                risk_score=safe_risk_score,
                confidence=self._safe_float(confidence, 100.0),
                
                # Context & Explanations
                reasons=clean_reasons,
                matched_indicators=indicator_names,
                matched_rules=clean_rules,
                severity_reason=self._safe_string(severity_reason, "No reason provided."),
                summary=summary_text,
                
                # Event Identifiers
                event_type=self._safe_string(event_type, "UNKNOWN"),
                event_id=self._safe_string(event_id, str(uuid.uuid4())),
                telemetry_source=self._safe_string(telemetry_source, "UNKNOWN"),
                timestamp=timestamp if isinstance(timestamp, datetime) else datetime.now(timezone.utc),
                
                # Risk Distribution
                base_risk=self._safe_float(base_risk),
                event_weight=self._safe_float(event_weight),
                final_risk=self._safe_float(final_risk),
                severity_threshold=self._safe_float(severity_threshold),
                
                # Indicator Statistics
                total_indicator_count=len(indicator_names),
                total_rule_count=len(clean_rules),
                highest_indicator_score=top_ind_score,
                highest_indicator_name=top_ind_name,
                
                # Classification Metadata
                classification_method=self._safe_string(classification_method),
                decision_source=self._safe_string(decision_source),
                pipeline_stage=self._safe_string(pipeline_stage),
                analysis_duration_ms=self._safe_float(analysis_duration_ms),
                
                # Engine & Versioning Context
                module_name=MODULE_NAME,
                engine_version=ENGINE_VERSION,
                rule_version=RULE_VERSION,
                metadata_version=METADATA_VERSION,
                analysis_id=str(uuid.uuid4())
            )
            
            return metadata
            
        except Exception as e:
            # Absolute fallback to ensure pipeline survival.
            # In a truly robust system, this block should never realistically be hit 
            # due to prior safe-casting, but guarantees enterprise safety.
            logger.error(f"Unexpected failure in SeverityMetadataBuilder: {e}", exc_info=True)
            
            return SeverityMetadata(
                severity="INFO",
                risk_score=0.0,
                confidence=0.0,
                reasons=["Failed to build metadata due to internal error."],
                matched_indicators=[],
                matched_rules=[],
                severity_reason="Metadata builder exception.",
                summary="System failure during metadata generation.",
                event_type="UNKNOWN",
                event_id=str(uuid.uuid4()),
                telemetry_source="ERROR",
                timestamp=datetime.now(timezone.utc),
                base_risk=0.0,
                event_weight=0.0,
                final_risk=0.0,
                severity_threshold=0.0,
                total_indicator_count=0,
                total_rule_count=0,
                highest_indicator_score=0.0,
                highest_indicator_name="None",
                classification_method="Fallback",
                decision_source=MODULE_NAME,
                pipeline_stage="Error Recovery",
                analysis_duration_ms=0.0,
                module_name=MODULE_NAME,
                engine_version=ENGINE_VERSION,
                rule_version=RULE_VERSION,
                metadata_version=METADATA_VERSION,
                analysis_id=str(uuid.uuid4())
            )