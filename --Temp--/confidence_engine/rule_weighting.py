"""
============================================================
Self-Evolving Security AI
Part 2.9.2 - Rule Weighting
============================================================

This module assigns confidence weights to detection rules.
It evaluates how much each already-triggered detection rule
contributes to confidence. It is completely independent from
risk scoring, severity calculation, and attack detection.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS & WEIGHT VALUES
# ============================================================
PUBLIC_IP_WEIGHT: float = 5.0
OUTBOUND_CONNECTION_WEIGHT: float = 5.0
DANGEROUS_PORT_WEIGHT: float = 15.0
HIGH_RISK_PORT_WEIGHT: float = 20.0
DANGEROUS_PROTOCOL_WEIGHT: float = 15.0
DNS_ABUSE_WEIGHT: float = 25.0
BEACONING_BEHAVIOR_WEIGHT: float = 30.0
TOR_ACTIVITY_WEIGHT: float = 35.0
PROXY_PORT_ACTIVITY_WEIGHT: float = 15.0
C2_CONNECTION_WEIGHT: float = 40.0
PROCESS_INJECTION_WEIGHT: float = 30.0
CREDENTIAL_DUMPING_WEIGHT: float = 35.0
PERSISTENCE_DETECTED_WEIGHT: float = 25.0
REGISTRY_PERSISTENCE_WEIGHT: float = 25.0
SCRIPT_EXECUTION_WEIGHT: float = 20.0
POWERSHELL_ENCODED_COMMAND_WEIGHT: float = 30.0
FILELESS_EXECUTION_WEIGHT: float = 35.0
MALICIOUS_DLL_WEIGHT: float = 25.0
SUSPICIOUS_REGISTRY_KEY_WEIGHT: float = 20.0
UNKNOWN_RULE_WEIGHT: float = 0.0

RULE_WEIGHTS = MappingProxyType({
    "public ip connection": PUBLIC_IP_WEIGHT,
    "outbound connection": OUTBOUND_CONNECTION_WEIGHT,
    "dangerous port": DANGEROUS_PORT_WEIGHT,
    "high risk port": HIGH_RISK_PORT_WEIGHT,
    "dangerous protocol": DANGEROUS_PROTOCOL_WEIGHT,
    "dns abuse indicator": DNS_ABUSE_WEIGHT,
    "beaconing behavior": BEACONING_BEHAVIOR_WEIGHT,
    "tor network activity": TOR_ACTIVITY_WEIGHT,
    "proxy port activity": PROXY_PORT_ACTIVITY_WEIGHT,
    "c2 connection": C2_CONNECTION_WEIGHT,
    "process injection": PROCESS_INJECTION_WEIGHT,
    "credential dumping": CREDENTIAL_DUMPING_WEIGHT,
    "persistence detected": PERSISTENCE_DETECTED_WEIGHT,
    "registry persistence": REGISTRY_PERSISTENCE_WEIGHT,
    "script execution": SCRIPT_EXECUTION_WEIGHT,
    "powershell encoded command": POWERSHELL_ENCODED_COMMAND_WEIGHT,
    "fileless execution": FILELESS_EXECUTION_WEIGHT,
    "malicious dll": MALICIOUS_DLL_WEIGHT,
    "suspicious registry key": SUSPICIOUS_REGISTRY_KEY_WEIGHT,
    "unknown rule": UNKNOWN_RULE_WEIGHT
})


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class RuleWeightResult:
    """
    Represents the result of the rule weighting calculation.

    Attributes:
        weighted_confidence (float): The total confidence weight of all recognized rules.
        matched_rule_count (int): Total number of unique rules processed.
        recognized_rule_count (int): Number of rules that matched a known weight.
        unknown_rule_count (int): Number of rules that did not match a known weight.
        recognized_rules (list[str]): List of normalized recognized rules.
        unknown_rules (list[str]): List of normalized unknown rules.
        rule_weights (dict[str, float]): Mapping of recognized rules to their weights.
        reasons (list[str]): Human-readable explanations of the applied weights.
        timestamp (datetime): The UTC timestamp of the calculation.
    """
    weighted_confidence: float
    matched_rule_count: int
    recognized_rule_count: int
    unknown_rule_count: int
    recognized_rules: list[str]
    unknown_rules: list[str]
    rule_weights: dict[str, float]
    reasons: list[str]
    timestamp: datetime


# ============================================================
# RULE WEIGHTING ENGINE
# ============================================================
class RuleWeightingEngine:
    """
    A stateless, thread-safe engine for assigning confidence weights
    to triggered detection rules.
    """

    def _normalize_rule(self, rule: str) -> str:
        """
        Normalizes a rule string by collapsing whitespace and converting to lowercase.

        Args:
            rule (str): The raw rule string.

        Returns:
            str: The normalized rule string.
        """
        return " ".join(rule.split()).lower()

    def _validate_input(self, matched_rules: Any) -> list[str]:
        """
        Safely parses arbitrary input into a list of string rules.
        Rejects invalid container types and empty strings.

        Args:
            matched_rules (Any): The raw input, potentially of mixed or invalid types.

        Returns:
            list[str]: A list of meaningful string representations of the rules.
        """
        if not isinstance(matched_rules, (list, tuple, set, frozenset)):
            return []

        valid_rules = []
        for item in matched_rules:
            if item is not None:
                cleaned = str(item).strip()
                if cleaned:
                    valid_rules.append(cleaned)
        return valid_rules

    def _remove_duplicates(self, rules: list[str]) -> list[str]:
        """
        Removes duplicate rules after normalization, preserving order of first appearance.

        Args:
            rules (list[str]): The list of raw string rules.

        Returns:
            list[str]: A deduplicated list of normalized rules.
        """
        seen = set()
        unique_rules = []
        for rule in rules:
            norm = self._normalize_rule(rule)
            if norm and norm not in seen:
                seen.add(norm)
                unique_rules.append(norm)
        return unique_rules

    def _lookup_weight(self, rule: str) -> float | None:
        """
        Retrieves the predefined weight for a normalized rule.

        Args:
            rule (str): The normalized rule string.

        Returns:
            float | None: The assigned weight, or None if unknown.
        """
        return RULE_WEIGHTS.get(rule)

    def _sum_weights(self, rule_weights: dict[str, float]) -> float:
        """
        Calculates the total weight from a dictionary of rule weights.

        Args:
            rule_weights (dict[str, float]): Mapping of rules to their weights.

        Returns:
            float: The rounded sum of all weights.
        """
        return round(sum(rule_weights.values()), 2)

    def _build_reasons(self, rule_weights: dict[str, float], unknown_rules: list[str], total_weight: float) -> list[str]:
        """
        Constructs human-readable reasons for the applied weights and appends summary metadata.

        Args:
            rule_weights (dict[str, float]): Mapping of recognized rules to their weights.
            unknown_rules (list[str]): List of rules that had no predefined weight.
            total_weight (float): The total calculated confidence weight.

        Returns:
            list[str]: A list of explanation strings.
        """
        reasons = []
        for rule, weight in rule_weights.items():
            reasons.append(f"Applied confidence weight {weight} for {rule.title()}.")
            
        reasons.append(f"Total weighted confidence: {total_weight}")
        reasons.append(f"Recognized rules: {len(rule_weights)}")
        reasons.append(f"Unknown rules: {len(unknown_rules)}")
        
        return reasons

    def _generate_output(
        self,
        weighted_confidence: float,
        matched_rule_count: int,
        recognized_rule_count: int,
        unknown_rule_count: int,
        recognized_rules: list[str],
        unknown_rules: list[str],
        rule_weights: dict[str, float],
        reasons: list[str]
    ) -> RuleWeightResult:
        """
        Constructs the final RuleWeightResult dataclass.

        Args:
            weighted_confidence (float): Total calculated confidence weight.
            matched_rule_count (int): Total unique rules processed.
            recognized_rule_count (int): Number of recognized rules.
            unknown_rule_count (int): Number of unknown rules.
            recognized_rules (list[str]): List of recognized rules.
            unknown_rules (list[str]): List of unknown rules.
            rule_weights (dict[str, float]): Mapping of rules to weights.
            reasons (list[str]): Explanations of applied weights.

        Returns:
            RuleWeightResult: The populated result object.
        """
        return RuleWeightResult(
            weighted_confidence=weighted_confidence,
            matched_rule_count=matched_rule_count,
            recognized_rule_count=recognized_rule_count,
            unknown_rule_count=unknown_rule_count,
            recognized_rules=recognized_rules,
            unknown_rules=unknown_rules,
            rule_weights=rule_weights,
            reasons=reasons,
            timestamp=datetime.now(timezone.utc)
        )

    def calculate(self, matched_rules: list[str]) -> RuleWeightResult:
        """
        Evaluates a list of triggered rules and calculates their total confidence weight.

        Args:
            matched_rules (list[str]): A list of rules that have been triggered.

        Returns:
            RuleWeightResult: The result containing the weighted confidence and metadata.
        """
        try:
            raw_rules = self._validate_input(matched_rules)
            unique_rules = self._remove_duplicates(raw_rules)

            recognized_rules = []
            unknown_rules = []
            rule_weights = {}

            for rule in unique_rules:
                weight = self._lookup_weight(rule)
                if weight is not None:
                    recognized_rules.append(rule)
                    rule_weights[rule] = weight
                else:
                    unknown_rules.append(rule)

            total_weight = self._sum_weights(rule_weights)
            reasons = self._build_reasons(rule_weights, unknown_rules, total_weight)

            return self._generate_output(
                weighted_confidence=total_weight,
                matched_rule_count=len(unique_rules),
                recognized_rule_count=len(recognized_rules),
                unknown_rule_count=len(unknown_rules),
                recognized_rules=recognized_rules,
                unknown_rules=unknown_rules,
                rule_weights=rule_weights,
                reasons=reasons
            )

        except Exception as e:
            logger.exception("Unexpected error in RuleWeightingEngine: %s", e)
            return self._generate_output(
                weighted_confidence=0.0,
                matched_rule_count=0,
                recognized_rule_count=0,
                unknown_rule_count=0,
                recognized_rules=[],
                unknown_rules=[],
                rule_weights={},
                reasons=["Engine encountered an unexpected error and returned a default empty result."]
            )