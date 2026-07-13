"""
============================================================
Self-Evolving Security AI
Part 2.8.2 - Risk Scoring
============================================================

This module is responsible for calculating a normalized risk 
score (0-100) for telemetry events. It applies weighted 
rules to various event indicators to quantify potential risk.

It strictly adheres to single responsibility: it calculates 
scores but does not assign qualitative severity levels.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

# Attempt to import SEVERITY_CONFIG from the previous step.
# Fallback is provided to ensure module independence and testability.
try:
    from filters.severity_config import SEVERITY_CONFIG
except ImportError:
    @dataclass(slots=True, frozen=True)
    class FallbackSeverityConfig:
        max_raw_score: float = 100.0
    SEVERITY_CONFIG = FallbackSeverityConfig()


# ============================================================
# SCORING CONSTANTS
# ============================================================
EXECUTABLE_SCORE = 10.0
SCRIPT_SCORE = 15.0
REGISTRY_SCORE = 25.0
NETWORK_SCORE = 10.0
ENCODED_CMD_SCORE = 35.0
TEMP_EXECUTION_SCORE = 20.0
STARTUP_SCORE = 30.0
PRIV_ESC_SCORE = 40.0

# ============================================================
# INDICATOR CONSTANTS
# ============================================================
_PERSISTENCE_KEYS = (
    "run",
    "runonce",
    "services",
    "winlogon",
    "image file execution options",
)


@dataclass(slots=True)
class RiskScore:
    """
    Represents the calculated risk score for a single event.
    Provides helper methods to safely accumulate and manage scores.
    """
    raw_score: float = 0.0
    normalized_score: float = 0.0
    max_possible_score: float = 100.0
    matched_rules: List[str] = field(default_factory=list)
    scoring_reasons: List[str] = field(default_factory=list)

    def add_score(self, points: float, rule_name: str, reason: str) -> None:
        """
        Adds points to the raw score and records the rule and reason.

        Args:
            points (float): The number of risk points to add.
            rule_name (str): The name of the matched indicator/rule.
            reason (str): Human-readable reason for the score addition.
        """
        self.raw_score += points
        self.matched_rules.append(rule_name)
        self.scoring_reasons.append(reason)

    def reset_score(self) -> None:
        """
        Resets the risk score and clears all matched rules and reasons.
        """
        self.raw_score = 0.0
        self.normalized_score = 0.0
        self.matched_rules.clear()
        self.scoring_reasons.clear()

    def get_raw_score(self) -> float:
        """
        Retrieves the unnormalized raw score.

        Returns:
            float: The current raw score.
        """
        return self.raw_score

    def get_normalized_score(self) -> float:
        """
        Retrieves the normalized score (0-100).

        Returns:
            float: The current normalized score.
        """
        return self.normalized_score


class RiskScorer:
    """
    Evaluates telemetry events against a set of heuristic rules 
    to calculate a normalized risk score.

    This class is thread-safe as it maintains no mutable state 
    between evaluations. Every call to `calculate` generates a 
    new, independent RiskScore object.
    """

    def __init__(self, config: Any = SEVERITY_CONFIG) -> None:
        """
        Initializes the RiskScorer with the provided configuration.

        Args:
            config: Configuration object containing max_raw_score.
        """
        self.config = config
        self._max_raw_score: float = getattr(self.config, 'max_raw_score', 100.0)
        if self._max_raw_score <= 0.0:
            self._max_raw_score = 100.0

    def _normalize(self, raw_score: float) -> float:
        """
        Converts the raw score into a normalized 0-100 range.
        Guarantees the score will never exceed 100.0.

        Args:
            raw_score (float): The accumulated raw points.

        Returns:
            float: The normalized risk score (0.0 to 100.0).
        """
        normalized = (raw_score / self._max_raw_score) * 100.0
        return max(0.0, min(100.0, round(normalized, 2)))

    def calculate(self, event: Dict[str, Any]) -> RiskScore:
        """
        Evaluates an event dictionary and calculates its total risk score based
        on matched malicious indicators.

        Args:
            event (Dict[str, Any]): The telemetry event dictionary.

        Returns:
            RiskScore: The populated risk score object containing the final
                       normalized score and the list of triggered rules.
        """
        score = RiskScore(max_possible_score=self._max_raw_score)

        if not isinstance(event, dict) or not event:
            return score

        ext = str(event.get("extension", "")).lower()
        file_path = str(event.get("file_path", "")).lower()
        cmdline = str(event.get("command_line", "")).lower()
        reg_key = str(event.get("registry_key", "")).lower()
        direction = str(event.get("direction", "")).upper()
        dest_ip = str(event.get("destination_ip", ""))
        is_priv_esc = event.get("privilege_escalation") is True

        if ext in (".exe", ".dll", ".sys", ".com"):
            score.add_score(
                points=EXECUTABLE_SCORE, 
                rule_name="Suspicious Executable", 
                reason=f"Event involves a known executable extension '{ext}'."
            )

        if ext in (".ps1", ".vbs", ".bat", ".cmd", ".js", ".vbe", ".wsf", ".scr"):
            score.add_score(
                points=SCRIPT_SCORE, 
                rule_name="Suspicious Script", 
                reason=f"Event involves an interpretable script extension '{ext}'."
            )

        if any(key in reg_key for key in _PERSISTENCE_KEYS):
            score.add_score(
                points=REGISTRY_SCORE, 
                rule_name="Persistence Behavior", 
                reason="Modification of a known persistence/autorun registry key."
            )

        if direction == "OUTBOUND" and dest_ip:
            if not dest_ip.startswith(("192.168.", "10.", "172.16.", "127.")):
                score.add_score(
                    points=NETWORK_SCORE, 
                    rule_name="Suspicious Network Destination", 
                    reason=f"Outbound connection established to external IP '{dest_ip}'."
                )

        if "-enc" in cmdline or "-encodedcommand" in cmdline or "bypass" in cmdline or "hidden" in cmdline:
            score.add_score(
                points=ENCODED_CMD_SCORE, 
                rule_name="Encoded/Hidden Command Line", 
                reason="Command line contains flags used for encoding, bypassing execution policies, or hiding windows."
            )

        if "\\appdata\\local\\temp" in file_path or "\\windows\\temp" in file_path:
            score.add_score(
                points=TEMP_EXECUTION_SCORE, 
                rule_name="Temporary Directory Execution", 
                reason="Activity originating from a temporary system or user directory."
            )

        if "\\start menu\\programs\\startup" in file_path:
            score.add_score(
                points=STARTUP_SCORE, 
                rule_name="Startup Folder Execution", 
                reason="Activity originating from the user Startup directory."
            )

        if is_priv_esc:
            score.add_score(
                points=PRIV_ESC_SCORE, 
                rule_name="Privilege Escalation Indicator", 
                reason="Event metadata explicitly flags this action as an escalation of privileges."
            )

        score.normalized_score = self._normalize(score.raw_score)
        
        return score