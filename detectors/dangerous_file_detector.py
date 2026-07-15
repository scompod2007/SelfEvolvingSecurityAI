"""
============================================================
Self-Evolving Security AI
Part 2.8.4 - Dangerous File Detection
============================================================

This module provides detection capabilities for identifying risky file-related
telemetry, such as executable/script extensions and execution/creation from
suspicious filesystem locations.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ============================================================
# SCORING CONSTANTS
# ============================================================
DANGEROUS_EXTENSION_SCORE: float = 20.0
DANGEROUS_LOCATION_SCORE: float = 15.0
DANGEROUS_COMBINATION_BONUS: float = 25.0

# ============================================================
# EXTENSION CONSTANTS
# ============================================================
_EXECUTABLE_EXTENSIONS: tuple[str, ...] = (
    ".exe",
    ".dll",
    ".sys",
    ".com",
    ".msi",
    ".drv",
)

_SCRIPT_EXTENSIONS: tuple[str, ...] = (
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".scr",
    ".pif",
)

_ALL_DANGEROUS_EXTENSIONS: tuple[str, ...] = (
    _EXECUTABLE_EXTENSIONS + _SCRIPT_EXTENSIONS
)

# ============================================================
# LOCATION CONSTANTS
# ============================================================
_SUSPICIOUS_LOCATIONS: tuple[str, ...] = (
    "\\appdata\\local\\temp",
    "\\windows\\temp",
    "\\appdata\\roaming",
    "\\start menu\\programs\\startup",
    "\\programdata",
    "\\users\\public\\downloads",
    "\\downloads",
    "\\$recycle.bin",
    "\\recycle.bin",
    "\\users\\public",
    "\\desktop",
    "\\inetcache",
    "\\temporary internet files",
)


@dataclass(slots=True)
class DangerousFileResult:
    """
    Represents the result of a dangerous file detection analysis.
    """

    is_dangerous: bool = False
    extension_detected: bool = False
    location_detected: bool = False
    extension: str = ""
    location: str = ""
    risk_points: float = 0.0
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class DangerousFileDetector:
    """
    Evaluates telemetry events to detect dangerous file extensions and locations.

    This class is completely stateless and thread-safe.
    """

    def _normalize_path(self, path: str) -> str:
        """
        Normalizes a filesystem path for consistent matching.

        Args:
            path (str): Raw filesystem path.

        Returns:
            str: Normalized path in lowercase with backslashes.
        """
        if not path or not isinstance(path, str):
            return ""
        return path.strip().replace("/", "\\").lower()

    def _detect_extension(
        self, normalized_path: str, explicit_extension: str = ""
    ) -> tuple[bool, str]:
        """
        Detects if a path or explicit extension matches known dangerous file types.

        Args:
            normalized_path (str): Normalized file path.
            explicit_extension (str): Optional explicit extension string.

        Returns:
            tuple[bool, str]: A tuple of (is_dangerous, detected_extension).
        """
        ext = ""
        if explicit_extension and isinstance(explicit_extension, str):
            ext = explicit_extension.strip().lower()
            if ext and not ext.startswith("."):
                ext = f".{ext}"

        if not ext and normalized_path:
            ext = Path(normalized_path).suffix.lower()

        if ext in _ALL_DANGEROUS_EXTENSIONS:
            return True, ext

        return False, ext

    def _detect_location(self, normalized_path: str) -> tuple[bool, str]:
        """
        Detects if a path is located within a known suspicious filesystem folder.

        Args:
            normalized_path (str): Normalized file path.

        Returns:
            tuple[bool, str]: A tuple of (is_suspicious_location, matched_location).
        """
        if not normalized_path:
            return False, ""

        for location in _SUSPICIOUS_LOCATIONS:
            if location in normalized_path:
                return True, location

        return False, ""

    def _calculate_score(
        self,
        extension_detected: bool,
        location_detected: bool,
        ext_str: str,
        loc_str: str,
    ) -> tuple[float, list[str], list[str]]:
        """
        Calculates risk score and builds rule tracking metadata.

        Args:
            extension_detected (bool): Whether a dangerous extension was found.
            location_detected (bool): Whether a suspicious location was found.
            ext_str (str): The detected extension string.
            loc_str (str): The detected location fragment.

        Returns:
            tuple[float, list[str], list[str]]: Total points, matched rules, and reasons.
        """
        risk_points = 0.0
        matched_rules: list[str] = []
        reasons: list[str] = []

        if extension_detected:
            risk_points += DANGEROUS_EXTENSION_SCORE
            matched_rules.append("Dangerous Extension")
            reasons.append(f"File possesses a risky extension: '{ext_str}'.")

        if location_detected:
            risk_points += DANGEROUS_LOCATION_SCORE
            matched_rules.append("Dangerous Location")
            reasons.append(f"File is located in a suspicious path: '{loc_str}'.")

        if extension_detected and location_detected:
            risk_points += DANGEROUS_COMBINATION_BONUS
            matched_rules.append("Dangerous Extension and Location Combination")
            reasons.append(
                "Combination of dangerous extension and suspicious location detected."
            )

        return risk_points, matched_rules, reasons

    def detect(self, event: dict[str, Any]) -> DangerousFileResult:
        """
        Analyzes a file telemetry event for dangerous extensions and locations.

        Args:
            event (dict[str, Any]): Telemetry event dictionary.

        Returns:
            DangerousFileResult: Result object containing detection analysis.
        """
        try:
            if not isinstance(event, dict) or not event:
                return DangerousFileResult()

            raw_path = str(
                event.get("file_path")
                or event.get("path")
                or event.get("process_path")
                or ""
            )
            explicit_ext = str(event.get("extension") or "")

            normalized_path = self._normalize_path(raw_path)

            ext_detected, ext_str = self._detect_extension(
                normalized_path, explicit_ext
            )
            loc_detected, loc_str = self._detect_location(normalized_path)

            is_dangerous = ext_detected or loc_detected

            points, rules, reasons = self._calculate_score(
                ext_detected, loc_detected, ext_str, loc_str
            )

            return DangerousFileResult(
                is_dangerous=is_dangerous,
                extension_detected=ext_detected,
                location_detected=loc_detected,
                extension=ext_str,
                location=loc_str,
                risk_points=points,
                matched_rules=rules,
                reasons=reasons,
            )
        except Exception:
            return DangerousFileResult()