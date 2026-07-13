"""
============================================================
Self-Evolving Security AI
Part 2.8.5 - Dangerous Registry Detection
============================================================

This module is responsible for analyzing Windows Registry 
modifications to identify dangerous activities indicating 
persistence, privilege escalation, process hijacking, and 
other malicious behaviors.

It operates entirely independently, assessing raw registry 
events and returning a standardized risk evaluation.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

# ============================================================
# CATEGORIES
# ============================================================

class RegistryCategory(Enum):
    """
    Enumeration of registry threat categories.
    """
    PERSISTENCE = auto()
    STARTUP = auto()
    PROCESS_HIJACKING = auto()
    CREDENTIAL_ACCESS = auto()
    PRIVILEGE_ESCALATION = auto()
    SECURITY_BYPASS = auto()
    UNKNOWN = auto()


# ============================================================
# SCORING CONSTANTS
# ============================================================

CATEGORY_SCORES: dict[RegistryCategory, float] = {
    RegistryCategory.PERSISTENCE: 25.0,
    RegistryCategory.STARTUP: 20.0,
    RegistryCategory.PROCESS_HIJACKING: 35.0,
    RegistryCategory.CREDENTIAL_ACCESS: 40.0,
    RegistryCategory.PRIVILEGE_ESCALATION: 45.0,
    RegistryCategory.SECURITY_BYPASS: 30.0,
    RegistryCategory.UNKNOWN: 5.0,
}

DANGEROUS_VALUE_SCORE: float = 15.0
ENCODED_CMD_SCORE: float = 25.0
TEMP_EXECUTION_SCORE: float = 20.0
COMBINATION_BONUS: float = 30.0

# ============================================================
# DETECTION CONSTANTS
# ============================================================

_KEY_MAPPINGS: tuple[tuple[str, RegistryCategory], ...] = (
    # Process Hijacking
    (r"\image file execution options", RegistryCategory.PROCESS_HIJACKING),
    (r"\appinit_dlls", RegistryCategory.PROCESS_HIJACKING),
    (r"\knowndlls", RegistryCategory.PROCESS_HIJACKING),
    
    # Credential Access
    (r"\system\currentcontrolset\control\lsa", RegistryCategory.CREDENTIAL_ACCESS),
    (r"\sam\sam", RegistryCategory.CREDENTIAL_ACCESS),
    (r"\security providers", RegistryCategory.CREDENTIAL_ACCESS),
    
    # Privilege Escalation
    (r"\system\currentcontrolset\services", RegistryCategory.PRIVILEGE_ESCALATION),
    
    # Security Bypass
    (r"\software\policies\microsoft\windows defender", RegistryCategory.SECURITY_BYPASS),
    (r"\system\currentcontrolset\control\wmi\autologger", RegistryCategory.SECURITY_BYPASS),
    (r"\software\microsoft\command processor", RegistryCategory.SECURITY_BYPASS),
    
    # Persistence
    (r"\software\microsoft\windows nt\currentversion\winlogon", RegistryCategory.PERSISTENCE),
    (r"userinit", RegistryCategory.PERSISTENCE),
    (r"shell", RegistryCategory.PERSISTENCE),
    
    # Startup
    (r"\software\microsoft\windows\currentversion\run", RegistryCategory.STARTUP),
    (r"\software\microsoft\windows\currentversion\runonce", RegistryCategory.STARTUP),
    (r"\software\microsoft\windows\currentversion\runservices", RegistryCategory.STARTUP),
    (r"\software\microsoft\windows\currentversion\policies\explorer\run", RegistryCategory.STARTUP),
    (r"\session manager\bootexecute", RegistryCategory.STARTUP),
    (r"\explorer\shell folders", RegistryCategory.STARTUP),
    (r"\startupapproved", RegistryCategory.STARTUP),
)

_DANGEROUS_EXECUTABLES: tuple[str, ...] = (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "bitsadmin.exe",
)

_MALWARE_EXTENSIONS: tuple[str, ...] = (
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".scr",
    ".vbs",
    ".js",
)

_ENCODED_COMMAND_FLAGS: tuple[str, ...] = (
    "-enc",
    "-encodedcommand",
    "bypass",
    "hidden",
    "invoke-expression",
    "iex",
)

_TEMP_LOCATIONS: tuple[str, ...] = (
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\users\\public\\",
    "\\recycle.bin",
    "\\$recycle.bin",
)


@dataclass(slots=True)
class DangerousRegistryResult:
    """
    Represents the result of a dangerous registry detection analysis.
    """
    is_dangerous: bool = False
    category: RegistryCategory = RegistryCategory.UNKNOWN
    registry_path: str = ""
    registry_value: str = ""
    risk_points: float = 0.0
    matched_rules: list[str] = field(default_factory=list)
    matched_keys: list[str] = field(default_factory=list)
    matched_values: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class DangerousRegistryDetector:
    """
    Evaluates telemetry events to detect malicious registry modifications.
    
    This class is completely stateless, thread-safe, and resilient 
    to missing or malformed event data.
    """

    def _normalize_registry_path(self, path: str) -> str:
        """
        Normalizes a registry key path for consistent matching.

        Args:
            path (str): Raw registry key path.

        Returns:
            str: Normalized path in lowercase with backslashes.
        """
        if not path or not isinstance(path, str):
            return ""
        return path.strip().replace("/", "\\").lower()

    def _normalize_registry_value(self, value: Any) -> str:
        """
        Normalizes a registry value payload for consistent matching.

        Args:
            value (Any): Raw registry value data.

        Returns:
            str: Normalized value string in lowercase.
        """
        if not value:
            return ""
        return str(value).strip().lower()

    def _detect_registry_key(self, norm_path: str) -> tuple[RegistryCategory, str]:
        """
        Detects if a registry path matches known suspicious locations.

        Args:
            norm_path (str): Normalized registry path.

        Returns:
            tuple[RegistryCategory, str]: The matched category and the specific key pattern.
        """
        if not norm_path:
            return RegistryCategory.UNKNOWN, ""
            
        for key_pattern, category in _KEY_MAPPINGS:
            if key_pattern in norm_path:
                return category, key_pattern
                
        return RegistryCategory.UNKNOWN, ""

    def _detect_registry_value(self, norm_value: str) -> tuple[bool, list[str]]:
        """
        Detects if a registry value contains dangerous executables or autorun malware.

        Args:
            norm_value (str): Normalized registry value data.

        Returns:
            tuple[bool, list[str]]: A boolean indicating if a threat was found, 
                                    and a list of the specific matched indicators.
        """
        matches = []
        if not norm_value:
            return False, matches
            
        for exec_name in _DANGEROUS_EXECUTABLES:
            if exec_name in norm_value:
                matches.append(exec_name)
                
        for ext in _MALWARE_EXTENSIONS:
            if ext in norm_value:
                matches.append(ext)
                
        return len(matches) > 0, matches

    def _detect_encoded_command(self, norm_value: str) -> tuple[bool, list[str]]:
        """
        Detects if a registry value contains flags indicating obfuscated/encoded execution.

        Args:
            norm_value (str): Normalized registry value data.

        Returns:
            tuple[bool, list[str]]: A boolean indicating if encoding was found, 
                                    and a list of the specific matched flags.
        """
        matches = []
        if not norm_value:
            return False, matches
            
        for flag in _ENCODED_COMMAND_FLAGS:
            if flag in norm_value:
                matches.append(flag)
                
        return len(matches) > 0, matches

    def _detect_temp_execution(self, norm_value: str) -> tuple[bool, str]:
        """
        Detects if a registry value references temporary or user-writable locations.

        Args:
            norm_value (str): Normalized registry value data.

        Returns:
            tuple[bool, str]: A boolean indicating if a temp location was found,
                              and the matched location string.
        """
        if not norm_value:
            return False, ""
            
        # Ensure we check the value data natively with path separators
        norm_value_path = norm_value.replace("/", "\\")
        for loc in _TEMP_LOCATIONS:
            if loc in norm_value_path:
                return True, loc
                
        return False, ""

    def _calculate_score(
        self,
        category: RegistryCategory,
        has_dangerous_exec: bool,
        has_encoded_cmd: bool,
        has_temp_exec: bool
    ) -> tuple[float, list[str], list[str]]:
        """
        Calculates the aggregate risk score and constructs explanation metadata.

        Args:
            category (RegistryCategory): The determined registry threat category.
            has_dangerous_exec (bool): True if dangerous executables were found.
            has_encoded_cmd (bool): True if obfuscated execution flags were found.
            has_temp_exec (bool): True if temp directory execution was found.

        Returns:
            tuple[float, list[str], list[str]]: Aggregate score, triggered rules, and human-readable reasons.
        """
        total_score = 0.0
        rules = []
        reasons = []

        # Base category scoring
        if category != RegistryCategory.UNKNOWN:
            base_score = CATEGORY_SCORES.get(category, 5.0)
            total_score += base_score
            rules.append(f"Category: {category.name}")
            reasons.append(f"Modification of a high-risk registry area ({category.name}).")

        # Value-based scoring
        if has_dangerous_exec:
            total_score += DANGEROUS_VALUE_SCORE
            rules.append("Dangerous Registry Value")
            reasons.append("Registry data contains references to powerful administrative tools or script extensions.")
            
        if has_encoded_cmd:
            total_score += ENCODED_CMD_SCORE
            rules.append("Encoded/Obfuscated Command")
            reasons.append("Registry data includes flags associated with script encoding, evasion, or window hiding.")
            
        if has_temp_exec:
            total_score += TEMP_EXECUTION_SCORE
            rules.append("Execution from Temp/Public Location")
            reasons.append("Registry data instructs execution originating from a user-writable or temporary directory.")

        # Multi-indicator combination bonus
        indicator_count = sum([
            1 if category != RegistryCategory.UNKNOWN else 0,
            1 if has_dangerous_exec else 0,
            1 if has_encoded_cmd else 0,
            1 if has_temp_exec else 0
        ])
        
        if indicator_count >= 2:
            total_score += COMBINATION_BONUS
            rules.append("Multiple Malicious Indicators")
            reasons.append(f"Combined {indicator_count} separate high-risk characteristics in a single registry event.")

        return total_score, rules, reasons

    def detect(self, event: dict[str, Any]) -> DangerousRegistryResult:
        """
        Analyzes a registry telemetry event to detect dangerous persistence, 
        escalation, or execution patterns.

        Args:
            event (dict[str, Any]): Telemetry event dictionary.

        Returns:
            DangerousRegistryResult: Result object containing detection details and risk scores.
        """
        try:
            if not isinstance(event, dict) or not event:
                return DangerousRegistryResult()

            # Extract possible key path locations
            raw_path = str(
                event.get("registry_path") or 
                event.get("registry_key") or 
                event.get("key_path") or 
                ""
            )
            
            # Extract possible value data
            raw_value = str(
                event.get("registry_value") or 
                event.get("value_data") or 
                event.get("data") or 
                ""
            )

            norm_path = self._normalize_registry_path(raw_path)
            norm_value = self._normalize_registry_value(raw_value)

            # Detection phases
            category, matched_key_pattern = self._detect_registry_key(norm_path)
            
            has_dangerous_exec, exec_matches = self._detect_registry_value(norm_value)
            has_encoded_cmd, enc_matches = self._detect_encoded_command(norm_value)
            has_temp_exec, temp_match = self._detect_temp_execution(norm_value)

            # Check if any malicious activity was flagged
            is_dangerous = (
                category != RegistryCategory.UNKNOWN or 
                has_dangerous_exec or 
                has_encoded_cmd or 
                has_temp_exec
            )

            # Score calculation
            score, rules, reasons = self._calculate_score(
                category, has_dangerous_exec, has_encoded_cmd, has_temp_exec
            )

            # Compile matched values for the result
            matched_vals = []
            matched_vals.extend(exec_matches)
            matched_vals.extend(enc_matches)
            if temp_match:
                matched_vals.append(temp_match)

            matched_keys_list = [matched_key_pattern] if matched_key_pattern else []

            return DangerousRegistryResult(
                is_dangerous=is_dangerous,
                category=category,
                registry_path=norm_path,
                registry_value=norm_value,
                risk_points=score,
                matched_rules=rules,
                matched_keys=matched_keys_list,
                matched_values=matched_vals,
                reasons=reasons
            )
            
        except Exception:
            return DangerousRegistryResult()