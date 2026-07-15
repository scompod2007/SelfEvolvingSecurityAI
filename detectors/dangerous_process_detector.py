"""
============================================================
Self-Evolving Security AI
Part 2.x.x - Dangerous Process Detection
============================================================

This module provides detection capabilities for identifying risky 
process-related telemetry, such as execution of LOLBins, malware, 
suspicious parent-child process relationships, and evasion techniques.[cite: 2]

It has been designed for improved maintainability, extensibility, 
future AI threat intelligence integration, robust exception handling, 
and high-performance stateless execution.[cite: 2]
"""

import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum, auto
from types import MappingProxyType
from typing import Any, Tuple, List, Dict

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)


# ============================================================
# ENUMS
# ============================================================

class ProcessCategory(Enum):
    """Enumeration of process classifications.[cite: 2]"""
    MALWARE = auto()
    OFFENSIVE_TOOL = auto()
    LOLBIN = auto()
    RANSOMWARE = auto()
    SCRIPT_ENGINE = auto()
    SYSTEM_PROCESS = auto()
    BROWSER = auto()
    OFFICE = auto()
    ADMIN_TOOL = auto()
    SECURITY_TOOL = auto()
    UNKNOWN = auto()


class LOLBinCategory(Enum):
    """Enumeration of Living-off-the-Land Binary categories.[cite: 2]"""
    EXECUTION = auto()
    DOWNLOAD = auto()
    BYPASS = auto()
    CREDENTIAL_ACCESS = auto()
    PERSISTENCE = auto()
    DEFENSE_EVASION = auto()
    NONE = auto()


class ProcessRiskLevel(Enum):
    """Qualitative assessment of process risk.[cite: 2]"""
    SAFE = auto()
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class SuspiciousPathCategory(Enum):
    """Categorization of filesystem paths known for malicious use.[cite: 2]"""
    TEMP = auto()
    PUBLIC = auto()
    DOWNLOADS = auto()
    STARTUP = auto()
    HIDDEN = auto()
    SYSTEM = auto()
    NONE = auto()


class IntegrityLevel(IntEnum):
    """Windows Integrity Levels.[cite: 2]"""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    SYSTEM = 4
    UNKNOWN = -1


# ============================================================
# SCORING CONSTANTS
# ============================================================

MALWARE_SCORE: float = 85.0
RANSOMWARE_SCORE: float = 95.0
OFFENSIVE_TOOL_SCORE: float = 65.0
LOLBIN_SCORE: float = 40.0
SCRIPT_EXEC_SCORE: float = 25.0
ENCODED_CMD_SCORE: float = 35.0
BASE64_CMD_SCORE: float = 30.0
SUSPICIOUS_ARGS_SCORE: float = 30.0
DOWNLOAD_EXEC_SCORE: float = 45.0
TEMP_EXECUTION_SCORE: float = 20.0
PUBLIC_FOLDER_SCORE: float = 25.0
HIDDEN_EXECUTION_SCORE: float = 30.0
MASQUERADING_SCORE: float = 75.0
UNSIGNED_BINARY_SCORE: float = 15.0
SUSPICIOUS_PARENT_SCORE: float = 50.0
PROCESS_CHAIN_SCORE: float = 40.0
PRIVILEGE_ABUSE_SCORE: float = 55.0
SYSTEM_ANOMALY_SCORE: float = 60.0
COMBINATION_BONUS: float = 30.0


# ============================================================
# IMMUTABLE CONSTANTS (MappingProxyType & Tuples)
# ============================================================

_KNOWN_LOLBINS = MappingProxyType({
    "powershell.exe": LOLBinCategory.EXECUTION,
    "cmd.exe": LOLBinCategory.EXECUTION,
    "wmic.exe": LOLBinCategory.EXECUTION,
    "rundll32.exe": LOLBinCategory.EXECUTION,
    "regsvr32.exe": LOLBinCategory.EXECUTION,
    "mshta.exe": LOLBinCategory.EXECUTION,
    "certutil.exe": LOLBinCategory.DOWNLOAD,
    "bitsadmin.exe": LOLBinCategory.DOWNLOAD,
    "msbuild.exe": LOLBinCategory.BYPASS,
    "csc.exe": LOLBinCategory.BYPASS,
    "reg.exe": LOLBinCategory.PERSISTENCE,
    "schtasks.exe": LOLBinCategory.PERSISTENCE,
    "vssadmin.exe": LOLBinCategory.DEFENSE_EVASION,
    "procdump.exe": LOLBinCategory.CREDENTIAL_ACCESS,
    "installutil.exe": LOLBinCategory.BYPASS,
    "bash.exe": LOLBinCategory.EXECUTION,
    "wscript.exe": LOLBinCategory.EXECUTION,
    "cscript.exe": LOLBinCategory.EXECUTION,
})

_KNOWN_MALWARE = (
    "wannacry.exe", "emotet.exe", "trickbot.exe", "agenttesla.exe",
    "remcos.exe", "njrat.exe", "darkcomet.exe", "nanocore.exe",
)

_KNOWN_OFFENSIVE_TOOLS = (
    "mimikatz.exe", "bloodhound.exe", "sharphound.exe", "rubeus.exe",
    "seatbelt.exe", "covenant.exe", "cobaltstrike.exe", "meterpreter.exe",
    "psexec.exe", "nmap.exe", "sqlmap.exe", "netcat.exe", "nc.exe",
)

_KNOWN_RANSOMWARE_TOOLS = (
    "ryuk.exe", "lockbit.exe", "revil.exe", "phobos.exe", "blackbasta.exe",
)

_KNOWN_SCRIPT_ENGINES = (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "python.exe", "perl.exe", "ruby.exe", "node.exe", "java.exe",
)

_KNOWN_WINDOWS_BINARIES = (
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "explorer.exe", "services.exe", "spoolsv.exe",
)

_KNOWN_OFFICE_PROCESSES = (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
)

_KNOWN_BROWSER_PROCESSES = (
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe",
)

_KNOWN_AV_EDR_PROCESSES = (
    "msmpeng.exe", "cb.exe", "cyserver.exe", "ds_agent.exe", "mcshield.exe",
)

_KNOWN_SUSPICIOUS_PARENTS = (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", 
    "iexplore.exe", "chrome.exe", "msedge.exe", "spoolsv.exe",
    "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "java.exe",
)

_KNOWN_TEMP_FOLDERS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\",
    "\\inetcache\\", "\\temporary internet files\\",
)

_KNOWN_PUBLIC_FOLDERS = (
    "\\users\\public\\", "\\programdata\\",
)

_KNOWN_DOWNLOAD_FOLDERS = (
    "\\downloads\\", "\\users\\public\\downloads\\",
)

_KNOWN_STARTUP_FOLDERS = (
    "\\start menu\\programs\\startup\\", "\\windows\\start menu\\programs\\startup\\",
)

_KNOWN_SYSTEM_FOLDERS = (
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\",
)

_KNOWN_SUSPICIOUS_EXTENSIONS = (
    ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", 
    ".jse", ".wsf", ".wsh", ".hta", ".scr", ".pif",
)

_SYSTEM_PROCESS_PATHS = MappingProxyType({
    "lsass.exe": "\\windows\\system32\\",
    "csrss.exe": "\\windows\\system32\\",
    "smss.exe": "\\windows\\system32\\",
    "wininit.exe": "\\windows\\system32\\",
    "services.exe": "\\windows\\system32\\",
    "svchost.exe": "\\windows\\system32\\",
    "winlogon.exe": "\\windows\\system32\\",
})


def _safe_string(value: Any) -> str:
    """Safely convert values to stripped strings.[cite: 2]"""
    if value is None:
        return ""
    return str(value).strip()


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert values to integers.[cite: 2]"""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# ============================================================
# RESULT DATACLASS
# ============================================================

@dataclass(slots=True)
class DangerousProcessResult:
    """
    Represents the result of a dangerous process detection analysis.[cite: 2]
    """
    is_dangerous: bool = False
    risk_points: float = 0.0
    risk_level: str = "INFO"
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    process_name: str = ""
    process_path: str = ""
    command_line: str = ""
    pid: int = 0
    parent_pid: int = 0
    parent_process: str = ""
    username: str = ""
    integrity_level: IntegrityLevel = IntegrityLevel.UNKNOWN
    
    matched_rules: List[str] = field(default_factory=list)
    matched_indicators: List[str] = field(default_factory=list)
    matched_commands: List[str] = field(default_factory=list)
    matched_processes: List[str] = field(default_factory=list)
    matched_paths: List[str] = field(default_factory=list)
    matched_parents: List[str] = field(default_factory=list)
    matched_behaviors: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


# ============================================================
# MAIN DETECTOR CLASS
# ============================================================

class DangerousProcessDetector:
    """
    Evaluates telemetry events to detect malicious processes, evasive 
    execution chains, privilege abuse, and anomaly indicators.[cite: 2]
    
    This class is completely stateless, thread-safe, and resilient 
    to missing or malformed event data.[cite: 2]
    """

    def _extract_timestamp(self, event: Dict[str, Any]) -> datetime:
        """Extracts and normalizes the timestamp from the telemetry event.[cite: 2]"""
        raw_ts = event.get("timestamp") or event.get("@timestamp")
        if not raw_ts:
            return datetime.now(timezone.utc)
        try:
            if isinstance(raw_ts, datetime):
                if raw_ts.tzinfo is None:
                    return raw_ts.replace(tzinfo=timezone.utc)
                return raw_ts.astimezone(timezone.utc)
            if isinstance(raw_ts, (int, float)):
                return datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            if isinstance(raw_ts, str):
                clean_ts = raw_ts.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_ts).astimezone(timezone.utc)
        except (ValueError, TypeError, OverflowError) as e:
            logger.debug(f"Failed to parse timestamp '{raw_ts}': {e}. Falling back to UTC now.")
        return datetime.now(timezone.utc)

    def _extract_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts and normalizes fields from the event dictionary.[cite: 2]"""
        process_path = _safe_string(event.get("process_path") or event.get("image_path") or event.get("path")).lower()
        process_name = _safe_string(event.get("process_name") or event.get("image")).lower()
        
        # Derive name from path if missing
        if not process_name and process_path:
            process_name = process_path.split("\\")[-1].split("/")[-1]

        command_line = _safe_string(event.get("command_line") or event.get("cmdline")).lower()
        parent_process = _safe_string(event.get("parent_process_name") or event.get("parent_image")).lower()
        username = _safe_string(event.get("username") or event.get("user"))
        pid = _safe_int(event.get("pid") or event.get("process_id"))
        parent_pid = _safe_int(event.get("parent_pid") or event.get("ppid"))
        
        raw_integrity = _safe_string(event.get("integrity_level")).upper()
        integrity_level = IntegrityLevel.UNKNOWN
        if "SYSTEM" in raw_integrity:
            integrity_level = IntegrityLevel.SYSTEM
        elif "HIGH" in raw_integrity:
            integrity_level = IntegrityLevel.HIGH
        elif "MEDIUM" in raw_integrity:
            integrity_level = IntegrityLevel.MEDIUM
        elif "LOW" in raw_integrity:
            integrity_level = IntegrityLevel.LOW
        elif "UNTRUSTED" in raw_integrity:
            integrity_level = IntegrityLevel.UNTRUSTED

        is_signed = event.get("is_signed")
        if not isinstance(is_signed, bool):
            is_signed = False  # Default to False for safer security posture

        return {
            "process_name": process_name,
            "process_path": process_path,
            "command_line": command_line,
            "pid": pid,
            "parent_pid": parent_pid,
            "parent_process": parent_process,
            "username": username,
            "integrity_level": integrity_level,
            "is_signed": is_signed,
            "timestamp": self._extract_timestamp(event)
        }

    # ============================================================
    # DETECTION HELPERS
    # ============================================================

    def _calculate_entropy(self, data: str) -> float:
        """Lightweight Shannon entropy calculation for a string.[cite: 2]"""
        if not data:
            return 0.0
        counts: Dict[str, int] = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        total = len(data)
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _detect_process_name(self, process_name: str) -> Tuple[bool, ProcessCategory]:
        """Detects if the process name belongs to known malware or offensive tools.[cite: 2]"""
        if process_name in _KNOWN_MALWARE:
            return True, ProcessCategory.MALWARE
        if process_name in _KNOWN_RANSOMWARE_TOOLS:
            return True, ProcessCategory.RANSOMWARE
        if process_name in _KNOWN_OFFENSIVE_TOOLS:
            return True, ProcessCategory.OFFENSIVE_TOOL
        return False, ProcessCategory.UNKNOWN

    def _detect_lolbin(self, process_name: str) -> Tuple[bool, LOLBinCategory]:
        """Detects if the process is a known Living-off-the-Land binary.[cite: 2]"""
        category = _KNOWN_LOLBINS.get(process_name, LOLBinCategory.NONE)
        return category != LOLBinCategory.NONE, category

    def _detect_script_execution(self, command_line: str) -> Tuple[bool, List[str]]:
        """Detects execution of script files via command line.[cite: 2]"""
        matches = []
        for ext in _KNOWN_SUSPICIOUS_EXTENSIONS:
            clean_ext = ext.lstrip(".")
            if clean_ext in ("ps1", "vbs", "bat", "cmd", "js", "vbe", "wsf", "hta"):
                if ext in command_line: 
                    matches.append(clean_ext)
        return len(matches) > 0, matches

    def _detect_encoded_command(self, command_line: str) -> bool:
        """Detects usage of encoded or hidden command line flags.[cite: 2]"""
        flags = ("-enc", "-encodedcommand", "-en", "-e ", "bypass", "hidden", "-w hidden", "-windowstyle hidden")
        return any(flag in command_line for flag in flags)

    def _detect_base64(self, command_line: str) -> bool:
        """Detects potential base64 payloads in command lines using heuristics.[cite: 2]"""
        if len(command_line) < 50:
            return False
        # Remove standard arguments and paths to isolate payload
        parts = command_line.split()
        for part in parts:
            if len(part) > 40 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', part):
                if self._calculate_entropy(part) > 5.0:
                    return True
        return False

    def _detect_suspicious_arguments(self, command_line: str) -> bool:
        """Detects suspicious arguments often used for evasion.[cite: 2]"""
        args = ("amsiinitfailed", "downgrade", "invoke-mimikatz", "bypass", "unrestricted", "iex ", "invoke-expression")
        return any(arg in command_line for arg in args)

    def _detect_download_execution(self, command_line: str) -> bool:
        """Detects command lines indicating network download activity.[cite: 2]"""
        dl_cmds = ("invoke-webrequest", "iwr ", "wget ", "curl ", "net.webclient", "downloadstring", "downloadfile")
        return any(cmd in command_line for cmd in dl_cmds)

    def _detect_temp_execution(self, process_path: str) -> bool:
        """Detects process execution from temporary directories.[cite: 2]"""
        return any(folder in process_path for folder in _KNOWN_TEMP_FOLDERS)

    def _detect_public_folder_execution(self, process_path: str) -> bool:
        """Detects process execution from public or universally writable directories.[cite: 2]"""
        return any(folder in process_path for folder in _KNOWN_PUBLIC_FOLDERS)

    def _detect_hidden_execution(self, process_path: str, command_line: str) -> bool:
        """Detects execution from hidden directories or explicitly hidden windows.[cite: 2]"""
        if "\\appdata\\local\\hidden\\" in process_path or "\\.hidden\\" in process_path:
            return True
        if "-windowstyle hidden" in command_line or "-w hidden" in command_line:
            return True
        return False

    def _detect_process_masquerading(self, process_name: str, process_path: str) -> bool:
        """Detects system processes executing from non-standard directories.[cite: 2]"""
        if not process_name or not process_path:
            return False
        expected_path = _SYSTEM_PROCESS_PATHS.get(process_name)
        if expected_path:
            return expected_path not in process_path
        return False

    def _detect_unsigned_binary(self, is_signed: bool, process_path: str) -> bool:
        """Detects unsigned binaries running from sensitive locations.[cite: 2]"""
        if is_signed:
            return False
        return any(folder in process_path for folder in _KNOWN_SYSTEM_FOLDERS)

    def _detect_suspicious_parent(self, parent_process: str, process_name: str) -> bool:
        """Detects applications like Office spawning scripting engines or shells.[cite: 2]"""
        if parent_process in _KNOWN_SUSPICIOUS_PARENTS:
            if process_name in _KNOWN_SCRIPT_ENGINES:
                return True
        return False

    def _detect_process_chain(self, parent_process: str, process_name: str, command_line: str) -> bool:
        """Detects anomalous execution chains (e.g., WMI spawning PowerShell).[cite: 2]"""
        if parent_process == "wmiprvse.exe" and process_name in _KNOWN_SCRIPT_ENGINES:
            return True
        if parent_process == "svchost.exe" and process_name == "cmd.exe" and "echo" not in command_line:
            return True
        return False

    def _detect_privilege_abuse(self, integrity_level: IntegrityLevel, command_line: str) -> bool:
        """Detects execution indicative of privilege escalation attempts.[cite: 2]"""
        if integrity_level in (IntegrityLevel.SYSTEM, IntegrityLevel.HIGH):
            abuse_cmds = ("whoami", "net user", "net localgroup administrators")
            return any(cmd in command_line for cmd in abuse_cmds)
        return False

    def _detect_system_process_anomaly(self, process_name: str, parent_process: str) -> bool:
        """Detects critical system processes spawned by incorrect parents.[cite: 2]"""
        if process_name == "lsass.exe" and parent_process != "wininit.exe":
            return True
        if process_name == "csrss.exe" and parent_process not in ("smss.exe", "svchost.exe"):
            return True
        if process_name == "svchost.exe" and parent_process != "services.exe":
            return True
        return False

    # ============================================================
    # FUTURE AI PLACEHOLDERS
    # ============================================================

    def _detect_process_hollowing_placeholder(self) -> bool:
        """TODO: Implement API hooking or memory analysis to detect hollowed processes.[cite: 2]"""
        return False

    def _detect_dll_injection_placeholder(self) -> bool:
        """TODO: Implement thread context and memory mapping analysis for DLL injection.[cite: 2]"""
        return False

    def _detect_reflective_loading_placeholder(self) -> bool:
        """TODO: Implement memory-backed module detection without disk backing.[cite: 2]"""
        return False

    def _detect_token_theft_placeholder(self) -> bool:
        """TODO: Implement thread token impersonation anomaly detection.[cite: 2]"""
        return False

    def _detect_memory_only_execution_placeholder(self) -> bool:
        """TODO: Implement unbacked memory execution detection (e.g., Cobalt Strike).[cite: 2]"""
        return False

    def _detect_behavior_model_placeholder(self) -> bool:
        """TODO: Implement behavioral sequence ML model hook.[cite: 2]"""
        return False

    def _detect_cloud_verdict_placeholder(self) -> bool:
        """TODO: Implement cloud sandbox verdict ingestion.[cite: 2]"""
        return False

    def _detect_threat_feed_placeholder(self) -> bool:
        """TODO: Implement dynamic IOC threat feed matching for process hashes.[cite: 2]"""
        return False

    def _check_reputation(self) -> bool:
        """TODO: Implement real-time process hash reputation checking.[cite: 2]"""
        return False

    def _check_signature(self) -> bool:
        """TODO: Implement deep authenticode signature validation.[cite: 2]"""
        return False

    def _check_cloud(self) -> bool:
        """TODO: Implement cloud-based anomaly scoring lookup.[cite: 2]"""
        return False

    def _check_ml_model(self) -> bool:
        """TODO: Implement local neural network scoring inference.[cite: 2]"""
        return False

    def _check_behavior_model(self) -> bool:
        """TODO: Implement user-entity behavior analytics (UEBA) baseline comparison.[cite: 2]"""
        return False

    def _check_threat_feed(self) -> bool:
        """TODO: Implement real-time MISP/OTX lookup.[cite: 2]"""
        return False

    # ============================================================
    # SCORING HELPERS
    # ============================================================

    def _score_process_name(self, is_malware: bool, category: ProcessCategory, score: float, rules: List[str], reasons: List[str]) -> float:
        if is_malware:
            if category == ProcessCategory.RANSOMWARE:
                score += RANSOMWARE_SCORE
                rules.append("Known Ransomware Tool")
                reasons.append("Process name matches a known ransomware executable.")
            elif category == ProcessCategory.MALWARE:
                score += MALWARE_SCORE
                rules.append("Known Malware")
                reasons.append("Process name matches a known malicious executable.")
            elif category == ProcessCategory.OFFENSIVE_TOOL:
                score += OFFENSIVE_TOOL_SCORE
                rules.append("Known Offensive Tool")
                reasons.append("Process name matches a known offensive security or exploitation tool.")
        return score

    def _score_lolbin(self, is_lolbin: bool, category: LOLBinCategory, score: float, rules: List[str], reasons: List[str]) -> float:
        if is_lolbin:
            score += LOLBIN_SCORE
            rules.append(f"LOLBin Execution ({category.name})")
            reasons.append(f"Execution of a dual-use administrative tool commonly abused for {category.name.lower()}.")
        return score

    def _score_path(self, masquerading: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if masquerading:
            score += MASQUERADING_SCORE
            rules.append("Process Masquerading")
            reasons.append("A critical system process is executing from an unauthorized directory.")
        return score

    def _score_command(self, susp_args: bool, dl_exec: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if susp_args:
            score += SUSPICIOUS_ARGS_SCORE
            rules.append("Suspicious Arguments")
            reasons.append("Command line contains arguments designed to bypass security controls.")
        if dl_exec:
            score += DOWNLOAD_EXEC_SCORE
            rules.append("Download and Execute")
            reasons.append("Command line attempts to download and execute payloads from the network.")
        return score

    def _score_parent(self, susp_parent: bool, anomaly_chain: bool, sys_anomaly: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if susp_parent:
            score += SUSPICIOUS_PARENT_SCORE
            rules.append("Suspicious Parent Process")
            reasons.append("Process spawned by a highly unusual parent (e.g., Office macro spawning shell).")
        if anomaly_chain:
            score += PROCESS_CHAIN_SCORE
            rules.append("Anomalous Process Chain")
            reasons.append("Process execution sequence matches known evasive or malicious patterns.")
        if sys_anomaly:
            score += SYSTEM_ANOMALY_SCORE
            rules.append("System Process Anomaly")
            reasons.append("Core system process spawned by an unauthorized parent process.")
        return score

    def _score_integrity(self, priv_abuse: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if priv_abuse:
            score += PRIVILEGE_ABUSE_SCORE
            rules.append("Privilege Abuse")
            reasons.append("Reconnaissance or administrative commands executed under SYSTEM context.")
        return score

    def _score_temp(self, is_temp: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if is_temp:
            score += TEMP_EXECUTION_SCORE
            rules.append("Execution from Temp")
            reasons.append("Process executed from a temporary or user-writable directory.")
        return score

    def _score_download(self, is_public: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if is_public:
            score += PUBLIC_FOLDER_SCORE
            rules.append("Execution from Public Folder")
            reasons.append("Process executed from a globally writable public folder.")
        return score

    def _score_script(self, is_script: bool, exts: List[str], score: float, rules: List[str], reasons: List[str]) -> float:
        if is_script:
            score += SCRIPT_EXEC_SCORE
            rules.append("Script Execution")
            reasons.append(f"Command line invokes dangerous script extensions: {', '.join(exts)}.")
        return score

    def _score_encoded(self, is_encoded: bool, is_base64: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if is_encoded:
            score += ENCODED_CMD_SCORE
            rules.append("Encoded Command")
            reasons.append("Command line utilizes flags specifically designed to hide or encode payloads.")
        if is_base64:
            score += BASE64_CMD_SCORE
            rules.append("Base64 Payload")
            reasons.append("Command line contains high-entropy data resembling Base64 encoded payloads.")
        return score

    def _score_unsigned(self, is_unsigned: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if is_unsigned:
            score += UNSIGNED_BINARY_SCORE
            rules.append("Unsigned Binary in System Path")
            reasons.append("An unsigned executable is running from a protected Windows system directory.")
        return score

    def _score_behavior(self, hidden_exec: bool, score: float, rules: List[str], reasons: List[str]) -> float:
        if hidden_exec:
            score += HIDDEN_EXECUTION_SCORE
            rules.append("Hidden Execution")
            reasons.append("Process attempts to execute completely hidden from the user interface.")
        return score

    def _score_combination(
        self,
        is_lolbin: bool,
        is_temp: bool,
        is_encoded: bool,
        dl_exec: bool,
        susp_parent: bool,
        score: float,
        rules: List[str],
        reasons: List[str]
    ) -> float:
        """Applies a combination bonus when multiple evasion techniques are layered.[cite: 2]"""
        indicator_count = sum([is_lolbin, is_temp, is_encoded, dl_exec, susp_parent])
        if indicator_count >= 3:
            score += COMBINATION_BONUS
            rules.append("Complex Evasion Chain")
            reasons.append(f"Event contains {indicator_count} overlapping evasive techniques.")
        return score

    def _calculate_score(
        self,
        is_malware: bool, mal_cat: ProcessCategory,
        is_lolbin: bool, lol_cat: LOLBinCategory,
        is_script: bool, script_exts: List[str],
        is_encoded: bool,
        is_base64: bool,
        susp_args: bool,
        dl_exec: bool,
        is_temp: bool,
        is_public: bool,
        hidden_exec: bool,
        masquerading: bool,
        unsigned_bin: bool,
        susp_parent: bool,
        anomaly_chain: bool,
        priv_abuse: bool,
        sys_anomaly: bool
    ) -> Tuple[float, List[str], List[str]]:
        """
        Orchestrates the calculation of the aggregate risk score via dedicated helpers.[cite: 2]
        """
        score = 0.0
        rules: List[str] = []
        reasons: List[str] = []

        score = self._score_process_name(is_malware, mal_cat, score, rules, reasons)
        score = self._score_lolbin(is_lolbin, lol_cat, score, rules, reasons)
        score = self._score_path(masquerading, score, rules, reasons)
        score = self._score_command(susp_args, dl_exec, score, rules, reasons)
        score = self._score_parent(susp_parent, anomaly_chain, sys_anomaly, score, rules, reasons)
        score = self._score_integrity(priv_abuse, score, rules, reasons)
        score = self._score_temp(is_temp, score, rules, reasons)
        score = self._score_download(is_public, score, rules, reasons)
        score = self._score_script(is_script, script_exts, score, rules, reasons)
        score = self._score_encoded(is_encoded, is_base64, score, rules, reasons)
        score = self._score_unsigned(unsigned_bin, score, rules, reasons)
        score = self._score_behavior(hidden_exec, score, rules, reasons)
        
        score = self._score_combination(
            is_lolbin, is_temp, is_encoded, dl_exec, susp_parent,
            score, rules, reasons
        )

        return score, rules, reasons

    def _get_risk_level(self, score: float) -> str:
        """Maps a numerical risk score to a qualitative risk level.[cite: 2]"""
        if score >= 80.0:
            return ProcessRiskLevel.CRITICAL.name
        if score >= 50.0:
            return ProcessRiskLevel.HIGH.name
        if score >= 25.0:
            return ProcessRiskLevel.MEDIUM.name
        if score > 0.0:
            return ProcessRiskLevel.LOW.name
        return ProcessRiskLevel.INFO.name

    def _calculate_confidence(self, rules: List[str]) -> float:
        """
        Calculates an independent confidence score (0-100) based on the number 
        of unique indicators matched by the detection engine.[cite: 2]
        """
        if not rules:
            return 0.0
        base_confidence = 60.0
        bonus = (len(set(rules)) - 1) * 8.0
        return min(100.0, max(0.0, base_confidence + bonus))

    # ============================================================
    # MAIN API
    # ============================================================

    def detect(self, event: Dict[str, Any]) -> DangerousProcessResult:
        """
        Analyzes a process telemetry event to detect malware, LOLBins, 
        evasion techniques, and anomalous execution chains.[cite: 2]

        Args:
            event (Dict[str, Any]): Telemetry event dictionary.

        Returns:
            DangerousProcessResult: Result object containing detection details, risk scores, and classifications.
        """
        try:
            if not isinstance(event, dict) or not event:
                logger.warning("Invalid or empty event provided to DangerousProcessDetector.")
                return DangerousProcessResult()

            # 1. Field Extraction
            fields = self._extract_fields(event)
            p_name = fields["process_name"]
            p_path = fields["process_path"]
            c_line = fields["command_line"]
            parent_name = fields["parent_process"]
            is_signed = fields["is_signed"]
            integrity = fields["integrity_level"]

            # 2. Heuristic Detection
            is_malware, mal_cat = self._detect_process_name(p_name)
            is_lolbin, lol_cat = self._detect_lolbin(p_name)
            is_script, script_exts = self._detect_script_execution(c_line)
            is_encoded = self._detect_encoded_command(c_line)
            is_base64 = self._detect_base64(c_line)
            susp_args = self._detect_suspicious_arguments(c_line)
            dl_exec = self._detect_download_execution(c_line)
            is_temp = self._detect_temp_execution(p_path)
            is_public = self._detect_public_folder_execution(p_path)
            hidden_exec = self._detect_hidden_execution(p_path, c_line)
            masquerading = self._detect_process_masquerading(p_name, p_path)
            unsigned_bin = self._detect_unsigned_binary(is_signed, p_path)
            susp_parent = self._detect_suspicious_parent(parent_name, p_name)
            anomaly_chain = self._detect_process_chain(parent_name, p_name, c_line)
            priv_abuse = self._detect_privilege_abuse(integrity, c_line)
            sys_anomaly = self._detect_system_process_anomaly(p_name, parent_name)

            # 3. Execution & Score Aggregation
            score, rules, reasons = self._calculate_score(
                is_malware, mal_cat,
                is_lolbin, lol_cat,
                is_script, script_exts,
                is_encoded, is_base64,
                susp_args, dl_exec,
                is_temp, is_public,
                hidden_exec, masquerading,
                unsigned_bin, susp_parent,
                anomaly_chain, priv_abuse,
                sys_anomaly
            )

            is_dangerous = score > 0.0
            risk_level = self._get_risk_level(score)
            confidence = self._calculate_confidence(rules)

            # Compile explicitly matched attributes for the result payload
            matched_processes = [p_name] if is_malware or is_lolbin or masquerading or sys_anomaly else []
            matched_commands = [c_line] if is_encoded or is_base64 or susp_args or dl_exec or is_script else []
            matched_paths = [p_path] if is_temp or is_public or masquerading or unsigned_bin else []
            matched_parents = [parent_name] if susp_parent or anomaly_chain or sys_anomaly else []
            matched_indicators = list(set(script_exts))

            return DangerousProcessResult(
                is_dangerous=is_dangerous,
                risk_points=score,
                risk_level=risk_level,
                confidence=confidence,
                timestamp=fields["timestamp"],
                process_name=p_name,
                process_path=p_path,
                command_line=c_line,
                pid=fields["pid"],
                parent_pid=fields["parent_pid"],
                parent_process=parent_name,
                username=fields["username"],
                integrity_level=integrity,
                matched_rules=rules,
                matched_indicators=matched_indicators,
                matched_commands=matched_commands,
                matched_processes=matched_processes,
                matched_paths=matched_paths,
                matched_parents=matched_parents,
                matched_behaviors=[],
                reasons=reasons
            )
            
        except (ValueError, TypeError, KeyError) as expected_err:
            logger.warning(f"Parsing error during process detection: {expected_err}")
            return DangerousProcessResult()
        except Exception as unexpected_err:
            logger.exception("Unexpected failure in DangerousProcessDetector.[cite: 2]")
            return DangerousProcessResult()