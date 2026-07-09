"""
============================================================
Self-Evolving Security AI
Filter Rules
Version : 1.1

Part 3.1
Rule Sets

This file ONLY stores filtering rules.

No filtering logic belongs here.

Used by:
    filters.py

Future:
    JSON rule loader
    YAML rule loader
    AI generated rules
============================================================
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import re

from dataclasses import dataclass, field
from datetime import datetime
from itertools import count
from pathlib import Path
from typing import Any

from filters.filter_config import FILTER_CONFIG


# ============================================================
# IGNORE PATHS
#
# Directory fragments known to generate high-volume,
# low-value telemetry. Matched as substrings against a
# normalized file path.
# ============================================================

IGNORE_PATHS = {

    # Windows Temporary
    r"\AppData\Local\Temp",
    r"\Windows\Temp",

    # Windows Cache
    r"\Windows\Prefetch",

    # Recycle Bin
    r"\$Recycle.Bin",
    r"\Recycler",

    # Browser Caches
    r"\Google\Chrome\User Data\Default\Cache",
    r"\Google\Chrome\User Data\Default\Code Cache",

    r"\Microsoft\Edge\User Data\Default\Cache",

    r"\Mozilla\Firefox\Profiles",

}

# ============================================================
# IGNORE FILES
#
# Exact filenames that are safe to ignore regardless of
# their location on disk.
# ============================================================

IGNORE_FILES = {

    # SQLite telemetry database
    "telemetry.db",
    "telemetry.db-journal",
    "telemetry.db-wal",
    "telemetry.db-shm",

    # Windows
    "Thumbs.db",
    "desktop.ini",

}

# ============================================================
# IGNORE EXTENSIONS
#
# File extensions that are routinely noisy and rarely
# security-relevant on their own.
# ============================================================

IGNORE_EXTENSIONS = {

    ".tmp",
    ".temp",
    ".etl",
    ".log",
    ".bak",
    ".old",

}

# ============================================================
# IGNORE FILE PATTERNS
#
# Glob-style patterns for future pattern-matching support
# (ENABLE_PATTERN_MATCHING in filter_config.py).
# ============================================================

IGNORE_PATTERNS = {

    "*.tmp",
    "*.temp",
    "*.etl",
    "*.log",
    "*.bak",
    "*.old",

}

# ============================================================
# IGNORE USERS
#
# Accounts whose routine activity is treated as background
# noise unless a NEVER_IGNORE rule overrides it.
# ============================================================

IGNORE_USERS = {

    "SYSTEM",

}

# ============================================================
# IGNORE IP ADDRESSES
#
# Loopback and local-only addresses with no external
# network exposure.
# ============================================================

IGNORE_IPS = {

    "127.0.0.1",
    "::1",

}

# ============================================================
# IGNORE TCP STATES
#
# Connection states that represent normal socket teardown
# rather than active network activity.
# ============================================================

IGNORE_STATES = {

    "TIME_WAIT",

}

# ============================================================
# IGNORE PORTS
#
# High-frequency local discovery/broadcast ports. These are
# noisy by design and not independently security-relevant;
# genuinely suspicious use of any port is still caught by
# NEVER_IGNORE_NETWORK_EVENTS and the severity engine.
# ============================================================

IGNORE_PORTS = {

    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram Service
    5353,  # mDNS (Multicast DNS)
    5355,  # LLMNR (Link-Local Multicast Name Resolution)

}

# ============================================================
# IGNORE REGISTRY KEYS
#
# Registry subkey fragments that change constantly during
# normal Windows/Explorer operation.
# ============================================================

IGNORE_REGISTRY = {

    r"\volatile environment",

    r"\muicache",

    r"\explorer\recentdocs",

}

# ============================================================
# IGNORE WINDOWS SERVICES
#
# Built-in Windows services whose routine start/stop/query
# activity is expected and not independently meaningful.
# ============================================================

IGNORE_SERVICES = {

    "Schedule",           # Task Scheduler
    "EventLog",           # Windows Event Log
    "Dnscache",           # DNS Client
    "LanmanWorkstation",  # Workstation service
    "Winmgmt",            # Windows Management Instrumentation

}

# ============================================================
# IGNORE NETWORK PROTOCOLS
#
# Local/low-level protocol chatter that is high-volume but
# not independently meaningful for detection.
# ============================================================

IGNORE_PROTOCOLS = {

    "IGMP",
    "SSDP",

}

# ============================================================
# DANGEROUS EXTENSIONS
# NEVER IGNORE THESE
#
# Executable, script, and installer extensions. Regardless
# of any ignore rule above, events involving these
# extensions must always reach the detection engine.
# ============================================================

DANGEROUS_EXTENSIONS = {

    ".exe",
    ".dll",
    ".sys",

    ".scr",
    ".cpl",

    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",

    ".msi",
    ".com",

}

# ============================================================
# NEVER IGNORE REGISTRY KEYS
#
# Persistence, authentication, and security-relevant
# registry locations. Always evaluated regardless of any
# matching IGNORE_REGISTRY entry.
# ============================================================

NEVER_IGNORE_REGISTRY = {

    r"\Run",
    r"\RunOnce",
    r"\Services",
    r"\Winlogon",
    r"\Lsa",
    r"\Windows Defender",
    r"\Policies",

}

# ============================================================
# NEVER IGNORE NETWORK EVENTS
#
# Network event types that always warrant evaluation,
# irrespective of IGNORE_PORTS, IGNORE_STATES, or
# IGNORE_PROTOCOLS matches.
# ============================================================

NEVER_IGNORE_NETWORK_EVENTS = {

    "NEW_OUTBOUND_CONNECTION",
    "LISTENING_PORT",
    "EXTERNAL_CONNECTION",
    "UNKNOWN_PROCESS",
    "DNS",
    "HTTP",
    "HTTPS",
    "SSH",
    "SMB",
    "RDP",

}

# ============================================================
# DUPLICATE FILTER CONSTANTS
#
# Governs how the duplicate cache in filters.py treats
# repeated events. DUPLICATE_WINDOW_SECONDS defines the
# time window in which an identical event hash is treated
# as a duplicate. BURST_SUPPRESSION_THRESHOLD defines how
# many repeats within that window trigger burst suppression
# rather than simple duplicate marking.
# ============================================================

DUPLICATE_WINDOW_SECONDS = 2

BURST_SUPPRESSION_THRESHOLD = 100

# ============================================================
# AI TUNING CONSTANTS
#
# Reserved constants for future rule loading, pattern
# matching, and rule validation behaviour. These are
# consumed by later parts of this module and by the
# Self-Evolving Learning layer, not by filters.py directly.
# ============================================================

MAX_IGNORE_FILE_SIZE = 1024

ENABLE_PATTERN_MATCHING = True

ENABLE_RULE_VALIDATION = True
# ============================================================
# Part 3.2
# Rule Lookup APIs
#
# Pure lookup functions. Each function answers a factual
# question about the rule data defined in Part 3.1
# ("does this value match a known rule?").
#
# No filtering DECISIONS are made here. Whether a match
# should result in an event being accepted, filtered, or
# escalated is decided exclusively in filters.py.
# ============================================================

# ============================================================
# INTERNAL NORMALIZATION HELPERS
#
# Shared by multiple public lookup functions below to avoid
# duplicated normalization code.
# ============================================================


def _normalize_path_string(path: str) -> str:
    """
    Normalize a raw path string for substring matching.

    Converts the value to a plain string, strips
    surrounding whitespace, and leaves the native path
    separators untouched so IGNORE_PATHS fragments
    (which use backslashes) match correctly on Windows
    telemetry paths.
    """

    return str(path).strip()


def _normalize_extension(extension: str) -> str:
    """
    Normalize a file extension for set membership checks.

    Ensures a single leading dot and lowercase form, e.g.
    "EXE" -> ".exe" and ".Ps1" -> ".ps1".
    """

    extension = extension.strip().lower()

    if extension and not extension.startswith("."):
        extension = f".{extension}"

    return extension


# ============================================================
# PATH LOOKUP
# ============================================================

def is_ignored_path(path: str) -> bool:
    """
    Check whether a file path falls under a known
    noisy/ignorable directory.

    Parameters
    ----------
    path : str
        Absolute or relative file path.

    Returns
    -------
    bool
        True if the path contains any fragment listed in
        IGNORE_PATHS.
    """

    if not path:
        return False

    normalized = _normalize_path_string(path).lower()

    for fragment in IGNORE_PATHS:

        if fragment.lower() in normalized:

            return True

    return False


# ============================================================
# FILE LOOKUP
# ============================================================

def is_ignored_file(filename: str) -> bool:
    """
    Check whether a filename is an exact match against
    the known ignorable file list.

    Parameters
    ----------
    filename : str
        A filename or a full path (only the final path
        component is compared).

    Returns
    -------
    bool
        True if the filename matches an entry in
        IGNORE_FILES, case-insensitively.
    """

    if not filename:
        return False

    try:

        name = Path(filename).name

    except Exception:

        name = filename

    name = name.strip().lower()

    return name in {

        f.lower()

        for f in IGNORE_FILES

    }


# ============================================================
# EXTENSION LOOKUP
# ============================================================

def is_ignored_extension(extension: str) -> bool:
    """
    Check whether a file extension is in the ignorable
    extension list.

    Parameters
    ----------
    extension : str
        File extension, with or without a leading dot
        (e.g. "tmp" or ".tmp").

    Returns
    -------
    bool
        True if the normalized extension is present in
        IGNORE_EXTENSIONS.
    """

    if not extension:
        return False

    normalized = _normalize_extension(extension)

    return normalized in {

        e.lower()

        for e in IGNORE_EXTENSIONS

    }


# ============================================================
# PATTERN LOOKUP
# ============================================================

def is_ignored_pattern(filename: str) -> bool:
    """
    Check whether a filename matches any glob-style
    ignore pattern.

    Parameters
    ----------
    filename : str
        A filename or a full path (only the final path
        component is matched).

    Returns
    -------
    bool
        True if the filename matches any pattern in
        IGNORE_PATTERNS.
    """

    if not filename:
        return False

    try:

        name = Path(filename).name

    except Exception:

        name = filename

    name = name.strip().lower()

    for pattern in IGNORE_PATTERNS:

        if fnmatch.fnmatch(name, pattern.lower()):

            return True

    return False


# ============================================================
# USER LOOKUP
# ============================================================

def is_ignored_user(user: str) -> bool:
    """
    Check whether a user account is in the ignorable
    user list.

    Parameters
    ----------
    user : str
        Account name associated with the event.

    Returns
    -------
    bool
        True if the user matches an entry in IGNORE_USERS,
        case-insensitively.
    """

    if not user:
        return False

    user = user.strip().lower()

    return user in {

        u.lower()

        for u in IGNORE_USERS

    }


# ============================================================
# IP LOOKUP
# ============================================================

def is_ignored_ip(ip: str) -> bool:
    """
    Check whether an IP address is in the ignorable
    IP list.

    Parameters
    ----------
    ip : str
        IPv4 or IPv6 address string.

    Returns
    -------
    bool
        True if the address matches an entry in
        IGNORE_IPS.
    """

    if not ip:
        return False

    try:

        normalized = str(ipaddress.ip_address(ip.strip()))

    except Exception:

        normalized = ip.strip()

    return normalized in IGNORE_IPS or ip.strip() in IGNORE_IPS


# ============================================================
# TCP STATE LOOKUP
# ============================================================

def is_ignored_state(state: str) -> bool:
    """
    Check whether a TCP connection state is in the
    ignorable state list.

    Parameters
    ----------
    state : str
        TCP state string (e.g. "TIME_WAIT", "ESTABLISHED").

    Returns
    -------
    bool
        True if the state matches an entry in
        IGNORE_STATES, case-insensitively.
    """

    if not state:
        return False

    state = state.strip().upper()

    return state in {

        s.upper()

        for s in IGNORE_STATES

    }


# ============================================================
# PORT LOOKUP
# ============================================================

def is_ignored_port(port: int | str) -> bool:
    """
    Check whether a network port is in the ignorable
    port list.

    Parameters
    ----------
    port : int | str
        Port number. Strings are coerced to int.

    Returns
    -------
    bool
        True if the port matches an entry in IGNORE_PORTS.
    """

    if port is None:
        return False

    try:

        port_number = int(port)

    except (TypeError, ValueError):

        return False

    return port_number in IGNORE_PORTS


# ============================================================
# REGISTRY LOOKUP
# ============================================================

def is_ignored_registry(key: str) -> bool:
    """
    Check whether a registry key path matches a known
    noisy/ignorable registry fragment.

    Parameters
    ----------
    key : str
        Registry key path.

    Returns
    -------
    bool
        True if the key contains any fragment listed in
        IGNORE_REGISTRY.
    """

    if not key:
        return False

    normalized = key.strip().lower()

    for fragment in IGNORE_REGISTRY:

        if fragment.lower() in normalized:

            return True

    return False


# ============================================================
# SERVICE LOOKUP
# ============================================================

def is_ignored_service(service: str) -> bool:
    """
    Check whether a Windows service name is in the
    ignorable service list.

    Parameters
    ----------
    service : str
        Windows service short name (e.g. "Schedule").

    Returns
    -------
    bool
        True if the service matches an entry in
        IGNORE_SERVICES, case-insensitively.
    """

    if not service:
        return False

    service = service.strip().lower()

    return service in {

        s.lower()

        for s in IGNORE_SERVICES

    }


# ============================================================
# PROTOCOL LOOKUP
# ============================================================

def is_ignored_protocol(protocol: str) -> bool:
    """
    Check whether a network protocol is in the ignorable
    protocol list.

    Parameters
    ----------
    protocol : str
        Protocol name (e.g. "IGMP", "SSDP").

    Returns
    -------
    bool
        True if the protocol matches an entry in
        IGNORE_PROTOCOLS, case-insensitively.
    """

    if not protocol:
        return False

    protocol = protocol.strip().upper()

    return protocol in {

        p.upper()

        for p in IGNORE_PROTOCOLS

    }


# ============================================================
# DANGEROUS EXTENSION LOOKUP
# ============================================================

def is_dangerous_extension(extension: str) -> bool:
    """
    Check whether a file extension is considered
    dangerous and must never be ignored.

    Parameters
    ----------
    extension : str
        File extension, with or without a leading dot.

    Returns
    -------
    bool
        True if the normalized extension is present in
        DANGEROUS_EXTENSIONS.
    """

    if not extension:
        return False

    normalized = _normalize_extension(extension)

    return normalized in {

        e.lower()

        for e in DANGEROUS_EXTENSIONS

    }


# ============================================================
# NEVER-IGNORE REGISTRY LOOKUP
# ============================================================

def is_never_ignore_registry(key: str) -> bool:
    """
    Check whether a registry key path matches a
    security-critical fragment that must always be
    evaluated, regardless of IGNORE_REGISTRY matches.

    Parameters
    ----------
    key : str
        Registry key path.

    Returns
    -------
    bool
        True if the key contains any fragment listed in
        NEVER_IGNORE_REGISTRY.
    """

    if not key:
        return False

    normalized = key.strip().lower()

    for fragment in NEVER_IGNORE_REGISTRY:

        if fragment.lower() in normalized:

            return True

    return False


# ============================================================
# NEVER-IGNORE NETWORK EVENT LOOKUP
# ============================================================

def is_never_ignore_network(event_type: str) -> bool:
    """
    Check whether a network event type must always be
    evaluated, regardless of IGNORE_PORTS, IGNORE_STATES,
    or IGNORE_PROTOCOLS matches.

    Parameters
    ----------
    event_type : str
        Network event type (e.g. "NEW_OUTBOUND_CONNECTION").

    Returns
    -------
    bool
        True if the event type matches an entry in
        NEVER_IGNORE_NETWORK_EVENTS, case-insensitively.
    """

    if not event_type:
        return False

    event_type = event_type.strip().upper()

    return event_type in {

        e.upper()

        for e in NEVER_IGNORE_NETWORK_EVENTS

    }
# ============================================================
# Part 3.3
# Rule Validation
#
# Validates the integrity of the rule data defined in
# Part 3.1. Detects duplicate/contradictory entries,
# malformed patterns, malformed extensions, malformed IPs,
# and malformed ports.
#
# No filtering logic belongs here. These functions report
# on the HEALTH of the rule database itself; they never
# decide whether an event should be accepted or filtered.
# ============================================================



# ============================================================
# INTERNAL VALIDATION HELPERS
#
# Used only by validate_rules(). Kept private since they
# are not part of the public rule-validation API.
# ============================================================


def _verify_ips() -> list[str]:
    """
    Verify that every entry in IGNORE_IPS is a
    syntactically valid IPv4 or IPv6 address.

    Returns
    -------
    list[str]
        IP entries that failed to parse.
    """

    invalid: list[str] = []

    for ip in IGNORE_IPS:

        try:

            ipaddress.ip_address(ip.strip())

        except Exception:

            invalid.append(ip)

    return invalid


def _verify_ports() -> list[Any]:
    """
    Verify that every entry in IGNORE_PORTS is a valid
    TCP/UDP port number in the range 0-65535.

    Returns
    -------
    list[Any]
        Port entries that are not valid integers within
        range.
    """

    invalid: list[Any] = []

    for port in IGNORE_PORTS:

        try:

            port_number = int(port)

        except (TypeError, ValueError):

            invalid.append(port)

            continue

        if not (0 <= port_number <= 65535):

            invalid.append(port)

    return invalid


# ============================================================
# DUPLICATE / CONTRADICTION DETECTION
# ============================================================

def check_duplicate_entries() -> dict[str, list[str]]:
    """
    Detect contradictory rule entries across the ignore
    and never-ignore rule sets.

    A contradiction occurs when the same entry appears in
    both an "ignore" set and its corresponding
    "never-ignore" / "dangerous" counterpart, since this
    creates an ambiguous instruction for the filter engine.

    Checks performed
    -----------------
    • IGNORE_EXTENSIONS vs DANGEROUS_EXTENSIONS
    • IGNORE_REGISTRY vs NEVER_IGNORE_REGISTRY
        (substring-aware: an ignore fragment that is a
        substring of, or contains, a never-ignore fragment
        is also flagged)

    Returns
    -------
    dict[str, list[str]]
        Mapping of conflict category -> list of
        conflicting entries. Empty lists indicate no
        conflicts were found in that category.
    """

    conflicts: dict[str, list[str]] = {

        "extension_conflicts": [],
        "registry_conflicts": [],

    }

    # --------------------------------------------------
    # Extension conflicts
    # --------------------------------------------------

    ignore_ext = {e.lower() for e in IGNORE_EXTENSIONS}
    dangerous_ext = {e.lower() for e in DANGEROUS_EXTENSIONS}

    conflicts["extension_conflicts"] = sorted(
        ignore_ext & dangerous_ext
    )

    # --------------------------------------------------
    # Registry conflicts (substring-aware)
    # --------------------------------------------------

    for ignore_fragment in IGNORE_REGISTRY:

        ignore_lower = ignore_fragment.lower()

        for never_fragment in NEVER_IGNORE_REGISTRY:

            never_lower = never_fragment.lower()

            if (
                ignore_lower in never_lower
                or never_lower in ignore_lower
            ):

                conflicts["registry_conflicts"].append(
                    f"{ignore_fragment} <-> {never_fragment}"
                )

    return conflicts


# ============================================================
# PATTERN VALIDATION
# ============================================================

def verify_patterns() -> list[str]:
    """
    Verify that every entry in IGNORE_PATTERNS is a
    syntactically valid glob-style pattern.

    A pattern is considered invalid if it is empty, or if
    it cannot be translated into a valid regular
    expression by fnmatch.

    Returns
    -------
    list[str]
        Patterns that failed validation.
    """

    invalid: list[str] = []

    for pattern in IGNORE_PATTERNS:

        if not pattern or not pattern.strip():

            invalid.append(pattern)

            continue

        try:

            compiled = fnmatch.translate(pattern)

            re.compile(compiled)

        except re.error:

            invalid.append(pattern)

    return invalid


# ============================================================
# EXTENSION VALIDATION
# ============================================================

def verify_extensions() -> dict[str, list[str]]:
    """
    Verify that every entry in IGNORE_EXTENSIONS and
    DANGEROUS_EXTENSIONS follows the expected extension
    format: a single leading dot followed by one or more
    alphanumeric characters.

    Returns
    -------
    dict[str, list[str]]
        Mapping of source set name -> list of malformed
        extensions found in that set.
    """

    pattern = re.compile(r"^\.[A-Za-z0-9]+$")

    invalid: dict[str, list[str]] = {

        "IGNORE_EXTENSIONS": [],
        "DANGEROUS_EXTENSIONS": [],

    }

    for extension in IGNORE_EXTENSIONS:

        if not pattern.match(extension):

            invalid["IGNORE_EXTENSIONS"].append(extension)

    for extension in DANGEROUS_EXTENSIONS:

        if not pattern.match(extension):

            invalid["DANGEROUS_EXTENSIONS"].append(extension)

    return invalid


# ============================================================
# MASTER VALIDATION
# ============================================================

def validate_rules() -> dict[str, Any]:
    """
    Run a full integrity check across the entire rule
    database and produce a structured validation report.

    Aggregates
    ----------
    • Duplicate / contradictory entries
    • Invalid wildcard patterns
    • Invalid extensions
    • Invalid IP addresses
    • Invalid ports

    Returns
    -------
    dict[str, Any]
        {
            "valid": bool,
            "duplicate_entries": dict[str, list[str]],
            "invalid_patterns": list[str],
            "invalid_extensions": dict[str, list[str]],
            "invalid_ips": list[str],
            "invalid_ports": list[Any],
        }

        "valid" is True only if every category above is
        empty.
    """

    duplicate_entries = check_duplicate_entries()

    invalid_patterns = verify_patterns()

    invalid_extensions = verify_extensions()

    invalid_ips = _verify_ips()

    invalid_ports = _verify_ports()

    has_errors = (

        any(duplicate_entries.values())
        or invalid_patterns
        or any(invalid_extensions.values())
        or invalid_ips
        or invalid_ports

    )

    return {

        "valid": not has_errors,

        "duplicate_entries": duplicate_entries,

        "invalid_patterns": invalid_patterns,

        "invalid_extensions": invalid_extensions,

        "invalid_ips": invalid_ips,

        "invalid_ports": invalid_ports,

    }


# ============================================================
# RULE SUMMARY / REPORTING
# ============================================================

def print_rule_summary() -> None:
    """
    Print a human-readable summary of the rule database,
    including entry counts for every rule set and the
    result of a full validation run.
    """

    print("\n========== FILTER RULES SUMMARY ==========\n")

    counts = {

        "IGNORE_PATHS": len(IGNORE_PATHS),
        "IGNORE_FILES": len(IGNORE_FILES),
        "IGNORE_EXTENSIONS": len(IGNORE_EXTENSIONS),
        "IGNORE_PATTERNS": len(IGNORE_PATTERNS),
        "IGNORE_USERS": len(IGNORE_USERS),
        "IGNORE_IPS": len(IGNORE_IPS),
        "IGNORE_STATES": len(IGNORE_STATES),
        "IGNORE_PORTS": len(IGNORE_PORTS),
        "IGNORE_REGISTRY": len(IGNORE_REGISTRY),
        "IGNORE_SERVICES": len(IGNORE_SERVICES),
        "IGNORE_PROTOCOLS": len(IGNORE_PROTOCOLS),
        "DANGEROUS_EXTENSIONS": len(DANGEROUS_EXTENSIONS),
        "NEVER_IGNORE_REGISTRY": len(NEVER_IGNORE_REGISTRY),
        "NEVER_IGNORE_NETWORK_EVENTS": len(
            NEVER_IGNORE_NETWORK_EVENTS
        ),

    }

    for name, count in counts.items():

        print(f"{name:<32}: {count}")

    print("\n---------- VALIDATION REPORT ----------\n")

    report = validate_rules()

    print(f"{'Overall valid':<32}: {report['valid']}")

    print(
        f"{'Extension conflicts':<32}: "
        f"{len(report['duplicate_entries']['extension_conflicts'])}"
    )

    print(
        f"{'Registry conflicts':<32}: "
        f"{len(report['duplicate_entries']['registry_conflicts'])}"
    )

    print(
        f"{'Invalid patterns':<32}: "
        f"{len(report['invalid_patterns'])}"
    )

    print(
        f"{'Invalid IGNORE_EXTENSIONS':<32}: "
        f"{len(report['invalid_extensions']['IGNORE_EXTENSIONS'])}"
    )

    print(
        f"{'Invalid DANGEROUS_EXTENSIONS':<32}: "
        f"{len(report['invalid_extensions']['DANGEROUS_EXTENSIONS'])}"
    )

    print(
        f"{'Invalid IPs':<32}: {len(report['invalid_ips'])}"
    )

    print(
        f"{'Invalid ports':<32}: {len(report['invalid_ports'])}"
    )

    print("\n============================================\n")
# ============================================================
# Part 3.4
# Runtime Statistics
#
# Tracks how the rule database is being exercised at
# runtime: how many rules are loaded, how often each rule
# category is hit, and how many events were ignored,
# flagged as dangerous, or flagged as never-ignore.
#
# This is bookkeeping only. No filtering decisions are
# made here — filters.py calls the increment helpers below
# after it has already decided how a rule lookup result
# should be treated.
# ============================================================



@dataclass(slots=True)
class RuleStatistics:
    """
    Runtime statistics for the rule database.

    Tracks rule-load counts and per-category hit counters
    so the engine (and, later, the AI layer) can reason
    about which rules are actually earning their keep.
    """

    # ========================================================
    # RULES LOADED
    # ========================================================

    rules_loaded: int = 0

    # ========================================================
    # RULE HITS (per category)
    # ========================================================

    path_hits: int = 0
    file_hits: int = 0
    extension_hits: int = 0
    pattern_hits: int = 0
    user_hits: int = 0
    ip_hits: int = 0
    state_hits: int = 0
    port_hits: int = 0
    registry_hits: int = 0
    service_hits: int = 0
    protocol_hits: int = 0

    # ========================================================
    # IGNORED EVENTS
    # ========================================================

    ignored_events: int = 0

    # ========================================================
    # DANGEROUS / NEVER-IGNORE HITS
    # ========================================================

    dangerous_hits: int = 0

    never_ignore_registry_hits: int = 0
    never_ignore_network_hits: int = 0

    # ========================================================
    # TOTALS
    # ========================================================

    total_lookups: int = 0

    # ========================================================
    # TIMING
    # ========================================================

    start_time: datetime = field(default_factory=datetime.utcnow)

    last_updated: datetime = field(default_factory=datetime.utcnow)


# ============================================================
# GLOBAL INSTANCE
# ============================================================

RULE_STATISTICS = RuleStatistics()


# ============================================================
# RULE LOAD TRACKING
# ============================================================

def record_rules_loaded() -> None:
    """
    Record that the rule database has been (re)loaded.

    Computes the total number of individual rule entries
    across every rule set defined in Part 3.1 and stores
    it in RULE_STATISTICS.rules_loaded.
    """

    RULE_STATISTICS.rules_loaded = (

        len(IGNORE_PATHS)
        + len(IGNORE_FILES)
        + len(IGNORE_EXTENSIONS)
        + len(IGNORE_PATTERNS)
        + len(IGNORE_USERS)
        + len(IGNORE_IPS)
        + len(IGNORE_STATES)
        + len(IGNORE_PORTS)
        + len(IGNORE_REGISTRY)
        + len(IGNORE_SERVICES)
        + len(IGNORE_PROTOCOLS)
        + len(DANGEROUS_EXTENSIONS)
        + len(NEVER_IGNORE_REGISTRY)
        + len(NEVER_IGNORE_NETWORK_EVENTS)

    )

    RULE_STATISTICS.last_updated = datetime.utcnow()


# ============================================================
# HIT RECORDING HELPERS
#
# Each helper increments the matching per-category counter
# plus the running total. Intended to be called by
# filters.py immediately after a corresponding
# is_ignored_*() / is_dangerous_*() / is_never_ignore_*()
# lookup returns True.
# ============================================================

def record_path_hit() -> None:
    """Record an IGNORE_PATHS match."""

    RULE_STATISTICS.path_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_file_hit() -> None:
    """Record an IGNORE_FILES match."""

    RULE_STATISTICS.file_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_extension_hit() -> None:
    """Record an IGNORE_EXTENSIONS match."""

    RULE_STATISTICS.extension_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_pattern_hit() -> None:
    """Record an IGNORE_PATTERNS match."""

    RULE_STATISTICS.pattern_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_user_hit() -> None:
    """Record an IGNORE_USERS match."""

    RULE_STATISTICS.user_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_ip_hit() -> None:
    """Record an IGNORE_IPS match."""

    RULE_STATISTICS.ip_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_state_hit() -> None:
    """Record an IGNORE_STATES match."""

    RULE_STATISTICS.state_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_port_hit() -> None:
    """Record an IGNORE_PORTS match."""

    RULE_STATISTICS.port_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_registry_hit() -> None:
    """Record an IGNORE_REGISTRY match."""

    RULE_STATISTICS.registry_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_service_hit() -> None:
    """Record an IGNORE_SERVICES match."""

    RULE_STATISTICS.service_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_protocol_hit() -> None:
    """Record an IGNORE_PROTOCOLS match."""

    RULE_STATISTICS.protocol_hits += 1
    RULE_STATISTICS.total_lookups += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_ignored_event() -> None:
    """
    Record that an event was ultimately ignored as a
    result of any ignore-rule match.
    """

    RULE_STATISTICS.ignored_events += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_dangerous_hit() -> None:
    """
    Record a DANGEROUS_EXTENSIONS match (an event that
    must never be ignored due to its extension).
    """

    RULE_STATISTICS.dangerous_hits += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_never_ignore_registry_hit() -> None:
    """
    Record a NEVER_IGNORE_REGISTRY match.
    """

    RULE_STATISTICS.never_ignore_registry_hits += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


def record_never_ignore_network_hit() -> None:
    """
    Record a NEVER_IGNORE_NETWORK_EVENTS match.
    """

    RULE_STATISTICS.never_ignore_network_hits += 1
    RULE_STATISTICS.last_updated = datetime.utcnow()


# ============================================================
# RESET
# ============================================================

def reset_statistics() -> None:
    """
    Reset all runtime rule statistics back to zero.

    Rule data itself (Part 3.1) is untouched; only the
    counters in RULE_STATISTICS are cleared. Useful for
    test isolation and for periodic statistics rollover.
    """

    RULE_STATISTICS.rules_loaded = 0

    RULE_STATISTICS.path_hits = 0
    RULE_STATISTICS.file_hits = 0
    RULE_STATISTICS.extension_hits = 0
    RULE_STATISTICS.pattern_hits = 0
    RULE_STATISTICS.user_hits = 0
    RULE_STATISTICS.ip_hits = 0
    RULE_STATISTICS.state_hits = 0
    RULE_STATISTICS.port_hits = 0
    RULE_STATISTICS.registry_hits = 0
    RULE_STATISTICS.service_hits = 0
    RULE_STATISTICS.protocol_hits = 0

    RULE_STATISTICS.ignored_events = 0

    RULE_STATISTICS.dangerous_hits = 0

    RULE_STATISTICS.never_ignore_registry_hits = 0
    RULE_STATISTICS.never_ignore_network_hits = 0

    RULE_STATISTICS.total_lookups = 0

    RULE_STATISTICS.start_time = datetime.utcnow()
    RULE_STATISTICS.last_updated = datetime.utcnow()


# ============================================================
# SUMMARY
# ============================================================

def get_statistics_summary() -> dict[str, Any]:
    """
    Return the current rule statistics as a plain
    dictionary.

    Useful for database insertion, logging, and future
    AI/self-evolving learning consumption.

    Returns
    -------
    dict[str, Any]
    """

    return {

        "rules_loaded": RULE_STATISTICS.rules_loaded,

        "hits": {

            "path": RULE_STATISTICS.path_hits,
            "file": RULE_STATISTICS.file_hits,
            "extension": RULE_STATISTICS.extension_hits,
            "pattern": RULE_STATISTICS.pattern_hits,
            "user": RULE_STATISTICS.user_hits,
            "ip": RULE_STATISTICS.ip_hits,
            "state": RULE_STATISTICS.state_hits,
            "port": RULE_STATISTICS.port_hits,
            "registry": RULE_STATISTICS.registry_hits,
            "service": RULE_STATISTICS.service_hits,
            "protocol": RULE_STATISTICS.protocol_hits,

        },

        "ignored_events": RULE_STATISTICS.ignored_events,

        "dangerous_hits": RULE_STATISTICS.dangerous_hits,

        "never_ignore_registry_hits": (
            RULE_STATISTICS.never_ignore_registry_hits
        ),

        "never_ignore_network_hits": (
            RULE_STATISTICS.never_ignore_network_hits
        ),

        "total_lookups": RULE_STATISTICS.total_lookups,

        "start_time": RULE_STATISTICS.start_time,

        "last_updated": RULE_STATISTICS.last_updated,

    }


def print_statistics_summary() -> None:
    """
    Print a human-readable summary of the current rule
    statistics.
    """

    print("\n========== RULE STATISTICS SUMMARY ==========\n")

    summary = get_statistics_summary()

    print(f"{'Rules loaded':<32}: {summary['rules_loaded']}")

    print()

    print("Hit counts:")

    for category, count in summary["hits"].items():

        print(f"    {category:<28}: {count}")

    print()

    print(f"{'Ignored events':<32}: {summary['ignored_events']}")

    print(
        f"{'Dangerous hits':<32}: {summary['dangerous_hits']}"
    )

    print(
        f"{'Never-ignore registry hits':<32}: "
        f"{summary['never_ignore_registry_hits']}"
    )

    print(
        f"{'Never-ignore network hits':<32}: "
        f"{summary['never_ignore_network_hits']}"
    )

    print(
        f"{'Total lookups':<32}: {summary['total_lookups']}"
    )

    print(f"{'Start time':<32}: {summary['start_time']}")

    print(f"{'Last updated':<32}: {summary['last_updated']}")

    print("\n===============================================\n")
# ============================================================
# Part 3.5
# Dynamic Rule Loader
#
# FUTURE SUPPORT ONLY.
#
# These functions allow the rule database to eventually be
# loaded from external JSON/YAML files and hot-reloaded at
# runtime, in preparation for the Self-Evolving Learning
# layer generating or updating rules automatically.
#
# They are NOT currently invoked by filters.py or anywhere
# else in the pipeline. They are production-ready but
# intentionally disconnected until the AI layer and a
# controlled rollout process exist.
#
# No filtering logic belongs here — these functions only
# load, merge, reload, and export rule DATA.
# ============================================================

try:

    import yaml

    _YAML_AVAILABLE = True

except ImportError:

    yaml = None

    _YAML_AVAILABLE = False

from filters.filter_config import FILTER_CONFIG

_loader_logger = logging.getLogger(__name__)

# ============================================================
# RULE SET REGISTRY
#
# Maps external-facing rule names to the live, in-memory
# rule sets defined in Part 3.1. Since Python sets are
# mutable, holding references here allows merge_rules()
# and export_rules() to operate on the actual module-level
# rule sets rather than copies.
# ============================================================

RULE_SET_REGISTRY: dict[str, set[Any]] = {

    "IGNORE_PATHS": IGNORE_PATHS,
    "IGNORE_FILES": IGNORE_FILES,
    "IGNORE_EXTENSIONS": IGNORE_EXTENSIONS,
    "IGNORE_PATTERNS": IGNORE_PATTERNS,
    "IGNORE_USERS": IGNORE_USERS,
    "IGNORE_IPS": IGNORE_IPS,
    "IGNORE_STATES": IGNORE_STATES,
    "IGNORE_PORTS": IGNORE_PORTS,
    "IGNORE_REGISTRY": IGNORE_REGISTRY,
    "IGNORE_SERVICES": IGNORE_SERVICES,
    "IGNORE_PROTOCOLS": IGNORE_PROTOCOLS,
    "DANGEROUS_EXTENSIONS": DANGEROUS_EXTENSIONS,
    "NEVER_IGNORE_REGISTRY": NEVER_IGNORE_REGISTRY,
    "NEVER_IGNORE_NETWORK_EVENTS": NEVER_IGNORE_NETWORK_EVENTS,

}


# ============================================================
# JSON LOADER
# ============================================================

def load_json_rules(path: Path | str | None = None) -> dict[str, Any]:
    """
    Load rule data from a JSON file.

    This function ONLY parses and returns the file contents.
    It does not merge the data into the live rule database —
    call merge_rules() explicitly for that.

    Parameters
    ----------
    path : Path | str | None
        Path to the JSON rule file. Defaults to
        FILTER_CONFIG.JSON_RULE_PATH.

    Returns
    -------
    dict[str, Any]
        Parsed rule data, keyed by rule set name. Returns
        an empty dict if the file is missing, unreadable,
        or does not contain a JSON object at the top level.
    """

    resolved_path = Path(path) if path else FILTER_CONFIG.JSON_RULE_PATH

    if not resolved_path.exists():

        _loader_logger.warning(
            "JSON rule file not found: %s", resolved_path
        )

        return {}

    try:

        with open(resolved_path, "r", encoding="utf-8") as handle:

            data = json.load(handle)

    except (OSError, json.JSONDecodeError) as exc:

        _loader_logger.error(
            "Failed to load JSON rule file %s: %s",
            resolved_path,
            exc,
        )

        return {}

    if not isinstance(data, dict):

        _loader_logger.error(
            "JSON rule file %s does not contain a top-level object",
            resolved_path,
        )

        return {}

    return data


# ============================================================
# YAML LOADER
# ============================================================

def load_yaml_rules(path: Path | str | None = None) -> dict[str, Any]:
    """
    Load rule data from a YAML file.

    This function ONLY parses and returns the file contents.
    It does not merge the data into the live rule database —
    call merge_rules() explicitly for that.

    Parameters
    ----------
    path : Path | str | None
        Path to the YAML rule file. Defaults to
        FILTER_CONFIG.YAML_RULE_PATH.

    Returns
    -------
    dict[str, Any]
        Parsed rule data, keyed by rule set name. Returns
        an empty dict if PyYAML is unavailable, the file is
        missing/unreadable, or does not contain a mapping
        at the top level.
    """

    if not _YAML_AVAILABLE:

        _loader_logger.warning(
            "PyYAML is not installed; cannot load YAML rules."
        )

        return {}

    resolved_path = Path(path) if path else FILTER_CONFIG.YAML_RULE_PATH

    if not resolved_path.exists():

        _loader_logger.warning(
            "YAML rule file not found: %s", resolved_path
        )

        return {}

    try:

        with open(resolved_path, "r", encoding="utf-8") as handle:

            data = yaml.safe_load(handle)

    except (OSError, yaml.YAMLError) as exc:

        _loader_logger.error(
            "Failed to load YAML rule file %s: %s",
            resolved_path,
            exc,
        )

        return {}

    if not isinstance(data, dict):

        _loader_logger.error(
            "YAML rule file %s does not contain a top-level mapping",
            resolved_path,
        )

        return {}

    return data


# ============================================================
# MERGE
# ============================================================

def merge_rules(
    new_rules: dict[str, Any],
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Merge externally loaded rule data into the live,
    in-memory rule sets.

    Parameters
    ----------
    new_rules : dict[str, Any]
        Rule data as returned by load_json_rules() or
        load_yaml_rules(). Keys must match entries in
        RULE_SET_REGISTRY to be applied; unrecognized keys
        are reported but ignored.

    overwrite : bool
        If True, each matching rule set is cleared before
        the new entries are added. If False (default), new
        entries are added alongside the existing ones.

    Returns
    -------
    dict[str, Any]
        {
            "merged": dict[str, int],       # set name -> entries added
            "unknown_keys": list[str],
            "errors": list[str],
        }
    """

    report: dict[str, Any] = {

        "merged": {},

        "unknown_keys": [],

        "errors": [],

    }

    for key, values in new_rules.items():

        target_set = RULE_SET_REGISTRY.get(key)

        if target_set is None:

            report["unknown_keys"].append(key)

            continue

        if not isinstance(values, (list, set, tuple)):

            report["errors"].append(
                f"{key}: expected a list of values, "
                f"got {type(values).__name__}"
            )

            continue

        if overwrite:

            target_set.clear()

        before_count = len(target_set)

        target_set.update(values)

        report["merged"][key] = len(target_set) - before_count

    record_rules_loaded()

    return report


# ============================================================
# RELOAD
# ============================================================

def reload_rules() -> dict[str, Any]:
    """
    Reload rule data from the configured JSON/YAML sources
    and merge it into the live rule database.

    Honors FILTER_CONFIG.ENABLE_JSON_RULES and
    FILTER_CONFIG.ENABLE_YAML_RULES. If both are disabled,
    this is a no-op that returns an empty report.

    This function is orchestration only — it is not
    currently called from anywhere in the active pipeline.
    It exists so that a future scheduler (driven by
    FILTER_CONFIG.AUTO_RELOAD_RULES and
    FILTER_CONFIG.RULE_RELOAD_INTERVAL) can call it safely
    once enabled.

    Returns
    -------
    dict[str, Any]
        {
            "json": dict[str, Any] | None,   # merge_rules() report, or None if skipped
            "yaml": dict[str, Any] | None,
        }
    """

    result: dict[str, Any] = {

        "json": None,

        "yaml": None,

    }

    if FILTER_CONFIG.ENABLE_JSON_RULES:

        json_data = load_json_rules()

        if json_data:

            result["json"] = merge_rules(json_data, overwrite=False)

    if FILTER_CONFIG.ENABLE_YAML_RULES:

        yaml_data = load_yaml_rules()

        if yaml_data:

            result["yaml"] = merge_rules(yaml_data, overwrite=False)

    return result


# ============================================================
# EXPORT
# ============================================================

def export_rules(
    path: Path | str,
    file_format: str = "json",
) -> bool:
    """
    Export the current in-memory rule database to disk.

    Useful for backups, version control snapshots, or
    handing the current rule state to the Self-Evolving
    Learning layer for analysis.

    Parameters
    ----------
    path : Path | str
        Destination file path.

    file_format : str
        Either "json" or "yaml". Defaults to "json".

    Returns
    -------
    bool
        True if the export succeeded, False otherwise.
    """

    file_format = file_format.strip().lower()

    if file_format not in ("json", "yaml"):

        _loader_logger.error(
            "Unsupported export format: %s", file_format
        )

        return False

    serializable = {

        name: sorted(rule_set, key=str)

        for name, rule_set in RULE_SET_REGISTRY.items()

    }

    destination = Path(path)

    try:

        destination.parent.mkdir(parents=True, exist_ok=True)

        if file_format == "json":

            with open(destination, "w", encoding="utf-8") as handle:

                json.dump(serializable, handle, indent=4, default=str)

        else:

            if not _YAML_AVAILABLE:

                _loader_logger.warning(
                    "PyYAML is not installed; cannot export YAML rules."
                )

                return False

            with open(destination, "w", encoding="utf-8") as handle:

                yaml.safe_dump(serializable, handle, sort_keys=True)

    except OSError as exc:

        _loader_logger.error(
            "Failed to export rules to %s: %s", destination, exc
        )

        return False

    return True
# ============================================================
# Part 3.6
# Future Self-Evolving AI Support
#
# ARCHITECTURE ONLY. No machine learning is implemented.
#
# This section defines the data structures and staging
# workflow that will eventually let the AI Engine propose
# new ignore rules, danger rules, reputation scores, and
# confidence adjustments — without ever letting the AI
# silently mutate the live, human-authored rule sets from
# Part 3.1.
#
# Everything the AI proposes lands in a STAGING area first
# (AI_RULE_PROPOSALS). Nothing is promoted into an active
# learned-rule set without going through
# validate_learned_rules() and an explicit
# promote_learned_rule() call. Nothing here is wired into
# filters.py yet.
# ============================================================


# ============================================================
# LEARNED RULE ENTRY
# ============================================================


@dataclass(slots=True)
class LearnedRuleEntry:
    """
    A single AI-proposed rule, pending or promoted.

    Represents one unit of "learning" — an ignore rule, a
    danger rule, a reputation update, or a confidence
    adjustment — before it becomes part of the trusted,
    active rule database.
    """

    rule_id: int
    category: str          # "ignore" | "danger" | "reputation" | "confidence"
    value: Any
    source: str = "unknown"
    confidence: float = 0.0
    approved: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved_at: datetime | None = None


# ============================================================
# STAGING REGISTRY
#
# All AI-proposed entries live here until explicitly
# promoted. Keyed by rule_id.
# ============================================================

AI_RULE_PROPOSALS: dict[int, LearnedRuleEntry] = {}

_ai_rule_id_counter = count(1)

# ============================================================
# APPROVED LEARNED RULE SETS
#
# Populated only via promote_learned_rule(). Kept separate
# from Part 3.1's human-authored sets so learned rules can
# always be audited, reset, or rolled back independently.
# ============================================================

LEARNED_IGNORE_RULES: set[Any] = set()

LEARNED_DANGER_RULES: set[Any] = set()

# ============================================================
# REPUTATION RULES
#
# entity -> reputation score (0.0 - 100.0). Neutral default
# is 50.0. No scoring algorithm is implemented; this is
# storage only.
# ============================================================

REPUTATION_RULES: dict[str, float] = {}

_DEFAULT_REPUTATION_SCORE = 50.0

# ============================================================
# CONFIDENCE ADJUSTMENTS
#
# category -> adjustment delta to be applied by the future
# confidence-scoring engine. Storage only; no application
# logic lives here (that belongs to filters.py's
# _calculate_confidence, once implemented).
# ============================================================

CONFIDENCE_ADJUSTMENTS: dict[str, float] = {}


# ============================================================
# FUTURE AI RULE INJECTION
# ============================================================

def propose_ai_rule(
    category: str,
    value: Any,
    source: str = "ai_engine",
    confidence: float = 0.0,
) -> int | None:
    """
    Submit an AI-proposed rule for staging.

    This is the single entry point the future AI Engine
    will use to suggest new rule data. Nothing is applied
    to the active rule database here — the proposal is
    only recorded in AI_RULE_PROPOSALS.

    Gated by FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS: if the
    switch is off, no proposal is recorded.

    Parameters
    ----------
    category : str
        One of "ignore", "danger", "reputation", "confidence".

    value : Any
        The proposed rule value (e.g. a path fragment, an
        extension, an entity name, or a category name for
        confidence adjustments).

    source : str
        Identifier for what generated the proposal (e.g.
        a model name or heuristic name).

    confidence : float
        The AI Engine's own confidence in this proposal,
        0-100. Storage only; not validated against any
        threshold here.

    Returns
    -------
    int | None
        The assigned rule_id, or None if proposals are
        currently disabled.
    """

    if not FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS:

        return None

    rule_id = next(_ai_rule_id_counter)

    AI_RULE_PROPOSALS[rule_id] = LearnedRuleEntry(
        rule_id=rule_id,
        category=category,
        value=value,
        source=source,
        confidence=confidence,
    )

    return rule_id


# ============================================================
# AUTOMATIC RULE VALIDATION (LEARNED RULES)
# ============================================================

def validate_learned_rules() -> dict[str, list[int]]:
    """
    Validate all pending proposals in AI_RULE_PROPOSALS.

    This performs structural validation only (well-formed
    category, non-empty value, confidence in range). It
    does NOT judge whether a proposal is a "good" security
    rule — that judgment is out of scope until an actual
    learning/reasoning component exists.

    Returns
    -------
    dict[str, list[int]]
        {
            "valid": list[int],     # rule_ids that passed structural checks
            "invalid": list[int],   # rule_ids that failed
        }
    """

    valid_categories = {"ignore", "danger", "reputation", "confidence"}

    result: dict[str, list[int]] = {

        "valid": [],

        "invalid": [],

    }

    for rule_id, entry in AI_RULE_PROPOSALS.items():

        is_valid = (

            entry.category in valid_categories
            and entry.value is not None
            and entry.value != ""
            and 0.0 <= entry.confidence <= 100.0

        )

        if is_valid:

            result["valid"].append(rule_id)

        else:

            result["invalid"].append(rule_id)

    return result


# ============================================================
# PROMOTION / REJECTION
# ============================================================

def promote_learned_rule(rule_id: int) -> bool:
    """
    Promote a validated proposal into its corresponding
    active learned-rule structure.

    Gated by FILTER_CONFIG.ENABLE_LEARNING_MODE: if the
    switch is off, promotion is refused even for
    structurally valid proposals.

    Parameters
    ----------
    rule_id : int
        The proposal's rule_id, as returned by
        propose_ai_rule().

    Returns
    -------
    bool
        True if the proposal was promoted, False if it was
        not found, failed validation, or learning mode is
        disabled.
    """

    if not FILTER_CONFIG.ENABLE_LEARNING_MODE:

        return False

    entry = AI_RULE_PROPOSALS.get(rule_id)

    if entry is None:

        return False

    validation = validate_learned_rules()

    if rule_id not in validation["valid"]:

        return False

    if entry.category == "ignore":

        LEARNED_IGNORE_RULES.add(entry.value)

    elif entry.category == "danger":

        LEARNED_DANGER_RULES.add(entry.value)

    elif entry.category == "reputation":

        REPUTATION_RULES[str(entry.value)] = entry.confidence

    elif entry.category == "confidence":

        CONFIDENCE_ADJUSTMENTS[str(entry.value)] = entry.confidence

    else:

        return False

    entry.approved = True

    entry.approved_at = datetime.utcnow()

    return True


def reject_learned_rule(rule_id: int) -> bool:
    """
    Discard a pending proposal without promoting it.

    Parameters
    ----------
    rule_id : int
        The proposal's rule_id.

    Returns
    -------
    bool
        True if the proposal existed and was removed,
        False otherwise.
    """

    return AI_RULE_PROPOSALS.pop(rule_id, None) is not None


# ============================================================
# LEARNED IGNORE / DANGER RULE ACCESS
# ============================================================

def is_learned_ignore(value: Any) -> bool:
    """
    Check whether a value has been promoted into
    LEARNED_IGNORE_RULES.

    Always returns False if FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS
    is disabled, regardless of stored content.
    """

    if not FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS:

        return False

    return value in LEARNED_IGNORE_RULES


def is_learned_danger(value: Any) -> bool:
    """
    Check whether a value has been promoted into
    LEARNED_DANGER_RULES.

    Always returns False if FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS
    is disabled, regardless of stored content.
    """

    if not FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS:

        return False

    return value in LEARNED_DANGER_RULES


# ============================================================
# REPUTATION ACCESS
# ============================================================

def get_reputation(entity: str) -> float:
    """
    Retrieve the stored reputation score for an entity.

    Returns the neutral default score if the entity has no
    stored reputation, or if
    FILTER_CONFIG.ENABLE_REPUTATION_ENGINE is disabled.

    Parameters
    ----------
    entity : str
        Process name, publisher, domain, or IP the score
        applies to.

    Returns
    -------
    float
        Reputation score, 0.0 - 100.0.
    """

    if not FILTER_CONFIG.ENABLE_REPUTATION_ENGINE:

        return _DEFAULT_REPUTATION_SCORE

    return REPUTATION_RULES.get(entity, _DEFAULT_REPUTATION_SCORE)


def set_reputation(entity: str, score: float) -> None:
    """
    Directly set a reputation score for an entity.

    Intended for manual overrides / test scaffolding. AI-
    driven updates should go through propose_ai_rule() and
    promote_learned_rule() instead, so they are auditable.

    Parameters
    ----------
    entity : str
        Process name, publisher, domain, or IP.

    score : float
        New reputation score. Clamped to 0.0 - 100.0.
    """

    REPUTATION_RULES[entity] = max(0.0, min(100.0, score))


# ============================================================
# CONFIDENCE ADJUSTMENT ACCESS
# ============================================================

def get_confidence_adjustment(category: str) -> float:
    """
    Retrieve the stored confidence adjustment for a
    category.

    Returns 0.0 (no adjustment) if none has been learned
    yet, or if FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS is
    disabled.

    Parameters
    ----------
    category : str
        Adjustment category name (defined by whatever
        future _calculate_confidence implementation in
        filters.py chooses to use).

    Returns
    -------
    float
        Adjustment delta.
    """

    if not FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS:

        return 0.0

    return CONFIDENCE_ADJUSTMENTS.get(category, 0.0)


# ============================================================
# RESET
# ============================================================

def reset_learned_rules() -> None:
    """
    Clear all learned rules, staged proposals, reputation
    scores, and confidence adjustments.

    Does not affect the human-authored rule sets from
    Part 3.1. Intended for test isolation and controlled
    rollback of AI-driven state.
    """

    AI_RULE_PROPOSALS.clear()

    LEARNED_IGNORE_RULES.clear()

    LEARNED_DANGER_RULES.clear()

    REPUTATION_RULES.clear()

    CONFIDENCE_ADJUSTMENTS.clear()


# ============================================================
# SUMMARY
# ============================================================

def get_ai_rule_summary() -> dict[str, Any]:
    """
    Return a snapshot of the current AI rule-learning
    state.

    Returns
    -------
    dict[str, Any]
    """

    return {

        "pending_proposals": len(AI_RULE_PROPOSALS),

        "learned_ignore_rules": len(LEARNED_IGNORE_RULES),

        "learned_danger_rules": len(LEARNED_DANGER_RULES),

        "reputation_entries": len(REPUTATION_RULES),

        "confidence_adjustments": len(CONFIDENCE_ADJUSTMENTS),

        "dynamic_filters_enabled": FILTER_CONFIG.ENABLE_DYNAMIC_FILTERS,

        "learning_mode_enabled": FILTER_CONFIG.ENABLE_LEARNING_MODE,

        "reputation_engine_enabled": FILTER_CONFIG.ENABLE_REPUTATION_ENGINE,

    }