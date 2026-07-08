"""
==========================================================
Telemetry Event Types
Self-Evolving Security AI

This module contains all event types used by the
telemetry collectors.

Having one centralized location prevents typos and
keeps event names consistent across the project.
==========================================================
"""

from enum import Enum


# ==========================================================
# Process Events
# ==========================================================

class ProcessEventType(Enum):
    """
    Process lifecycle events.
    """

    CREATED = "PROCESS_CREATED"

    TERMINATED = "PROCESS_TERMINATED"


# ==========================================================
# File Events
# ==========================================================

class FileEventType(Enum):
    """
    File system events.
    """

    CREATED = "FILE_CREATED"

    MODIFIED = "FILE_MODIFIED"

    DELETED = "FILE_DELETED"

    RENAMED = "FILE_RENAMED"

    ACCESSED = "FILE_ACCESSED"


# ==========================================================
# Network Events
# ==========================================================

class NetworkEventType(Enum):
    """
    Network connection events.
    """

    CONNECTED = "NETWORK_CONNECTED"

    DISCONNECTED = "NETWORK_DISCONNECTED"

    TCP_CONNECTION = "TCP_CONNECTION"

    UDP_CONNECTION = "UDP_CONNECTION"

    DNS_QUERY = "DNS_QUERY"

    HTTP_REQUEST = "HTTP_REQUEST"

    HTTPS_REQUEST = "HTTPS_REQUEST"


# ==========================================================
# Registry Events
# ==========================================================

class RegistryEventType(str, Enum):
    """
    Windows Registry events.
    """

    KEY_CREATED = "REGISTRY_KEY_CREATED"

    KEY_MODIFIED = "REGISTRY_KEY_MODIFIED"

    KEY_DELETED = "REGISTRY_KEY_DELETED"

    VALUE_CREATED = "REGISTRY_VALUE_CREATED"

    VALUE_MODIFIED = "REGISTRY_VALUE_MODIFIED"

    VALUE_DELETED = "REGISTRY_VALUE_DELETED"


# ==========================================================
# Service Events (Future)
# ==========================================================

class ServiceEventType(Enum):
    """
    Windows Service events.
    """

    CREATED = "SERVICE_CREATED"

    STARTED = "SERVICE_STARTED"

    STOPPED = "SERVICE_STOPPED"

    MODIFIED = "SERVICE_MODIFIED"

    DELETED = "SERVICE_DELETED"


# ==========================================================
# Driver Events (Future)
# ==========================================================

class DriverEventType(Enum):
    """
    Kernel driver events.
    """

    LOADED = "DRIVER_LOADED"

    UNLOADED = "DRIVER_UNLOADED"


# ==========================================================
# AI Behavior Events (Future)
# ==========================================================

class BehaviorEventType(Enum):
    """
    High-level AI behavior detections.
    """

    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"

    MASS_FILE_RENAME = "MASS_FILE_RENAME"

    MASS_FILE_DELETE = "MASS_FILE_DELETE"

    MASS_FILE_MODIFICATION = "MASS_FILE_MODIFICATION"

    RANSOMWARE_BEHAVIOR = "RANSOMWARE_BEHAVIOR"

    DATA_EXFILTRATION = "DATA_EXFILTRATION"

    PERSISTENCE_DETECTED = "PERSISTENCE_DETECTED"

    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"

    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"

    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"