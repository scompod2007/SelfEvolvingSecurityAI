"""
============================================================
Self-Evolving Security AI
Part 2.8.6 - Dangerous Network Detection
============================================================

This module provides detection capabilities for identifying risky 
network-related telemetry, such as connections to public IPs, 
suspicious ports, dangerous protocols, and DNS abuse.

It has been refactored for improved maintainability, extensibility, 
future AI threat intelligence integration, robust exception handling, 
and high-performance stateless execution.
"""

import ipaddress
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from types import MappingProxyType
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)


# ============================================================
# CATEGORIES
# ============================================================
class PortCategory(Enum):
    """Enumeration of network port threat categories."""
    REMOTE_ACCESS = auto()
    DATABASE = auto()
    MALWARE = auto()
    ADMINISTRATION = auto()
    PROXY = auto()
    TOR = auto()
    STANDARD = auto()
    UNKNOWN = auto()


# ============================================================
# SCORING CONSTANTS
# ============================================================
PUBLIC_IP_SCORE: float = 10.0
OUTBOUND_SCORE: float = 5.0
DANGEROUS_PORT_SCORE: float = 15.0
HIGH_RISK_PORT_BONUS: float = 20.0
DANGEROUS_PROTOCOL_SCORE: float = 15.0
DNS_SCORE: float = 20.0
TOR_SCORE: float = 40.0
PROXY_SCORE: float = 15.0
BEACON_SCORE: float = 25.0
COMBINATION_BONUS: float = 30.0
BROADCAST_SCORE: float = 15.0


# ============================================================
# DETECTION CONSTANTS (IMMUTABLE)
# ============================================================
_PORT_CATEGORIES = MappingProxyType({
    21: PortCategory.REMOTE_ACCESS,
    22: PortCategory.REMOTE_ACCESS,
    23: PortCategory.REMOTE_ACCESS,
    25: PortCategory.STANDARD,
    53: PortCategory.STANDARD,
    69: PortCategory.REMOTE_ACCESS,
    80: PortCategory.STANDARD,
    110: PortCategory.STANDARD,
    135: PortCategory.ADMINISTRATION,
    137: PortCategory.ADMINISTRATION,
    138: PortCategory.ADMINISTRATION,
    139: PortCategory.ADMINISTRATION,
    143: PortCategory.STANDARD,
    389: PortCategory.ADMINISTRATION,
    443: PortCategory.STANDARD,
    445: PortCategory.ADMINISTRATION,
    465: PortCategory.STANDARD,
    587: PortCategory.STANDARD,
    636: PortCategory.ADMINISTRATION,
    1433: PortCategory.DATABASE,
    1521: PortCategory.DATABASE,
    3306: PortCategory.DATABASE,
    3389: PortCategory.REMOTE_ACCESS,
    4444: PortCategory.MALWARE,
    5555: PortCategory.MALWARE,
    5900: PortCategory.REMOTE_ACCESS,
    6667: PortCategory.MALWARE,
    8080: PortCategory.PROXY,
    8443: PortCategory.PROXY,
    9001: PortCategory.TOR,
    9050: PortCategory.TOR,
    1080: PortCategory.PROXY,
    31337: PortCategory.MALWARE,
})

_HIGH_RISK_PORTS: tuple[int, ...] = (
    21,    # FTP
    23,    # Telnet
    445,   # SMB
    3389,  # RDP
    4444,  # Common Metasploit payload port
    5555,  # Common Android ADB / malware port
    31337, # BackOrifice
)

_DANGEROUS_PROTOCOLS: tuple[str, ...] = (
    "SMB", "FTP", "TELNET", "TFTP", "RDP", "SSH", "TOR", "SOCKS",
    "LDAP", "LDAPS", "NFS", "RSH", "RLOGIN", "SNMP", "SMTPS", 
    "POP3", "IMAP", "MQTT", "SMBV1"
)

_DNS_PORTS: tuple[int, ...] = (53, 5353)

# Placeholder for future Threat Intelligence integration
_KNOWN_TOR_NODES: tuple[str, ...] = ()


def _safe_string(value: Any) -> str:
    """
    Safely convert values to strings.

    Args:
        value (Any): Any raw value.

    Returns:
        str: A stripped, safe string representation.
    """
    if value is None:
        return ""
    return str(value).strip()


@dataclass(slots=True)
class DangerousNetworkResult:
    """
    Represents the result of a dangerous network detection analysis.
    """
    is_dangerous: bool = False
    public_ip_detected: bool = False
    outbound_detected: bool = False
    dangerous_port_detected: bool = False
    dangerous_protocol_detected: bool = False
    dns_indicator_detected: bool = False
    tor_detected: bool = False
    beacon_detected: bool = False
    port: int = 0
    port_category: PortCategory = PortCategory.UNKNOWN
    protocol: str = ""
    destination_ip: str = ""
    risk_points: float = 0.0
    risk_level: str = "LOW"
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    matched_rules: list[str] = field(default_factory=list)
    matched_ports: list[int] = field(default_factory=list)
    matched_protocols: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class DangerousNetworkDetector:
    """
    Evaluates telemetry events to detect malicious network connections, 
    dangerous ports, risky protocols, and DNS abuse.
    
    This class is completely stateless, thread-safe, and resilient 
    to missing or malformed event data. It handles exceptions gracefully 
    to ensure the broader telemetry pipeline never crashes.
    """

    def _extract_timestamp(self, event: dict[str, Any]) -> datetime:
        """
        Extracts and normalizes the timestamp from the telemetry event.

        Args:
            event (dict[str, Any]): Telemetry event dictionary.

        Returns:
            datetime: A timezone-aware UTC datetime object.
        """
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
                # Standardize ISO-8601 formatting for Python's fromisoformat
                clean_ts = raw_ts.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_ts).astimezone(timezone.utc)
                
        except (ValueError, TypeError, OverflowError) as e:
            logger.debug(f"Failed to parse timestamp '{raw_ts}': {e}. Falling back to current UTC time.")
            
        return datetime.now(timezone.utc)

    def _extract_fields(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Extract and normalize fields from the event dictionary.

        Args:
            event (dict[str, Any]): Telemetry event dictionary.

        Returns:
            dict[str, Any]: A dictionary containing normalized event fields.
        """
        raw_ip = _safe_string(event.get("destination_ip") or event.get("ip"))
        raw_protocol = _safe_string(event.get("protocol")).upper()
        raw_direction = _safe_string(event.get("direction")).upper()
        raw_domain = _safe_string(event.get("domain") or event.get("hostname"))
        
        port = 0
        port_val = event.get("destination_port") or event.get("port")
        if port_val is not None:
            try:
                parsed_port = int(port_val)
                if 1 <= parsed_port <= 65535:
                    port = parsed_port
            except (ValueError, TypeError):
                pass
                
        return {
            "destination_ip": raw_ip,
            "protocol": raw_protocol,
            "direction": raw_direction,
            "domain": raw_domain,
            "port": port,
            "timestamp": self._extract_timestamp(event)
        }

    def _detect_public_ip(self, ip_str: str) -> tuple[bool, str]:
        """
        Detects if an IP address is a public, globally routable address, 
        or handles unresolved hostnames.

        Args:
            ip_str (str): Normalized IP address string.

        Returns:
            tuple[bool, str]: A boolean indicating if it is public/suspicious,
                              and a description of the IP type or hostname.
        """
        if not ip_str:
            return False, ""

        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Broadcast Detection
            if ip.version == 4 and ip_str == "255.255.255.255":
                return True, "Broadcast Address"
            
            # Treat as non-public (benign/internal)
            if (ip.is_private or ip.is_loopback or ip.is_link_local or 
                ip.is_unspecified or ip.is_reserved):
                return False, ""
            
            if ip.is_multicast:
                return True, "Multicast Address"
                
            if ip.is_global:
                return True, "Public IP"

        except ValueError:
            logger.debug(f"Malformed or unresolved IP encountered: {ip_str}")
            # Check if it looks like an unresolved hostname instead of an IP
            if any(c.isalpha() for c in ip_str):
                return False, "Hostname (Unresolved)"

        return False, ""

    def _detect_dangerous_port(self, port: int) -> tuple[bool, PortCategory]:
        """
        Identifies the category of a port and determines if it is dangerous.

        Args:
            port (int): The network port number.

        Returns:
            tuple[bool, PortCategory]: Boolean indicating if the port is dangerous,
                                       and the PortCategory enumeration.
        """
        if port == 0:
            return False, PortCategory.UNKNOWN

        category = _PORT_CATEGORIES.get(port, PortCategory.UNKNOWN)
        
        is_dangerous = category in (
            PortCategory.REMOTE_ACCESS, 
            PortCategory.MALWARE, 
            PortCategory.ADMINISTRATION, 
            PortCategory.PROXY, 
            PortCategory.TOR
        )
        
        return is_dangerous, category

    def _detect_outbound(self, direction: str) -> bool:
        """
        Detects if the network connection direction is outbound.

        Args:
            direction (str): Normalized direction data.

        Returns:
            bool: True if the connection is outbound.
        """
        return direction == "OUTBOUND"

    def _detect_protocol(self, protocol: str) -> bool:
        """
        Detects if the protocol is inherently dangerous or suspicious.

        Args:
            protocol (str): Normalized protocol string.

        Returns:
            bool: True if the protocol is in the dangerous protocols list.
        """
        return protocol in _DANGEROUS_PROTOCOLS

    def _calculate_entropy(self, data: str) -> float:
        """
        Lightweight Shannon entropy calculation for a string.

        Args:
            data (str): The string to evaluate.

        Returns:
            float: The calculated entropy in bits.
        """
        if not data:
            return 0.0
            
        counts: dict[str, int] = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1
            
        entropy = 0.0
        total = len(data)
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
            
        return entropy

    def _detect_dns(self, port: int, domain: str) -> tuple[bool, str]:
        """
        Detects DNS abuse or tunneling indicators via improved lightweight heuristics.

        Args:
            port (int): Network port.
            domain (str): Domain name being queried.

        Returns:
            tuple[bool, str]: Boolean indicating DNS abuse, and a reason string.
        """
        if port not in _DNS_PORTS or not domain:
            return False, ""

        domain_str = domain.lower()
        labels = domain_str.split(".")

        # Heuristic 1: Unusually long single label
        if any(len(label) > 30 for label in labels):
            return True, "Unusually long DNS label (possible tunneling or DGA)"

        # Heuristic 2: Excessive subdomains
        if len(labels) > 4:
            return True, "Excessive subdomains in DNS query"

        # Heuristic 3: High ratio of numeric characters
        digits = sum(1 for c in domain_str if c.isdigit())
        if len(domain_str) > 0 and (digits / len(domain_str)) > 0.4:
            return True, "High ratio of numeric characters in domain"

        # Heuristic 4: High Shannon Entropy calculation
        if self._calculate_entropy(domain_str) > 4.5:
            return True, "High entropy DNS query (possible DGA/exfiltration)"

        return False, ""

    def _detect_tor(self, ip_str: str, category: PortCategory) -> bool:
        """
        Detects potential TOR activity based on port category or IP lists.

        Args:
            ip_str (str): Normalized IP address.
            category (PortCategory): Detected port category.

        Returns:
            bool: True if TOR activity is suspected.
        """
        if category == PortCategory.TOR:
            return True
            
        # Evaluates against known exit nodes if available
        if ip_str and ip_str in _KNOWN_TOR_NODES:
            return True
            
        return False

    def _detect_beacon(self, event: dict[str, Any]) -> bool:
        """
        Placeholder helper for detecting beaconing indicators.
        
        Future expansion: This will analyze timestamps, intervals, 
        and destination consistency to flag command and control beacons.

        Args:
            event (dict[str, Any]): Telemetry event.

        Returns:
            bool: Currently returns False.
        """
        # Awaiting future temporal/stateful telemetry analysis module hook
        return False

    # ============================================================
    # FUTURE THREAT INTELLIGENCE HOOKS
    # ============================================================

    def _check_reputation(self, target: str) -> bool:
        """
        Evaluates the target (IP/Hostname) against reputation feeds.
        
        TODO: Implement real-time or cached API lookups to Threat Intelligence 
        services (e.g., VirusTotal, AbuseIPDB, IBM X-Force) to determine if 
        the target is known to be malicious.
        """
        return False

    def _check_geoip(self, ip_str: str) -> str:
        """
        Maps the IP address to geographical data.
        
        TODO: Integrate a local GeoIP database (like MaxMind GeoLite2) to 
        identify high-risk regions or impossible travel scenarios without 
        relying on high-latency remote API calls.
        """
        return ""

    def _check_threat_feed(self, indicator: str) -> bool:
        """
        Checks indicators of compromise (IOCs) against ingested threat feeds.
        
        TODO: Implement memory-mapped lookups against ingested MISP or OTX 
        pulse lists to identify documented malicious infrastructure.
        """
        return False

    def _check_c2(self, target: str) -> bool:
        """
        Identifies known Command and Control (C2) botnet infrastructure.
        
        TODO: Implement matching against specialized C2 tracking lists 
        (e.g., Feodo Tracker) to immediately flag critical severity events.
        """
        return False

    def _check_malware_ports(self, port: int) -> bool:
        """
        Cross-references the destination port with dynamic malware port lists.
        
        TODO: Implement a dynamic threat-model update system to ingest and 
        check against shifting port patterns utilized by modern malware families.
        """
        return False

    # ============================================================
    # SCORING HELPERS
    # ============================================================

    def _score_public_ip(self, public_ip: bool, ip_reason: str, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for public IP / broadcast detections."""
        if public_ip:
            if ip_reason == "Broadcast Address":
                score += BROADCAST_SCORE
                rules.append("Broadcast IP")
                reasons.append("Connection established to a broadcast address (255.255.255.255).")
            else:
                score += PUBLIC_IP_SCORE
                rules.append("Public IP Connection")
                reasons.append(f"Connection established to a non-private, globally routable or unusual IP address ({ip_reason}).")
        return score

    def _score_outbound(self, outbound: bool, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for outbound connections."""
        if outbound:
            score += OUTBOUND_SCORE
            rules.append("Outbound Connection")
            reasons.append("Connection direction is outbound.")
        return score

    def _score_port(self, dangerous_port: bool, port: int, category: PortCategory, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for dangerous port usage."""
        if dangerous_port:
            score += DANGEROUS_PORT_SCORE
            rules.append(f"Dangerous Port Category: {category.name}")
            reasons.append(f"Network connection uses a port associated with {category.name.replace('_', ' ')}.")
            
            if port in _HIGH_RISK_PORTS:
                score += HIGH_RISK_PORT_BONUS
                rules.append("High-Risk Port")
                reasons.append(f"Port {port} is specifically flagged as a highly targeted or malicious port.")
        return score

    def _score_protocol(self, dangerous_protocol: bool, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for risky protocols."""
        if dangerous_protocol:
            score += DANGEROUS_PROTOCOL_SCORE
            rules.append("Dangerous Protocol")
            reasons.append("Connection uses a protocol prone to abuse or insecure transmission.")
        return score

    def _score_dns(self, dns_indicator: bool, dns_reason: str, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for DNS abuse indicators."""
        if dns_indicator:
            score += DNS_SCORE
            rules.append("DNS Abuse Indicator")
            reasons.append(dns_reason)
        return score

    def _score_tor(self, tor_indicator: bool, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for TOR activity detections."""
        if tor_indicator:
            score += TOR_SCORE
            rules.append("TOR Network Activity")
            reasons.append("Connection attributes match known TOR ports or exit nodes.")
        return score

    def _score_proxy(self, category: PortCategory, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for known proxy port usage."""
        if category == PortCategory.PROXY:
            score += PROXY_SCORE
            rules.append("Proxy Port Activity")
            reasons.append("Connection utilizes a known proxy or evasion port.")
        return score

    def _score_beacon(self, beacon_indicator: bool, score: float, rules: list[str], reasons: list[str]) -> float:
        """Updates score and metrics for C2 beaconing behavior."""
        if beacon_indicator:
            score += BEACON_SCORE
            rules.append("Beaconing Behavior")
            reasons.append("Connection exhibits repetitive, periodic intervals typical of C2 beaconing.")
        return score

    def _score_combination(
        self,
        outbound: bool,
        public_ip: bool,
        dangerous_port: bool,
        tor_indicator: bool,
        dangerous_protocol: bool,
        score: float,
        rules: list[str],
        reasons: list[str]
    ) -> float:
        """Applies a bonus score if multiple severe conditions are met simultaneously."""
        if outbound and public_ip and (dangerous_port or tor_indicator or dangerous_protocol):
            score += COMBINATION_BONUS
            rules.append("High-Risk Outbound Combination")
            reasons.append("Combined indicators: Outbound connection to a public IP using a dangerous port or protocol.")
        return score

    def _calculate_score(
        self,
        public_ip: bool,
        ip_reason: str,
        outbound: bool,
        dangerous_port: bool,
        port: int,
        dangerous_protocol: bool,
        dns_indicator: bool,
        dns_reason: str,
        tor_indicator: bool,
        beacon_indicator: bool,
        category: PortCategory
    ) -> tuple[float, list[str], list[str]]:
        """
        Orchestrates the calculation of the aggregate risk score via dedicated helpers.

        Returns:
            tuple[float, list[str], list[str]]: Aggregate score, triggered rules, and human-readable reasons.
        """
        score = 0.0
        rules: list[str] = []
        reasons: list[str] = []

        score = self._score_public_ip(public_ip, ip_reason, score, rules, reasons)
        score = self._score_outbound(outbound, score, rules, reasons)
        score = self._score_port(dangerous_port, port, category, score, rules, reasons)
        score = self._score_protocol(dangerous_protocol, score, rules, reasons)
        score = self._score_dns(dns_indicator, dns_reason, score, rules, reasons)
        score = self._score_tor(tor_indicator, score, rules, reasons)
        score = self._score_proxy(category, score, rules, reasons)
        score = self._score_beacon(beacon_indicator, score, rules, reasons)
        
        score = self._score_combination(
            outbound, public_ip, dangerous_port, 
            tor_indicator, dangerous_protocol, 
            score, rules, reasons
        )

        return score, rules, reasons

    def _get_risk_level(self, score: float) -> str:
        """
        Maps a numerical risk score to a qualitative risk level.
        
        Args:
            score (float): Total calculated risk score.
            
        Returns:
            str: One of 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.
        """
        if score >= 70.0:
            return "CRITICAL"
        if score >= 40.0:
            return "HIGH"
        if score >= 20.0:
            return "MEDIUM"
        return "LOW"

    def _calculate_confidence(self, rules: list[str]) -> float:
        """
        Calculates an independent confidence score (0-100) based on the number 
        of unique indicators matched by the detection engine.
        
        Args:
            rules (list[str]): List of all triggered rule names.
            
        Returns:
            float: Confidence percentage.
        """
        if not rules:
            return 0.0
            
        base_confidence = 50.0
        bonus = (len(set(rules)) - 1) * 10.0
        return min(100.0, max(0.0, base_confidence + bonus))

    def detect(self, event: dict[str, Any]) -> DangerousNetworkResult:
        """
        Analyzes a network telemetry event to detect dangerous ports, 
        protocols, destinations, and anomalous behaviors.

        Args:
            event (dict[str, Any]): Telemetry event dictionary.

        Returns:
            DangerousNetworkResult: Result object containing detection details, risk scores, and classifications.
        """
        try:
            if not isinstance(event, dict) or not event:
                logger.warning("Invalid or empty event provided to DangerousNetworkDetector.")
                return DangerousNetworkResult()

            # 1. Field Extraction
            fields = self._extract_fields(event)
            ip_val = fields["destination_ip"]
            protocol_val = fields["protocol"]
            direction_val = fields["direction"]
            domain_val = fields["domain"]
            port_val = fields["port"]
            timestamp_val = fields["timestamp"]

            # 2. Heuristic Detetion
            has_public_ip, ip_reason = self._detect_public_ip(ip_val)
            is_outbound = self._detect_outbound(direction_val)
            has_dangerous_port, port_category = self._detect_dangerous_port(port_val)
            has_dangerous_protocol = self._detect_protocol(protocol_val)
            has_dns_indicator, dns_reason = self._detect_dns(port_val, domain_val)
            has_tor = self._detect_tor(ip_val, port_category)
            has_beacon = self._detect_beacon(event)

            # 3. Execution & Score Aggregation
            score, rules, reasons = self._calculate_score(
                has_public_ip, ip_reason,
                is_outbound,
                has_dangerous_port, port_val,
                has_dangerous_protocol,
                has_dns_indicator, dns_reason,
                has_tor,
                has_beacon,
                port_category
            )

            is_dangerous = score > 0.0
            risk_level = self._get_risk_level(score)
            confidence = self._calculate_confidence(rules)

            # Compile explicitly matched attributes for the result payload
            matched_ports = [port_val] if port_val > 0 and (has_dangerous_port or has_dns_indicator or has_tor or port_category == PortCategory.PROXY) else []
            matched_protocols = [protocol_val] if protocol_val and has_dangerous_protocol else []

            return DangerousNetworkResult(
                is_dangerous=is_dangerous,
                public_ip_detected=has_public_ip,
                outbound_detected=is_outbound,
                dangerous_port_detected=has_dangerous_port,
                dangerous_protocol_detected=has_dangerous_protocol,
                dns_indicator_detected=has_dns_indicator,
                tor_detected=has_tor,
                beacon_detected=has_beacon,
                port=port_val,
                port_category=port_category,
                protocol=protocol_val,
                destination_ip=ip_val,
                risk_points=score,
                risk_level=risk_level,
                confidence=confidence,
                timestamp=timestamp_val,
                matched_rules=rules,
                matched_ports=matched_ports,
                matched_protocols=matched_protocols,
                reasons=reasons
            )
            
        except (ValueError, TypeError, KeyError) as expected_err:
            logger.warning(f"Parsing error during network detection: {expected_err}")
            return DangerousNetworkResult()
        except Exception as unexpected_err:
            logger.exception("Unexpected failure in DangerousNetworkDetector.")
            return DangerousNetworkResult()