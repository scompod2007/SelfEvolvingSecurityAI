"""
============================================================
Self-Evolving Security AI
Part 2.9.3 - Whitelist Adjustment
============================================================

This module adjusts an already calculated confidence score by
reducing it when telemetry matches known trusted entities.
It is completely independent of risk and severity calculations.
"""

import ipaddress
import logging
import os
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
MIN_CONFIDENCE: float = 0.0
MAX_CONFIDENCE: float = 100.0
MAX_REDUCTION: float = 60.0

TRUSTED_PROCESS_REDUCTION: float = 20.0
TRUSTED_PUBLISHER_REDUCTION: float = 15.0
TRUSTED_CERTIFICATE_REDUCTION: float = 20.0
TRUSTED_DOMAIN_REDUCTION: float = 15.0
TRUSTED_IP_REDUCTION: float = 25.0

TRUSTED_PROCESSES: frozenset[str] = frozenset([
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "csrss.exe",
    "winlogon.exe",
    "system",
    "idle"
])

TRUSTED_PUBLISHERS: frozenset[str] = frozenset([
    "microsoft",
    "google",
    "mozilla",
    "adobe",
    "intel",
    "amd",
    "advanced micro devices",
    "nvidia",
    "cisco",
    "cisco systems",
    "vmware",
    "oracle",
    "apple"
])

TRUSTED_CERTIFICATE_ISSUERS: frozenset[str] = frozenset([
    "microsoft corporation",
    "microsoft windows",
    "google llc",
    "digicert",
    "digicert inc",
    "let's encrypt",
    "sectigo",
    "sectigo limited",
    "globalsign",
    "globalsign nv-sa",
    "entrust",
    "entrust, inc."
])

TRUSTED_EXACT_DOMAINS: frozenset[str] = frozenset([
    "windowsupdate.com",
    "microsoft.com",
    "google.com",
    "github.com",
    "ubuntu.com",
    "mozilla.org",
    "python.org",
    "openai.com"
])

TRUSTED_SUFFIX_DOMAINS: tuple[str, ...] = (
    "windowsupdate.com",
    "microsoft.com",
    "google.com",
    "github.com",
    "ubuntu.com",
    "mozilla.org",
    "python.org",
    "openai.com"
)

TRUSTED_IPS: frozenset[str] = frozenset([
    # Explicitly trusted individual IPs can be added here
])

_TRUSTED_NETWORK_STRINGS: tuple[str, ...] = (
    # Explicitly trusted CIDR ranges can be added here
)

TRUSTED_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = tuple(
    ipaddress.ip_network(net) for net in _TRUSTED_NETWORK_STRINGS
)


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class WhitelistAdjustmentResult:
    """
    Represents the result of a whitelist confidence adjustment.
    """
    original_confidence: float
    adjusted_confidence: float
    confidence_reduction: float
    process_reduction: float
    domain_reduction: float
    ip_reduction: float
    certificate_reduction: float
    publisher_reduction: float
    trusted_process_detected: bool
    trusted_domain_detected: bool
    trusted_ip_detected: bool
    trusted_certificate_detected: bool
    trusted_publisher_detected: bool
    matched_process: str
    matched_domain: str
    matched_ip: str
    matched_certificate: str
    matched_publisher: str
    matched_categories: list[str]
    reasons: list[str]
    timestamp: datetime


# ============================================================
# ENGINE
# ============================================================
class WhitelistAdjustmentEngine:
    """
    Stateless, thread-safe engine for reducing confidence scores
    based on trusted whitelist categories.
    """

    def _validate_confidence(self, current_confidence: Any) -> float:
        """
        Validates, parses, and clamps the incoming confidence score.

        Args:
            current_confidence (Any): The raw confidence score.

        Returns:
            float: A safe float representation of the confidence, clamped to valid bounds.
        """
        try:
            conf = float(current_confidence)
            if conf != conf:
                return MIN_CONFIDENCE
            return max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, conf))
        except (ValueError, TypeError):
            return MIN_CONFIDENCE

    def _normalize(self, value: Any) -> str:
        """
        Normalizes a string value for safe, case-insensitive comparison.

        Args:
            value (Any): The raw value to normalize.

        Returns:
            str: The normalized string.
        """
        if value is None:
            return ""
        try:
            return " ".join(str(value).split()).lower()
        except (ValueError, TypeError, AttributeError):
            return ""

    def _normalize_publisher(self, publisher: Any) -> str:
        """
        Normalizes a publisher string by stripping legal suffixes.

        Args:
            publisher (Any): The raw publisher string.

        Returns:
            str: The normalized publisher string.
        """
        pub = self._normalize(publisher)
        if not pub:
            return ""
        
        suffixes = (
            "inc.", "inc", "ltd.", "ltd", "corporation", "corp.", "corp",
            "llc", "limited", "co.", "company", "plc"
        )
        
        words = pub.split()
        while words and words[-1] in suffixes:
            words.pop()
            
        return " ".join(words).rstrip(",").strip()

    def _normalize_certificate(self, cert: Any) -> str:
        """
        Normalizes a certificate string by stripping common prefixes.

        Args:
            cert (Any): The raw certificate string.

        Returns:
            str: The normalized certificate string.
        """
        c = self._normalize(cert)
        if not c:
            return ""
            
        prefixes = ("cn=", "o=", "ou=")
        changed = True
        while changed:
            changed = False
            for p in prefixes:
                if c.startswith(p):
                    c = c[len(p):].strip()
                    changed = True
                        
        return c

    def _extract_fields(self, telemetry: dict[str, Any]) -> dict[str, str]:
        """
        Extracts and normalizes relevant fields from the telemetry dictionary.

        Args:
            telemetry (dict[str, Any]): The raw telemetry data.

        Returns:
            dict[str, str]: A dictionary of normalized extraction fields.
        """
        if not isinstance(telemetry, dict):
            return {
                "process": "",
                "domain": "",
                "ip": "",
                "certificate_issuer": "",
                "certificate_subject": "",
                "publisher": ""
            }

        raw_process = (
            telemetry.get("process_name") or
            telemetry.get("process_path") or
            telemetry.get("image_path") or
            ""
        )
        process = self._normalize(os.path.basename(str(raw_process).replace("\\", "/")))

        raw_domain = (
            telemetry.get("destination_domain") or
            telemetry.get("domain") or
            telemetry.get("hostname") or
            telemetry.get("query") or
            telemetry.get("dns_query") or
            telemetry.get("url") or
            telemetry.get("server_name") or
            ""
        )
        raw_domain_str = str(raw_domain).strip()
        if "://" in raw_domain_str:
            try:
                parsed = urllib.parse.urlparse(raw_domain_str).hostname
                if parsed:
                    raw_domain_str = parsed
            except Exception:
                pass
        domain = self._normalize(raw_domain_str)

        ip = self._normalize(telemetry.get("destination_ip", ""))
        
        cert_issuer = self._normalize_certificate(telemetry.get("certificate_issuer", ""))
        cert_subject = self._normalize_certificate(telemetry.get("certificate_subject", ""))
            
        publisher = self._normalize_publisher(telemetry.get("publisher", ""))

        return {
            "process": process,
            "domain": domain,
            "ip": ip,
            "certificate_issuer": cert_issuer,
            "certificate_subject": cert_subject,
            "publisher": publisher
        }

    def _match_process(self, process: str) -> tuple[bool, str]:
        """
        Checks if the process matches a trusted process.

        Args:
            process (str): The normalized process name.

        Returns:
            tuple[bool, str]: Match status and the matched process.
        """
        if not process:
            return False, ""
        if process in TRUSTED_PROCESSES:
            return True, process
        return False, ""

    def _match_domain(self, domain: str) -> tuple[bool, str]:
        """
        Checks if the domain matches a trusted domain via exact or suffix matching.

        Args:
            domain (str): The normalized domain name.

        Returns:
            tuple[bool, str]: Match status and the matched domain.
        """
        if not domain:
            return False, ""
        if domain in TRUSTED_EXACT_DOMAINS:
            return True, domain
        for trusted in TRUSTED_SUFFIX_DOMAINS:
            if domain.endswith(f".{trusted}"):
                return True, trusted
        return False, ""

    def _match_ip(self, ip_str: str) -> tuple[bool, str]:
        """
        Checks if the IP address belongs to an explicitly trusted network or IP.

        Args:
            ip_str (str): The normalized IP address string.

        Returns:
            tuple[bool, str]: Match status and the matched IP.
        """
        if not ip_str:
            return False, ""
        if ip_str in TRUSTED_IPS:
            return True, ip_str
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for network in TRUSTED_NETWORKS:
                if ip_obj in network:
                    return True, ip_str
        except ValueError:
            pass
        return False, ""

    def _match_certificate(self, cert_issuer: str, cert_subject: str) -> tuple[bool, str]:
        """
        Checks if the certificate matches a trusted issuer via exact matching.

        Args:
            cert_issuer (str): The normalized certificate issuer string.
            cert_subject (str): The normalized certificate subject string.

        Returns:
            tuple[bool, str]: Match status and the matched certificate string.
        """
        if cert_issuer and cert_issuer in TRUSTED_CERTIFICATE_ISSUERS:
            return True, cert_issuer
        if cert_subject and cert_subject in TRUSTED_CERTIFICATE_ISSUERS:
            return True, cert_subject
        return False, ""

    def _match_publisher(self, publisher: str) -> tuple[bool, str]:
        """
        Checks if the publisher matches a trusted software publisher via exact matching.

        Args:
            publisher (str): The normalized publisher string.

        Returns:
            tuple[bool, str]: Match status and the matched publisher.
        """
        if not publisher:
            return False, ""
        if publisher in TRUSTED_PUBLISHERS:
            return True, publisher
        return False, ""

    def _apply_reductions(
        self,
        proc_match: bool,
        dom_match: bool,
        ip_match: bool,
        cert_match: bool,
        pub_match: bool
    ) -> tuple[float, float, float, float, float, float, list[str]]:
        """
        Calculates the total confidence reduction and compiles matched categories.
        Scalions individual reductions proportionally if the total exceeds the maximum cap.

        Args:
            proc_match (bool): True if a trusted process was detected.
            dom_match (bool): True if a trusted domain was detected.
            ip_match (bool): True if a trusted IP was detected.
            cert_match (bool): True if a trusted certificate was detected.
            pub_match (bool): True if a trusted publisher was detected.

        Returns:
            tuple[float, float, float, float, float, float, list[str]]: 
                Capped total reduction, individual reductions, and list of matched categories.
        """
        categories = []
        p_red = d_red = i_red = c_red = pub_red = 0.0

        if proc_match:
            p_red = TRUSTED_PROCESS_REDUCTION
            categories.append("Trusted Process")
        if dom_match:
            d_red = TRUSTED_DOMAIN_REDUCTION
            categories.append("Trusted Domain")
        if ip_match:
            i_red = TRUSTED_IP_REDUCTION
            categories.append("Trusted IP")
        if cert_match:
            c_red = TRUSTED_CERTIFICATE_REDUCTION
            categories.append("Trusted Certificate")
        if pub_match:
            pub_red = TRUSTED_PUBLISHER_REDUCTION
            categories.append("Trusted Publisher")

        total_reduction = p_red + d_red + i_red + c_red + pub_red
        
        if total_reduction > MAX_REDUCTION:
            scale = MAX_REDUCTION / total_reduction
            p_red *= scale
            d_red *= scale
            i_red *= scale
            c_red *= scale
            pub_red *= scale
            capped_reduction = MAX_REDUCTION
        else:
            capped_reduction = total_reduction

        unique_categories = sorted(list(set(categories)))

        return capped_reduction, p_red, d_red, i_red, c_red, pub_red, unique_categories

    def _clamp_confidence(self, confidence: float) -> float:
        """
        Ensures the confidence score remains within the valid range.

        Args:
            confidence (float): The calculated confidence score.

        Returns:
            float: The clamped confidence score.
        """
        return max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, confidence))

    def _build_reasons(
        self,
        reduction: float,
        categories: list[str],
        adjusted_confidence: float
    ) -> list[str]:
        """
        Constructs human-readable reasons for the applied confidence reductions.

        Args:
            reduction (float): The total confidence reduction applied.
            categories (list[str]): The list of matched trusted categories.
            adjusted_confidence (float): The final adjusted confidence score.

        Returns:
            list[str]: A list of explanation strings.
        """
        if reduction > 0.0:
            return [
                f"Total whitelist reduction: {reduction:.2f}",
                f"Matched whitelist categories: {', '.join(categories)}",
                f"Adjusted confidence: {adjusted_confidence:.2f}"
            ]
        return ["No whitelist categories matched. Confidence remains unchanged."]

    def _generate_output(
        self,
        original_confidence: float,
        adjusted_confidence: float,
        reduction: float,
        p_red: float,
        d_red: float,
        i_red: float,
        c_red: float,
        pub_red: float,
        proc_match: bool,
        dom_match: bool,
        ip_match: bool,
        cert_match: bool,
        pub_match: bool,
        proc_str: str,
        dom_str: str,
        ip_str: str,
        cert_str: str,
        pub_str: str,
        categories: list[str],
        reasons: list[str]
    ) -> WhitelistAdjustmentResult:
        """
        Constructs the final WhitelistAdjustmentResult dataclass.

        Args:
            original_confidence (float): The initial confidence score.
            adjusted_confidence (float): The final clamped confidence score.
            reduction (float): The total reduction applied.
            p_red (float): Process reduction amount.
            d_red (float): Domain reduction amount.
            i_red (float): IP reduction amount.
            c_red (float): Certificate reduction amount.
            pub_red (float): Publisher reduction amount.
            proc_match (bool): Trusted process detection status.
            dom_match (bool): Trusted domain detection status.
            ip_match (bool): Trusted IP detection status.
            cert_match (bool): Trusted certificate detection status.
            pub_match (bool): Trusted publisher detection status.
            proc_str (str): Matched process string.
            dom_str (str): Matched domain string.
            ip_str (str): Matched IP string.
            cert_str (str): Matched certificate string.
            pub_str (str): Matched publisher string.
            categories (list[str]): List of matched categories.
            reasons (list[str]): Explanations of applied reductions.

        Returns:
            WhitelistAdjustmentResult: The populated result object.
        """
        return WhitelistAdjustmentResult(
            original_confidence=original_confidence,
            adjusted_confidence=adjusted_confidence,
            confidence_reduction=reduction,
            process_reduction=p_red,
            domain_reduction=d_red,
            ip_reduction=i_red,
            certificate_reduction=c_red,
            publisher_reduction=pub_red,
            trusted_process_detected=proc_match,
            trusted_domain_detected=dom_match,
            trusted_ip_detected=ip_match,
            trusted_certificate_detected=cert_match,
            trusted_publisher_detected=pub_match,
            matched_process=proc_str,
            matched_domain=dom_str,
            matched_ip=ip_str,
            matched_certificate=cert_str,
            matched_publisher=pub_str,
            matched_categories=categories,
            reasons=reasons,
            timestamp=datetime.now(timezone.utc)
        )

    def adjust(self, current_confidence: float, telemetry: dict[str, Any]) -> WhitelistAdjustmentResult:
        """
        Evaluates telemetry against trusted whitelists and reduces confidence accordingly.

        Args:
            current_confidence (float): The previously calculated confidence score.
            telemetry (dict[str, Any]): The raw telemetry event data.

        Returns:
            WhitelistAdjustmentResult: The result containing the adjusted confidence and metadata.
        """
        try:
            original_conf = self._validate_confidence(current_confidence)
            fields = self._extract_fields(telemetry)

            proc_match, proc_str = self._match_process(fields["process"])
            dom_match, dom_str = self._match_domain(fields["domain"])
            ip_match, ip_str = self._match_ip(fields["ip"])
            cert_match, cert_str = self._match_certificate(fields["certificate_issuer"], fields["certificate_subject"])
            pub_match, pub_str = self._match_publisher(fields["publisher"])

            reduction, p_red, d_red, i_red, c_red, pub_red, categories = self._apply_reductions(
                proc_match, dom_match, ip_match, cert_match, pub_match
            )

            adjusted_conf = self._clamp_confidence(original_conf - reduction)
            reasons = self._build_reasons(reduction, categories, adjusted_conf)

            return self._generate_output(
                original_confidence=original_conf,
                adjusted_confidence=adjusted_conf,
                reduction=reduction,
                p_red=p_red,
                d_red=d_red,
                i_red=i_red,
                c_red=c_red,
                pub_red=pub_red,
                proc_match=proc_match,
                dom_match=dom_match,
                ip_match=ip_match,
                cert_match=cert_match,
                pub_match=pub_match,
                proc_str=proc_str,
                dom_str=dom_str,
                ip_str=ip_str,
                cert_str=cert_str,
                pub_str=pub_str,
                categories=categories,
                reasons=reasons
            )

        except Exception as e:
            logger.exception("Unexpected error in WhitelistAdjustmentEngine: %s", e)
            safe_conf = self._validate_confidence(current_confidence)
            return self._generate_output(
                original_confidence=safe_conf,
                adjusted_confidence=safe_conf,
                reduction=0.0,
                p_red=0.0,
                d_red=0.0,
                i_red=0.0,
                c_red=0.0,
                pub_red=0.0,
                proc_match=False,
                dom_match=False,
                ip_match=False,
                cert_match=False,
                pub_match=False,
                proc_str="",
                dom_str="",
                ip_str="",
                cert_str="",
                pub_str="",
                categories=[],
                reasons=["Whitelist adjustment failed due to an internal error. Confidence unchanged."]
            )