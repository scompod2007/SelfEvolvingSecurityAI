"""
==========================================================
Network Monitor - Version 1
Self-Evolving Security AI

Part 1
    Helper Functions
    Metadata Builder
    Save Event

Part 2
    Snapshot Engine
    Connection Diff Engine

Part 3
    Network Monitoring
    Thread Loop

Part 4
    Start
    Stop

Design Notes
------------
Version 1 is intentionally built ONLY on psutil.net_connections().
No raw sockets, no packet capture, no Npcap/WinPcap/Scapy. This
keeps it lightweight, dependency-free, and safe to run continuously
as a read-only telemetry collector.

The database schema (network_events) already contains every column
a Version 2 packet-capture / DNS-monitoring / GeoIP layer would need
to populate. Version 1 fills every column it reasonably can from
psutil + stdlib, and leaves the rest (hostname when unresolved,
future GeoIP/JA3/ASN fields not yet in the schema) for later work
without requiring a schema migration.
==========================================================
"""

import getpass
import ipaddress
import socket
import threading
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import psutil

from database.db import get_connection, close_connection
from collectors.event_types import NetworkEventType


class NetworkMonitor:
    """
    Windows Network Connection Monitor - Version 1

    Snapshot-diff architecture built entirely on
    psutil.net_connections(). A single background thread
    polls the current connection table on a fixed interval,
    compares it against the previous snapshot, and emits
    events only for what actually changed.
    """

    # ------------------------------------------------------
    # Port -> friendly service name.
    #
    # This powers `service_name` (fine-grained classification)
    # and is deliberately larger than the coarse `protocol`
    # category set below -- e.g. MySQL/PostgreSQL/MongoDB show
    # up here even though they all just fall under the generic
    # "DATABASE" protocol/boolean flag.
    # ------------------------------------------------------

    PORT_SERVICE_MAP: Dict[int, str] = {
        20: "FTP_DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        135: "RPC",
        137: "NETBIOS",
        138: "NETBIOS",
        139: "NETBIOS",
        143: "IMAP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        1433: "SQL_SERVER",
        1521: "ORACLE",
        2049: "NFS",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRESQL",
        5900: "VNC",
        6379: "REDIS",
        8080: "HTTP_ALT",
        8443: "HTTPS_ALT",
        27017: "MONGODB",
    }

    MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}

    DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 27017}

    # Well-known Windows system process names (lower-case).
    # Combined with pid checks (0 = Idle, 4 = System) in
    # _is_system_process().

    SYSTEM_PROCESS_NAMES = {
        "system",
        "system idle process",
        "svchost.exe",
        "lsass.exe",
        "wininit.exe",
        "services.exe",
        "csrss.exe",
        "smss.exe",
        "winlogon.exe",
        "spoolsv.exe",
        "dwm.exe",
        "registry",
    }

    DEFAULT_INTERVAL_SECONDS = 1.0

    def __init__(self, interval: float = DEFAULT_INTERVAL_SECONDS):

        self.running = False

        self.interval = interval

        # protects self.snapshot / self.connection_start_times
        # against concurrent access between the monitor thread
        # and anything else that might touch them later

        self.lock = threading.Lock()

        # current connection table: key -> base_info dict

        self.snapshot: Dict[tuple, dict] = {}

        # first-seen wall-clock time per connection key, used to
        # compute connection_duration on close / state-change

        self.connection_start_times: Dict[tuple, float] = {}

        # reverse-DNS cache: ip -> hostname (or None if unresolved)
        # avoids repeat lookups for the same remote IP

        self.hostname_cache: Dict[str, Optional[str]] = {}

        # process metadata cache: pid -> (create_time, info dict)
        # keyed with create_time so a reused pid doesn't return
        # stale metadata for a different process

        self.process_cache: Dict[int, Tuple[float, dict]] = {}

        self.thread: Optional[threading.Thread] = None

    # ======================================================
    # PART 1 - HELPER FUNCTIONS
    # ======================================================

    def get_user_name(self) -> Optional[str]:
        """
        Return the current Windows username running this monitor.
        """

        try:

            return getpass.getuser()

        except Exception:

            return None

    def generate_event_uuid(self) -> str:

        return str(uuid.uuid4())

    def generate_operation_id(self) -> str:

        return str(uuid.uuid4())

    def get_hostname(self, ip_address_str: Optional[str]) -> Optional[str]:
        """
        Reverse-DNS lookup for a remote IP, with caching and a
        short timeout so a slow/unresponsive DNS server can never
        stall the monitoring loop for long. Only called when an
        event actually fires (not on every snapshot poll), so the
        cost of this call never scales with idle connection count.
        """

        if not ip_address_str:

            return None

        if ip_address_str in self.hostname_cache:

            return self.hostname_cache[ip_address_str]

        hostname: Optional[str] = None

        previous_timeout = socket.getdefaulttimeout()

        try:

            socket.setdefaulttimeout(0.5)

            hostname = socket.gethostbyaddr(ip_address_str)[0]

        except (socket.herror, socket.gaierror, socket.timeout, OSError):

            hostname = None

        except Exception:

            hostname = None

        finally:

            socket.setdefaulttimeout(previous_timeout)

        self.hostname_cache[ip_address_str] = hostname

        return hostname

    def get_process(self, pid: Optional[int]) -> Optional[psutil.Process]:
        """
        Safely obtain a psutil.Process handle for a pid.
        Returns None for invalid pids or processes that no
        longer exist / cannot be inspected.
        """

        if pid is None or pid <= 0:

            return None

        try:

            return psutil.Process(pid)

        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, ValueError):

            return None

        except Exception:

            return None

    def get_process_name(self, proc: Optional[psutil.Process]) -> Optional[str]:

        if proc is None:

            return None

        try:

            return proc.name()

        except Exception:

            return None

    def get_process_path(self, proc: Optional[psutil.Process]) -> Optional[str]:

        if proc is None:

            return None

        try:

            return proc.exe()

        except Exception:

            return None

    def get_process_username(self, proc: Optional[psutil.Process]) -> Optional[str]:

        if proc is None:

            return None

        try:

            return proc.username()

        except Exception:

            return None

    def get_command_line(self, proc: Optional[psutil.Process]) -> Optional[str]:

        if proc is None:

            return None

        try:

            return " ".join(proc.cmdline())

        except Exception:

            return None

    def _get_process_info(self, pid: Optional[int]) -> dict:
        """
        Build a small metadata dict for a pid, using the process
        cache (keyed by pid + create_time) to avoid re-querying
        psutil for processes we already inspected this run.
        """

        empty_info = {
            "process_name": None,
            "parent_process_id": None,
            "process_path": None,
            "process_username": None,
            "command_line": None,
        }

        proc = self.get_process(pid)

        if proc is None:

            return empty_info

        try:

            create_time = proc.create_time()

        except Exception:

            create_time = None

        cached = self.process_cache.get(pid)

        if cached is not None and create_time is not None and cached[0] == create_time:

            return cached[1]

        info = dict(empty_info)

        info["process_name"] = self.get_process_name(proc)

        try:

            info["parent_process_id"] = proc.ppid()

        except Exception:

            info["parent_process_id"] = None

        info["process_path"] = self.get_process_path(proc)

        info["process_username"] = self.get_process_username(proc)

        info["command_line"] = self.get_command_line(proc)

        if create_time is not None:

            self.process_cache[pid] = (create_time, info)

        return info

    def classify_ip(self, ip_address_str: Optional[str]) -> dict:
        """
        Classify an IP address into the AI-ready boolean feature
        set. Returns all zeros for None/unparseable addresses
        rather than raising.
        """

        result = {
            "is_private_ip": 0,
            "is_public_ip": 0,
            "is_loopback": 0,
            "is_link_local": 0,
            "is_multicast": 0,
            "is_broadcast": 0,
            "is_ipv6": 0,
        }

        if not ip_address_str:

            return result

        try:

            # strip IPv6 zone id (e.g. "fe80::1%3") before parsing

            clean_ip = ip_address_str.split("%")[0]

            ip_obj = ipaddress.ip_address(clean_ip)

        except ValueError:

            return result

        result["is_ipv6"] = 1 if ip_obj.version == 6 else 0

        result["is_loopback"] = 1 if ip_obj.is_loopback else 0

        result["is_link_local"] = 1 if ip_obj.is_link_local else 0

        result["is_multicast"] = 1 if ip_obj.is_multicast else 0

        result["is_private_ip"] = 1 if ip_obj.is_private else 0

        result["is_broadcast"] = 1 if clean_ip == "255.255.255.255" else 0

        is_public = not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or bool(result["is_broadcast"])
        )

        result["is_public_ip"] = 1 if is_public else 0

        return result

    def is_private_ip(self, ip_address_str: Optional[str]) -> bool:

        return bool(self.classify_ip(ip_address_str)["is_private_ip"])

    def is_external_ip(self, ip_address_str: Optional[str]) -> bool:

        return bool(self.classify_ip(ip_address_str)["is_public_ip"])

    def is_loopback(self, ip_address_str: Optional[str]) -> bool:

        return bool(self.classify_ip(ip_address_str)["is_loopback"])

    def is_ipv6(self, ip_address_str: Optional[str]) -> bool:

        return bool(self.classify_ip(ip_address_str)["is_ipv6"])

    def classify_port(self, port: Optional[int]) -> str:
        """
        Fine-grained service classification for a single port.
        """

        if port is None:

            return "UNKNOWN"

        return self.PORT_SERVICE_MAP.get(port, "UNKNOWN")

    def detect_service(self, source_port: Optional[int], destination_port: Optional[int]) -> str:
        """
        Fine-grained service_name for a connection: checks the
        destination port first (the usual "server" side for
        outbound connections), then falls back to the source
        port (covers the case where this machine IS the server).
        """

        for port in (destination_port, source_port):

            service = self.classify_port(port)

            if service != "UNKNOWN":

                return service

        return "UNKNOWN"

    def classify_protocol(self, source_port: Optional[int], destination_port: Optional[int]) -> str:
        """
        Coarse application-layer category, aligned with the
        is_dns / is_http / is_https / ... boolean flag set.
        This is intentionally a smaller vocabulary than
        service_name (e.g. MySQL and PostgreSQL both fall
        under "DATABASE" here).
        """

        ports = {p for p in (source_port, destination_port) if p is not None}

        if 53 in ports:
            return "DNS"

        if ports & {443, 8443}:
            return "HTTPS"

        if ports & {80, 8080}:
            return "HTTP"

        if 3389 in ports:
            return "RDP"

        if 445 in ports:
            return "SMB"

        if 22 in ports:
            return "SSH"

        if 123 in ports:
            return "NTP"

        if ports & {67, 68}:
            return "DHCP"

        if ports & self.MAIL_PORTS:
            return "MAIL"

        if ports & self.DATABASE_PORTS:
            return "DATABASE"

        return "OTHER"

    def _build_protocol_flags(self, source_port: Optional[int], destination_port: Optional[int]) -> dict:
        """
        Build every is_<protocol> boolean flag from the pair of
        ports involved in a connection.
        """

        ports = {p for p in (source_port, destination_port) if p is not None}

        flags = {
            "is_dns": 1 if 53 in ports else 0,
            "is_http": 1 if (ports & {80, 8080}) else 0,
            "is_https": 1 if (ports & {443, 8443}) else 0,
            "is_rdp": 1 if 3389 in ports else 0,
            "is_smb": 1 if 445 in ports else 0,
            "is_ssh": 1 if 22 in ports else 0,
            "is_ntp": 1 if 123 in ports else 0,
            "is_dhcp": 1 if (ports & {67, 68}) else 0,
            "is_mail": 1 if (ports & self.MAIL_PORTS) else 0,
            "is_database": 1 if (ports & self.DATABASE_PORTS) else 0,
        }

        flags["is_common_service"] = 1 if any(flags.values()) else 0

        return flags

    def _is_system_process(self, pid: Optional[int], process_name: Optional[str]) -> bool:
        """
        Heuristic classification of "is this a core OS process".
        Combines well-known pids (0 = Idle, 4 = System) with a
        curated name list. Deliberately conservative -- false
        negatives here are far safer than false positives for
        downstream anomaly-detection models.
        """

        if pid in (0, 4):

            return True

        if process_name and process_name.lower() in self.SYSTEM_PROCESS_NAMES:

            return True

        return False

    # ======================================================
    # Metadata Builder
    # ======================================================

    def build_metadata(self, base_info: dict, connection_duration: Optional[float] = None) -> dict:
        """
        Expand a connection's base_info (as stored in the
        snapshot) into the full AI-ready metadata dict matching
        the network_events schema exactly. This is only called
        when an event actually fires -- never on every poll --
        so the more expensive derived fields (hostname lookup)
        stay cheap in aggregate.
        """

        metadata = dict(base_info)

        source_port = metadata.get("source_port")

        destination_port = metadata.get("destination_port")

        destination_ip = metadata.get("destination_ip")

        process_id = metadata.get("process_id")

        process_name = metadata.get("process_name")

        connection_state = metadata.get("connection_state")

        metadata["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        metadata["protocol"] = self.classify_protocol(source_port, destination_port)

        metadata["service_name"] = self.detect_service(source_port, destination_port)

        metadata["hostname"] = self.get_hostname(destination_ip)

        metadata["connection_duration"] = connection_duration

        metadata["user_name"] = self.get_user_name()

        ip_flags = self.classify_ip(destination_ip)

        metadata.update(ip_flags)

        if destination_ip:

            metadata["is_local_connection"] = 1 if (ip_flags["is_private_ip"] or ip_flags["is_loopback"]) else 0

            metadata["is_external_connection"] = 1 if ip_flags["is_public_ip"] else 0

        else:

            metadata["is_local_connection"] = 0

            metadata["is_external_connection"] = 0

        metadata.update(self._build_protocol_flags(source_port, destination_port))

        metadata["is_listening"] = 1 if connection_state == "LISTEN" else 0

        metadata["is_established"] = 1 if connection_state == "ESTABLISHED" else 0

        metadata["is_system_process"] = 1 if self._is_system_process(process_id, process_name) else 0

        metadata["operation_id"] = self.generate_operation_id()

        metadata["event_uuid"] = self.generate_event_uuid()

        return metadata

    # ======================================================
    # Save Event
    # ======================================================

    def save_event(self, event_type: str, metadata: dict) -> None:
        """
        Save a network event into the SQLite database.
        Uses only database.db's get_connection()/close_connection();
        never opens a connection directly. Rolls back and logs on
        failure -- never raises out of this method.
        """

        conn = None

        try:

            conn = get_connection()

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO network_events
                (
                    timestamp,
                    event_type,
                    process_id,
                    process_name,
                    parent_process_id,
                    process_path,
                    process_username,
                    command_line,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    transport,
                    network_family,
                    connection_state,
                    hostname,
                    service_name,
                    connection_duration,
                    user_name,
                    is_private_ip,
                    is_public_ip,
                    is_loopback,
                    is_link_local,
                    is_multicast,
                    is_broadcast,
                    is_ipv6,
                    is_local_connection,
                    is_external_connection,
                    is_dns,
                    is_http,
                    is_https,
                    is_rdp,
                    is_smb,
                    is_ssh,
                    is_ntp,
                    is_dhcp,
                    is_mail,
                    is_database,
                    is_common_service,
                    is_listening,
                    is_established,
                    is_system_process,
                    operation_id,
                    event_uuid
                )
                VALUES
                (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    metadata.get("timestamp"),
                    event_type,
                    metadata.get("process_id"),
                    metadata.get("process_name"),
                    metadata.get("parent_process_id"),
                    metadata.get("process_path"),
                    metadata.get("process_username"),
                    metadata.get("command_line"),
                    metadata.get("source_ip"),
                    metadata.get("source_port"),
                    metadata.get("destination_ip"),
                    metadata.get("destination_port"),
                    metadata.get("protocol"),
                    metadata.get("transport"),
                    metadata.get("network_family"),
                    metadata.get("connection_state"),
                    metadata.get("hostname"),
                    metadata.get("service_name"),
                    metadata.get("connection_duration"),
                    metadata.get("user_name"),
                    metadata.get("is_private_ip"),
                    metadata.get("is_public_ip"),
                    metadata.get("is_loopback"),
                    metadata.get("is_link_local"),
                    metadata.get("is_multicast"),
                    metadata.get("is_broadcast"),
                    metadata.get("is_ipv6"),
                    metadata.get("is_local_connection"),
                    metadata.get("is_external_connection"),
                    metadata.get("is_dns"),
                    metadata.get("is_http"),
                    metadata.get("is_https"),
                    metadata.get("is_rdp"),
                    metadata.get("is_smb"),
                    metadata.get("is_ssh"),
                    metadata.get("is_ntp"),
                    metadata.get("is_dhcp"),
                    metadata.get("is_mail"),
                    metadata.get("is_database"),
                    metadata.get("is_common_service"),
                    metadata.get("is_listening"),
                    metadata.get("is_established"),
                    metadata.get("is_system_process"),
                    metadata.get("operation_id"),
                    metadata.get("event_uuid"),
                ),
            )

            conn.commit()

        except Exception as e:

            print(f"[DATABASE ERROR] {e}")

            if conn is not None:

                try:

                    conn.rollback()

                except Exception:

                    pass

        finally:

            if conn is not None:

                close_connection(conn)

    # ======================================================
    # PART 2 - SNAPSHOT ENGINE
    # ======================================================

    def _build_connection_record(self, conn) -> Optional[Tuple[tuple, dict]]:
        """
        Convert a single psutil connection record (pconn namedtuple)
        into (key, base_info). Returns None for malformed/unreadable
        entries so one bad record can never crash a full snapshot.
        """

        try:

            pid = conn.pid

            laddr = conn.laddr

            raddr = conn.raddr

            family = conn.family

            conn_type = conn.type

            status = conn.status

        except Exception:

            return None

        source_ip = laddr.ip if laddr else None

        source_port = laddr.port if laddr else None

        destination_ip = raddr.ip if raddr else None

        destination_port = raddr.port if raddr else None

        transport = (
            "TCP" if conn_type == socket.SOCK_STREAM
            else "UDP" if conn_type == socket.SOCK_DGRAM
            else "OTHER"
        )

        network_family = (
            "IPv6" if family == socket.AF_INET6
            else "IPv4" if family == socket.AF_INET
            else "OTHER"
        )

        connection_state = status if status else "NONE"

        process_info = self._get_process_info(pid)

        base_info = {
            "process_id": pid,
            "process_name": process_info["process_name"],
            "parent_process_id": process_info["parent_process_id"],
            "process_path": process_info["process_path"],
            "process_username": process_info["process_username"],
            "command_line": process_info["command_line"],
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "transport": transport,
            "network_family": network_family,
            "connection_state": connection_state,
        }

        key = (pid, source_ip, source_port, destination_ip, destination_port, transport)

        return key, base_info

    def take_snapshot(self) -> Dict[tuple, dict]:
        """
        Enumerate every current inet connection via
        psutil.net_connections() and return a dict keyed by
        (pid, local_ip, local_port, remote_ip, remote_port,
        transport) for O(1) lookup during diffing.

        Never raises: enumeration failures (e.g. running
        without Administrator) are logged and yield an empty
        snapshot for this cycle rather than crashing the thread.
        """

        snapshot: Dict[tuple, dict] = {}

        try:

            connections = psutil.net_connections(kind="inet")

        except (psutil.AccessDenied, PermissionError):

            print(
                "[NETWORK MONITOR] Access denied enumerating connections. "
                "Run as Administrator to see all process connections."
            )

            return snapshot

        except Exception as e:

            print(f"[NETWORK MONITOR] Failed to enumerate connections: {e}")

            return snapshot

        for conn in connections:

            try:

                record = self._build_connection_record(conn)

            except Exception:

                continue

            if record is None:

                continue

            key, base_info = record

            snapshot[key] = base_info

        return snapshot

    # ======================================================
    # Connection Diff Engine
    # ======================================================

    def _state_change_event_type(self, transport: Optional[str]) -> str:
        """
        The existing NetworkEventType enum has no dedicated
        "state changed" member, so state-change events borrow
        the transport-specific members instead:

            TCP connection state change -> TCP_CONNECTION
            UDP connection state change -> UDP_CONNECTION
            anything else               -> CONNECTED (fallback)

        This keeps state-change events unambiguous and distinct
        from CONNECTED/DISCONNECTED without requiring any change
        to event_types.py. The precise state itself (ESTABLISHED,
        TIME_WAIT, CLOSE_WAIT, ...) is always available in the
        connection_state column regardless of which event_type
        value is stored here.
        """

        if transport == "TCP":

            return NetworkEventType.TCP_CONNECTION.value

        if transport == "UDP":

            return NetworkEventType.UDP_CONNECTION.value

        return NetworkEventType.CONNECTED.value

    def compare_snapshots(
        self,
        old_snapshot: Dict[tuple, dict],
        new_snapshot: Dict[tuple, dict],
    ) -> List[Tuple[str, dict]]:
        """
        Compare two connection snapshots and return a list of
        (event_type_value, metadata) tuples.

        Mapped onto the existing NetworkEventType enum as:

            connection created        -> CONNECTED
            connection closed         -> DISCONNECTED
            connection state changed  -> TCP_CONNECTION / UDP_CONNECTION

        Never duplicates, never events for unchanged connections.
        """

        events: List[Tuple[str, dict]] = []

        old_keys = set(old_snapshot.keys())

        new_keys = set(new_snapshot.keys())

        created_keys = new_keys - old_keys

        closed_keys = old_keys - new_keys

        common_keys = old_keys & new_keys

        # ---------- Connections created ----------

        for key in created_keys:

            base_info = new_snapshot[key]

            self.connection_start_times[key] = time.time()

            metadata = self.build_metadata(base_info, connection_duration=0.0)

            events.append((NetworkEventType.CONNECTED.value, metadata))

        # ---------- Connections closed ----------

        for key in closed_keys:

            base_info = old_snapshot[key]

            start_time = self.connection_start_times.pop(key, None)

            duration = (time.time() - start_time) if start_time is not None else None

            metadata = self.build_metadata(base_info, connection_duration=duration)

            events.append((NetworkEventType.DISCONNECTED.value, metadata))

        # ---------- Connection state changes ----------

        for key in common_keys:

            old_info = old_snapshot[key]

            new_info = new_snapshot[key]

            if old_info.get("connection_state") != new_info.get("connection_state"):

                start_time = self.connection_start_times.get(key)

                duration = (time.time() - start_time) if start_time is not None else None

                metadata = self.build_metadata(new_info, connection_duration=duration)

                event_type = self._state_change_event_type(new_info.get("transport"))

                events.append((event_type, metadata))

        return events

    # ======================================================
    # Emit (console + persist)
    # ======================================================

    def _emit(self, event_type: str, metadata: dict) -> None:
        """
        Print a concise EDR-style log line, then persist the
        event. Console output never dumps the raw metadata dict.
        """

        process_name = metadata.get("process_name") or "UNKNOWN"

        source_ip = metadata.get("source_ip") or "-"

        source_port = metadata.get("source_port")

        source = f"{source_ip}:{source_port}" if source_port is not None else source_ip

        destination_ip = metadata.get("destination_ip")

        destination_port = metadata.get("destination_port")

        if destination_ip:

            destination = f"{destination_ip}:{destination_port}" if destination_port is not None else destination_ip

        else:

            destination = "-"

        protocol = metadata.get("protocol", "OTHER")

        state = metadata.get("connection_state", "NONE")

        print(f"[{event_type}]")

        print(process_name)

        print(source)

        print("  \u2193")

        print(destination)

        print(protocol)

        print(state)

        print("-" * 50)

        self.save_event(event_type, metadata)

    # ======================================================
    # PART 3 - NETWORK MONITORING / THREAD LOOP
    # ======================================================

    def _monitor_loop(self) -> None:
        """
        Single background worker thread. No busy-waiting: each
        cycle sleeps for self.interval, then takes one snapshot,
        diffs it, and emits whatever changed. Never lets an
        exception in one cycle kill the thread.
        """

        while self.running:

            time.sleep(self.interval)

            if not self.running:

                break

            events: List[Tuple[str, dict]] = []

            try:

                with self.lock:

                    new_snapshot = self.take_snapshot()

                    events = self.compare_snapshots(self.snapshot, new_snapshot)

                    self.snapshot = new_snapshot

            except Exception as e:

                print(f"[NETWORK MONITOR] Snapshot cycle failed: {e}")

                continue

            for event_type, metadata in events:

                try:

                    self._emit(event_type, metadata)

                except Exception as e:

                    print(f"[NETWORK MONITOR] Failed to emit event: {e}")

    # ======================================================
    # PART 4 - START / STOP
    # ======================================================

    def start(self) -> None:
        """
        Print the startup banner, capture an initial baseline
        snapshot (no events emitted for pre-existing connections
        -- matches the Registry Monitor's convention of treating
        the first snapshot as a baseline, not a set of creations),
        then launch the single monitoring thread.
        """

        print("=" * 60)

        print("Self-Evolving Security AI")

        print("Network Monitor")

        print("Version 1")

        print("=" * 60)

        self.running = True

        with self.lock:

            self.snapshot = self.take_snapshot()

        print(f"[NETWORK MONITOR] Baseline captured: {len(self.snapshot)} active connections.")

        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)

        self.thread.start()

        print("[NETWORK MONITOR] Monitoring started. Press Ctrl+C to stop.")

        try:

            while self.running:

                self.thread.join(timeout=1)

        except KeyboardInterrupt:

            self.stop()

    def stop(self) -> None:
        """
        Gracefully stop the monitor. Read-only by design: there
        are no OS handles to release here (unlike the Registry
        Monitor's open key handles) -- just the worker thread to
        join.
        """

        print("[NETWORK MONITOR] Stopping...")

        self.running = False

        if self.thread is not None:

            self.thread.join(timeout=self.interval + 5)

        print("[NETWORK MONITOR] Stopped.")


if __name__ == "__main__":

    monitor = NetworkMonitor()

    monitor.start()