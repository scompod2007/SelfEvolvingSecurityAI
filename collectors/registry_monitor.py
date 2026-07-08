"""
==========================================================
Registry Monitor - Version 1
Self-Evolving Security AI

Native Windows API Implementation
(ctypes + advapi32.dll -- no pywin32, no polling)

Features
--------
✓ Event-driven monitoring via RegNotifyChangeKeyValue
✓ One thread per watched registry root
✓ Snapshot + diff engine (keys and values)
✓ AI-ready metadata / correlation fields
✓ Graceful handling of access-denied / deleted keys
==========================================================
"""

import os
import struct
import getpass
import threading
import uuid
from ctypes import (
    WinDLL,
    byref,
    cast,
    create_unicode_buffer,
    POINTER,
    c_byte,
)
from ctypes import wintypes
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from database.db import get_connection, close_connection
from collectors.event_types import RegistryEventType


# ==========================================================
# Native Windows API bindings
# ==========================================================

advapi32 = WinDLL("Advapi32.dll", use_last_error=True)
kernel32 = WinDLL("Kernel32.dll", use_last_error=True)

# ---------------- HKEY root constants ----------------

HKEY_LOCAL_MACHINE = wintypes.HKEY(0x80000002)
HKEY_CURRENT_USER = wintypes.HKEY(0x80000001)

# ---------------- Access rights ----------------

KEY_READ = 0x20019
KEY_NOTIFY = 0x0010

# ---------------- Notify filter flags ----------------

REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008

# ---------------- Registry value types ----------------

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11

# ---------------- Win32 error codes ----------------

ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_MORE_DATA = 234
ERROR_NO_MORE_ITEMS = 259
ERROR_KEY_DELETED = 1018

# ---------------- Wait constants ----------------

INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000
WAIT_FAILED = 0xFFFFFFFF


# ---------------- Function prototypes ----------------

advapi32.RegOpenKeyExW.argtypes = [
    wintypes.HKEY,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    POINTER(wintypes.HKEY),
]
advapi32.RegOpenKeyExW.restype = wintypes.LONG

advapi32.RegNotifyChangeKeyValue.argtypes = [
    wintypes.HKEY,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.HANDLE,
    wintypes.BOOL,
]
advapi32.RegNotifyChangeKeyValue.restype = wintypes.LONG

advapi32.RegCloseKey.argtypes = [wintypes.HKEY]
advapi32.RegCloseKey.restype = wintypes.LONG

advapi32.RegEnumKeyExW.argtypes = [
    wintypes.HKEY,
    wintypes.DWORD,
    wintypes.LPWSTR,
    POINTER(wintypes.DWORD),
    POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    POINTER(wintypes.DWORD),
    POINTER(wintypes.FILETIME),
]
advapi32.RegEnumKeyExW.restype = wintypes.LONG

advapi32.RegEnumValueW.argtypes = [
    wintypes.HKEY,
    wintypes.DWORD,
    wintypes.LPWSTR,
    POINTER(wintypes.DWORD),
    POINTER(wintypes.DWORD),
    POINTER(wintypes.DWORD),
    POINTER(c_byte),
    POINTER(wintypes.DWORD),
]
advapi32.RegEnumValueW.restype = wintypes.LONG

advapi32.RegQueryValueExW.argtypes = [
    wintypes.HKEY,
    wintypes.LPCWSTR,
    POINTER(wintypes.DWORD),
    POINTER(wintypes.DWORD),
    POINTER(c_byte),
    POINTER(wintypes.DWORD),
]
advapi32.RegQueryValueExW.restype = wintypes.LONG

kernel32.CreateEventW.argtypes = [
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.BOOL,
    wintypes.LPCWSTR,
]
kernel32.CreateEventW.restype = wintypes.HANDLE

kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.SetEvent.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.WaitForMultipleObjects.argtypes = [
    wintypes.DWORD,
    POINTER(wintypes.HANDLE),
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.WaitForMultipleObjects.restype = wintypes.DWORD


# ==========================================================
# Registry Monitor
# ==========================================================


class RegistryMonitor:
    """
    Windows Registry Monitor - Version 1

    Native Windows API implementation (ctypes + advapi32.dll).

    Architecture
        Part 1  Helper Functions
        Part 2  Snapshot / Diff Engine
        Part 3  Event-Driven Monitoring (RegNotifyChangeKeyValue)
        Part 4  Start / Stop
    """

    # ---------------- Hive name -> native root handle ----------------

    HIVE_MAP: Dict[str, wintypes.HKEY] = {
        "HKLM": HKEY_LOCAL_MACHINE,
        "HKCU": HKEY_CURRENT_USER,
    }

    # ---------------- Watched roots per hive ----------------
    #
    # More paths can be appended here later without touching
    # the monitoring architecture itself.

    WATCHED_PATHS: Dict[str, List[str]] = {
        "HKLM": [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SYSTEM\CurrentControlSet\Services",
            r"SOFTWARE\Policies",
            r"SOFTWARE\Microsoft\Windows Defender",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ],
        "HKCU": [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Policies",
        ],
    }

    def __init__(self):

        self.running = False

        self.threads: List[threading.Thread] = []

        # snapshot cache: (hive_name, root_path) -> tree dict

        self.snapshots: Dict[Tuple[str, str], Dict[str, dict]] = {}

        self.lock = threading.Lock()

        # native manual-reset stop event, shared by all threads

        self.stop_event = kernel32.CreateEventW(None, True, False, None)

    # ======================================================
    # PART 1 - HELPER FUNCTIONS
    # ======================================================

    def get_user_name(self) -> Optional[str]:

        try:

            return getpass.getuser()

        except Exception:

            return None

    def generate_event_uuid(self) -> str:

        return str(uuid.uuid4())

    def generate_operation_id(self) -> str:

        return str(uuid.uuid4())

    def get_hive(self, registry_path: str) -> str:

        upper_path = registry_path.upper()

        if upper_path.startswith("HKLM") or upper_path.startswith("HKEY_LOCAL_MACHINE"):
            return "HKLM"

        elif upper_path.startswith("HKCU") or upper_path.startswith("HKEY_CURRENT_USER"):
            return "HKCU"

        elif upper_path.startswith("HKCR") or upper_path.startswith("HKEY_CLASSES_ROOT"):
            return "HKCR"

        elif upper_path.startswith("HKU") or upper_path.startswith("HKEY_USERS"):
            return "HKU"

        elif upper_path.startswith("HKCC") or upper_path.startswith("HKEY_CURRENT_CONFIG"):
            return "HKCC"

        return "UNKNOWN"

    def is_startup_location(self, registry_path: str) -> int:

        startup_keys = [
            r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
            r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
            r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN",
            r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
        ]

        upper_path = registry_path.upper()

        for key in startup_keys:

            if key in upper_path:

                return 1

        return 0

    def is_sensitive_key(self, registry_path: str) -> int:

        sensitive_keywords = [
            "DEFENDER",
            "POLICIES",
            "SERVICES",
            "SECURITY",
            "FIREWALL",
            "UAC",
            "WINLOGON",
            "LSA",
            "SAM",
        ]

        upper_path = registry_path.upper()

        for keyword in sensitive_keywords:

            if keyword in upper_path:

                return 1

        return 0

    # ======================================================
    # Metadata Builder
    # ======================================================

    def build_registry_metadata(
        self,
        registry_path: str,
        value_name: Optional[str] = None,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        value_type: Optional[int] = None,
        previous_exists: bool = False,
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
    ) -> dict:
        """
        Build AI-ready registry metadata matching the
        registry_events schema exactly.
        """

        metadata = {}

        metadata["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        metadata["registry_path"] = registry_path

        metadata["hive"] = self.get_hive(registry_path)

        metadata["key_name"] = os.path.basename(registry_path)

        metadata["value_name"] = value_name

        metadata["old_value"] = old_value

        metadata["new_value"] = new_value

        metadata["value_type"] = value_type

        metadata["process_id"] = process_id

        metadata["process_name"] = process_name

        metadata["user_name"] = self.get_user_name()

        metadata["is_startup_location"] = self.is_startup_location(registry_path)

        metadata["is_sensitive_key"] = self.is_sensitive_key(registry_path)

        metadata["previous_exists"] = int(previous_exists)

        metadata["operation_id"] = self.generate_operation_id()

        metadata["event_uuid"] = self.generate_event_uuid()

        return metadata

    # ======================================================
    # Save Event
    # ======================================================

    def save_event(self, event_type: str, metadata: dict) -> None:
        """
        Save a registry event into the SQLite database.
        """

        conn = None

        try:

            conn = get_connection()

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO registry_events
                (
                    timestamp,
                    event_type,
                    registry_path,
                    hive,
                    key_name,
                    value_name,
                    old_value,
                    new_value,
                    value_type,
                    process_id,
                    process_name,
                    user_name,
                    is_startup_location,
                    is_sensitive_key,
                    previous_exists,
                    operation_id,
                    event_uuid
                )
                VALUES
                (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    metadata["timestamp"],
                    event_type,
                    metadata["registry_path"],
                    metadata["hive"],
                    metadata["key_name"],
                    metadata["value_name"],
                    metadata["old_value"],
                    metadata["new_value"],
                    metadata["value_type"],
                    metadata["process_id"],
                    metadata["process_name"],
                    metadata["user_name"],
                    metadata["is_startup_location"],
                    metadata["is_sensitive_key"],
                    metadata["previous_exists"],
                    metadata["operation_id"],
                    metadata["event_uuid"],
                ),
            )

            conn.commit()

        except Exception as e:

            print(f"[DATABASE ERROR] {e}")

        finally:

            if conn:

                close_connection(conn)

    # ======================================================
    # PART 2 - SNAPSHOT / DIFF ENGINE
    # ======================================================

    def _open_key(
        self,
        hive_handle: wintypes.HKEY,
        sub_path: str,
        access: int = KEY_READ,
    ) -> Tuple[Optional[wintypes.HKEY], int]:
        """
        Thin wrapper over RegOpenKeyExW.
        Returns (handle, win32_error_code).
        """

        handle = wintypes.HKEY()

        result = advapi32.RegOpenKeyExW(
            hive_handle,
            sub_path,
            0,
            access,
            byref(handle),
        )

        if result != ERROR_SUCCESS:

            return None, result

        return handle, ERROR_SUCCESS

    def _convert_registry_value(self, raw: bytes, value_type: int):
        """
        Convert raw registry bytes into a display-safe string,
        based on the value's REG_* type.
        """

        try:

            if value_type in (REG_SZ, REG_EXPAND_SZ):

                text = raw.decode("utf-16-le", errors="ignore")

                return text.split("\x00", 1)[0]

            elif value_type == REG_MULTI_SZ:

                text = raw.decode("utf-16-le", errors="ignore")

                parts = [p for p in text.split("\x00") if p]

                return "; ".join(parts)

            elif value_type == REG_DWORD:

                if len(raw) >= 4:

                    return str(struct.unpack("<I", raw[:4])[0])

                return raw.hex()

            elif value_type == REG_DWORD_BIG_ENDIAN:

                if len(raw) >= 4:

                    return str(struct.unpack(">I", raw[:4])[0])

                return raw.hex()

            elif value_type == REG_QWORD:

                if len(raw) >= 8:

                    return str(struct.unpack("<Q", raw[:8])[0])

                return raw.hex()

            elif value_type == REG_BINARY:

                return raw.hex()

            elif value_type == REG_NONE:

                return ""

            else:

                return raw.hex()

        except Exception:

            return raw.hex() if raw else ""

    def _enum_subkeys(self, hkey: wintypes.HKEY) -> List[str]:
        """
        Enumerate immediate subkey names of an open key handle.
        """

        subkeys = []

        index = 0

        name_capacity = 512

        while True:

            name_buf = create_unicode_buffer(name_capacity)

            name_len = wintypes.DWORD(name_capacity)

            result = advapi32.RegEnumKeyExW(
                hkey,
                index,
                name_buf,
                byref(name_len),
                None,
                None,
                None,
                None,
            )

            if result == ERROR_NO_MORE_ITEMS:

                break

            if result == ERROR_MORE_DATA:

                name_capacity *= 2

                continue

            if result != ERROR_SUCCESS:

                break

            subkeys.append(name_buf.value)

            index += 1

        return subkeys

    def _enum_values(self, hkey: wintypes.HKEY) -> Dict[str, Tuple[str, int]]:
        """
        Enumerate values of an open key handle.
        Returns {value_name: (display_value, value_type)}
        """

        values: Dict[str, Tuple[str, int]] = {}

        index = 0

        while True:

            name_capacity = 512

            data_capacity = 8192

            while True:

                name_buf = create_unicode_buffer(name_capacity)

                name_len = wintypes.DWORD(name_capacity)

                value_type = wintypes.DWORD(0)

                data_buf = (c_byte * data_capacity)()

                data_len = wintypes.DWORD(data_capacity)

                result = advapi32.RegEnumValueW(
                    hkey,
                    index,
                    name_buf,
                    byref(name_len),
                    None,
                    byref(value_type),
                    cast(data_buf, POINTER(c_byte)),
                    byref(data_len),
                )

                if result == ERROR_MORE_DATA:

                    name_capacity *= 2

                    data_capacity *= 2

                    continue

                break

            if result == ERROR_NO_MORE_ITEMS:

                break

            if result != ERROR_SUCCESS:

                break

            raw_bytes = bytes(bytearray(data_buf)[: data_len.value])

            display_value = self._convert_registry_value(raw_bytes, value_type.value)

            values[name_buf.value] = (display_value, value_type.value)

            index += 1

        return values

    def snapshot_key(self, hive_handle: wintypes.HKEY, sub_path: str) -> Optional[dict]:
        """
        Snapshot the immediate values and subkey names of a
        single registry key. Returns None if the key cannot
        be opened (deleted, access denied, etc).
        """

        handle, result = self._open_key(hive_handle, sub_path)

        if handle is None:

            return None

        try:

            values = self._enum_values(handle)

            subkeys = self._enum_subkeys(handle)

        finally:

            advapi32.RegCloseKey(handle)

        return {"values": values, "subkeys": subkeys}

    def snapshot_tree(self, hive_handle: wintypes.HKEY, sub_path: str) -> Dict[str, dict]:
        """
        Recursively snapshot a subtree into a flat dict keyed
        by relative registry path.
        """

        tree: Dict[str, dict] = {}

        node = self.snapshot_key(hive_handle, sub_path)

        if node is None:

            return tree

        tree[sub_path] = node

        for child in node["subkeys"]:

            child_path = f"{sub_path}\\{child}"

            tree.update(self.snapshot_tree(hive_handle, child_path))

        return tree

    def diff_snapshot(
        self,
        hive_name: str,
        old_tree: Dict[str, dict],
        new_tree: Dict[str, dict],
    ) -> List[Tuple[str, dict]]:
        """
        Compare two snapshots of the same subtree and return a
        list of (RegistryEventType, metadata) tuples describing
        every key/value that was created, modified, or deleted.
        """

        events: List[Tuple[str, dict]] = []

        old_paths = set(old_tree.keys())

        new_paths = set(new_tree.keys())

        # ---------- Keys created ----------

        for path in new_paths - old_paths:

            full_path = f"{hive_name}\\{path}"

            metadata = self.build_registry_metadata(
                registry_path=full_path,
                previous_exists=False,
            )

            events.append((RegistryEventType.KEY_CREATED, metadata))

        # ---------- Keys deleted ----------

        for path in old_paths - new_paths:

            full_path = f"{hive_name}\\{path}"

            metadata = self.build_registry_metadata(
                registry_path=full_path,
                previous_exists=True,
            )

            events.append((RegistryEventType.KEY_DELETED, metadata))

        # ---------- Keys present on both sides ----------

        for path in old_paths & new_paths:

            full_path = f"{hive_name}\\{path}"

            old_values = old_tree[path]["values"]

            new_values = new_tree[path]["values"]

            old_names = set(old_values.keys())

            new_names = set(new_values.keys())

            value_changed = False

            for name in new_names - old_names:

                new_data, new_type = new_values[name]

                metadata = self.build_registry_metadata(
                    registry_path=full_path,
                    value_name=name,
                    old_value=None,
                    new_value=new_data,
                    value_type=new_type,
                    previous_exists=False,
                )

                events.append((RegistryEventType.VALUE_CREATED, metadata))

                value_changed = True

            for name in old_names - new_names:

                old_data, old_type = old_values[name]

                metadata = self.build_registry_metadata(
                    registry_path=full_path,
                    value_name=name,
                    old_value=old_data,
                    new_value=None,
                    value_type=old_type,
                    previous_exists=True,
                )

                events.append((RegistryEventType.VALUE_DELETED, metadata))

                value_changed = True

            for name in old_names & new_names:

                old_data, old_type = old_values[name]

                new_data, new_type = new_values[name]

                if old_data != new_data or old_type != new_type:

                    metadata = self.build_registry_metadata(
                        registry_path=full_path,
                        value_name=name,
                        old_value=old_data,
                        new_value=new_data,
                        value_type=new_type,
                        previous_exists=True,
                    )

                    events.append((RegistryEventType.VALUE_MODIFIED, metadata))

                    value_changed = True

            # subkey list changed (renames / reordering) but the key
            # itself was neither created nor deleted, and no direct
            # value change explains it -> report as KEY_MODIFIED

            if not value_changed and old_tree[path]["subkeys"] != new_tree[path]["subkeys"]:

                metadata = self.build_registry_metadata(
                    registry_path=full_path,
                    previous_exists=True,
                )

                events.append((RegistryEventType.KEY_MODIFIED, metadata))

        return events

    # ======================================================
    # Emit (print + persist)
    # ======================================================

    def _emit(self, event_type: str, metadata: dict) -> None:

        print(f"[{event_type.value}]")

        print(metadata["registry_path"])

        if metadata.get("value_name"):

            print("Value:")

            print(metadata["value_name"])

            print("Old:")

            print(metadata["old_value"])

            print("New:")

            print(metadata["new_value"])

        print("-" * 50)

        self.save_event(event_type, metadata)

    # ======================================================
    # PART 3 - EVENT-DRIVEN MONITORING
    # ======================================================

    def _watch_root(self, hive_name: str, sub_path: str) -> None:
        """
        Monitor a single registry root using RegNotifyChangeKeyValue.

        This thread blocks on WaitForMultipleObjects and is only
        woken up by Windows (notify_event) or by stop() (stop_event).
        There is no polling timer anywhere in this loop.
        """

        hive_handle = self.HIVE_MAP[hive_name]

        handle, result = self._open_key(hive_handle, sub_path, KEY_READ | KEY_NOTIFY)

        if handle is None:

            if result == ERROR_FILE_NOT_FOUND:

                print(f"[REGISTRY MONITOR] Path not found, skipping: {hive_name}\\{sub_path}")

            elif result == ERROR_ACCESS_DENIED:

                print(f"[REGISTRY MONITOR] Access denied, skipping: {hive_name}\\{sub_path}")

            else:

                print(f"[REGISTRY MONITOR] Could not open {hive_name}\\{sub_path} (error {result})")

            return

        notify_event = kernel32.CreateEventW(None, False, False, None)

        # initial snapshot, taken before we start waiting for changes

        with self.lock:

            self.snapshots[(hive_name, sub_path)] = self.snapshot_tree(hive_handle, sub_path)

        notify_filter = (
            REG_NOTIFY_CHANGE_NAME
            | REG_NOTIFY_CHANGE_LAST_SET
            | REG_NOTIFY_CHANGE_ATTRIBUTES
            | REG_NOTIFY_CHANGE_SECURITY
        )

        wait_handles = (wintypes.HANDLE * 2)(notify_event, self.stop_event)

        try:

            while self.running:

                # Register for the next change notification.
                # fAsynchronous=True: this call returns immediately and
                # signals notify_event when a change occurs -- no
                # blocking / polling happens inside this call itself.

                reg_result = advapi32.RegNotifyChangeKeyValue(
                    handle,
                    True,
                    notify_filter,
                    notify_event,
                    True,
                )

                if reg_result == ERROR_KEY_DELETED:

                    print(f"[REGISTRY MONITOR] Key deleted, stopping watch: {hive_name}\\{sub_path}")

                    break

                if reg_result != ERROR_SUCCESS:

                    print(
                        f"[REGISTRY MONITOR] RegNotifyChangeKeyValue failed on "
                        f"{hive_name}\\{sub_path} (error {reg_result})"
                    )

                    break

                # Block here -- woken only by Windows (notify_event)
                # or by stop() (stop_event). No timeout, no sleep loop.

                wait_result = kernel32.WaitForMultipleObjects(
                    2,
                    wait_handles,
                    False,
                    INFINITE,
                )

                if wait_result == WAIT_OBJECT_0 + 1:

                    # stop_event fired

                    break

                if wait_result != WAIT_OBJECT_0:

                    # unexpected wait failure

                    print(f"[REGISTRY MONITOR] Wait failed on {hive_name}\\{sub_path}")

                    break

                if not self.running:

                    break

                # notify_event fired -> something changed below this root

                with self.lock:

                    old_tree = self.snapshots.get((hive_name, sub_path), {})

                    new_tree = self.snapshot_tree(hive_handle, sub_path)

                    events = self.diff_snapshot(hive_name, old_tree, new_tree)

                    self.snapshots[(hive_name, sub_path)] = new_tree

                for event_type, metadata in events:

                    self._emit(event_type, metadata)

        finally:

            advapi32.RegCloseKey(handle)

            kernel32.CloseHandle(notify_event)

    # ======================================================
    # PART 4 - START / STOP
    # ======================================================

    def start(self) -> None:

        print("=" * 60)

        print("Self-Evolving Security AI")

        print("Registry Monitor")

        print("Version 1")

        print("=" * 60)

        self.running = True

        for hive_name, paths in self.WATCHED_PATHS.items():

            for sub_path in paths:

                thread = threading.Thread(
                    target=self._watch_root,
                    args=(hive_name, sub_path),
                    daemon=True,
                )

                thread.start()

                self.threads.append(thread)

                print(f"[REGISTRY MONITOR] Watching {hive_name}\\{sub_path}")

        print("[REGISTRY MONITOR] Monitoring started. Press Ctrl+C to stop.")

        try:

            while self.running:

                # Join with a timeout purely so this main thread can
                # notice Ctrl+C; the worker threads themselves never
                # poll -- they block on WaitForMultipleObjects.

                for thread in self.threads:

                    thread.join(timeout=1)

        except KeyboardInterrupt:

            self.stop()

    def stop(self) -> None:

        print("[REGISTRY MONITOR] Stopping...")

        self.running = False

        # Wake every waiting thread immediately via the shared
        # manual-reset stop event.

        kernel32.SetEvent(self.stop_event)

        for thread in self.threads:

            thread.join(timeout=5)

        kernel32.CloseHandle(self.stop_event)

        print("[REGISTRY MONITOR] Stopped.")


if __name__ == "__main__":

    monitor = RegistryMonitor()

    monitor.start()