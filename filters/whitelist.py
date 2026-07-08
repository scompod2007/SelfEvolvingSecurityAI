"""
============================================================
Self-Evolving Security AI
Whitelist Engine
Version : 1.0

Part 1.2A

Trusted Processes
Trusted Process Paths

Filtering logic DOES NOT belong here.

This file only stores trusted entities.

============================================================
"""

from pathlib import Path

# ============================================================
# TRUSTED PROCESSES
# ============================================================

TRUSTED_PROCESSES = {

    # Windows Core

    "System",
    "System Idle Process",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "spoolsv.exe",
    "dwm.exe",
    "taskhostw.exe",
    "RuntimeBroker.exe",
    "WmiPrvSE.exe",
    "dllhost.exe",

    # Windows Defender

    "MsMpEng.exe",
    "MpDefenderCoreService.exe",
    "NisSrv.exe",
    "SecurityHealthService.exe",

    # Windows Search

    "SearchIndexer.exe",
    "SearchHost.exe",

    # Windows Update

    "TiWorker.exe",
    "TrustedInstaller.exe",

    # Explorer

    "explorer.exe",

}

# ============================================================
# TRUSTED PROCESS PATHS
# ============================================================

TRUSTED_PROCESS_PATHS = {

    Path(r"C:\Windows"),
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),

}

# ============================================================
# PROCESS LOOKUP
# ============================================================

def is_trusted_process(process_name: str) -> bool:
    """
    Returns True if process is trusted.
    """

    if not process_name:
        return False

    return process_name.lower() in {

        p.lower()

        for p in TRUSTED_PROCESSES

    }


# ============================================================
# PROCESS PATH LOOKUP
# ============================================================

def is_trusted_process_path(path: str) -> bool:
    """
    Checks whether a process is running from
    a trusted installation folder.
    """

    if not path:
        return False

    try:

        process_path = Path(path).resolve()

    except Exception:

        return False

    for trusted in TRUSTED_PROCESS_PATHS:

        try:

            trusted = trusted.resolve()

            if process_path.is_relative_to(trusted):

                return True

        except Exception:

            continue

    return False


# ============================================================
# SUMMARY
# ============================================================

def whitelist_summary():

    return {

        "trusted_processes": len(TRUSTED_PROCESSES),
        "trusted_process_paths": len(TRUSTED_PROCESS_PATHS),

    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("Whitelist Summary")
    print("----------------------------")

    for k, v in whitelist_summary().items():

        print(f"{k:25}: {v}")
# ============================================================
# PART 1.2B
# Trusted Publishers
# Trusted Folders
# Trusted Registry Keys
# Trusted IPs
# Trusted Networks
# ============================================================

from pathlib import Path
import ipaddress

# ============================================================
# TRUSTED PUBLISHERS
# ============================================================

TRUSTED_PUBLISHERS = {

    # Microsoft
    "Microsoft Corporation",

    # Browsers
    "Google LLC",
    "Google Inc.",
    "Mozilla Corporation",
    "Brave Software Inc.",

    # Hardware
    "Intel Corporation",
    "NVIDIA Corporation",
    "Advanced Micro Devices, Inc.",
    "Realtek Semiconductor Corp.",

    # Development
    "Python Software Foundation",
    "Oracle Corporation",
    "GitHub, Inc.",
    "Docker Inc.",
    "OpenJS Foundation",

    # Virtualization
    "VMware, Inc.",
    "Oracle VM VirtualBox",

}

# ============================================================
# TRUSTED FOLDERS
# ============================================================

TRUSTED_FOLDERS = {

    Path(r"C:\Windows"),
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),

    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),

    Path(r"C:\ProgramData"),

    Path(r"C:\Users\Public"),

}

# ============================================================
# TRUSTED REGISTRY KEYS
# ============================================================

TRUSTED_REGISTRY_KEYS = {

    r"Software\Classes",

    r"Software\Microsoft\Windows\CurrentVersion\Explorer",

    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",

    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",

}

# ============================================================
# TRUSTED IPS
# ============================================================

TRUSTED_IPS = {

    "127.0.0.1",

    "::1",

}

# ============================================================
# TRUSTED NETWORKS
# ============================================================

TRUSTED_NETWORKS = {

    "127.0.0.0/8",

    "::1/128",

}

# ============================================================
# PUBLISHER LOOKUP
# ============================================================

def is_trusted_publisher(publisher: str) -> bool:

    if not publisher:
        return False

    publisher = publisher.strip().lower()

    return publisher in {

        p.lower()

        for p in TRUSTED_PUBLISHERS

    }


# ============================================================
# FOLDER LOOKUP
# ============================================================

def is_trusted_folder(path: str) -> bool:

    if not path:
        return False

    try:

        file_path = Path(path).resolve()

    except Exception:

        return False

    for folder in TRUSTED_FOLDERS:

        try:

            if file_path.is_relative_to(folder.resolve()):

                return True

        except Exception:

            continue

    return False


# ============================================================
# REGISTRY LOOKUP
# ============================================================

def is_trusted_registry_key(key: str) -> bool:

    if not key:
        return False

    key = key.lower()

    for trusted in TRUSTED_REGISTRY_KEYS:

        if trusted.lower() in key:

            return True

    return False


# ============================================================
# IP LOOKUP
# ============================================================

def is_trusted_ip(ip: str) -> bool:

    if not ip:
        return False

    return ip in TRUSTED_IPS


# ============================================================
# NETWORK LOOKUP
# ============================================================

def is_trusted_network(ip: str) -> bool:

    if not ip:
        return False

    try:

        address = ipaddress.ip_address(ip)

    except Exception:

        return False

    for network in TRUSTED_NETWORKS:

        try:

            if address in ipaddress.ip_network(network, strict=False):

                return True

        except Exception:

            continue

    return False


# ============================================================
# SUMMARY
# ============================================================

def whitelist_part2_summary():

    return {

        "trusted_publishers": len(TRUSTED_PUBLISHERS),

        "trusted_folders": len(TRUSTED_FOLDERS),

        "trusted_registry_keys": len(TRUSTED_REGISTRY_KEYS),

        "trusted_ips": len(TRUSTED_IPS),

        "trusted_networks": len(TRUSTED_NETWORKS),

    }