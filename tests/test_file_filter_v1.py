import os
import sys

# ------------------------------------------------------------
# Add project root
# ------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

# ------------------------------------------------------------
# Imports
# ------------------------------------------------------------
from filters.filters import FilterEngine, FileFilter

# ------------------------------------------------------------
# Create Engine
# ------------------------------------------------------------
engine = FilterEngine()
file_filter = FileFilter(engine)

# ------------------------------------------------------------
# Helper
# ------------------------------------------------------------
def run_test(title, event):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    result = file_filter.filter_event(event)

    print(f"Accepted       : {result.accepted}")
    print(f"Filtered       : {result.filtered}")
    print(f"Reason         : {result.reason}")
    print(f"Severity       : {result.severity}")
    print(f"Confidence     : {result.confidence}")
    print(f"Duplicate      : {result.duplicate}")
    print(f"Whitelisted    : {result.whitelisted}")
    print(f"Suspicious     : {result.suspicious}")
    print(f"Correlation ID : {result.correlation_id}")
    print(f"Event Hash     : {result.event_hash}")

# ============================================================
# TEST 1
# Normal File
# ============================================================

run_test(
    "TEST 1 - NORMAL FILE",
    {
        "file_path": r"C:\Users\Test\document.txt",
        "event_type": "FILE_CREATE",
        "process_name": "notepad.exe",
        "extension": ".txt",
        "user": "Sanjay"
    }
)

# ============================================================
# TEST 2
# Ignored Extension (.tmp)
# ============================================================

run_test(
    "TEST 2 - TMP FILE",
    {
    "file_path": r"C:\Users\Test\temp.tmp",
    "event_type": "FILE_CREATE",
    "process_name": "myprogram.exe",
    "extension": ".tmp",
    }
)

# ============================================================
# TEST 3
# Dangerous Extension (.exe)
# ============================================================

run_test(
    "TEST 3 - EXE FILE",
    {
        "file_path": r"C:\Users\Test\virus.exe",
        "event_type": "FILE_CREATE",
        "process_name": "cmd.exe",
        "extension": ".exe",
        "user": "Sanjay"
    }
)

# ============================================================
# TEST 4
# Duplicate Detection
# ============================================================

duplicate_event = {
    "file_path": r"C:\Users\Test\duplicate.txt",
    "event_type": "FILE_CREATE",
    "process_name": "python.exe",
    "extension": ".txt",
    "user": "Sanjay"
}

run_test(
    "TEST 4A - FIRST DUPLICATE EVENT",
    duplicate_event
)

run_test(
    "TEST 4B - SECOND DUPLICATE EVENT",
    duplicate_event
)

# ============================================================
# TEST 5
# Whitelisted Process
# ============================================================

run_test(
    "TEST 5 - WHITELISTED PROCESS",
    {
        "file_path": r"C:\Users\Test\safe.txt",
        "event_type": "FILE_READ",
        "process_name": "explorer.exe",
        "extension": ".txt",
        "user": "Sanjay"
    }
)

# ============================================================
# TEST 6
# System32 Delete
# ============================================================

run_test(
    "TEST 6 - SYSTEM32 DELETE",
    {
        "file_path": r"C:\Windows\System32\kernel32.dll",
        "event_type": "FILE_DELETE",
        "process_name": "malware.exe",
        "extension": ".dll",
    }
)

print("\n")
print("=" * 70)
print("ALL MANUAL TESTS COMPLETED")
print("=" * 70)