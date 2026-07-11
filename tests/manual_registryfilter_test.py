import os
import sys
from datetime import datetime, timezone

# Add the project root to the Python path to allow importing from 'filters'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from filters.filters import FilterEngine, RegistryFilter
except ImportError:
    print("Error: Could not import FilterEngine or RegistryFilter.")
    print("Please ensure this script is run from the project's root directory,")
    print("and that the project structure (filters/__init__.py) is correct.")
    sys.exit(1)


def run_test(title: str, event: dict, registry_filter: RegistryFilter):
    """
    Runs a single test case and prints the formatted result.
    """
    print("=" * 70)
    print(title.upper())
    print("=" * 70)

    result = registry_filter.filter_event(event)

    print(f"{'Accepted':<15}: {result.accepted}")
    print(f"{'Filtered':<15}: {result.filtered}")
    print(f"{'Reason':<15}: {result.reason}")
    print(f"{'Severity':<15}: {result.severity}")
    print(f"{'Confidence':<15}: {result.confidence}")
    print(f"{'Duplicate':<15}: {result.duplicate}")
    print(f"{'Whitelisted':<15}: {result.whitelisted}")
    print(f"{'Suspicious':<15}: {result.suspicious}")
    print(f"{'Correlation ID':<15}: {result.correlation_id}")
    print(f"{'Event Hash':<15}: {result.event_hash}")
    print("-" * 70)
    print()


def main():
    """
    Main entry point for the manual test script.
    """
    print("\n" + "=" * 70)
    print("MANUAL REGISTRY FILTER VERIFICATION SCRIPT")
    print("=" * 70 + "\n")

    engine = FilterEngine()
    registry_filter = RegistryFilter(engine)

    # =========================================================
    # TEST 1: Normal Registry Modification
    # =========================================================
    test_1_event = {
        "hive": "HKCU",
        "registry_key": "Software\\TestApp\\Settings",
        "value_name": "Theme",
        "value_data": "Dark",
        "operation": "MODIFY",
        "event_type": "REGISTRY_MODIFY",
        "process_name": "testapp.exe",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 1 - NORMAL REGISTRY MODIFICATION", test_1_event, registry_filter)

    # =========================================================
    # TEST 2: Trusted Registry Modification
    # =========================================================
    test_2_event = {
        "hive": "HKLM",
        "registry_key": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        "value_name": "ShowTaskViewButton",
        "value_data": 0,
        "operation": "MODIFY",
        "event_type": "REGISTRY_MODIFY",
        "process_name": "explorer.exe",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 2 - TRUSTED REGISTRY MODIFICATION", test_2_event, registry_filter)

    # =========================================================
    # TEST 3: Duplicate Registry Modification
    # =========================================================
    test_3_event = {
        "hive": "HKCU",
        "registry_key": "Software\\AnotherApp\\Config",
        "value_name": "LastUser",
        "value_data": "admin",
        "operation": "MODIFY",
        "event_type": "REGISTRY_MODIFY",
        "process_name": "anotherapp.exe",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 3A - FIRST DUPLICATE REGISTRY MODIFICATION", test_3_event, registry_filter)
    run_test("TEST 3B - SECOND DUPLICATE REGISTRY MODIFICATION", test_3_event, registry_filter)

    # =========================================================
    # TEST 4: Suspicious Registry Modification
    # =========================================================
    test_4_event = {
        "hive": "HKCU",
        "registry_key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "MyMalware",
        "value_data": "C:\\Users\\Public\\malware.exe",
        "operation": "CREATE",
        "event_type": "REGISTRY_CREATE",
        "process_name": "powershell.exe",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 4 - SUSPICIOUS REGISTRY MODIFICATION", test_4_event, registry_filter)

    # =========================================================
    # TEST 5: Critical Registry Modification
    # =========================================================
    test_5_event = {
        "hive": "HKLM",
        "registry_key": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "value_name": "Shell",
        "value_data": "explorer.exe, C:\\temp\\evil.dll",
        "operation": "MODIFY",
        "event_type": "REGISTRY_MODIFY",
        "process_name": "reg.exe",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 5 - CRITICAL REGISTRY MODIFICATION", test_5_event, registry_filter)

    # =========================================================
    # TEST 6: Invalid Event
    # =========================================================
    test_6_event = {}
    run_test("TEST 6 - INVALID EVENT (EMPTY DICT)", test_6_event, registry_filter)

    print("=" * 70)
    print("ALL MANUAL REGISTRY FILTER TESTS COMPLETED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()