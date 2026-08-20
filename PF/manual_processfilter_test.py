import os
import sys
from datetime import datetime, timezone

# Add the project root to the Python path to allow importing from 'filters'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from filters.filters import FilterEngine, ProcessFilter
except ImportError:
    print("Error: Could not import FilterEngine or ProcessFilter.")
    print("Please ensure this script is run from the project's root directory,")
    print("and that the project structure (filters/__init__.py) is correct.")
    sys.exit(1)


def run_test(title: str, event: dict, process_filter: ProcessFilter):
    """
    Runs a single test case and prints the formatted result.
    """
    print("=" * 70)
    print(title.upper())
    print("=" * 70)

    result = process_filter.filter_event(event)

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
    print("MANUAL PROCESS FILTER VERIFICATION SCRIPT")
    print("=" * 70 + "\n")

    engine = FilterEngine()
    process_filter = ProcessFilter(engine)

    # =========================================================
    # TEST 1: Normal Process
    # =========================================================
    test_1_event = {
        "process_name": "python.exe",
        "process_path": "C:\\Python39\\python.exe",
        "event_type": "PROCESS_CREATE",
        "pid": 1234,
        "parent_pid": 5678,
        "command_line": "python.exe my_script.py",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 1 - NORMAL PROCESS", test_1_event, process_filter)

    # =========================================================
    # TEST 2: Trusted Process
    # =========================================================
    test_2_event = {
        "process_name": "explorer.exe",
        "process_path": "C:\\Windows\\explorer.exe",
        "event_type": "PROCESS_CREATE",
        "pid": 2345,
        "parent_pid": 6789,
        "publisher": "Microsoft Corporation",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 2 - TRUSTED PROCESS", test_2_event, process_filter)

    # =========================================================
    # TEST 3: Duplicate Process
    # =========================================================
    test_3_event = {
        "process_name": "data_processor.exe",
        "process_path": "C:\\Apps\\data_processor.exe",
        "event_type": "PROCESS_CREATE",
        "pid": 3456,
        "parent_pid": 7890,
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 3A - FIRST DUPLICATE PROCESS", test_3_event, process_filter)
    run_test("TEST 3B - SECOND DUPLICATE PROCESS", test_3_event, process_filter)

    # =========================================================
    # TEST 4: Suspicious Process
    # =========================================================
    test_4_event = {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "event_type": "PROCESS_CREATE",
        "pid": 4567,
        "parent_pid": 8901,
        "command_line": "powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAAVwBvAHIAbABkACc=",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 4 - SUSPICIOUS PROCESS", test_4_event, process_filter)

    # =========================================================
    # TEST 5: Critical Process
    # =========================================================
    test_5_event = {
        "process_name": "lsass.exe",
        "process_path": "C:\\Windows\\System32\\lsass.exe",
        "event_type": "PROCESS_TERMINATE",
        "pid": 5678,
        "parent_pid": 9012,
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 5 - CRITICAL PROCESS", test_5_event, process_filter)

    # =========================================================
    # TEST 6: Invalid Event
    # =========================================================
    test_6_event = {}
    run_test("TEST 6 - INVALID EVENT (EMPTY DICT)", test_6_event, process_filter)

    print("=" * 70)
    print("ALL MANUAL PROCESS FILTER TESTS COMPLETED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()