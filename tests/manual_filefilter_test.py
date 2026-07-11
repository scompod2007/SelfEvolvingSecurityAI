import os
import sys
from datetime import datetime, timezone

# Add the project root to the Python path to allow importing from 'filters'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from filters.filters import FilterEngine, FileFilter
except ImportError:
    print("Error: Could not import FilterEngine or FileFilter.")
    print("Please ensure this script is run from the project's root directory,")
    print("and that the project structure (filters/__init__.py) is correct.")
    sys.exit(1)


def run_test(title: str, event: dict, file_filter: FileFilter):
    """
    Runs a single test case and prints the formatted result.
    """
    print("=" * 70)
    print(title.upper())
    print("=" * 70)

    result = file_filter.filter_event(event)

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
    print("MANUAL FILE FILTER VERIFICATION SCRIPT")
    print("=" * 70 + "\n")

    engine = FilterEngine()
    file_filter = FileFilter(engine)

    # =========================================================
    # TEST 1: Normal File Creation
    # =========================================================
    test_1_event = {
        "file_path": "C:\\Users\\TestUser\\Documents\\report.docx",
        "file_name": "report.docx",
        "extension": ".docx",
        "operation": "CREATE",
        "process_name": "winword.exe",
        "file_size": 12345,
        "event_type": "FILE_CREATE",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 1 - NORMAL FILE CREATION", test_1_event, file_filter)

    # =========================================================
    # TEST 2: Trusted File Operation
    # =========================================================
    test_2_event = {
        "file_path": "C:\\Users\\Public\\Documents\\report.txt",
        "file_name": "report.txt",
        "extension": ".txt",
        "operation": "MODIFY",
        "process_name": "notepad.exe",
        "file_size": 2048,
        "event_type": "FILE_MODIFY",
        "timestamp": datetime.now(timezone.utc)
    }

    run_test("TEST 2 - TRUSTED FILE OPERATION", test_2_event, file_filter)

    # =========================================================
    # TEST 3: Duplicate File Event
    # =========================================================
    test_3_event = {
        "file_path": "C:\\Users\\TestUser\\AppData\\Local\\MyApp\\cache.dat",
        "file_name": "cache.dat",
        "extension": ".dat", # Changed from .json to a non-whitelisted extension
        "operation": "MODIFY",
        "process_name": "myapp.exe", # Non-whitelisted process
        "file_size": 1024,
        "event_type": "FILE_MODIFY",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 3A - FIRST DUPLICATE FILE EVENT", test_3_event, file_filter)
    run_test("TEST 3B - SECOND DUPLICATE FILE EVENT", test_3_event, file_filter)

    # =========================================================
    # TEST 4: Suspicious File Operation
    # =========================================================
    test_4_event = {
        "file_path": "C:\\Users\\TestUser\\Downloads\\unverified_installer.exe",
        "file_name": "unverified_installer.exe",
        "extension": ".exe",
        "operation": "CREATE",
        "process_name": "chrome.exe",
        "file_size": 512000,
        "event_type": "FILE_CREATE",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 4 - SUSPICIOUS FILE OPERATION", test_4_event, file_filter)

    # =========================================================
    # TEST 5: Critical File Operation
    # =========================================================
    test_5_event = {
        "file_path": "C:\\Windows\\System32\\malicious.dll",
        "file_name": "malicious.dll",
        "extension": ".dll",
        "operation": "CREATE",
        "process_name": "powershell.exe",
        "file_size": 99999,
        "event_type": "FILE_CREATE",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 5 - CRITICAL FILE OPERATION", test_5_event, file_filter)

    # =========================================================
    # TEST 6: Invalid Event
    # =========================================================
    test_6_event = {}
    run_test("TEST 6 - INVALID EVENT (EMPTY DICT)", test_6_event, file_filter)

    print("=" * 70)
    print("ALL MANUAL FILE FILTER TESTS COMPLETED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()