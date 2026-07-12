import os
import sys
from datetime import datetime, timezone

try:
    PROJECT_ROOT = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
    sys.path.insert(0, PROJECT_ROOT)

    from engine.filter_engine import FilterEngine

except ImportError:
    print("Error: Unable to import FilterEngine.")
    sys.exit(1)


def print_result(test_num, test_name, result):
    print("======================================================================")
    print(f"TEST {test_num} - {test_name}")
    print("======================================================================")
    print()

    print(f"Accepted       : {getattr(result, 'accepted', False)}")
    print(f"Filtered       : {getattr(result, 'filtered', False)}")
    print(f"Reason         : {getattr(result, 'reason', 'No reason provided')}")
    print(f"Severity       : {getattr(result, 'severity', 'INFO')}")
    print(f"Confidence     : {getattr(result, 'confidence', 100.0)}")
    print(f"Duplicate      : {getattr(result, 'duplicate', False)}")
    print(f"Whitelisted    : {getattr(result, 'whitelisted', False)}")
    print(f"Suspicious     : {getattr(result, 'suspicious', False)}")
    print(f"Correlation ID : {getattr(result, 'correlation_id', '')}")
    print(f"Event Hash     : {getattr(result, 'event_hash', '')}")

    print()
    print("----------------------------------------------------------------------")
    print()


def run_manual_tests():
    print("Initializing FilterEngine...\n")

    engine = FilterEngine()

    # ==========================================================
    # TEST 1 - PROCESS EVENT
    # ==========================================================
    process_event = {
        "event_type": "PROCESS_CREATE",
        "pid": 1024,
        "process_name": "cmd.exe",
        "process_path": r"C:\Windows\System32\cmd.exe",
        "command_line": "cmd.exe /c echo test",
    }

    result = engine.filter_event(process_event)
    print_result("1", "PROCESS EVENT", result)

    # ==========================================================
    # TEST 2 - NETWORK EVENT
    # ==========================================================
    network_event = {
        "event_type": "NETWORK_CONNECT",
        "pid": 2048,
        "source_ip": "192.168.1.100",
        "destination_ip": "8.8.8.8",
        "source_port": 12345,
        "destination_port": 53,
        "protocol": "UDP",
        "direction": "OUTBOUND",
    }

    result = engine.filter_event(network_event)
    print_result("2", "NETWORK EVENT", result)

    # ==========================================================
    # TEST 3 - REGISTRY EVENT
    # ==========================================================
    registry_event = {
        "event_type": "REGISTRY_MODIFY",
        "pid": 3072,
        "registry_key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "hive": "HKLM",
        "operation": "MODIFY",
        "process_name": "regedit.exe",
        "value_name": "TestEntry",
        "value_data": r"C:\temp\malicious.exe",
    }

    result = engine.filter_event(registry_event)
    print_result("3", "REGISTRY EVENT", result)

    # ==========================================================
    # TEST 4 - FILE EVENT
    # ==========================================================
    file_event = {
        "event_type": "FILE_CREATE",
        "pid": 4096,
        "file_path": r"C:\Users\Public\Documents\test.txt",
        "file_name": "test.txt",
        "extension": ".txt",
        "operation": "CREATE",
        "process_name": "explorer.exe",
        "file_size": 2048,
        "timestamp": datetime.now(timezone.utc),
    }

    result = engine.filter_event(file_event)
    print_result("4", "FILE EVENT", result)

    # ==========================================================
    # TEST 5 - UNKNOWN EVENT
    # ==========================================================
    unknown_event = {
        "event_type": "UNKNOWN_EVENT",
        "pid": 5120,
        "data": "random data",
    }

    result = engine.filter_event(unknown_event)
    print_result("5", "UNKNOWN EVENT", result)

    # ==========================================================
    # TEST 6 - INVALID EVENT
    # ==========================================================
    invalid_event = {}

    result = engine.filter_event(invalid_event)
    print_result("6", "INVALID EVENT", result)

    # ==========================================================
    # TEST 7 - MIXED EVENT STREAM
    # ==========================================================
    print("======================================================================")
    print("TEST 7 - MIXED EVENT STREAM")
    print("======================================================================")
    print()

    mixed_events = [
        process_event,
        network_event,
        registry_event,
        file_event,
        process_event,
        {
            "event_type": "PROCESS_CREATE",
            "pid": 1234,
            "process_name": "explorer.exe",
            "process_path": r"C:\Windows\System32\explorer.exe",
        },
        {},
        {
            "event_type": "UNKNOWN_EVENT",
        },
    ]

    for index, event in enumerate(mixed_events, start=1):
        result = engine.filter_event(event)

        event_type = (
            event.get("event_type", "MISSING_TYPE")
            if isinstance(event, dict)
            else "INVALID_FORMAT"
        )

        print(
            f"Stream Event {index:<2} "
            f"[{event_type:<18}] "
            f"Accepted={getattr(result, 'accepted', False)} "
            f"Filtered={getattr(result, 'filtered', False)}"
        )

    print()
    print("----------------------------------------------------------------------")
    print()

    # ==========================================================
    # TEST 8 - ERROR HANDLING
    # ==========================================================
    engine.dispatch_table["CRASH_EVENT"] = "ForceAttributeErrorToTriggerException"

    crash_event = {
        "event_type": "CRASH_EVENT",
    }

    result = engine.filter_event(crash_event)
    print_result("8", "ERROR HANDLING", result)

    del engine.dispatch_table["CRASH_EVENT"]

    print("======================================================================")
    print("ALL FILTER ENGINE MANUAL TESTS COMPLETED")
    print("======================================================================")


if __name__ == "__main__":
    run_manual_tests()