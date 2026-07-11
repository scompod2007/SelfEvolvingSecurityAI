import os
import sys
from datetime import datetime, timezone

# Add the project root to the Python path to allow importing from 'filters'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from filters.filters import FilterEngine, NetworkFilter
except ImportError:
    print("Error: Could not import FilterEngine or NetworkFilter.")
    print("Please ensure this script is run from the project's root directory,")
    print("and that the project structure (filters/__init__.py) is correct.")
    sys.exit(1)


def run_test(title: str, event: dict, network_filter: NetworkFilter):
    """
    Runs a single test case and prints the formatted result.
    """
    print("=" * 70)
    print(title.upper())
    print("=" * 70)

    result = network_filter.filter_event(event)

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
    print("MANUAL NETWORK FILTER VERIFICATION SCRIPT")
    print("=" * 70 + "\n")

    engine = FilterEngine()
    network_filter = NetworkFilter(engine)

    # =========================================================
    # TEST 1: Normal Connection
    # =========================================================
    test_1_event = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 50500,
        "destination_port": 50000,  # Changed from 443 to a non-whitelisted port
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "event_type": "NETWORK_CONNECT",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 1 - NORMAL CONNECTION", test_1_event, network_filter)

    # =========================================================
    # TEST 2: Trusted Connection (Internal Loopback)
    # =========================================================
    test_2_event = {
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "source_port": 51000,
        "destination_port": 8080,
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "event_type": "NETWORK_CONNECT",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 2 - TRUSTED CONNECTION", test_2_event, network_filter)

    # =========================================================
    # TEST 3: Duplicate Connection
    # =========================================================
    test_3_event = {
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.1",
        "source_port": 52000,
        "destination_port": 50001,  # Changed from 445 to a non-whitelisted port
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "event_type": "NETWORK_CONNECT",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 3A - FIRST DUPLICATE CONNECTION", test_3_event, network_filter)
    run_test("TEST 3B - SECOND DUPLICATE CONNECTION", test_3_event, network_filter)

    # =========================================================
    # TEST 4: Suspicious Connection (Risky Protocol to External IP)
    # =========================================================
    test_4_event = {
        "source_ip": "192.168.1.20",
        "destination_ip": "45.33.32.156",  # Changed to a public IP to avoid ignore rule
        "source_port": 53000,
        "destination_port": 23,
        "protocol": "TELNET",
        "direction": "OUTBOUND",
        "event_type": "NETWORK_CONNECT",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 4 - SUSPICIOUS CONNECTION", test_4_event, network_filter)

    # =========================================================
    # TEST 5: Critical Connection (Outbound RDP)
    # =========================================================
    test_5_event = {
        "source_ip": "192.168.1.30",
        "destination_ip": "1.2.3.4", # Public IP
        "source_port": 54000,
        "destination_port": 3389, # RDP Port
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "event_type": "NETWORK_CONNECT",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 5 - CRITICAL CONNECTION", test_5_event, network_filter)

    # =========================================================
    # TEST 6: Invalid Event
    # =========================================================
    test_6_event = {}
    run_test("TEST 6 - INVALID EVENT (EMPTY DICT)", test_6_event, network_filter)
    print("===========================++++++++++++++++++++++++___---________")
    # =========================================================
    # TEST 3: Duplicate Connection
    # =========================================================
    test_3_event = {
        "source_ip": "192.168.1.10",
        "destination_ip": "45.33.32.156",  # Public IP to avoid internal ignore rule
        "source_port": 52000,
        "destination_port": 50001,
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "event_type": "NETWORK_CONNECT",
        "timestamp": datetime.now(timezone.utc)
    }
    run_test("TEST 3A - FIRST DUPLICATE CONNECTION", test_3_event, network_filter)
    run_test("TEST 3B - SECOND DUPLICATE CONNECTION", test_3_event, network_filter)
    print("donnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnneeeeeeeeeeeeeeeeeeeeeeeee")
    print("=" * 70)
    print("ALL MANUAL NETWORK FILTER TESTS COMPLETED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()