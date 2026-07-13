import sys
import os
import time
from datetime import datetime, timezone
import random

# Add project root to path so we can import 'filters' when running from 'tests' folder
try:
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, PROJECT_ROOT)

    from filters.filter_config import FILTER_CONFIG
    from filters.event_fingerprint import EventFingerprint
    from filters.duplicate_cache import DuplicateCache
    from filters.duplicate_detector import DuplicateDetector
except ImportError as e:
    print(f"Error: Unable to import required modules. {e}")
    print("Ensure you are running this from the project root or tests/ directory.")
    sys.exit(1)


def print_header(text: str) -> None:
    """Print a formatted header for each test section."""
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def print_test_result(test_name: str, passed: bool, details: str = "") -> None:
    """Print a standardized PASS/FAIL result."""
    status = "PASS" if passed else "FAIL"
    print(f"\n[{status}] {test_name}")
    if details:
        print(f"       {details}")


def run_manual_tests() -> None:
    """Run all manual tests for the Duplicate Engine."""
    print_header("Initializing Duplicate Engine Manual Tests")
    
    # Initialize the detector and track overall script execution time
    detector = DuplicateDetector(config=FILTER_CONFIG)
    detector.reset_statistics()
    start_time_total = time.perf_counter()

    # Base event for testing
    event_base = {
        "event_type": "PROCESS_CREATE",
        "pid": 1024,
        "process_name": "cmd.exe",
        "process_path": r"C:\Windows\System32\cmd.exe",
        "command_line": "cmd.exe /c echo test",
        "timestamp": datetime.now(timezone.utc), # Runtime field, should be ignored by hashing
        "correlation_id": "CID-12345"
    }

    # ==========================================================
    # TEST 1 - First Event
    # ==========================================================
    print_header("TEST 1 - First Event")
    decision1 = detector.check(event_base)
    
    # Verification
    passed_1 = (decision1.is_duplicate is False) and (decision1.duplicate_count == 1)
    
    print(f"Fingerprint    : {decision1.fingerprint}")
    print(f"Is Duplicate   : {decision1.is_duplicate}")
    print(f"Reason         : {decision1.reason}")
    print(f"Duplicate Count: {decision1.duplicate_count}")
    
    print_test_result("Test 1: New event identified correctly", passed_1)


    # ==========================================================
    # TEST 2 - Exact Duplicate
    # ==========================================================
    print_header("TEST 2 - Exact Duplicate")
    
    # Send the exact same event
    decision2 = detector.check(event_base)
    
    # Verification
    passed_2 = (decision2.is_duplicate is True) and (decision2.duplicate_count == 2)
    
    print(f"Fingerprint    : {decision2.fingerprint}")
    print(f"Is Duplicate   : {decision2.is_duplicate}")
    print(f"Reason         : {decision2.reason}")
    print(f"Duplicate Count: {decision2.duplicate_count}")
    
    print_test_result("Test 2: Exact duplicate identified correctly", passed_2)


    # ==========================================================
    # TEST 3 - Different Event
    # ==========================================================
    print_header("TEST 3 - Different Event")
    
    # Change a stable field
    event_diff = event_base.copy()
    event_diff["pid"] = 2048 
    
    decision3 = detector.check(event_diff)
    
    # Verification
    passed_3 = (decision3.is_duplicate is False) and (decision3.duplicate_count == 1)
    passed_3_fp = decision3.fingerprint != decision1.fingerprint
    
    print(f"Fingerprint    : {decision3.fingerprint}")
    print(f"Is Duplicate   : {decision3.is_duplicate}")
    print(f"Reason         : {decision3.reason}")
    print(f"Duplicate Count: {decision3.duplicate_count}")
    
    print_test_result("Test 3: Different event identified correctly", passed_3 and passed_3_fp)


    # ==========================================================
    # TEST 4 - Expired Duplicate
    # ==========================================================
    print_header("TEST 4 - Expired Duplicate")
    
    # Store original TTL to restore it later
    original_ttl = getattr(detector.config, "DUPLICATE_TTL_SECONDS", 60)
    
    # Temporarily force expiration
    detector.config.DUPLICATE_TTL_SECONDS = 1
    
    print("Waiting 1.1 seconds for cache entry to expire...")
    time.sleep(1.1)
    
    # Explicitly call cleanup to enforce expiration immediately
    expired_removed, _ = detector.cache.cleanup()
    print(f"Manual cleanup expired entries removed: {expired_removed}")
    
    # Send the base event again
    decision4 = detector.check(event_base)
    
    # Verification: should be treated as a new event because it expired
    passed_4 = (decision4.is_duplicate is False) and (decision4.duplicate_count == 1)
    
    print(f"Fingerprint    : {decision4.fingerprint}")
    print(f"Is Duplicate   : {decision4.is_duplicate}")
    print(f"Reason         : {decision4.reason}")
    print(f"Duplicate Count: {decision4.duplicate_count}")
    
    print_test_result("Test 4: Expired event treated as new", passed_4)
    
    # Restore original TTL
    detector.config.DUPLICATE_TTL_SECONDS = original_ttl


    # ==========================================================
    # TEST 5 - Cache Cleanup
    # ==========================================================
    print_header("TEST 5 - Cache Cleanup")
    
    # Store original max size configs
    original_max = getattr(detector.config, "MAX_EVENT_CACHE", None)
    original_dup_max = getattr(detector.config, "MAX_DUPLICATE_CACHE_SIZE", None)
    
    # Force a very small cache size limit
    detector.config.MAX_EVENT_CACHE = 5
    detector.config.MAX_DUPLICATE_CACHE_SIZE = 5
    
    # Insert multiple distinct events to trigger cache overflow
    for i in range(10):
        evt = event_base.copy()
        evt["pid"] = 3000 + i
        detector.check(evt)
        
    # Call cleanup
    expired, overflow = detector.cache.cleanup()
    usage = detector.cache.cache_usage()
    
    # Verification
    passed_5 = (usage["entries"] <= 5) and (overflow > 0)
    
    print(f"Expired entries removed : {expired}")
    print(f"Overflow entries removed: {overflow}")
    print(f"Current cache size      : {usage['entries']}")
    print(f"Cache usage percent     : {usage['usage_percent']}%")
    
    print_test_result("Test 5: Cache overflow cleanup successful", passed_5)
    
    # Restore configs
    if original_max is not None:
        detector.config.MAX_EVENT_CACHE = original_max
    if original_dup_max is not None:
        detector.config.MAX_DUPLICATE_CACHE_SIZE = original_dup_max


    # ==========================================================
    # TEST 6 - Stress Test
    # ==========================================================
    print_header("TEST 6 - Stress Test")
    print("Generating 1,000 mixed events (unique and duplicates)...")
    
    stress_events = []
    # Generate 500 unique events and 500 exact duplicates of those
    for i in range(500):
        evt = {
            "event_type": "NETWORK_CONNECT",
            "source_ip": f"192.168.1.{i % 254 + 1}",
            "destination_port": random.randint(1024, 65535),
            "protocol": "TCP"
        }
        stress_events.append(evt)      # Unique insertion
        stress_events.append(evt)      # Duplicate insertion
        
    # Shuffle so duplicates don't always appear immediately after originals
    random.shuffle(stress_events)
    
    start_stress = time.perf_counter()
    
    for evt in stress_events:
        detector.check(evt)
        
    end_stress = time.perf_counter()
    stress_duration = end_stress - start_stress
    
    stress_stats = detector.get_statistics()
    
    print(f"Total events           : 1000")
    print(f"Unique events          : {stress_stats['total_unique']}")
    print(f"Duplicates             : {stress_stats['total_duplicates']}")
    print(f"Duplicate Rate         : {stress_stats['duplicate_rate']}%")
    print(f"Cache Hit Ratio        : {stress_stats['cache_hit_ratio']}%")
    print(f"Final Cache Size       : {detector.cache.size()}")
    print(f"Execution Time         : {stress_duration:.4f} seconds")
    
    passed_6 = (stress_stats['total_events'] >= 1000)
    print_test_result("Test 6: Stress test completed efficiently", passed_6)


    # ==========================================================
    # SUMMARY
    # ==========================================================
    total_execution_time = time.perf_counter() - start_time_total
    final_stats = detector.get_statistics()
    
    print("\n==============================")
    print("DUPLICATE ENGINE TEST SUMMARY")
    print("==============================")
    print(f"Total Events: {final_stats['total_events']}")
    print(f"Total Duplicates: {final_stats['total_duplicates']}")
    print(f"Duplicate Rate: {final_stats['duplicate_rate']}%")
    print(f"Cache Hit Ratio: {final_stats['cache_hit_ratio']}%")
    print(f"Final Cache Size: {detector.cache.size()}")
    print(f"Execution Time: {total_execution_time:.4f} seconds")
    print("==============================\n")


if __name__ == "__main__":
    run_manual_tests()