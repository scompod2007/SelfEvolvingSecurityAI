import os
import sys
import unittest
from datetime import datetime
from pathlib import Path

# Ensure the project root is in the path for correct module resolution
sys.path.insert(0, os.path.abspath('.'))

# Conditional import guard for robustness
try:
    from filters.filters import FilterEngine, FileFilter, _duplicate_cache, FilterStatistics
    from filters.filter_config import FILTER_CONFIG
    from filters.filter_rules import reset_statistics, RULE_STATISTICS
except ImportError as e:
    print(f"Critical Import Error: {e}", file=sys.stderr)
    print("Please ensure the project files are in the 'filters/' directory and the test is run from the project root.", file=sys.stderr)
    sys.exit(1)

# ============================================================
# PRODUCTION-QUALITY TEST SUITE
# ============================================================

class TestFileFilter(unittest.TestCase):
    """
    Verifies the complete functionality of the FileFilter class.
    Each test corresponds to a specific requirement.
    """

    def setUp(self):
        """
        This method runs before each test, ensuring a clean state.
        It resets all caches, statistics, and configurations.
        """
        # Reset global state from other modules
        _duplicate_cache.clear()
        reset_statistics()

        # Create a fresh engine with clean statistics for each test
        engine = FilterEngine()
        engine.statistics = FilterStatistics()

        # Reset configuration to a known default state
        default_config = FILTER_CONFIG.__class__()
        for key in FILTER_CONFIG.__annotations__:
            setattr(FILTER_CONFIG, key, getattr(default_config, key))
        
        # Explicitly enable all features under test
        FILTER_CONFIG.ENABLE_FILTERS = True
        FILTER_CONFIG.ENABLE_WHITELIST = True
        FILTER_CONFIG.ENABLE_DUPLICATE_FILTER = True
        FILTER_CONFIG.ENABLE_STATISTICS = True
        FILTER_CONFIG.ENABLE_SEVERITY_ENGINE = True
        FILTER_CONFIG.ENABLE_CONFIDENCE_ENGINE = True
        FILTER_CONFIG.ENABLE_CORRELATION_ID = True

        self.file_filter = FileFilter(engine)

    # 1. Test Valid Event
    def test_valid_file_event(self):
        event = {"file_path": r"C:\Users\test\document.txt", "event_type": "FILE_READ"}
        result = self.file_filter.filter_event(event)
        self.assertTrue(result.accepted)
        self.assertFalse(result.filtered)
        self.assertEqual(result.reason, "Accepted")

    # 2. Test Invalid Event
    def test_invalid_event_object(self):
        result = self.file_filter.filter_event("this is not a dictionary")
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "Invalid event object")

    # 3. Test Missing Fields
    def test_missing_required_field(self):
        result = self.file_filter.filter_event({"event_type": "FILE_DELETE"})
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "Missing required field: file_path")

    # 4. Test Ignored Path
    def test_ignored_path(self):
        event = {"file_path": r"C:\Windows\Temp\somefile.log", "event_type": "FILE_CREATE"}
        result = self.file_filter.filter_event(event)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "Ignored path")

    # 5. Test Ignored Filename
    def test_ignored_filename(self):
        event = {"file_path": r"C:\data\Thumbs.db", "event_type": "FILE_CREATE"}
        result = self.file_filter.filter_event(event)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "Ignored file")

    # 6. Test Ignored Extension
    def test_ignored_extension(self):
        event = {"file_path": r"C:\data\backup.tmp", "event_type": "FILE_CREATE", "extension": ".tmp"}
        result = self.file_filter.filter_event(event)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "Ignored extension")

    # 7. Test Dangerous Extension Override
    def test_dangerous_extension_override(self):
        event = {"file_path": r"C:\Windows\Temp\malicious.exe", "event_type": "FILE_CREATE", "extension": ".exe"}
        result = self.file_filter.filter_event(event)
        self.assertTrue(result.accepted, "Dangerous extension should override ignore rules")
        self.assertTrue(result.suspicious)
        self.assertEqual(result.severity, "HIGH")

    # 8. Test Whitelisted Process
    def test_whitelisted_process(self):
        event = {"file_path": r"C:\data\config.xml", "event_type": "FILE_READ", "process_name": "svchost.exe"}
        result = self.file_filter.filter_event(event)
        self.assertFalse(result.accepted)
        self.assertTrue(result.whitelisted)
        self.assertEqual(result.reason, "Whitelisted process")

    # 9. Test Whitelisted Folder
    def test_whitelisted_folder(self):
        event = {"file_path": r"C:\Windows\System32\drivers\etc\hosts", "event_type": "FILE_READ"}
        result = self.file_filter.filter_event(event)
        self.assertFalse(result.accepted)
        self.assertTrue(result.whitelisted)
        self.assertEqual(result.reason, "Whitelisted folder")

    # 10. Test Whitelisted Publisher
    def test_whitelisted_publisher(self):
        event = {"file_path": r"C:\tools\vscode.exe", "event_type": "FILE_READ", "publisher": "Microsoft Corporation"}
        result = self.file_filter.filter_event(event)
        self.assertFalse(result.accepted)
        self.assertTrue(result.whitelisted)
        self.assertEqual(result.reason, "Whitelisted publisher")

    # 11. Test Duplicate Detection
    def test_duplicate_detection(self):
        event = {"file_path": r"C:\logs\app.log", "event_type": "FILE_WRITE", "process_name": "app.exe"}
        result1 = self.file_filter.filter_event(event)
        self.assertTrue(result1.accepted, "First event should be accepted")
        result2 = self.file_filter.filter_event(event)
        self.assertFalse(result2.accepted, "Second event should be filtered as a duplicate")
        self.assertTrue(result2.duplicate)
        self.assertEqual(result2.reason, "Duplicate event")

    # 12. Test Severity Calculation
    def test_severity_calculation(self):
        event_crit = {"file_path": r"C:\Windows\System32\k32.dll", "event_type": "FILE_DELETE", "extension": ".dll"}
        self.assertEqual(self.file_filter.filter_event(event_crit).severity, "CRITICAL")
        event_high = {"file_path": r"C:\downloads\p.exe", "event_type": "FILE_CREATE", "extension": ".exe"}
        self.assertEqual(self.file_filter.filter_event(event_high).severity, "HIGH")
        event_med = {"file_path": r"C:\docs\doc.txt.old", "event_type": "FILE_RENAME"}
        self.assertEqual(self.file_filter.filter_event(event_med).severity, "MEDIUM")
        event_info = {"file_path": r"C:\docs\data.csv", "event_type": "FILE_READ"}
        self.assertEqual(self.file_filter.filter_event(event_info).severity, "INFO")

    # 13. Test Confidence Calculation
    def test_confidence_calculation(self):
        event_base = {"file_path": r"C:\s.py", "event_type": "READ", "process_path": r"C:\temp\p.exe"}
        self.assertEqual(self.file_filter.filter_event(event_base).confidence, 100.0)
        event_system = {**event_base, "user": "SYSTEM"}
        self.assertEqual(self.file_filter.filter_event(event_system).confidence, 90.0)
        event_trusted_path = {**event_base, "process_path": r"C:\Program Files\App\app.exe"}
        self.assertEqual(self.file_filter.filter_event(event_trusted_path).confidence, 80.0)
        event_crit = {"file_path": r"C:\Windows\System32\k32.dll", "event_type": "FILE_DELETE", "extension": ".dll"}
        self.assertEqual(self.file_filter.filter_event(event_crit).confidence, 100.0)

    # 14. Test Correlation ID Generation
    def test_correlation_id_generation(self):
        event = {"file_path": "a.txt", "event_type": "READ"}
        FILTER_CONFIG.ENABLE_CORRELATION_ID = True
        self.assertTrue(self.file_filter.filter_event(event).correlation_id.startswith("CID-"))
        FILTER_CONFIG.ENABLE_CORRELATION_ID = False
        self.assertEqual(self.file_filter.filter_event(event).correlation_id, "")

    # 15. Test Statistics Updates
    def test_statistics_updates(self):
        stats = self.file_filter.engine.statistics
        self.file_filter.filter_event({"file_path": "accepted.txt", "event_type": "READ"})
        self.assertEqual(stats.files_stored, 1, "Accepted event should increment files_stored")
        self.file_filter.filter_event({"file_path": r"C:\Windows\Temp\ignored.tmp", "event_type": "WRITE"})
        self.assertEqual(stats.files_filtered, 1, "Ignored event should increment files_filtered")
        self.assertEqual(stats.ignored_events, 1, "Ignored event should increment ignored_events")
        self.file_filter.filter_event({"file_path": "whitelisted.txt", "event_type": "READ", "process_name": "explorer.exe"})
        self.assertEqual(stats.files_filtered, 2, "Whitelisted event should increment files_filtered")
        event_dupe = {"file_path": "duplicate.txt", "event_type": "READ"}
        self.file_filter.filter_event(event_dupe) # Stored
        self.file_filter.filter_event(event_dupe) # Filtered
        self.assertEqual(stats.files_filtered, 3, "Duplicate event should increment files_filtered")
        self.assertEqual(stats.duplicates_removed, 1, "Duplicate event should increment duplicates_removed")
        self.assertEqual(stats.total_events, 5, "Total events should reflect all processed events")

    # 16. Test Final FilterResult Values
    def test_final_filter_result_values(self):
        event = {"file_path": r"C:\Windows\Temp\payload.exe", "event_type": "FILE_CREATE", "extension": ".exe"}
        result = self.file_filter.filter_event(event)
        self.assertTrue(result.accepted)
        self.assertEqual(result.severity, "HIGH")
        self.assertTrue(result.correlation_id.startswith("CID-"))
        self.assertEqual(len(result.event_hash), 64)
        self.assertIsInstance(result.timestamp, datetime)

if __name__ == '__main__':
    # This allows the test to be run directly
    unittest.main()