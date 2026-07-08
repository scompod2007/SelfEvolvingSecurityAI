"""
============================================================
Self-Evolving Security AI
Filter Configuration
Version: 1.0
============================================================

Purpose
-------
Central configuration for the entire filtering system.

NO filtering logic belongs here.

This file only contains:

    • Feature switches
    • Thresholds
    • Performance options
    • Debug options
    • Future AI options

Every module imports settings from here.

Example

from filters.filter_config import FILTER_CONFIG

if FILTER_CONFIG.ENABLE_FILE_FILTER:
    ...

============================================================
"""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class FilterConfig:
    """
    Global Filter Configuration
    """

    # ========================================================
    # MASTER SWITCHES
    # ========================================================

    ENABLE_FILTERS: bool = True

    ENABLE_FILE_FILTER: bool = True
    ENABLE_PROCESS_FILTER: bool = True
    ENABLE_NETWORK_FILTER: bool = True
    ENABLE_REGISTRY_FILTER: bool = True

    ENABLE_WHITELIST: bool = True

    ENABLE_DUPLICATE_FILTER: bool = True

    ENABLE_STATISTICS: bool = True

    ENABLE_SEVERITY_ENGINE: bool = True

    ENABLE_CONFIDENCE_ENGINE: bool = True

    ENABLE_CORRELATION_ENGINE: bool = True

    # ========================================================
    # PERFORMANCE
    # ========================================================

    MAX_EVENT_CACHE: int = 10000

    DUPLICATE_WINDOW_SECONDS: int = 2

    BURST_THRESHOLD: int = 50

    CACHE_CLEANUP_INTERVAL: int = 60

    # ========================================================
    # LOGGING
    # ========================================================

    ENABLE_LOGGING: bool = True

    LOG_IGNORED_EVENTS: bool = False

    LOG_DUPLICATES: bool = False

    LOG_PERFORMANCE: bool = False

    LOG_FILTER_DECISIONS: bool = False

    # ========================================================
    # DEBUG
    # ========================================================

    DEBUG_MODE: bool = False

    VERBOSE: bool = False

    PRINT_FILTER_REASON: bool = False

    # ========================================================
    # AI PREPARATION
    # ========================================================

    ENABLE_AI_METADATA: bool = True

    ENABLE_EVENT_TAGS: bool = True

    ENABLE_EVENT_HASH: bool = True

    ENABLE_CORRELATION_ID: bool = True

    ENABLE_CONFIDENCE_SCORE: bool = True

    ENABLE_SEVERITY_SCORE: bool = True

    # ========================================================
    # FUTURE SUPPORT
    # ========================================================

    ENABLE_JSON_RULES: bool = False

    ENABLE_YAML_RULES: bool = False

    JSON_RULE_PATH: Path = Path("filters/rules.json")

    YAML_RULE_PATH: Path = Path("filters/rules.yaml")

    AUTO_RELOAD_RULES: bool = False

    RULE_RELOAD_INTERVAL: int = 30

    # ========================================================
    # FILTER BEHAVIOUR
    # ========================================================

    IGNORE_LOOPBACK: bool = True

    IGNORE_DUPLICATES: bool = True

    IGNORE_TEMP_FILES: bool = True

    IGNORE_CACHE_FILES: bool = True

    IGNORE_TIME_WAIT: bool = True

    # Never ignore executable content
    NEVER_IGNORE_EXECUTABLES: bool = True

    NEVER_IGNORE_SCRIPTS: bool = True

    NEVER_IGNORE_DRIVERS: bool = True

    NEVER_IGNORE_DLLS: bool = True

    # ========================================================
    # FUTURE MACHINE LEARNING
    # ========================================================

    ENABLE_DYNAMIC_FILTERS: bool = False

    ENABLE_LEARNING_MODE: bool = False

    ENABLE_AUTO_WHITELIST: bool = False

    ENABLE_REPUTATION_ENGINE: bool = False

    # ========================================================
    # RESERVED
    # ========================================================

    RESERVED: dict = field(default_factory=dict)


# ============================================================
# GLOBAL INSTANCE
# ============================================================

FILTER_CONFIG = FilterConfig()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_filter_enabled(name: str) -> bool:
    """
    Check whether a feature is enabled.

    Example
    -------
    if is_filter_enabled("ENABLE_FILE_FILTER"):
        ...
    """

    return getattr(FILTER_CONFIG, name, False)


def enable(name: str):
    """
    Enable a configuration option.
    """

    if hasattr(FILTER_CONFIG, name):
        setattr(FILTER_CONFIG, name, True)


def disable(name: str):
    """
    Disable a configuration option.
    """

    if hasattr(FILTER_CONFIG, name):
        setattr(FILTER_CONFIG, name, False)


def toggle(name: str):
    """
    Toggle a configuration option.
    """

    if hasattr(FILTER_CONFIG, name):
        current = getattr(FILTER_CONFIG, name)
        setattr(FILTER_CONFIG, name, not current)


def print_configuration():
    """
    Pretty-print current configuration.
    """

    print("\n========== FILTER CONFIGURATION ==========\n")

    for key, value in vars(FILTER_CONFIG).items():
        print(f"{key:<35} : {value}")

    print("\n==========================================\n")


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    print_configuration()