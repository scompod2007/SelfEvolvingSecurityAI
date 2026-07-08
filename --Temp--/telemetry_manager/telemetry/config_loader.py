"""
Configuration loader for the Telemetry Manager.

Reads config.json and merges it over a complete set of defaults.
Never raises on a missing or malformed config file -- a bad or
absent config should never prevent the telemetry layer from
starting, so problems are logged as warnings and repaired with
defaults instead.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    "process_monitor": True,
    "file_monitor": True,
    "registry_monitor": True,
    "network_monitor": True,

    "process_interval": 2,
    "network_interval": 1,
    "registry_interval": 2,
    "file_interval": 1,

    "health_check_interval": 5,

    # How often (seconds) cached statistics are refreshed from the
    # database in the background. Not part of the original spec's
    # example config.json, but required by the "statistics should
    # not query the database every second" constraint.
    "stats_refresh_interval": 10,

    # Passed through to FileMonitor's constructor. The current
    # FileMonitor implementation ignores this (it auto-discovers
    # every mounted drive) but the key is kept for forward
    # compatibility with a future revision that honors it.
    "file_watch_path": None,
}

# Keys that must be boolean feature switches.
_BOOL_KEYS = (
    "process_monitor",
    "file_monitor",
    "registry_monitor",
    "network_monitor",
)

# Keys that must be positive numbers (int or float).
_NUMERIC_KEYS = (
    "process_interval",
    "network_interval",
    "registry_interval",
    "file_interval",
    "health_check_interval",
    "stats_refresh_interval",
)


class ConfigLoader:
    """Loads and validates config.json for the Telemetry Manager."""

    def __init__(self, config_path: str = "config.json", logger: Optional[logging.Logger] = None):

        self.config_path = Path(config_path)

        self.logger = logger or logging.getLogger("telemetry_manager")

    def load(self) -> Dict[str, Any]:
        """
        Load configuration from disk, merge over defaults, validate
        types, and return a complete well-typed config dict. Always
        succeeds -- never raises.
        """

        config = dict(DEFAULT_CONFIG)

        raw = self._read_file()

        for key, value in raw.items():

            if key not in DEFAULT_CONFIG:

                self.logger.warning("Unknown config key '%s' ignored.", key)

                continue

            config[key] = value

        self._validate(config)

        return config

    def _read_file(self) -> Dict[str, Any]:

        if not self.config_path.exists():

            self.logger.warning(
                "Config file '%s' not found. Using default configuration.",
                self.config_path,
            )

            return {}

        try:

            with self.config_path.open("r", encoding="utf-8") as handle:

                data = json.load(handle)

        except (json.JSONDecodeError, OSError) as e:

            self.logger.warning(
                "Failed to read config file '%s' (%s). Using default configuration.",
                self.config_path, e,
            )

            return {}

        if not isinstance(data, dict):

            self.logger.warning(
                "Config file '%s' does not contain a JSON object. Using default configuration.",
                self.config_path,
            )

            return {}

        return data

    def _validate(self, config: Dict[str, Any]) -> None:
        """Coerce/repair invalid values in-place, logging each repair."""

        for key in _BOOL_KEYS:

            if not isinstance(config.get(key), bool):

                self.logger.warning(
                    "Config key '%s' must be a boolean, got %r. Defaulting to %r.",
                    key, config.get(key), DEFAULT_CONFIG[key],
                )

                config[key] = DEFAULT_CONFIG[key]

        for key in _NUMERIC_KEYS:

            value = config.get(key)

            invalid = (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value <= 0
            )

            if invalid:

                self.logger.warning(
                    "Config key '%s' must be a positive number, got %r. Defaulting to %r.",
                    key, value, DEFAULT_CONFIG[key],
                )

                config[key] = DEFAULT_CONFIG[key]
