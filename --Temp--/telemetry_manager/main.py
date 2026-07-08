"""
Entry point for the Self-Evolving Security AI Telemetry Manager.

Usage
-----
    python main.py [--config CONFIG_PATH] [--log-dir LOG_DIR]

Run this from the project root (the directory containing
collectors/, database/, and telemetry/) so the relative imports in
telemetry/telemetry_manager.py resolve correctly.
"""

import argparse

from telemetry.telemetry_manager import TelemetryManager


def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(description="Self-Evolving Security AI - Telemetry Manager")

    parser.add_argument(
        "--config", default="config.json",
        help="Path to config.json (default: ./config.json)",
    )

    parser.add_argument(
        "--log-dir", default="logs",
        help="Directory for telemetry_manager.log (default: ./logs)",
    )

    return parser.parse_args()


def main() -> None:

    args = parse_args()

    manager = TelemetryManager(config_path=args.config, log_dir=args.log_dir)

    manager.run()


if __name__ == "__main__":

    main()
