"""
Central logging setup for the Telemetry Manager.

Every orchestration-level event (startup, shutdown, collector
started/stopped/restarted, errors, health checks) is logged through
the shared "telemetry_manager" logger to both logs/telemetry_manager.log
and the console. Collectors themselves are untouched and keep using
their own print() statements -- this logger is purely for the
manager layer.
"""

import logging
from pathlib import Path


LOGGER_NAME = "telemetry_manager"


def setup_logger(
    log_dir: str = "logs",
    log_file: str = "telemetry_manager.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Create (or return, if already configured) the shared Telemetry
    Manager logger, writing to logs/telemetry_manager.log and stdout.
    """

    logger = logging.getLogger(LOGGER_NAME)

    if logger.handlers:

        # Already configured -- avoid attaching duplicate handlers
        # if setup_logger() is called more than once.

        return logger

    logger.setLevel(level)

    Path(log_dir).mkdir(parents=True, exist_ok=True)

    log_path = Path(log_dir) / log_file

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")

    file_handler.setFormatter(formatter)

    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()

    console_handler.setFormatter(formatter)

    console_handler.setLevel(level)

    logger.addHandler(file_handler)

    logger.addHandler(console_handler)

    logger.propagate = False

    return logger
