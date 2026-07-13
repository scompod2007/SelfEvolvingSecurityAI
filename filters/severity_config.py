from dataclasses import dataclass, field
from enum import IntEnum


class SeverityLevel(IntEnum):
    """
    Enumeration of standard severity levels.
    Implemented as an IntEnum to allow easy comparative logic (e.g., CRITICAL > HIGH).
    """
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    def __str__(self) -> str:
        return self.name


@dataclass(slots=True, frozen=True)
class SeverityThresholds:
    """
    Defines the minimum normalized risk score (0-100) required to achieve each severity level.
    This class is frozen to guarantee thread safety across the engine.
    """
    info: int = 0
    low: int = 20
    medium: int = 40
    high: int = 70
    critical: int = 90


@dataclass(slots=True)
class SeverityConfig:
    """
    Configuration for the Severity Engine.
    Controls whether the engine is enabled and defines the scoring thresholds.
    """
    enable_severity_engine: bool = True
    thresholds: SeverityThresholds = field(default_factory=SeverityThresholds)
    
    # The absolute maximum score a raw event could theoretically reach 
    # before being normalized down to the 0-100 scale.
    max_raw_score: float = 100.0


# Global instance to be imported by the Severity Engine and other modules
SEVERITY_CONFIG = SeverityConfig()