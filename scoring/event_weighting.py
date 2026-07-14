"""
============================================================
Self-Evolving Security AI
Part 2.8.3 - Event Weighting
============================================================

This module is responsible for assigning a base risk weight 
depending on the telemetry event type. It is completely 
independent of heuristic risk scoring and severity assignment.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Any


class EventType(Enum):
    """
    Enumeration of supported telemetry event types.
    """
    PROCESS = auto()
    FILE = auto()
    NETWORK = auto()
    REGISTRY = auto()
    UNKNOWN = auto()


@dataclass(slots=True, frozen=True)
class EventWeights:
    """
    Configuration for base event weights.
    Provides the default weight values for each event category.
    """
    process: float = 15.0
    file: float = 10.0
    network: float = 12.0
    registry: float = 18.0
    unknown: float = 5.0


@dataclass(slots=True)
class EventWeightResult:
    """
    Represents the result of an event weighting evaluation.
    Contains the assigned weight, detected type, and the reasoning.
    """
    weight: float
    event_type: EventType
    reason: str


class EventWeightEngine:
    """
    Engine responsible for detecting event types from telemetry data
    and assigning the appropriate base risk weights.
    
    This class is entirely stateless and thread-safe.
    """

    def __init__(self, weights: EventWeights | None = None) -> None:
        """
        Initializes the EventWeightEngine.

        Args:
            weights (EventWeights | None): Custom weights configuration.
                                           Defaults to standard EventWeights.
        """
        self.weights = weights or EventWeights()

    def _detect_type(self, event: dict[str, Any]) -> EventType:
        """
        Infers the event type based on the presence of specific keys 
        or explicit event_type declarations in the dictionary.

        Args:
            event (dict[str, Any]): The telemetry event.

        Returns:
            EventType: The detected event type, or UNKNOWN if no match is found.
        """
        # First, check explicit event_type string if present
        event_type_str = str(event.get("event_type", "")).upper()
        if "NETWORK" in event_type_str:
            return EventType.NETWORK
        if "REGISTRY" in event_type_str:
            return EventType.REGISTRY
        if "FILE" in event_type_str:
            return EventType.FILE
        if "PROCESS" in event_type_str:
            return EventType.PROCESS

        # Fallback to key-based heuristic detection
        keys = event.keys()

        if "destination_ip" in keys or "source_ip" in keys or "port" in keys or "protocol" in keys:
            return EventType.NETWORK

        if "registry_key" in keys or "registry_path" in keys or "registry_value" in keys:
            return EventType.REGISTRY

        if "file_path" in keys or "extension" in keys or "operation" in keys:
            return EventType.FILE

        if "command_line" in keys or ("process_name" in keys and "pid" in keys):
            return EventType.PROCESS

        return EventType.UNKNOWN

    def evaluate(self, event: Any) -> EventWeightResult:
        """
        Evaluates a telemetry event to assign its base risk weight.

        Validates the input, detects the event type, and returns the 
        corresponding weight result. Never raises an exception on bad input.

        Args:
            event (Any): The telemetry event to evaluate.

        Returns:
            EventWeightResult: The assigned weight, detected type, and reason.
        """
        # Validate event is a non-empty dictionary
        if not isinstance(event, dict) or not event:
            return EventWeightResult(
                weight=self.weights.unknown,
                event_type=EventType.UNKNOWN,
                reason="Invalid, empty, or missing event data."
            )

        detected_type = self._detect_type(event)

        if detected_type == EventType.PROCESS:
            return EventWeightResult(
                weight=self.weights.process,
                event_type=EventType.PROCESS,
                reason="Event detected as a Process event based on fields."
            )
        elif detected_type == EventType.FILE:
            return EventWeightResult(
                weight=self.weights.file,
                event_type=EventType.FILE,
                reason="Event detected as a File event based on fields."
            )
        elif detected_type == EventType.NETWORK:
            return EventWeightResult(
                weight=self.weights.network,
                event_type=EventType.NETWORK,
                reason="Event detected as a Network event based on fields."
            )
        elif detected_type == EventType.REGISTRY:
            return EventWeightResult(
                weight=self.weights.registry,
                event_type=EventType.REGISTRY,
                reason="Event detected as a Registry event based on fields."
            )
        else:
            return EventWeightResult(
                weight=self.weights.unknown,
                event_type=EventType.UNKNOWN,
                reason="Event fields do not match any known category."
            )


def combine_weight(base_risk: float, event_weight: float) -> float:
    """
    Combines a base risk score with an assigned event weight.
    
    This function strictly adds the values and does not perform normalization 
    or severity assignment.

    Args:
        base_risk (float): The previously calculated base risk score.
        event_weight (float): The weight assigned to the event type.

    Returns:
        float: The combined total risk value.
    """
    return base_risk + event_weight