import hashlib
import json
from pathlib import Path
from typing import Any, Dict

"""
Generates deterministic fingerprints for telemetry events.

Identical logical events always produce identical hashes,
regardless of dictionary ordering.
"""

class EventFingerprint:
    IGNORED_FIELDS = {
        "correlation_id",
        "timestamp",
        "confidence",
        "severity",
        "metadata"
    }

    @classmethod
    def generate_fingerprint(cls, event: Dict[str, Any]) -> str:
        if not isinstance(event, dict):
            return hashlib.sha256(b"").hexdigest()

        filtered_event = {
            k: v
            for k, v in event.items()
            if str(k).strip().lower() not in cls.IGNORED_FIELDS
        }

        normalized_event = cls._normalize_data(filtered_event)
        
        json_str = json.dumps(
            normalized_event, 
            sort_keys=True, 
            separators=(',', ':')
        )
        
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    @classmethod
    def _normalize_data(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                str(k).strip().lower(): cls._normalize_data(v)
                for k, v in data.items()
            }
        elif isinstance(data, set):
            return sorted(cls._normalize_data(item) for item in data)

        elif isinstance(data, (list, tuple)):
            return [cls._normalize_data(item) for item in data]
        elif isinstance(data, Path):
            return str(data).strip().lower()
        elif isinstance(data, str):
            return data.strip().lower()
        elif data is None:
            return None
        elif isinstance(data, (int, float, bool)):
            return data
        else:
            return str(data).strip().lower()