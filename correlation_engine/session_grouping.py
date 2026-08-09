"""
============================================================
Self-Evolving Security AI
Part 2.10.3 - Session Grouping Engine
============================================================

This module groups telemetry events into logical sessions based
on process ancestry, user, host, and correlation identifiers. It
supports sliding expiration windows, idle timeouts, maximum
durations, and nested/child sessions.

It is completely independent from confidence scoring, risk
scoring, and severity calculation.
"""

import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

# ============================================================
# LOGGING CONFIGURATION
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
DETERMINISTIC_ID_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "self-evolving-security-ai.session-grouping"
)

DEFAULT_IDLE_TIMEOUT_SECONDS: float = 300.0
DEFAULT_MAX_DURATION_SECONDS: float = 3600.0 * 8.0


# ============================================================
# ENUMS
# ============================================================
class SessionType(Enum):
    """Enumerates the supported kinds of sessions."""
    PARENT_PROCESS_SESSION = "parent_process_session"
    USER_SESSION = "user_session"
    HOST_SESSION = "host_session"
    INTERACTIVE_SESSION = "interactive_session"
    SERVICE_SESSION = "service_session"
    CORRELATION_ID_SESSION = "correlation_id_session"
    UNKNOWN = "unknown"


# ============================================================
# CONFIGURATION DATACLASS
# ============================================================
@dataclass(slots=True)
class SessionConfig:
    """
    Configuration controlling session windowing behavior.

    Attributes:
        idle_timeout_seconds (float): Maximum gap between events before a
            session is considered expired.
        max_duration_seconds (float): Absolute maximum lifetime of a session
            regardless of activity.
        sliding_window (bool): Whether the idle timeout resets on each new
            event (sliding) or is measured from session start only.
        allow_nested_sessions (bool): Whether child sessions may be created
            beneath an existing parent session.
        default_session_type (SessionType): Fallback type when no more
            specific session type can be determined.
    """
    idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS
    max_duration_seconds: float = DEFAULT_MAX_DURATION_SECONDS
    sliding_window: bool = True
    allow_nested_sessions: bool = True
    default_session_type: SessionType = SessionType.HOST_SESSION


# ============================================================
# SESSION DATACLASS (MUTABLE, INTERNAL STATE)
# ============================================================
@dataclass(slots=True)
class Session:
    """
    Represents a single active or expired session.

    Attributes:
        session_id (str): Deterministic UUID identifying this session.
        session_type (SessionType): The kind of session.
        session_key (str): The grouping key (e.g. PID, user, host) that
            defines session membership.
        parent_session_id (str | None): Identifier of the parent session,
            if this is a nested/child session.
        child_session_ids (list[str]): Identifiers of any nested child sessions.
        event_ids (list[str]): Ordered identifiers of events in this session.
        start_time (datetime): UTC timestamp of the first event.
        last_activity_time (datetime): UTC timestamp of the most recent event.
        end_time (datetime | None): UTC timestamp the session was closed, if closed.
        metadata (dict[str, Any]): Additional structured session context.
    """
    session_id: str
    session_type: SessionType
    session_key: str
    parent_session_id: str | None
    child_session_ids: list[str]
    event_ids: list[str]
    start_time: datetime
    last_activity_time: datetime
    end_time: datetime | None
    metadata: dict[str, Any]


# ============================================================
# OUTPUT DATACLASS
# ============================================================
@dataclass(slots=True)
class SessionResult:
    """
    Represents the immutable, reportable outcome of processing an event
    against the session grouping engine.

    Attributes:
        session_id (str): Identifier of the session the event was assigned to.
        session_type (SessionType): The kind of session.
        is_new_session (bool): Whether this event created a new session.
        event_count (int): Total number of events in the session so far.
        session_duration_seconds (float): Elapsed seconds since session start.
        confidence (float): Confidence that this event truly belongs to the session.
        reasons (list[str]): Human-readable explanations for the assignment.
        metadata (dict[str, Any]): Additional structured context.
        timestamp (datetime): UTC timestamp of when this result was computed.
    """
    session_id: str
    session_type: SessionType
    is_new_session: bool
    event_count: int
    session_duration_seconds: float
    confidence: float
    reasons: list[str]
    metadata: dict[str, Any]
    timestamp: datetime


# ============================================================
# SESSION GROUPING ENGINE
# ============================================================
class SessionGroupingEngine:
    """
    A thread-safe engine that groups telemetry events into logical
    sessions using sliding or fixed expiration windows. Maintains
    internal indexes keyed by session grouping key for O(1) lookup
    and performs automatic cleanup of expired sessions.
    """

    def __init__(self, config: SessionConfig | None = None) -> None:
        """
        Initializes the engine with an optional configuration.

        Args:
            config (SessionConfig | None): Engine configuration. Uses
                defaults when omitted.
        """
        self._config: SessionConfig = config or SessionConfig()
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._active_by_key: dict[str, str] = {}

    # ------------------------------------------------------------
    # NORMALIZATION HELPERS
    # ------------------------------------------------------------
    def _normalize_str(self, value: Any) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned.lower() if cleaned else None

    def _normalize_int(self, value: Any) -> int | None:
        if value is None or isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _extract_event_id(self, event: Mapping[str, Any]) -> str:
        for key in ("event_id", "id", "uuid"):
            normalized = self._normalize_str(event.get(key))
            if normalized:
                return normalized
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, repr(sorted(event.items(), key=lambda kv: str(kv[0])))))

    def _extract_timestamp(self, event: Mapping[str, Any]) -> datetime:
        raw = event.get("timestamp")
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    def _determine_session_key(self, event: Mapping[str, Any]) -> tuple[str, SessionType]:
        """
        Determines the grouping key and session type for an event, in order
        of specificity: parent PID, correlation ID, user, host.

        Args:
            event (Mapping[str, Any]): The event to classify.

        Returns:
            tuple[str, SessionType]: The grouping key and inferred session type.
        """
        ppid = self._normalize_int(event.get("ppid") or event.get("parent_pid"))
        if ppid is not None:
            return f"ppid:{ppid}", SessionType.PARENT_PROCESS_SESSION

        correlation_id = self._normalize_str(event.get("correlation_id"))
        if correlation_id:
            return f"correlation:{correlation_id}", SessionType.CORRELATION_ID_SESSION

        is_interactive = event.get("interactive")
        user = self._normalize_str(event.get("user") or event.get("username"))
        if user and is_interactive:
            return f"interactive:{user}", SessionType.INTERACTIVE_SESSION

        is_service = self._normalize_str(event.get("session_class")) == "service"
        process_name = self._normalize_str(event.get("process_name"))
        if is_service and process_name:
            return f"service:{process_name}", SessionType.SERVICE_SESSION

        if user:
            return f"user:{user}", SessionType.USER_SESSION

        host = self._normalize_str(event.get("host") or event.get("hostname"))
        if host:
            return f"host:{host}", SessionType.HOST_SESSION

        return "unassigned", self._config.default_session_type

    def _make_session_id(self, session_key: str, start_time: datetime) -> str:
        key = f"{session_key}:{start_time.isoformat()}"
        return str(uuid.uuid5(DETERMINISTIC_ID_NAMESPACE, key))

    # ------------------------------------------------------------
    # SESSION LIFECYCLE
    # ------------------------------------------------------------
    def _is_expired(self, session: Session, event_time: datetime) -> bool:
        """
        Determines whether a session has expired relative to a new event's
        timestamp, based on idle timeout and maximum duration rules.
        """
        idle_elapsed = (event_time - session.last_activity_time).total_seconds()
        if idle_elapsed > self._config.idle_timeout_seconds:
            return True

        total_elapsed = (event_time - session.start_time).total_seconds()
        if total_elapsed > self._config.max_duration_seconds:
            return True

        return False

    def _close_session(self, session: Session, end_time: datetime) -> None:
        session.end_time = end_time
        self._active_by_key.pop(session.session_key, None)

    def expire_sessions(self, reference_time: datetime | None = None) -> int:
        """
        Scans all active sessions and closes any that have exceeded their
        idle timeout or maximum duration as of the reference time.

        Args:
            reference_time (datetime | None): The time to evaluate expiration
                against. Defaults to the current UTC time.

        Returns:
            int: The number of sessions closed by this call.
        """
        now = reference_time or datetime.now(timezone.utc)
        closed_count = 0
        with self._lock:
            for session_key, session_id in list(self._active_by_key.items()):
                session = self._sessions.get(session_id)
                if session is None or session.end_time is not None:
                    self._active_by_key.pop(session_key, None)
                    continue
                if self._is_expired(session, now):
                    self._close_session(session, now)
                    closed_count += 1
        return closed_count

    # ------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------
    def process_event(self, event: Mapping[str, Any]) -> SessionResult:
        """
        Assigns an event to an existing or newly created session, applying
        sliding/idle expiration and maximum duration rules.

        Args:
            event (Mapping[str, Any]): The telemetry event to process.

        Returns:
            SessionResult: The outcome of session assignment for this event.
        """
        if not isinstance(event, Mapping):
            logger.warning("process_event received a non-mapping event; returning a safe default result.")
            now = datetime.now(timezone.utc)
            return SessionResult(
                session_id="",
                session_type=SessionType.UNKNOWN,
                is_new_session=False,
                event_count=0,
                session_duration_seconds=0.0,
                confidence=0.0,
                reasons=["Invalid event input; expected a mapping."],
                metadata={},
                timestamp=now
            )

        try:
            with self._lock:
                event_id = self._extract_event_id(event)
                event_time = self._extract_timestamp(event)
                session_key, session_type = self._determine_session_key(event)

                existing_session_id = self._active_by_key.get(session_key)
                existing_session = self._sessions.get(existing_session_id) if existing_session_id else None

                is_new_session = True
                reasons: list[str] = []

                if existing_session is not None and existing_session.end_time is None:
                    if self._is_expired(existing_session, event_time):
                        self._close_session(existing_session, event_time)
                        reasons.append(f"Previous session for key '{session_key}' expired; starting a new session.")
                    else:
                        is_new_session = False

                if is_new_session:
                    session_id = self._make_session_id(session_key, event_time)
                    session = Session(
                        session_id=session_id,
                        session_type=session_type,
                        session_key=session_key,
                        parent_session_id=None,
                        child_session_ids=[],
                        event_ids=[event_id],
                        start_time=event_time,
                        last_activity_time=event_time,
                        end_time=None,
                        metadata={}
                    )
                    self._sessions[session_id] = session
                    self._active_by_key[session_key] = session_id
                    reasons.append(f"Created new {session_type.value} for key '{session_key}'.")
                else:
                    session = existing_session
                    session.event_ids.append(event_id)
                    if self._config.sliding_window:
                        session.last_activity_time = event_time
                    reasons.append(f"Assigned event to existing {session_type.value} '{session.session_id}'.")

                duration = (session.last_activity_time - session.start_time).total_seconds()
                confidence = 1.0 if session_key != "unassigned" else 0.3

                return SessionResult(
                    session_id=session.session_id,
                    session_type=session.session_type,
                    is_new_session=is_new_session,
                    event_count=len(session.event_ids),
                    session_duration_seconds=round(max(duration, 0.0), 3),
                    confidence=confidence,
                    reasons=reasons,
                    metadata={"session_key": session_key},
                    timestamp=datetime.now(timezone.utc)
                )

        except Exception as e:
            logger.exception("Unexpected error in SessionGroupingEngine.process_event: %s", e)
            now = datetime.now(timezone.utc)
            return SessionResult(
                session_id="",
                session_type=SessionType.UNKNOWN,
                is_new_session=False,
                event_count=0,
                session_duration_seconds=0.0,
                confidence=0.0,
                reasons=["Engine encountered an unexpected error and returned a default empty result."],
                metadata={},
                timestamp=now
            )

    def process_events(self, events: Sequence[Mapping[str, Any]]) -> list[SessionResult]:
        """
        Processes a batch of events sequentially, in timestamp/arrival order,
        against the session grouping engine.

        Args:
            events (Sequence[Mapping[str, Any]]): The events to process.

        Returns:
            list[SessionResult]: One result per input event, in order.
        """
        if not isinstance(events, Sequence):
            logger.warning("process_events received a non-sequence input; returning no results.")
            return []
        return [self.process_event(event) for event in events]

    def create_child_session(self, parent_session_id: str, session_key: str, session_type: SessionType, start_time: datetime | None = None) -> Session | None:
        """
        Explicitly creates a nested child session beneath an existing parent
        session, when nested sessions are enabled by configuration.

        Args:
            parent_session_id (str): Identifier of the parent session.
            session_key (str): Grouping key for the new child session.
            session_type (SessionType): The kind of session to create.
            start_time (datetime | None): Start time for the child session.
                Defaults to the current UTC time.

        Returns:
            Session | None: The newly created child session, or None if
            nested sessions are disabled or the parent does not exist.
        """
        if not self._config.allow_nested_sessions:
            logger.info("create_child_session called but nested sessions are disabled by configuration.")
            return None

        with self._lock:
            parent = self._sessions.get(parent_session_id)
            if parent is None:
                logger.warning("create_child_session: parent session '%s' not found.", parent_session_id)
                return None

            now = start_time or datetime.now(timezone.utc)
            child_id = self._make_session_id(session_key, now)
            child = Session(
                session_id=child_id,
                session_type=session_type,
                session_key=session_key,
                parent_session_id=parent_session_id,
                child_session_ids=[],
                event_ids=[],
                start_time=now,
                last_activity_time=now,
                end_time=None,
                metadata={}
            )
            self._sessions[child_id] = child
            parent.child_session_ids.append(child_id)
            self._active_by_key[session_key] = child_id
            return child

    def get_session(self, session_id: str) -> Session | None:
        """
        Retrieves a session by its identifier.

        Args:
            session_id (str): The session identifier.

        Returns:
            Session | None: The session, or None if not found.
        """
        with self._lock:
            return self._sessions.get(session_id)

    def get_statistics(self) -> dict[str, Any]:
        """
        Computes summary statistics across all known sessions.

        Returns:
            dict[str, Any]: A dictionary of aggregate session statistics.
        """
        with self._lock:
            total = len(self._sessions)
            active = sum(1 for s in self._sessions.values() if s.end_time is None)
            closed = total - active
            total_events = sum(len(s.event_ids) for s in self._sessions.values())
            by_type: dict[str, int] = {}
            for s in self._sessions.values():
                by_type[s.session_type.value] = by_type.get(s.session_type.value, 0) + 1

            return {
                "total_sessions": total,
                "active_sessions": active,
                "closed_sessions": closed,
                "total_events": total_events,
                "sessions_by_type": by_type,
            }
