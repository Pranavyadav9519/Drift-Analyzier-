"""
core/logger.py — In-memory event logger

Stores detection events in RAM only — nothing ever touches disk or a database.
All events are automatically purged when the process restarts, honouring the
zero-data-persistence ideology.

Thread-safe via a simple lock so both the Flask app and the monitor service
can log events concurrently without corrupting the buffer.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any


# Maximum number of events to keep in memory at one time.
# Old events are silently dropped when the buffer fills up.
MAX_BUFFER_SIZE = 500


class EventLogger:
    """
    Lightweight in-memory circular buffer for threat events.

    Events are plain dicts — no schema enforcement — so every service
    can log whatever context it finds useful.

    Example usage:
        logger = EventLogger()
        logger.log("phishing_url", {"url": "http://evil.xyz/", "score": 0.91})
        recent = logger.get_recent_events(limit=10)
    """

    def __init__(self, max_size: int = MAX_BUFFER_SIZE) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def log(self, threat_type: str, details: dict[str, Any] | None = None) -> None:
        """
        Record a single threat detection event.

        :param threat_type: Canonical threat type string (e.g. "phishing_url")
        :param details: Arbitrary context dict — whatever the caller wants to attach
        """
        event = {
            "timestamp": time.time(),
            "threat_type": threat_type,
            "details": details or {},
        }
        with self._lock:
            self._buffer.append(event)

    def get_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return the most recent `limit` events in reverse-chronological order.

        :param limit: Maximum number of events to return (capped at buffer size)
        :returns: List of event dicts, newest first
        """
        with self._lock:
            events = list(self._buffer)
        # Sort newest-first and apply limit
        return sorted(events, key=lambda e: e["timestamp"], reverse=True)[:limit]

    def count_by_type(self) -> dict[str, int]:
        """
        Return a summary count of events grouped by threat type.

        Useful for health-check endpoints and the popup stats badge.
        """
        with self._lock:
            events = list(self._buffer)

        counts: dict[str, int] = {}
        for event in events:
            threat_type = event.get("threat_type", "unknown")
            counts[threat_type] = counts.get(threat_type, 0) + 1
        return counts

    def clear(self) -> None:
        """Wipe all events from the buffer (e.g. on user request)."""
        with self._lock:
            self._buffer.clear()

    @property
    def total_events(self) -> int:
        """Total number of events currently in the buffer."""
        with self._lock:
            return len(self._buffer)
