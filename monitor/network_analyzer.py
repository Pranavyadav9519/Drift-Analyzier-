"""
monitor/network_analyzer.py — Network anomaly detection

Inspects active network connections and detects:
  - Unexpected outbound connections to unusual port ranges
  - Connections to known malicious port indicators
  - Unusually high connection counts (potential port scan / data exfil)
  - Newly established connections to non-standard ports

Uses only the standard library (socket + subprocess) so it works
without any additional dependencies.
"""

from __future__ import annotations

import platform
import subprocess
import re
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .system_monitor import SystemMonitor

logger = logging.getLogger("network_analyzer")

# Ports that are almost never used by legitimate desktop software but
# are commonly seen in C2 (command-and-control) traffic
SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444,   # Metasploit default
    1337,   # Common hacking port
    31337,  # Classic backdoor port
    6666,   # Common IRC / malware
    6667,   # IRC (often used by botnets)
    12345,  # Common backdoor
    54321,  # Reverse shell
    9001,   # Tor default OR Metasploit
    8888,   # Often used by malware C2
})

# Threshold: alert if a single process has more than this many established connections
HIGH_CONNECTION_COUNT_THRESHOLD = 50

# Store previously seen connections to detect *new* suspicious ones
_PREVIOUSLY_SEEN_CONNECTIONS: set[str] = set()


class NetworkAnalyzer:
    """
    Monitors active network connections for anomalous patterns.

    :param monitor: Reference to the parent SystemMonitor for event queuing
    """

    def __init__(self, monitor: "SystemMonitor") -> None:
        self._monitor = monitor

    def check_network_connections(self) -> None:
        """
        Enumerate active network connections and flag suspicious ones.

        Checks for connections to known-bad ports and unusually high
        connection counts that may indicate scanning or exfiltration.
        """
        connections = self._get_active_connections()

        suspicious_found: list[dict] = []
        connection_count = len(connections)

        for connection in connections:
            remote_port = connection.get("remote_port", 0)
            remote_address = connection.get("remote_address", "")
            state = connection.get("state", "")

            # Only look at established outbound connections
            if state not in ("ESTABLISHED", "SYN_SENT"):
                continue

            # Check for connections to suspicious ports
            if remote_port in SUSPICIOUS_PORTS:
                connection_key = f"{remote_address}:{remote_port}"
                if connection_key not in _PREVIOUSLY_SEEN_CONNECTIONS:
                    _PREVIOUSLY_SEEN_CONNECTIONS.add(connection_key)
                    suspicious_found.append({
                        "remote": connection_key,
                        "reason": f"Connection to suspicious port {remote_port}",
                    })

        # Check for abnormally high total connection count
        if connection_count > HIGH_CONNECTION_COUNT_THRESHOLD:
            logger.warning(
                "High connection count detected: %d active connections", connection_count
            )
            self._monitor.queue_event(
                "network_anomaly",
                {
                    "connection_count": connection_count,
                    "threshold": HIGH_CONNECTION_COUNT_THRESHOLD,
                    "description": (
                        f"Unusually high number of network connections ({connection_count}). "
                        "Possible port scan or data exfiltration in progress."
                    ),
                },
            )

        for suspicious in suspicious_found:
            logger.warning("Suspicious network connection: %s", suspicious)
            self._monitor.queue_event(
                "network_anomaly",
                {
                    "remote": suspicious["remote"],
                    "reason": suspicious["reason"],
                    "description": (
                        f"Outbound connection to suspicious port: {suspicious['remote']}"
                    ),
                },
            )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_active_connections(self) -> list[dict]:
        """
        Return a list of active network connection dicts.

        Each dict contains: remote_address, remote_port, state.
        Uses psutil if available; falls back to netstat.
        """
        try:
            import psutil  # type: ignore[import]
            connections = []
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:
                    connections.append({
                        "remote_address": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "state": conn.status,
                    })
            return connections
        except (ImportError, Exception):
            pass

        # Fallback: parse netstat output
        return self._parse_netstat()

    def _parse_netstat(self) -> list[dict]:
        """
        Parse 'netstat -n' output into a list of connection dicts.

        Works on Linux, macOS, and Windows.
        """
        connections: list[dict] = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["netstat", "-n"],
                    capture_output=True, text=True, timeout=10,
                )
            else:
                result = subprocess.run(
                    ["netstat", "-tn"],
                    capture_output=True, text=True, timeout=10,
                )

            # Pattern to extract IP:port and state from netstat output
            # Handles both IPv4 and IPv6 formatted lines
            pattern = re.compile(
                r"(?:tcp|udp)\s+\d+\s+\d+\s+[\d.:*\[\]]+\s+([\d.:*\[\]]+)\s+(\w+)",
                re.IGNORECASE,
            )

            for line in result.stdout.splitlines():
                match = pattern.search(line)
                if match:
                    remote_full, state = match.group(1), match.group(2)
                    # Extract the port from the last colon-separated segment
                    parts = remote_full.rsplit(":", 1)
                    if len(parts) == 2:
                        try:
                            connections.append({
                                "remote_address": parts[0],
                                "remote_port": int(parts[1]),
                                "state": state.upper(),
                            })
                        except ValueError:
                            pass  # Non-numeric port — skip

        except Exception as exc:
            logger.debug("netstat unavailable: %s", exc)

        return connections
