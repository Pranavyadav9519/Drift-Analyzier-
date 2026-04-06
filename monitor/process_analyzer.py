"""
monitor/process_analyzer.py — Suspicious process detection

Scans running processes and system logs for signs of:
  - Privilege escalation (sudo calls, UAC prompts, setuid binaries)
  - Known malicious process name patterns
  - Unusual parent-child process relationships

Uses only standard library + psutil (optional) to stay lightweight.
Falls back to shell commands if psutil is not installed.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import platform
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .system_monitor import SystemMonitor

logger = logging.getLogger("process_analyzer")

# Process names that strongly suggest malicious activity
SUSPICIOUS_PROCESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"mimikatz", re.IGNORECASE),
    re.compile(r"meterpreter", re.IGNORECASE),
    re.compile(r"netcat|ncat|nc\.exe", re.IGNORECASE),
    re.compile(r"cobaltstrike|beacon\.exe", re.IGNORECASE),
    re.compile(r"keylog", re.IGNORECASE),
    re.compile(r"cryptominer|xmrig", re.IGNORECASE),
    re.compile(r"powershell.*-enc", re.IGNORECASE),   # encoded PS commands
    re.compile(r"wscript.*vbs", re.IGNORECASE),
]

# sudo / privilege escalation log patterns (Linux/macOS)
PRIVILEGE_LOG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sudo:.*COMMAND", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    re.compile(r"su\[.*\].*failed", re.IGNORECASE),
    re.compile(r"pam_unix.*auth.*failure", re.IGNORECASE),
]

# Track which processes we have already alerted on to avoid spam
_ALREADY_ALERTED: set[str] = set()


class ProcessAnalyzer:
    """
    Analyses running processes and privilege escalation signals.

    :param monitor: Reference to the parent SystemMonitor for event queuing
    """

    def __init__(self, monitor: "SystemMonitor") -> None:
        self._monitor = monitor
        self._last_log_position: int = 0

    def scan_running_processes(self) -> None:
        """
        Enumerate running processes and check for suspicious names/patterns.

        Uses psutil if available for richer process info, otherwise falls
        back to 'ps aux' on Unix or 'tasklist' on Windows.
        """
        process_list = self._get_process_list()

        for process_entry in process_list:
            for pattern in SUSPICIOUS_PROCESS_PATTERNS:
                if pattern.search(process_entry):
                    # Extract a short identifier for deduplication
                    alert_key = pattern.pattern + process_entry[:40]
                    if alert_key not in _ALREADY_ALERTED:
                        _ALREADY_ALERTED.add(alert_key)
                        logger.warning("Suspicious process detected: %s", process_entry[:80])
                        self._monitor.queue_event(
                            "suspicious_process",
                            {
                                "process": process_entry[:80],
                                "pattern_matched": pattern.pattern,
                                "description": f"Suspicious process detected: {process_entry[:60]}",
                            },
                        )
                    break  # One match per process is enough

    def check_privilege_escalation(self) -> None:
        """
        Parse recent system authentication logs for privilege escalation.

        Checks /var/log/auth.log (Ubuntu/Debian), /var/log/secure (RHEL/CentOS),
        and macOS system.log. Silently skips if log files are inaccessible.
        """
        system = platform.system()

        if system == "Linux":
            log_candidates = ["/var/log/auth.log", "/var/log/secure"]
        elif system == "Darwin":
            log_candidates = ["/var/log/system.log"]
        else:
            # Windows — privilege escalation detection via event log is complex;
            # a future version can use win32evtlog.
            return

        for log_path in log_candidates:
            if os.path.exists(log_path):
                self._scan_log_file(log_path)
                break

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_process_list(self) -> list[str]:
        """
        Return a list of running process command strings.

        Tries psutil first (richer info), then falls back to shell commands.
        """
        try:
            import psutil  # type: ignore[import]
            return [
                f"{proc.name()} {' '.join(proc.cmdline())}"
                for proc in psutil.process_iter(["name", "cmdline"])
                if proc.info["name"]
            ]
        except (ImportError, Exception):
            pass

        # Shell fallback
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV"],
                    capture_output=True, text=True, timeout=5,
                )
            else:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=5,
                )
            return result.stdout.splitlines()
        except Exception as exc:
            logger.debug("Process list unavailable: %s", exc)
            return []

    def _scan_log_file(self, log_path: str) -> None:
        """
        Read new lines appended to a log file since the last scan.

        Only reads lines added after the previous scan position to avoid
        re-processing the entire log on every poll cycle.
        """
        try:
            with open(log_path, "r", errors="replace") as log_file:
                log_file.seek(self._last_log_position)
                new_lines = log_file.readlines()
                self._last_log_position = log_file.tell()

            for line in new_lines:
                for pattern in PRIVILEGE_LOG_PATTERNS:
                    if pattern.search(line):
                        logger.warning("Privilege event in log: %s", line.strip()[:100])
                        self._monitor.queue_event(
                            "privilege_escalation",
                            {
                                "log_line": line.strip()[:100],
                                "log_file": log_path,
                                "description": "Privilege escalation attempt detected in system log",
                            },
                        )
                        break  # One match per line is enough

        except PermissionError:
            # Normal — log files often require root to read
            logger.debug("No permission to read %s", log_path)
        except Exception as exc:
            logger.debug("Log scan error for %s: %s", log_path, exc)
