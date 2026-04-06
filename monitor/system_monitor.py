"""
monitor/system_monitor.py — Silent background system observer

Watches for privilege escalation, root access attempts, and suspicious
system-level events. When a threat is detected it sends the event to
the ML service for scoring and triggers a native OS alert with remedy steps.

Design principles:
  - Zero data persistence: events exist only in RAM
  - No UI: communicates via native OS notifications only
  - Graceful degradation: if the ML service is unavailable, still alerts locally
  - Cross-platform: works on Windows, macOS, and Linux
"""

from __future__ import annotations

import os
import sys
import time
import threading
import logging
import platform
import subprocess
import urllib.request
import json
from typing import Any

# ── Logging setup — INFO to stdout, nothing written to disk ─────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("system_monitor")

# ── Service endpoints ────────────────────────────────────────────────────────

ML_SERVICE_URL = os.environ.get("ML_SERVICE_URL", "http://localhost:5001")
PHISHING_API_URL = os.environ.get("PHISHING_API_URL", "http://localhost:5050")

# How often to poll system logs and processes (seconds)
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL", "5"))

# How long between repeat alerts for the same threat type (seconds)
ALERT_COOLDOWN_SECONDS = 60


class SystemMonitor:
    """
    Orchestrates all monitoring components and handles threat escalation.

    Each sub-analyser runs in its own thread, feeding events into the
    shared _pending_events queue. The main loop picks up events, queries
    the ML service, and fires native OS alerts when threats are confirmed.
    """

    def __init__(self) -> None:
        self._running = False
        self._pending_events: list[dict[str, Any]] = []
        self._events_lock = threading.Lock()
        # Track last alert time per threat type to avoid notification spam
        self._last_alert_time: dict[str, float] = {}
        self._alert_lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start all monitoring threads. Blocks until stop() is called."""
        self._running = True
        logger.info("Drift Analyzer system monitor started (press Ctrl+C to stop)")

        threads = [
            threading.Thread(target=self._watch_privilege_events, daemon=True),
            threading.Thread(target=self._watch_processes, daemon=True),
            threading.Thread(target=self._watch_network, daemon=True),
        ]
        for thread in threads:
            thread.start()

        # Main event processing loop
        try:
            while self._running:
                self._process_pending_events()
                time.sleep(POLL_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            logger.info("Monitor stopping — no data was stored.")
            self._running = False

    def stop(self) -> None:
        """Signal all threads to stop gracefully."""
        self._running = False

    def queue_event(self, event_type: str, details: dict[str, Any]) -> None:
        """
        Add a raw system event to the processing queue.

        :param event_type: Short descriptor (e.g. "privilege_escalation")
        :param details: Any additional context about the event
        """
        event = {
            "event_type": event_type,
            "details": details,
            "timestamp": time.time(),
        }
        with self._events_lock:
            self._pending_events.append(event)

    # ── Event processing ──────────────────────────────────────────────────────

    def _process_pending_events(self) -> None:
        """Drain the pending queue, score each event, and alert if needed."""
        with self._events_lock:
            events_to_process = list(self._pending_events)
            self._pending_events.clear()

        for event in events_to_process:
            self._handle_event(event)

    def _handle_event(self, event: dict[str, Any]) -> None:
        """
        Decide whether an event deserves an alert.

        First checks the ML service for a threat score. Falls back to
        rule-based severity if the ML service is unreachable.
        """
        event_type = event["event_type"]
        details = event.get("details", {})

        # Ask the ML service to score the event
        threat_info = self._query_ml_service(event_type, details)

        if threat_info and threat_info.get("is_threat"):
            threat_type = threat_info.get("threat_type", event_type)
            remedy_steps = threat_info.get("remedy_steps", [])
            self._trigger_alert(threat_type, details, remedy_steps)
        elif event_type in ("privilege_escalation", "root_access", "sudo_attempt"):
            # High-severity events get alerted even without ML confirmation
            self._trigger_alert(
                "root_access_attempt",
                details,
                [
                    "Deny the privilege request immediately",
                    "Identify which application triggered the request",
                    "Run an antivirus scan if you did not initiate this",
                ],
            )

    def _trigger_alert(
        self,
        threat_type: str,
        details: dict[str, Any],
        remedy_steps: list[str],
    ) -> None:
        """
        Fire a native OS notification for a detected threat, with cooldown.

        :param threat_type: Canonical threat type for the notification title
        :param details: Event context used in the notification body
        :param remedy_steps: First 2–3 steps shown in the notification
        """
        # Enforce cooldown so we don't spam the user with repeated alerts
        now = time.time()
        with self._alert_lock:
            last = self._last_alert_time.get(threat_type, 0)
            if now - last < ALERT_COOLDOWN_SECONDS:
                return
            self._last_alert_time[threat_type] = now

        title = f"⚠️ Drift Analyzer — {threat_type.replace('_', ' ').title()} Detected"
        body_lines = []
        if details.get("description"):
            body_lines.append(details["description"])
        # Show up to 3 remedy steps in the notification
        for i, step in enumerate(remedy_steps[:3], start=1):
            body_lines.append(f"{i}. {step}")
        body = "\n".join(body_lines) if body_lines else "Threat detected. Check the extension popup."

        logger.warning("THREAT DETECTED: %s — %s", threat_type, details)
        _send_os_notification(title, body)

    # ── Monitoring threads ────────────────────────────────────────────────────

    def _watch_privilege_events(self) -> None:
        """Watch for privilege escalation attempts in system logs."""
        from .process_analyzer import ProcessAnalyzer
        analyzer = ProcessAnalyzer(self)
        while self._running:
            try:
                analyzer.check_privilege_escalation()
            except Exception as exc:
                logger.debug("Privilege watcher error: %s", exc)
            time.sleep(POLL_INTERVAL_SECONDS)

    def _watch_processes(self) -> None:
        """Watch for suspicious running processes."""
        from .process_analyzer import ProcessAnalyzer
        analyzer = ProcessAnalyzer(self)
        while self._running:
            try:
                analyzer.scan_running_processes()
            except Exception as exc:
                logger.debug("Process watcher error: %s", exc)
            time.sleep(POLL_INTERVAL_SECONDS * 2)  # Less frequent scan

    def _watch_network(self) -> None:
        """Watch for network anomalies."""
        from .network_analyzer import NetworkAnalyzer
        analyzer = NetworkAnalyzer(self)
        while self._running:
            try:
                analyzer.check_network_connections()
            except Exception as exc:
                logger.debug("Network watcher error: %s", exc)
            time.sleep(POLL_INTERVAL_SECONDS)

    # ── ML service integration ─────────────────────────────────────────────

    def _query_ml_service(
        self,
        event_type: str,
        details: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Ask the ML service whether an event is a threat.

        :returns: ML service response dict, or None if the service is unreachable
        """
        payload = json.dumps({
            "event_type": event_type,
            "loginHour": details.get("hour", time.localtime().tm_hour),
            "loginDayOfWeek": details.get("weekday", time.localtime().tm_wday),
            "isNewDevice": int(details.get("is_new_device", False)),
        }).encode("utf-8")

        try:
            request = urllib.request.Request(
                f"{ML_SERVICE_URL}/threat/predict",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                return json.loads(response.read())
        except Exception as exc:
            logger.debug("ML service unreachable: %s", exc)
            return None


# ── Native OS notification helper ────────────────────────────────────────────

def _send_os_notification(title: str, body: str) -> None:
    """
    Send a native OS desktop notification without any external libraries.

    Supports Windows (win10toast / PowerShell fallback), macOS (osascript),
    and Linux (notify-send).
    """
    system = platform.system()
    try:
        if system == "Darwin":
            # macOS: use AppleScript via osascript
            script = f'display notification "{body}" with title "{title}"'
            subprocess.run(["osascript", "-e", script], check=False, timeout=5)

        elif system == "Windows":
            # Windows: try PowerShell toast notification
            ps_script = (
                f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
                f"ContentType = WindowsRuntime] | Out-Null; "
                f"$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
                f"[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                f"$template.SelectSingleNode('//text[@id=1]').InnerText = '{title}'; "
                f"$template.SelectSingleNode('//text[@id=2]').InnerText = '{body}'; "
                f"$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
                f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Drift Analyzer').Show($toast);"
            )
            subprocess.run(
                ["powershell", "-Command", ps_script],
                check=False, timeout=10,
            )

        else:
            # Linux: use notify-send (libnotify)
            subprocess.run(
                ["notify-send", "--urgency=critical", "--expire-time=10000", title, body],
                check=False, timeout=5,
            )
    except Exception as exc:
        # Notification failed — log to stdout so the user at least sees it in the terminal
        logger.warning("OS notification failed (%s): %s | %s", exc, title, body)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    monitor = SystemMonitor()
    monitor.start()
