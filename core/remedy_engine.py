"""
core/remedy_engine.py — Centralised threat response logic

Each threat type is mapped to:
  - A human-readable description
  - A severity level
  - A numbered list of actionable steps the user can take RIGHT NOW

Design principle: remedies are plain English — no jargon, no tech-speak.
The user should be able to read the list and act within 60 seconds.
"""

from __future__ import annotations

from typing import TypedDict


class RemedyCard(TypedDict):
    """Structured threat response returned to the caller."""

    threat_type: str
    severity: str          # "low" | "medium" | "high" | "critical"
    description: str
    remedies: list[str]


# ---------------------------------------------------------------------------
# Remedy database — one entry per threat type
# ---------------------------------------------------------------------------

_REMEDY_DATABASE: dict[str, RemedyCard] = {
    "phishing_url": {
        "threat_type": "phishing_url",
        "severity": "high",
        "description": (
            "A URL you were about to visit shows strong signs of being a phishing "
            "page — a fake site designed to steal your credentials or install malware."
        ),
        "remedies": [
            "Do NOT click the link or enter any information on that page.",
            "Close the tab immediately if you already opened it.",
            "Report the URL to Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/",
            "If you typed a password there, change that password on the real site right now.",
            "Enable two-factor authentication (2FA) on any account that may be affected.",
            "Run a quick antivirus scan to check for any drive-by malware downloads.",
        ],
    },
    "anomalous_login": {
        "threat_type": "anomalous_login",
        "severity": "medium",
        "description": (
            "A login event was detected that falls outside your normal usage patterns "
            "(unusual hour, new device, or atypical location). This may indicate "
            "that someone else is accessing your account."
        ),
        "remedies": [
            "Check your active sessions and log out of all unfamiliar devices.",
            "Change your password immediately — use a long, random passphrase.",
            "Enable two-factor authentication (2FA) if it is not already active.",
            "Review recent account activity for unauthorised changes or messages.",
            "Check for any email forwarding rules that you did not set up.",
            "Contact support for the affected service if you see suspicious activity.",
        ],
    },
    "root_access_attempt": {
        "threat_type": "root_access_attempt",
        "severity": "critical",
        "description": (
            "A process attempted to gain root (administrator) privileges on your system. "
            "This is a strong indicator of a privilege escalation attack or malware "
            "trying to take full control of your device."
        ),
        "remedies": [
            "Deny the privilege request — click 'No' or 'Cancel' immediately.",
            "Identify which application triggered the request (check the prompt text).",
            "If you did not initiate the action, disconnect from the internet NOW.",
            "Run a full antivirus/antimalware scan in safe mode.",
            "Check recently installed applications and uninstall anything unfamiliar.",
            "Review startup programs and scheduled tasks for unknown entries.",
            "Consider restoring from a known-good backup if the system behaves strangely.",
            "Report the incident to your IT security team or a professional.",
        ],
    },
    "social_engineering": {
        "threat_type": "social_engineering",
        "severity": "high",
        "description": (
            "Behavioural patterns on this page suggest a social engineering attempt — "
            "psychological manipulation tactics designed to pressure you into revealing "
            "information, clicking a link, or transferring money."
        ),
        "remedies": [
            "Stop and breathe — social engineering relies on urgency and panic; slow down.",
            "Verify the request through a completely separate channel (call the organisation directly).",
            "Never provide passwords, OTP codes, or financial details via chat, email, or phone.",
            "Do not download attachments or click links from unexpected messages.",
            "Check the sender's actual email address for subtle misspellings.",
            "Trust your instinct — if something feels off, it almost certainly is.",
            "Report the attempt to your organisation's security team or IT helpdesk.",
        ],
    },
    "suspicious_process": {
        "threat_type": "suspicious_process",
        "severity": "medium",
        "description": (
            "A process on your system is exhibiting suspicious behaviour — "
            "unusual network connections, unexpected file access, or disguised executable names."
        ),
        "remedies": [
            "Open Task Manager (Windows) / Activity Monitor (Mac) / top (Linux) and identify the process.",
            "Do NOT kill it yet — note the process name, PID, and file path first.",
            "Search the process name online to determine if it is legitimate.",
            "If confirmed malicious, terminate the process and delete its executable.",
            "Run a full antivirus scan immediately.",
            "Check if any browser extensions or recently installed software launched the process.",
        ],
    },
    "usb_anomaly": {
        "threat_type": "usb_anomaly",
        "severity": "medium",
        "description": (
            "An unexpected USB device was connected to your system. "
            "Malicious USB devices (BadUSB, rubber ducky) can execute commands silently."
        ),
        "remedies": [
            "Physically remove the USB device immediately.",
            "Do not open any files that auto-launched from the device.",
            "Check which files the device accessed using your OS audit logs.",
            "Run an antivirus scan on any files that were touched.",
            "If you did not plug in the device yourself, treat this as a physical security incident.",
            "Review and disable AutoRun/AutoPlay features on your operating system.",
        ],
    },
    "network_anomaly": {
        "threat_type": "network_anomaly",
        "severity": "medium",
        "description": (
            "Unusual outbound network traffic was detected — "
            "unexpected connections to unknown external addresses, data exfiltration patterns, "
            "or port scanning activity."
        ),
        "remedies": [
            "Check active network connections: run 'netstat -an' or 'ss -tunp' in a terminal.",
            "Identify the process responsible for the unusual connection.",
            "Block the connection using your firewall if the destination is unknown.",
            "Disconnect from the network if you suspect active data exfiltration.",
            "Review recently installed software and browser extensions.",
            "Change passwords for any cloud services, email, or financial accounts.",
            "Contact your Internet Service Provider if the behaviour persists.",
        ],
    },
}

# Default fallback for unknown threat types
_UNKNOWN_REMEDY: RemedyCard = {
    "threat_type": "unknown",
    "severity": "medium",
    "description": "An unclassified threat signal was detected on your system.",
    "remedies": [
        "Stay calm and do not take any irreversible actions yet.",
        "Document what you observed — screenshot, timestamp, affected application.",
        "Disconnect from the internet as a precaution.",
        "Run a full antivirus scan.",
        "Contact your IT security team or a professional for assistance.",
    ],
}


class RemedyEngine:
    """
    Maps threat types to structured, actionable remedy cards.

    Usage:
        engine = RemedyEngine()
        card = engine.get_remedy("phishing_url")
        print(card["remedies"])
    """

    def get_remedy(self, threat_type: str) -> RemedyCard:
        """
        Return the remedy card for a given threat type.

        :param threat_type: One of the known threat type strings (see _REMEDY_DATABASE).
        :returns: A RemedyCard dict with description, severity, and step-by-step remedies.
        """
        return _REMEDY_DATABASE.get(threat_type, _UNKNOWN_REMEDY)

    def list_threat_types(self) -> list[str]:
        """Return a list of all known threat type identifiers."""
        return list(_REMEDY_DATABASE.keys())

    def get_all_remedies(self) -> dict[str, RemedyCard]:
        """Return the full remedy database (useful for API documentation endpoints)."""
        return dict(_REMEDY_DATABASE)
