import hashlib
import urllib.parse
import re


class PrivacyManager:
    """Handles privacy-preserving operations — all processing is 100% local."""

    def __init__(self):
        self._external_calls: list = []

    def anonymize_url(self, url: str) -> str:
        """Anonymize a URL by hashing the domain and stripping query parameters."""
        try:
            parsed = urllib.parse.urlparse(url)
            hashed_domain = hashlib.sha256(parsed.netloc.encode()).hexdigest()[:12]
            return f"{parsed.scheme}://{hashed_domain}/[path_redacted]"
        except Exception:
            return "[invalid_url]"

    def strip_pii(self, text: str) -> str:
        """Remove potential PII (emails, IPs) from a string before logging."""
        text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL]', text)
        text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP]', text)
        return text

    def log_privately(self, message: str) -> None:
        """Log a message after stripping any PII."""
        safe_message = self.strip_pii(message)
        print(f"[PRIVATE LOG]: {safe_message}")

    def record_external_call(self, destination: str) -> None:
        """Record an external API call (used in tests to verify none occur)."""
        self._external_calls.append(destination)

    def verify_no_external_api_calls(self) -> bool:
        """Assert that no external API calls were recorded.

        Raises:
            Exception: If any external call was registered.
        """
        if self._external_calls:
            raise Exception(
                f"External API calls detected: {self._external_calls}"
            )
        return True

    def get_privacy_report(self) -> dict:
        """Return a summary confirming local-only processing."""
        return {
            "external_calls": len(self._external_calls),
            "external_call_destinations": list(self._external_calls),
            "local_processing_only": len(self._external_calls) == 0,
            "pii_protection": True,
            "data_retention": "session-only",
        }
