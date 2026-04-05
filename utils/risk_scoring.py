"""
utils/risk_scoring.py — Sentinel Zero Local
Risk scoring engine with per-signal explainability.

Combines ML model output with heuristic signals to produce a 0–100 risk
score and a human-readable explanation list (e.g., for the dashboard).
"""

from __future__ import annotations

import dataclasses
from typing import Optional


# ── Score thresholds ──────────────────────────────────────────────────────────

SCORE_HIGH = 70      # ≥70 → PHISHING / HIGH
SCORE_MEDIUM = 40    # 40–69 → SUSPICIOUS / MEDIUM
# 0–39 → SAFE / LOW


# ── Individual signal weights ─────────────────────────────────────────────────

# Each signal contributes a fixed number of points (positive = more suspicious).
# Capped totals are enforced to prevent any single signal dominating the score.

_SIGNALS: list[dict] = [
    {
        "key": "contains_ip",
        "points": 20,
        "label": "IP address used instead of domain name",
        "condition": lambda f: f.get("contains_ip", 0) == 1,
    },
    {
        "key": "no_https",
        "points": 10,
        "label": "No HTTPS — connection is unencrypted",
        "condition": lambda f: f.get("has_https", 1) == 0,
    },
    {
        "key": "suspicious_tld",
        "points": 20,
        "label": "Suspicious top-level domain (e.g. .xyz, .top, .tk)",
        "condition": lambda f: f.get("suspicious_tld", 0) == 1,
    },
    {
        "key": "trusted_domain",
        "points": -30,
        "label": "Verified trusted domain (whitelist match)",
        "condition": lambda f: f.get("is_trusted_domain", 0) == 1,
    },
    {
        "key": "phishing_keywords",
        "points": 7,
        "max_points": 35,
        "label_template": "Contains {count} phishing keyword(s) (e.g. 'verify', 'login', 'paypal', 'aadhaar')",
        "condition": lambda f: f.get("num_phishing_keywords", 0),
        "multiplier_key": "num_phishing_keywords",
    },
    {
        "key": "deep_subdomains",
        "points": 5,
        "max_points": 15,
        "label_template": "Deep subdomain nesting ({count} levels)",
        "condition": lambda f: f.get("subdomain_count", 0) > 1,
        "multiplier_key": "subdomain_count",
    },
    {
        "key": "at_sign",
        "points": 10,
        "max_points": 10,
        "label_template": "URL contains '@' sign — common obfuscation technique",
        "condition": lambda f: f.get("num_at_signs", 0) > 0,
        "multiplier_key": "num_at_signs",
    },
    {
        "key": "hyphens",
        "points": 2,
        "max_points": 10,
        "label_template": "Multiple hyphens in domain ({count} found)",
        "condition": lambda f: f.get("num_hyphens", 0) > 1,
        "multiplier_key": "num_hyphens",
    },
    {
        "key": "long_url",
        "points": 10,
        "label": "Unusually long URL (>100 characters)",
        "condition": lambda f: f.get("url_length", 0) > 100,
    },
    {
        "key": "double_slash",
        "points": 10,
        "label": "Double slash in URL path — redirection obfuscation",
        "condition": lambda f: f.get("double_slash_in_path", 0) == 1,
    },
    {
        "key": "non_standard_port",
        "points": 10,
        "label": "Non-standard port specified",
        "condition": lambda f: f.get("has_port", 0) == 1,
    },
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclasses.dataclass
class RiskExplanation:
    """A single contributing signal with its point contribution."""
    signal_key: str
    points: int
    label: str

    def as_dict(self) -> dict:
        sign = "+" if self.points >= 0 else ""
        return {
            "signal": self.signal_key,
            "points": self.points,
            "label": f"{self.label} ({sign}{self.points} pts)",
        }


@dataclasses.dataclass
class RiskResult:
    """Full risk assessment result with score, level, verdict, and explanations."""
    score: int                          # 0–100
    risk_level: str                     # "low" | "medium" | "high"
    verdict: str                        # "SAFE" | "SUSPICIOUS" | "PHISHING"
    ml_contribution: int                # Points from ML model (0–50)
    heuristic_contribution: int         # Points from heuristic signals
    explanations: list[RiskExplanation]
    ml_score: Optional[float] = None    # Raw ML output (0.0–1.0), if available

    @property
    def top_reasons(self) -> list[str]:
        """Return the top 3 reason labels sorted by absolute point contribution."""
        sorted_expl = sorted(self.explanations, key=lambda e: abs(e.points), reverse=True)
        return [e.label for e in sorted_expl[:3]]

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "ml_contribution": self.ml_contribution,
            "heuristic_contribution": self.heuristic_contribution,
            "ml_score": self.ml_score,
            "explanations": [e.as_dict() for e in self.explanations],
            "top_reasons": self.top_reasons,
        }


# ── Core scoring function ─────────────────────────────────────────────────────

def compute_risk_score(
    features: dict,
    ml_score: Optional[float] = None,
) -> RiskResult:
    """Compute a 0–100 risk score with per-signal explanations.

    Args:
        features: Feature dict from ``URLFeatureExtractor.extract_features()``.
        ml_score: Optional ML model probability output (0.0–1.0). When
            provided, it contributes up to 50 points to the base score.

    Returns:
        :class:`RiskResult` with score, risk level, verdict, and explanations.
    """
    explanations: list[RiskExplanation] = []

    # ── ML contribution (0–50 points) ─────────────────────────────────────
    ml_pts = 0
    if ml_score is not None:
        ml_pts = int(round(ml_score * 50))
        explanations.append(RiskExplanation(
            signal_key="ml_model",
            points=ml_pts,
            label=f"ML classifier score {ml_score:.2f} → {ml_pts} base pts",
        ))

    # ── Heuristic signals ─────────────────────────────────────────────────
    heuristic_pts = 0
    for sig in _SIGNALS:
        triggered = sig["condition"](features)
        if not triggered:
            continue

        multiplier_key = sig.get("multiplier_key")
        if multiplier_key:
            count = int(features.get(multiplier_key, 0))
            raw_pts = sig["points"] * count
            max_pts = sig.get("max_points", raw_pts)
            pts = int(min(raw_pts, max_pts)) if max_pts > 0 else int(max(raw_pts, -max_pts))
            label = sig.get("label_template", sig.get("label", sig["key"])).replace(
                "{count}", str(count)
            )
        else:
            pts = sig["points"]
            label = sig.get("label", sig["key"])

        heuristic_pts += pts
        explanations.append(RiskExplanation(
            signal_key=sig["key"],
            points=pts,
            label=label,
        ))

    # ── Final score ───────────────────────────────────────────────────────
    raw_score = ml_pts + heuristic_pts
    score = max(0, min(100, raw_score))

    # ── Risk classification ───────────────────────────────────────────────
    if score >= SCORE_HIGH:
        risk_level = "high"
        verdict = "PHISHING"
    elif score >= SCORE_MEDIUM:
        risk_level = "medium"
        verdict = "SUSPICIOUS"
    else:
        risk_level = "low"
        verdict = "SAFE"

    return RiskResult(
        score=score,
        risk_level=risk_level,
        verdict=verdict,
        ml_contribution=ml_pts,
        heuristic_contribution=heuristic_pts,
        explanations=explanations,
        ml_score=ml_score,
    )


# ── Convenience wrapper ───────────────────────────────────────────────────────

def score_url(url: str, ml_score: Optional[float] = None) -> RiskResult:
    """Extract features from ``url`` and compute the risk score.

    Args:
        url: Raw URL string.
        ml_score: Optional ML model probability (0.0–1.0).

    Returns:
        :class:`RiskResult` with full explainability.
    """
    from utils.feature_extractor import URLFeatureExtractor  # local import avoids circular

    features = URLFeatureExtractor(url).extract_features()
    return compute_risk_score(features, ml_score=ml_score)
