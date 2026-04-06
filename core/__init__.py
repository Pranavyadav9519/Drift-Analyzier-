"""
core/__init__.py — Drift Analyzer shared detection logic

This package centralizes threat classification, remedy mapping,
and in-memory event logging so that every service speaks the same language.
"""

from .remedy_engine import RemedyEngine
from .threat_classifier import ThreatClassifier
from .logger import EventLogger

__all__ = ["RemedyEngine", "ThreatClassifier", "EventLogger"]
