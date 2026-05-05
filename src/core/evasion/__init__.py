"""Consolidated defense-evasion and anti-detection managers (catalog / simulation helpers)."""

from .anti_detection import AntiDetection
from .defense_evasion import DefenseEvasionManager

__all__ = ["AntiDetection", "DefenseEvasionManager"]
