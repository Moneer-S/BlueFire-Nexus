"""Anti-detection manager (heavy checks load psutil on first anomaly use only)."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

__all__ = ["AntiDetectionManager", "anti_detection"]


@lru_cache(maxsize=1)
def _anti_detection_instance():  # type: ignore[misc]
    """Process-wide singleton; instantiates lazily."""
    from .manager_impl import AntiDetectionManager

    return AntiDetectionManager()


def __getattr__(name: str) -> Any:
    if name == "AntiDetectionManager":
        from .manager_impl import AntiDetectionManager

        return AntiDetectionManager
    if name == "anti_detection":
        return _anti_detection_instance()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
