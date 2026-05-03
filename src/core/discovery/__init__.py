"""Host, service, and account discovery helpers (lazy: pulls psutil on first use)."""

from __future__ import annotations

from typing import Any

__all__ = ["Discovery"]


def __getattr__(name: str) -> Any:
    if name == "Discovery":
        from .discovery import Discovery

        return Discovery
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
