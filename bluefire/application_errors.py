"""Errors shared by application services and transport adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class APIError(Exception):
    """Safe, explicit application error that may cross an HTTP boundary."""

    status: int
    code: str
    message: str
    details: Any | None = None


__all__ = ["APIError"]
