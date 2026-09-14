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


def public_job_failure(error: Exception) -> dict[str, str]:
    """Expose reviewed recovery guidance without copying arbitrary error text."""
    if isinstance(error, APIError):
        messages = {
            "run_record_incomplete": "The run stopped and cleanup was reconciled, but its interrupted attempt could not be durably recorded.",
            "replay_record_incomplete": "The replay stopped and cleanup was reconciled, but its interrupted attempt could not be durably recorded.",
            "run_cleanup_deferred": "The run stopped, but cleanup could not be reconciled. Inspect the retained result before starting again.",
            "replay_cleanup_deferred": "The replay stopped, but cleanup could not be reconciled. Inspect the retained result before starting again.",
        }
        if error.code in messages:
            return {
                "code": error.code,
                "message": messages[error.code],
                "exception_type": type(error).__name__,
            }
    return {
        "code": "execution_callback_failed",
        "message": "execution callback failed",
        "exception_type": type(error).__name__,
    }


__all__ = ["APIError"]
