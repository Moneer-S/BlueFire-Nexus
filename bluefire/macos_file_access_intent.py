"""Inactive reviewed Darwin task data, never creator custody or task authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .macos_file_access_contract import MAX_OPERATION_NS, MacOSFileAccessContractError

_OPERATIONS = ("baseline", "harden", "probe", "verify_owner", "rollback", "close_attempt")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = set(
    "schema_version operation task_id transport_request_hash context_digest binding_digest control_revision issued_at_ms expires_at_ms issued_monotonic_ns deadline_ns".split()
)


def _require(value: bool) -> None:
    if not value:
        raise MacOSFileAccessContractError("The original Darwin creator operation is unavailable.")


def _intent(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == _FIELDS)
    _require(
        value["schema_version"] == "bluefire.macos-file-access-reviewed-task.v1"
        and type(value["operation"]) is str
        and value["operation"] in _OPERATIONS
    )
    for field in ("transport_request_hash", "context_digest", "binding_digest"):
        _require(type(value[field]) is str and _DIGEST.fullmatch(value[field]) is not None)
    _require(
        type(value["task_id"]) is str
        and value["task_id"] == "execute-" + value["transport_request_hash"][7:]
    )
    for field in (
        "control_revision",
        "issued_at_ms",
        "expires_at_ms",
        "issued_monotonic_ns",
        "deadline_ns",
    ):
        _require(type(value[field]) is int and 0 < value[field] < 2**64)
    _require(
        value["control_revision"] < 2**31
        and value["expires_at_ms"] < 2**63
        and 0 < value["expires_at_ms"] - value["issued_at_ms"] <= 5000
        and 0 < value["deadline_ns"] - value["issued_monotonic_ns"] <= MAX_OPERATION_NS
    )
    return dict(value)


@dataclass(frozen=True)
class ReviewedMacOSTaskIntent:
    """Inactive canonical data, not an approval or producer reservation."""

    _document: dict[str, Any]

    @classmethod
    def from_document(cls, value: Any) -> ReviewedMacOSTaskIntent:
        return cls(_intent(value))

    def document(self) -> dict[str, Any]:
        return _intent(self._document)
