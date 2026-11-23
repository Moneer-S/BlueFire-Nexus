"""Read-only contracts for optional platform and security data adapters.

These interfaces make configuration readiness explicit without treating an
unconfigured cloud, SIEM, EDR, Event Log, or audit service as evidence.
Credentials are represented only by references resolved by a deployment-owned
secret provider; raw credential values are not accepted by this contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol

from .collectors import CollectorDescriptor, CollectorHealth


class CollectorAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BoundedAdapterQuery:
    query_template_id: str
    scope_ref: str
    start_at: str
    end_at: str
    max_records: int
    max_bytes: int
    credential_reference: str | None = None

    def __post_init__(self) -> None:
        for label, value, maximum in (
            ("query_template_id", self.query_template_id, 200),
            ("scope_ref", self.scope_ref, 500),
            ("start_at", self.start_at, 40),
            ("end_at", self.end_at, 40),
        ):
            if not isinstance(value, str) or not value or len(value) > maximum or "\0" in value:
                raise CollectorAdapterError(f"adapter {label} is invalid")
        try:
            start = datetime.fromisoformat(self.start_at.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.end_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CollectorAdapterError("adapter query timestamps are invalid") from exc
        if start.tzinfo is None or end.tzinfo is None or start > end:
            raise CollectorAdapterError("adapter query time window is invalid")
        if (
            isinstance(self.max_records, bool)
            or not isinstance(self.max_records, int)
            or not 1 <= self.max_records <= 100_000
            or isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or not 1 <= self.max_bytes <= 64 * 1024 * 1024
        ):
            raise CollectorAdapterError("adapter query bounds are invalid")
        if self.credential_reference is not None and (
            not isinstance(self.credential_reference, str)
            or not self.credential_reference.startswith("secret-ref:")
            or len(self.credential_reference) > 500
        ):
            raise CollectorAdapterError("adapter credential must be an opaque secret reference")


@dataclass(frozen=True, slots=True)
class AdapterPage:
    records: tuple[Mapping[str, Any], ...]
    next_cursor: str | None
    complete: bool


class WindowsEventLogAdapter(Protocol):
    descriptor: CollectorDescriptor

    def readiness(self) -> CollectorHealth: ...

    def query_registered_xpath(self, request: BoundedAdapterQuery) -> AdapterPage: ...


class LinuxAuditRuntimeAdapter(Protocol):
    descriptor: CollectorDescriptor

    def readiness(self) -> CollectorHealth: ...

    def query_audit_or_journal(self, request: BoundedAdapterQuery) -> AdapterPage: ...


class CloudIdentityAuditAdapter(Protocol):
    descriptor: CollectorDescriptor

    def readiness(self) -> CollectorHealth: ...

    def query_identity_audit(self, request: BoundedAdapterQuery) -> AdapterPage: ...


class SecurityQueryAdapter(Protocol):
    """Shared bounded query surface for SIEM and EDR providers."""

    descriptor: CollectorDescriptor

    def readiness(self) -> CollectorHealth: ...

    def query_registered_template(self, request: BoundedAdapterQuery) -> AdapterPage: ...


__all__ = [
    "AdapterPage",
    "BoundedAdapterQuery",
    "CloudIdentityAuditAdapter",
    "CollectorAdapterError",
    "LinuxAuditRuntimeAdapter",
    "SecurityQueryAdapter",
    "WindowsEventLogAdapter",
]
