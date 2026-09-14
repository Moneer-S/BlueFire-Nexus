"""In-memory narrowing of one immutable broker enrollment; replay never resets usage."""

from __future__ import annotations

from typing import Any, Mapping

from .ai_broker_contract import BrokerEnrollment
from .ai_live_authorization import (
    COUNTERS,
    refused,
    request_reservation,
    reserve_usage,
    validate_authorization,
)


class BrokerLiveAuthorizations:
    def __init__(self, enrollment: BrokerEnrollment) -> None:
        self.enrollment = enrollment
        self.grants: dict[str, dict[str, Any]] = {}
        self.current: str | None = None

    def authorize(self, value: Mapping[str, Any]) -> str:
        self.enrollment.require_current(self.enrollment.config)
        grant = validate_authorization(
            value, config=self.enrollment.config, context_digest=self.enrollment.digest
        )
        if (
            grant["context"]["kind"] != "broker"
            or grant["expires_at_ms"] > self.enrollment.expires_at_ms
            or set(grant["purposes"]) - {name for name, _ in self.enrollment.schemas}
        ):
            raise refused("live_context_unavailable")
        identity = str(grant["authorization_id"])
        prior = self.grants.get(identity)
        if prior is not None:
            if (
                prior["document"] != grant
                or prior["status"] != "active"
                or self.current != identity
            ):
                raise refused("live_authorization_invalid")
            return identity
        if len(self.grants) >= 64:
            raise refused("live_usage_exhausted")
        if self.current is not None:
            self.grants[self.current]["status"] = "revoked"
        self.grants[identity] = {
            "document": grant,
            "status": "active",
            "usage": dict.fromkeys(COUNTERS, 0),
        }
        self.current = identity
        return identity

    def revoke(self, identity: str) -> str:
        if identity not in self.grants:
            raise refused("live_authorization_invalid")
        self.grants[identity]["status"] = "revoked"
        if self.current == identity:
            self.current = None
        return identity

    def reserve(self, body: bytes) -> int:
        if self.current is None:
            raise refused()
        row = self.grants[self.current]
        grant = row["document"]
        validate_authorization(
            grant, config=self.enrollment.config, context_digest=self.enrollment.digest
        )
        reservation = request_reservation(self.enrollment.config, body, grant)
        row["usage"] = reserve_usage(row["usage"], grant["limits"], reservation)
        return int(grant["expires_at_ms"])
