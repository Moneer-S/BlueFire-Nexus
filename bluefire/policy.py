"""Deny-by-default policy evaluation for Execute manifests."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from .config import RunnerProfile
from .contracts import ActionDefinition, ExecutionMode, SafetyTier
from .planner import PlanStep
from .util import content_hash


class PolicyError(ValueError):
    pass


class PolicyStatus(str, Enum):
    ALLOWED = "allowed"
    REFUSED = "refused"
    CONTROL_BLOCKED = "control_blocked"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True, slots=True)
class ApprovalState:
    schema_version: str
    approved_by: str
    issued_at: str
    expires_at: str
    request_hash: str
    action_id: str
    runner_profile_id: str
    target_scope_digest: str
    nonce: str

    def validate(
        self,
        *,
        request_hash: str,
        action_id: str,
        runner_profile_id: str,
        target_scope_digest: str,
        now: datetime | None = None,
    ) -> None:
        if self.schema_version != "bluefire.approval.v1":
            raise PolicyError("approval schema version is unsupported")
        if not self.approved_by.strip() or not self.nonce.strip():
            raise PolicyError("approval identity and nonce are required")
        expected = (request_hash, action_id, runner_profile_id, target_scope_digest)
        actual = (
            self.request_hash,
            self.action_id,
            self.runner_profile_id,
            self.target_scope_digest,
        )
        if actual != expected:
            raise PolicyError("approval is not bound to this exact request")
        current = now or datetime.now(timezone.utc)
        issued = _parse_timestamp(self.issued_at)
        expires = _parse_timestamp(self.expires_at)
        if issued > current or expires <= current or expires <= issued:
            raise PolicyError("approval is not currently valid")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "approved_by": self.approved_by,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "request_hash": self.request_hash,
            "action_id": self.action_id,
            "runner_profile_id": self.runner_profile_id,
            "target_scope_digest": self.target_scope_digest,
            "nonce": self.nonce,
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    schema_version: str
    status: PolicyStatus
    step_id: str
    behavior_id: str
    action_id: str | None
    runner_profile_id: str | None
    reasons: tuple[str, ...]
    required_approvals: tuple[str, ...]
    evaluated_capabilities: tuple[str, ...]
    target_scope_digest: str
    policy_digest: str

    @property
    def allowed(self) -> bool:
        return self.status is PolicyStatus.ALLOWED

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "step_id": self.step_id,
            "behavior_id": self.behavior_id,
            "action_id": self.action_id,
            "runner_profile_id": self.runner_profile_id,
            "reasons": list(self.reasons),
            "required_approvals": list(self.required_approvals),
            "evaluated_capabilities": list(self.evaluated_capabilities),
            "target_scope_digest": self.target_scope_digest,
            "policy_digest": self.policy_digest,
        }


class PolicyEngine:
    def evaluate(
        self,
        *,
        step: PlanStep,
        action: ActionDefinition,
        mode: ExecutionMode,
        profile: RunnerProfile | None,
        platform: str,
        target_scope: Mapping[str, Any],
        request_hash: str,
        approval: ApprovalState | None,
    ) -> PolicyDecision:
        scope_digest = content_hash(target_scope)
        reasons: list[str] = []
        required_approvals: list[str] = []
        status = PolicyStatus.ALLOWED

        if mode is not ExecutionMode.EXECUTE:
            reasons.append("runner policy is not applicable to Simulate")
            status = PolicyStatus.REFUSED
        elif profile is None:
            reasons.append("Execute requires an explicit runner profile")
            status = PolicyStatus.REFUSED
        elif profile.mode is not ExecutionMode.EXECUTE:
            reasons.append("selected profile is not an Execute profile")
            status = PolicyStatus.REFUSED
        elif step.action_id != action.id:
            reasons.append("plan action does not match the registered action")
            status = PolicyStatus.REFUSED
        elif action.id not in profile.enabled_actions:
            reasons.append("action is disabled by the runner profile")
            status = PolicyStatus.REFUSED
        elif action.id in tuple(getattr(profile, "blocked_actions", ())):
            reasons.append("runner profile control blocks this action")
            status = PolicyStatus.CONTROL_BLOCKED

        if profile is not None and status is PolicyStatus.ALLOWED:
            declared_capabilities = set(step.required_capabilities) | set(action.capabilities)
            missing_capabilities = sorted(declared_capabilities - set(profile.capabilities))
            if missing_capabilities:
                reasons.append(
                    "profile lacks capabilities: " + ", ".join(sorted(set(missing_capabilities)))
                )
                status = PolicyStatus.REFUSED
            if (
                step.safety_tier not in profile.safety_tiers
                or action.safety_tier not in profile.safety_tiers
            ):
                reasons.append("profile does not authorize the requested safety tier")
                status = PolicyStatus.REFUSED
            profile_platforms = tuple(getattr(profile, "platforms", ("sandbox",)))
            if platform not in action.platforms or platform not in profile_platforms:
                reasons.append("action, profile, and requested platform do not intersect")
                status = PolicyStatus.REFUSED

        if profile is not None and status is PolicyStatus.ALLOWED:
            requested_refs = target_scope.get("scope_refs", [])
            if not isinstance(requested_refs, list) or not all(
                isinstance(item, str) for item in requested_refs
            ):
                reasons.append("target scope references are malformed")
                status = PolicyStatus.REFUSED
            elif not set(requested_refs).issubset(set(profile.scope)):
                reasons.append("target scope expands beyond the selected profile")
                status = PolicyStatus.REFUSED
            else:
                network_destination = target_scope.get("network_destination")
                if network_destination is not None and not self._network_allowed(
                    str(network_destination), tuple(getattr(profile, "network_allowlist", ()))
                ):
                    reasons.append("network destination is outside the profile allowlist")
                    status = PolicyStatus.REFUSED

        if profile is not None and status is PolicyStatus.ALLOWED:
            approval_needed = profile.approval_required or step.safety_tier is SafetyTier.RESTRICTED
            if approval_needed:
                required_approvals.append("operator")
                if approval is None:
                    reasons.append("an operator approval bound to this request is required")
                    status = PolicyStatus.APPROVAL_REQUIRED
                else:
                    try:
                        approval.validate(
                            request_hash=request_hash,
                            action_id=action.id,
                            runner_profile_id=profile.id,
                            target_scope_digest=scope_digest,
                        )
                    except PolicyError as exc:
                        reasons.append(str(exc))
                        status = PolicyStatus.APPROVAL_REQUIRED

        if status is PolicyStatus.ALLOWED:
            reasons.append("request is within the registered action and selected profile")
        digest_body = {
            "status": status.value,
            "step_id": step.step_id,
            "behavior_id": step.behavior_id,
            "action_id": step.action_id,
            "runner_profile_id": profile.id if profile else None,
            "reasons": reasons,
            "capabilities": list(step.required_capabilities),
            "target_scope_digest": scope_digest,
        }
        return PolicyDecision(
            schema_version="bluefire.policy-decision.v1",
            status=status,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            runner_profile_id=profile.id if profile else None,
            reasons=tuple(reasons),
            required_approvals=tuple(required_approvals),
            evaluated_capabilities=step.required_capabilities,
            target_scope_digest=scope_digest,
            policy_digest=content_hash(digest_body),
        )

    @staticmethod
    def _network_allowed(destination: str, allowlist: tuple[str, ...]) -> bool:
        try:
            host, separator, port_text = destination.rpartition(":")
            if not separator or not port_text.isdigit():
                return False
            address = ipaddress.ip_address(host.strip("[]"))
            port = int(port_text)
        except ValueError:
            return False
        if not 1 <= port <= 65535 or not address.is_loopback:
            return False
        networks = []
        for item in allowlist:
            try:
                networks.append(ipaddress.ip_network(item, strict=True))
            except ValueError:
                return False
        return any(
            address.version == network.version and address in network for network in networks
        )


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError("approval timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise PolicyError("approval timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


__all__ = [
    "ApprovalState",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyError",
    "PolicyStatus",
]
