"""Sealed JSON contracts for the Rust runner boundary.

The control-plane catalog exposes stable logical behavior parameters.  The
runner receives a separate, lower-level manifest produced only after typed
artifact binding and policy evaluation.  Hashing here mirrors ``runner``'s
canonical serde representation.
"""

from __future__ import annotations

import os
import platform as host_platform
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .config import EnvironmentReference, RunnerProfile
from .contracts import ActionDefinition, SafetyTier
from .util import content_hash, json_clone


class RunnerContractError(ValueError):
    """Raised when a runner document cannot be safely constructed."""


EFFECT_CAPABILITIES: Mapping[str, str] = {
    "filesystem.read": "filesystem_read",
    "filesystem.write": "filesystem_write",
    "process.spawn": "process_spawn",
    "network.loopback": "network_loopback",
    "export.local": "export_local",
    "cleanup": "cleanup",
}

_TIER_RANK = {
    SafetyTier.SAFE: 1,
    SafetyTier.CONTROLLED: 2,
    SafetyTier.RESTRICTED: 3,
}


def current_platform() -> str:
    value = host_platform.system().casefold()
    if value == "darwin":
        return "macos"
    if value in {"windows", "linux"}:
        return value
    raise RunnerContractError(f"unsupported runner platform: {value or 'unknown'}")


def resolve_environment_path(
    reference: EnvironmentReference,
    *,
    environ: Mapping[str, str] | None = None,
    must_exist: bool,
) -> Path:
    values = os.environ if environ is None else environ
    raw = values.get(reference.env, "").strip()
    if not raw:
        raise RunnerContractError(f"required environment reference is unset: {reference.env}")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise RunnerContractError(f"{reference.env} must contain an absolute path")
    if must_exist and not path.is_file():
        raise RunnerContractError(f"{reference.env} does not identify a runner binary")
    if not must_exist:
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            raise RunnerContractError(f"{reference.env} does not identify a sandbox directory")
    return path.resolve(strict=must_exist)


def effect_capabilities(values: Sequence[str]) -> list[str]:
    result = [EFFECT_CAPABILITIES[value] for value in values if value in EFFECT_CAPABILITIES]
    if not result:
        raise RunnerContractError("runner actions must declare at least one effect capability")
    if len(result) != len(set(result)):
        raise RunnerContractError("runner effect capabilities contain duplicates")
    return result


def execution_limits(profile: RunnerProfile) -> dict[str, int]:
    return {
        "timeout_ms": profile.budgets.max_seconds * 1000,
        "max_stdout_bytes": min(profile.budgets.max_bytes, 1024 * 1024),
        "max_stderr_bytes": min(profile.budgets.max_bytes, 1024 * 1024),
        "max_artifact_bytes": profile.budgets.max_bytes,
        "max_files": profile.budgets.max_artifacts,
    }


def seal_profile(document: Mapping[str, Any]) -> dict[str, Any]:
    sealed: dict[str, Any] = dict(json_clone(document))
    if sealed.get("schema_version") != "bluefire.runner-profile.v1":
        raise RunnerContractError("runner profile schema version is unsupported")
    sealed["policy_digest"] = ""
    sealed["policy_digest"] = content_hash(sealed)
    return sealed


def build_runner_profile(
    profile: RunnerProfile,
    *,
    sandbox_root: str | Path,
    platform: str | None = None,
    filesystem_scope: Sequence[str] = ("fixtures", "staged", "exports"),
    network_destinations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    if profile.mode.value != "execute":
        raise RunnerContractError("only Execute profiles can be compiled for the Rust runner")
    sandbox = Path(sandbox_root)
    if not sandbox.is_absolute():
        raise RunnerContractError("runner sandbox root must be absolute")
    sandbox.mkdir(parents=True, exist_ok=True)
    actual_platform = platform or current_platform()
    if actual_platform not in profile.platforms:
        raise RunnerContractError("selected runner profile does not support this platform")
    tiers = sorted(profile.safety_tiers, key=_TIER_RANK.__getitem__)
    runner_capabilities = effect_capabilities(profile.capabilities)
    profile_doc = {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": profile.id,
        "runner_id": "bluefire-rust-runner.v1",
        "platform": actual_platform,
        "sandbox_root": str(sandbox.resolve(strict=True)),
        "allowed_actions": list(profile.enabled_actions),
        "control_blocked_actions": list(profile.blocked_actions),
        "capabilities": runner_capabilities,
        "max_safety_tier": tiers[-1].value,
        "approval_required_at_or_above": "safe" if profile.approval_required else None,
        "target_scope": {
            "filesystem": list(filesystem_scope),
            "network": [dict(item) for item in network_destinations],
        },
        "limits": execution_limits(profile),
        "policy_digest": "",
    }
    return seal_profile(profile_doc)


def seal_manifest(document: Mapping[str, Any]) -> dict[str, Any]:
    sealed: dict[str, Any] = dict(json_clone(document))
    if sealed.get("schema_version") != "bluefire.runner-manifest.v1":
        raise RunnerContractError("runner manifest schema version is unsupported")
    sealed["request_hash"] = ""
    approval = sealed.get("approval")
    if approval is not None:
        if not isinstance(approval, dict):
            raise RunnerContractError("runner approval must be an object")
        approval["request_hash"] = ""
    digest = content_hash(sealed)
    sealed["request_hash"] = digest
    if isinstance(approval, dict):
        approval["request_hash"] = digest
    return sealed


def build_execution_manifest(
    *,
    run_id: str,
    step_id: str,
    behavior_id: str,
    action: ActionDefinition,
    runner_profile: Mapping[str, Any],
    params: Mapping[str, Any],
    filesystem_scope: Sequence[str],
    network_destinations: Sequence[Mapping[str, Any]] = (),
    evidence_refs: Sequence[str] = (),
    approved_by: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = timestamp + timedelta(minutes=5)
    requested_at = timestamp.isoformat().replace("+00:00", "Z")
    expires_at = expires.isoformat().replace("+00:00", "Z")
    approval = None
    if approved_by is not None:
        identity = approved_by.strip()
        if not identity or len(identity) > 128:
            raise RunnerContractError("approval identity must contain 1..=128 characters")
        approval = {
            "approved_by": identity,
            "approved_at": requested_at,
            "expires_at": expires_at,
            "request_hash": "",
        }
    runner_id = runner_profile.get("runner_id")
    profile_id = runner_profile.get("profile_id")
    platform = runner_profile.get("platform")
    policy_digest = runner_profile.get("policy_digest")
    if not all(isinstance(value, str) and value for value in (runner_id, profile_id, platform)):
        raise RunnerContractError("runner profile identity fields are missing")
    if not isinstance(policy_digest, str) or not policy_digest.startswith("sha256:"):
        raise RunnerContractError("runner profile has no sealed policy digest")
    cleanup_action = action.cleanup_action_id or "sandbox.cleanup.v1"
    document = {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": f"request-{uuid.uuid4().hex}",
        "run_id": run_id,
        "step_id": step_id,
        "behavior_id": behavior_id,
        "action_id": action.id,
        "mode": "execute",
        "runner_id": runner_id,
        "runner_profile_id": profile_id,
        "platform": platform,
        "requested_at": requested_at,
        "expires_at": expires_at,
        "params": dict(params),
        "target_scope": {
            "filesystem": list(filesystem_scope),
            "network": [dict(item) for item in network_destinations],
        },
        "required_capabilities": effect_capabilities(action.capabilities),
        "safety_tier": action.safety_tier.value,
        "limits": dict(runner_profile["limits"]),
        "cleanup_action_id": cleanup_action,
        "policy_digest": policy_digest,
        "approval": approval,
        "evidence_refs": list(evidence_refs),
        "request_hash": "",
    }
    return seal_manifest(document)


__all__ = [
    "EFFECT_CAPABILITIES",
    "RunnerContractError",
    "build_execution_manifest",
    "build_runner_profile",
    "current_platform",
    "effect_capabilities",
    "execution_limits",
    "resolve_environment_path",
    "seal_manifest",
    "seal_profile",
]
