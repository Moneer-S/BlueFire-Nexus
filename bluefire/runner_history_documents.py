"""Strict historical native document shapes, without executing or renewing them."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .runner_contracts import (
    EFFECT_CAPABILITIES,
    seal_manifest,
    seal_profile,
    validate_reviewed_manifest,
)
from .util import canonical_json_bytes, parse_iso8601_datetime

_MANIFEST_REQUIRED = frozenset(
    {
        "schema_version",
        "request_id",
        "run_id",
        "step_id",
        "behavior_id",
        "action_id",
        "mode",
        "runner_id",
        "runner_profile_id",
        "platform",
        "requested_at",
        "expires_at",
        "params",
        "target_scope",
        "required_capabilities",
        "safety_tier",
        "limits",
        "cleanup_action_id",
        "policy_digest",
        "request_hash",
    }
)
_MANIFEST_OPTIONAL = frozenset(
    {"execution_binding", "provider_binding", "reviewed_operation", "approval", "evidence_refs"}
)
_PROFILE_REQUIRED = frozenset(
    {
        "schema_version",
        "profile_id",
        "runner_id",
        "platform",
        "sandbox_root",
        "allowed_actions",
        "capabilities",
        "max_safety_tier",
        "target_scope",
        "limits",
        "policy_digest",
    }
)
_PROFILE_OPTIONAL = frozenset(
    {
        "reviewed_execution",
        "control_blocked_actions",
        "action_bindings",
        "provider_bindings",
        "provider_artifacts",
        "approval_required_at_or_above",
    }
)
_LIMIT_FIELDS = frozenset(
    {"timeout_ms", "max_stdout_bytes", "max_stderr_bytes", "max_artifact_bytes", "max_files"}
)
_TIERS = {"safe", "controlled", "restricted"}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("historical native document schema is invalid")


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and bool(item) for item in value)


def _scope(value: Any) -> None:
    _require(isinstance(value, dict) and not set(value) - {"filesystem", "network"})
    _require(_strings(value.get("filesystem", [])))
    network = value.get("network", [])
    _require(isinstance(network, list))
    for destination in network:
        _require(isinstance(destination, dict) and set(destination) == {"host", "port"})
        _require(isinstance(destination["host"], str) and bool(destination["host"]))
        _require(type(destination["port"]) is int and 0 <= destination["port"] <= 65535)


def _common(
    document: Mapping[str, Any], required: frozenset[str], optional: frozenset[str]
) -> None:
    _require(required <= document.keys() and not document.keys() - required - optional)
    structured = {
        "params",
        "target_scope",
        "limits",
        "required_capabilities",
        "capabilities",
        "allowed_actions",
    }
    for field in required - structured:
        _require(isinstance(document[field], str) and bool(document[field]))
    limits = document["limits"]
    _require(isinstance(limits, dict) and set(limits) == _LIMIT_FIELDS)
    _require(all(type(value) is int and 0 <= value <= (2**64 - 1) for value in limits.values()))
    _scope(document["target_scope"])


def validate_history_documents(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    platform: str,
    sandbox: Path,
) -> None:
    """Accept supported native shapes and exact old sandbox; never refresh expiry."""
    _common(manifest, _MANIFEST_REQUIRED, _MANIFEST_OPTIONAL)
    _common(profile, _PROFILE_REQUIRED, _PROFILE_OPTIONAL)
    _require(
        manifest["mode"] == "execute" and manifest["platform"] == profile["platform"] == platform
    )
    stored_sandbox = Path(profile["sandbox_root"])
    _require(stored_sandbox.is_absolute() and stored_sandbox == sandbox)
    _require(stored_sandbox.resolve(strict=True) == sandbox.resolve(strict=True))
    _require(isinstance(manifest["params"], dict))
    for document, field in ((manifest, "required_capabilities"), (profile, "capabilities")):
        _require(_strings(document[field]))
        _require(set(document[field]) <= set(EFFECT_CAPABILITIES.values()))
    _require(_strings(profile["allowed_actions"]))
    _require(_strings(profile.get("control_blocked_actions", [])))
    _require(_strings(manifest.get("evidence_refs", [])))
    _require(manifest["safety_tier"] in _TIERS and profile["max_safety_tier"] in _TIERS)
    _require(profile.get("approval_required_at_or_above") in _TIERS | {None})
    requested = parse_iso8601_datetime(manifest["requested_at"])
    expires = parse_iso8601_datetime(manifest["expires_at"])
    _require(requested.tzinfo is not None and expires.tzinfo is not None and requested <= expires)
    approval = manifest.get("approval")
    if approval is not None:
        _require(
            isinstance(approval, dict)
            and set(approval) == {"approved_by", "approved_at", "expires_at", "request_hash"}
        )
        _require(all(isinstance(value, str) and bool(value) for value in approval.values()))
        approved_at = parse_iso8601_datetime(approval["approved_at"])
        approval_expiry = parse_iso8601_datetime(approval["expires_at"])
        _require(
            approved_at.tzinfo is not None
            and approval_expiry.tzinfo is not None
            and approved_at <= approval_expiry
        )
        _require(approval["request_hash"] == manifest["request_hash"])
    _require(canonical_json_bytes(seal_profile(profile)) == canonical_json_bytes(profile))
    _require(canonical_json_bytes(seal_manifest(manifest)) == canonical_json_bytes(manifest))
    validate_reviewed_manifest(manifest, profile)
