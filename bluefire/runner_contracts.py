"""Sealed JSON contracts for the Rust runner boundary.

The control-plane catalog exposes stable logical behavior parameters.  The
runner receives a separate, lower-level manifest produced only after typed
artifact binding and policy evaluation.  Hashing here mirrors ``runner``'s
canonical serde representation.
"""

from __future__ import annotations

import os
import platform as host_platform
import re
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
    "native.execution": "native_execution",
    "sandbox.restricted": "sandbox_restricted",
    "filesystem.read": "filesystem_read",
    "filesystem.write": "filesystem_write",
    "process.spawn": "process_spawn",
    "process.discovery": "process_discovery",
    "system.discovery": "system_discovery",
    "network.loopback": "network_loopback",
    "export.local": "export_local",
    "cleanup": "cleanup",
}

_TIER_RANK = {
    SafetyTier.SAFE: 1,
    SafetyTier.CONTROLLED: 2,
    SafetyTier.RESTRICTED: 3,
}

_RFC3339_MICROSECONDS = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})"
)
_EXECUTION_BINDING_SCHEMA = "bluefire.runner-execution-binding.v1"
_ACTION_PROGRAM_SCHEMA = "bluefire.action-program.v1"
_ACTION_PROGRAM_ADAPTER = "bluefire.builtin-runner-adapter.v1"
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PACKAGE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_EXECUTION_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "catalog_generation",
        "catalog_digest",
        "logical_behavior_id",
        "logical_action_id",
        "package_id",
        "package_version",
        "package_digest",
        "content_digest",
        "program_digest",
        "runner_opcode",
        "opcode_contract_digest",
        "constants",
    }
)
_REVIEWED_PROGRAM_CONSTANTS: Mapping[str, Mapping[str, Any]] = {
    "endpoint.discovery.processes.v1": {},
    "endpoint.discovery.system.v1": {},
    "sandbox.execution.native-canary.v1": {},
    "sandbox.identity-material.inspect.v1": {},
    "sandbox.identity-material.seed.v1": {},
    "sandbox.observability.variant.v1": {},
    "sandbox.peer.handoff.v1": {"method": "POST"},
    "sandbox.archive.tar.v1": {"archive_format": "ustar"},
    "sandbox.cleanup.v1": {},
    "sandbox.collection.stage.v1": {},
    "sandbox.discovery.list.v1": {},
    "sandbox.discovery.metadata.v1": {},
    "sandbox.discovery.recursive.v1": {},
    "sandbox.export.local.v1": {},
    "sandbox.fixture.create.v1": {"content_template": "telemetry-seed"},
    "sandbox.fixture.transform.v1": {},
    "sandbox.network.loopback.v1": {"method": "POST"},
    "sandbox.restricted.persistence-marker.v1": {"marker_kind": "detection-canary"},
}


def _format_rust_datetime(value: datetime, *, context: str) -> str:
    """Match chrono's RFC 3339 ``AutoSi`` representation exactly."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise RunnerContractError(f"{context} must include a timezone offset")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond == 0:
        timespec = "seconds"
    elif normalized.microsecond % 1_000 == 0:
        timespec = "milliseconds"
    else:
        timespec = "microseconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _normalize_rust_datetime(value: str, *, context: str) -> str:
    if _RFC3339_MICROSECONDS.fullmatch(value) is None:
        raise RunnerContractError(f"{context} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RunnerContractError(f"{context} must be an RFC 3339 timestamp") from exc
    return _format_rust_datetime(parsed, context=context)


def _canonical_execution_binding(
    value: Mapping[str, Any],
    *,
    context: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _EXECUTION_BINDING_FIELDS:
        raise RunnerContractError(f"{context} must have the exact execution-binding fields")
    if value.get("schema_version") != _EXECUTION_BINDING_SCHEMA:
        raise RunnerContractError(f"{context}.schema_version is unsupported")
    generation = value.get("catalog_generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= (1 << 63) - 1
    ):
        raise RunnerContractError(f"{context}.catalog_generation is invalid")
    digests: dict[str, str] = {}
    for field in (
        "catalog_digest",
        "package_digest",
        "content_digest",
        "program_digest",
        "opcode_contract_digest",
    ):
        digest = value.get(field)
        if not isinstance(digest, str) or _SHA256_DIGEST.fullmatch(digest) is None:
            raise RunnerContractError(f"{context}.{field} must be exact lowercase SHA-256")
        digests[field] = digest
    identifiers: dict[str, str] = {}
    for field in ("logical_behavior_id", "logical_action_id", "runner_opcode"):
        identifier = value.get(field)
        if (
            not isinstance(identifier, str)
            or len(identifier) > 128
            or _STABLE_ID.fullmatch(identifier) is None
        ):
            raise RunnerContractError(f"{context}.{field} is invalid")
        identifiers[field] = identifier
    package_id = value.get("package_id")
    if (
        not isinstance(package_id, str)
        or len(package_id) > 128
        or _PACKAGE_ID.fullmatch(package_id) is None
    ):
        raise RunnerContractError(f"{context}.package_id is invalid")
    package_version = value.get("package_version")
    if not isinstance(package_version, str):
        raise RunnerContractError(f"{context}.package_version is invalid")
    match = _SEMVER.fullmatch(package_version)
    if (
        match is None
        or len(package_version) > 128
        or any(int(match.group(index)) > (1 << 64) - 1 for index in (1, 2, 3))
        or any(
            part.isdigit() and len(part) > 1 and part.startswith("0")
            for part in (match.group(4) or "").split(".")
        )
    ):
        raise RunnerContractError(f"{context}.package_version is invalid")
    constants = value.get("constants")
    if not isinstance(constants, Mapping) or len(constants) > 32:
        raise RunnerContractError(f"{context}.constants must be a bounded object")
    opcode = identifiers["runner_opcode"]
    expected_constants = _REVIEWED_PROGRAM_CONSTANTS.get(opcode)
    if expected_constants is None or dict(constants) != dict(expected_constants):
        raise RunnerContractError(
            f"{context}.constants do not exactly match the reviewed runner opcode"
        )
    canonical_constants = dict(sorted(dict(constants).items()))
    program = {
        "schema_version": _ACTION_PROGRAM_SCHEMA,
        "steps": [
            {
                "opcode": opcode,
                "adapter": _ACTION_PROGRAM_ADAPTER,
                "constants": canonical_constants,
            }
        ],
    }
    if digests["program_digest"] != content_hash(program):
        raise RunnerContractError(f"{context}.program_digest does not match its program")
    return {
        "schema_version": _EXECUTION_BINDING_SCHEMA,
        "catalog_generation": generation,
        "catalog_digest": digests["catalog_digest"],
        "logical_behavior_id": identifiers["logical_behavior_id"],
        "logical_action_id": identifiers["logical_action_id"],
        "package_id": package_id,
        "package_version": package_version,
        "package_digest": digests["package_digest"],
        "content_digest": digests["content_digest"],
        "program_digest": digests["program_digest"],
        "runner_opcode": opcode,
        "opcode_contract_digest": digests["opcode_contract_digest"],
        "constants": canonical_constants,
    }


def _canonical_action_bindings(
    value: Sequence[Mapping[str, Any]],
    *,
    context: str,
) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) > 512:
        raise RunnerContractError(f"{context} must be a bounded list")
    bindings = [
        _canonical_execution_binding(item, context=f"{context}[{index}]")
        for index, item in enumerate(value)
    ]
    pairs = [(binding["logical_behavior_id"], binding["logical_action_id"]) for binding in bindings]
    if len(pairs) != len(set(pairs)):
        raise RunnerContractError(f"{context} contains a duplicate logical behavior/action pair")
    identities = {
        (binding["catalog_generation"], binding["catalog_digest"]) for binding in bindings
    }
    if len(identities) > 1:
        raise RunnerContractError(f"{context} spans more than one catalog generation")
    return sorted(
        bindings,
        key=lambda item: (str(item["logical_behavior_id"]), str(item["logical_action_id"])),
    )


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
    if "action_bindings" in sealed:
        raw_bindings = sealed["action_bindings"]
        if not isinstance(raw_bindings, list):
            raise RunnerContractError("runner profile action_bindings must be a list")
        bindings = _canonical_action_bindings(
            raw_bindings,
            context="runner profile action_bindings",
        )
        if bindings:
            sealed["action_bindings"] = bindings
        else:
            sealed.pop("action_bindings")
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
    action_bindings: Sequence[Mapping[str, Any]] = (),
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
    bindings = _canonical_action_bindings(
        action_bindings,
        context="runner profile action_bindings",
    )
    allowed_actions = set(profile.enabled_actions)
    blocked_actions = set(profile.blocked_actions)
    for binding in bindings:
        logical_action = str(binding["logical_action_id"])
        opcode = str(binding["runner_opcode"])
        if logical_action not in allowed_actions:
            raise RunnerContractError("runner profile action binding logical action is not enabled")
        if opcode not in allowed_actions or opcode in blocked_actions:
            raise RunnerContractError(
                "runner profile action binding cannot bypass backing opcode policy"
            )
    profile_doc: dict[str, Any] = {
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
    if bindings:
        profile_doc["action_bindings"] = bindings
    return seal_profile(profile_doc)


def seal_manifest(document: Mapping[str, Any]) -> dict[str, Any]:
    sealed: dict[str, Any] = dict(json_clone(document))
    if sealed.get("schema_version") != "bluefire.runner-manifest.v1":
        raise RunnerContractError("runner manifest schema version is unsupported")
    if "execution_binding" in sealed:
        raw_binding = sealed["execution_binding"]
        if not isinstance(raw_binding, Mapping):
            raise RunnerContractError("runner execution_binding must be an object")
        sealed["execution_binding"] = _canonical_execution_binding(
            raw_binding,
            context="runner execution_binding",
        )
    approval = sealed.get("approval")
    if approval is not None:
        if not isinstance(approval, dict):
            raise RunnerContractError("runner approval must be an object")
    for field in ("requested_at", "expires_at"):
        value = sealed.get(field)
        if not isinstance(value, str):
            raise RunnerContractError(f"manifest {field} must be an explicit string")
        sealed[field] = _normalize_rust_datetime(value, context=f"manifest {field}")
    sealed["request_hash"] = ""
    if isinstance(approval, dict):
        for field in ("approved_at", "expires_at"):
            value = approval.get(field)
            if not isinstance(value, str):
                raise RunnerContractError(f"approval {field} must be an explicit string")
            approval[field] = _normalize_rust_datetime(value, context=f"approval {field}")
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
    approval_record: Mapping[str, Any] | None,
    execution_binding: Mapping[str, Any] | None = None,
    resolved_cleanup_action_id: str | None = None,
    timeout_ms: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = timestamp + timedelta(minutes=5)
    requested_at = _format_rust_datetime(timestamp, context="manifest requested_at")
    expires_at = _format_rust_datetime(expires, context="manifest expires_at")
    approval = None
    if approval_record is not None:
        raw_identity = approval_record.get("approved_by")
        identity = raw_identity.strip() if isinstance(raw_identity, str) else ""
        if not identity or len(identity) > 128:
            raise RunnerContractError("approval identity must contain 1..=128 characters")
        approved_at = approval_record.get("approved_at")
        approval_expires_at = approval_record.get("expires_at")
        if not isinstance(approved_at, str) or not isinstance(approval_expires_at, str):
            raise RunnerContractError("approval timestamps must be explicit strings")
        approval = {
            "approved_by": identity,
            "approved_at": _normalize_rust_datetime(approved_at, context="approval approved_at"),
            "expires_at": _normalize_rust_datetime(
                approval_expires_at, context="approval expires_at"
            ),
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
    binding = (
        None
        if execution_binding is None
        else _canonical_execution_binding(
            execution_binding,
            context="runner execution_binding",
        )
    )
    if binding is not None:
        if (
            binding["logical_behavior_id"] != behavior_id
            or binding["logical_action_id"] != action.id
        ):
            raise RunnerContractError(
                "runner execution binding does not match the logical behavior/action"
            )
        profile_bindings = runner_profile.get("action_bindings")
        if not isinstance(profile_bindings, list):
            raise RunnerContractError(
                "runner execution binding is absent from the sealed runner profile"
            )
        canonical_profile_bindings = _canonical_action_bindings(
            profile_bindings,
            context="runner profile action_bindings",
        )
        if binding not in canonical_profile_bindings:
            raise RunnerContractError(
                "runner execution binding does not exactly match the sealed runner profile"
            )
        for name, constant in binding["constants"].items():
            if name in params and params[name] != constant:
                raise RunnerContractError(
                    "runner parameters conflict with a reviewed execution-binding constant"
                )
    profile_limits = runner_profile.get("limits")
    if not isinstance(profile_limits, Mapping):
        raise RunnerContractError("runner profile limits are missing")
    maximum_timeout = profile_limits.get("timeout_ms")
    if isinstance(maximum_timeout, bool) or not isinstance(maximum_timeout, int):
        raise RunnerContractError("runner profile timeout is invalid")
    effective_timeout = maximum_timeout if timeout_ms is None else timeout_ms
    if (
        isinstance(effective_timeout, bool)
        or not isinstance(effective_timeout, int)
        or not 1 <= effective_timeout <= maximum_timeout
    ):
        raise RunnerContractError("manifest timeout must be within the runner profile limit")
    manifest_limits = dict(profile_limits)
    manifest_limits["timeout_ms"] = effective_timeout
    if resolved_cleanup_action_id is not None and (
        not isinstance(resolved_cleanup_action_id, str)
        or resolved_cleanup_action_id != "sandbox.cleanup.v1"
    ):
        raise RunnerContractError("resolved native cleanup action must be sandbox.cleanup.v1")
    cleanup_action = (
        resolved_cleanup_action_id
        or ("sandbox.cleanup.v1" if binding is not None else action.cleanup_action_id)
        or "sandbox.cleanup.v1"
    )
    if cleanup_action != "sandbox.cleanup.v1":
        raise RunnerContractError("native runner cleanup action must be sandbox.cleanup.v1")
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
        "limits": manifest_limits,
        "cleanup_action_id": cleanup_action,
        "policy_digest": policy_digest,
        "approval": approval,
        "evidence_refs": list(evidence_refs),
        "request_hash": "",
    }
    if binding is not None:
        document["execution_binding"] = binding
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
