"""Sealed JSON contracts for the Rust runner boundary.

The control-plane catalog exposes stable logical behavior parameters.  The
runner receives a separate, lower-level manifest produced only after typed
artifact binding and policy evaluation.  Hashing here mirrors ``runner``'s
canonical serde representation.
"""

from __future__ import annotations

import json
import os
import platform as host_platform
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .config import EnvironmentReference, RunnerProfile
from .contracts import ActionDefinition, ContractError, SafetyTier
from .native_tool_installations import canonical_native_tool_installations
from .provider_runner_contracts import (
    ProviderRunnerContractError,
    canonical_provider_artifacts,
    canonical_provider_binding,
    canonical_provider_bindings,
)
from .runner_reviewed_execution import (
    ReviewedExecutionError,
    canonical_reviewed_execution,
    canonical_reviewed_operation,
    reviewed_action_ids,
    validate_reviewed_manifest,
    validate_reviewed_profile,
)
from .util import canonical_json_bytes, content_hash, json_clone, parse_iso8601_datetime


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
    "cloud.aws.s3.access": "cloud_aws_s3_access",
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
_GRANT_ATTEMPT_FIELDS = frozenset(
    {
        "schema_version",
        "issuer",
        "grant_id",
        "grant_digest",
        "attempt_id",
        "lease_digest",
        "compiled_digest",
        "plan_digest",
        "native_envelope_digest",
        "run_id",
        "issued_at",
        "expires_at",
    }
)
_GRANT_CLEANUP_FIELDS = _GRANT_ATTEMPT_FIELDS | {
    "obligation_digest",
    "runner_policy_digest",
    "workspace_id",
    "receipts",
    "timeout_ms",
}
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
    "endpoint.discovery.windows-version.v1": {},
    "sandbox.execution.native-canary.v1": {},
    "sandbox.execution.process-tree-cancellation-witness.v1": {},
    "sandbox.identity-material.inspect.v1": {},
    "sandbox.identity-material.seed.v1": {},
    "sandbox.observability.variant.v1": {},
    "sandbox.peer.handoff.v1": {"method": "POST"},
    "sandbox.archive.tar.v1": {"archive_format": "ustar"},
    "sandbox.cleanup.v1": {},
    "sandbox.collection.stage.v1": {},
    "sandbox.collection.records.v1": {},
    "sandbox.collection.archive.v1": {},
    "sandbox.collection.atomic-gzip.v1": {},
    "sandbox.permission.chmod.v1": {},
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
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise RunnerContractError(f"{context} must be an RFC 3339 timestamp") from exc
    return _format_rust_datetime(parsed, context=context)


def grant_attempt_authorization_digest(compiled_digest: str, plan_digest: str) -> str:
    """Bind both immutable plans into the finite profile, before any lease is issued."""
    for value in (compiled_digest, plan_digest):
        if not isinstance(value, str) or _SHA256_DIGEST.fullmatch(value) is None:
            raise RunnerContractError("grant attempt plan bindings must be exact SHA-256")
    return content_hash(
        {
            "schema_version": "bluefire.grant-attempt-plan-binding.v1",
            "compiled_digest": compiled_digest,
            "plan_digest": plan_digest,
        }
    )


def _canonical_grant_attempt(value: Mapping[str, Any], *, wire: bool) -> dict[str, str]:
    fields = _GRANT_ATTEMPT_FIELDS | ({"request_hash"} if wire else set())
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerContractError("grant attempt must have the exact provenance fields")
    if (
        value.get("schema_version") != "bluefire.runner-grant-attempt.v1"
        or value.get("issuer") != "capability-grant-controller.v1"
    ):
        raise RunnerContractError("grant attempt provenance is unsupported")
    for name, prefix in (("grant_id", "grant-"), ("attempt_id", "attempt-")):
        if (
            not isinstance(value[name], str)
            or re.fullmatch(prefix + r"[0-9a-f]{32}", value[name]) is None
        ):
            raise RunnerContractError(f"grant attempt {name} is invalid")
    if (
        not isinstance(value["run_id"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["run_id"]) is None
    ):
        raise RunnerContractError("grant attempt run_id is invalid")
    for name in (
        "grant_digest",
        "lease_digest",
        "compiled_digest",
        "plan_digest",
        "native_envelope_digest",
    ):
        if not isinstance(value[name], str) or _SHA256_DIGEST.fullmatch(value[name]) is None:
            raise RunnerContractError(f"grant attempt {name} must be exact SHA-256")
    result = dict(value)
    for name in ("issued_at", "expires_at"):
        if not isinstance(value[name], str):
            raise RunnerContractError(f"grant attempt {name} must be explicit")
        result[name] = _normalize_rust_datetime(value[name], context="grant attempt " + name)
    if parse_iso8601_datetime(result["issued_at"]) >= parse_iso8601_datetime(result["expires_at"]):
        raise RunnerContractError("grant attempt deadline must follow issuance")
    if wire and (
        not isinstance(value["request_hash"], str)
        or (value["request_hash"] and _SHA256_DIGEST.fullmatch(value["request_hash"]) is None)
    ):
        raise RunnerContractError("grant attempt request_hash is invalid")
    return result


class VerifiedGrantAttempt:
    """A trusted claim adapter's provenance, not a bearer or in-process security boundary."""

    __slots__ = ("_document",)
    _document: Mapping[str, str]

    def __init__(self) -> None:
        raise TypeError("Grant attempt authority must come from the trusted lease claim adapter")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Verified grant attempt provenance is immutable")

    def to_dict(self) -> dict[str, str]:
        return dict(self._document)


def _verified_grant_attempt(
    document: Mapping[str, Any], *, expected_document_digest: str
) -> VerifiedGrantAttempt:
    """Called only after an atomic lease claim; the expected digest comes from its stored row.

    The caller must verify grant liveness, claim identity and exact compilation
    independently. Never supply the expected digest from client input or recompute
    it as authority for an untrusted document. This factory performs no DB claim.
    """
    if (
        not isinstance(expected_document_digest, str)
        or _SHA256_DIGEST.fullmatch(expected_document_digest) is None
        or content_hash(document) != expected_document_digest
    ):
        raise RunnerContractError("grant attempt differs from the trusted claimed document")
    canonical = _canonical_grant_attempt(document, wire=False)
    verified = object.__new__(VerifiedGrantAttempt)
    object.__setattr__(verified, "_document", MappingProxyType(canonical))
    return verified


def _canonical_grant_cleanup(value: Mapping[str, Any], *, wire: bool) -> dict[str, Any]:
    fields = _GRANT_CLEANUP_FIELDS | ({"request_hash"} if wire else set())
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerContractError("grant cleanup must have the exact obligation fields")
    if value.get("schema_version") != "bluefire.runner-grant-cleanup.v1":
        raise RunnerContractError("grant cleanup provenance is unsupported")
    shared = {key: value[key] for key in _GRANT_ATTEMPT_FIELDS}
    shared["schema_version"] = "bluefire.runner-grant-attempt.v1"
    result: dict[str, Any] = _canonical_grant_attempt(shared, wire=False)
    result["schema_version"] = value["schema_version"]
    for name in ("obligation_digest", "runner_policy_digest"):
        if not isinstance(value[name], str) or _SHA256_DIGEST.fullmatch(value[name]) is None:
            raise RunnerContractError(f"grant cleanup {name} must be exact SHA-256")
        result[name] = value[name]
    if (
        not isinstance(value["workspace_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["workspace_id"]) is None
    ):
        raise RunnerContractError("grant cleanup workspace identity is invalid")
    receipts = value["receipts"]
    if not isinstance(receipts, list) or not 1 <= len(receipts) <= 512:
        raise RunnerContractError("grant cleanup receipt count is invalid")
    seen: set[str] = set()
    normalized = []
    for receipt in receipts:
        if not isinstance(receipt, Mapping) or set(receipt) != {
            "receipt_id",
            "source_request_hash",
            "source_task_id",
        }:
            raise RunnerContractError("grant cleanup receipt lineage is invalid")
        receipt_id = receipt["receipt_id"]
        if (
            not isinstance(receipt_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt_id) is None
            or receipt_id in seen
            or not isinstance(receipt["source_request_hash"], str)
            or _SHA256_DIGEST.fullmatch(receipt["source_request_hash"]) is None
            or not isinstance(receipt["source_task_id"], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", receipt["source_task_id"]) is None
        ):
            raise RunnerContractError("grant cleanup receipt lineage is invalid")
        seen.add(receipt_id)
        normalized.append(dict(receipt))
    duration = (
        parse_iso8601_datetime(result["expires_at"]) - parse_iso8601_datetime(result["issued_at"])
    ).total_seconds() * 1000
    if (
        type(value["timeout_ms"]) is not int
        or not 1 <= value["timeout_ms"] <= 120_000
        or duration > 120_000
        or value["timeout_ms"] > duration
    ):
        raise RunnerContractError("grant cleanup exceeds its finite time allowance")
    result.update(
        workspace_id=value["workspace_id"], receipts=normalized, timeout_ms=value["timeout_ms"]
    )
    if wire:
        request_hash = value["request_hash"]
        if not isinstance(request_hash, str) or (
            request_hash and _SHA256_DIGEST.fullmatch(request_hash) is None
        ):
            raise RunnerContractError("grant cleanup request_hash is invalid")
        result["request_hash"] = request_hash
    return result


class VerifiedGrantCleanup:
    """Trusted receipt-obligation provenance, not a bearer or an in-process boundary."""

    __slots__ = ("_document",)
    _document: bytes

    def __init__(self) -> None:
        raise TypeError("Grant cleanup authority must come from the trusted obligation adapter")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Verified grant cleanup provenance is immutable")

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = json.loads(self._document)
        return document


def _verified_grant_cleanup(
    document: Mapping[str, Any], *, expected_document_digest: str
) -> VerifiedGrantCleanup:
    """Mint after a durable cleanup claim verified against prior tasks and native receipts.

    The expected digest must come from an independently stored obligation claim.
    This validates provenance only; it does not claim a task, reopen business
    authority, authenticate evidence, or extend the reserved cleanup deadline.
    """
    if (
        not isinstance(expected_document_digest, str)
        or _SHA256_DIGEST.fullmatch(expected_document_digest) is None
        or content_hash(document) != expected_document_digest
    ):
        raise RunnerContractError("grant cleanup differs from its trusted obligation document")
    canonical = _canonical_grant_cleanup(document, wire=False)
    verified = object.__new__(VerifiedGrantCleanup)
    object.__setattr__(verified, "_document", canonical_json_bytes(canonical))
    return verified


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
    if "file_access_binding" in sealed:
        from .file_access_contract import FileAccessContractError, canonical_file_access_binding

        try:
            if sealed.get("platform") != "linux":
                raise FileAccessContractError("file-access binding requires Linux")
            sealed["file_access_binding"] = canonical_file_access_binding(
                sealed["file_access_binding"]
            )
        except FileAccessContractError as exc:
            raise RunnerContractError(str(exc)) from exc
    try:
        tools = canonical_native_tool_installations(
            sealed.get("native_tool_installations", []),
            platform=sealed.get("platform", ""),
            allowed_actions=sealed.get("allowed_actions", []),
        )
    except ContractError as exc:
        raise RunnerContractError(str(exc)) from exc
    if tools:
        sealed["native_tool_installations"] = tools
    else:
        sealed.pop("native_tool_installations", None)
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
    try:
        provider_bindings = canonical_provider_bindings(
            sealed.get("provider_bindings", []),
            context="runner profile provider_bindings",
        )
        provider_artifacts = canonical_provider_artifacts(
            sealed.get("provider_artifacts", []),
            context="runner profile provider_artifacts",
        )
    except ProviderRunnerContractError as exc:
        raise RunnerContractError(str(exc)) from exc
    referenced_artifacts = {
        (binding["artifact_sha256"], binding["artifact_size"]) for binding in provider_bindings
    }
    supplied_artifacts = {
        (artifact["artifact_sha256"], artifact["artifact_size"]) for artifact in provider_artifacts
    }
    if referenced_artifacts != supplied_artifacts:
        raise RunnerContractError(
            "runner profile provider artifacts must exactly cover its provider bindings"
        )
    if provider_bindings:
        sealed["provider_bindings"] = provider_bindings
        sealed["provider_artifacts"] = provider_artifacts
    else:
        sealed.pop("provider_bindings", None)
        sealed.pop("provider_artifacts", None)
    if "reviewed_execution" in sealed:
        try:
            sealed["reviewed_execution"] = canonical_reviewed_execution(
                sealed["reviewed_execution"]
            )
            validate_reviewed_profile(sealed)
        except ReviewedExecutionError as exc:
            raise RunnerContractError(str(exc)) from exc
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
    provider_bindings: Sequence[Mapping[str, Any]] = (),
    provider_artifacts: Sequence[Mapping[str, Any]] = (),
    reviewed_execution: Mapping[str, Any] | None = None,
    file_access_binding: Any = None,
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
    try:
        providers = canonical_provider_bindings(
            provider_bindings,
            context="runner profile provider_bindings",
        )
        artifacts = canonical_provider_artifacts(
            provider_artifacts,
            context="runner profile provider_artifacts",
        )
    except ProviderRunnerContractError as exc:
        raise RunnerContractError(str(exc)) from exc
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
    for binding in providers:
        logical_action = str(binding["logical_action_id"])
        if logical_action not in allowed_actions or logical_action in blocked_actions:
            raise RunnerContractError("runner profile provider action is not enabled")
        if actual_platform not in binding["platforms"]:
            raise RunnerContractError("runner profile provider does not support this platform")
        if "native_execution" not in runner_capabilities:
            raise RunnerContractError("runner profile lacks the provider execution capability")
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
    if providers:
        profile_doc["provider_bindings"] = providers
        profile_doc["provider_artifacts"] = artifacts
    if reviewed_execution is not None:
        try:
            profile_doc["reviewed_execution"] = canonical_reviewed_execution(reviewed_execution)
            reviewed_actions = reviewed_action_ids(profile_doc)
            if not reviewed_actions.issubset(allowed_actions):
                raise ReviewedExecutionError(
                    "reviewed execution includes a disabled action or opcode"
                )
            profile_doc["allowed_actions"] = sorted(reviewed_actions)
        except ReviewedExecutionError as exc:
            raise RunnerContractError(str(exc)) from exc
    # Tool identity comes only from the operator-reviewed profile. Project to
    # this execution's finite action set so recovery cleanup does not require
    # an unrelated tool installation or acquire its authority.
    configured_tools = (
        installation.to_dict() for installation in profile.native_tool_installations
    )
    installations = [
        record
        for record in configured_tools
        if record["platform"] == actual_platform
        and record["adapter_id"] in profile_doc["allowed_actions"]
    ]
    if installations:
        profile_doc["native_tool_installations"] = installations
    if file_access_binding is not None:
        from .file_access_contract import VerifiedFileAccessBinding

        if not isinstance(file_access_binding, VerifiedFileAccessBinding):
            raise RunnerContractError(
                "file-access provenance must come from the trusted stored binding"
            )
        profile_doc["file_access_binding"] = file_access_binding.to_dict()
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
    if "provider_binding" in sealed:
        raw_provider = sealed["provider_binding"]
        if not isinstance(raw_provider, Mapping):
            raise RunnerContractError("runner provider_binding must be an object")
        try:
            sealed["provider_binding"] = canonical_provider_binding(
                raw_provider,
                context="runner provider_binding",
            )
        except ProviderRunnerContractError as exc:
            raise RunnerContractError(str(exc)) from exc
    if "execution_binding" in sealed and "provider_binding" in sealed:
        raise RunnerContractError("runner manifest cannot select two package execution models")
    if "reviewed_operation" in sealed:
        try:
            sealed["reviewed_operation"] = canonical_reviewed_operation(
                sealed["reviewed_operation"], authorized=True
            )
        except ReviewedExecutionError as exc:
            raise RunnerContractError(str(exc)) from exc
    approval = sealed.get("approval")
    grant_attempt = None
    grant_cleanup = None
    if "grant_attempt" in sealed:
        if approval is not None or "grant_cleanup" in sealed:
            raise RunnerContractError("runner manifest cannot combine approval and grant authority")
        grant_attempt = _canonical_grant_attempt(sealed["grant_attempt"], wire=True)
        if grant_attempt["run_id"] != sealed.get("run_id"):
            raise RunnerContractError("grant attempt belongs to another run")
        sealed["grant_attempt"] = grant_attempt
    if "grant_cleanup" in sealed:
        if approval is not None:
            raise RunnerContractError("runner manifest cannot combine approval and grant authority")
        grant_cleanup = _canonical_grant_cleanup(sealed["grant_cleanup"], wire=True)
        if grant_cleanup["run_id"] != sealed.get("run_id"):
            raise RunnerContractError("grant cleanup belongs to another run")
        sealed["grant_cleanup"] = grant_cleanup
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
    if grant_attempt is not None:
        grant_attempt["request_hash"] = ""
    if grant_cleanup is not None:
        grant_cleanup["request_hash"] = ""
    digest = content_hash(sealed)
    sealed["request_hash"] = digest
    if isinstance(approval, dict):
        approval["request_hash"] = digest
    if grant_attempt is not None:
        grant_attempt["request_hash"] = digest
    if grant_cleanup is not None:
        grant_cleanup["request_hash"] = digest
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
    grant_attempt: VerifiedGrantAttempt | None = None,
    grant_cleanup: VerifiedGrantCleanup | None = None,
    execution_binding: Mapping[str, Any] | None = None,
    provider_binding: Mapping[str, Any] | None = None,
    reviewed_operation: Mapping[str, Any] | None = None,
    resolved_cleanup_action_id: str | None = None,
    timeout_ms: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = timestamp + timedelta(minutes=5)
    requested_at = _format_rust_datetime(timestamp, context="manifest requested_at")
    expires_at = _format_rust_datetime(expires, context="manifest expires_at")
    approval = None
    grant_document = None
    if grant_attempt is not None:
        if (
            type(grant_attempt) is not VerifiedGrantAttempt
            or approval_record is not None
            or grant_cleanup is not None
        ):
            raise RunnerContractError(
                "grant authority requires the verified claim without approval"
            )
        grant_document = _canonical_grant_attempt(grant_attempt.to_dict(), wire=False)
        envelope = runner_profile.get("reviewed_execution")
        if (
            not isinstance(envelope, Mapping)
            or reviewed_operation is None
            or grant_document["run_id"] != run_id
            or content_hash(envelope) != grant_document["native_envelope_digest"]
            or envelope.get("authorization_digest")
            != grant_attempt_authorization_digest(
                grant_document["compiled_digest"], grant_document["plan_digest"]
            )
            or parse_iso8601_datetime(grant_document["issued_at"]) > timestamp
            or parse_iso8601_datetime(grant_document["expires_at"]) <= timestamp
        ):
            raise RunnerContractError("grant attempt does not bind the current finite run envelope")
        expires = min(expires, parse_iso8601_datetime(grant_document["expires_at"]))
        expires_at = _format_rust_datetime(expires, context="manifest expires_at")
        grant_document["request_hash"] = ""
    cleanup_document = None
    if grant_cleanup is not None:
        if type(grant_cleanup) is not VerifiedGrantCleanup or approval_record is not None:
            raise RunnerContractError(
                "cleanup authority requires the verified obligation without approval"
            )
        cleanup_document = _canonical_grant_cleanup(grant_cleanup.to_dict(), wire=False)
        envelope = runner_profile.get("reviewed_execution")
        if (
            not isinstance(envelope, Mapping)
            or reviewed_operation is None
            or action.id != "sandbox.cleanup.v1"
            or behavior_id != "sandbox.cleanup.v1"
            or execution_binding is not None
            or provider_binding is not None
            or filesystem_scope
            or network_destinations
            or dict(params)
            != {"receipt_ids": [row["receipt_id"] for row in cleanup_document["receipts"]]}
            or cleanup_document["run_id"] != run_id
            or cleanup_document["runner_policy_digest"] != runner_profile.get("policy_digest")
            or cleanup_document["native_envelope_digest"] != content_hash(envelope)
            or envelope.get("authorization_digest")
            != grant_attempt_authorization_digest(
                cleanup_document["compiled_digest"], cleanup_document["plan_digest"]
            )
            or parse_iso8601_datetime(cleanup_document["issued_at"]) > timestamp
            or parse_iso8601_datetime(cleanup_document["expires_at"]) <= timestamp
        ):
            raise RunnerContractError(
                "grant cleanup does not bind the exact receipt-only operation"
            )
        expires = min(expires, parse_iso8601_datetime(cleanup_document["expires_at"]))
        expires_at = _format_rust_datetime(expires, context="manifest expires_at")
        cleanup_document["request_hash"] = ""
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
    if execution_binding is not None and provider_binding is not None:
        raise RunnerContractError("runner manifest cannot select two package execution models")
    binding = (
        None
        if execution_binding is None
        else _canonical_execution_binding(
            execution_binding,
            context="runner execution_binding",
        )
    )
    try:
        provider = (
            None
            if provider_binding is None
            else canonical_provider_binding(
                provider_binding,
                context="runner provider_binding",
            )
        )
    except ProviderRunnerContractError as exc:
        raise RunnerContractError(str(exc)) from exc
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
    if provider is not None:
        if (
            provider["logical_behavior_id"] != behavior_id
            or provider["logical_action_id"] != action.id
        ):
            raise RunnerContractError(
                "runner provider binding does not match the logical behavior/action"
            )
        raw_profile_providers = runner_profile.get("provider_bindings")
        if not isinstance(raw_profile_providers, list):
            raise RunnerContractError(
                "runner provider binding is absent from the sealed runner profile"
            )
        try:
            profile_providers = canonical_provider_bindings(
                raw_profile_providers,
                context="runner profile provider_bindings",
            )
        except ProviderRunnerContractError as exc:
            raise RunnerContractError(str(exc)) from exc
        if provider not in profile_providers:
            raise RunnerContractError(
                "runner provider binding does not exactly match the sealed runner profile"
            )
        expected_inputs = [
            {
                "name": item.name,
                "type": item.type,
                "required": item.required,
                "multiple": item.multiple,
            }
            for item in action.inputs
        ]
        expected_outputs = [
            {
                "name": item.name,
                "type": item.type,
                "required": item.required,
                "multiple": item.multiple,
            }
            for item in action.outputs
        ]
        expected_parameters = [
            {
                "name": item.name,
                "type": item.type.value,
                "required": item.required,
                "default": item.default,
                "enum": list(item.enum),
                "minimum": item.minimum,
                "maximum": item.maximum,
            }
            for item in action.parameters
        ]
        if (
            provider["inputs"] != expected_inputs
            or provider["outputs"] != expected_outputs
            or provider["parameters"] != expected_parameters
            or provider["capabilities"] != effect_capabilities(action.capabilities)
            or provider["safety_tier"] != action.safety_tier.value
            or provider["platforms"] != list(action.platforms)
            or provider["mutates"] is not action.mutates
            or provider["cleanup_action_id"] != action.cleanup_action_id
        ):
            raise RunnerContractError(
                "runner provider binding differs from the signed logical action contract"
            )
    profile_limits = runner_profile.get("limits")
    if not isinstance(profile_limits, Mapping):
        raise RunnerContractError("runner profile limits are missing")
    maximum_timeout = profile_limits.get("timeout_ms")
    if isinstance(maximum_timeout, bool) or not isinstance(maximum_timeout, int):
        raise RunnerContractError("runner profile timeout is invalid")
    effective_timeout = maximum_timeout if timeout_ms is None else timeout_ms
    if cleanup_document is not None:
        if (
            type(profile_limits.get("max_files")) is not int
            or len(cleanup_document["receipts"]) > profile_limits["max_files"]
        ):
            raise RunnerContractError("grant cleanup receipts exceed the runner profile file limit")
        remaining_ms = int((expires - timestamp).total_seconds() * 1000)
        cleanup_timeout = min(cleanup_document["timeout_ms"], remaining_ms, maximum_timeout)
        if timeout_ms is None:
            effective_timeout = cleanup_timeout
        elif type(timeout_ms) is not int or not 1 <= timeout_ms <= cleanup_timeout:
            raise RunnerContractError("manifest timeout exceeds its cleanup obligation allowance")
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
        or (
            "sandbox.cleanup.v1"
            if binding is not None or provider is not None
            else action.cleanup_action_id
        )
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
    if provider is not None:
        document["provider_binding"] = provider
    try:
        if reviewed_operation is not None:
            document["reviewed_operation"] = canonical_reviewed_operation(
                reviewed_operation, authorized=True
            )
        validate_reviewed_manifest(document, runner_profile)
    except ReviewedExecutionError as exc:
        raise RunnerContractError(str(exc)) from exc
    if grant_document is not None:
        document["grant_attempt"] = grant_document
    if cleanup_document is not None:
        document["grant_cleanup"] = cleanup_document
    return seal_manifest(document)


__all__ = [
    "EFFECT_CAPABILITIES",
    "RunnerContractError",
    "VerifiedGrantAttempt",
    "VerifiedGrantCleanup",
    "build_execution_manifest",
    "build_runner_profile",
    "current_platform",
    "effect_capabilities",
    "execution_limits",
    "grant_attempt_authorization_digest",
    "resolve_environment_path",
    "seal_manifest",
    "seal_profile",
]
