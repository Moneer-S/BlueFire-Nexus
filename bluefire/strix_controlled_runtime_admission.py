"""Effect-free V2 admission and launch identity for controlled Strix.

These canonical declarations bind controller-owned references; they do not
authenticate those references, qualify a runtime, materialize paths, acquire a
credential, install a transport, or launch a process. The legacy V1 runtime and
its Docker launch plan remain a separate protocol. A future composition must
reopen every protected reference and enforce the private workspace before use.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, cast

from .engine_container_custody import ContainerCustodyPlanV2
from .engine_network_policy import (
    EngineNetworkPlanV2,
    validate_model_gateway_url,
    validate_target_url,
)
from .strix_adapter import STRIX_API_TYPE, StrixBudgets, StrixModelGateway, StrixScope
from .strix_controlled_backend import (
    _DEFAULT_REMOTE_COMMAND_ALLOWLIST,
    BACKEND_NAME,
    CAIDO_PORT,
    ControlledRuntimeProfile,
    _expected_manifest_environment,
)
from .strix_controlled_execution_identity import StrixControlledExecutionIdentityV2
from .strix_image_contract import StrixImageAdmissionDecisionV2, StrixImageContractV2
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

ADMISSION_SCHEMA = "bluefire.strix-controlled-runtime-admission.v2"
LAUNCH_SCHEMA = "bluefire.strix-controlled-launch-plan.v2"
MAX_DOCUMENT_BYTES = 128 * 1024
FILESYSTEM_CONFORMANCE = MappingProxyType(
    {
        "schema_version": "bluefire.strix-filesystem-conformance-status.v2",
        "sdk_version": "0.19.0",
        "status": "blocked-unverified",
        "remote_helper_directory": "/tmp/openai-agents/bin",
        "tmp_mount_noexec": True,
        "full_filesystem_tool_conformance": False,
    }
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[a-z0-9.+-]*)\Z")
_CLAIM_FIELDS = frozenset(
    {
        "schema_version",
        "claim_ref",
        "job_id",
        "attempt_id",
        "experiment_id",
        "preparation_ref",
        "preparation_id",
        "preparation_record_digest",
        "acceptance_record_digest",
        "binding_digest",
        "delegation_digest",
        "submission_id",
        "intent_digest",
        "job_request_digest",
        "runtime_resolution_ref",
        "preflight_revision",
        "preflight_experiment_digest",
        "claimed_at",
    }
)
_ADMISSION_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "binding_digest",
        "delegation_digest",
        "objective_ref",
        "environment_ref",
        "execution_identity",
        "execution_identity_ref",
        "image_contract",
        "image_admission_decision",
        "bootstrap_package_identity",
        "backend_package_identity",
        "sdk_package_identity",
        "network_plan",
        "custody_plan",
        "scope",
        "gateway",
        "budgets",
        "controlled_manifest",
        "caido_relay_identity",
        "private_workspace",
        "launch_executable",
        "path_environment",
        "accepted_execution_claim",
        "accepted_execution_claim_ref",
        "filesystem_conformance",
        "production_runtime_admitted",
        "live_execution_proven",
    }
)


class StrixControlledRuntimeAdmissionError(ValueError):
    """A V2 declaration is inconsistent, mixed-version, or noncanonical."""


def _refuse(label: str) -> StrixControlledRuntimeAdmissionError:
    return StrixControlledRuntimeAdmissionError(f"controlled V2 runtime {label} is invalid")


def _exact(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise _refuse(label)
    return cast(dict[str, Any], value)


def _same(value: Any, expected: Any, label: str) -> None:
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise _refuse(label)


def _text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _refuse(label)
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refuse(label)
    return value


def _path(value: Any, label: str) -> str:
    path = _text(value, label)
    parsed = PurePosixPath(path)
    if (
        not parsed.is_absolute()
        or str(parsed) != path
        or "\\" in path
        or "%" in path
        or any(part in {"..", "~"} for part in parsed.parts)
        or path == "/"
    ):
        raise _refuse(label)
    return path


def _decode(payload: bytes) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise _refuse("duplicate key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise _refuse("JSON constant")

    result = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    if type(result) is not dict:
        raise _refuse("document")
    return cast(dict[str, Any], result)


def _package(value: Any, *, module: str, module_digest: str | None = None) -> dict[str, Any]:
    row = _exact(
        value,
        frozenset(
            {"package", "version", "artifact_digest", "source_revision", "module", "module_digest"}
        ),
        "BlueFire package",
    )
    _same(row["package"], "bluefire-nexus", "BlueFire package name")
    _same(row["module"], module, "BlueFire package module")
    if type(row["version"]) is not str or _VERSION.fullmatch(row["version"]) is None:
        raise _refuse("BlueFire package version")
    if (
        type(row["source_revision"]) is not str
        or _REVISION.fullmatch(row["source_revision"]) is None
    ):
        raise _refuse("BlueFire package revision")
    _digest(row["artifact_digest"], "BlueFire package artifact")
    _digest(row["module_digest"], "BlueFire package module")
    if module_digest is not None:
        _same(row["module_digest"], module_digest, "bootstrap module")
    return row


def _claim(value: Any, admission: Mapping[str, Any]) -> dict[str, Any]:
    """Bind the existing accepted-claim protocol without granting its authority."""
    row = _exact(value, _CLAIM_FIELDS, "accepted execution claim fields")
    _same(row["schema_version"], "bluefire.engine-attempt-execution-claim.v1", "claim protocol")
    for field, prefix in (("job_id", "job"), ("experiment_id", "experiment")):
        identifier = _text(row[field], f"claim {prefix}", maximum=64)
        if re.fullmatch(prefix + r"-[0-9a-f]{32}", identifier) is None:
            raise _refuse(f"claim {prefix}")
    _text(row["submission_id"], "claim submission", maximum=160)
    for field in _CLAIM_FIELDS - {
        "schema_version",
        "job_id",
        "attempt_id",
        "experiment_id",
        "submission_id",
        "preflight_revision",
        "claimed_at",
    }:
        _digest(row[field], f"claim {field}")
    if type(row["preflight_revision"]) is not int or not 1 <= row["preflight_revision"] < 2**63:
        raise _refuse("claim preflight revision")
    parse_iso8601_datetime(_text(row["claimed_at"], "claim time", maximum=40))
    for field in ("attempt_id", "binding_digest", "delegation_digest"):
        _same(row[field], admission[field], f"claim {field}")
    claim_ref = content_hash(
        {
            "schema_version": "bluefire.engine-attempt-execution-claim-ref.v1",
            **{field: row[field] for field in _CLAIM_FIELDS - {"schema_version", "claim_ref"}},
        }
    )
    _same(row["claim_ref"], claim_ref, "claim reference")
    _same(admission["accepted_execution_claim_ref"], claim_ref, "accepted claim reference")
    return row


def _validate(value: Any) -> dict[str, Any]:
    row = _exact(value, _ADMISSION_FIELDS, "admission fields")
    _same(row["schema_version"], ADMISSION_SCHEMA, "admission schema")
    attempt = row["attempt_id"]
    if type(attempt) is not str or _ATTEMPT.fullmatch(attempt) is None:
        raise _refuse("attempt")
    for field in ("binding_digest", "delegation_digest", "objective_ref", "environment_ref"):
        _digest(row[field], field)
    identity = StrixControlledExecutionIdentityV2.from_mapping(row["execution_identity"])
    identity.require_expected_digest(row["execution_identity_ref"])
    image = StrixImageContractV2.from_mapping(row["image_contract"])
    identity.verify_image_contract(image)
    execution = identity.to_dict()
    _same(execution["attempt_id"], attempt, "execution attempt")
    profile = ControlledRuntimeProfile(**execution["controlled_runtime_profile"])
    network = EngineNetworkPlanV2.from_mapping(row["network_plan"])
    custody = ContainerCustodyPlanV2.from_mapping(row["custody_plan"])
    _same(network.attempt_id, attempt, "network attempt")
    _same(custody.attempt_id, attempt, "custody attempt")
    _same(custody.network_id, network.network_id, "custody network")
    _same(custody.network_policy_digest, network.policy_digest, "custody network policy")
    _same(profile.policy_digest, network.policy_digest, "profile policy")
    _same(profile.boundary_digest, custody.disposable_boundary_ref, "profile boundary")
    network.validate_runtime_profile_network(image.to_dict()["runtime_profile"]["network"])
    for field in (
        "image_reference",
        "platform_child_manifest_digest",
        "image_config_digest",
        "image_relation_receipt_ref",
    ):
        expected = execution["derived_image_reference" if field == "image_reference" else field]
        _same(getattr(custody, field), expected, f"custody {field}")
    runtime = image.to_dict()["runtime_profile"]
    _same(profile.sandbox_user, runtime["user"], "profile image runtime user")
    _same(profile.sandbox_user, custody.expected_user, "profile custody user")
    _same(profile.tmpfs_contract_digest, content_hash(runtime["tmpfs"]), "tmpfs contract")
    for field, expected in (
        ("expected_user", runtime["user"]),
        ("expected_capabilities", tuple(runtime["cap_add"])),
        ("memory_bytes", runtime["memory_bytes"]),
        ("nano_cpus", runtime["nano_cpus"]),
        ("pids_limit", runtime["pids_limit"]),
        ("expected_container_count", 1),
    ):
        _same(getattr(custody, field), expected, f"custody {field}")
    mounts = [
        {
            "mount_type": "tmpfs",
            "source": "",
            "destination": destination,
            "read_only": False,
            "options_digest": content_hash({"options": options}),
        }
        for destination, options in sorted(runtime["tmpfs"].items())
    ]
    _same([mount.to_dict() for mount in custody.expected_mounts], mounts, "custody mounts")
    decision_row = _exact(
        row["image_admission_decision"],
        frozenset(StrixImageAdmissionDecisionV2.__dataclass_fields__),
        "image decision",
    )
    decision = StrixImageAdmissionDecisionV2(
        **{**decision_row, "missing_checks": tuple(decision_row["missing_checks"])}
    )
    _same(decision_row, asdict(decision), "image decision encoding")
    _same(decision.contract_digest, image.contract_digest, "decision image contract")
    for field in (
        "local_build_qualified",
        "hosted_qualification_complete",
        "image_admitted_for_runtime",
    ):
        _same(getattr(decision, field), True, f"decision {field}")
    for field in (
        "notices_complete",
        "license_review_complete",
        "redistribution_authorized",
        "production_runtime_admitted",
        "live_execution_proven",
    ):
        _same(getattr(decision, field), False, f"decision {field}")
    _same(decision.missing_checks, (), "decision missing checks")
    _same(decision.redistribution_rights_confirmed, None, "redistribution rights")
    _same(
        execution["derived_image_decision_ref"],
        content_hash(
            {
                "schema_version": "bluefire.strix-image-admission-decision-ref.v2",
                "decision": asdict(decision),
            }
        ),
        "image decision ref",
    )

    bootstrap = _package(
        row["bootstrap_package_identity"],
        module="bluefire.strix_controlled_bootstrap",
        module_digest=profile.bootstrap_digest,
    )
    backend = _package(row["backend_package_identity"], module="bluefire.strix_controlled_backend")
    for field in ("version", "artifact_digest", "source_revision"):
        _same(backend[field], bootstrap[field], f"backend package {field}")
    _same(
        row["sdk_package_identity"],
        {"package": "openai-agents", "version": "0.19.0", "artifact_digest": profile.sdk_digest},
        "SDK package",
    )
    manifest: dict[str, Any] = {
        "version": 1,
        "root": "/workspace",
        "entries": {},
        "environment": {"value": _expected_manifest_environment(profile)},
        "users": [],
        "groups": [],
        "extra_path_grants": [],
        "remote_mount_command_allowlist": list(_DEFAULT_REMOTE_COMMAND_ALLOWLIST),
    }
    _same(row["controlled_manifest"], manifest, "controller-derived manifest")
    _same(content_hash(manifest), profile.manifest_digest, "profile manifest")
    _same(
        row["caido_relay_identity"],
        {
            "schema_version": "bluefire.strix-caido-relay-identity.v2",
            "caido_version": "0.56.0",
            "caido_sdk_client_version": "0.2.0",
            "proxy_origin": f"http://127.0.0.1:{CAIDO_PORT}",
            "relay_digest": profile.relay_digest,
            "upstream_digest": profile.relay_upstream_digest,
            "channel_digest": profile.relay_channel_digest,
            "retry_digest": profile.relay_retry_digest,
            "model_gateway": network.model_gateway.to_dict(),
            "manifest_environment": manifest["environment"]["value"],
        },
        "Caido relay identity",
    )
    scope_row = _exact(row["scope"], frozenset(StrixScope.__dataclass_fields__), "scope")
    scope = StrixScope(
        **{**scope_row, "resolved_addresses": tuple(scope_row["resolved_addresses"])}
    )
    _same(scope_row, asdict(scope), "scope encoding")
    validate_target_url(network, scope.target)
    _same(scope.resolved_addresses, (network.target.address,), "resolved target")
    _same(scope.network_name, network.network_name, "scope network")
    _same(scope.network_policy_digest, network.policy_digest, "scope network policy")
    gateway_row = _exact(
        row["gateway"], frozenset(StrixModelGateway.__dataclass_fields__), "gateway"
    )
    gateway = StrixModelGateway(**gateway_row)
    _same(gateway.base_url, network.model_gateway.origin, "model gateway")
    validate_model_gateway_url(network, gateway.base_url + network.model_gateway.path)
    budgets_row = _exact(row["budgets"], frozenset(StrixBudgets.__dataclass_fields__), "budgets")
    StrixBudgets(**budgets_row)
    workspace = _exact(
        row["private_workspace"],
        frozenset(
            {
                "schema_version",
                "attempt_id",
                "root",
                "home",
                "temporary",
                "config_directory",
                "config_file",
                "mcp_file",
                "objective_file",
                "workspace",
                "objective_sha256",
                "workspace_receipt_ref",
                "directory_mode",
                "config_document",
                "mcp_document",
                "credential_persistence",
                "docker_host",
            }
        ),
        "private workspace",
    )
    root = _path(workspace["root"], "private root")
    if PurePosixPath(root).name != attempt:
        raise _refuse("private attempt root")
    _same(workspace["schema_version"], "bluefire.strix-private-workspace.v2", "workspace schema")
    _same(workspace["attempt_id"], attempt, "workspace attempt")
    for field, suffix in (
        ("home", "home"),
        ("temporary", "tmp"),
        ("config_directory", "config"),
        ("config_file", "config/cli-config.json"),
        ("mcp_file", "config/mcp-servers.json"),
        ("objective_file", "objective.txt"),
        ("workspace", "workspace"),
    ):
        _same(workspace[field], f"{root}/{suffix}", f"private {field}")
    _same(workspace["docker_host"], f"unix://{root}/docker.sock", "private Docker socket")
    _same(workspace["directory_mode"], "0700", "private directory mode")
    _same(workspace["config_document"], {"env": {}}, "empty config")
    _same(workspace["mcp_document"], [], "empty MCP config")
    _same(workspace["credential_persistence"], False, "credential persistence")
    _digest(workspace["objective_sha256"], "objective bytes")
    _digest(workspace["workspace_receipt_ref"], "protected workspace receipt")
    executable = _exact(
        row["launch_executable"], frozenset({"path", "sha256"}), "launch executable"
    )
    _path(executable["path"], "launch executable path")
    executable_path = PurePosixPath(executable["path"])
    if executable_path == PurePosixPath(root) or PurePosixPath(root) in executable_path.parents:
        raise _refuse("private writable executable")
    _digest(executable["sha256"], "launch executable digest")
    for directory in _text(row["path_environment"], "PATH").split(":"):
        entry = PurePosixPath(_path(directory, "PATH entry"))
        if entry == PurePosixPath(root) or PurePosixPath(root) in entry.parents:
            raise _refuse("private writable PATH entry")
    _claim(row["accepted_execution_claim"], row)
    _same(row["filesystem_conformance"], dict(FILESYSTEM_CONFORMANCE), "Filesystem conformance")
    _same(row["production_runtime_admitted"], False, "production admission")
    _same(row["live_execution_proven"], False, "live execution")
    return row


@dataclass(frozen=True, slots=True, repr=False)
class StrixControlledRuntimeAdmissionV2:
    """Canonical controller declaration, never a production admission capability."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        try:
            if (
                type(self.canonical_bytes) is not bytes
                or not 0 < len(self.canonical_bytes) <= MAX_DOCUMENT_BYTES
            ):
                raise _refuse("bytes")
            row = _validate(_decode(self.canonical_bytes))
            _same(
                self.canonical_bytes.decode("utf-8"),
                canonical_json_bytes(row).decode("utf-8"),
                "canonical encoding",
            )
        except (TypeError, ValueError, RuntimeError, UnicodeError, RecursionError, OverflowError):
            raise _refuse("admission") from None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixControlledRuntimeAdmissionV2:
        try:
            return cls(canonical_json_bytes(_validate(value)))
        except (TypeError, ValueError, RuntimeError, UnicodeError, RecursionError, OverflowError):
            raise _refuse("admission") from None

    def to_dict(self) -> dict[str, Any]:
        return _decode(self.canonical_bytes)

    @property
    def admission_ref(self) -> str:
        return content_hash(self.to_dict())

    def require_expected_ref(self, expected_ref: str) -> None:
        _same(
            self.admission_ref,
            _digest(expected_ref, "protected admission ref"),
            "protected admission ref",
        )

    def __repr__(self) -> str:
        return f"StrixControlledRuntimeAdmissionV2(admission_ref={self.admission_ref!r})"


def _launch_document(admission: StrixControlledRuntimeAdmissionV2) -> dict[str, Any]:
    row = admission.to_dict()
    identity = row["execution_identity"]
    profile = identity["controlled_runtime_profile"]
    workspace = row["private_workspace"]
    gateway = row["gateway"]
    budgets = row["budgets"]
    environment = {
        "HOME": workspace["home"],
        "PATH": row["path_environment"],
        "TMPDIR": workspace["temporary"],
        "XDG_CONFIG_HOME": workspace["config_directory"],
        "DOCKER_HOST": workspace["docker_host"],
        "STRIX_RUNTIME_BACKEND": BACKEND_NAME,
        "STRIX_IMAGE": identity["derived_image_reference"],
        "STRIX_LLM": gateway["model"],
        "STRIX_API_TYPE": STRIX_API_TYPE,
        "LLM_API_BASE": gateway["base_url"],
        "STRIX_DOCKER_SANDBOX_NETWORK": row["network_plan"]["network_name"],
        "STRIX_RUN_ID": row["attempt_id"],
        "STRIX_RUN_TYPE": "bluefire",
        "STRIX_TELEMETRY": "false",
        "STRIX_NO_UPDATE_CHECK": "1",
        "STRIX_RUN_RECORD_TIMINGS": "true",
        "BLUEFIRE_STRIX_ATTEMPT_ID": row["attempt_id"],
    }
    for field in (
        "source_revision",
        "build_digest",
        "profile_digest",
        "policy_digest",
        "relay_digest",
        "relay_upstream_digest",
        "relay_channel_digest",
        "relay_retry_digest",
        "boundary_digest",
        "admission_digest",
        "image_digest",
        "manifest_digest",
        "sdk_digest",
        "bootstrap_digest",
        "sandbox_uid",
        "sandbox_gid",
    ):
        environment["BLUEFIRE_STRIX_" + field.upper()] = str(profile[field])
    environment["BLUEFIRE_STRIX_TMPFS_DIGEST"] = profile["tmpfs_contract_digest"]
    argv = [
        row["launch_executable"]["path"],
        "-n",
        "--target",
        row["scope"]["target"],
        "--scan-mode",
        "quick",
        "--scope-mode",
        "full",
        "--instruction-file",
        workspace["objective_file"],
        "--config",
        workspace["config_file"],
        "--mcp-config",
        workspace["mcp_file"],
        "--max-turns",
        str(budgets["max_turns_per_agent"]),
        "--max-budget",
        budgets["max_model_cost_usd"],
        "--fail-on",
        "info",
    ]
    # The future exec broker must bind this complete controller-derived identity,
    # including the manifest proxy environment; worker environment is not input.
    broker = {
        "schema_version": "bluefire.strix-controlled-exec-broker-binding.v2",
        "admission_ref": admission.admission_ref,
        "execution_identity_ref": row["execution_identity_ref"],
        "accepted_execution_claim_ref": row["accepted_execution_claim_ref"],
        "network_plan_digest": content_hash(row["network_plan"]),
        "custody_plan_digest": content_hash(row["custody_plan"]),
        "controlled_profile_ref": profile["profile_digest"],
        "manifest_digest": profile["manifest_digest"],
        "caido_relay_identity": row["caido_relay_identity"],
        "environment": environment,
        "argv": argv,
        "cwd": workspace["workspace"],
    }
    return {
        "schema_version": LAUNCH_SCHEMA,
        "admission": row,
        "admission_ref": admission.admission_ref,
        "argv": argv,
        "environment": environment,
        "required_secret_environment": ["LLM_API_KEY"],
        "cwd": workspace["workspace"],
        "wall_seconds": budgets["wall_seconds"],
        "exec_broker_binding_digest": content_hash(broker),
        "production_runtime_admitted": False,
    }


@dataclass(frozen=True, slots=True, repr=False)
class StrixControlledLaunchPlanV2:
    """Secret-free proposed launch bytes, with no worker or transport attached."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        try:
            if (
                type(self.canonical_bytes) is not bytes
                or not 0 < len(self.canonical_bytes) <= MAX_DOCUMENT_BYTES
            ):
                raise _refuse("launch bytes")
            row = _decode(self.canonical_bytes)
            admission = StrixControlledRuntimeAdmissionV2.from_mapping(row["admission"])
            if self.canonical_bytes != canonical_json_bytes(_launch_document(admission)):
                raise _refuse("launch encoding")
        except (
            KeyError,
            TypeError,
            ValueError,
            RuntimeError,
            UnicodeError,
            RecursionError,
            OverflowError,
        ):
            raise _refuse("launch") from None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixControlledLaunchPlanV2:
        try:
            return cls(canonical_json_bytes(value))
        except (TypeError, ValueError, RuntimeError, UnicodeError, RecursionError, OverflowError):
            raise _refuse("launch") from None

    def to_dict(self) -> dict[str, Any]:
        return _decode(self.canonical_bytes)

    @property
    def launch_digest(self) -> str:
        return content_hash(self.to_dict())

    @property
    def exec_broker_binding_digest(self) -> str:
        return cast(str, self.to_dict()["exec_broker_binding_digest"])

    def __repr__(self) -> str:
        return f"StrixControlledLaunchPlanV2(launch_digest={self.launch_digest!r})"


def build_controlled_launch_plan(
    admission: StrixControlledRuntimeAdmissionV2,
    *,
    expected_admission_ref: str,
    expected_execution_claim_ref: str,
) -> StrixControlledLaunchPlanV2:
    """Construct only from canonical V2 bytes and independently held exact refs."""
    if type(admission) is not StrixControlledRuntimeAdmissionV2:
        raise _refuse("admission type")
    checked = StrixControlledRuntimeAdmissionV2(admission.canonical_bytes)
    checked.require_expected_ref(expected_admission_ref)
    _same(
        checked.to_dict()["accepted_execution_claim_ref"],
        _digest(expected_execution_claim_ref, "protected claim ref"),
        "protected claim ref",
    )
    return StrixControlledLaunchPlanV2(canonical_json_bytes(_launch_document(checked)))


__all__ = [
    "ADMISSION_SCHEMA",
    "LAUNCH_SCHEMA",
    "FILESYSTEM_CONFORMANCE",
    "StrixControlledRuntimeAdmissionError",
    "StrixControlledRuntimeAdmissionV2",
    "StrixControlledLaunchPlanV2",
    "build_controlled_launch_plan",
]
