"""Finite reviewed authority for the future owned-user-service adapter.

These documents bind a service request to ordinary claimed approval and the
enrollment-authenticated runner transport. They do not implement service
effects. Native protected admission and durable resource reservation remain
required before an effect can run.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping, cast

from .contracts import ContractError
from .service_observation_runtime import (
    canonical_installation_reference,
    canonical_observation_runtime,
    validate_scope_installations,
)
from .tool_adapters.service_operation_binding import ServiceOperationBinding
from .util import canonical_json_bytes, content_hash

SCOPE_SCHEMA = "bluefire.owned-user-service-scope.v1"
GRANT_SCHEMA = "bluefire.owned-user-service-grant.v1"
ADMISSION_SCHEMA = "bluefire.owned-user-service-admission.v1"
SCOPE_SCHEMA_V2 = "bluefire.owned-user-service-scope.v2"
GRANT_SCHEMA_V2 = "bluefire.owned-user-service-grant.v2"
ADMISSION_SCHEMA_V2 = "bluefire.owned-user-service-admission.v2"
PROFILE_POLICY_FIELDS = (
    "id",
    "mode",
    "environment_type",
    "platforms",
    "runner_binary",
    "sandbox_root",
    "scope",
    "network_allowlist",
    "capabilities",
    "safety_tiers",
    "approval_required",
    "enabled_actions",
    "blocked_actions",
    "cleanup_policy",
    "budgets",
    "secrets",
    "native_tool_installations",
)
SETUP_EFFECTS = ("create_unit", "reload", "enable", "start")
CLEANUP_EFFECTS = ("stop", "disable", "remove_links", "remove_unit", "reload_after_cleanup")
SERVICE_ACTION_ID = "owned.user_service.fixed_wait.v1"
FIXED_UNIT_TEMPLATE = (
    "[Unit]\n"
    "Description=BlueFire owned user service\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart={payload_path} owned-service-payload --duration-seconds {duration_seconds}\n"
    "RuntimeMaxSec={max_runtime_seconds}s\n"
    "MemoryMax={memory_max_bytes}\n"
    "TasksMax={max_processes}\n"
    "KillMode=control-group\n"
    "Restart=no\n"
    "NoNewPrivileges=yes\n"
    "PrivateTmp=yes\n"
    "ProtectSystem=strict\n"
    "ProtectHome=read-only\n"
    "ProtectKernelTunables=yes\n"
    "ProtectKernelModules=yes\n"
    "ProtectControlGroups=yes\n"
    "RestrictSUIDSGID=yes\n"
    "[Install]\n"
    "WantedBy=default.target\n"
)
FIXED_TEMPLATE_DIGEST = "sha256:" + hashlib.sha256(FIXED_UNIT_TEMPLATE.encode("utf-8")).hexdigest()
_MAX_SCOPE_BYTES = 16 * 1024
_MAX_GRANT_BYTES = 32 * 1024
_MAX_ADMISSION_BYTES = 36 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_CLAIM_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_TIERS = frozenset({"safe", "controlled", "restricted"})
_SCOPE_FIELDS = frozenset(
    "schema_version scenario_id step_id action_id profile_id profile_policy_digest "
    "target_scope_digest workspace target manager unit template installations effects "
    "parameters limits created_at setup_expires_at cleanup_expires_at".split()
)
_GRANT_FIELDS = frozenset(
    "schema_version scope scope_digest claim run_id step_id action_id manifest_request_hash "
    "operation_binding execution".split()
)


class OwnedServiceAuthorityError(ContractError):
    """A reviewed owned-service scope or claim is invalid."""


def _fail(message: str) -> OwnedServiceAuthorityError:
    return OwnedServiceAuthorityError("owned-service authority: " + message)


def _check_operation_timeout(
    manifest: Mapping[str, Any], scope: Mapping[str, Any], operation: str
) -> None:
    limits = manifest.get("limits")
    if not isinstance(limits, Mapping):
        raise _fail("manifest has no operation timeout")
    timeout_ms = limits.get("timeout_ms")
    field = "setup_timeout_seconds" if operation in SETUP_EFFECTS else "cleanup_timeout_seconds"
    maximum = scope["limits"][field] * 1000
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= maximum:
        raise _fail("manifest timeout exceeds the reviewed operation window")


def _object(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _fail(f"{label} must contain exactly its declared fields")
    return value


def _text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _fail(f"invalid {label}")
    return value


def _bounded_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail(f"invalid {label}")
    return value


def _utc(value: Any, label: str, *, claim_time: bool = False) -> datetime:
    text = _text(value, _CLAIM_UTC if claim_time else _UTC, label)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise _fail(f"invalid {label}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise _fail(f"invalid {label}")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _absolute_posix_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
        raise _fail(f"invalid {label}")
    path = PurePosixPath(value)
    if str(path) != value or any(part in {".", ".."} for part in path.parts):
        raise _fail(f"invalid {label}")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail("duplicate JSON field")
        result[key] = value
    return result


def profile_policy_projection(profile: Any) -> dict[str, Any]:
    """Return the explicit configured-profile policy projection used by scope.

    The runner's final sealed profile is deliberately not used here: it is
    assembled after approval and contains request-specific bindings. The
    selected fields are the complete configured policy surface, including
    native installation declarations and resource budgets, but no runtime
    credential values.
    """

    source = profile.to_dict() if callable(getattr(profile, "to_dict", None)) else profile
    if not isinstance(source, Mapping) or not set(PROFILE_POLICY_FIELDS) <= set(source):
        raise _fail("configured runner profile is incomplete")
    projection = {field: source[field] for field in PROFILE_POLICY_FIELDS}
    try:
        canonical_json_bytes(projection)
    except (TypeError, ValueError, RecursionError) as exc:
        raise _fail("configured runner profile is not canonical JSON") from exc
    return cast(dict[str, Any], json.loads(canonical_json_bytes(projection)))


def profile_policy_digest(profile: Any) -> str:
    return content_hash(profile_policy_projection(profile))


def _installation(value: Any, label: str) -> dict[str, str]:
    try:
        return canonical_installation_reference(value, label)
    except ContractError as exc:
        raise _fail(str(exc)) from exc


def _check_installations(scope: Mapping[str, Any], records: Any, *, configured: bool) -> None:
    try:
        validate_scope_installations(scope, records, configured=configured)
    except ContractError as exc:
        raise _fail(str(exc)) from exc


def _scope_document(value: Any) -> dict[str, Any]:
    v2 = isinstance(value, Mapping) and value.get("schema_version") == SCOPE_SCHEMA_V2
    data = _object(value, _SCOPE_FIELDS | {"observation_runtime"} if v2 else _SCOPE_FIELDS, "scope")
    if data["schema_version"] not in (SCOPE_SCHEMA, SCOPE_SCHEMA_V2):
        raise _fail("unsupported scope schema")
    for field in ("scenario_id", "step_id", "action_id", "profile_id"):
        _text(data[field], _ID, field)
    if data["action_id"] != SERVICE_ACTION_ID:
        raise _fail("unsupported owned-service action")
    for field in ("profile_policy_digest", "target_scope_digest"):
        _text(data[field], _DIGEST, field)

    workspace = _object(data["workspace"], frozenset({"workspace_id", "root"}), "workspace")
    workspace_document = {
        "workspace_id": _text(workspace["workspace_id"], _ID, "workspace ID"),
        "root": _absolute_posix_path(workspace["root"], "workspace root"),
    }

    target = _object(
        data["target"],
        frozenset({"owner_uid", "boot_id", "manager_instance_id"}),
        "target",
    )
    owner_uid = _bounded_int(target["owner_uid"], 1, 2**32 - 2, "non-root owner UID")
    boot_id = _text(target["boot_id"], _BOOT, "boot ID")
    if boot_id == "00000000-0000-0000-0000-000000000000":
        raise _fail("empty boot ID")
    target_document = {
        "owner_uid": owner_uid,
        "boot_id": boot_id,
        "manager_instance_id": _text(target["manager_instance_id"], _NONCE, "manager instance ID"),
    }

    manager = _object(data["manager"], frozenset({"kind", "bus_identity"}), "manager")
    if manager["kind"] != "systemd.user.v1":
        raise _fail("unsupported user manager")
    expected_bus = f"unix:path=/run/user/{owner_uid}/bus"
    if manager["bus_identity"] != expected_bus:
        raise _fail("user manager bus identity does not match the target UID")
    manager_document = {"kind": "systemd.user.v1", "bus_identity": expected_bus}

    unit = _object(data["unit"], frozenset({"nonce", "name", "content_digest"}), "unit")
    nonce = _text(unit["nonce"], _NONCE, "generated unit nonce")
    if nonce == "0" * 32 or unit["name"] != f"bluefire-{nonce}.service":
        raise _fail("unit name does not derive from its generated nonce")
    unit_document = {
        "nonce": nonce,
        "name": f"bluefire-{nonce}.service",
        "content_digest": _text(unit["content_digest"], _DIGEST, "rendered unit digest"),
    }

    template = _object(data["template"], frozenset({"template_id", "content_digest"}), "template")
    if (
        template["template_id"] != "bluefire.user-service.fixed-wait.v1"
        or template["content_digest"] != FIXED_TEMPLATE_DIGEST
    ):
        raise _fail("unsupported fixed service template")
    template_document = {
        "template_id": "bluefire.user-service.fixed-wait.v1",
        "content_digest": FIXED_TEMPLATE_DIGEST,
    }

    installations = _object(
        data["installations"], frozenset({"manager", "payload"}), "installations"
    )
    installation_document = {
        "manager": _installation(installations["manager"], "manager installation"),
        "payload": _installation(installations["payload"], "payload installation"),
    }

    effects = _object(data["effects"], frozenset({"setup", "cleanup"}), "effects")
    if effects["setup"] != list(SETUP_EFFECTS) or effects["cleanup"] != list(CLEANUP_EFFECTS):
        raise _fail("service effects differ from the fixed lifecycle")
    effect_document = {"setup": list(SETUP_EFFECTS), "cleanup": list(CLEANUP_EFFECTS)}

    parameters = _object(
        data["parameters"],
        frozenset({"duration_seconds", "memory_max_bytes"}),
        "parameters",
    )
    duration = _bounded_int(parameters["duration_seconds"], 1, 120, "payload duration")
    memory = _bounded_int(
        parameters["memory_max_bytes"], 16 * 1024 * 1024, 512 * 1024 * 1024, "payload memory bound"
    )
    parameter_document = {"duration_seconds": duration, "memory_max_bytes": memory}

    limits = _object(
        data["limits"],
        frozenset(
            {
                "setup_timeout_seconds",
                "cleanup_timeout_seconds",
                "max_unit_bytes",
                "max_runtime_seconds",
                "max_memory_bytes",
                "max_processes",
            }
        ),
        "limits",
    )
    limit_document = {
        "setup_timeout_seconds": _bounded_int(
            limits["setup_timeout_seconds"], 1, 60, "setup timeout"
        ),
        "cleanup_timeout_seconds": _bounded_int(
            limits["cleanup_timeout_seconds"], 1, 60, "cleanup timeout"
        ),
        "max_unit_bytes": _bounded_int(limits["max_unit_bytes"], 256, 16 * 1024, "unit byte limit"),
        "max_runtime_seconds": _bounded_int(limits["max_runtime_seconds"], 1, 120, "runtime limit"),
        "max_memory_bytes": _bounded_int(
            limits["max_memory_bytes"], 16 * 1024 * 1024, 512 * 1024 * 1024, "memory limit"
        ),
        "max_processes": _bounded_int(limits["max_processes"], 1, 16, "process limit"),
    }
    if (
        duration > limit_document["max_runtime_seconds"]
        or memory > limit_document["max_memory_bytes"]
    ):
        raise _fail("payload parameters exceed reviewed resource limits")

    created_at = _utc(data["created_at"], "scope creation time")
    setup_expires_at = _utc(data["setup_expires_at"], "setup expiry")
    cleanup_expires_at = _utc(data["cleanup_expires_at"], "cleanup expiry")
    if not created_at < setup_expires_at <= created_at + timedelta(minutes=5):
        raise _fail("setup authority must expire within five minutes")
    if not setup_expires_at <= cleanup_expires_at <= created_at + timedelta(hours=1):
        raise _fail("cleanup authority must have a separate finite expiry within one hour")

    document = {
        "schema_version": data["schema_version"],
        "scenario_id": str(data["scenario_id"]),
        "step_id": str(data["step_id"]),
        "action_id": str(data["action_id"]),
        "profile_id": str(data["profile_id"]),
        "profile_policy_digest": str(data["profile_policy_digest"]),
        "target_scope_digest": str(data["target_scope_digest"]),
        "workspace": workspace_document,
        "target": target_document,
        "manager": manager_document,
        "unit": unit_document,
        "template": template_document,
        "installations": installation_document,
        "effects": effect_document,
        "parameters": parameter_document,
        "limits": limit_document,
        "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "setup_expires_at": setup_expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cleanup_expires_at": cleanup_expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if v2:
        try:
            document["observation_runtime"] = canonical_observation_runtime(
                data["observation_runtime"]
            )
        except ContractError as exc:
            raise _fail(str(exc)) from exc
    if unit_document["content_digest"] != _unit_content_digest(document):
        raise _fail("rendered unit bytes differ from the reviewed content digest")
    encoded = canonical_json_bytes(document)
    if len(encoded) > _MAX_SCOPE_BYTES:
        raise _fail("scope exceeds its byte bound")
    return document


@dataclass(frozen=True, slots=True)
class OwnedServiceScope:
    """Canonical reviewed service scope; contains no command or shell text."""

    _canonical: bytes

    def __post_init__(self) -> None:
        if type(self._canonical) is not bytes or len(self._canonical) > _MAX_SCOPE_BYTES:
            raise _fail("scope must be bounded immutable bytes")
        try:
            normalized = canonical_json_bytes(
                _scope_document(json.loads(self._canonical, object_pairs_hook=_unique_object))
            )
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid scope encoding") from exc
        if normalized != self._canonical:
            raise _fail("scope must use canonical encoding")

    @classmethod
    def from_mapping(cls, value: Any) -> OwnedServiceScope:
        return cls(canonical_json_bytes(_scope_document(value)))

    @classmethod
    def from_json(cls, value: bytes) -> OwnedServiceScope:
        if type(value) is not bytes or len(value) > _MAX_SCOPE_BYTES:
            raise _fail("scope JSON exceeds its byte bound")
        try:
            parsed = json.loads(value.decode("utf-8"), object_pairs_hook=_unique_object)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid scope JSON") from exc
        return cls.from_mapping(parsed)

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def canonical_bytes(self) -> bytes:
        return self._canonical

    def identity_mapping(self) -> dict[str, Any]:
        """Project exact v1 journal identity fields without changing that schema."""

        document = self.to_dict()
        return {
            "schema_version": "bluefire.owned-user-service.v1",
            "authorization_digest": self.digest,
            "runner_profile_id": document["profile_id"],
            "workspace_id": document["workspace"]["workspace_id"],
            "target_scope_digest": document["target_scope_digest"],
            "owner_uid": document["target"]["owner_uid"],
            "boot_id": document["target"]["boot_id"],
            "manager_id": document["target"]["manager_instance_id"],
            "unit_nonce": document["unit"]["nonce"],
            "unit_content_digest": document["unit"]["content_digest"],
            "created_at": document["created_at"],
            "cleanup_due_at": document["cleanup_expires_at"],
        }


def generate_owned_service_unit_nonce() -> str:
    """Generate an unguessable one-resource nonce for a reviewed scope."""

    return secrets.token_hex(16)


def compile_owned_service_scope(value: Any, *, profile: Any) -> OwnedServiceScope:
    """Validate scope before approval and bind it to the configured profile policy."""

    scope = OwnedServiceScope.from_mapping(value)
    document = scope.to_dict()
    if document["profile_policy_digest"] != profile_policy_digest(profile):
        raise _fail("scope differs from the configured runner profile policy")
    profile_document = profile.to_dict() if callable(getattr(profile, "to_dict", None)) else profile
    if not isinstance(profile_document, Mapping) or document["profile_id"] != profile_document.get(
        "id"
    ):
        raise _fail("scope runner profile identity does not match")
    _check_installations(
        document, profile_document.get("native_tool_installations"), configured=True
    )
    return scope


def _render_unit(document: Mapping[str, Any]) -> bytes:
    payload = document["installations"]["payload"]["path"]
    parameters = document["parameters"]
    limits = document["limits"]
    return render_owned_service_unit_bytes(
        payload_path=payload,
        duration_seconds=parameters["duration_seconds"],
        max_runtime_seconds=limits["max_runtime_seconds"],
        memory_max_bytes=parameters["memory_max_bytes"],
        max_processes=limits["max_processes"],
    )


def render_owned_service_unit_bytes(
    *,
    payload_path: str,
    duration_seconds: int,
    max_runtime_seconds: int,
    memory_max_bytes: int,
    max_processes: int,
) -> bytes:
    """Render the fixed unit from finite parameters before scope compilation."""

    path = _absolute_posix_path(payload_path, "payload installation path")
    if not re.fullmatch(r"/[A-Za-z0-9._+/-]+", path):
        raise _fail("payload installation path contains unsupported systemd characters")
    duration = _bounded_int(duration_seconds, 1, 120, "payload duration")
    runtime = _bounded_int(max_runtime_seconds, 1, 120, "runtime limit")
    memory = _bounded_int(memory_max_bytes, 16 * 1024 * 1024, 512 * 1024 * 1024, "memory limit")
    processes = _bounded_int(max_processes, 1, 16, "process limit")
    if duration > runtime:
        raise _fail("payload duration exceeds runtime limit")
    return FIXED_UNIT_TEMPLATE.format(
        payload_path=path,
        duration_seconds=duration,
        max_runtime_seconds=runtime,
        memory_max_bytes=memory,
        max_processes=processes,
    ).encode("utf-8")


def _unit_content_digest(document: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_render_unit(document)).hexdigest()


def render_owned_service_unit(scope: OwnedServiceScope) -> bytes:
    """Render only the fixed wait-service unit whose digest is in ``scope``."""

    if not isinstance(scope, OwnedServiceScope):
        raise _fail("unit rendering requires a compiled scope")
    document = scope.to_dict()
    rendered = _render_unit(document)
    if ("sha256:" + hashlib.sha256(rendered).hexdigest()) != document["unit"]["content_digest"]:
        raise _fail("unit bytes do not match the reviewed scope")
    if len(rendered) > document["limits"]["max_unit_bytes"]:
        raise _fail("rendered unit exceeds the reviewed byte limit")
    return rendered


def _claim_document(value: Any) -> dict[str, str]:
    fields = frozenset(
        {
            "approval_id",
            "state_digest",
            "plan_digest",
            "target_scope_digest",
            "profile_id",
            "maximum_tier",
            "consumed_at",
            "approval_expires_at",
        }
    )
    data = _object(value, fields, "claimed approval")
    if not isinstance(data["approval_id"], str) or not data["approval_id"].startswith("approval-"):
        raise _fail("invalid claimed approval ID")
    for field in ("state_digest", "plan_digest", "target_scope_digest"):
        _text(data[field], _DIGEST, field)
    profile_id = _text(data["profile_id"], _ID, "claimed profile ID")
    tier = data["maximum_tier"]
    if tier not in _TIERS:
        raise _fail("invalid claimed approval tier")
    consumed = _utc(data["consumed_at"], "approval consumed time", claim_time=True)
    expires = _utc(data["approval_expires_at"], "approval expiry", claim_time=True)
    if not consumed < expires:
        raise _fail("claimed approval has an invalid expiry")
    return {
        "approval_id": str(data["approval_id"]),
        "state_digest": str(data["state_digest"]),
        "plan_digest": str(data["plan_digest"]),
        "target_scope_digest": str(data["target_scope_digest"]),
        "profile_id": profile_id,
        "maximum_tier": str(tier),
        "consumed_at": _utc_text(consumed),
        "approval_expires_at": _utc_text(expires),
    }


def _grant_document(value: Any) -> dict[str, Any]:
    data = _object(value, _GRANT_FIELDS, "grant")
    if data["schema_version"] not in (GRANT_SCHEMA, GRANT_SCHEMA_V2):
        raise _fail("unsupported grant schema")
    scope = OwnedServiceScope.from_mapping(data["scope"])
    if (data["schema_version"] == GRANT_SCHEMA_V2) != (
        scope.to_dict()["schema_version"] == SCOPE_SCHEMA_V2
    ):
        raise _fail("grant and scope schema families differ")
    if _text(data["scope_digest"], _DIGEST, "scope digest") != scope.digest:
        raise _fail("grant scope digest mismatch")
    claim = _claim_document(data["claim"])
    for field in ("run_id", "step_id", "action_id"):
        _text(data[field], _ID, field)
    _text(data["manifest_request_hash"], _DIGEST, "manifest request hash")
    try:
        operation_binding = ServiceOperationBinding.from_mapping(data["operation_binding"])
    except ContractError as exc:
        raise _fail("invalid pending operation binding") from exc
    binding_document = operation_binding.to_dict()
    execution = _object(
        data["execution"],
        frozenset({"task_id", "manifest_digest", "profile_digest", "operation_binding_digest"}),
        "execution binding",
    )
    task_id = _text(execution["task_id"], re.compile(r"execute-[0-9a-f]{64}"), "task ID")
    _ = task_id
    execution_document = {
        "task_id": str(execution["task_id"]),
        "manifest_digest": _text(execution["manifest_digest"], _DIGEST, "manifest digest"),
        "profile_digest": _text(execution["profile_digest"], _DIGEST, "sealed profile digest"),
        "operation_binding_digest": operation_binding.digest,
    }
    if (
        _text(execution["operation_binding_digest"], _DIGEST, "operation binding digest")
        != operation_binding.digest
    ):
        raise _fail("operation binding digest mismatch")
    scope_doc = scope.to_dict()
    consumed_at = _utc(claim["consumed_at"], "approval consumed time", claim_time=True)
    if (
        not _utc(scope_doc["created_at"], "scope creation time")
        <= consumed_at
        < _utc(scope_doc["setup_expires_at"], "setup expiry")
    ):
        raise _fail("claimed approval was not consumed inside its reviewed setup window")
    operation = binding_document["operation"]
    if operation not in (*scope_doc["effects"]["setup"], *scope_doc["effects"]["cleanup"]):
        raise _fail("operation is outside the reviewed service lifecycle")
    if (
        claim["profile_id"] != scope_doc["profile_id"]
        or claim["target_scope_digest"] != scope_doc["target_scope_digest"]
        or data["step_id"] != scope_doc["step_id"]
        or data["action_id"] != scope_doc["action_id"]
        or binding_document["reviewed_scope_digest"] != scope.digest
        or binding_document["identity"] != scope.identity_mapping()
        or binding_document["manager_installation_digest"]
        != scope_doc["installations"]["manager"]["digest"]
        or binding_document["payload_installation_digest"]
        != scope_doc["installations"]["payload"]["digest"]
    ):
        raise _fail("grant claim does not match its reviewed scope")
    return {
        "schema_version": data["schema_version"],
        "scope": scope_doc,
        "scope_digest": scope.digest,
        "claim": claim,
        "run_id": str(data["run_id"]),
        "step_id": str(data["step_id"]),
        "action_id": str(data["action_id"]),
        "manifest_request_hash": str(data["manifest_request_hash"]),
        "operation_binding": binding_document,
        "execution": execution_document,
    }


@dataclass(frozen=True, slots=True)
class OwnedServiceGrant:
    """Claimed, request-bound service authority carried inside transport HMAC."""

    _canonical: bytes

    def __post_init__(self) -> None:
        if type(self._canonical) is not bytes or len(self._canonical) > _MAX_GRANT_BYTES:
            raise _fail("grant must be bounded immutable bytes")
        try:
            normalized = canonical_json_bytes(
                _grant_document(json.loads(self._canonical, object_pairs_hook=_unique_object))
            )
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid grant encoding") from exc
        if normalized != self._canonical:
            raise _fail("grant must use canonical encoding")

    @classmethod
    def from_mapping(cls, value: Any) -> OwnedServiceGrant:
        return cls(canonical_json_bytes(_grant_document(value)))

    @classmethod
    def from_json(cls, value: bytes) -> OwnedServiceGrant:
        if type(value) is not bytes or len(value) > _MAX_GRANT_BYTES:
            raise _fail("grant JSON exceeds its byte bound")
        try:
            parsed = json.loads(value.decode("utf-8"), object_pairs_hook=_unique_object)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid grant JSON") from exc
        return cls.from_mapping(parsed)

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def canonical_bytes(self) -> bytes:
        return self._canonical


def mint_owned_service_grant(
    *,
    scope: OwnedServiceScope,
    claimed_approval: Mapping[str, Any],
    approval_binding: Mapping[str, Any],
    operation_binding: ServiceOperationBinding,
    run_id: str,
    manifest: Mapping[str, Any],
    sealed_profile: Mapping[str, Any],
    task_id: str,
    now: datetime | None = None,
) -> OwnedServiceGrant:
    """Mint only from an actual claimed approval after validating scope ties."""

    if not isinstance(scope, OwnedServiceScope):
        raise _fail("grant requires a compiled reviewed scope")
    if claimed_approval.get("status") != "claimed":
        raise _fail("grant requires a durably claimed approval")
    if not isinstance(operation_binding, ServiceOperationBinding):
        raise _fail("grant requires a committed pending journal binding")
    scope_doc = scope.to_dict()
    claim = _claim_document(
        {
            key: claimed_approval.get(source)
            for key, source in (
                ("approval_id", "approval_id"),
                ("state_digest", "state_digest"),
                ("plan_digest", "plan_digest"),
                ("target_scope_digest", "target_scope_digest"),
                ("profile_id", "profile_id"),
                ("maximum_tier", "maximum_tier"),
                ("consumed_at", "consumed_at"),
                ("approval_expires_at", "expires_at"),
            )
        }
    )
    expected_claim = {
        "state_digest": approval_binding.get("state_digest"),
        "plan_digest": approval_binding.get("plan_digest"),
        "target_scope_digest": approval_binding.get("target_scope_digest"),
        "profile_id": approval_binding.get("profile_id"),
        "maximum_tier": approval_binding.get("maximum_tier"),
    }
    if (
        any(claim[field] != expected_claim[field] for field in expected_claim)
        or approval_binding.get("owned_service_scope_digest") != scope.digest
    ):
        raise _fail("durable claim does not bind this reviewed scope")
    current = now or datetime.now(timezone.utc)
    consumed = _utc(claim["consumed_at"], "approval consumed time", claim_time=True)
    expiry = _utc(claim["approval_expires_at"], "approval expiry", claim_time=True)
    setup_expiry = _utc(scope_doc["setup_expires_at"], "setup expiry")
    cleanup_expiry = _utc(scope_doc["cleanup_expires_at"], "cleanup expiry")
    operation = operation_binding.to_dict()["operation"]
    if operation not in (*SETUP_EFFECTS, *CLEANUP_EFFECTS):
        raise _fail("pending journal operation is outside the reviewed lifecycle")
    setup_authority = operation in SETUP_EFFECTS
    operation_expiry = setup_expiry if setup_authority else cleanup_expiry
    if current.tzinfo is None or current.utcoffset() != timedelta(0):
        raise _fail("grant clock must be timezone-aware UTC")
    if (
        consumed >= setup_expiry
        or not consumed <= current.astimezone(timezone.utc) < operation_expiry
    ):
        raise _fail("claimed approval or operation authority is expired")
    if setup_authority and current.astimezone(timezone.utc) >= expiry:
        raise _fail("setup approval is expired")
    created_at = _utc(scope_doc["created_at"], "scope creation time")
    if current.astimezone(timezone.utc) < created_at or consumed < created_at:
        raise _fail("scope was not created before its claimed approval")
    if not isinstance(manifest, Mapping) or not isinstance(sealed_profile, Mapping):
        raise _fail("manifest and sealed profile are required")
    if (
        manifest.get("step_id") != scope_doc["step_id"]
        or manifest.get("action_id") != scope_doc["action_id"]
        or manifest.get("run_id") != run_id
        or manifest.get("runner_profile_id") != scope_doc["profile_id"]
        or manifest.get("params") != scope_doc["parameters"]
        or not isinstance(manifest.get("request_hash"), str)
        or _DIGEST.fullmatch(str(manifest.get("request_hash"))) is None
        or sealed_profile.get("profile_id") != scope_doc["profile_id"]
        or sealed_profile.get("sandbox_root") != scope_doc["workspace"]["root"]
    ):
        raise _fail("manifest or sealed profile differs from reviewed scope")
    _check_operation_timeout(manifest, scope_doc, operation)
    checked_task_id = _text(task_id, re.compile(r"execute-[0-9a-f]{64}"), "task ID")
    if scope_doc["schema_version"] == SCOPE_SCHEMA_V2:
        _check_installations(
            scope_doc, sealed_profile.get("native_tool_installations"), configured=False
        )
    value = {
        "schema_version": (
            GRANT_SCHEMA_V2 if scope_doc["schema_version"] == SCOPE_SCHEMA_V2 else GRANT_SCHEMA
        ),
        "scope": scope_doc,
        "scope_digest": scope.digest,
        "claim": claim,
        "run_id": _text(run_id, _ID, "run ID"),
        "step_id": scope_doc["step_id"],
        "action_id": scope_doc["action_id"],
        "manifest_request_hash": manifest["request_hash"],
        "operation_binding": operation_binding.to_dict(),
        "execution": {
            "task_id": checked_task_id,
            "manifest_digest": content_hash(manifest),
            "profile_digest": content_hash(sealed_profile),
            "operation_binding_digest": operation_binding.digest,
        },
    }
    return OwnedServiceGrant.from_mapping(value)


def validate_owned_service_grant_for_request(
    grant: OwnedServiceGrant,
    *,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    task_id: str,
    now: datetime | None = None,
    check_expiry: bool = True,
) -> None:
    """Check all request bindings before a receiver may construct admission."""

    if not isinstance(grant, OwnedServiceGrant):
        raise _fail("service request has no validated grant")
    document = grant.to_dict()
    execution = document["execution"]
    claim = document["claim"]
    scope = document["scope"]
    operation = document["operation_binding"]["operation"]
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() != timedelta(0):
        raise _fail("grant validation clock must be timezone-aware")
    current = current.astimezone(timezone.utc)
    setup_expiry = _utc(scope["setup_expires_at"], "setup expiry")
    cleanup_expiry = _utc(scope["cleanup_expires_at"], "cleanup expiry")
    claim_expiry = _utc(claim["approval_expires_at"], "approval expiry", claim_time=True)
    consumed = _utc(claim["consumed_at"], "approval consumed time", claim_time=True)
    created_at = _utc(scope["created_at"], "scope creation time")
    if operation not in (*SETUP_EFFECTS, *CLEANUP_EFFECTS):
        raise _fail("grant operation is outside the reviewed lifecycle")
    setup_authority = operation in SETUP_EFFECTS
    operation_expiry = setup_expiry if setup_authority else cleanup_expiry
    if not created_at <= consumed < setup_expiry or current < consumed:
        raise _fail("claimed approval was not consumed inside its reviewed setup window")
    _check_installations(scope, profile.get("native_tool_installations"), configured=False)
    if check_expiry and (
        current >= operation_expiry or (setup_authority and current >= claim_expiry)
    ):
        raise _fail("service operation grant is expired")
    if (
        document["step_id"] != manifest.get("step_id")
        or document["action_id"] != manifest.get("action_id")
        or document["run_id"] != manifest.get("run_id")
        or document["manifest_request_hash"] != manifest.get("request_hash")
        or manifest.get("params") != scope["parameters"]
        or execution["manifest_digest"] != content_hash(manifest)
        or execution["profile_digest"] != content_hash(profile)
        or execution["task_id"] != task_id
        or claim["profile_id"] != profile.get("profile_id")
        or scope["profile_id"] != profile.get("profile_id")
        or scope["workspace"]["root"] != profile.get("sandbox_root")
    ):
        raise _fail("grant does not match authenticated execution request")
    _check_operation_timeout(manifest, scope, operation)


def _admission_document(value: Any) -> dict[str, Any]:
    data = _object(
        value, frozenset({"schema_version", "grant", "grant_digest", "issuer"}), "admission"
    )
    if data["schema_version"] not in (ADMISSION_SCHEMA, ADMISSION_SCHEMA_V2):
        raise _fail("unsupported admission schema")
    grant = OwnedServiceGrant.from_mapping(data["grant"])
    if (data["schema_version"] == ADMISSION_SCHEMA_V2) != (
        grant.to_dict()["schema_version"] == GRANT_SCHEMA_V2
    ):
        raise _fail("admission and grant schema families differ")
    if _text(data["grant_digest"], _DIGEST, "grant digest") != grant.digest:
        raise _fail("admission grant digest mismatch")
    issuer = _object(
        data["issuer"],
        frozenset(
            {
                "runner_id",
                "client_id",
                "enrollment_generation",
                "peer_fingerprint",
                "server_instance_id",
            }
        ),
        "authenticated issuer",
    )
    issuer_document = {
        "runner_id": _text(issuer["runner_id"], _ID, "enrolled runner ID"),
        "client_id": _text(issuer["client_id"], _ID, "enrolled client ID"),
        "enrollment_generation": _text(
            issuer["enrollment_generation"], _DIGEST, "enrollment generation"
        ),
        "peer_fingerprint": _text(issuer["peer_fingerprint"], _FINGERPRINT, "peer fingerprint"),
        "server_instance_id": _text(issuer["server_instance_id"], _ID, "server instance ID"),
    }
    result = {
        "schema_version": data["schema_version"],
        "grant": grant.to_dict(),
        "grant_digest": grant.digest,
        "issuer": issuer_document,
    }
    if len(canonical_json_bytes(result)) > _MAX_ADMISSION_BYTES:
        raise _fail("admission exceeds its byte bound")
    return result


@dataclass(frozen=True, slots=True)
class OwnedServiceAdmission:
    """Authenticated receiver-to-native handoff; not usable without native support."""

    _canonical: bytes

    def __post_init__(self) -> None:
        if type(self._canonical) is not bytes or len(self._canonical) > _MAX_ADMISSION_BYTES:
            raise _fail("admission must be bounded immutable bytes")
        try:
            normalized = canonical_json_bytes(
                _admission_document(json.loads(self._canonical, object_pairs_hook=_unique_object))
            )
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid admission encoding") from exc
        if normalized != self._canonical:
            raise _fail("admission must use canonical encoding")

    @classmethod
    def create(
        cls, grant: OwnedServiceGrant, *, issuer: Mapping[str, Any]
    ) -> OwnedServiceAdmission:
        return cls(
            canonical_json_bytes(
                _admission_document(
                    {
                        "schema_version": (
                            ADMISSION_SCHEMA_V2
                            if grant.to_dict()["schema_version"] == GRANT_SCHEMA_V2
                            else ADMISSION_SCHEMA
                        ),
                        "grant": grant.to_dict(),
                        "grant_digest": grant.digest,
                        "issuer": dict(issuer),
                    }
                )
            )
        )

    @classmethod
    def from_mapping(cls, value: Any) -> OwnedServiceAdmission:
        return cls(canonical_json_bytes(_admission_document(value)))

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def canonical_bytes(self) -> bytes:
        return self._canonical


__all__ = [
    "ADMISSION_SCHEMA",
    "ADMISSION_SCHEMA_V2",
    "CLEANUP_EFFECTS",
    "GRANT_SCHEMA",
    "GRANT_SCHEMA_V2",
    "OwnedServiceAdmission",
    "OwnedServiceAuthorityError",
    "OwnedServiceGrant",
    "OwnedServiceScope",
    "SCOPE_SCHEMA",
    "SCOPE_SCHEMA_V2",
    "SETUP_EFFECTS",
    "SERVICE_ACTION_ID",
    "compile_owned_service_scope",
    "generate_owned_service_unit_nonce",
    "mint_owned_service_grant",
    "profile_policy_digest",
    "profile_policy_projection",
    "render_owned_service_unit",
    "render_owned_service_unit_bytes",
    "validate_owned_service_grant_for_request",
]
