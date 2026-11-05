"""Effect-free adapter for Strix's reviewed ``bluefire-controlled`` backend.

The module deliberately has no import-time dependency on Strix, Docker, or the
OpenAI Agents SDK.  It describes a narrow controller transport and builds the
SDK subclasses only after the exact installed SDK version and public contract
have been checked.  The transport is injected by the trusted controller; this
module opens no socket, starts no process, and accepts no host path.

The first profile is intentionally one-shot.  Strix receives the already-open
session returned by the registered backend.  Generic SDK ``create`` and
``resume`` entry points refuse so a serialized state or a repeated API call
cannot replay the sandbox effect.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import inspect
import io
import re
import threading
import uuid
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, Awaitable, Callable, Literal, Mapping, Protocol, cast

from .util import content_hash

BACKEND_NAME = "bluefire-controlled"
STRIX_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"
STRIX_PACKAGE_VERSION = "1.7.0"
AGENTS_PACKAGE_VERSION = "0.19.0"
CAIDO_PORT = 48080
WORKSPACE_ROOT = "/workspace"
DEFAULT_EXEC_TIMEOUT_SECONDS = 120.0
MAX_EXEC_ARGUMENTS = 64
MAX_EXEC_ARGUMENT_BYTES = 8192
MAX_EXEC_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_WORKSPACE_OBJECT_BYTES = 32 * 1024 * 1024
WRITE_CHUNK_BYTES = 64 * 1024

_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$")
_RESOURCE_ID = re.compile(r"^sandbox-[0-9a-f]{32}$")
_TRANSFER_ID = re.compile(r"^transfer-[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^operation-[0-9a-f]{32}$")
_OBSERVATION_ID = re.compile(r"^observation-[0-9a-f]{32}$")
_SAFE_RELAY_HOST = "127.0.0.1"
_DEFAULT_REMOTE_COMMAND_ALLOWLIST = (
    "ls",
    "find",
    "stat",
    "cat",
    "less",
    "head",
    "tail",
    "du",
    "grep",
    "rg",
    "wc",
    "sort",
    "cut",
    "cp",
    "tee",
    "echo",
    "mkdir",
    "rm",
)


class ControlledBackendError(RuntimeError):
    """Raised when the controlled backend cannot prove its exact contract."""


class ControlledTransportError(ControlledBackendError):
    """Raised for a typed controller-transport failure."""


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _new_operation_id() -> str:
    return "operation-" + uuid.uuid4().hex


def _new_observation_id() -> str:
    return "observation-" + uuid.uuid4().hex


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ControlledBackendError(f"{label} is invalid")
    return value


def _require_attempt(value: Any) -> str:
    if not isinstance(value, str) or _ATTEMPT_ID.fullmatch(value) is None:
        raise ControlledBackendError("controlled attempt identity is invalid")
    return value


def _require_image(value: Any) -> str:
    if not isinstance(value, str) or _IMAGE_REFERENCE.fullmatch(value) is None:
        raise ControlledBackendError("controlled image reference is invalid")
    return value


def _require_bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ControlledBackendError(f"{label} is outside its bound")
    return int(value)


def _require_identifier(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ControlledBackendError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ControlledRuntimeProfile:
    """Exact non-secret identity and limits for one disposable Strix attempt."""

    schema_version: str
    attempt_id: str
    source_revision: str
    build_digest: str
    policy_digest: str
    relay_digest: str
    relay_upstream_digest: str
    relay_channel_digest: str
    relay_retry_digest: str
    boundary_digest: str
    admission_digest: str
    image_reference: str
    image_digest: str
    manifest_digest: str
    sdk_digest: str
    bootstrap_digest: str
    tmpfs_contract_digest: str
    sandbox_uid: int
    sandbox_gid: int
    profile_digest: str
    exec_timeout_seconds: int = 120
    exec_output_limit_bytes: int = MAX_EXEC_OUTPUT_BYTES
    workspace_object_limit_bytes: int = MAX_WORKSPACE_OBJECT_BYTES
    write_chunk_bytes: int = WRITE_CHUNK_BYTES

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.strix-controlled-profile.v1":
            raise ControlledBackendError("controlled runtime profile schema is unsupported")
        _require_attempt(self.attempt_id)
        if self.source_revision != STRIX_SOURCE_REVISION:
            raise ControlledBackendError("controlled Strix source revision does not match")
        for value, label in (
            (self.build_digest, "controlled build digest"),
            (self.policy_digest, "controlled policy digest"),
            (self.relay_digest, "controlled relay digest"),
            (self.relay_upstream_digest, "controlled relay upstream digest"),
            (self.relay_channel_digest, "controlled relay channel digest"),
            (self.relay_retry_digest, "controlled relay retry digest"),
            (self.boundary_digest, "controlled boundary digest"),
            (self.admission_digest, "controlled admission digest"),
            (self.image_digest, "controlled image digest"),
            (self.manifest_digest, "controlled manifest digest"),
            (self.sdk_digest, "controlled SDK digest"),
            (self.bootstrap_digest, "controlled bootstrap digest"),
            (self.tmpfs_contract_digest, "controlled tmpfs digest"),
            (self.profile_digest, "controlled profile digest"),
        ):
            _require_digest(value, label)
        image = _require_image(self.image_reference)
        if image.rsplit("@", 1)[-1] != self.image_digest:
            raise ControlledBackendError("controlled image reference and digest do not match")
        _require_bounded_int(self.sandbox_uid, "controlled sandbox UID", 1, 2**31 - 1)
        _require_bounded_int(self.sandbox_gid, "controlled sandbox GID", 1, 2**31 - 1)
        if self.sandbox_uid == 0 or self.sandbox_gid == 0:
            raise ControlledBackendError("controlled sandbox identity must be non-root")
        if (
            self.exec_timeout_seconds != 120
            or self.exec_output_limit_bytes != MAX_EXEC_OUTPUT_BYTES
            or self.workspace_object_limit_bytes != MAX_WORKSPACE_OBJECT_BYTES
            or self.write_chunk_bytes != WRITE_CHUNK_BYTES
        ):
            raise ControlledBackendError(
                "controlled runtime limits do not match the reviewed profile"
            )
        if content_hash(self._profile_body()) != self.profile_digest:
            raise ControlledBackendError("controlled profile digest does not match")

    @classmethod
    def create(
        cls,
        *,
        attempt_id: str,
        build_digest: str,
        policy_digest: str,
        relay_digest: str,
        relay_upstream_digest: str,
        relay_channel_digest: str,
        relay_retry_digest: str,
        boundary_digest: str,
        admission_digest: str,
        image_reference: str,
        image_digest: str,
        manifest_digest: str,
        sdk_digest: str,
        bootstrap_digest: str,
        tmpfs_contract_digest: str,
        sandbox_uid: int,
        sandbox_gid: int,
    ) -> "ControlledRuntimeProfile":
        body = {
            "schema_version": "bluefire.strix-controlled-profile.v1",
            "attempt_id": attempt_id,
            "source_revision": STRIX_SOURCE_REVISION,
            "build_digest": build_digest,
            "policy_digest": policy_digest,
            "relay_digest": relay_digest,
            "relay_upstream_digest": relay_upstream_digest,
            "relay_channel_digest": relay_channel_digest,
            "relay_retry_digest": relay_retry_digest,
            "boundary_digest": boundary_digest,
            "admission_digest": admission_digest,
            "image_reference": image_reference,
            "image_digest": image_digest,
            "manifest_digest": manifest_digest,
            "sdk_digest": sdk_digest,
            "bootstrap_digest": bootstrap_digest,
            "tmpfs_contract_digest": tmpfs_contract_digest,
            "sandbox_uid": sandbox_uid,
            "sandbox_gid": sandbox_gid,
            "exec_timeout_seconds": 120,
            "exec_output_limit_bytes": MAX_EXEC_OUTPUT_BYTES,
            "workspace_object_limit_bytes": MAX_WORKSPACE_OBJECT_BYTES,
            "write_chunk_bytes": WRITE_CHUNK_BYTES,
        }
        return cls(
            schema_version="bluefire.strix-controlled-profile.v1",
            attempt_id=attempt_id,
            source_revision=STRIX_SOURCE_REVISION,
            build_digest=build_digest,
            policy_digest=policy_digest,
            relay_digest=relay_digest,
            relay_upstream_digest=relay_upstream_digest,
            relay_channel_digest=relay_channel_digest,
            relay_retry_digest=relay_retry_digest,
            boundary_digest=boundary_digest,
            admission_digest=admission_digest,
            image_reference=image_reference,
            image_digest=image_digest,
            manifest_digest=manifest_digest,
            sdk_digest=sdk_digest,
            bootstrap_digest=bootstrap_digest,
            tmpfs_contract_digest=tmpfs_contract_digest,
            sandbox_uid=sandbox_uid,
            sandbox_gid=sandbox_gid,
            profile_digest=content_hash(body),
        )

    def _profile_body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "source_revision": self.source_revision,
            "build_digest": self.build_digest,
            "policy_digest": self.policy_digest,
            "relay_digest": self.relay_digest,
            "relay_upstream_digest": self.relay_upstream_digest,
            "relay_channel_digest": self.relay_channel_digest,
            "relay_retry_digest": self.relay_retry_digest,
            "boundary_digest": self.boundary_digest,
            "admission_digest": self.admission_digest,
            "image_reference": self.image_reference,
            "image_digest": self.image_digest,
            "manifest_digest": self.manifest_digest,
            "sdk_digest": self.sdk_digest,
            "bootstrap_digest": self.bootstrap_digest,
            "tmpfs_contract_digest": self.tmpfs_contract_digest,
            "sandbox_uid": self.sandbox_uid,
            "sandbox_gid": self.sandbox_gid,
            "exec_timeout_seconds": self.exec_timeout_seconds,
            "exec_output_limit_bytes": self.exec_output_limit_bytes,
            "workspace_object_limit_bytes": self.workspace_object_limit_bytes,
            "write_chunk_bytes": self.write_chunk_bytes,
        }

    @property
    def identity_digest(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.strix-controlled-identity.v1",
                "attempt_id": self.attempt_id,
                "profile_digest": self.profile_digest,
                "policy_digest": self.policy_digest,
                "relay_digest": self.relay_digest,
                "relay_upstream_digest": self.relay_upstream_digest,
                "relay_channel_digest": self.relay_channel_digest,
                "relay_retry_digest": self.relay_retry_digest,
                "boundary_digest": self.boundary_digest,
                "admission_digest": self.admission_digest,
                "image_digest": self.image_digest,
                "manifest_digest": self.manifest_digest,
                "sdk_digest": self.sdk_digest,
                "bootstrap_digest": self.bootstrap_digest,
            }
        )

    @property
    def sandbox_user(self) -> str:
        return f"{self.sandbox_uid}:{self.sandbox_gid}"


@dataclass(frozen=True, slots=True)
class ControlledSandboxHandle:
    attempt_id: str
    resource_id: str
    resource_digest: str
    opaque_ref: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_attempt(self.attempt_id)
        _require_identifier(self.resource_id, "controlled sandbox resource", _RESOURCE_ID)
        _require_digest(self.resource_digest, "controlled sandbox resource digest")
        if self.opaque_ref is None:
            raise ControlledBackendError("controlled sandbox reference is unavailable")


def _request_digest(kind: str, profile: ControlledRuntimeProfile, body: Mapping[str, Any]) -> str:
    return content_hash(
        {
            "schema_version": f"bluefire.strix-controlled-{kind}-request.v1",
            "identity_digest": profile.identity_digest,
            "attempt_id": profile.attempt_id,
            "profile_digest": profile.profile_digest,
            **dict(body),
        }
    )


@dataclass(frozen=True, slots=True)
class ControlledCreateRequest:
    schema_version: str
    attempt_id: str
    identity_digest: str
    profile_digest: str
    request_digest: str
    image_reference: str
    image_digest: str
    manifest_digest: str
    sandbox_user: str
    read_only_root: bool
    tmpfs_contract_digest: str
    exposed_ports: tuple[int, ...]
    host_port_mode: str

    @classmethod
    def create(cls, profile: ControlledRuntimeProfile) -> "ControlledCreateRequest":
        body = {
            "image_reference": profile.image_reference,
            "image_digest": profile.image_digest,
            "manifest_digest": profile.manifest_digest,
            "sandbox_user": profile.sandbox_user,
            "read_only_root": True,
            "tmpfs_contract_digest": profile.tmpfs_contract_digest,
            "exposed_ports": [CAIDO_PORT],
            "host_port_mode": "controller-relay-only",
        }
        return cls(
            schema_version="bluefire.strix-controlled-create-request.v1",
            attempt_id=profile.attempt_id,
            identity_digest=profile.identity_digest,
            profile_digest=profile.profile_digest,
            request_digest=_request_digest("create", profile, body),
            image_reference=profile.image_reference,
            image_digest=profile.image_digest,
            manifest_digest=profile.manifest_digest,
            sandbox_user=profile.sandbox_user,
            read_only_root=True,
            tmpfs_contract_digest=profile.tmpfs_contract_digest,
            exposed_ports=(CAIDO_PORT,),
            host_port_mode="controller-relay-only",
        )


@dataclass(frozen=True, slots=True)
class ControlledCreateReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    handle: ControlledSandboxHandle
    lifecycle: Literal["running"]


@dataclass(frozen=True, slots=True)
class ControlledExecRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    argv: tuple[str, ...] = field(repr=False)
    timeout_seconds: float
    working_directory: str
    stdin_mode: Literal["disabled"] = "disabled"
    pty: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ControlledExecReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    exit_code: int
    stdout_digest: str
    stderr_digest: str
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    complete: bool = True


@dataclass(frozen=True, slots=True)
class ControlledReadRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    observation_id: str
    handle: ControlledSandboxHandle
    workspace_path: str
    byte_limit: int


@dataclass(frozen=True, slots=True)
class ControlledReadReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    workspace_path: str
    content_digest: str
    content: bytes = field(repr=False)
    regular_file: bool = True
    canonical: bool = True


@dataclass(frozen=True, slots=True)
class ControlledWriteBeginRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    workspace_path: str
    content_size: int
    content_digest: str
    chunk_size: int


@dataclass(frozen=True, slots=True)
class ControlledWriteBeginReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    transfer_id: str
    next_offset: int


@dataclass(frozen=True, slots=True)
class ControlledWriteChunkRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    transfer_id: str
    index: int
    offset: int
    total_size: int
    content_digest: str
    chunk_digest: str
    chunk: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ControlledWriteChunkReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    transfer_id: str
    chunk_digest: str
    next_offset: int


@dataclass(frozen=True, slots=True)
class ControlledWriteCommitRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    transfer_id: str
    workspace_path: str
    content_size: int
    content_digest: str


@dataclass(frozen=True, slots=True)
class ControlledWriteCommitReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    transfer_id: str
    workspace_path: str
    content_size: int
    content_digest: str
    atomically_published: bool


@dataclass(frozen=True, slots=True)
class ControlledWriteAbortRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    transfer_id: str


@dataclass(frozen=True, slots=True)
class ControlledLifecycleRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    attempt_id: str
    relay_digest: str
    relay_upstream_digest: str
    relay_channel_digest: str
    relay_retry_digest: str
    observation_id: str | None = None
    handle: ControlledSandboxHandle | None = field(default=None, repr=False)
    operation_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ControlledLifecycleReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str | None
    lifecycle: Literal["running", "cancelled", "absent", "unknown"]
    relay_lifecycle: Literal["active", "absent", "not_applicable", "unknown"]
    operation_lifecycle: Literal["terminal", "not_applicable", "unknown"]


@dataclass(frozen=True, slots=True)
class ControlledWriteReconcileRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    transfer_id: str | None
    workspace_path: str
    content_size: int
    content_digest: str


@dataclass(frozen=True, slots=True)
class ControlledWriteReconcileReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    operation_id: str
    workspace_path: str
    content_size: int
    content_digest: str
    outcome: Literal["published", "not_published", "unknown"]
    transfer_lifecycle: Literal["absent", "active", "unknown"]


@dataclass(frozen=True, slots=True)
class ControlledWorkspaceBlobRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    operation_id: str
    handle: ControlledSandboxHandle
    byte_limit: int
    archive: bytes | None = field(default=None, repr=False)
    archive_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ControlledWorkspaceBlobReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    archive_digest: str
    archive_size: int
    archive: bytes = field(repr=False)
    sealed: bool = True


@dataclass(frozen=True, slots=True)
class ControlledHydrateReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    archive_digest: str
    applied: bool


@dataclass(frozen=True, slots=True)
class ControlledPortRequest:
    schema_version: str
    request_digest: str
    identity_digest: str
    handle: ControlledSandboxHandle
    container_port: int
    relay_digest: str
    upstream_digest: str
    channel_digest: str
    retry_contract_digest: str


@dataclass(frozen=True, slots=True)
class ControlledPortReceipt:
    schema_version: str
    request_digest: str
    identity_digest: str
    resource_digest: str
    container_port: int
    relay_digest: str
    upstream_digest: str
    channel_digest: str
    retry_contract_digest: str
    retry_count: int
    host: str
    port: int
    tls: bool
    published_host_port: bool


class ControlledControllerTransport(Protocol):
    """Controller-owned operations available to the restricted backend.

    Implementations are responsible for enforcing the same identities at the
    effect boundary and for durable custody receipts.  No method accepts a host
    path, Docker endpoint, environment map, arbitrary stdin, or mount.
    """

    async def create_exact(self, request: ControlledCreateRequest) -> ControlledCreateReceipt: ...

    async def reconcile_create(
        self, request: ControlledLifecycleRequest
    ) -> ControlledLifecycleReceipt: ...

    async def exec_exact(self, request: ControlledExecRequest) -> ControlledExecReceipt: ...

    async def cancel_exact(
        self, request: ControlledLifecycleRequest
    ) -> ControlledLifecycleReceipt: ...

    async def read_exact(self, request: ControlledReadRequest) -> ControlledReadReceipt: ...

    async def begin_write_exact(
        self, request: ControlledWriteBeginRequest
    ) -> ControlledWriteBeginReceipt: ...

    async def write_chunk_exact(
        self, request: ControlledWriteChunkRequest
    ) -> ControlledWriteChunkReceipt: ...

    async def commit_write_exact(
        self, request: ControlledWriteCommitRequest
    ) -> ControlledWriteCommitReceipt: ...

    async def reconcile_write_exact(
        self, request: ControlledWriteReconcileRequest
    ) -> ControlledWriteReconcileReceipt: ...

    async def abort_write_exact(
        self, request: ControlledWriteAbortRequest
    ) -> ControlledLifecycleReceipt: ...

    async def running_exact(
        self, request: ControlledLifecycleRequest
    ) -> ControlledLifecycleReceipt: ...

    async def persist_exact(
        self, request: ControlledWorkspaceBlobRequest
    ) -> ControlledWorkspaceBlobReceipt: ...

    async def hydrate_exact(
        self, request: ControlledWorkspaceBlobRequest
    ) -> ControlledHydrateReceipt: ...

    async def resolve_caido_exact(
        self, request: ControlledPortRequest
    ) -> ControlledPortReceipt: ...

    async def delete_exact(
        self, request: ControlledLifecycleRequest
    ) -> ControlledLifecycleReceipt: ...


_TRANSPORT_METHODS = (
    "create_exact",
    "reconcile_create",
    "exec_exact",
    "cancel_exact",
    "read_exact",
    "begin_write_exact",
    "write_chunk_exact",
    "commit_write_exact",
    "reconcile_write_exact",
    "abort_write_exact",
    "running_exact",
    "persist_exact",
    "hydrate_exact",
    "resolve_caido_exact",
    "delete_exact",
)


def _require_transport(transport: Any) -> ControlledControllerTransport:
    if transport is None or any(
        not callable(getattr(transport, name, None)) for name in _TRANSPORT_METHODS
    ):
        raise ControlledBackendError("controlled controller transport is unavailable")
    return cast(ControlledControllerTransport, transport)


@dataclass(frozen=True, slots=True)
class _AgentsContract:
    base_client: type[Any]
    base_session: type[Any]
    state: type[Any]
    exec_result: type[Any]
    exposed_port_endpoint: type[Any]
    resolve_snapshot: Callable[[Any, str], Any]


def _require_parameters(callable_value: Any, expected: tuple[str, ...], label: str) -> None:
    if not callable(callable_value):
        raise ControlledBackendError(f"Agents SDK {label} is unavailable")
    try:
        names = tuple(inspect.signature(callable_value).parameters)
    except (TypeError, ValueError) as exc:
        raise ControlledBackendError(f"Agents SDK {label} signature is unavailable") from exc
    if names != expected:
        raise ControlledBackendError(f"Agents SDK {label} contract changed")


def _load_agents_contract(
    *,
    version_getter: Callable[[str], str],
    module_loader: Callable[[str], Any],
) -> _AgentsContract:
    try:
        installed = version_getter("openai-agents")
    except Exception as exc:
        raise ControlledBackendError("required Agents SDK is unavailable") from exc
    if installed != AGENTS_PACKAGE_VERSION:
        raise ControlledBackendError("Agents SDK version does not match the reviewed contract")
    try:
        session_module = module_loader("agents.sandbox.session")
        snapshot_module = module_loader("agents.sandbox.snapshot")
        types_module = module_loader("agents.sandbox.types")
    except Exception as exc:
        raise ControlledBackendError("reviewed Agents SDK modules are unavailable") from exc
    base_client = getattr(session_module, "BaseSandboxClient", None)
    base_session = getattr(session_module, "BaseSandboxSession", None)
    state = getattr(session_module, "SandboxSessionState", None)
    exec_result = getattr(types_module, "ExecResult", None)
    exposed_port_endpoint = getattr(types_module, "ExposedPortEndpoint", None)
    resolve_snapshot = getattr(snapshot_module, "resolve_snapshot", None)
    if not all(
        isinstance(value, type)
        for value in (
            base_client,
            base_session,
            state,
            exec_result,
            exposed_port_endpoint,
        )
    ):
        raise ControlledBackendError("reviewed Agents SDK public types are unavailable")
    if not callable(resolve_snapshot):
        raise ControlledBackendError("Agents SDK snapshot resolver is unavailable")
    values = _AgentsContract(
        base_client=cast(type[Any], base_client),
        base_session=cast(type[Any], base_session),
        state=cast(type[Any], state),
        exec_result=cast(type[Any], exec_result),
        exposed_port_endpoint=cast(type[Any], exposed_port_endpoint),
        resolve_snapshot=cast(Callable[[Any, str], Any], resolve_snapshot),
    )
    for owner, name, expected in (
        (values.base_client, "create", ("self", "snapshot", "manifest", "options")),
        (values.base_client, "delete", ("self", "session")),
        (values.base_client, "resume", ("self", "state")),
        (values.base_client, "deserialize_session_state", ("self", "payload")),
        (values.base_session, "_exec_internal", ("self", "command", "timeout")),
        (values.base_session, "start", ("self",)),
        (values.base_session, "resolve_exposed_port", ("self", "port")),
        (values.base_session, "read", ("self", "path", "user")),
        (values.base_session, "write", ("self", "path", "data", "user")),
        (values.base_session, "running", ("self",)),
        (values.base_session, "persist_workspace", ("self",)),
        (values.base_session, "hydrate_workspace", ("self", "data")),
    ):
        _require_parameters(getattr(owner, name, None), expected, f"{owner.__name__}.{name}")
    return values


def _expected_manifest_environment(profile: ControlledRuntimeProfile) -> dict[str, str]:
    proxy = f"http://127.0.0.1:{CAIDO_PORT}"
    return {
        "PYTHONUNBUFFERED": "1",
        "HOST_GATEWAY": "host.docker.internal",
        "STRIX_HOST_UID": str(profile.sandbox_uid),
        "STRIX_HOST_GID": str(profile.sandbox_gid),
        "http_proxy": proxy,
        "https_proxy": proxy,
        "ALL_PROXY": proxy,
        "NO_PROXY": "localhost,127.0.0.1",
    }


def validate_controlled_manifest(manifest: Any, profile: ControlledRuntimeProfile) -> str:
    """Validate Strix's exact workspace manifest without resolving dynamic values."""

    if getattr(manifest, "version", None) != 1 or getattr(manifest, "root", None) != WORKSPACE_ROOT:
        raise ControlledBackendError("controlled workspace manifest root is invalid")
    entries = getattr(manifest, "entries", None)
    users = getattr(manifest, "users", None)
    groups = getattr(manifest, "groups", None)
    grants = getattr(manifest, "extra_path_grants", None)
    if not isinstance(entries, Mapping) or entries:
        raise ControlledBackendError("controlled workspace manifest entries are not admitted")
    if users not in ([], ()) or groups not in ([], ()) or grants not in ([], ()):
        raise ControlledBackendError("controlled workspace manifest identities are not admitted")
    allowlist = getattr(manifest, "remote_mount_command_allowlist", None)
    if not isinstance(allowlist, list) or tuple(allowlist) != _DEFAULT_REMOTE_COMMAND_ALLOWLIST:
        raise ControlledBackendError("controlled workspace manifest command contract changed")
    environment = getattr(manifest, "environment", None)
    raw_environment = getattr(environment, "value", None)
    if not isinstance(raw_environment, Mapping) or dict(
        raw_environment
    ) != _expected_manifest_environment(profile):
        raise ControlledBackendError("controlled workspace manifest environment does not match")
    if not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw_environment.items()
    ):
        raise ControlledBackendError("controlled workspace manifest environment is dynamic")
    model_dump = getattr(manifest, "model_dump", None)
    if not callable(model_dump):
        raise ControlledBackendError("controlled workspace manifest cannot be serialized")
    try:
        document = model_dump(mode="json")
        actual = content_hash(document)
    except Exception as exc:
        raise ControlledBackendError("controlled workspace manifest serialization failed") from exc
    if actual != profile.manifest_digest:
        raise ControlledBackendError("controlled workspace manifest digest does not match")
    return actual


def _workspace_path(value: Any) -> str:
    raw = value.as_posix() if isinstance(value, Path) else str(value)
    if (
        not raw
        or "\\" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise ControlledBackendError("controlled workspace path is invalid")
    raw_parts = raw.split("/")
    if raw.startswith("/"):
        raw_parts = raw_parts[1:]
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ControlledBackendError("controlled workspace path is not canonical")
    path = PurePosixPath(raw)
    if not path.is_absolute():
        path = PurePosixPath(WORKSPACE_ROOT) / path
    if path == PurePosixPath(WORKSPACE_ROOT) or ".." in path.parts or "." in path.parts:
        raise ControlledBackendError("controlled workspace path is not a file path")
    try:
        path.relative_to(PurePosixPath(WORKSPACE_ROOT))
    except ValueError as exc:
        raise ControlledBackendError("controlled workspace path escaped its root") from exc
    canonical = path.as_posix()
    if len(canonical.encode("utf-8")) > 1024 or "//" in canonical:
        raise ControlledBackendError("controlled workspace path is outside its bound")
    return canonical


def _bounded_payload(data: io.IOBase, maximum: int) -> bytes:
    if not isinstance(data, io.IOBase):
        raise ControlledBackendError("controlled workspace payload must be a byte stream")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = data.read(WRITE_CHUNK_BYTES)
        if chunk in (b"", ""):
            break
        if not isinstance(chunk, (bytes, bytearray)):
            raise ControlledBackendError("controlled workspace payload must contain bytes")
        value = bytes(chunk)
        total += len(value)
        if total > maximum:
            raise ControlledBackendError("controlled workspace payload exceeds its bound")
        chunks.append(value)
    return b"".join(chunks)


def _operation_lifecycle_request(
    profile: ControlledRuntimeProfile,
    kind: str,
    *,
    handle: ControlledSandboxHandle | None,
    operation_digest: str | None = None,
) -> ControlledLifecycleRequest:
    observation_id = _new_observation_id() if kind == "running" else None
    body: dict[str, Any] = {
        "resource_digest": handle.resource_digest if handle is not None else None,
        "operation_digest": operation_digest,
        "relay_digest": profile.relay_digest,
        "relay_upstream_digest": profile.relay_upstream_digest,
        "relay_channel_digest": profile.relay_channel_digest,
        "relay_retry_digest": profile.relay_retry_digest,
        "observation_id": observation_id,
    }
    return ControlledLifecycleRequest(
        schema_version=f"bluefire.strix-controlled-{kind}-request.v1",
        request_digest=_request_digest(kind, profile, body),
        identity_digest=profile.identity_digest,
        attempt_id=profile.attempt_id,
        relay_digest=profile.relay_digest,
        relay_upstream_digest=profile.relay_upstream_digest,
        relay_channel_digest=profile.relay_channel_digest,
        relay_retry_digest=profile.relay_retry_digest,
        observation_id=observation_id,
        handle=handle,
        operation_digest=operation_digest,
    )


def _check_receipt_identity(
    receipt: Any,
    request_digest: str,
    profile: ControlledRuntimeProfile,
    *,
    resource_digest: str | None = None,
) -> None:
    expected_schema = {
        ControlledCreateReceipt: "bluefire.strix-controlled-create-receipt.v1",
        ControlledExecReceipt: "bluefire.strix-controlled-exec-receipt.v1",
        ControlledReadReceipt: "bluefire.strix-controlled-read-receipt.v1",
        ControlledWriteBeginReceipt: "bluefire.strix-controlled-write-begin-receipt.v1",
        ControlledWriteChunkReceipt: "bluefire.strix-controlled-write-chunk-receipt.v1",
        ControlledWriteCommitReceipt: "bluefire.strix-controlled-write-commit-receipt.v1",
        ControlledWriteReconcileReceipt: "bluefire.strix-controlled-write-reconcile-receipt.v1",
        ControlledLifecycleReceipt: "bluefire.strix-controlled-lifecycle-receipt.v1",
        ControlledWorkspaceBlobReceipt: "bluefire.strix-controlled-persist-receipt.v1",
        ControlledHydrateReceipt: "bluefire.strix-controlled-hydrate-receipt.v1",
        ControlledPortReceipt: "bluefire.strix-controlled-port-receipt.v1",
    }.get(type(receipt))
    if (
        expected_schema is None
        or getattr(receipt, "schema_version", None) != expected_schema
        or getattr(receipt, "request_digest", None) != request_digest
        or getattr(receipt, "identity_digest", None) != profile.identity_digest
        or (
            resource_digest is not None
            and getattr(receipt, "resource_digest", None) != resource_digest
        )
    ):
        raise ControlledTransportError("controlled transport receipt identity drifted")


def _session_types(contract: _AgentsContract) -> tuple[type[Any], type[Any], type[Any]]:
    BaseClient = contract.base_client
    BaseSession = contract.base_session
    State = contract.state

    class ControlledSessionState(State):  # type: ignore[misc, valid-type]
        type: Literal["bluefire-controlled"] = "bluefire-controlled"
        attempt_id: str
        resource_id: str
        resource_digest: str
        identity_digest: str
        profile_digest: str
        policy_digest: str
        relay_digest: str
        relay_upstream_digest: str
        relay_channel_digest: str
        relay_retry_digest: str
        image_digest: str
        sdk_digest: str
        bootstrap_digest: str

    class ControlledSandboxSession(BaseSession):  # type: ignore[misc, valid-type]
        state: ControlledSessionState

        def __init__(
            self,
            *,
            profile: ControlledRuntimeProfile,
            transport: ControlledControllerTransport,
            handle: ControlledSandboxHandle,
            state: ControlledSessionState,
        ) -> None:
            self._profile = profile
            self._transport = transport
            self._handle = handle
            self.state = state
            self._phase = "running"
            self._operation_unknown = False
            self._relay_resolved = False
            self._lock = asyncio.Lock()

        def supports_pty(self) -> bool:
            return False

        def _ensure_active(self) -> None:
            if self._phase != "running" or self._operation_unknown:
                raise ControlledBackendError("controlled sandbox is not available for new work")

        async def _ensure_backend_started(self) -> None:
            alive = await self.running()
            if not alive:
                raise ControlledBackendError("controlled sandbox did not start")

        async def _shutdown_backend(self) -> None:
            await self._delete_owned()

        async def _cancel(self, operation_digest: str) -> None:
            request = _operation_lifecycle_request(
                self._profile,
                "cancel",
                handle=self._handle,
                operation_digest=operation_digest,
            )
            try:
                receipt = await self._transport.cancel_exact(request)
                _check_receipt_identity(
                    receipt,
                    request.request_digest,
                    self._profile,
                    resource_digest=self._handle.resource_digest,
                )
                if (
                    receipt.lifecycle not in {"cancelled", "absent"}
                    or receipt.operation_lifecycle != "terminal"
                ):
                    self._operation_unknown = True
            except BaseException:
                self._operation_unknown = True

        async def _exec_internal(self, *command: str | Path, timeout: float | None = None) -> Any:
            argv = tuple(str(item) for item in command)
            if not argv or len(argv) > MAX_EXEC_ARGUMENTS:
                raise ControlledBackendError("controlled exec argument count is invalid")
            encoded = 0
            for item in argv:
                if not item or any(
                    (ord(character) < 32 and character not in {"\t", "\n"}) or ord(character) == 127
                    for character in item
                ):
                    raise ControlledBackendError("controlled exec argument is invalid")
                encoded += len(item.encode("utf-8"))
            if encoded > MAX_EXEC_ARGUMENT_BYTES:
                raise ControlledBackendError("controlled exec arguments exceed their bound")
            deadline = DEFAULT_EXEC_TIMEOUT_SECONDS if timeout is None else timeout
            if (
                isinstance(deadline, bool)
                or not isinstance(deadline, (int, float))
                or not 0 < float(deadline) <= self._profile.exec_timeout_seconds
            ):
                raise ControlledBackendError("controlled exec deadline is invalid")
            operation_id = _new_operation_id()
            body = {
                "resource_digest": self._handle.resource_digest,
                "operation_id": operation_id,
                "argv": list(argv),
                "timeout_seconds": float(deadline),
                "working_directory": WORKSPACE_ROOT,
                "stdin_mode": "disabled",
                "pty": False,
            }
            request = ControlledExecRequest(
                schema_version="bluefire.strix-controlled-exec-request.v1",
                request_digest=_request_digest("exec", self._profile, body),
                identity_digest=self._profile.identity_digest,
                operation_id=operation_id,
                handle=self._handle,
                argv=argv,
                timeout_seconds=float(deadline),
                working_directory=WORKSPACE_ROOT,
            )
            async with self._lock:
                self._ensure_active()
                try:
                    receipt = await self._transport.exec_exact(request)
                except asyncio.CancelledError:
                    await self._cancel(request.request_digest)
                    raise
                except BaseException:
                    self._operation_unknown = True
                    raise
                try:
                    _check_receipt_identity(
                        receipt,
                        request.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                    if not receipt.complete:
                        raise ControlledTransportError("controlled exec receipt is partial")
                    if (
                        not isinstance(receipt.exit_code, int)
                        or isinstance(receipt.exit_code, bool)
                        or not -1 <= receipt.exit_code <= 255
                        or not isinstance(receipt.stdout, bytes)
                        or not isinstance(receipt.stderr, bytes)
                        or len(receipt.stdout) + len(receipt.stderr)
                        > self._profile.exec_output_limit_bytes
                        or _sha256_bytes(receipt.stdout) != receipt.stdout_digest
                        or _sha256_bytes(receipt.stderr) != receipt.stderr_digest
                    ):
                        raise ControlledTransportError("controlled exec receipt is invalid")
                except BaseException:
                    self._operation_unknown = True
                    raise
                return contract.exec_result(
                    stdout=receipt.stdout,
                    stderr=receipt.stderr,
                    exit_code=receipt.exit_code,
                )

        @staticmethod
        def _check_user(user: Any, profile: ControlledRuntimeProfile) -> None:
            if user is None:
                return
            raw = getattr(user, "name", user)
            allowed = {str(profile.sandbox_uid), profile.sandbox_user}
            if not isinstance(raw, str) or raw not in allowed:
                raise ControlledBackendError("controlled sandbox user is not admitted")

        async def read(self, path: Path, *, user: Any = None) -> io.IOBase:
            self._check_user(user, self._profile)
            workspace_path = _workspace_path(path)
            observation_id = _new_observation_id()
            body = {
                "resource_digest": self._handle.resource_digest,
                "observation_id": observation_id,
                "workspace_path": workspace_path,
                "byte_limit": self._profile.workspace_object_limit_bytes,
            }
            request = ControlledReadRequest(
                schema_version="bluefire.strix-controlled-read-request.v1",
                request_digest=_request_digest("read", self._profile, body),
                identity_digest=self._profile.identity_digest,
                observation_id=observation_id,
                handle=self._handle,
                workspace_path=workspace_path,
                byte_limit=self._profile.workspace_object_limit_bytes,
            )
            async with self._lock:
                self._ensure_active()
                receipt = await self._transport.read_exact(request)
                _check_receipt_identity(
                    receipt,
                    request.request_digest,
                    self._profile,
                    resource_digest=self._handle.resource_digest,
                )
                if (
                    receipt.workspace_path != workspace_path
                    or not receipt.regular_file
                    or not receipt.canonical
                    or not isinstance(receipt.content, bytes)
                    or len(receipt.content) > self._profile.workspace_object_limit_bytes
                    or _sha256_bytes(receipt.content) != receipt.content_digest
                ):
                    raise ControlledTransportError("controlled read receipt is invalid")
                return io.BytesIO(receipt.content)

        async def write(self, path: Path, data: io.IOBase, *, user: Any = None) -> None:
            self._check_user(user, self._profile)
            workspace_path = _workspace_path(path)
            payload = _bounded_payload(data, self._profile.workspace_object_limit_bytes)
            content_digest = _sha256_bytes(payload)
            operation_id = _new_operation_id()
            begin_body = {
                "resource_digest": self._handle.resource_digest,
                "operation_id": operation_id,
                "workspace_path": workspace_path,
                "content_size": len(payload),
                "content_digest": content_digest,
                "chunk_size": self._profile.write_chunk_bytes,
            }
            begin = ControlledWriteBeginRequest(
                schema_version="bluefire.strix-controlled-write-begin-request.v1",
                request_digest=_request_digest("write-begin", self._profile, begin_body),
                identity_digest=self._profile.identity_digest,
                operation_id=operation_id,
                handle=self._handle,
                workspace_path=workspace_path,
                content_size=len(payload),
                content_digest=content_digest,
                chunk_size=self._profile.write_chunk_bytes,
            )
            async with self._lock:
                self._ensure_active()
                started: ControlledWriteBeginReceipt | None = None
                transfer_id: str | None = None
                try:
                    started = await self._transport.begin_write_exact(begin)
                    _check_receipt_identity(
                        started,
                        begin.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                    transfer_id = _require_identifier(
                        started.transfer_id, "controlled write transfer", _TRANSFER_ID
                    )
                    if started.next_offset != 0:
                        raise ControlledTransportError("controlled write began at the wrong offset")
                    offset = 0
                    index = 0
                    while offset < len(payload):
                        chunk = payload[offset : offset + self._profile.write_chunk_bytes]
                        chunk_digest = _sha256_bytes(chunk)
                        chunk_body = {
                            "resource_digest": self._handle.resource_digest,
                            "operation_id": operation_id,
                            "transfer_id": transfer_id,
                            "index": index,
                            "offset": offset,
                            "total_size": len(payload),
                            "content_digest": content_digest,
                            "chunk_digest": chunk_digest,
                        }
                        chunk_request = ControlledWriteChunkRequest(
                            schema_version="bluefire.strix-controlled-write-chunk-request.v1",
                            request_digest=_request_digest(
                                "write-chunk", self._profile, chunk_body
                            ),
                            identity_digest=self._profile.identity_digest,
                            operation_id=operation_id,
                            handle=self._handle,
                            transfer_id=transfer_id,
                            index=index,
                            offset=offset,
                            total_size=len(payload),
                            content_digest=content_digest,
                            chunk_digest=chunk_digest,
                            chunk=chunk,
                        )
                        chunk_receipt = await self._transport.write_chunk_exact(chunk_request)
                        _check_receipt_identity(
                            chunk_receipt,
                            chunk_request.request_digest,
                            self._profile,
                            resource_digest=self._handle.resource_digest,
                        )
                        offset += len(chunk)
                        if (
                            chunk_receipt.transfer_id != transfer_id
                            or chunk_receipt.chunk_digest != chunk_digest
                            or chunk_receipt.next_offset != offset
                        ):
                            raise ControlledTransportError("controlled write chunk receipt drifted")
                        index += 1
                    commit_body = {
                        "resource_digest": self._handle.resource_digest,
                        "operation_id": operation_id,
                        "transfer_id": transfer_id,
                        "workspace_path": workspace_path,
                        "content_size": len(payload),
                        "content_digest": content_digest,
                    }
                    commit = ControlledWriteCommitRequest(
                        schema_version="bluefire.strix-controlled-write-commit-request.v1",
                        request_digest=_request_digest("write-commit", self._profile, commit_body),
                        identity_digest=self._profile.identity_digest,
                        operation_id=operation_id,
                        handle=self._handle,
                        transfer_id=transfer_id,
                        workspace_path=workspace_path,
                        content_size=len(payload),
                        content_digest=content_digest,
                    )
                    committed = await self._transport.commit_write_exact(commit)
                    _check_receipt_identity(
                        committed,
                        commit.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                    if (
                        committed.transfer_id != transfer_id
                        or committed.workspace_path != workspace_path
                        or committed.content_size != len(payload)
                        or committed.content_digest != content_digest
                        or not committed.atomically_published
                    ):
                        raise ControlledTransportError("controlled write commit is invalid")
                except BaseException as write_error:
                    reconcile_body = {
                        "resource_digest": self._handle.resource_digest,
                        "operation_id": operation_id,
                        "transfer_id": transfer_id,
                        "workspace_path": workspace_path,
                        "content_size": len(payload),
                        "content_digest": content_digest,
                    }
                    reconcile = ControlledWriteReconcileRequest(
                        schema_version="bluefire.strix-controlled-write-reconcile-request.v1",
                        request_digest=_request_digest(
                            "write-reconcile", self._profile, reconcile_body
                        ),
                        identity_digest=self._profile.identity_digest,
                        operation_id=operation_id,
                        handle=self._handle,
                        transfer_id=transfer_id,
                        workspace_path=workspace_path,
                        content_size=len(payload),
                        content_digest=content_digest,
                    )
                    try:
                        reconciled = await self._transport.reconcile_write_exact(reconcile)
                        _check_receipt_identity(
                            reconciled,
                            reconcile.request_digest,
                            self._profile,
                            resource_digest=self._handle.resource_digest,
                        )
                        if (
                            reconciled.operation_id != operation_id
                            or reconciled.workspace_path != workspace_path
                            or reconciled.content_size != len(payload)
                            or reconciled.content_digest != content_digest
                            or reconciled.transfer_lifecycle != "absent"
                        ):
                            raise ControlledTransportError(
                                "controlled write reconciliation drifted"
                            )
                    except BaseException as reconcile_error:
                        self._operation_unknown = True
                        raise ControlledTransportError(
                            "controlled write outcome is unknown"
                        ) from reconcile_error
                    if reconciled.outcome == "published":
                        if isinstance(write_error, asyncio.CancelledError):
                            raise write_error
                        return
                    if reconciled.outcome != "not_published":
                        self._operation_unknown = True
                        raise ControlledTransportError(
                            "controlled write outcome is unknown"
                        ) from write_error
                    if transfer_id is not None:
                        abort_body = {
                            "resource_digest": self._handle.resource_digest,
                            "operation_id": operation_id,
                            "transfer_id": transfer_id,
                        }
                        abort = ControlledWriteAbortRequest(
                            schema_version="bluefire.strix-controlled-write-abort-request.v1",
                            request_digest=_request_digest(
                                "write-abort", self._profile, abort_body
                            ),
                            identity_digest=self._profile.identity_digest,
                            operation_id=operation_id,
                            handle=self._handle,
                            transfer_id=transfer_id,
                        )
                        try:
                            aborted = await self._transport.abort_write_exact(abort)
                            _check_receipt_identity(
                                aborted,
                                abort.request_digest,
                                self._profile,
                                resource_digest=self._handle.resource_digest,
                            )
                            if aborted.lifecycle not in {"absent", "cancelled"}:
                                self._operation_unknown = True
                        except BaseException:
                            self._operation_unknown = True
                    if self._operation_unknown:
                        raise ControlledTransportError(
                            "controlled write cleanup is unverified"
                        ) from write_error
                    raise

        async def running(self) -> bool:
            request = _operation_lifecycle_request(self._profile, "running", handle=self._handle)
            async with self._lock:
                if self._phase == "absent":
                    return False
                try:
                    receipt = await self._transport.running_exact(request)
                    _check_receipt_identity(
                        receipt,
                        request.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                except BaseException:
                    self._phase = "unknown"
                    raise
                admitted_relay_states = (
                    {"active"} if self._relay_resolved else {"active", "not_applicable"}
                )
                if (
                    receipt.lifecycle == "running"
                    and receipt.relay_lifecycle in admitted_relay_states
                    and receipt.operation_lifecycle == "not_applicable"
                ):
                    return True
                if receipt.lifecycle == "absent" and receipt.relay_lifecycle == "absent":
                    self._phase = "absent"
                    return False
                self._phase = "unknown"
                raise ControlledTransportError("controlled sandbox running state is unknown")

        async def persist_workspace(self) -> io.IOBase:
            operation_id = _new_operation_id()
            body = {
                "resource_digest": self._handle.resource_digest,
                "operation_id": operation_id,
                "byte_limit": self._profile.workspace_object_limit_bytes,
            }
            request = ControlledWorkspaceBlobRequest(
                schema_version="bluefire.strix-controlled-persist-request.v1",
                request_digest=_request_digest("persist", self._profile, body),
                identity_digest=self._profile.identity_digest,
                operation_id=operation_id,
                handle=self._handle,
                byte_limit=self._profile.workspace_object_limit_bytes,
            )
            async with self._lock:
                self._ensure_active()
                receipt = await self._transport.persist_exact(request)
                _check_receipt_identity(
                    receipt,
                    request.request_digest,
                    self._profile,
                    resource_digest=self._handle.resource_digest,
                )
                if (
                    not receipt.sealed
                    or not isinstance(receipt.archive, bytes)
                    or receipt.archive_size != len(receipt.archive)
                    or receipt.archive_size > self._profile.workspace_object_limit_bytes
                    or _sha256_bytes(receipt.archive) != receipt.archive_digest
                ):
                    raise ControlledTransportError("controlled workspace archive is invalid")
                return io.BytesIO(receipt.archive)

        async def hydrate_workspace(self, data: io.IOBase) -> None:
            archive = _bounded_payload(data, self._profile.workspace_object_limit_bytes)
            archive_digest = _sha256_bytes(archive)
            operation_id = _new_operation_id()
            body = {
                "resource_digest": self._handle.resource_digest,
                "operation_id": operation_id,
                "byte_limit": self._profile.workspace_object_limit_bytes,
                "archive_digest": archive_digest,
                "archive_size": len(archive),
            }
            request = ControlledWorkspaceBlobRequest(
                schema_version="bluefire.strix-controlled-hydrate-request.v1",
                request_digest=_request_digest("hydrate", self._profile, body),
                identity_digest=self._profile.identity_digest,
                operation_id=operation_id,
                handle=self._handle,
                byte_limit=self._profile.workspace_object_limit_bytes,
                archive=archive,
                archive_digest=archive_digest,
            )
            async with self._lock:
                self._ensure_active()
                try:
                    receipt = await self._transport.hydrate_exact(request)
                    _check_receipt_identity(
                        receipt,
                        request.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                    if receipt.archive_digest != archive_digest or not receipt.applied:
                        raise ControlledTransportError("controlled workspace hydration is invalid")
                except BaseException:
                    self._operation_unknown = True
                    raise

        async def _resolve_exposed_port(self, port: int) -> Any:
            if port != CAIDO_PORT:
                raise ControlledBackendError("controlled sandbox exposes only the Caido port")
            body = {
                "resource_digest": self._handle.resource_digest,
                "container_port": port,
                "relay_digest": self._profile.relay_digest,
                "upstream_digest": self._profile.relay_upstream_digest,
                "channel_digest": self._profile.relay_channel_digest,
                "retry_contract_digest": self._profile.relay_retry_digest,
            }
            request = ControlledPortRequest(
                schema_version="bluefire.strix-controlled-port-request.v1",
                request_digest=_request_digest("port", self._profile, body),
                identity_digest=self._profile.identity_digest,
                handle=self._handle,
                container_port=port,
                relay_digest=self._profile.relay_digest,
                upstream_digest=self._profile.relay_upstream_digest,
                channel_digest=self._profile.relay_channel_digest,
                retry_contract_digest=self._profile.relay_retry_digest,
            )
            try:
                async with self._lock:
                    self._ensure_active()
                    receipt = await self._transport.resolve_caido_exact(request)
                    _check_receipt_identity(
                        receipt,
                        request.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                    if (
                        receipt.container_port != CAIDO_PORT
                        or receipt.relay_digest != self._profile.relay_digest
                        or receipt.upstream_digest != self._profile.relay_upstream_digest
                        or receipt.channel_digest != self._profile.relay_channel_digest
                        or receipt.retry_contract_digest != self._profile.relay_retry_digest
                        or receipt.retry_count != 0
                        or receipt.host != _SAFE_RELAY_HOST
                        or isinstance(receipt.port, bool)
                        or not isinstance(receipt.port, int)
                        or not 1 <= receipt.port <= 65535
                        or receipt.tls is not False
                        or receipt.published_host_port
                    ):
                        raise ControlledTransportError("controlled Caido relay receipt is invalid")
                    self._relay_resolved = True
                    return contract.exposed_port_endpoint(
                        host=receipt.host,
                        port=receipt.port,
                        tls=receipt.tls,
                        query="",
                    )
            except BaseException as relay_error:
                try:
                    await self._delete_owned()
                except BaseException as cleanup_error:
                    raise ControlledTransportError(
                        "controlled Caido relay failure is not reconciled"
                    ) from cleanup_error
                raise relay_error

        async def _delete_owned(self) -> None:
            async with self._lock:
                if self._phase == "absent":
                    return
                self._phase = "deleting"
                request = _operation_lifecycle_request(self._profile, "delete", handle=self._handle)
                try:
                    receipt = await self._transport.delete_exact(request)
                    _check_receipt_identity(
                        receipt,
                        request.request_digest,
                        self._profile,
                        resource_digest=self._handle.resource_digest,
                    )
                except BaseException:
                    self._phase = "unknown"
                    raise
                if receipt.lifecycle != "absent" or receipt.relay_lifecycle != "absent":
                    self._phase = "unknown"
                    raise ControlledTransportError("controlled sandbox deletion is unverified")
                self._phase = "absent"
                self._operation_unknown = False

    class ControlledSandboxClient(BaseClient):  # type: ignore[misc, valid-type]
        backend_id = BACKEND_NAME
        supports_default_options = False

        def __init__(
            self,
            *,
            profile: ControlledRuntimeProfile,
            transport: ControlledControllerTransport,
        ) -> None:
            super().__init__()
            self._profile = profile
            self._transport = transport
            self._opened = False
            self._session: ControlledSandboxSession | None = None

        async def create(
            self,
            *,
            snapshot: Any = None,
            manifest: Any = None,
            options: Any,
        ) -> Any:
            _ = (snapshot, manifest, options)
            raise ControlledBackendError("generic controlled sandbox creation is disabled")

        async def resume(self, state: Any) -> Any:
            _ = state
            raise ControlledBackendError("controlled sandbox resume is disabled")

        def deserialize_session_state(self, payload: dict[str, object]) -> Any:
            model_validate = getattr(ControlledSessionState, "model_validate", None)
            if not callable(model_validate):
                raise ControlledBackendError("controlled session state parser is unavailable")
            state = model_validate(payload)
            if (
                getattr(state, "attempt_id", None) != self._profile.attempt_id
                or getattr(state, "identity_digest", None) != self._profile.identity_digest
                or getattr(state, "profile_digest", None) != self._profile.profile_digest
                or getattr(state, "relay_digest", None) != self._profile.relay_digest
                or getattr(state, "relay_upstream_digest", None)
                != self._profile.relay_upstream_digest
                or getattr(state, "relay_channel_digest", None)
                != self._profile.relay_channel_digest
                or getattr(state, "relay_retry_digest", None) != self._profile.relay_retry_digest
            ):
                raise ControlledBackendError("controlled session state identity drifted")
            return state

        async def open_live_session(self, manifest: Any) -> ControlledSandboxSession:
            if self._opened:
                raise ControlledBackendError("controlled sandbox creation cannot be replayed")
            self._opened = True
            request = ControlledCreateRequest.create(self._profile)
            try:
                receipt = await self._transport.create_exact(request)
                _check_receipt_identity(receipt, request.request_digest, self._profile)
                if (
                    receipt.lifecycle != "running"
                    or not isinstance(receipt.handle, ControlledSandboxHandle)
                    or receipt.handle.attempt_id != self._profile.attempt_id
                ):
                    raise ControlledTransportError("controlled sandbox create receipt is invalid")
            except BaseException as create_error:
                reconcile = _operation_lifecycle_request(
                    self._profile,
                    "reconcile-create",
                    handle=None,
                    operation_digest=request.request_digest,
                )
                reconciled = False
                try:
                    settled = await self._transport.reconcile_create(reconcile)
                    _check_receipt_identity(settled, reconcile.request_digest, self._profile)
                    reconciled = (
                        settled.lifecycle == "absent" and settled.relay_lifecycle == "absent"
                    )
                except BaseException:
                    pass
                if not reconciled:
                    raise ControlledTransportError(
                        "controlled partial creation is not reconciled"
                    ) from create_error
                raise
            handle = receipt.handle
            try:
                session_id = uuid.uuid4()
                snapshot = contract.resolve_snapshot(None, str(session_id))
                state = ControlledSessionState(
                    session_id=session_id,
                    snapshot=snapshot,
                    manifest=manifest,
                    exposed_ports=(CAIDO_PORT,),
                    workspace_root_ready=False,
                    attempt_id=self._profile.attempt_id,
                    resource_id=handle.resource_id,
                    resource_digest=handle.resource_digest,
                    identity_digest=self._profile.identity_digest,
                    profile_digest=self._profile.profile_digest,
                    policy_digest=self._profile.policy_digest,
                    relay_digest=self._profile.relay_digest,
                    relay_upstream_digest=self._profile.relay_upstream_digest,
                    relay_channel_digest=self._profile.relay_channel_digest,
                    relay_retry_digest=self._profile.relay_retry_digest,
                    image_digest=self._profile.image_digest,
                    sdk_digest=self._profile.sdk_digest,
                    bootstrap_digest=self._profile.bootstrap_digest,
                )
                self._session = ControlledSandboxSession(
                    profile=self._profile,
                    transport=self._transport,
                    handle=handle,
                    state=state,
                )
            except BaseException as assembly_error:
                cleanup = asyncio.create_task(
                    _delete_created_handle(self._profile, self._transport, handle)
                )
                cleaned = False
                try:
                    cleaned = await asyncio.shield(cleanup)
                except BaseException:
                    pass
                if not cleaned:
                    raise ControlledTransportError(
                        "controlled post-create initialization is not reconciled"
                    ) from assembly_error
                raise
            return self._session

        async def delete(self, session: Any) -> Any:
            if session is not self._session or not isinstance(session, ControlledSandboxSession):
                raise ControlledBackendError("controlled client does not own this session")
            await session._delete_owned()
            return session

    return ControlledSessionState, ControlledSandboxSession, ControlledSandboxClient


async def _delete_created_handle(
    profile: ControlledRuntimeProfile,
    transport: ControlledControllerTransport,
    handle: ControlledSandboxHandle,
) -> bool:
    """Delete a created resource before an SDK session exists to own it."""

    request = _operation_lifecycle_request(profile, "delete", handle=handle)
    try:
        receipt = await transport.delete_exact(request)
        _check_receipt_identity(
            receipt,
            request.request_digest,
            profile,
            resource_digest=handle.resource_digest,
        )
    except BaseException:
        return False
    return (
        receipt.lifecycle == "absent"
        and receipt.relay_lifecycle == "absent"
        and receipt.operation_lifecycle in {"terminal", "not_applicable"}
    )


async def _cleanup_failed_start(client: Any, session: Any) -> bool:
    try:
        await client.delete(session)
    except BaseException:
        return False
    return True


def create_registered_backend(
    profile: ControlledRuntimeProfile,
    transport: ControlledControllerTransport,
    *,
    version_getter: Callable[[str], str] = metadata.version,
    module_loader: Callable[[str], Any] = importlib.import_module,
) -> Callable[..., Awaitable[tuple[Any, Any]]]:
    """Return the public Strix backend callable for one exact attempt."""

    checked_transport = _require_transport(transport)
    consumption_lock = threading.Lock()
    consumed = False

    async def backend(
        *,
        image: str,
        manifest: Any,
        exposed_ports: tuple[int, ...],
        bind_mounts: list[dict[str, Any]] | None = None,
    ) -> tuple[Any, Any]:
        nonlocal consumed
        if image != profile.image_reference:
            raise ControlledBackendError("controlled backend image does not match")
        if exposed_ports != (CAIDO_PORT,):
            raise ControlledBackendError("controlled backend exposes only Caido")
        if bind_mounts not in (None, []):
            raise ControlledBackendError("controlled backend does not permit bind mounts")
        validate_controlled_manifest(manifest, profile)
        contract = _load_agents_contract(
            version_getter=version_getter,
            module_loader=module_loader,
        )
        _, _, Client = _session_types(contract)
        with consumption_lock:
            if consumed:
                raise ControlledBackendError("controlled sandbox creation cannot be replayed")
            consumed = True
        client = Client(profile=profile, transport=checked_transport)
        session = await client.open_live_session(manifest)
        try:
            await session.start()
        except BaseException as start_error:
            cleanup = asyncio.create_task(_cleanup_failed_start(client, session))
            cleaned = False
            try:
                cleaned = await asyncio.shield(cleanup)
            except BaseException:
                pass
            if not cleaned:
                raise ControlledTransportError(
                    "controlled failed start is not reconciled"
                ) from start_error
            raise
        return client, session

    return backend


__all__ = [
    "AGENTS_PACKAGE_VERSION",
    "BACKEND_NAME",
    "CAIDO_PORT",
    "ControlledBackendError",
    "ControlledControllerTransport",
    "ControlledCreateRequest",
    "ControlledCreateReceipt",
    "ControlledExecRequest",
    "ControlledExecReceipt",
    "ControlledHydrateReceipt",
    "ControlledLifecycleRequest",
    "ControlledLifecycleReceipt",
    "ControlledPortRequest",
    "ControlledPortReceipt",
    "ControlledReadRequest",
    "ControlledReadReceipt",
    "ControlledRuntimeProfile",
    "ControlledSandboxHandle",
    "ControlledTransportError",
    "ControlledWorkspaceBlobReceipt",
    "ControlledWorkspaceBlobRequest",
    "ControlledWriteAbortRequest",
    "ControlledWriteBeginRequest",
    "ControlledWriteBeginReceipt",
    "ControlledWriteChunkRequest",
    "ControlledWriteChunkReceipt",
    "ControlledWriteCommitRequest",
    "ControlledWriteCommitReceipt",
    "ControlledWriteReconcileRequest",
    "ControlledWriteReconcileReceipt",
    "STRIX_PACKAGE_VERSION",
    "STRIX_SOURCE_REVISION",
    "create_registered_backend",
    "validate_controlled_manifest",
]
