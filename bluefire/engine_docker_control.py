"""Fail-closed Docker API authorization for one Strix attempt.

This module is deliberately effect-free: it opens no socket, contacts no
daemon, starts no process, and rewrites no upstream request. A future private
Unix-socket proxy can normalize one request into :class:`DockerApiRequest`,
authorize it here, and enforce the returned response contract.

The pinned upstream currently emits unsafe create options (including a host
gateway) and omits BlueFire's custody label. Those raw requests are therefore
expected to be refused until a separately reviewed backend emits this exact
contract. The policy never silently repairs an unsafe request.
"""

from __future__ import annotations

import json
import re
from dataclasses import InitVar, asdict, dataclass, fields, replace
from dataclasses import field as dataclass_field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from .engine_container_custody import (
    V2_RUNTIME_PLATFORM,
    ContainerCustodyPlan,
    ContainerCustodyPlanV2,
    EngineContainerCustodyError,
    container_image_identity_digest,
)
from .engine_network_policy import EngineNetworkPlan, EngineNetworkPlanV2, EngineNetworkPolicyError
from .strix_adapter import StrixBuildIdentity
from .strix_controlled_execution_identity import (
    StrixControlledExecutionIdentityError,
    StrixControlledExecutionIdentityV2,
)
from .strix_image_contract import (
    StrixImageAdmissionDecisionV2,
    StrixImageContractError,
    StrixImageContractV2,
    proposed_image_runtime_profile,
    validate_v2_image_reference,
)
from .util import content_hash, json_clone


class EngineDockerPolicyError(ValueError):
    """Raised when a request or controller policy is not admissible."""


class DockerApiOperation(str, Enum):
    PING = "ping"
    VERSION = "version"
    INFO = "info"
    IMAGE_INSPECT = "image_inspect"
    CONTAINER_CREATE = "container_create"
    CONTAINER_START = "container_start"
    CONTAINER_INSPECT = "container_inspect"
    CONTAINER_EXEC_CREATE = "container_exec_create"
    CONTAINER_ARCHIVE = "container_archive"
    CONTAINER_LOGS = "container_logs"
    CONTAINER_STOP = "container_stop"
    CONTAINER_KILL = "container_kill"
    CONTAINER_DELETE = "container_delete"
    EXEC_START = "exec_start"
    EXEC_INSPECT = "exec_inspect"


class DockerResponseContract(str, Enum):
    PING = "ping"
    VERSION_REDACTED = "version_redacted"
    INFO_REDACTED = "info_redacted"
    EXACT_IMAGE = "exact_image"
    REGISTER_PENDING_CONTAINER = "register_pending_container"
    VERIFY_AND_REGISTER_CONTAINER = "verify_and_register_container"
    OWNED_CONTAINER = "owned_container"
    REGISTER_EXEC = "register_exec"
    OWNED_EXEC = "owned_exec"
    EMPTY = "empty"
    BOUNDED_ARCHIVE = "bounded_archive"
    BOUNDED_LOG_STREAM = "bounded_log_stream"
    BOUNDED_EXEC_STREAM = "bounded_exec_stream"


_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_ID = re.compile(r"^[0-9a-f]{12,64}$")
_FULL_RESOURCE_ID = re.compile(r"^[0-9a-f]{64}$")
_API_VERSION = re.compile(r"^v1\.(?:4[4-9]|[5-9][0-9])$")
_HEADER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_CONTAINER_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_CGROUP_PARENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,191}$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$")
_LABEL_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,127}$")
_NETWORK_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_TMPFS_OPTION = re.compile(
    r"^(?:rw|ro|nodev|nosuid|noexec|exec|size=[1-9][0-9]{0,11}[kmg]?|mode=0[0-7]{3})$"
)
_V1_PROJECTION_TMPFS_OPTIONS = "nodev,nosuid,rw,size=512m"
_PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}")
_BODY_LIMIT = 64 * 1024
_TARGET_LIMIT = 2048
_MAX_EXEC_ARGUMENTS = 64
_MAX_EXEC_ARGUMENT_BYTES = 8192
_MAX_LOG_TAIL = 10_000
_MAX_STOP_SECONDS = 30
_ALLOWED_HEADERS = frozenset({"accept", "content-length", "content-type", "host", "user-agent"})


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineDockerPolicyError(f"{label} fields do not match the contract")
    return value


def _text(
    value: Any,
    label: str,
    pattern: re.Pattern[str] | None = None,
    *,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise EngineDockerPolicyError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    return _text(value, label, _DIGEST, maximum=71)


def _string_tuple(
    value: Sequence[str], label: str, pattern: re.Pattern[str], *, maximum_items: int
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or len(value) > maximum_items:
        raise EngineDockerPolicyError(f"{label} is invalid")
    result = tuple(_text(item, label, pattern, maximum=128) for item in value)
    if tuple(sorted(set(result))) != result:
        raise EngineDockerPolicyError(f"{label} must be unique and sorted")
    return result


def _json_object(raw: bytes, label: str) -> Mapping[str, Any]:
    if not raw or len(raw) > _BODY_LIMIT:
        raise EngineDockerPolicyError(f"{label} JSON body is outside its bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EngineDockerPolicyError(f"{label} JSON body is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise EngineDockerPolicyError(f"{label} JSON body must not contain a BOM")

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in rows:
            if key in result:
                raise EngineDockerPolicyError(f"{label} JSON body contains duplicate keys")
            result[key] = item
        return result

    def constant(_: str) -> None:
        raise EngineDockerPolicyError(f"{label} JSON body contains a non-finite number")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except EngineDockerPolicyError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EngineDockerPolicyError(f"{label} JSON body is invalid") from exc
    if not isinstance(value, Mapping):
        raise EngineDockerPolicyError(f"{label} JSON body must be an object")
    return value


def _canonical_target(target: str) -> tuple[str, str]:
    if (
        not isinstance(target, str)
        or not target.startswith("/")
        or len(target) > _TARGET_LIMIT
        or "\\" in target
        or any(ord(character) < 32 or ord(character) > 126 for character in target)
    ):
        raise EngineDockerPolicyError("Docker request target is invalid")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise EngineDockerPolicyError("Docker request target must be origin-relative")
    if "//" in parsed.path or any(part in {".", ".."} for part in parsed.path.split("/")):
        raise EngineDockerPolicyError("Docker request path is not canonical")
    index = 0
    while index < len(parsed.path):
        if parsed.path[index] != "%":
            index += 1
            continue
        match = _PERCENT_ESCAPE.match(parsed.path, index)
        if match is None:
            raise EngineDockerPolicyError("Docker request path escaping is not canonical")
        decoded = int(match.group()[1:], 16)
        if decoded == 0 or decoded == 0x5C or decoded < 0x20 or decoded == 0x7F:
            raise EngineDockerPolicyError("Docker request path escape is unsafe")
        index = match.end()
    return parsed.path, parsed.query


def _query(query: str, *, fields: frozenset[str]) -> dict[str, str]:
    if not query:
        if fields:
            raise EngineDockerPolicyError("Docker request query is missing")
        return {}
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise EngineDockerPolicyError("Docker request query is invalid") from exc
    if len(pairs) != len(fields) or {key for key, _ in pairs} != fields:
        raise EngineDockerPolicyError("Docker request query fields do not match the contract")
    if len({key for key, _ in pairs}) != len(pairs):
        raise EngineDockerPolicyError("Docker request query contains duplicates")
    if pairs != sorted(pairs) or urlencode(pairs) != query:
        raise EngineDockerPolicyError("Docker request query is not canonical")
    return dict(pairs)


def _no_query(query: str) -> None:
    if query:
        raise EngineDockerPolicyError("Docker request does not permit query parameters")


def _no_body(request: "DockerApiRequest") -> None:
    if request.body:
        raise EngineDockerPolicyError("Docker request does not permit a body")


def _expect_bool(value: Any, label: str, expected: bool) -> None:
    if not isinstance(value, bool) or value is not expected:
        raise EngineDockerPolicyError(f"{label} must be {str(expected).lower()}")


def _expect_int(value: Any, label: str, expected: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise EngineDockerPolicyError(f"{label} does not match the reviewed integer")


@dataclass(frozen=True, slots=True)
class DockerTmpfs:
    destination: str
    options: str
    options_digest: str
    size_bytes: int

    def __post_init__(self) -> None:
        if _tmpfs_values(self.destination, self.options, self.options_digest) != (
            self.destination,
            self.options,
            self.options_digest,
            self.size_bytes,
        ):
            raise EngineDockerPolicyError("Docker tmpfs fields are not canonical")

    @classmethod
    def create(cls, *, destination: str, options: str, options_digest: str) -> "DockerTmpfs":
        destination, options, digest, size_bytes = _tmpfs_values(
            destination, options, options_digest
        )
        return cls(
            destination=destination,
            options=options,
            options_digest=digest,
            size_bytes=size_bytes,
        )


@dataclass(frozen=True, slots=True)
class DockerTmpfsV2:
    """One V2 tmpfs. Exact options are checked against the reopened profile."""

    destination: str
    options: str
    options_digest: str
    size_bytes: int

    def __post_init__(self) -> None:
        _text(self.destination, "V2 Docker tmpfs destination", maximum=260)
        if not isinstance(self.options, str) or len(self.options) > 128:
            raise EngineDockerPolicyError("V2 Docker tmpfs options are invalid")
        if _digest(self.options_digest, "V2 Docker tmpfs options") != content_hash(
            {"options": self.options}
        ):
            raise EngineDockerPolicyError("V2 Docker tmpfs options digest does not match")
        size_match = re.search(r"(?:^|,)size=([1-9][0-9]*)(?:,|$)", self.options)
        if (
            size_match is None
            or isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes != int(size_match.group(1))
        ):
            raise EngineDockerPolicyError("V2 Docker tmpfs size is invalid")

    @classmethod
    def create(cls, *, destination: str, options: str, options_digest: str) -> "DockerTmpfsV2":
        if not isinstance(options, str):
            raise EngineDockerPolicyError("V2 Docker tmpfs options are invalid")
        match = re.search(r"(?:^|,)size=([1-9][0-9]*)(?:,|$)", options)
        if match is None:
            raise EngineDockerPolicyError("V2 Docker tmpfs size is missing")
        return cls(destination, options, options_digest, int(match.group(1)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "destination": self.destination,
            "options": self.options,
            "options_digest": self.options_digest,
            "size_bytes": self.size_bytes,
        }


def _tmpfs_values(destination: Any, options: Any, options_digest: Any) -> tuple[str, str, str, int]:
    destination = _text(destination, "Docker tmpfs destination", maximum=260)
    if not destination.startswith("/") or "\\" in destination:
        raise EngineDockerPolicyError("Docker tmpfs destination is not absolute")
    if any(part in {"", ".", ".."} for part in destination.split("/")[1:]):
        raise EngineDockerPolicyError("Docker tmpfs destination is not canonical")
    if not isinstance(options, str) or not options or len(options) > 128:
        raise EngineDockerPolicyError("Docker tmpfs options are invalid")
    tokens = options.split(",")
    if (
        len(tokens) > 8
        or any(_TMPFS_OPTION.fullmatch(token) is None for token in tokens)
        or sorted(set(tokens)) != tokens
        or ({"rw", "ro"} & set(tokens)) not in ({"rw"}, {"ro"})
        or {"exec", "noexec"} <= set(tokens)
    ):
        raise EngineDockerPolicyError("Docker tmpfs options are not canonical")
    digest = _digest(options_digest, "Docker tmpfs options")
    if content_hash({"options": options}) != digest:
        raise EngineDockerPolicyError("Docker tmpfs options digest does not match")
    size_tokens = [token for token in tokens if token.startswith("size=")]
    if len(size_tokens) != 1 or not {"nodev", "nosuid"} <= set(tokens):
        raise EngineDockerPolicyError("Docker tmpfs requires one bounded size and safe flags")
    raw_size = size_tokens[0].removeprefix("size=")
    multiplier = {"k": 1024, "m": 1024**2, "g": 1024**3}.get(raw_size[-1], 1)
    number = raw_size[:-1] if raw_size[-1].isalpha() else raw_size
    size_bytes = int(number) * multiplier
    if not 1 <= size_bytes <= 256 * 1024**3:
        raise EngineDockerPolicyError("Docker tmpfs size is outside its bound")
    return destination, options, digest, size_bytes


@dataclass(frozen=True, slots=True)
class DockerApiPolicy:
    schema_version: str
    attempt_id: str
    api_version: str
    daemon_instance_digest: str
    disposable_boundary_ref: str
    baseline_inventory_digest: str
    image_reference: str
    image_digest: str
    network_name: str
    network_id: str
    network_policy_digest: str
    container_name: str
    required_labels: tuple[tuple[str, str], ...]
    expected_user: str
    expected_capabilities: tuple[str, ...]
    expected_ipc_mode: str
    expected_pid_mode: str
    expected_uts_mode: str
    tmpfs: tuple[DockerTmpfs, ...]
    memory_bytes: int
    nano_cpus: int
    pids_limit: int
    expected_container_count: int
    cgroup_parent: str
    exec_working_directory: str
    exec_deadline_seconds: int
    exec_response_byte_limit: int
    archive_response_byte_limit: int
    log_response_byte_limit: int

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.engine-docker-api-policy.v1":
            raise EngineDockerPolicyError("Docker API policy schema is unsupported")
        attempt_id = _text(self.attempt_id, "Docker attempt ID", _ATTEMPT_ID, maximum=47)
        _text(self.api_version, "Docker API version", _API_VERSION, maximum=8)
        _digest(self.daemon_instance_digest, "Docker daemon instance")
        _digest(self.disposable_boundary_ref, "Docker disposable boundary")
        _digest(self.baseline_inventory_digest, "Docker baseline inventory")
        image = _text(
            self.image_reference,
            "Docker image reference",
            _IMAGE_REFERENCE,
            maximum=327,
        )
        image_digest = _digest(self.image_digest, "Docker image")
        if image.rsplit("@", 1)[-1] != image_digest:
            raise EngineDockerPolicyError("Docker image reference and digest do not match")
        _text(self.network_name, "Docker network name", _NETWORK_NAME, maximum=128)
        _text(self.network_id, "Docker network ID", _FULL_RESOURCE_ID, maximum=64)
        _digest(self.network_policy_digest, "Docker network policy")
        if (
            self.container_name != f"strix-sandbox-{attempt_id[-12:]}"
            or _CONTAINER_NAME.fullmatch(self.container_name) is None
        ):
            raise EngineDockerPolicyError("Docker container name is not attempt-bound")
        if not isinstance(self.required_labels, tuple):
            raise EngineDockerPolicyError("Docker required labels are invalid")
        labels: list[tuple[str, str]] = []
        for item in self.required_labels:
            if not isinstance(item, tuple) or len(item) != 2:
                raise EngineDockerPolicyError("Docker required label is invalid")
            key = _text(item[0], "Docker label key", _LABEL_KEY, maximum=128)
            label_value = _text(item[1], "Docker label value", maximum=200)
            labels.append((key, label_value))
        if tuple(sorted(set(labels))) != self.required_labels:
            raise EngineDockerPolicyError("Docker required labels are not canonical")
        label_map = dict(labels)
        required = {
            "bluefire.engine.attempt": attempt_id,
            "strix-run-id": attempt_id,
            "strix-run-type": "bluefire",
        }
        if any(label_map.get(key) != value for key, value in required.items()):
            raise EngineDockerPolicyError("Docker labels do not bind exact attempt ownership")
        user = _text(self.expected_user, "Docker sandbox user", _USER, maximum=64)
        if user in {"0", "0:0", "root"} or user.startswith("0:"):
            raise EngineDockerPolicyError("Docker policy requires a non-root sandbox user")
        if (
            not isinstance(self.expected_capabilities, tuple)
            or tuple(sorted(set(self.expected_capabilities))) != self.expected_capabilities
            or not set(self.expected_capabilities) <= {"NET_ADMIN", "NET_RAW"}
        ):
            raise EngineDockerPolicyError("Docker policy capability set is not supported")
        # Moby represents private/default PID and UTS namespaces as the empty
        # string. Unlike IpcMode, neither enum accepts the literal "private".
        # Pinning the wire/inspect values here keeps the create request and the
        # later positive-ownership proof on the same daemon semantics.
        if (
            self.expected_ipc_mode,
            self.expected_pid_mode,
            self.expected_uts_mode,
        ) != ("private", "", ""):
            raise EngineDockerPolicyError("Docker policy namespace modes are not private")
        if (
            not isinstance(self.tmpfs, tuple)
            or not self.tmpfs
            or any(not isinstance(item, DockerTmpfs) for item in self.tmpfs)
            or tuple(sorted(item.destination for item in self.tmpfs))
            != tuple(item.destination for item in self.tmpfs)
            or len({item.destination for item in self.tmpfs}) != len(self.tmpfs)
        ):
            raise EngineDockerPolicyError("Docker tmpfs policy is not canonical")
        for bounded_value, label, minimum, maximum in (
            (self.memory_bytes, "Docker memory", 1, 256 * 1024**3),
            (self.nano_cpus, "Docker nano CPUs", 1, 256_000_000_000),
            (self.pids_limit, "Docker PID limit", 1, 65_536),
        ):
            if (
                isinstance(bounded_value, bool)
                or not isinstance(bounded_value, int)
                or not minimum <= bounded_value <= maximum
            ):
                raise EngineDockerPolicyError(f"{label} is outside its bound")
        if sum(item.size_bytes for item in self.tmpfs) > self.memory_bytes:
            raise EngineDockerPolicyError("Docker tmpfs capacity exceeds the memory limit")
        _expect_int(self.expected_container_count, "Docker container count", 1)
        if (
            self.cgroup_parent != f"bluefire/{attempt_id}"
            or _CGROUP_PARENT.fullmatch(self.cgroup_parent) is None
        ):
            raise EngineDockerPolicyError("Docker cgroup parent is not attempt-bound")
        if self.exec_working_directory not in {item.destination for item in self.tmpfs}:
            raise EngineDockerPolicyError("Docker exec directory is not an admitted tmpfs")
        for bounded_value, label, expected in (
            (self.exec_deadline_seconds, "Docker exec deadline", 120),
            (self.exec_response_byte_limit, "Docker exec response bound", 4 * 1024**2),
            (self.archive_response_byte_limit, "Docker archive response bound", 32 * 1024**2),
            (self.log_response_byte_limit, "Docker log response bound", 4 * 1024**2),
        ):
            _expect_int(bounded_value, label, expected)

    @classmethod
    def create(
        cls,
        *,
        build: StrixBuildIdentity,
        network: EngineNetworkPlan,
        custody: ContainerCustodyPlan,
        api_version: str,
        tmpfs_options: Mapping[str, str],
    ) -> "DockerApiPolicy":
        attempt_id = _text(custody.attempt_id, "Docker attempt ID", _ATTEMPT_ID, maximum=47)
        if network.attempt_id != attempt_id:
            raise EngineDockerPolicyError("Docker plans bind different attempts")
        version = _text(api_version, "Docker API version", _API_VERSION, maximum=8)
        if custody.network_policy_digest != network.policy_digest:
            raise EngineDockerPolicyError("Docker plans bind different network policies")
        if build.image_reference.rsplit("@", 1)[-1] != custody.sandbox_image_digest:
            raise EngineDockerPolicyError("Docker plans bind different sandbox images")
        if (
            isinstance(custody.expected_container_count, bool)
            or not isinstance(custody.expected_container_count, int)
            or custody.expected_container_count != 1
        ):
            raise EngineDockerPolicyError("Docker policy permits exactly one sandbox container")
        if _FULL_RESOURCE_ID.fullmatch(custody.network_id) is None:
            raise EngineDockerPolicyError("Docker policy requires a full network identity")
        if custody.expected_user in {"0", "0:0", "root"} or custody.expected_user.startswith("0:"):
            raise EngineDockerPolicyError("Docker policy requires a non-root sandbox user")
        if not set(custody.expected_capabilities) <= {"NET_ADMIN", "NET_RAW"}:
            raise EngineDockerPolicyError("Docker policy capability set is not supported")
        labels = tuple(custody.required_labels)
        label_map = dict(labels)
        required = {
            "bluefire.engine.attempt": attempt_id,
            "strix-run-id": attempt_id,
            "strix-run-type": "bluefire",
        }
        if any(label_map.get(key) != value for key, value in required.items()):
            raise EngineDockerPolicyError("Docker labels do not bind exact attempt ownership")
        if set(tmpfs_options) != {item.destination for item in custody.expected_mounts}:
            raise EngineDockerPolicyError("Docker tmpfs destinations do not match custody")
        mounts: list[DockerTmpfs] = []
        for item in custody.expected_mounts:
            if item.mount_type != "tmpfs" or item.source:
                raise EngineDockerPolicyError("Docker policy permits only source-free tmpfs")
            mount = DockerTmpfs.create(
                destination=item.destination,
                options=tmpfs_options[item.destination],
                options_digest=item.options_digest,
            )
            if ("ro" if item.read_only else "rw") not in mount.options.split(","):
                raise EngineDockerPolicyError("Docker tmpfs access mode does not match custody")
            mounts.append(mount)
        mounts.sort(key=lambda item: item.destination)
        if not mounts:
            raise EngineDockerPolicyError("Docker policy requires an isolated tmpfs workspace")
        if sum(item.size_bytes for item in mounts) > custody.memory_bytes:
            raise EngineDockerPolicyError("Docker tmpfs capacity exceeds the memory limit")
        working = next(
            (item.destination for item in mounts if item.destination == "/workspace"),
            mounts[0].destination,
        )
        suffix = attempt_id[-12:]
        return cls(
            schema_version="bluefire.engine-docker-api-policy.v1",
            attempt_id=attempt_id,
            api_version=version,
            daemon_instance_digest=custody.daemon_instance_digest,
            disposable_boundary_ref=custody.disposable_boundary_ref,
            baseline_inventory_digest=custody.baseline_inventory_digest,
            image_reference=build.image_reference,
            image_digest=custody.sandbox_image_digest,
            network_name=network.network_name,
            network_id=custody.network_id,
            network_policy_digest=network.policy_digest,
            container_name=f"strix-sandbox-{suffix}",
            required_labels=labels,
            expected_user=custody.expected_user,
            expected_capabilities=custody.expected_capabilities,
            expected_ipc_mode="private",
            expected_pid_mode="",
            expected_uts_mode="",
            tmpfs=tuple(mounts),
            memory_bytes=custody.memory_bytes,
            nano_cpus=custody.nano_cpus,
            pids_limit=custody.pids_limit,
            expected_container_count=custody.expected_container_count,
            cgroup_parent=f"bluefire/{attempt_id}",
            exec_working_directory=working,
            exec_deadline_seconds=120,
            exec_response_byte_limit=4 * 1024**2,
            archive_response_byte_limit=32 * 1024**2,
            log_response_byte_limit=4 * 1024**2,
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    "schema_version": self.schema_version,
                    "attempt_id": self.attempt_id,
                    "api_version": self.api_version,
                    "daemon_instance_digest": self.daemon_instance_digest,
                    "disposable_boundary_ref": self.disposable_boundary_ref,
                    "baseline_inventory_digest": self.baseline_inventory_digest,
                    "image_reference": self.image_reference,
                    "image_digest": self.image_digest,
                    "network_name": self.network_name,
                    "network_id": self.network_id,
                    "network_policy_digest": self.network_policy_digest,
                    "container_name": self.container_name,
                    "required_labels": dict(self.required_labels),
                    "expected_user": self.expected_user,
                    "expected_capabilities": list(self.expected_capabilities),
                    "expected_ipc_mode": self.expected_ipc_mode,
                    "expected_pid_mode": self.expected_pid_mode,
                    "expected_uts_mode": self.expected_uts_mode,
                    "tmpfs": [
                        {
                            "destination": item.destination,
                            "options": item.options,
                            "options_digest": item.options_digest,
                            "size_bytes": item.size_bytes,
                        }
                        for item in self.tmpfs
                    ],
                    "memory_bytes": self.memory_bytes,
                    "nano_cpus": self.nano_cpus,
                    "pids_limit": self.pids_limit,
                    "expected_container_count": self.expected_container_count,
                    "cgroup_parent": self.cgroup_parent,
                    "exec_working_directory": self.exec_working_directory,
                    "exec_deadline_seconds": self.exec_deadline_seconds,
                    "exec_response_byte_limit": self.exec_response_byte_limit,
                    "archive_response_byte_limit": self.archive_response_byte_limit,
                    "log_response_byte_limit": self.log_response_byte_limit,
                }
            )
        )

    @property
    def policy_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class ControllerVerifiedImageRelation:
    """Exact result of a controller verifier; construction alone grants no trust."""

    image_reference: str
    runtime_platform: str
    platform_child_manifest_digest: str
    image_config_digest: str
    image_relation_receipt_ref: str

    def __post_init__(self) -> None:
        container_image_identity_digest(
            image_reference=self.image_reference,
            runtime_platform=self.runtime_platform,
            platform_child_manifest_digest=self.platform_child_manifest_digest,
            image_config_digest=self.image_config_digest,
            image_relation_receipt_ref=self.image_relation_receipt_ref,
        )


class ControllerImageRelationVerifier(Protocol):
    """Controller-owned capability, never supplied from engine or operator input."""

    def verify_image_relation(
        self,
        *,
        image_reference: str,
        runtime_platform: str,
        platform_child_manifest_digest: str,
        image_config_digest: str,
        image_relation_receipt_ref: str,
    ) -> ControllerVerifiedImageRelation: ...


@dataclass(frozen=True, slots=True)
class ControllerVerifiedImageAdmission:
    """Exact controller result; constructing it directly does not authenticate input."""

    image_contract_digest: str
    image_admission_decision_ref: str
    execution_identity_digest: str
    protected_execution_identity_digest: str
    runtime_qualification_ref: str
    runtime_qualification_admitted: bool
    image_admitted_for_runtime: bool
    missing_checks: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (
            self.image_contract_digest,
            self.image_admission_decision_ref,
            self.execution_identity_digest,
            self.protected_execution_identity_digest,
            self.runtime_qualification_ref,
        ):
            _digest(value, "controller image admission identity")
        if (
            self.execution_identity_digest != self.protected_execution_identity_digest
            or self.runtime_qualification_admitted is not True
            or self.image_admitted_for_runtime is not True
            or self.missing_checks != ()
        ):
            raise EngineDockerPolicyError("controller image admission result is not qualified")


class ControllerImageAdmissionVerifier(Protocol):
    """Controller-owned capability for authenticated image and runtime qualification."""

    def verify_image_admission(
        self,
        *,
        image_contract_digest: str,
        image_admission_decision_ref: str,
        execution_identity_digest: str,
        protected_execution_identity_digest: str,
        runtime_qualification_ref: str,
    ) -> ControllerVerifiedImageAdmission: ...


def _v2_admission_decision_ref(decision: StrixImageAdmissionDecisionV2) -> str:
    if type(decision) is not StrixImageAdmissionDecisionV2:
        raise EngineDockerPolicyError("V2 image admission decision is unavailable")
    if (
        decision.image_admitted_for_runtime is not True
        or decision.local_build_qualified is not True
        or decision.hosted_qualification_complete is not True
        or decision.missing_checks != ()
        or decision.notices_complete is not False
        or decision.license_review_complete is not False
        or decision.production_runtime_admitted is not False
        or decision.live_execution_proven is not False
        or decision.redistribution_authorized is not False
        or decision.redistribution_rights_confirmed is not None
    ):
        raise EngineDockerPolicyError("V2 image admission decision is not qualified")
    return content_hash(
        {
            "schema_version": "bluefire.strix-image-admission-decision-ref.v2",
            "decision": asdict(decision),
        }
    )


@dataclass(frozen=True, slots=True)
class DockerApiPolicyV2:
    """V2 policy requiring an exact controller-verified image relation.

    This module checks the verifier's binding; it does not implement receipt
    authentication or produce a proof. Production composition must inject the
    trusted verifier, and there is no permissive default.
    """

    _common_values: tuple[tuple[str, Any], ...]
    image_reference: str
    platform_child_manifest_digest: str
    image_config_digest: str
    image_relation_receipt_ref: str
    tmpfs: tuple[DockerTmpfsV2, ...]
    memory_swap_bytes: int
    upstream_build_ref: str
    upstream_image_reference: str
    image_contract_digest: str
    execution_identity_digest: str
    custody_plan_digest: str
    image_runtime_profile_digest: str
    controlled_runtime_profile_ref: str
    runtime_qualification_ref: str
    image_admission_decision_ref: str
    controller_relation_verifier: InitVar[ControllerImageRelationVerifier]
    controller_admission_verifier: InitVar[ControllerImageAdmissionVerifier]
    network: InitVar[EngineNetworkPlanV2]
    custody: InitVar[ContainerCustodyPlanV2]
    image_contract: InitVar[StrixImageContractV2]
    execution_identity: InitVar[StrixControlledExecutionIdentityV2]
    protected_execution_identity_digest: InitVar[str]
    image_admission_decision: InitVar[StrixImageAdmissionDecisionV2]
    verified_relation: ControllerVerifiedImageRelation = dataclass_field(init=False, repr=False)
    verified_admission: ControllerVerifiedImageAdmission = dataclass_field(init=False, repr=False)

    def _v1_projection(self) -> DockerApiPolicy:
        """Validate shared policy settings without retaining a usable v1 policy."""

        expected = frozenset(DockerApiPolicy.__dataclass_fields__) - {
            "schema_version",
            "image_reference",
            "image_digest",
            "tmpfs",
        }
        if (
            not isinstance(self._common_values, tuple)
            or any(not isinstance(item, tuple) or len(item) != 2 for item in self._common_values)
            or tuple(sorted(self._common_values, key=lambda item: item[0])) != self._common_values
        ):
            raise EngineDockerPolicyError("v2 Docker common policy is not canonical")
        values = dict(self._common_values)
        if len(values) != len(self._common_values) or set(values) != expected:
            raise EngineDockerPolicyError("v2 Docker common policy fields do not match")
        try:
            reference = validate_v2_image_reference(
                self.image_reference, "derived Docker image reference"
            )
        except StrixImageContractError as exc:
            raise EngineDockerPolicyError("derived Docker image reference is invalid") from exc
        return DockerApiPolicy(
            schema_version="bluefire.engine-docker-api-policy.v1",
            image_reference=reference,
            image_digest=reference.rsplit("@", 1)[-1],
            tmpfs=(
                DockerTmpfs.create(
                    destination="/workspace",
                    options=_V1_PROJECTION_TMPFS_OPTIONS,
                    options_digest=content_hash({"options": _V1_PROJECTION_TMPFS_OPTIONS}),
                ),
            ),
            **values,
        )

    def _verify_contract_identity_and_profile(
        self,
        *,
        image_contract: StrixImageContractV2,
        execution_identity: StrixControlledExecutionIdentityV2,
        protected_execution_identity_digest: str,
        image_admission_decision: StrixImageAdmissionDecisionV2,
    ) -> None:
        if (
            type(image_contract) is not StrixImageContractV2
            or type(execution_identity) is not StrixControlledExecutionIdentityV2
        ):
            raise EngineDockerPolicyError("V2 Docker image contract or identity is unavailable")
        try:
            contract = StrixImageContractV2(image_contract.canonical_bytes)
            identity = StrixControlledExecutionIdentityV2(execution_identity.canonical_bytes)
            identity.require_expected_digest(protected_execution_identity_digest)
            identity.verify_image_contract(contract)
            upstream_reference = validate_v2_image_reference(
                self.upstream_image_reference, "upstream Docker image reference"
            )
            expected_profile = proposed_image_runtime_profile(
                network_id=self.network_id,
                network_name=self.network_name,
                network_policy_digest=self.network_policy_digest,
            )
        except (
            StrixImageContractError,
            StrixControlledExecutionIdentityError,
            TypeError,
            ValueError,
        ) as exc:
            raise EngineDockerPolicyError(
                "V2 Docker image contract or identity is invalid"
            ) from exc
        contract_row = contract.to_dict()
        identity_row = identity.to_dict()
        derived = contract_row["derived_image"]
        upstream = contract_row["upstream_image"]
        runtime_profile = contract_row["runtime_profile"]
        embedded_profile = identity_row["controlled_runtime_profile"]
        decision_ref = _v2_admission_decision_ref(image_admission_decision)
        expected_bindings = (
            (self.image_contract_digest, contract.contract_digest),
            (self.execution_identity_digest, identity.identity_digest),
            (self.upstream_build_ref, identity_row["startup_build_ref"]),
            (upstream_reference, upstream["index_reference"]),
            (upstream_reference, identity_row["upstream_oci_index_reference"]),
            (self.image_reference, derived["index_reference"]),
            (self.image_reference, identity_row["derived_image_reference"]),
            (self.platform_child_manifest_digest, derived["platform_child"]["digest"]),
            (self.image_config_digest, derived["config"]["digest"]),
            (self.image_relation_receipt_ref, identity_row["image_relation_receipt_ref"]),
            (self.image_runtime_profile_digest, contract.runtime_profile_digest),
            (self.controlled_runtime_profile_ref, identity_row["controlled_runtime_profile_ref"]),
            (self.runtime_qualification_ref, identity_row["runtime_qualification_ref"]),
            (self.image_admission_decision_ref, decision_ref),
            (decision_ref, identity_row["derived_image_decision_ref"]),
            (image_admission_decision.contract_digest, contract.contract_digest),
            (self.attempt_id, identity_row["attempt_id"]),
            (self.upstream_build_ref, embedded_profile["build_digest"]),
            (self.image_reference, embedded_profile["image_reference"]),
        )
        if any(actual != expected for actual, expected in expected_bindings):
            raise EngineDockerPolicyError("V2 Docker contract, identity, or decision differs")
        if runtime_profile != expected_profile:
            raise EngineDockerPolicyError("V2 Docker runtime profile network differs")
        if (
            runtime_profile["runtime_installs"] is not False
            or runtime_profile["runtime_image_pulls"] is not False
            or runtime_profile["preloaded_image_required"] is not True
        ):
            raise EngineDockerPolicyError("V2 Docker runtime requires an offline preloaded image")
        if (
            embedded_profile["sandbox_uid"],
            embedded_profile["sandbox_gid"],
        ) != (1000, 1000):
            raise EngineDockerPolicyError("V2 Docker sandbox user differs from controlled profile")
        if (
            self.expected_user != runtime_profile["user"]
            or self.expected_capabilities != tuple(runtime_profile["cap_add"])
            or self.memory_bytes != runtime_profile["memory_bytes"]
            or self.memory_swap_bytes != runtime_profile["memory_swap_bytes"]
            or self.nano_cpus != runtime_profile["nano_cpus"]
            or self.pids_limit != runtime_profile["pids_limit"]
            or self.exec_working_directory != runtime_profile["working_directory"]
        ):
            raise EngineDockerPolicyError(
                "V2 Docker custody differs from qualified runtime profile"
            )
        _expect_int(
            self.memory_swap_bytes,
            "V2 Docker memory swap",
            runtime_profile["memory_swap_bytes"],
        )
        if (
            not isinstance(self.tmpfs, tuple)
            or len(self.tmpfs) != 4
            or any(type(item) is not DockerTmpfsV2 for item in self.tmpfs)
            or tuple(item.destination for item in self.tmpfs)
            != tuple(sorted(runtime_profile["tmpfs"]))
            or {item.destination: item.options for item in self.tmpfs} != runtime_profile["tmpfs"]
            or sum(item.size_bytes for item in self.tmpfs) > self.memory_bytes
        ):
            raise EngineDockerPolicyError("V2 Docker tmpfs differs from qualified runtime profile")

    def __post_init__(
        self,
        controller_relation_verifier: ControllerImageRelationVerifier,
        controller_admission_verifier: ControllerImageAdmissionVerifier,
        network: EngineNetworkPlanV2,
        custody: ContainerCustodyPlanV2,
        image_contract: StrixImageContractV2,
        execution_identity: StrixControlledExecutionIdentityV2,
        protected_execution_identity_digest: str,
        image_admission_decision: StrixImageAdmissionDecisionV2,
    ) -> None:
        base_policy = self._v1_projection()
        if type(network) is not EngineNetworkPlanV2:
            raise EngineDockerPolicyError("V2 Docker network plan is unavailable")
        try:
            reopened_network = EngineNetworkPlanV2.from_mapping(network.to_dict())
        except (EngineNetworkPolicyError, TypeError, ValueError) as exc:
            raise EngineDockerPolicyError("V2 Docker network plan is invalid") from exc
        if (
            self.attempt_id != reopened_network.attempt_id
            or self.network_name != reopened_network.network_name
            or self.network_id != reopened_network.network_id
            or self.network_policy_digest != reopened_network.policy_digest
        ):
            raise EngineDockerPolicyError("V2 Docker network plan differs from policy")
        if type(custody) is not ContainerCustodyPlanV2:
            raise EngineDockerPolicyError("V2 Docker custody plan is unavailable")
        try:
            reopened_custody = ContainerCustodyPlanV2.from_mapping(custody.to_dict())
        except (EngineContainerCustodyError, TypeError, ValueError) as exc:
            raise EngineDockerPolicyError("V2 Docker custody plan is invalid") from exc
        custody_bindings = (
            (self.custody_plan_digest, reopened_custody.plan_digest),
            (self.attempt_id, reopened_custody.attempt_id),
            (self.daemon_instance_digest, reopened_custody.daemon_instance_digest),
            (self.disposable_boundary_ref, reopened_custody.disposable_boundary_ref),
            (self.baseline_inventory_digest, reopened_custody.baseline_inventory_digest),
            (self.required_labels, reopened_custody.required_labels),
            (self.image_reference, reopened_custody.image_reference),
            (V2_RUNTIME_PLATFORM, reopened_custody.runtime_platform),
            (
                self.platform_child_manifest_digest,
                reopened_custody.platform_child_manifest_digest,
            ),
            (self.image_config_digest, reopened_custody.image_config_digest),
            (self.image_relation_receipt_ref, reopened_custody.image_relation_receipt_ref),
            (self.network_id, reopened_custody.network_id),
            (self.network_policy_digest, reopened_custody.network_policy_digest),
            (self.expected_capabilities, reopened_custody.expected_capabilities),
            (self.expected_user, reopened_custody.expected_user),
            (self.memory_bytes, reopened_custody.memory_bytes),
            (self.nano_cpus, reopened_custody.nano_cpus),
            (self.pids_limit, reopened_custody.pids_limit),
            (self.expected_container_count, reopened_custody.expected_container_count),
        )
        if any(actual != expected for actual, expected in custody_bindings):
            raise EngineDockerPolicyError("V2 Docker custody plan differs from policy")
        if tuple(item.destination for item in self.tmpfs) != tuple(
            item.destination for item in reopened_custody.expected_mounts
        ) or any(
            mount.mount_type != "tmpfs"
            or mount.source
            or mount.read_only
            or mount.options_digest != tmpfs.options_digest
            for mount, tmpfs in zip(reopened_custody.expected_mounts, self.tmpfs, strict=True)
        ):
            raise EngineDockerPolicyError("V2 Docker tmpfs differs from custody plan")
        child = _digest(self.platform_child_manifest_digest, "platform child manifest")
        config = _digest(self.image_config_digest, "image config")
        receipt = _digest(self.image_relation_receipt_ref, "image relation receipt reference")
        try:
            identity_digest = container_image_identity_digest(
                image_reference=self.image_reference,
                runtime_platform=V2_RUNTIME_PLATFORM,
                platform_child_manifest_digest=child,
                image_config_digest=config,
                image_relation_receipt_ref=receipt,
            )
        except ValueError as exc:
            raise EngineDockerPolicyError("v2 Docker image identity is invalid") from exc
        if (
            dict(base_policy.required_labels).get("bluefire.engine.image-identity")
            != identity_digest
        ):
            raise EngineDockerPolicyError("Docker create labels do not bind v2 image identity")
        self._verify_contract_identity_and_profile(
            image_contract=image_contract,
            execution_identity=execution_identity,
            protected_execution_identity_digest=protected_execution_identity_digest,
            image_admission_decision=image_admission_decision,
        )
        if not callable(getattr(controller_admission_verifier, "verify_image_admission", None)):
            raise EngineDockerPolicyError("controller image admission verifier is unavailable")
        try:
            admitted = controller_admission_verifier.verify_image_admission(
                image_contract_digest=self.image_contract_digest,
                image_admission_decision_ref=self.image_admission_decision_ref,
                execution_identity_digest=self.execution_identity_digest,
                protected_execution_identity_digest=protected_execution_identity_digest,
                runtime_qualification_ref=self.runtime_qualification_ref,
            )
        except Exception as exc:
            raise EngineDockerPolicyError("controller image admission verification failed") from exc
        expected_admission = ControllerVerifiedImageAdmission(
            image_contract_digest=self.image_contract_digest,
            image_admission_decision_ref=self.image_admission_decision_ref,
            execution_identity_digest=self.execution_identity_digest,
            protected_execution_identity_digest=protected_execution_identity_digest,
            runtime_qualification_ref=self.runtime_qualification_ref,
            runtime_qualification_admitted=True,
            image_admitted_for_runtime=True,
            missing_checks=(),
        )
        if type(admitted) is not ControllerVerifiedImageAdmission or admitted != expected_admission:
            raise EngineDockerPolicyError(
                "controller image admission verification does not bind image"
            )
        object.__setattr__(self, "verified_admission", admitted)
        if not callable(getattr(controller_relation_verifier, "verify_image_relation", None)):
            raise EngineDockerPolicyError("controller image relation verifier is unavailable")
        try:
            verified = controller_relation_verifier.verify_image_relation(
                image_reference=self.image_reference,
                runtime_platform=V2_RUNTIME_PLATFORM,
                platform_child_manifest_digest=child,
                image_config_digest=config,
                image_relation_receipt_ref=receipt,
            )
        except Exception as exc:
            raise EngineDockerPolicyError("controller image relation verification failed") from exc
        expected_relation = ControllerVerifiedImageRelation(
            image_reference=self.image_reference,
            runtime_platform=V2_RUNTIME_PLATFORM,
            platform_child_manifest_digest=child,
            image_config_digest=config,
            image_relation_receipt_ref=receipt,
        )
        if type(verified) is not ControllerVerifiedImageRelation or verified != expected_relation:
            raise EngineDockerPolicyError(
                "controller image relation verification does not bind image"
            )
        object.__setattr__(self, "verified_relation", verified)

    @classmethod
    def create(
        cls,
        *,
        build: StrixBuildIdentity,
        derived_image_reference: str,
        network: EngineNetworkPlanV2,
        custody: ContainerCustodyPlanV2,
        image_contract: StrixImageContractV2,
        execution_identity: StrixControlledExecutionIdentityV2,
        protected_execution_identity_digest: str,
        image_admission_decision: StrixImageAdmissionDecisionV2,
        controller_relation_verifier: ControllerImageRelationVerifier,
        controller_admission_verifier: ControllerImageAdmissionVerifier,
        api_version: str,
        tmpfs_options: Mapping[str, str],
    ) -> "DockerApiPolicyV2":
        if type(network) is not EngineNetworkPlanV2:
            raise EngineDockerPolicyError("v2 Docker policy requires v2 network plan")
        if type(custody) is not ContainerCustodyPlanV2:
            raise EngineDockerPolicyError("v2 Docker policy requires v2 custody")
        if (
            type(image_contract) is not StrixImageContractV2
            or type(execution_identity) is not StrixControlledExecutionIdentityV2
        ):
            raise EngineDockerPolicyError(
                "v2 Docker policy requires reopened contract and identity"
            )
        try:
            network = EngineNetworkPlanV2.from_mapping(network.to_dict())
            contract = StrixImageContractV2(image_contract.canonical_bytes)
            identity = StrixControlledExecutionIdentityV2(execution_identity.canonical_bytes)
            identity.require_expected_digest(protected_execution_identity_digest)
            identity.verify_image_contract(contract)
            derived_reference = validate_v2_image_reference(
                derived_image_reference, "derived Docker image reference"
            )
        except (
            StrixImageContractError,
            StrixControlledExecutionIdentityError,
            TypeError,
            ValueError,
            EngineNetworkPolicyError,
        ) as exc:
            raise EngineDockerPolicyError(
                "V2 Docker contract, identity, or network is invalid"
            ) from exc
        parsed = ContainerCustodyPlanV2.from_mapping(custody.to_dict())
        if parsed.image_reference != derived_reference:
            raise EngineDockerPolicyError("Docker plans bind different image references")
        identity_row = identity.to_dict()
        contract_row = contract.to_dict()
        if (
            type(build) is not StrixBuildIdentity
            or build.to_dict() != identity_row["startup_build_identity"]
            or content_hash(build.to_dict()) != identity_row["startup_build_ref"]
            or build.image_reference != contract_row["upstream_image"]["index_reference"]
        ):
            raise EngineDockerPolicyError("V2 Docker upstream build differs from identity")
        runtime_profile = contract_row["runtime_profile"]
        try:
            network.validate_runtime_profile_network(runtime_profile["network"])
        except EngineNetworkPolicyError as exc:
            raise EngineDockerPolicyError("V2 Docker runtime profile network differs") from exc
        if (
            network.attempt_id != parsed.attempt_id
            or parsed.network_id != network.network_id
            or parsed.network_policy_digest != network.policy_digest
            or runtime_profile["network"]
            != {
                "id": network.network_id,
                "name": network.network_name,
                "policy_digest": network.policy_digest,
                "internal": True,
                "attach_additional_networks": False,
            }
            or parsed.expected_user != runtime_profile["user"]
            or list(parsed.expected_capabilities) != runtime_profile["cap_add"]
            or parsed.memory_bytes != runtime_profile["memory_bytes"]
            or parsed.nano_cpus != runtime_profile["nano_cpus"]
            or parsed.pids_limit != runtime_profile["pids_limit"]
            or parsed.expected_container_count != 1
        ):
            raise EngineDockerPolicyError("V2 Docker custody differs from qualified profile")
        expected_tmpfs = runtime_profile["tmpfs"]
        if not isinstance(tmpfs_options, Mapping) or dict(tmpfs_options) != expected_tmpfs:
            raise EngineDockerPolicyError("V2 Docker tmpfs options differ from qualified profile")
        if tuple(item.destination for item in parsed.expected_mounts) != tuple(
            sorted(expected_tmpfs)
        ):
            raise EngineDockerPolicyError(
                "V2 Docker custody tmpfs set differs from qualified profile"
            )
        mounts: list[DockerTmpfsV2] = []
        for item in parsed.expected_mounts:
            options = expected_tmpfs[item.destination]
            if (
                item.mount_type != "tmpfs"
                or item.source
                or item.read_only
                or item.options_digest != content_hash({"options": options})
            ):
                raise EngineDockerPolicyError(
                    "V2 Docker custody tmpfs differs from qualified profile"
                )
            mounts.append(
                DockerTmpfsV2.create(
                    destination=item.destination,
                    options=options,
                    options_digest=item.options_digest,
                )
            )
        decision_ref = _v2_admission_decision_ref(image_admission_decision)
        common = parsed.to_dict()
        for field in (
            "image_reference",
            "runtime_platform",
            "platform_child_manifest_digest",
            "image_config_digest",
            "image_relation_receipt_ref",
        ):
            common.pop(field)
        common["schema_version"] = "bluefire.engine-container-custody.v1"
        common["sandbox_image_digest"] = parsed.image_reference.rsplit("@", 1)[-1]
        common["expected_mounts"] = [
            {
                "mount_type": "tmpfs",
                "source": "",
                "destination": "/workspace",
                "read_only": False,
                "options_digest": content_hash({"options": _V1_PROJECTION_TMPFS_OPTIONS}),
            }
        ]
        base_policy = DockerApiPolicy.create(
            # V1's common constructor uses build.image_reference as its image
            # input. This temporary projection validates common policy fields;
            # the original build remains bound to the upstream index above.
            build=replace(build, image_reference=derived_reference),
            # The V1 projection validates only fields shared with this V2 plan.
            network=network,  # type: ignore[arg-type]
            custody=ContainerCustodyPlan.from_mapping(common),
            api_version=api_version,
            tmpfs_options={"/workspace": _V1_PROJECTION_TMPFS_OPTIONS},
        )
        common_values = tuple(
            sorted(
                (item.name, getattr(base_policy, item.name))
                for item in fields(DockerApiPolicy)
                if item.name not in {"schema_version", "image_reference", "image_digest", "tmpfs"}
            )
        )
        return cls(
            _common_values=common_values,
            image_reference=derived_reference,
            platform_child_manifest_digest=parsed.platform_child_manifest_digest,
            image_config_digest=parsed.image_config_digest,
            image_relation_receipt_ref=parsed.image_relation_receipt_ref,
            tmpfs=tuple(mounts),
            memory_swap_bytes=runtime_profile["memory_swap_bytes"],
            upstream_build_ref=identity_row["startup_build_ref"],
            upstream_image_reference=build.image_reference,
            image_contract_digest=contract.contract_digest,
            execution_identity_digest=identity.identity_digest,
            custody_plan_digest=parsed.plan_digest,
            image_runtime_profile_digest=contract.runtime_profile_digest,
            controlled_runtime_profile_ref=identity_row["controlled_runtime_profile_ref"],
            runtime_qualification_ref=identity_row["runtime_qualification_ref"],
            image_admission_decision_ref=decision_ref,
            controller_relation_verifier=controller_relation_verifier,
            controller_admission_verifier=controller_admission_verifier,
            network=network,
            custody=parsed,
            image_contract=contract,
            execution_identity=identity,
            protected_execution_identity_digest=protected_execution_identity_digest,
            image_admission_decision=image_admission_decision,
        )

    @property
    def schema_version(self) -> str:
        return "bluefire.engine-docker-api-policy.v2"

    @property
    def image_identity_digest(self) -> str:
        return container_image_identity_digest(
            image_reference=self.image_reference,
            runtime_platform=V2_RUNTIME_PLATFORM,
            platform_child_manifest_digest=self.platform_child_manifest_digest,
            image_config_digest=self.image_config_digest,
            image_relation_receipt_ref=self.image_relation_receipt_ref,
        )

    @property
    def image_runtime_profile(self) -> Mapping[str, Any]:
        """The exact reviewed profile verified against the reopened contract."""

        return proposed_image_runtime_profile(
            network_id=self.network_id,
            network_name=self.network_name,
            network_policy_digest=self.network_policy_digest,
        )

    def __getattr__(self, name: str) -> Any:
        if name == "image_digest":
            raise AttributeError("v2 Docker policy has no ambiguous image_digest")
        values = dict(self._common_values)
        if name not in values:
            raise AttributeError(name)
        return values[name]

    def to_dict(self) -> dict[str, Any]:
        row = self._v1_projection().to_dict()
        row.pop("image_digest")
        row["schema_version"] = self.schema_version
        row["runtime_platform"] = V2_RUNTIME_PLATFORM
        row["platform_child_manifest_digest"] = self.platform_child_manifest_digest
        row["image_config_digest"] = self.image_config_digest
        row["image_relation_receipt_ref"] = self.image_relation_receipt_ref
        row["tmpfs"] = [item.to_dict() for item in self.tmpfs]
        row["memory_swap_bytes"] = self.memory_swap_bytes
        row["upstream_build_ref"] = self.upstream_build_ref
        row["upstream_image_reference"] = self.upstream_image_reference
        row["image_contract_digest"] = self.image_contract_digest
        row["execution_identity_digest"] = self.execution_identity_digest
        row["custody_plan_digest"] = self.custody_plan_digest
        row["protected_execution_identity_digest"] = (
            self.verified_admission.protected_execution_identity_digest
        )
        row["image_runtime_profile_digest"] = self.image_runtime_profile_digest
        row["controlled_runtime_profile_ref"] = self.controlled_runtime_profile_ref
        row["runtime_qualification_ref"] = self.runtime_qualification_ref
        row["image_admission_decision_ref"] = self.image_admission_decision_ref
        return row

    @property
    def policy_digest(self) -> str:
        return content_hash(self.to_dict())


DockerPolicy = DockerApiPolicy | DockerApiPolicyV2


def validate_docker_container_namespace_proof(
    policy: DockerPolicy, host_config: Mapping[str, Any]
) -> None:
    """Verify Moby's exact private namespace representation.

    Docker create and container inspect both use an empty ``PidMode`` and
    ``UTSMode`` for private namespaces. ``IpcMode`` is a different Moby enum
    and supports the explicit ``private`` value. Requiring all three fields
    prevents a pending container from being promoted after joining host or
    another container's namespaces.
    """

    if not isinstance(policy, (DockerApiPolicy, DockerApiPolicyV2)) or not isinstance(
        host_config, Mapping
    ):
        raise EngineDockerPolicyError("Docker container namespace proof is invalid")
    expected = {
        "IpcMode": policy.expected_ipc_mode,
        "PidMode": policy.expected_pid_mode,
        "UTSMode": policy.expected_uts_mode,
    }
    for field, value in expected.items():
        if (
            field not in host_config
            or not isinstance(host_config[field], str)
            or host_config[field] != value
        ):
            raise EngineDockerPolicyError(
                f"Docker container {field} does not prove a private namespace"
            )


@dataclass(frozen=True, slots=True)
class DockerApiRequest:
    method: str
    target: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def __post_init__(self) -> None:
        if self.method not in {"DELETE", "GET", "HEAD", "POST"}:
            raise EngineDockerPolicyError("Docker request method is unsupported")
        _canonical_target(self.target)
        if not isinstance(self.body, bytes) or len(self.body) > _BODY_LIMIT:
            raise EngineDockerPolicyError("Docker request body is outside its bound")
        if not isinstance(self.headers, tuple) or tuple(sorted(self.headers)) != self.headers:
            raise EngineDockerPolicyError("Docker request headers are not canonical")
        values: dict[str, str] = {}
        for item in self.headers:
            if not isinstance(item, tuple) or len(item) != 2:
                raise EngineDockerPolicyError("Docker request header is invalid")
            key, raw_value = item
            if (
                not isinstance(key, str)
                or key != key.lower()
                or _HEADER_NAME.fullmatch(key) is None
                or key not in _ALLOWED_HEADERS
                or key in values
            ):
                raise EngineDockerPolicyError("Docker request header is not permitted")
            values[key] = _text(raw_value, f"Docker {key} header", maximum=256)
        if values.get("host", "docker") != "docker":
            raise EngineDockerPolicyError("Docker request host is not the private proxy")
        if values.get("accept", "application/json") not in {"*/*", "application/json"}:
            raise EngineDockerPolicyError("Docker request accept type is not permitted")
        if "content-length" in values and values["content-length"] != str(len(self.body)):
            raise EngineDockerPolicyError("Docker content length does not match")
        if self.body:
            if values.get("content-type") != "application/json":
                raise EngineDockerPolicyError("Docker JSON body requires application/json")
        elif "content-type" in values:
            raise EngineDockerPolicyError("Docker bodyless request has a content type")

    @classmethod
    def create(
        cls,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> "DockerApiRequest":
        rows: list[tuple[str, str]] = []
        for raw_key, raw_value in (headers or {}).items():
            if (
                not isinstance(raw_key, str)
                or raw_key != raw_key.lower()
                or _HEADER_NAME.fullmatch(raw_key) is None
                or raw_key not in _ALLOWED_HEADERS
            ):
                raise EngineDockerPolicyError("Docker request header is not permitted")
            rows.append((raw_key, _text(raw_value, f"Docker {raw_key} header", maximum=256)))
        return cls(method=method, target=target, headers=tuple(sorted(rows)), body=body)


@dataclass(frozen=True, slots=True)
class DockerOwnership:
    daemon_instance_digest: str
    pending_container_ids: tuple[str, ...]
    container_ids: tuple[str, ...]
    exec_bindings: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _digest(self.daemon_instance_digest, "owned Docker daemon instance")
        for label, values in (
            ("pending Docker container ID", self.pending_container_ids),
            ("owned Docker container ID", self.container_ids),
        ):
            if (
                not isinstance(values, tuple)
                or tuple(sorted(set(values))) != values
                or any(
                    not isinstance(item, str) or _FULL_RESOURCE_ID.fullmatch(item) is None
                    for item in values
                )
            ):
                raise EngineDockerPolicyError(f"{label} is invalid")
        if set(self.pending_container_ids) & set(self.container_ids):
            raise EngineDockerPolicyError("Docker container cannot be both pending and owned")
        if not isinstance(self.exec_bindings, tuple) or tuple(sorted(self.exec_bindings)) != (
            self.exec_bindings
        ):
            raise EngineDockerPolicyError("owned Docker exec bindings are not canonical")
        seen: set[str] = set()
        for item in self.exec_bindings:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or _FULL_RESOURCE_ID.fullmatch(item[0]) is None
                or _FULL_RESOURCE_ID.fullmatch(item[1]) is None
                or item[0] in seen
                or item[1] not in self.container_ids
            ):
                raise EngineDockerPolicyError("owned Docker exec binding is invalid")
            seen.add(item[0])

    @classmethod
    def create(
        cls,
        *,
        daemon_instance_digest: str,
        pending_container_ids: Sequence[str] = (),
        container_ids: Sequence[str] = (),
        exec_bindings: Sequence[tuple[str, str]] = (),
    ) -> "DockerOwnership":
        pending = _string_tuple(
            pending_container_ids,
            "pending Docker container ID",
            _FULL_RESOURCE_ID,
            maximum_items=16,
        )
        containers = _string_tuple(
            container_ids, "owned Docker container ID", _FULL_RESOURCE_ID, maximum_items=16
        )
        if set(pending) & set(containers):
            raise EngineDockerPolicyError("Docker container cannot be both pending and owned")
        rows: list[tuple[str, str]] = []
        for value in exec_bindings:
            if not isinstance(value, tuple) or len(value) != 2:
                raise EngineDockerPolicyError("owned Docker exec binding is invalid")
            exec_id = _text(value[0], "owned Docker exec ID", _FULL_RESOURCE_ID, maximum=64)
            container_id = _text(
                value[1], "owned Docker exec container ID", _FULL_RESOURCE_ID, maximum=64
            )
            if container_id not in containers:
                raise EngineDockerPolicyError("owned Docker exec belongs to an unknown container")
            rows.append((exec_id, container_id))
        result = tuple(sorted(rows))
        if len(set(result)) != len(result) or len({item[0] for item in result}) != len(result):
            raise EngineDockerPolicyError("owned Docker exec bindings are not unique")
        return cls(
            daemon_instance_digest=_digest(daemon_instance_digest, "owned Docker daemon instance"),
            pending_container_ids=pending,
            container_ids=containers,
            exec_bindings=result,
        )

    def owns_container(self, resource_id: str) -> bool:
        return resource_id in self.container_ids

    def has_pending_container(self, resource_id: str) -> bool:
        return resource_id in self.pending_container_ids

    def exec_container(self, resource_id: str) -> str | None:
        return next(
            (
                container_id
                for exec_id, container_id in self.exec_bindings
                if exec_id == resource_id
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class DockerApiDecision:
    """Request authorization plus mandatory future-proxy response obligations.

    A successful decision is not evidence that a returned resource is owned.
    The proxy must apply ``response_contract`` and its byte/deadline bounds;
    create results remain pending until exact inspection promotes them.
    """

    operation: DockerApiOperation
    response_contract: DockerResponseContract
    policy_digest: str
    body_digest: str | None
    resource_id: str | None
    owner_container_id: str | None
    deadline_seconds: int
    response_byte_limit: int


def _decision(
    policy: DockerPolicy,
    operation: DockerApiOperation,
    response: DockerResponseContract,
    *,
    body: Mapping[str, Any] | None = None,
    resource_id: str | None = None,
    owner_container_id: str | None = None,
    deadline_seconds: int = 10,
    response_byte_limit: int = 64 * 1024,
) -> DockerApiDecision:
    return DockerApiDecision(
        operation=operation,
        response_contract=response,
        policy_digest=policy.policy_digest,
        body_digest=content_hash(body) if body is not None else None,
        resource_id=resource_id,
        owner_container_id=owner_container_id,
        deadline_seconds=deadline_seconds,
        response_byte_limit=response_byte_limit,
    )


def _required_owned_container(resource_id: str, ownership: DockerOwnership) -> None:
    if _FULL_RESOURCE_ID.fullmatch(resource_id) is None or not ownership.owns_container(
        resource_id
    ):
        raise EngineDockerPolicyError("Docker container is not positively owned")


def _required_owned_exec(resource_id: str, ownership: DockerOwnership) -> str:
    if _FULL_RESOURCE_ID.fullmatch(resource_id) is None:
        raise EngineDockerPolicyError("Docker exec ID is invalid")
    owner = ownership.exec_container(resource_id)
    if owner is None:
        raise EngineDockerPolicyError("Docker exec is not positively owned")
    return owner


def _validate_create(policy: DockerPolicy, request: DockerApiRequest) -> Mapping[str, Any]:
    if isinstance(policy, DockerApiPolicyV2):
        return _validate_create_v2(policy, request)
    row = _exact(
        _json_object(request.body, "Docker container create"),
        frozenset(
            {
                "AttachStderr",
                "AttachStdin",
                "AttachStdout",
                "Cmd",
                "Env",
                "HostConfig",
                "Image",
                "Labels",
                "NetworkDisabled",
                "NetworkingConfig",
                "OpenStdin",
                "StdinOnce",
                "Tty",
                "User",
            }
        ),
        "Docker container create",
    )
    if row["Image"] != policy.image_reference:
        raise EngineDockerPolicyError("Docker create image is not the reviewed digest")
    if row["User"] != policy.expected_user:
        raise EngineDockerPolicyError("Docker create user does not match custody")
    if row["Env"] != []:
        raise EngineDockerPolicyError("Docker create environment must be empty")
    if row["Cmd"] != ["tail", "-f", "/dev/null"]:
        raise EngineDockerPolicyError("Docker create command is not fixed")
    if row["Labels"] != dict(policy.required_labels):
        raise EngineDockerPolicyError("Docker create labels do not bind exact ownership")
    for key in (
        "AttachStderr",
        "AttachStdin",
        "AttachStdout",
        "NetworkDisabled",
        "OpenStdin",
        "StdinOnce",
        "Tty",
    ):
        _expect_bool(row[key], f"Docker create {key}", False)
    host = _exact(
        row["HostConfig"],
        frozenset(
            {
                "AutoRemove",
                "Binds",
                "CapAdd",
                "CapDrop",
                "CgroupParent",
                "DeviceRequests",
                "Devices",
                "Dns",
                "DnsOptions",
                "DnsSearch",
                "ExtraHosts",
                "IpcMode",
                "LogConfig",
                "Memory",
                "Mounts",
                "NanoCpus",
                "NetworkMode",
                "OomKillDisable",
                "PidMode",
                "PidsLimit",
                "PortBindings",
                "Privileged",
                "PublishAllPorts",
                "ReadonlyRootfs",
                "RestartPolicy",
                "SecurityOpt",
                "Tmpfs",
                "UTSMode",
            }
        ),
        "Docker create HostConfig",
    )
    for key in ("AutoRemove", "OomKillDisable", "Privileged", "PublishAllPorts"):
        _expect_bool(host[key], f"Docker {key}", False)
    _expect_bool(host["ReadonlyRootfs"], "Docker ReadonlyRootfs", True)
    for key in (
        "Binds",
        "DeviceRequests",
        "Devices",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "Mounts",
    ):
        if host[key] != []:
            raise EngineDockerPolicyError("Docker create includes a prohibited host attachment")
    if host["PortBindings"] != {}:
        raise EngineDockerPolicyError("Docker create must not publish ports")
    if host["CapAdd"] != list(policy.expected_capabilities) or host["CapDrop"] != ["ALL"]:
        raise EngineDockerPolicyError("Docker create capabilities do not match custody")
    if "SYS_ADMIN" in policy.expected_capabilities:
        raise EngineDockerPolicyError("Docker SYS_ADMIN capability is never permitted")
    if host["SecurityOpt"] != ["no-new-privileges:true"]:
        raise EngineDockerPolicyError("Docker create security options are not fixed")
    if host["NetworkMode"] != policy.network_name:
        raise EngineDockerPolicyError("Docker create network mode does not match")
    validate_docker_container_namespace_proof(policy, host)
    if (
        host["CgroupParent"] != policy.cgroup_parent
        or _CGROUP_PARENT.fullmatch(str(host["CgroupParent"])) is None
    ):
        raise EngineDockerPolicyError("Docker create cgroup parent does not match")
    _expect_int(host["Memory"], "Docker create memory limit", policy.memory_bytes)
    _expect_int(host["NanoCpus"], "Docker create CPU limit", policy.nano_cpus)
    _expect_int(host["PidsLimit"], "Docker create PID limit", policy.pids_limit)
    restart = _exact(
        host["RestartPolicy"],
        frozenset({"MaximumRetryCount", "Name"}),
        "Docker restart policy",
    )
    _expect_int(restart["MaximumRetryCount"], "Docker restart count", 0)
    if restart["Name"] != "no":
        raise EngineDockerPolicyError("Docker create restart policy is not fixed")
    if host["LogConfig"] != {
        "Config": {"max-file": "1", "max-size": "10m"},
        "Type": "json-file",
    }:
        raise EngineDockerPolicyError("Docker create log policy is not fixed")
    if host["Tmpfs"] != {item.destination: item.options for item in policy.tmpfs}:
        raise EngineDockerPolicyError("Docker create tmpfs does not match custody")
    networking = _exact(
        row["NetworkingConfig"], frozenset({"EndpointsConfig"}), "Docker NetworkingConfig"
    )
    endpoints = networking["EndpointsConfig"]
    if not isinstance(endpoints, Mapping) or set(endpoints) != {policy.network_name}:
        raise EngineDockerPolicyError("Docker create endpoint set does not match")
    endpoint = _exact(
        endpoints[policy.network_name],
        frozenset({"Aliases", "NetworkID"}),
        "Docker endpoint",
    )
    if endpoint != {"Aliases": [], "NetworkID": policy.network_id}:
        raise EngineDockerPolicyError("Docker create endpoint is not exact")
    return row


def _validate_create_v2(policy: DockerApiPolicyV2, request: DockerApiRequest) -> Mapping[str, Any]:
    """Require the reopened V2 image contract's exact Docker create settings."""

    profile = policy.image_runtime_profile
    row = _exact(
        _json_object(request.body, "V2 Docker container create"),
        frozenset(
            {
                "AttachStderr",
                "AttachStdin",
                "AttachStdout",
                "Cmd",
                "Entrypoint",
                "Env",
                "HostConfig",
                "Image",
                "Labels",
                "NetworkDisabled",
                "NetworkingConfig",
                "OpenStdin",
                "StdinOnce",
                "Tty",
                "User",
                "WorkingDir",
            }
        ),
        "V2 Docker container create",
    )
    environment = [f"{key}={profile['environment'][key]}" for key in sorted(profile["environment"])]
    for field_name, expected in (
        ("Image", policy.image_reference),
        ("User", profile["user"]),
        ("Cmd", profile["command"]),
        ("Entrypoint", profile["entrypoint"]),
        ("Env", environment),
        ("WorkingDir", profile["working_directory"]),
        ("Labels", dict(policy.required_labels)),
    ):
        if row[field_name] != expected:
            raise EngineDockerPolicyError(
                f"V2 Docker create {field_name} differs from runtime profile"
            )
    for key in (
        "AttachStderr",
        "AttachStdin",
        "AttachStdout",
        "NetworkDisabled",
        "OpenStdin",
        "StdinOnce",
        "Tty",
    ):
        _expect_bool(row[key], f"V2 Docker create {key}", False)
    host = _exact(
        row["HostConfig"],
        frozenset(
            {
                "AutoRemove",
                "Binds",
                "CapAdd",
                "CapDrop",
                "CgroupParent",
                "DeviceRequests",
                "Devices",
                "Dns",
                "DnsOptions",
                "DnsSearch",
                "ExtraHosts",
                "IpcMode",
                "LogConfig",
                "Memory",
                "MemorySwap",
                "Mounts",
                "NanoCpus",
                "NetworkMode",
                "OomKillDisable",
                "PidMode",
                "PidsLimit",
                "PortBindings",
                "Privileged",
                "PublishAllPorts",
                "ReadonlyRootfs",
                "RestartPolicy",
                "SecurityOpt",
                "Tmpfs",
                "UTSMode",
            }
        ),
        "V2 Docker create HostConfig",
    )
    for key in ("AutoRemove", "OomKillDisable", "Privileged", "PublishAllPorts"):
        _expect_bool(host[key], f"V2 Docker {key}", False)
    _expect_bool(host["ReadonlyRootfs"], "V2 Docker ReadonlyRootfs", True)
    for key in (
        "Binds",
        "DeviceRequests",
        "Devices",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "Mounts",
    ):
        if host[key] != []:
            raise EngineDockerPolicyError("V2 Docker create includes a prohibited host attachment")
    if host["PortBindings"] != {}:
        raise EngineDockerPolicyError("V2 Docker create must not publish ports")
    if host["CapAdd"] != profile["cap_add"] or host["CapDrop"] != profile["cap_drop"]:
        raise EngineDockerPolicyError("V2 Docker create capabilities differ from runtime profile")
    if host["SecurityOpt"] != profile["security_options"]:
        raise EngineDockerPolicyError(
            "V2 Docker create security options differ from runtime profile"
        )
    if host["NetworkMode"] != policy.network_name:
        raise EngineDockerPolicyError("V2 Docker create network differs from runtime profile")
    validate_docker_container_namespace_proof(policy, host)
    if host["CgroupParent"] != policy.cgroup_parent:
        raise EngineDockerPolicyError("V2 Docker create cgroup parent is not attempt-bound")
    for key, expected in (
        ("Memory", policy.memory_bytes),
        ("MemorySwap", policy.memory_swap_bytes),
        ("NanoCpus", policy.nano_cpus),
        ("PidsLimit", policy.pids_limit),
    ):
        _expect_int(host[key], f"V2 Docker create {key}", expected)
    restart = _exact(
        host["RestartPolicy"],
        frozenset({"MaximumRetryCount", "Name"}),
        "V2 Docker restart policy",
    )
    _expect_int(restart["MaximumRetryCount"], "V2 Docker restart count", 0)
    if restart["Name"] != profile["restart_policy"]:
        raise EngineDockerPolicyError(
            "V2 Docker create restart policy differs from runtime profile"
        )
    if host["LogConfig"] != {
        "Config": {"max-file": "1", "max-size": "10m"},
        "Type": "json-file",
    }:
        raise EngineDockerPolicyError("V2 Docker create log policy is not fixed")
    if host["Tmpfs"] != profile["tmpfs"]:
        raise EngineDockerPolicyError("V2 Docker create tmpfs differs from runtime profile")
    networking = _exact(
        row["NetworkingConfig"], frozenset({"EndpointsConfig"}), "V2 Docker NetworkingConfig"
    )
    endpoints = networking["EndpointsConfig"]
    if not isinstance(endpoints, Mapping) or set(endpoints) != {policy.network_name}:
        raise EngineDockerPolicyError("V2 Docker create endpoint set differs from runtime profile")
    endpoint = _exact(
        endpoints[policy.network_name],
        frozenset({"Aliases", "NetworkID"}),
        "V2 Docker endpoint",
    )
    if endpoint != {"Aliases": [], "NetworkID": policy.network_id}:
        raise EngineDockerPolicyError("V2 Docker create endpoint is not exact")
    return row


def _validate_exec(policy: DockerPolicy, request: DockerApiRequest) -> Mapping[str, Any]:
    row = _exact(
        _json_object(request.body, "Docker exec create"),
        frozenset(
            {
                "AttachStderr",
                "AttachStdin",
                "AttachStdout",
                "Cmd",
                "DetachKeys",
                "Env",
                "Privileged",
                "Tty",
                "User",
                "WorkingDir",
            }
        ),
        "Docker exec create",
    )
    _expect_bool(row["AttachStdin"], "Docker exec AttachStdin", False)
    _expect_bool(row["AttachStdout"], "Docker exec AttachStdout", True)
    _expect_bool(row["AttachStderr"], "Docker exec AttachStderr", True)
    _expect_bool(row["Privileged"], "Docker exec Privileged", False)
    _expect_bool(row["Tty"], "Docker exec Tty", False)
    if row["DetachKeys"] != "" or row["Env"] != []:
        raise EngineDockerPolicyError("Docker exec may not override keys or environment")
    if row["User"] != policy.expected_user:
        raise EngineDockerPolicyError("Docker exec user does not match custody")
    if row["WorkingDir"] != policy.exec_working_directory:
        raise EngineDockerPolicyError("Docker exec working directory is not the isolated workspace")
    command = row["Cmd"]
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= _MAX_EXEC_ARGUMENTS
        or any(
            not isinstance(item, str)
            or not item
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in command
        )
        or sum(len(item.encode("utf-8")) for item in command) > _MAX_EXEC_ARGUMENT_BYTES
    ):
        raise EngineDockerPolicyError("Docker exec command is outside its sandbox bound")
    return row


def _archive_path(value: str, policy: DockerPolicy) -> str:
    if (
        not isinstance(value, str)
        or value != policy.exec_working_directory
        or value not in {item.destination for item in policy.tmpfs}
    ):
        # Docker resolves the requested path inside the container. A lexical
        # descendant check cannot prove that a descendant is not a symlink to
        # the root filesystem. Until the controller has trusted resolved-path
        # evidence, only the exact admitted tmpfs mountpoint may be archived.
        raise EngineDockerPolicyError("Docker archive path is not the exact admitted mountpoint")
    return value


def authorize_docker_api_request(
    policy: DockerPolicy,
    request: DockerApiRequest,
    ownership: DockerOwnership,
) -> DockerApiDecision:
    """Authorize one normalized request against one immutable attempt policy."""

    if ownership.daemon_instance_digest != policy.daemon_instance_digest:
        raise EngineDockerPolicyError("Docker daemon identity changed after admission")
    path, query = _canonical_target(request.target)
    prefix = f"/{policy.api_version}"
    if request.method in {"GET", "HEAD"} and path == "/_ping":
        _no_query(query)
        _no_body(request)
        return _decision(policy, DockerApiOperation.PING, DockerResponseContract.PING)
    if request.method == "GET" and path == "/version":
        _no_query(query)
        _no_body(request)
        return _decision(
            policy,
            DockerApiOperation.VERSION,
            DockerResponseContract.VERSION_REDACTED,
            response_byte_limit=16 * 1024,
        )
    if request.method == "GET" and path == f"{prefix}/info":
        _no_query(query)
        _no_body(request)
        return _decision(
            policy,
            DockerApiOperation.INFO,
            DockerResponseContract.INFO_REDACTED,
            response_byte_limit=64 * 1024,
        )

    image_prefix = f"{prefix}/images/"
    if request.method == "GET" and path.startswith(image_prefix) and path.endswith("/json"):
        _no_query(query)
        _no_body(request)
        encoded = path[len(image_prefix) : -len("/json")]
        decoded = unquote(encoded)
        if quote(decoded, safe="") != encoded or decoded != policy.image_reference:
            raise EngineDockerPolicyError("Docker image inspection is outside the reviewed image")
        return _decision(
            policy,
            DockerApiOperation.IMAGE_INSPECT,
            DockerResponseContract.EXACT_IMAGE,
            response_byte_limit=1024 * 1024,
        )

    if request.method == "POST" and path == f"{prefix}/containers/create":
        values = _query(query, fields=frozenset({"name"}))
        if (
            values["name"] != policy.container_name
            or _CONTAINER_NAME.fullmatch(values["name"]) is None
        ):
            raise EngineDockerPolicyError("Docker container name is not attempt-bound")
        if (
            len(ownership.pending_container_ids) + len(ownership.container_ids)
            >= policy.expected_container_count
        ):
            raise EngineDockerPolicyError("Docker container count is exhausted")
        body = _validate_create(policy, request)
        return _decision(
            policy,
            DockerApiOperation.CONTAINER_CREATE,
            DockerResponseContract.REGISTER_PENDING_CONTAINER,
            body=body,
            response_byte_limit=4096,
        )

    container_match = re.fullmatch(
        rf"{re.escape(prefix)}/containers/([0-9a-f]{{64}})/(json|start|exec|archive|logs|stop|kill)",
        path,
    )
    if container_match:
        container_id, action = container_match.groups()
        if request.method == "GET" and action == "json":
            _no_query(query)
            _no_body(request)
            if ownership.has_pending_container(container_id):
                return _decision(
                    policy,
                    DockerApiOperation.CONTAINER_INSPECT,
                    DockerResponseContract.VERIFY_AND_REGISTER_CONTAINER,
                    resource_id=container_id,
                    response_byte_limit=1024 * 1024,
                )
            _required_owned_container(container_id, ownership)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_INSPECT,
                DockerResponseContract.OWNED_CONTAINER,
                resource_id=container_id,
                response_byte_limit=1024 * 1024,
            )
        _required_owned_container(container_id, ownership)
        if request.method == "POST" and action == "start":
            _no_query(query)
            _no_body(request)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_START,
                DockerResponseContract.EMPTY,
                resource_id=container_id,
            )
        if request.method == "POST" and action == "exec":
            if isinstance(policy, DockerApiPolicyV2):
                raise EngineDockerPolicyError("V2 Docker exec is not admitted for runtime installs")
            _no_query(query)
            body = _validate_exec(policy, request)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_EXEC_CREATE,
                DockerResponseContract.REGISTER_EXEC,
                body=body,
                resource_id=container_id,
                owner_container_id=container_id,
            )
        if request.method == "GET" and action == "archive":
            values = _query(query, fields=frozenset({"path"}))
            _archive_path(values["path"], policy)
            _no_body(request)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_ARCHIVE,
                DockerResponseContract.BOUNDED_ARCHIVE,
                resource_id=container_id,
                deadline_seconds=30,
                response_byte_limit=policy.archive_response_byte_limit,
            )
        if request.method == "GET" and action == "logs":
            values = _query(
                query,
                fields=frozenset({"follow", "stderr", "stdout", "tail", "timestamps"}),
            )
            if (
                values["follow"] != "0"
                or values["stderr"] != "1"
                or values["stdout"] != "1"
                or values["timestamps"] != "1"
                or not values["tail"].isdigit()
                or not 0 <= int(values["tail"]) <= _MAX_LOG_TAIL
                or str(int(values["tail"])) != values["tail"]
            ):
                raise EngineDockerPolicyError("Docker log request is outside its bound")
            _no_body(request)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_LOGS,
                DockerResponseContract.BOUNDED_LOG_STREAM,
                resource_id=container_id,
                deadline_seconds=30,
                response_byte_limit=policy.log_response_byte_limit,
            )
        if request.method == "POST" and action == "stop":
            values = _query(query, fields=frozenset({"t"}))
            if (
                not values["t"].isdigit()
                or not 0 <= int(values["t"]) <= _MAX_STOP_SECONDS
                or str(int(values["t"])) != values["t"]
            ):
                raise EngineDockerPolicyError("Docker stop timeout is outside its bound")
            _no_body(request)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_STOP,
                DockerResponseContract.EMPTY,
                resource_id=container_id,
            )
        if request.method == "POST" and action == "kill":
            values = _query(query, fields=frozenset({"signal"}))
            if values["signal"] not in {"SIGKILL", "SIGTERM"}:
                raise EngineDockerPolicyError("Docker kill signal is not permitted")
            _no_body(request)
            return _decision(
                policy,
                DockerApiOperation.CONTAINER_KILL,
                DockerResponseContract.EMPTY,
                resource_id=container_id,
            )

    delete_match = re.fullmatch(rf"{re.escape(prefix)}/containers/([0-9a-f]{{64}})", path)
    if request.method == "DELETE" and delete_match:
        container_id = delete_match.group(1)
        _required_owned_container(container_id, ownership)
        if _query(query, fields=frozenset({"force", "v"})) != {"force": "1", "v": "1"}:
            raise EngineDockerPolicyError("Docker delete flags are not fixed")
        _no_body(request)
        return _decision(
            policy,
            DockerApiOperation.CONTAINER_DELETE,
            DockerResponseContract.EMPTY,
            resource_id=container_id,
        )

    exec_match = re.fullmatch(rf"{re.escape(prefix)}/exec/([0-9a-f]{{64}})/(start|json)", path)
    if exec_match:
        if isinstance(policy, DockerApiPolicyV2):
            raise EngineDockerPolicyError("V2 Docker exec is not admitted for runtime installs")
        exec_id, action = exec_match.groups()
        container_id = _required_owned_exec(exec_id, ownership)
        _no_query(query)
        if request.method == "POST" and action == "start":
            row = _exact(
                _json_object(request.body, "Docker exec start"),
                frozenset({"Detach", "Tty"}),
                "Docker exec start",
            )
            _expect_bool(row["Detach"], "Docker exec Detach", False)
            _expect_bool(row["Tty"], "Docker exec Tty", False)
            return _decision(
                policy,
                DockerApiOperation.EXEC_START,
                DockerResponseContract.BOUNDED_EXEC_STREAM,
                body=row,
                resource_id=exec_id,
                owner_container_id=container_id,
                deadline_seconds=policy.exec_deadline_seconds,
                response_byte_limit=policy.exec_response_byte_limit,
            )
        if request.method == "GET" and action == "json":
            _no_body(request)
            return _decision(
                policy,
                DockerApiOperation.EXEC_INSPECT,
                DockerResponseContract.OWNED_EXEC,
                resource_id=exec_id,
                owner_container_id=container_id,
            )

    raise EngineDockerPolicyError("Docker API operation is not permitted")


__all__ = [
    "ControllerImageAdmissionVerifier",
    "ControllerImageRelationVerifier",
    "ControllerVerifiedImageAdmission",
    "ControllerVerifiedImageRelation",
    "DockerApiDecision",
    "DockerApiOperation",
    "DockerApiPolicy",
    "DockerApiPolicyV2",
    "DockerApiRequest",
    "DockerOwnership",
    "DockerResponseContract",
    "DockerTmpfs",
    "DockerTmpfsV2",
    "EngineDockerPolicyError",
    "authorize_docker_api_request",
    "validate_docker_container_namespace_proof",
]
