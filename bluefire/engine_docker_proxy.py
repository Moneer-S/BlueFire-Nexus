"""Effect-free protocol core for one controller-owned Docker policy proxy.

The core opens no socket and contacts no daemon.  It accepts one complete
HTTP/1.1 request as bytes, asks an injected transport to exchange those exact
bytes with the already-admitted daemon, validates the complete response, and
publishes only a bounded redacted reply.  Request authorization and resource
ownership come from :mod:`bluefire.engine_docker_control`.

The current Docker policy cannot represent HTTP upgrade headers.  Exec and log
streams are therefore limited to bounded HTTP 200 Docker multiplex frames;
raw upgrades are refused until the policy contract is explicitly extended.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import threading
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qsl

from .engine_docker_control import (
    DockerApiDecision,
    DockerApiOperation,
    DockerApiPolicy,
    DockerApiRequest,
    DockerOwnership,
    DockerResponseContract,
    EngineDockerPolicyError,
    authorize_docker_api_request,
)
from .util import content_hash, json_clone


class EngineDockerProxyError(RuntimeError):
    """Raised for a malformed or unpublishable proxy exchange."""


_METHOD = re.compile(rb"(?:DELETE|GET|HEAD|POST)")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_RESOURCE_ID = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUEST_LIMIT = 128 * 1024
_HEADER_LIMIT = 32 * 1024
_AUDIT_TEXT_LIMIT = 96
_GO_MODE_DIRECTORY = 0x80000000
_GO_MODE_TYPE_MASK = 0x8F280000
_ALLOWED_REQUEST_HEADERS = frozenset(
    {"accept", "content-length", "content-type", "host", "user-agent"}
)
_ALLOWED_RESPONSE_HEADERS = frozenset(
    {
        "api-version",
        "builder-version",
        "cache-control",
        "content-length",
        "content-type",
        "date",
        "docker-experimental",
        "ostype",
        "pragma",
        "server",
        "swarm",
        "x-docker-container-path-stat",
    }
)


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe_text(value: Any, label: str, *, maximum: int = _AUDIT_TEXT_LIMIT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise EngineDockerProxyError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    text = _safe_text(value, label, maximum=71)
    if _DIGEST.fullmatch(text) is None:
        raise EngineDockerProxyError(f"{label} is invalid")
    return text


def _canonical_json(raw: bytes, label: str) -> Mapping[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise EngineDockerProxyError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise EngineDockerProxyError(f"{label} contains a non-finite number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except EngineDockerProxyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngineDockerProxyError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise EngineDockerProxyError(f"{label} must be an object")
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(json_clone(dict(value)), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


class DockerProxyCancellation(Protocol):
    def is_cancelled(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class DockerDaemonExchange:
    request_digest: str
    daemon_instance_digest: str
    raw_response: bytes

    def __post_init__(self) -> None:
        _digest(self.request_digest, "Docker exchange request digest")
        _digest(self.daemon_instance_digest, "Docker exchange daemon digest")
        if not isinstance(self.raw_response, bytes):
            raise EngineDockerProxyError("Docker exchange response is invalid")


class DockerDaemonTransport(Protocol):
    def exchange(
        self,
        raw_request: bytes,
        *,
        deadline_monotonic_ns: int,
        cancellation: DockerProxyCancellation,
    ) -> DockerDaemonExchange: ...


@dataclass(frozen=True, slots=True)
class DockerProxyAuditRecord:
    schema_version: str
    request_ref: str
    sequence: int
    phase: str
    outcome: str
    operation: str
    policy_digest: str
    request_digest: str
    response_digest: str | None
    state_before_digest: str
    state_after_digest: str
    started_monotonic_ns: int
    ended_monotonic_ns: int
    reconciliation_required: bool

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.engine-docker-proxy-audit.v1":
            raise EngineDockerProxyError("Docker proxy audit schema is unsupported")
        _digest(self.request_ref, "Docker proxy request reference")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise EngineDockerProxyError("Docker proxy audit sequence is invalid")
        if self.phase not in {"refused", "validated", "published", "suppressed"}:
            raise EngineDockerProxyError("Docker proxy audit phase is invalid")
        if self.outcome not in {
            "accepted",
            "audit_failed",
            "busy",
            "cancelled",
            "deadline_exceeded",
            "policy_refused",
            "protocol_refused",
            "reconciliation_required",
            "response_refused",
            "transport_failed",
        }:
            raise EngineDockerProxyError("Docker proxy audit outcome is invalid")
        _safe_text(self.operation, "Docker proxy operation", maximum=64)
        _digest(self.policy_digest, "Docker proxy policy digest")
        _digest(self.request_digest, "Docker proxy request digest")
        if self.response_digest is not None:
            _digest(self.response_digest, "Docker proxy response digest")
        _digest(self.state_before_digest, "Docker proxy prior state")
        _digest(self.state_after_digest, "Docker proxy next state")
        for value, label in (
            (self.started_monotonic_ns, "Docker proxy start"),
            (self.ended_monotonic_ns, "Docker proxy end"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EngineDockerProxyError(f"{label} is invalid")
        if self.ended_monotonic_ns < self.started_monotonic_ns:
            raise EngineDockerProxyError("Docker proxy audit chronology is invalid")

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    "schema_version": self.schema_version,
                    "request_ref": self.request_ref,
                    "sequence": self.sequence,
                    "phase": self.phase,
                    "outcome": self.outcome,
                    "operation": self.operation,
                    "policy_digest": self.policy_digest,
                    "request_digest": self.request_digest,
                    "response_digest": self.response_digest,
                    "state_before_digest": self.state_before_digest,
                    "state_after_digest": self.state_after_digest,
                    "started_monotonic_ns": self.started_monotonic_ns,
                    "ended_monotonic_ns": self.ended_monotonic_ns,
                    "reconciliation_required": self.reconciliation_required,
                }
            )
        )


class DockerProxyAuditSink(Protocol):
    def append(self, record: DockerProxyAuditRecord) -> str: ...


@dataclass(frozen=True, slots=True)
class DockerProxyReply:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    head_response: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise EngineDockerProxyError("Docker proxy reply status is invalid")
        if not 100 <= self.status_code <= 599:
            raise EngineDockerProxyError("Docker proxy reply status is invalid")
        if not isinstance(self.headers, tuple) or tuple(sorted(self.headers)) != self.headers:
            raise EngineDockerProxyError("Docker proxy reply headers are not canonical")
        seen: set[str] = set()
        for key, value in self.headers:
            if key in seen or key not in {"content-length", "content-type"}:
                raise EngineDockerProxyError("Docker proxy reply header is invalid")
            seen.add(key)
            _safe_text(value, f"Docker proxy {key}", maximum=128)
        if not isinstance(self.body, bytes):
            raise EngineDockerProxyError("Docker proxy reply body is invalid")
        if not isinstance(self.head_response, bool):
            raise EngineDockerProxyError("Docker proxy reply kind is invalid")
        values = dict(self.headers)
        if self.status_code == 204:
            if self.body or self.headers or self.head_response:
                raise EngineDockerProxyError("Docker empty reply framing is invalid")
            return
        length = values.get("content-length")
        if length is None or len(length) > 20 or not length.isdigit() or str(int(length)) != length:
            raise EngineDockerProxyError("Docker proxy reply length is invalid")
        if self.head_response:
            if self.status_code != 200 or self.body:
                raise EngineDockerProxyError("Docker HEAD reply framing is invalid")
        elif length != str(len(self.body)):
            raise EngineDockerProxyError("Docker proxy reply length does not match")

    @classmethod
    def create(
        cls, status_code: int, body: bytes = b"", *, content_type: str | None = None
    ) -> "DockerProxyReply":
        if status_code == 204:
            if body or content_type is not None:
                raise EngineDockerProxyError("Docker empty reply framing is invalid")
            return cls(status_code=status_code, headers=(), body=b"")
        rows = [("content-length", str(len(body)))]
        if content_type is not None:
            rows.append(("content-type", content_type))
        return cls(status_code=status_code, headers=tuple(sorted(rows)), body=body)

    @classmethod
    def head(
        cls, status_code: int, representation_length: int, *, content_type: str | None = None
    ) -> "DockerProxyReply":
        if (
            isinstance(representation_length, bool)
            or not isinstance(representation_length, int)
            or representation_length < 0
        ):
            raise EngineDockerProxyError("Docker HEAD representation length is invalid")
        rows = [("content-length", str(representation_length))]
        if content_type is not None:
            rows.append(("content-type", content_type))
        return cls(
            status_code=status_code,
            headers=tuple(sorted(rows)),
            body=b"",
            head_response=True,
        )

    @classmethod
    def refused(cls, *, status_code: int = 403) -> "DockerProxyReply":
        body = b'{"error":"docker_proxy_refused"}'
        return cls.create(status_code, body, content_type="application/json")

    def to_http_bytes(self) -> bytes:
        reason = {
            200: "OK",
            201: "Created",
            204: "No Content",
            403: "Forbidden",
            409: "Conflict",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }.get(self.status_code, "Error")
        headers = b"".join(f"{key}: {value}\r\n".encode("ascii") for key, value in self.headers)
        return (
            f"HTTP/1.1 {self.status_code} {reason}\r\n".encode("ascii")
            + headers
            + b"\r\n"
            + self.body
        )


@dataclass(frozen=True, slots=True)
class DockerProxyState:
    ownership: DockerOwnership
    quarantined_container_ids: tuple[str, ...]
    quarantined_exec_bindings: tuple[tuple[str, str], ...]
    generation: int
    reconciliation_required: bool

    def __post_init__(self) -> None:
        if not isinstance(self.ownership, DockerOwnership):
            raise EngineDockerProxyError("Docker proxy ownership is invalid")
        for values, label in (
            (self.quarantined_container_ids, "Docker quarantined container"),
            (tuple(item[0] for item in self.quarantined_exec_bindings), "Docker quarantined exec"),
        ):
            if tuple(sorted(set(values))) != values or any(
                not isinstance(item, str) or _RESOURCE_ID.fullmatch(item) is None for item in values
            ):
                raise EngineDockerProxyError(f"{label} identity is invalid")
        if tuple(sorted(self.quarantined_exec_bindings)) != self.quarantined_exec_bindings:
            raise EngineDockerProxyError("Docker quarantined exec bindings are not canonical")
        for _exec_id, container_id in self.quarantined_exec_bindings:
            if _RESOURCE_ID.fullmatch(container_id) is None:
                raise EngineDockerProxyError("Docker quarantined exec owner is invalid")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 0
        ):
            raise EngineDockerProxyError("Docker proxy generation is invalid")

    @classmethod
    def create(cls, ownership: DockerOwnership) -> "DockerProxyState":
        return cls(
            ownership=ownership,
            quarantined_container_ids=(),
            quarantined_exec_bindings=(),
            generation=0,
            reconciliation_required=False,
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    "daemon_instance_digest": self.ownership.daemon_instance_digest,
                    "pending_container_ids": list(self.ownership.pending_container_ids),
                    "container_ids": list(self.ownership.container_ids),
                    "exec_bindings": [list(item) for item in self.ownership.exec_bindings],
                    "quarantined_container_ids": list(self.quarantined_container_ids),
                    "quarantined_exec_bindings": [
                        list(item) for item in self.quarantined_exec_bindings
                    ],
                    "generation": self.generation,
                    "reconciliation_required": self.reconciliation_required,
                }
            )
        )

    @property
    def state_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class _ParsedResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class _ValidatedResponse:
    reply: DockerProxyReply
    next_ownership: DockerOwnership
    discovered_container_id: str | None = None
    discovered_exec: tuple[str, str] | None = None


def parse_docker_http_request(raw: bytes) -> DockerApiRequest:
    if not isinstance(raw, bytes) or not raw or len(raw) > _REQUEST_LIMIT:
        raise EngineDockerProxyError("Docker request is outside its bound")
    if b"\r\n\r\n" not in raw:
        raise EngineDockerProxyError("Docker request framing is ambiguous")
    head, body = raw.split(b"\r\n\r\n", 1)
    if b"\n" in head.replace(b"\r\n", b"") or b"\r" in head.replace(b"\r\n", b""):
        raise EngineDockerProxyError("Docker request line endings are invalid")
    if len(head) > _HEADER_LIMIT:
        raise EngineDockerProxyError("Docker request headers exceed the bound")
    lines = head.split(b"\r\n")
    if not lines or len(lines[0]) > 4096:
        raise EngineDockerProxyError("Docker request line is invalid")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or _METHOD.fullmatch(parts[0]) is None or parts[2] != b"HTTP/1.1":
        raise EngineDockerProxyError("Docker request line is invalid")
    try:
        method = parts[0].decode("ascii")
        target = parts[1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise EngineDockerProxyError("Docker request line is invalid") from exc
    if not target.startswith("/") or target.startswith("//") or "#" in target:
        raise EngineDockerProxyError("Docker request target is not origin-form")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise EngineDockerProxyError("Docker request header is malformed")
        raw_name, raw_value = line.split(b":", 1)
        if _HEADER_NAME.fullmatch(raw_name) is None:
            raise EngineDockerProxyError("Docker request header name is invalid")
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.decode("ascii").strip(" \t")
        except UnicodeDecodeError as exc:
            raise EngineDockerProxyError("Docker request header is invalid") from exc
        if name in values or name not in _ALLOWED_REQUEST_HEADERS:
            raise EngineDockerProxyError("Docker request header is not permitted")
        if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise EngineDockerProxyError("Docker request header value is invalid")
        values[name] = value
    if values.get("host") != "docker":
        raise EngineDockerProxyError("Docker request host is invalid")
    length_text = values.get("content-length")
    if length_text is None:
        if body:
            raise EngineDockerProxyError("Docker request body lacks an exact length")
    else:
        if (
            len(length_text) > 20
            or not length_text.isdigit()
            or str(int(length_text)) != length_text
        ):
            raise EngineDockerProxyError("Docker request length is noncanonical")
        if int(length_text) != len(body):
            raise EngineDockerProxyError("Docker request length does not match")
    try:
        return DockerApiRequest.create(method=method, target=target, headers=values, body=body)
    except EngineDockerPolicyError as exc:
        raise EngineDockerProxyError("Docker request violates the policy grammar") from exc


def _parse_docker_http_response(
    raw: bytes, *, limit: int, head_response: bool = False
) -> _ParsedResponse:
    if not isinstance(raw, bytes) or not raw or len(raw) > limit + _HEADER_LIMIT:
        raise EngineDockerProxyError("Docker response is outside its bound")
    if b"\r\n\r\n" not in raw:
        raise EngineDockerProxyError("Docker response framing is ambiguous")
    head, body = raw.split(b"\r\n\r\n", 1)
    if b"\n" in head.replace(b"\r\n", b"") or b"\r" in head.replace(b"\r\n", b""):
        raise EngineDockerProxyError("Docker response line endings are invalid")
    if len(head) > _HEADER_LIMIT:
        raise EngineDockerProxyError("Docker response headers exceed the bound")
    lines = head.split(b"\r\n")
    if not lines:
        raise EngineDockerProxyError("Docker response status is missing")
    if (
        len(lines[0]) > 128
        or re.fullmatch(rb"HTTP/1\.1 [1-5][0-9]{2}(?: [\x20-\x7e]{0,64})?", lines[0]) is None
    ):
        raise EngineDockerProxyError("Docker response status is invalid")
    status = lines[0].split(b" ", 2)
    if (
        len(status) < 2
        or status[0] != b"HTTP/1.1"
        or not re.fullmatch(rb"[1-5][0-9]{2}", status[1])
    ):
        raise EngineDockerProxyError("Docker response status is invalid")
    status_code = int(status[1])
    if 100 <= status_code < 200 or 300 <= status_code < 400:
        raise EngineDockerProxyError("Docker interim and redirect responses are refused")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise EngineDockerProxyError("Docker response header is malformed")
        raw_name, raw_value = line.split(b":", 1)
        if _HEADER_NAME.fullmatch(raw_name) is None:
            raise EngineDockerProxyError("Docker response header name is invalid")
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.decode("ascii").strip(" \t")
        except UnicodeDecodeError as exc:
            raise EngineDockerProxyError("Docker response header is invalid") from exc
        if name in values or name not in _ALLOWED_RESPONSE_HEADERS:
            raise EngineDockerProxyError("Docker response header is not permitted")
        if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise EngineDockerProxyError("Docker response header value is invalid")
        values[name] = value
    length_text = values.get("content-length")
    if length_text is None and status_code == 204 and not body:
        length_text = "0"
    if (
        length_text is None
        or len(length_text) > 20
        or not length_text.isdigit()
        or str(int(length_text)) != length_text
    ):
        raise EngineDockerProxyError("Docker response length is missing or noncanonical")
    length = int(length_text)
    if (
        len(body) > limit
        or head_response
        and (body or length > limit)
        or not head_response
        and length != len(body)
    ):
        raise EngineDockerProxyError("Docker response length is outside its bound")
    return _ParsedResponse(status_code=status_code, headers=values, body=body)


def _json_response(response: _ParsedResponse, *, status: int) -> Mapping[str, Any]:
    if response.status_code != status or response.headers.get("content-type") != "application/json":
        raise EngineDockerProxyError("Docker JSON response contract is not satisfied")
    return _canonical_json(response.body, "Docker response")


def _expect_equal(mapping: Mapping[str, Any], field: str, expected: Any, label: str) -> None:
    actual = mapping.get(field)
    if (
        actual != expected
        or type(expected) is int
        and (isinstance(actual, bool) or not isinstance(actual, int))
    ):
        raise EngineDockerProxyError(f"Docker inspect {label} does not match admission")


def _expect_present_empty(mapping: Mapping[str, Any], field: str, label: str) -> None:
    if field not in mapping or mapping[field] not in (None, [], {}):
        raise EngineDockerProxyError(f"Docker inspect {label} is not empty")


def _validate_container_inspect(
    row: Mapping[str, Any],
    policy: DockerApiPolicy,
    container_id: str,
    *,
    pending_promotion: bool,
) -> None:
    _expect_equal(row, "Id", container_id, "identity")
    _expect_equal(row, "Image", policy.image_digest, "image")
    _expect_equal(row, "Name", "/" + policy.container_name, "name")
    config = row.get("Config")
    host = row.get("HostConfig")
    network = row.get("NetworkSettings")
    state = row.get("State")
    if (
        not isinstance(config, dict)
        or not isinstance(host, dict)
        or not isinstance(network, dict)
        or not isinstance(state, dict)
    ):
        raise EngineDockerProxyError("Docker inspect lacks required configuration")
    for field, expected, label in (
        ("Image", policy.image_reference, "configured image"),
        ("User", policy.expected_user, "user"),
        ("Labels", dict(policy.required_labels), "labels"),
        ("Cmd", ["tail", "-f", "/dev/null"], "command"),
        ("AttachStderr", False, "stderr attachment"),
        ("AttachStdin", False, "stdin attachment"),
        ("AttachStdout", False, "stdout attachment"),
        ("NetworkDisabled", False, "network disabled state"),
        ("Tty", False, "terminal"),
        ("OpenStdin", False, "stdin"),
        ("StdinOnce", False, "one-shot stdin"),
    ):
        _expect_equal(config, field, expected, label)
    _expect_present_empty(config, "Env", "environment")
    tmpfs = {item.destination: item.options for item in policy.tmpfs}
    host_expectations: tuple[tuple[str, Any, str], ...] = (
        ("Privileged", False, "privileged mode"),
        ("ReadonlyRootfs", True, "root filesystem"),
        ("NetworkMode", policy.network_name, "network"),
        ("PublishAllPorts", False, "published ports"),
        ("Memory", policy.memory_bytes, "memory"),
        ("NanoCpus", policy.nano_cpus, "CPU"),
        ("PidsLimit", policy.pids_limit, "PID limit"),
        ("CgroupParent", policy.cgroup_parent, "cgroup"),
        ("CapAdd", list(policy.expected_capabilities), "capabilities"),
        ("CapDrop", ["ALL"], "dropped capabilities"),
        ("Tmpfs", tmpfs, "tmpfs"),
        ("AutoRemove", False, "automatic removal"),
        ("OomKillDisable", False, "OOM behavior"),
        (
            "RestartPolicy",
            {"MaximumRetryCount": 0, "Name": "no"},
            "restart policy",
        ),
        (
            "LogConfig",
            {"Config": {"max-file": "1", "max-size": "10m"}, "Type": "json-file"},
            "log policy",
        ),
        ("UsernsMode", "", "user namespace"),
    )
    for field, expected, label in host_expectations:
        _expect_equal(host, field, expected, label)
    for field in (
        "Binds",
        "Devices",
        "DeviceRequests",
        "ExtraHosts",
        "Links",
        "PortBindings",
        "VolumesFrom",
        "GroupAdd",
        "Dns",
        "DnsOptions",
        "DnsSearch",
    ):
        _expect_present_empty(host, field, field)
    if host.get("Mounts", []) not in (None, [], {}):
        raise EngineDockerProxyError("Docker inspect Mounts is not empty")
    if host.get("PidMode") != policy.expected_pid_mode:
        raise EngineDockerProxyError("Docker inspect PID namespace is not private")
    if host.get("IpcMode") != policy.expected_ipc_mode:
        raise EngineDockerProxyError("Docker inspect IPC namespace is not private")
    if host.get("UTSMode") != policy.expected_uts_mode:
        raise EngineDockerProxyError("Docker inspect UTS namespace is not private")
    if host.get("SecurityOpt") != ["no-new-privileges:true"]:
        raise EngineDockerProxyError("Docker inspect security options do not match")
    networks = network.get("Networks")
    if not isinstance(networks, dict) or set(networks) != {policy.network_name}:
        raise EngineDockerProxyError("Docker inspect network membership does not match")
    endpoint = networks[policy.network_name]
    if not isinstance(endpoint, dict) or endpoint.get("NetworkID") != policy.network_id:
        raise EngineDockerProxyError("Docker inspect network identity does not match")
    _expect_present_empty(network, "Ports", "network ports")
    if "Mounts" not in row:
        raise EngineDockerProxyError("Docker inspect mounts are missing")
    mounts = row["Mounts"]
    if not isinstance(mounts, list):
        raise EngineDockerProxyError("Docker inspect mounts are invalid")
    destinations: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, dict) or mount.get("Type") != "tmpfs":
            raise EngineDockerProxyError("Docker inspect includes a non-tmpfs mount")
        destination = mount.get("Destination")
        if destination not in tmpfs or mount.get("Source") not in (None, ""):
            raise EngineDockerProxyError("Docker inspect tmpfs does not match admission")
        destinations.add(destination)
    if len(destinations) != len(mounts) or destinations and destinations != set(tmpfs):
        raise EngineDockerProxyError("Docker inspect tmpfs set is incomplete")
    state_fields: tuple[tuple[str, type[Any]], ...] = (
        ("Status", str),
        ("Running", bool),
        ("Paused", bool),
        ("Restarting", bool),
        ("OOMKilled", bool),
        ("Dead", bool),
        ("Pid", int),
        ("ExitCode", int),
        ("Error", str),
    )
    for field, expected_type in state_fields:
        value = state.get(field)
        if not isinstance(value, expected_type) or expected_type is int and isinstance(value, bool):
            raise EngineDockerProxyError("Docker inspect lifecycle state is invalid")
    if pending_promotion:
        expected_state: tuple[tuple[str, Any], ...] = (
            ("Status", "created"),
            ("Running", False),
            ("Paused", False),
            ("Restarting", False),
            ("OOMKilled", False),
            ("Dead", False),
            ("Pid", 0),
            ("ExitCode", 0),
            ("Error", ""),
        )
        if any(state.get(field) != expected for field, expected in expected_state):
            raise EngineDockerProxyError("Docker pending container is not in its created state")


def _validate_multiplex_stream(body: bytes) -> None:
    offset = 0
    while offset < len(body):
        if len(body) - offset < 8:
            raise EngineDockerProxyError("Docker multiplex stream has a truncated header")
        stream_type = body[offset]
        if stream_type not in {1, 2} or body[offset + 1 : offset + 4] != b"\x00\x00\x00":
            raise EngineDockerProxyError("Docker multiplex stream header is invalid")
        size = struct.unpack(">I", body[offset + 4 : offset + 8])[0]
        offset += 8
        if size > len(body) - offset:
            raise EngineDockerProxyError("Docker multiplex stream frame is truncated")
        offset += size
    if offset != len(body):
        raise EngineDockerProxyError("Docker multiplex stream has trailing bytes")


def _validate_archive_stat(
    request: DockerApiRequest, encoded: str | None, policy: DockerApiPolicy
) -> None:
    if encoded is None or len(encoded) > 4096:
        raise EngineDockerProxyError("Docker archive stat header is missing or oversized")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EngineDockerProxyError("Docker archive stat header is invalid") from exc
    if len(raw) > 2048:
        raise EngineDockerProxyError("Docker archive stat header is oversized")
    stat = _canonical_json(raw, "Docker archive stat")
    if set(stat) != {"name", "size", "mode", "mtime", "linkTarget"}:
        raise EngineDockerProxyError("Docker archive stat fields do not match")
    query = dict(parse_qsl(request.target.partition("?")[2], keep_blank_values=True))
    path = query.get("path", "")
    if path != policy.exec_working_directory:
        raise EngineDockerProxyError(
            "Docker archive requires the exact admitted workspace mountpoint"
        )
    expected_name = path.rsplit("/", 1)[-1]
    name = stat.get("name")
    size = stat.get("size")
    mode = stat.get("mode")
    mtime = stat.get("mtime")
    link_target = stat.get("linkTarget")
    if (
        name != expected_name
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or isinstance(mode, bool)
        or not isinstance(mode, int)
        or not 0 <= mode <= 0xFFFFFFFF
        or mode & _GO_MODE_TYPE_MASK != _GO_MODE_DIRECTORY
        or not isinstance(mtime, str)
        or not 1 <= len(mtime) <= 64
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in mtime)
        or not isinstance(link_target, str)
        or link_target
    ):
        raise EngineDockerProxyError("Docker archive stat does not match the request")


def _candidate_discovery(
    decision: DockerApiDecision, response: _ParsedResponse
) -> tuple[str | None, tuple[str, str] | None]:
    if response.status_code != 201:
        return None, None
    try:
        row = _canonical_json(response.body, "Docker candidate response")
    except EngineDockerProxyError:
        return None, None
    resource_id = row.get("Id")
    if not isinstance(resource_id, str) or _RESOURCE_ID.fullmatch(resource_id) is None:
        return None, None
    if decision.response_contract is DockerResponseContract.REGISTER_PENDING_CONTAINER:
        return resource_id, None
    if (
        decision.response_contract is DockerResponseContract.REGISTER_EXEC
        and decision.owner_container_id is not None
    ):
        return None, (resource_id, decision.owner_container_id)
    return None, None


def _ownership(
    state: DockerProxyState,
    *,
    pending: tuple[str, ...] | None = None,
    containers: tuple[str, ...] | None = None,
    exec_bindings: tuple[tuple[str, str], ...] | None = None,
) -> DockerOwnership:
    return DockerOwnership.create(
        daemon_instance_digest=state.ownership.daemon_instance_digest,
        pending_container_ids=pending
        if pending is not None
        else state.ownership.pending_container_ids,
        container_ids=containers if containers is not None else state.ownership.container_ids,
        exec_bindings=exec_bindings if exec_bindings is not None else state.ownership.exec_bindings,
    )


def _validated_response(
    policy: DockerApiPolicy,
    request: DockerApiRequest,
    decision: DockerApiDecision,
    response: _ParsedResponse,
    state: DockerProxyState,
) -> _ValidatedResponse:
    contract = decision.response_contract
    api = policy.api_version.removeprefix("v")
    if (
        response.headers.get("api-version") != api
        or response.headers.get("docker-experimental") not in {"true", "false"}
        or response.headers.get("ostype") != "linux"
    ):
        raise EngineDockerProxyError("Docker common response headers do not match admission")
    ping_headers = {
        "builder-version",
        "cache-control",
        "pragma",
        "swarm",
    }
    present_ping_headers = ping_headers.intersection(response.headers)
    if present_ping_headers and contract is not DockerResponseContract.PING:
        raise EngineDockerProxyError("Docker response has ping-only headers")
    if (
        "x-docker-container-path-stat" in response.headers
        and contract is not DockerResponseContract.BOUNDED_ARCHIVE
    ):
        raise EngineDockerProxyError("Docker response has an operation-mismatched header")
    ownership = state.ownership
    if contract is DockerResponseContract.PING:
        if (
            response.headers.get("builder-version") not in {None, "1", "2"}
            or response.headers.get("cache-control") != "no-cache, no-store, must-revalidate"
            or response.headers.get("pragma") != "no-cache"
            or response.headers.get("content-type") != "text/plain; charset=utf-8"
            or response.headers.get("swarm")
            not in {None, "active", "error", "inactive", "locked", "pending"}
        ):
            raise EngineDockerProxyError("Docker ping headers do not match admission")
        if response.status_code != 200 or response.body not in (
            {b""} if request.method == "HEAD" else {b"OK"}
        ):
            raise EngineDockerProxyError("Docker ping response is invalid")
        reply = (
            DockerProxyReply.head(200, 2, content_type="text/plain")
            if request.method == "HEAD"
            else DockerProxyReply.create(200, response.body, content_type="text/plain")
        )
        return _ValidatedResponse(reply, ownership)
    if contract is DockerResponseContract.VERSION_REDACTED:
        row = _json_response(response, status=200)
        api = policy.api_version.removeprefix("v")
        if row.get("ApiVersion") != api or row.get("Os") != "linux":
            raise EngineDockerProxyError("Docker version does not match admission")
        body = _canonical_bytes({"ApiVersion": api, "Os": "linux"})
        return _ValidatedResponse(
            DockerProxyReply.create(200, body, content_type="application/json"), ownership
        )
    if contract is DockerResponseContract.INFO_REDACTED:
        row = _json_response(response, status=200)
        if not isinstance(row.get("ID"), str) or not row["ID"] or row.get("OSType") != "linux":
            raise EngineDockerProxyError("Docker info does not match admission")
        body = _canonical_bytes({"ID": "redacted", "OSType": "linux"})
        return _ValidatedResponse(
            DockerProxyReply.create(200, body, content_type="application/json"), ownership
        )
    if contract is DockerResponseContract.EXACT_IMAGE:
        row = _json_response(response, status=200)
        repo_digests = row.get("RepoDigests")
        if (
            row.get("Id") != policy.image_digest
            or not isinstance(repo_digests, list)
            or any(not isinstance(item, str) for item in repo_digests)
            or policy.image_reference not in repo_digests
        ):
            raise EngineDockerProxyError("Docker image inspection does not match admission")
        body = _canonical_bytes(
            {"Id": policy.image_digest, "RepoDigests": [policy.image_reference]}
        )
        return _ValidatedResponse(
            DockerProxyReply.create(200, body, content_type="application/json"), ownership
        )
    if contract is DockerResponseContract.REGISTER_PENDING_CONTAINER:
        row = _json_response(response, status=201)
        container_id = row.get("Id")
        if (
            not isinstance(container_id, str)
            or _RESOURCE_ID.fullmatch(container_id) is None
            or row.get("Warnings") not in (None, [])
            or set(row) - {"Id", "Warnings"}
        ):
            raise EngineDockerProxyError("Docker create response is invalid")
        pending = tuple(sorted((*ownership.pending_container_ids, container_id)))
        next_owner = _ownership(state, pending=pending)
        body = _canonical_bytes({"Id": container_id, "Warnings": []})
        return _ValidatedResponse(
            DockerProxyReply.create(201, body, content_type="application/json"),
            next_owner,
            discovered_container_id=container_id,
        )
    if contract in {
        DockerResponseContract.VERIFY_AND_REGISTER_CONTAINER,
        DockerResponseContract.OWNED_CONTAINER,
    }:
        row = _json_response(response, status=200)
        if decision.resource_id is None:
            raise EngineDockerProxyError("Docker inspect decision lacks an identity")
        _validate_container_inspect(
            row,
            policy,
            decision.resource_id,
            pending_promotion=(contract is DockerResponseContract.VERIFY_AND_REGISTER_CONTAINER),
        )
        next_owner = ownership
        if contract is DockerResponseContract.VERIFY_AND_REGISTER_CONTAINER:
            pending = tuple(
                item for item in ownership.pending_container_ids if item != decision.resource_id
            )
            containers = tuple(sorted((*ownership.container_ids, decision.resource_id)))
            next_owner = _ownership(state, pending=pending, containers=containers)
        body = _canonical_bytes(
            {
                "Id": decision.resource_id,
                "Image": policy.image_digest,
                "Name": "/" + policy.container_name,
            }
        )
        return _ValidatedResponse(
            DockerProxyReply.create(200, body, content_type="application/json"), next_owner
        )
    if contract is DockerResponseContract.REGISTER_EXEC:
        row = _json_response(response, status=201)
        exec_id = row.get("Id")
        if (
            not isinstance(exec_id, str)
            or _RESOURCE_ID.fullmatch(exec_id) is None
            or set(row) != {"Id"}
            or decision.owner_container_id is None
        ):
            raise EngineDockerProxyError("Docker exec creation response is invalid")
        bindings = tuple(sorted((*ownership.exec_bindings, (exec_id, decision.owner_container_id))))
        next_owner = _ownership(state, exec_bindings=bindings)
        body = _canonical_bytes({"Id": exec_id})
        return _ValidatedResponse(
            DockerProxyReply.create(201, body, content_type="application/json"),
            next_owner,
            discovered_exec=(exec_id, decision.owner_container_id),
        )
    if contract is DockerResponseContract.OWNED_EXEC:
        row = _json_response(response, status=200)
        if (
            row.get("ID") != decision.resource_id
            or row.get("ContainerID") != decision.owner_container_id
        ):
            raise EngineDockerProxyError("Docker exec inspection does not match ownership")
        if (
            not isinstance(row.get("Running"), bool)
            or isinstance(row.get("ExitCode"), bool)
            or not isinstance(row.get("ExitCode"), int)
        ):
            raise EngineDockerProxyError("Docker exec inspection state is invalid")
        body = _canonical_bytes(
            {
                "ContainerID": decision.owner_container_id,
                "ExitCode": row["ExitCode"],
                "ID": decision.resource_id,
                "Running": row["Running"],
            }
        )
        return _ValidatedResponse(
            DockerProxyReply.create(200, body, content_type="application/json"), ownership
        )
    if contract is DockerResponseContract.EMPTY:
        if response.status_code != 204 or response.body or "content-type" in response.headers:
            raise EngineDockerProxyError("Docker empty response contract is not satisfied")
        next_owner = ownership
        if decision.operation is DockerApiOperation.CONTAINER_DELETE and decision.resource_id:
            containers = tuple(
                item for item in ownership.container_ids if item != decision.resource_id
            )
            bindings = tuple(
                item for item in ownership.exec_bindings if item[1] != decision.resource_id
            )
            next_owner = _ownership(state, containers=containers, exec_bindings=bindings)
        return _ValidatedResponse(DockerProxyReply.create(204), next_owner)
    if contract is DockerResponseContract.BOUNDED_ARCHIVE:
        if (
            response.status_code != 200
            or response.headers.get("content-type") != "application/x-tar"
        ):
            raise EngineDockerProxyError("Docker archive response contract is not satisfied")
        _validate_archive_stat(
            request, response.headers.get("x-docker-container-path-stat"), policy
        )
        return _ValidatedResponse(
            DockerProxyReply.create(200, response.body, content_type="application/x-tar"), ownership
        )
    if contract in {
        DockerResponseContract.BOUNDED_LOG_STREAM,
        DockerResponseContract.BOUNDED_EXEC_STREAM,
    }:
        if (
            response.status_code != 200
            or response.headers.get("content-type") != "application/vnd.docker.raw-stream"
        ):
            raise EngineDockerProxyError("Docker stream response contract is not satisfied")
        _validate_multiplex_stream(response.body)
        return _ValidatedResponse(
            DockerProxyReply.create(
                200, response.body, content_type="application/vnd.docker.raw-stream"
            ),
            ownership,
        )
    raise EngineDockerProxyError("Docker response contract is unsupported")


class DockerPolicyProxy:
    """Single-attempt, single-flight effect-free Docker proxy core."""

    def __init__(
        self,
        *,
        policy: DockerApiPolicy,
        ownership: DockerOwnership,
        transport: DockerDaemonTransport,
        audit: DockerProxyAuditSink,
        monotonic_ns: Callable[[], int],
    ) -> None:
        if ownership.daemon_instance_digest != policy.daemon_instance_digest:
            raise EngineDockerProxyError("Docker proxy ownership binds another daemon")
        self._policy = policy
        self._transport = transport
        self._audit = audit
        self._monotonic_ns = monotonic_ns
        self._lock = threading.Lock()
        self._state = DockerProxyState.create(ownership)
        self._inflight: str | None = None
        self._sequence = 0

    def snapshot(self) -> DockerProxyState:
        with self._lock:
            return self._state

    def _now(self) -> int:
        value = self._monotonic_ns()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EngineDockerProxyError("Docker proxy clock is invalid")
        return value

    def _audit_record(
        self,
        *,
        request_ref: str,
        sequence: int,
        phase: str,
        outcome: str,
        operation: str,
        request_digest: str,
        response_digest: str | None,
        before: DockerProxyState,
        after: DockerProxyState,
        started: int,
        ended: int,
    ) -> DockerProxyAuditRecord:
        return DockerProxyAuditRecord(
            schema_version="bluefire.engine-docker-proxy-audit.v1",
            request_ref=request_ref,
            sequence=sequence,
            phase=phase,
            outcome=outcome,
            operation=operation,
            policy_digest=self._policy.policy_digest,
            request_digest=request_digest,
            response_digest=response_digest,
            state_before_digest=before.state_digest,
            state_after_digest=after.state_digest,
            started_monotonic_ns=started,
            ended_monotonic_ns=ended,
            reconciliation_required=after.reconciliation_required,
        )

    def _append_audit(self, record: DockerProxyAuditRecord) -> None:
        receipt = self._audit.append(record)
        _digest(receipt, "Docker proxy audit receipt")
        if receipt != content_hash(record.to_dict()):
            raise EngineDockerProxyError("Docker proxy audit receipt does not match")

    def _quarantine(
        self,
        before: DockerProxyState,
        validated: _ValidatedResponse | None,
        candidate_container_id: str | None,
        candidate_exec: tuple[str, str] | None,
    ) -> DockerProxyState:
        containers = set(before.quarantined_container_ids)
        execs = set(before.quarantined_exec_bindings)
        ownership = before.ownership
        discovered_container_id = (
            validated.discovered_container_id
            if validated is not None and validated.discovered_container_id is not None
            else candidate_container_id
        )
        discovered_exec = (
            validated.discovered_exec
            if validated is not None and validated.discovered_exec is not None
            else candidate_exec
        )
        if discovered_container_id is not None:
            containers.add(discovered_container_id)
            pending = tuple(sorted({*ownership.pending_container_ids, discovered_container_id}))
            ownership = _ownership(before, pending=pending)
        if discovered_exec is not None:
            execs.add(discovered_exec)
        return DockerProxyState(
            ownership=ownership,
            quarantined_container_ids=tuple(sorted(containers)),
            quarantined_exec_bindings=tuple(sorted(execs)),
            generation=before.generation + 1,
            reconciliation_required=True,
        )

    def _failure(self, *, timeout: bool = False, busy: bool = False) -> DockerProxyReply:
        if timeout:
            return DockerProxyReply.refused(status_code=504)
        if busy:
            return DockerProxyReply.refused(status_code=409)
        return DockerProxyReply.refused(status_code=503)

    def handle(self, raw_request: bytes, cancellation: DockerProxyCancellation) -> DockerProxyReply:
        request_digest = _sha256_bytes(raw_request if isinstance(raw_request, bytes) else b"")
        try:
            started = self._now()
        except Exception:
            return self._failure()
        with self._lock:
            if self._inflight is not None:
                return self._failure(busy=True)
            if self._state.reconciliation_required:
                return self._failure()
            self._sequence += 1
            sequence = self._sequence
            before = self._state
            request_ref = content_hash(
                {
                    "schema_version": "bluefire.engine-docker-proxy-request-ref.v1",
                    "policy_digest": self._policy.policy_digest,
                    "request_digest": request_digest,
                    "sequence": sequence,
                    "state_digest": before.state_digest,
                }
            )
            self._inflight = request_ref
        deadline = started + 60 * 1_000_000_000
        decision: DockerApiDecision | None = None
        validated: _ValidatedResponse | None = None
        candidate_container_id: str | None = None
        candidate_exec: tuple[str, str] | None = None
        response_digest: str | None = None
        operation = "unparsed"
        transport_entered = False
        try:
            if cancellation.is_cancelled():
                raise _ProxyRefusal("cancelled")
            request = parse_docker_http_request(raw_request)
            try:
                decision = authorize_docker_api_request(self._policy, request, before.ownership)
            except EngineDockerPolicyError as exc:
                raise _ProxyRefusal("policy_refused") from exc
            operation = decision.operation.value
            deadline = started + decision.deadline_seconds * 1_000_000_000
            if self._now() >= deadline or cancellation.is_cancelled():
                raise _ProxyRefusal("deadline_exceeded" if self._now() >= deadline else "cancelled")
            transport_entered = True
            exchange = self._transport.exchange(
                raw_request,
                deadline_monotonic_ns=deadline,
                cancellation=cancellation,
            )
            if exchange.request_digest != request_digest:
                raise EngineDockerProxyError("Docker transport response binds another request")
            if exchange.daemon_instance_digest != self._policy.daemon_instance_digest:
                raise EngineDockerProxyError("Docker daemon identity changed during exchange")
            response_digest = _sha256_bytes(exchange.raw_response)
            response = _parse_docker_http_response(
                exchange.raw_response,
                limit=decision.response_byte_limit,
                head_response=request.method == "HEAD",
            )
            candidate_container_id, candidate_exec = _candidate_discovery(decision, response)
            validated = _validated_response(self._policy, request, decision, response, before)
            if self._now() >= deadline or cancellation.is_cancelled():
                raise _ProxyRefusal("deadline_exceeded" if self._now() >= deadline else "cancelled")
            proposed = DockerProxyState(
                ownership=validated.next_ownership,
                quarantined_container_ids=before.quarantined_container_ids,
                quarantined_exec_bindings=before.quarantined_exec_bindings,
                generation=before.generation + 1,
                reconciliation_required=False,
            )
            try:
                self._append_audit(
                    self._audit_record(
                        request_ref=request_ref,
                        sequence=sequence,
                        phase="validated",
                        outcome="accepted",
                        operation=operation,
                        request_digest=request_digest,
                        response_digest=response_digest,
                        before=before,
                        after=proposed,
                        started=started,
                        ended=self._now(),
                    )
                )
            except Exception as exc:
                raise _ProxyRefusal("audit_failed") from exc
            if self._now() >= deadline or cancellation.is_cancelled():
                raise _ProxyRefusal("deadline_exceeded" if self._now() >= deadline else "cancelled")
            with self._lock:
                if self._inflight != request_ref or self._state.state_digest != before.state_digest:
                    raise EngineDockerProxyError("Docker proxy state changed during publication")
                self._state = proposed
            try:
                self._append_audit(
                    self._audit_record(
                        request_ref=request_ref,
                        sequence=sequence,
                        phase="published",
                        outcome="accepted",
                        operation=operation,
                        request_digest=request_digest,
                        response_digest=response_digest,
                        before=before,
                        after=proposed,
                        started=started,
                        ended=self._now(),
                    )
                )
            except Exception as exc:
                with self._lock:
                    self._state = replace(
                        self._state,
                        generation=self._state.generation + 1,
                        reconciliation_required=True,
                    )
                raise _ProxyRefusal("audit_failed") from exc
            if self._now() >= deadline or cancellation.is_cancelled():
                with self._lock:
                    self._state = replace(
                        self._state,
                        generation=self._state.generation + 1,
                        reconciliation_required=True,
                    )
                raise _ProxyRefusal("deadline_exceeded" if self._now() >= deadline else "cancelled")
            return validated.reply
        except _ProxyRefusal as exc:
            reason = exc.reason
            with self._lock:
                current = self._state
                if transport_entered and current.state_digest == before.state_digest:
                    self._state = self._quarantine(
                        before, validated, candidate_container_id, candidate_exec
                    )
                    current = self._state
            try:
                self._append_audit(
                    self._audit_record(
                        request_ref=request_ref,
                        sequence=sequence,
                        phase="suppressed" if transport_entered else "refused",
                        outcome=reason,
                        operation=operation,
                        request_digest=request_digest,
                        response_digest=response_digest,
                        before=before,
                        after=current,
                        started=started,
                        ended=max(started, self._now()),
                    )
                )
            except Exception:
                if transport_entered:
                    with self._lock:
                        self._state = replace(
                            self._state,
                            generation=self._state.generation + 1,
                            reconciliation_required=True,
                        )
            return self._failure(timeout=reason == "deadline_exceeded")
        except Exception:
            with self._lock:
                current = self._state
                if transport_entered and current.state_digest == before.state_digest:
                    self._state = self._quarantine(
                        before, validated, candidate_container_id, candidate_exec
                    )
            try:
                current = self.snapshot()
                self._append_audit(
                    self._audit_record(
                        request_ref=request_ref,
                        sequence=sequence,
                        phase="suppressed" if transport_entered else "refused",
                        outcome="response_refused"
                        if response_digest is not None
                        else ("transport_failed" if transport_entered else "protocol_refused"),
                        operation=operation,
                        request_digest=request_digest,
                        response_digest=response_digest,
                        before=before,
                        after=current,
                        started=started,
                        ended=max(started, self._now()),
                    )
                )
            except Exception:
                if transport_entered:
                    with self._lock:
                        self._state = replace(
                            self._state,
                            generation=self._state.generation + 1,
                            reconciliation_required=True,
                        )
            return self._failure()
        finally:
            with self._lock:
                if self._inflight == request_ref:
                    self._inflight = None


class _ProxyRefusal(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


__all__ = [
    "DockerDaemonExchange",
    "DockerDaemonTransport",
    "DockerPolicyProxy",
    "DockerProxyAuditRecord",
    "DockerProxyAuditSink",
    "DockerProxyCancellation",
    "DockerProxyReply",
    "DockerProxyState",
    "EngineDockerProxyError",
    "parse_docker_http_request",
]
