"""Docker policy proxy wire contracts, framing, and response validation.

This execution-layer module is effect free. It parses complete bounded Docker
HTTP messages and validates policy-specific replies; daemon custody and state
publication remain in :mod:`bluefire.engine_docker_proxy`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import parse_qsl

from .engine_docker_control import (
    DockerApiDecision,
    DockerApiPolicyV2,
    DockerApiRequest,
    DockerOwnership,
    DockerPolicy,
    DockerResponseContract,
    EngineDockerPolicyError,
)
from .util import json_clone


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
    next_v2_exec_bindings: tuple[object, ...] | None = None


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


def _same_json_value_v2(actual: Any, expected: Any) -> bool:
    """Compare V2 inspect values recursively without Python's bool/int equality."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _same_json_value_v2(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_json_value_v2(observed, value)
            for observed, value in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _expect_equal_v2(mapping: Mapping[str, Any], field: str, expected: Any, label: str) -> None:
    if field not in mapping or not _same_json_value_v2(mapping[field], expected):
        raise EngineDockerProxyError(f"Docker inspect {label} does not match admission")


def _expect_present_empty(mapping: Mapping[str, Any], field: str, label: str) -> None:
    if field not in mapping or mapping[field] not in (None, [], {}):
        raise EngineDockerProxyError(f"Docker inspect {label} is not empty")


def _image_config_digest(policy: DockerPolicy) -> str:
    if isinstance(policy, DockerApiPolicyV2):
        return policy.image_config_digest
    return policy.image_digest


def _validate_container_inspect(
    row: Mapping[str, Any],
    policy: DockerPolicy,
    container_id: str,
    *,
    pending_promotion: bool,
) -> None:
    _expect_equal(row, "Id", container_id, "identity")
    _expect_equal(row, "Image", _image_config_digest(policy), "image")
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
    is_v2 = isinstance(policy, DockerApiPolicyV2)
    expect_equal = _expect_equal_v2 if is_v2 else _expect_equal
    if isinstance(policy, DockerApiPolicyV2):
        profile = policy.image_runtime_profile
    else:
        profile = None
    command = profile["command"] if profile is not None else ["tail", "-f", "/dev/null"]
    config_expectations: tuple[tuple[str, Any, str], ...] = (
        ("Image", policy.image_reference, "configured image"),
        ("User", policy.expected_user, "user"),
        ("Labels", dict(policy.required_labels), "labels"),
        ("Cmd", command, "command"),
        ("AttachStderr", False, "stderr attachment"),
        ("AttachStdin", False, "stdin attachment"),
        ("AttachStdout", False, "stdout attachment"),
        ("NetworkDisabled", False, "network disabled state"),
        ("Tty", False, "terminal"),
        ("OpenStdin", False, "stdin"),
        ("StdinOnce", False, "one-shot stdin"),
    )
    if profile is not None:
        config_expectations += (
            ("Entrypoint", profile["entrypoint"], "entrypoint"),
            ("WorkingDir", profile["working_directory"], "working directory"),
        )
    for field, expected, label in config_expectations:
        expect_equal(config, field, expected, label)
    if profile is not None:
        environment = profile["environment"]
        expect_equal(
            config,
            "Env",
            [f"{key}={environment[key]}" for key in sorted(environment)],
            "environment",
        )
    else:
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
    if isinstance(policy, DockerApiPolicyV2):
        host_expectations += (("MemorySwap", policy.memory_swap_bytes, "memory swap"),)
    for field, expected, label in host_expectations:
        expect_equal(host, field, expected, label)
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
        if is_v2:
            if mount.get("RW") is not True:
                raise EngineDockerProxyError("Docker inspect tmpfs is not writable")
            if mount.get("Mode") not in (None, "", tmpfs[destination]):
                raise EngineDockerProxyError("Docker inspect tmpfs mode contradicts admission")
            if mount.get("Propagation") not in (None, "", "rprivate"):
                raise EngineDockerProxyError("Docker inspect tmpfs propagation is not private")
        destinations.add(destination)
    if is_v2:
        if len(destinations) != len(mounts) or destinations != set(tmpfs):
            raise EngineDockerProxyError("Docker inspect tmpfs set is incomplete")
    elif len(destinations) != len(mounts) or destinations and destinations != set(tmpfs):
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
    request: DockerApiRequest, encoded: str | None, policy: DockerPolicy
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


__all__ = [
    "DockerProxyReply",
    "EngineDockerProxyError",
    "parse_docker_http_request",
]
