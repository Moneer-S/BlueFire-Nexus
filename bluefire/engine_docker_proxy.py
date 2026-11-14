"""Effect-free protocol core for one controller-owned Docker policy proxy.

The core opens no socket and contacts no daemon.  It accepts one complete
HTTP/1.1 request as bytes, asks an injected transport to exchange those exact
bytes with the already-admitted daemon, validates the complete response, and
publishes only a bounded redacted reply.  Request authorization and resource
ownership come from :mod:`bluefire.engine_docker_control`.

The controller transport normalizes an admitted Docker exec attachment into a
bounded HTTP 200 multiplex response before this effect-free core validates it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
from contextlib import nullcontext
from dataclasses import dataclass, replace
from functools import partial
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qsl

from .engine_docker_attached_stream import (
    MAX_DOCKER_STREAM_OVERHEAD_BYTES,
    DockerAttachedStreamError,
    decode_docker_multiplex_stream,
)
from .engine_docker_control import (
    DockerApiDecision,
    DockerApiOperation,
    DockerApiPolicyV2,
    DockerApiRequest,
    DockerOwnership,
    DockerPolicy,
    DockerResponseContract,
    EngineDockerPolicyError,
    authorize_docker_api_request,
)
from .engine_docker_exec_admission import DockerExecAdmissionV2, DockerExecBindingV2
from .engine_docker_exec_cancellation import (
    DockerExecCancellationLaneV2,
    DockerExecCancellationReceiptV2,
)
from .engine_docker_exec_dispatch import DockerExecDispatchRuntimeV2, DockerExecSendGateV2
from .engine_docker_exec_lifecycle import (
    DockerExecDispatchGate,
    DockerProxyAuditRecord,
    DockerProxyState,
    EngineDockerProxyError,
    _digest,
    _ownership,
    _safe_text,
    _same_json_value_v2,
    complete_v2_exec,
    exec_failure_outcome,
    exec_watch_outcome,
    make_proxy_audit_record,
    proxy_failure_status,
    quarantine_admission,
    quarantine_exchange,
    register_v2_exec,
    require_exec_custody,
    require_operation_live,
    start_v2_exec,
    transition_custody,
)
from .engine_docker_exec_lifecycle import (
    DockerProxyRefusal as _ProxyRefusal,
)
from .engine_docker_exec_signals import read_monotonic_anchor_ns, read_monotonic_ns
from .util import content_hash, json_clone

_METHOD = re.compile(rb"(?:DELETE|GET|HEAD|POST)")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_RESOURCE_ID = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_LIMIT = 128 * 1024
_HEADER_LIMIT = 32 * 1024
_GO_MODE_DIRECTORY = 0x80000000
_GO_MODE_TYPE_MASK = 0x8F280000
_ALLOWED_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "host",
        "upgrade",
        "user-agent",
    }
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


@dataclass(frozen=True, slots=True)
class DockerV2EffectiveNetworkBinding:
    """Controller context for one observed placement, not network reachability."""

    attempt_id: str
    claim_ref: str
    controller_fence: str
    network_policy_digest: str
    target_plan_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, str) or not self.attempt_id:
            raise EngineDockerProxyError("Docker network receipt attempt is invalid")
        for name in (
            "claim_ref",
            "controller_fence",
            "network_policy_digest",
            "target_plan_digest",
        ):
            _digest(getattr(self, name), f"Docker network receipt {name}")


@dataclass(frozen=True, slots=True)
class DockerV2EffectiveNetworkReceipt:
    """A published Docker inspect observed exactly one admitted attachment."""

    attempt_id: str
    claim_ref: str
    controller_fence: str
    network_policy_digest: str
    target_plan_digest: str
    container_id: str
    observed_network_id: str
    observed_network_name: str
    disallowed_networks_absent: bool
    inspect_response_digest: str
    published_audit_ref: str
    state_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.attempt_id, str)
            or not self.attempt_id
            or not isinstance(self.observed_network_name, str)
            or not self.observed_network_name
            or _RESOURCE_ID.fullmatch(self.container_id) is None
            or _RESOURCE_ID.fullmatch(self.observed_network_id) is None
            or self.disallowed_networks_absent is not True
        ):
            raise EngineDockerProxyError("Docker effective network receipt is invalid")
        for name in (
            "claim_ref",
            "controller_fence",
            "network_policy_digest",
            "target_plan_digest",
            "inspect_response_digest",
            "published_audit_ref",
            "state_digest",
        ):
            _digest(getattr(self, name), f"Docker effective network {name}")

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "schema_version": "bluefire.engine-docker-effective-network-receipt.v2",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }

    @property
    def receipt_ref(self) -> str:
        return content_hash(self.to_dict())

    def require(
        self,
        *,
        binding: DockerV2EffectiveNetworkBinding,
        policy: DockerApiPolicyV2,
        state: DockerProxyState,
    ) -> None:
        if (
            type(binding) is not DockerV2EffectiveNetworkBinding
            or type(policy) is not DockerApiPolicyV2
            or type(state) is not DockerProxyState
            or any(
                getattr(self, name) != getattr(binding, name)
                for name in binding.__dataclass_fields__
            )
            or self.attempt_id != policy.attempt_id
            or self.network_policy_digest != policy.network_policy_digest
            or self.observed_network_id != policy.network_id
            or self.observed_network_name != policy.network_name
            or self.container_id not in state.ownership.container_ids
            or self.state_digest != state.state_digest
            or state.reconciliation_required
        ):
            raise EngineDockerProxyError("Docker effective network receipt is not current")


class DockerDaemonTransport(Protocol):
    """Bound receiving before buffering; closing exec I/O does not prove exit.

    Any deadline, cancellation, receive cap or uncertain exchange must raise.
    V2 custody then quarantines the entire owned container for teardown and
    reconciliation; a transport must never retry an effectful Docker request.
    """

    def exchange(
        self,
        raw_request: bytes,
        *,
        deadline_monotonic_ns: int,
        response_byte_limit: int,
        cancellation: DockerProxyCancellation,
        dispatch_gate: DockerExecDispatchGate | None = None,
    ) -> DockerDaemonExchange: ...


class DockerProxyAuditSink(Protocol):
    def append(self, record: DockerProxyAuditRecord) -> str: ...


class DockerProxyCustody(Protocol):
    """Controller persistence of intent and full state, never new authority."""

    def prepare(
        self,
        *,
        request_ref: str,
        sequence: int,
        operation: str,
        request_digest: str,
        policy_digest: str,
        state: DockerProxyState,
    ) -> None: ...

    def retain(self, record: DockerProxyAuditRecord, state: DockerProxyState) -> None: ...

    def reopen(self) -> DockerProxyRestoredCustody: ...


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


class DockerProxyRestoredCustody(Protocol):
    """One durable recovery view; evidence, never fresh execution authority."""

    attempt_id: str
    policy_digest: str
    daemon_instance_digest: str
    state: DockerProxyState
    sequence: int
    journal_digest: str
    audits: tuple[DockerProxyAuditRecord, ...]


@dataclass(frozen=True, slots=True)
class _ValidatedResponse:
    reply: DockerProxyReply
    next_ownership: DockerOwnership
    discovered_container_id: str | None = None
    discovered_exec: tuple[str, str] | None = None
    next_v2_exec_bindings: tuple[DockerExecBindingV2, ...] | None = None


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
    connection = values.get("connection")
    upgrade = values.get("upgrade")
    if connection is not None or upgrade is not None:
        if (
            method != "POST"
            or re.fullmatch(r"/v1\.[0-9]+/exec/[0-9a-f]{64}/start", target) is None
            or connection is None
            or connection.lower() != "upgrade"
            or upgrade is None
            or upgrade.lower() != "tcp"
        ):
            raise EngineDockerProxyError("Docker request upgrade is not permitted")
    if values.get("host") != "docker":
        raise EngineDockerProxyError("Docker request host is invalid")
    if values.get("accept-encoding") not in {None, "gzip, deflate"}:
        raise EngineDockerProxyError("Docker request encoding is not permitted")
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


def _validate_multiplex_stream(body: bytes, *, decoded_limit: int) -> None:
    try:
        decode_docker_multiplex_stream(
            body,
            decoded_limit=decoded_limit,
            overhead_limit=MAX_DOCKER_STREAM_OVERHEAD_BYTES,
        )
    except DockerAttachedStreamError as exc:
        raise EngineDockerProxyError(
            "Docker multiplex stream is invalid or outside its bound"
        ) from exc


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


def _validated_response(
    policy: DockerPolicy,
    request: DockerApiRequest,
    decision: DockerApiDecision,
    response: _ParsedResponse,
    state: DockerProxyState,
    exec_admission: DockerExecAdmissionV2 | None = None,
    exec_deadline_monotonic_ns: int | None = None,
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
            row.get("Id") != _image_config_digest(policy)
            or not isinstance(repo_digests, list)
            or any(not isinstance(item, str) for item in repo_digests)
            or policy.image_reference not in repo_digests
        ):
            raise EngineDockerProxyError("Docker image inspection does not match admission")
        body = _canonical_bytes(
            {"Id": _image_config_digest(policy), "RepoDigests": [policy.image_reference]}
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
                "Image": _image_config_digest(policy),
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
        v2_bindings = state.v2_exec_bindings
        if isinstance(policy, DockerApiPolicyV2):
            if exec_admission is None:
                raise EngineDockerProxyError("Docker V2 exec response lacks admission")
            v2_bindings = register_v2_exec(
                state, exec_id, exec_admission, exec_deadline_monotonic_ns
            )
        body = _canonical_bytes({"Id": exec_id})
        return _ValidatedResponse(
            DockerProxyReply.create(201, body, content_type="application/json"),
            next_owner,
            discovered_exec=(exec_id, decision.owner_container_id),
            next_v2_exec_bindings=v2_bindings,
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
        v2_bindings = state.v2_exec_bindings
        if isinstance(policy, DockerApiPolicyV2):
            v2_bindings = complete_v2_exec(
                state, decision.resource_id, exec_admission, row, policy.expected_user
            )
        body = _canonical_bytes(
            {
                "ContainerID": decision.owner_container_id,
                "ExitCode": row["ExitCode"],
                "ID": decision.resource_id,
                "Running": row["Running"],
            }
        )
        return _ValidatedResponse(
            DockerProxyReply.create(200, body, content_type="application/json"),
            ownership,
            next_v2_exec_bindings=v2_bindings,
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
        return _ValidatedResponse(
            DockerProxyReply.create(204),
            next_owner,
            next_v2_exec_bindings=tuple(
                item
                for item in state.v2_exec_bindings
                if item.admission.container_id in next_owner.container_ids
            ),
        )
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
        expected_stream_type = (
            "application/vnd.docker.multiplexed-stream"
            if contract is DockerResponseContract.BOUNDED_EXEC_STREAM
            else "application/vnd.docker.raw-stream"
        )
        if (
            response.status_code != 200
            or response.headers.get("content-type") != expected_stream_type
        ):
            raise EngineDockerProxyError("Docker stream response contract is not satisfied")
        _validate_multiplex_stream(response.body, decoded_limit=decision.response_byte_limit)
        v2_bindings = state.v2_exec_bindings
        if (
            isinstance(policy, DockerApiPolicyV2)
            and contract is DockerResponseContract.BOUNDED_EXEC_STREAM
        ):
            v2_bindings = start_v2_exec(state, decision.resource_id)
        return _ValidatedResponse(
            DockerProxyReply.create(200, response.body, content_type=expected_stream_type),
            ownership,
            next_v2_exec_bindings=v2_bindings,
        )
    raise EngineDockerProxyError("Docker response contract is unsupported")


class DockerPolicyProxy:
    """Single-attempt, single-flight effect-free Docker proxy core."""

    def __init__(
        self,
        *,
        policy: DockerPolicy,
        ownership: DockerOwnership,
        transport: DockerDaemonTransport,
        audit: DockerProxyAuditSink,
        monotonic_ns: Callable[[], int],
        custody: DockerProxyCustody | None = None,
        restore_from_custody: bool = False,
        exec_runtime: DockerExecDispatchRuntimeV2 | None = None,
        exec_cancellation: DockerExecCancellationLaneV2 | None = None,
        effective_network_binding: DockerV2EffectiveNetworkBinding | None = None,
    ) -> None:
        if ownership.daemon_instance_digest != policy.daemon_instance_digest:
            raise EngineDockerProxyError("Docker proxy ownership binds another daemon")
        self._policy = policy
        self._transport = transport
        self._audit = audit
        self._custody = custody
        self._audit_record = partial(make_proxy_audit_record, policy_digest=policy.policy_digest)
        self._monotonic_ns = monotonic_ns
        self._exec_runtime, self._exec_cancellation = exec_runtime, exec_cancellation
        if effective_network_binding is not None and (
            type(effective_network_binding) is not DockerV2EffectiveNetworkBinding
            or type(policy) is not DockerApiPolicyV2
            or effective_network_binding.attempt_id != policy.attempt_id
            or effective_network_binding.network_policy_digest != policy.network_policy_digest
            or custody is None
            or audit is not custody
        ):
            raise EngineDockerProxyError("Docker effective network custody or binding differs")
        self._effective_network_binding = effective_network_binding
        self._effective_network_receipt: DockerV2EffectiveNetworkReceipt | None = None
        self._lock = threading.Lock()
        if not isinstance(restore_from_custody, bool):
            raise EngineDockerProxyError("Docker proxy recovery choice is invalid")
        if custody is None:
            if restore_from_custody:
                raise EngineDockerProxyError("Docker proxy durable custody is unavailable")
            restored_state = DockerProxyState.create(ownership)
            restored_sequence = 0
        else:
            try:
                restored_custody = custody.reopen()
                restored_state = restored_custody.state
                restored_sequence = restored_custody.sequence
                _digest(restored_custody.journal_digest, "Docker proxy custody journal")
            except Exception as exc:
                raise EngineDockerProxyError("Docker proxy durable custody is unavailable") from exc
            if (
                restored_custody.attempt_id != policy.attempt_id
                or restored_custody.policy_digest != policy.policy_digest
                or restored_custody.daemon_instance_digest != policy.daemon_instance_digest
                or not isinstance(restored_state, DockerProxyState)
                or restored_state.ownership != ownership
            ):
                raise EngineDockerProxyError(
                    "Docker proxy restored custody does not match ownership"
                )
            if not restore_from_custody and (
                restored_sequence != 0 or restored_state != DockerProxyState.create(ownership)
            ):
                raise EngineDockerProxyError("Docker proxy durable custody is not pristine")
        if (
            isinstance(restored_sequence, bool)
            or not isinstance(restored_sequence, int)
            or restored_sequence < 0
        ):
            raise EngineDockerProxyError("Docker proxy restored sequence is invalid")
        self._state = restored_state
        self._inflight: str | None = None
        self._sequence = restored_sequence
        # V2 requires a successful, audited image inspect immediately before
        # create. The single-flight proxy consumes this one-use proof on the
        # next request; no v1 state or digest changes.
        self._v2_image_verified_for_create = False

    def snapshot(self) -> DockerProxyState:
        with self._lock:
            return self._state

    def effective_network_receipt(self) -> DockerV2EffectiveNetworkReceipt | None:
        """Return only a currently owned, published V2 inspect observation."""

        with self._lock:
            receipt = self._effective_network_receipt
            state = self._state
        binding = self._effective_network_binding
        custody = self._custody
        if (
            receipt is None
            or binding is None
            or custody is None
            or type(self._policy) is not DockerApiPolicyV2
        ):
            return None
        try:
            receipt.require(binding=binding, policy=self._policy, state=state)
            restored = custody.reopen()
            if (
                restored.state != state
                or not restored.audits
                or content_hash(restored.audits[-1].to_dict()) != receipt.published_audit_ref
            ):
                return None
        except Exception:
            return None
        return receipt

    def _issue_effective_network_receipt(
        self,
        *,
        response: _ParsedResponse,
        record: DockerProxyAuditRecord,
        state: DockerProxyState,
        container_id: str,
    ) -> DockerV2EffectiveNetworkReceipt:
        binding = self._effective_network_binding
        policy = self._policy
        if (
            binding is None
            or type(policy) is not DockerApiPolicyV2
            or self._custody is None
            or record.phase != "published"
            or record.outcome != "accepted"
            or record.operation != DockerApiOperation.CONTAINER_INSPECT.value
            or record.response_digest is None
            or record.state_after_digest != state.state_digest
            or record.reconciliation_required
            or container_id not in state.ownership.container_ids
        ):
            raise EngineDockerProxyError("Docker network receipt lacks published inspection")
        restored = self._custody.reopen()
        if (
            restored.attempt_id != policy.attempt_id
            or restored.policy_digest != policy.policy_digest
            or restored.state != state
            or not restored.audits
            or restored.audits[-1] != record
        ):
            raise EngineDockerProxyError("Docker network inspection is not durably published")
        row = _json_response(response, status=200)
        network_settings = row.get("NetworkSettings")
        networks = network_settings.get("Networks") if isinstance(network_settings, dict) else None
        if (
            row.get("Id") != container_id
            or not isinstance(networks, dict)
            or set(networks) != {policy.network_name}
            or not isinstance(networks[policy.network_name], dict)
            or networks[policy.network_name].get("NetworkID") != policy.network_id
        ):
            raise EngineDockerProxyError("Docker inspected network differs from admission")
        receipt = DockerV2EffectiveNetworkReceipt(
            attempt_id=policy.attempt_id,
            claim_ref=binding.claim_ref,
            controller_fence=binding.controller_fence,
            network_policy_digest=policy.network_policy_digest,
            target_plan_digest=binding.target_plan_digest,
            container_id=container_id,
            observed_network_id=networks[policy.network_name]["NetworkID"],
            observed_network_name=policy.network_name,
            disallowed_networks_absent=True,
            inspect_response_digest=record.response_digest,
            published_audit_ref=content_hash(record.to_dict()),
            state_digest=state.state_digest,
        )
        receipt.require(binding=binding, policy=policy, state=state)
        return receipt

    def _now(self) -> int:
        return read_monotonic_ns(self._monotonic_ns)

    def _append_audit(self, record: DockerProxyAuditRecord, state: DockerProxyState) -> None:
        if record.state_after_digest != state.state_digest:
            raise EngineDockerProxyError("Docker proxy audit custody does not match")
        if self._custody is not None:
            self._custody.retain(record, state)
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
        decision: DockerApiDecision | None = None,
        known_binding: DockerExecBindingV2 | None = None,
    ) -> DockerProxyState:
        return quarantine_exchange(
            before,
            validated,
            candidate_container_id,
            candidate_exec,
            decision,
            known_binding,
            v2=isinstance(self._policy, DockerApiPolicyV2),
        )

    def _failure(self, *, timeout: bool = False, busy: bool = False) -> DockerProxyReply:
        return DockerProxyReply.refused(
            status_code=proxy_failure_status(timeout=timeout, busy=busy)
        )

    def _retain_exec_uncertainty(self, admission: DockerExecAdmissionV2) -> None:
        with self._lock:
            if admission.policy_digest != self._policy.policy_digest:
                raise EngineDockerProxyError("exec cancellation does not own this container")
            self._state = quarantine_admission(self._state, admission)
        if self._exec_runtime is not None:
            try:
                self._exec_runtime.mark_uncertain(admission)
            except Exception:
                pass  # Local reconciliation stays mandatory even if persistence failed.

    def _fence_exec(self, admission: DockerExecAdmissionV2) -> None:
        self._retain_exec_uncertainty(admission)

    def cancel_exec(
        self, admission: DockerExecAdmissionV2, *, reason: str = "uncertain_exchange"
    ) -> DockerExecCancellationReceiptV2:
        """Independent custody lane; never wait for the blocked attach lock."""
        self._retain_exec_uncertainty(admission)
        if self._exec_cancellation is None:
            raise EngineDockerProxyError("exec cancellation custody lane is unavailable")
        require_exec_custody(self._policy, self._exec_runtime, self._exec_cancellation)
        return self._exec_cancellation.cancel(admission, reason=reason)

    def handle(
        self,
        raw_request: bytes,
        cancellation: DockerProxyCancellation,
        *,
        exec_admission: DockerExecAdmissionV2 | None = None,
    ) -> DockerProxyReply:
        request_digest = _sha256_bytes(raw_request if isinstance(raw_request, bytes) else b"")
        if exec_admission is not None and type(exec_admission) is not DockerExecAdmissionV2:
            return self._failure()
        try:
            started = read_monotonic_anchor_ns(self._monotonic_ns)
        except Exception:
            if exec_admission is not None:
                with self._lock:
                    known = next(
                        (
                            item
                            for item in self._state.v2_exec_bindings
                            if item.admission.admission_digest == exec_admission.admission_digest
                        ),
                        None,
                    )
                    if known is not None:
                        self._state = self._quarantine(
                            self._state, None, None, None, known_binding=known
                        )
                if known is not None:
                    try:
                        self.cancel_exec(exec_admission, reason="clock_failed")
                    except Exception:
                        pass
            return self._failure()
        with self._lock:
            if self._inflight is not None:
                return self._failure(busy=True)
            if self._state.reconciliation_required:
                return self._failure()
            self._sequence += 1
            sequence = self._sequence
            before = self._state
            image_was_verified_for_create = self._v2_image_verified_for_create
            self._v2_image_verified_for_create = False
            request_ref_identity = {
                "schema_version": "bluefire.engine-docker-proxy-request-ref.v1",
                "policy_digest": self._policy.policy_digest,
                "request_digest": request_digest,
                "sequence": sequence,
                "state_digest": before.state_digest,
            }
            if isinstance(self._policy, DockerApiPolicyV2):
                request_ref_identity["schema_version"] = (
                    "bluefire.engine-docker-proxy-request-ref.v2"
                )
                request_ref_identity["image_inspect_verified_for_create"] = (
                    image_was_verified_for_create
                )
                request_ref_identity["exec_admission_digest"] = (
                    exec_admission.admission_digest if exec_admission is not None else None
                )
            request_ref = content_hash(request_ref_identity)
            self._inflight = request_ref
        deadline = started + 60 * 1_000_000_000
        decision: DockerApiDecision | None = None
        validated: _ValidatedResponse | None = None
        candidate_container_id: str | None = None
        candidate_exec: tuple[str, str] | None = None
        response_digest: str | None = None
        operation = "unparsed"
        transport_entered = False
        binding: DockerExecBindingV2 | None = None
        exec_deadline: int | None = None
        dispatch_gate: DockerExecSendGateV2 | None = None
        try:
            request = parse_docker_http_request(raw_request)
            binding = next(
                (
                    item
                    for item in before.v2_exec_bindings
                    if f"/exec/{item.exec_id}/" in request.target
                ),
                None,
            )
            try:
                decision = authorize_docker_api_request(
                    self._policy,
                    request,
                    before.ownership,
                    exec_admission=exec_admission,
                    exec_binding=binding,
                )
            except EngineDockerPolicyError as exc:
                raise _ProxyRefusal("policy_refused") from exc
            operation = decision.operation.value
            if (
                isinstance(self._policy, DockerApiPolicyV2)
                and decision.operation is DockerApiOperation.CONTAINER_EXEC_CREATE
            ):
                if (
                    exec_admission is None
                    or len(before.v2_exec_operation_ids) >= 1024
                    or exec_admission.request.operation_id in before.v2_exec_operation_ids
                    or any(item.phase != "complete" for item in before.v2_exec_bindings)
                ):
                    raise _ProxyRefusal("exec_operation_replayed_or_unsettled")

            if (
                isinstance(self._policy, DockerApiPolicyV2)
                and decision.operation is DockerApiOperation.CONTAINER_CREATE
                and not image_was_verified_for_create
            ):
                raise _ProxyRefusal("image_inspect_required")
            deadline = started + int(decision.deadline_seconds * 1_000_000_000)
            if isinstance(self._policy, DockerApiPolicyV2) and decision.operation in {
                DockerApiOperation.CONTAINER_EXEC_CREATE,
                DockerApiOperation.EXEC_START,
                DockerApiOperation.EXEC_INSPECT,
            }:
                if (
                    decision.operation is DockerApiOperation.CONTAINER_EXEC_CREATE
                    and exec_admission is not None
                ):
                    exec_deadline = started + int(
                        exec_admission.request.timeout_seconds * 1_000_000_000
                    )
                elif binding is not None:
                    exec_deadline = binding.deadline_monotonic_ns
                if exec_deadline is None:
                    raise _ProxyRefusal("exec_deadline_unavailable")
                deadline = min(deadline, exec_deadline)
            require_operation_live(cancellation, self._monotonic_ns, deadline)
            if (
                exec_deadline is not None
                and exec_admission is not None
                and isinstance(self._policy, DockerApiPolicyV2)
            ):
                if self._exec_runtime is None or self._exec_cancellation is None:
                    raise _ProxyRefusal("exec_runtime_unavailable")
                if self._exec_runtime.continuous_custody is None:
                    raise _ProxyRefusal("exec_custody_unavailable")
                try:
                    require_exec_custody(self._policy, self._exec_runtime, self._exec_cancellation)
                except Exception as exc:
                    raise _ProxyRefusal("exec_custody_unavailable") from exc
            if self._custody is not None:
                try:
                    self._custody.prepare(
                        request_ref=request_ref,
                        sequence=sequence,
                        operation=operation,
                        request_digest=request_digest,
                        policy_digest=self._policy.policy_digest,
                        state=before,
                    )
                except Exception as exc:
                    raise _ProxyRefusal("audit_failed") from exc
            require_operation_live(cancellation, self._monotonic_ns, deadline)
            if (
                exec_deadline is not None
                and exec_admission is not None
                and isinstance(self._policy, DockerApiPolicyV2)
            ):
                runtime = self._exec_runtime
                if runtime is None:
                    raise _ProxyRefusal("exec_runtime_unavailable")
                try:
                    dispatch_gate = runtime.gate(
                        exec_admission,
                        operation=operation,
                        request_digest=request_digest,
                        deadline_monotonic_ns=deadline,
                        operation_deadline_monotonic_ns=exec_deadline,
                        custody_plan_digest=self._policy.custody_plan_digest,
                        network_policy_digest=self._policy.network_policy_digest,
                        cancellation=cancellation,
                        exec_id=(binding.exec_id if binding is not None else None),
                    )
                except Exception as exc:
                    self._retain_exec_uncertainty(exec_admission)
                    raise _ProxyRefusal(
                        exec_failure_outcome(exc, default="exec_reservation_failed")
                    ) from exc
            transport_entered = True
            watch = (
                self._exec_cancellation.watch(
                    exec_admission,
                    cancellation,
                    deadline_monotonic_ns=deadline,
                    on_uncertain=lambda: self._fence_exec(exec_admission),
                )
                if dispatch_gate is not None
                and self._exec_cancellation is not None
                and exec_admission is not None
                else nullcontext()
            )
            with watch as custody_watch:
                exchange = self._transport.exchange(
                    raw_request,
                    deadline_monotonic_ns=deadline,
                    response_byte_limit=decision.response_byte_limit,
                    cancellation=cancellation,
                    **({"dispatch_gate": dispatch_gate} if dispatch_gate is not None else {}),
                )
            custody_outcome = exec_watch_outcome(custody_watch)
            if custody_outcome is not None and exec_admission is not None:
                self._retain_exec_uncertainty(exec_admission)
            if dispatch_gate is not None and not dispatch_gate.sent:
                raise _ProxyRefusal("exec_dispatch_refused")
            if exchange.request_digest != request_digest:
                raise EngineDockerProxyError("Docker transport response binds another request")
            if exchange.daemon_instance_digest != self._policy.daemon_instance_digest:
                raise EngineDockerProxyError("Docker daemon identity changed during exchange")
            response_digest = _sha256_bytes(exchange.raw_response)
            response_limit = decision.response_byte_limit
            if decision.response_contract is DockerResponseContract.BOUNDED_EXEC_STREAM:
                response_limit += MAX_DOCKER_STREAM_OVERHEAD_BYTES
            response = _parse_docker_http_response(
                exchange.raw_response,
                limit=response_limit,
                head_response=request.method == "HEAD",
            )
            candidate_container_id, candidate_exec = _candidate_discovery(decision, response)
            if custody_outcome is not None:
                raise _ProxyRefusal(custody_outcome)
            validated = _validated_response(
                self._policy, request, decision, response, before, exec_admission, exec_deadline
            )
            require_operation_live(cancellation, self._monotonic_ns, deadline)
            if (
                dispatch_gate is not None
                and self._exec_runtime is not None
                and exec_admission is not None
            ):
                if decision.operation is DockerApiOperation.CONTAINER_EXEC_CREATE:
                    if validated.discovered_exec is None:
                        raise EngineDockerProxyError("exec creation lacks durable custody")
                    self._exec_runtime.record_created(exec_admission, validated.discovered_exec[0])
                elif decision.operation is DockerApiOperation.EXEC_START:
                    self._exec_runtime.record_started(exec_admission)
                else:
                    self._exec_runtime.record_complete(exec_admission)
            proposed = transition_custody(
                before,
                validated.next_ownership,
                validated.next_v2_exec_bindings,
                exec_admission,
                decision.operation,
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
                    ),
                    proposed,
                )
            except Exception as exc:
                raise _ProxyRefusal("audit_failed") from exc
            require_operation_live(cancellation, self._monotonic_ns, deadline)
            with self._lock:
                if self._inflight != request_ref or self._state.state_digest != before.state_digest:
                    raise EngineDockerProxyError("Docker proxy state changed during publication")
                self._state = proposed
            try:
                published_record = self._audit_record(
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
                self._append_audit(
                    published_record,
                    proposed,
                )
            except Exception as exc:
                with self._lock:
                    self._state = replace(
                        self._state,
                        generation=self._state.generation + 1,
                        reconciliation_required=True,
                    )
                raise _ProxyRefusal("audit_failed") from exc
            try:
                require_operation_live(cancellation, self._monotonic_ns, deadline)
            except _ProxyRefusal:
                with self._lock:
                    self._state = replace(
                        self._state,
                        generation=self._state.generation + 1,
                        reconciliation_required=True,
                    )
                raise
            if (
                isinstance(self._policy, DockerApiPolicyV2)
                and decision.operation is DockerApiOperation.IMAGE_INSPECT
            ):
                with self._lock:
                    self._v2_image_verified_for_create = True
            if (
                self._effective_network_binding is not None
                and isinstance(self._policy, DockerApiPolicyV2)
                and decision.operation is DockerApiOperation.CONTAINER_INSPECT
                and decision.resource_id is not None
            ):
                issued = self._issue_effective_network_receipt(
                    response=response,
                    record=published_record,
                    state=proposed,
                    container_id=decision.resource_id,
                )
                with self._lock:
                    self._effective_network_receipt = issued
            return validated.reply
        except _ProxyRefusal as exc:
            reason = exc.reason
            with self._lock:
                current = self._state
                if transport_entered or (
                    binding is not None
                    and reason
                    in {
                        "cancelled",
                        "deadline_exceeded",
                        "exec_deadline_unavailable",
                        "exec_custody_unavailable",
                        "exec_reservation_failed",
                    }
                ):
                    self._state = self._quarantine(
                        current, validated, candidate_container_id, candidate_exec, decision
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
                    ),
                    current,
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
        except Exception as exc:
            with self._lock:
                current = self._state
                if transport_entered or binding is not None:
                    self._state = self._quarantine(
                        current,
                        validated,
                        candidate_container_id,
                        candidate_exec,
                        decision,
                        binding,
                    )
            try:
                current = self.snapshot()
                self._append_audit(
                    self._audit_record(
                        request_ref=request_ref,
                        sequence=sequence,
                        phase="suppressed" if transport_entered else "refused",
                        outcome=exec_failure_outcome(
                            exc,
                            response_received=response_digest is not None,
                            transport_entered=transport_entered,
                        ),
                        operation=operation,
                        request_digest=request_digest,
                        response_digest=response_digest,
                        before=before,
                        after=current,
                        started=started,
                        ended=max(started, self._now()),
                    ),
                    current,
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
            if exec_admission is not None and self.snapshot().reconciliation_required:
                try:
                    self.cancel_exec(exec_admission)
                except Exception:
                    pass  # Absence remains unverified; outer custody reconciliation must settle it.
            with self._lock:
                if self._inflight == request_ref:
                    self._inflight = None


__all__ = [
    "DockerDaemonExchange",
    "DockerDaemonTransport",
    "DockerExecDispatchGate",
    "DockerPolicyProxy",
    "DockerProxyAuditRecord",
    "DockerProxyAuditSink",
    "DockerProxyCancellation",
    "DockerProxyReply",
    "DockerProxyState",
    "DockerV2EffectiveNetworkBinding",
    "DockerV2EffectiveNetworkReceipt",
    "EngineDockerProxyError",
    "parse_docker_http_request",
]
