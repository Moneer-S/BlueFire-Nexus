"""Controller-owned, test-only Caido SDK wire subset for Strix mechanics.

It adopts a prebound worker-netns listener and provides no live-Caido,
live-model, target-execution, outbound-network, or production proof.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import re
import socket
import stat
import threading
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Protocol, Sequence

from .util import content_hash

PROVIDER_KIND = "bluefire-test-caido-protocol"
PROVIDER_ID = "bluefire.test-caido-protocol-provider.v1"
MANIFEST_SCHEMA = "bluefire.test-caido-protocol-provider-manifest.v1"
BINDING_SCHEMA = "bluefire.test-caido-listener-binding.v1"
AUDIT_SCHEMA = "bluefire.test-caido-protocol-audit.v1"
READY_SCHEMA = "bluefire.test-caido-protocol-ready.v1"
DRAIN_SCHEMA = "bluefire.test-caido-protocol-drain.v1"
ACTIVATION_MODE = "installed_deterministic_test"

TEST_PROVIDER = True
LIVE_CAIDO_PROOF = False
PRODUCTION_ELIGIBLE = False

CAIDO_SDK_CLIENT_VERSION = "0.2.0"
CAIDO_SERVER_AUTH_VERSION = "0.1.2"
CAIDO_SDK_CLIENT_WHEEL_DIGEST = (
    "sha256:bc573651681c093ee9663c7924d38d522a89cea60e2ce00d34ba9b02942b1da1"
)
CAIDO_SERVER_AUTH_WHEEL_DIGEST = (
    "sha256:40c6cd3728e24cdff402c4efa5d8f55bf6e6cc73ac0169bdea1ad1e34faff8ff"
)
WIRE_FIXTURE_DIGEST = "sha256:0f83caa9253b07fec972b5aae877b8495cf5c81c8893df27b708fc515fe74966"
PROJECT_DOCUMENT_DIGEST = "sha256:ea2c5935a9921295c029d2912589df5997f2b9eec185b1bf73556f1af7d986cf"
STRIX_BOOTSTRAP_SOURCE_DIGEST = (
    "sha256:f493e3a7c9219e52520d2fadfd8dde78782e17440056f98aa068b146a0e788af"
)

LISTENER_HOST = "127.0.0.1"
LISTENER_PORT = 48080
# Linux SO_NETNS_COOKIE is a stable u64 identifier of the socket's network
# namespace, including after SCM_RIGHTS transfers it to another process.
SO_NETNS_COOKIE = 71
MAX_HEADER_BYTES = 8_192
MAX_BODY_BYTES = 65_536
MAX_MANIFEST_BYTES = 65_536
MAX_AUDIT_BYTES = 1_048_576
MAX_CONNECTIONS = 4

_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CURL_AGENT = re.compile(r"curl/[0-9]+(?:\.[0-9]+){1,3}\Z")
_SDK_AGENT = "Python/3.12 aiohttp/3.14.5"
_LOGIN_QUERY = "mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"
_DOCUMENT_DIGESTS = MappingProxyType(
    {
        "CreateProject": (
            "sha256:7aca14aacc7d50eb42e348c699b43f721f3c1eee66d2a1a4dbfd11b90ed63b3e"
        ),
        "SelectProject": (
            "sha256:02c6c676bf070ade1a491b7461deefa05f557a7192a3886e18798b0992abe40b"
        ),
        "DeleteProject": (
            "sha256:005a89043f528c674d6f4b76c65583437785fd2d5a4bfbdf0fbe8840650f28e7"
        ),
    }
)


class TestCaidoProviderError(ValueError):
    """Stable, secret-free test-provider refusal."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Test Caido protocol provider refused: " + code)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _require_digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise TestCaidoProviderError("identity_invalid")
    return value


def provider_source_digest() -> str:
    """Digest every maintained source file that implements this provider."""

    directory = os.path.dirname(os.path.realpath(__file__))
    paths = {
        "bluefire/test_caido_protocol_entry.py": os.path.join(
            directory, "test_caido_protocol_entry.py"
        ),
        "bluefire/test_caido_protocol_provider.py": os.path.realpath(__file__),
        "bluefire/test_caido_protocol_server.py": os.path.join(
            directory, "test_caido_protocol_server.py"
        ),
    }
    files: list[dict[str, str]] = []
    try:
        for name, path in sorted(paths.items()):
            info = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1_000_000:
                raise OSError
            with open(path, "rb") as source:  # noqa: PTH123 - installed package source
                files.append({"name": name, "digest": _sha256(source.read())})
    except OSError:
        raise TestCaidoProviderError("provider_source_unavailable") from None
    return content_hash(
        {
            "schema_version": "bluefire.test-caido-protocol-provider-source.v1",
            "files": files,
        }
    )


@dataclass(frozen=True, slots=True)
class TestCaidoListenerBinding:
    """Controller-attested custody of one prebound worker-netns listener."""

    attempt_id: str
    container_ref: str
    provider_generation_ref: str
    owner_process_ref: str
    listener_ref: str
    custody_ref: str
    netns_device: int
    netns_inode: int
    netns_cookie: int
    listener_device: int
    listener_inode: int
    host: str = LISTENER_HOST
    port: int = LISTENER_PORT
    family: int = socket.AF_INET
    socket_type: int = socket.SOCK_STREAM
    schema_version: str = BINDING_SCHEMA
    provider_kind: str = PROVIDER_KIND

    def __post_init__(self) -> None:
        if (
            self.schema_version != BINDING_SCHEMA
            or self.provider_kind != PROVIDER_KIND
            or type(self.attempt_id) is not str
            or _ATTEMPT.fullmatch(self.attempt_id) is None
            or self.host != LISTENER_HOST
            or self.port != LISTENER_PORT
            or self.family != socket.AF_INET
            or self.socket_type != socket.SOCK_STREAM
        ):
            raise TestCaidoProviderError("listener_binding_invalid")
        for value in (
            self.container_ref,
            self.provider_generation_ref,
            self.owner_process_ref,
            self.listener_ref,
            self.custody_ref,
        ):
            _require_digest(value)
        for number in (
            self.netns_device,
            self.netns_inode,
            self.netns_cookie,
            self.listener_device,
            self.listener_inode,
        ):
            if type(number) is not int or number < 0:
                raise TestCaidoProviderError("listener_binding_invalid")
        if (
            self.netns_inode == 0
            or not 0 < self.netns_cookie < 2**64
            or self.listener_inode == 0
        ):
            raise TestCaidoProviderError("listener_binding_invalid")

    def as_mapping(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value: object) -> TestCaidoListenerBinding:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise TestCaidoProviderError("listener_binding_invalid")
        try:
            return cls(**dict(value))
        except (TypeError, ValueError):
            raise TestCaidoProviderError("listener_binding_invalid") from None


@dataclass(frozen=True, slots=True)
class TestCaidoProviderManifest:
    """Exact installed deterministic-test identity; never a production grant."""

    accepted_claim_digest: str
    runtime_admission_digest: str
    controlled_profile_digest: str
    authorization_digest: str
    provider_source_digest: str
    binding: TestCaidoListenerBinding
    request_budget: int = 32
    replay_budget: int = 8
    mutation_budget: int = 4
    refusal_budget: int = 16
    byte_budget: int = 262_144
    schema_version: str = MANIFEST_SCHEMA
    provider_id: str = PROVIDER_ID
    provider_kind: str = PROVIDER_KIND
    activation_mode: str = ACTIVATION_MODE
    caido_sdk_client_version: str = CAIDO_SDK_CLIENT_VERSION
    caido_server_auth_version: str = CAIDO_SERVER_AUTH_VERSION
    caido_sdk_client_wheel_digest: str = CAIDO_SDK_CLIENT_WHEEL_DIGEST
    caido_server_auth_wheel_digest: str = CAIDO_SERVER_AUTH_WHEEL_DIGEST
    wire_fixture_digest: str = WIRE_FIXTURE_DIGEST
    project_document_digest: str = PROJECT_DOCUMENT_DIGEST
    strix_bootstrap_source_digest: str = STRIX_BOOTSTRAP_SOURCE_DIGEST
    test_provider: bool = TEST_PROVIDER
    live_caido_proof: bool = LIVE_CAIDO_PROOF
    production_eligible: bool = PRODUCTION_ELIGIBLE

    def __post_init__(self) -> None:
        fixed = (
            self.schema_version == MANIFEST_SCHEMA
            and self.provider_id == PROVIDER_ID
            and self.provider_kind == PROVIDER_KIND
            and self.activation_mode == ACTIVATION_MODE
            and self.caido_sdk_client_version == CAIDO_SDK_CLIENT_VERSION
            and self.caido_server_auth_version == CAIDO_SERVER_AUTH_VERSION
            and self.caido_sdk_client_wheel_digest == CAIDO_SDK_CLIENT_WHEEL_DIGEST
            and self.caido_server_auth_wheel_digest == CAIDO_SERVER_AUTH_WHEEL_DIGEST
            and self.wire_fixture_digest == WIRE_FIXTURE_DIGEST
            and self.project_document_digest == PROJECT_DOCUMENT_DIGEST
            and self.strix_bootstrap_source_digest == STRIX_BOOTSTRAP_SOURCE_DIGEST
            and self.test_provider is True
            and self.live_caido_proof is False
            and self.production_eligible is False
            and type(self.binding) is TestCaidoListenerBinding
        )
        if not fixed:
            raise TestCaidoProviderError("manifest_identity_invalid")
        for value in (
            self.accepted_claim_digest,
            self.runtime_admission_digest,
            self.controlled_profile_digest,
            self.authorization_digest,
            self.provider_source_digest,
        ):
            _require_digest(value)
        limits = (
            (self.request_budget, 4, 128),
            (self.replay_budget, 1, 32),
            (self.mutation_budget, 4, 4),
            (self.refusal_budget, 1, 64),
            (self.byte_budget, 4_096, 1_048_576),
        )
        if any(type(value) is not int or not low <= value <= high for value, low, high in limits):
            raise TestCaidoProviderError("manifest_limits_invalid")

    @property
    def identity_ref(self) -> str:
        return content_hash(self.as_mapping())

    def as_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = value.as_mapping() if name == "binding" else value
        return result

    @classmethod
    def from_mapping(cls, value: object) -> TestCaidoProviderManifest:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise TestCaidoProviderError("manifest_invalid")
        row = dict(value)
        row["binding"] = TestCaidoListenerBinding.from_mapping(row["binding"])
        try:
            manifest = cls(**row)
        except (TypeError, ValueError):
            raise TestCaidoProviderError("manifest_invalid") from None
        if manifest.provider_source_digest != provider_source_digest():
            raise TestCaidoProviderError("provider_source_changed")
        return manifest


class RuntimeState(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    DRAINED = "drained"


@dataclass(frozen=True, slots=True)
class TestCaidoAuditRecord:
    sequence: int
    attempt_id: str
    provider_identity_ref: str
    state: RuntimeState
    operation: str
    outcome: str
    request_digest: str | None
    response_digest: str | None
    request_budget_remaining: int
    replay_budget_remaining: int
    mutation_budget_remaining: int
    refusal_budget_remaining: int
    byte_budget_remaining: int
    schema_version: str = AUDIT_SCHEMA
    test_provider: bool = TEST_PROVIDER
    live_caido_proof: bool = LIVE_CAIDO_PROOF

    def as_mapping(self) -> dict[str, Any]:
        return {
            name: getattr(self, name).value if name == "state" else getattr(self, name)
            for name in self.__dataclass_fields__
        }


class TestCaidoAuditSink(Protocol):
    def append(self, record: TestCaidoAuditRecord) -> None: ...


class MemoryTestCaidoAuditSink:
    """Bounded in-memory sink for tests; installed launches use the fd sink."""

    def __init__(self) -> None:
        self.records: list[TestCaidoAuditRecord] = []

    def append(self, record: TestCaidoAuditRecord) -> None:
        if len(self.records) >= 512:
            raise TestCaidoProviderError("audit_bound")
        self.records.append(record)


class FileDescriptorTestCaidoAuditSink:
    """Durable controller-opened private audit file; never accepts a path."""

    def __init__(self, descriptor: int) -> None:
        if type(descriptor) is not int or descriptor < 0:
            raise TestCaidoProviderError("audit_descriptor_invalid")
        try:
            info = os.fstat(descriptor)
            append_enabled = True
            writable = True
            if os.name == "posix":
                fcntl = importlib.import_module("fcntl")
                flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                append_enabled = bool(flags & os.O_APPEND)
                writable = bool(flags & os.O_ACCMODE)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size != 0
                or (os.name == "posix" and info.st_mode & 0o077)
                or os.lseek(descriptor, 0, os.SEEK_CUR) != 0
                or not append_enabled
                or not writable
            ):
                raise OSError
            os.set_inheritable(descriptor, False)
        except OSError:
            raise TestCaidoProviderError("audit_descriptor_invalid") from None
        self._descriptor = descriptor
        self._size = info.st_size
        self._closed = False
        self._lock = threading.Lock()

    def append(self, record: TestCaidoAuditRecord) -> None:
        payload = _canonical(record.as_mapping()) + b"\n"
        with self._lock:
            if self._closed or self._size + len(payload) > MAX_AUDIT_BYTES:
                raise TestCaidoProviderError("audit_bound")
            remaining = memoryview(payload)
            try:
                while remaining:
                    count = os.write(self._descriptor, remaining)
                    if count <= 0:
                        raise OSError
                    remaining = remaining[count:]
                os.fsync(self._descriptor)
            except OSError:
                raise TestCaidoProviderError("audit_write_unknown") from None
            self._size += len(payload)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                os.close(self._descriptor)


@dataclass(frozen=True, slots=True)
class _Request:
    method: str
    target: str
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _CommittedMutation:
    request_digest: str
    response: bytes = field(repr=False)


def _json_object(raw: bytes) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in rows:
            if key in value:
                raise ValueError
            value[key] = child
        return value

    def constant(_value: str) -> None:
        raise ValueError

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise TestCaidoProviderError("json_invalid") from None
    if not isinstance(value, dict):
        raise TestCaidoProviderError("json_invalid")
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 24 or nodes > 4096:
            raise TestCaidoProviderError("json_invalid")
        if isinstance(item, dict):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)

    visit(value, 0)
    return value


def _parse_request(raw: bytes, expected_port: int) -> _Request:
    if type(raw) is not bytes or not raw or len(raw) > MAX_HEADER_BYTES + MAX_BODY_BYTES + 4:
        raise TestCaidoProviderError("message_bound")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or len(head) > MAX_HEADER_BYTES or len(body) > MAX_BODY_BYTES:
        raise TestCaidoProviderError("framing_invalid")
    lines = head.split(b"\r\n")
    try:
        request_line = lines[0].decode("ascii")
    except UnicodeError:
        raise TestCaidoProviderError("framing_invalid") from None
    match = re.fullmatch(r"(GET|POST) (/health|/graphql) HTTP/1\.1", request_line)
    if match is None:
        raise TestCaidoProviderError("route_invalid")
    headers: dict[str, str] = {}
    allowed = {
        "host",
        "accept",
        "accept-encoding",
        "user-agent",
        "authorization",
        "content-type",
        "content-length",
    }
    for line in lines[1:]:
        name, delimiter, value = line.partition(b":")
        try:
            key = name.decode("ascii").lower()
            text = value.decode("ascii").strip()
        except UnicodeError:
            raise TestCaidoProviderError("header_invalid") from None
        if (
            delimiter != b":"
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", key)
            or key not in allowed
            or key in headers
            or not text
        ):
            raise TestCaidoProviderError("header_invalid")
        headers[key] = text
    if headers.get("host") != f"{LISTENER_HOST}:{expected_port}":
        raise TestCaidoProviderError("host_invalid")
    if headers.get("accept") != "*/*":
        raise TestCaidoProviderError("header_invalid")
    length = headers.get("content-length")
    if body:
        if length != str(len(body)):
            raise TestCaidoProviderError("length_invalid")
    elif length not in (None, "0"):
        raise TestCaidoProviderError("length_invalid")
    return _Request(match[1], match[2], MappingProxyType(headers), body)


def _http_response(status: int, reason: str, value: Mapping[str, Any]) -> bytes:
    body = _canonical(value)
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body


def _auth_error() -> bytes:
    return _http_response(
        200,
        "OK",
        {
            "errors": [
                {
                    "message": "Authorization refused",
                    "extensions": {"CAIDO": {"code": "AUTHORIZATION", "reason": "INVALID_TOKEN"}},
                }
            ]
        },
    )


class TestCaidoProtocolRuntime:
    """Finite attempt-local public-wire state machine with no external effects."""

    def __init__(
        self,
        manifest: TestCaidoProviderManifest,
        audit: TestCaidoAuditSink | None = None,
    ) -> None:
        if type(manifest) is not TestCaidoProviderManifest:
            raise TestCaidoProviderError("manifest_invalid")
        if manifest.provider_source_digest != provider_source_digest():
            raise TestCaidoProviderError("provider_source_changed")
        self.manifest = manifest
        self._identity_ref = manifest.identity_ref
        self._audit_sink = audit or MemoryTestCaidoAuditSink()
        self._lock = threading.RLock()
        self._state = RuntimeState.ACTIVE
        self._sequence = 0
        self._requests = manifest.request_budget
        self._replays = manifest.replay_budget
        self._mutations = manifest.mutation_budget
        self._refusals = manifest.refusal_budget
        self._bytes = manifest.byte_budget
        self._token: str | None = None
        self._project: dict[str, Any] | None = None
        self._selected = False
        self._deleted = False
        self._journal: dict[str, _CommittedMutation] = {}

    @property
    def state(self) -> RuntimeState:
        with self._lock:
            return self._state

    @property
    def provider_identity_ref(self) -> str:
        return self._identity_ref

    def _audit(
        self,
        operation: str,
        outcome: str,
        request_digest: str | None = None,
        response_digest: str | None = None,
    ) -> None:
        self._sequence += 1
        record = TestCaidoAuditRecord(
            self._sequence,
            self.manifest.binding.attempt_id,
            self._identity_ref,
            self._state,
            operation,
            outcome,
            request_digest,
            response_digest,
            self._requests,
            self._replays,
            self._mutations,
            self._refusals,
            self._bytes,
        )
        try:
            self._audit_sink.append(record)
        except Exception:
            self._revoke(RuntimeState.UNKNOWN)
            raise TestCaidoProviderError("audit_write_unknown") from None

    def _revoke(self, state: RuntimeState = RuntimeState.REVOKED) -> None:
        """Drop attempt authority and cached bearer responses before any further I/O."""

        self._state = state
        self._token = None
        self._project = None
        self._selected = False
        self._deleted = False
        self._journal.clear()

    def record_refusal(self, code: str, byte_count: int) -> None:
        with self._lock:
            self._active()
            self._consume_bytes(byte_count)
            self._consume_request()
            self._refuse("wire", code)

    def _active(self) -> None:
        if self._state is not RuntimeState.ACTIVE:
            raise TestCaidoProviderError("state_refused")

    def _consume_bytes(self, count: int) -> None:
        if type(count) is not int or count < 0 or count > self._bytes:
            self._revoke()
            self._audit("wire", "refused:byte_budget_exhausted")
            raise TestCaidoProviderError("byte_budget_exhausted")
        self._bytes -= count

    def _consume_request(self) -> None:
        if self._requests <= 0:
            self._revoke()
            self._audit("wire", "refused:request_budget_exhausted")
            raise TestCaidoProviderError("request_budget_exhausted")
        self._requests -= 1

    def _refuse(self, operation: str, code: str) -> NoReturn:
        self._refusals -= 1
        if self._refusals < 0:
            self._revoke()
        self._audit(operation, "refused:" + code)
        if self._refusals < 0:
            raise TestCaidoProviderError("refusal_budget_exhausted")
        raise TestCaidoProviderError(code)

    def _replay_or_prepare(self, slot: str, digest: str) -> bytes | None:
        committed = self._journal.get(slot)
        if committed is None:
            if self._mutations <= 0:
                self._refuse(slot, "mutation_budget_exhausted")
            self._audit(slot, "prepared", digest)
            return None
        if not hmac.compare_digest(committed.request_digest, digest):
            self._refuse(slot, "mutation_conflict")
        if slot != "DeleteProject" and self._deleted:
            self._refuse(slot, "mutation_stale")
        if self._replays <= 0:
            self._refuse(slot, "replay_budget_exhausted")
        self._replays -= 1
        self._audit(slot, "replayed", digest, _sha256(committed.response))
        return committed.response

    def _commit(self, slot: str, digest: str, response: bytes) -> bytes:
        self._mutations -= 1
        self._journal[slot] = _CommittedMutation(digest, response)
        self._audit(slot, "committed", digest, _sha256(response))
        return response

    def handle(self, raw: bytes, *, expected_port: int = LISTENER_PORT) -> bytes:
        with self._lock:
            self._active()
            self._consume_bytes(len(raw) if isinstance(raw, bytes) else 0)
            self._consume_request()
            try:
                request = _parse_request(raw, expected_port)
            except TestCaidoProviderError as error:
                self._refuse("wire", error.code)
            if request.target == "/health":
                return self._health(request)
            return self._graphql(request)
        raise AssertionError("unreachable")

    def _health(self, request: _Request) -> bytes:
        if (
            request.method != "GET"
            or request.body
            or request.headers.get("user-agent") != _SDK_AGENT
            or request.headers.get("accept-encoding") != "gzip, deflate"
            or "authorization" in request.headers
            or "content-type" in request.headers
        ):
            self._refuse("health", "health_invalid")
        response = _http_response(
            200,
            "OK",
            {
                "name": "BlueFire Test Caido protocol provider",
                "version": "caido-sdk-client-wire-0.2.0-test",
                "ready": True,
                "test_provider": True,
                "live_caido_proof": False,
            },
        )
        self._audit("health", "ready", _sha256(request.body), _sha256(response))
        return response

    def _graphql(self, request: _Request) -> bytes:
        if request.method != "POST" or request.headers.get("content-type") != "application/json":
            self._refuse("graphql", "graphql_invalid")
        value = _json_object(request.body)
        if value == {"query": _LOGIN_QUERY}:
            return self._login(request)
        if (
            request.headers.get("user-agent") != _SDK_AGENT
            or request.headers.get("accept-encoding") != "gzip, deflate"
        ):
            self._refuse("graphql", "sdk_headers_invalid")
        authorization = request.headers.get("authorization")
        expected = "Bearer " + self._token if self._token is not None else ""
        if (
            not expected
            or authorization is None
            or not hmac.compare_digest(authorization, expected)
        ):
            self._refusals -= 1
            if self._refusals < 0:
                self._revoke()
            self._audit("graphql", "authorization_refused")
            return _auth_error()
        return self._project_operation(value)

    def _login(self, request: _Request) -> bytes:
        agent = request.headers.get("user-agent")
        if (
            agent is None
            or _CURL_AGENT.fullmatch(agent) is None
            or "authorization" in request.headers
            or "accept-encoding" in request.headers
            or set(request.headers)
            != {"host", "user-agent", "accept", "content-type", "content-length"}
        ):
            self._refuse("LoginAsGuest", "login_headers_invalid")
        digest = content_hash(
            {
                "schema_version": "bluefire.test-caido-login-request.v1",
                "provider_identity_ref": self._identity_ref,
                "query_digest": _sha256(_LOGIN_QUERY.encode("utf-8")),
            }
        )
        replay = self._replay_or_prepare("LoginAsGuest", digest)
        if replay is not None:
            return replay
        self._token = "bft_" + os.urandom(32).hex()
        response = _http_response(
            200,
            "OK",
            {"data": {"loginAsGuest": {"token": {"accessToken": self._token}}}},
        )
        return self._commit("LoginAsGuest", digest, response)

    def _project_operation(self, value: Mapping[str, Any]) -> bytes:
        if set(value) not in ({"query", "variables"}, {"query", "variables", "operationName"}):
            self._refuse("graphql", "graphql_fields_invalid")
        query, variables = value.get("query"), value.get("variables")
        if not isinstance(query, str) or not isinstance(variables, dict):
            self._refuse("graphql", "graphql_fields_invalid")
        normalized = re.sub(r"\s+", " ", query).strip()
        document_digest = _sha256(normalized.encode("utf-8"))
        operation = next(
            (name for name, digest in _DOCUMENT_DIGESTS.items() if digest == document_digest),
            None,
        )
        if operation is None or value.get("operationName", operation) != operation:
            self._refuse("graphql", "graphql_document_refused")
        request_digest = content_hash(
            {
                "schema_version": "bluefire.test-caido-project-request.v1",
                "provider_identity_ref": self._identity_ref,
                "operation": operation,
                "document_digest": document_digest,
                "variables": variables,
            }
        )
        if operation == "CreateProject":
            return self._create_project(variables, request_digest)
        if operation == "SelectProject":
            return self._select_project(variables, request_digest)
        return self._delete_project(variables, request_digest)

    def _project_value(self) -> dict[str, Any]:
        assert self._project is not None
        return dict(self._project)

    def _create_project(self, variables: dict[str, Any], digest: str) -> bytes:
        if variables != {"input": {"name": "sandbox", "temporary": True}}:
            self._refuse("CreateProject", "project_input_refused")
        replay = self._replay_or_prepare("CreateProject", digest)
        if replay is not None:
            return replay
        if self._project is not None:
            self._refuse("CreateProject", "project_exists")
        project_id = (
            "bf-test-" + hashlib.sha256(self._identity_ref.encode("ascii")).hexdigest()[:32]
        )
        self._project = {
            "__typename": "Project",
            "id": project_id,
            "name": "sandbox",
            "path": "/workspace/.bluefire-test-caido/sandbox",
            "status": "READY",
            "temporary": True,
            "createdAt": "2026-01-01T00:00:00+00:00",
            "updatedAt": "2026-01-01T00:00:00+00:00",
            "version": "0.0.0-test-protocol",
            "size": 0,
            "readOnly": False,
        }
        response = _http_response(
            200,
            "OK",
            {
                "data": {
                    "createProject": {
                        "__typename": "CreateProjectPayload",
                        "error": None,
                        "project": self._project_value(),
                    }
                }
            },
        )
        return self._commit("CreateProject", digest, response)

    def _select_project(self, variables: dict[str, Any], digest: str) -> bytes:
        project_id = None if self._project is None else self._project["id"]
        if "SelectProject" in self._journal:
            replay = self._replay_or_prepare("SelectProject", digest)
            if replay is not None:
                return replay
        if variables != {"id": project_id} or project_id is None or self._deleted:
            self._refuse("SelectProject", "project_identity_refused")
        replay = self._replay_or_prepare("SelectProject", digest)
        if replay is not None:
            return replay
        self._selected = True
        response = _http_response(
            200,
            "OK",
            {
                "data": {
                    "selectProject": {
                        "__typename": "SelectProjectPayload",
                        "currentProject": {
                            "__typename": "CurrentProject",
                            "project": self._project_value(),
                        },
                        "error": None,
                    }
                }
            },
        )
        return self._commit("SelectProject", digest, response)

    def _delete_project(self, variables: dict[str, Any], digest: str) -> bytes:
        project_id = None if self._project is None else self._project["id"]
        if variables != {"id": project_id} or project_id is None:
            self._refuse("DeleteProject", "project_identity_refused")
        replay = self._replay_or_prepare("DeleteProject", digest)
        if replay is not None:
            return replay
        self._deleted = True
        self._selected = False
        response = _http_response(
            200,
            "OK",
            {
                "data": {
                    "deleteProject": {
                        "__typename": "DeleteProjectPayload",
                        "deletedId": project_id,
                        "error": None,
                    }
                }
            },
        )
        return self._commit("DeleteProject", digest, response)

    def cancel(self) -> None:
        with self._lock:
            if self._state is RuntimeState.DRAINED:
                return
            if (
                self._state is RuntimeState.REVOKED
                and self._token is None
                and self._project is None
                and not self._journal
                and not self._deleted
            ):
                return
            unknown = self._state is RuntimeState.UNKNOWN
            self._revoke(RuntimeState.UNKNOWN if unknown else RuntimeState.REVOKED)
            self._audit("lifecycle", "cancelled_unknown" if unknown else "revoked")

    def drain(self) -> None:
        with self._lock:
            if self._state not in {
                RuntimeState.REVOKED,
                RuntimeState.UNKNOWN,
                RuntimeState.DRAINED,
            }:
                raise TestCaidoProviderError("state_refused")
            self._token = None
            self._project = None
            self._selected = False
            self._deleted = False
            self._journal.clear()
            self._state = RuntimeState.DRAINED
            self._audit("lifecycle", "drained")


def provider_descriptor() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.test-caido-protocol-provider-descriptor.v1",
        "provider_id": PROVIDER_ID,
        "provider_kind": PROVIDER_KIND,
        "activation_mode": ACTIVATION_MODE,
        "test_provider": True,
        "live_caido_proof": False,
        "production_eligible": False,
        "caido_sdk_client_version": CAIDO_SDK_CLIENT_VERSION,
        "caido_server_auth_version": CAIDO_SERVER_AUTH_VERSION,
        "caido_sdk_client_wheel_digest": CAIDO_SDK_CLIENT_WHEEL_DIGEST,
        "caido_server_auth_wheel_digest": CAIDO_SERVER_AUTH_WHEEL_DIGEST,
        "wire_fixture_digest": WIRE_FIXTURE_DIGEST,
        "project_document_digest": PROJECT_DOCUMENT_DIGEST,
        "strix_bootstrap_source_digest": STRIX_BOOTSTRAP_SOURCE_DIGEST,
        "provider_source_digest": provider_source_digest(),
        "listener": {"host": LISTENER_HOST, "port": LISTENER_PORT, "prebound": True},
        "supported_operations": [
            "health",
            "LoginAsGuest",
            "CreateProject",
            "SelectProject",
            "DeleteProject",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    from .test_caido_protocol_entry import main as entry_main

    return entry_main(argv)


if __name__ == "__main__":  # pragma: no cover - exercised as installed module
    raise SystemExit(main())
