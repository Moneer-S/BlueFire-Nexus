"""Pure, bounded worker/controller messages for the controlled Strix transport.

This module owns no stream, process, socket, sandbox, or authority source.  A
controller must supply the reviewed profile, immutable claim/plan/fence binding,
and its own live transport.  Worker handles carry only inert resource identity;
the controller resolves them against handles returned by its own transport.

An ambiguous channel is never resumed.  Durable controller custody and fence
checks must seed any separate recovery path for an existing sandbox or write;
this pure channel does not claim to implement restart recovery.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping

from . import strix_controlled_backend as backend
from .util import canonical_json_bytes, content_hash

PROTOCOL_VERSION = "bluefire.strix-controlled-worker-channel.v1"
MAX_FRAME_BYTES = 48 * 1024 * 1024  # A 32 MiB archive plus canonical base64 and envelope.
MAX_REQUESTS = 1024
MAX_PENDING = 2
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_RESOURCE = re.compile(r"sandbox-[0-9a-f]{32}\Z")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}\Z")
_OBSERVATION = re.compile(r"observation-[0-9a-f]{32}\Z")
_TRANSFER = re.compile(r"transfer-[0-9a-f]{32}\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}\Z")
_SANDBOX_USER = re.compile(r"[1-9][0-9]{0,9}:[1-9][0-9]{0,9}\Z")


class ControlledWorkerChannelError(ValueError):
    """A channel refusal.  Its message never contains received data."""


def _refuse() -> ControlledWorkerChannelError:
    return ControlledWorkerChannelError("controlled worker channel refused")


def _exact_int(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _digest(value: Any) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("JSON constant")


def encode_frame(value: Mapping[str, Any]) -> bytes:
    """Encode one exact canonical JSON frame, with a four-byte LE length."""
    try:
        raw = canonical_json_bytes(dict(value))
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _refuse() from None
    if not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise _refuse()
    return len(raw).to_bytes(4, "little") + raw


def decode_frame(frame: bytes) -> dict[str, Any]:
    """Reject an oversized header before parsing or copying its body."""
    if type(frame) is not bytes or len(frame) < 4:
        raise _refuse()
    size = int.from_bytes(frame[:4], "little")
    if not 0 < size <= MAX_FRAME_BYTES or len(frame) != size + 4:
        raise _refuse()
    raw = frame[4:]
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicates_rejected,
            parse_constant=_reject_constant,
        )
        if type(value) is not dict or canonical_json_bytes(value) != raw:
            raise ValueError("noncanonical JSON")
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        raise _refuse() from None
    return value


class FrameDecoder:
    """Incremental framing with no body allocation above the advertised cap."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._size: int | None = None
        self._poisoned = False

    @property
    def poisoned(self) -> bool:
        return self._poisoned

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        if self._poisoned or type(data) is not bytes:
            raise _refuse()
        result: list[dict[str, Any]] = []
        cursor = 0
        try:
            while cursor < len(data):
                target = 4 if self._size is None else self._size + 4
                count = min(target - len(self._buffer), len(data) - cursor)
                self._buffer.extend(data[cursor : cursor + count])
                cursor += count
                if self._size is None and len(self._buffer) == 4:
                    self._size = int.from_bytes(self._buffer, "little")
                    if not 0 < self._size <= MAX_FRAME_BYTES:
                        raise _refuse()
                if self._size is not None and len(self._buffer) == self._size + 4:
                    if len(result) >= MAX_REQUESTS:
                        raise _refuse()
                    result.append(decode_frame(bytes(self._buffer)))
                    self._buffer.clear()
                    self._size = None
        except ControlledWorkerChannelError:
            self._poisoned = True
            self._buffer.clear()
            raise
        return result

    def eof(self) -> None:
        self._poisoned = True
        raise _refuse()


@dataclass(frozen=True, slots=True)
class ControlledWorkerBinding:
    attempt_id: str
    claim_digest: str
    plan_digest: str
    profile_digest: str
    identity_digest: str
    controller_fence: str
    deadline_ns: int
    nonce: str

    def __post_init__(self) -> None:
        if (
            type(self.attempt_id) is not str
            or backend._ATTEMPT_ID.fullmatch(self.attempt_id) is None
            or not all(
                _digest(value)
                for value in (
                    self.claim_digest,
                    self.plan_digest,
                    self.profile_digest,
                    self.identity_digest,
                    self.controller_fence,
                )
            )
            or not _exact_int(self.deadline_ns, 1, 2**63 - 1)
            or type(self.nonce) is not str
            or _HEX32.fullmatch(self.nonce) is None
        ):
            raise _refuse()

    def wire(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "claim_digest": self.claim_digest,
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "identity_digest": self.identity_digest,
            "controller_fence": self.controller_fence,
            "deadline_ns": self.deadline_ns,
            "nonce": self.nonce,
        }


@dataclass(frozen=True, slots=True)
class _InertWorkerRef:
    """A non-capability marker used solely to satisfy the backend handle type."""


_INERT_REF = _InertWorkerRef()


@dataclass(frozen=True, slots=True)
class _Method:
    request_type: type[Any]
    receipt_type: type[Any]
    kind: str
    request_fields: tuple[tuple[str, str], ...]
    receipt_fields: tuple[tuple[str, str], ...]
    digest_fields: tuple[str, ...]


_BASE_REQUEST = (("schema_version", "str"), ("request_digest", "digest"), ("identity_digest", "digest"))
_BASE_RECEIPT = _BASE_REQUEST
_HANDLE = (("handle", "handle"),)
_RESOURCE_RECEIPT = _BASE_RECEIPT + (("resource_digest", "digest"),)
_LIFECYCLE_REQUEST = _BASE_REQUEST + (
    ("attempt_id", "attempt"),
    ("relay_digest", "digest"),
    ("relay_upstream_digest", "digest"),
    ("relay_channel_digest", "digest"),
    ("relay_retry_digest", "digest"),
    ("observation_id", "optional_observation"),
    ("handle", "optional_handle"),
    ("operation_digest", "optional_digest"),
)
_LIFECYCLE_RECEIPT = _BASE_RECEIPT + (
    ("resource_digest", "optional_digest"),
    ("lifecycle", "lifecycle"),
    ("relay_lifecycle", "relay_lifecycle"),
    ("operation_lifecycle", "operation_lifecycle"),
)
_LIFECYCLE_BODY = (
    "resource_digest", "operation_digest", "relay_digest", "relay_upstream_digest",
    "relay_channel_digest", "relay_retry_digest", "observation_id",
)
_BLOB_REQUEST = _BASE_REQUEST + (
    ("operation_id", "operation"), ("handle", "handle"), ("byte_limit", "object_limit"),
    ("archive", "optional_archive"), ("archive_digest", "optional_digest"),
)

# Every accepted method and every serialized field appears in this literal table.
METHODS: Mapping[str, _Method] = MappingProxyType({
    "create_exact": _Method(
        backend.ControlledCreateRequest, backend.ControlledCreateReceipt, "create",
        _BASE_REQUEST + (
            ("attempt_id", "attempt"), ("profile_digest", "digest"),
            ("image_reference", "image"), ("image_digest", "digest"),
            ("manifest_digest", "digest"), ("sandbox_user", "sandbox_user"),
            ("read_only_root", "true"), ("tmpfs_contract_digest", "digest"),
            ("exposed_ports", "caido_ports"), ("host_port_mode", "relay_only"),
        ),
        _BASE_RECEIPT + (("handle", "handle"), ("lifecycle", "running")),
        ("image_reference", "image_digest", "manifest_digest", "sandbox_user", "read_only_root", "tmpfs_contract_digest", "exposed_ports", "host_port_mode"),
    ),
    "reconcile_create": _Method(backend.ControlledLifecycleRequest, backend.ControlledLifecycleReceipt, "reconcile-create", _LIFECYCLE_REQUEST, _LIFECYCLE_RECEIPT, _LIFECYCLE_BODY),
    "exec_exact": _Method(
        backend.ControlledExecRequest, backend.ControlledExecReceipt, "exec",
        _BASE_REQUEST + (("operation_id", "operation"),) + _HANDLE + (
            ("argv", "argv"), ("timeout_seconds", "timeout"),
            ("working_directory", "workspace_root"), ("stdin_mode", "disabled"),
            ("pty", "false"),
        ),
        _RESOURCE_RECEIPT + (
            ("exit_code", "exit_code"), ("stdout_digest", "digest"),
            ("stderr_digest", "digest"), ("stdout", "output"),
            ("stderr", "output"), ("complete", "true"),
        ),
        ("resource_digest", "operation_id", "argv", "timeout_seconds", "working_directory", "stdin_mode", "pty"),
    ),
    "cancel_exact": _Method(backend.ControlledLifecycleRequest, backend.ControlledLifecycleReceipt, "cancel", _LIFECYCLE_REQUEST, _LIFECYCLE_RECEIPT, _LIFECYCLE_BODY),
    "read_exact": _Method(
        backend.ControlledReadRequest, backend.ControlledReadReceipt, "read",
        _BASE_REQUEST + (("observation_id", "observation"),) + _HANDLE + (("workspace_path", "path"), ("byte_limit", "object_limit")),
        _RESOURCE_RECEIPT + (("workspace_path", "path"), ("content_digest", "digest"), ("content", "archive"), ("regular_file", "true"), ("canonical", "true")),
        ("resource_digest", "observation_id", "workspace_path", "byte_limit"),
    ),
    "begin_write_exact": _Method(
        backend.ControlledWriteBeginRequest, backend.ControlledWriteBeginReceipt, "write-begin",
        _BASE_REQUEST + (("operation_id", "operation"),) + _HANDLE + (("workspace_path", "path"), ("content_size", "size"), ("content_digest", "digest"), ("chunk_size", "chunk_size")),
        _RESOURCE_RECEIPT + (("transfer_id", "transfer"), ("next_offset", "size")),
        ("resource_digest", "operation_id", "workspace_path", "content_size", "content_digest", "chunk_size"),
    ),
    "write_chunk_exact": _Method(
        backend.ControlledWriteChunkRequest, backend.ControlledWriteChunkReceipt, "write-chunk",
        _BASE_REQUEST + (("operation_id", "operation"),) + _HANDLE + (("transfer_id", "transfer"), ("index", "index"), ("offset", "size"), ("total_size", "size"), ("content_digest", "digest"), ("chunk_digest", "digest"), ("chunk", "chunk")),
        _RESOURCE_RECEIPT + (("transfer_id", "transfer"), ("chunk_digest", "digest"), ("next_offset", "size")),
        ("resource_digest", "operation_id", "transfer_id", "index", "offset", "total_size", "content_digest", "chunk_digest"),
    ),
    "commit_write_exact": _Method(
        backend.ControlledWriteCommitRequest, backend.ControlledWriteCommitReceipt, "write-commit",
        _BASE_REQUEST + (("operation_id", "operation"),) + _HANDLE + (("transfer_id", "transfer"), ("workspace_path", "path"), ("content_size", "size"), ("content_digest", "digest")),
        _RESOURCE_RECEIPT + (("transfer_id", "transfer"), ("workspace_path", "path"), ("content_size", "size"), ("content_digest", "digest"), ("atomically_published", "true")),
        ("resource_digest", "operation_id", "transfer_id", "workspace_path", "content_size", "content_digest"),
    ),
    "reconcile_write_exact": _Method(
        backend.ControlledWriteReconcileRequest, backend.ControlledWriteReconcileReceipt, "write-reconcile",
        _BASE_REQUEST + (("operation_id", "operation"),) + _HANDLE + (("transfer_id", "optional_transfer"), ("workspace_path", "path"), ("content_size", "size"), ("content_digest", "digest")),
        _RESOURCE_RECEIPT + (("operation_id", "operation"), ("workspace_path", "path"), ("content_size", "size"), ("content_digest", "digest"), ("outcome", "write_outcome"), ("transfer_lifecycle", "transfer_lifecycle")),
        ("resource_digest", "operation_id", "transfer_id", "workspace_path", "content_size", "content_digest"),
    ),
    "abort_write_exact": _Method(
        backend.ControlledWriteAbortRequest, backend.ControlledLifecycleReceipt, "write-abort",
        _BASE_REQUEST + (("operation_id", "operation"),) + _HANDLE + (("transfer_id", "transfer"),),
        _LIFECYCLE_RECEIPT,
        ("resource_digest", "operation_id", "transfer_id"),
    ),
    "running_exact": _Method(backend.ControlledLifecycleRequest, backend.ControlledLifecycleReceipt, "running", _LIFECYCLE_REQUEST, _LIFECYCLE_RECEIPT, _LIFECYCLE_BODY),
    "persist_exact": _Method(
        backend.ControlledWorkspaceBlobRequest, backend.ControlledWorkspaceBlobReceipt, "persist",
        _BLOB_REQUEST,
        _RESOURCE_RECEIPT + (("archive_digest", "digest"), ("archive_size", "size"), ("archive", "archive"), ("sealed", "true")),
        ("resource_digest", "operation_id", "byte_limit"),
    ),
    "hydrate_exact": _Method(
        backend.ControlledWorkspaceBlobRequest, backend.ControlledHydrateReceipt, "hydrate",
        _BLOB_REQUEST,
        _RESOURCE_RECEIPT + (("archive_digest", "digest"), ("applied", "true")),
        ("resource_digest", "operation_id", "byte_limit", "archive_digest", "archive_size"),
    ),
    "resolve_caido_exact": _Method(
        backend.ControlledPortRequest, backend.ControlledPortReceipt, "port",
        _BASE_REQUEST + _HANDLE + (("container_port", "caido_port"), ("relay_digest", "digest"), ("upstream_digest", "digest"), ("channel_digest", "digest"), ("retry_contract_digest", "digest")),
        _RESOURCE_RECEIPT + (("container_port", "caido_port"), ("relay_digest", "digest"), ("upstream_digest", "digest"), ("channel_digest", "digest"), ("retry_contract_digest", "digest"), ("retry_count", "zero"), ("host", "loopback"), ("port", "port"), ("tls", "false"), ("published_host_port", "false")),
        ("resource_digest", "container_port", "relay_digest", "upstream_digest", "channel_digest", "retry_contract_digest"),
    ),
    "delete_exact": _Method(backend.ControlledLifecycleRequest, backend.ControlledLifecycleReceipt, "delete", _LIFECYCLE_REQUEST, _LIFECYCLE_RECEIPT, _LIFECYCLE_BODY),
})


def _path(value: Any) -> bool:
    if type(value) is not str or not value.startswith("/workspace/"):
        return False
    if len(value.encode("utf-8")) > 1024 or "\\" in value:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/")[1:])


def _decode_bytes(value: Any, maximum: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise _refuse()
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise _refuse() from None
    if len(raw) > maximum or base64.b64encode(raw).decode("ascii") != value:
        raise _refuse()
    return raw


def _handle_wire(handle: Any) -> dict[str, str]:
    if (
        type(handle) is not backend.ControlledSandboxHandle
        or type(handle.attempt_id) is not str
        or backend._ATTEMPT_ID.fullmatch(handle.attempt_id) is None
        or type(handle.resource_id) is not str
        or _RESOURCE.fullmatch(handle.resource_id) is None
        or not _digest(handle.resource_digest)
        or handle.opaque_ref is None
    ):
        raise _refuse()
    return {
        "attempt_id": handle.attempt_id,
        "resource_id": handle.resource_id,
        "resource_digest": handle.resource_digest,
    }


def _decode_handle(value: Any, handles: Mapping[tuple[str, str], backend.ControlledSandboxHandle] | None) -> backend.ControlledSandboxHandle:
    if (
        type(value) is not dict
        or set(value) != {"attempt_id", "resource_id", "resource_digest"}
        or type(value["attempt_id"]) is not str
        or backend._ATTEMPT_ID.fullmatch(value["attempt_id"]) is None
        or type(value["resource_id"]) is not str
        or _RESOURCE.fullmatch(value["resource_id"]) is None
        or not _digest(value["resource_digest"])
    ):
        raise _refuse()
    if handles is not None:
        handle = handles.get((value["resource_id"], value["resource_digest"]))
        if handle is None or _handle_wire(handle) != value:
            raise _refuse()
        return handle
    return backend.ControlledSandboxHandle(
        attempt_id=value["attempt_id"],
        resource_id=value["resource_id"],
        resource_digest=value["resource_digest"],
        opaque_ref=_INERT_REF,
    )


def _field(value: Any, rule: str, handles: Mapping[tuple[str, str], backend.ControlledSandboxHandle] | None = None) -> Any:
    if rule == "handle":
        if type(value) is backend.ControlledSandboxHandle:
            return value
        return _decode_handle(value, handles)
    if rule == "optional_handle":
        return None if value is None else _field(value, "handle", handles)
    if rule in {"chunk", "output", "archive", "optional_archive"}:
        if value is None and rule == "optional_archive":
            return None
        if type(value) is bytes:
            raw = value
        else:
            maximum = {
                "chunk": backend.WRITE_CHUNK_BYTES,
                "output": backend.MAX_EXEC_OUTPUT_BYTES,
                "archive": backend.MAX_WORKSPACE_OBJECT_BYTES,
                "optional_archive": backend.MAX_WORKSPACE_OBJECT_BYTES,
            }[rule]
            raw = _decode_bytes(value, maximum)
        maximum = backend.WRITE_CHUNK_BYTES if rule == "chunk" else backend.MAX_EXEC_OUTPUT_BYTES if rule == "output" else backend.MAX_WORKSPACE_OBJECT_BYTES
        if len(raw) > maximum:
            raise _refuse()
        return raw
    if rule == "argv":
        if type(value) not in {tuple, list} or not 1 <= len(value) <= backend.MAX_EXEC_ARGUMENTS:
            raise _refuse()
        if not all(type(part) is str and part and all((ord(char) >= 32 and ord(char) != 127) or char in {"\t", "\n"} for char in part) for part in value):
            raise _refuse()
        if sum(len(part.encode("utf-8")) for part in value) > backend.MAX_EXEC_ARGUMENT_BYTES:
            raise _refuse()
        return tuple(value)
    if rule == "caido_ports":
        if (
            type(value) not in {list, tuple}
            or len(value) != 1
            or type(value[0]) is not int
            or value[0] != backend.CAIDO_PORT
        ):
            raise _refuse()
        return (backend.CAIDO_PORT,)
    patterns = {
        "digest": _DIGEST, "attempt": backend._ATTEMPT_ID,
        "operation": _OPERATION, "observation": _OBSERVATION,
        "transfer": _TRANSFER, "image": _IMAGE, "sandbox_user": _SANDBOX_USER,
    }
    if rule in patterns:
        if type(value) is not str or patterns[rule].fullmatch(value) is None:
            raise _refuse()
        return value
    if rule.startswith("optional_"):
        return None if value is None else _field(value, rule[9:], handles)
    literals: dict[str, Any] = {
        "true": True, "false": False, "zero": 0, "running": "running",
        "workspace_root": backend.WORKSPACE_ROOT, "disabled": "disabled",
        "relay_only": "controller-relay-only", "caido_port": backend.CAIDO_PORT,
        "loopback": "127.0.0.1", "chunk_size": backend.WRITE_CHUNK_BYTES,
        "object_limit": backend.MAX_WORKSPACE_OBJECT_BYTES,
    }
    if rule in literals:
        expected = literals[rule]
        if type(value) is not type(expected) or value != expected:
            raise _refuse()
        return value
    enums = {
        "lifecycle": {"running", "cancelled", "absent", "unknown"},
        "relay_lifecycle": {"active", "absent", "not_applicable", "unknown"},
        "operation_lifecycle": {"terminal", "not_applicable", "unknown"},
        "write_outcome": {"published", "not_published", "unknown"},
        "transfer_lifecycle": {"absent", "active", "unknown"},
    }
    if rule in enums:
        if type(value) is not str or value not in enums[rule]:
            raise _refuse()
        return value
    if rule == "str":
        if type(value) is not str or len(value.encode("utf-8")) > 128:
            raise _refuse()
        return value
    if rule == "path":
        if not _path(value):
            raise _refuse()
        return value
    if rule == "timeout":
        if type(value) is not float or not math.isfinite(value) or not 0 < value <= 120.0:
            raise _refuse()
        return value
    bounds = {
        "size": (0, backend.MAX_WORKSPACE_OBJECT_BYTES),
        "index": (0, backend.MAX_WORKSPACE_OBJECT_BYTES // backend.WRITE_CHUNK_BYTES),
        "exit_code": (-1, 255), "port": (1, 65535),
    }
    if rule in bounds:
        low, high = bounds[rule]
        if not _exact_int(value, low, high):
            raise _refuse()
        return value
    raise _refuse()


def _payload(value: Any, expected_type: type[Any], fields: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    if type(value) is not expected_type:
        raise _refuse()
    result: dict[str, Any] = {}
    for name, rule in fields:
        try:
            field_value = _field(object.__getattribute__(value, name), rule)
        except (AttributeError, UnicodeError):
            raise _refuse() from None
        if rule in {"handle", "optional_handle"}:
            result[name] = None if field_value is None else _handle_wire(field_value)
        elif rule in {"chunk", "output", "archive", "optional_archive"}:
            result[name] = None if field_value is None else base64.b64encode(field_value).decode("ascii")
        elif rule == "argv":
            result[name] = list(field_value)
        elif rule == "caido_ports":
            result[name] = list(field_value)
        else:
            result[name] = field_value
    return result


def _inflate(payload: Any, expected_type: type[Any], fields: tuple[tuple[str, str], ...], handles: Mapping[tuple[str, str], backend.ControlledSandboxHandle] | None = None) -> Any:
    if type(payload) is not dict or set(payload) != {name for name, _rule in fields}:
        raise _refuse()
    values = {name: _field(payload[name], rule, handles) for name, rule in fields}
    try:
        return expected_type(**values)
    except (TypeError, ValueError):
        raise _refuse() from None


def _request_body(method: _Method, request: Any) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for name in method.digest_fields:
        if name == "resource_digest":
            handle = object.__getattribute__(request, "handle")
            body[name] = None if handle is None else handle.resource_digest
        elif name == "archive_size":
            archive = object.__getattribute__(request, "archive")
            if type(archive) is not bytes:
                raise _refuse()
            body[name] = len(archive)
        else:
            value = object.__getattribute__(request, name)
            body[name] = list(value) if type(value) is tuple else value
    return body


def _validate_request(method_name: str, request: Any, profile: backend.ControlledRuntimeProfile, binding: ControlledWorkerBinding) -> None:
    method = METHODS[method_name]
    if (
        request.schema_version != f"bluefire.strix-controlled-{method.kind}-request.v1"
        or request.identity_digest != binding.identity_digest
        or request.request_digest != content_hash({
            "schema_version": f"bluefire.strix-controlled-{method.kind}-request.v1",
            "identity_digest": profile.identity_digest,
            "attempt_id": profile.attempt_id,
            "profile_digest": profile.profile_digest,
            **_request_body(method, request),
        })
    ):
        raise _refuse()
    if method_name in {"create_exact", "reconcile_create", "cancel_exact", "running_exact", "delete_exact"} and request.attempt_id != binding.attempt_id:
        raise _refuse()
    if method_name != "create_exact" and request.handle is not None and request.handle.attempt_id != binding.attempt_id:
        raise _refuse()
    if method_name == "create_exact":
        expected = backend.ControlledCreateRequest.create(profile)
        if request != expected:
            raise _refuse()
    elif method_name in {"reconcile_create", "cancel_exact", "running_exact", "delete_exact"}:
        if (
            request.relay_digest != profile.relay_digest
            or request.relay_upstream_digest != profile.relay_upstream_digest
            or request.relay_channel_digest != profile.relay_channel_digest
            or request.relay_retry_digest != profile.relay_retry_digest
        ):
            raise _refuse()
        if method_name == "reconcile_create" and (request.handle is not None or request.operation_digest is None or request.observation_id is not None):
            raise _refuse()
        if method_name == "cancel_exact" and (request.handle is None or request.operation_digest is None or request.observation_id is not None):
            raise _refuse()
        if method_name == "running_exact" and (request.handle is None or request.observation_id is None or request.operation_digest is not None):
            raise _refuse()
        if method_name == "delete_exact" and (request.handle is None or request.observation_id is not None or request.operation_digest is not None):
            raise _refuse()
    elif method_name == "persist_exact" and (request.archive is not None or request.archive_digest is not None):
        raise _refuse()
    elif method_name == "hydrate_exact" and (type(request.archive) is not bytes or _sha256(request.archive) != request.archive_digest):
        raise _refuse()
    elif method_name == "write_chunk_exact" and (
        not request.chunk or _sha256(request.chunk) != request.chunk_digest
        or request.offset + len(request.chunk) > request.total_size
        or request.offset != request.index * backend.WRITE_CHUNK_BYTES
        or (request.offset + len(request.chunk) < request.total_size and len(request.chunk) != backend.WRITE_CHUNK_BYTES)
    ):
        raise _refuse()
    elif method_name == "resolve_caido_exact" and (
        request.relay_digest != profile.relay_digest
        or request.upstream_digest != profile.relay_upstream_digest
        or request.channel_digest != profile.relay_channel_digest
        or request.retry_contract_digest != profile.relay_retry_digest
    ):
        raise _refuse()


def _validate_receipt(method_name: str, receipt: Any, request: Any, binding: ControlledWorkerBinding) -> None:
    method = METHODS[method_name]
    expected_schema = "bluefire.strix-controlled-lifecycle-receipt.v1" if method.receipt_type is backend.ControlledLifecycleReceipt else f"bluefire.strix-controlled-{method.kind}-receipt.v1"
    if (
        receipt.schema_version != expected_schema
        or receipt.request_digest != request.request_digest
        or receipt.identity_digest != binding.identity_digest
    ):
        raise _refuse()
    request_handle = None if method_name == "create_exact" else request.handle
    if request_handle is not None and receipt.resource_digest != request_handle.resource_digest:
        raise _refuse()
    if method_name == "create_exact":
        if receipt.handle.attempt_id != binding.attempt_id:
            raise _refuse()
    elif method_name == "exec_exact":
        if (
            len(receipt.stdout) + len(receipt.stderr) > backend.MAX_EXEC_OUTPUT_BYTES
            or _sha256(receipt.stdout) != receipt.stdout_digest
            or _sha256(receipt.stderr) != receipt.stderr_digest
        ):
            raise _refuse()
    elif method_name == "read_exact":
        if receipt.workspace_path != request.workspace_path or len(receipt.content) > request.byte_limit or _sha256(receipt.content) != receipt.content_digest:
            raise _refuse()
    elif method_name == "begin_write_exact":
        if receipt.next_offset != 0:
            raise _refuse()
    elif method_name == "write_chunk_exact":
        if receipt.transfer_id != request.transfer_id or receipt.chunk_digest != request.chunk_digest or receipt.next_offset != request.offset + len(request.chunk):
            raise _refuse()
    elif method_name == "commit_write_exact":
        if (receipt.transfer_id, receipt.workspace_path, receipt.content_size, receipt.content_digest) != (request.transfer_id, request.workspace_path, request.content_size, request.content_digest):
            raise _refuse()
    elif method_name == "reconcile_write_exact":
        if (receipt.operation_id, receipt.workspace_path, receipt.content_size, receipt.content_digest) != (request.operation_id, request.workspace_path, request.content_size, request.content_digest):
            raise _refuse()
    elif method_name == "persist_exact":
        if receipt.archive_size != len(receipt.archive) or receipt.archive_size > request.byte_limit or _sha256(receipt.archive) != receipt.archive_digest:
            raise _refuse()
    elif method_name == "hydrate_exact":
        if receipt.archive_digest != request.archive_digest:
            raise _refuse()
    elif method_name == "resolve_caido_exact":
        if (
            receipt.relay_digest != request.relay_digest
            or receipt.upstream_digest != request.upstream_digest
            or receipt.channel_digest != request.channel_digest
            or receipt.retry_contract_digest != request.retry_contract_digest
        ):
            raise _refuse()


def _ambiguous_receipt(method: str, receipt: Any) -> bool:
    generic = (
        isinstance(receipt, backend.ControlledLifecycleReceipt)
        and (
            receipt.lifecycle == "unknown"
            or receipt.relay_lifecycle == "unknown"
            or receipt.operation_lifecycle == "unknown"
        )
    ) or (
        isinstance(receipt, backend.ControlledWriteReconcileReceipt)
        and (receipt.outcome == "unknown" or receipt.transfer_lifecycle == "unknown")
    )
    if generic:
        return True
    if method in {"delete_exact", "reconcile_create"}:
        return bool(receipt.lifecycle != "absent" or receipt.relay_lifecycle != "absent")
    if method == "cancel_exact":
        return bool(receipt.lifecycle not in {"cancelled", "absent"} or receipt.operation_lifecycle != "terminal")
    if method == "abort_write_exact":
        return bool(receipt.lifecycle not in {"absent", "cancelled"})
    if method == "running_exact":
        return not (
            (receipt.lifecycle == "running" and receipt.relay_lifecycle in {"active", "not_applicable"} and receipt.operation_lifecycle == "not_applicable")
            or (receipt.lifecycle == "absent" and receipt.relay_lifecycle == "absent")
        )
    if method == "reconcile_write_exact":
        return bool(receipt.transfer_lifecycle != "absent")
    return False


_WIRE_KEYS = {
    "protocol_version", "binding", "direction", "sequence", "request_id",
    "method", "reply_to_sequence", "payload",
}


class _Channel:
    def __init__(self, profile: backend.ControlledRuntimeProfile, binding: ControlledWorkerBinding) -> None:
        if type(profile) is not backend.ControlledRuntimeProfile or type(binding) is not ControlledWorkerBinding:
            raise _refuse()
        if (
            binding.attempt_id != profile.attempt_id
            or binding.profile_digest != profile.profile_digest
            or binding.identity_digest != profile.identity_digest
        ):
            raise _refuse()
        self.profile = profile
        self.binding = binding
        self._binding_bytes = canonical_json_bytes(binding.wire())
        self._sent_sequence = 0
        self._received_sequence = 0
        self._last_now_ns = 0
        self._seen_ids: set[str] = set()
        self._seen_digests: dict[str, str] = {}
        self._operation_owner: dict[str, str] = {}
        self._write_meta: dict[str, tuple[str, int, str]] = {}
        self._write_transfer: dict[str, str] = {}
        self._write_offset: dict[str, int] = {}
        self._retired: set[tuple[str, str]] = set()
        self._create_seen = False
        self._pending: dict[str, tuple[int, str, Any]] = {}
        self._poisoned = False

    @property
    def usable(self) -> bool:
        return not self._poisoned

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def abandon(self) -> None:
        self._poisoned = True

    def timeout(self) -> None:
        self._poisoned = True

    def eof(self) -> None:
        self._poisoned = True

    def partial(self) -> None:
        """Record an ambiguous short write or incomplete read."""
        self._poisoned = True

    def _clock(self, now_ns: int) -> None:
        if (
            self._poisoned or not _exact_int(now_ns, 1, 2**63 - 1)
            or now_ns < self._last_now_ns or now_ns >= self.binding.deadline_ns
        ):
            self._poisoned = True
            raise _refuse()
        self._last_now_ns = now_ns

    def _envelope(self, direction: str, sequence: int, request_id: str, method: str, reply_to_sequence: int | None, payload: dict[str, Any]) -> bytes:
        return encode_frame({
            "protocol_version": PROTOCOL_VERSION,
            "binding": self.binding.wire(),
            "direction": direction,
            "sequence": sequence,
            "request_id": request_id,
            "method": method,
            "reply_to_sequence": reply_to_sequence,
            "payload": payload,
        })

    def _check_new_request(self, method: str, request: Any) -> None:
        if (
            request.request_digest in self._seen_digests
            or (method == "create_exact" and self._create_seen)
            or len(self._seen_ids) >= MAX_REQUESTS
            or len(self._pending) >= MAX_PENDING
        ):
            raise _refuse()
        if method == "cancel_exact":
            pending_exec = [
                pending_request.request_digest
                for _sequence, pending_method, pending_request in self._pending.values()
                if pending_method == "exec_exact"
            ]
            if (
                pending_exec != [request.operation_digest]
                or any(pending_method == "cancel_exact" for _sequence, pending_method, _request in self._pending.values())
            ):
                raise _refuse()
        elif self._pending:
            raise _refuse()
        if method != "create_exact" and request.handle is not None:
            key = (request.handle.resource_id, request.handle.resource_digest)
            if key in self._retired:
                raise _refuse()
        if method == "reconcile_create":
            if request.operation_digest != backend.ControlledCreateRequest.create(self.profile).request_digest:
                raise _refuse()
        elif method == "cancel_exact":
            if self._seen_digests.get(request.operation_digest) != "exec_exact":
                raise _refuse()
        if method in {"exec_exact", "begin_write_exact", "persist_exact", "hydrate_exact"}:
            operation_id = request.operation_id
            if operation_id in self._operation_owner:
                raise _refuse()
        if method in {"write_chunk_exact", "commit_write_exact", "reconcile_write_exact", "abort_write_exact"}:
            if self._operation_owner.get(request.operation_id) != "begin_write_exact":
                raise _refuse()
            if self._write_transfer.get(request.operation_id) != request.transfer_id:
                raise _refuse()
            path, size, digest = self._write_meta[request.operation_id]
            if method == "write_chunk_exact":
                if (
                    request.total_size != size
                    or request.content_digest != digest
                    or request.offset != self._write_offset[request.operation_id]
                ):
                    raise _refuse()
            elif method in {"commit_write_exact", "reconcile_write_exact"}:
                if (request.workspace_path, request.content_size, request.content_digest) != (path, size, digest):
                    raise _refuse()
                if method == "commit_write_exact" and self._write_offset[request.operation_id] != size:
                    raise _refuse()

    def _record_request(self, method: str, request: Any) -> None:
        self._seen_digests[request.request_digest] = method
        if method == "create_exact":
            self._create_seen = True
        if method in {"exec_exact", "begin_write_exact", "persist_exact", "hydrate_exact"}:
            self._operation_owner[request.operation_id] = method
        if method == "begin_write_exact":
            self._write_meta[request.operation_id] = (
                request.workspace_path, request.content_size, request.content_digest,
            )

    def _record_receipt(self, method: str, request: Any, receipt: Any) -> None:
        if method == "begin_write_exact":
            self._write_transfer[request.operation_id] = receipt.transfer_id
            self._write_offset[request.operation_id] = 0
        elif method == "write_chunk_exact":
            self._write_offset[request.operation_id] = receipt.next_offset
        elif method == "delete_exact" and receipt.lifecycle == "absent" and receipt.relay_lifecycle == "absent":
            self._retired.add((request.handle.resource_id, request.handle.resource_digest))

    def _receive(self, frame: bytes, now_ns: int, direction: str) -> dict[str, Any]:
        try:
            self._clock(now_ns)
            value = decode_frame(frame)
            if (
                set(value) != _WIRE_KEYS
                or value["protocol_version"] != PROTOCOL_VERSION
                or type(value["binding"]) is not dict
                or canonical_json_bytes(value["binding"]) != self._binding_bytes
                or value["direction"] != direction
                or not _exact_int(value["sequence"], 1, 2**63 - 1)
                or value["sequence"] != self._received_sequence + 1
                or type(value["request_id"]) is not str
                or _HEX32.fullmatch(value["request_id"]) is None
                or type(value["method"]) is not str
                or value["method"] not in METHODS
            ):
                raise _refuse()
            self._received_sequence += 1
            return value
        except ControlledWorkerChannelError:
            self._poisoned = True
            raise


class WorkerChannel(_Channel):
    """Worker-side pure request/response state, allowing exec and cancel in flight."""

    def request(self, method: str, request: Any, *, request_id: str, now_ns: int) -> bytes:
        self._clock(now_ns)
        if type(method) is not str or method not in METHODS or type(request_id) is not str or _HEX32.fullmatch(request_id) is None or request_id in self._seen_ids:
            raise _refuse()
        spec = METHODS[method]
        payload = _payload(request, spec.request_type, spec.request_fields)
        if method != "create_exact" and request.handle is not None and request.handle.opaque_ref is not _INERT_REF:
            raise _refuse()
        _validate_request(method, request, self.profile, self.binding)
        self._check_new_request(method, request)
        sequence = self._sent_sequence + 1
        frame = self._envelope("request", sequence, request_id, method, None, payload)
        self._sent_sequence = sequence
        self._seen_ids.add(request_id)
        self._record_request(method, request)
        self._pending[request_id] = (sequence, method, request)
        return frame

    def response(self, frame: bytes, *, now_ns: int) -> tuple[str, str, Any]:
        value = self._receive(frame, now_ns, "response")
        try:
            request_id = value["request_id"]
            pending = self._pending.get(request_id)
            if (
                pending is None
                or value["method"] != pending[1]
                or not _exact_int(value["reply_to_sequence"], 1, 2**63 - 1)
                or value["reply_to_sequence"] != pending[0]
            ):
                raise _refuse()
            spec = METHODS[pending[1]]
            receipt = _inflate(value["payload"], spec.receipt_type, spec.receipt_fields)
            _validate_receipt(pending[1], receipt, pending[2], self.binding)
            del self._pending[request_id]
            self._record_receipt(pending[1], pending[2], receipt)
            if _ambiguous_receipt(pending[1], receipt):
                self._poisoned = True
            return pending[1], request_id, receipt
        except ControlledWorkerChannelError:
            self._poisoned = True
            raise


class ControllerChannel(_Channel):
    """Controller-side pure join state and original-handle resolver."""

    def __init__(self, profile: backend.ControlledRuntimeProfile, binding: ControlledWorkerBinding) -> None:
        super().__init__(profile, binding)
        self._handles: dict[tuple[str, str], backend.ControlledSandboxHandle] = {}

    def request(self, frame: bytes, *, now_ns: int) -> tuple[str, str, Any]:
        value = self._receive(frame, now_ns, "request")
        try:
            request_id = value["request_id"]
            if request_id in self._seen_ids or value["reply_to_sequence"] is not None:
                raise _refuse()
            method = value["method"]
            spec = METHODS[method]
            request = _inflate(value["payload"], spec.request_type, spec.request_fields, self._handles)
            _validate_request(method, request, self.profile, self.binding)
            self._check_new_request(method, request)
            self._seen_ids.add(request_id)
            self._record_request(method, request)
            self._pending[request_id] = (value["sequence"], method, request)
            return method, request_id, request
        except ControlledWorkerChannelError:
            self._poisoned = True
            raise

    def response(self, request_id: str, receipt: Any, *, now_ns: int) -> bytes:
        self._clock(now_ns)
        try:
            pending = self._pending.get(request_id)
            if pending is None:
                raise _refuse()
            sequence, method, request = pending
            spec = METHODS[method]
            payload = _payload(receipt, spec.receipt_type, spec.receipt_fields)
            _validate_receipt(method, receipt, request, self.binding)
            if method == "create_exact":
                handle = receipt.handle
                key = (handle.resource_id, handle.resource_digest)
                if key in self._handles or handle.opaque_ref is _INERT_REF:
                    raise _refuse()
            response_sequence = self._sent_sequence + 1
            frame = self._envelope("response", response_sequence, request_id, method, sequence, payload)
            if method == "create_exact":
                self._handles[key] = handle
            self._sent_sequence = response_sequence
            del self._pending[request_id]
            self._record_receipt(method, request, receipt)
            if method == "delete_exact" and receipt.lifecycle == "absent" and receipt.relay_lifecycle == "absent":
                self._handles.pop((request.handle.resource_id, request.handle.resource_digest), None)
            if _ambiguous_receipt(method, receipt):
                self._poisoned = True
            return frame
        except ControlledWorkerChannelError:
            self._poisoned = True
            raise


class ControllerDispatcher:
    """Literal dispatch to the controller's fifteen typed methods, without I/O."""

    def __init__(self, channel: ControllerChannel, transport: backend.ControlledControllerTransport) -> None:
        self.channel = channel
        self._calls: Mapping[str, Callable[[Any], Awaitable[Any]]] = MappingProxyType({
            "create_exact": transport.create_exact,
            "reconcile_create": transport.reconcile_create,
            "exec_exact": transport.exec_exact,
            "cancel_exact": transport.cancel_exact,
            "read_exact": transport.read_exact,
            "begin_write_exact": transport.begin_write_exact,
            "write_chunk_exact": transport.write_chunk_exact,
            "commit_write_exact": transport.commit_write_exact,
            "reconcile_write_exact": transport.reconcile_write_exact,
            "abort_write_exact": transport.abort_write_exact,
            "running_exact": transport.running_exact,
            "persist_exact": transport.persist_exact,
            "hydrate_exact": transport.hydrate_exact,
            "resolve_caido_exact": transport.resolve_caido_exact,
            "delete_exact": transport.delete_exact,
        })

    async def dispatch(self, frame: bytes, *, received_ns: int, replied_ns: int) -> bytes:
        try:
            method, request_id, request = self.channel.request(frame, now_ns=received_ns)
            receipt = await self._calls[method](request)
            return self.channel.response(request_id, receipt, now_ns=replied_ns)
        except BaseException:
            self.channel.abandon()
        # Outside the handler, so a caller cannot inspect the original error's
        # context or traceback for controller secrets.
        raise _refuse()
