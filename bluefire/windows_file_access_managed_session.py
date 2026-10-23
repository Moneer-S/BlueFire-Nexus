"""Authenticated live handoff for one protected Windows correction retest.

The durable runner Execute row is the admission record.  This module adds only
the live Ready/acknowledgement handoff needed before the watchdog may create a
one-use Begin.  Setup and native protocol bytes are public evidence; credential
bytes and Begin never enter this channel.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, BinaryIO, Mapping

from .execution_contracts import execution_task_identity
from .util import canonical_json_bytes, content_hash
from .windows_file_access_managed_evidence import (
    READY_CONSUME_FIELDS,
    READY_CONSUME_SCHEMA,
    PersistedManagedCorrectionReady,
)

DESCRIPTOR_SCHEMA = "bluefire.windows-correction-managed-session.v1"
FRAME_SCHEMA = "bluefire.windows-correction-watchdog-frame.v1"
STATUS_SCHEMA = "bluefire.windows-correction-managed-status.v1"
ACK_SCHEMA = "bluefire.windows-correction-managed-ack.v1"
ACTION_ID = "private.windows.file_read_pair_correction.v3"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PUBLIC_BYTES = 256 * 1024
_MAX_FRAME_BYTES = 512 * 1024
_FRAME_HEADER = struct.Struct("!I")
_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema_version",
        "session_nonce",
        "task_id",
        "transport_request_hash",
        "expected_binding",
        "correction_binding",
        "setup_record_b64",
        "setup_receipt_b64",
        "target_descriptor_sha256",
        "packet_b64",
        "packet_issued_at_ms",
    }
)
_ACK_FIELDS = frozenset(
    {
        "schema_version",
        "original_task_id",
        "original_request_hash",
        "session_nonce",
        "packet_digest",
        "ready_digest",
        "ack_nonce",
        "persisted_consume_receipt",
        "persisted_consume_digest",
    }
)
ACK_FIELDS = _ACK_FIELDS


class ManagedCorrectionSessionError(RuntimeError):
    """Path- and secret-free refusal for the fixed managed session."""


def _require(valid: bool) -> None:
    if not valid:
        raise ManagedCorrectionSessionError("Managed Windows correction session is invalid.")


def _milliseconds(value: datetime) -> int:
    _require(isinstance(value, datetime) and value.utcoffset() is not None)
    utc = value.astimezone(timezone.utc)
    delta = utc - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000 + delta.microseconds // 1_000


def _public_bytes(value: Any) -> bytes:
    _require(isinstance(value, str) and 0 < len(value) <= 4 * _MAX_PUBLIC_BYTES)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        ) from None
    _require(0 < len(raw) <= _MAX_PUBLIC_BYTES)
    _require(base64.b64encode(raw).decode("ascii") == value)
    return raw


def public_b64(value: bytes) -> str:
    _require(type(value) is bytes and 0 < len(value) <= _MAX_PUBLIC_BYTES)
    return base64.b64encode(value).decode("ascii")


@dataclass(frozen=True, slots=True, repr=False)
class ManagedCorrectionDescriptor:
    value: Mapping[str, Any] = field(repr=False)
    setup_record: bytes = field(repr=False)
    setup_receipt: bytes = field(repr=False)
    packet: bytes = field(repr=False)
    packet_digest: str
    packet_deadline: float = field(repr=False)

    def __repr__(self) -> str:
        return "ManagedCorrectionDescriptor(public_only=True)"


def expected_binding_from_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    try:
        request = manifest["params"]["windows_file_read_request"]
        fields = (
            "operation_job_id",
            "generation",
            "control_revision",
            "credential_binding_digest",
            "host",
            "resource",
            "correction_binding_digest",
        )
        _require(isinstance(request, dict) and all(name in request for name in fields))
        return {name: request[name] for name in fields}
    except (KeyError, TypeError):
        raise ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        ) from None


def correction_inputs(
    descriptor: ManagedCorrectionDescriptor,
) -> tuple[Any, Any, Any]:
    """Rebuild only exact public v3 inputs; no credential authority is created."""

    from . import windows_file_access_native_wire as wire
    from . import windows_file_access_pair_admission as pair
    from .windows_file_access_correction_contract import CorrectionObservationInput, _validated

    row = descriptor.value
    packet_row = wire._document(descriptor.packet)
    checked_setup = object.__new__(pair.VerifiedWindowsPairSetup)
    object.__setattr__(checked_setup, "_raw", descriptor.setup_record)
    object.__setattr__(checked_setup, "_receipt", descriptor.setup_receipt)
    pair.checked_provenance(checked_setup)
    observation_input = CorrectionObservationInput(
        checked_setup,
        canonical_json_bytes(row["correction_binding"]),
        str(row["target_descriptor_sha256"]),
    )
    _validated(observation_input)
    original = wire.validate_correction_original_reservation(
        {
            "manifest": dict(packet_row["manifest"]),
            "profile": dict(packet_row["profile"]),
            "task_id": row["task_id"],
            "transport_request_hash": row["transport_request_hash"],
        },
        expected_binding=row["expected_binding"],
    )
    packet = wire.PreparedPacket(
        descriptor.packet,
        original,
        descriptor.packet_deadline,
        descriptor.packet_deadline,
    )
    wire.validate_correction_retained_packet(original, packet._raw)
    return observation_input, original, packet


def validate_descriptor(
    value: Any,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    task_id: str | None = None,
    request_hash: str | None = None,
    require_live: bool = True,
) -> ManagedCorrectionDescriptor:
    """Validate the public descriptor against the ordinary Execute identity."""

    try:
        row = dict(value)
    except (TypeError, ValueError):
        raise ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        ) from None
    _require(set(row) == _DESCRIPTOR_FIELDS and row.get("schema_version") == DESCRIPTOR_SCHEMA)
    expected_task, expected_hash = execution_task_identity(manifest, profile)
    checked_task = expected_task if task_id is None else task_id
    checked_hash = expected_hash if request_hash is None else request_hash
    _require(
        manifest.get("action_id") == ACTION_ID
        and checked_task == expected_task == row.get("task_id")
        and checked_hash == expected_hash == row.get("transport_request_hash")
        and _DIGEST.fullmatch(expected_hash) is not None
        and isinstance(row.get("expected_binding"), dict)
        and isinstance(row.get("correction_binding"), dict)
        and _HEX_32.fullmatch(str(row.get("session_nonce"))) is not None
        and _DIGEST.fullmatch(str(row.get("target_descriptor_sha256"))) is not None
    )
    packet_issued_at_ms = row.get("packet_issued_at_ms")
    _require(
        type(packet_issued_at_ms) is int
        and 0 < packet_issued_at_ms < 253_402_300_800_000
    )
    setup_record = _public_bytes(row.get("setup_record_b64"))
    setup_receipt = _public_bytes(row.get("setup_receipt_b64"))
    packet = _public_bytes(row.get("packet_b64"))

    from . import windows_file_access_native_wire as wire

    _require(row["expected_binding"] == expected_binding_from_manifest(manifest))
    wire.validate_correction_original_reservation(
        {
            "manifest": dict(manifest),
            "profile": dict(profile),
            "task_id": expected_task,
            "transport_request_hash": expected_hash,
        },
        expected_binding=row["expected_binding"],
    )
    packet_document = wire._document(packet)
    _require(
        packet_document.get("task_id") == expected_task
        and packet_document.get("request_hash") == expected_hash
    )
    requested_at_ms = _milliseconds(wire._time(manifest["requested_at"]))
    expires_at_ms = _milliseconds(wire._time(manifest["expires_at"]))
    remaining_ms = packet_document.get("remaining_ms")
    now_ms = time.time_ns() // 1_000_000
    _require(
        type(remaining_ms) is int
        and 0 < remaining_ms <= 5_000
        and requested_at_ms <= packet_issued_at_ms < expires_at_ms
        and (not require_live or packet_issued_at_ms <= now_ms < expires_at_ms)
    )
    elapsed_ms = max(0, now_ms - packet_issued_at_ms)
    local_remaining_ms = min(remaining_ms - elapsed_ms, expires_at_ms - now_ms)
    _require(not require_live or local_remaining_ms > 0)
    local_deadline = time.monotonic() + max(0, local_remaining_ms) / 1_000
    descriptor = ManagedCorrectionDescriptor(
        value=row,
        setup_record=setup_record,
        setup_receipt=setup_receipt,
        packet=packet,
        packet_digest=content_hash(packet_document),
        packet_deadline=local_deadline,
    )
    correction_inputs(descriptor)
    return descriptor


def build_descriptor(
    *,
    session_nonce: str,
    task_id: str,
    transport_request_hash: str,
    expected_binding: Mapping[str, Any],
    correction_binding: Mapping[str, Any],
    setup_record: bytes,
    setup_receipt: bytes,
    target_descriptor_sha256: str,
    packet: bytes,
    packet_issued_at_ms: int,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema_version": DESCRIPTOR_SCHEMA,
        "session_nonce": session_nonce,
        "task_id": task_id,
        "transport_request_hash": transport_request_hash,
        "expected_binding": dict(expected_binding),
        "correction_binding": dict(correction_binding),
        "setup_record_b64": public_b64(setup_record),
        "setup_receipt_b64": public_b64(setup_receipt),
        "target_descriptor_sha256": target_descriptor_sha256,
        "packet_b64": public_b64(packet),
        "packet_issued_at_ms": packet_issued_at_ms,
    }
    validate_descriptor(
        row,
        manifest,
        profile,
        task_id=task_id,
        request_hash=transport_request_hash,
    )
    return row


def _consume_receipt_document(
    value: Any,
    *,
    task_id: str,
    request_hash: str,
    session_nonce: str,
    packet_digest: str,
    ready_digest: str,
    ack_nonce: str,
) -> dict[str, Any]:
    try:
        row = dict(value)
    except (TypeError, ValueError):
        raise ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        ) from None
    _require(
        set(row) == READY_CONSUME_FIELDS
        and row.get("schema_version") == READY_CONSUME_SCHEMA
        and row.get("protocol") == "correction_v3"
        and row.get("task_id") == task_id
        and row.get("transport_request_hash") == request_hash
        and row.get("session_nonce") == session_nonce
        and row.get("packet_digest") == packet_digest
        and row.get("ready_digest") == ready_digest
        and row.get("ack_nonce") == ack_nonce
    )
    for name in ("claim_digest", "ready_evidence_digest"):
        _require(_DIGEST.fullmatch(str(row.get(name))) is not None)
    return row


def callback_consume_receipt(
    value: Any,
    descriptor: ManagedCorrectionDescriptor,
    *,
    ready_digest: str,
    ack_nonce: str,
) -> dict[str, Any]:
    """Accept only the exact receipt type minted by the original product store."""

    _require(type(value) is PersistedManagedCorrectionReady)
    return _consume_receipt_document(
        value.document(),
        task_id=str(descriptor.value["task_id"]),
        request_hash=str(descriptor.value["transport_request_hash"]),
        session_nonce=str(descriptor.value["session_nonce"]),
        packet_digest=descriptor.packet_digest,
        ready_digest=ready_digest,
        ack_nonce=ack_nonce,
    )


def _retained_consume_receipt(
    value: Any,
    *,
    task_id: str,
    request_hash: str,
    session_nonce: str,
    packet_digest: str,
    ready_digest: str,
) -> dict[str, Any]:
    try:
        candidate = dict(value)
    except (TypeError, ValueError):
        raise ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        ) from None
    return _consume_receipt_document(
        candidate,
        task_id=task_id,
        request_hash=request_hash,
        session_nonce=session_nonce,
        packet_digest=packet_digest,
        ready_digest=ready_digest,
        ack_nonce=str(candidate.get("ack_nonce")),
    )


def persisted_consume_digest(value: Mapping[str, Any]) -> str:
    return content_hash(dict(value))


def _frame_authentication(key: bytes | bytearray, unsigned: Mapping[str, Any]) -> str:
    _require(type(key) in {bytes, bytearray} and len(key) == 32)
    return "sha256:" + hmac.new(bytes(key), canonical_json_bytes(dict(unsigned)), hashlib.sha256).hexdigest()


def encode_frame(kind: str, payload: Mapping[str, Any], key: bytes | bytearray) -> bytes:
    unsigned = {
        "schema_version": FRAME_SCHEMA,
        "kind": kind,
        "payload": dict(payload),
    }
    frame = {**unsigned, "authentication": _frame_authentication(key, unsigned)}
    raw = canonical_json_bytes(frame)
    _require(0 < len(raw) <= _MAX_FRAME_BYTES)
    return _FRAME_HEADER.pack(len(raw)) + raw


def decode_frame(raw: bytes, *, expected_kind: str, key: bytes | bytearray) -> dict[str, Any]:
    import json

    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_FRAME_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ManagedCorrectionSessionError(
            "Managed Windows correction frame is invalid."
        ) from None
    _require(
        isinstance(value, dict)
        and set(value) == {"schema_version", "kind", "payload", "authentication"}
        and value.get("schema_version") == FRAME_SCHEMA
        and value.get("kind") == expected_kind
        and isinstance(value.get("payload"), dict)
        and isinstance(value.get("authentication"), str)
        and canonical_json_bytes(value) == raw
    )
    unsigned = {key_name: value[key_name] for key_name in ("schema_version", "kind", "payload")}
    _require(hmac.compare_digest(value["authentication"], _frame_authentication(key, unsigned)))
    return dict(value["payload"])


def write_frame(stream: BinaryIO, kind: str, payload: Mapping[str, Any], key: bytes | bytearray) -> None:
    data = memoryview(encode_frame(kind, payload, key))
    while data:
        count = stream.write(data)
        _require(type(count) is int and 0 < count <= len(data))
        data = data[count:]
    stream.flush()


def read_frame(stream: BinaryIO, *, expected_kind: str, key: bytes | bytearray) -> dict[str, Any]:
    def exact(length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            part = stream.read(length - len(data))
            _require(type(part) is bytes and 0 < len(part) <= length - len(data))
            data.extend(part)
        return bytes(data)

    length = _FRAME_HEADER.unpack(exact(_FRAME_HEADER.size))[0]
    _require(0 < length <= _MAX_FRAME_BYTES)
    return decode_frame(exact(length), expected_kind=expected_kind, key=key)


def watchdog_ready_payload(
    descriptor: ManagedCorrectionDescriptor, ready: bytes, ack_nonce: str
) -> dict[str, Any]:
    from . import windows_file_access_native_wire as wire

    _require(type(ready) is bytes and _HEX_32.fullmatch(ack_nonce) is not None)
    _observation, original, packet = correction_inputs(descriptor)
    retained = wire.validate_correction_retained_packet(original, packet._raw)
    wire.validate_correction_ready(retained, ready)
    return {
        "original_task_id": descriptor.value["task_id"],
        "original_request_hash": descriptor.value["transport_request_hash"],
        "session_nonce": descriptor.value["session_nonce"],
        "packet_digest": descriptor.packet_digest,
        "ready_b64": public_b64(ready),
        "ready_digest": content_hash(wire._document(ready)),
        "ack_nonce": ack_nonce,
    }


def validate_watchdog_ready_payload(
    value: Mapping[str, Any], descriptor: ManagedCorrectionDescriptor
) -> tuple[dict[str, Any], bytes]:
    row = dict(value)
    expected_fields = {
        "original_task_id",
        "original_request_hash",
        "session_nonce",
        "packet_digest",
        "ready_b64",
        "ready_digest",
        "ack_nonce",
    }
    ready = _public_bytes(row.get("ready_b64"))
    expected = watchdog_ready_payload(descriptor, ready, str(row.get("ack_nonce")))
    _require(set(row) == expected_fields and row == expected)
    return row, ready


def validate_watchdog_ack(
    value: Mapping[str, Any],
    descriptor: ManagedCorrectionDescriptor,
    ready_payload: Mapping[str, Any],
) -> dict[str, Any]:
    row = dict(value)
    ready_row, _ready = validate_watchdog_ready_payload(ready_payload, descriptor)
    receipt = _consume_receipt_document(
        row.get("persisted_consume_receipt"),
        task_id=str(descriptor.value["task_id"]),
        request_hash=str(descriptor.value["transport_request_hash"]),
        session_nonce=str(descriptor.value["session_nonce"]),
        packet_digest=descriptor.packet_digest,
        ready_digest=str(ready_row["ready_digest"]),
        ack_nonce=str(ready_row["ack_nonce"]),
    )
    _require(
        set(row) == _ACK_FIELDS
        and row.get("schema_version") == ACK_SCHEMA
        and row.get("original_task_id") == descriptor.value["task_id"]
        and row.get("original_request_hash")
        == descriptor.value["transport_request_hash"]
        and row.get("session_nonce") == descriptor.value["session_nonce"]
        and row.get("packet_digest") == descriptor.packet_digest
        and row.get("ready_digest") == ready_row["ready_digest"]
        and row.get("ack_nonce") == ready_row["ack_nonce"]
        and row.get("persisted_consume_digest")
        == persisted_consume_digest(receipt)
    )
    return row


def acknowledgement_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(value)
    _require(set(row) == _ACK_FIELDS and row.get("schema_version") == ACK_SCHEMA)
    return {
        "schema_version": ACK_SCHEMA,
        "original_task_id": row["original_task_id"],
        "original_request_hash": row["original_request_hash"],
        "session_nonce": row["session_nonce"],
        "state": "acknowledged",
        "persisted_consume_digest": row["persisted_consume_digest"],
    }


def validate_acknowledgement_payload(
    value: Mapping[str, Any], acknowledgement: Mapping[str, Any]
) -> dict[str, Any]:
    expected = acknowledgement_payload(acknowledgement)
    row = dict(value)
    _require(row == expected)
    return row


class ManagedCorrectionControl:
    """In-memory live authority; a reconstructed server cannot recreate ack."""

    def __init__(
        self,
        descriptor: ManagedCorrectionDescriptor,
        *,
        enrollment_binding: Mapping[str, str],
    ) -> None:
        self.descriptor = descriptor
        self.enrollment_binding = dict(enrollment_binding)
        self._lock = threading.RLock()
        self._ready_event = threading.Event()
        self._ack_event = threading.Event()
        self._delivered_event = threading.Event()
        self._closed_event = threading.Event()
        self._ready: bytes | None = None
        self._ready_digest: str | None = None
        self._ack_nonce: str | None = None
        self._ack: dict[str, Any] | None = None
        self._failure: str | None = None

    @property
    def task_id(self) -> str:
        return str(self.descriptor.value["task_id"])

    @property
    def request_hash(self) -> str:
        return str(self.descriptor.value["transport_request_hash"])

    @property
    def session_nonce(self) -> str:
        return str(self.descriptor.value["session_nonce"])

    @property
    def deadline(self) -> float:
        return self.descriptor.packet_deadline

    def matches_binding(self, binding: Mapping[str, str]) -> bool:
        return hmac.compare_digest(
            canonical_json_bytes(self.enrollment_binding), canonical_json_bytes(dict(binding))
        )

    def publish_ready(self, ready: bytes, ack_nonce: str) -> None:
        from . import windows_file_access_native_wire as wire

        _require(type(ready) is bytes and _HEX_32.fullmatch(ack_nonce) is not None)
        packet_row = wire._document(self.descriptor.packet)
        original = wire.validate_correction_original_reservation(
            {
                "manifest": dict(packet_row["manifest"]),
                "profile": dict(packet_row["profile"]),
                "task_id": self.task_id,
                "transport_request_hash": self.request_hash,
            },
            expected_binding=self.descriptor.value["expected_binding"],
        )
        retained = wire.validate_correction_retained_packet(original, self.descriptor.packet)
        wire.validate_correction_ready(retained, ready)
        with self._lock:
            _require(self._ready is None and not self._closed_event.is_set())
            self._ready = ready
            self._ready_digest = content_hash(wire._document(ready))
            self._ack_nonce = ack_nonce
            self._ready_event.set()

    def status(self) -> dict[str, Any]:
        with self._lock:
            if self._failure is not None:
                state = "failed"
            elif self._delivered_event.is_set():
                state = "acknowledged"
            elif self._ready is not None:
                state = "ready"
            else:
                state = "waiting_ready"
            row: dict[str, Any] = {
                "schema_version": STATUS_SCHEMA,
                "original_task_id": self.task_id,
                "original_request_hash": self.request_hash,
                "session_nonce": self.session_nonce,
                "state": state,
                "packet_digest": self.descriptor.packet_digest,
            }
            if self._ready is not None and self._failure is None:
                row.update(
                    {
                        "ready_b64": public_b64(self._ready),
                        "ready_digest": self._ready_digest,
                        "ack_nonce": self._ack_nonce,
                    }
                )
            if self._failure is not None:
                row["failure"] = self._failure
            return row

    def register_ack(self, value: Mapping[str, Any]) -> dict[str, Any]:
        row = dict(value)
        with self._lock:
            receipt = _consume_receipt_document(
                row.get("persisted_consume_receipt"),
                task_id=self.task_id,
                request_hash=self.request_hash,
                session_nonce=self.session_nonce,
                packet_digest=self.descriptor.packet_digest,
                ready_digest=str(self._ready_digest),
                ack_nonce=str(self._ack_nonce),
            )
            _require(
                set(row) == _ACK_FIELDS
                and row.get("schema_version") == ACK_SCHEMA
                and row.get("original_task_id") == self.task_id
                and row.get("original_request_hash") == self.request_hash
                and row.get("session_nonce") == self.session_nonce
                and row.get("packet_digest") == self.descriptor.packet_digest
                and row.get("ready_digest") == self._ready_digest
                and row.get("ack_nonce") == self._ack_nonce
                and isinstance(row.get("persisted_consume_digest"), str)
                and row["persisted_consume_digest"]
                == persisted_consume_digest(receipt)
                and self._ready is not None
                and self._ack is None
                and not self._closed_event.is_set()
            )
            self._ack = row
            self._ack_event.set()
            return dict(row)

    def wait_delivered(self, acknowledgement: Mapping[str, Any]) -> dict[str, Any]:
        row = dict(acknowledgement)
        with self._lock:
            _require(self._ack is not None and row == self._ack)
        while not self._delivered_event.wait(0.01):
            _require(not self._closed_event.is_set() and time.monotonic() < self.deadline)
        return {
            "schema_version": ACK_SCHEMA,
            "original_task_id": self.task_id,
            "original_request_hash": self.request_hash,
            "session_nonce": self.session_nonce,
            "state": "acknowledged",
            "persisted_consume_digest": row["persisted_consume_digest"],
        }

    def accept_ack(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return self.wait_delivered(self.register_ack(value))

    def wait_ack(self, cancel_event: threading.Event) -> dict[str, Any]:
        while not self._ack_event.wait(0.01):
            _require(
                not cancel_event.is_set()
                and not self._closed_event.is_set()
                and time.monotonic() < self.deadline
            )
        with self._lock:
            _require(
                self._ack is not None
                and not cancel_event.is_set()
                and not self._closed_event.is_set()
            )
            return dict(self._ack)

    def mark_delivered(self, acknowledgement: Mapping[str, Any]) -> None:
        row = dict(acknowledgement)
        with self._lock:
            _require(self._ack is not None and row == self._ack)
            self._delivered_event.set()

    def fail(self, reason: str) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = reason[:128]
            self._closed_event.set()

    def close(self) -> None:
        self._closed_event.set()


def new_ack_nonce() -> str:
    return secrets.token_hex(32)


def validate_status(
    value: Mapping[str, Any], descriptor: ManagedCorrectionDescriptor
) -> dict[str, Any]:
    row = dict(value)
    common = {
        "schema_version",
        "original_task_id",
        "original_request_hash",
        "session_nonce",
        "state",
        "packet_digest",
    }
    _require(
        row.get("schema_version") == STATUS_SCHEMA
        and row.get("original_task_id") == descriptor.value["task_id"]
        and row.get("original_request_hash")
        == descriptor.value["transport_request_hash"]
        and row.get("session_nonce") == descriptor.value["session_nonce"]
        and row.get("packet_digest") == descriptor.packet_digest
        and row.get("state") in {"waiting_ready", "ready", "acknowledged", "failed"}
    )
    if row["state"] == "waiting_ready":
        _require(set(row) == common)
    elif row["state"] in {"ready", "acknowledged"}:
        _require(set(row) == common | {"ready_b64", "ready_digest", "ack_nonce"})
        ready = _public_bytes(row["ready_b64"])
        from . import windows_file_access_native_wire as wire

        _require(
            content_hash(wire._document(ready)) == row.get("ready_digest")
            and _DIGEST.fullmatch(str(row.get("ready_digest"))) is not None
            and _HEX_32.fullmatch(str(row.get("ack_nonce"))) is not None
        )
    else:
        _require(set(row) == common | {"failure"} and isinstance(row.get("failure"), str))
    return row


def validate_ack_response(
    value: Mapping[str, Any],
    descriptor: ManagedCorrectionDescriptor,
    consume_digest: str,
) -> dict[str, Any]:
    row = dict(value)
    _require(
        set(row)
        == {
            "schema_version",
            "original_task_id",
            "original_request_hash",
            "session_nonce",
            "state",
            "persisted_consume_digest",
        }
        and row.get("schema_version") == ACK_SCHEMA
        and row.get("original_task_id") == descriptor.value["task_id"]
        and row.get("original_request_hash")
        == descriptor.value["transport_request_hash"]
        and row.get("session_nonce") == descriptor.value["session_nonce"]
        and row.get("state") == "acknowledged"
        and row.get("persisted_consume_digest") == consume_digest
    )
    return row


def ready_bytes_from_status(
    value: Mapping[str, Any], descriptor: ManagedCorrectionDescriptor
) -> bytes:
    row = validate_status(value, descriptor)
    _require(row["state"] in {"ready", "acknowledged"})
    return _public_bytes(row["ready_b64"])


def ready_consume_identity(
    value: Mapping[str, Any], descriptor: ManagedCorrectionDescriptor
) -> dict[str, Any]:
    row = validate_status(value, descriptor)
    _require(row["state"] == "ready")
    return {
        "task_id": descriptor.value["task_id"],
        "transport_request_hash": descriptor.value["transport_request_hash"],
        "session_nonce": descriptor.value["session_nonce"],
        "packet_digest": descriptor.packet_digest,
        "ready_digest": row["ready_digest"],
        "ack_nonce": row["ack_nonce"],
    }
