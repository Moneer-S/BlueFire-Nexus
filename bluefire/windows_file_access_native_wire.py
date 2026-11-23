"""Pure native-reader wire adapter; no execution, credentials or Job authority.

Hashes establish consistency only. Trusted admission supplies expected bindings
and original deadlines. Historical parsing never enables replay or settlement.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._windows_file_access_native_contract import (
    _CORRECTION,
    _PAIR,
    _V1,
    ACTION,
    BEGIN_MAX,
    CAPABILITY,
    ERROR_CODES,
    ERROR_SCHEMA,
    ISSUES,
    PROOF_SCHEMA,
    PUBLIC_MAX,
    READY_MAX,
    READY_SCHEMA,
    REQUEST_SCHEMA,
    RESULT_SCHEMA,
    STAGES,
    TERMINAL_MAX,
    NativeWireError,
    _clock,
    _document,
    _exact,
    _hex,
    _int,
    _mono,
    _original,
    _Protocol,
    _require,
    _same,
    _time,
)
from ._windows_file_access_pair_proof import pair_proof, reader_phase
from .util import canonical_json_bytes, content_hash

__all__ = (
    "ACTION",
    "CAPABILITY",
    "PUBLIC_MAX",
    "BEGIN_MAX",
    "NativeWireError",
    "OriginalReservation",
    "RetainedPacket",
    "PreparedPacket",
    "NativeProjection",
    "validate_original_reservation",
    "validate_retained_packet",
    "prepare_packet",
    "validate_ready",
    "begin_prefix",
    "public_frame",
    "validate_terminal",
    "ERROR_SCHEMA",
    "READY_SCHEMA",
    "REQUEST_SCHEMA",
    "RESULT_SCHEMA",
    "PROOF_SCHEMA",
    "ISSUES",
    "STAGES",
    "PairNativeProjection",
    "PAIR_ACTION",
    "PAIR_CAPABILITY",
    "validate_pair_original_reservation",
    "validate_pair_retained_packet",
    "prepare_pair_packet",
    "pair_public_frame",
    "validate_pair_ready",
    "pair_begin_prefix",
    "validate_pair_terminal",
    "CORRECTION_ACTION",
    "CORRECTION_CAPABILITY",
    "validate_correction_original_reservation",
    "validate_correction_retained_packet",
    "prepare_correction_packet",
    "correction_public_frame",
    "validate_correction_ready",
    "correction_begin_prefix",
    "validate_correction_terminal",
)

PAIR_ACTION, PAIR_CAPABILITY = _PAIR.action, _PAIR.capability
CORRECTION_ACTION, CORRECTION_CAPABILITY = _CORRECTION.action, _CORRECTION.capability


@dataclass(frozen=True, slots=True)
class OriginalReservation:
    _raw: bytes = field(repr=False)
    _expected: bytes = field(repr=False)
    _protocol: _Protocol = field(default=_V1, repr=False, kw_only=True)

    def __post_init__(self) -> None:
        _require(type(self._raw) is bytes and type(self._expected) is bytes)
        _original(self._raw, self._expected, protocol=self._protocol)


@dataclass(frozen=True, slots=True)
class RetainedPacket:
    _raw: bytes = field(repr=False)
    _original: OriginalReservation = field(repr=False)

    def __post_init__(self) -> None:
        _require(type(self._raw) is bytes)
        _retained(self._original, self._raw)


@dataclass(frozen=True, slots=True)
class PreparedPacket:
    _raw: bytes = field(repr=False)
    _original: OriginalReservation = field(repr=False)
    _deadline: float
    _original_deadline: float

    def __post_init__(self) -> None:
        _require(type(self._raw) is bytes)
        _retained(self._original, self._raw)
        _require(_mono(self._deadline) <= _mono(self._original_deadline))


@dataclass(frozen=True, slots=True)
class NativeProjection:
    _terminal: bytes = field(repr=False)
    outcome: str
    observation_complete: bool
    local_cleanup: str
    settled: bool = field(default=False, init=False)
    owned_job_cleanup: str = field(default="unverified", init=False)
    independent_observation: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _require(type(self._terminal) is bytes and type(self.observation_complete) is bool)
        _document(self._terminal, TERMINAL_MAX)
        _require(
            self.outcome in ("allowed", "data_access_denied", "unknown")
            and self.local_cleanup in ("verified", "unknown")
        )
        _require(self.observation_complete == (self.outcome != "unknown"))


@dataclass(frozen=True, slots=True)
class PairNativeProjection(NativeProjection):
    reader_outcome: str | None
    owner_outcome: str | None

    def __post_init__(self) -> None:
        NativeProjection.__post_init__(self)
        for outcome in (self.reader_outcome, self.owner_outcome):
            _require(outcome in (None, "allowed", "data_access_denied", "unknown"))
        _require(
            not self.observation_complete
            or (self.reader_outcome == self.outcome and self.owner_outcome == "allowed")
        )


def validate_original_reservation(
    original_context: Any, *, expected_binding: Any
) -> OriginalReservation:
    context, expected = _original(original_context, expected_binding)
    return OriginalReservation(canonical_json_bytes(context), canonical_json_bytes(expected))


def _reservation(value: OriginalReservation, protocol: _Protocol = _V1) -> dict[str, Any]:
    _require(type(value) is OriginalReservation and value._protocol is protocol)
    return _original(value._raw, value._expected, protocol=protocol)[0]


def _retained(original: OriginalReservation, public_bytes: bytes) -> dict[str, Any]:
    _require(type(public_bytes) is bytes)
    _require(type(original) is OriginalReservation)
    context, row = _reservation(original, original._protocol), _document(public_bytes)
    _exact(row, "schema_version challenge task_id request_hash manifest profile remaining_ms")
    _require(row["schema_version"] == original._protocol.schema("request"))
    _hex(row["challenge"], 64)
    _require(
        _same(row["manifest"], context["manifest"])
        and _same(row["profile"], context["profile"])
        and row["task_id"] == context["task_id"]
        and row["request_hash"] == context["transport_request_hash"]
    )
    _int(row["remaining_ms"], 1, context["manifest"]["limits"]["timeout_ms"])
    return row


def validate_retained_packet(original: OriginalReservation, public_bytes: bytes) -> RetainedPacket:
    _reservation(original)
    return _validate_retained_packet(original, public_bytes)


def _validate_retained_packet(original: OriginalReservation, public_bytes: bytes) -> RetainedPacket:
    return RetainedPacket(canonical_json_bytes(_retained(original, public_bytes)), original)


def prepare_packet(
    original: OriginalReservation,
    *,
    challenge: str,
    clock: datetime,
    monotonic_now: float,
    original_monotonic_deadline: float,
) -> PreparedPacket:
    _reservation(original)
    return _prepare_packet(
        original,
        challenge=challenge,
        clock=clock,
        monotonic_now=monotonic_now,
        original_monotonic_deadline=original_monotonic_deadline,
    )


def _prepare_packet(
    original: OriginalReservation,
    *,
    challenge: str,
    clock: datetime,
    monotonic_now: float,
    original_monotonic_deadline: float,
) -> PreparedPacket:
    context, now, mono, deadline = (
        _reservation(original, original._protocol),
        _clock(clock),
        _mono(monotonic_now),
        _mono(original_monotonic_deadline),
    )
    manifest = context["manifest"]
    _require(
        _time(manifest["requested_at"]) <= now < _time(manifest["expires_at"]) and mono < deadline
    )
    delta = _time(manifest["expires_at"]) - now
    wall_ms = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
    remaining = min(5000, manifest["limits"]["timeout_ms"], wall_ms, int((deadline - mono) * 1000))
    _int(remaining, 1, 5000)
    row = {
        "schema_version": original._protocol.schema("request"),
        "challenge": _hex(challenge, 64),
        "task_id": context["task_id"],
        "request_hash": context["transport_request_hash"],
        "manifest": manifest,
        "profile": context["profile"],
        "remaining_ms": remaining,
    }
    retained = _validate_retained_packet(original, canonical_json_bytes(row))
    return PreparedPacket(retained._raw, original, min(deadline, mono + remaining / 1000), deadline)


def _prepared(packet: PreparedPacket, clock: datetime, monotonic_now: float) -> RetainedPacket:
    _require(type(packet) is PreparedPacket)
    retained = _validate_retained_packet(packet._original, packet._raw)
    row, now, mono = _document(retained._raw), _clock(clock), _mono(monotonic_now)
    _require(_time(row["manifest"]["requested_at"]) <= now < _time(row["manifest"]["expires_at"]))
    _require(mono < _mono(packet._deadline) <= _mono(packet._original_deadline))
    return retained


def public_frame(packet: PreparedPacket, *, clock: datetime, monotonic_now: float) -> bytes:
    _require(type(packet) is PreparedPacket)
    _reservation(packet._original)
    return _public_frame(packet, clock=clock, monotonic_now=monotonic_now)


def _public_frame(packet: PreparedPacket, *, clock: datetime, monotonic_now: float) -> bytes:
    raw = _prepared(packet, clock, monotonic_now)._raw
    return struct.pack("<I", len(raw)) + raw


def _binding(packet: RetainedPacket) -> dict[str, Any]:
    _require(type(packet) is RetainedPacket)
    row = _document(packet._raw)
    request = row["manifest"]["params"]["windows_file_read_request"]
    keys: tuple[str, ...] = ("generation", "control_revision", "credential_binding_digest")
    if packet._original._protocol is _CORRECTION:
        keys += ("correction_binding_digest",)
    return {
        "challenge": row["challenge"],
        "packet_digest": content_hash(row),
        "task_id": row["task_id"],
        "request_hash": row["request_hash"],
        **{key: request[key] for key in keys},
    }


def validate_ready(packet: RetainedPacket, ready_bytes: bytes) -> None:
    _require(type(packet) is RetainedPacket)
    _reservation(packet._original)
    _validate_ready(packet, ready_bytes)


def _validate_ready(packet: RetainedPacket, ready_bytes: bytes) -> None:
    _require(type(packet) is RetainedPacket and type(ready_bytes) is bytes)
    _retained(packet._original, packet._raw)
    row = _document(ready_bytes, READY_MAX)
    _require(
        _same(
            row,
            dict(
                _binding(packet),
                schema_version=packet._original._protocol.schema("ready"),
                readiness_scope="protocol_only",
            ),
        )
    )


def begin_prefix(packet: PreparedPacket, *, clock: datetime, monotonic_now: float) -> bytearray:
    _require(type(packet) is PreparedPacket)
    _reservation(packet._original)
    return _begin_prefix(packet, clock=clock, monotonic_now=monotonic_now)


def _begin_prefix(packet: PreparedPacket, *, clock: datetime, monotonic_now: float) -> bytearray:
    binding = _binding(_prepared(packet, clock, monotonic_now))
    prefix = (
        bytearray(packet._original._protocol.magic)
        + bytearray.fromhex(binding["challenge"])
        + bytearray.fromhex(binding["packet_digest"][7:])
        + bytearray.fromhex(binding["generation"])
        + bytearray(struct.pack("<I", binding["control_revision"]))
        + bytearray.fromhex(binding["credential_binding_digest"][7:])
    )
    if packet._original._protocol is _CORRECTION:
        prefix += bytearray.fromhex(binding["correction_binding_digest"][7:])
    return prefix


def _proof(row: Any, request: dict[str, Any], returncode: int) -> tuple[str, bool, str]:
    outcome, clean = reader_phase(row, request)
    _require(returncode == (4 if outcome == "unknown" else 0))
    return outcome, outcome != "unknown", "verified" if clean else "unknown"


def validate_terminal(
    original: OriginalReservation,
    retained_packet: RetainedPacket,
    ready_bytes: bytes,
    terminal_bytes: bytes,
    *,
    clock: datetime,
    returncode: int,
) -> NativeProjection:
    _reservation(original)
    return NativeProjection(
        *_terminal(
            original,
            retained_packet,
            ready_bytes,
            terminal_bytes,
            clock=clock,
            returncode=returncode,
        )[:4]
    )


def _terminal(
    original: OriginalReservation,
    retained_packet: RetainedPacket,
    ready_bytes: bytes,
    terminal_bytes: bytes,
    *,
    clock: datetime,
    returncode: int,
) -> tuple[bytes, str, bool, str, str | None, str | None]:
    _require(
        type(retained_packet) is RetainedPacket
        and type(ready_bytes) is bytes
        and type(terminal_bytes) is bytes
    )
    protocol = original._protocol
    packet = _validate_retained_packet(original, retained_packet._raw)
    context, now = _reservation(original, protocol), _clock(clock)
    _validate_ready(packet, ready_bytes)
    _require(
        len(ready_bytes) + len(terminal_bytes) + 8
        <= context["manifest"]["limits"]["max_stdout_bytes"]
    )
    row = _document(terminal_bytes, TERMINAL_MAX)
    _exact(
        row,
        "schema_version challenge packet_digest task_id request_hash generation control_revision credential_binding_digest operation observed_at result"
        + (" correction_binding_digest" if protocol is _CORRECTION else ""),
    )
    _require(
        _same({key: row[key] for key in _binding(packet)}, _binding(packet))
        and row["schema_version"] == protocol.schema("result")
        and row["operation"] == protocol.operation
    )
    _int(returncode, 0, 4)
    observed = row["observed_at"]
    if observed is not None:
        observed = _time(observed, canonical=True)
        _require(
            _time(context["manifest"]["requested_at"])
            <= observed
            < _time(context["manifest"]["expires_at"])
            and observed <= now
        )
    result = row["result"]
    _require(type(result) is dict)
    reader_outcome = owner_outcome = None
    if result.get("schema_version") == protocol.schema("error"):
        _exact(result, "schema_version code possible_effects")
        _require(
            returncode == 4
            and type(result["code"]) is str
            and result["code"] in ERROR_CODES
            and type(result["possible_effects"]) is bool
        )
        outcome, complete, cleanup = "unknown", False, "unknown"
    else:
        _require(
            observed is not None or (protocol is not _V1 and result.get("outcome") == "unknown")
        )
        request = context["manifest"]["params"]["windows_file_read_request"]
        if protocol is not _V1:
            outcome, complete, cleanup, reader_outcome, owner_outcome = pair_proof(
                result, request, returncode, protocol=protocol
            )
        else:
            outcome, complete, cleanup = _proof(result, request, returncode)
    return canonical_json_bytes(row), outcome, complete, cleanup, reader_outcome, owner_outcome


def validate_pair_original_reservation(
    original_context: Any, *, expected_binding: Any
) -> OriginalReservation:
    """Require an independently retained original pair-v2 claim and binding.

    This is not enrollment admission: upstream must establish actual protected
    v2 provenance/read budget. A v1 max_reads:1 enrollment is never upgraded.
    """
    context, expected = _original(original_context, expected_binding, protocol=_PAIR)
    return OriginalReservation(
        canonical_json_bytes(context), canonical_json_bytes(expected), _protocol=_PAIR
    )


def validate_pair_retained_packet(
    original: OriginalReservation, public_bytes: bytes
) -> RetainedPacket:
    _reservation(original, _PAIR)
    return _validate_retained_packet(original, public_bytes)


def prepare_pair_packet(
    original: OriginalReservation,
    *,
    challenge: str,
    clock: datetime,
    monotonic_now: float,
    original_monotonic_deadline: float,
) -> PreparedPacket:
    _reservation(original, _PAIR)
    return _prepare_packet(
        original,
        challenge=challenge,
        clock=clock,
        monotonic_now=monotonic_now,
        original_monotonic_deadline=original_monotonic_deadline,
    )


def pair_public_frame(packet: PreparedPacket, *, clock: datetime, monotonic_now: float) -> bytes:
    _require(type(packet) is PreparedPacket)
    _reservation(packet._original, _PAIR)
    return _public_frame(packet, clock=clock, monotonic_now=monotonic_now)


def validate_pair_ready(packet: RetainedPacket, ready_bytes: bytes) -> None:
    _require(type(packet) is RetainedPacket)
    _reservation(packet._original, _PAIR)
    _validate_ready(packet, ready_bytes)


def pair_begin_prefix(
    packet: PreparedPacket, *, clock: datetime, monotonic_now: float
) -> bytearray:
    _require(type(packet) is PreparedPacket)
    _reservation(packet._original, _PAIR)
    return _begin_prefix(packet, clock=clock, monotonic_now=monotonic_now)


def validate_pair_terminal(
    original: OriginalReservation,
    retained_packet: RetainedPacket,
    ready_bytes: bytes,
    terminal_bytes: bytes,
    *,
    clock: datetime,
    returncode: int,
) -> PairNativeProjection:
    _reservation(original, _PAIR)
    return PairNativeProjection(
        *_terminal(
            original,
            retained_packet,
            ready_bytes,
            terminal_bytes,
            clock=clock,
            returncode=returncode,
        )
    )


def validate_correction_original_reservation(
    original_context: Any, *, expected_binding: Any
) -> OriginalReservation:
    """Bind an upstream-authorized correction claim, not authenticate its source.

    The opaque correction digest must come from durable correction admission;
    its presence proves consistency only, never correction causation or authority.
    """
    context, expected = _original(original_context, expected_binding, protocol=_CORRECTION)
    return OriginalReservation(
        canonical_json_bytes(context), canonical_json_bytes(expected), _protocol=_CORRECTION
    )


def validate_correction_retained_packet(
    original: OriginalReservation, public_bytes: bytes
) -> RetainedPacket:
    _reservation(original, _CORRECTION)
    return _validate_retained_packet(original, public_bytes)


def prepare_correction_packet(
    original: OriginalReservation,
    *,
    challenge: str,
    clock: datetime,
    monotonic_now: float,
    original_monotonic_deadline: float,
) -> PreparedPacket:
    _reservation(original, _CORRECTION)
    return _prepare_packet(
        original,
        challenge=challenge,
        clock=clock,
        monotonic_now=monotonic_now,
        original_monotonic_deadline=original_monotonic_deadline,
    )


def correction_public_frame(
    packet: PreparedPacket, *, clock: datetime, monotonic_now: float
) -> bytes:
    _require(type(packet) is PreparedPacket)
    _reservation(packet._original, _CORRECTION)
    return _public_frame(packet, clock=clock, monotonic_now=monotonic_now)


def validate_correction_ready(packet: RetainedPacket, ready_bytes: bytes) -> None:
    _require(type(packet) is RetainedPacket)
    _reservation(packet._original, _CORRECTION)
    _validate_ready(packet, ready_bytes)


def correction_begin_prefix(
    packet: PreparedPacket, *, clock: datetime, monotonic_now: float
) -> bytearray:
    _require(type(packet) is PreparedPacket)
    _reservation(packet._original, _CORRECTION)
    return _begin_prefix(packet, clock=clock, monotonic_now=monotonic_now)


def validate_correction_terminal(
    original: OriginalReservation,
    retained_packet: RetainedPacket,
    ready_bytes: bytes,
    terminal_bytes: bytes,
    *,
    clock: datetime,
    returncode: int,
) -> PairNativeProjection:
    _reservation(original, _CORRECTION)
    return PairNativeProjection(
        *_terminal(
            original,
            retained_packet,
            ready_bytes,
            terminal_bytes,
            clock=clock,
            returncode=returncode,
        )
    )
