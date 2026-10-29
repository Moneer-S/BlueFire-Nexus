"""Authenticated terminal and cleanup result for one managed correction session."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from . import windows_file_access_managed_session as session
from . import windows_file_access_native_wire as wire
from ._windows_file_access_cleanup_proof import validate_retained_cleanup
from .execution_contracts import execution_task_identity
from .util import canonical_json_bytes, content_hash
from .windows_file_access_managed_evidence import (
    MANAGED_CORRECTION_LINEAGE_SCHEMA,
    AuthenticatedManagedCorrectionClosure,
)

RESULT_SCHEMA = "bluefire.windows-correction-managed-result.v1"
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "state",
        "session_nonce",
        "task_id",
        "transport_request_hash",
        "packet_b64",
        "packet_digest",
        "ready_b64",
        "ready_digest",
        "terminal_b64",
        "terminal_digest",
        "actual_returncode",
        "persisted_consume_receipt",
        "persisted_consume_digest",
        "cleanup_receipt_b64",
        "cleanup_receipt_digest",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedManagedCorrectionResult:
    """Exact validated public terminal and owned cleanup from the watchdog."""

    value: Mapping[str, Any] = field(repr=False)
    packet: bytes = field(repr=False)
    ready: bytes = field(repr=False)
    terminal: bytes = field(repr=False)
    cleanup_receipt: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "AuthenticatedManagedCorrectionResult(closed=True)"


def build_managed_result(
    descriptor: session.ManagedCorrectionDescriptor,
    *,
    ready: bytes,
    terminal: bytes,
    actual_returncode: int,
    persisted_consume_receipt: Mapping[str, Any],
    cleanup_receipt: bytes,
) -> dict[str, Any]:
    """Build the public durable closure after exact terminal and owned cleanup."""

    _observation, original, packet = session.correction_inputs(descriptor)
    retained = wire.validate_correction_retained_packet(original, packet._raw)
    wire.validate_correction_ready(retained, ready)
    wire.validate_correction_terminal(
        original,
        retained,
        ready,
        terminal,
        clock=datetime.now(timezone.utc),
        returncode=actual_returncode,
    )
    proof = validate_retained_cleanup(cleanup_receipt, descriptor.packet)
    ready_digest = content_hash(wire._document(ready))
    terminal_digest = content_hash(wire._document(terminal))
    consume_receipt = session._retained_consume_receipt(
        persisted_consume_receipt,
        task_id=str(descriptor.value["task_id"]),
        request_hash=str(descriptor.value["transport_request_hash"]),
        session_nonce=str(descriptor.value["session_nonce"]),
        packet_digest=descriptor.packet_digest,
        ready_digest=ready_digest,
    )
    session._require(
        proof["protocol"] == "correction_v3"
        and proof["task_id"] == descriptor.value["task_id"]
        and proof["transport_request_hash"] == descriptor.value["transport_request_hash"]
        and proof["packet_digest"] == descriptor.packet_digest
        and proof["supported_terminal_returncode"] == actual_returncode
    )
    return {
        "schema_version": RESULT_SCHEMA,
        "state": "closed",
        "session_nonce": descriptor.value["session_nonce"],
        "task_id": descriptor.value["task_id"],
        "transport_request_hash": descriptor.value["transport_request_hash"],
        "packet_b64": session.public_b64(descriptor.packet),
        "packet_digest": descriptor.packet_digest,
        "ready_b64": session.public_b64(ready),
        "ready_digest": ready_digest,
        "terminal_b64": session.public_b64(terminal),
        "terminal_digest": terminal_digest,
        "actual_returncode": actual_returncode,
        "persisted_consume_receipt": consume_receipt,
        "persisted_consume_digest": session.persisted_consume_digest(consume_receipt),
        "cleanup_receipt_b64": session.public_b64(cleanup_receipt),
        "cleanup_receipt_digest": content_hash(proof),
    }


def validate_managed_result(
    value: Mapping[str, Any],
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    expected_packet: bytes | None = None,
    expected_session_nonce: str | None = None,
) -> AuthenticatedManagedCorrectionResult:
    row = dict(value)
    session._require(
        set(row) == _RESULT_FIELDS
        and row.get("schema_version") == RESULT_SCHEMA
        and row.get("state") == "closed"
        and session._HEX_32.fullmatch(str(row.get("session_nonce"))) is not None
        and (expected_session_nonce is None or row["session_nonce"] == expected_session_nonce)
    )
    task_id, request_hash = execution_task_identity(manifest, profile)
    session._require(
        manifest.get("action_id") == session.ACTION_ID
        and row.get("task_id") == task_id
        and row.get("transport_request_hash") == request_hash
    )
    packet = session._public_bytes(row.get("packet_b64"))
    ready = session._public_bytes(row.get("ready_b64"))
    terminal = session._public_bytes(row.get("terminal_b64"))
    cleanup_receipt = session._public_bytes(row.get("cleanup_receipt_b64"))
    session._require(expected_packet is None or packet == expected_packet)
    original = wire.validate_correction_original_reservation(
        {
            "manifest": dict(manifest),
            "profile": dict(profile),
            "task_id": task_id,
            "transport_request_hash": request_hash,
        },
        expected_binding=session.expected_binding_from_manifest(manifest),
    )
    retained = wire.validate_correction_retained_packet(original, packet)
    wire.validate_correction_ready(retained, ready)
    actual_returncode = row.get("actual_returncode")
    if type(actual_returncode) is not int:
        raise session.ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        )
    session._require(actual_returncode in (0, 4))
    wire.validate_correction_terminal(
        original,
        retained,
        ready,
        terminal,
        clock=datetime.now(timezone.utc),
        returncode=actual_returncode,
    )
    proof = validate_retained_cleanup(cleanup_receipt, packet)
    ready_digest = content_hash(wire._document(ready))
    terminal_digest = content_hash(wire._document(terminal))
    packet_digest = content_hash(wire._document(packet))
    consume_receipt = session._retained_consume_receipt(
        row.get("persisted_consume_receipt"),
        task_id=task_id,
        request_hash=request_hash,
        session_nonce=str(row["session_nonce"]),
        packet_digest=packet_digest,
        ready_digest=ready_digest,
    )
    session._require(
        row.get("packet_digest") == packet_digest == proof["packet_digest"]
        and row.get("ready_digest") == ready_digest
        and row.get("terminal_digest") == terminal_digest
        and row.get("cleanup_receipt_digest") == content_hash(proof)
        and proof["protocol"] == "correction_v3"
        and proof["task_id"] == task_id
        and proof["transport_request_hash"] == request_hash
        and proof["supported_terminal_returncode"] == actual_returncode
        and row.get("persisted_consume_digest") == session.persisted_consume_digest(consume_receipt)
    )
    return AuthenticatedManagedCorrectionResult(
        value=row,
        packet=packet,
        ready=ready,
        terminal=terminal,
        cleanup_receipt=cleanup_receipt,
    )


def build_runner_result(
    descriptor: session.ManagedCorrectionDescriptor,
    managed_result: Mapping[str, Any],
    *,
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, Any]:
    packet_row = wire._document(descriptor.packet)
    manifest, profile = packet_row["manifest"], packet_row["profile"]
    validate_managed_result(
        managed_result,
        manifest,
        profile,
        expected_packet=descriptor.packet,
        expected_session_nonce=str(descriptor.value["session_nonce"]),
    )

    def timestamp(value: datetime) -> str:
        session._require(value.utcoffset() is not None)
        return (
            value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )

    return {
        "schema_version": "bluefire.runner-result.v1",
        "request_id": manifest["request_id"],
        "run_id": manifest["run_id"],
        "step_id": manifest["step_id"],
        "behavior_id": manifest["behavior_id"],
        "action_id": manifest["action_id"],
        "status": "success",
        "runner_id": manifest["runner_id"],
        "runner_profile_id": manifest["runner_profile_id"],
        "platform": manifest["platform"],
        "request_hash": manifest["request_hash"],
        "policy_digest": profile["policy_digest"],
        "started_at": timestamp(started_at),
        "finished_at": timestamp(finished_at),
        "output": {"windows_correction": dict(managed_result)},
        "stdout": {"text": "", "total_bytes": 0, "truncated": False},
        "stderr": {"text": "", "total_bytes": 0, "truncated": False},
        "receipt_ids": [],
        "cleanup": None,
        "evidence": [],
        "error": None,
        "limitations": ["managed correction watchdog closure"],
    }


def validate_runner_result(
    result: Mapping[str, Any],
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    expected_packet: bytes | None = None,
    expected_session_nonce: str | None = None,
) -> AuthenticatedManagedCorrectionResult:
    output = result.get("output")
    if not isinstance(output, dict) or set(output) != {"windows_correction"}:
        raise session.ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        )
    managed = output.get("windows_correction")
    if not isinstance(managed, dict):
        raise session.ManagedCorrectionSessionError(
            "Managed Windows correction session is invalid."
        )
    return validate_managed_result(
        managed,
        manifest,
        profile,
        expected_packet=expected_packet,
        expected_session_nonce=expected_session_nonce,
    )


def native_closure(
    result: AuthenticatedManagedCorrectionResult, *, claim_digest: str
) -> AuthenticatedManagedCorrectionClosure:
    """Convert an authenticated result to the exact durable-store handoff type."""

    session._require(type(result) is AuthenticatedManagedCorrectionResult)
    session._require(session._DIGEST.fullmatch(claim_digest) is not None)
    value = result.value
    consume = session._retained_consume_receipt(
        value["persisted_consume_receipt"],
        task_id=str(value["task_id"]),
        request_hash=str(value["transport_request_hash"]),
        session_nonce=str(value["session_nonce"]),
        packet_digest=str(value["packet_digest"]),
        ready_digest=str(value["ready_digest"]),
    )
    lineage = {
        "schema_version": MANAGED_CORRECTION_LINEAGE_SCHEMA,
        "protocol": "correction_v3",
        "task_id": value["task_id"],
        "transport_request_hash": value["transport_request_hash"],
        "claim_digest": claim_digest,
        "packet_digest": value["packet_digest"],
        "ready_digest": value["ready_digest"],
        "terminal_digest": value["terminal_digest"],
        "actual_returncode": value["actual_returncode"],
        "receipt_digest": value["cleanup_receipt_digest"],
        "session_nonce": value["session_nonce"],
        "ack_nonce": consume["ack_nonce"],
        "consume_receipt_digest": session.persisted_consume_digest(consume),
    }
    closure = object.__new__(AuthenticatedManagedCorrectionClosure)
    object.__setattr__(closure, "_receipt", result.cleanup_receipt)
    object.__setattr__(closure, "_packet", result.packet)
    object.__setattr__(closure, "_lineage", canonical_json_bytes(lineage))
    closure.document()
    return closure
