"""Controller-internal admission for one already reserved Linux file read.

The caller supplies only the saved attempt identity and preassigned native
request identities. This module neither chooses a target nor dispatches a task.
Every target fact is reopened from ProductStore and the live Linux controller
context before the store atomically consumes one request ordinal.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from . import file_access_context
from .engine_attempt_contract import AttemptRole, AttemptState
from .engine_experiment import EngineExperiment
from .engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
)
from .engine_file_access_target import EngineFileReadTargetPolicy
from .file_access_contract import PROBE_ACTION, verify_file_access_binding
from .product_store import ProductStore
from .util import content_hash

ADMISSION_RECEIPT_SCHEMA = "bluefire.engine-file-access-request-claim.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT_ID = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_TASK_ID = re.compile(r"execute-[0-9a-f]{64}\Z")
_ACTIVE_STATES = frozenset({AttemptState.QUEUED, AttemptState.PREFLIGHT, AttemptState.RUNNING})
_CLAIM_FIELDS = frozenset(
    {
        "schema_version",
        "claim_ref",
        "reservation_ref",
        "policy_digest",
        "attempt_id",
        "ordinal",
        "task_id",
        "request_hash",
        "transport_request_hash",
        "claimed_at_ms",
    }
)


class EngineFileAccessAdmissionError(ValueError):
    """The reserved read cannot be admitted against current controller facts."""


class _ControllerService(Protocol):
    product_store: ProductStore


@dataclass(frozen=True, slots=True)
class EngineFileAccessAdmissionReceipt:
    """Canonical accounting receipt, without execution or target authority."""

    schema_version: str
    claim_ref: str
    reservation_ref: str
    policy_digest: str
    attempt_id: str
    ordinal: int
    task_id: str
    request_hash: str
    transport_request_hash: str
    claimed_at_ms: int

    @classmethod
    def from_claim(cls, value: Mapping[str, Any]) -> EngineFileAccessAdmissionReceipt:
        if not isinstance(value, Mapping) or set(value) != _CLAIM_FIELDS:
            raise EngineFileAccessAdmissionError("saved admission claim is invalid")
        if (
            value["schema_version"] != ADMISSION_RECEIPT_SCHEMA
            or any(
                not isinstance(value[key], str) or _DIGEST.fullmatch(value[key]) is None
                for key in (
                    "claim_ref",
                    "reservation_ref",
                    "policy_digest",
                    "request_hash",
                    "transport_request_hash",
                )
            )
            or not isinstance(value["attempt_id"], str)
            or _ATTEMPT_ID.fullmatch(value["attempt_id"]) is None
            or not isinstance(value["task_id"], str)
            or _TASK_ID.fullmatch(value["task_id"]) is None
            or value["task_id"] != "execute-" + value["request_hash"][7:]
            or type(value["ordinal"]) is not int
            or value["ordinal"] < 1
            or type(value["claimed_at_ms"]) is not int
            or value["claimed_at_ms"] < 1
        ):
            raise EngineFileAccessAdmissionError("saved admission claim is invalid")
        identity = {
            "schema_version": ADMISSION_RECEIPT_SCHEMA,
            "reservation_ref": value["reservation_ref"],
            "ordinal": value["ordinal"],
            "task_id": value["task_id"],
            "request_hash": value["request_hash"],
            "transport_request_hash": value["transport_request_hash"],
        }
        if content_hash(identity) != value["claim_ref"]:
            raise EngineFileAccessAdmissionError("saved admission claim is invalid")
        return cls(**{key: value[key] for key in _CLAIM_FIELDS})

    def to_dict(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in _CLAIM_FIELDS}


def _server_now_ms() -> int:
    return time.time_ns() // 1_000_000


def admit_engine_file_access_request(
    service: _ControllerService,
    attempt_id: str,
    *,
    ordinal: int,
    task_id: str,
    request_hash: str,
    transport_request_hash: str,
) -> EngineFileAccessAdmissionReceipt:
    """Recheck the exact live target, then consume one saved request ordinal.

    The service and its ProductStore are controller-owned. No caller-supplied
    control, enrollment, binding, snapshot, policy, or operation is accepted.
    A successful claim is permanent, including if a later dispatch fails.
    """

    try:
        return _admit(
            service,
            attempt_id,
            ordinal=ordinal,
            task_id=task_id,
            request_hash=request_hash,
            transport_request_hash=transport_request_hash,
        )
    except EngineFileAccessAdmissionError:
        raise
    except Exception:
        # Store and native inspection errors may include protected paths.
        raise EngineFileAccessAdmissionError("reserved file read is unavailable") from None


def _admit(
    service: _ControllerService,
    attempt_id: str,
    *,
    ordinal: int,
    task_id: str,
    request_hash: str,
    transport_request_hash: str,
) -> EngineFileAccessAdmissionReceipt:
    if file_access_context.is_windows_host() or file_access_context.is_macos_host():
        raise EngineFileAccessAdmissionError("Linux file read is unavailable")
    if type(service.product_store) is not ProductStore:
        raise EngineFileAccessAdmissionError("protected product store is unavailable")
    store = service.product_store
    now_ms = _server_now_ms()
    reservation = store.get_engine_file_access_target_reservation(attempt_id)
    policy = EngineFileReadTargetPolicy.from_mapping(reservation["policy"])
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(reservation["experiment_id"])
    )
    _index, entry = experiment._attempt(attempt_id)
    attempt = entry.record.binding
    phase = (
        HISTORICAL_BASELINE
        if attempt.role is AttemptRole.BASELINE
        else CURRENT_HARDENED if attempt.role is AttemptRole.ADAPTIVE_SEARCH else None
    )
    if (
        phase is None
        or entry.record.state not in _ACTIVE_STATES
        or reservation["attempt_id"] != attempt_id
        or reservation["experiment_id"] != experiment.experiment_id
        or reservation["job_id"] != entry.job_id
        or reservation["run_id"] != attempt.run_id
        or reservation["role"] != attempt.role.value
        or reservation["action_id"] != PROBE_ACTION
        or reservation["binding_digest"] != attempt.binding_digest
        or reservation["mechanism_ref"] != attempt.scope_ref
        or reservation["target_snapshot_ref"] != attempt.target_snapshot_ref
        or reservation["historical_snapshot_ref"] != experiment.initial_target_snapshot_ref
        or experiment.current_target_snapshot_ref != attempt.target_snapshot_ref
        or reservation["policy_digest"] != policy.policy_digest
        or policy.snapshot.to_dict()["phase"] != phase
    ):
        raise EngineFileAccessAdmissionError("saved file-read owner changed")

    owner_id = policy.historical_snapshot.to_dict()["control_owner_id"]
    current_view = store.get_file_access_control(owner_id)
    control = current_view["document"]
    expected_status = "baseline_verified" if phase == HISTORICAL_BASELINE else "hardened"
    expected_mode = "0640" if phase == HISTORICAL_BASELINE else "0600"
    if (
        current_view["pending_operation"] is not False
        or current_view["usages_settled"] is not True
        or control["control_owner_id"] != owner_id
        or control["status"] != expected_status
        or control["binding"]["mode"] != expected_mode
        or control["enrollment_id"] != policy.mechanism.to_dict()["enrollment_id"]
    ):
        raise EngineFileAccessAdmissionError("retained file control is not settled")

    enrolled = file_access_context.enrollment(service, now_ms)
    actual = file_access_context.binding(enrolled, revision=control["revision"], now_ms=now_ms)
    if actual != control["binding"] or content_hash(actual) != control["binding_digest"]:
        raise EngineFileAccessAdmissionError("live file binding changed")
    current_binding = verify_file_access_binding(
        actual, expected_document_digest=control["binding_digest"], now_ms=now_ms
    )

    current_record = store.get_linux_file_access_revision_record(owner_id, control["revision"])
    if (
        current_record["document"] != control
        or current_record["document_digest"] != current_view["document_digest"]
    ):
        raise EngineFileAccessAdmissionError("current control revision changed")
    historical_revision = policy.historical_snapshot.to_dict()["control_revision"]
    historical_record = store.get_linux_file_access_revision_record(owner_id, historical_revision)
    historical_control = historical_record["document"]
    historical_binding = verify_file_access_binding(
        historical_control["binding"],
        expected_document_digest=historical_control["binding_digest"],
        now_ms=now_ms,
    )
    expected_historical_binding = {
        **actual,
        "control_revision": historical_revision,
        "mode": "0640",
    }
    if historical_binding.to_dict() != expected_historical_binding:
        raise EngineFileAccessAdmissionError("historical file binding changed")
    mechanism = FileAccessReadMechanism.from_verified_binding(
        historical_binding, baseline=historical_control["baseline"]
    )
    historical = FileAccessTargetSnapshot.from_controller_records(
        historical_binding,
        mechanism=mechanism,
        control_record=historical_record,
        operation_records=store.file_access_operation_records(historical_record["job_id"]),
        phase=HISTORICAL_BASELINE,
    )
    if phase == HISTORICAL_BASELINE:
        if historical_revision != control["revision"]:
            raise EngineFileAccessAdmissionError("baseline control revision changed")
        snapshot = historical
    else:
        if historical_revision + 1 != control["revision"]:
            raise EngineFileAccessAdmissionError("hardened control lineage changed")
        snapshot = FileAccessTargetSnapshot.from_controller_records(
            current_binding,
            mechanism=mechanism,
            control_record=current_record,
            operation_records=store.file_access_operation_records(current_record["job_id"]),
            phase=CURRENT_HARDENED,
        )
    policy.require_current(
        expected_policy_digest=reservation["policy_digest"],
        attempt=attempt,
        current_mechanism=mechanism,
        current_historical_snapshot=historical,
        current_snapshot=snapshot,
        historical_binding=historical_binding,
        current_binding=current_binding,
        now_ms=now_ms,
    )
    claim = store.claim_engine_file_access_request(
        attempt_id,
        ordinal=ordinal,
        task_id=task_id,
        request_hash=request_hash,
        transport_request_hash=transport_request_hash,
    )
    if claim["reservation_ref"] != reservation["reservation_ref"]:
        raise EngineFileAccessAdmissionError("saved admission claim changed")
    return EngineFileAccessAdmissionReceipt.from_claim(claim)


__all__ = [
    "ADMISSION_RECEIPT_SCHEMA",
    "EngineFileAccessAdmissionError",
    "EngineFileAccessAdmissionReceipt",
    "admit_engine_file_access_request",
]
