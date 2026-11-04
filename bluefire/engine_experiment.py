"""Pure state for a reviewed external-engine defense experiment.

Only baseline exploration and fresh adaptive search are external-engine work.
The retained reproducer and legitimate-use control are controller-owned checks,
so they never acquire invented engine, model, or upstream-session provenance.
This module has no process, network, target, model, or mutation authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable, Mapping, cast

from .engine_attempt_contract import (
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptContractError,
    EngineAttemptRecord,
    EngineEvidenceItem,
    EvidenceCategory,
)
from .evidence import EvidenceProvenance, EvidenceRecord
from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineExperimentError(ValueError):
    """Raised when an engine experiment violates its closed workflow."""


class CleanupState(str, Enum):
    PENDING = "pending"
    VERIFIED_ABSENT = "verified_absent"
    RESIDUE = "residue"
    UNKNOWN = "unknown"


class DefenseState(str, Enum):
    REVIEWED = "reviewed"
    APPLIED = "applied"
    RETAINED = "retained"
    ROLLED_BACK = "rolled_back"
    UNKNOWN = "unknown"


class ControllerCheckRole(str, Enum):
    RETAINED_REPRODUCER = "retained_reproducer"
    LEGITIMATE_USE = "legitimate_use"


class ControllerCheckState(str, Enum):
    RESERVED = "reserved"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ControllerPerformer(str, Enum):
    BLUEFIRE_CONTROLLER = "bluefire.controller"
    TRUSTED_CLIENT = "bluefire.trusted-client"


ENGINE_CAPABILITY_SCOPE_VERSION = "bluefire.engine-capability-delegation.v1"

_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_CHECK_ID = re.compile(r"^controller-check-[0-9a-f]{32}$")
_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")
_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_CHANGE_ID = re.compile(r"^defense-change-[0-9a-f]{32}$")
_BLUEFIRE_EVIDENCE_ID = re.compile(r"^evidence-[0-9a-f]{20}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TERMINAL_ATTEMPT_STATES = frozenset(
    {
        AttemptState.COMPLETED,
        AttemptState.PARTIAL,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.BUDGET_EXHAUSTED,
        AttemptState.UNKNOWN,
    }
)
_TERMINAL_CHECK_STATES = frozenset(
    {
        ControllerCheckState.COMPLETED,
        ControllerCheckState.FAILED,
        ControllerCheckState.UNKNOWN,
    }
)
_ENGINE_ROLE_ORDER = (AttemptRole.BASELINE, AttemptRole.ADAPTIVE_SEARCH)
_CHECK_ROLE_ORDER = (
    ControllerCheckRole.RETAINED_REPRODUCER,
    ControllerCheckRole.LEGITIMATE_USE,
)
_ENGINE_CATEGORIES = frozenset({EvidenceCategory.ENGINE_ASSERTION, EvidenceCategory.TOOL_RESULT})


class _ControllerObservationAuthority:
    __slots__ = ()


_CONTROLLER_OBSERVATION_AUTHORITY = _ControllerObservationAuthority()


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineExperimentError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineExperimentError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineExperimentError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, maximum=40)
    try:
        parse_iso8601_datetime(text)
    except ValueError as exc:
        raise EngineExperimentError(f"{label} is not bounded RFC 3339") from exc
    return text


def _record_from_mapping(value: Any) -> EngineAttemptRecord:
    try:
        record = EngineAttemptRecord.from_mapping(cast(Mapping[str, Any], value))
    except (EngineAttemptContractError, TypeError) as exc:
        raise EngineExperimentError("engine attempt record is invalid") from exc
    if record.to_dict() != json_clone(value):
        raise EngineExperimentError("engine attempt record is not canonical")
    return record


def _binding_from_object(value: EngineAttemptBinding) -> EngineAttemptBinding:
    try:
        binding = EngineAttemptBinding.from_mapping(value.to_dict())
    except (AttributeError, EngineAttemptContractError, TypeError) as exc:
        raise EngineExperimentError("engine attempt binding is invalid") from exc
    return binding


def _evidence_from_mapping(value: Any) -> EngineEvidenceItem:
    try:
        evidence = EngineEvidenceItem.from_mapping(cast(Mapping[str, Any], value))
    except (EngineAttemptContractError, TypeError) as exc:
        raise EngineExperimentError("engine evidence is invalid") from exc
    if evidence.to_dict() != json_clone(value):
        raise EngineExperimentError("engine evidence is not canonical")
    return evidence


@dataclass(frozen=True, slots=True)
class EngineAttemptEntry:
    schema_version: str
    job_id: str
    delegation_digest: str
    execution_approval_digest: str
    execution_approval_id: str
    record: EngineAttemptRecord
    evidence: tuple[EngineEvidenceItem, ...]
    artifact_manifest_ref: str | None
    cleanup_state: CleanupState
    cleanup_evidence_ref: str | None
    settled_at: str | None

    @classmethod
    def reserve(
        cls,
        job_id: str,
        binding: EngineAttemptBinding,
        *,
        delegation_digest: str,
        execution_approval_digest: str,
        execution_approval_id: str,
    ) -> "EngineAttemptEntry":
        binding = _binding_from_object(binding)
        entry = cls(
            schema_version="bluefire.engine-attempt-entry.v2",
            job_id=job_id,
            delegation_digest=_digest(delegation_digest, "engine delegation"),
            execution_approval_digest=_digest(
                execution_approval_digest, "engine execution approval"
            ),
            execution_approval_id=execution_approval_id,
            record=EngineAttemptRecord.create(binding),
            evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.PENDING,
            cleanup_evidence_ref=None,
            settled_at=None,
        )
        entry.validate()
        return entry

    @classmethod
    def from_mapping(cls, value: Any) -> "EngineAttemptEntry":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine attempt entry")
        raw_evidence = row["evidence"]
        if not isinstance(raw_evidence, list) or len(raw_evidence) > 512:
            raise EngineExperimentError("engine attempt evidence is invalid")
        try:
            entry = cls(
                schema_version=row["schema_version"],
                job_id=row["job_id"],
                delegation_digest=row["delegation_digest"],
                execution_approval_digest=row["execution_approval_digest"],
                execution_approval_id=row["execution_approval_id"],
                record=_record_from_mapping(row["record"]),
                evidence=tuple(_evidence_from_mapping(item) for item in raw_evidence),
                artifact_manifest_ref=row["artifact_manifest_ref"],
                cleanup_state=CleanupState(row["cleanup_state"]),
                cleanup_evidence_ref=row["cleanup_evidence_ref"],
                settled_at=row["settled_at"],
            )
        except EngineExperimentError:
            raise
        except (TypeError, ValueError) as exc:
            raise EngineExperimentError("engine attempt entry is invalid") from exc
        entry.validate()
        if entry.to_dict() != json_clone(value):
            raise EngineExperimentError("engine attempt entry is not canonical")
        return entry

    def validate(self) -> None:
        if self.schema_version != "bluefire.engine-attempt-entry.v2":
            raise EngineExperimentError("engine attempt entry schema is unsupported")
        if _JOB_ID.fullmatch(self.job_id) is None:
            raise EngineExperimentError("engine attempt job ID is invalid")
        _digest(self.delegation_digest, "engine delegation")
        _digest(self.execution_approval_digest, "engine execution approval")
        if _APPROVAL_ID.fullmatch(self.execution_approval_id) is None:
            raise EngineExperimentError("engine execution approval identity is invalid")
        binding = self.record.binding
        if binding.role not in _ENGINE_ROLE_ORDER:
            raise EngineExperimentError("controller checks cannot use engine provenance")
        if any(
            item.attempt_id != binding.attempt_id or item.run_id != binding.run_id
            for item in self.evidence
        ):
            raise EngineExperimentError("attempt evidence belongs to another attempt or run")
        if any(item.category not in _ENGINE_CATEGORIES for item in self.evidence):
            raise EngineExperimentError("engine attempt entry contains controller evidence")
        if len({item.evidence_id for item in self.evidence}) != len(self.evidence):
            raise EngineExperimentError("engine attempt evidence contains duplicate identities")
        if self.artifact_manifest_ref is not None:
            _digest(self.artifact_manifest_ref, "artifact manifest reference")
        if self.cleanup_evidence_ref is not None:
            _digest(self.cleanup_evidence_ref, "cleanup evidence reference")
        if self.settled_at is not None:
            _timestamp(self.settled_at, "attempt settlement time")
        terminal = self.record.state in _TERMINAL_ATTEMPT_STATES
        if terminal != (self.settled_at is not None):
            raise EngineExperimentError("attempt settlement does not match its terminal state")
        if not terminal and (
            self.cleanup_state is not CleanupState.PENDING
            or self.cleanup_evidence_ref is not None
            or self.artifact_manifest_ref is not None
        ):
            raise EngineExperimentError("active attempt cannot claim artifacts or cleanup")
        if terminal and (
            self.cleanup_state is CleanupState.PENDING or self.cleanup_evidence_ref is None
        ):
            raise EngineExperimentError("settled attempt requires a cleanup receipt")
        if self.record.ended_at is not None and self.settled_at is not None:
            if parse_iso8601_datetime(self.settled_at) < parse_iso8601_datetime(
                self.record.ended_at
            ):
                raise EngineExperimentError("attempt settlement predates its terminal record")
        if self.evidence:
            if (
                self.record.started_at is None
                or self.record.ended_at is None
                or self.settled_at is None
            ):
                raise EngineExperimentError("engine evidence lacks a complete attempt boundary")
            started = parse_iso8601_datetime(self.record.started_at)
            ended = parse_iso8601_datetime(self.record.ended_at)
            settled = parse_iso8601_datetime(self.settled_at)
            for item in self.evidence:
                observed = parse_iso8601_datetime(item.observed_at)
                if not started <= observed <= ended <= settled:
                    raise EngineExperimentError(
                        "engine evidence falls outside its attempt lifecycle"
                    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "delegation_digest": self.delegation_digest,
            "execution_approval_digest": self.execution_approval_digest,
            "execution_approval_id": self.execution_approval_id,
            "record": self.record.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "artifact_manifest_ref": self.artifact_manifest_ref,
            "cleanup_state": self.cleanup_state.value,
            "cleanup_evidence_ref": self.cleanup_evidence_ref,
            "settled_at": self.settled_at,
        }


@dataclass(frozen=True, slots=True)
class ControllerCheckRecord:
    schema_version: str
    check_id: str
    experiment_id: str
    job_id: str
    run_id: str
    role: ControllerCheckRole
    performer: ControllerPerformer
    mechanism_ref: str
    target_snapshot_ref: str
    input_digest: str
    result_digest: str | None
    state: ControllerCheckState
    independent_evidence_refs: tuple[str, ...]
    created_at: str
    settled_at: str | None
    cleanup_state: CleanupState
    cleanup_evidence_ref: str | None

    @classmethod
    def reserve(
        cls,
        *,
        check_id: str,
        experiment_id: str,
        job_id: str,
        run_id: str,
        role: ControllerCheckRole,
        mechanism_ref: str,
        target_snapshot_ref: str,
        input_digest: str,
        created_at: str,
    ) -> "ControllerCheckRecord":
        performer = (
            ControllerPerformer.BLUEFIRE_CONTROLLER
            if role is ControllerCheckRole.RETAINED_REPRODUCER
            else ControllerPerformer.TRUSTED_CLIENT
        )
        record = cls(
            schema_version="bluefire.engine-controller-check.v1",
            check_id=check_id,
            experiment_id=experiment_id,
            job_id=job_id,
            run_id=run_id,
            role=role,
            performer=performer,
            mechanism_ref=mechanism_ref,
            target_snapshot_ref=target_snapshot_ref,
            input_digest=input_digest,
            result_digest=None,
            state=ControllerCheckState.RESERVED,
            independent_evidence_refs=(),
            created_at=created_at,
            settled_at=None,
            cleanup_state=CleanupState.PENDING,
            cleanup_evidence_ref=None,
        )
        record.validate()
        return record

    @classmethod
    def from_mapping(cls, value: Any) -> "ControllerCheckRecord":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "controller check")
        refs = row["independent_evidence_refs"]
        if not isinstance(refs, list):
            raise EngineExperimentError("controller check evidence references are invalid")
        try:
            record = cls(
                schema_version=row["schema_version"],
                check_id=row["check_id"],
                experiment_id=row["experiment_id"],
                job_id=row["job_id"],
                run_id=row["run_id"],
                role=ControllerCheckRole(row["role"]),
                performer=ControllerPerformer(row["performer"]),
                mechanism_ref=row["mechanism_ref"],
                target_snapshot_ref=row["target_snapshot_ref"],
                input_digest=row["input_digest"],
                result_digest=row["result_digest"],
                state=ControllerCheckState(row["state"]),
                independent_evidence_refs=tuple(refs),
                created_at=row["created_at"],
                settled_at=row["settled_at"],
                cleanup_state=CleanupState(row["cleanup_state"]),
                cleanup_evidence_ref=row["cleanup_evidence_ref"],
            )
        except (TypeError, ValueError) as exc:
            raise EngineExperimentError("controller check is invalid") from exc
        record.validate()
        if record.to_dict() != json_clone(value):
            raise EngineExperimentError("controller check is not canonical")
        return record

    def validate(self) -> None:
        if self.schema_version != "bluefire.engine-controller-check.v1":
            raise EngineExperimentError("controller check schema is unsupported")
        if (
            _CHECK_ID.fullmatch(self.check_id) is None
            or _EXPERIMENT_ID.fullmatch(self.experiment_id) is None
            or _JOB_ID.fullmatch(self.job_id) is None
            or _RUN_ID.fullmatch(self.run_id) is None
        ):
            raise EngineExperimentError("controller check identity is invalid")
        expected_performer = (
            ControllerPerformer.BLUEFIRE_CONTROLLER
            if self.role is ControllerCheckRole.RETAINED_REPRODUCER
            else ControllerPerformer.TRUSTED_CLIENT
        )
        if self.performer is not expected_performer:
            raise EngineExperimentError("controller check performer is invalid")
        for value, label in (
            (self.mechanism_ref, "controller check mechanism"),
            (self.target_snapshot_ref, "controller check target snapshot"),
            (self.input_digest, "controller check input"),
        ):
            _digest(value, label)
        if self.result_digest is not None:
            _digest(self.result_digest, "controller check result")
        if self.cleanup_evidence_ref is not None:
            _digest(self.cleanup_evidence_ref, "controller check cleanup receipt")
        if (
            len(self.independent_evidence_refs) > 64
            or len(set(self.independent_evidence_refs)) != len(self.independent_evidence_refs)
            or any(
                _BLUEFIRE_EVIDENCE_ID.fullmatch(reference) is None
                for reference in self.independent_evidence_refs
            )
        ):
            raise EngineExperimentError("controller check evidence references are invalid")
        created = parse_iso8601_datetime(_timestamp(self.created_at, "check creation time"))
        terminal = self.state in _TERMINAL_CHECK_STATES
        if terminal != (self.settled_at is not None):
            raise EngineExperimentError("controller check settlement is inconsistent")
        if (
            self.settled_at is not None
            and parse_iso8601_datetime(_timestamp(self.settled_at, "check settlement time"))
            < created
        ):
            raise EngineExperimentError("controller check settled before creation")
        if terminal and (
            self.result_digest is None
            or self.cleanup_state is CleanupState.PENDING
            or self.cleanup_evidence_ref is None
        ):
            raise EngineExperimentError("settled controller check is incomplete")
        if not terminal and (
            self.result_digest is not None
            or self.independent_evidence_refs
            or self.cleanup_state is not CleanupState.PENDING
            or self.cleanup_evidence_ref is not None
        ):
            raise EngineExperimentError("reserved controller check cannot claim an outcome")
        if self.state in {ControllerCheckState.COMPLETED, ControllerCheckState.FAILED} and not (
            self.independent_evidence_refs
        ):
            raise EngineExperimentError("controller check outcome requires independent evidence")

    def settle(
        self,
        *,
        state: ControllerCheckState,
        result_digest: str,
        independent_evidence_refs: Iterable[str],
        cleanup_state: CleanupState,
        cleanup_evidence_ref: str,
        settled_at: str,
    ) -> "ControllerCheckRecord":
        if self.state is not ControllerCheckState.RESERVED or state not in _TERMINAL_CHECK_STATES:
            raise EngineExperimentError("controller check transition is invalid")
        result = replace(
            self,
            state=state,
            result_digest=_digest(result_digest, "controller check result"),
            independent_evidence_refs=tuple(independent_evidence_refs),
            settled_at=_timestamp(settled_at, "controller check settlement time"),
            cleanup_state=cleanup_state,
            cleanup_evidence_ref=_digest(cleanup_evidence_ref, "controller check cleanup receipt"),
        )
        result.validate()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "check_id": self.check_id,
            "experiment_id": self.experiment_id,
            "job_id": self.job_id,
            "run_id": self.run_id,
            "role": self.role.value,
            "performer": self.performer.value,
            "mechanism_ref": self.mechanism_ref,
            "target_snapshot_ref": self.target_snapshot_ref,
            "input_digest": self.input_digest,
            "result_digest": self.result_digest,
            "state": self.state.value,
            "independent_evidence_refs": list(self.independent_evidence_refs),
            "created_at": self.created_at,
            "settled_at": self.settled_at,
            "cleanup_state": self.cleanup_state.value,
            "cleanup_evidence_ref": self.cleanup_evidence_ref,
        }


@dataclass(frozen=True, slots=True)
class IndependentObservationRecord:
    """Controller-attested link to one immutable target-side EvidenceRecord."""

    schema_version: str
    target_snapshot_ref: str
    mechanism_ref: str
    attempt_id: str | None
    check_id: str | None
    check_input_digest: str | None
    controller_receipt_digest: str
    evidence: EvidenceRecord
    _controller_attestation: object | None = field(
        default=None,
        repr=False,
        compare=False,
        init=False,
    )

    @classmethod
    def create(
        cls,
        *,
        target_snapshot_ref: str,
        mechanism_ref: str,
        evidence: EvidenceRecord,
        attempt_id: str | None = None,
        check_id: str | None = None,
        check_input_digest: str | None = None,
        _controller_authority: object | None = None,
    ) -> "IndependentObservationRecord":
        if _controller_authority is not _CONTROLLER_OBSERVATION_AUTHORITY:
            raise EngineExperimentError(
                "independent observation requires trusted controller authority"
            )
        checked = EvidenceRecord.from_mapping(evidence.to_dict())
        owner_id = attempt_id if attempt_id is not None else check_id
        content = _tenant_observation_content(checked)
        receipt = content_hash(
            {
                "schema_version": "bluefire.engine-independent-observation-receipt.v1",
                "owner_kind": "engine_attempt" if attempt_id is not None else "controller_check",
                "owner_id": owner_id,
                "attempt_id": attempt_id,
                "check_id": check_id,
                "check_input_digest": check_input_digest,
                "target_snapshot_ref": target_snapshot_ref,
                "mechanism_ref": mechanism_ref,
                "evidence_id": checked.evidence_id,
                "evidence_record_hash": checked.record_hash,
                "evidence_content_hash": checked.content_hash,
                "run_id": checked.run_id,
                "assessment": content.get("assessment"),
            }
        )
        value = cls(
            schema_version="bluefire.engine-independent-observation.v1",
            target_snapshot_ref=target_snapshot_ref,
            mechanism_ref=mechanism_ref,
            attempt_id=attempt_id,
            check_id=check_id,
            check_input_digest=check_input_digest,
            controller_receipt_digest=receipt,
            evidence=checked,
        )
        object.__setattr__(value, "_controller_attestation", _controller_authority)
        value.validate()
        return value

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        _controller_authority: object | None = None,
    ) -> "IndependentObservationRecord":
        if _controller_authority is not _CONTROLLER_OBSERVATION_AUTHORITY:
            raise EngineExperimentError(
                "independent observation requires trusted controller authority"
            )
        fields = frozenset(
            {
                "schema_version",
                "target_snapshot_ref",
                "mechanism_ref",
                "attempt_id",
                "check_id",
                "check_input_digest",
                "controller_receipt_digest",
                "evidence",
            }
        )
        row = _exact(value, fields, "independent observation")
        try:
            result = cls(
                schema_version=row["schema_version"],
                target_snapshot_ref=row["target_snapshot_ref"],
                mechanism_ref=row["mechanism_ref"],
                attempt_id=row["attempt_id"],
                check_id=row["check_id"],
                check_input_digest=row["check_input_digest"],
                controller_receipt_digest=row["controller_receipt_digest"],
                evidence=EvidenceRecord.from_mapping(row["evidence"]),
            )
        except (TypeError, ValueError) as exc:
            raise EngineExperimentError("independent observation is invalid") from exc
        object.__setattr__(result, "_controller_attestation", _controller_authority)
        result.validate()
        if result.to_dict() != json_clone(value):
            raise EngineExperimentError("independent observation is not canonical")
        return result

    def validate(self) -> None:
        if self._controller_attestation is not _CONTROLLER_OBSERVATION_AUTHORITY:
            raise EngineExperimentError(
                "independent observation requires trusted controller authority"
            )
        if self.schema_version != "bluefire.engine-independent-observation.v1":
            raise EngineExperimentError("independent observation schema is unsupported")
        _digest(self.target_snapshot_ref, "observation target snapshot")
        _digest(self.mechanism_ref, "observation mechanism")
        _digest(self.controller_receipt_digest, "controller observation receipt")
        if (self.attempt_id is None) == (self.check_id is None):
            raise EngineExperimentError("observation requires exactly one workflow owner")
        owner_id = self.attempt_id if self.attempt_id is not None else self.check_id
        if self.attempt_id is not None and _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise EngineExperimentError("observation attempt identity is invalid")
        if self.check_id is not None and _CHECK_ID.fullmatch(self.check_id) is None:
            raise EngineExperimentError("observation check identity is invalid")
        if self.attempt_id is not None and self.check_input_digest is not None:
            raise EngineExperimentError("engine-attempt observation cannot bind check input")
        if self.check_id is not None:
            _digest(self.check_input_digest, "controller check observation input")
        checked = EvidenceRecord.from_mapping(self.evidence.to_dict())
        if checked.provenance is not EvidenceProvenance.OBSERVED:
            raise EngineExperimentError("independent observation provenance is invalid")
        content = _tenant_observation_content(checked)
        if content.get("attempt_id") != owner_id:
            raise EngineExperimentError("observation owner binding changed")
        expected_receipt = content_hash(
            {
                "schema_version": "bluefire.engine-independent-observation-receipt.v1",
                "owner_kind": (
                    "engine_attempt" if self.attempt_id is not None else "controller_check"
                ),
                "owner_id": owner_id,
                "attempt_id": self.attempt_id,
                "check_id": self.check_id,
                "check_input_digest": self.check_input_digest,
                "target_snapshot_ref": self.target_snapshot_ref,
                "mechanism_ref": self.mechanism_ref,
                "evidence_id": checked.evidence_id,
                "evidence_record_hash": checked.record_hash,
                "evidence_content_hash": checked.content_hash,
                "run_id": checked.run_id,
                "assessment": self.assessment,
            }
        )
        if self.controller_receipt_digest != expected_receipt:
            raise EngineExperimentError("controller observation receipt changed")

    @property
    def evidence_id(self) -> str:
        return self.evidence.evidence_id

    @property
    def assessment(self) -> str:
        assessment = _tenant_observation_content(self.evidence).get("assessment")
        if assessment not in {
            "unauthorized_disclosure",
            "authorization_denied",
            "legitimate_use_succeeded",
            "no_protected_effect",
            "unknown",
        }:
            raise EngineExperimentError("independent observation assessment is invalid")
        return str(assessment)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_snapshot_ref": self.target_snapshot_ref,
            "mechanism_ref": self.mechanism_ref,
            "attempt_id": self.attempt_id,
            "check_id": self.check_id,
            "check_input_digest": self.check_input_digest,
            "controller_receipt_digest": self.controller_receipt_digest,
            "evidence": self.evidence.to_dict(),
        }


def _controller_observation_record(
    *,
    target_snapshot_ref: str,
    mechanism_ref: str,
    evidence: EvidenceRecord,
    attempt_id: str | None = None,
    check_id: str | None = None,
    check_input_digest: str | None = None,
) -> IndependentObservationRecord:
    """Trusted controller persistence seam; never expose as an API operation."""

    return IndependentObservationRecord.create(
        target_snapshot_ref=target_snapshot_ref,
        mechanism_ref=mechanism_ref,
        evidence=evidence,
        attempt_id=attempt_id,
        check_id=check_id,
        check_input_digest=check_input_digest,
        _controller_authority=_CONTROLLER_OBSERVATION_AUTHORITY,
    )


def _tenant_observation_content(record: EvidenceRecord) -> Mapping[str, Any]:
    try:
        from .tenant_record_observer import checked_observation_content

        return checked_observation_content(record)
    except (ImportError, TypeError, ValueError) as exc:
        raise EngineExperimentError("unsupported independent observation") from exc


@dataclass(frozen=True, slots=True)
class EngineDefenseChange:
    schema_version: str
    change_id: str
    experiment_id: str
    mechanism_ref: str
    preimage_digest: str
    approved_configuration_digest: str
    applied_configuration_digest: str | None
    application_receipt_digest: str | None
    reconciliation_receipt_digest: str | None
    before_target_snapshot_ref: str
    after_target_snapshot_ref: str
    rollback_digest: str
    rollback_operation_digest: str | None
    rollback_receipt_digest: str | None
    reviewed_by: str
    reviewed_at: str
    responsible_actor: str
    state: DefenseState
    applied_at: str | None
    reconciled_at: str | None
    retained_at: str | None
    rollback_started_at: str | None
    rolled_back_at: str | None

    @classmethod
    def reviewed(
        cls,
        *,
        change_id: str,
        experiment_id: str,
        mechanism_ref: str,
        preimage_digest: str,
        approved_configuration_digest: str,
        before_target_snapshot_ref: str,
        after_target_snapshot_ref: str,
        rollback_digest: str,
        reviewed_by: str,
        reviewed_at: str,
    ) -> "EngineDefenseChange":
        value = cls(
            schema_version="bluefire.engine-defense-change.v2",
            change_id=change_id,
            experiment_id=experiment_id,
            mechanism_ref=mechanism_ref,
            preimage_digest=preimage_digest,
            approved_configuration_digest=approved_configuration_digest,
            applied_configuration_digest=None,
            application_receipt_digest=None,
            reconciliation_receipt_digest=None,
            before_target_snapshot_ref=before_target_snapshot_ref,
            after_target_snapshot_ref=after_target_snapshot_ref,
            rollback_digest=rollback_digest,
            rollback_operation_digest=None,
            rollback_receipt_digest=None,
            reviewed_by=reviewed_by,
            reviewed_at=reviewed_at,
            responsible_actor="bluefire.controller",
            state=DefenseState.REVIEWED,
            applied_at=None,
            reconciled_at=None,
            retained_at=None,
            rollback_started_at=None,
            rolled_back_at=None,
        )
        value.validate()
        return value

    @classmethod
    def from_mapping(cls, value: Any) -> "EngineDefenseChange":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine defense change")
        try:
            result = cls(**{**row, "state": DefenseState(row["state"])})
        except (TypeError, ValueError) as exc:
            raise EngineExperimentError("engine defense change is invalid") from exc
        result.validate()
        if result.to_dict() != json_clone(value):
            raise EngineExperimentError("engine defense change is not canonical")
        return result

    def validate(self) -> None:
        if self.schema_version != "bluefire.engine-defense-change.v2":
            raise EngineExperimentError("engine defense change schema is unsupported")
        if (
            _CHANGE_ID.fullmatch(self.change_id) is None
            or _EXPERIMENT_ID.fullmatch(self.experiment_id) is None
        ):
            raise EngineExperimentError("engine defense change identity is invalid")
        for value, label in (
            (self.mechanism_ref, "mechanism reference"),
            (self.preimage_digest, "defense preimage"),
            (self.approved_configuration_digest, "approved defense configuration"),
            (self.before_target_snapshot_ref, "before target snapshot"),
            (self.after_target_snapshot_ref, "after target snapshot"),
            (self.rollback_digest, "rollback plan"),
        ):
            _digest(value, label)
        if self.before_target_snapshot_ref == self.after_target_snapshot_ref:
            raise EngineExperimentError("defense target snapshot did not change")
        for optional_value, label in (
            (self.applied_configuration_digest, "applied defense configuration"),
            (self.application_receipt_digest, "defense application receipt"),
            (self.reconciliation_receipt_digest, "defense reconciliation receipt"),
            (self.rollback_operation_digest, "defense rollback operation"),
            (self.rollback_receipt_digest, "defense rollback receipt"),
        ):
            if optional_value is not None:
                _digest(optional_value, label)
        if (
            self.applied_configuration_digest is not None
            and self.applied_configuration_digest != self.approved_configuration_digest
        ):
            raise EngineExperimentError(
                "applied defense configuration differs from its reviewed configuration"
            )
        _text(self.reviewed_by, "defense reviewer")
        reviewed = parse_iso8601_datetime(_timestamp(self.reviewed_at, "defense review time"))
        if self.responsible_actor != "bluefire.controller":
            raise EngineExperimentError("engine worker cannot be the defensive-change actor")
        for optional_time, label in (
            (self.applied_at, "defense application time"),
            (self.reconciled_at, "defense reconciliation time"),
            (self.retained_at, "defense retention time"),
            (self.rollback_started_at, "defense rollback start time"),
            (self.rolled_back_at, "defense rollback time"),
        ):
            if (
                optional_time is not None
                and parse_iso8601_datetime(_timestamp(optional_time, label)) < reviewed
            ):
                raise EngineExperimentError("defense transition predates review")
        if self.state is DefenseState.REVIEWED and any(
            value is not None
            for value in (
                self.applied_configuration_digest,
                self.application_receipt_digest,
                self.reconciliation_receipt_digest,
                self.rollback_operation_digest,
                self.rollback_receipt_digest,
                self.applied_at,
                self.reconciled_at,
                self.retained_at,
                self.rollback_started_at,
                self.rolled_back_at,
            )
        ):
            raise EngineExperimentError("reviewed defense already claims an operation")
        if (self.reconciliation_receipt_digest is None) != (self.reconciled_at is None):
            raise EngineExperimentError("defense reconciliation receipt is incomplete")
        applied_verified = all(
            value is not None
            for value in (
                self.applied_configuration_digest,
                self.reconciliation_receipt_digest,
                self.reconciled_at,
            )
        )
        applied_unverified = all(
            value is None
            for value in (
                self.applied_configuration_digest,
                self.reconciliation_receipt_digest,
                self.reconciled_at,
            )
        )
        if not (applied_verified or applied_unverified):
            raise EngineExperimentError("defense application verification is incomplete")
        application_started = (
            self.application_receipt_digest is not None and self.applied_at is not None
        )
        rollback_started = (
            self.rollback_operation_digest is not None and self.rollback_started_at is not None
        )
        if (self.rollback_operation_digest is None) != (self.rollback_started_at is None):
            raise EngineExperimentError("defense rollback operation receipt is incomplete")
        if self.state is DefenseState.APPLIED and (
            not application_started
            or not applied_verified
            or rollback_started
            or any(
                value is not None
                for value in (
                    self.retained_at,
                    self.rolled_back_at,
                    self.rollback_receipt_digest,
                )
            )
        ):
            raise EngineExperimentError("applied defense has invalid operation fields")
        if self.state is DefenseState.RETAINED and (
            not application_started
            or not applied_verified
            or self.retained_at is None
            or rollback_started
            or self.rolled_back_at is not None
            or self.rollback_receipt_digest is not None
        ):
            raise EngineExperimentError("retained defense fields are inconsistent")
        if self.state is DefenseState.UNKNOWN and (
            not application_started
            or self.retained_at is not None
            or self.rolled_back_at is not None
            or self.rollback_receipt_digest is not None
            or (not rollback_started and not applied_unverified)
        ):
            raise EngineExperimentError("unknown defense fields are inconsistent")
        if self.state is DefenseState.ROLLED_BACK and (
            not application_started
            or not rollback_started
            or self.rollback_receipt_digest is None
            or self.rolled_back_at is None
            or self.retained_at is not None
        ):
            raise EngineExperimentError("rolled-back defense fields are inconsistent")
        applied_boundary = self.reconciled_at or self.applied_at
        if applied_boundary is not None:
            boundary = parse_iso8601_datetime(applied_boundary)
            if (
                self.reconciled_at is not None
                and self.applied_at is not None
                and (
                    parse_iso8601_datetime(self.reconciled_at)
                    < parse_iso8601_datetime(self.applied_at)
                )
            ):
                raise EngineExperimentError("defense reconciliation predates application")
            if self.retained_at is not None and parse_iso8601_datetime(self.retained_at) < boundary:
                raise EngineExperimentError("defense retention predates application")
            if (
                self.rolled_back_at is not None
                and parse_iso8601_datetime(self.rolled_back_at) < boundary
            ):
                raise EngineExperimentError("defense rollback predates application")
        if self.rollback_started_at is not None:
            rollback_started_at = parse_iso8601_datetime(self.rollback_started_at)
            if applied_boundary is None or rollback_started_at < parse_iso8601_datetime(
                applied_boundary
            ):
                raise EngineExperimentError("defense rollback started before application")
            if (
                self.rolled_back_at is not None
                and parse_iso8601_datetime(self.rolled_back_at) < rollback_started_at
            ):
                raise EngineExperimentError("defense rollback completed before it started")

    def apply(
        self,
        *,
        applied_configuration_digest: str,
        application_receipt_digest: str,
        applied_at: str,
    ) -> "EngineDefenseChange":
        if self.state is not DefenseState.UNKNOWN or self.rollback_operation_digest is not None:
            raise EngineExperimentError(
                "defense application must be durably begun before it can be verified"
            )
        return self.reconcile_applied(
            applied_configuration_digest=applied_configuration_digest,
            reconciliation_receipt_digest=application_receipt_digest,
            reconciled_at=applied_at,
        )

    def reconcile_applied(
        self,
        *,
        applied_configuration_digest: str,
        reconciliation_receipt_digest: str,
        reconciled_at: str,
    ) -> "EngineDefenseChange":
        if self.state is not DefenseState.UNKNOWN or self.rollback_operation_digest is not None:
            raise EngineExperimentError("defense state does not require reconciliation")
        if applied_configuration_digest != self.approved_configuration_digest:
            raise EngineExperimentError(
                "applied defense configuration differs from its reviewed configuration"
            )
        result = replace(
            self,
            state=DefenseState.APPLIED,
            applied_configuration_digest=_digest(
                applied_configuration_digest, "applied defense configuration"
            ),
            reconciliation_receipt_digest=_digest(
                reconciliation_receipt_digest, "defense reconciliation receipt"
            ),
            reconciled_at=_timestamp(reconciled_at, "defense reconciliation time"),
        )
        result.validate()
        return result

    def application_unknown(
        self, *, application_receipt_digest: str, applied_at: str
    ) -> "EngineDefenseChange":
        if self.state is not DefenseState.REVIEWED:
            raise EngineExperimentError("only an attempted application can become unknown")
        result = replace(
            self,
            state=DefenseState.UNKNOWN,
            application_receipt_digest=_digest(
                application_receipt_digest, "defense application receipt"
            ),
            applied_at=_timestamp(applied_at, "defense application time"),
        )
        result.validate()
        return result

    def begin_rollback(
        self, *, rollback_operation_digest: str, rollback_started_at: str
    ) -> "EngineDefenseChange":
        if (
            self.state
            not in {
                DefenseState.APPLIED,
                DefenseState.RETAINED,
                DefenseState.UNKNOWN,
            }
            or self.rollback_operation_digest is not None
        ):
            raise EngineExperimentError("defense rollback operation cannot begin")
        result = replace(
            self,
            state=DefenseState.UNKNOWN,
            rollback_operation_digest=_digest(
                rollback_operation_digest, "defense rollback operation"
            ),
            rollback_started_at=_timestamp(rollback_started_at, "defense rollback start time"),
            retained_at=None,
        )
        result.validate()
        return result

    def retain(self, *, retained_at: str) -> "EngineDefenseChange":
        if self.state is not DefenseState.APPLIED:
            raise EngineExperimentError("only an applied defense can be retained")
        result = replace(
            self,
            state=DefenseState.RETAINED,
            retained_at=_timestamp(retained_at, "defense retention time"),
        )
        result.validate()
        return result

    def rollback(
        self, *, rollback_receipt_digest: str, rolled_back_at: str
    ) -> "EngineDefenseChange":
        if self.state is not DefenseState.UNKNOWN or self.rollback_operation_digest is None:
            raise EngineExperimentError(
                "defense rollback must be durably begun before it can be verified"
            )
        result = replace(
            self,
            state=DefenseState.ROLLED_BACK,
            rollback_receipt_digest=_digest(rollback_receipt_digest, "defense rollback receipt"),
            retained_at=None,
            rolled_back_at=_timestamp(rolled_back_at, "defense rollback time"),
        )
        result.validate()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "change_id": self.change_id,
            "experiment_id": self.experiment_id,
            "mechanism_ref": self.mechanism_ref,
            "preimage_digest": self.preimage_digest,
            "approved_configuration_digest": self.approved_configuration_digest,
            "applied_configuration_digest": self.applied_configuration_digest,
            "application_receipt_digest": self.application_receipt_digest,
            "reconciliation_receipt_digest": self.reconciliation_receipt_digest,
            "before_target_snapshot_ref": self.before_target_snapshot_ref,
            "after_target_snapshot_ref": self.after_target_snapshot_ref,
            "rollback_digest": self.rollback_digest,
            "rollback_operation_digest": self.rollback_operation_digest,
            "rollback_receipt_digest": self.rollback_receipt_digest,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "responsible_actor": self.responsible_actor,
            "state": self.state.value,
            "applied_at": self.applied_at,
            "reconciled_at": self.reconciled_at,
            "retained_at": self.retained_at,
            "rollback_started_at": self.rollback_started_at,
            "rolled_back_at": self.rolled_back_at,
        }


@dataclass(frozen=True, slots=True)
class EngineExperiment:
    schema_version: str
    experiment_id: str
    revision: int
    previous_revision_digest: str | None
    objective_ref: str
    environment_ref: str
    scope_ref: str
    scope_version: str
    initial_target_snapshot_ref: str
    current_target_snapshot_ref: str | None
    attempts: tuple[EngineAttemptEntry, ...]
    checks: tuple[ControllerCheckRecord, ...]
    independent_observations: tuple[IndependentObservationRecord, ...]
    defense_change: EngineDefenseChange | None
    created_at: str
    updated_at: str

    @classmethod
    def create(
        cls,
        *,
        experiment_id: str,
        objective_ref: str,
        environment_ref: str,
        scope_ref: str,
        scope_version: str,
        target_snapshot_ref: str,
        created_at: str,
    ) -> "EngineExperiment":
        value = cls(
            schema_version="bluefire.engine-experiment.v2",
            experiment_id=experiment_id,
            revision=1,
            previous_revision_digest=None,
            objective_ref=objective_ref,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
            scope_version=scope_version,
            initial_target_snapshot_ref=target_snapshot_ref,
            current_target_snapshot_ref=target_snapshot_ref,
            attempts=(),
            checks=(),
            independent_observations=(),
            defense_change=None,
            created_at=created_at,
            updated_at=created_at,
        )
        value.validate()
        return value

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        _controller_authority: object | None = None,
    ) -> "EngineExperiment":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine experiment")
        raw_attempts = row["attempts"]
        raw_checks = row["checks"]
        raw_observations = row["independent_observations"]
        if (
            not isinstance(raw_attempts, list)
            or not isinstance(raw_checks, list)
            or not isinstance(raw_observations, list)
            or len(raw_attempts) > 2
            or len(raw_checks) > 2
            or len(raw_observations) > 256
        ):
            raise EngineExperimentError("engine experiment collections are invalid")
        if raw_observations and _controller_authority is not _CONTROLLER_OBSERVATION_AUTHORITY:
            raise EngineExperimentError(
                "persisted independent observations require trusted controller authority"
            )
        try:
            result = cls(
                schema_version=row["schema_version"],
                experiment_id=row["experiment_id"],
                revision=row["revision"],
                previous_revision_digest=row["previous_revision_digest"],
                objective_ref=row["objective_ref"],
                environment_ref=row["environment_ref"],
                scope_ref=row["scope_ref"],
                scope_version=row["scope_version"],
                initial_target_snapshot_ref=row["initial_target_snapshot_ref"],
                current_target_snapshot_ref=row["current_target_snapshot_ref"],
                attempts=tuple(EngineAttemptEntry.from_mapping(item) for item in raw_attempts),
                checks=tuple(ControllerCheckRecord.from_mapping(item) for item in raw_checks),
                independent_observations=tuple(
                    IndependentObservationRecord.from_mapping(
                        item,
                        _controller_authority=_controller_authority,
                    )
                    for item in raw_observations
                ),
                defense_change=(
                    None
                    if row["defense_change"] is None
                    else EngineDefenseChange.from_mapping(row["defense_change"])
                ),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
        except EngineExperimentError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise EngineExperimentError("engine experiment is invalid") from exc
        result.validate()
        if result.to_dict() != json_clone(value):
            raise EngineExperimentError("engine experiment is not canonical")
        return result

    @classmethod
    def _from_controller_mapping(cls, value: Any) -> "EngineExperiment":
        """Rehydrate controller-attested observations from protected persistence only."""

        return cls.from_mapping(
            value,
            _controller_authority=_CONTROLLER_OBSERVATION_AUTHORITY,
        )

    def validate(self) -> None:
        if self.schema_version != "bluefire.engine-experiment.v2":
            raise EngineExperimentError("engine experiment schema is unsupported")
        if _EXPERIMENT_ID.fullmatch(self.experiment_id) is None:
            raise EngineExperimentError("engine experiment identity is invalid")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or not 1 <= self.revision <= 10_000
        ):
            raise EngineExperimentError("engine experiment revision is invalid")
        if self.revision == 1:
            if self.previous_revision_digest is not None:
                raise EngineExperimentError("initial experiment has prior revision state")
        elif self.previous_revision_digest is None:
            raise EngineExperimentError("updated experiment lacks its prior revision digest")
        if self.previous_revision_digest is not None:
            _digest(self.previous_revision_digest, "previous experiment revision")
        for value, label in (
            (self.objective_ref, "objective reference"),
            (self.environment_ref, "environment reference"),
            (self.scope_ref, "scope reference"),
            (self.initial_target_snapshot_ref, "initial target snapshot"),
        ):
            _digest(value, label)
        if self.current_target_snapshot_ref is not None:
            _digest(self.current_target_snapshot_ref, "current target snapshot")
        if self.scope_version != ENGINE_CAPABILITY_SCOPE_VERSION:
            raise EngineExperimentError(
                "external engine requires its versioned capability delegation"
            )
        created = parse_iso8601_datetime(_timestamp(self.created_at, "experiment creation time"))
        updated = parse_iso8601_datetime(_timestamp(self.updated_at, "experiment update time"))
        if updated < created:
            raise EngineExperimentError("engine experiment update predates creation")

        roles = tuple(entry.record.binding.role for entry in self.attempts)
        if roles != _ENGINE_ROLE_ORDER[: len(roles)]:
            raise EngineExperimentError("engine attempt roles are out of order")
        check_roles = tuple(check.role for check in self.checks)
        if check_roles != _CHECK_ROLE_ORDER[: len(check_roles)]:
            raise EngineExperimentError("controller check roles are out of order")
        identities: set[str] = set()
        sessions: set[str] = set()
        delegation_digests: set[str] = set()
        approval_digests: set[str] = set()
        approval_ids: set[str] = set()
        engine_evidence_ids: set[str] = set()
        for index, entry in enumerate(self.attempts):
            entry.validate()
            binding = entry.record.binding
            if (
                binding.experiment_id != self.experiment_id
                or binding.objective_ref != self.objective_ref
                or binding.environment_ref != self.environment_ref
                or binding.scope_ref != self.scope_ref
                or binding.scope_version != self.scope_version
            ):
                raise EngineExperimentError("attempt binding differs from its experiment")
            for identity in (binding.attempt_id, binding.run_id, entry.job_id):
                if identity in identities:
                    raise EngineExperimentError("experiment reuses a workflow identity")
                identities.add(identity)
            if entry.delegation_digest in delegation_digests:
                raise EngineExperimentError("engine attempt reuses a delegation")
            delegation_digests.add(entry.delegation_digest)
            if entry.execution_approval_digest in approval_digests:
                raise EngineExperimentError("engine attempt reuses an execution approval")
            approval_digests.add(entry.execution_approval_digest)
            if entry.execution_approval_id in approval_ids:
                raise EngineExperimentError("engine attempt reuses an execution approval identity")
            approval_ids.add(entry.execution_approval_id)
            if entry.record.upstream_session_id is not None:
                if entry.record.upstream_session_id in sessions:
                    raise EngineExperimentError("engine attempt reuses an upstream session")
                sessions.add(entry.record.upstream_session_id)
            expected_parent = None if index == 0 else self.attempts[0].record.binding.attempt_id
            if binding.parent_attempt_id != expected_parent:
                raise EngineExperimentError("engine attempt lineage is invalid")
            expected_target = (
                self.initial_target_snapshot_ref
                if binding.role is AttemptRole.BASELINE
                else self._historical_defense_target_snapshot()
            )
            if binding.target_snapshot_ref != expected_target:
                raise EngineExperimentError("engine attempt target snapshot changed")
            binding_created = parse_iso8601_datetime(binding.created_at)
            if binding_created < created or binding_created > updated:
                raise EngineExperimentError("engine attempt creation time is invalid")
            lifecycle_times = [
                parse_iso8601_datetime(value)
                for value in (
                    entry.record.started_at,
                    entry.record.ended_at,
                    entry.settled_at,
                )
                if value is not None
            ]
            if any(
                lifecycle_time < binding_created or lifecycle_time > updated
                for lifecycle_time in lifecycle_times
            ):
                raise EngineExperimentError(
                    "engine attempt lifecycle is outside the saved experiment"
                )
            if binding.role is AttemptRole.ADAPTIVE_SEARCH:
                reproducer = self._check_for_role(ControllerCheckRole.RETAINED_REPRODUCER)
                if reproducer is not None and reproducer.settled_at is not None:
                    reproducer_settled = parse_iso8601_datetime(reproducer.settled_at)
                    if reproducer_settled <= updated and (
                        binding_created < reproducer_settled
                        or (
                            entry.record.started_at is not None
                            and parse_iso8601_datetime(entry.record.started_at) < reproducer_settled
                        )
                    ):
                        raise EngineExperimentError(
                            "adaptive search predates retained reproducer settlement"
                        )
            known_for_entry = set(engine_evidence_ids)
            for item in entry.evidence:
                if item.evidence_id in engine_evidence_ids:
                    raise EngineExperimentError("experiment reuses engine evidence")
                if not set(item.parent_evidence_ids) <= known_for_entry:
                    raise EngineExperimentError("engine evidence cites an unavailable source")
                known_for_entry.add(item.evidence_id)
                engine_evidence_ids.add(item.evidence_id)

        for check in self.checks:
            check.validate()
            if check.experiment_id != self.experiment_id:
                raise EngineExperimentError("controller check belongs to another experiment")
            for identity in (check.check_id, check.run_id, check.job_id):
                if identity in identities:
                    raise EngineExperimentError("experiment reuses a workflow identity")
                identities.add(identity)
            if check.target_snapshot_ref != self._historical_defense_target_snapshot():
                raise EngineExperimentError("controller check target snapshot changed")
            if (
                self.defense_change is None
                or check.mechanism_ref != self.defense_change.mechanism_ref
            ):
                raise EngineExperimentError("controller check mechanism changed")
            check_created = parse_iso8601_datetime(check.created_at)
            if check_created < created or check_created > updated:
                raise EngineExperimentError("controller check creation time is invalid")
            if (
                self.defense_change is None
                or self.defense_change.reconciled_at is None
                or check_created < parse_iso8601_datetime(self.defense_change.reconciled_at)
            ):
                raise EngineExperimentError(
                    "controller check predates verified defense application"
                )
            if check.role is ControllerCheckRole.LEGITIMATE_USE:
                adaptive_owner = self._entry_for_role(AttemptRole.ADAPTIVE_SEARCH)
                if (
                    adaptive_owner is None
                    or adaptive_owner.settled_at is None
                    or check_created < parse_iso8601_datetime(adaptive_owner.settled_at)
                ):
                    raise EngineExperimentError("legitimate-use check predates adaptive settlement")
            if check.settled_at is not None and parse_iso8601_datetime(check.settled_at) > updated:
                raise EngineExperimentError("controller check settlement postdates the experiment")

        observation_ids: set[str] = set()
        observations_by_owner: dict[str, set[str]] = {}
        for observation in self.independent_observations:
            observation.validate()
            if observation.evidence_id in observation_ids:
                raise EngineExperimentError("experiment reuses an independent observation")
            observation_ids.add(observation.evidence_id)
            if observation.evidence.target_scope_ref != self.scope_ref:
                raise EngineExperimentError("independent observation scope changed")
            if observation.attempt_id is not None:
                _index, attempt = self._attempt(observation.attempt_id)
                owner_id = observation.attempt_id
                owner_run_id = attempt.record.binding.run_id
                owner_snapshot = attempt.record.binding.target_snapshot_ref
                if (
                    attempt.record.state not in _TERMINAL_ATTEMPT_STATES
                    or attempt.record.started_at is None
                    or attempt.record.ended_at is None
                    or attempt.settled_at is None
                ):
                    raise EngineExperimentError(
                        "independent observation requires a settled engine attempt"
                    )
                observed = parse_iso8601_datetime(observation.evidence.timestamp)
                binding_created = parse_iso8601_datetime(attempt.record.binding.created_at)
                started_at = parse_iso8601_datetime(attempt.record.started_at)
                ended_at = parse_iso8601_datetime(attempt.record.ended_at)
                attempt_settled_at = parse_iso8601_datetime(attempt.settled_at)
                if not binding_created <= started_at <= observed <= ended_at <= attempt_settled_at:
                    raise EngineExperimentError(
                        "independent observation falls outside its attempt lifecycle"
                    )
            else:
                _index, check = self._check(cast(str, observation.check_id))
                owner_id = cast(str, observation.check_id)
                owner_run_id = check.run_id
                owner_snapshot = check.target_snapshot_ref
                if observation.check_input_digest != check.input_digest:
                    raise EngineExperimentError("controller observation check intent changed")
                if observation.mechanism_ref != check.mechanism_ref:
                    raise EngineExperimentError("controller observation mechanism changed")
                observed = parse_iso8601_datetime(observation.evidence.timestamp)
                created_at = parse_iso8601_datetime(check.created_at)
                check_settled_at = (
                    None if check.settled_at is None else parse_iso8601_datetime(check.settled_at)
                )
                if observed < created_at or (
                    check_settled_at is not None and observed > check_settled_at
                ):
                    raise EngineExperimentError(
                        "controller observation falls outside its check lifecycle"
                    )
            if observed > updated:
                raise EngineExperimentError(
                    "independent observation postdates the saved experiment"
                )
            if (
                observation.evidence.run_id != owner_run_id
                or observation.target_snapshot_ref != owner_snapshot
            ):
                raise EngineExperimentError("independent observation owner binding changed")
            observations_by_owner.setdefault(owner_id, set()).add(observation.evidence_id)
        for check in self.checks:
            if not set(check.independent_evidence_refs) <= observations_by_owner.get(
                check.check_id, set()
            ):
                raise EngineExperimentError("controller check cites unavailable evidence")

        self._validate_workflow_stage()
        self._validate_defense_state()

    def _validate_workflow_stage(self) -> None:
        baseline = self._entry_for_role(AttemptRole.BASELINE)
        adaptive = self._entry_for_role(AttemptRole.ADAPTIVE_SEARCH)
        reproducer = self._check_for_role(ControllerCheckRole.RETAINED_REPRODUCER)
        legitimate = self._check_for_role(ControllerCheckRole.LEGITIMATE_USE)
        if reproducer is not None:
            defense_has_verified_applied_history = (
                self.defense_change is not None
                and self.defense_change.applied_configuration_digest
                == self.defense_change.approved_configuration_digest
                and self.defense_change.reconciliation_receipt_digest is not None
                and self.defense_change.reconciled_at is not None
            )
            defense_preserves_historical_applied_state = self.defense_change is not None and (
                self.defense_change.state
                in {
                    DefenseState.APPLIED,
                    DefenseState.RETAINED,
                    DefenseState.ROLLED_BACK,
                }
                or (
                    self.defense_change.state is DefenseState.UNKNOWN
                    and self.defense_change.rollback_operation_digest is not None
                )
            )
            if (
                baseline is None
                or baseline.record.state not in _TERMINAL_ATTEMPT_STATES
                or not defense_has_verified_applied_history
                or not defense_preserves_historical_applied_state
            ):
                raise EngineExperimentError("retained reproducer is ahead of the workflow")
        if adaptive is not None and (
            reproducer is None
            or reproducer.state not in _TERMINAL_CHECK_STATES
            or reproducer.cleanup_state is not CleanupState.VERIFIED_ABSENT
        ):
            raise EngineExperimentError("adaptive search is ahead of the workflow")
        if legitimate is not None and (
            adaptive is None
            or adaptive.record.state not in _TERMINAL_ATTEMPT_STATES
            or adaptive.cleanup_state is not CleanupState.VERIFIED_ABSENT
        ):
            raise EngineExperimentError("legitimate-use check is ahead of the workflow")

    def _validate_defense_state(self) -> None:
        if self.defense_change is None:
            if self.current_target_snapshot_ref != self.initial_target_snapshot_ref:
                raise EngineExperimentError("target changed without a defensive change")
            return
        change = self.defense_change
        change.validate()
        if (
            change.experiment_id != self.experiment_id
            or change.before_target_snapshot_ref != self.initial_target_snapshot_ref
        ):
            raise EngineExperimentError("defense change belongs to another experiment state")
        baseline = self._entry_for_role(AttemptRole.BASELINE)
        if (
            baseline is None
            or baseline.record.state not in _TERMINAL_ATTEMPT_STATES
            or baseline.cleanup_state is not CleanupState.VERIFIED_ABSENT
            or not any(
                observation.attempt_id == baseline.record.binding.attempt_id
                and observation.mechanism_ref == change.mechanism_ref
                and observation.target_snapshot_ref == self.initial_target_snapshot_ref
                and observation.assessment == "unauthorized_disclosure"
                for observation in self.independent_observations
            )
        ):
            raise EngineExperimentError("defense lacks its independent baseline proof")
        if baseline.settled_at is None or parse_iso8601_datetime(
            change.reviewed_at
        ) < parse_iso8601_datetime(baseline.settled_at):
            raise EngineExperimentError("defense review predates baseline settlement")
        transition_times = (
            change.reviewed_at,
            change.applied_at,
            change.reconciled_at,
            change.retained_at,
            change.rollback_started_at,
            change.rolled_back_at,
        )
        if any(
            value is not None
            and parse_iso8601_datetime(value) > parse_iso8601_datetime(self.updated_at)
            for value in transition_times
        ):
            raise EngineExperimentError("defense transition postdates the saved experiment")
        workflow_settlements = [
            parse_iso8601_datetime(settled_at)
            for settled_at in (
                *(entry.settled_at for entry in self.attempts),
                *(check.settled_at for check in self.checks),
            )
            if settled_at is not None
        ]
        if change.retained_at is not None and any(
            parse_iso8601_datetime(change.retained_at) < settled_at
            for settled_at in workflow_settlements
        ):
            raise EngineExperimentError("defense retention predates workflow settlement")
        if change.rollback_started_at is not None and any(
            parse_iso8601_datetime(change.rollback_started_at) < settled_at
            for settled_at in workflow_settlements
        ):
            raise EngineExperimentError("defense rollback predates workflow settlement")
        if change.rolled_back_at is not None and any(
            parse_iso8601_datetime(change.rolled_back_at) < settled_at
            for settled_at in workflow_settlements
        ):
            raise EngineExperimentError("defense rollback predates workflow settlement")
        expected = {
            DefenseState.REVIEWED: self.initial_target_snapshot_ref,
            DefenseState.APPLIED: change.after_target_snapshot_ref,
            DefenseState.RETAINED: change.after_target_snapshot_ref,
            DefenseState.ROLLED_BACK: self.initial_target_snapshot_ref,
            DefenseState.UNKNOWN: None,
        }[change.state]
        if self.current_target_snapshot_ref != expected:
            raise EngineExperimentError("current target snapshot differs from defense state")
        if change.state is DefenseState.RETAINED:
            self._require_complete_workflow()
            self._require_owned_work_absent()
        if change.state is DefenseState.ROLLED_BACK or (
            change.state is DefenseState.UNKNOWN and change.rollback_operation_digest is not None
        ):
            self._require_owned_work_absent()

    def _changed(self, *, timestamp: str, **changes: Any) -> "EngineExperiment":
        when = _timestamp(timestamp, "experiment update time")
        if parse_iso8601_datetime(when) < parse_iso8601_datetime(self.updated_at):
            raise EngineExperimentError("experiment update moved backward")
        value = replace(
            self,
            revision=self.revision + 1,
            previous_revision_digest=self.digest,
            updated_at=when,
            **changes,
        )
        value.validate()
        return value

    def reserve_attempt(
        self,
        binding: EngineAttemptBinding,
        *,
        job_id: str,
        delegation_digest: str,
        execution_approval_digest: str,
        execution_approval_id: str,
        timestamp: str,
    ) -> "EngineExperiment":
        binding = _binding_from_object(binding)
        if len(self.attempts) >= len(_ENGINE_ROLE_ORDER):
            raise EngineExperimentError("engine experiment already has every engine attempt")
        expected_role = _ENGINE_ROLE_ORDER[len(self.attempts)]
        if binding.role is not expected_role:
            raise EngineExperimentError("engine attempt role is not the next workflow stage")
        if binding.scope_version != ENGINE_CAPABILITY_SCOPE_VERSION:
            raise EngineExperimentError("legacy authorization cannot admit an engine attempt")
        if expected_role is AttemptRole.ADAPTIVE_SEARCH:
            reproducer = self._check_for_role(ControllerCheckRole.RETAINED_REPRODUCER)
            if (
                reproducer is None
                or reproducer.state not in _TERMINAL_CHECK_STATES
                or reproducer.cleanup_state is not CleanupState.VERIFIED_ABSENT
            ):
                raise EngineExperimentError(
                    "adaptive search requires the settled retained reproducer"
                )
        if self.attempts:
            previous = self.attempts[-1]
            if (
                previous.record.state not in _TERMINAL_ATTEMPT_STATES
                or previous.cleanup_state is not CleanupState.VERIFIED_ABSENT
            ):
                raise EngineExperimentError(
                    "owned engine work must be verified absent before continuation"
                )
        entry = EngineAttemptEntry.reserve(
            job_id,
            binding,
            delegation_digest=delegation_digest,
            execution_approval_digest=execution_approval_digest,
            execution_approval_id=execution_approval_id,
        )
        return self._changed(timestamp=timestamp, attempts=(*self.attempts, entry))

    def update_attempt_record(
        self, record: EngineAttemptRecord, *, timestamp: str
    ) -> "EngineExperiment":
        record = _record_from_mapping(record.to_dict())
        index, current = self._attempt(record.binding.attempt_id)
        if current.record.binding_digest != record.binding_digest:
            raise EngineExperimentError("engine attempt binding changed")
        if current.settled_at is not None:
            raise EngineExperimentError("settled engine attempt cannot be rewritten")
        self._require_record_transition(current.record, record)
        return self._replace_attempt(index, replace(current, record=record), timestamp=timestamp)

    def settle_attempt(
        self,
        record: EngineAttemptRecord,
        *,
        engine_evidence: Iterable[EngineEvidenceItem],
        artifact_manifest_ref: str | None,
        cleanup_state: CleanupState,
        cleanup_evidence_ref: str,
        settled_at: str,
    ) -> "EngineExperiment":
        record = _record_from_mapping(record.to_dict())
        if record.state not in _TERMINAL_ATTEMPT_STATES:
            raise EngineExperimentError("only a terminal attempt can settle")
        index, current = self._attempt(record.binding.attempt_id)
        if current.record.binding_digest != record.binding_digest or current.settled_at is not None:
            raise EngineExperimentError("engine attempt settlement changed or was repeated")
        self._require_record_transition(current.record, record)
        evidence = tuple(_evidence_from_mapping(item.to_dict()) for item in engine_evidence)
        if any(item.category not in _ENGINE_CATEGORIES for item in evidence):
            raise EngineExperimentError("engine runtime cannot create independent evidence")
        self._validate_engine_evidence(current, evidence)
        known = {item.evidence_id for entry in self.attempts for item in entry.evidence}
        for item in evidence:
            if item.evidence_id in known:
                raise EngineExperimentError("engine evidence identity was reused")
            if not set(item.parent_evidence_ids) <= known:
                raise EngineExperimentError("engine evidence cites an unavailable source")
            known.add(item.evidence_id)
        entry = replace(
            current,
            record=record,
            evidence=(*current.evidence, *evidence),
            artifact_manifest_ref=(
                None
                if artifact_manifest_ref is None
                else _digest(artifact_manifest_ref, "artifact manifest reference")
            ),
            cleanup_state=cleanup_state,
            cleanup_evidence_ref=_digest(cleanup_evidence_ref, "attempt cleanup receipt"),
            settled_at=_timestamp(settled_at, "attempt settlement time"),
        )
        entry.validate()
        return self._replace_attempt(index, entry, timestamp=settled_at)

    def reconcile_attempt_cleanup(
        self,
        attempt_id: str,
        *,
        cleanup_state: CleanupState,
        cleanup_evidence_ref: str,
        timestamp: str,
    ) -> "EngineExperiment":
        index, current = self._attempt(attempt_id)
        if current.record.state not in _TERMINAL_ATTEMPT_STATES:
            raise EngineExperimentError("active engine attempt cleanup cannot reconcile")
        allowed = {
            CleanupState.UNKNOWN: {
                CleanupState.UNKNOWN,
                CleanupState.RESIDUE,
                CleanupState.VERIFIED_ABSENT,
            },
            CleanupState.RESIDUE: {CleanupState.RESIDUE, CleanupState.VERIFIED_ABSENT},
            CleanupState.VERIFIED_ABSENT: {CleanupState.VERIFIED_ABSENT},
        }
        if cleanup_state not in allowed.get(current.cleanup_state, set()):
            raise EngineExperimentError("attempt cleanup reconciliation regressed")
        entry = replace(
            current,
            cleanup_state=cleanup_state,
            cleanup_evidence_ref=_digest(cleanup_evidence_ref, "attempt cleanup receipt"),
        )
        entry.validate()
        return self._replace_attempt(index, entry, timestamp=timestamp)

    def record_independent_observation(
        self, observation: IndependentObservationRecord, *, timestamp: str
    ) -> "EngineExperiment":
        observation.validate()
        if observation.evidence_id in {item.evidence_id for item in self.independent_observations}:
            raise EngineExperimentError("independent observation identity was reused")
        when = parse_iso8601_datetime(_timestamp(timestamp, "observation update time"))
        try:
            observed = parse_iso8601_datetime(observation.evidence.timestamp)
        except ValueError as exc:
            raise EngineExperimentError("independent observation time is invalid") from exc
        if when < observed:
            raise EngineExperimentError("observation update predates the observation")
        if observation.attempt_id is not None:
            _index, attempt_owner = self._attempt(observation.attempt_id)
            if attempt_owner.record.binding.run_id != observation.evidence.run_id:
                raise EngineExperimentError("observation run differs from its engine attempt")
        else:
            _index, check_owner = self._check(cast(str, observation.check_id))
            if check_owner.run_id != observation.evidence.run_id:
                raise EngineExperimentError("observation run differs from its controller check")
        return self._changed(
            timestamp=timestamp,
            independent_observations=(*self.independent_observations, observation),
        )

    def review_defense(self, change: EngineDefenseChange, *, timestamp: str) -> "EngineExperiment":
        change = EngineDefenseChange.from_mapping(change.to_dict())
        reviewed_at = _timestamp(timestamp, "defense review update time")
        if change.reviewed_at != reviewed_at:
            raise EngineExperimentError("defense review time differs from its persisted event")
        if self.defense_change is not None or len(self.attempts) != 1:
            raise EngineExperimentError("defense review requires exactly one baseline")
        baseline = self.attempts[0]
        if (
            baseline.record.binding.role is not AttemptRole.BASELINE
            or baseline.record.state not in _TERMINAL_ATTEMPT_STATES
            or baseline.cleanup_state is not CleanupState.VERIFIED_ABSENT
        ):
            raise EngineExperimentError("defense review requires a settled clean baseline")
        if change.state is not DefenseState.REVIEWED:
            raise EngineExperimentError("defense must begin as a reviewed controller change")
        if (
            change.experiment_id != self.experiment_id
            or change.before_target_snapshot_ref != self.initial_target_snapshot_ref
        ):
            raise EngineExperimentError("defense belongs to another experiment state")
        if not any(
            observation.attempt_id == baseline.record.binding.attempt_id
            and observation.mechanism_ref == change.mechanism_ref
            and observation.target_snapshot_ref == self.initial_target_snapshot_ref
            and observation.assessment == "unauthorized_disclosure"
            for observation in self.independent_observations
        ):
            raise EngineExperimentError("defense mechanism lacks independent baseline proof")
        return self._changed(timestamp=reviewed_at, defense_change=change)

    def begin_defense_application(
        self,
        change_id: str,
        *,
        operation_receipt_digest: str,
        started_at: str,
    ) -> "EngineExperiment":
        change = self._defense(change_id)
        unknown = change.application_unknown(
            application_receipt_digest=operation_receipt_digest,
            applied_at=started_at,
        )
        return self._changed(
            timestamp=started_at,
            defense_change=unknown,
            current_target_snapshot_ref=None,
        )

    def mark_defense_application_unknown(
        self,
        change_id: str,
        *,
        application_receipt_digest: str,
        applied_at: str,
    ) -> "EngineExperiment":
        return self.begin_defense_application(
            change_id,
            operation_receipt_digest=application_receipt_digest,
            started_at=applied_at,
        )

    def apply_defense(
        self,
        change_id: str,
        *,
        applied_configuration_digest: str,
        reconciliation_receipt_digest: str,
        observed_target_snapshot_ref: str,
        reconciled_at: str,
    ) -> "EngineExperiment":
        """Verify a durably begun application; never initiates external mutation."""

        change = self._defense(change_id)
        if change.state is not DefenseState.UNKNOWN or change.rollback_operation_digest is not None:
            raise EngineExperimentError(
                "defense application must be durably begun before it can be verified"
            )
        return self.reconcile_defense_applied(
            change_id,
            applied_configuration_digest=applied_configuration_digest,
            reconciliation_receipt_digest=reconciliation_receipt_digest,
            observed_target_snapshot_ref=observed_target_snapshot_ref,
            reconciled_at=reconciled_at,
        )

    def reconcile_defense_applied(
        self,
        change_id: str,
        *,
        applied_configuration_digest: str,
        reconciliation_receipt_digest: str,
        observed_target_snapshot_ref: str,
        reconciled_at: str,
    ) -> "EngineExperiment":
        change = self._defense(change_id)
        if change.state is not DefenseState.UNKNOWN:
            raise EngineExperimentError("defense state does not require reconciliation")
        if observed_target_snapshot_ref != change.after_target_snapshot_ref:
            raise EngineExperimentError("reconciled defense target snapshot changed")
        applied = change.reconcile_applied(
            applied_configuration_digest=applied_configuration_digest,
            reconciliation_receipt_digest=reconciliation_receipt_digest,
            reconciled_at=reconciled_at,
        )
        return self._changed(
            timestamp=reconciled_at,
            defense_change=applied,
            current_target_snapshot_ref=observed_target_snapshot_ref,
        )

    def reserve_controller_check(
        self, check: ControllerCheckRecord, *, timestamp: str
    ) -> "EngineExperiment":
        check = ControllerCheckRecord.from_mapping(check.to_dict())
        reserved_at = _timestamp(timestamp, "controller check reservation time")
        if check.created_at != reserved_at:
            raise EngineExperimentError("controller check creation differs from its reservation")
        if check.state is not ControllerCheckState.RESERVED:
            raise EngineExperimentError("controller check must begin reserved")
        if len(self.checks) >= len(_CHECK_ROLE_ORDER):
            raise EngineExperimentError("engine experiment already has every controller check")
        expected_role = _CHECK_ROLE_ORDER[len(self.checks)]
        if check.role is not expected_role or check.experiment_id != self.experiment_id:
            raise EngineExperimentError("controller check is not the next workflow stage")
        if self.defense_change is None or self.defense_change.state is not DefenseState.APPLIED:
            raise EngineExperimentError("controller check requires a verified applied defense")
        if (
            check.mechanism_ref != self.defense_change.mechanism_ref
            or check.target_snapshot_ref != self.defense_change.after_target_snapshot_ref
        ):
            raise EngineExperimentError("controller check changed its reviewed target")
        if expected_role is ControllerCheckRole.RETAINED_REPRODUCER:
            baseline = self._entry_for_role(AttemptRole.BASELINE)
            if (
                baseline is None
                or baseline.record.state not in _TERMINAL_ATTEMPT_STATES
                or baseline.cleanup_state is not CleanupState.VERIFIED_ABSENT
            ):
                raise EngineExperimentError("retained reproducer requires a clean baseline")
        else:
            adaptive = self._entry_for_role(AttemptRole.ADAPTIVE_SEARCH)
            if (
                adaptive is None
                or adaptive.record.state not in _TERMINAL_ATTEMPT_STATES
                or adaptive.cleanup_state is not CleanupState.VERIFIED_ABSENT
            ):
                raise EngineExperimentError("legitimate-use check requires adaptive settlement")
        return self._changed(timestamp=reserved_at, checks=(*self.checks, check))

    def settle_controller_check(
        self, check: ControllerCheckRecord, *, timestamp: str
    ) -> "EngineExperiment":
        check = ControllerCheckRecord.from_mapping(check.to_dict())
        settled_at = _timestamp(timestamp, "controller check settlement update time")
        index, current = self._check(check.check_id)
        if current.state is not ControllerCheckState.RESERVED:
            raise EngineExperimentError("controller check settlement was repeated")
        if (
            check.schema_version != current.schema_version
            or check.check_id != current.check_id
            or check.experiment_id != current.experiment_id
            or check.job_id != current.job_id
            or check.run_id != current.run_id
            or check.role is not current.role
            or check.performer is not current.performer
            or check.mechanism_ref != current.mechanism_ref
            or check.target_snapshot_ref != current.target_snapshot_ref
            or check.input_digest != current.input_digest
            or check.created_at != current.created_at
            or check.state not in _TERMINAL_CHECK_STATES
            or check.settled_at != settled_at
        ):
            raise EngineExperimentError("controller check identity or intent changed")
        check.validate()
        known = {
            observation.evidence_id
            for observation in self.independent_observations
            if observation.check_id == check.check_id
        }
        if not set(check.independent_evidence_refs) <= known:
            raise EngineExperimentError("controller check cites unavailable evidence")
        return self._replace_check(index, check, timestamp=settled_at)

    def reconcile_check_cleanup(
        self,
        check_id: str,
        *,
        cleanup_state: CleanupState,
        cleanup_evidence_ref: str,
        timestamp: str,
    ) -> "EngineExperiment":
        index, current = self._check(check_id)
        if current.state not in _TERMINAL_CHECK_STATES:
            raise EngineExperimentError("active controller check cleanup cannot reconcile")
        allowed = {
            CleanupState.UNKNOWN: {
                CleanupState.UNKNOWN,
                CleanupState.RESIDUE,
                CleanupState.VERIFIED_ABSENT,
            },
            CleanupState.RESIDUE: {
                CleanupState.RESIDUE,
                CleanupState.VERIFIED_ABSENT,
            },
            CleanupState.VERIFIED_ABSENT: {CleanupState.VERIFIED_ABSENT},
        }
        if cleanup_state not in allowed.get(current.cleanup_state, set()):
            raise EngineExperimentError("controller cleanup reconciliation regressed")
        check = replace(
            current,
            cleanup_state=cleanup_state,
            cleanup_evidence_ref=_digest(cleanup_evidence_ref, "controller check cleanup receipt"),
        )
        check.validate()
        return self._replace_check(index, check, timestamp=timestamp)

    def retain_defense(self, change_id: str, *, retained_at: str) -> "EngineExperiment":
        self._require_complete_workflow()
        self._require_owned_work_absent()
        change = self._defense(change_id)
        retained = change.retain(retained_at=retained_at)
        return self._changed(timestamp=retained_at, defense_change=retained)

    def rollback_defense(
        self,
        change_id: str,
        *,
        rollback_receipt_digest: str,
        observed_target_snapshot_ref: str,
        rolled_back_at: str,
    ) -> "EngineExperiment":
        self._require_owned_work_absent()
        change = self._defense(change_id)
        if observed_target_snapshot_ref != self.initial_target_snapshot_ref:
            raise EngineExperimentError("rollback did not verify the reviewed preimage snapshot")
        rolled_back = change.rollback(
            rollback_receipt_digest=rollback_receipt_digest,
            rolled_back_at=rolled_back_at,
        )
        return self._changed(
            timestamp=rolled_back_at,
            defense_change=rolled_back,
            current_target_snapshot_ref=self.initial_target_snapshot_ref,
        )

    def begin_defense_rollback(
        self,
        change_id: str,
        *,
        rollback_operation_digest: str,
        rollback_started_at: str,
    ) -> "EngineExperiment":
        """Persist rollback intent before the controller mutates the target."""

        self._require_owned_work_absent()
        change = self._defense(change_id)
        unknown = change.begin_rollback(
            rollback_operation_digest=rollback_operation_digest,
            rollback_started_at=rollback_started_at,
        )
        return self._changed(
            timestamp=rollback_started_at,
            defense_change=unknown,
            current_target_snapshot_ref=None,
        )

    def reconcile_defense_rolled_back(
        self,
        change_id: str,
        *,
        rollback_receipt_digest: str,
        observed_target_snapshot_ref: str,
        rolled_back_at: str,
    ) -> "EngineExperiment":
        return self.rollback_defense(
            change_id,
            rollback_receipt_digest=rollback_receipt_digest,
            observed_target_snapshot_ref=observed_target_snapshot_ref,
            rolled_back_at=rolled_back_at,
        )

    def _require_complete_workflow(self) -> None:
        if (
            tuple(entry.record.binding.role for entry in self.attempts) != _ENGINE_ROLE_ORDER
            or tuple(check.role for check in self.checks) != _CHECK_ROLE_ORDER
            or any(entry.record.state not in _TERMINAL_ATTEMPT_STATES for entry in self.attempts)
            or any(check.state not in _TERMINAL_CHECK_STATES for check in self.checks)
        ):
            raise EngineExperimentError("defense disposition waits for the complete workflow")

    def _require_owned_work_absent(self) -> None:
        if any(
            entry.record.state not in _TERMINAL_ATTEMPT_STATES
            or entry.cleanup_state is not CleanupState.VERIFIED_ABSENT
            for entry in self.attempts
        ) or any(
            check.state not in _TERMINAL_CHECK_STATES
            or check.cleanup_state is not CleanupState.VERIFIED_ABSENT
            for check in self.checks
        ):
            raise EngineExperimentError("owned workflow work is not verified absent")

    def _applied_target_snapshot(self) -> str:
        if self.defense_change is None or self.defense_change.state not in {
            DefenseState.APPLIED,
            DefenseState.RETAINED,
        }:
            raise EngineExperimentError("verified applied target snapshot is unavailable")
        return self.defense_change.after_target_snapshot_ref

    def _historical_defense_target_snapshot(self) -> str:
        if self.defense_change is None or self.defense_change.state is DefenseState.REVIEWED:
            raise EngineExperimentError("historical applied target snapshot is unavailable")
        if (
            self.defense_change.state is DefenseState.UNKNOWN
            and self.defense_change.rollback_operation_digest is None
        ):
            raise EngineExperimentError("historical applied target snapshot is unavailable")
        if self.defense_change.state in {
            DefenseState.UNKNOWN,
            DefenseState.ROLLED_BACK,
        } and (
            self.defense_change.applied_configuration_digest
            != self.defense_change.approved_configuration_digest
            or self.defense_change.reconciliation_receipt_digest is None
            or self.defense_change.reconciled_at is None
        ):
            raise EngineExperimentError(
                "historical applied target snapshot lacks verified application"
            )
        return self.defense_change.after_target_snapshot_ref

    def _defense(self, change_id: str) -> EngineDefenseChange:
        if self.defense_change is None or self.defense_change.change_id != change_id:
            raise EngineExperimentError("selected defensive change is unavailable")
        return self.defense_change

    def _attempt(self, attempt_id: str) -> tuple[int, EngineAttemptEntry]:
        found = [
            (index, entry)
            for index, entry in enumerate(self.attempts)
            if entry.record.binding.attempt_id == attempt_id
        ]
        if len(found) != 1:
            raise EngineExperimentError("selected engine attempt is unavailable")
        return found[0]

    def _check(self, check_id: str) -> tuple[int, ControllerCheckRecord]:
        found = [
            (index, check) for index, check in enumerate(self.checks) if check.check_id == check_id
        ]
        if len(found) != 1:
            raise EngineExperimentError("selected controller check is unavailable")
        return found[0]

    def _entry_for_role(self, role: AttemptRole) -> EngineAttemptEntry | None:
        return next(
            (entry for entry in self.attempts if entry.record.binding.role is role),
            None,
        )

    def _check_for_role(self, role: ControllerCheckRole) -> ControllerCheckRecord | None:
        return next((check for check in self.checks if check.role is role), None)

    def _replace_attempt(
        self, index: int, entry: EngineAttemptEntry, *, timestamp: str
    ) -> "EngineExperiment":
        attempts = list(self.attempts)
        attempts[index] = entry
        return self._changed(timestamp=timestamp, attempts=tuple(attempts))

    def _replace_check(
        self, index: int, check: ControllerCheckRecord, *, timestamp: str
    ) -> "EngineExperiment":
        checks = list(self.checks)
        checks[index] = check
        return self._changed(timestamp=timestamp, checks=tuple(checks))

    @staticmethod
    def _require_record_transition(
        current: EngineAttemptRecord, proposed: EngineAttemptRecord
    ) -> None:
        if current.state is proposed.state:
            raise EngineExperimentError("engine attempt lifecycle did not advance")
        try:
            expected = current.transition(
                proposed.state,
                upstream_session_id=proposed.upstream_session_id,
                timestamp=(
                    proposed.started_at
                    if proposed.state is AttemptState.RUNNING
                    else proposed.ended_at
                    if proposed.state in _TERMINAL_ATTEMPT_STATES
                    else None
                ),
                exit_code=proposed.exit_code,
                completeness=proposed.completeness,
                exit_reason=proposed.exit_reason,
                limitations=proposed.limitations,
            )
        except EngineAttemptContractError as exc:
            raise EngineExperimentError("engine attempt lifecycle transition is invalid") from exc
        if expected.to_dict() != proposed.to_dict():
            raise EngineExperimentError("engine attempt lifecycle history changed")

    @staticmethod
    def _validate_engine_evidence(
        entry: EngineAttemptEntry, evidence: Iterable[EngineEvidenceItem]
    ) -> None:
        binding = entry.record.binding
        if any(
            item.attempt_id != binding.attempt_id or item.run_id != binding.run_id
            for item in evidence
        ):
            raise EngineExperimentError("engine evidence belongs to another attempt or run")

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "revision": self.revision,
            "previous_revision_digest": self.previous_revision_digest,
            "objective_ref": self.objective_ref,
            "environment_ref": self.environment_ref,
            "scope_ref": self.scope_ref,
            "scope_version": self.scope_version,
            "initial_target_snapshot_ref": self.initial_target_snapshot_ref,
            "current_target_snapshot_ref": self.current_target_snapshot_ref,
            "attempts": [entry.to_dict() for entry in self.attempts],
            "checks": [check.to_dict() for check in self.checks],
            "independent_observations": [
                observation.to_dict() for observation in self.independent_observations
            ],
            "defense_change": (
                None if self.defense_change is None else self.defense_change.to_dict()
            ),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
