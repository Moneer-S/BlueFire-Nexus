"""Trusted controller operations for the generated tenant-record experiment.

The external engine never imports this module.  A BlueFire controller process
uses the narrow :class:`TenantRecordControllerTarget` port after it has admitted
an owned disposable target.  The port exposes fixed tenant-lab operations, not
URLs, commands, paths, credentials, or defensive authority to the engine.

This module deliberately keeps the two external-engine attempts separate from
the retained reproducer and legitimate-use checks.  Engine responses remain
untrusted until the protected target audit row and response bytes agree through
``observe_tenant_response``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast

from .engine_attempt_contract import AttemptRole as EngineAttemptRole
from .engine_experiment import (
    CleanupState,
    EngineAttemptEntry,
    IndependentObservationRecord,
    _controller_observation_record,
)
from .evidence import EvidenceRecord
from .tenant_record_controller_contract import (
    _ATTEMPT_ID,
    _CHECK_ID,
    _OPERATION_ID,
    _RUN_ID,
    SCHEMA_CHECK,
    SCHEMA_DISPOSITION,
    SCHEMA_ENGINE_OBSERVATION,
    SCHEMA_MUTATION,
    ControllerCheckRole,
    LabDisposition,
    MutationState,
    TenantDefensePlan,
    TenantFailureMechanism,
    TenantRecordControllerError,
    TenantRoute,
    TenantTargetCleanup,
    TenantTargetOperationUnknown,
    TenantTargetReadback,
    _checked_config,
    _defense_review_binding,
    _digest,
    _timestamp,
    tenant_target_snapshot_ref,
)
from .tenant_record_controller_contract import (
    SCHEMA_MECHANISM as SCHEMA_MECHANISM,
)
from .tenant_record_controller_contract import (
    SCHEMA_PLAN as SCHEMA_PLAN,
)
from .tenant_record_controller_contract import (
    SCHEMA_REVIEW as SCHEMA_REVIEW,
)
from .tenant_record_lab import (
    TenantDefenseConfig,
    TenantRecordFixture,
    baseline_defense_config,
    defense_change_receipt,
    generate_tenant_record_fixture,
    hardened_defense_config,
    mint_lab_session,
)
from .tenant_record_observer import (
    TenantAuditRow,
    checked_observation_content,
    observe_tenant_response,
)
from .tenant_record_service import TenantResponse
from .util import content_hash, json_clone, parse_iso8601_datetime


class TenantRecordControllerTarget(Protocol):
    """Narrow trusted target port implemented outside the engine worker."""

    def current_config(self) -> TenantDefenseConfig | None: ...

    def audit_row(self, request_id: str) -> TenantAuditRow: ...

    def controller_request(
        self,
        mechanism: TenantFailureMechanism,
        *,
        source_identity: str,
        session_token: str | None,
    ) -> TenantResponse: ...

    def apply_defense(self, plan: TenantDefensePlan) -> TenantTargetReadback: ...

    def rollback_defense(
        self, plan: TenantDefensePlan, *, operation_id: str
    ) -> TenantTargetReadback: ...

    def cleanup_lab(
        self,
        fixture: TenantRecordFixture,
        *,
        expected_config_digest: str,
        operation_id: str,
    ) -> TenantTargetCleanup: ...


@dataclass(frozen=True, slots=True)
class TenantMutationSettlement:
    operation_id: str
    direction: str
    state: MutationState
    plan_digest: str
    target_receipt_digest: str
    observed_config_digest: str | None
    target_snapshot_id: str | None
    change_id: str | None
    change_receipt_digest: str | None
    settled_at: str

    def __post_init__(self) -> None:
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise TenantRecordControllerError("mutation operation identity is invalid")
        if self.direction not in {"apply", "rollback", "reconcile_apply", "reconcile_rollback"}:
            raise TenantRecordControllerError("mutation direction is invalid")
        _digest(self.plan_digest, "mutation plan")
        _digest(self.target_receipt_digest, "mutation target receipt")
        if self.observed_config_digest is not None:
            _digest(self.observed_config_digest, "observed configuration")
        if (self.observed_config_digest is None) != (self.target_snapshot_id is None):
            raise TenantRecordControllerError("mutation readback is incomplete")
        applied = self.state is MutationState.APPLIED and self.direction in {
            "apply",
            "reconcile_apply",
        }
        if applied:
            if (
                not isinstance(self.change_id, str)
                or not self.change_id.startswith("change-")
                or self.change_receipt_digest is None
            ):
                raise TenantRecordControllerError("applied mutation lacks its change receipt")
            _digest(self.change_receipt_digest, "applied change receipt")
        elif self.change_id is not None or self.change_receipt_digest is not None:
            raise TenantRecordControllerError("non-applied mutation claimed a change receipt")
        _timestamp(self.settled_at, "mutation settlement time")

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_MUTATION,
            "operation_id": self.operation_id,
            "direction": self.direction,
            "state": self.state.value,
            "plan_digest": self.plan_digest,
            "target_receipt_digest": self.target_receipt_digest,
            "observed_config_digest": self.observed_config_digest,
            "target_snapshot_id": self.target_snapshot_id,
            "change_id": self.change_id,
            "change_receipt_digest": self.change_receipt_digest,
            "settled_at": self.settled_at,
        }


@dataclass(frozen=True, slots=True)
class TenantEngineObservation:
    role: EngineAttemptRole
    attempt_id: str
    run_id: str
    evidence: EvidenceRecord
    assessment: str
    target_snapshot_id: str
    failure_mechanism: TenantFailureMechanism | None

    def __post_init__(self) -> None:
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise TenantRecordControllerError("engine attempt identity is invalid")
        if _RUN_ID.fullmatch(self.run_id) is None:
            raise TenantRecordControllerError("engine observation run identity is invalid")
        content = checked_observation_content(self.evidence)
        if (
            content["attempt_id"] != self.attempt_id
            or self.evidence.run_id != self.run_id
            or content["assessment"] != self.assessment
            or content["target_snapshot_id"] != self.target_snapshot_id
        ):
            raise TenantRecordControllerError("engine observation evidence is inconsistent")
        if self.role is EngineAttemptRole.BASELINE:
            if self.assessment == "unauthorized_disclosure" and self.failure_mechanism is None:
                raise TenantRecordControllerError("baseline disclosure lacks its exact mechanism")
            if self.failure_mechanism is not None:
                mechanism = self.failure_mechanism
                environment = json_clone(self.evidence.environment)
                returned = content["returned_record_ids"]
                if (
                    environment.get("fixture_digest") != mechanism.fixture_digest
                    or mechanism.original_target_snapshot_id != self.target_snapshot_id
                    or mechanism.route.value != content["route"]
                    or mechanism.protected_tenant_id != content["requested_tenant"]
                    or mechanism.protected_tenant_id != content["authenticated_tenant"]
                    or (
                        mechanism.route is TenantRoute.RECORD_LOOKUP
                        and returned != [mechanism.record_id]
                    )
                    or (
                        mechanism.route is TenantRoute.BOUNDED_EXPORT
                        and mechanism.record_id is not None
                    )
                ):
                    raise TenantRecordControllerError(
                        "baseline failure mechanism does not match its observed request"
                    )
        elif self.failure_mechanism is not None:
            raise TenantRecordControllerError("adaptive observation cannot redefine the baseline")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_ENGINE_OBSERVATION,
            "role": self.role.value,
            "attempt_id": self.attempt_id,
            "run_id": self.run_id,
            "evidence_id": self.evidence.evidence_id,
            "evidence_digest": self.evidence.record_hash,
            "assessment": self.assessment,
            "target_snapshot_id": self.target_snapshot_id,
            "failure_mechanism": (
                None if self.failure_mechanism is None else self.failure_mechanism.to_dict()
            ),
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    @property
    def mechanism_ref(self) -> str:
        """Return the exact controller-observed mechanism, not an engine claim."""

        if self.failure_mechanism is not None:
            return cast(str, content_hash(self.failure_mechanism.to_dict()))
        content = checked_observation_content(self.evidence)
        return cast(
            str,
            content_hash(
                {
                    "schema_version": "bluefire.tenant-record-observed-mechanism.v1",
                    "target_snapshot_id": self.target_snapshot_id,
                    "route": content["route"],
                    "source_identity": content["source_identity"],
                    "requested_tenant": content["requested_tenant"],
                    "authenticated_tenant": content["authenticated_tenant"],
                    "audit_row_digest": content["audit_row_digest"],
                }
            ),
        )

    @property
    def target_snapshot_ref(self) -> str:
        """Return the digest reference used by the engine-attempt binding."""

        content = checked_observation_content(self.evidence)
        environment = json_clone(self.evidence.environment)
        return tenant_target_snapshot_ref(
            fixture_digest=environment["fixture_digest"],
            target_snapshot_id=self.target_snapshot_id,
            service_generation=content["service_generation"],
        )

    def independent_observation(self) -> IndependentObservationRecord:
        """Admit this protected target observation to canonical experiment state.

        The returned value carries the controller-only attestation used by the
        experiment state machine.  It is still the caller's responsibility to
        verify that the byte-identical evidence record is present in the
        finalized RunStore bundle before persistence.
        """

        return _controller_observation_record(
            target_snapshot_ref=self.target_snapshot_ref,
            mechanism_ref=self.mechanism_ref,
            attempt_id=self.attempt_id,
            evidence=self.evidence,
        )


@dataclass(frozen=True, slots=True)
class TenantControllerCheck:
    role: ControllerCheckRole
    check_id: str
    run_id: str
    mechanism_digest: str
    evidence: EvidenceRecord
    assessment: str
    passed: bool
    target_snapshot_id: str
    performed_at: str

    def __post_init__(self) -> None:
        if _CHECK_ID.fullmatch(self.check_id) is None or _RUN_ID.fullmatch(self.run_id) is None:
            raise TenantRecordControllerError("controller check identity is invalid")
        _digest(self.mechanism_digest, "controller check mechanism")
        if type(self.passed) is not bool:
            raise TenantRecordControllerError("controller check result is invalid")
        content = checked_observation_content(self.evidence)
        if (
            content["attempt_id"] != self.check_id
            or self.evidence.run_id != self.run_id
            or content["assessment"] != self.assessment
            or content["target_snapshot_id"] != self.target_snapshot_id
        ):
            raise TenantRecordControllerError("controller check evidence is inconsistent")
        expected = (
            self.assessment == "authorization_denied"
            if self.role is ControllerCheckRole.RETAINED_REPRODUCER
            else self.assessment == "legitimate_use_succeeded"
        )
        if self.passed is not expected:
            raise TenantRecordControllerError("controller check conclusion is inconsistent")
        _timestamp(self.performed_at, "controller check time")
        if self.performed_at != self.evidence.timestamp:
            raise TenantRecordControllerError(
                "controller check time does not match the protected target event"
            )

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_CHECK,
            "role": self.role.value,
            "check_id": self.check_id,
            "run_id": self.run_id,
            "mechanism_digest": self.mechanism_digest,
            "evidence_id": self.evidence.evidence_id,
            "evidence_digest": self.evidence.record_hash,
            "assessment": self.assessment,
            "passed": self.passed,
            "target_snapshot_id": self.target_snapshot_id,
            "performed_at": self.performed_at,
        }


@dataclass(frozen=True, slots=True)
class TenantLabDispositionReceipt:
    operation_id: str
    disposition: LabDisposition
    fixture_digest: str
    target_snapshot_id: str | None
    target_config_digest: str | None
    engine_observation_digests: tuple[str, str]
    engine_cleanup_receipts: tuple[str, str]
    reproducer_check_digest: str
    legitimate_use_check_digest: str
    target_cleanup_receipt_digest: str | None
    recorded_at: str

    def __post_init__(self) -> None:
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise TenantRecordControllerError("disposition operation identity is invalid")
        if not self.operation_id.startswith("tenant-cleanup-"):
            raise TenantRecordControllerError("disposition requires a cleanup operation identity")
        _digest(self.fixture_digest, "disposition fixture")
        for value in self.engine_cleanup_receipts:
            _digest(value, "engine cleanup receipt")
        if len(set(self.engine_cleanup_receipts)) != 2:
            raise TenantRecordControllerError("disposition cleanup receipts are not distinct")
        _digest(self.reproducer_check_digest, "reproducer check")
        _digest(self.legitimate_use_check_digest, "legitimate-use check")
        if self.target_config_digest is not None:
            _digest(self.target_config_digest, "disposition target configuration")
        for value in self.engine_observation_digests:
            _digest(value, "engine observation")
        if len(set(self.engine_observation_digests)) != 2:
            raise TenantRecordControllerError("disposition engine observations are not distinct")
        if self.target_cleanup_receipt_digest is not None:
            _digest(self.target_cleanup_receipt_digest, "target cleanup receipt")
        if self.disposition is LabDisposition.CLEANED:
            if (
                self.target_snapshot_id is not None
                or self.target_config_digest is not None
                or self.target_cleanup_receipt_digest is None
            ):
                raise TenantRecordControllerError("cleaned disposition retained target state")
        elif self.disposition is LabDisposition.RETAINED_HARDENING:
            if (
                self.target_snapshot_id is None
                or self.target_config_digest is None
                or self.target_cleanup_receipt_digest is not None
            ):
                raise TenantRecordControllerError("retained disposition is incomplete")
        elif (
            self.target_snapshot_id is None
            or self.target_config_digest is None
            or self.target_cleanup_receipt_digest is None
        ):
            raise TenantRecordControllerError("unknown disposition lost its target state")
        _timestamp(self.recorded_at, "disposition time")

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_DISPOSITION,
            "operation_id": self.operation_id,
            "disposition": self.disposition.value,
            "fixture_digest": self.fixture_digest,
            "target_snapshot_id": self.target_snapshot_id,
            "target_config_digest": self.target_config_digest,
            "engine_observation_digests": list(self.engine_observation_digests),
            "engine_cleanup_receipts": list(self.engine_cleanup_receipts),
            "reproducer_check_digest": self.reproducer_check_digest,
            "legitimate_use_check_digest": self.legitimate_use_check_digest,
            "target_cleanup_receipt_digest": self.target_cleanup_receipt_digest,
            "recorded_at": self.recorded_at,
        }


class TenantRecordExperimentController:
    """Trusted coordinator for one generated tenant-record fixture.

    The durable workflow must enter its UNKNOWN mutation phase before invoking
    ``apply_defense``, ``rollback_defense``, or ``cleanup_lab``.  The narrow
    ``TenantTargetOperationUnknown`` translation preserves adapter-reported
    uncertainty, while the outer write-ahead state covers process loss.
    """

    def __init__(
        self,
        *,
        fixture: TenantRecordFixture,
        target: TenantRecordControllerTarget,
        signing_key: bytes,
    ) -> None:
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise TenantRecordControllerError("controller signing key is invalid")
        self.fixture = fixture
        self._target = target
        self._signing_key = signing_key
        current = self._current_config()
        if current.fixture_digest != fixture.digest:
            raise TenantRecordControllerError("target belongs to another generated fixture")

    def _current_config(self) -> TenantDefenseConfig:
        value = self._target.current_config()
        if value is None:
            raise TenantRecordControllerError("current target configuration is unknown")
        return _checked_config(value)

    def _require_plan(self, plan: TenantDefensePlan) -> TenantDefensePlan:
        if not isinstance(plan, TenantDefensePlan) or plan.fixture_digest != self.fixture.digest:
            raise TenantRecordControllerError("defense plan belongs to another fixture")
        baseline = baseline_defense_config(self.fixture)
        if plan.before != baseline:
            raise TenantRecordControllerError("defense plan does not use the exact baseline")
        if plan.after.session_key_id is None or plan.after.application_nonce is None:
            raise TenantRecordControllerError("defense plan is missing its hardened identity")
        expected_after = hardened_defense_config(
            self.fixture,
            signing_key=self._signing_key,
            key_id=plan.after.session_key_id,
            application_nonce=plan.after.application_nonce,
            prior=baseline,
        )
        if plan.after != expected_after:
            raise TenantRecordControllerError(
                "defense plan is not bound to the controller signing key"
            )
        # Reconstruct the immutable plan so all constructor validation and the
        # exact reviewed-plan derivation run again at every mutating boundary.
        return TenantDefensePlan(
            operation_id=plan.operation_id,
            fixture_digest=plan.fixture_digest,
            before=plan.before,
            after=plan.after,
            review_id=plan.review_id,
            review_digest=plan.review_digest,
            responsible_actor=plan.responsible_actor,
            planned_at=plan.planned_at,
        )

    def prepare_defense(
        self,
        *,
        operation_id: str,
        key_id: str,
        application_nonce: str,
        responsible_actor: str,
        planned_at: str,
    ) -> TenantDefensePlan:
        before = self._current_config()
        expected = baseline_defense_config(self.fixture)
        if before != expected:
            raise TenantRecordControllerError("defense requires the exact current baseline")
        after = hardened_defense_config(
            self.fixture,
            signing_key=self._signing_key,
            key_id=key_id,
            application_nonce=application_nonce,
            prior=before,
        )
        review = _defense_review_binding(
            before,
            after,
            responsible_actor=responsible_actor,
            reviewed_at=planned_at,
        )
        review_digest = content_hash(review)
        return TenantDefensePlan(
            operation_id=operation_id,
            fixture_digest=self.fixture.digest,
            before=before,
            after=after,
            review_id="review-" + review_digest.removeprefix("sha256:")[:20],
            review_digest=review_digest,
            responsible_actor=responsible_actor,
            planned_at=planned_at,
        )

    @staticmethod
    def _classify_readback(
        plan: TenantDefensePlan,
        readback: TenantTargetReadback,
        *,
        direction: str,
        settled_at: str,
        operation_id: str,
    ) -> TenantMutationSettlement:
        _timestamp(settled_at, "mutation settlement time")
        if parse_iso8601_datetime(settled_at) < parse_iso8601_datetime(plan.planned_at):
            raise TenantRecordControllerError("mutation settlement predates its plan")
        observed = (
            None if readback.observed_config is None else _checked_config(readback.observed_config)
        )
        if direction in {"apply", "reconcile_apply"}:
            state = (
                MutationState.APPLIED
                if observed == plan.after
                else MutationState.NOT_APPLIED if observed == plan.before else MutationState.UNKNOWN
            )
        else:
            state = (
                MutationState.ROLLED_BACK
                if observed == plan.before
                else (
                    MutationState.NOT_ROLLED_BACK
                    if observed == plan.after
                    else MutationState.UNKNOWN
                )
            )
        change_receipt = (
            defense_change_receipt(
                plan.before,
                plan.after,
                responsible_actor=plan.responsible_actor,
                applied_at=settled_at,
            )
            if state is MutationState.APPLIED
            else None
        )
        return TenantMutationSettlement(
            operation_id=operation_id,
            direction=direction,
            state=state,
            plan_digest=plan.digest,
            target_receipt_digest=readback.receipt_digest,
            observed_config_digest=None if observed is None else observed.digest,
            target_snapshot_id=None if observed is None else observed.target_snapshot_id,
            change_id=(None if change_receipt is None else cast(str, change_receipt["change_id"])),
            change_receipt_digest=(
                None if change_receipt is None else content_hash(change_receipt)
            ),
            settled_at=settled_at,
        )

    def apply_defense(
        self, plan: TenantDefensePlan, *, settled_at: str
    ) -> TenantMutationSettlement:
        plan = self._require_plan(plan)
        if self._current_config() != plan.before:
            raise TenantRecordControllerError("defense preimage changed before apply")
        try:
            readback = self._target.apply_defense(plan)
        except TenantTargetOperationUnknown as exc:
            readback = TenantTargetReadback(observed_config=None, receipt_digest=exc.receipt_digest)
        return self._classify_readback(
            plan,
            readback,
            direction="apply",
            settled_at=settled_at,
            operation_id=plan.operation_id,
        )

    def reconcile_defense(
        self,
        plan: TenantDefensePlan,
        *,
        direction: str,
        operation_id: str,
        settled_at: str,
        observation_receipt_digest: str,
    ) -> TenantMutationSettlement:
        plan = self._require_plan(plan)
        if direction not in {"apply", "rollback"}:
            raise TenantRecordControllerError("reconciliation direction is invalid")
        value = self._target.current_config()
        readback = TenantTargetReadback(
            observed_config=None if value is None else _checked_config(value),
            receipt_digest=observation_receipt_digest,
        )
        return self._classify_readback(
            plan,
            readback,
            direction=f"reconcile_{direction}",
            settled_at=settled_at,
            operation_id=operation_id,
        )

    def rollback_defense(
        self,
        plan: TenantDefensePlan,
        *,
        operation_id: str,
        settled_at: str,
    ) -> TenantMutationSettlement:
        plan = self._require_plan(plan)
        if not operation_id.startswith("tenant-rollback-"):
            raise TenantRecordControllerError("rollback operation identity is invalid")
        if self._current_config() != plan.after:
            raise TenantRecordControllerError("rollback requires the exact hardened state")
        try:
            readback = self._target.rollback_defense(plan, operation_id=operation_id)
        except TenantTargetOperationUnknown as exc:
            readback = TenantTargetReadback(observed_config=None, receipt_digest=exc.receipt_digest)
        return self._classify_readback(
            plan,
            readback,
            direction="rollback",
            settled_at=settled_at,
            operation_id=operation_id,
        )

    def observe_engine_response(
        self,
        *,
        role: EngineAttemptRole,
        attempt_id: str,
        run_id: str,
        response: TenantResponse,
        step_id: str,
        target_scope_ref: str,
    ) -> TenantEngineObservation:
        request_id = response.headers.get("x-bluefire-lab-request")
        if not isinstance(request_id, str):
            raise TenantRecordControllerError("engine response lacks its target request identity")
        row = self._target.audit_row(request_id)
        config = self._current_config()
        evidence = observe_tenant_response(
            fixture=self.fixture,
            config=config,
            audit_row=row,
            response_status=response.status,
            response_headers=response.headers,
            response_body=response.body,
            attempt_id=attempt_id,
            run_id=run_id,
            step_id=step_id,
            target_scope_ref=target_scope_ref,
        )
        content = checked_observation_content(evidence)
        mechanism = (
            TenantFailureMechanism.from_baseline_audit(self.fixture, config, row)
            if role is EngineAttemptRole.BASELINE
            and content["assessment"] == "unauthorized_disclosure"
            else None
        )
        return TenantEngineObservation(
            role=role,
            attempt_id=attempt_id,
            run_id=run_id,
            evidence=evidence,
            assessment=cast(str, content["assessment"]),
            target_snapshot_id=config.target_snapshot_id,
            failure_mechanism=mechanism,
        )

    def _observe_controller_response(
        self,
        *,
        role: ControllerCheckRole,
        check_id: str,
        run_id: str,
        mechanism: TenantFailureMechanism,
        response: TenantResponse,
        target_scope_ref: str,
        performed_at: str,
    ) -> TenantControllerCheck:
        request_id = response.headers.get("x-bluefire-lab-request")
        if not isinstance(request_id, str):
            raise TenantRecordControllerError("controller response lacks its request identity")
        config = self._current_config()
        evidence = observe_tenant_response(
            fixture=self.fixture,
            config=config,
            audit_row=self._target.audit_row(request_id),
            response_status=response.status,
            response_headers=response.headers,
            response_body=response.body,
            attempt_id=check_id,
            run_id=run_id,
            step_id=role.value,
            target_scope_ref=target_scope_ref,
        )
        content = checked_observation_content(evidence)
        assessment = cast(str, content["assessment"])
        passed = (
            assessment == "authorization_denied"
            if role is ControllerCheckRole.RETAINED_REPRODUCER
            else assessment == "legitimate_use_succeeded"
        )
        return TenantControllerCheck(
            role=role,
            check_id=check_id,
            run_id=run_id,
            mechanism_digest=mechanism.request_digest,
            evidence=evidence,
            assessment=assessment,
            passed=passed,
            target_snapshot_id=config.target_snapshot_id,
            performed_at=performed_at,
        )

    def run_exact_reproducer(
        self,
        mechanism: TenantFailureMechanism,
        *,
        check_id: str,
        run_id: str,
        target_scope_ref: str,
        performed_at: str,
    ) -> TenantControllerCheck:
        self._require_mechanism(mechanism)
        if self._current_config().mode != "signed_session":
            raise TenantRecordControllerError("reproducer requires the hardened target")
        response = self._target.controller_request(
            mechanism,
            source_identity="controller_probe",
            session_token=None,
        )
        return self._observe_controller_response(
            role=ControllerCheckRole.RETAINED_REPRODUCER,
            check_id=check_id,
            run_id=run_id,
            mechanism=mechanism,
            response=response,
            target_scope_ref=target_scope_ref,
            performed_at=performed_at,
        )

    def run_legitimate_use(
        self,
        mechanism: TenantFailureMechanism,
        *,
        check_id: str,
        run_id: str,
        target_scope_ref: str,
        performed_at: str,
        issued_at: datetime,
        lifetime_seconds: int,
    ) -> TenantControllerCheck:
        self._require_mechanism(mechanism)
        config = self._current_config()
        if config.mode != "signed_session":
            raise TenantRecordControllerError("legitimate-use check requires the hardened target")
        token = mint_lab_session(
            self.fixture,
            config,
            signing_key=self._signing_key,
            subject_id=self.fixture.legitimate_subject_id,
            tenant_id=self.fixture.protected_tenant_id,
            issued_at=issued_at,
            lifetime_seconds=lifetime_seconds,
        )
        response = self._target.controller_request(
            mechanism,
            source_identity="ordinary_user",
            session_token=token,
        )
        return self._observe_controller_response(
            role=ControllerCheckRole.LEGITIMATE_USE,
            check_id=check_id,
            run_id=run_id,
            mechanism=mechanism,
            response=response,
            target_scope_ref=target_scope_ref,
            performed_at=performed_at,
        )

    def _require_mechanism(self, mechanism: TenantFailureMechanism) -> None:
        baseline = baseline_defense_config(self.fixture)
        protected_records = {
            record.record_id
            for record in self.fixture.records_for(self.fixture.protected_tenant_id)
        }
        if (
            not isinstance(mechanism, TenantFailureMechanism)
            or mechanism.fixture_digest != self.fixture.digest
            or mechanism.protected_tenant_id != self.fixture.protected_tenant_id
            or mechanism.original_target_snapshot_id != baseline.target_snapshot_id
            or (
                mechanism.route is TenantRoute.RECORD_LOOKUP
                and mechanism.record_id not in protected_records
            )
        ):
            raise TenantRecordControllerError("failure mechanism belongs to another fixture")
        # Force the canonical digest check even if a caller mutated an unsafe
        # foreign object that merely mimics the dataclass.
        TenantFailureMechanism(
            fixture_digest=mechanism.fixture_digest,
            original_target_snapshot_id=mechanism.original_target_snapshot_id,
            route=mechanism.route,
            protected_tenant_id=mechanism.protected_tenant_id,
            record_id=mechanism.record_id,
            request_digest=mechanism.request_digest,
        )

    @staticmethod
    def _verified_cleanup_receipts(
        cleanup: tuple[EngineAttemptEntry, EngineAttemptEntry],
        *,
        baseline: TenantEngineObservation,
        adaptive: TenantEngineObservation,
    ) -> tuple[str, str]:
        checked = tuple(EngineAttemptEntry.from_mapping(item.to_dict()) for item in cleanup)
        by_role = {item.record.binding.role: item for item in checked}
        if set(by_role) != {EngineAttemptRole.BASELINE, EngineAttemptRole.ADAPTIVE_SEARCH}:
            raise TenantRecordControllerError("both engine attempts require cleanup proof")
        ordered = (by_role[EngineAttemptRole.BASELINE], by_role[EngineAttemptRole.ADAPTIVE_SEARCH])
        if (
            ordered[0].record.binding.attempt_id != baseline.attempt_id
            or ordered[1].record.binding.attempt_id != adaptive.attempt_id
            or ordered[0].record.binding.run_id != baseline.run_id
            or ordered[1].record.binding.run_id != adaptive.run_id
            or any(item.cleanup_state is not CleanupState.VERIFIED_ABSENT for item in ordered)
            or any(item.cleanup_evidence_ref is None for item in ordered)
        ):
            raise TenantRecordControllerError("engine-owned work is not verified absent")
        return cast(tuple[str, str], tuple(item.cleanup_evidence_ref for item in ordered))

    def _require_checks(
        self,
        reproducer: TenantControllerCheck,
        legitimate: TenantControllerCheck,
        *,
        current: TenantDefenseConfig,
    ) -> None:
        expected_environment = {
            "fixture_digest": self.fixture.digest,
            "target_snapshot_id": current.target_snapshot_id,
            "service_generation": current.service_generation,
        }
        environments = (
            json_clone(reproducer.evidence.environment),
            json_clone(legitimate.evidence.environment),
        )
        reproducer_content = checked_observation_content(reproducer.evidence)
        legitimate_content = checked_observation_content(legitimate.evidence)
        if (
            reproducer.role is not ControllerCheckRole.RETAINED_REPRODUCER
            or legitimate.role is not ControllerCheckRole.LEGITIMATE_USE
            or not reproducer.passed
            or not legitimate.passed
            or reproducer.target_snapshot_id != legitimate.target_snapshot_id
            or reproducer.target_snapshot_id != current.target_snapshot_id
            or reproducer.mechanism_digest != legitimate.mechanism_digest
            or environments != (expected_environment, expected_environment)
            or reproducer_content["source_identity"] != "controller_probe"
            or legitimate_content["source_identity"] != "ordinary_user"
        ):
            raise TenantRecordControllerError("final disposition requires both successful controls")

    def _require_engine_observations(
        self,
        baseline: TenantEngineObservation,
        adaptive: TenantEngineObservation,
        reproducer: TenantControllerCheck,
        *,
        current: TenantDefenseConfig,
    ) -> tuple[str, str]:
        baseline_config = baseline_defense_config(self.fixture)
        baseline_environment = {
            "fixture_digest": self.fixture.digest,
            "target_snapshot_id": baseline_config.target_snapshot_id,
            "service_generation": baseline_config.service_generation,
        }
        adaptive_environment = {
            "fixture_digest": self.fixture.digest,
            "target_snapshot_id": current.target_snapshot_id,
            "service_generation": current.service_generation,
        }
        baseline_content = checked_observation_content(baseline.evidence)
        adaptive_content = checked_observation_content(adaptive.evidence)
        if (
            baseline.role is not EngineAttemptRole.BASELINE
            or adaptive.role is not EngineAttemptRole.ADAPTIVE_SEARCH
            or baseline.failure_mechanism is None
            or baseline.assessment != "unauthorized_disclosure"
            or baseline.failure_mechanism.request_digest != reproducer.mechanism_digest
            or adaptive.target_snapshot_id != reproducer.target_snapshot_id
            or adaptive.assessment not in {"authorization_denied", "no_protected_effect"}
            or baseline_content["source_identity"] != "engine_worker"
            or adaptive_content["source_identity"] != "engine_worker"
            or json_clone(baseline.evidence.environment) != baseline_environment
            or json_clone(adaptive.evidence.environment) != adaptive_environment
        ):
            raise TenantRecordControllerError(
                "final disposition requires baseline and fresh adaptive observations"
            )
        self._require_mechanism(baseline.failure_mechanism)
        return baseline.digest, adaptive.digest

    @staticmethod
    def _require_journey_chronology(
        plan: TenantDefensePlan,
        baseline: TenantEngineObservation,
        reproducer: TenantControllerCheck,
        adaptive: TenantEngineObservation,
        legitimate: TenantControllerCheck,
        recorded_at: str,
    ) -> None:
        _timestamp(recorded_at, "disposition time")
        ordered = (
            parse_iso8601_datetime(baseline.evidence.timestamp),
            parse_iso8601_datetime(plan.planned_at),
            parse_iso8601_datetime(reproducer.performed_at),
            parse_iso8601_datetime(adaptive.evidence.timestamp),
            parse_iso8601_datetime(legitimate.performed_at),
            parse_iso8601_datetime(recorded_at),
        )
        if any(later < earlier for earlier, later in zip(ordered, ordered[1:], strict=False)):
            raise TenantRecordControllerError("experiment evidence chronology is invalid")

    def retain_hardening(
        self,
        plan: TenantDefensePlan,
        *,
        operation_id: str,
        baseline: TenantEngineObservation,
        adaptive: TenantEngineObservation,
        reproducer: TenantControllerCheck,
        legitimate_use: TenantControllerCheck,
        engine_cleanup: tuple[EngineAttemptEntry, EngineAttemptEntry],
        recorded_at: str,
    ) -> TenantLabDispositionReceipt:
        plan = self._require_plan(plan)
        current = self._current_config()
        self._require_checks(reproducer, legitimate_use, current=current)
        observations = self._require_engine_observations(
            baseline, adaptive, reproducer, current=current
        )
        self._require_journey_chronology(
            plan, baseline, reproducer, adaptive, legitimate_use, recorded_at
        )
        cleanup = self._verified_cleanup_receipts(
            engine_cleanup, baseline=baseline, adaptive=adaptive
        )
        if current != plan.after or reproducer.target_snapshot_id != current.target_snapshot_id:
            raise TenantRecordControllerError("retained hardening is not the verified target state")
        return TenantLabDispositionReceipt(
            operation_id=operation_id,
            disposition=LabDisposition.RETAINED_HARDENING,
            fixture_digest=self.fixture.digest,
            target_snapshot_id=current.target_snapshot_id,
            target_config_digest=current.digest,
            engine_observation_digests=observations,
            engine_cleanup_receipts=cleanup,
            reproducer_check_digest=reproducer.digest,
            legitimate_use_check_digest=legitimate_use.digest,
            target_cleanup_receipt_digest=None,
            recorded_at=recorded_at,
        )

    def cleanup_lab(
        self,
        plan: TenantDefensePlan,
        *,
        operation_id: str,
        baseline: TenantEngineObservation,
        adaptive: TenantEngineObservation,
        reproducer: TenantControllerCheck,
        legitimate_use: TenantControllerCheck,
        engine_cleanup: tuple[EngineAttemptEntry, EngineAttemptEntry],
        recorded_at: str,
    ) -> TenantLabDispositionReceipt:
        plan = self._require_plan(plan)
        current = self._current_config()
        if current != plan.after:
            raise TenantRecordControllerError("lab cleanup requires the verified hardened state")
        self._require_checks(reproducer, legitimate_use, current=current)
        observations = self._require_engine_observations(
            baseline, adaptive, reproducer, current=current
        )
        self._require_journey_chronology(
            plan, baseline, reproducer, adaptive, legitimate_use, recorded_at
        )
        cleanup = self._verified_cleanup_receipts(
            engine_cleanup, baseline=baseline, adaptive=adaptive
        )
        try:
            result = self._target.cleanup_lab(
                self.fixture,
                expected_config_digest=current.digest,
                operation_id=operation_id,
            )
        except TenantTargetOperationUnknown as exc:
            result = TenantTargetCleanup(verified_absent=False, receipt_digest=exc.receipt_digest)
        disposition = LabDisposition.CLEANED if result.verified_absent else LabDisposition.UNKNOWN
        return TenantLabDispositionReceipt(
            operation_id=operation_id,
            disposition=disposition,
            fixture_digest=self.fixture.digest,
            target_snapshot_id=None if result.verified_absent else current.target_snapshot_id,
            target_config_digest=None if result.verified_absent else current.digest,
            engine_observation_digests=observations,
            engine_cleanup_receipts=cleanup,
            reproducer_check_digest=reproducer.digest,
            legitimate_use_check_digest=legitimate_use.digest,
            target_cleanup_receipt_digest=result.receipt_digest,
            recorded_at=recorded_at,
        )


def generate_held_out_variation(
    seed: bytes, *, primary: TenantRecordFixture
) -> TenantRecordFixture:
    """Create a new generated fixture without carrying the private seed forward."""

    held_out = generate_tenant_record_fixture(seed, held_out=True)
    if (
        held_out.fixture_id == primary.fixture_id
        or held_out.resource_generation == primary.resource_generation
        or held_out.target_snapshot_id == primary.target_snapshot_id
        or held_out.protected_tenant_id == primary.protected_tenant_id
        or held_out.route_order == primary.route_order
    ):
        raise TenantRecordControllerError("held-out variation did not change the lab")
    return held_out
