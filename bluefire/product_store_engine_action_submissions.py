"""Atomic acceptance receipts joining prepared actions to the existing jobs."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable
from typing import Any, Mapping, Protocol, cast

from . import product_store_engine_actions as preparations
from . import product_store_engine_jobs as jobs
from .engine_action_contract import (
    EnginePreparedApprovalState,
    EngineWorkspaceAction,
    PreparedEngineAction,
    PreparedEngineActionLimits,
    engine_action_contract,
)
from .engine_attempt_contract import EngineAttemptBinding
from .engine_delegation import EngineCapabilityDelegation, EngineExecutionApprovalBinding
from .engine_experiment import ControllerCheckRecord, ControllerCheckRole, EngineExperiment
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash, parse_iso8601_datetime

_RECEIPT_SCHEMA = "bluefire.engine-action-acceptance.v1"
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "preparation_id",
        "protected_request_ref",
        "experiment_id",
        "action_kind",
        "accepted_at",
        "job",
        "transition",
    }
)


class SubmissionStore(preparations.EngineActionProductStore, jobs.EngineJobProductStore, Protocol):
    pass


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Add v17 receipts in the existing ProductStore migration transaction."""
    if not connection.in_transaction:
        raise ProductStoreError("engine action acceptance migration requires one transaction")
    connection.execute("""CREATE TABLE IF NOT EXISTS engine_action_acceptances (
        request_ref TEXT PRIMARY KEY REFERENCES engine_action_preparations(request_ref),
        preparation_id TEXT NOT NULL UNIQUE,
        preparation_record_digest TEXT NOT NULL,
        approval_digest TEXT,
        reservation_json TEXT NOT NULL CHECK (json_valid(reservation_json))
            CHECK (length(CAST(reservation_json AS BLOB)) <= 512),
        receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json))
            CHECK (length(CAST(receipt_json AS BLOB)) <= 4096),
        record_digest TEXT NOT NULL UNIQUE
    )""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS engine_action_acceptances_no_update
        BEFORE UPDATE ON engine_action_acceptances BEGIN
            SELECT RAISE(ABORT, 'engine action acceptances are immutable'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS engine_action_acceptances_no_delete
        BEFORE DELETE ON engine_action_acceptances BEGIN
            SELECT RAISE(ABORT, 'engine action acceptances are append-only'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS engine_action_acceptances_valid_insert
        BEFORE INSERT ON engine_action_acceptances BEGIN
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM engine_action_acceptances
                WHERE request_ref = NEW.request_ref OR preparation_id = NEW.preparation_id
                   OR record_digest = NEW.record_digest
            ) THEN RAISE(ABORT, 'engine action acceptance conflicts with append-only history') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM engine_action_preparations WHERE request_ref = NEW.request_ref
                    AND record_digest = NEW.preparation_record_digest
            ) THEN RAISE(ABORT, 'engine action acceptance preparation changed') END;
        END""")


def _reviewer(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProductStoreError("trusted engine action reviewer is invalid")
    return value


def _load_at(
    store: SubmissionStore,
    connection: sqlite3.Connection,
    *,
    experiment_id: str,
    preparation_id: str,
    request_ref: str,
) -> tuple[sqlite3.Row, Mapping[str, Any], EngineExperiment, Mapping[str, Any] | None]:
    preparations._digest(preparation_id, "engine action preparation identity")
    preparations._digest(request_ref, "engine action preparation reference")
    row = connection.execute(
        """
        SELECT preparation.*, version.document_json AS experiment_document_json,
            version.digest AS version_digest
        FROM engine_action_preparations AS preparation
        JOIN engine_experiment_versions AS version
            ON version.experiment_id = preparation.experiment_id
            AND version.revision = preparation.experiment_revision
        WHERE preparation.request_ref = ?
    """,
        (request_ref,),
    ).fetchone()
    if row is None or row["experiment_id"] != experiment_id:
        raise ProductStoreError("engine action preparation was not found")
    experiment = jobs._engine_document(json.loads(str(row["experiment_document_json"])))
    if experiment.digest != row["version_digest"] or experiment.digest != row["experiment_digest"]:
        raise ProductStoreError("engine action preparation historical experiment changed")
    approval = preparations._approval_document(store, connection, row["approval_request_id"])
    action = EngineWorkspaceAction(str(row["action_kind"]))
    record = preparations.EngineActionPreparationStoreMixin._protected_engine_action_from_row(
        row,
        experiment,
        approval,
        reviewed_plan=preparations._retained_review_plan(
            connection, action=action, experiment=experiment
        ),
    )
    kind, effect, summary, changes, engine, requires = engine_action_contract(action)
    public = PreparedEngineAction.create(
        protected_request_ref=request_ref,
        experiment_id=experiment_id,
        revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=record["workspace_digest"],
        action_kind=action,
        preparation_kind=kind,
        effect_kind=effect,
        effect_summary=summary,
        changes_target=changes,
        uses_external_engine=engine,
        requires_approval=requires,
        approval_state=(
            EnginePreparedApprovalState.NOT_REQUIRED
            if approval is None
            else EnginePreparedApprovalState(approval["status"])
        ),
        approval_review_binding_digest=record["approval_review_binding_digest"],
        approval_expires_at=None if approval is None else approval["expires_at"],
        submission_id=record["submission_id"],
        intent_digest=record["intent_digest"],
        limits=PreparedEngineActionLimits.from_mapping(record["limits"]),
        prepared_at=record["prepared_at"],
        expires_at=record["expires_at"],
    )
    if public.preparation_id != preparation_id:
        raise ProductStoreError("engine action preparation identity changed")
    return row, record, experiment, approval


def _approval_at(
    store: SubmissionStore,
    connection: sqlite3.Connection,
    *,
    record: Mapping[str, Any],
    reviewer: str,
    now: str | None,
) -> Mapping[str, Any] | None:
    identity = record["approval_request_id"]
    if identity is None:
        return None
    row = store._approval_row(connection, identity)
    status = row["status"]
    if status not in {"pending", "approved", "consumed", "claimed"}:
        raise ProductStoreError("prepared engine approval is unavailable")
    requested = preparations._timestamp(row["requested_at"], "engine approval request time")
    expiry = preparations._timestamp(row["expires_at"], "engine approval expiry")
    if expiry != record["expires_at"]:
        raise ProductStoreError("prepared engine approval expiry changed")
    times = [requested]
    for field, required in (
        ("approved_at", status != "pending"),
        ("consumed_at", status in {"consumed", "claimed"}),
        ("claimed_at", status == "claimed"),
    ):
        value = row[field]
        if required:
            times.append(preparations._timestamp(value, "engine approval lifecycle time"))
        elif value is not None:
            raise ProductStoreError("prepared engine approval lifecycle conflicts")
    parsed = [parse_iso8601_datetime(value) for value in times]
    if parsed != sorted(parsed) or parsed[-1] >= parse_iso8601_datetime(expiry):
        raise ProductStoreError("prepared engine approval chronology changed")
    if status == "pending":
        if row["approved_by"] is not None or row["nonce"] is not None:
            raise ProductStoreError("pending engine approval gained authority")
    elif (
        row["approved_by"] != reviewer
        or not isinstance(row["nonce"], str)
        or not row["nonce"]
        or len(row["nonce"]) > 200
    ):
        raise ProductStoreError("prepared engine approval reviewer or nonce changed")
    if now is not None:
        current = parse_iso8601_datetime(now)
        if parsed[-1] > current or current >= parse_iso8601_datetime(expiry):
            raise ProductStoreError("prepared engine approval is expired or future dated")
        if status == "pending":
            connection.execute(
                """UPDATE approval_requests SET status = 'approved',
                approved_at = ?, approved_by = ?, nonce = ?
                WHERE approval_id = ? AND status = 'pending'""",
                (now, reviewer, uuid.uuid4().hex, identity),
            )
            status = "approved"
        if status == "approved":
            connection.execute(
                """UPDATE approval_requests SET status = 'consumed', consumed_at = ?
                WHERE approval_id = ? AND status = 'approved'""",
                (now, identity),
            )
    return cast(
        Mapping[str, Any],
        store._approval_from_row(store._approval_row(connection, identity)).to_dict(),
    )


def _kind(record: Mapping[str, Any]) -> str:
    action = EngineWorkspaceAction(record["action_kind"])
    if action in {
        EngineWorkspaceAction.START_BASELINE,
        EngineWorkspaceAction.START_ADAPTIVE_SEARCH,
    }:
        return "engine-attempt"
    if action in {EngineWorkspaceAction.APPLY_DEFENSE, EngineWorkspaceAction.ROLLBACK_DEFENSE}:
        return "engine-controller-operation"
    if action in {EngineWorkspaceAction.REPEAT_MECHANISM, EngineWorkspaceAction.RUN_LEGITIMATE_USE}:
        return "engine-controller-check"
    raise ProductStoreError("prepared action does not have an available job kind")


def _job_at(
    store: SubmissionStore,
    connection: sqlite3.Connection,
    record: Mapping[str, Any],
    experiment: EngineExperiment,
    *,
    reservation: Mapping[str, Any] | None = None,
) -> Mapping[str, Any] | None:
    if record["submission_id"] is None:
        return None
    job_id, _submission = store._job_submission_binding(
        record["submission_id"], record["intent_digest"]
    )
    row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None:
        return None
    request, submission = jobs._saved_job_request(store, row)
    if (
        row["kind"] != _kind(record)
        or request != record["protected_request"]["job_request"]
        or submission["intent_digest"] != record["intent_digest"]
    ):
        raise ProductStoreError("accepted engine job differs from its retained request")
    if row["kind"] in {"engine-attempt", "engine-controller-check"}:
        reserved_row = connection.execute(
            """SELECT document_json, digest, prior_digest
            FROM engine_experiment_versions WHERE experiment_id = ? AND revision = ?""",
            (experiment.experiment_id, experiment.revision + 1),
        ).fetchone()
        if reserved_row is None:
            raise ProductStoreError("accepted engine job has no exact experiment reservation")
        reserved = jobs._engine_document(json.loads(str(reserved_row["document_json"])))
        if (
            reserved.digest != reserved_row["digest"]
            or reserved_row["prior_digest"] != experiment.digest
            or (
                reservation is not None
                and reservation
                != {
                    "revision": reserved.revision,
                    "digest": reserved.digest,
                    "reserved_at": reserved.updated_at,
                }
            )
        ):
            raise ProductStoreError("accepted engine job reservation history changed")
        if not (
            parse_iso8601_datetime(record["prepared_at"])
            <= parse_iso8601_datetime(reserved.updated_at)
            <= parse_iso8601_datetime(str(row["created_at"]))
        ):
            raise ProductStoreError("accepted engine job reservation chronology changed")
        if row["kind"] == "engine-attempt":
            authority = record["protected_request"]["authority"]["document"]
            binding = EngineAttemptBinding.from_mapping(authority["binding"])
            delegation = EngineCapabilityDelegation.from_mapping(authority["delegation"])
            approval = EngineExecutionApprovalBinding.from_mapping(authority["approval_binding"])
            entry = next(
                (
                    entry
                    for entry in reserved.attempts
                    if entry.record.binding.attempt_id == binding.attempt_id
                ),
                None,
            )
            context = json.loads(str(row["progress_json"])).get("_engine_execution")
            expected = jobs._context_for(
                experiment_id=experiment.experiment_id,
                attempt_id=binding.attempt_id,
                job_id=job_id,
                delegation=delegation,
                approval=approval,
            )
            if entry is None or (
                entry.record.binding != binding
                or entry.job_id != job_id
                or entry.delegation_digest != delegation.delegation_digest
                or entry.execution_approval_digest != content_hash(approval.to_dict())
                or entry.execution_approval_id != record["approval_request_id"]
                or context != expected
            ):
                raise ProductStoreError("accepted engine attempt authority reservation changed")
            successor = experiment.reserve_attempt(
                binding,
                job_id=job_id,
                delegation_digest=delegation.delegation_digest,
                execution_approval_digest=content_hash(approval.to_dict()),
                execution_approval_id=record["approval_request_id"],
                timestamp=reserved.updated_at,
            )
        else:
            check = next(
                (check for check in reserved.checks if check.check_id == request["check_id"]),
                None,
            )
            if (
                check is None
                or check.job_id != job_id
                or jobs._check_request(experiment, check) != request
            ):
                raise ProductStoreError("accepted controller check reservation changed")
            expected_check = ControllerCheckRecord.reserve(
                check_id=request["check_id"],
                experiment_id=experiment.experiment_id,
                job_id=job_id,
                run_id=request["run_id"],
                role=ControllerCheckRole(request["role"]),
                mechanism_ref=request["mechanism_ref"],
                target_snapshot_ref=request["target_snapshot_ref"],
                input_digest=request["input_digest"],
                created_at=request["reserved_at"],
            )
            successor = experiment.reserve_controller_check(
                expected_check, timestamp=request["reserved_at"]
            )
        if reserved.to_dict() != successor.to_dict():
            raise ProductStoreError(
                "accepted engine job successor differs from its exact reservation"
            )
    elif reservation is not None:
        raise ProductStoreError("accepted defense job gained an experiment reservation")
    return store._job_from_row(row)


def _reservation_at(
    connection: sqlite3.Connection,
    record: Mapping[str, Any],
    experiment: EngineExperiment,
) -> Mapping[str, Any] | None:
    if (
        record["preparation_kind"] == "controller_transition"
        or _kind(record) == "engine-controller-operation"
    ):
        return None
    row = connection.execute(
        """SELECT document_json, digest FROM engine_experiment_versions
        WHERE experiment_id = ? AND revision = ?""",
        (experiment.experiment_id, experiment.revision + 1),
    ).fetchone()
    if row is None:
        raise ProductStoreError("accepted engine job reservation is unavailable")
    reserved = jobs._engine_document(json.loads(str(row["document_json"])))
    if reserved.digest != row["digest"]:
        raise ProductStoreError("accepted engine job reservation digest changed")
    return {
        "revision": reserved.revision,
        "digest": reserved.digest,
        "reserved_at": reserved.updated_at,
    }


def _receipt_at(
    store: SubmissionStore,
    connection: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    record: Mapping[str, Any],
    experiment: EngineExperiment,
    preparation_id: str,
    reviewer: str,
) -> Mapping[str, Any] | None:
    saved = connection.execute(
        "SELECT * FROM engine_action_acceptances WHERE request_ref = ?", (record["request_ref"],)
    ).fetchone()
    if saved is None:
        return None
    document = json.loads(str(saved["receipt_json"]))
    if not isinstance(document, dict) or set(document) != _RECEIPT_FIELDS:
        raise ProductStoreError("saved engine acceptance fields changed")
    identity = dict(document)
    receipt_id = identity.pop("receipt_id")
    if (
        canonical_json(document) != saved["receipt_json"]
        or content_hash(identity) != receipt_id
        or saved["preparation_id"] != preparation_id
        or saved["preparation_record_digest"] != row["record_digest"]
        or document["schema_version"] != _RECEIPT_SCHEMA
        or document["preparation_id"] != preparation_id
        or document["protected_request_ref"] != record["request_ref"]
        or document["experiment_id"] != experiment.experiment_id
        or document["action_kind"] != record["action_kind"]
    ):
        raise ProductStoreError("saved engine acceptance binding changed")
    preparations._timestamp(document["accepted_at"], "engine action acceptance time")
    approval = _approval_at(store, connection, record=record, reviewer=reviewer, now=None)
    approval_digest = None if approval is None else content_hash(approval)
    reservation = json.loads(str(saved["reservation_json"]))
    if canonical_json(reservation) != saved["reservation_json"] or reservation != _reservation_at(
        connection, record, experiment
    ):
        raise ProductStoreError("saved engine acceptance reservation changed")
    if approval is not None and approval["status"] != "claimed":
        raise ProductStoreError("accepted engine approval is not claimed")
    if approval_digest != saved["approval_digest"] or saved["record_digest"] != content_hash(
        {
            "receipt": document,
            "preparation_record_digest": row["record_digest"],
            "approval_digest": approval_digest,
            "reservation": reservation,
        }
    ):
        raise ProductStoreError("saved engine acceptance integrity changed")
    job = _job_at(store, connection, record, experiment, reservation=reservation)
    if approval is not None and (job is None or approval["claimed_at"] != job["created_at"]):
        raise ProductStoreError("accepted engine claim differs from its fixed job time")
    if record["submission_id"] is not None:
        if (
            job is None
            or document["job"] != {"job_id": job["job_id"], "kind": job["kind"]}
            or document["transition"] is not None
        ):
            raise ProductStoreError("accepted engine job identity changed")
    else:
        expected = _transition(experiment, record, document["accepted_at"])
        transition = document["transition"]
        if document["job"] is not None or transition != {
            "revision": expected.revision,
            "digest": expected.digest,
        }:
            raise ProductStoreError("accepted engine transition changed")
        jobs._historical_experiment_at(
            connection, experiment.experiment_id, expected.revision, expected.digest
        )
    return cast(Mapping[str, Any], document)


def _transition(
    experiment: EngineExperiment, record: Mapping[str, Any], now: str
) -> EngineExperiment:
    action = EngineWorkspaceAction(record["action_kind"])
    if action is EngineWorkspaceAction.REVIEW_DEFENSE:
        _plan, change = preparations._tenant_defense_review_authority(
            record["protected_request"]["authority"]["document"]
        )
        return experiment.review_defense(change, timestamp=change.reviewed_at)
    if action is EngineWorkspaceAction.RETAIN_DEFENSE and experiment.defense_change is not None:
        return experiment.retain_defense(experiment.defense_change.change_id, retained_at=now)
    raise ProductStoreError("prepared controller transition is unavailable")


class EngineActionSubmissionStoreMixin:
    def recover_engine_action_acceptance(
        self: SubmissionStore,
        *,
        experiment_id: str,
        preparation_id: str,
        request_ref: str,
        reviewer: str,
    ) -> Mapping[str, Any] | None:
        """Repair only a completely proven legacy claim; never enqueue work.

        The acceptance writer revalidates the proof in its write transaction.
        A missing or conflicting reservation cannot become a fresh admission.
        """
        reviewer = _reviewer(reviewer)
        with self._connection() as connection:
            _row, record, experiment, approval = _load_at(
                self,
                connection,
                experiment_id=experiment_id,
                preparation_id=preparation_id,
                request_ref=request_ref,
            )
            job = _job_at(self, connection, record, experiment)
            if job is None:
                if approval is not None and approval["status"] == "claimed":
                    raise ProductStoreError("claimed engine action has no exact job reservation")
                return None
            if approval is None or approval["status"] != "claimed":
                raise ProductStoreError("unreceipted engine job conflicts with preparation")

        def refuse_fresh_admission(_record: Mapping[str, Any]) -> None:
            raise ProductStoreError("legacy engine claim reservation disappeared")

        values = {
            "experiment_id": experiment_id,
            "preparation_id": preparation_id,
            "request_ref": request_ref,
            "reviewer": reviewer,
        }
        EngineActionSubmissionStoreMixin.accept_engine_action_preparation(
            self,
            **values,
            validate_workspace=refuse_fresh_admission,
        )
        return EngineActionSubmissionStoreMixin.get_engine_action_acceptance(self, **values)

    def get_engine_action_acceptance(
        self: SubmissionStore,
        *,
        experiment_id: str,
        preparation_id: str,
        request_ref: str,
        reviewer: str,
    ) -> Mapping[str, Any] | None:
        reviewer = _reviewer(reviewer)
        with self._connection() as connection:
            row, record, experiment, _approval = _load_at(
                self,
                connection,
                experiment_id=experiment_id,
                preparation_id=preparation_id,
                request_ref=request_ref,
            )
            return _receipt_at(
                self,
                connection,
                row=row,
                record=record,
                experiment=experiment,
                preparation_id=preparation_id,
                reviewer=reviewer,
            )

    def accept_engine_action_preparation(
        self: SubmissionStore,
        *,
        experiment_id: str,
        preparation_id: str,
        request_ref: str,
        reviewer: str,
        validate_workspace: Callable[[Mapping[str, Any]], None],
    ) -> tuple[Mapping[str, Any], bool]:
        """Accept with claim, reservation/transition and receipt in one transaction.

        For jobs the returned value is private to the JobController factory.
        HTTP callers receive only get_engine_action_acceptance's strict receipt.
        """
        reviewer = _reviewer(reviewer)
        with self._connection(write=True) as connection:
            row, record, experiment, approval = _load_at(
                self,
                connection,
                experiment_id=experiment_id,
                preparation_id=preparation_id,
                request_ref=request_ref,
            )
            existing = _receipt_at(
                self,
                connection,
                row=row,
                record=record,
                experiment=experiment,
                preparation_id=preparation_id,
                reviewer=reviewer,
            )
            if existing is not None:
                job = _job_at(self, connection, record, experiment)
                return (existing if job is None else job), False
            action = EngineWorkspaceAction(record["action_kind"])
            if action in {
                EngineWorkspaceAction.RECONCILE_DEFENSE,
                EngineWorkspaceAction.RECONCILE_ROLLBACK,
            }:
                raise ProductStoreError("prepared reconciliation is unavailable")
            job = _job_at(self, connection, record, experiment)
            recovered = job is not None
            if recovered:
                assert job is not None
                # Atomic acceptance cannot leave a partial record.  Recovery of a
                # legacy claim requires the exact fixed job and its reservation.
                if approval is None or approval["status"] != "claimed":
                    raise ProductStoreError("unreceipted engine job conflicts with preparation")
                approval = _approval_at(
                    self, connection, record=record, reviewer=reviewer, now=None
                )
                assert approval is not None
                now = str(approval["claimed_at"])
                if now != job["created_at"] or parse_iso8601_datetime(now) > parse_iso8601_datetime(
                    utc_now()
                ):
                    raise ProductStoreError("legacy engine claim differs from its fixed job time")
            else:
                jobs._active_experiment_at(
                    connection,
                    experiment_id,
                    expected_revision=experiment.revision,
                    expected_digest=experiment.digest,
                )
                now = utc_now()
                if (
                    not parse_iso8601_datetime(record["prepared_at"])
                    <= parse_iso8601_datetime(now)
                    < parse_iso8601_datetime(record["expires_at"])
                ):
                    raise ProductStoreError("prepared engine action is expired or future dated")
                validate_workspace({**record, "experiment_document": experiment.to_dict()})
                if approval is not None and approval["status"] == "claimed":
                    raise ProductStoreError("claimed engine action has no exact job reservation")
                approval = _approval_at(self, connection, record=record, reviewer=reviewer, now=now)
                protected = record["protected_request"]
                request = protected["job_request"]
                common = {
                    "experiment_id": experiment_id,
                    "job_request": request,
                    "submission_id": record["submission_id"],
                    "intent_digest": record["intent_digest"],
                    "expected_revision": experiment.revision,
                    "expected_experiment_digest": experiment.digest,
                }
                if action in {
                    EngineWorkspaceAction.START_BASELINE,
                    EngineWorkspaceAction.START_ADAPTIVE_SEARCH,
                }:
                    assert approval is not None
                    authority = protected["authority"]["document"]
                    job, _created = jobs.reserve_engine_attempt_submission_at(
                        self,
                        connection,
                        **common,
                        binding=authority["binding"],
                        delegation=authority["delegation"],
                        approval_binding=authority["approval_binding"],
                        approval_id=approval["approval_id"],
                        approval_nonce=approval["nonce"],
                        approved_by=reviewer,
                        job_kind=_kind(record),
                        reserved_at=now,
                    )
                elif action in {
                    EngineWorkspaceAction.APPLY_DEFENSE,
                    EngineWorkspaceAction.ROLLBACK_DEFENSE,
                }:
                    job, _created = jobs.reserve_engine_defense_operation_submission_at(
                        self,
                        connection,
                        **common,
                        change_id=request["change_id"],
                        operation=request["operation"],
                        job_kind=_kind(record),
                        originating_job_id=request["originating_job_id"],
                        originating_operation_receipt_digest=request[
                            "originating_operation_receipt_digest"
                        ],
                    )
                elif action in {
                    EngineWorkspaceAction.REPEAT_MECHANISM,
                    EngineWorkspaceAction.RUN_LEGITIMATE_USE,
                }:
                    job, _created = jobs.reserve_engine_controller_check_submission_at(
                        self,
                        connection,
                        **common,
                        check_id=request["check_id"],
                        run_id=request["run_id"],
                        role=request["role"],
                        mechanism_ref=request["mechanism_ref"],
                        target_snapshot_ref=request["target_snapshot_ref"],
                        input_digest=request["input_digest"],
                        reserved_at=request["reserved_at"],
                        job_kind=_kind(record),
                    )
                else:
                    updated = _transition(experiment, record, now)
                    jobs._append_experiment_at(connection, experiment, updated)
            transition = (
                None
                if job is not None
                else {"revision": updated.revision, "digest": updated.digest}
            )
            document = {
                "schema_version": _RECEIPT_SCHEMA,
                "preparation_id": preparation_id,
                "protected_request_ref": request_ref,
                "experiment_id": experiment_id,
                "action_kind": action.value,
                "accepted_at": now,
                "job": None if job is None else {"job_id": job["job_id"], "kind": job["kind"]},
                "transition": transition,
            }
            receipt = {**document, "receipt_id": content_hash(document)}
            final_approval = preparations._approval_document(
                self, connection, record["approval_request_id"]
            )
            approval_digest = None if final_approval is None else content_hash(final_approval)
            reservation = _reservation_at(connection, record, experiment)
            if job is not None:
                _job_at(self, connection, record, experiment, reservation=reservation)
            digest = content_hash(
                {
                    "receipt": receipt,
                    "preparation_record_digest": row["record_digest"],
                    "approval_digest": approval_digest,
                    "reservation": reservation,
                }
            )
            connection.execute(
                """INSERT INTO engine_action_acceptances(
                request_ref, preparation_id, preparation_record_digest, approval_digest,
                reservation_json, receipt_json, record_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    request_ref,
                    preparation_id,
                    row["record_digest"],
                    approval_digest,
                    canonical_json(reservation),
                    canonical_json(receipt),
                    digest,
                ),
            )
            return (receipt if job is None else job), not recovered
