"""Private v21 persistence for the effect-free Strix admission issuer.

Every complete issuance record commits with exactly one v20 lifecycle event.
Legacy reservations cannot be adopted: their missing protected evidence cannot
be reconstructed. No public resources, routes, credentials or locations live here.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import asdict
from typing import Any, Protocol

from . import product_store_strix_runtime_records as runtime
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .strix_admission_contract import (
    RESOURCE_KINDS,
    ServerResolvedStrixAdmissionRequest,
    StrixAbsenceReceipt,
    StrixAdmissionIssuanceConflict,
    StrixAdmissionIssuanceError,
    StrixIssuanceHead,
    StrixIssuanceRecord,
    StrixPreAdmissionProfile,
    StrixReconciliationEvidence,
    StrixResourceReceipt,
)
from .util import content_hash, parse_iso8601_datetime

_TRANSITIONS = {
    "reserved": {"preparing", "revoked"},
    "preparing": {"preparing", "verified", "unknown", "revoked"},
    "verified": {"unknown", "revoked", "cleaned"},
    "unknown": {"verified", "revoked", "cleaned"},
    "revoked": {"cleaned"},
    "cleaned": set(),
}


class StrixIssuanceAdmissionSource(Protocol):
    """Read-only protected source of the exact complete v20 admission document.

    Called before acquiring the persistence transaction. Resource verification
    remains the issuer's responsibility; persistence binds this document to its
    complete retained receipt set and independently checks current authority.
    """

    def reopen_exact_admission(self, record: StrixIssuanceRecord) -> Mapping[str, Any]: ...

    def verify_admission(self, record: StrixIssuanceRecord, document: Mapping[str, Any]) -> bool:
        """Independently reopen gateway/model policy and source-root custody.

        Prove model_id and custody_source_ref against those protected owners,
        plus the actual installed build/qualification and policy digests. These
        fields cannot be inferred from opaque receipts. Equality alone is not
        verification. Returning anything other than True refuses retention.
        """
        ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise ProductStoreError("Strix issuer migration requires one owning transaction")
    connection.execute("""CREATE TABLE IF NOT EXISTS strix_runtime_issuance_records (
        attempt_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 4096),
        document_json TEXT NOT NULL CHECK(json_valid(document_json))
          CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
        record_digest TEXT NOT NULL UNIQUE,
        previous_record_digest TEXT,
        runtime_event_digest TEXT NOT NULL UNIQUE,
        receipt_set_digest TEXT NOT NULL,
        PRIMARY KEY(attempt_id,sequence),
        FOREIGN KEY(attempt_id,sequence)
          REFERENCES strix_runtime_admission_events(attempt_id,sequence),
        FOREIGN KEY(previous_record_digest) REFERENCES strix_runtime_issuance_records(record_digest),
        FOREIGN KEY(runtime_event_digest) REFERENCES strix_runtime_admission_events(event_digest)
    )""")
    for suffix, clause in {
        "no_replace": "BEFORE INSERT ON strix_runtime_issuance_records WHEN EXISTS(SELECT 1 FROM strix_runtime_issuance_records WHERE attempt_id=NEW.attempt_id AND sequence=NEW.sequence OR record_digest=NEW.record_digest OR runtime_event_digest=NEW.runtime_event_digest)",
        "no_update": "BEFORE UPDATE ON strix_runtime_issuance_records",
        "no_delete": "BEFORE DELETE ON strix_runtime_issuance_records",
    }.items():
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS strix_runtime_issuance_records_{suffix} "
            f"{clause} BEGIN SELECT RAISE(ABORT,'Strix issuance records are immutable'); END"
        )


def _document(record: StrixIssuanceRecord) -> dict[str, Any]:
    record.validate()
    return runtime._bounded_document(asdict(record), context="Strix issuance record")


def _decode(document: Mapping[str, Any]) -> StrixIssuanceRecord:
    try:
        row = dict(document)
        profile = dict(row.pop("profile"))
        request = dict(profile.pop("request"))
        request["head"] = StrixIssuanceHead(**request["head"])
        value = ServerResolvedStrixAdmissionRequest(**request)
        retained_profile = StrixPreAdmissionProfile(value, **profile)
        resources = tuple(StrixResourceReceipt(**item) for item in row.pop("resources"))
        evidence = row.pop("reconciliation_evidence")
        if evidence is not None:
            evidence = dict(evidence)
            evidence["resources"] = tuple(
                StrixResourceReceipt(**item) for item in evidence["resources"]
            )
            evidence["absence"] = tuple(StrixAbsenceReceipt(**item) for item in evidence["absence"])
            evidence = StrixReconciliationEvidence(**evidence)
        record = StrixIssuanceRecord(
            profile=retained_profile,
            resources=resources,
            reconciliation_evidence=evidence,
            **row,
        )
        if canonical_json(_document(record)) != canonical_json(document):
            raise ValueError("issuance document changed during decoding")
        return record
    except (TypeError, ValueError, KeyError, RecursionError) as exc:
        raise StrixAdmissionIssuanceError("Strix issuance record integrity changed") from exc


def _reservation(request: ServerResolvedStrixAdmissionRequest) -> dict[str, Any]:
    request.validate()
    head = request.head
    return {
        "schema_version": runtime.ADMISSION_RESERVATION_SCHEMA,
        **{
            name: getattr(request, name)
            for name in (
                "attempt_id",
                "binding_digest",
                "delegation_digest",
                "objective_ref",
                "environment_ref",
                "target_snapshot_digest",
                "created_at",
                "expires_at",
            )
        },
        **{
            name: getattr(head, name)
            for name in (
                "experiment_id",
                "experiment_revision",
                "experiment_digest",
                "authority_ref",
                "authority_generation",
                "authority_record_digest",
                "qualification_ref",
            )
        },
        "request_digest": request.request_digest,
    }


def _active(
    connection: sqlite3.Connection,
    request: ServerResolvedStrixAdmissionRequest,
    head: StrixIssuanceHead,
) -> None:
    head.validate()
    if not head.active or head != request.head:
        raise StrixAdmissionIssuanceConflict("Strix issuance authority/head changed")
    chain = runtime._read_authority_chain(connection, head.authority_ref)
    current = chain[-1] if chain else None
    experiment = connection.execute(
        "SELECT active_revision,active_digest FROM engine_experiment_heads WHERE experiment_id=?",
        (head.experiment_id,),
    ).fetchone()
    if (
        current is None
        or current["authority"]["state"] != "active"
        or current["authority"]["generation"] != head.authority_generation
        or current["authority_record_digest"] != head.authority_record_digest
        or current["authority"]["strix_build_digest"] != head.build_digest
        or current["authority"]["qualification_manifest_ref"] != head.qualification_ref
        or experiment is None
        or experiment["active_revision"] != head.experiment_revision
        or experiment["active_digest"] != head.experiment_digest
    ):
        raise StrixAdmissionIssuanceConflict("Strix issuance active authority/experiment changed")


def _lifetime(request: ServerResolvedStrixAdmissionRequest, recorded_at: str) -> None:
    if not (
        parse_iso8601_datetime(request.created_at)
        <= parse_iso8601_datetime(recorded_at)
        < parse_iso8601_datetime(request.expires_at)
    ):
        raise StrixAdmissionIssuanceConflict("Strix issuance is outside its lifetime")


def _transition(previous: StrixIssuanceRecord, record: StrixIssuanceRecord) -> None:
    record.validate()
    if (
        record.profile != previous.profile
        or record.sequence != previous.sequence + 1
        or record.previous_digest != previous.record_digest
        or record.state not in _TRANSITIONS[previous.state]
        or not set(previous.resources).issubset(record.resources)
    ):
        raise StrixAdmissionIssuanceConflict("Strix issuance immutable lifecycle changed")
    if record.state == "preparing":
        if previous.state == "reserved":
            valid = not record.resources and record.pending_kind is None
        elif previous.pending_kind is None:
            valid = (
                record.resources == previous.resources
                and record.pending_kind in RESOURCE_KINDS
                and record.pending_kind not in {r.kind for r in previous.resources}
            )
        else:
            valid = (
                record.pending_kind is None
                and record.resources[:-1] == previous.resources
                and len(record.resources) == len(previous.resources) + 1
                and record.resources[-1].kind == previous.pending_kind
            )
        if not valid or record.reconciliation_evidence != previous.reconciliation_evidence:
            raise StrixAdmissionIssuanceConflict("Strix issuance preparation evidence changed")
    if record.state in {"unknown", "revoked"} and (
        record.resources != previous.resources
        or record.pending_kind != previous.pending_kind
        or record.reconciliation_evidence != previous.reconciliation_evidence
    ):
        raise StrixAdmissionIssuanceConflict("Strix issuance interruption evidence changed")
    evidence = record.reconciliation_evidence
    if evidence is not None and evidence.resources != record.resources:
        raise StrixAdmissionIssuanceConflict("Strix issuance inventory differs from receipts")
    if record.state == "verified" and previous.state == "unknown" and evidence is None:
        raise StrixAdmissionIssuanceConflict("Strix issuance recovery lacks complete inventory")
    if (
        record.state == "verified"
        and previous.state == "preparing"
        and (record.resources != previous.resources or previous.pending_kind is not None)
    ):
        raise StrixAdmissionIssuanceConflict("Strix issuance verification bypassed preparation")
    if record.state == "verified" and evidence is not None and evidence.absence:
        raise StrixAdmissionIssuanceConflict("Strix verified issuance contains absence evidence")
    if record.state == "cleaned" and record.pending_kind is not None:
        raise StrixAdmissionIssuanceConflict("Strix cleaned issuance retains pending work")


def strix_issuance_proof_bundle_digest(record: StrixIssuanceRecord) -> str:
    """Deterministic receipt-set identity required of the private admission source."""
    record.validate()
    return content_hash(
        {
            "schema_version": "bluefire.strix-issuance-proof-bundle.v1",
            "profile_digest": record.profile.profile_digest,
            "resources": [asdict(r) for r in sorted(record.resources, key=lambda r: r.kind)],
        }
    )


def strix_issuance_admission_commitment(
    profile: StrixPreAdmissionProfile,
    document: Mapping[str, Any],
) -> str:
    """Exact full-document proof required of the final protected custody owner.

    Only custody_record_digest is excluded because it is this very commitment.
    The established v20 admission_proof_bundle_digest is included unchanged.
    All other admission fields, including model and source identity, are bound.
    The independent issuer verifier must reopen this custody manifest as part
    of source_root_custody verification before a verified state is requested.
    """
    checked = runtime._admission(document)
    checked.pop("custody_record_digest")
    return content_hash(
        {
            "schema_version": "bluefire.strix-issuance-admission-proof.v1",
            "profile_digest": profile.profile_digest,
            "admission": checked,
        }
    )


def _bind_admission(record: StrixIssuanceRecord, document: Mapping[str, Any]) -> dict[str, Any]:
    checked = runtime._admission(document)
    request = record.profile.request
    reserved = _reservation(request)
    for name in set(reserved) - {"schema_version", "request_digest"}:
        if checked[name] != reserved[name]:
            raise StrixAdmissionIssuanceConflict("Strix issuance admission request changed")
    if (
        checked["build_digest"] != request.head.build_digest
        or content_hash(checked["budgets"]) != request.budgets_digest
        or content_hash(checked["limits"]) != request.limits_digest
        or checked["custody_record_digest"]
        != strix_issuance_admission_commitment(record.profile, checked)
    ):
        raise StrixAdmissionIssuanceConflict("Strix issuance admission policy/proof changed")
    if {r.kind for r in record.resources} != set(RESOURCE_KINDS):
        raise StrixAdmissionIssuanceConflict("Strix issuance admission lacks complete receipts")
    for receipt in record.resources:
        prefix = {
            "scope": "scope_record",
            "gateway": "gateway_record",
            "source_root_custody": "custody_record",
        }.get(receipt.kind, receipt.kind)
        if (
            checked[prefix + "_ref"] != receipt.resource_ref
            or checked[prefix + "_digest"] != receipt.receipt_digest
        ):
            raise StrixAdmissionIssuanceConflict("Strix issuance admission resource changed")
    return checked


def _read_at(connection: sqlite3.Connection, attempt_id: str) -> StrixIssuanceRecord | None:
    if not connection.in_transaction:
        raise ProductStoreError("Strix issuance read requires one owning snapshot")
    if not isinstance(attempt_id, str) or runtime._ATTEMPT.fullmatch(attempt_id) is None:
        raise StrixAdmissionIssuanceError("invalid immutable attempt ID")
    reservation = runtime._read_reservation(connection, attempt_id)
    rows = connection.execute(
        "SELECT * FROM strix_runtime_issuance_records WHERE attempt_id=? ORDER BY sequence",
        (attempt_id,),
    ).fetchall()
    if not rows:
        if reservation is not None:
            raise StrixAdmissionIssuanceConflict("legacy Strix reservation lacks issuance evidence")
        return None
    if reservation is None:
        raise StrixAdmissionIssuanceError("Strix issuance reservation is missing")
    events = runtime._read_admission_chain(connection, attempt_id)
    if len(rows) != len(events):
        raise StrixAdmissionIssuanceError("Strix issuance/runtime lifecycle length differs")
    previous = None
    verified = None
    for row, event in zip(rows, events, strict=True):
        record = _decode(runtime._canonical_row(row))
        document = event["document"]
        if (
            row["attempt_id"] != record.profile.request.attempt_id
            or row["sequence"] != record.sequence
            or row["record_digest"] != record.record_digest
            or row["previous_record_digest"] != record.previous_digest
            or row["runtime_event_digest"] != event["event_digest"]
            or row["receipt_set_digest"] != strix_issuance_proof_bundle_digest(record)
            or record.sequence != document["sequence"]
            or record.state != document["state"]
            or reservation["document"] != _reservation(record.profile.request)
            or document["lifecycle_basis_ref"]
            != (record.profile.request.request_digest if previous is None else record.record_digest)
        ):
            raise StrixAdmissionIssuanceError("Strix issuance/runtime lifecycle integrity changed")
        if previous is None:
            if (
                record.sequence != 1
                or record.resources
                or record.pending_kind
                or record.reconciliation_evidence
            ):
                raise StrixAdmissionIssuanceError("Strix issuance initial evidence changed")
        else:
            _transition(previous, record)
        if record.state == "verified":
            verified = record
        previous = record
    state = runtime._read_strix_runtime_admission_state(connection, attempt_id)
    admission = state["admission"]
    if verified is not None:
        if admission is None:
            raise StrixAdmissionIssuanceError("Strix issuance verified admission is missing")
        _bind_admission(verified, admission["document"])
    elif admission is not None:
        raise StrixAdmissionIssuanceError("Strix issuance has an unverified admission")
    return previous


def _insert(connection: sqlite3.Connection, record: StrixIssuanceRecord, event_digest: str) -> None:
    connection.execute(
        "INSERT INTO strix_runtime_issuance_records VALUES(?,?,?,?,?,?,?)",
        (
            record.profile.request.attempt_id,
            record.sequence,
            canonical_json(_document(record)),
            record.record_digest,
            record.previous_digest,
            event_digest,
            strix_issuance_proof_bundle_digest(record),
        ),
    )


class ProductStoreStrixAdmissionIssuerPersistence:
    """Complete private issuer adapter; all callbacks finish before atomic guards.

    The clock and admission source perform read-only resolution. They are never
    invoked while a ProductStore transaction is held. No allocation occurs here.
    """

    def __init__(
        self,
        store: runtime.StrixRuntimeStore,
        *,
        admissions: StrixIssuanceAdmissionSource,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._store = store
        self._admissions = admissions
        self._clock = clock

    def reserve(
        self,
        record: StrixIssuanceRecord,
        *,
        active_head: StrixIssuanceHead,
    ) -> StrixIssuanceRecord:
        _document(record)
        if (
            record.sequence != 1
            or record.state != "reserved"
            or record.resources
            or record.pending_kind
            or record.reconciliation_evidence
        ):
            raise StrixAdmissionIssuanceError("Strix issuance initial reservation required")
        recorded_at = runtime._timestamp(self._clock(), "Strix issuance reservation time")
        try:
            with self._store._connection(write=True) as connection:
                _lifetime(record.profile.request, recorded_at)
                _active(connection, record.profile.request, active_head)
                existing = _read_at(connection, record.profile.request.attempt_id)
                if existing is not None:
                    if existing.profile != record.profile:
                        raise StrixAdmissionIssuanceConflict(
                            "immutable Strix issuance reservation changed"
                        )
                    return existing
                runtime._reserve_strix_runtime_admission_at(
                    connection, _reservation(record.profile.request)
                )
                event = runtime._read_admission_chain(
                    connection, record.profile.request.attempt_id
                )[-1]
                _insert(connection, record, event["event_digest"])
                return record
        except (ResourceConflictError, sqlite3.IntegrityError) as exc:
            raise StrixAdmissionIssuanceConflict(str(exc)) from exc

    def read(self, attempt_id: str) -> StrixIssuanceRecord | None:
        # Respect existing protected read scopes, otherwise establish one
        # snapshot for every joined read on the pinned ProductStore database.
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            return _read_at(connection, attempt_id)

    def compare_and_swap(
        self,
        record: StrixIssuanceRecord,
        *,
        expected_digest: str,
        active_head: StrixIssuanceHead | None,
    ) -> StrixIssuanceRecord:
        _document(record)
        runtime._digest(expected_digest, "Strix issuance expected digest")
        admission = None
        if record.state == "verified":
            admission = _bind_admission(record, self._admissions.reopen_exact_admission(record))
            if self._admissions.verify_admission(record, admission) is not True:
                raise StrixAdmissionIssuanceError("independent Strix admission verification failed")
        recorded_at = runtime._timestamp(self._clock(), "Strix issuance event time")
        try:
            with self._store._connection(write=True) as connection:
                previous = _read_at(connection, record.profile.request.attempt_id)
                # No CAS retry returns success: only one caller may allocate.
                if previous is None or previous.record_digest != expected_digest:
                    raise StrixAdmissionIssuanceConflict("Strix issuance lifecycle CAS changed")
                _transition(previous, record)
                if record.state in {"preparing", "verified"}:
                    if active_head is None:
                        raise StrixAdmissionIssuanceConflict("Strix issuance active head required")
                    _lifetime(record.profile.request, recorded_at)
                    _active(connection, record.profile.request, active_head)
                elif active_head is not None:
                    _active(connection, record.profile.request, active_head)
                events = runtime._read_admission_chain(
                    connection, record.profile.request.attempt_id
                )
                kwargs = {
                    "lifecycle_basis_ref": record.record_digest,
                    "recorded_at": recorded_at,
                    "expected_head_digest": events[-1]["event_digest"],
                }
                if admission is not None:
                    result = runtime._retain_verified_strix_runtime_admission_at(
                        connection, document=admission, **kwargs
                    )
                    event_digest = result["lifecycle_head_digest"]
                else:
                    result = runtime._append_strix_runtime_admission_event_at(
                        connection,
                        attempt_id=record.profile.request.attempt_id,
                        state=record.state,
                        issuer_evidence=True,
                        **kwargs,
                    )
                    event_digest = result["event_digest"]
                _insert(connection, record, event_digest)
                retained = _read_at(connection, record.profile.request.attempt_id)
                if retained != record:
                    raise StrixAdmissionIssuanceConflict("Strix issuance retained record changed")
                return record
        except (ResourceConflictError, sqlite3.IntegrityError) as exc:
            raise StrixAdmissionIssuanceConflict(str(exc)) from exc

    def confirm_verified(
        self,
        *,
        attempt_id: str,
        expected_digest: str,
        active_head: StrixIssuanceHead,
    ) -> StrixIssuanceRecord:
        runtime._digest(expected_digest, "Strix issuance expected digest")
        recorded_at = runtime._timestamp(self._clock(), "Strix issuance confirmation time")
        # No callbacks after this point: event, admission and both heads share
        # the same owning snapshot and no competing writer can intervene.
        with self._store._connection(write=True) as connection:
            record = _read_at(connection, attempt_id)
            if (
                record is None
                or record.record_digest != expected_digest
                or record.state != "verified"
            ):
                raise StrixAdmissionIssuanceConflict("Strix verified issuance lifecycle changed")
            _lifetime(record.profile.request, recorded_at)
            _active(connection, record.profile.request, active_head)
            return record
