"""Live admission over saved ProductStore rows; no native read is dispatched."""

from __future__ import annotations

import copy
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, cast

import pytest

from bluefire import engine_file_access_admission as admission
from bluefire import file_access_context
from bluefire import product_store_engine_file_access as reservation_store
from bluefire.engine_attempt_contract import AttemptRole, EngineAttemptBinding
from bluefire.engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    EngineDefenseChange,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
)
from bluefire.engine_file_access_target import EngineFileReadTargetPolicy
from bluefire.execution_contracts import execution_task_identity
from bluefire.file_access_contract import MAX_BYTES, verify_file_access_binding
from bluefire.product_store import ProductStore
from bluefire.product_store_serialization import canonical_json
from bluefire.runner_contracts import seal_manifest
from bluefire.util import content_hash
from tests_platform import test_engine_experiment as workflow_fixture
from tests_platform.test_engine_file_access_snapshot import _controller_case

NOW_MS = 1_000_000
OWNER_ID = "job-" + "0" * 32


def _digest(marker: str) -> str:
    return "sha256:" + marker * 64


def _stamp(milliseconds: int) -> str:
    return (
        datetime.fromtimestamp(milliseconds / 1000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _validate_experiment(document: Mapping[str, Any]) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], EngineExperiment._from_controller_mapping(document).to_dict())


def _hardened_case(historical_record: Mapping[str, Any]):
    """Retie the independent harden fixture to the exact saved baseline preimage."""

    _, _, _, current_record, operation = _controller_case(CURRENT_HARDENED)
    current_record = copy.deepcopy(current_record)
    operation = copy.deepcopy(operation)
    before = historical_record["document"]
    review_context = operation["document"]["review_context"]
    review = operation["document"]["review"]
    preparation = operation["preparation"]
    preparation["prior"] = copy.deepcopy(before)
    review_context["control_digest"] = content_hash(before)
    review["control_digest"] = content_hash(before)
    review["context_digest"] = content_hash(review_context)
    review["review_digest"] = content_hash(
        {key: value for key, value in review.items() if key != "review_digest"}
    )
    operation["document"]["submitted_request"]["review_digest"] = review["review_digest"]
    preparation["context_digest"] = review["context_digest"]
    for profile in preparation["profiles"].values():
        profile["reviewed_execution"]["authorization_digest"] = review["review_digest"]
    for pair in operation["tasks"]:
        task = pair["task"]
        profile = preparation["profiles"]["retained"]
        task["runner_profile"] = copy.deepcopy(profile)
        manifest = task["manifest"]
        manifest["reviewed_operation"]["authorization_digest"] = review["review_digest"]
        manifest["request_hash"] = ""
        manifest["approval"]["request_hash"] = ""
        sealed = seal_manifest(manifest)
        task_id, transport_hash = execution_task_identity(sealed, profile)
        task["manifest"] = sealed
        task["task_id"] = task_id
        task["request_hash"] = sealed["request_hash"]
        task["transport_request_hash"] = transport_hash
        pair["terminal"]["task_id"] = task_id
        pair["terminal"]["request_hash"] = sealed["request_hash"]
    current_record["document"]["baseline"] = copy.deepcopy(before["baseline"])
    current_record["document_digest"] = content_hash(current_record["document"])
    operation["outcome"]["evidence_digest"] = content_hash(operation["tasks"])
    operation["outcome"]["control_digest"] = current_record["document_digest"]
    operation["outcome_digest"] = content_hash(operation["outcome"])
    current_binding = verify_file_access_binding(
        current_record["document"]["binding"],
        expected_document_digest=current_record["document"]["binding_digest"],
        now_ms=NOW_MS,
    )
    mechanism = FileAccessReadMechanism.from_verified_binding(
        current_binding, baseline=before["baseline"]
    )
    snapshot = FileAccessTargetSnapshot.from_controller_records(
        current_binding,
        mechanism=mechanism,
        control_record=current_record,
        operation_records=operation,
        phase=CURRENT_HARDENED,
    )
    return snapshot, current_binding, current_record, operation


def _insert_control(path: Path, record: Mapping[str, Any], operation: Mapping[str, Any]) -> None:
    job_id = record["job_id"]
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                job_id,
                "file_access.operation",
                "completed",
                "{}",
                "{}",
                None,
                None,
                "1970-01-01T00:16:40Z",
                "1970-01-01T00:16:40Z",
            ),
        )
        connection.execute(
            "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
            (
                job_id,
                operation["control_owner_id"],
                record["document"]["enrollment_id"],
                operation["document"]["review"]["operation"],
                canonical_json(operation["document"]),
                content_hash(operation["document"]),
            ),
        )
        connection.execute(
            "INSERT INTO file_access_preparations VALUES(?,?,?)",
            (
                job_id,
                canonical_json(operation["preparation"]),
                content_hash(operation["preparation"]),
            ),
        )
        for pair in operation["tasks"]:
            task, terminal = pair["task"], pair["terminal"]
            connection.execute(
                "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                (
                    task["task_id"],
                    job_id,
                    task["step_id"],
                    task["request_hash"],
                    canonical_json(task),
                    content_hash(task),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
                (task["task_id"], canonical_json(terminal), content_hash(terminal)),
            )
        connection.execute(
            "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
            (job_id, canonical_json(operation["outcome"]), content_hash(operation["outcome"])),
        )
        connection.execute(
            "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
            (
                OWNER_ID,
                record["document"]["revision"],
                job_id,
                canonical_json(record["document"]),
                record["document_digest"],
            ),
        )


def _attempt(
    *,
    role: AttemptRole,
    mechanism: FileAccessReadMechanism,
    snapshot: FileAccessTargetSnapshot,
    created_ms: int,
    parent_id: str | None,
) -> EngineAttemptBinding:
    marker = "1" if role is AttemptRole.BASELINE else "2"
    return EngineAttemptBinding(
        schema_version="bluefire.engine-attempt-binding.v1",
        experiment_id="experiment-" + "1" * 32,
        attempt_id="engine-attempt-" + marker * 32,
        run_id=f"run-19700101T0016{created_ms // 1000 % 60:02d}Z-" + marker * 16,
        role=role,
        objective_ref=_digest("1"),
        environment_ref=_digest("2"),
        target_snapshot_ref=snapshot.target_snapshot_ref,
        scope_ref=mechanism.mechanism_ref,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        engine_id="strix",
        engine_version="1.7.0",
        engine_revision="4" * 40,
        engine_package_digest=_digest("5"),
        policy_overlay_digest=_digest("6"),
        model_provider="controlled-test-provider",
        model_id="controlled-file-read-v1",
        model_data_destination="attempt-local-loopback-test-provider",
        model_authorization_ref=_digest("7"),
        wall_clock_seconds=780,
        action_limit=8,
        cost_limit_microunits=50_000,
        artifact_byte_limit=MAX_BYTES,
        created_at=_stamp(created_ms),
        parent_attempt_id=parent_id,
    )


def _save_experiment(store: ProductStore, experiment: EngineExperiment) -> None:
    first = EngineExperiment.create(
        experiment_id=experiment.experiment_id,
        objective_ref=experiment.objective_ref,
        environment_ref=experiment.environment_ref,
        scope_ref=experiment.scope_ref,
        scope_version=experiment.scope_version,
        target_snapshot_ref=experiment.initial_target_snapshot_ref,
        created_at=experiment.created_at,
    )
    created = store.create_engine_experiment(
        first.experiment_id, first.to_dict(), validator=_validate_experiment
    )
    saved = replace(
        experiment,
        revision=2,
        previous_revision_digest=created["digest"],
    )
    saved.validate()
    store.save_engine_experiment(
        first.experiment_id,
        saved.to_dict(),
        expected_revision=1,
        expected_digest=created["digest"],
        validator=_validate_experiment,
    )


def _baseline_experiment(
    mechanism: FileAccessReadMechanism, snapshot: FileAccessTargetSnapshot
) -> tuple[EngineExperiment, EngineAttemptBinding]:
    attempt = _attempt(
        role=AttemptRole.BASELINE,
        mechanism=mechanism,
        snapshot=snapshot,
        created_ms=NOW_MS,
        parent_id=None,
    )
    experiment = EngineExperiment.create(
        experiment_id=attempt.experiment_id,
        objective_ref=attempt.objective_ref,
        environment_ref=attempt.environment_ref,
        scope_ref=attempt.scope_ref,
        scope_version=attempt.scope_version,
        target_snapshot_ref=attempt.target_snapshot_ref,
        created_at=_stamp(NOW_MS - 1_000),
    )
    experiment = experiment.reserve_attempt(
        attempt,
        job_id="job-" + "1" * 32,
        delegation_digest=_digest("8"),
        execution_approval_digest=_digest("9"),
        execution_approval_id="approval-" + "1" * 32,
        timestamp=attempt.created_at,
    )
    return experiment, attempt


def _adaptive_experiment(
    monkeypatch: pytest.MonkeyPatch,
    mechanism: FileAccessReadMechanism,
    historical: FileAccessTargetSnapshot,
    current: FileAccessTargetSnapshot,
) -> tuple[EngineExperiment, EngineAttemptBinding]:
    """Use a settled synthetic workflow to reach the saved adaptive stage."""

    baseline, baseline_binding = _baseline_experiment(mechanism, historical)
    # The workflow fixture generates independently checked tenant evidence for
    # the necessary baseline and retained-reproducer stages.
    monkeypatch.setattr(workflow_fixture, "SCOPE_REF", mechanism.mechanism_ref)
    baseline = workflow_fixture._settle_latest_attempt(
        baseline,
        started_at=_stamp(NOW_MS + 1_000),
        ended_at=_stamp(NOW_MS + 3_000),
    )
    observed = _controller_observation_record(
        target_snapshot_ref=historical.target_snapshot_ref,
        mechanism_ref=mechanism.mechanism_ref,
        attempt_id=baseline_binding.attempt_id,
        evidence=workflow_fixture._tenant_observation(
            owner_id=baseline_binding.attempt_id,
            run_id=baseline_binding.run_id,
            timestamp=_stamp(NOW_MS + 2_000),
            hardened=False,
        ),
    )
    baseline = baseline.record_independent_observation(observed, timestamp=_stamp(NOW_MS + 4_000))
    change_id = "defense-change-" + "e" * 32
    change = EngineDefenseChange.reviewed(
        change_id=change_id,
        experiment_id=baseline.experiment_id,
        mechanism_ref=mechanism.mechanism_ref,
        preimage_digest=_digest("e"),
        approved_configuration_digest=_digest("f"),
        before_target_snapshot_ref=historical.target_snapshot_ref,
        after_target_snapshot_ref=current.target_snapshot_ref,
        rollback_digest=_digest("0"),
        reviewed_by="operator",
        reviewed_at=_stamp(NOW_MS + 5_000),
    )
    baseline = baseline.review_defense(change, timestamp=_stamp(NOW_MS + 5_000))
    baseline = baseline.begin_defense_application(
        change_id, operation_receipt_digest=_digest("1"), started_at=_stamp(NOW_MS + 6_000)
    )
    baseline = baseline.apply_defense(
        change_id,
        applied_configuration_digest=_digest("f"),
        reconciliation_receipt_digest=_digest("2"),
        observed_target_snapshot_ref=current.target_snapshot_ref,
        reconciled_at=_stamp(NOW_MS + 7_000),
    )
    check = ControllerCheckRecord.reserve(
        check_id="controller-check-" + "c" * 32,
        experiment_id=baseline.experiment_id,
        job_id="job-" + "c" * 32,
        run_id="run-19700101T001648Z-" + "c" * 16,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=mechanism.mechanism_ref,
        target_snapshot_ref=current.target_snapshot_ref,
        input_digest=_digest("3"),
        created_at=_stamp(NOW_MS + 8_000),
    )
    baseline = baseline.reserve_controller_check(check, timestamp=check.created_at)
    observed = _controller_observation_record(
        target_snapshot_ref=current.target_snapshot_ref,
        mechanism_ref=mechanism.mechanism_ref,
        check_id=check.check_id,
        check_input_digest=check.input_digest,
        evidence=workflow_fixture._tenant_observation(
            owner_id=check.check_id,
            run_id=check.run_id,
            timestamp=_stamp(NOW_MS + 9_000),
            hardened=True,
        ),
    )
    baseline = baseline.record_independent_observation(observed, timestamp=_stamp(NOW_MS + 9_000))
    check = check.settle(
        state=ControllerCheckState.COMPLETED,
        result_digest=_digest("4"),
        independent_evidence_refs=(observed.evidence_id,),
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("5"),
        settled_at=_stamp(NOW_MS + 10_000),
    )
    baseline = baseline.settle_controller_check(check, timestamp=_stamp(NOW_MS + 10_000))
    adaptive = _attempt(
        role=AttemptRole.ADAPTIVE_SEARCH,
        mechanism=mechanism,
        snapshot=current,
        created_ms=NOW_MS + 11_000,
        parent_id=baseline_binding.attempt_id,
    )
    experiment = baseline.reserve_attempt(
        adaptive,
        job_id="job-" + "2" * 32,
        delegation_digest=_digest("6"),
        execution_approval_digest=_digest("7"),
        execution_approval_id="approval-" + "2" * 32,
        timestamp=adaptive.created_at,
    )
    return experiment, adaptive


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    adaptive = request.param == "adaptive"
    clock = NOW_MS + (12_000 if adaptive else 100)
    monkeypatch.setattr(admission, "_server_now_ms", lambda: clock)
    monkeypatch.setattr(reservation_store, "_server_now_ms", lambda: clock)
    monkeypatch.setattr(file_access_context, "is_windows_host", lambda: False)
    monkeypatch.setattr(file_access_context, "is_macos_host", lambda: False)
    historical, mechanism, historical_binding, historical_record, historical_operation = (
        _controller_case(HISTORICAL_BASELINE)
    )
    store = ProductStore(tmp_path / "product.db")
    _insert_control(store.path, historical_record, historical_operation)
    if adaptive:
        current, current_binding, current_record, current_operation = _hardened_case(
            historical_record
        )
        _insert_control(store.path, current_record, current_operation)
        experiment, attempt = _adaptive_experiment(monkeypatch, mechanism, historical, current)
    else:
        current, current_binding = historical, historical_binding
        experiment, attempt = _baseline_experiment(mechanism, historical)
    _save_experiment(store, experiment)
    policy = EngineFileReadTargetPolicy.from_controller(
        attempt=attempt,
        mechanism=mechanism,
        historical_snapshot=historical,
        snapshot=current,
        historical_binding=historical_binding,
        current_binding=current_binding,
        now_ms=clock,
        request_budget=2,
        deadline_ms=clock + 120_000,
    )
    reservation = store.reserve_engine_file_access_target(
        experiment.experiment_id, attempt.attempt_id, policy
    )
    source = current_binding.to_dict()
    enrolled = {
        "document": {
            "enrollment_id": source["enrollment_id"],
            "resource_id": source["resource_id"],
            "resource_generation": source["resource_generation"],
            "expires_at_ms": source["expires_at_ms"],
            "worker": source["worker"],
        },
        "document_digest": source["enrollment_digest"],
    }
    monkeypatch.setattr(file_access_context, "enrollment", lambda _service, _now: enrolled)
    monkeypatch.setattr(
        file_access_context,
        "inspect_file_access_resource",
        lambda **_kwargs: {"mode": source["mode"], "resource": source["resource"]},
    )
    service = SimpleNamespace(product_store=store)
    return service, store, attempt, policy, reservation, enrolled, source


def _admit(service: Any, attempt_id: str, ordinal: int = 1, marker: str = "a"):
    request_hash = _digest(marker)
    return admission.admit_engine_file_access_request(
        service,
        attempt_id,
        ordinal=ordinal,
        task_id="execute-" + request_hash[7:],
        request_hash=request_hash,
        transport_request_hash=content_hash({"transport": marker}),
    )


@pytest.mark.parametrize("case", ["baseline", "adaptive"], indirect=True)
def test_live_admission_claims_exact_request(case) -> None:
    service, store, attempt, policy, reservation, _enrolled, _source = case
    receipt = _admit(service, attempt.attempt_id)
    assert type(receipt) is admission.EngineFileAccessAdmissionReceipt
    assert receipt.to_dict() == store.list_engine_file_access_request_claims(attempt.attempt_id)[0]
    assert receipt.reservation_ref == reservation["reservation_ref"]
    assert receipt.policy_digest == policy.policy_digest
    assert _admit(service, attempt.attempt_id, 2, "b").ordinal == 2
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id, 2, "b")
    assert len(store.list_engine_file_access_request_claims(attempt.attempt_id)) == 2


@pytest.mark.parametrize("case", ["baseline", "adaptive"], indirect=True)
def test_pending_operation_inserted_after_live_checks_consumes_no_claim(
    case, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store, attempt, policy, _reservation, _enrolled, _source = case
    original_claim = store.claim_engine_file_access_request
    owner_id = policy.snapshot.to_dict()["control_owner_id"]
    enrollment_id = policy.mechanism.to_dict()["enrollment_id"]
    pending_job = "job-" + "f" * 32

    def interposed_claim(*args: Any, **kwargs: Any):
        operation = {"schema_version": "bluefire.file-access-operation.v1", "state": "pending"}
        with sqlite3.connect(store.path) as connection:
            connection.execute(
                "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    pending_job,
                    "file_access.operation",
                    "running",
                    "{}",
                    "{}",
                    None,
                    None,
                    "1970-01-01T00:16:40Z",
                    "1970-01-01T00:16:40Z",
                ),
            )
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (
                    pending_job,
                    owner_id,
                    enrollment_id,
                    "harden",
                    canonical_json(operation),
                    content_hash(operation),
                ),
            )
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(store, "claim_engine_file_access_request", interposed_claim)
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


@pytest.mark.parametrize("case", ["baseline", "adaptive"], indirect=True)
@pytest.mark.parametrize(
    "change",
    ["enrollment", "resource", "revision", "pending", "usage", "history", "current_operation"],
)
def test_stale_or_substituted_controller_facts_consume_no_claim(
    case, change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store, attempt, _policy, _reservation, enrolled, source = case
    if change == "enrollment":
        changed = copy.deepcopy(enrolled)
        changed["document_digest"] = _digest("f")
        monkeypatch.setattr(file_access_context, "enrollment", lambda _service, _now: changed)
    elif change == "resource":
        changed = copy.deepcopy(source["resource"])
        changed["inode"] += 1
        monkeypatch.setattr(
            file_access_context,
            "inspect_file_access_resource",
            lambda **_kwargs: {"mode": source["mode"], "resource": changed},
        )
    elif change in {"revision", "pending", "usage"}:
        original = store.get_file_access_control

        def changed_control(owner_id: str):
            result = copy.deepcopy(original(owner_id))
            if change == "revision":
                result["document"]["revision"] += 1
            elif change == "pending":
                result["pending_operation"] = True
            else:
                result["usages_settled"] = False
            return result

        monkeypatch.setattr(store, "get_file_access_control", changed_control)
    else:
        original = store.file_access_operation_records
        target_job = (
            "job-"
            + ("2" if change == "history" or attempt.role is AttemptRole.BASELINE else "5") * 32
        )

        def changed_operation(job_id: str):
            result = copy.deepcopy(original(job_id))
            if job_id == target_job:
                result["tasks"][0]["task"]["request_hash"] = _digest("f")
            return result

        monkeypatch.setattr(store, "file_access_operation_records", changed_operation)
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


@pytest.mark.parametrize("case", ["baseline", "adaptive"], indirect=True)
def test_wrong_owner_task_and_budget_consume_no_extra_claim(case) -> None:
    service, store, attempt, _policy, _reservation, _enrolled, _source = case
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, "engine-attempt-" + "f" * 32)
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        admission.admit_engine_file_access_request(
            service,
            attempt.attempt_id,
            ordinal=1,
            task_id="execute-" + "f" * 64,
            request_hash=_digest("a"),
            transport_request_hash=_digest("b"),
        )
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id, 2)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []
    _admit(service, attempt.attempt_id)
    _admit(service, attempt.attempt_id, 2, "b")
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id, 3, "c")
    assert len(store.list_engine_file_access_request_claims(attempt.attempt_id)) == 2


@pytest.mark.parametrize("case", ["baseline", "adaptive"], indirect=True)
@pytest.mark.parametrize("change", ["policy", "digest", "attempt_binding"])
def test_substituted_protected_reservation_consumes_no_claim(
    case, change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store, attempt, _policy, _reservation, _enrolled, _source = case
    original = store.get_engine_file_access_target_reservation

    def changed_reservation(attempt_id: str):
        result = copy.deepcopy(original(attempt_id))
        if change == "policy":
            result["policy"]["request_budget"] += 1
        elif change == "digest":
            result["policy_digest"] = _digest("f")
        else:
            result["binding_digest"] = _digest("f")
        return result

    monkeypatch.setattr(store, "get_engine_file_access_target_reservation", changed_reservation)
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


@pytest.mark.parametrize("case", ["adaptive"], indirect=True)
def test_historical_enrollment_expiry_cannot_be_substituted(
    case, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store, attempt, policy, _reservation, _enrolled, _source = case
    original = store.get_linux_file_access_revision_record
    historical_revision = policy.historical_snapshot.to_dict()["control_revision"]

    def changed_revision(owner_id: str, revision: int):
        result = copy.deepcopy(original(owner_id, revision))
        if revision == historical_revision:
            result["document"]["binding"]["expires_at_ms"] += 1
            result["document"]["binding_digest"] = content_hash(result["document"]["binding"])
            result["document_digest"] = content_hash(result["document"])
        return result

    monkeypatch.setattr(store, "get_linux_file_access_revision_record", changed_revision)
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


@pytest.mark.parametrize("case", ["baseline", "adaptive"], indirect=True)
def test_expired_policy_consumes_no_claim(case, monkeypatch: pytest.MonkeyPatch) -> None:
    service, store, attempt, policy, _reservation, _enrolled, _source = case
    monkeypatch.setattr(admission, "_server_now_ms", lambda: policy.deadline_ms)
    with pytest.raises(admission.EngineFileAccessAdmissionError):
        _admit(service, attempt.attempt_id)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []
