"""Pure collection-to-admission joins; no dispatch, runtime or AWS authority."""

from copy import deepcopy
from datetime import timedelta

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_admission import S3HostAdmission, approved_request
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_host_config import selected_environment
from bluefire.s3_access_wire import S3WorkerRequest, timestamp
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_admission import reseal
from tests_platform.test_s3_audit_admission import audit_admitted
from tests_platform.test_s3_audit_wire import request_row


def collection_admitted(phase="baseline"):
    value = audit_admitted()
    raw = request_row(phase)
    request = S3WorkerRequest.from_mapping(raw)
    collection = request.to_dict()["audit"]
    entry = value["configuration"]["environments"][0]
    entry["audit_source"] = deepcopy(collection["source"])
    entry["managed_profile_digest"] = collection["source"]["managed_profile_digest"]
    params = value["manifest"]["params"]
    params["worker_request"] = request.to_dict()
    approval = params["workflow_approval"]
    approval.update(
        workflow_job_id=collection["workflow_job_id"],
        operation_job_id=collection["operation_job_id"],
        phase="audit_" + phase,
        scope_digest=request.to_dict()["scope_digest"],
        request_digest=request.digest,
        prior_run_ids=[read["run_id"] for read in collection["original_pair"]["reads"]],
    )
    approval["audit_workflow_digest"] = content_hash(
        audit.build_workflow(
            S3AccessScope.from_mapping(entry["scope"]),
            entry["audit_source"],
            workflow_job_id=approval["workflow_job_id"],
            environment_id=entry["environment_id"],
        )
    )
    value["manifest"].update(
        requested_at=collection["issued_at"],
        expires_at=collection["deadline"],
        run_id="run-20261009T000100Z-" + "3" * 16,
    )
    value["manifest"]["limits"]["timeout_ms"] = 30_000
    value["manifest"]["approval"].update(
        approved_at=collection["issued_at"], expires_at=collection["deadline"]
    )
    value["now"] = timestamp(collection["issued_at"])
    reseal(value)
    return value


def reseal_request(value):
    params = value["manifest"]["params"]
    request = S3WorkerRequest.from_mapping(params["worker_request"])
    params["worker_request"] = request.to_dict()
    params["workflow_approval"]["request_digest"] = request.digest
    reseal(value)
    return request


@pytest.mark.parametrize("phase", ["baseline", "retest"])
def test_collection_admission_joins_original_pair_and_enrolled_commitment(phase):
    value = collection_admitted(phase)
    before = deepcopy(value)
    admission = S3HostAdmission.issue(**value)
    admission.recheck(**value)
    row = admission.to_dict()
    params = value["manifest"]["params"]
    collection = params["worker_request"]["audit"]
    assert row["schema_version"] == "bluefire.s3-access-admission.v3"
    assert row["host"]["audit_workflow"]["source"] == collection["source"]
    assert row["host"]["fixture_lifecycle"] is None
    assert row["manifest_digest"] == content_hash(value["manifest"])
    assert row["approval_digest"] == content_hash(params["workflow_approval"])
    assert timestamp(row["issued_at"]) == timestamp(collection["issued_at"])
    assert timestamp(row["expires_at"]) == timestamp(collection["deadline"])
    assert value == before


@pytest.mark.parametrize("schema", ["v1", "v2"])
def test_collection_rejects_resealed_legacy_approval(schema):
    value = collection_admitted()
    approval = value["manifest"]["params"]["workflow_approval"]
    approval["schema_version"] = "bluefire.s3-workflow-approval." + schema
    approval.pop("audit_workflow_digest")
    reseal(value)
    with pytest.raises(S3AccessError):
        approved_request(
            value["manifest"], value["profile"], task_id=value["task_id"], now=value["now"]
        )


@pytest.mark.parametrize("schema", ["v1", "v2", "v3"])
def test_collection_cannot_gain_host_authority_from_legacy_configuration(schema):
    value = collection_admitted()
    value["configuration"]["schema_version"] = "bluefire.s3-host-environments." + schema
    params = value["manifest"]["params"]
    params["workflow_approval"]["schema_version"] = "bluefire.s3-workflow-approval.v1"
    params["workflow_approval"].pop("audit_workflow_digest")
    reseal(value)
    request = S3WorkerRequest.from_mapping(params["worker_request"])
    with pytest.raises(S3AccessError, match="collection requires its exact new enrolled"):
        selected_environment(
            value["configuration"], request, params["workflow_approval"], value["profile"]
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("workflow_job_id", "job-" + "4" * 32),
        ("operation_job_id", "job-" + "4" * 32),
        ("phase", "audit_retest"),
        ("phase", "baseline"),
        ("phase", "cleanup"),
        ("environment_id", "different-environment"),
    ],
)
def test_resealed_collection_cannot_substitute_approved_workflow_operation_phase_or_environment(
    field, replacement
):
    value = collection_admitted()
    value["manifest"]["params"]["workflow_approval"][field] = replacement
    reseal(value)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize("runs", [[], [0], [1], [0, 0], ["unrelated"]])
def test_collection_requires_both_distinct_original_runs_in_approved_history(runs):
    value = collection_admitted()
    approval = value["manifest"]["params"]["workflow_approval"]
    original = approval["prior_run_ids"]
    approval["prior_run_ids"] = [original[run] if type(run) is int else run for run in runs]
    reseal(value)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)


def test_collection_accepts_original_pair_with_other_preceding_runs_in_any_history_order():
    value = collection_admitted()
    approval = value["manifest"]["params"]["workflow_approval"]
    approval["prior_run_ids"] = [
        "run-20261009T000005Z-" + "9" * 16,
        *reversed(approval["prior_run_ids"]),
    ]
    reseal(value)
    admission = S3HostAdmission.issue(**value)
    admission.recheck(**value)


@pytest.mark.parametrize("side", ["request", "enrollment"])
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("audit_source_id", "different-audit-source"),
        ("audit_bucket", "bluefire-other-audit-fixture"),
        ("audit_bucket_region", "us-east-2"),
        ("collector_role_arn", "arn:aws:iam::123456789012:role/other-audit-reader"),
        ("managed_profile_digest", "sha256:" + "b" * 64),
        ("audit_limits", {**audit.LIMIT_CEILINGS, "events": 400}),
    ],
)
def test_resealed_collection_requires_exact_source_not_just_valid_descriptor(
    side, field, replacement
):
    value = collection_admitted()
    entry = value["configuration"]["environments"][0]
    params = value["manifest"]["params"]
    if side == "request":
        raw = params["worker_request"]
        raw["audit"]["source"][field] = deepcopy(replacement)
        raw["audit_authority_digest"] = content_hash(raw["audit"]["source"])
        reseal_request(value)
    else:
        entry["audit_source"][field] = deepcopy(replacement)
        if field == "managed_profile_digest":
            entry["managed_profile_digest"] = replacement
        params["workflow_approval"]["audit_workflow_digest"] = content_hash(
            audit.build_workflow(
                S3AccessScope.from_mapping(entry["scope"]),
                entry["audit_source"],
                workflow_job_id=params["workflow_approval"]["workflow_job_id"],
                environment_id=entry["environment_id"],
            )
        )
        reseal(value)
    with pytest.raises(
        S3AccessError, match="collection differs from its exact enrolled commitment"
    ):
        S3HostAdmission.issue(**value)


def test_host_collection_workflow_cannot_follow_a_resealed_different_commitment():
    value = collection_admitted()
    entry = value["configuration"]["environments"][0]
    params = value["manifest"]["params"]
    approval = params["workflow_approval"]
    approval["workflow_job_id"] = "job-" + "4" * 32
    approval["audit_workflow_digest"] = content_hash(
        audit.build_workflow(
            S3AccessScope.from_mapping(entry["scope"]),
            entry["audit_source"],
            workflow_job_id=approval["workflow_job_id"],
            environment_id=entry["environment_id"],
        )
    )
    reseal(value)
    with pytest.raises(
        S3AccessError, match="collection differs from its exact enrolled commitment"
    ):
        selected_environment(
            value["configuration"],
            S3WorkerRequest.from_mapping(params["worker_request"]),
            approval,
            value["profile"],
        )


@pytest.mark.parametrize("field", ["requested_at", "expires_at"])
@pytest.mark.parametrize("seconds", [-1, 1])
def test_resealed_manifest_must_keep_original_collection_interval(field, seconds):
    value = collection_admitted()
    value["now"] += timedelta(seconds=2)
    value["manifest"][field] = (
        (timestamp(value["manifest"][field]) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )
    reseal(value)
    with pytest.raises(S3AccessError, match="protected admission"):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize("seconds", [-1, 30])
def test_collection_current_admission_cannot_start_outside_original_interval(seconds):
    value = collection_admitted()
    value["now"] += timedelta(seconds=seconds)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)


def test_collection_admission_may_shorten_but_never_renew_original_interval():
    value = collection_admitted()
    original_issued = value["now"]
    value["now"] += timedelta(seconds=7)
    value["manifest"]["approval"]["expires_at"] = (
        (original_issued + timedelta(seconds=20)).isoformat().replace("+00:00", "Z")
    )
    reseal(value)
    admission = S3HostAdmission.issue(**value)
    assert timestamp(admission.to_dict()["issued_at"]) == original_issued + timedelta(seconds=7)
    assert timestamp(admission.to_dict()["expires_at"]) == original_issued + timedelta(seconds=20)
    admission.recheck(**value)
    with pytest.raises(S3AccessError):
        admission.recheck(**{**value, "now": original_issued + timedelta(seconds=20)})


@pytest.mark.parametrize(("field", "seconds"), [("issued_at", -1), ("expires_at", 31)])
def test_recheck_refuses_tampered_collection_admission_interval(field, seconds):
    value = collection_admitted()
    admission = S3HostAdmission.issue(**value).to_dict()
    admission[field] = (
        (value["now"] + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    )
    changed = S3HostAdmission(canonical_json_bytes(admission))
    with pytest.raises(S3AccessError):
        changed.recheck(**value)


@pytest.mark.parametrize("operation", ["probe_read", "legitimate_read"])
@pytest.mark.parametrize("phase", ["audit_baseline", "audit_retest"])
def test_collection_phases_do_not_admit_unchanged_business_requests(operation, phase):
    value = audit_admitted(operation)
    value["manifest"]["params"]["workflow_approval"]["phase"] = phase
    reseal(value)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)
