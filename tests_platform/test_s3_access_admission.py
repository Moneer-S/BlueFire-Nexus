"""Exact cloud authority remains bound to configured host and inherited channels."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from bluefire.runner_client import execution_task_identity
from bluefire.runner_contracts import seal_manifest, seal_profile
from bluefire.s3_access_admission import S3HostAdmission, approved_request
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding as file_access_binding
from tests_platform.test_s3_access_host_config import checked, configured
from tests_platform.test_s3_access_wire import NOW, request_row


def admitted_fixture():
    configuration = checked(configured())
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "owned_service_admission_v1.json").read_text(
            encoding="utf-8"
        )
    )
    profile = configuration["environments"][0]["profile"]
    request = S3WorkerRequest.from_mapping(request_row("inspect_policy"))
    manifest = fixture["manifest"]
    manifest.update(
        action_id="owned.aws.s3_access.v1",
        required_capabilities=["cloud_aws_s3_access"],
        policy_digest=profile["policy_digest"],
        requested_at=NOW.isoformat().replace("+00:00", "Z"),
        expires_at=request.to_dict()["deadline"],
    )
    manifest["approval"].update(
        approved_at=manifest["requested_at"], expires_at=manifest["expires_at"]
    )
    manifest["params"] = {
        "worker_request": request.to_dict(),
        "workflow_approval": {
            "schema_version": "bluefire.s3-workflow-approval.v1",
            "workflow_job_id": "job-workflow",
            "operation_job_id": "job-inspect",
            "environment_id": "test-environment",
            "scope_digest": request.to_dict()["scope_digest"],
            "request_digest": request.digest,
            "phase": "inspect",
            "reviewed_by": "operator",
            "review_digest": "sha256:" + "f" * 64,
            "expected_workflow_revision": 0,
            "prior_run_ids": [],
            "policy_change_digest": None,
        },
    }
    manifest = seal_manifest(manifest)
    return {
        "configuration": configuration,
        "manifest": manifest,
        "profile": profile,
        "issuer": fixture["admission"]["issuer"],
        "task_id": execution_task_identity(manifest, profile)[0],
        "runner_digest": "sha256:" + "e" * 64,
        "credential_digest": "sha256:" + "d" * 64,
        "owner_uid": 1000,
        "now": NOW,
    }


def reseal(fixture):
    fixture["manifest"] = seal_manifest(fixture["manifest"])
    fixture["task_id"] = execution_task_identity(fixture["manifest"], fixture["profile"])[0]


def test_exact_host_admission_and_recheck_bind_the_whole_request():
    fixture = admitted_fixture()
    admission = S3HostAdmission.issue(**fixture)
    admission.recheck(**fixture)
    assert admission.to_dict()["approval_digest"] == content_hash(
        fixture["manifest"]["params"]["workflow_approval"]
    )
    assert "secret" not in repr(admission)
    assert "credential_digest" in admission.to_dict()


def test_human_reviewer_name_matches_the_saved_product_review_contract():
    fixture = admitted_fixture()
    fixture["manifest"]["params"]["workflow_approval"]["reviewed_by"] = "Jane Doe"
    reseal(fixture)
    admission = S3HostAdmission.issue(**fixture)
    admission.recheck(**fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_workflow_revision", True),
        ("expected_workflow_revision", -1),
        ("expected_workflow_revision", 1_000_001),
        ("review_digest", None),
        ("phase", "apply"),
        ("prior_run_ids", ["run-one", "run-one"]),
        ("environment_id", "other"),
        ("policy_change_digest", "sha256:" + "a" * 64),
        ("request_digest", "sha256:" + "b" * 64),
    ],
)
def test_resealed_request_cannot_change_closed_workflow_authority(field, value):
    fixture = admitted_fixture()
    fixture["manifest"]["params"]["workflow_approval"][field] = value
    reseal(fixture)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**fixture)


def test_scope_drift_expiry_and_changed_credential_identity_fail_recheck():
    fixture = admitted_fixture()
    admission = S3HostAdmission.issue(**fixture)
    changed = deepcopy(fixture)
    changed["credential_digest"] = "sha256:" + "a" * 64
    with pytest.raises(S3AccessError):
        admission.recheck(**changed)
    changed = deepcopy(fixture)
    changed["configuration"]["environments"][0]["runtime_digest"] = "sha256:" + "a" * 64
    with pytest.raises(S3AccessError):
        admission.recheck(**changed)
    from datetime import timedelta

    changed = {**fixture, "now": NOW + timedelta(seconds=60)}
    with pytest.raises(S3AccessError):
        admission.recheck(**changed)


def test_task_identity_and_ordinary_loopback_capability_cannot_supply_s3_authority():
    fixture = admitted_fixture()
    with pytest.raises(S3AccessError):
        approved_request(fixture["manifest"], fixture["profile"], task_id="execute-other", now=NOW)
    fixture["manifest"]["required_capabilities"] = ["network_loopback"]
    reseal(fixture)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**fixture)


def test_resealed_endpoint_binding_is_refused_before_cloud_admission():
    fixture = admitted_fixture()
    fixture["profile"]["file_access_binding"] = file_access_binding()
    fixture["profile"] = seal_profile(fixture["profile"])
    fixture["manifest"]["policy_digest"] = fixture["profile"]["policy_digest"]
    reseal(fixture)
    with pytest.raises(S3AccessError):
        approved_request(
            fixture["manifest"], fixture["profile"], task_id=fixture["task_id"], now=NOW
        )


def test_explicit_null_endpoint_binding_is_refused_before_profile_sealing(monkeypatch):
    fixture = admitted_fixture()
    fixture["profile"]["file_access_binding"] = None

    def unexpected_sealing(_profile):
        pytest.fail("mixed authority must be rejected before profile sealing")

    monkeypatch.setattr("bluefire.s3_access_admission.seal_profile", unexpected_sealing)
    with pytest.raises(S3AccessError):
        approved_request(
            fixture["manifest"], fixture["profile"], task_id=fixture["task_id"], now=NOW
        )
