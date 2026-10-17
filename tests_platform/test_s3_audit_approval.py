"""Saved-source approval construction only; no store, runtime or cloud effects."""

from copy import deepcopy
from datetime import timedelta

import pytest

from bluefire import product_store_s3_access as records
from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_host_config import selected_environment
from bluefire.s3_access_wire import S3WorkerRequest
from tests_platform.test_s3_access_admission import admitted_fixture
from tests_platform.test_s3_audit_admission import audit_admitted
from tests_platform.test_s3_fixture_admission import configured_fixture


def saved(value):
    params = value["manifest"]["params"]
    approval = params["workflow_approval"]
    owner = {
        "job_id": approval["workflow_job_id"],
        "request": {"environment": deepcopy(value["configuration"]["environments"][0])},
    }
    document = {
        "s3_access": {
            "phase": approval["phase"],
            "expected_revision": approval["expected_workflow_revision"],
            "review": {
                "review_digest": approval["review_digest"],
                "prior_run_ids": deepcopy(approval["prior_run_ids"]),
            },
        },
        "submitted_request": {"reviewed_by": approval["reviewed_by"]},
    }
    return (
        owner,
        approval["operation_job_id"],
        document,
        S3WorkerRequest.from_mapping(params["worker_request"]),
    )


@pytest.mark.parametrize("factory", [admitted_fixture, configured_fixture])
def test_legacy_saved_approval_is_unchanged(factory):
    value = factory()
    assert (
        records.workflow_approval(*saved(value)) == value["manifest"]["params"]["workflow_approval"]
    )


@pytest.mark.parametrize(
    "operation", ["inspect_policy", "prepare_fixture", "rollback_policy", "cleanup_fixture"]
)
def test_saved_audited_approval_matches_original_commitment(operation):
    value = audit_admitted(operation)
    before = deepcopy(value)
    assert (
        records.workflow_approval(*saved(value)) == value["manifest"]["params"]["workflow_approval"]
    )
    assert value == before


def test_audit_approval_uses_saved_source_not_submitted_source():
    value = audit_admitted()
    owner, identifier, document, request = saved(value)
    document["submitted_request"]["audit_source"] = {"audit_bucket": "untrusted-substitution"}
    document["s3_access"]["audit_workflow_digest"] = "sha256:" + "f" * 64
    assert (
        records.workflow_approval(owner, identifier, document, request)
        == value["manifest"]["params"]["workflow_approval"]
    )


@pytest.mark.parametrize("binding", ["source", "workflow", "environment"])
def test_changed_saved_binding_cannot_use_original_host_commitment(binding):
    value = audit_admitted()
    owner, identifier, document, request = saved(value)
    if binding == "source":
        owner["request"]["environment"]["audit_source"][
            "audit_bucket"
        ] = "bluefire-other-audit-fixture"
    elif binding == "workflow":
        owner["job_id"] = "job-" + "3" * 32
    else:
        owner["request"]["environment"]["environment_id"] = "other-environment"
    approval = records.workflow_approval(owner, identifier, document, request)
    assert (
        approval["audit_workflow_digest"]
        != value["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"]
    )
    if binding != "workflow":
        with pytest.raises(S3AccessError):
            selected_environment(value["configuration"], request, approval, value["profile"])


def test_expired_saved_source_is_not_renewed_when_building_recovery_approval():
    value = audit_admitted("rollback_policy", source_seconds=1)
    value["now"] += timedelta(seconds=2)
    owner, identifier, document, request = saved(value)
    before = deepcopy(owner)
    assert (
        records.workflow_approval(owner, identifier, document, request)
        == value["manifest"]["params"]["workflow_approval"]
    )
    assert owner == before


def test_present_invalid_audit_source_never_falls_back_to_legacy_approval():
    value = audit_admitted()
    owner, identifier, document, request = saved(value)
    owner["request"]["environment"]["audit_source"] = None
    with pytest.raises(S3AccessError):
        records.workflow_approval(owner, identifier, document, request)


def test_fixture_audit_approval_keeps_original_fixture_authority():
    value = audit_admitted("prepare_fixture")
    approval = records.workflow_approval(*saved(value))
    original = value["manifest"]["params"]["workflow_approval"]
    assert approval["schema_version"] == audit.APPROVAL_SCHEMA
    for key in ("fixture_authority_digest", "fixture_intent_id"):
        assert approval[key] == original[key]
