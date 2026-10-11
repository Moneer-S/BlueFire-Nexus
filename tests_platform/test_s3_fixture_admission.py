"""Fixture authority requires a new exact enrolled generation, never a v1 upgrade."""

from copy import deepcopy

import pytest

from bluefire.s3_access_admission import S3HostAdmission
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_host_config import public_environments, validate_configuration
from bluefire.s3_access_wire import S3WorkerRequest
from tests_platform.test_s3_access_admission import admitted_fixture, reseal
from tests_platform.test_s3_fixture_sdk import fixture_request


def configured_fixture():
    value = admitted_fixture()
    request, descriptor = fixture_request()
    descriptor["generation_digest"] = value["issuer"]["enrollment_generation"]
    from bluefire.s3_access_contract import S3AccessScope
    from bluefire.s3_fixture_contract import authority_digest

    row = request.to_dict()
    row["fixture_authority_digest"] = authority_digest(
        S3AccessScope.from_mapping(row["scope"]), descriptor
    )
    request = S3WorkerRequest.from_mapping(row)
    config = value["configuration"]
    config["schema_version"] = "bluefire.s3-host-environments.v2"
    entry = config["environments"][0]
    entry.update(
        scope=row["scope"],
        fixture_lifecycle=descriptor,
        exclusive_writer_digest=descriptor["exclusive_writer_digest"],
    )
    params = value["manifest"]["params"]
    params["worker_request"] = request.to_dict()
    params["workflow_approval"].update(
        schema_version="bluefire.s3-workflow-approval.v2",
        phase="prepare",
        scope_digest=row["scope_digest"],
        request_digest=request.digest,
        fixture_authority_digest=row["fixture_authority_digest"],
        fixture_intent_id=row["fixture"]["intent_id"],
    )
    reseal(value)
    return value


def check_configuration(value):
    config = value["configuration"]
    return validate_configuration(
        config, runner_id=config["runner_id"], profile_ids=(value["profile"]["profile_id"],)
    )


@pytest.mark.parametrize("bound", [False, True])
def test_fresh_configuration_and_admission_bind_fixture_generation(bound):
    value = configured_fixture()
    if bound:
        value["configuration"]["schema_version"] = "bluefire.s3-host-environments.v3"
        value["configuration"]["environments"][0]["managed_profile_digest"] = "sha256:" + "a" * 64
    assert check_configuration(value) == value["configuration"]
    admission = S3HostAdmission.issue(**value)
    admission.recheck(**value)
    assert admission.to_dict()["schema_version"] == "bluefire.s3-access-admission.v2"
    assert (
        admission.to_dict()["host"]["fixture_lifecycle"]
        == value["configuration"]["environments"][0]["fixture_lifecycle"]
    )
    assert (
        public_environments(value["configuration"])[0]["fixture_lifecycle"]
        == admission.to_dict()["host"]["fixture_lifecycle"]
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value["configuration"].update(
            schema_version="bluefire.s3-host-environments.v1"
        ),
        lambda value: value["configuration"]["environments"][0].pop("fixture_lifecycle"),
        lambda value: value["configuration"]["environments"][0]["fixture_lifecycle"].update(
            bucket_shape="versioned"
        ),
        lambda value: value["configuration"]["environments"][0]["fixture_lifecycle"].update(
            scope_digest="sha256:" + "f" * 64
        ),
    ],
)
def test_old_or_changed_configuration_cannot_gain_fixture_operations(change):
    value = configured_fixture()
    change(value)
    with pytest.raises(S3AccessError):
        check_configuration(value)


def test_same_descriptor_cannot_be_reused_under_different_enrollment_generation():
    value = configured_fixture()
    value["issuer"]["enrollment_generation"] = "sha256:" + "2" * 64
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)


def test_fixture_binding_cannot_use_legacy_workflow_approval():
    value = configured_fixture()
    value["manifest"]["params"]["workflow_approval"][
        "schema_version"
    ] = "bluefire.s3-workflow-approval.v1"
    reseal(value)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)


def test_new_environment_keeps_descriptor_on_unchanged_v1_business_request():
    value = configured_fixture()
    old = admitted_fixture()["manifest"]["params"]
    request = deepcopy(old["worker_request"])
    request["scope"] = value["configuration"]["environments"][0]["scope"]
    request["scope_digest"] = value["manifest"]["params"]["worker_request"]["scope_digest"]
    request = S3WorkerRequest.from_mapping(request)
    old["worker_request"] = request.to_dict()
    old["workflow_approval"].update(
        scope_digest=request.to_dict()["scope_digest"], request_digest=request.digest
    )
    value["manifest"]["params"] = old
    reseal(value)
    assert (
        S3HostAdmission.issue(**value).to_dict()["schema_version"]
        == "bluefire.s3-access-admission.v2"
    )
