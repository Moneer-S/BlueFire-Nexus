"""Pure audited admission and historical shapes, not native or AWS authority."""

from copy import deepcopy
from datetime import timedelta

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire import s3_fixture_contract as fixtures
from bluefire.s3_access_admission import S3HostAdmission, approved_request
from bluefire.s3_access_configuration import AUDIT_SCHEMA
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_host_config import selected_environment
from bluefire.s3_access_recovery import execution_manifest, validate_recovery_context
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_admission import admitted_fixture, reseal
from tests_platform.test_s3_access_wire import NOW, request_row
from tests_platform.test_s3_audit_collection_contract import source_row
from tests_platform.test_s3_fixture_admission import configured_fixture


def audit_admitted(operation="inspect_policy", *, source_seconds=3600):
    fixture_operation = operation in fixtures.SEND_LIMITS
    value = configured_fixture() if fixture_operation else admitted_fixture()
    entry = value["configuration"]["environments"][0]
    params = value["manifest"]["params"]
    raw = deepcopy(params["worker_request"]) if fixture_operation else request_row(operation)
    if fixture_operation:
        raw.update(operation=operation, max_sends=fixtures.SEND_LIMITS[operation])
    request = S3WorkerRequest.from_mapping(raw)
    params["worker_request"] = request.to_dict()
    phase = {
        "inspect_policy": "inspect",
        "probe_read": "baseline",
        "legitimate_read": "baseline",
        "apply_policy": "apply",
        "reconcile_policy": "reconcile",
        "rollback_policy": "rollback",
        "prepare_fixture": "prepare",
        "reconcile_fixture": "reconcile_fixtures",
        "cleanup_fixture": "cleanup",
    }[operation]
    value["configuration"]["schema_version"] = AUDIT_SCHEMA
    entry["managed_profile_digest"] = "sha256:" + "a" * 64
    scope = S3AccessScope.from_mapping(entry["scope"])
    entry["audit_source"] = {
        **source_row(scope),
        "managed_profile_digest": entry["managed_profile_digest"],
        "protected_runtime_digest": entry["runtime_digest"],
        "worker_generation": entry["worker_generation"],
        "expires_at": (NOW + timedelta(seconds=source_seconds)).isoformat().replace("+00:00", "Z"),
    }
    approval = params["workflow_approval"]
    approval.update(
        schema_version=audit.APPROVAL_SCHEMA,
        workflow_job_id="job-" + "1" * 32,
        operation_job_id="job-" + "2" * 32,
        phase=phase,
        scope_digest=request.to_dict()["scope_digest"],
        request_digest=request.digest,
        policy_change_digest=(
            content_hash(raw["policy_change"]) if raw["policy_change"] is not None else None
        ),
    )
    approval["audit_workflow_digest"] = content_hash(
        audit.build_workflow(
            scope,
            entry["audit_source"],
            workflow_job_id=approval["workflow_job_id"],
            environment_id=entry["environment_id"],
        )
    )
    reseal(value)
    return value


def original_context(value):
    params = value["manifest"]["params"]
    request = S3WorkerRequest.from_mapping(params["worker_request"])
    manifest = execution_manifest(request, params["workflow_approval"], value["profile"])
    transport_hash = content_hash({"manifest": manifest, "profile": value["profile"]})
    return request, {
        "schema_version": "bluefire.s3-original-task.v1",
        "request_digest": request.digest,
        "task_id": "execute-" + transport_hash.removeprefix("sha256:"),
        "transport_request_hash": transport_hash,
        "manifest": manifest,
        "profile": deepcopy(value["profile"]),
        "transport_identity": {
            "schema_version": "bluefire.runner-transport-identity.v1",
            "runner_id": value["profile"]["runner_id"],
            "client_id": "client.synthetic.v1",
            "transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
            **{
                name: "sha256:" + "a" * 64
                for name in (
                    "server_fingerprint",
                    "client_fingerprint",
                    "authenticated_peer_fingerprint",
                    "enrollment_generation",
                    "runner_binary_digest",
                    "inventory_digest",
                )
            },
        },
    }


@pytest.mark.parametrize("operation", ["inspect_policy", "prepare_fixture"])
def test_audited_admission_binds_complete_commitment_and_explicit_fixture_null(operation):
    value = audit_admitted(operation)
    original = deepcopy(value["manifest"]["params"]["worker_request"])
    admission = S3HostAdmission.issue(**value)
    admission.recheck(**value)
    row = admission.to_dict()
    assert row["schema_version"] == "bluefire.s3-access-admission.v3"
    host = row["host"]
    assert set(host) == {
        "environment_id",
        "scope_digest",
        "runtime_digest",
        "worker_generation",
        "ledger_root",
        "runtime_root",
        "owner_uid",
        "audit_workflow",
        "fixture_lifecycle",
    }
    assert host["fixture_lifecycle"] == value["configuration"]["environments"][0].get(
        "fixture_lifecycle"
    )
    assert (
        content_hash(host["audit_workflow"])
        == value["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"]
    )
    assert host["audit_workflow"]["budget"]["workflow"]["sessions"] == 2
    assert value["manifest"]["params"]["worker_request"] == original
    assert original["schema_version"] == (
        fixtures.REQUEST_SCHEMA
        if operation == "prepare_fixture"
        else "bluefire.s3-worker-request.v1"
    )
    host["audit_workflow"]["source"]["audit_limits"]["events"] = 1
    assert admission.to_dict()["host"]["audit_workflow"]["source"]["audit_limits"]["events"] == 500


def test_audited_fixture_enrollment_retains_descriptor_on_unchanged_business_v1_request():
    value = audit_admitted("prepare_fixture")
    entry = value["configuration"]["environments"][0]
    raw = request_row("probe_read")
    scope = S3AccessScope.from_mapping(entry["scope"])
    raw.update(scope=scope.to_dict(), scope_digest=scope.digest)
    request = S3WorkerRequest.from_mapping(raw)
    params = value["manifest"]["params"]
    params["worker_request"] = request.to_dict()
    params["workflow_approval"].update(phase="baseline", request_digest=request.digest)
    params["workflow_approval"].pop("fixture_authority_digest")
    params["workflow_approval"].pop("fixture_intent_id")
    reseal(value)
    admission = S3HostAdmission.issue(**value)
    assert admission.to_dict()["host"]["fixture_lifecycle"] == entry["fixture_lifecycle"]
    assert params["worker_request"]["schema_version"] == "bluefire.s3-worker-request.v1"
    admission.recheck(**value)


@pytest.mark.parametrize("operation", ["inspect_policy", "prepare_fixture"])
def test_v4_configuration_refuses_legacy_approval_even_when_resealed(operation):
    value = audit_admitted(operation)
    approval = value["manifest"]["params"]["workflow_approval"]
    approval.pop("audit_workflow_digest")
    approval["schema_version"] = (
        "bluefire.s3-workflow-approval.v2"
        if operation == "prepare_fixture"
        else "bluefire.s3-workflow-approval.v1"
    )
    reseal(value)
    with pytest.raises(S3AccessError, match="exact new enrolled configuration"):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize(
    "schema",
    [
        "bluefire.s3-host-environments.v1",
        "bluefire.s3-host-environments.v2",
        "bluefire.s3-host-environments.v3",
    ],
)
def test_audited_approval_cannot_upgrade_legacy_config(schema):
    value = audit_admitted("prepare_fixture" if schema.endswith("v2") else "inspect_policy")
    value["configuration"]["schema_version"] = schema
    entry = value["configuration"]["environments"][0]
    entry.pop("audit_source")
    if not schema.endswith("v3"):
        entry.pop("managed_profile_digest")
    with pytest.raises(S3AccessError, match="exact new enrolled configuration"):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize(
    "change", ["missing_digest", "extra", "malformed_digest", "legacy_plus_digest"]
)
def test_audited_workflow_approval_is_closed_and_requires_exact_digest_shape(change):
    value = audit_admitted()
    approval = value["manifest"]["params"]["workflow_approval"]
    if change == "missing_digest":
        approval.pop("audit_workflow_digest")
    elif change == "extra":
        approval["audit_source"] = {}
    elif change == "malformed_digest":
        approval["audit_workflow_digest"] = True
    else:
        approval["schema_version"] = "bluefire.s3-workflow-approval.v1"
    reseal(value)
    with pytest.raises(S3AccessError):
        approved_request(value["manifest"], value["profile"], task_id=value["task_id"], now=NOW)


@pytest.mark.parametrize(
    "operation",
    [
        "probe_read",
        "prepare_fixture",
        "reconcile_policy",
        "rollback_policy",
        "reconcile_fixture",
        "cleanup_fixture",
    ],
)
def test_original_commitment_cannot_be_substituted_on_business_or_recovery_paths(operation):
    value = audit_admitted(operation)
    value["configuration"]["environments"][0]["audit_source"][
        "audit_bucket"
    ] = "bluefire-other-audit-fixture"
    with pytest.raises(S3AccessError, match="exact enrolled commitment"):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize(
    "binding", ["managed_profile_digest", "protected_runtime_digest", "worker_generation"]
)
def test_resealed_source_still_requires_original_enrolled_profile_runtime_generation(binding):
    value = audit_admitted()
    entry = value["configuration"]["environments"][0]
    entry["audit_source"][binding] = "sha256:" + "f" * 64
    value["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"] = content_hash(
        audit.build_workflow(
            S3AccessScope.from_mapping(entry["scope"]),
            entry["audit_source"],
            workflow_job_id="job-" + "1" * 32,
            environment_id=entry["environment_id"],
        )
    )
    reseal(value)
    with pytest.raises(S3AccessError, match="enrolled profile or runtime"):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize(
    "operation",
    ["inspect_policy", "probe_read", "legitimate_read", "apply_policy", "prepare_fixture"],
)
def test_expired_audit_source_refuses_new_business_without_extending_commitment(operation):
    value = audit_admitted(operation, source_seconds=5)
    value["now"] = NOW + timedelta(seconds=5)
    before = deepcopy(value["configuration"])
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)
    assert value["configuration"] == before


def test_business_admission_and_recheck_end_at_original_source_expiry():
    value = audit_admitted(source_seconds=5)
    admission = S3HostAdmission.issue(**value)
    assert admission.to_dict()["expires_at"] == "2026-10-09T00:00:05.000000Z"
    with pytest.raises(S3AccessError):
        admission.recheck(**{**value, "now": NOW + timedelta(seconds=5)})


@pytest.mark.parametrize("operation", ["probe_read", "cleanup_fixture"])
def test_recheck_rejects_source_change_instead_of_rebinding_original_commitment(operation):
    value = audit_admitted(operation)
    admission = S3HostAdmission.issue(**value)
    value["configuration"]["environments"][0]["audit_source"][
        "audit_bucket"
    ] = "bluefire-other-audit-fixture"
    with pytest.raises(S3AccessError):
        admission.recheck(**value)


@pytest.mark.parametrize(
    "operation", ["reconcile_policy", "rollback_policy", "reconcile_fixture", "cleanup_fixture"]
)
def test_expired_source_preserves_otherwise_authorized_recovery_with_original_deadlines(operation):
    value = audit_admitted(operation, source_seconds=5)
    value["now"] = NOW + timedelta(seconds=6)
    before = deepcopy(value["manifest"]["params"])
    admission = S3HostAdmission.issue(**value)
    admission.recheck(**value)
    assert (
        admission.to_dict()["host"]["audit_workflow"]["source"]["expires_at"]
        == "2026-10-09T00:00:05Z"
    )
    assert admission.to_dict()["expires_at"] == "2026-10-09T00:00:30.000000Z"
    assert value["manifest"]["params"] == before
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**{**value, "now": NOW + timedelta(seconds=30)})


@pytest.mark.parametrize(
    "operation", ["reconcile_policy", "rollback_policy", "reconcile_fixture", "cleanup_fixture"]
)
def test_audit_expiry_exception_does_not_authorize_a_different_review_phase(operation):
    value = audit_admitted(operation, source_seconds=5)
    value["now"] = NOW + timedelta(seconds=6)
    value["manifest"]["params"]["workflow_approval"]["phase"] = "baseline"
    reseal(value)
    with pytest.raises(S3AccessError):
        S3HostAdmission.issue(**value)


@pytest.mark.parametrize("operation", ["inspect_policy", "prepare_fixture"])
def test_historical_context_preserves_original_v3_digest_without_fresh_admission_or_clock(
    monkeypatch, operation
):
    value = audit_admitted(operation, source_seconds=5)
    request, context = original_context(value)
    before = deepcopy(context)

    def no_current_authority(*args, **kwargs):
        pytest.fail("historical validation must not acquire or renew current authority")

    monkeypatch.setattr(S3WorkerRequest, "assert_current", no_current_authority)
    monkeypatch.setattr(audit, "build_workflow", no_current_authority)
    assert validate_recovery_context(request, context) == before
    assert context == before
    assert (
        context["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"]
        == value["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"]
    )


def test_historical_v3_digest_change_cannot_preserve_original_manifest_or_task_identity():
    value = audit_admitted()
    request, context = original_context(value)
    context["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"] = (
        "sha256:" + "f" * 64
    )
    with pytest.raises(S3AccessError):
        validate_recovery_context(request, context)


@pytest.mark.parametrize("fixture_host", [False, True])
def test_legacy_admission_bytes_remain_exact_and_have_no_audit_fields(fixture_host):
    value = configured_fixture() if fixture_host else admitted_fixture()
    request = S3WorkerRequest.from_mapping(value["manifest"]["params"]["worker_request"])
    approval = value["manifest"]["params"]["workflow_approval"]
    entry = selected_environment(value["configuration"], request, approval, value["profile"])
    expected = {
        "schema_version": (
            "bluefire.s3-access-admission.v2" if fixture_host else "bluefire.s3-access-admission.v1"
        ),
        "issuer": value["issuer"],
        "manifest_digest": content_hash(value["manifest"]),
        "profile_digest": content_hash(value["profile"]),
        "request_digest": request.digest,
        "approval_digest": content_hash(approval),
        "host": {
            "environment_id": entry["environment_id"],
            "scope_digest": request.to_dict()["scope_digest"],
            "runtime_digest": entry["runtime_digest"],
            "worker_generation": entry["worker_generation"],
            "ledger_root": entry["ledger_root"],
            "runtime_root": entry["runtime_root"],
            "owner_uid": 1000,
            **({"fixture_lifecycle": entry["fixture_lifecycle"]} if fixture_host else {}),
        },
        "native_runner_digest": value["runner_digest"],
        "credential_digest": value["credential_digest"],
        "issued_at": "2026-10-09T00:00:00.000000Z",
        "expires_at": "2026-10-09T00:00:30.000000Z",
    }
    admission = S3HostAdmission.issue(**value)
    assert admission.canonical_bytes() == canonical_json_bytes(expected)
    admission.recheck(**value)
