"""Synthetic closed-contract tests for Windows harden admission and retest."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from bluefire import windows_file_access_correction_admission as correction
from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_pair_admission as pair
from bluefire.util import content_hash
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED

pytest_plugins = ("tests_platform.test_windows_file_access_pair_provenance",)


@pytest.fixture
def correction_case(paired):
    _, checked, _ = paired
    imported = pair.import_document(checked, now_ms=ISSUED + 1)
    record = imported["enrollment"]
    baseline = {
        "schema_version": "bluefire.windows-file-readable-baseline.v2",
        "non_owner": "allowed",
        "owner": "allowed",
        "size_bytes": record["resource"]["size_bytes"],
        "sha256": record["resource"]["sha256"],
        "resource_generation": record["generation"],
        "observed_at": datetime.fromtimestamp((ISSUED + 500) / 1000, timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "native_cleanup": "verified",
        "owned_job_cleanup": "verified",
        "independent_observation": False,
        "baseline_digest": content_hash({"synthetic": "complete-baseline"}),
    }
    control = {
        "schema_version": correction.CONTROL_SCHEMA,
        "control_owner_id": imported["control_owner_id"],
        "enrollment_id": imported["enrollment_id"],
        "generation": imported["generation"],
        "revision": 2,
        "status": "baseline_verified",
        "original_import_digest": content_hash(imported),
        "operation_job_id": "job-" + "1" * 32,
        "task_id": "synthetic-baseline-task",
        "transport_request_hash": content_hash({"synthetic": "transport"}),
        "resource": record["resource"],
        "baseline": baseline,
    }
    previous_descriptor = content_hash({"synthetic": "prior-descriptor"})
    context = correction.correction_context(imported, control, previous_descriptor)
    return {
        "checked": checked,
        "imported": imported,
        "control": control,
        "previous_descriptor": previous_descriptor,
        "context": context,
    }


def harden_original(case, *, review_expires_at_ms=None):
    imported, control, context = case["imported"], case["control"], case["context"]
    expires = review_expires_at_ms or ISSUED + 8000
    review_body = {
        "schema_version": "bluefire.file-access-control-review.v1",
        "operation": "harden",
        "control_owner_id": imported["control_owner_id"],
        "control_digest": content_hash(control),
        "context_digest": content_hash(context),
        "enrollment_digest": content_hash(imported["enrollment"]),
        "expires_at_ms": expires,
        "effect": "Synthetic reviewed harden and fresh paired retest",
    }
    review = {**review_body, "review_digest": content_hash(review_body)}
    submission_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    original = {
        "submitted_request": {
            "submission_id": submission_id,
            "review": {"operation": "harden", "control_owner_id": imported["control_owner_id"]},
            "review_digest": review["review_digest"],
            "reviewed_by": "synthetic-operator",
        },
        "review": review,
        "review_context": context,
        "enrollment_digest": content_hash(imported["enrollment"]),
        "created_at_ms": ISSUED + 1,
    }
    job_id = "job-" + submission_id.replace("-", "")
    return original, job_id


def prepared(case, *, review_expires_at_ms=None, issued_at_ms=ISSUED + 2):
    original, job_id = harden_original(case, review_expires_at_ms=review_expires_at_ms)
    value = correction.build_preparation(
        job_id,
        original,
        case["imported"],
        case["control"],
        issued_at_ms=issued_at_ms,
    )
    return original, value


@pytest.mark.timeout(10)
def test_correction_context_requires_complete_prior_allowed_reads_and_cleanup(correction_case):
    case = correction_case
    assert case["context"]["control_revision"] == 3
    assert case["context"]["target_resource"] == {
        **case["imported"]["enrollment"]["resource"],
        "state": "metadata_only",
    }
    assert (
        case["context"]["target_resource"]["owner_sid"] == case["control"]["resource"]["owner_sid"]
    )
    assert (
        case["context"]["target_resource"]["file_identity"]
        == case["control"]["resource"]["file_identity"]
    )

    mutations = (
        ("non_owner", "denied"),
        ("owner", "unknown"),
        ("native_cleanup", "unknown"),
        ("owned_job_cleanup", "failed"),
    )
    for key, value in mutations:
        control = deepcopy(case["control"])
        control["baseline"][key] = value
        with pytest.raises(wire.NativeWireError):
            correction.correction_context(case["imported"], control, case["previous_descriptor"])


@pytest.mark.timeout(10)
@pytest.mark.parametrize(
    "mutation",
    [
        "extra_key",
        "bool_revision",
        "bad_digest",
        "wrong_generation",
        "wrong_enrollment",
        "wrong_receipt",
        "changed_resource",
        "readable_target",
        "expired_parent",
    ],
)
def test_correction_binding_is_exact_and_bound_to_original_setup(correction_case, mutation):
    case = correction_case
    _, value = prepared(case)
    binding = deepcopy(value["binding"])
    if mutation == "extra_key":
        binding["extra"] = True
    elif mutation == "bool_revision":
        binding["control_revision"] = True
    elif mutation == "bad_digest":
        binding["prior_control_digest"] = "sha256:not-a-digest"
    elif mutation == "wrong_generation":
        binding["generation"] = "f" * 32
    elif mutation == "wrong_enrollment":
        binding["enrollment_digest"] = content_hash({"different": "setup"})
    elif mutation == "wrong_receipt":
        binding["protected_receipt_digest"] = content_hash({"different": "receipt"})
    elif mutation == "changed_resource":
        binding["target_resource"]["sha256"] = content_hash({"changed": "resource"})
    elif mutation == "readable_target":
        binding["target_resource"]["state"] = "readable"
    else:
        binding["expires_at_ms"] = case["imported"]["enrollment"]["expires_at_ms"] + 1
    with pytest.raises(wire.NativeWireError):
        correction.validate_correction_binding(binding, case["checked"])


@pytest.mark.timeout(10)
def test_harden_preparation_binds_exact_submission_control_and_context(correction_case):
    case = correction_case
    original, value = prepared(case)
    assert (
        correction.validate_retained_preparation(value, original, case["imported"], case["control"])
        == value
    )
    assert value["binding"]["prior_control_digest"] == content_hash(case["control"])
    assert value["binding"]["baseline_digest"] == case["control"]["baseline"]["baseline_digest"]
    assert value["binding"]["target_resource"] == case["context"]["target_resource"]

    mutations = []
    wrong_submission = deepcopy(original)
    wrong_submission["submitted_request"]["submission_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    mutations.append(wrong_submission)
    wrong_control = deepcopy(case["control"])
    wrong_control["revision"] = 3
    with pytest.raises(wire.NativeWireError):
        correction.build_preparation(
            value["job_id"], original, case["imported"], wrong_control, issued_at_ms=ISSUED + 2
        )
    for changed in mutations:
        with pytest.raises((wire.NativeWireError, ValueError)):
            correction.build_preparation(
                value["job_id"], changed, case["imported"], case["control"], issued_at_ms=ISSUED + 2
            )

    for field, replacement in (
        ("context_digest", content_hash({"wrong": "context"})),
        ("control_digest", content_hash({"wrong": "control"})),
        ("review_digest", content_hash({"wrong": "review"})),
    ):
        changed = deepcopy(original)
        changed["review"][field] = replacement
        with pytest.raises(wire.NativeWireError):
            correction.build_preparation(
                value["job_id"], changed, case["imported"], case["control"], issued_at_ms=ISSUED + 2
            )


@pytest.mark.timeout(10)
@pytest.mark.parametrize(
    ("review_expiry", "expected_expiry"),
    [(ISSUED + 7000, ISSUED + 7000), (ISSUED + 50000, ISSUED + 10002)],
)
def test_preparation_deadline_is_capped_by_review_and_original_ten_second_budget(
    correction_case, review_expiry, expected_expiry
):
    _, value = prepared(correction_case, review_expires_at_ms=review_expiry)
    assert value["expires_at_ms"] == expected_expiry
    assert value["expires_at_ms"] <= value["issued_at_ms"] + correction.OPERATION_MS
    assert value["expires_at_ms"] <= correction_case["imported"]["enrollment"]["expires_at_ms"]


@pytest.mark.timeout(10)
def test_retest_is_capped_at_five_seconds_and_cannot_renew_original_authority(correction_case):
    _, value = prepared(correction_case, review_expires_at_ms=ISSUED + 8000)
    five_second_original, _ = correction.build_retest_original(
        value["binding"],
        correction_case["checked"],
        issued_at_ms=ISSUED + 2000,
        reviewed_by="synthetic-operator",
    )
    assert five_second_original["manifest"]["expires_at"] == datetime.fromtimestamp(
        (ISSUED + 7000) / 1000, timezone.utc
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    original, expected = correction.build_retest_original(
        value["binding"],
        correction_case["checked"],
        issued_at_ms=ISSUED + 7000,
        reviewed_by="synthetic-operator",
    )
    assert original["manifest"]["expires_at"] == datetime.fromtimestamp(
        (ISSUED + 8000) / 1000, timezone.utc
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert expected["correction_binding_digest"] == content_hash(value["binding"])
    retest_expiry_ms = int(
        datetime.fromisoformat(
            original["manifest"]["expires_at"].replace("Z", "+00:00")
        ).timestamp()
        * 1000
    )
    assert retest_expiry_ms <= value["binding"]["expires_at_ms"]
    assert original["manifest"]["requested_at"] == datetime.fromtimestamp(
        (ISSUED + 7000) / 1000, timezone.utc
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with pytest.raises(wire.NativeWireError):
        correction.build_retest_original(
            value["binding"],
            correction_case["checked"],
            issued_at_ms=value["binding"]["expires_at_ms"],
            reviewed_by="synthetic-operator",
        )


@pytest.mark.timeout(10)
def test_correction_profile_keeps_original_profile_immutable_except_scoped_authority(
    correction_case,
):
    record, receipt = pair.checked_provenance(correction_case["checked"])
    original_profile = receipt["private_profile"]
    profile = correction.correction_profile(correction_case["checked"])
    changed = {"allowed_actions", "capabilities", "policy_digest"}
    assert {key for key in original_profile if original_profile[key] != profile[key]} == changed
    assert profile["allowed_actions"] == [wire._CORRECTION.action]
    assert profile["capabilities"] == [wire._CORRECTION.capability]
    assert profile["policy_digest"] == content_hash({**profile, "policy_digest": ""})
    original_host = record["host"]
    host = correction.correction_host(correction_case["checked"])
    assert {key for key in original_host if original_host[key] != host[key]} == {"profile_digest"}
    assert host["profile_digest"] == profile["policy_digest"]
