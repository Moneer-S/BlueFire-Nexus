"""Independent exact-authority checks for retained-file admission; no runner executes."""

from copy import deepcopy

import pytest

from bluefire.product_store_errors import ProductStoreError
from bluefire.runner_contracts import seal_manifest, seal_profile
from tests_platform.test_file_access_control import claim, manifest_for
from tests_platform.test_file_access_control import operation as operation


@pytest.mark.parametrize("change", ["limits", "capabilities", "scope", "approval_policy"])
def test_resealed_profile_cannot_change_reviewed_base_policy(operation, change):
    prepared = deepcopy(operation.prepared)
    profile = prepared["profiles"]["retained"]
    if change == "limits":
        profile["limits"]["max_artifact_bytes"] += 1
    elif change == "capabilities":
        profile["capabilities"] = []
    elif change == "scope":
        profile["target_scope"]["filesystem"].append("unreviewed")
    else:
        profile["approval_required_at_or_above"] = None
    prepared["profiles"]["retained"] = seal_profile(profile)
    assert prepared["profiles"]["retained"] != operation.prepared["profiles"]["retained"]

    with pytest.raises((ProductStoreError, ValueError)):
        operation.store.prepare_file_access_operation(operation.job["job_id"], prepared)

    records = operation.store.file_access_operation_records(operation.job["job_id"])
    assert records["preparation"] is None
    assert records["tasks"] == []


@pytest.mark.parametrize(
    "change", ["behavior", "capabilities", "safety_tier", "cleanup", "extra_field"]
)
def test_resealed_manifest_cannot_change_fixed_native_fields(operation, change):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    manifest, profile = manifest_for(operation)
    if change == "behavior":
        manifest["behavior_id"] = "sandbox.fixture.transform.v1"
    elif change == "capabilities":
        manifest["required_capabilities"] = []
    elif change == "safety_tier":
        manifest["safety_tier"] = "elevated"
    elif change == "cleanup":
        manifest["cleanup_action_id"] = None
    else:
        manifest["unreviewed"] = "not part of the fixed native contract"

    with pytest.raises((ProductStoreError, ValueError)):
        claim(operation, seal_manifest(manifest), profile)

    assert operation.store.file_access_operation_records(operation.job["job_id"])["tasks"] == []


@pytest.mark.parametrize(
    "change", ["pre_approval", "future", "reversed", "extended", "approval_extra"]
)
def test_resealed_manifest_cannot_change_original_task_lifetime(operation, change):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    manifest, profile = manifest_for(operation)
    if change == "pre_approval":
        manifest["requested_at"] = "1970-01-01T00:00:00Z"
        manifest["expires_at"] = "1970-01-01T00:05:00Z"
    elif change == "future":
        manifest["requested_at"] = "1970-01-01T00:00:03Z"
        manifest["expires_at"] = "1970-01-01T00:05:03Z"
    elif change == "reversed":
        manifest["expires_at"] = "1970-01-01T00:00:01Z"
    elif change == "extended":
        manifest["expires_at"] = "1970-01-01T00:06:02Z"
    else:
        manifest["approval"]["unreviewed"] = "not part of the native approval contract"

    with pytest.raises((ProductStoreError, ValueError)):
        claim(operation, seal_manifest(manifest), profile)

    assert operation.store.file_access_operation_records(operation.job["job_id"])["tasks"] == []


def test_exact_native_lifetime_preserves_valid_admission(operation):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    manifest, profile = manifest_for(operation)
    task_id = claim(operation, manifest, profile)

    records = operation.store.file_access_operation_records(operation.job["job_id"])
    assert len(records["tasks"]) == 1
    assert records["tasks"][0]["task"]["task_id"] == task_id
    assert records["tasks"][0]["terminal"] is None
