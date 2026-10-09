"""Boundary compatibility and reviewed tool projection without native effects."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire import domain_errors, execution_contracts, runner_client, runner_contracts
from bluefire.file_access_preparation import validate_preparation
from bluefire.native_tool_installations import NativeToolInstallation
from bluefire.product_store_errors import ProductStoreError
from bluefire.runner_contracts import build_runner_profile, seal_profile
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.util import content_hash
from tests_platform.test_file_access_control import operation as operation
from tests_platform.test_native_tool_installations import record


def test_neutral_error_and_transport_identity_exports_preserve_type_identity():
    assert ProductStoreError is domain_errors.ProductStoreError
    assert RunnerTransportError is domain_errors.RunnerTransportError
    assert runner_client.execution_task_identity is execution_contracts.execution_task_identity
    with pytest.raises(RunnerTransportError):
        runner_client.reject_forbidden_execution_keys({"command": "not authorized"})


@pytest.fixture
def configured_preparation(operation, monkeypatch):
    chmod = record()
    unrelated = {**chmod, "adapter_id": "sandbox.archive.tar.v1", "tool_id": "gnu.tar.v1"}
    base = replace(
        operation.profile,
        native_tool_installations=tuple(
            NativeToolInstallation.from_mapping(item) for item in (chmod, unrelated)
        ),
    )
    prepared = deepcopy(operation.prepared)
    prepared["profile_document"] = base.to_dict()
    context = {**operation.context, "profile_digest": content_hash(base.to_dict())}
    review_body = {
        **{key: value for key, value in operation.review.items() if key != "review_digest"},
        "context_digest": content_hash(context),
    }
    review = {**review_body, "review_digest": content_hash(review_body)}
    prepared["context_digest"] = review["context_digest"]
    envelope = {
        **prepared["profiles"]["retained"]["reviewed_execution"],
        "authorization_digest": review["review_digest"],
    }
    selected = replace(
        base, enabled_actions=tuple(sorted({row["action_id"] for row in prepared["recipe"]}))
    )
    prepared["profiles"]["retained"] = build_runner_profile(
        selected,
        sandbox_root=prepared["roots"]["retained"],
        filesystem_scope=prepared["profiles"]["retained"]["target_scope"]["filesystem"],
        platform="linux",
        reviewed_execution=envelope,
    )
    assert prepared["profiles"]["retained"]["native_tool_installations"] == [chmod]
    original = {
        "review": review,
        "review_context": context,
        "enrollment_digest": operation.context["enrollment_digest"],
        "submitted_request": operation.request,
    }
    monkeypatch.setattr(runner_contracts, "current_platform", lambda: "linux")
    monkeypatch.setattr(
        Path, "mkdir", lambda *args, **kwargs: pytest.fail("admission wrote a directory")
    )
    return prepared, original, operation.enrollment, unrelated


def test_configured_chmod_identity_is_preserved_by_pure_preparation(configured_preparation):
    prepared, original, enrollment, _ = configured_preparation
    validate_preparation(prepared, original, enrollment, None)


@pytest.mark.parametrize("change", ["missing", "substituted", "unrelated"])
def test_resealed_tool_changes_cannot_escape_reviewed_projection(configured_preparation, change):
    prepared, original, enrollment, unrelated = configured_preparation
    profile = prepared["profiles"]["retained"]
    if change == "missing":
        profile.pop("native_tool_installations")
    elif change == "substituted":
        profile["native_tool_installations"][0]["content_sha256"] = "sha256:" + "c" * 64
    else:
        profile["native_tool_installations"].append(unrelated)
    with pytest.raises(ValueError):
        prepared["profiles"]["retained"] = seal_profile(profile)
        validate_preparation(prepared, original, enrollment, None)
