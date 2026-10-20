"""Pure sealed Darwin task provenance; no native runner or worker starts."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bluefire.config import load_config
from bluefire.contracts import ActionDefinition, SafetyTier, SourceProvenance
from bluefire.macos_file_access_method import CLOSE_ACTION, METHODS, PROBE_ACTION
from bluefire.runner_contracts import (
    RunnerContractError,
    VerifiedMacOSFileAccessBinding,
    VerifiedMacOSFileAccessCleanup,
    _verified_grant_attempt,
    _verified_macos_file_access_cleanup,
    build_execution_manifest,
    build_runner_profile,
    grant_attempt_authorization_digest,
    seal_manifest,
    seal_profile,
    verify_macos_file_access_binding,
)
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_IDS
from bluefire.runner_reviewed_execution import ReviewedExecutionError, reviewed_action_ids
from bluefire.util import content_hash
from tests_platform.test_macos_file_access_contract import binding


def original_binding():
    return {**binding(), "mode": "0600", "control_revision": 3}


def cleanup_claim():
    return {
        "schema_version": "bluefire.macos-file-access-artifact-closure-claim.v1",
        "attempt_id": "attempt-" + "1" * 32,
        "lease_digest": content_hash("lease"),
        "compiled_digest": content_hash("compiled"),
        "run_id": "run-1",
        "cleanup_step_id": "close",
        "issued_at_ms": 1500,
        "expires_at_ms": 11500,
        "issued_monotonic_ns": 1000,
        "deadline_ns": 10_000_001_000,
        "scope": "attempt_artifact_closure_only",
    }


def profile_document():
    return seal_profile(
        {
            "schema_version": "bluefire.runner-profile.v1",
            "profile_id": "original-macos.v1",
            "runner_id": "bluefire-macos-workspace.v1",
            "platform": "macos",
            "sandbox_root": "/private/var/empty/fake-attempt",
            "allowed_actions": sorted(METHODS),
            "control_blocked_actions": [],
            "target_scope": {"filesystem": [], "network": []},
            "limits": {"timeout_ms": 5000, "max_files": 8},
            "macos_file_access_binding": original_binding(),
            "reviewed_execution": {
                "schema_version": "bluefire.reviewed-execution.v1",
                "authorization_digest": grant_attempt_authorization_digest(
                    content_hash("compiled"), content_hash("plan")
                ),
                "operations": [
                    {
                        "step_id": step,
                        "behavior_id": action,
                        "action_id": action,
                        "execution_binding_digest": None,
                    }
                    for step, action in zip(("probe", "owner", "close"), METHODS, strict=True)
                ],
            },
            "policy_digest": "",
        }
    )


def action(action_id):
    return ActionDefinition(
        schema_version="bluefire.action.v1",
        id=action_id,
        title="Fixed Darwin method",
        purpose="Test exact original-workspace metadata contract",
        safety_tier=SafetyTier.CONTROLLED,
        capabilities=("cleanup",) if action_id == CLOSE_ACTION else ("filesystem.read",),
        platforms=("macos",),
        inputs=(),
        outputs=(),
        parameters=(),
        mutates=False,
        cleanup_action_id=None if action_id == CLOSE_ACTION else CLOSE_ACTION,
        provenance=SourceProvenance("test", "fake", "test", False),
    )


def build(action_id=CLOSE_ACTION, **overrides):
    profile = profile_document()
    step = "close" if action_id == CLOSE_ACTION else "probe"
    operation = next(
        row for row in profile["reviewed_execution"]["operations"] if row["step_id"] == step
    )
    kwargs = {
        "run_id": "run-1",
        "step_id": step,
        "behavior_id": action_id,
        "action": action(action_id),
        "runner_profile": profile,
        "params": {},
        "filesystem_scope": (),
        "approval_record": None,
        "reviewed_operation": {
            **operation,
            "authorization_digest": profile["reviewed_execution"]["authorization_digest"],
        },
        "resolved_cleanup_action_id": CLOSE_ACTION,
        "now": datetime.fromtimestamp(2, timezone.utc),
        "now_monotonic_ns": 1_000_001_000,
    }
    if action_id == CLOSE_ACTION:
        claim = cleanup_claim()
        kwargs["macos_file_access_cleanup"] = _verified_macos_file_access_cleanup(
            claim, expected_document_digest=content_hash(claim)
        )
    else:
        claim = {
            "schema_version": "bluefire.runner-grant-attempt.v1",
            "issuer": "capability-grant-controller.v1",
            "grant_id": "grant-" + "2" * 32,
            "grant_digest": content_hash("grant"),
            "attempt_id": "attempt-" + "1" * 32,
            "lease_digest": content_hash("lease"),
            "compiled_digest": content_hash("compiled"),
            "plan_digest": content_hash("plan"),
            "native_envelope_digest": content_hash(profile["reviewed_execution"]),
            "run_id": "run-1",
            "issued_at": "1970-01-01T00:00:01.500Z",
            "expires_at": "1970-01-01T00:00:07Z",
        }
        kwargs["grant_attempt"] = _verified_grant_attempt(
            claim, expected_document_digest=content_hash(claim)
        )
    kwargs.update(overrides)
    return build_execution_manifest(**kwargs)


def test_verified_binding_is_distinct_immutable_and_never_a_native_inventory_entry(tmp_path):
    original = original_binding()
    verified = verify_macos_file_access_binding(
        original,
        expected_document_digest=content_hash(original),
        now_ms=2000,
        now_monotonic_ns=1000,
    )
    original["mode"] = "0640"
    assert verified.to_dict()["mode"] == "0600"
    with pytest.raises(TypeError):
        VerifiedMacOSFileAccessBinding()
    with pytest.raises(AttributeError):
        verified._document = b"{}"
    config = load_config(Path(__file__).parents[1] / "config/bluefire.example.yaml")
    source = next(row for row in config.runner_profiles if row.id == "sandbox-execute.v1")
    source = replace(
        source, platforms=("macos",), enabled_actions=METHODS, native_tool_installations=()
    )
    profile = build_runner_profile(
        source,
        sandbox_root=tmp_path,
        platform="macos",
        filesystem_scope=(),
        reviewed_execution=profile_document()["reviewed_execution"],
        macos_file_access_binding=verified,
    )
    assert profile["runner_id"] == "bluefire-macos-workspace.v1"
    assert profile["macos_file_access_binding"] == verified.to_dict()
    assert profile["target_scope"] == {"filesystem": [], "network": []}
    assert reviewed_action_ids(profile) == set(METHODS)
    assert not set(METHODS).intersection(BUILTIN_RUNNER_ACTION_IDS)
    with pytest.raises(RunnerContractError):
        build_runner_profile(
            source, sandbox_root=tmp_path, platform="macos", macos_file_access_binding=original
        )


@pytest.mark.parametrize("change", ["digest", "wall", "monotonic", "mode"])
def test_binding_requires_exact_retained_digest_and_original_deadlines(change):
    original = original_binding()
    digest = content_hash(original)
    if change == "mode":
        original["mode"] = "0640"
        digest = content_hash(original)
    with pytest.raises(RunnerContractError):
        verify_macos_file_access_binding(
            original,
            expected_document_digest=content_hash("other") if change == "digest" else digest,
            now_ms=original["expires_at_ms"] if change == "wall" else 2000,
            now_monotonic_ns=original["original_deadline_ns"] if change == "monotonic" else 1000,
        )


@pytest.mark.parametrize(
    "change", ["platform", "runner", "linux", "scope", "native", "mixed", "no_binding"]
)
def test_macos_profile_cannot_widen_linux_native_or_filesystem_authority(change):
    profile = profile_document()
    if change == "platform":
        profile["platform"] = "linux"
    elif change == "runner":
        profile["runner_id"] = "bluefire-rust-runner.v1"
    elif change == "linux":
        profile["file_access_binding"] = {}
    elif change == "scope":
        profile["target_scope"]["filesystem"] = ["exports"]
    elif change == "native":
        profile["action_bindings"] = [{}]
    elif change == "mixed":
        profile["reviewed_execution"]["operations"][0]["action_id"] = "sandbox.fixture.create.v1"
    else:
        del profile["macos_file_access_binding"]
    with pytest.raises((RunnerContractError, ReviewedExecutionError)):
        seal_profile(profile)


def test_business_and_closure_manifests_use_distinct_original_mac_authorities():
    business, close = build(PROBE_ACTION), build()
    assert business["grant_attempt"]["request_hash"] == business["request_hash"]
    assert "macos_file_access_cleanup" not in business
    assert close["macos_file_access_cleanup"] == cleanup_claim()
    assert "request_hash" not in close["macos_file_access_cleanup"]
    assert close["cleanup_action_id"] == business["cleanup_action_id"] == CLOSE_ACTION
    assert close["params"] == {} and close["target_scope"] == {"filesystem": [], "network": []}
    assert "grant_attempt" not in close and "grant_cleanup" not in close
    assert seal_manifest(close) == close
    claim = cleanup_claim()
    verified = _verified_macos_file_access_cleanup(
        claim, expected_document_digest=content_hash(claim)
    )
    claim["scope"] = "whole_enrollment"
    assert verified.to_dict() == cleanup_claim()
    with pytest.raises(TypeError):
        VerifiedMacOSFileAccessCleanup()
    with pytest.raises(AttributeError):
        verified._document = b"{}"


@pytest.mark.parametrize(
    "change", ["wall", "monotonic", "missing_clock", "step", "scope", "params", "generic_cleanup"]
)
def test_close_requires_exact_claim_and_independently_unexpired_cleanup_time(change):
    overrides = {
        "wall": {"now": datetime.fromtimestamp(11.5, timezone.utc)},
        "monotonic": {"now_monotonic_ns": cleanup_claim()["deadline_ns"]},
        "missing_clock": {"now_monotonic_ns": None},
        "step": {"step_id": "other"},
        "scope": {"filesystem_scope": ("exports",)},
        "params": {"params": {"receipt_ids": []}},
        "generic_cleanup": {"resolved_cleanup_action_id": "sandbox.cleanup.v1"},
    }
    with pytest.raises(RunnerContractError):
        build(**overrides[change])


def test_closure_cannot_renew_expiry_or_accept_a_rehashed_generic_cleanup_claim():
    close = build()
    changed = deepcopy(close)
    changed["expires_at"] = "1970-01-01T00:00:12Z"
    with pytest.raises(RunnerContractError):
        seal_manifest(changed)
    changed = cleanup_claim()
    changed["schema_version"] = "bluefire.runner-grant-cleanup.v1"
    with pytest.raises(RunnerContractError):
        _verified_macos_file_access_cleanup(changed, expected_document_digest=content_hash(changed))
    with pytest.raises(RunnerContractError):
        _verified_macos_file_access_cleanup(
            cleanup_claim(), expected_document_digest=content_hash("other")
        )
