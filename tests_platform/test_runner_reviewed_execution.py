from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bluefire.registry import load_builtin_registry
from bluefire.runner_contracts import (
    RunnerContractError,
    build_execution_manifest,
    build_runner_profile,
    current_platform,
    seal_manifest,
    seal_profile,
)
from bluefire.util import content_hash
from tests_platform.test_provider_runner_contracts import _profile as provider_profile
from tests_platform.test_runner_contracts import _alias_action, _execute_profile, _execution_binding

DIGEST = "sha256:" + "a" * 64


def operation(
    action: str = "sandbox.fixture.create.v1",
    *,
    step: str = "first",
    behavior: str | None = None,
    binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "step_id": step,
        "behavior_id": behavior or action,
        "action_id": action,
        "execution_binding_digest": None if binding is None else content_hash(binding),
    }


def authority(*operations: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": DIGEST,
        "operations": list(operations) or [operation()],
    }


def reviewed_profile(tmp_path: Path, **kwargs: Any) -> dict[str, Any]:
    return build_runner_profile(
        _execute_profile(), sandbox_root=tmp_path / "sandbox", platform=current_platform(), **kwargs
    )


def manifest(
    profile: dict[str, Any], selected: dict[str, Any] | None, **kwargs: Any
) -> dict[str, Any]:
    return build_execution_manifest(
        run_id="run.reviewed.v1",
        step_id="first",
        behavior_id="sandbox.fixture.create.v1",
        action=load_builtin_registry().get_action("sandbox.fixture.create.v1"),
        runner_profile=profile,
        params={},
        filesystem_scope=("fixtures",),
        approval_record=None,
        reviewed_operation=selected,
        **kwargs,
    )


def test_profile_seals_all_reviewed_alternatives_and_cleanup_without_extra_authority(
    tmp_path: Path,
) -> None:
    approved = authority(
        operation(),
        operation("sandbox.collection.records.v1", step="second"),
        operation("sandbox.cleanup.v1", step="cleanup"),
    )
    profile = reviewed_profile(tmp_path, reviewed_execution=approved)
    assert profile["allowed_actions"] == sorted(
        item["action_id"] for item in approved["operations"]
    )
    assert profile["reviewed_execution"]["operations"] == sorted(
        approved["operations"], key=lambda item: item["step_id"]
    )
    changed = copy.deepcopy(profile)
    changed["reviewed_execution"]["authorization_digest"] = "sha256:" + "b" * 64
    assert seal_profile(changed)["policy_digest"] != profile["policy_digest"]
    assert seal_profile(profile)["policy_digest"] == profile["policy_digest"]


@pytest.mark.parametrize(
    "allowed",
    [
        [],
        ["sandbox.fixture.create.v1"] * 2,
        ["sandbox.fixture.create.v1", "sandbox.network.loopback.v1"],
    ],
)
def test_resealing_cannot_widen_or_drop_reviewed_action_allowlist(
    tmp_path: Path, allowed: list[str]
) -> None:
    profile = reviewed_profile(tmp_path, reviewed_execution=authority())
    profile["allowed_actions"] = allowed
    with pytest.raises(RunnerContractError, match="exactly cover"):
        seal_profile(profile)


@pytest.mark.parametrize("blocked", [False, True])
def test_compilation_refuses_disabled_or_blocked_reviewed_actions(
    tmp_path: Path, blocked: bool
) -> None:
    original = _execute_profile()
    configured = (
        replace(original, blocked_actions=("sandbox.fixture.create.v1",))
        if blocked
        else replace(original, enabled_actions=("sandbox.cleanup.v1",))
    )
    with pytest.raises(RunnerContractError, match="blocked|disabled"):
        build_runner_profile(
            configured,
            sandbox_root=tmp_path,
            platform=current_platform(),
            reviewed_execution=authority(),
        )


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {**authority(), "extra": True},
        {**authority(), "schema_version": "future"},
        {**authority(), "authorization_digest": "sha256:short"},
        authority({**operation(), "extra": True}),
        authority(
            {
                "step_id": "first",
                "action_id": "sandbox.fixture.create.v1",
                "behavior_id": "sandbox.fixture.create.v1",
            }
        ),
        authority({**operation(), "execution_binding_digest": False}),
        authority({**operation(), "step_id": "*"}),
        {**authority(), "operations": []},
        authority(operation(), operation()),
        authority(*(operation(step=f"step-{index}") for index in range(513))),
    ],
)
def test_present_reviewed_authority_is_strict(tmp_path: Path, bad: Any) -> None:
    profile = reviewed_profile(tmp_path)
    profile["reviewed_execution"] = bad
    with pytest.raises(RunnerContractError):
        seal_profile(profile)


def test_legacy_omission_does_not_grant_reviewed_authority(tmp_path: Path) -> None:
    profile = reviewed_profile(tmp_path)
    legacy = manifest(profile, None)
    assert "reviewed_execution" not in seal_profile(profile)
    assert "reviewed_operation" not in seal_manifest(legacy)
    with pytest.raises(RunnerContractError, match="legacy"):
        manifest(profile, {**operation(), "authorization_digest": DIGEST})


@pytest.mark.parametrize(
    "selected",
    [
        None,
        {},
        {**operation(), "authorization_digest": "sha256:" + "b" * 64},
        {**operation(), "authorization_digest": DIGEST, "step_id": "second"},
        {**operation(), "authorization_digest": DIGEST, "behavior_id": "changed.v1"},
        {**operation(), "authorization_digest": DIGEST, "action_id": "sandbox.cleanup.v1"},
        {
            **operation(),
            "authorization_digest": DIGEST,
            "execution_binding_digest": "sha256:" + "c" * 64,
        },
        {**operation(), "authorization_digest": DIGEST, "extra": "anything"},
    ],
)
def test_manifest_requires_exact_reviewed_identity(tmp_path: Path, selected: Any) -> None:
    with pytest.raises(RunnerContractError):
        manifest(reviewed_profile(tmp_path, reviewed_execution=authority()), selected)


def test_reviewed_manifest_hash_covers_authority_and_identity(tmp_path: Path) -> None:
    profile = reviewed_profile(tmp_path, reviewed_execution=authority())
    document = manifest(profile, {**operation(), "authorization_digest": DIGEST})
    assert document["reviewed_operation"]["execution_binding_digest"] is None
    changed = copy.deepcopy(document)
    changed["reviewed_operation"]["step_id"] = "second"
    assert seal_manifest(changed)["request_hash"] != document["request_hash"]
    for bad in (None, {**document["reviewed_operation"], "extra": True}):
        changed["reviewed_operation"] = bad
        with pytest.raises(RunnerContractError):
            seal_manifest(changed)


def test_native_alias_requires_reviewed_binding_and_does_not_authorize_direct_opcode(
    tmp_path: Path,
) -> None:
    binding = _execution_binding()
    action_id = str(binding["logical_action_id"])
    behavior = str(binding["logical_behavior_id"])
    opcode = str(binding["runner_opcode"])
    selected = operation(action_id, behavior=behavior, binding=binding)
    configured = replace(
        _execute_profile(), enabled_actions=(*_execute_profile().enabled_actions, action_id)
    )
    profile = build_runner_profile(
        configured,
        sandbox_root=tmp_path,
        platform=current_platform(),
        action_bindings=(binding,),
        reviewed_execution=authority(selected),
    )
    assert profile["allowed_actions"] == sorted([action_id, opcode])
    built = build_execution_manifest(
        run_id="run.reviewed.v1",
        step_id="first",
        behavior_id=behavior,
        action=_alias_action(action_id, opcode),
        runner_profile=profile,
        params={},
        filesystem_scope=(),
        approval_record=None,
        execution_binding=binding,
        reviewed_operation={**selected, "authorization_digest": DIGEST},
    )
    assert built["reviewed_operation"]["execution_binding_digest"] == content_hash(binding)
    with pytest.raises(RunnerContractError, match="outside reviewed"):
        build_execution_manifest(
            run_id="run.reviewed.v1",
            step_id="first",
            behavior_id=opcode,
            action=load_builtin_registry().get_action(opcode),
            runner_profile=profile,
            params={},
            filesystem_scope=(),
            approval_record=None,
            reviewed_operation={**operation(opcode), "authorization_digest": DIGEST},
        )
    changed = copy.deepcopy(profile)
    changed["reviewed_execution"]["operations"][0]["execution_binding_digest"] = None
    with pytest.raises(RunnerContractError, match="missing its execution binding"):
        seal_profile(changed)


def test_reviewed_provider_digest_binds_provider_wire_field_not_native_alias(
    tmp_path: Path,
) -> None:
    profile, action, binding = provider_profile(tmp_path)
    selected = operation(action.id, behavior=binding["logical_behavior_id"], binding=binding)
    profile["reviewed_execution"] = authority(selected)
    profile["allowed_actions"] = [action.id]
    profile = seal_profile(profile)
    built = build_execution_manifest(
        run_id="run.reviewed.v1",
        step_id="first",
        behavior_id=binding["logical_behavior_id"],
        action=action,
        runner_profile=profile,
        params={"label": "release"},
        filesystem_scope=(),
        approval_record=None,
        provider_binding=binding,
        reviewed_operation={**selected, "authorization_digest": DIGEST},
    )
    assert "execution_binding" not in built
    assert built["reviewed_operation"]["execution_binding_digest"] == content_hash(binding)
    profile["reviewed_execution"]["operations"][0]["execution_binding_digest"] = (
        "sha256:" + "d" * 64
    )
    with pytest.raises(RunnerContractError, match="binding differs"):
        seal_profile(profile)
