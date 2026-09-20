from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.config import ConfigError, RunnerProfile, load_config
from bluefire.native_tool_installations import SCHEMA, NativeToolInstallation
from bluefire.runner_contracts import build_runner_profile

ROOT = Path(__file__).resolve().parents[1]
NATIVE_ACTION = "sandbox.permission.chmod.v1"


def record(*, adapter_id: str = NATIVE_ACTION, platform: str = "linux") -> dict[str, object]:
    return {
        "schema_version": SCHEMA,
        "adapter_id": adapter_id,
        "adapter_version": "1.0.0",
        "adapter_contract_digest": "sha256:" + "a" * 64,
        "tool_id": "gnu.coreutils.chmod.v1",
        "tool_version": "9.5",
        "platform": platform,
        "architecture": "x86_64",
        "content_sha256": "sha256:" + "b" * 64,
        "size_bytes": 1234,
        "installation_location": "/usr/bin/chmod",
    }


def execute_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    profile = next(item for item in config.runner_profiles if item.mode.value == "execute")
    return replace(
        profile, platforms=("linux",), enabled_actions=(*profile.enabled_actions, NATIVE_ACTION)
    )


def profile_document(profile: RunnerProfile, tools: object = None) -> dict[str, object]:
    document = profile.to_dict()
    if tools is not None:
        document["native_tool_installations"] = tools
    return document


def test_profile_config_round_trip_is_immutable_and_legacy_shape_stays_absent() -> None:
    profile = execute_profile()
    legacy = RunnerProfile.from_mapping(profile.to_dict())
    assert "native_tool_installations" not in legacy.to_dict()
    empty = RunnerProfile.from_mapping(profile_document(profile, []))
    assert "native_tool_installations" not in empty.to_dict()

    source = profile_document(profile, [record()])
    parsed = RunnerProfile.from_mapping(source)
    source["native_tool_installations"][0]["tool_version"] = "changed"  # type: ignore[index]
    assert parsed.native_tool_installations[0].to_dict()["tool_version"] == "9.5"
    output = parsed.to_dict()
    output["native_tool_installations"][0]["tool_version"] = "changed"  # type: ignore[index]
    assert parsed.native_tool_installations[0].to_dict()["tool_version"] == "9.5"


@pytest.mark.parametrize(
    "field,value", [("native_tool_installations", None), ("native_tool_installations", {})]
)
def test_profile_config_rejects_non_list_installations(field: str, value: object) -> None:
    document = profile_document(execute_profile())
    document[field] = value
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(document)


def test_profile_config_rejects_simulate_duplicate_scope_platform_and_count() -> None:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    simulate = next(item for item in config.runner_profiles if item.mode.value == "simulate")
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(profile_document(simulate, [record()]))

    execute = execute_profile()
    duplicate = profile_document(execute, [record(), record()])
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(duplicate)

    outside_action = profile_document(execute, [record(adapter_id="sandbox.permission.other.v1")])
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(outside_action)

    outside_platform = profile_document(execute, [record(platform="windows")])
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(outside_platform)

    too_many = [record(adapter_id=f"sandbox.permission.chmod-{index}.v1") for index in range(17)]
    too_many_doc = profile_document(execute, too_many)
    too_many_doc["enabled_actions"] = [item["adapter_id"] for item in too_many]
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(too_many_doc)


def test_built_runner_profile_binds_identity_and_cleanup_projects_final_actions(
    tmp_path: Path,
) -> None:
    profile = execute_profile()
    installation = NativeToolInstallation.from_mapping(record())
    bound = replace(profile, native_tool_installations=(installation,))
    first = build_runner_profile(bound, sandbox_root=tmp_path / "sandbox", platform="linux")
    assert first["native_tool_installations"][0]["adapter_id"] == NATIVE_ACTION

    changed = replace(
        bound,
        native_tool_installations=(
            NativeToolInstallation.from_mapping({**record(), "tool_version": "9.6"}),
        ),
    )
    second = build_runner_profile(changed, sandbox_root=tmp_path / "sandbox", platform="linux")
    assert second["policy_digest"] != first["policy_digest"]

    cleanup = replace(bound, enabled_actions=("sandbox.cleanup.v1",))
    recovery = build_runner_profile(
        cleanup,
        sandbox_root=tmp_path / "sandbox",
        platform="linux",
        reviewed_execution={
            "schema_version": "bluefire.reviewed-execution.v1",
            "authorization_digest": "sha256:" + "c" * 64,
            "operations": [
                {
                    "step_id": "cleanup",
                    "behavior_id": "sandbox.cleanup.v1",
                    "action_id": "sandbox.cleanup.v1",
                    "execution_binding_digest": None,
                }
            ],
        },
    )
    assert "native_tool_installations" not in recovery


def test_invalid_profile_installation_surfaces_config_error() -> None:
    profile = execute_profile()
    document = profile_document(profile, [{**record(), "content_sha256": ""}])
    with pytest.raises(ConfigError):
        RunnerProfile.from_mapping(document)
