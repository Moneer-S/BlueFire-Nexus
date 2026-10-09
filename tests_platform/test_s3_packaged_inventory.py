"""Reserved cloud descriptors do not widen ordinary packaged runner authority."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from bluefire.runner_bootstrap import (
    RunnerBootstrapError,
    bootstrap_runner,
    validate_runner_inventory,
)
from bluefire.runner_client import canonical_runner_inventory
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_IDS,
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RunnerInventoryAuthorityError,
    packaged_builtin_inventory,
    validate_builtin_action_inventory,
)
from tests_platform.test_runner_bootstrap import _fake_native, _inventory
from tools.stage_native_runner import stage_native_runner

RESERVED_ID = "owned.aws.s3_access.v1"


def inventory(platform: str) -> dict[str, Any]:
    value = copy.deepcopy(dict(_inventory(platform=platform)))
    value["actions"].append(
        {
            "schema_version": "bluefire.runner-action-sdk.v1",
            "action_id": RESERVED_ID,
            "action_version": "1.0.0",
            "readiness": "structural",
            "capabilities": ["cloud_aws_s3_access"],
            "platforms": ["linux"],
            "native_tool_binding": None,
        }
    )
    return value


def binary(tmp_path: Path, platform: str) -> Path:
    result = tmp_path / ("bluefire-runner.exe" if platform == "windows" else "bluefire-runner")
    result.write_bytes(_fake_native(platform))
    return result


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_reserved_descriptor_stages_bootstraps_and_preserves_siblings(
    tmp_path: Path, platform: str
) -> None:
    source = binary(tmp_path, platform)
    destination = tmp_path / "packaged"
    destination.mkdir()
    sibling = destination / "other-platform"
    sibling.mkdir()
    (sibling / "keep").write_bytes(b"preserve sibling bytes")
    raw = inventory(platform)
    original = copy.deepcopy(raw)
    manifest = stage_native_runner(
        source, destination, platform_name=platform, architecture="x86_64", inventory=raw
    )
    assert raw == original
    assert (sibling / "keep").read_bytes() == b"preserve sibling bytes"
    validate_runner_inventory(raw, manifest)
    result = bootstrap_runner(
        environ={},
        resource_root=destination,
        managed_root=tmp_path / "managed",
        platform_name=platform,
        architecture="x86_64",
        inventory_probe=lambda _binary: raw,
    )
    assert result.binary_path.read_bytes() == source.read_bytes()
    assert result.managed_binary is True
    assert RESERVED_ID not in BUILTIN_RUNNER_ACTION_IDS
    assert len(BUILTIN_RUNNER_ACTION_VERSIONS) == 26
    projected = packaged_builtin_inventory(raw)
    assert {row["action_id"] for row in projected["actions"]} == BUILTIN_RUNNER_ACTION_IDS


@pytest.mark.parametrize("platform", ["windows", "linux"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "other"),
        ("action_version", "2.0.0"),
        ("readiness", "ready"),
        ("readiness", "unavailable"),
        ("capabilities", ["network_loopback"]),
        ("capabilities", ["cloud_aws_s3_access", "network_loopback"]),
        ("platforms", ["windows"]),
        ("platforms", ["linux", "windows"]),
        ("native_tool_binding", {}),
    ],
)
def test_reserved_field_changes_refuse_before_publication(
    tmp_path: Path, platform: str, field: str, value: Any
) -> None:
    source = binary(tmp_path, platform)
    raw = inventory(platform)
    raw["actions"][-1][field] = value
    destination = tmp_path / "packaged"
    destination.mkdir()
    (destination / "unchanged").write_bytes(b"original")
    with pytest.raises(RunnerBootstrapError, match="invalid inventory"):
        stage_native_runner(
            source, destination, platform_name=platform, architecture="x86_64", inventory=raw
        )
    assert [(path.name, path.read_bytes()) for path in destination.iterdir()] == [
        ("unchanged", b"original")
    ]


@pytest.mark.parametrize("platform", ["windows", "linux"])
@pytest.mark.parametrize(
    "change", ["duplicate_reserved", "unknown", "shadow", "missing_ordinary", "canonical"]
)
def test_reserved_catalog_does_not_hide_other_authority_failures(
    tmp_path: Path, platform: str, change: str
) -> None:
    source = binary(tmp_path, platform)
    raw = inventory(platform)
    if change == "duplicate_reserved":
        raw["actions"].append(copy.deepcopy(raw["actions"][-1]))
    elif change == "unknown":
        raw["actions"][-1]["action_id"] = "unreviewed.cloud.v1"
    elif change == "shadow":
        raw["actions"][-1]["action_id"] = raw["actions"][0]["action_id"]
    elif change == "missing_ordinary":
        raw["actions"].pop(0)
    else:
        raw = copy.deepcopy(dict(canonical_runner_inventory(raw)))
    with pytest.raises(RunnerBootstrapError, match="invalid inventory"):
        stage_native_runner(
            source,
            tmp_path / "packaged",
            platform_name=platform,
            architecture="x86_64",
            inventory=raw,
        )


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_reserved_descriptor_is_never_ordinary_execution_authority(platform: str) -> None:
    raw = inventory(platform)
    for value in (raw, canonical_runner_inventory(raw)):
        with pytest.raises(RunnerInventoryAuthorityError, match="required runner action set"):
            validate_builtin_action_inventory(value, required_action_ids={RESERVED_ID})
    assert len(packaged_builtin_inventory(_inventory())["actions"]) == 26


@pytest.mark.parametrize("platform", ["windows", "linux"])
@pytest.mark.parametrize(
    "value", ["x" * (2 * 1024 * 1024), object()], ids=["oversized", "non_json"]
)
def test_uninspected_reserved_metadata_still_receives_complete_validation(
    tmp_path: Path, platform: str, value: Any
) -> None:
    source = binary(tmp_path, platform)
    raw = inventory(platform)
    raw["actions"][-1]["uninspected_metadata"] = value
    with pytest.raises(RunnerBootstrapError, match="invalid inventory"):
        stage_native_runner(
            source,
            tmp_path / "packaged",
            platform_name=platform,
            architecture="x86_64",
            inventory=raw,
        )
