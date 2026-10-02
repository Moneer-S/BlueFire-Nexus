"""Inventory-only parity for real packaged bytes; no native action is dispatched."""

import hashlib
import json
import platform
import shutil
from pathlib import Path

import pytest

from bluefire.runner_bootstrap import (
    current_platform,
    load_runner_manifest,
    validate_runner_inventory,
)
from bluefire.runner_client import SubprocessRustRunner
from bluefire.tool_adapters.registry import adapter_for, known_adapter_ids

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = [
    ("windows", "bluefire/native/bluefire-runner.exe", "bluefire/native/runner-manifest.json"),
    (
        "linux",
        "bluefire/native/linux-x86_64/bluefire-runner",
        "bluefire/native/linux-x86_64/runner-manifest.json",
    ),
]


def expectations():
    data = json.loads(
        (ROOT / "tests_platform/fixtures/native_tool_descriptors_v1.json").read_text()
    )
    assert data["schema_version"] == "bluefire.native-tool-descriptor-expectations.v1"
    rows = {row["action_id"]: row for row in data["actions"]}
    assert len(data["actions"]) == len(rows) == 2
    assert set(rows) == known_adapter_ids()
    for action_id, row in rows.items():
        spec = adapter_for(action_id)
        assert row["action_version"] == spec.VERSION
        assert row["readiness"] == "structural"
        assert row["native_tool_binding"] == {
            "adapter_id": action_id,
            "adapter_version": spec.VERSION,
            "adapter_contract_digest": spec.CONTRACT.digest,
            "tool_id": spec.TOOL_ID,
        }
    return rows


def test_descriptor_expectations_match_current_python_tool_contracts():
    expectations()


@pytest.mark.parametrize("target,binary_path,manifest_path", ARTIFACTS)
def test_committed_host_native_inventory_matches_full_tool_descriptors(
    tmp_path, target, binary_path, manifest_path
):
    if current_platform() != target or platform.machine().lower() not in {"amd64", "x86_64"}:
        pytest.skip("committed artifact is not executable on this host platform/architecture")
    source = ROOT / binary_path
    manifest = load_runner_manifest(
        resource_root=(ROOT / manifest_path).parent, platform_name=target, architecture="x86_64"
    )
    payload = source.read_bytes()
    assert len(payload) == manifest.size
    assert hashlib.sha256(payload).hexdigest() == manifest.sha256
    # Execute only a byte-identical private copy; do not change checkout permissions.
    binary = tmp_path / source.name
    shutil.copyfile(source, binary)
    binary.chmod(0o700)
    runner = SubprocessRustRunner(binary, tmp_path / "transport", timeout_seconds=30.0)
    inventory = runner.inventory()
    validate_runner_inventory(inventory, manifest)
    rows = {row["action_id"]: row for row in inventory["actions"]}
    for action_id, expected in expectations().items():
        assert rows[action_id] == expected
