"""Offline gzip native-tool binding tests; no utility or runner is invoked."""

from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.contracts import ContractError
from bluefire.native_tool_candidate import SCHEMA, validate_candidate_inspection
from bluefire.native_tool_execution_readiness import (
    inspected_tool_rows,
    reviewed_native_tool_descriptor,
)
from bluefire.native_tool_installations import (
    CANDIDATE_SCHEMA,
    NativeToolInstallation,
)
from bluefire.native_tool_installations import SCHEMA as INSTALLATION_SCHEMA
from bluefire.service import BlueFireService
from bluefire.tool_adapters import chmod, gzip
from bluefire.tool_adapters.registry import known_adapter_ids
from bluefire.util import content_hash
from tests_platform.test_native_tool_approval_binding import configured_profile
from tests_platform.test_native_tool_inspection_transport import InspectingRunner

ROOT = Path(__file__).resolve().parents[1]


def candidate() -> dict[str, str]:
    return {
        "schema_version": CANDIDATE_SCHEMA,
        "action_id": gzip.ADAPTER_ID,
        "installation_location": "/opt/bluefire/gzip/bin/gzip",
        "tool_version": "1.13",
    }


def installation() -> NativeToolInstallation:
    return NativeToolInstallation.from_mapping(
        {
            "schema_version": INSTALLATION_SCHEMA,
            "adapter_id": gzip.ADAPTER_ID,
            "adapter_version": gzip.VERSION,
            "adapter_contract_digest": gzip.CONTRACT.digest,
            "tool_id": gzip.TOOL_ID,
            "tool_version": "1.13",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": "sha256:" + "b" * 64,
            "size_bytes": 1234,
            "installation_location": candidate()["installation_location"],
        }
    )


def result() -> dict[str, object]:
    value = installation()
    return {
        "schema_version": SCHEMA,
        "candidate_digest": content_hash(candidate()),
        "status": "ready",
        "code": "verified",
        "installation": value.to_dict(),
        "platform": "linux",
        "architecture": "x86_64",
    }


def _chmod_installation() -> NativeToolInstallation:
    return NativeToolInstallation.from_mapping(
        {
            "schema_version": INSTALLATION_SCHEMA,
            "adapter_id": chmod.ADAPTER_ID,
            "adapter_version": chmod.VERSION,
            "adapter_contract_digest": chmod.CONTRACT.digest,
            "tool_id": chmod.TOOL_ID,
            "tool_version": "9.5",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": "sha256:" + "c" * 64,
            "size_bytes": 1234,
            "installation_location": "/usr/bin/chmod",
        }
    )


def _descriptor(adapter_id: str, version: str, digest: str, tool_id: str) -> dict[str, object]:
    return {
        "schema_version": "bluefire.runner-action-sdk.v1",
        "action_id": adapter_id,
        "action_version": version,
        "readiness": "structural",
        "native_tool_binding": {
            "adapter_id": adapter_id,
            "adapter_version": version,
            "adapter_contract_digest": digest,
            "tool_id": tool_id,
        },
    }


def _inspection_result(value: NativeToolInstallation) -> dict[str, object]:
    record = value.to_dict()
    return {
        "schema_version": "bluefire.native-tool-inspection.v1",
        "installation_digest": value.digest,
        "status": "ready",
        "code": "verified",
        "content_sha256": record["content_sha256"],
        "size_bytes": record["size_bytes"],
        "platform": record["platform"],
        "architecture": record["architecture"],
    }


def test_gzip_contract_is_closed_and_bounds_parameters() -> None:
    assert gzip.contract().to_dict()["adapter_id"] == gzip.ADAPTER_ID
    assert gzip.contract().to_dict()["source"]["content_digest"] == gzip.SOURCE_DIGEST
    assert (
        gzip.contract().to_dict()["source"]["revision"]
        == "388942adbd9641f4dfdcf079d7efe9a75ec0ac43"
    )
    assert (
        gzip.normalize_parameters({"stage_variant": "heldout", "max_collection_bytes": 1})[
            "stage_variant"
        ]
        == "heldout"
    )
    for values in (
        {"stage_variant": "other", "max_collection_bytes": 1},
        {"stage_variant": "primary", "max_collection_bytes": 1_048_577},
        {"stage_variant": "primary", "max_collection_bytes": True},
        {"stage_variant": "primary", "max_collection_bytes": 1, "path": "/tmp/x"},
    ):
        with pytest.raises(ContractError):
            gzip.normalize_parameters(values)


def test_registry_is_closed_to_only_reviewed_external_adapters() -> None:
    assert known_adapter_ids() == frozenset({gzip.ADAPTER_ID, "sandbox.permission.chmod.v1"})
    with pytest.raises(ContractError):
        from bluefire.tool_adapters.registry import adapter_for

        adapter_for("gnu.unreviewed.v1")


def test_gzip_candidate_and_installation_bind_exact_contract() -> None:
    assert (
        validate_candidate_inspection(candidate(), result())["installation"]["tool_id"]
        == gzip.TOOL_ID
    )
    tampered = result()
    tampered["installation"] = {
        **tampered["installation"],
        "adapter_contract_digest": "sha256:" + "c" * 64,
    }
    with pytest.raises(ContractError):
        validate_candidate_inspection(candidate(), tampered)


def test_gzip_compiled_descriptor_requires_exact_digest_and_unknown_action_refuses() -> None:
    descriptor = {
        "schema_version": "bluefire.runner-action-sdk.v1",
        "action_id": gzip.ADAPTER_ID,
        "action_version": gzip.VERSION,
        "readiness": "structural",
        "native_tool_binding": {
            "adapter_id": gzip.ADAPTER_ID,
            "adapter_version": gzip.VERSION,
            "adapter_contract_digest": gzip.CONTRACT.digest,
            "tool_id": gzip.TOOL_ID,
        },
    }
    canonical = [
        {
            "action_id": gzip.ADAPTER_ID,
            "action_version": gzip.VERSION,
            "readiness": "structural",
            "contract_digest": content_hash(descriptor),
        }
    ]
    found, row = reviewed_native_tool_descriptor(
        {"platform": "linux", "actions": [descriptor]}, canonical, action_id=gzip.ADAPTER_ID
    )
    assert found == descriptor and row == canonical[0]
    with pytest.raises(ContractError):
        reviewed_native_tool_descriptor(
            {"platform": "linux", "actions": [descriptor]},
            canonical,
            action_id="sandbox.unknown.v1",
        )


@pytest.mark.parametrize("change", [{"action_version": "1.0.0"}, {"native_tool_binding": None}])
def test_legacy_or_unbound_gzip_inventory_cannot_become_structurally_ready(change) -> None:
    descriptor = {
        "schema_version": "bluefire.runner-action-sdk.v1",
        "action_id": gzip.ADAPTER_ID,
        "action_version": gzip.VERSION,
        "readiness": "structural",
        "native_tool_binding": {
            "adapter_id": gzip.ADAPTER_ID,
            "adapter_version": gzip.VERSION,
            "adapter_contract_digest": gzip.CONTRACT.digest,
            "tool_id": gzip.TOOL_ID,
        },
    }
    descriptor.update(change)
    canonical = [
        {
            "action_id": gzip.ADAPTER_ID,
            "action_version": descriptor["action_version"],
            "readiness": "structural",
            "contract_digest": content_hash(descriptor),
        }
    ]
    with pytest.raises(ContractError):
        reviewed_native_tool_descriptor(
            {"platform": "linux", "actions": [descriptor]}, canonical, action_id=gzip.ADAPTER_ID
        )


def test_inspected_tool_rows_keeps_distinct_chmod_and_gzip_bindings() -> None:
    chmod_value = _chmod_installation()
    gzip_value = installation()
    descriptors = [
        _descriptor(chmod.ADAPTER_ID, chmod.VERSION, chmod.CONTRACT.digest, chmod.TOOL_ID),
        _descriptor(gzip.ADAPTER_ID, gzip.VERSION, gzip.CONTRACT.digest, gzip.TOOL_ID),
    ]
    canonical = [
        {
            "action_id": item["action_id"],
            "action_version": item["action_version"],
            "readiness": item["readiness"],
            "contract_digest": content_hash(item),
        }
        for item in descriptors
    ]

    class Runner:
        def inspect_native_tool(self, record: dict[str, object]) -> dict[str, object]:
            value = chmod_value if record["adapter_id"] == chmod.ADAPTER_ID else gzip_value
            return _inspection_result(value)

    rows = inspected_tool_rows(
        Runner(),
        [chmod_value, gzip_value],
        {"platform": "linux", "actions": descriptors},
        canonical,
    )
    assert set(rows) == {chmod.ADAPTER_ID, gzip.ADAPTER_ID}
    assert (
        rows[chmod.ADAPTER_ID]["native_tool_installation_digest"]
        != rows[gzip.ADAPTER_ID]["native_tool_installation_digest"]
    )
    assert rows[chmod.ADAPTER_ID]["contract_digest"] != rows[gzip.ADAPTER_ID]["contract_digest"]


def test_inspected_tool_rows_rejects_second_failure_without_partial_ready_map() -> None:
    chmod_value = _chmod_installation()
    gzip_value = installation()
    descriptors = [
        _descriptor(chmod.ADAPTER_ID, chmod.VERSION, chmod.CONTRACT.digest, chmod.TOOL_ID),
        _descriptor(gzip.ADAPTER_ID, gzip.VERSION, gzip.CONTRACT.digest, gzip.TOOL_ID),
    ]
    canonical = [
        {
            "action_id": item["action_id"],
            "action_version": item["action_version"],
            "readiness": item["readiness"],
            "contract_digest": content_hash(item),
        }
        for item in descriptors
    ]

    class Runner:
        calls = 0

        def inspect_native_tool(self, record: dict[str, object]) -> dict[str, object]:
            self.calls += 1
            if self.calls == 2:
                return {"status": "unavailable", "code": "inspection_unavailable"}
            return _inspection_result(chmod_value)

    runner = Runner()
    with pytest.raises(ContractError):
        inspected_tool_rows(
            runner,
            [chmod_value, gzip_value],
            {"platform": "linux", "actions": descriptors},
            canonical,
        )
    assert runner.calls == 2


def test_gzip_candidate_setup_uses_normal_bluefire_service(tmp_path) -> None:
    class Runner(InspectingRunner):
        def inventory(self):
            value = dict(super().inventory())
            value["actions"] = [
                item for item in value["actions"] if item["action_id"] != gzip.ADAPTER_ID
            ] + [_descriptor(gzip.ADAPTER_ID, gzip.VERSION, gzip.CONTRACT.digest, gzip.TOOL_ID)]
            return value

        def inspect_native_tool_candidate(self, request: dict[str, str]) -> dict[str, object]:
            assert request == candidate()
            self.inspect_calls += 1
            return result()

    runner = Runner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, tmp_path / "workspace"),
    )
    document = configured_profile().to_dict()
    document["id"] = "draft.gzip-unenrolled.v1"
    document["platforms"] = ["linux"]
    document["enabled_actions"].append(gzip.ADAPTER_ID)
    document["native_tool_installations"] = []
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    try:
        before = service.product_store.get_resource("runner_profile", document["id"])
        assert service.inspect_runner_profile_tool(document["id"], candidate()) == result()
        assert runner.inspect_calls == 1
        assert runner.execute_calls == 0
        assert service.product_store.get_resource("runner_profile", document["id"]) == before
        assert service.store.list_runs() == []
    finally:
        service.close()


def test_compiled_gzip_binding_matches_python_contract_digest_and_version() -> None:
    source = (ROOT / "runner" / "src" / "atomic_gzip.rs").read_text(encoding="utf-8")
    assert 'adapter_version: "1.1.0"' in source
    assert f'adapter_contract_digest:\n        "{gzip.CONTRACT.digest}"' in source
