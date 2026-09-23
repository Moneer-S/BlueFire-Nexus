from __future__ import annotations

from typing import Any, Mapping

import pytest

from bluefire.contracts import ContractError
from bluefire.native_tool_execution_readiness import inspected_tool_rows
from bluefire.native_tool_installations import SCHEMA, NativeToolInstallation
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RunnerInventoryAuthorityError,
    validate_builtin_action_inventory,
)
from bluefire.tool_adapters.chmod import ADAPTER_ID, CONTRACT, TOOL_ID, VERSION
from bluefire.util import content_hash


def record() -> NativeToolInstallation:
    return NativeToolInstallation.from_mapping(
        {
            "schema_version": SCHEMA,
            "adapter_id": ADAPTER_ID,
            "adapter_version": VERSION,
            "adapter_contract_digest": CONTRACT.digest,
            "tool_id": TOOL_ID,
            "tool_version": "9.5",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": "sha256:" + "b" * 64,
            "size_bytes": 1234,
            "installation_location": "/usr/bin/chmod",
        }
    )


def inventory() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    descriptor = {
        "schema_version": "bluefire.runner-action-sdk.v1",
        "action_id": ADAPTER_ID,
        "action_version": VERSION,
        "readiness": "structural",
        "native_tool_binding": {
            "adapter_id": ADAPTER_ID,
            "adapter_version": VERSION,
            "adapter_contract_digest": CONTRACT.digest,
            "tool_id": TOOL_ID,
        },
    }
    return {"platform": "linux", "actions": [descriptor]}, [
        {
            "action_id": ADAPTER_ID,
            "action_version": VERSION,
            "readiness": "structural",
            "contract_digest": content_hash(descriptor),
        }
    ]


class VerifiedInspector:
    def __init__(self, value: NativeToolInstallation) -> None:
        self.value = value
        self.calls = 0

    def inspect_native_tool(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        assert value == self.value.to_dict()
        return {
            "schema_version": "bluefire.native-tool-inspection.v1",
            "installation_digest": self.value.digest,
            "status": "ready",
            "code": "verified",
            "content_sha256": self.value.to_dict()["content_sha256"],
            "size_bytes": self.value.to_dict()["size_bytes"],
            "platform": "linux",
            "architecture": "x86_64",
        }


def test_verified_binding_overrides_structural_row() -> None:
    value = record()
    raw, canonical = inventory()
    runner = VerifiedInspector(value)
    rows = inspected_tool_rows(runner, [value], raw, canonical)
    assert rows[ADAPTER_ID]["readiness"] == "ready"
    assert rows[ADAPTER_ID]["native_tool_installation_digest"] == value.digest
    assert rows[ADAPTER_ID]["tool_inspection"]["code"] == "verified"
    assert runner.calls == 1


def test_no_installations_never_calls_inspector() -> None:
    runner = VerifiedInspector(record())
    assert inspected_tool_rows(runner, [], {"platform": "windows"}, []) == {}
    assert runner.calls == 0


@pytest.mark.parametrize(
    "change,message",
    [
        (lambda raw, canonical: raw.update(platform="windows"), "platform"),
        (
            lambda raw, canonical: raw["actions"][0]["native_tool_binding"].update(
                tool_id="bad.v1"
            ),
            "binding",
        ),
        (lambda raw, canonical: raw["actions"][0].update(action_version="9.9.9"), "version"),
        (lambda raw, canonical: canonical.clear(), "canonical"),
    ],
)
def test_corrupted_inventory_or_binding_refuses(change, message: str) -> None:
    value = record()
    raw, canonical = inventory()
    change(raw, canonical)
    with pytest.raises(ContractError, match=message):
        inspected_tool_rows(VerifiedInspector(value), [value], raw, canonical)


def test_duplicate_records_are_rejected_before_inspection() -> None:
    value = record()
    raw, canonical = inventory()
    runner = VerifiedInspector(value)
    with pytest.raises(ContractError, match="duplicated"):
        inspected_tool_rows(runner, [value, value], raw, canonical)
    assert runner.calls == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw, canonical: canonical[0].update(contract_digest="sha256:" + "e" * 64),
        lambda raw, canonical: canonical[0].update(readiness="ready"),
        lambda raw, canonical: raw["actions"][0].update(readiness=[]),
        lambda raw, canonical: canonical[0].update(readiness=[]),
    ],
)
def test_canonical_and_raw_rows_must_match(mutate) -> None:
    value = record()
    raw, canonical = inventory()
    mutate(raw, canonical)
    with pytest.raises(ContractError):
        inspected_tool_rows(VerifiedInspector(value), [value], raw, canonical)


@pytest.mark.parametrize(
    "inspection",
    [
        {},
        {"status": "unavailable", "code": "inspection_unavailable"},
        {"status": "ready", "code": "binding_mismatch"},
    ],
)
def test_malformed_or_unverified_inspection_refuses(inspection: dict[str, object]) -> None:
    value = record()
    raw, canonical = inventory()

    class BadInspector(VerifiedInspector):
        def inspect_native_tool(self, _value: Mapping[str, Any]) -> Mapping[str, Any]:
            if not inspection:
                return {}
            base = super().inspect_native_tool(_value)
            base.update(inspection)
            return base

    with pytest.raises(ContractError, match="inspection"):
        inspected_tool_rows(BadInspector(value), [value], raw, canonical)


def test_inspection_exception_is_sanitized() -> None:
    value = record()
    raw, canonical = inventory()

    class FailingInspector:
        def inspect_native_tool(self, _value: Mapping[str, Any]) -> Mapping[str, Any]:
            raise OSError("/private/host/path leaked")

    with pytest.raises(ContractError) as caught:
        inspected_tool_rows(FailingInspector(), [value], raw, canonical)
    assert str(caught.value) == "native tool execution readiness: native tool inspection failed"


def test_inventory_validator_keeps_ready_actions_and_requires_known_chmod_exception() -> None:
    raw, _canonical = inventory()
    raw.update(
        {
            "schema_version": "bluefire.runner-inventory.v1",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": "0.1.0",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        }
    )
    raw["actions"].append(
        {
            "schema_version": "bluefire.runner-action-sdk.v1",
            "action_id": "sandbox.fixture.create.v1",
            "action_version": BUILTIN_RUNNER_ACTION_VERSIONS["sandbox.fixture.create.v1"],
            "readiness": "ready",
        }
    )
    with pytest.raises(RunnerInventoryAuthorityError):
        validate_builtin_action_inventory(raw, required_action_ids={ADAPTER_ID})
    checked = validate_builtin_action_inventory(
        raw,
        required_action_ids={ADAPTER_ID, "sandbox.fixture.create.v1"},
        structural_tool_action_ids={ADAPTER_ID},
    )
    assert checked["sandbox.fixture.create.v1"]["readiness"] == "ready"
    with pytest.raises(RunnerInventoryAuthorityError):
        validate_builtin_action_inventory(
            raw,
            required_action_ids={ADAPTER_ID},
            structural_tool_action_ids={"sandbox.arbitrary.v1"},
        )


def test_changed_record_or_unverified_inspection_refuses() -> None:
    value = record()
    raw, canonical = inventory()
    changed = NativeToolInstallation.from_mapping(
        {**value.to_dict(), "adapter_contract_digest": "sha256:" + "d" * 64}
    )
    with pytest.raises(ContractError, match="binding"):
        inspected_tool_rows(VerifiedInspector(value), [changed], raw, canonical)

    class MissingInspector:
        pass

    with pytest.raises(ContractError, match="unavailable"):
        inspected_tool_rows(MissingInspector(), [value], raw, canonical)
