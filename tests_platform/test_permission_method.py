from __future__ import annotations

from typing import Any, Mapping

import pytest

from bluefire.contracts import SafetyTier
from bluefire.permission_method import existing_cleanup_receipts
from bluefire.planner import PlanStep
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError
from bluefire.tool_adapters.chmod import CONTRACT

RECEIPT = "a" * 64
SHA = "b" * 64


def _step(parameters: Mapping[str, Any] | None = None) -> PlanStep:
    return PlanStep(
        step_id="permission",
        behavior_id="sandbox.permission.relax.v1",
        action_id="sandbox.permission.chmod.v1",
        simulation_id="simulation.sandbox.permission.relax.v1",
        parameters=dict(parameters or {"mode": "0660"}),
        inputs={"fixture": {"from_step": "transform", "artifact": "fixture"}},
        expected_outputs=("fixture",),
        required_capabilities=("filesystem.read", "filesystem.write", "process.spawn"),
        safety_tier=SafetyTier.CONTROLLED,
        alternates=(),
    )


def _fixture(**overrides: Any) -> dict[str, Any]:
    value = {
        "type": "artifact.sandbox.fixture.v1",
        "path": "fixtures/transformed.jsonl",
        "sha256": SHA,
        "size": 17,
        "record_count": 6,
        "redact_values": True,
        "receipt_ids": [RECEIPT],
    }
    value.update(overrides)
    return value


def _output(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "artifact": "fixtures/transformed.jsonl",
        "sha256": SHA,
        "size": 17,
        "requested_mode": "0660",
        "before_mode": "0644",
        "after_mode": "0660",
        "tool": {
            "installation_digest": "sha256:" + "c" * 64,
            "adapter_contract_digest": CONTRACT.digest,
            "tool_version": "9.4",
        },
        "exit_code": 0,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    value.update(overrides)
    return value


def test_permission_adapter_binds_fixed_fixture_and_receipt() -> None:
    adapted = RunnerActionAdapter().adapt(
        _step(), bound_inputs={"fixture": _fixture()}, receipt_ids=(RECEIPT,)
    )
    assert adapted.params == {
        "source_fixture_id": "transformed",
        "source_sha256": SHA,
        "source_receipt_id": RECEIPT,
        "source_size": 17,
        "mode": "0660",
    }
    assert adapted.filesystem_scope == ("fixtures/transformed.jsonl",)
    assert adapted.observable_paths == ("fixtures/transformed.jsonl",)


def test_permission_adapter_carries_runner_owned_hash_and_size() -> None:
    other_sha = "c" * 64
    adapted = RunnerActionAdapter().adapt(
        _step(),
        bound_inputs={"fixture": _fixture(sha256=other_sha, size=2048)},
        receipt_ids=(RECEIPT,),
    )
    assert adapted.params["source_sha256"] == other_sha
    assert adapted.params["source_size"] == 2048


@pytest.mark.parametrize(
    "fixture, receipts",
    [
        ({"path": "fixtures/other.jsonl"}, (RECEIPT,)),
        (_fixture(receipt_ids=["c" * 64]), (RECEIPT,)),
        (_fixture(size=0), (RECEIPT,)),
        (_fixture(size=67 * 1024 * 1024), (RECEIPT,)),
        (_fixture(size=True), (RECEIPT,)),
        (_fixture(sha256="not-a-sha"), (RECEIPT,)),
        (_fixture(), ("c" * 64,)),
    ],
)
def test_permission_adapter_rejects_forged_bindings(
    fixture: Mapping[str, Any], receipts: tuple[str, ...]
) -> None:
    with pytest.raises(RunnerAdapterError):
        RunnerActionAdapter().adapt(
            _step(), bound_inputs={"fixture": fixture}, receipt_ids=receipts
        )


def test_permission_adapter_rejects_operator_binding_parameters() -> None:
    with pytest.raises(RunnerAdapterError, match="only the reviewed mode"):
        RunnerActionAdapter().adapt(
            _step({"mode": "0660", "source_sha256": SHA}),
            bound_inputs={"fixture": _fixture()},
            receipt_ids=(RECEIPT,),
        )


def test_permission_output_preserves_content_and_receipt() -> None:
    outputs = RunnerActionAdapter().logical_outputs(
        _step(),
        bound_inputs={"fixture": _fixture()},
        runner_output=_output(),
        receipt_ids=(RECEIPT,),
    )
    assert outputs["fixture"]["receipt_ids"] == [RECEIPT]
    assert outputs["fixture"]["sha256"] == SHA


@pytest.mark.parametrize("available", [(), ("c" * 64,), (RECEIPT, RECEIPT)])
def test_permission_output_requires_exact_single_existing_receipt(
    available: tuple[str, ...],
) -> None:
    with pytest.raises(RunnerAdapterError, match="exactly|available"):
        RunnerActionAdapter().logical_outputs(
            _step(),
            bound_inputs={"fixture": _fixture()},
            runner_output=_output(),
            receipt_ids=available,
        )


def test_existing_cleanup_receipt_binding_is_exact_and_metadata_only() -> None:
    params = {
        "source_fixture_id": "transformed",
        "source_sha256": SHA,
        "source_receipt_id": RECEIPT,
        "source_size": 17,
        "mode": "0660",
    }
    assert existing_cleanup_receipts("sandbox.permission.chmod.v1", params, (RECEIPT,)) == (
        RECEIPT,
    )
    with pytest.raises(RunnerAdapterError):
        existing_cleanup_receipts("sandbox.permission.chmod.v1", params, ())
    with pytest.raises(RunnerAdapterError):
        existing_cleanup_receipts(
            "sandbox.permission.chmod.v1", {**params, "unexpected": True}, (RECEIPT,)
        )
    assert existing_cleanup_receipts("sandbox.fixture.transform.v1", params, (RECEIPT,)) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("artifact", "fixtures/other.jsonl"),
        ("sha256", "c" * 64),
        ("size", 18),
        ("requested_mode", "0600"),
    ],
)
def test_permission_output_rejects_identity_mismatch(field: str, value: Any) -> None:
    with pytest.raises(RunnerAdapterError):
        RunnerActionAdapter().logical_outputs(
            _step(),
            bound_inputs={"fixture": _fixture()},
            runner_output=_output(**{field: value}),
            receipt_ids=(RECEIPT,),
        )
