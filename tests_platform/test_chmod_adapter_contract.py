"""Offline contract tests; no chmod, installation, or runner is invoked."""

from __future__ import annotations

from copy import deepcopy

import pytest

from bluefire.contracts import ContractError
from bluefire.tool_adapters import ToolAdapterContract, chmod


def test_contract_has_fixed_review_identity_and_digest() -> None:
    contract = chmod.contract()
    assert contract.to_dict()["adapter_id"] == chmod.ADAPTER_ID
    assert contract.to_dict()["tool_id"] == chmod.TOOL_ID
    assert contract.to_dict()["behavior_id"] == chmod.BEHAVIOR_ID
    assert contract.to_dict()["source"]["revision"] == "6132b92779873cb0d05bef07ba0a480d47eb1cc8"
    assert contract.to_dict()["source"]["content_digest"] == chmod.SOURCE_DIGEST
    assert contract.to_dict()["source"]["reference"].endswith("/atomics/T1222.002/T1222.002.yaml")
    assert contract.to_dict()["supervision"]["network"] == "none"
    assert contract.to_dict()["supervision"]["filesystem"] == "receipt-owned-workspace"
    assert contract.to_dict()["supervision"]["privilege"] == "current-user"
    assert contract.to_dict()["result"]["observation_schema"] == "observation.permission.mode.v1"
    assert contract.digest.startswith("sha256:")


def test_only_bounded_mode_choice_normalizes() -> None:
    assert chmod.normalize_parameters({"mode": "0660"})["mode"] == "0660"
    assert chmod.FIXED_ARGUMENTS == ("<mode>", "--", "/proc/self/fd/<held-file>")


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"source_fixture_id": "arbitrary-fixture", "mode": "0660"},
        {"source_sha256": "a" * 64, "mode": "0660"},
        {"source_receipt_id": "receipt-id", "mode": "0660"},
        {"mode": "0777"},
        {"mode": "0660", "path": "/etc/passwd"},
    ],
)
def test_parameters_refuse_missing_unreviewed_or_path_controls(values) -> None:
    with pytest.raises(ContractError):
        chmod.normalize_parameters(values)


def test_contract_snapshot_is_detached_and_unknown_metadata_is_rejected() -> None:
    document = chmod.contract().to_dict()
    original = deepcopy(document)
    document["parameters"][0]["enum"].append("0777")
    assert chmod.contract().to_dict() == original
    document["supervision"]["command"] = "chmod"
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("network", "loopback"),
        ("privilege", "root"),
        ("filesystem", "host-files"),
        ("cleanup_action_id", ""),
    ],
)
def test_supervision_cannot_claim_broader_authority(field: str, value: str) -> None:
    document = chmod.contract().to_dict()
    document["supervision"][field] = value
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)
