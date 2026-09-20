"""Contract fixtures are deliberately not installed-tool or execution evidence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from bluefire.contracts import ContractError
from bluefire.tool_adapters import ToolAdapterContract


@pytest.fixture
def document():
    return {
        "schema_version": "bluefire.tool-adapter.v1",
        "adapter_id": "adapter.example.v1",
        "adapter_version": "1.0.0",
        "tool_id": "tool.example.v1",
        "source": {
            "project": "Contract test fixture",
            "reference": "https://example.invalid/reviewed/1.0.0",
            "revision": "1.0.0",
            "content_digest": "sha256:" + "a" * 64,
            "license": "MIT",
        },
        "action_id": "example.action.v1",
        "action_version": "1.0.0",
        "behavior_id": "example.behavior.v1",
        "implementation_id": "example.implementation.v1",
        "implementation_version": "1.0.0",
        "compatibility": {
            "platforms": ["linux"],
            "architectures": ["x86_64"],
            "target_type": "owned_endpoint",
            "prerequisite_ids": ["example.installation.v1", "example.observer.v1"],
        },
        "parameters": [
            {
                "name": "variant",
                "type": "string",
                "enum": ["primary", "variation"],
                "required": True,
            },
            {"name": "count", "type": "integer", "minimum": 1, "maximum": 8, "default": 8},
            {"name": "redact", "type": "boolean", "default": True},
        ],
        "supervision": {
            "invocation_id": "example.fixed-invocation.v1",
            "installation_binding": "verified-version-and-digest",
            "network": "none",
            "privilege": "current-user",
            "working_directory": "private-adapter-workspace",
            "environment": "adapter-allowlist",
            "cancellation": "terminate-owned-process-tree",
            "filesystem": "receipt-owned-workspace",
            "cleanup_action_id": "sandbox.cleanup.v1",
        },
        "limits": {
            "timeout_ms": 5000,
            "max_input_bytes": 8192,
            "max_output_bytes": 8192,
            "max_diagnostic_bytes": 1024,
            "max_artifacts": 1,
            "max_artifact_bytes": 8192,
            "max_processes": 1,
            "max_attempts": 1,
        },
        "result": {
            "parser_id": "example.parser.v1",
            "artifact_types": ["artifact.example.v1"],
            "observation_schema": "observation.example.v1",
        },
    }


def test_canonical_snapshot_does_not_share_mutable_review_data(document):
    contract = ToolAdapterContract.from_mapping(document)
    reordered = dict(reversed(list(document.items())))
    assert ToolAdapterContract.from_mapping(reordered).digest == contract.digest
    original = deepcopy(document)
    document["limits"]["max_attempts"] = 2
    exported = contract.to_dict()
    exported["parameters"][0]["enum"].append("unreviewed")
    assert contract.to_dict() == original
    assert ToolAdapterContract.from_mapping(document).digest != contract.digest
    assert contract.validate_parameters({"variant": "primary"}) == {
        "variant": "primary",
        "count": 8,
        "redact": True,
    }


@pytest.mark.parametrize(
    "field", ["command", "script", "executable", "args", "module", "url", "target", "approval"]
)
@pytest.mark.parametrize(
    "section", [None, "source", "compatibility", "supervision", "limits", "result"]
)
def test_unknown_fields_cannot_expand_review_contract(document, section, field):
    target = document if section is None else document[section]
    target[field] = "unreviewed"
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"variant": "unreviewed"},
        {"variant": "primary", "count": True},
        {"variant": "primary", "count": 0},
        {"variant": "primary", "count": 9},
        {"variant": "primary", "count": 1.5},
        {"variant": "primary", "redact": "false"},
        {"variant": "primary", "executable": "tool"},
        {"variant": "primary", "target": "new"},
    ],
)
def test_request_has_only_typed_reviewed_values(document, values):
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document).validate_parameters(values)


@pytest.mark.parametrize(
    "limit",
    [
        "timeout_ms",
        "max_input_bytes",
        "max_output_bytes",
        "max_diagnostic_bytes",
        "max_artifacts",
        "max_artifact_bytes",
        "max_processes",
        "max_attempts",
    ],
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5, 2**63, "8", None])
def test_resource_limits_are_finite_positive_integers(document, limit, value):
    document["limits"][limit] = value
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("network", "any"),
        ("privilege", "root"),
        ("working_directory", "/tmp"),
        ("environment", "inherit"),
        ("installation_binding", "search-path"),
        ("cancellation", "leave-running"),
        ("filesystem", "host"),
        ("invocation_id", "python script.py"),
        ("cleanup_action_id", ""),
    ],
)
def test_v1_supervision_cannot_be_widened_by_metadata(document, field, value):
    document["supervision"][field] = value
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize(
    "spec",
    [
        {"name": "input", "type": "string"},
        {"name": "input", "type": "string", "enum": ["x" * 129]},
        {"name": "input", "type": "string_list"},
        {"name": "input", "type": "number"},
        {"name": "input", "type": "integer", "minimum": 0},
        {"name": "input", "type": "integer", "minimum": 0, "maximum": float("nan")},
        {"name": "input", "type": "integer", "minimum": 0, "maximum": float("inf")},
        {"name": "input", "type": "integer", "minimum": 0.5, "maximum": 8},
    ],
)
def test_parameter_schema_has_no_unbounded_or_nonfinite_inputs(document, spec):
    document["parameters"] = [spec]
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize(
    "reference", ["http://example.invalid", "file:///tool", "https://fixture@example.invalid"]
)
def test_source_identity_is_not_an_installation_url_or_credential_channel(document, reference):
    document["source"]["reference"] = reference
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bluefire.tool-adapter.v2"),
        ("adapter_id", "unversioned"),
        ("action_version", "latest"),
    ],
)
def test_identity_and_contract_versions_are_exact(document, field, value):
    document[field] = value
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


def test_missing_and_duplicate_contract_data_is_rejected(document):
    del document["limits"]["max_attempts"]
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


def test_declared_prerequisites_do_not_make_a_tool_installed_or_executable(document):
    contract = ToolAdapterContract.from_mapping(document)
    assert not hasattr(contract, "execute")
    assert not hasattr(contract, "install")
    assert "ready" not in contract.to_dict()
    assert "approval" not in contract.to_dict()


def test_extreme_numeric_bounds_remain_contract_errors(document):
    document["parameters"][1]["maximum"] = 10**400
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


@pytest.mark.parametrize("kind,choices", [("integer", list(range(33))), ("boolean", [True] * 33)])
def test_every_enum_has_a_per_field_limit(document, kind, choices):
    document["parameters"] = [
        {
            "name": "choice",
            "type": kind,
            "enum": choices,
            "minimum": 0,
            "maximum": 32,
        }
    ]
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)


def test_malformed_source_url_remains_a_contract_error(document):
    document["source"]["reference"] = "https://[invalid"
    with pytest.raises(ContractError):
        ToolAdapterContract.from_mapping(document)
