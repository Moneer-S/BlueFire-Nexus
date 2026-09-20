from __future__ import annotations

import pytest

from bluefire.contracts import ContractError
from bluefire.native_tool_installations import SCHEMA, NativeToolInstallation


def record() -> dict[str, object]:
    return {
        "schema_version": SCHEMA,
        "adapter_id": "sandbox.permission.chmod.v1",
        "adapter_version": "1.0.0",
        "adapter_contract_digest": "sha256:" + "a" * 64,
        "tool_id": "gnu.coreutils.chmod.v1",
        "tool_version": "9.5",
        "platform": "linux",
        "architecture": "x86_64",
        "content_sha256": "sha256:" + "b" * 64,
        "size_bytes": 1234,
        "installation_location": "/usr/bin/chmod",
    }


def test_round_trip_is_immutable_and_detached() -> None:
    source = record()
    installation = NativeToolInstallation.from_mapping(source)
    source["tool_version"] = "changed"
    output = installation.to_dict()
    output["tool_version"] = "changed"
    assert installation.to_dict()["tool_version"] == "9.5"
    assert installation.digest.startswith("sha256:")


@pytest.mark.parametrize("field", sorted(set(record()) - {"schema_version"}))
def test_unknown_or_missing_shape_is_rejected(field: str) -> None:
    value = record()
    value.pop(field)
    with pytest.raises(ContractError):
        NativeToolInstallation.from_mapping(value)


def test_extra_field_is_rejected() -> None:
    value = record()
    value["invocation"] = ["--mode", "0666"]
    with pytest.raises(ContractError):
        NativeToolInstallation.from_mapping(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "bluefire.other.v1"),
        ("adapter_id", "chmod"),
        ("adapter_version", "1"),
        ("adapter_contract_digest", "bad"),
        ("tool_id", "chmod"),
        ("tool_version", "x" * 65),
        ("platform", "windows"),
        ("architecture", "armv7"),
        ("content_sha256", "sha256:" + "A" * 64),
        ("size_bytes", 0),
        ("size_bytes", True),
        ("size_bytes", 128 * 1024 * 1024 + 1),
        ("architecture", []),
        ("platform", {}),
        ("installation_location", "/"),
        ("installation_location", "/usr/bin/chmod/"),
        ("installation_location", "/usr/bin/chmod\x7f"),
        ("installation_location", "/usr/bin/\ud800"),
        ("installation_location", "relative/chmod"),
        ("installation_location", "/usr/./bin/chmod"),
        ("installation_location", "/usr//bin/chmod"),
        ("installation_location", "/usr/bin/.."),
        ("installation_location", "/usr/bin\\chmod"),
    ],
)
def test_invalid_values_and_injection_are_rejected(field: str, value: object) -> None:
    candidate = record()
    candidate[field] = value
    with pytest.raises(ContractError):
        NativeToolInstallation.from_mapping(candidate)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("expected_adapter_id", "mismatch"),
        ("expected_adapter_version", "mismatch"),
        ("expected_adapter_contract_digest", "sha256:" + "c" * 64),
        ("expected_tool_id", "mismatch"),
        ("expected_platform", "mismatch"),
        ("expected_architecture", "mismatch"),
    ],
)
def test_binding_rejects_every_identity_mismatch(key: str, value: str) -> None:
    installation = NativeToolInstallation.from_mapping(record())
    expected = {
        "expected_adapter_id": "sandbox.permission.chmod.v1",
        "expected_adapter_version": "1.0.0",
        "expected_adapter_contract_digest": "sha256:" + "a" * 64,
        "expected_tool_id": "gnu.coreutils.chmod.v1",
        "expected_platform": "linux",
        "expected_architecture": "x86_64",
    }
    expected[key] = value
    with pytest.raises(ContractError):
        installation.check_binding(**expected)


def test_binding_accepts_exact_compiled_identity() -> None:
    installation = NativeToolInstallation.from_mapping(record())
    installation.check_binding(
        expected_adapter_id="sandbox.permission.chmod.v1",
        expected_adapter_version="1.0.0",
        expected_adapter_contract_digest="sha256:" + "a" * 64,
        expected_tool_id="gnu.coreutils.chmod.v1",
        expected_platform="linux",
        expected_architecture="x86_64",
    )
