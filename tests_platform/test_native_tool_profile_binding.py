from __future__ import annotations

import pytest

from bluefire.contracts import ContractError
from bluefire.native_tool_installations import (
    SCHEMA,
    NativeToolInstallation,
    canonical_native_tool_installations,
)
from bluefire.runner_contracts import RunnerContractError, seal_profile


def installation() -> dict[str, object]:
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


def profile(*, tools: object = ...) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "bluefire.runner-profile.v1",
        "platform": "linux",
        "allowed_actions": ["sandbox.permission.chmod.v1"],
        "policy_digest": "",
    }
    if tools is not ...:
        document["native_tool_installations"] = tools
    return document


def test_profile_binding_accepts_exact_record_and_is_detached() -> None:
    source = installation()
    sealed = canonical_native_tool_installations(
        [source], platform="linux", allowed_actions=[source["adapter_id"]]
    )
    source["tool_version"] = "changed"
    assert sealed[0]["tool_version"] == "9.5"
    sealed[0]["tool_version"] = "sealed-change"
    assert source["tool_version"] == "changed"
    assert (
        canonical_native_tool_installations(
            [installation()], platform="linux", allowed_actions=["sandbox.permission.chmod.v1"]
        )[0]["tool_version"]
        == "9.5"
    )


@pytest.mark.parametrize("change", ["omit", "empty"])
def test_legacy_omitted_or_empty_content_hash_is_rejected(change: str) -> None:
    value = installation()
    if change == "omit":
        del value["content_sha256"]
    else:
        value["content_sha256"] = ""
    with pytest.raises(ContractError):
        NativeToolInstallation.from_mapping(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("installation_location", "/usr/bin/other"),
        ("content_sha256", "sha256:" + "c" * 64),
        ("tool_version", "9.6"),
    ],
)
def test_binding_digest_changes_with_identity_fields(field: str, value: str) -> None:
    original = NativeToolInstallation.from_mapping(installation()).digest
    changed = installation()
    changed[field] = value
    assert NativeToolInstallation.from_mapping(changed).digest != original


def test_profile_binding_rejects_malformed_duplicate_and_out_of_scope_records() -> None:
    malformed = installation()
    malformed.pop("adapter_id")
    with pytest.raises(ContractError):
        canonical_native_tool_installations(
            [malformed], platform="linux", allowed_actions=["sandbox.permission.chmod.v1"]
        )

    duplicate = installation()
    with pytest.raises(ContractError, match="duplicated"):
        canonical_native_tool_installations(
            [installation(), duplicate],
            platform="linux",
            allowed_actions=["sandbox.permission.chmod.v1"],
        )

    wrong_platform = installation()
    wrong_platform["platform"] = "windows"
    with pytest.raises(ContractError):
        canonical_native_tool_installations(
            [wrong_platform], platform="linux", allowed_actions=["sandbox.permission.chmod.v1"]
        )

    outside_scope = installation()
    outside_scope["adapter_id"] = "sandbox.permission.other.v1"
    with pytest.raises(ContractError, match="outside"):
        canonical_native_tool_installations(
            [outside_scope], platform="linux", allowed_actions=["sandbox.permission.chmod.v1"]
        )


def test_canonical_installation_hash_matches_rust_golden_vector() -> None:
    assert NativeToolInstallation.from_mapping(installation()).digest == (
        "sha256:fd6a0ff27b30372ab441730505a2b3c3ae03e2c923632232ee832ab5021c16c8"
    )


def test_profile_seal_preserves_legacy_absent_and_empty_tool_shape() -> None:
    absent = seal_profile(profile())
    empty = seal_profile(profile(tools=[]))
    assert "native_tool_installations" not in absent
    assert "native_tool_installations" not in empty
    assert absent["policy_digest"] == empty["policy_digest"]


def test_profile_seal_binds_nonempty_identity_and_detaches_input() -> None:
    source = installation()
    sealed = seal_profile(profile(tools=[source]))
    assert sealed["policy_digest"] != seal_profile(profile())["policy_digest"]
    source["tool_version"] = "changed"
    assert sealed["native_tool_installations"][0]["tool_version"] == "9.5"
    sealed["native_tool_installations"][0]["tool_version"] = "sealed-change"
    assert source["tool_version"] == "changed"


@pytest.mark.parametrize(
    "tools",
    [
        [{**installation(), "content_sha256": ""}],
        [{**installation(), "platform": "windows"}],
        [{**installation()}, {**installation()}],
        [{**installation(), "adapter_id": "sandbox.permission.other.v1"}],
    ],
)
def test_profile_seal_translates_invalid_tool_records(tools: list[dict[str, object]]) -> None:
    with pytest.raises(RunnerContractError):
        seal_profile(profile(tools=tools))
