"""Synthetic metadata only: no approved binaries, installs, services or tool execution."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from bluefire.contracts import ContractError
from bluefire.native_tool_installations import SCHEMA as INSTALLATION_SCHEMA
from bluefire.tool_adapters import chmod, gzip
from bluefire.tool_adapters.contracts import ToolAdapterContract
from bluefire.tool_adapters.owned_sftp import (
    BUNDLE_SCHEMA,
    METHOD_ID,
    REFERENCE_FIELDS,
    REQUEST_SCHEMA,
    VERSION,
    OwnedSftpToolBundle,
    preparation_contract,
    prepare_client_selection,
)
from bluefire.tool_adapters.registry import contract_for, known_adapter_ids
from bluefire.util import canonical_json_bytes, content_hash


def digest(label):
    return content_hash({"synthetic_test_value": label})


@pytest.fixture
def document():
    contract = preparation_contract()
    members = []
    for role, (source_id, program, tool_id) in contract["member_roles"].items():
        members.append(
            {
                "role": role,
                "source_id": source_id,
                "build_id": source_id + ".synthetic-test-build",
                "build_manifest_ref": digest(source_id + "-build"),
                "protected_installation_ref": digest(role + "-protected-inspection"),
                "installation": {
                    "schema_version": INSTALLATION_SCHEMA,
                    "adapter_id": METHOD_ID,
                    "adapter_version": VERSION,
                    "adapter_contract_digest": content_hash(contract),
                    "tool_id": tool_id,
                    "tool_version": contract["sources"][source_id]["version"],
                    "platform": "linux",
                    "architecture": "x86_64",
                    "content_sha256": digest(role + "-fake-binary"),
                    "size_bytes": 1234,
                    "installation_location": "/opt/bluefire/reviewed/bin/" + program,
                },
            }
        )
    return {
        "schema_version": BUNDLE_SCHEMA,
        "contract_digest": content_hash(contract),
        "platform": "linux",
        "architecture": "x86_64",
        "sources": contract["sources"],
        "members": members,
    }


def selection(bundle):
    references = {field: digest(field) for field in REFERENCE_FIELDS}
    return (
        {
            "schema_version": REQUEST_SCHEMA,
            "bundle_digest": bundle.digest,
            "max_transfer_bytes": 8192,
            **references,
        },
        references,
    )


def prepare(bundle, request, references, expected=None):
    return prepare_client_selection(
        bundle,
        request,
        expected_bundle_digest=expected or bundle.digest,
        current_references=references,
    )


def member(document, role):
    return next(row for row in document["members"] if row["role"] == role)


def test_bundle_is_a_canonical_snapshot_with_all_native_roles(document):
    bundle = OwnedSftpToolBundle.from_mapping(document)
    original = bundle.to_dict()
    document["members"].reverse()
    assert OwnedSftpToolBundle.from_mapping(document).digest == bundle.digest
    document["members"][0]["installation"]["content_sha256"] = digest("changed")
    exported = bundle.to_dict()
    exported["sources"]["openssh"]["version"] = "changed"
    assert bundle.to_dict() == original
    assert set(row["role"] for row in original["members"]) == {
        "client",
        "transport",
        "server",
        "session_helper",
        "auth_helper",
        "observer",
    }


def test_matching_metadata_remains_unavailable_and_does_not_activate_shipping_registry(document):
    bundle = OwnedSftpToolBundle.from_mapping(document)
    request, references = selection(bundle)
    result = prepare(bundle, request, references)
    assert result["execution_available"] is False
    assert result["reason"] == "compiled_sftp_consumer_unimplemented"
    assert result["request_digest"] == content_hash(request)
    assert result["current_references_digest"] == content_hash(references)
    assert known_adapter_ids() == {chmod.ADAPTER_ID, gzip.ADAPTER_ID}
    with pytest.raises(ContractError, match="unknown native tool adapter"):
        contract_for(METHOD_ID)


@pytest.mark.parametrize(
    "role", ["client", "transport", "server", "session_helper", "auth_helper", "observer"]
)
def test_missing_or_duplicate_helper_never_forms_complete_bundle(document, role):
    row = member(document, role)
    document["members"].remove(row)
    with pytest.raises(ContractError):
        OwnedSftpToolBundle.from_mapping(document)
    document["members"].append(deepcopy(document["members"][0]))
    with pytest.raises(ContractError, match="duplicate executable role"):
        OwnedSftpToolBundle.from_mapping(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "interpreter"),
        ("source_id", "strace"),
        ("build_id", "sh script"),
        ("build_manifest_ref", "not-a-digest"),
        ("protected_installation_ref", "not-a-digest"),
    ],
)
def test_member_role_source_and_build_are_closed(document, field, value):
    member(document, "auth_helper")[field] = value
    with pytest.raises(ContractError):
        OwnedSftpToolBundle.from_mapping(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool_id", "openssh.sftp.v1"),
        ("tool_version", "9.9p1"),
        ("architecture", "aarch64"),
        ("adapter_contract_digest", "sha256:" + "0" * 64),
        ("content_sha256", "bad"),
        ("size_bytes", True),
        ("size_bytes", 0),
        ("size_bytes", 128 * 1024 * 1024 + 1),
        ("installation_location", "/opt/bluefire/bin/ssh"),
        ("installation_location", "/opt/bluefire/../bin/sshd-auth"),
        ("installation_location", "/opt/bluefire//bin/sshd-auth"),
        ("installation_location", "relative/sshd-auth"),
        ("installation_location", "//host/bin/sshd-auth"),
        ("installation_location", "/opt/bluefire/sshd-auth\n"),
        ("installation_location", "/opt/bluefire\\bin/sshd-auth"),
    ],
)
def test_helper_identity_cannot_change_role_version_abi_hash_size_or_escape_path(
    document, field, value
):
    member(document, "auth_helper")["installation"][field] = value
    with pytest.raises(ContractError):
        OwnedSftpToolBundle.from_mapping(document)


def test_helpers_cannot_mix_reviewed_builds_or_reuse_protected_identity(document):
    row = member(document, "session_helper")
    row["build_manifest_ref"] = digest("different-build")
    with pytest.raises(ContractError, match="share an exact reviewed build"):
        OwnedSftpToolBundle.from_mapping(document)
    row["build_manifest_ref"] = member(document, "server")["build_manifest_ref"]
    row["protected_installation_ref"] = member(document, "server")["protected_installation_ref"]
    with pytest.raises(ContractError, match="distinct protected executable identities"):
        OwnedSftpToolBundle.from_mapping(document)


def test_changed_helper_digest_requires_a_new_independent_bundle_review(document):
    original = OwnedSftpToolBundle.from_mapping(document)
    member(document, "auth_helper")["installation"]["content_sha256"] = digest("replacement")
    replacement = OwnedSftpToolBundle.from_mapping(document)
    request, references = selection(replacement)
    with pytest.raises(ContractError, match="independently supplied review"):
        prepare(replacement, request, references, expected=original.digest)
    request["bundle_digest"] = original.digest
    with pytest.raises(ContractError, match="independently supplied review"):
        prepare(replacement, request, references)


@pytest.mark.parametrize("field", REFERENCE_FIELDS)
def test_missing_invalid_or_changed_current_references_fail_closed(document, field):
    bundle = OwnedSftpToolBundle.from_mapping(document)
    request, current = selection(bundle)
    request[field] = digest("historical-or-stale-" + field)
    with pytest.raises(ContractError, match="current prerequisite changed"):
        prepare(bundle, request, current)
    request[field] = "historical-finding-is-not-a-current-reference"
    with pytest.raises(ContractError, match="SHA-256 reference"):
        prepare(bundle, request, current)
    request[field] = current[field]
    del current[field]
    with pytest.raises(ContractError, match="current prerequisites"):
        prepare(bundle, request, current)
    del request[field]
    with pytest.raises(ContractError, match="client preparation"):
        prepare(bundle, request, current)


@pytest.mark.parametrize(
    "extra", ["argv", "config", "script", "host", "remote_command", "privilege", "ready"]
)
def test_no_request_can_supply_execution_controls(document, extra):
    bundle = OwnedSftpToolBundle.from_mapping(document)
    request, references = selection(bundle)
    request[extra] = "unreviewed"
    with pytest.raises(ContractError):
        prepare(bundle, request, references)
    document[extra] = "unreviewed"
    with pytest.raises(ContractError):
        OwnedSftpToolBundle.from_mapping(document)


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, 1_048_577, "8192"])
def test_transfer_limit_is_small_finite_and_typed(document, limit):
    bundle = OwnedSftpToolBundle.from_mapping(document)
    request, references = selection(bundle)
    request["max_transfer_bytes"] = limit
    with pytest.raises(ContractError, match="transfer byte limit"):
        prepare(bundle, request, references)


def test_pinned_source_and_direct_constructor_cannot_bypass_validation(document):
    original = deepcopy(document)
    document["sources"]["openssh"]["revision"] = "0" * 40
    with pytest.raises(ContractError):
        OwnedSftpToolBundle.from_mapping(document)
    with pytest.raises(ContractError):
        OwnedSftpToolBundle(canonical_json_bytes(document))
    bundle = OwnedSftpToolBundle.from_mapping(original)
    encoded = canonical_json_bytes(bundle.to_dict())
    assert OwnedSftpToolBundle(encoded).digest == bundle.digest
    with pytest.raises(ContractError, match="canonical encoding"):
        OwnedSftpToolBundle(json.dumps(bundle.to_dict(), indent=2).encode())
    with pytest.raises(ContractError):
        OwnedSftpToolBundle(
            encoded.replace(b'"platform":"linux"', b'"platform":"linux","platform":"linux"')
        )
    with pytest.raises(ContractError):
        OwnedSftpToolBundle(b" " * (16 * 1024 + 1))


def test_v1_digests_and_supervision_remain_unchanged():
    assert (
        gzip.CONTRACT.digest
        == "sha256:dd6aec4a80857571f54097f0e8814f3e4307f50c90f8517bff2714381e1ee4ad"
    )
    assert (
        chmod.CONTRACT.digest
        == "sha256:db1c271df09ccd2c781e8b7df4e042fb33e76c90ab8cd621dc8f52dcd3a57dd8"
    )
    for module in (gzip, chmod):
        for field, widened in (("network", "owned-loopback-only"), ("privilege", "root")):
            data = module.contract().to_dict()
            data["supervision"][field] = widened
            with pytest.raises(ContractError, match="unsupported adapter v1"):
                ToolAdapterContract.from_mapping(data)
