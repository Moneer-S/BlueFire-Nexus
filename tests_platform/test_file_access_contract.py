from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from bluefire.config import load_config
from bluefire.file_access_contract import (
    OWNER_ACTION,
    PROBE_ACTION,
    FileAccessContractError,
    VerifiedFileAccessBinding,
    canonical_file_access_binding,
    canonical_file_access_observation,
    validate_file_access_observation,
    verify_file_access_binding,
)
from bluefire.file_access_method import outputs, request
from bluefire.registry import load_builtin_registry
from bluefire.runner_contracts import build_runner_profile, seal_profile
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.file_access_fixtures import binding, observation


@pytest.mark.parametrize(
    "path,value",
    [
        (("unexpected",), True),
        (("mode",), "0666"),
        (("resource", "root"), "/etc"),
        (("worker", "uid"), 1001),
        (("worker", "pid"), True),
        (("resource", "owner_uid"), 1002),
        (("resource", "group_gid"), 1000),
        (("resource", "device"), 4),
        (("resource", "acl_digest"), "sha256:" + "0" * 64),
        (("resource", "size"), 1048577),
        (("worker", "namespaces", "mnt"), "mnt:[0]"),
        (("resource", "record_count"), 0),
    ],
)
def test_binding_closed_shape(path, value):
    document = binding()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(FileAccessContractError):
        canonical_file_access_binding(document)


def test_independent_digest_and_immutable_provenance():
    document = binding()
    with pytest.raises(TypeError):
        VerifiedFileAccessBinding()
    with pytest.raises(FileAccessContractError):
        verify_file_access_binding(
            document, expected_document_digest="sha256:" + "0" * 64, now_ms=1_000_000
        )
    with pytest.raises(FileAccessContractError):
        verify_file_access_binding(
            document,
            expected_document_digest=content_hash(document),
            now_ms=document["expires_at_ms"],
        )
    verified = verify_file_access_binding(
        document, expected_document_digest=content_hash(document), now_ms=1_000_000
    )
    document["mode"] = "0600"
    assert verified.to_dict()["mode"] == "0640"
    with pytest.raises(AttributeError):
        verified._document = b"{}"


def test_profile_absent_legacy_and_verified_extension(tmp_path):
    config = load_config(Path(__file__).parents[1] / "config/bluefire.example.yaml")
    profile = next(row for row in config.runner_profiles if row.id == "sandbox-execute.v1")
    kwargs = {"sandbox_root": tmp_path, "platform": "linux"}
    legacy = build_runner_profile(profile, **kwargs)
    assert "file_access_binding" not in legacy
    document = binding()
    verified = verify_file_access_binding(
        document, expected_document_digest=content_hash(document), now_ms=1_000_000
    )
    current = build_runner_profile(profile, **kwargs, file_access_binding=verified)
    assert current["file_access_binding"] == document
    assert current["policy_digest"] != legacy["policy_digest"]
    with pytest.raises((ValueError, TypeError)):
        build_runner_profile(profile, **kwargs, file_access_binding=document)
    with pytest.raises(ValueError):
        seal_profile({**legacy, "file_access_binding": None})
    with pytest.raises(ValueError):
        seal_profile({**current, "platform": "windows"})


@pytest.mark.parametrize("owner,denied", [(False, False), (False, True), (True, False)])
def test_exact_observation(owner, denied):
    value = observation(owner=owner, denied=denied)
    assert (
        validate_file_access_observation(
            value, binding=binding(), request_hash=value["request_hash"], reader=value["reader"]
        )
        == value
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("reader", "other"),
        ("challenge", "0" * 64),
        ("request_hash", "sha256:" + "0" * 64),
        ("control_revision", 2),
        ("observed_at_ms", 1_800_000),
        ("mode", "0600"),
    ],
)
def test_observation_cannot_change_original_request(field, value):
    original = observation()
    changed = copy.deepcopy(original)
    changed[field] = value
    with pytest.raises(FileAccessContractError):
        validate_file_access_observation(
            changed, binding=binding(), request_hash=original["request_hash"], reader="non_owner"
        )


def test_denial_never_invents_data_or_owner_success():
    denied = observation(denied=True)
    assert denied["sha256"] is None
    denied["record_count"] = 6
    with pytest.raises(FileAccessContractError):
        canonical_file_access_observation(denied)
    with pytest.raises(FileAccessContractError):
        canonical_file_access_observation(observation(owner=True, denied=True))


def report(value, path):
    payload = canonical_json_bytes(value)
    return {
        "observation": value,
        "report": {
            "path": path,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        },
    }


def test_adapter_typed_dependency_and_only_report_cleanup():
    probe = outputs(
        PROBE_ACTION,
        {},
        bound_inputs={},
        runner_output=report(observation(), "fixtures/access-probe.json"),
        receipt_ids=["1" * 64],
    )
    assert probe["workspace"]["receipt_ids"] == ["1" * 64]
    assert probe["workspace"]["root"] == "fixtures"
    owner = outputs(
        OWNER_ACTION,
        {},
        bound_inputs={"probe": probe["probe"]},
        runner_output=report(observation(owner=True), "fixtures/access-owner.json"),
        receipt_ids=["2" * 64],
    )
    assert owner["verification"]["probe_observation_digest"] == probe["probe"]["observation_digest"]
    with pytest.raises(ValueError):
        request(PROBE_ACTION, {"uid": 1002}, {})
    with pytest.raises(ValueError):
        request(OWNER_ACTION, {}, {})
    changed = observation(owner=True)
    changed["resource"]["inode"] += 1
    with pytest.raises(ValueError):
        outputs(
            OWNER_ACTION,
            {},
            bound_inputs={"probe": probe["probe"]},
            runner_output=report(changed, "fixtures/access-owner.json"),
            receipt_ids=["2" * 64],
        )


def test_catalog_methods_are_linux_only_and_have_no_user_parameters():
    registry = load_builtin_registry()
    for action_id in (PROBE_ACTION, OWNER_ACTION):
        action = registry.get_action(action_id)
        assert not action.parameters
        assert len(action.platforms) == 1
        assert action.cleanup_action_id == "sandbox.cleanup.v1"
