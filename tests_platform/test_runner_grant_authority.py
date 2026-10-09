from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.config import load_config
from bluefire.registry import load_builtin_registry
from bluefire.runner_contracts import (
    RunnerContractError,
    VerifiedGrantAttempt,
    VerifiedGrantCleanup,
    _verified_grant_attempt,
    _verified_grant_cleanup,
    build_execution_manifest,
    build_runner_profile,
    current_platform,
    grant_attempt_authorization_digest,
    seal_manifest,
    seal_profile,
)
from bluefire.util import content_hash


def test_plan_binding_matches_native_shared_hash_vector():
    assert grant_attempt_authorization_digest("sha256:" + "c" * 64, "sha256:" + "d" * 64) == (
        "sha256:b87d288d8ef3e774e6a2ebc5d78cd28df06c85fde7574be46340aed7d7d181d0"
    )


@pytest.fixture
def grant_case(tmp_path):
    config = load_config(Path(__file__).resolve().parents[1] / "config/bluefire.example.yaml")
    profile = next(item for item in config.runner_profiles if item.mode.value == "execute")
    action = load_builtin_registry().get_action("sandbox.fixture.create.v1")
    now = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)
    compiled, plan = "sha256:" + "c" * 64, "sha256:" + "d" * 64
    authorization = grant_attempt_authorization_digest(compiled, plan)
    operation = {
        "step_id": "create_fixture",
        "behavior_id": action.id,
        "action_id": action.id,
        "execution_binding_digest": None,
    }
    envelope = {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": authorization,
        "operations": [operation],
    }
    runner = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        reviewed_execution=envelope,
    )
    provenance = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": "capability-grant-controller.v1",
        "grant_id": "grant-" + "a" * 32,
        "grant_digest": "sha256:" + "a" * 64,
        "attempt_id": "attempt-" + "b" * 32,
        "lease_digest": "sha256:" + "b" * 64,
        "compiled_digest": compiled,
        "plan_digest": plan,
        "native_envelope_digest": content_hash(runner["reviewed_execution"]),
        "run_id": "run-grant-test",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    }
    arguments = dict(
        run_id=provenance["run_id"],
        step_id=operation["step_id"],
        behavior_id=action.id,
        action=action,
        runner_profile=runner,
        params={
            "path": "fixtures/input.jsonl",
            "content_template": "telemetry-seed",
            "record_count": 6,
        },
        filesystem_scope=("fixtures/input.jsonl",),
        approval_record=None,
        reviewed_operation={**operation, "authorization_digest": authorization},
        now=now,
    )
    return provenance, arguments


def mint(document):
    """Stand in for the trusted stored-row digest in these synthetic boundary tests."""
    return _verified_grant_attempt(document, expected_document_digest=content_hash(document))


def test_grant_attempt_is_distinct_immutable_provenance_and_caps_deadline(grant_case):
    document, arguments = grant_case
    verified = mint(document)
    manifest = build_execution_manifest(**arguments, grant_attempt=verified)
    assert manifest["approval"] is None
    assert "approved_by" not in manifest["grant_attempt"]
    assert manifest["grant_attempt"]["issuer"] == "capability-grant-controller.v1"
    assert manifest["expires_at"] == manifest["grant_attempt"]["expires_at"]
    assert manifest["grant_attempt"]["request_hash"] == manifest["request_hash"]
    unsigned = copy.deepcopy(manifest)
    unsigned["request_hash"] = unsigned["grant_attempt"]["request_hash"] = ""
    assert content_hash(unsigned) == manifest["request_hash"]
    document["grant_id"] = "grant-" + "e" * 32
    assert verified.to_dict()["grant_id"] != document["grant_id"]
    with pytest.raises(AttributeError):
        verified._document = document
    with pytest.raises(TypeError):
        VerifiedGrantAttempt()


def test_raw_or_modified_claim_provenance_cannot_enter_builder(grant_case):
    document, arguments = grant_case
    with pytest.raises(RunnerContractError):
        build_execution_manifest(**arguments, grant_attempt=document)
    stored_digest = content_hash(document)
    document["attempt_id"] = "attempt-" + "e" * 32
    with pytest.raises(RunnerContractError):
        _verified_grant_attempt(document, expected_document_digest=stored_digest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bluefire.runner-grant-attempt.v2"),
        ("issuer", "operator"),
        ("approved_by", "operator"),
        ("request_hash", ""),
        ("grant_id", "grant-invalid"),
        ("attempt_id", "attempt-" + "A" * 32),
        ("lease_digest", "sha256:" + "A" * 64),
        ("run_id", "../another"),
        ("expires_at", "2026-10-03T11:00:00Z"),
    ],
)
def test_claim_factory_rejects_unknown_or_malformed_provenance(grant_case, field, value):
    document, _ = grant_case
    with pytest.raises(RunnerContractError):
        mint({**document, field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "another-run"),
        ("compiled_digest", "sha256:" + "e" * 64),
        ("plan_digest", "sha256:" + "e" * 64),
        ("native_envelope_digest", "sha256:" + "e" * 64),
        ("issued_at", "2026-10-03T12:00:01Z"),
        ("expires_at", "2026-10-03T12:00:00Z"),
    ],
)
def test_grant_build_requires_current_exact_run_plan_and_envelope(grant_case, field, value):
    document, arguments = grant_case
    with pytest.raises(RunnerContractError):
        build_execution_manifest(**arguments, grant_attempt=mint({**document, field: value}))


def test_ambiguous_null_and_unreviewed_authority_are_refused(grant_case):
    document, arguments = grant_case
    verified = mint(document)
    with pytest.raises(RunnerContractError):
        build_execution_manifest(**{**arguments, "approval_record": {}}, grant_attempt=verified)
    with pytest.raises(RunnerContractError):
        build_execution_manifest(
            **{**arguments, "reviewed_operation": None}, grant_attempt=verified
        )
    legacy = build_execution_manifest(**arguments)
    assert "grant_attempt" not in legacy
    with pytest.raises(RunnerContractError):
        seal_manifest({**legacy, "grant_attempt": None})
    manifested = build_execution_manifest(**arguments, grant_attempt=verified)
    with pytest.raises(RunnerContractError):
        seal_manifest({**manifested, "approval": {}})


def test_grant_cannot_expand_the_finite_envelope_without_a_new_claim(grant_case):
    document, arguments = grant_case
    profile = copy.deepcopy(arguments["runner_profile"])
    extra = {**profile["reviewed_execution"]["operations"][0], "step_id": "second_create"}
    profile["reviewed_execution"]["operations"].append(extra)
    profile = seal_profile(profile)
    with pytest.raises(RunnerContractError, match="current finite run envelope"):
        build_execution_manifest(
            **{**arguments, "runner_profile": profile}, grant_attempt=mint(document)
        )


def test_grant_expiry_and_profile_timeout_still_bound_each_request(grant_case):
    document, arguments = grant_case
    verified = mint(document)
    with pytest.raises(RunnerContractError, match="current finite run envelope"):
        build_execution_manifest(
            **{**arguments, "now": arguments["now"] + timedelta(seconds=60)},
            grant_attempt=verified,
        )
    with pytest.raises(RunnerContractError, match="runner profile limit"):
        build_execution_manifest(
            **arguments,
            grant_attempt=verified,
            timeout_ms=arguments["runner_profile"]["limits"]["timeout_ms"] + 1,
        )
    later = {**document, "expires_at": "2026-10-03T12:10:00Z"}
    manifest = build_execution_manifest(**arguments, grant_attempt=mint(later))
    assert manifest["expires_at"] == "2026-10-03T12:05:00Z"


def test_claim_provenance_requires_every_field_and_explicit_utc_compatible_times(grant_case):
    document, _ = grant_case
    for field in document:
        incomplete = {key: value for key, value in document.items() if key != field}
        with pytest.raises(RunnerContractError, match="exact provenance fields"):
            mint(incomplete)
    for field in ("issued_at", "expires_at"):
        for value in (None, 1, "2026-10-03T12:00:00", "2026-10-03T12:00:00.1234567Z"):
            with pytest.raises(RunnerContractError):
                mint({**document, field: value})


@pytest.fixture
def cleanup_case(grant_case):
    document, arguments = grant_case
    action = load_builtin_registry().get_action("sandbox.cleanup.v1")
    operation = {
        "step_id": "clean",
        "behavior_id": action.id,
        "action_id": action.id,
        "execution_binding_digest": None,
    }
    profile = copy.deepcopy(arguments["runner_profile"])
    profile["reviewed_execution"]["operations"].append(operation)
    profile["allowed_actions"].append(action.id)
    profile = seal_profile(profile)
    document = {
        **document,
        "schema_version": "bluefire.runner-grant-cleanup.v1",
        "native_envelope_digest": content_hash(profile["reviewed_execution"]),
        "runner_policy_digest": profile["policy_digest"],
        "obligation_digest": "sha256:" + "e" * 64,
        "workspace_id": "f" * 64,
        "receipts": [
            {
                "receipt_id": "1" * 64,
                "source_request_hash": "sha256:" + "2" * 64,
                "source_task_id": "task-source",
            }
        ],
        "issued_at": "2026-10-03T12:01:00Z",
        "expires_at": "2026-10-03T12:01:10Z",
        "timeout_ms": 10_000,
    }
    return document, {
        **arguments,
        "action": action,
        "behavior_id": action.id,
        "step_id": operation["step_id"],
        "runner_profile": profile,
        "params": {"receipt_ids": ["1" * 64]},
        "filesystem_scope": (),
        "reviewed_operation": {
            **operation,
            "authorization_digest": profile["reviewed_execution"]["authorization_digest"],
        },
        "now": datetime(2026, 10, 3, 12, 1, tzinfo=timezone.utc),
    }


def mint_cleanup(document):
    return _verified_grant_cleanup(document, expected_document_digest=content_hash(document))


def test_cleanup_obligation_is_distinct_immutable_and_does_not_renew_business(cleanup_case):
    document, arguments = cleanup_case
    authority = mint_cleanup(document)
    manifest = build_execution_manifest(**arguments, grant_cleanup=authority)
    assert manifest["approval"] is None and "grant_attempt" not in manifest
    assert manifest["grant_cleanup"]["request_hash"] == manifest["request_hash"]
    assert manifest["expires_at"] == document["expires_at"]
    assert manifest["limits"]["timeout_ms"] == 10_000
    assert "approved_by" not in manifest["grant_cleanup"]
    unsigned = copy.deepcopy(manifest)
    unsigned["request_hash"] = unsigned["grant_cleanup"]["request_hash"] = ""
    assert manifest["request_hash"] == content_hash(unsigned)
    document["receipts"][0]["source_task_id"] = "changed"
    exposed = authority.to_dict()
    exposed["receipts"].clear()
    assert authority.to_dict()["receipts"][0]["source_task_id"] == "task-source"
    with pytest.raises(AttributeError):
        authority._document = b"{}"
    with pytest.raises(TypeError):
        VerifiedGrantCleanup()


@pytest.mark.parametrize(
    "change",
    [
        "raw",
        "approval",
        "business",
        "action",
        "alias",
        "scope",
        "network",
        "receipts",
        "profile",
        "envelope",
        "expired",
        "timeout",
    ],
)
def test_cleanup_cannot_expand_business_or_receipt_authority(cleanup_case, change):
    document, arguments = cleanup_case
    authority = mint_cleanup(document)
    if change == "raw":
        authority = document
    elif change == "approval":
        arguments["approval_record"] = {}
    elif change == "business":
        arguments["grant_attempt"] = {}
    elif change == "action":
        arguments["action"] = load_builtin_registry().get_action("sandbox.fixture.create.v1")
        arguments["behavior_id"] = arguments["action"].id
    elif change == "alias":
        arguments["execution_binding"] = {}
    elif change == "scope":
        arguments["filesystem_scope"] = ("fixtures",)
    elif change == "network":
        arguments["network_destinations"] = ({"host": "127.0.0.1", "port": 4317},)
    elif change == "receipts":
        arguments["params"] = {"receipt_ids": ["3" * 64]}
    elif change == "profile":
        arguments["runner_profile"]["policy_digest"] = "sha256:" + "3" * 64
    elif change == "envelope":
        arguments["runner_profile"]["reviewed_execution"]["operations"].pop()
    elif change == "expired":
        arguments["now"] += timedelta(seconds=10)
    else:
        arguments["timeout_ms"] = 10_001
    with pytest.raises(RunnerContractError):
        build_execution_manifest(**arguments, grant_cleanup=authority)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bluefire.runner-grant-attempt.v1"),
        ("issuer", "operator"),
        ("workspace_id", "../unowned"),
        ("obligation_digest", "sha256:" + "A" * 64),
        ("runner_policy_digest", None),
        ("receipts", []),
        ("receipts", [{"receipt_id": "1" * 64}]),
        ("timeout_ms", True),
        ("timeout_ms", 10_001),
        ("expires_at", "2026-10-03T12:04:00Z"),
    ],
)
def test_cleanup_factory_rejects_unknown_or_unbounded_obligations(cleanup_case, field, value):
    document, _ = cleanup_case
    with pytest.raises(RunnerContractError):
        mint_cleanup({**document, field: value})


def test_cleanup_claim_hash_and_deadline_cannot_be_replaced(cleanup_case):
    document, arguments = cleanup_case
    stored = content_hash(document)
    with pytest.raises(RunnerContractError):
        _verified_grant_cleanup(
            {**document, "obligation_digest": "sha256:" + "9" * 64}, expected_document_digest=stored
        )
    late = build_execution_manifest(
        **{**arguments, "now": arguments["now"] + timedelta(seconds=8)},
        grant_cleanup=mint_cleanup(document),
    )
    assert late["limits"]["timeout_ms"] == 2000
    with pytest.raises(RunnerContractError):
        seal_manifest({**late, "grant_attempt": {}})
    with pytest.raises(RunnerContractError):
        seal_manifest({**late, "grant_cleanup": None})
