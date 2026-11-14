"""Pure bridge identities; these tests do not inspect or change a live file."""

from __future__ import annotations

import copy
import hashlib
import uuid

import pytest

from bluefire.engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    EngineFileAccessSnapshotError,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
    verify_file_access_snapshot_pair,
)
from bluefire.execution_contracts import execution_task_identity
from bluefire.file_access_contract import request_challenge, verify_file_access_binding
from bluefire.file_access_observation import control_observation
from bluefire.file_access_plan import recipe as file_access_recipe
from bluefire.permission_method import adapt_permission_method
from bluefire.runner_contracts import seal_manifest
from bluefire.tool_adapters.chmod import CONTRACT
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.file_access_fixtures import binding as fixture_binding
from tests_platform.file_access_fixtures import observation as fixture_observation


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _job(character: str) -> str:
    return "job-" + character * 32


def _verified(document: dict):
    return verify_file_access_binding(
        document, expected_document_digest=content_hash(document), now_ms=1_000_000
    )


def _baseline(document: dict) -> dict:
    return {
        "baseline_digest": _digest("1"),
        "non_owner": "allowed",
        "owner": "allowed",
        "record_count": document["resource"]["record_count"],
        "sha256": document["resource"]["sha256"],
        "source_binding": {
            "operation_job_id": _job("2"),
            "evidence_digest": _digest("1"),
        },
    }


def _pair():
    before_document = fixture_binding()
    before_document["control_revision"] = 2
    after_document = copy.deepcopy(before_document)
    after_document["control_revision"] = 3
    after_document["mode"] = "0600"
    original = _baseline(before_document)
    before_binding = _verified(before_document)
    after_binding = _verified(after_document)
    mechanism = FileAccessReadMechanism.from_verified_binding(before_binding, baseline=original)
    before = FileAccessTargetSnapshot.from_verified_binding(
        before_binding,
        mechanism=mechanism,
        control_owner_id=_job("0"),
        control_digest=_digest("3"),
        source_operation_job_id=_job("2"),
        source_evidence_digest=_digest("1"),
        phase=HISTORICAL_BASELINE,
    )
    after = FileAccessTargetSnapshot.from_verified_binding(
        after_binding,
        mechanism=mechanism,
        control_owner_id=_job("0"),
        control_digest=_digest("4"),
        prior_control_digest=_digest("3"),
        source_operation_job_id=_job("5"),
        source_evidence_digest=_digest("6"),
        phase=CURRENT_HARDENED,
    )
    return mechanism, before, after, before_binding, after_binding, original


def test_original_mechanism_stays_fixed_while_snapshot_changes() -> None:
    mechanism, before, after, before_binding, after_binding, original = _pair()
    same_mechanism = FileAccessReadMechanism.from_verified_binding(after_binding, baseline=original)

    assert same_mechanism.mechanism_ref == mechanism.mechanism_ref
    assert before.target_snapshot_ref != after.target_snapshot_ref
    assert before.to_dict()["mode"] == "0640"
    assert after.to_dict()["mode"] == "0600"
    assert before.to_dict()["control_revision"] == 2
    assert after.to_dict()["control_revision"] == 3
    assert mechanism.to_dict()["probe_uid"] == 1002
    assert mechanism.to_dict()["probe_action_id"] == "file_access.probe.non_owner.v1"
    assert before.to_dict()["resource_path"].endswith("/fixtures/transformed.jsonl")
    mechanism.matches_verified_binding(before_binding)
    mechanism.matches_verified_binding(after_binding)
    verify_file_access_snapshot_pair(before, after, mechanism=mechanism)


def test_mapping_roundtrip_is_detached_and_not_provenance() -> None:
    mechanism, before, after, _, _, _ = _pair()
    source = after.to_dict()
    parsed = FileAccessTargetSnapshot.from_mapping(source)
    source["content"]["sha256"] = _digest("f")

    assert parsed.target_snapshot_ref == after.target_snapshot_ref
    assert FileAccessReadMechanism.from_mapping(mechanism.to_dict()).mechanism_ref == (
        mechanism.mechanism_ref
    )
    assert FileAccessTargetSnapshot.from_mapping(before.to_dict()).to_dict() == before.to_dict()
    with pytest.raises(TypeError):
        FileAccessTargetSnapshot()
    with pytest.raises(AttributeError):
        after._document = b"{}"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("probe_uid", 1001),
        ("probe_uid", True),
        ("probe_action_id", "file_access.verify.owner.v1"),
        ("resource_path", "/tmp/transformed.jsonl"),
        ("resource_id", "file-resource-" + "a" * 32),
        ("resource_generation", "file-generation-" + "b" * 32),
        ("original_read_evidence_digest", _digest("f")),
    ],
)
def test_mechanism_rejects_substituted_uid_path_resource_or_proof(field, value) -> None:
    mechanism, _, _, before_binding, _, _ = _pair()
    changed = mechanism.to_dict()
    changed[field] = value
    if field == "original_read_evidence_digest":
        with pytest.raises(EngineFileAccessSnapshotError):
            FileAccessTargetSnapshot.from_mapping(_pair()[1].to_dict()).matches_mechanism(
                FileAccessReadMechanism.from_mapping(changed)
            )
    elif field == "resource_id":
        with pytest.raises(EngineFileAccessSnapshotError):
            FileAccessReadMechanism.from_mapping(changed).matches_verified_binding(before_binding)
    elif field == "resource_generation":
        with pytest.raises(EngineFileAccessSnapshotError):
            FileAccessReadMechanism.from_mapping(changed)
    else:
        with pytest.raises(EngineFileAccessSnapshotError):
            FileAccessReadMechanism.from_mapping(changed)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("unexpected",), True),
        (("phase",), HISTORICAL_BASELINE),
        (("mode",), "0640"),
        (("control_revision",), True),
        (("resource_path",), "/etc/passwd"),
        (("resource_identity", "owner_uid"), 1002),
        (("resource_identity", "device"), 4),
        (("content", "sha256"), "SHA256:" + "a" * 64),
        (("content", "record_count"), True),
        (("acl", "acl_digest"), _digest("e")),
        (("source", "operation"), "baseline"),
        (("source", "job_id"), "job-other"),
        (("source", "evidence_digest"), "invalid"),
    ],
)
def test_snapshot_parser_is_closed_and_canonical(path, value) -> None:
    _, _, after, _, _, _ = _pair()
    changed = after.to_dict()
    target = changed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(EngineFileAccessSnapshotError):
        FileAccessTargetSnapshot.from_mapping(changed)


def test_snapshot_matches_reopened_binding_and_mechanism() -> None:
    mechanism, before, after, _, after_binding, _ = _pair()
    after.matches_mechanism(mechanism)
    after.matches_verified_binding(after_binding)
    with pytest.raises(EngineFileAccessSnapshotError):
        before.matches_verified_binding(after_binding)

    changed = after.to_dict()
    changed["binding_digest"] = _digest("e")
    with pytest.raises(EngineFileAccessSnapshotError):
        FileAccessTargetSnapshot.from_mapping(changed).matches_verified_binding(after_binding)
    changed = after.to_dict()
    changed["baseline_evidence_digest"] = _digest("e")
    with pytest.raises(EngineFileAccessSnapshotError):
        FileAccessTargetSnapshot.from_mapping(changed).matches_mechanism(mechanism)
    changed = after.to_dict()
    changed["resource_id"] = "file-resource-" + "f" * 32
    with pytest.raises(EngineFileAccessSnapshotError):
        FileAccessTargetSnapshot.from_mapping(changed).matches_mechanism(mechanism)


def test_source_evidence_and_revision_cannot_be_reused() -> None:
    mechanism, before, after, _, after_binding, _ = _pair()
    with pytest.raises(EngineFileAccessSnapshotError):
        FileAccessTargetSnapshot.from_verified_binding(
            after_binding,
            mechanism=mechanism,
            control_owner_id=_job("0"),
            control_digest=_digest("4"),
            prior_control_digest=_digest("3"),
            source_operation_job_id=_job("2"),
            source_evidence_digest=_digest("1"),
            phase=CURRENT_HARDENED,
        )
    stale = after.to_dict()
    stale["control_revision"] = 4
    with pytest.raises(EngineFileAccessSnapshotError):
        verify_file_access_snapshot_pair(
            before, FileAccessTargetSnapshot.from_mapping(stale), mechanism=mechanism
        )


def test_harden_snapshot_requires_exact_historical_control_preimage() -> None:
    mechanism, before, after, _, _, _ = _pair()
    substituted = after.to_dict()
    substituted["prior_control_digest"] = _digest("f")
    with pytest.raises(EngineFileAccessSnapshotError):
        verify_file_access_snapshot_pair(
            before, FileAccessTargetSnapshot.from_mapping(substituted), mechanism=mechanism
        )


def test_stored_control_revision_must_match_binding_source_and_digest() -> None:
    mechanism, before, _, before_binding, _, original = _pair()
    control = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": _job("0"),
        "enrollment_id": before.to_dict()["enrollment_id"],
        "revision": 2,
        "status": "baseline_verified",
        "binding": before_binding.to_dict(),
        "binding_digest": before.to_dict()["binding_digest"],
        "source": {"retained": "owned"},
        "baseline": original,
    }
    source = {"job_id": _job("2"), "document": control, "document_digest": content_hash(control)}
    matching = before.to_dict()
    matching["control_digest"] = source["document_digest"]
    snapshot = FileAccessTargetSnapshot.from_mapping(matching)
    snapshot.matches_control_revision(source, mechanism=mechanism, binding=before_binding)

    changed = copy.deepcopy(source)
    changed["document"]["status"] = "hardened"
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_control_revision(changed, mechanism=mechanism, binding=before_binding)
    changed = copy.deepcopy(source)
    changed["document"]["binding"]["resource_id"] = "file-resource-" + "f" * 32
    changed["document_digest"] = content_hash(changed["document"])
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_control_revision(changed, mechanism=mechanism, binding=before_binding)


def _controller_case(phase: str):
    historical = phase == HISTORICAL_BASELINE
    operation = "baseline" if historical else "harden"
    job_id = _job("2" if historical else "5")
    owner_id = _job("0")
    document = fixture_binding()
    document["control_revision"] = 2 if historical else 3
    document["mode"] = "0640" if historical else "0600"
    verified = _verified(document)
    rows = file_access_recipe(operation)
    source_fixture = {
        "type": "artifact.sandbox.fixture.v1",
        "path": "fixtures/transformed.jsonl",
        "sha256": document["resource"]["sha256"][7:],
        "size": document["resource"]["size"],
        "record_count": document["resource"]["record_count"],
        "redact_values": False,
        "receipt_ids": ["c" * 64],
    }
    source = {"fixture": source_fixture}
    prior_binding = {
        **document,
        "control_revision": document["control_revision"] - 1,
        "mode": "0640",
    }
    previous = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": owner_id,
        "enrollment_id": document["enrollment_id"],
        "revision": document["control_revision"] - 1,
        "status": "created" if historical else "baseline_verified",
        "binding": prior_binding,
        "binding_digest": content_hash(prior_binding),
        "source": source,
        "baseline": None if historical else _baseline(document),
    }
    previous_digest = content_hash(previous)
    review_context = {
        "enrollment_digest": document["enrollment_digest"],
        "profile_digest": content_hash({}),
        "profile_id": "profile-test",
        "implementations": {},
        "control_digest": previous_digest,
        "recipe": rows,
    }
    review_body = {
        "schema_version": "bluefire.file-access-control-review.v1",
        "operation": operation,
        "control_owner_id": owner_id,
        "context_digest": content_hash(review_context),
        "enrollment_digest": document["enrollment_digest"],
        "control_digest": previous_digest,
        "expires_at_ms": document["expires_at_ms"],
        "effect": "reviewed file access",
    }
    review = {**review_body, "review_digest": content_hash(review_body)}
    submitted = {
        "submission_id": str(uuid.UUID(hex=job_id[4:])),
        "review": {"operation": operation, "control_owner_id": owner_id},
        "review_digest": review["review_digest"],
        "reviewed_by": "test operator",
    }
    operations = [
        {
            "step_id": row["step_id"],
            "behavior_id": row["behavior_id"],
            "action_id": row["action_id"],
            "execution_binding_digest": None,
        }
        for row in rows
    ]
    authority = {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": review["review_digest"],
        "operations": operations,
    }

    def profile(workspace: str) -> dict:
        value = {
            "schema_version": "bluefire.runner-profile.v1",
            "profile_id": "profile-test",
            "runner_id": "bluefire-rust-runner.v1",
            "platform": "linux",
            "policy_digest": _digest("d"),
            "limits": {},
            "sandbox_root": "/owned/" + workspace,
            "allowed_actions": sorted({row["action_id"] for row in rows}),
            "reviewed_execution": authority,
        }
        if workspace == "observation":
            value["file_access_binding"] = document
        return value

    profiles = {"retained": profile("retained")}
    if historical:
        profiles["observation"] = profile("observation")
    run_id = "run-20261104T120000Z-" + "e" * 16
    tasks = []
    for index, row in enumerate(rows):
        step = row["step_id"]
        action = row["action_id"]
        workspace = row["workspace"]
        if step in ("probe", "owner"):
            params = {}
            scope = [
                "fixtures/access-probe.json" if step == "probe" else "fixtures/access-owner.json"
            ]
        elif step == "mode":
            params = adapt_permission_method(
                {"mode": "0600"},
                bound_inputs={"fixture": source_fixture},
                available_receipt_ids=["c" * 64],
            )
            scope = ["fixtures/transformed.jsonl"]
        else:
            params = {"receipt_ids": ["b" * 64, "a" * 64]}
            scope = []
        manifest = seal_manifest(
            {
                "schema_version": "bluefire.runner-manifest.v1",
                "request_id": "request-" + str(index),
                "run_id": run_id,
                "step_id": step,
                "behavior_id": row["behavior_id"],
                "action_id": action,
                "mode": "execute",
                "runner_id": "bluefire-rust-runner.v1",
                "runner_profile_id": "profile-test",
                "platform": "linux",
                "requested_at": "1970-01-01T00:16:39Z",
                "expires_at": "1970-01-01T00:21:39Z",
                "params": params,
                "target_scope": {"filesystem": scope, "network": []},
                "required_capabilities": [],
                "safety_tier": "safe",
                "limits": {},
                "cleanup_action_id": "sandbox.cleanup.v1",
                "policy_digest": _digest("d"),
                "approval": {
                    "approved_by": "test operator",
                    "approved_at": "1970-01-01T00:16:38Z",
                    "expires_at": "1970-01-01T00:21:40Z",
                    "request_hash": "",
                },
                "evidence_refs": [],
                "request_hash": "",
                "reviewed_operation": {
                    **operations[index],
                    "authorization_digest": review["review_digest"],
                },
            }
        )
        task_id, transport_hash = execution_task_identity(manifest, profiles[workspace])
        task = {
            "job_id": job_id,
            "task_id": task_id,
            "step_id": step,
            "request_hash": manifest["request_hash"],
            "transport_request_hash": transport_hash,
            "manifest": manifest,
            "runner_profile": profiles[workspace],
        }
        if step in ("probe", "owner"):
            observed = fixture_observation(document, owner=step == "owner")
            observed["request_hash"] = manifest["request_hash"]
            observed["challenge"] = request_challenge(document, manifest["request_hash"])
            observed["closure"]["request_hash"] = manifest["request_hash"]
            observed["closure"]["challenge"] = observed["challenge"]
            observed["observed_at_ms"] = 1_000_000 + index
            payload = canonical_json_bytes(observed)
            result = {
                "status": "success",
                "receipt_ids": [("a" if step == "probe" else "b") * 64],
                "output": {
                    "observation": observed,
                    "report": {
                        "path": scope[0],
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    },
                },
            }
        elif step == "mode":
            result = {
                "status": "success",
                "receipt_ids": ["c" * 64],
                "output": {
                    "artifact": "fixtures/transformed.jsonl",
                    "sha256": source_fixture["sha256"],
                    "size": source_fixture["size"],
                    "requested_mode": "0600",
                    "before_mode": "0640",
                    "after_mode": "0600",
                    "tool": {
                        "installation_digest": _digest("f"),
                        "adapter_contract_digest": CONTRACT.digest,
                        "tool_version": "1.0",
                    },
                    "exit_code": 0,
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                },
            }
        else:
            result = {"status": "success"}
        terminal = {
            "task_id": task_id,
            "request_hash": manifest["request_hash"],
            "result": result,
            "receipt_snapshot": {"documents": {}, "committed": []},
        }
        tasks.append({"task": task, "terminal": terminal})
    baseline = (
        {
            "baseline_digest": content_hash({"tasks": tasks, "binding": document}),
            "non_owner": "allowed",
            "owner": "allowed",
            "record_count": document["resource"]["record_count"],
            "sha256": document["resource"]["sha256"],
            "source_binding": {
                "operation_job_id": job_id,
                "evidence_digest": content_hash({"tasks": tasks, "binding": document}),
            },
        }
        if historical
        else _baseline(document)
    )
    mechanism = FileAccessReadMechanism.from_verified_binding(verified, baseline=baseline)
    control = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": owner_id,
        "enrollment_id": document["enrollment_id"],
        "revision": document["control_revision"],
        "status": "baseline_verified" if historical else "hardened",
        "binding": document,
        "binding_digest": content_hash(document),
        "source": source,
        "baseline": baseline,
    }
    control_record = {
        "job_id": job_id,
        "document": control,
        "document_digest": content_hash(control),
    }
    outcome = {
        "state": "complete",
        "evidence_digest": content_hash(tasks),
        "control_digest": control_record["document_digest"],
    }
    if historical:
        outcome["verified_observation"] = control_observation(
            "baseline", tasks, binding=document, now_ms=1_000_002
        )
    operation_records = {
        "document": {
            "submitted_request": submitted,
            "review": review,
            "review_context": review_context,
            "enrollment_digest": document["enrollment_digest"],
            "created_at_ms": 998_000,
        },
        "control_owner_id": owner_id,
        "preparation": {
            "schema_version": "bluefire.file-access-operation-preparation.v1",
            "job_id": job_id,
            "run_id": run_id,
            "context_digest": review["context_digest"],
            "enrollment_digest": document["enrollment_digest"],
            "recipe": rows,
            "plan": {
                "schema_version": "bluefire.execution-plan.v1",
                "scenario_id": "scenario.file-access-control-" + operation + ".v1",
                "objective": "reviewed file access",
                "mode": "execute",
                "ai_enabled": False,
                "autonomy": "off",
                "ai_provider": {},
                "runner_profile_id": "profile-test",
                "scenario_digest": _digest("e"),
                "steps": [
                    {
                        "step_id": row["step_id"],
                        "behavior_id": row["behavior_id"],
                        "action_id": row["action_id"],
                        "parameters": row["parameters"],
                        "inputs": {},
                    }
                    for row in rows
                ],
                "edges": [],
            },
            "source": source,
            "prior": previous,
            "target_binding": document,
            "target_binding_digest": content_hash(document),
            "revision": document["control_revision"],
            "roots": {key: profile["sandbox_root"] for key, profile in profiles.items()},
            "profiles": profiles,
            "profile_document": {},
            "approval": {"approved_by": "test operator"},
        },
        "tasks": tasks,
        "outcome": outcome,
        "outcome_digest": content_hash(outcome),
    }
    snapshot = FileAccessTargetSnapshot.from_controller_records(
        verified,
        mechanism=mechanism,
        control_record=control_record,
        operation_records=operation_records,
        phase=phase,
    )
    return snapshot, mechanism, verified, control_record, operation_records


@pytest.mark.parametrize("phase", [HISTORICAL_BASELINE, CURRENT_HARDENED])
def test_controller_records_replay_exact_native_recipe(phase: str) -> None:
    snapshot, mechanism, verified, control_record, records = _controller_case(phase)
    assert snapshot.to_dict()["mode"] == ("0640" if phase == HISTORICAL_BASELINE else "0600")
    snapshot.matches_control_revision(control_record, mechanism=mechanism, binding=verified)
    snapshot.matches_operation_records(records, binding=verified)


@pytest.mark.parametrize(
    ("phase", "change"),
    [
        (HISTORICAL_BASELINE, "one_task"),
        (HISTORICAL_BASELINE, "wrong_action"),
        (HISTORICAL_BASELINE, "wrong_uid"),
        (HISTORICAL_BASELINE, "wrong_request"),
        (HISTORICAL_BASELINE, "wrong_terminal"),
        (HISTORICAL_BASELINE, "wrong_observation"),
        (HISTORICAL_BASELINE, "wrong_review_schema"),
        (HISTORICAL_BASELINE, "wrong_review_digest"),
        (HISTORICAL_BASELINE, "wrong_submitted_review"),
        (HISTORICAL_BASELINE, "wrong_enrollment"),
        (HISTORICAL_BASELINE, "wrong_recipe_bool"),
        (CURRENT_HARDENED, "empty_tasks"),
        (CURRENT_HARDENED, "wrong_action"),
        (CURRENT_HARDENED, "wrong_control_digest"),
        (CURRENT_HARDENED, "wrong_chmod_output"),
    ],
)
def test_controller_records_refuse_substituted_originals(phase: str, change: str) -> None:
    snapshot, _, verified, _, source = _controller_case(phase)
    changed = copy.deepcopy(source)
    document = changed["document"]
    tasks = changed["tasks"]
    if change == "one_task":
        changed["tasks"] = tasks[:1]
    elif change == "empty_tasks":
        changed["tasks"] = []
    elif change == "wrong_action":
        tasks[0]["task"]["manifest"]["action_id"] = "sandbox.cleanup.v1"
    elif change == "wrong_uid":
        tasks[0]["terminal"]["result"]["output"]["observation"]["principal"]["uid"] = 1001
    elif change == "wrong_request":
        tasks[0]["task"]["request_hash"] = _digest("f")
    elif change == "wrong_terminal":
        tasks[0]["terminal"]["task_id"] = "execute-" + "f" * 64
    elif change == "wrong_observation":
        tasks[1]["terminal"]["result"]["output"]["observation"]["resource_id"] = (
            "file-resource-" + "f" * 32
        )
    elif change == "wrong_review_schema":
        document["review"]["schema_version"] = "wrong.v1"
    elif change == "wrong_review_digest":
        document["review"]["review_digest"] = _digest("f")
    elif change == "wrong_submitted_review":
        document["submitted_request"]["review"]["operation"] = "reset"
    elif change == "wrong_enrollment":
        document["enrollment_digest"] = _digest("f")
    elif change == "wrong_recipe_bool":
        changed["preparation"]["recipe"][2]["parameters"]["verify_removal"] = 1
    elif change == "wrong_control_digest":
        document["review"]["control_digest"] = _digest("f")
    elif change == "wrong_chmod_output":
        tasks[0]["terminal"]["result"]["output"]["after_mode"] = "0640"
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_operation_records(changed, binding=verified)


def test_embedded_bool_values_cannot_alias_integer_identities() -> None:
    snapshot, mechanism, verified, control_record, source = _controller_case(HISTORICAL_BASELINE)
    changed_control = copy.deepcopy(control_record)
    changed_control["document"]["binding"]["resource"]["root_inode"] = True
    changed_control["document_digest"] = content_hash(changed_control["document"])
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_control_revision(changed_control, mechanism=mechanism, binding=verified)

    changed = copy.deepcopy(source)
    changed["preparation"]["prior"]["revision"] = True  # Original revision is 1.
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_operation_records(changed, binding=verified)
    changed = copy.deepcopy(source)
    changed["preparation"]["target_binding"]["resource"]["root_inode"] = True
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_operation_records(changed, binding=verified)
    changed = copy.deepcopy(source)
    changed["tasks"][0]["task"]["runner_profile"]["file_access_binding"]["resource"][
        "root_inode"
    ] = True
    with pytest.raises(EngineFileAccessSnapshotError):
        snapshot.matches_operation_records(changed, binding=verified)
