"""Synthetic durable native reads; no file read, runner, or engine is launched."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from typing import Any, Callable

import pytest

from bluefire.engine_attempt_contract import EngineAttemptRecord
from bluefire.engine_file_access_observation import (
    OBSERVATION_SCHEMA,
    PRODUCER,
    EngineFileAccessObservationError,
    project_finalized_file_access_observation,
)
from bluefire.engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.execution_contracts import execution_task_identity
from bluefire.file_access_contract import (
    ACL_ABSENT_DIGEST,
    OWNER_ACTION,
    PROBE_ACTION,
    request_challenge,
    validate_file_access_observation,
    verify_file_access_binding,
)
from bluefire.product_store import ProductStore
from bluefire.product_store_serialization import canonical_json
from bluefire.run_store import RunStore
from bluefire.util import content_hash

CREATED = "2026-11-04T12:00:00Z"
STARTED = "2026-11-04T12:01:00Z"
REQUESTED = "2026-11-04T12:01:10Z"
OBSERVED = "2026-11-04T12:01:11Z"
ENDED = "2026-11-04T12:02:00Z"
FINALIZED = "2026-11-04T12:03:00Z"
NOW_MS = 1793793600000


def _binding(mode: str) -> dict[str, Any]:
    generation = "a" * 32
    root = "/run/bluefire-file-access/data/" + generation
    return {
        "schema_version": "bluefire.file-access-execution.v1",
        "enrollment_id": "file-enrollment-" + "b" * 32,
        "enrollment_digest": content_hash({"enrollment": 1}),
        "expires_at_ms": NOW_MS + 720_000,
        "resource_id": "file-resource-" + "c" * 32,
        "resource_generation": "file-generation-" + generation,
        "control_revision": 2 if mode == "0640" else 3,
        "mode": mode,
        "resource": {
            "root": root,
            "root_device": 4,
            "root_inode": 5,
            "parent_device": 4,
            "parent_inode": 6,
            "device": 4,
            "inode": 7,
            "owner_uid": 1000,
            "group_gid": 1002,
            "sha256": content_hash({"records": 8}),
            "size": 128,
            "record_count": 8,
            "acl_digest": ACL_ABSENT_DIGEST,
            "parent_acl_digest": ACL_ABSENT_DIGEST,
        },
        "worker": {
            "socket_path": "/run/bluefire-file-access/control/" + generation + "/probe.sock",
            "uid": 1002,
            "gid": 1002,
            "pid": 2345,
            "start_ticks": 54321,
            "launch_nonce": "d" * 64,
            "namespaces": {kind: f"{kind}:[1]" for kind in ("mnt", "net", "pid", "ipc")},
        },
    }


def _attempt(snapshot_ref: str, *, role: str) -> EngineAttemptRecord:
    binding = {
        "schema_version": "bluefire.engine-attempt-binding.v1",
        "experiment_id": "experiment-" + "1" * 32,
        "attempt_id": "engine-attempt-" + ("2" if role == "baseline" else "3") * 32,
        "run_id": "run-20261104T120000Z-" + ("4" if role == "baseline" else "5") * 16,
        "role": role,
        "objective_ref": content_hash({"objective": 1}),
        "environment_ref": content_hash({"environment": 1}),
        "target_snapshot_ref": snapshot_ref,
        "scope_ref": content_hash({"scope": 1}),
        "scope_version": "bluefire.engine-capability-delegation.v1",
        "engine_id": "strix",
        "engine_version": "1.0",
        "engine_revision": "a" * 40,
        "engine_package_digest": content_hash({"package": 1}),
        "policy_overlay_digest": content_hash({"policy": 1}),
        "model_provider": "openai",
        "model_id": "test-model",
        "model_data_destination": "local-test",
        "model_authorization_ref": content_hash({"authorization": 1}),
        "wall_clock_seconds": 120,
        "action_limit": 4,
        "cost_limit_microunits": 0,
        "artifact_byte_limit": 4096,
        "created_at": CREATED,
        "parent_attempt_id": None if role == "baseline" else "engine-attempt-" + "2" * 32,
    }
    return EngineAttemptRecord.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt.v1",
            "binding": binding,
            "binding_digest": content_hash(binding),
            "state": "completed",
            "upstream_session_id": "session-1",
            "started_at": STARTED,
            "ended_at": ENDED,
            "exit_code": 0,
            "completeness": "complete",
            "exit_reason": None,
            "limitations": [],
        }
    )


def _case(
    tmp_path,
    *,
    mode: str = "0600",
    reader: str = "non_owner",
    outcome: str = "permission_denied",
    status: str = "success",
    requested_at: str = REQUESTED,
    native_job: str | None = None,
    closure_state: str = "verified_closed",
    finalize: bool = True,
    evidence_content_change: dict[str, Any] | None = None,
    native_run_override: str | None = None,
    native_action_override: str | None = None,
    attempt_role_override: str | None = None,
    observation_change: Callable[[dict[str, Any]], None] | None = None,
    profile_resource_root_override: str | None = None,
    run_result_change: dict[str, Any] | None = None,
    attempt_state_override: str | None = None,
    prior_control_digest_override: str | None = None,
    prior_mode_override: str | None = None,
):
    binding = _binding(mode)
    verified = verify_file_access_binding(
        binding, expected_document_digest=content_hash(binding), now_ms=NOW_MS
    )
    baseline = {
        "baseline_digest": content_hash({"original read": 1}),
        "non_owner": "allowed",
        "owner": "allowed",
        "record_count": 8,
        "sha256": binding["resource"]["sha256"],
        "source_binding": {
            "operation_job_id": "job-" + "6" * 32,
            "evidence_digest": content_hash({"original read": 1}),
        },
    }
    mechanism = FileAccessReadMechanism.from_verified_binding(verified, baseline=baseline)
    phase = HISTORICAL_BASELINE if mode == "0640" else CURRENT_HARDENED
    source_job = "job-" + ("6" if mode == "0640" else "8") * 32
    control_owner = "job-" + "7" * 32
    prior_control_document = None
    if mode == "0600":
        prior_binding = _binding("0640")
        if prior_mode_override is not None:
            prior_binding["mode"] = prior_mode_override
        prior_control_document = {
            "schema_version": "bluefire.retained-file-control.v1",
            "control_owner_id": control_owner,
            "enrollment_id": prior_binding["enrollment_id"],
            "revision": prior_binding["control_revision"],
            "status": "baseline_verified",
            "binding": prior_binding,
            "binding_digest": content_hash(prior_binding),
            "source": {},
            "baseline": baseline,
        }
    control_document = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": control_owner,
        "enrollment_id": binding["enrollment_id"],
        "revision": binding["control_revision"],
        "status": "baseline_verified" if mode == "0640" else "hardened",
        "binding": binding,
        "binding_digest": content_hash(binding),
        "source": {},
        "baseline": baseline,
    }
    snapshot = FileAccessTargetSnapshot.from_verified_binding(
        verified,
        mechanism=mechanism,
        control_owner_id=control_owner,
        control_digest=content_hash(control_document),
        prior_control_digest=(
            None
            if prior_control_document is None
            else prior_control_digest_override or content_hash(prior_control_document)
        ),
        source_operation_job_id=source_job,
        source_evidence_digest=(
            baseline["baseline_digest"] if mode == "0640" else content_hash({"harden": 1})
        ),
        phase=phase,
    )
    attempt = _attempt(
        snapshot.target_snapshot_ref,
        role=attempt_role_override or ("baseline" if mode == "0640" else "adaptive_search"),
    )
    if attempt_state_override is not None:
        changed = attempt.to_dict()
        changed["state"] = attempt_state_override
        changed["upstream_session_id"] = None
        changed["started_at"] = None
        changed["ended_at"] = None if attempt_state_override == "queued" else ENDED
        changed["exit_code"] = None
        changed["completeness"] = "unknown"
        attempt = EngineAttemptRecord.from_mapping(changed)
    native_job = native_job or "job-" + "9" * 32
    action = native_action_override or (PROBE_ACTION if reader == "non_owner" else OWNER_ACTION)
    step = "probe" if reader == "non_owner" else "owner"
    request_hash = content_hash({"request": reader, "mode": mode})
    manifest = {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": "request-1",
        "run_id": native_run_override or attempt.binding.run_id,
        "step_id": step,
        "behavior_id": action,
        "action_id": action,
        "runner_id": "bluefire-rust-runner.v1",
        "runner_profile_id": "profile-test",
        "platform": "linux",
        "requested_at": requested_at,
        "expires_at": "2026-11-04T12:06:10Z",
        "mode": "execute",
        "policy_digest": content_hash({"runner policy": 1}),
        "request_hash": request_hash,
    }
    profile = {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": "profile-test",
        "runner_id": "bluefire-rust-runner.v1",
        "platform": "linux",
        "policy_digest": manifest["policy_digest"],
        "allowed_actions": [PROBE_ACTION, OWNER_ACTION] if reader == "owner" else [action],
        "file_access_binding": binding,
    }
    if profile_resource_root_override is not None:
        profile["file_access_binding"] = deepcopy(binding)
        profile["file_access_binding"]["resource"]["root"] = profile_resource_root_override
    task_id, transport = execution_task_identity(manifest, profile)
    task = {
        "job_id": native_job,
        "task_id": task_id,
        "step_id": step,
        "request_hash": request_hash,
        "transport_request_hash": transport,
        "manifest": manifest,
        "runner_profile": profile,
    }
    principal = (
        {key: binding["worker"][key] for key in ("uid", "gid", "pid", "start_ticks", "namespaces")}
        if reader == "non_owner"
        else {
            "uid": 1000,
            "gid": 1000,
            "pid": 3456,
            "start_ticks": 65432,
            "namespaces": binding["worker"]["namespaces"],
        }
    )
    challenge = request_challenge(binding, request_hash)
    observation = {
        "schema_version": "bluefire.file-access-observation.v1",
        "reader": reader,
        "request_hash": request_hash,
        "challenge": challenge,
        "binding_digest": content_hash(binding),
        "resource_id": binding["resource_id"],
        "resource_generation": binding["resource_generation"],
        "control_revision": binding["control_revision"],
        "observed_at_ms": int(
            datetime.fromisoformat(OBSERVED.replace("Z", "+00:00")).timestamp() * 1000
        ),
        "outcome": outcome,
        "sha256": binding["resource"]["sha256"] if outcome == "allowed" else None,
        "size": binding["resource"]["size"],
        "record_count": binding["resource"]["record_count"] if outcome == "allowed" else None,
        "mode": mode,
        "principal": principal,
        "resource": {key: value for key, value in binding["resource"].items() if key != "root"}
        | {"mode": mode},
        "closure": {
            "state": "verified_closed",
            "request_hash": request_hash,
            "challenge": challenge,
            "principal_digest": content_hash(principal),
        },
    }
    if observation_change is not None:
        observation_change(observation)
    result = {
        "schema_version": "bluefire.runner-result.v1",
        "request_id": manifest["request_id"],
        "run_id": manifest["run_id"],
        "step_id": step,
        "behavior_id": action,
        "action_id": action,
        "runner_id": manifest["runner_id"],
        "runner_profile_id": manifest["runner_profile_id"],
        "platform": "linux",
        "request_hash": request_hash,
        "policy_digest": manifest["policy_digest"],
        "status": status,
        "output": {"observation": observation},
    }
    preceding_probe = None
    probe_task = probe_terminal = probe_closure = None
    if reader == "owner":
        probe_manifest = {
            **manifest,
            "request_id": "request-probe",
            "step_id": "probe",
            "behavior_id": PROBE_ACTION,
            "action_id": PROBE_ACTION,
            "requested_at": "2026-11-04T12:01:05Z",
            "request_hash": content_hash({"preceding probe": mode}),
        }
        probe_id, probe_transport = execution_task_identity(probe_manifest, profile)
        probe_task = {
            "job_id": native_job,
            "task_id": probe_id,
            "step_id": "probe",
            "request_hash": probe_manifest["request_hash"],
            "transport_request_hash": probe_transport,
            "manifest": probe_manifest,
            "runner_profile": profile,
        }
        probe_observation = deepcopy(observation)
        probe_observation.update(
            reader="non_owner",
            request_hash=probe_manifest["request_hash"],
            challenge=request_challenge(binding, probe_manifest["request_hash"]),
            observed_at_ms=observation["observed_at_ms"] - 3000,
            outcome="allowed" if mode == "0640" else "permission_denied",
            sha256=binding["resource"]["sha256"] if mode == "0640" else None,
            record_count=binding["resource"]["record_count"] if mode == "0640" else None,
            principal={
                key: binding["worker"][key]
                for key in ("uid", "gid", "pid", "start_ticks", "namespaces")
            },
        )
        probe_observation["closure"] = {
            "state": "verified_closed",
            "request_hash": probe_manifest["request_hash"],
            "challenge": probe_observation["challenge"],
            "principal_digest": content_hash(probe_observation["principal"]),
        }
        probe_result = {
            **result,
            "request_id": probe_manifest["request_id"],
            "step_id": "probe",
            "behavior_id": PROBE_ACTION,
            "action_id": PROBE_ACTION,
            "request_hash": probe_manifest["request_hash"],
            "output": {"observation": probe_observation},
        }
        probe_terminal = {
            "task_id": probe_id,
            "request_hash": probe_manifest["request_hash"],
            "result": probe_result,
            "receipt_snapshot": {"documents": {}, "committed": []},
        }
        probe_closure = {
            "task_id": probe_id,
            "request_hash": probe_manifest["request_hash"],
            "terminal_digest": content_hash(probe_result),
            "proof": {
                "state": "verified_closed",
                "binding_digest": content_hash(binding),
                "evidence_digest": content_hash(probe_observation),
            },
        }
        result["output"]["verification"] = {
            "probe_observation_digest": content_hash(probe_observation),
            "observation_digest": content_hash(observation),
            "request_hash": request_hash,
        }
        preceding_probe = {
            "task_id": probe_id,
            "request_hash": probe_manifest["request_hash"],
            "observation_digest": content_hash(probe_observation),
            "closure_digest": content_hash(probe_closure),
        }
    terminal = {
        "task_id": task_id,
        "request_hash": request_hash,
        "result": result,
        "receipt_snapshot": {"documents": {}, "committed": []},
    }
    worker_closure = {
        "task_id": task_id,
        "request_hash": request_hash,
        "terminal_digest": content_hash(result),
        "proof": {
            "state": closure_state,
            "binding_digest": content_hash(binding),
            "evidence_digest": content_hash(observation),
        },
    }
    store = ProductStore(tmp_path / "product.db")
    with store._connection(write=True) as connection:
        if prior_control_document is not None:
            prior_job = baseline["source_binding"]["operation_job_id"]
            connection.execute(
                "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
                "VALUES(?,?,'queued','{}','{}',?,?)",
                (prior_job, "file_access.operation", CREATED, CREATED),
            )
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (
                    prior_job,
                    control_owner,
                    binding["enrollment_id"],
                    "baseline",
                    "{}",
                    content_hash({}),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                (
                    control_owner,
                    prior_control_document["revision"],
                    prior_job,
                    canonical_json(prior_control_document),
                    content_hash(prior_control_document),
                ),
            )
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
            "VALUES(?,?,'queued','{}','{}',?,?)",
            (source_job, "file_access.operation", CREATED, CREATED),
        )
        connection.execute(
            "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
            (
                source_job,
                control_owner,
                binding["enrollment_id"],
                "baseline" if mode == "0640" else "harden",
                "{}",
                content_hash({}),
            ),
        )
        connection.execute(
            "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
            (
                control_owner,
                binding["control_revision"],
                source_job,
                canonical_json(control_document),
                content_hash(control_document),
            ),
        )
        if native_job not in {source_job, baseline["source_binding"]["operation_job_id"]}:
            connection.execute(
                "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
                "VALUES(?,?,'queued','{}','{}',?,?)",
                (native_job, "file_access.operation", CREATED, CREATED),
            )
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (
                    native_job,
                    control_owner,
                    binding["enrollment_id"],
                    "baseline",
                    "{}",
                    content_hash({}),
                ),
            )
        if probe_task is not None and probe_terminal is not None and probe_closure is not None:
            connection.execute(
                "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                (
                    probe_task["task_id"],
                    native_job,
                    "probe",
                    probe_task["request_hash"],
                    canonical_json(probe_task),
                    content_hash(probe_task),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
                (
                    probe_task["task_id"],
                    canonical_json(probe_terminal),
                    content_hash(probe_terminal),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_worker_closures VALUES(?,?,?)",
                (
                    probe_task["task_id"],
                    canonical_json(probe_closure),
                    content_hash(probe_closure),
                ),
            )
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (task_id, native_job, step, request_hash, canonical_json(task), content_hash(task)),
        )
        connection.execute(
            "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
            (task_id, canonical_json(terminal), content_hash(terminal)),
        )
        if reader == "non_owner":
            connection.execute(
                "INSERT INTO file_access_worker_closures VALUES(?,?,?)",
                (task_id, canonical_json(worker_closure), content_hash(worker_closure)),
            )
    assessment = (
        "legitimate_use_succeeded"
        if reader == "owner"
        else "unauthorized_disclosure" if outcome == "allowed" else "authorization_denied"
    )
    content = {
        "schema_version": OBSERVATION_SCHEMA,
        "independent_observation": True,
        "engine_assertion": False,
        "attempt_id": attempt.binding.attempt_id,
        "native_task_id": task_id,
        "native_run_id": manifest["run_id"],
        "native_request_hash": request_hash,
        "native_transport_request_hash": transport,
        "native_terminal_digest": content_hash(terminal),
        "native_observation_digest": content_hash(observation),
        "closure_digest": (
            content_hash(worker_closure)
            if reader == "non_owner"
            else content_hash(observation["closure"])
        ),
        "binding_digest": content_hash(binding),
        "mechanism_ref": mechanism.mechanism_ref,
        "target_snapshot_ref": snapshot.target_snapshot_ref,
        "reader": reader,
        "uid": principal["uid"],
        "outcome": outcome,
        "assessment": assessment,
        "mode": mode,
        "resource_generation": binding["resource_generation"],
        "observed_at_ms": observation["observed_at_ms"],
        "preceding_probe": preceding_probe,
    }
    if evidence_content_change is not None:
        content.update(evidence_content_change)
    evidence = EvidenceRecord.create(
        run_id=attempt.binding.run_id,
        step_id=step,
        behavior_id=action,
        action_id=action,
        provenance=EvidenceProvenance.OBSERVED,
        producer=PRODUCER,
        content=content,
        target_scope_ref=attempt.binding.scope_ref,
        timestamp=OBSERVED,
    )
    runs = RunStore(tmp_path / "runs")
    if finalize:
        result_document = {
            "schema_version": "bluefire.engine-observation-result.v1",
            "status": "completed",
            "experiment_id": attempt.binding.experiment_id,
            "attempt_id": attempt.binding.attempt_id,
            "binding_digest": attempt.binding_digest,
            "target_snapshot_ref": snapshot.target_snapshot_ref,
            "scope_ref": attempt.binding.scope_ref,
            "attempt_state": attempt.state.value,
            "attempt_started_at": STARTED,
            "attempt_ended_at": ENDED,
            "observation_count": 1,
            "observation_evidence_digest": content_hash([evidence.to_dict()]),
        }
        if run_result_change is not None:
            result_document.update(run_result_change)
        runs.publish_finalized_run(
            attempt.binding.run_id,
            created_at=CREATED,
            finalized_at=FINALIZED,
            scenario={
                "schema_version": "bluefire.engine-observation-scenario.v1",
                "experiment_id": attempt.binding.experiment_id,
                "attempt_id": attempt.binding.attempt_id,
                "objective_ref": attempt.binding.objective_ref,
                "environment_ref": attempt.binding.environment_ref,
                "target_snapshot_ref": snapshot.target_snapshot_ref,
                "scope_ref": attempt.binding.scope_ref,
            },
            plan={
                "schema_version": "bluefire.engine-observation-plan.v1",
                "attempt_id": attempt.binding.attempt_id,
                "binding_digest": attempt.binding_digest,
            },
            policy={
                "schema_version": "bluefire.engine-observation-policy.v1",
                "required_provenance": "observed",
                "engine_assertions_admitted": False,
                "target_snapshot_ref": snapshot.target_snapshot_ref,
                "scope_ref": attempt.binding.scope_ref,
            },
            profile={
                "schema_version": "bluefire.engine-observation-profile.v1",
                "controller_attested": True,
            },
            result=result_document,
            evidence=[evidence.to_dict()],
            detections=(),
            replay={},
        )
    args = {
        "tasks": store,
        "runs": runs,
        "attempt": attempt,
        "verified_binding": verified,
        "mechanism": mechanism,
        "snapshot": snapshot,
        "expected_mechanism_ref": mechanism.mechanism_ref,
        "expected_native_job_id": native_job,
        "expected_native_run_id": manifest["run_id"],
        "expected_request_hash": request_hash,
        "task_id": task_id,
        "transport_request_hash": transport,
        "evidence_id": evidence.evidence_id,
    }
    return args, observation


@pytest.mark.parametrize(
    ("mode", "reader", "outcome", "assessment"),
    [
        ("0640", "non_owner", "allowed", "unauthorized_disclosure"),
        ("0600", "non_owner", "permission_denied", "authorization_denied"),
        ("0600", "non_owner", "allowed", "unauthorized_disclosure"),
    ],
)
def test_projects_exact_finalized_native_read(tmp_path, mode, reader, outcome, assessment):
    args, observation = _case(tmp_path, mode=mode, reader=reader, outcome=outcome)
    projected = project_finalized_file_access_observation(**args)
    assert projected["assessment"] == assessment
    assert projected["outcome"] == outcome
    assert projected["mode"] == mode
    assert projected["observed_at_ms"] == observation["observed_at_ms"]
    assert projected["projection_digest"] == content_hash(
        {key: value for key, value in projected.items() if key != "projection_digest"}
    )


@pytest.mark.parametrize("status", ["refused", "failed", "control_blocked"])
def test_refusal_or_job_status_never_proves_denial(tmp_path, status):
    args, _ = _case(tmp_path, status=status)
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_chmod_receipt_cannot_replace_a_native_read(tmp_path):
    args, _ = _case(tmp_path, native_action_override="sandbox.permission.chmod.v1")
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_historical_0640_read_cannot_prove_current_0600_attempt(tmp_path):
    args, _ = _case(
        tmp_path, mode="0640", outcome="allowed", attempt_role_override="adaptive_search"
    )
    saved = args["tasks"].file_access_task_record(
        args["task_id"], args["transport_request_hash"], include_terminal=True
    )
    run = args["runs"].get_run(args["attempt"].binding.run_id, require_finalized=True)
    assert saved["task"]["manifest"]["run_id"] == args["attempt"].binding.run_id
    assert saved["terminal"]["result"]["status"] == "success"
    assert run["evidence"]["records"][0]["evidence_id"] == args["evidence_id"]
    with pytest.raises(EngineFileAccessObservationError, match="target or attempt"):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize(
    "change",
    [
        {"prior_control_digest_override": content_hash({"other baseline control": 1})},
        {"prior_mode_override": "0600"},
    ],
)
def test_hardened_snapshot_requires_exact_prior_0640_revision(tmp_path, change):
    args, _ = _case(tmp_path, **change)
    with pytest.raises(EngineFileAccessObservationError, match="0640 predecessor"):
        project_finalized_file_access_observation(**args)


def test_original_baseline_task_cannot_be_reused_as_fresh_read(tmp_path):
    args, _ = _case(tmp_path, native_job="job-" + "6" * 32)
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize("requested", ["2026-11-04T11:59:59Z", "2026-11-04T12:01:12Z"])
def test_read_must_be_inside_new_attempt_time(tmp_path, requested):
    args, _ = _case(tmp_path, requested_at=requested)
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_worker_closure_must_be_verified_and_exact(tmp_path):
    args, _ = _case(tmp_path, closure_state="not_sent")
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize(
    "change",
    [
        {"engine_assertion": True},
        {"assessment": "unauthorized_disclosure"},
        {"native_request_hash": content_hash({"other request": 1})},
    ],
)
def test_finalized_evidence_must_match_native_read_byte_for_byte(tmp_path, change):
    args, _ = _case(tmp_path, evidence_content_change=change)
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_even_verified_owner_success_cannot_become_engine_attempt_observation(tmp_path):
    args, _ = _case(tmp_path, reader="owner", outcome="allowed")
    task = args["tasks"].file_access_task_record(
        args["task_id"], args["transport_request_hash"], include_terminal=True
    )
    operation = args["tasks"].file_access_operation_records(args["expected_native_job_id"])
    finalized = args["runs"].get_run(args["attempt"].binding.run_id, require_finalized=True)
    assert task["terminal"]["result"]["status"] == "success"
    assert [row["task"]["step_id"] for row in operation["tasks"]] == ["probe", "owner"]
    assert (
        EvidenceRecord.from_mapping(finalized["evidence"]["records"][0]).evidence_id
        == args["evidence_id"]
    )
    for row, reader in zip(operation["tasks"], ("non_owner", "owner"), strict=True):
        validate_file_access_observation(
            row["terminal"]["result"]["output"]["observation"],
            binding=args["verified_binding"].to_dict(),
            request_hash=row["task"]["request_hash"],
            reader=reader,
        )
    with args["tasks"]._connection() as connection:
        closed = connection.execute(
            "SELECT document_json,document_digest FROM file_access_worker_closures WHERE task_id=?",
            (operation["tasks"][0]["task"]["task_id"],),
        ).fetchone()
    assert closed is not None
    closure = json.loads(closed["document_json"])
    assert content_hash(closure) == closed["document_digest"]
    assert closure["proof"]["state"] == "verified_closed"
    assert closure["terminal_digest"] == content_hash(operation["tasks"][0]["terminal"]["result"])
    verification = task["terminal"]["result"]["output"]["verification"]
    assert verification["probe_observation_digest"] == content_hash(
        operation["tasks"][0]["terminal"]["result"]["output"]["observation"]
    )
    with pytest.raises(EngineFileAccessObservationError, match="non-owner native probe"):
        project_finalized_file_access_observation(**args)


def test_wrong_expected_mechanism_and_snapshot_are_rejected(tmp_path):
    args, _ = _case(tmp_path)
    wrong_mechanism = {**args, "expected_mechanism_ref": content_hash({"other": 1})}
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**wrong_mechanism)
    wrong_attempt = {
        **args,
        "attempt": _attempt(content_hash({"other snapshot": 1}), role="adaptive_search"),
    }
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**wrong_attempt)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("expected_native_job_id", "job-" + "e" * 32),
        ("expected_native_run_id", "run-20261104T120100Z-" + "e" * 16),
        ("expected_request_hash", content_hash({"other request": 1})),
    ],
)
def test_pre_dispatch_native_task_reservation_must_match(tmp_path, field, replacement):
    args, _ = _case(tmp_path)
    args[field] = replacement
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("task_id", "execute-" + "e" * 64),
        ("transport_request_hash", content_hash({"other transport": 1})),
    ],
)
def test_reopened_task_requires_exact_id_and_full_transport_hash(tmp_path, field, replacement):
    args, _ = _case(tmp_path)
    args[field] = replacement
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_native_task_cannot_be_imported_from_another_run(tmp_path):
    args, _ = _case(
        tmp_path,
        native_run_override="run-20261104T120100Z-" + "e" * 16,
    )
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_finalized_run_and_exact_evidence_are_required(tmp_path):
    args, _ = _case(tmp_path, finalize=False)
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)
    args, _ = _case(tmp_path / "other")
    missing = {**args, "evidence_id": "evidence-" + "f" * 20}
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**missing)


def _change_uid(row: dict[str, Any]) -> None:
    row["principal"]["uid"] = 1001
    row["closure"]["principal_digest"] = content_hash(row["principal"])


def _change_inode(row: dict[str, Any]) -> None:
    row["resource"]["inode"] += 1


@pytest.mark.parametrize("change", [_change_uid, _change_inode])
def test_native_uid_and_resource_identity_cannot_be_resealed(tmp_path, change):
    args, _ = _case(tmp_path, observation_change=change)
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


def test_native_task_profile_cannot_target_another_path(tmp_path):
    args, _ = _case(tmp_path, profile_resource_root_override="/tmp/other-resource")
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize("state", ["queued", "failed"])
def test_nonterminal_or_never_started_attempt_has_no_read_proof(tmp_path, state):
    args, _ = _case(tmp_path, attempt_state_override=state)
    with pytest.raises(EngineFileAccessObservationError, match="target or attempt"):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize("change", [{"independent_observation": 1}, {"engine_assertion": 0}])
def test_rehashed_bool_as_int_evidence_is_not_canonical(tmp_path, change):
    args, _ = _case(tmp_path, evidence_content_change=change)
    with pytest.raises(EngineFileAccessObservationError, match="finalized evidence differs"):
        project_finalized_file_access_observation(**args)


def test_rehashed_boolean_run_count_is_not_an_integer(tmp_path):
    args, _ = _case(tmp_path, run_result_change={"observation_count": True})
    with pytest.raises(EngineFileAccessObservationError, match="finalized run differs"):
        project_finalized_file_access_observation(**args)


def test_boolean_native_observation_time_is_rejected(tmp_path):
    args, _ = _case(tmp_path, observation_change=lambda row: row.update(observed_at_ms=True))
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)


@pytest.mark.parametrize(
    "change",
    [
        {"attempt_id": "engine-attempt-" + "e" * 32},
        {"target_snapshot_ref": content_hash({"other target": 1})},
        {"status": "failed"},
    ],
)
def test_finalized_run_metadata_must_match_attempt(tmp_path, change):
    args, _ = _case(tmp_path, run_result_change=change)
    with pytest.raises(EngineFileAccessObservationError, match="finalized run differs"):
        project_finalized_file_access_observation(**args)


def test_denial_cannot_claim_file_contents_or_owner_success(tmp_path):
    args, observation = _case(tmp_path)
    bad = deepcopy(observation)
    bad["sha256"] = args["verified_binding"].to_dict()["resource"]["sha256"]
    with pytest.raises(ValueError):
        validate_file_access_observation(
            bad,
            binding=args["verified_binding"].to_dict(),
            request_hash=observation["request_hash"],
            reader="non_owner",
        )
    args, _ = _case(tmp_path / "owner", reader="owner", outcome="permission_denied")
    with pytest.raises(EngineFileAccessObservationError):
        project_finalized_file_access_observation(**args)
