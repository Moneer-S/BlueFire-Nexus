"""Fail-closed projection of a native Linux file read into engine evidence.

The caller must first obtain the binding and snapshot through the controller's
stored-control and live-enrollment guard. This module dispatches no read and
grants no authority. It reopens the original native task and a finalized run;
engine reports, permission-change receipts, refusals, and exit codes are never
substitutes for the native read observation.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .engine_attempt_contract import AttemptRole, AttemptState, EngineAttemptRecord
from .engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
)
from .evidence import EvidenceProvenance, EvidenceRecord
from .file_access_contract import (
    PROBE_ACTION,
    VerifiedFileAccessBinding,
    canonical_file_access_binding,
    validate_file_access_observation,
)
from .product_store_file_access_records import _document
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

OBSERVATION_SCHEMA = "bluefire.engine-file-access-observation.v1"
PRODUCER = "observer.file-access-native.v1"
_EVIDENCE_ID = re.compile(r"evidence-[0-9a-f]{20}\Z")
_JOB_ID = re.compile(r"job-[0-9a-f]{32}\Z")
_RUN_ID = re.compile(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TERMINAL = frozenset(
    {
        AttemptState.COMPLETED,
        AttemptState.PARTIAL,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.BUDGET_EXHAUSTED,
        AttemptState.UNKNOWN,
    }
)


class EngineFileAccessObservationError(ValueError):
    """The exact independently observed file read is unavailable."""


class NativeTaskSource(Protocol):
    """Read-only portion of ProductStore used by this projection."""

    def file_access_task_record(
        self, task_id: str, transport_request_hash: str, *, include_terminal: bool = True
    ) -> Mapping[str, Any]: ...

    def _connection(self, *, write: bool = False) -> Any: ...

    def get_linux_file_access_revision_record(
        self, owner_id: str, revision: int
    ) -> Mapping[str, Any]: ...

    def file_access_operation_records(self, job_id: str) -> Mapping[str, Any]: ...


class FinalizedRunSource(Protocol):
    """Read-only portion of RunStore used by this projection."""

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]: ...


def project_finalized_file_access_observation(
    *,
    tasks: NativeTaskSource,
    runs: FinalizedRunSource,
    attempt: EngineAttemptRecord,
    verified_binding: VerifiedFileAccessBinding,
    mechanism: FileAccessReadMechanism,
    snapshot: FileAccessTargetSnapshot,
    expected_mechanism_ref: str,
    expected_native_job_id: str,
    expected_native_run_id: str,
    expected_request_hash: str,
    task_id: str,
    transport_request_hash: str,
    evidence_id: str,
) -> dict[str, Any]:
    """Reopen exact native and finalized-run records and derive one read outcome.

    Expected refs must come from the saved experiment and its pre-dispatch
    attempt-owned native task reservation, not from the submitted observation.
    The attempt binding supplies the target snapshot and run references. A new
    native task must occur within that attempt; the historical source is excluded.
    """

    try:
        return _project(
            tasks=tasks,
            runs=runs,
            attempt=attempt,
            verified_binding=verified_binding,
            mechanism=mechanism,
            snapshot=snapshot,
            expected_mechanism_ref=expected_mechanism_ref,
            expected_native_job_id=expected_native_job_id,
            expected_native_run_id=expected_native_run_id,
            expected_request_hash=expected_request_hash,
            task_id=task_id,
            transport_request_hash=transport_request_hash,
            evidence_id=evidence_id,
        )
    except EngineFileAccessObservationError:
        raise
    except Exception:
        # Nested task/runner/store exceptions may contain protected paths.
        raise EngineFileAccessObservationError(
            "exact file-access observation evidence is unavailable"
        ) from None


def _project(
    *,
    tasks: NativeTaskSource,
    runs: FinalizedRunSource,
    attempt: EngineAttemptRecord,
    verified_binding: VerifiedFileAccessBinding,
    mechanism: FileAccessReadMechanism,
    snapshot: FileAccessTargetSnapshot,
    expected_mechanism_ref: str,
    expected_native_job_id: str,
    expected_native_run_id: str,
    expected_request_hash: str,
    task_id: str,
    transport_request_hash: str,
    evidence_id: str,
) -> dict[str, Any]:
    if (
        type(attempt) is not EngineAttemptRecord
        or type(verified_binding) is not VerifiedFileAccessBinding
        or type(mechanism) is not FileAccessReadMechanism
        or type(snapshot) is not FileAccessTargetSnapshot
        or not isinstance(expected_mechanism_ref, str)
        or expected_mechanism_ref != mechanism.mechanism_ref
        or not isinstance(expected_native_job_id, str)
        or _JOB_ID.fullmatch(expected_native_job_id) is None
        or not isinstance(expected_native_run_id, str)
        or _RUN_ID.fullmatch(expected_native_run_id) is None
        or not isinstance(expected_request_hash, str)
        or _DIGEST.fullmatch(expected_request_hash) is None
        or not isinstance(evidence_id, str)
        or _EVIDENCE_ID.fullmatch(evidence_id) is None
    ):
        raise EngineFileAccessObservationError("observation owner or source identity is invalid")
    checked_attempt = EngineAttemptRecord.from_mapping(attempt.to_dict())
    owner = checked_attempt.binding
    source = canonical_file_access_binding(verified_binding.to_dict())
    checked_mechanism = FileAccessReadMechanism.from_mapping(mechanism.to_dict())
    checked_snapshot = FileAccessTargetSnapshot.from_mapping(snapshot.to_dict())
    checked_mechanism.matches_verified_binding(verified_binding)
    checked_snapshot.matches_mechanism(checked_mechanism)
    checked_snapshot.matches_verified_binding(verified_binding)
    target = checked_snapshot.to_dict()
    control = _mapping(
        tasks.get_linux_file_access_revision_record(
            target["control_owner_id"], target["control_revision"]
        )
    )
    checked_snapshot.matches_control_revision(
        control, mechanism=checked_mechanism, binding=verified_binding
    )
    if target["phase"] == CURRENT_HARDENED:
        _verify_prior_baseline_revision(
            tasks=tasks,
            target=target,
            mechanism=checked_mechanism,
            current_binding=source,
        )
    if owner.role not in {AttemptRole.BASELINE, AttemptRole.ADAPTIVE_SEARCH}:
        raise EngineFileAccessObservationError("file-access attempt role is unsupported")
    expected_phase = HISTORICAL_BASELINE if owner.role is AttemptRole.BASELINE else CURRENT_HARDENED
    if (
        owner.target_snapshot_ref != checked_snapshot.target_snapshot_ref
        or expected_native_run_id != owner.run_id
        or target["phase"] != expected_phase
        or checked_attempt.state not in _TERMINAL
        or checked_attempt.started_at is None
        or checked_attempt.ended_at is None
    ):
        raise EngineFileAccessObservationError("observation target or attempt is unavailable")
    started = parse_iso8601_datetime(checked_attempt.started_at)
    ended = parse_iso8601_datetime(checked_attempt.ended_at)
    created = parse_iso8601_datetime(owner.created_at)
    if not created <= started <= ended:
        raise EngineFileAccessObservationError("observation attempt time is invalid")

    saved = tasks.file_access_task_record(task_id, transport_request_hash, include_terminal=True)
    native_operation = _mapping(tasks.file_access_operation_records(expected_native_job_id))
    if native_operation.get("control_owner_id") != target["control_owner_id"]:
        raise EngineFileAccessObservationError("native task belongs to another retained control")
    task = _exact(
        saved.get("task"),
        {
            "job_id",
            "task_id",
            "step_id",
            "request_hash",
            "transport_request_hash",
            "manifest",
            "runner_profile",
        },
    )
    terminal = _exact(
        saved.get("terminal"), {"task_id", "request_hash", "result", "receipt_snapshot"}
    )
    manifest = _mapping(task["manifest"])
    profile = _mapping(task["runner_profile"])
    allowed_actions = profile.get("allowed_actions")
    result = _mapping(terminal["result"])
    action = manifest.get("action_id")
    reader = "non_owner"
    if action != PROBE_ACTION:
        raise EngineFileAccessObservationError(
            "engine-attempt observation requires the non-owner native probe"
        )
    if (
        task["task_id"] != task_id
        or task["transport_request_hash"] != transport_request_hash
        or saved.get("document_digest") != content_hash(task)
        or terminal["task_id"] != task_id
        or terminal["request_hash"] != task["request_hash"]
        or task["job_id"] != expected_native_job_id
        or manifest.get("run_id") != expected_native_run_id
        or task["request_hash"] != expected_request_hash
        or manifest.get("request_hash") != task["request_hash"]
        or manifest.get("step_id") != task["step_id"]
        or manifest.get("mode") != "execute"
        or manifest.get("platform") != "linux"
        or task["job_id"]
        in (target["source"]["job_id"], checked_mechanism.to_dict()["original_read_job_id"])
        or profile.get("platform") != "linux"
        or canonical_json_bytes(profile.get("file_access_binding")) != canonical_json_bytes(source)
        or not isinstance(allowed_actions, list)
        or action not in allowed_actions
        or manifest.get("runner_profile_id") != profile.get("profile_id")
        or manifest.get("runner_id") != profile.get("runner_id")
        or manifest.get("policy_digest") != profile.get("policy_digest")
    ):
        raise EngineFileAccessObservationError("native read task differs from its attempt")
    requested = parse_iso8601_datetime(manifest["requested_at"])
    expires = parse_iso8601_datetime(manifest["expires_at"])
    observed_raw = _mapping(_mapping(result.get("output")).get("observation"))
    observation = validate_file_access_observation(
        observed_raw, binding=source, request_hash=task["request_hash"], reader=reader
    )
    observed = datetime.fromtimestamp(observation["observed_at_ms"] / 1000, timezone.utc)
    if not started <= requested <= observed <= ended or not observed < expires:
        raise EngineFileAccessObservationError("native read is outside the fresh attempt")
    expected_result = {
        "schema_version": "bluefire.runner-result.v1",
        "request_id": manifest.get("request_id"),
        "run_id": manifest.get("run_id"),
        "step_id": manifest.get("step_id"),
        "behavior_id": manifest.get("behavior_id"),
        "action_id": action,
        "runner_id": manifest.get("runner_id"),
        "runner_profile_id": manifest.get("runner_profile_id"),
        "platform": "linux",
        "request_hash": task["request_hash"],
        "policy_digest": profile.get("policy_digest"),
        "status": "success",
    }
    if any(value is None or result.get(key) != value for key, value in expected_result.items()):
        raise EngineFileAccessObservationError("native runner result is not an authenticated read")

    closure_digest = _reopen_worker_closure(
        tasks, task_id, task["request_hash"], result, source, observation
    )
    assessment = _assessment(observation["outcome"])
    expected_content = {
        "schema_version": OBSERVATION_SCHEMA,
        "independent_observation": True,
        "engine_assertion": False,
        "attempt_id": owner.attempt_id,
        "native_task_id": task_id,
        "native_run_id": manifest["run_id"],
        "native_request_hash": task["request_hash"],
        "native_transport_request_hash": transport_request_hash,
        "native_terminal_digest": content_hash(terminal),
        "native_observation_digest": content_hash(observation),
        "closure_digest": closure_digest,
        "binding_digest": content_hash(source),
        "mechanism_ref": expected_mechanism_ref,
        "target_snapshot_ref": owner.target_snapshot_ref,
        "reader": reader,
        "uid": observation["principal"]["uid"],
        "outcome": observation["outcome"],
        "assessment": assessment,
        "mode": observation["mode"],
        "resource_generation": observation["resource_generation"],
        "observed_at_ms": observation["observed_at_ms"],
        "preceding_probe": None,
    }
    run = _mapping(runs.get_run(owner.run_id, require_finalized=True))
    if run.get("run_id") != owner.run_id:
        raise EngineFileAccessObservationError("finalized observation run identity changed")
    _verify_run_binding(run, checked_attempt, observed)
    evidence = _find_evidence(run, evidence_id)
    if (
        evidence.run_id != owner.run_id
        or evidence.provenance is not EvidenceProvenance.OBSERVED
        or evidence.producer != PRODUCER
        or evidence.target_scope_ref != owner.scope_ref
        or evidence.action_id != action
        or evidence.step_id != task["step_id"]
        or evidence.behavior_id != manifest.get("behavior_id")
        or canonical_json_bytes(evidence.content) != canonical_json_bytes(expected_content)
        or parse_iso8601_datetime(evidence.timestamp) != observed
    ):
        raise EngineFileAccessObservationError("finalized evidence differs from the native read")
    projection = {
        "schema_version": "bluefire.engine-file-access-observation-projection.v1",
        "attempt_id": owner.attempt_id,
        "run_id": owner.run_id,
        "target_snapshot_ref": owner.target_snapshot_ref,
        "mechanism_ref": expected_mechanism_ref,
        "evidence_id": evidence_id,
        "record_hash": evidence.record_hash,
        "native_task_id": task_id,
        "native_request_hash": task["request_hash"],
        "reader": reader,
        "outcome": observation["outcome"],
        "assessment": assessment,
        "mode": observation["mode"],
        "observed_at_ms": observation["observed_at_ms"],
    }
    projection["projection_digest"] = content_hash(projection)
    return projection


def _reopen_worker_closure(
    tasks: NativeTaskSource,
    task_id: str,
    request_hash: str,
    result: Mapping[str, Any],
    binding: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> str:
    with tasks._connection() as connection:
        row = connection.execute(
            "SELECT document_json, document_digest FROM file_access_worker_closures "
            "WHERE task_id=? AND length(CAST(document_json AS BLOB)) BETWEEN 1 AND 16384",
            (task_id,),
        ).fetchone()
        closure = _exact(_document(row), {"task_id", "request_hash", "terminal_digest", "proof"})
        digest = row["document_digest"]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise EngineFileAccessObservationError("native worker closure digest is invalid")
    proof = _exact(closure["proof"], {"state", "binding_digest", "evidence_digest"})
    if (
        closure["task_id"] != task_id
        or closure["request_hash"] != request_hash
        or closure["terminal_digest"] != content_hash(result)
        or proof
        != {
            "state": "verified_closed",
            "binding_digest": content_hash(binding),
            "evidence_digest": content_hash(observation),
        }
    ):
        raise EngineFileAccessObservationError("native worker closure is unresolved")
    return digest


def _verify_prior_baseline_revision(
    *,
    tasks: NativeTaskSource,
    target: Mapping[str, Any],
    mechanism: FileAccessReadMechanism,
    current_binding: Mapping[str, Any],
) -> None:
    revision = target["control_revision"]
    if type(revision) is not int or revision < 2:
        raise EngineFileAccessObservationError("hardened control lacks a baseline predecessor")
    prior = _exact(
        tasks.get_linux_file_access_revision_record(target["control_owner_id"], revision - 1),
        {"job_id", "document", "document_digest"},
    )
    document = _mapping(prior["document"])
    binding = canonical_file_access_binding(document["binding"])
    expected_binding = dict(current_binding)
    expected_binding["control_revision"] = revision - 1
    expected_binding["mode"] = "0640"
    baseline = _mapping(document.get("baseline"))
    original = mechanism.to_dict()
    source = _mapping(baseline.get("source_binding"))
    if (
        prior["document_digest"] != target["prior_control_digest"]
        or content_hash(document) != target["prior_control_digest"]
        or prior["job_id"] != original["original_read_job_id"]
        or document.get("schema_version") != "bluefire.retained-file-control.v1"
        or document.get("control_owner_id") != target["control_owner_id"]
        or document.get("enrollment_id") != target["enrollment_id"]
        or type(document.get("revision")) is not int
        or document["revision"] != revision - 1
        or document.get("status") != "baseline_verified"
        or binding != expected_binding
        or document.get("binding_digest") != content_hash(binding)
        or baseline.get("baseline_digest") != target["baseline_evidence_digest"]
        or source.get("operation_job_id") != prior["job_id"]
        or source.get("evidence_digest") != target["baseline_evidence_digest"]
    ):
        raise EngineFileAccessObservationError("hardened snapshot lost its 0640 predecessor")


def _verify_run_binding(
    run: Mapping[str, Any], attempt: EngineAttemptRecord, observed: datetime
) -> None:
    owner = attempt.binding
    scenario = _mapping(run.get("scenario"))
    plan = _mapping(run.get("plan"))
    policy = _mapping(run.get("policy"))
    profile = _mapping(run.get("profile"))
    envelope = _exact(run.get("evidence"), {"schema_version", "records"})
    rows = envelope["records"]
    if (
        scenario.get("schema_version") != "bluefire.engine-observation-scenario.v1"
        or scenario.get("experiment_id") != owner.experiment_id
        or scenario.get("attempt_id") != owner.attempt_id
        or scenario.get("objective_ref") != owner.objective_ref
        or scenario.get("environment_ref") != owner.environment_ref
        or scenario.get("target_snapshot_ref") != owner.target_snapshot_ref
        or scenario.get("scope_ref") != owner.scope_ref
        or plan.get("schema_version") != "bluefire.engine-observation-plan.v1"
        or plan.get("attempt_id") != owner.attempt_id
        or plan.get("binding_digest") != owner.binding_digest
        or policy.get("schema_version") != "bluefire.engine-observation-policy.v1"
        or policy.get("required_provenance") != EvidenceProvenance.OBSERVED.value
        or policy.get("engine_assertions_admitted") is not False
        or policy.get("target_snapshot_ref") != owner.target_snapshot_ref
        or policy.get("scope_ref") != owner.scope_ref
        or profile.get("schema_version") != "bluefire.engine-observation-profile.v1"
        or profile.get("controller_attested") is not True
        or not isinstance(rows, list)
        or type(run.get("observation_count")) is not int
        or run.get("observation_count") != len(rows)
        or run.get("observation_evidence_digest") != content_hash(rows)
        or run.get("schema_version") != "bluefire.engine-observation-result.v1"
        or run.get("status") != "completed"
        or run.get("experiment_id") != owner.experiment_id
        or run.get("attempt_id") != owner.attempt_id
        or run.get("binding_digest") != owner.binding_digest
        or run.get("target_snapshot_ref") != owner.target_snapshot_ref
        or run.get("scope_ref") != owner.scope_ref
        or run.get("attempt_state") != attempt.state.value
        or run.get("attempt_started_at") != attempt.started_at
        or run.get("attempt_ended_at") != attempt.ended_at
    ):
        raise EngineFileAccessObservationError("finalized run differs from its attempt binding")
    # RunStore.get_run merges result.json into the top-level run mapping.
    if attempt.ended_at is None:
        raise EngineFileAccessObservationError("observation attempt end is unavailable")
    finalized = parse_iso8601_datetime(run["finalized_at"])
    if finalized < parse_iso8601_datetime(attempt.ended_at) or observed > finalized:
        raise EngineFileAccessObservationError("finalized run predates the independent read")


def _find_evidence(run: Mapping[str, Any], evidence_id: str) -> EvidenceRecord:
    envelope = _exact(run.get("evidence"), {"schema_version", "records"})
    rows = envelope["records"]
    if envelope["schema_version"] != "1.0" or not isinstance(rows, list) or len(rows) > 256:
        raise EngineFileAccessObservationError("finalized evidence envelope is unavailable")
    found: EvidenceRecord | None = None
    seen: set[str] = set()
    for row in rows:
        record = EvidenceRecord.from_mapping(_mapping(row))
        if record.evidence_id in seen:
            raise EngineFileAccessObservationError("finalized run repeats evidence identity")
        seen.add(record.evidence_id)
        if record.evidence_id == evidence_id:
            found = record
    if found is None:
        raise EngineFileAccessObservationError("exact observation is absent from finalized run")
    return found


def _assessment(outcome: str) -> str:
    if outcome == "allowed":
        return "unauthorized_disclosure"
    if outcome == "permission_denied":
        return "authorization_denied"
    raise EngineFileAccessObservationError("native read outcome is unsupported")


def _exact(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineFileAccessObservationError("exact observation document is unavailable")
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EngineFileAccessObservationError("observation document is unavailable")
    return value


__all__ = [
    "EngineFileAccessObservationError",
    "OBSERVATION_SCHEMA",
    "PRODUCER",
    "project_finalized_file_access_observation",
]
