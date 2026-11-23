"""Read-only, selected-run S3 facts joined to their retained workflow phases."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Sequence

from .product_store_errors import ProductStoreError
from .run_store import RunStoreError
from .s3_access_contract import S3AccessError
from .s3_access_executor import validate_execution
from .s3_access_results import job_id
from .s3_access_wire import S3WorkerRequest
from .util import canonical_json_bytes, content_hash

if TYPE_CHECKING:
    from .s3_access_jobs import S3AccessJobs

SCHEMA = "bluefire.s3-access-comparison.v1"
PROOF = "saved_read_results_only"
PHASES = ("baseline", "retest")
READERS = {"probe_read": "probe", "legitimate_read": "legitimate"}
ROWS = (("probe", "primary"), ("legitimate", "primary"), ("legitimate", "health"))


class _Unavailable(ValueError):
    pass


def _require(value: Any) -> None:
    if not value:
        raise _Unavailable("saved_binding_invalid")


def _is_s3(snapshot: Mapping[str, Any]) -> bool:
    plan = snapshot.get("plan")
    return (
        snapshot.get("scenario_id") == "bluefire.s3-access"
        or any(key in snapshot for key in ("s3_workflow_job_id", "s3_execution"))
        or isinstance(plan, Mapping)
        and plan.get("schema_version") == "bluefire.s3-operation-plan.v1"
    )


def project_s3_access(
    snapshots: Sequence[Mapping[str, Any]], jobs: S3AccessJobs | None
) -> Mapping[str, Any] | None:
    """Never discover a host, read current authority, or adopt a missing result."""
    if not any(_is_s3(row) for row in snapshots):
        return None
    try:
        if not all(_is_s3(row) for row in snapshots):
            raise _Unavailable("mixed_selection")
        if jobs is None:
            raise _Unavailable("saved_context_unavailable")
        before = _selected_sources(snapshots, jobs)
        answer = _project(before)
        # Recheck the selected immutable join, not the owner's growing history.
        after = _selected_sources(snapshots, jobs)
        _require(canonical_json_bytes(before) == canonical_json_bytes(after))
        return answer
    except _Unavailable as exc:
        reason = str(exc)
    except (
        S3AccessError,
        ProductStoreError,
        RunStoreError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ):
        reason = "saved_binding_invalid"
    return {
        "schema_version": SCHEMA,
        "state": "unavailable",
        "reason": reason,
        "proof_scope": PROOF,
    }


def _selected_sources(snapshots: Sequence[Mapping[str, Any]], jobs: S3AccessJobs) -> dict[str, Any]:
    owners = {job_id(row["s3_workflow_job_id"]) for row in snapshots}
    if len(owners) != 1:
        raise _Unavailable("incompatible_context")
    owner_id = next(iter(owners))
    try:
        owner, history = jobs.retained_operations(owner_id)
    except ProductStoreError:
        raise _Unavailable("saved_context_unavailable") from None
    environment = owner["request"]["environment"]
    runtime = owner["request"]["runtime"]
    selected = []
    phases: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        run_id = snapshot["run_id"]
        plan = snapshot["plan"]
        _require(set(plan) == {"schema_version", "request"})
        _require(plan["schema_version"] == "bluefire.s3-operation-plan.v1")
        request = S3WorkerRequest.from_mapping(plan["request"])
        raw = request.to_dict()
        _require(raw == plan["request"] and request.digest == snapshot["s3_request_digest"])
        execution = validate_execution(request, snapshot["s3_execution"])
        _require(execution == snapshot["s3_execution"])
        if raw["operation"] not in READERS:
            raise _Unavailable("unsupported_operation")
        matches = [
            (row, requests, index)
            for row, requests in history
            for index, saved_id in enumerate(row["run_ids"])
            if saved_id == run_id
        ]
        _require(len(matches) == 1)
        row, requests, index = matches[0]
        phase, operation_id = row["phase"], row["operation_job_id"]
        if phase not in PHASES:
            raise _Unavailable("unsupported_operation")
        _require(
            operation_id == snapshot["s3_operation_job_id"]
            and requests[index].to_dict() == raw
            and row["executions"][index] == execution
            and raw["scope"] == environment["scope"]
            and raw["runtime_digest"] == runtime["runtime_digest"]
            and raw["worker_generation"] == runtime["worker_generation"]
            and snapshot["profile"] == {"id": runtime["runner_profile_id"]}
            and snapshot["policy"]
            == {"scope_digest": raw["scope_digest"], "review_digest": row["review_digest"]}
        )
        # The generic reader already verified this bundle. A later store read must
        # still be integrity-valid and byte-equivalent to that exact snapshot.
        _require(jobs.runs.validate_bundle(run_id).get("valid") is True)
        _require(canonical_json_bytes(jobs.runs.get_run(run_id)) == canonical_json_bytes(snapshot))
        _require(jobs.runs.validate_bundle(run_id).get("valid") is True)
        recorded = [
            READERS[item.to_dict()["operation"]] for item in requests[: len(row["run_ids"])]
        ]
        _require(len(recorded) == len(set(recorded)))
        phase_identity = {"operation_job_id": operation_id, "recorded_readers": sorted(recorded)}
        if phase in phases and phases[phase] != phase_identity:
            raise _Unavailable("ambiguous_phase")
        phases[phase] = phase_identity
        selected.append(
            {
                "run_id": run_id,
                "operation_job_id": operation_id,
                "phase": phase,
                "reader": READERS[raw["operation"]],
                "scope_digest": raw["scope_digest"],
                "request_digest": request.digest,
                "review_digest": row["review_digest"],
                "execution_digest": content_hash(execution),
                "execution": execution,
            }
        )
    if len({(row["phase"], row["reader"]) for row in selected}) != len(selected):
        raise _Unavailable("ambiguous_phase")
    if len({row["execution"]["provenance"] for row in selected}) != 1:
        raise _Unavailable("incompatible_context")
    if len({row["scope_digest"] for row in selected}) != 1:
        raise _Unavailable("incompatible_context")
    return {
        "workflow_job_id": owner_id,
        "scope_digest": selected[0]["scope_digest"],
        "environment_digest": content_hash(environment),
        "runtime_digest": content_hash(runtime),
        "phases": phases,
        "selected": sorted(selected, key=lambda row: (row["phase"], row["reader"])),
    }


def _project(source: Mapping[str, Any]) -> dict[str, Any]:
    selected = {(row["phase"], row["reader"]): row for row in source["selected"]}
    phases: dict[str, Any] = {}
    gaps = []
    for phase in PHASES:
        identity = source["phases"].get(phase)
        if identity is None:
            phases[phase] = None
            continue
        rows = [
            selected[(phase, reader)]
            for reader in ("probe", "legitimate")
            if (phase, reader) in selected
        ]
        complete = len(rows) == 2
        phases[phase] = {
            "operation_job_id": identity["operation_job_id"],
            "run_ids": [row["run_id"] for row in rows],
            "selection_complete": complete,
            "observation_complete": complete and all(_observed(row) for row in rows),
            "cleanup": (
                "verified"
                if complete and all(row["execution"]["cleanup"] == "verified" for row in rows)
                else "unknown"
            ),
        }
    for phase in PHASES:
        if phases[phase] is None:
            gaps.append(phase + "_missing")
    for phase in PHASES:
        if phases[phase] is not None and not phases[phase]["selection_complete"]:
            gaps.append(phase + "_selection_incomplete")
    for phase in PHASES:
        if phases[phase] is not None and not phases[phase]["observation_complete"]:
            gaps.append(phase + "_observations_incomplete")
    if any(row["execution"]["cleanup"] != "verified" for row in source["selected"]):
        gaps.append("cleanup_unresolved")
    paired = not gaps
    state = (
        "retest_only"
        if phases["baseline"] is None
        else "baseline_only" if phases["retest"] is None else "paired" if paired else "partial"
    )
    rows = []
    for reader, purpose in ROWS:
        baseline = _cell(source, selected, "baseline", reader, purpose)
        retest = _cell(source, selected, "retest", reader, purpose)
        rows.append(
            {
                "reader": reader,
                "purpose": purpose,
                "baseline": baseline,
                "retest": retest,
                "changed": baseline["state"] != retest["state"] if paired else None,
            }
        )
    bindings = [
        {key: value for key, value in row.items() if key != "execution"}
        for row in source["selected"]
    ]
    source_digest = content_hash(
        {
            "workflow_job_id": source["workflow_job_id"],
            "scope_digest": source["scope_digest"],
            "environment_digest": source["environment_digest"],
            "runtime_digest": source["runtime_digest"],
            "selected": bindings,
        }
    )
    return {
        "schema_version": SCHEMA,
        "state": state,
        "workflow_job_id": source["workflow_job_id"],
        "scope_digest": source["scope_digest"],
        "source_digest": source_digest,
        "baseline": phases["baseline"],
        "retest": phases["retest"],
        "rows": rows,
        "change_state": (
            "unknown"
            if not paired
            else "changed" if any(row["changed"] for row in rows) else "unchanged"
        ),
        "gaps": gaps,
        "proof_scope": PROOF,
        "effective_access_claim": False,
        "defensive_effectiveness_claim": False,
    }


def _observed(row: Mapping[str, Any]) -> bool:
    execution = row["execution"]
    return bool(
        execution["admission"]["accepted"]
        and execution["result"] is not None
        and execution["result"]["outcome"] == "observed"
    )


def _cell(source, selected, phase: str, reader: str, purpose: str) -> dict[str, Any]:
    row = selected.get((phase, reader))
    if row is None:
        recorded = source["phases"].get(phase, {}).get("recorded_readers", [])
        return {
            "run_id": None,
            "state": "not_selected" if reader in recorded else "not_recorded",
            "provenance": None,
            "cleanup": None,
        }
    execution = row["execution"]
    state = "unreported"
    if _observed(row):
        objects = execution["result"]["data"]["objects"]
        matches = [item["result"] for item in objects if item["purpose"] == purpose]
        _require(len(matches) == 1)
        state = matches[0]
    return {
        "run_id": row["run_id"],
        "state": state,
        "provenance": execution["provenance"],
        "cleanup": execution["cleanup"],
    }
