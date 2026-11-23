"""Read-only explanation of retained AD projections, without minting source authority.

Installed execution authenticates and minimizes the original receiver terminal before
recording it. This adapter checks that retained linkage and its run bundles; parsing
saved data or matching a digest does not authenticate a remote principal or receipt.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from . import ad_smb_results as results
from . import product_store_ad_smb as records
from .ad_smb_contract import AdSmbError, exact
from .product_store_assistance import job_at
from .product_store_errors import ProductStoreError
from .run_store import RunStoreError
from .util import canonical_json_bytes, content_hash

KIND = "ad_smb_workflow"
LIMITATIONS = [
    "This explains one exact retained AD workflow snapshot only. It cannot dispatch, read a file, change an ACL, collect audit, recover a task, or grant authority.",
    "Saved runner-reported projections retain their original provenance; digest and task-linkage checks do not authenticate a remote reader or independently verify a receiver result. Synthetic fixtures remain authored evidence.",
    "A reviewed ACL change or matching descriptor readback does not establish effective access. Probe and legitimate-reader outcomes remain separate; no combined prevention claim is made.",
    "Distinct local contexts do not prove a fresh server logon. Remote session closure and authenticated remote-reader identity remain unknown.",
    "Snapshot times are receiver completion times, not native observation times. Reads have no recorded native observation timestamp; request times are not observation times.",
    "Audit completeness is a saved collector assertion. Missing events cannot prove denial; a share access-check event does not prove an NTFS read or returned bytes.",
    "Missing stages, unavailable original results, unknown cleanup, and incomplete audit remain unknown. Later workflow changes refuse this selection; the store does not supply historical snapshots for reopening an older digest.",
]
_ERROR = "The selected saved AD workflow is unavailable or changed."
_JOB = re.compile(r"job-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _require(condition: bool) -> None:
    if not condition:
        raise ProductStoreError(_ERROR)


def selection(value: Any) -> dict[str, Any]:
    _require(
        isinstance(value, dict)
        and set(value) == {"kind", "workflow_job_id", "result_digest"}
        and value["kind"] == KIND
        and isinstance(value["workflow_job_id"], str)
        and _JOB.fullmatch(value["workflow_job_id"]) is not None
        and isinstance(value["result_digest"], str)
        and _DIGEST.fullmatch(value["result_digest"]) is not None
    )
    return dict(value)


def _task(request, original, execution):
    row = {
        "step": request["step"],
        "request_digest": content_hash(request),
        "task_id": original["task_id"] if original is not None else None,
        "original_digest": content_hash(original) if original is not None else None,
        "execution_digest": content_hash(execution) if execution is not None else None,
        "requested_at": request["requested_at"],
        "provenance": execution["provenance"] if execution is not None else None,
        "dispatch": execution["dispatch"] if execution is not None else "unknown",
        "cleanup": execution["cleanup"] if execution is not None else "unknown",
        "observation": None,
    }
    observation = execution["observation"] if execution is not None else None
    if observation is None:
        return row
    if request["step"].startswith("read_"):
        keys = (
            "reader",
            "purpose",
            "state",
            "bytes_read",
            "local_cleanup",
            "server_session_closed",
            "authenticated_remote_reader",
            "fresh_server_logon",
            "independent_observation",
            "effective_access_claim",
        )
        row["observation"] = {key: observation[key] for key in keys}
    elif request["step"] == "collect_audit":
        keys = (
            "events",
            "truncated",
            "authenticated_source",
            "independent_observation",
            "effective_access_claim",
        )
        audit = {key: observation[key] for key in keys}
        normalized = observation.get("normalized_observation")
        audit["normalization"] = None
        if normalized is not None:
            audit["normalization"] = {
                key: normalized[key]
                for key in (
                    "capture_state",
                    "window_start",
                    "window_end",
                    "reported_completeness",
                    "input_events",
                    "duplicate_events",
                    "limitations",
                )
            }
            # Only fixed classifications/counts: no XML, host names, SIDs, paths or logon IDs.
            counts = Counter(
                (event["event_id"], event["audit_outcome"], event["binding"])
                for event in normalized["events"]
            )
            audit["normalization"]["classification_counts"] = [
                {"event_id": event, "audit_outcome": outcome, "binding": binding, "count": count}
                for (event, outcome, binding), count in sorted(counts.items())
            ]
        row["observation"] = audit
    else:
        snapshot = observation.get("snapshot")
        row["observation"] = {
            "state": observation.get("state", "inspection_recorded"),
            "receiver_completed_at": snapshot["observed_at"] if snapshot is not None else None,
            "descriptor_digest": (
                content_hash(snapshot["descriptor"]) if snapshot is not None else None
            ),
        }
    return row


def _pending_run(jobs, owner, child):
    """Accept only an untouched retained run, never finalize or recover its terminal."""
    run = child["progress"]["run_id"]
    _require(isinstance(run, str) and child["result_ref"] is None)
    initial = child["progress"]["initial_run"]
    path = jobs.runs._run_path(run, must_exist=True)
    required = {
        *jobs._documents(owner, child),
        "result.json",
        "evidence.json",
        "detections.json",
        "events.jsonl",
    }
    _require({item.name for item in path.iterdir()} == required)
    _require(
        all(
            jobs.runs.read_json(run, key) == value
            for key, value in jobs._documents(owner, child).items()
        )
    )
    _require(jobs.runs.read_json(run, "result.json") == initial["result"])
    _require(jobs.runs.read_events(run) == initial["events"])
    _require(jobs.runs.read_json(run, "evidence.json") == {"schema_version": "1.0", "records": []})
    _require(
        jobs.runs.read_json(run, "detections.json") == {"schema_version": "1.0", "candidates": []}
    )
    return content_hash(initial)


def _capture(jobs, identifier):
    with jobs.store._connection() as connection:
        owner = records.owner_at(jobs.store, connection, identifier)
        progress = owner["progress"]
        _require(
            type(progress["revision"]) is int
            and 0 <= progress["revision"] <= 100
            and type(progress["stopped"]) is bool
            and progress["policy_state"] in {"baseline", "hardened", "unknown"}
        )
        _require(isinstance(progress["operations"], list) and len(progress["operations"]) <= 6)
        operations, bindings, seen = [], [], set()
        saved = progress["operations"]
        pending = progress["pending_operation"]
        identifiers = [row["job_id"] for row in saved] + ([pending] if pending else [])
        _require(bool(identifiers))
        for index, operation_id in enumerate(identifiers):
            _require(operation_id not in seen)
            seen.add(operation_id)
            child = job_at(jobs.store, connection, results.job_id(operation_id))
            records._validate_child(owner, child)
            marker = child["request"]["ad_smb"]
            _require(marker["prior_progress"]["operations"] == saved[:index])
            _require(child["state"] in results.TERMINAL)
            phase = marker["phase"]
            tasks = child["progress"]["tasks"]
            requests = child["request"]["requests"]
            _require(isinstance(tasks, list) and len(tasks) <= len(requests))
            projected, executions = [], []
            resolved = True
            for task_index, request in enumerate(requests):
                task = tasks[task_index] if task_index < len(tasks) else None
                original = execution = None
                if task is not None:
                    exact(task, {"index", "context", "execution", "recovery"}, "AD saved task")
                    _require(type(task["index"]) is int and task["index"] == task_index)
                    original = task["context"]
                    if original is not None:
                        results.original_context(request, original)
                    _require(
                        all(
                            value is None or isinstance(value, dict)
                            for value in (task["execution"], task["recovery"])
                        )
                    )
                    execution = (
                        task["recovery"] if task["recovery"] is not None else task["execution"]
                    )
                    if task["recovery"] is not None and task["execution"] is not None:
                        _require(task["recovery"] == task["execution"])
                    if execution is not None:
                        if execution.get("provenance") == "controller_local":
                            # Reuse the durable controller marker checks rather than trusting a label.
                            records._executions(owner, child)
                        else:
                            execution = results.validate_execution(request, execution)
                            _require(
                                execution["provenance"]
                                == owner["request"]["environment"]["provenance"]
                            )
                        _require(execution["dispatch"] == "not_started" or original is not None)
                        executions.append(execution)
                    else:
                        _require(original is not None)
                resolved = resolved and execution is not None
                projected.append(_task(request, original, execution))
            # A later original task cannot exist past an unresolved terminal checkpoint.
            _require(all(task["execution"] is not None for task in tasks[:-1]))
            outcome = results.outcome(phase, executions, saved[:index])
            if index < len(saved):
                records._executions(owner, child)
                expected = {
                    "job_id": operation_id,
                    "phase": phase,
                    "run_id": child["progress"]["run_id"],
                    "outcome": outcome,
                    "executions": executions,
                }
                _require(saved[index] == expected and child["result_ref"] == expected["run_id"])
                jobs._publish(owner, child, executions, outcome, read_only=True)
                run_digest = content_hash(jobs.runs.read_json(expected["run_id"], "manifest.json"))
            else:
                run_digest = _pending_run(jobs, owner, child)
                if not resolved:
                    outcome = {**outcome, "state": "unknown", "cleanup": "unknown"}
            operations.append(
                {
                    "operation_job_id": operation_id,
                    "phase": phase,
                    "state": child["state"],
                    "run_id": child["progress"]["run_id"],
                    "outcome": outcome,
                    "tasks": projected,
                }
            )
            bindings.append(
                {
                    "operation_job_id": operation_id,
                    "state": child["state"],
                    "request_digest": content_hash(child["request"]),
                    "tasks_digest": content_hash(tasks),
                    "run_digest": run_digest,
                }
            )
        summary = {
            "schema_version": "bluefire.ad-smb-assistance-summary.v1",
            "proof_scope": "saved_ad_workflow_only",
            "provenance": owner["request"]["environment"]["provenance"],
            **{
                key: progress[key]
                for key in ("revision", "policy_state", "stopped", "pending_operation")
            },
            "operations": operations,
            "missing_phases": [
                phase
                for phase in results.PHASES
                if phase not in {row["phase"] for row in operations}
            ],
            "effective_access_claim": False,
        }
        _require(len(canonical_json_bytes(summary)) <= 64 * 1024)
        binding = {
            "workflow_job_id": identifier,
            "request_digest": content_hash(owner["request"]),
            "progress_digest": content_hash(progress),
            "operations": bindings,
        }
        return summary, content_hash(binding)


def context(
    service: Any, value: Any = None, *, workflow_job_id: str | None = None
) -> dict[str, Any]:
    try:
        chosen = selection(value) if value is not None else None
        identifier = chosen["workflow_job_id"] if chosen is not None else workflow_job_id
        results.job_id(identifier)
        summary, result_digest = _capture(service.ad_smb, identifier)
        current = selection(
            {"kind": KIND, "workflow_job_id": identifier, "result_digest": result_digest}
        )
        _require(chosen is None or current == chosen)
        _require(_capture(service.ad_smb, identifier) == (summary, result_digest))
        document = {
            "schema_version": "bluefire.assistance-context.v1",
            "selected": current,
            "analysis_only": True,
            "capabilities": [],
            "reference_summary": summary,
            "limitations": list(LIMITATIONS),
        }
        return {**document, "context_digest": content_hash(document)}
    except (
        AdSmbError,
        RunStoreError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        OSError,
    ) as exc:
        raise ProductStoreError(_ERROR) from exc
