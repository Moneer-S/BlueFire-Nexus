"""Read-only reconciliation controller for previously admitted file operations."""

from typing import Any, Mapping

from .file_access_recovery import partial_inventory, recover_tasks
from .product_store_errors import ProductStoreError
from .runner_transport_errors import RunnerTransportError
from .util import content_hash


def reconcile(control, job_id: str, request: Mapping[str, Any]) -> dict[str, Any]:
    from . import file_access_context
    from .capability_resources import exact, text
    from .file_access_execution import _engine, _finish

    exact(
        request,
        {"submission_id", "expected_outcome_digest", "reviewed_by"},
        "file-access reconciliation",
    )
    text(request["reviewed_by"], "reviewing operator", 128)
    _, created = control.store.begin_file_access_reconciliation(job_id, request)
    if not created:
        receipt = control.store.get_file_access_reconciliation(job_id, request["submission_id"])
        if receipt["state"] == "completed":
            completed: dict[str, Any] = control.operation(job_id)
            return completed
        saved = control.store.file_access_operation_records(job_id)
        if saved["outcome"]["state"] != "unknown":
            control.store.finish_file_access_reconciliation(
                job_id, request["submission_id"], problem=None
            )
            settled: dict[str, Any] = control.operation(job_id)
            return settled
    problem = None
    try:
        saved = control.store.file_access_operation_records(job_id)
        if not saved["tasks"]:
            control.store.finish_file_access_operation(
                job_id,
                outcome={"state": "refused_no_effect", "evidence_digest": content_hash([])},
                expected_outcome_digest=request["expected_outcome_digest"],
            )
        else:
            prepared = saved["preparation"]
            enrolled = control._enrollment()
            if enrolled["document_digest"] != prepared["enrollment_digest"]:
                raise ProductStoreError("Original setup generation changed.")
            current = file_access_context.execution(control.service, enrolled)
            if (
                content_hash(current["profile"].to_dict())
                != saved["document"]["review_context"]["profile_digest"]
                or current["implementation_digests"]
                != saved["document"]["review_context"]["implementations"]
            ):
                raise ProductStoreError("Original runner profile or implementation changed.")
            engine = _engine(control, current)
            runner = getattr(current["runner"], "runner", current["runner"])
            outputs, complete = recover_tasks(control, job_id, prepared, engine, runner)
            original = {
                **saved["document"]["submitted_request"],
                "review": saved["document"]["review"],
            }
            refreshed = control.store.file_access_operation_records(job_id)
            if all(
                row["terminal"]["result"].get("schema_version") == "bluefire.task-not-sent.v1"
                for row in refreshed["tasks"]
            ):
                control.store.finish_file_access_operation(
                    job_id,
                    outcome={
                        "state": "refused_no_effect",
                        "evidence_digest": content_hash(refreshed["tasks"]),
                    },
                    expected_outcome_digest=request["expected_outcome_digest"],
                )
            elif complete:
                _finish(
                    control,
                    job_id,
                    original,
                    prepared,
                    current,
                    engine,
                    outputs,
                    expected_outcome_digest=request["expected_outcome_digest"],
                )
            else:
                saved = control.store.file_access_operation_records(job_id)
                inventory = partial_inventory(saved, prepared, engine)
                prior = prepared["prior"]
                document = {
                    "schema_version": "bluefire.retained-file-control.v1",
                    "control_owner_id": saved["control_owner_id"],
                    "enrollment_id": enrolled["document"]["enrollment_id"],
                    "revision": prepared["revision"],
                    "status": "recovery_required",
                    "binding": None,
                    "binding_digest": content_hash(None),
                    "source": {"recovery": inventory},
                    "baseline": None if prior is None else prior["baseline"],
                }
                control.store.finish_file_access_operation(
                    job_id,
                    outcome={
                        "state": "settled_partial",
                        "evidence_digest": content_hash(saved["tasks"]),
                    },
                    control=document,
                    expected_outcome_digest=request["expected_outcome_digest"],
                )
    except (ProductStoreError, RunnerTransportError, ValueError, KeyError, OSError):
        problem = {
            "code": "file_access_reconciliation_unresolved",
            "message": "The original effects remain unresolved; no task was repeated.",
        }
    control.store.finish_file_access_reconciliation(
        job_id, request["submission_id"], problem=problem
    )
    reconciled: dict[str, Any] = control.operation(job_id)
    return reconciled
