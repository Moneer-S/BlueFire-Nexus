"""Application control flow over the original Darwin workspace and journal."""

from __future__ import annotations

from typing import Any

from . import product_store_macos_file_access as macos
from .capability_resources import exact
from .execution_contracts import execution_task_identity
from .product_store_errors import ProductStoreError
from .util import content_hash


def endpoint(service):
    from .macos_file_access_endpoint import OriginalWorkspaceEndpoint

    current = getattr(service, "_macos_workspace_endpoint", None)
    macos.require(type(current) is OriginalWorkspaceEndpoint)
    current.assert_current()
    return current


def import_setup(service, request, now_ms):
    exact(request, {"enrollment_id", "enrollment_digest"}, "Darwin setup selection")
    setup = macos.setup_document(endpoint(service).current_setup())
    enrolled = macos.enrollment_document(setup)
    macos.require(
        request
        == {"enrollment_id": enrolled["enrollment_id"], "enrollment_digest": content_hash(enrolled)}
    )
    return service.product_store.import_macos_file_access_setup(setup, now_ms=now_ms)


def enrollment(service, now_ms):
    setup = macos.setup_document(endpoint(service).current_setup())
    expected = macos.enrollment_document(setup)
    macos.require(now_ms < expected["expires_at_ms"])
    saved = service.product_store.get_file_access_enrollment(expected["enrollment_id"])
    macos.require(saved == {"document": expected, "document_digest": content_hash(expected)})
    return saved


def status(service, now_ms) -> dict[str, Any]:
    try:
        setup = macos.setup_document(endpoint(service).current_setup())
        enrolled = macos.enrollment_document(setup)
        macos.require(now_ms < enrolled["expires_at_ms"])
    except (OSError, RuntimeError, ValueError, ProductStoreError):
        return {
            "schema_version": "bluefire.file-access-status.v1",
            "platform": "macos",
            "available": False,
            "problem": {
                "code": "file_access_enrollment_unavailable",
                "message": "The original protected macOS workspace is required.",
            },
            "enrollment": None,
            "allowed_operations": [],
        }
    return {
        "schema_version": "bluefire.file-access-status.v1",
        "platform": "macos",
        "available": True,
        "problem": None,
        "enrollment": {
            "enrollment_id": enrolled["enrollment_id"],
            "enrollment_digest": content_hash(enrolled),
            "expires_at_ms": enrolled["expires_at_ms"],
            "owner_uid": setup["binding"]["owner"]["effective_uid"],
            "probe_uid": setup["binding"]["reader"]["effective_uid"],
        },
        "allowed_operations": [],
    }


def context(service, operation, owner_id, now_ms):
    macos.require(operation in macos.PLANS)
    enrolled = enrollment(service, now_ms)
    control = service.product_store.get_file_access_control(owner_id)
    macos.require(
        macos.is_control(control["document"]) and operation in macos.permitted(control["document"])
    )
    creator = endpoint(service).review_context(operation)
    exact(
        creator,
        {"schema_version", "operation", "state", "binding", "probe_digest", "context_digest"},
        "Darwin creator context",
    )
    macos.require(
        creator["schema_version"] == "bluefire.macos-file-access-creator-context.v1"
        and creator["operation"] == operation
        and creator["binding"] == control["document"]["binding"]
        and creator["context_digest"]
        == content_hash({k: v for k, v in creator.items() if k != "context_digest"})
    )
    reviewed = {
        "schema_version": macos.CONTEXT_SCHEMA,
        "operation": operation,
        "enrollment_digest": enrolled["document_digest"],
        "control_digest": control["document_digest"],
        "creator_context": creator,
    }
    return {
        "enrollment": enrolled,
        "control": control,
        "review_context": reviewed,
        "context_digest": content_hash(reviewed),
        "expires_at_ms": enrolled["document"]["expires_at_ms"],
        "allowed_operations": macos.permitted(control["document"]),
    }


def projection(service, view, now_ms, *, _saved_only=False) -> dict[str, Any]:
    control = view["document"]
    pending = view["pending_operation"] or not view["usages_settled"]
    live = False
    if not _saved_only:
        try:
            live = endpoint(service).review_context("baseline")["binding"] == control["binding"]
        except (OSError, RuntimeError, ValueError, ProductStoreError):
            pass
    binding = control["binding"]
    return {
        "schema_version": "bluefire.file-access-control.v1",
        "platform": "macos",
        "control_owner_id": control["control_owner_id"],
        "control_digest": view["document_digest"],
        "revision": control["revision"],
        "status": "uncertain" if pending else control["status"],
        "resource": {
            "resource_id": binding["generation"],
            "resource_generation": binding["generation"],
            "sha256": binding["resource"]["sha256"],
            "size": binding["resource"]["size_bytes"],
            "record_count": binding["resource"]["record_count"],
            "mode": binding["mode"],
        },
        "baseline": control["baseline"],
        "usage_state": "pending" if pending else "settled",
        "allowed_operations": (
            macos.permitted(control)
            if live and not pending and now_ms < binding["expires_at_ms"]
            else []
        ),
        "operations": [
            job
            for job in service.product_store.list_jobs()
            if job["kind"] == "file_access.operation"
            and job["request"].get("control_owner_id") == control["control_owner_id"]
        ],
    }


def execute(control, ctx, request):
    from .macos_file_access_bridge import MacOSWorkspaceTaskTransport
    from .macos_file_access_clock import darwin_clock_ns

    store = control.store
    task_id = None
    prepared = None
    try:
        ctx.checkpoint()
        op, owner_id = request["review"]["operation"], request["review"]["control_owner_id"]
        current = context(control.service, op, owner_id, control.clock())
        macos.require(current["context_digest"] == request["review"]["context_digest"])
        reviewed = store.file_access_operation_records(ctx.job_id)["document"]
        prepared = macos.build_preparation(
            ctx.job_id,
            control.service.store._new_run_id(),
            op,
            reviewed,
            control.clock(),
            darwin_clock_ns(),
        )
        store.prepare_file_access_operation(ctx.job_id, prepared, now_ms=control.clock())
        manifest, profile = prepared["manifest"], prepared["runner_profile"]
        task_id, _ = execution_task_identity(manifest, profile)

        def validate_context():
            endpoint(control.service).assert_current()
            macos.require(not ctx.cancellation_event.is_set())

        ctx.checkpoint()
        store.register_file_access_task(
            ctx.job_id,
            task_id=task_id,
            step_id=op,
            manifest=manifest,
            runner_profile=profile,
            now_ms=control.clock(),
            validate_context=validate_context,
        )
        # Task registration has committed before the transport can commit its
        # attempted-dispatch marker and write on the original inherited channel.
        transport = MacOSWorkspaceTaskTransport(endpoint(control.service), store)
        result = transport.execute_task(
            manifest, profile, task_id=task_id, cancel_event=ctx.cancellation_event
        )
        store.record_file_access_task_terminal(
            task_id, request_hash=manifest["request_hash"], result=result
        )
        claim = store.file_access_task_record(
            task_id, execution_task_identity(manifest, profile)[1]
        )["task"]
        receipt = macos.validate_receipt(claim, prepared, result)
        macos.require(receipt["state"] == "complete")
        store.record_file_access_worker_closure(
            task_id,
            request_hash=manifest["request_hash"],
            proof={
                "state": "verified_closed",
                "binding_digest": receipt["binding_digest"],
                "evidence_digest": content_hash(receipt),
            },
        )
        ctx.checkpoint()
        endpoint(control.service).assert_current()
        macos._require_original_monotonic_deadline(prepared)
        store.finish_file_access_operation(
            ctx.job_id,
            outcome={"state": "complete", "evidence_digest": content_hash(receipt)},
            control=macos.next_control(current["control"]["document"], prepared, receipt),
            now_ms=control.clock(),
        )
        control._publish(ctx.job_id, {"phase": "completed"})
    except BaseException:
        records = store.file_access_operation_records(ctx.job_id)
        if records["outcome"] is None:
            dispatched = macos.has_dispatch(store, ctx.job_id)
            if not dispatched:
                for row in records["tasks"]:
                    claim = row["task"]
                    not_sent = {
                        "schema_version": "bluefire.task-not-sent.v1",
                        "task_id": claim["task_id"],
                        "request_hash": claim["request_hash"],
                    }
                    store.record_file_access_task_terminal(
                        claim["task_id"], request_hash=claim["request_hash"], result=not_sent
                    )
                    store.record_file_access_worker_closure(
                        claim["task_id"],
                        request_hash=claim["request_hash"],
                        proof={
                            "state": "not_sent",
                            "binding_digest": content_hash(
                                claim["runner_profile"]["macos_file_access_binding"]
                            ),
                            "evidence_digest": content_hash(not_sent),
                        },
                    )
            store.finish_file_access_operation(
                ctx.job_id,
                outcome={
                    "state": "unknown" if dispatched else "refused_no_effect",
                    "evidence_digest": content_hash(records["tasks"]),
                },
            )
        control._publish(
            ctx.job_id,
            {"phase": "uncertain" if macos.has_dispatch(store, ctx.job_id) else "not_dispatched"},
        )
        raise
