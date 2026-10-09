"""Explicit human-reviewed retained-file operations and public projections."""

from __future__ import annotations

import time
from typing import Any, Mapping

from . import file_access_context
from .capability_resources import exact, text
from .file_access_contract import FileAccessContractError
from .job_runtime import JobResult
from .product_store_assistance import job_at, patch
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_file_access import KIND, OPERATIONS, allowed_operations
from .util import content_hash

EFFECTS = {
    "create": "Create eight generated JSONL records in the sole enrolled data root, retain their exact creation receipt, and set group-readable mode 0640.",
    "baseline": "Freshly read the same generated file as the enrolled non-owner and owner, compare all bytes and records, then clean only observation artifacts.",
    "harden": "Change only the exact retained generated file from mode 0640 to owner-only 0600; independently verify unchanged contents, identities and ACLs.",
    "rollback": "Restore the exact retained generated file to mode 0640 and freshly verify that both the enrolled non-owner and owner can read identical bytes.",
    "reset": "Delete only the retained generated file through its original native creation receipt after every usage and request has settled.",
}


class FileAccessControl:
    def __init__(self, service, *, clock=None):
        self.service, self.store = service, service.product_store
        self.clock = clock or (lambda: time.time_ns() // 1_000_000)

    def _publish(self, job_id, values):
        values = safe_document(values, context="file-access progress")
        with self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, job_id)
            if job["kind"] != KIND:
                raise ProductStoreError("File-access progress has a different operation owner.")
            patch(connection, job, values)

    def _enrollment(self):
        return file_access_context.enrollment(self.service, self.clock())

    def status(self) -> dict[str, Any]:
        try:
            enrollment = self._enrollment()
            document = enrollment["document"]
        except (FileAccessContractError, OSError, ProductStoreError):
            return {
                "schema_version": "bluefire.file-access-status.v1",
                "available": False,
                "problem": {
                    "code": "file_access_enrollment_unavailable",
                    "message": "An explicitly enrolled disposable Linux non-owner session is required.",
                },
                "enrollment": None,
                "allowed_operations": [],
            }
        with self.store._connection() as connection:
            created = connection.execute(
                "SELECT 1 FROM file_access_operations WHERE enrollment_id=? AND operation='create'",
                (document["enrollment_id"],),
            ).fetchone()
        return {
            "schema_version": "bluefire.file-access-status.v1",
            "available": True,
            "problem": None,
            "enrollment": {
                "enrollment_id": document["enrollment_id"],
                "enrollment_digest": enrollment["document_digest"],
                "expires_at_ms": document["expires_at_ms"],
                "owner_uid": 1000,
                "probe_uid": document["worker"]["uid"],
            },
            "allowed_operations": [] if created else ["create"],
        }

    def _context(self, operation, owner_id):
        enrollment = self._enrollment()
        runtime = file_access_context.execution(self.service, enrollment)
        control = None
        if operation != "create":
            control = self.store.get_file_access_control(owner_id)
            document = control["document"]
            if document["enrollment_id"] != enrollment["document"]["enrollment_id"]:
                raise ProductStoreError("The control belongs to another enrolled generation.")
            if document["status"] == "recovery_required":
                from .file_access_recovery import validate_inventory
                from .orchestrator import Orchestrator

                validate_inventory(Orchestrator, document["source"]["recovery"])
            elif document["status"] != "reset":
                fresh = file_access_context.binding(
                    enrollment, revision=document["revision"], now_ms=self.clock()
                )
                if (
                    fresh != document["binding"]
                    or content_hash(fresh) != document["binding_digest"]
                ):
                    raise ProductStoreError("The retained resource or its preimage changed.")
        from .file_access_execution import recipe

        context = {
            "enrollment_digest": enrollment["document_digest"],
            "profile_digest": content_hash(runtime["profile"].to_dict()),
            "profile_id": runtime["profile"].id,
            "implementations": runtime["implementation_digests"],
            "control_digest": None if control is None else control["document_digest"],
            "recipe": recipe(operation, None if control is None else control["document"]),
        }
        return {
            **runtime,
            "control": control,
            "context_digest": content_hash(context),
            "review_context": context,
        }

    def review(self, request: Mapping[str, Any]) -> dict[str, Any]:
        exact(request, {"operation", "control_owner_id"}, "file-access control review")
        operation, owner_id = request["operation"], request["control_owner_id"]
        if operation not in OPERATIONS or ((owner_id is None) != (operation == "create")):
            raise ProductStoreError("Select one exact retained-file control operation.")
        current = self._context(operation, owner_id)
        control = current["control"]
        if control is None:
            if "create" not in self.status()["allowed_operations"]:
                raise ProductStoreError("The enrolled resource already has a creation obligation.")
        elif (
            control["pending_operation"]
            or not control["usages_settled"]
            or operation not in allowed_operations(control["document"]["status"])
        ):
            raise ProductStoreError(
                "Settle all usages before reviewing this retained control operation."
            )
        effect = EFFECTS[operation]
        if operation == "reset" and control["document"]["status"] == "recovery_required":
            effect = "Remove only the original receipt-owned seed, retained generated file, and observation artifacts still present in at most two original workspaces, after every original task and worker request is verified closed."
        body = {
            "schema_version": "bluefire.file-access-control-review.v1",
            "operation": operation,
            "control_owner_id": owner_id,
            "context_digest": current["context_digest"],
            "enrollment_digest": current["enrollment"]["document_digest"],
            "control_digest": None if control is None else control["document_digest"],
            "expires_at_ms": current["expires_at_ms"],
            "effect": effect,
        }
        return {**body, "review_digest": content_hash(body)}

    def submit(self, request: Mapping[str, Any]) -> dict[str, Any]:
        exact(
            request,
            {"submission_id", "review", "review_digest", "reviewed_by"},
            "file-access operation",
        )
        request = safe_document(request, context="file-access operation")
        text(request["reviewed_by"], "reviewing operator", 128)
        job_id, _ = self.store._job_submission_binding(
            request["submission_id"], content_hash(request)
        )
        previous = self.store.get_job_submission(
            KIND, submission_id=request["submission_id"], intent_digest=content_hash(request)
        )
        if previous is not None:
            if previous["progress"].get("submitted_request") != request:
                raise ProductStoreError("The saved operation has another exact reviewed request.")
            return self.operation(job_id)
        raw = request["review"]
        exact(raw, {"operation", "control_owner_id"}, "file-access review request")
        reviewed = self.review(raw)
        if request["review_digest"] != reviewed["review_digest"]:
            raise ProductStoreError("The reviewed file-access context changed; review it again.")
        current = self._context(raw["operation"], raw["control_owner_id"])
        if current["context_digest"] != reviewed["context_digest"]:
            raise ProductStoreError("The reviewed file-access context changed before reservation.")
        try:
            self.service.job_controller.submit(
                KIND,
                request,
                submission_id=request["submission_id"],
                intent_digest=content_hash(request),
                submission_factory=lambda: self.store.create_file_access_operation(
                    request,
                    review_document=reviewed,
                    review_context=current["review_context"],
                    enrollment_id=current["enrollment"]["document"]["enrollment_id"],
                    now_ms=self.clock(),
                ),
                callback=self._execute,
            )
        except BaseException:
            saved = self.store.get_job_submission(
                KIND, submission_id=request["submission_id"], intent_digest=content_hash(request)
            )
            if (
                saved is not None
                and saved["state"] == "failed"
                and saved.get("error", {}).get("code") == "job_scheduling_failed"
            ):
                self.store.finish_file_access_operation(
                    job_id,
                    outcome={"state": "refused_no_effect", "evidence_digest": content_hash([])},
                )
            raise
        return self.operation(job_id)

    def _execute(self, ctx, _marker):
        from .file_access_execution import execute

        saved = self.store.file_access_operation_records(ctx.job_id)["document"]
        request = {**saved["submitted_request"], "review": saved["review"]}
        execute(self, ctx, request)
        return JobResult(progress={"phase": "completed"})

    def controls(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.file-access-control-list.v1",
            "controls": [
                {key: row["document"][key] for key in ("control_owner_id", "status", "revision")}
                for row in self.store.list_file_access_controls()
            ],
        }

    def control(self, owner_id: str) -> dict[str, Any]:
        view = self.store.get_file_access_control(owner_id)
        document = view["document"]
        binding, baseline = document["binding"], document["baseline"]
        pending = view["pending_operation"] or not view["usages_settled"]
        resource = (
            None
            if binding is None or document["status"] == "reset"
            else {
                "resource_id": binding["resource_id"],
                "resource_generation": binding["resource_generation"],
                **{key: binding["resource"][key] for key in ("sha256", "size", "record_count")},
                "mode": binding["mode"],
            }
        )
        return {
            "schema_version": "bluefire.file-access-control.v1",
            "control_owner_id": owner_id,
            "control_digest": view["document_digest"],
            "revision": document["revision"],
            "status": "uncertain" if view["pending_operation"] else document["status"],
            "resource": resource,
            "baseline": (
                None
                if baseline is None
                else {
                    key: baseline[key]
                    for key in ("baseline_digest", "non_owner", "owner", "record_count", "sha256")
                }
            ),
            "usage_state": "pending" if pending else "settled",
            "allowed_operations": [] if pending else allowed_operations(document["status"]),
            "operations": [
                job
                for job in self.store.list_jobs()
                if job["kind"] == KIND and job["request"].get("control_owner_id") == owner_id
            ],
        }

    def operation(self, job_id: str) -> dict[str, Any]:
        job = self.store.get_job(job_id)
        if job["kind"] != KIND:
            raise ProductStoreError("Select a saved file-access operation.")
        owner_id = job["request"]["control_owner_id"]
        with self.store._connection() as connection:
            present = connection.execute(
                "SELECT 1 FROM file_access_revisions WHERE control_owner_id=?", (owner_id,)
            ).fetchone()
        records = self.store.file_access_operation_records(job_id)
        if (
            job["state"] in ("failed", "cancelled", "interrupted")
            and records["outcome"] is None
            and not records["tasks"]
        ):
            self.store.finish_file_access_operation(
                job_id, outcome={"state": "refused_no_effect", "evidence_digest": content_hash([])}
            )
            records = self.store.file_access_operation_records(job_id)
        outcome = records["outcome"]
        if (
            job["state"] not in ("completed", "failed", "cancelled", "interrupted")
            or outcome is None
            or outcome["state"] != "complete"
        ):
            job = {
                **job,
                "progress": {
                    key: value
                    for key, value in job["progress"].items()
                    if key != "verified_observation"
                },
            }
        return {
            "schema_version": "bluefire.file-access-operation.v1",
            "job": job,
            "control": self.control(owner_id) if present else None,
            "reconciliation": (
                None
                if outcome is None
                else {
                    "outcome_digest": records["outcome_digest"],
                    "state": outcome["state"],
                    "available": outcome["state"] == "unknown",
                }
            ),
            "reconciliation_receipt": self.store.latest_file_access_reconciliation(job_id),
        }

    def composition_context(self, owner_id: str) -> dict[str, Any]:
        return file_access_context.composition(self.service, owner_id, self.clock())

    def reconcile(self, job_id: str, request: Mapping[str, Any]) -> dict[str, Any]:
        from .file_access_reconciliation import reconcile

        return reconcile(self, job_id, request)

    def reconciliation(self, job_id: str, submission_id: str) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.file-access-reconciliation.v1",
            "operation_job_id": job_id,
            "receipt": self.store.get_file_access_reconciliation(job_id, submission_id),
        }
