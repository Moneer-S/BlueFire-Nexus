"""Append-only ownership for one retained generated Linux file per enrollment.

Only authenticated controller observations enter this store. Missing task terminals
remain obligations: reopening the store never infers that a read or mutation ended.
"""

from __future__ import annotations

import json
from typing import Any, cast

from . import product_store_file_access_admission as admission
from .capability_resources import digest, exact
from .product_store_capability_grants import control_usages_settled as _usage_settled
from .product_store_errors import ProductStoreError
from .product_store_file_access_admission import allowed_operations as allowed_operations
from .product_store_file_access_native_evidence import NativeEvidenceStoreMixin
from .product_store_serialization import canonical_json, utc_now
from .product_store_windows_file_access import WindowsSetupStoreMixin
from .util import content_hash

OPERATIONS = ("create", "baseline", "harden", "rollback", "reset")
KIND = "file_access.operation"
_TABLES = {
    "file_access_enrollments": "enrollment_id TEXT PRIMARY KEY, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_setup_imports": "control_owner_id TEXT PRIMARY KEY, enrollment_id TEXT NOT NULL UNIQUE REFERENCES file_access_enrollments(enrollment_id), generation TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_operations": "job_id TEXT PRIMARY KEY REFERENCES jobs(job_id), control_owner_id TEXT NOT NULL, enrollment_id TEXT NOT NULL, operation TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_preparations": "job_id TEXT PRIMARY KEY REFERENCES file_access_operations(job_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_windows_control_evidence": "job_id TEXT NOT NULL REFERENCES file_access_operations(job_id), stage TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, PRIMARY KEY(job_id,stage)",
    "file_access_reconciliations": "submission_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES file_access_operations(job_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_reconciliation_results": "submission_id TEXT PRIMARY KEY REFERENCES file_access_reconciliations(submission_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_task_claims": "task_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES file_access_operations(job_id), step_id TEXT NOT NULL, request_hash TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, UNIQUE(job_id,step_id)",
    "file_access_task_terminals": "task_id TEXT PRIMARY KEY REFERENCES file_access_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_task_evidence": "task_id TEXT NOT NULL REFERENCES file_access_task_claims(task_id), stage TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, PRIMARY KEY(task_id,stage)",
    "file_access_owned_process_closures": "task_id TEXT PRIMARY KEY REFERENCES file_access_task_claims(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_worker_closures": "task_id TEXT PRIMARY KEY REFERENCES file_access_task_terminals(task_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_outcomes": "sequence INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES file_access_operations(job_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    "file_access_revisions": "control_owner_id TEXT NOT NULL, revision INTEGER NOT NULL, job_id TEXT NOT NULL UNIQUE REFERENCES file_access_operations(job_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL, PRIMARY KEY(control_owner_id,revision)",
}


def initialize_schema(connection):
    if not connection.in_transaction:
        raise ProductStoreError("File-access migration requires one transaction.")
    for table, definition in _TABLES.items():
        connection.execute(f"CREATE TABLE IF NOT EXISTS {table}({definition})")
        for operation in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'file-access history is append-only'); END"
            )


def _document(row):
    if row is None:
        raise ProductStoreError("The retained file-access record is unavailable.")
    try:
        value = json.loads(row["document_json"])
        if not isinstance(value, dict) or content_hash(value) != row["document_digest"]:
            raise ValueError("digest")
        return value
    except (ValueError, TypeError, KeyError) as exc:
        raise ProductStoreError(
            "The retained file-access record failed integrity verification."
        ) from exc


def _control_at(connection, owner_id):
    row = connection.execute(
        "SELECT * FROM file_access_revisions WHERE control_owner_id=? ORDER BY revision DESC LIMIT 1",
        (owner_id,),
    ).fetchone()
    if row is None:
        from . import product_store_windows_file_access as windows

        imported = windows.at(connection, owner_id=owner_id)
        document = windows.document(imported)
        return {"document": document, "document_digest": imported["document_digest"]}
    document = _document(row)
    if document["control_owner_id"] != owner_id or document["revision"] != row["revision"]:
        raise ProductStoreError("The retained file control lineage changed.")
    return {"document": document, "document_digest": row["document_digest"]}


def _pending(connection, owner_id):
    rows = connection.execute(
        "SELECT o.job_id,r.document_json,r.document_digest FROM file_access_operations o "
        "LEFT JOIN file_access_outcomes r ON r.sequence=(SELECT MAX(sequence) FROM file_access_outcomes WHERE job_id=o.job_id) WHERE o.control_owner_id=?",
        (owner_id,),
    ).fetchall()
    return any(
        row["document_json"] is None
        or _document(row)["state"] not in ("complete", "settled_partial", "refused_no_effect")
        for row in rows
    )


def _outcome_at(connection, job_id):
    return connection.execute(
        "SELECT * FROM file_access_outcomes WHERE job_id=? ORDER BY sequence DESC LIMIT 1",
        (job_id,),
    ).fetchone()


def guard_control(store, connection, grant):
    environment = grant["environment"]
    view = _control_at(connection, environment["control_owner_id"])
    control = view["document"]
    if (
        view["document_digest"] != environment["control_digest"]
        or control["status"] != "hardened"
        or control["revision"] != environment["control_revision"]
        or content_hash(control["binding"]["resource"]) != environment["resource_digest"]
        or control["binding"]["resource_generation"] != environment["resource_generation"]
        or control["binding"]["resource_id"] != environment["resource_id"]
        or control["binding"]["enrollment_digest"] != environment["probe_enrollment_digest"]
        or control["baseline"]["baseline_digest"] != environment["baseline_digest"]
        or _pending(connection, environment["control_owner_id"])
    ):
        raise ProductStoreError("The exact hardened retained file control is unavailable.")


class FileAccessStoreMixin(NativeEvidenceStoreMixin, WindowsSetupStoreMixin):
    def save_file_access_enrollment(self, document, *, expected_document_digest):
        """Caller obtained the expected digest from the independently verified setup anchor."""
        if content_hash(document) != digest(expected_document_digest, "setup enrollment digest"):
            raise ProductStoreError("File-access setup enrollment changed.")
        store = cast(Any, self)
        with store._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM file_access_enrollments WHERE enrollment_id=?",
                (document["enrollment_id"],),
            ).fetchone()
            if row is not None:
                if _document(row) != document:
                    raise ProductStoreError("The file-access enrollment is already immutable.")
                return
            connection.execute(
                "INSERT INTO file_access_enrollments VALUES(?,?,?)",
                (document["enrollment_id"], canonical_json(document), expected_document_digest),
            )

    def get_file_access_enrollment(self, enrollment_id):
        store = cast(Any, self)
        with store._connection() as connection:
            row = connection.execute(
                "SELECT * FROM file_access_enrollments WHERE enrollment_id=?", (enrollment_id,)
            ).fetchone()
            return {"document": _document(row), "document_digest": row["document_digest"]}

    def get_file_access_control(self, owner_id):
        store = cast(Any, self)
        with store._connection() as connection:
            view = _control_at(connection, owner_id)
            return {
                **view,
                "pending_operation": _pending(connection, owner_id),
                "usages_settled": _usage_settled(store, connection, owner_id),
            }

    def get_file_access_control_revision(self, owner_id, revision):
        store = cast(Any, self)
        with store._connection() as connection:
            row = connection.execute(
                "SELECT * FROM file_access_revisions WHERE control_owner_id=? AND revision=?",
                (owner_id, revision),
            ).fetchone()
            if row is None and type(revision) is int and revision == 1:
                from . import product_store_windows_file_access as windows

                imported = windows.at(connection, owner_id=owner_id)
                return {
                    "document": windows.document(imported),
                    "document_digest": imported["document_digest"],
                }
            return {"document": _document(row), "document_digest": row["document_digest"]}

    def list_file_access_controls(self):
        store = cast(Any, self)
        with store._connection() as connection:
            ids = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT control_owner_id FROM file_access_revisions ORDER BY rowid"
                )
            ]
            ids.extend(
                row[0]
                for row in connection.execute(
                    "SELECT control_owner_id FROM file_access_setup_imports ORDER BY rowid"
                )
                if row[0] not in ids
            )
            return [_control_at(connection, owner_id) for owner_id in ids]

    def create_file_access_operation(
        self, request, *, review_document, review_context, enrollment_id, now_ms
    ):
        """Reserve the retained resource and publish exact intent before dispatch."""
        store = cast(Any, self)
        exact(
            request,
            {"submission_id", "review", "review_digest", "reviewed_by"},
            "file-access submission",
        )
        exact(request["review"], {"operation", "control_owner_id"}, "file-access review request")
        review = review_document
        if content_hash(review_context) != review["context_digest"]:
            raise ProductStoreError("The operation lacks its independently reviewed context.")
        operation = review["operation"]
        if (
            operation not in OPERATIONS
            or review["review_digest"] != request["review_digest"]
            or {key: review[key] for key in ("operation", "control_owner_id")} != request["review"]
            or content_hash({key: value for key, value in review.items() if key != "review_digest"})
            != request["review_digest"]
        ):
            raise ProductStoreError("The exact file-access operation review is invalid.")
        job_id, binding = store._job_submission_binding(
            request["submission_id"], content_hash(request)
        )
        owner_id = job_id if operation == "create" else review["control_owner_id"]
        with store._connection(write=True) as connection:
            previous = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if previous is not None:
                job = store._matching_job_submission(previous, KIND, binding)
                if job["progress"].get("submitted_request") != request:
                    raise ProductStoreError("The operation ID already names another exact review.")
                return job, False
            enrollment = _document(
                connection.execute(
                    "SELECT * FROM file_access_enrollments WHERE enrollment_id=?", (enrollment_id,)
                ).fetchone()
            )
            if (
                not now_ms < enrollment["expires_at_ms"]
                or now_ms >= review["expires_at_ms"]
                or review["enrollment_digest"] != content_hash(enrollment)
                or review_context["enrollment_digest"] != content_hash(enrollment)
            ):
                raise ProductStoreError("The file-access operation review expired.")
            if operation == "create":
                if enrollment.get("schema_version") in (
                    "bluefire.windows-file-access-enrollment.v1",
                    "bluefire.windows-file-access-enrollment.v2",
                ):
                    raise ProductStoreError("Windows protected setup is not a create operation.")
                if (
                    review["control_owner_id"] is not None
                    or review["control_digest"] is not None
                    or connection.execute(
                        "SELECT 1 FROM file_access_operations WHERE enrollment_id=? AND operation='create'",
                        (enrollment_id,),
                    ).fetchone()
                ):
                    raise ProductStoreError(
                        "This enrolled resource already has an owned creation obligation."
                    )
            else:
                control = _control_at(connection, owner_id)
                permitted = admission.permitted_operations(
                    store, connection, control["document"], review_context, now_ms=now_ms
                )
                if (
                    control["document_digest"] != review["control_digest"]
                    or control["document"]["enrollment_id"] != enrollment_id
                    or operation not in permitted
                    or _pending(connection, owner_id)
                    or not _usage_settled(store, connection, owner_id)
                ):
                    raise ProductStoreError(
                        "Settle current usages and review the exact current file control."
                    )
            marker = {
                "schema_version": "bluefire.file-access-operation-request.v1",
                "control_owner_id": owner_id,
                "operation": operation,
                "review_digest": request["review_digest"],
                "_submission": binding,
            }
            progress = {
                "submitted_request": request,
                "phase": "reserved",
                "control_owner_id": owner_id,
            }
            now = utc_now()
            connection.execute(
                "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) VALUES(?,?,'queued',?,?,?,?)",
                (job_id, KIND, canonical_json(marker), canonical_json(progress), now, now),
            )
            document = {
                "submitted_request": request,
                "review": review,
                "review_context": review_context,
                "enrollment_digest": content_hash(enrollment),
                "created_at_ms": now_ms,
            }
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (
                    job_id,
                    owner_id,
                    enrollment_id,
                    operation,
                    canonical_json(document),
                    content_hash(document),
                ),
            )
            return (
                store._job_from_row(
                    connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
                ),
                True,
            )

    def prepare_file_access_operation(self, job_id, document, *, now_ms=None):
        store = cast(Any, self)
        with store._connection(write=True) as connection:
            operation = connection.execute(
                "SELECT * FROM file_access_operations WHERE job_id=?", (job_id,)
            ).fetchone()
            original = _document(operation)
            if document["job_id"] != job_id:
                raise ProductStoreError("The operation preparation has another owner.")
            previous = connection.execute(
                "SELECT * FROM file_access_preparations WHERE job_id=?", (job_id,)
            ).fetchone()
            if previous is not None:
                if _document(previous) != document:
                    raise ProductStoreError("The exact operation preparation is already immutable.")
                return
            owner = store._job_from_row(
                connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            )
            if (
                owner["state"] not in ("queued", "running")
                or owner["progress"].get("stopped")
                or _outcome_at(connection, job_id) is not None
            ):
                raise ProductStoreError("The stopped operation cannot prepare new work.")
            enrollment = _document(
                connection.execute(
                    "SELECT * FROM file_access_enrollments WHERE enrollment_id=?",
                    (operation["enrollment_id"],),
                ).fetchone()
            )
            prior = (
                None
                if operation["operation"] == "create"
                else _control_at(connection, operation["control_owner_id"])["document"]
            )
            admission.validate_preparation(
                store, connection, operation, original, document, enrollment, prior, now_ms=now_ms
            )
            connection.execute(
                "INSERT INTO file_access_preparations VALUES(?,?,?)",
                (job_id, canonical_json(document), content_hash(document)),
            )

    def file_access_preparation(self, job_id):
        store = cast(Any, self)
        with store._connection() as connection:
            row = connection.execute(
                "SELECT * FROM file_access_preparations WHERE job_id=?", (job_id,)
            ).fetchone()
            document = _document(row)
            return {"document": document, "document_digest": row["document_digest"]}

    def register_file_access_task(
        self, job_id, *, task_id, step_id, manifest, runner_profile, now_ms, validate_context
    ):
        store = cast(Any, self)
        digest(manifest["request_hash"], "control task request hash")
        with store._connection(write=True) as connection:
            operation = connection.execute(
                "SELECT * FROM file_access_operations WHERE job_id=?", (job_id,)
            ).fetchone()
            document = _document(operation)
            owner = store._job_from_row(
                connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            )
            if (
                owner["state"] not in ("queued", "running")
                or owner["progress"].get("stopped")
                or now_ms >= document["review"]["expires_at_ms"]
                or connection.execute(
                    "SELECT 1 FROM file_access_outcomes WHERE job_id=?", (job_id,)
                ).fetchone()
            ):
                raise ProductStoreError(
                    "The retained file operation no longer admits business work."
                )
            if (
                "approval" not in manifest
                or "grant_attempt" in manifest
                or "grant_cleanup" in manifest
            ):
                raise ProductStoreError(
                    "Retained file changes require exact human-reviewed task authority."
                )
            preparation = _document(
                connection.execute(
                    "SELECT * FROM file_access_preparations WHERE job_id=?", (job_id,)
                ).fetchone()
            )
            from . import product_store_windows_file_access as windows

            if windows.is_preparation(preparation):
                windows.register_task(
                    connection,
                    operation=operation,
                    original=document,
                    prepared=preparation,
                    control_document=_control_at(connection, operation["control_owner_id"])[
                        "document"
                    ],
                    usage_settled=_usage_settled(store, connection, operation["control_owner_id"]),
                    task_id=task_id,
                    step_id=step_id,
                    manifest=manifest,
                    profile=runner_profile,
                    now_ms=now_ms,
                    validate_context=validate_context,
                )
                return
            expected = next(
                (row for row in preparation["recipe"] if row["step_id"] == step_id), None
            )
            if (
                expected is None
                or manifest["run_id"] != preparation["run_id"]
                or manifest["step_id"] != step_id
                or manifest["action_id"] != expected["action_id"]
                or runner_profile["sandbox_root"] != preparation["roots"][expected["workspace"]]
            ):
                raise ProductStoreError("The task differs from its fixed reviewed preparation.")
            tasks = connection.execute(
                "SELECT * FROM file_access_task_claims WHERE job_id=? ORDER BY rowid", (job_id,)
            ).fetchall()
            prefix = [
                {
                    "task": _document(task),
                    "terminal": _document(
                        connection.execute(
                            "SELECT * FROM file_access_task_terminals WHERE task_id=?",
                            (task["task_id"],),
                        ).fetchone()
                    ),
                }
                for task in tasks
            ]
            from .file_access_preparation import validate_task

            validate_task(
                preparation, prefix, task_id, step_id, manifest, runner_profile, now_ms=now_ms
            )
            if operation["operation"] != "create":
                if _control_at(connection, operation["control_owner_id"])[
                    "document_digest"
                ] != document["review"]["control_digest"] or not _usage_settled(
                    store, connection, operation["control_owner_id"]
                ):
                    raise ProductStoreError("The exact retained control preimage changed.")
            validate_context()
            from .execution_contracts import execution_task_identity

            record = {
                "job_id": job_id,
                "task_id": task_id,
                "step_id": step_id,
                "request_hash": manifest["request_hash"],
                "transport_request_hash": execution_task_identity(manifest, runner_profile)[1],
                "manifest": manifest,
                "runner_profile": runner_profile,
            }
            connection.execute(
                "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                (
                    task_id,
                    job_id,
                    step_id,
                    manifest["request_hash"],
                    canonical_json(record),
                    content_hash(record),
                ),
            )

    def file_access_task_record(self, task_id, transport_request_hash, *, include_terminal=True):
        """Return one exact retained claim without revalidating its historical admission."""
        store = cast(Any, self)
        if type(include_terminal) is not bool:
            raise ProductStoreError("The retained file-access terminal selection is invalid.")
        if not isinstance(task_id, str) or not task_id:
            raise ProductStoreError("The retained file-access task identity is invalid.")
        if not isinstance(transport_request_hash, str):
            raise ProductStoreError("The retained file-access transport identity is invalid.")
        try:
            digest(transport_request_hash, "file-access transport request hash")
        except ValueError as exc:
            raise ProductStoreError(
                "The retained file-access transport identity is invalid."
            ) from exc

        with store._connection() as connection:
            row = connection.execute(
                "SELECT * FROM file_access_task_claims WHERE task_id=?", (task_id,)
            ).fetchone()
            document = _document(row)
            manifest = document.get("manifest")
            runner_profile = document.get("runner_profile")
            if not isinstance(manifest, dict) or not isinstance(runner_profile, dict):
                raise ProductStoreError("The retained file-access task binding is invalid.")
            try:
                digest(row["request_hash"], "file-access task request hash")
                from .execution_contracts import execution_task_identity

                expected_task_id, expected_transport_hash = execution_task_identity(
                    manifest, runner_profile
                )
            except (TypeError, ValueError, RecursionError) as exc:
                raise ProductStoreError(
                    "The retained file-access task binding is invalid."
                ) from exc
            if (
                document.get("task_id") != row["task_id"]
                or row["task_id"] != task_id
                or document.get("job_id") != row["job_id"]
                or document.get("step_id") != row["step_id"]
                or document.get("request_hash") != row["request_hash"]
                or not isinstance(manifest.get("run_id"), str)
                or not manifest["run_id"]
                or manifest.get("step_id") != row["step_id"]
                or manifest.get("request_hash") != row["request_hash"]
                or expected_task_id != row["task_id"]
                or document.get("transport_request_hash") != expected_transport_hash
                or transport_request_hash != expected_transport_hash
            ):
                raise ProductStoreError("The retained file-access task binding changed.")

            terminal_row = None
            if include_terminal:
                terminal_row = connection.execute(
                    "SELECT * FROM file_access_task_terminals WHERE task_id=?", (task_id,)
                ).fetchone()
            terminal = None
            if terminal_row is not None:
                terminal = _document(terminal_row)
                if (
                    terminal_row["task_id"] != row["task_id"]
                    or terminal.get("task_id") != row["task_id"]
                    or terminal.get("request_hash") != row["request_hash"]
                ):
                    raise ProductStoreError("The retained file-access terminal binding changed.")
            return {
                "task": document,
                "document_digest": row["document_digest"],
                "terminal": terminal,
            }

    def record_file_access_task_terminal(
        self, task_id, *, request_hash, result, receipt_snapshot=None
    ):
        store = cast(Any, self)
        with store._connection(write=True) as connection:
            task = connection.execute(
                "SELECT * FROM file_access_task_claims WHERE task_id=?", (task_id,)
            ).fetchone()
            _document(task)
            if task["request_hash"] != request_hash:
                raise ProductStoreError("File-access terminal belongs to another registered task.")
            document = {
                "task_id": task_id,
                "request_hash": request_hash,
                "result": result,
                "receipt_snapshot": receipt_snapshot or {"documents": {}, "committed": []},
            }
            previous = connection.execute(
                "SELECT * FROM file_access_task_terminals WHERE task_id=?", (task_id,)
            ).fetchone()
            if previous is not None:
                if _document(previous) != document:
                    raise ProductStoreError("The authenticated file-access terminal is immutable.")
                return
            connection.execute(
                "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
                (task_id, canonical_json(document), content_hash(document)),
            )

    def record_file_access_worker_closure(self, task_id, *, request_hash, proof):
        from .capability_packs import FILE_ACCESS_METHODS

        store = cast(Any, self)
        exact(proof, {"state", "binding_digest", "evidence_digest"}, "worker closure")
        digest(proof["evidence_digest"], "worker closure evidence")
        with store._connection(write=True) as connection:
            task = _document(
                connection.execute(
                    "SELECT * FROM file_access_task_claims WHERE task_id=?", (task_id,)
                ).fetchone()
            )
            terminal = _document(
                connection.execute(
                    "SELECT * FROM file_access_task_terminals WHERE task_id=?", (task_id,)
                ).fetchone()
            )
            if (
                task["request_hash"] != request_hash
                or task["manifest"]["action_id"] != FILE_ACCESS_METHODS[0]
                or proof["binding_digest"]
                != content_hash(task["runner_profile"]["file_access_binding"])
                or proof["state"] not in ("verified_closed", "not_sent")
                or (
                    proof["state"] == "not_sent"
                    and terminal["result"].get("schema_version") != "bluefire.task-not-sent.v1"
                )
            ):
                raise ProductStoreError("Worker closure differs from its exact original request.")
            document = {
                "task_id": task_id,
                "request_hash": request_hash,
                "terminal_digest": content_hash(terminal["result"]),
                "proof": proof,
            }
            previous = connection.execute(
                "SELECT * FROM file_access_worker_closures WHERE task_id=?", (task_id,)
            ).fetchone()
            if previous is not None:
                if _document(previous) != document:
                    raise ProductStoreError("Original worker closure is immutable.")
                return
            connection.execute(
                "INSERT INTO file_access_worker_closures VALUES(?,?,?)",
                (task_id, canonical_json(document), content_hash(document)),
            )

    def finish_file_access_operation(
        self,
        job_id,
        *,
        outcome,
        control=None,
        expected_outcome_digest=None,
        verified_observation=None,
        now_ms=None,
    ):
        """Publish verified control revision with all registered tasks terminal atomically."""
        store = cast(Any, self)
        exact(outcome, {"state", "evidence_digest"}, "file-access operation outcome")
        if outcome["state"] not in ("complete", "settled_partial", "refused_no_effect", "unknown"):
            raise ProductStoreError("File-access operation outcome is invalid.")
        digest(outcome["evidence_digest"], "verified operation evidence")
        with store._connection(write=True) as connection:
            operation = connection.execute(
                "SELECT * FROM file_access_operations WHERE job_id=?", (job_id,)
            ).fetchone()
            document = _document(operation)
            if document["review_context"].get("schema_version") in (
                "bluefire.windows-file-access-baseline-context.v1",
                "bluefire.windows-file-access-baseline-context.v2",
                "bluefire.windows-file-access-correction-context.v1",
            ) and (
                control is not None
                or verified_observation is not None
                or outcome["state"] in ("complete", "settled_partial")
            ):
                raise ProductStoreError(
                    "Windows publication requires its separate complete proof boundary."
                )
            if (
                outcome["state"] == "refused_no_effect"
                and connection.execute(
                    "SELECT 1 FROM file_access_windows_control_evidence WHERE job_id=? LIMIT 1",
                    (job_id,),
                ).fetchone()
            ):
                raise ProductStoreError("A dispatched Windows correction remains an obligation.")
            record = {
                **outcome,
                "control_digest": content_hash(control) if control is not None else None,
            }
            if verified_observation is not None:
                if outcome["state"] != "complete" or operation["operation"] not in (
                    "baseline",
                    "rollback",
                ):
                    raise ProductStoreError(
                        "Only complete original reads can publish observation proof."
                    )
                record["verified_observation"] = verified_observation
            previous = _outcome_at(connection, job_id)
            if previous is not None:
                previous_document = _document(previous)
                if previous_document == record:
                    return
                if (
                    expected_outcome_digest != previous["document_digest"]
                    or previous_document["state"] != "unknown"
                    or outcome["state"] == "unknown"
                ):
                    raise ProductStoreError(
                        "Reconciliation requires the exact uncertain original operation."
                    )
            elif expected_outcome_digest is not None:
                raise ProductStoreError("There is no uncertain original operation to reconcile.")
            tasks = connection.execute(
                "SELECT * FROM file_access_task_claims WHERE job_id=? ORDER BY rowid", (job_id,)
            ).fetchall()
            originals = []
            if outcome["state"] != "unknown":
                for task in tasks:
                    terminal = _document(
                        connection.execute(
                            "SELECT * FROM file_access_task_terminals WHERE task_id=?",
                            (task["task_id"],),
                        ).fetchone()
                    )
                    if (
                        terminal["task_id"] != task["task_id"]
                        or terminal["request_hash"] != task["request_hash"]
                    ):
                        raise ProductStoreError(
                            "A file-access task terminal lost its exact binding."
                        )
                    if (
                        outcome["state"] == "refused_no_effect"
                        and terminal["result"].get("schema_version") != "bluefire.task-not-sent.v1"
                    ):
                        raise ProductStoreError(
                            "A dispatched task cannot be dismissed as no effect."
                        )
                    claimed = _document(task)
                    originals.append({"task": claimed, "terminal": terminal})
                    from .capability_packs import FILE_ACCESS_METHODS

                    if claimed["manifest"]["action_id"] == FILE_ACCESS_METHODS[0]:
                        closure = _document(
                            connection.execute(
                                "SELECT * FROM file_access_worker_closures WHERE task_id=?",
                                (task["task_id"],),
                            ).fetchone()
                        )
                        if (
                            closure["terminal_digest"] != content_hash(terminal["result"])
                            or closure["request_hash"] != task["request_hash"]
                        ):
                            raise ProductStoreError(
                                "An original worker request remains unresolved."
                            )
            if control is not None:
                if outcome["state"] not in ("complete", "settled_partial") or not tasks:
                    raise ProductStoreError(
                        "A retained control revision needs actual verified task effects."
                    )
                if (outcome["state"] == "settled_partial") != (
                    control["status"] == "recovery_required"
                ):
                    raise ProductStoreError(
                        "A partial outcome permits only an explicit reviewed reset."
                    )
                prepared = _document(
                    connection.execute(
                        "SELECT * FROM file_access_preparations WHERE job_id=?", (job_id,)
                    ).fetchone()
                )
                if outcome["state"] == "complete":
                    expected_status = {
                        "create": "created",
                        "baseline": "baseline_verified",
                        "harden": "hardened",
                        "rollback": "rolled_back",
                        "reset": "reset",
                    }[operation["operation"]]
                    if (
                        control["status"] != expected_status
                        or [task["step_id"] for task in tasks]
                        != [row["step_id"] for row in prepared["recipe"]]
                        or any(
                            _document(
                                connection.execute(
                                    "SELECT * FROM file_access_task_terminals WHERE task_id=?",
                                    (task["task_id"],),
                                ).fetchone()
                            )["result"].get("status")
                            != "success"
                            for task in tasks
                        )
                    ):
                        raise ProductStoreError(
                            "Complete control requires the entire exact successful recipe."
                        )
                    if operation["operation"] in ("baseline", "rollback"):
                        from .file_access_observation import validate_committed_observation

                        validate_committed_observation(
                            job_id,
                            operation["operation"],
                            prepared,
                            originals,
                            control=control,
                            outcome=outcome,
                            observation=verified_observation,
                            now_ms=now_ms,
                        )
                else:
                    from .file_access_receipts import validate_partial_sources

                    validate_partial_sources(prepared, originals, control)
                owner_id = operation["control_owner_id"]
                prior = (
                    None
                    if operation["operation"] == "create"
                    else _control_at(connection, owner_id)
                )
                expected_revision = 1 if prior is None else prior["document"]["revision"] + 1
                if (
                    control["control_owner_id"] != owner_id
                    or control["enrollment_id"] != operation["enrollment_id"]
                    or control["revision"] != expected_revision
                    or (
                        prior is not None
                        and prior["document_digest"] != document["review"]["control_digest"]
                    )
                ):
                    raise ProductStoreError(
                        "The retained control revision does not follow its exact reviewed parent."
                    )
                connection.execute(
                    "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                    (
                        owner_id,
                        expected_revision,
                        job_id,
                        canonical_json(control),
                        content_hash(control),
                    ),
                )
            elif outcome["state"] in ("complete", "settled_partial"):
                raise ProductStoreError(
                    "A complete retained file operation requires its verified revision."
                )
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                (job_id, canonical_json(record), content_hash(record)),
            )

    def file_access_operation_records(self, job_id):
        store = cast(Any, self)
        with store._connection() as connection:
            operation = connection.execute(
                "SELECT * FROM file_access_operations WHERE job_id=?", (job_id,)
            ).fetchone()
            document = _document(operation)
            tasks = connection.execute(
                "SELECT * FROM file_access_task_claims WHERE job_id=? ORDER BY rowid", (job_id,)
            ).fetchall()
            outcome = _outcome_at(connection, job_id)
            preparation_row = connection.execute(
                "SELECT * FROM file_access_preparations WHERE job_id=?", (job_id,)
            ).fetchone()
            preparation = _document(preparation_row) if preparation_row is not None else None
            return {
                "document": document,
                "control_owner_id": operation["control_owner_id"],
                "preparation": preparation,
                "tasks": [
                    {
                        "task": _document(row),
                        "terminal": (
                            _document(terminal)
                            if (
                                terminal := connection.execute(
                                    "SELECT * FROM file_access_task_terminals WHERE task_id=?",
                                    (row["task_id"],),
                                ).fetchone()
                            )
                            is not None
                            else None
                        ),
                    }
                    for row in tasks
                ],
                "outcome": _document(outcome) if outcome is not None else None,
                "outcome_digest": outcome["document_digest"] if outcome is not None else None,
            }

    def begin_file_access_reconciliation(self, job_id, request):
        store = cast(Any, self)
        store._job_submission_binding(request["submission_id"], content_hash(request))
        with store._connection(write=True) as connection:
            previous = connection.execute(
                "SELECT * FROM file_access_reconciliations WHERE submission_id=?",
                (request["submission_id"],),
            ).fetchone()
            if previous is not None:
                if previous["job_id"] != job_id or _document(previous) != request:
                    raise ProductStoreError(
                        "The reconciliation identity already names another request."
                    )
                return request, False
            outcome = _outcome_at(connection, job_id)
            if (
                _document(outcome)["state"] != "unknown"
                or outcome["document_digest"] != request["expected_outcome_digest"]
            ):
                raise ProductStoreError(
                    "Review the exact uncertain original operation before reconciliation."
                )
            connection.execute(
                "INSERT INTO file_access_reconciliations VALUES(?,?,?,?)",
                (request["submission_id"], job_id, canonical_json(request), content_hash(request)),
            )
            return request, True

    def finish_file_access_reconciliation(self, job_id, submission_id, *, problem):
        store = cast(Any, self)
        with store._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM file_access_reconciliations WHERE submission_id=?", (submission_id,)
            ).fetchone()
            request = _document(row)
            if row["job_id"] != job_id:
                raise ProductStoreError(
                    "Reconciliation completion belongs to another original operation."
                )
            result = {
                "submission_id": submission_id,
                "submitted_request": request,
                "state": "completed",
                "problem": problem,
            }
            previous = connection.execute(
                "SELECT * FROM file_access_reconciliation_results WHERE submission_id=?",
                (submission_id,),
            ).fetchone()
            if previous is not None:
                if _document(previous) != result:
                    raise ProductStoreError("Reconciliation result is immutable.")
                return
            connection.execute(
                "INSERT INTO file_access_reconciliation_results VALUES(?,?,?)",
                (submission_id, canonical_json(result), content_hash(result)),
            )

    def get_file_access_reconciliation(self, job_id, submission_id):
        store = cast(Any, self)
        with store._connection() as connection:
            row = connection.execute(
                "SELECT * FROM file_access_reconciliations WHERE submission_id=?", (submission_id,)
            ).fetchone()
            request = _document(row)
            if row["job_id"] != job_id:
                raise ProductStoreError("The reconciliation belongs to another original operation.")
            result = connection.execute(
                "SELECT * FROM file_access_reconciliation_results WHERE submission_id=?",
                (submission_id,),
            ).fetchone()
            return (
                _document(result)
                if result is not None
                else {
                    "submission_id": submission_id,
                    "submitted_request": request,
                    "state": "pending",
                    "problem": None,
                }
            )

    def latest_file_access_reconciliation(self, job_id):
        store = cast(Any, self)
        with store._connection() as connection:
            row = connection.execute(
                "SELECT submission_id FROM file_access_reconciliations WHERE job_id=? ORDER BY rowid DESC LIMIT 1",
                (job_id,),
            ).fetchone()
        return (
            None
            if row is None
            else self.get_file_access_reconciliation(job_id, row["submission_id"])
        )
