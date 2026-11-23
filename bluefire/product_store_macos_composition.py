"""Append-only attempt provenance for the closed Darwin composition pack."""

from __future__ import annotations

import sqlite3
import sys
import time
from contextlib import contextmanager
from typing import Any, Mapping

from . import product_store_capability_cleanup as cleanup
from . import product_store_capability_grants as records
from . import product_store_capability_transport as transport
from .capability_resources import digest
from .macos_file_access_clock import darwin_clock_ns
from .macos_file_access_contract import MAX_MESSAGE, MAX_REQUESTS
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_file_access_records import (
    _control_at as _file_access_control_at,
)
from .product_store_file_access_records import (
    _document as _file_access_document,
)
from .product_store_file_access_records import (
    _pending as _file_access_pending,
)
from .product_store_file_access_records import (
    imported_at as _file_access_imported_at,
)
from .product_store_serialization import canonical_json
from .util import canonical_json_bytes, content_hash

_ACTIONS = {
    "probe": "macos.file_access.probe.v1",
    "verify_owner": "macos.file_access.verify_owner.v1",
    "close_attempt": "macos.file_access.close_attempt.v1",
}
_ATTEMPT_SCHEMA = "bluefire.macos-file-access-attempt-dispatch.v1"
_CLEANUP_SCHEMA = "bluefire.macos-file-access-artifact-closure-claim.v1"
_MAX_INT = 2**63 - 1
_MAX_RESULT_BYTES = 4 * MAX_MESSAGE


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise ProductStoreError("Darwin composition migration requires one transaction.")
    definitions = {
        "capability_macos_file_access_attempts": "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
        "capability_macos_file_access_events": "sequence INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id TEXT NOT NULL REFERENCES capability_macos_file_access_attempts(attempt_id), event_type TEXT NOT NULL, event_key TEXT NOT NULL, document_json TEXT NOT NULL, document_digest TEXT NOT NULL, UNIQUE(attempt_id,event_type,event_key)",
        "capability_macos_file_access_closures": "attempt_id TEXT PRIMARY KEY REFERENCES capability_macos_file_access_attempts(attempt_id), document_json TEXT NOT NULL, document_digest TEXT NOT NULL",
    }
    for table, definition in definitions.items():
        connection.execute(f"CREATE TABLE IF NOT EXISTS {table}({definition})")
        for operation in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} "
                f"BEFORE {operation} ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'Darwin composition history is append-only'); END"
            )


def _integer(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INT:
        raise ProductStoreError(f"The retained {name} is invalid.")
    return value


def _time_pair(wall: Any, monotonic: Any, name: str) -> tuple[int, int]:
    return _integer(wall, name + " wall time"), _integer(monotonic, name + " monotonic time")


def _result_document(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProductStoreError("The original Darwin runner result is invalid.")
    try:
        result = dict(safe_document(dict(value), context="Darwin task result"))
        if len(canonical_json_bytes(result)) > _MAX_RESULT_BYTES:
            raise ProductStoreError(
                "The original Darwin runner result exceeds its finite message bound."
            )
    except (TypeError, RecursionError) as exc:
        raise ProductStoreError("The original Darwin runner result is invalid.") from exc
    return result


def _append(connection, table: str, attempt_id: str, event_type: str, event_key: str, document):
    encoded = canonical_json(dict(document))
    binding = content_hash(dict(document))
    # Internal callers supply only the literal Mac events table; all values stay bound.
    connection.execute(
        f"INSERT INTO {table}(attempt_id,event_type,event_key,document_json,document_digest) "  # nosec B608
        "VALUES(?,?,?,?,?)",
        (attempt_id, event_type, event_key, encoded, binding),
    )
    return binding


def _event(connection, attempt_id: str, event_type: str, event_key: str):
    row = connection.execute(
        "SELECT * FROM capability_macos_file_access_events "
        "WHERE attempt_id=? AND event_type=? AND event_key=?",
        (attempt_id, event_type, event_key),
    ).fetchone()
    return None if row is None else records._document(row)


def _payload_at(store, connection, task, lease, compiled, *, purpose="business"):
    payload_row = records._one(
        connection, "SELECT * FROM capability_task_payloads WHERE task_id=?", task["task_id"]
    )
    payload = records._document(payload_row, field="payload_json", digest_field="payload_digest")
    claim_row, claim = records._claim_at(connection, task["attempt_id"], lease)
    workspace = cleanup.workspace_at(connection, task["attempt_id"], lease)
    dependency = store._capability_dependency_at(connection, task["attempt_id"], lease)
    manifest, profile = payload.get("manifest"), payload.get("runner_profile")
    if not isinstance(manifest, Mapping) or not isinstance(profile, Mapping):
        raise ProductStoreError("The retained Darwin task payload is incomplete.")
    macos_cleanup_claim = None
    macos_cleanup_claim_digest = None
    if purpose == "macos_cleanup":
        cleanup_event = _event(connection, task["attempt_id"], "cleanup_claim", "close_attempt")
        registration = _event(
            connection, task["attempt_id"], "cleanup_task_registered", task["task_id"]
        )
        if cleanup_event is None or registration is None:
            raise ProductStoreError("The retained Mac closure task lacks its dedicated claim.")
        macos_cleanup_claim = cleanup_event["claim"]
        macos_cleanup_claim_digest = cleanup_event["claim_digest"]
        if (
            registration.get("task_id") != task["task_id"]
            or registration.get("step_id") != task["step_id"]
            or registration.get("request_hash") != task["request_hash"]
            or registration.get("cleanup_claim_digest") != macos_cleanup_claim_digest
            or registration.get("payload_digest") != content_hash(payload)
        ):
            raise ProductStoreError("The retained Mac closure registration changed.")
    elif purpose != "business":
        raise ProductStoreError("The Darwin task payload purpose is invalid.")
    expected = transport.payload_document(
        purpose=purpose,
        task_id=task["task_id"],
        attempt_id=task["attempt_id"],
        lease=lease,
        step_id=task["step_id"],
        request_hash=task["request_hash"],
        manifest=manifest,
        runner_profile=profile,
        attempt_claim=claim,
        attempt_claim_digest=claim_row["document_digest"],
        workspace=workspace,
        dependency=dependency,
        macos_cleanup_claim=macos_cleanup_claim,
        macos_cleanup_claim_digest=macos_cleanup_claim_digest,
    )
    if payload != expected:
        raise ProductStoreError("The retained Darwin task payload changed.")
    return payload


def _mac_dependency(compiled: Mapping[str, Any]) -> dict[str, Any]:
    dependency = compiled.get("macos_file_access")
    expected = {
        "schema_version",
        "probe_step_id",
        "owner_step_id",
        "cleanup_step_id",
        "control_owner_id",
        "control_digest",
        "resource_id",
        "resource_generation",
        "resource_digest",
        "probe_enrollment_digest",
        "baseline_digest",
        "control_revision",
        "workspace_custody_digest",
        "binding_digest",
    }
    if not isinstance(dependency, dict) or set(dependency) != expected:
        raise ProductStoreError("The compiled Darwin composition dependency is invalid.")
    if dependency["schema_version"] != "bluefire.macos-file-access-composition-dependency.v1":
        raise ProductStoreError("The compiled Darwin composition dependency changed.")
    for key in (
        "control_digest",
        "resource_digest",
        "probe_enrollment_digest",
        "baseline_digest",
        "workspace_custody_digest",
        "binding_digest",
    ):
        digest(dependency[key], "Darwin " + key)
    for key in (
        "probe_step_id",
        "owner_step_id",
        "cleanup_step_id",
        "control_owner_id",
        "resource_id",
        "resource_generation",
    ):
        if not isinstance(dependency[key], str) or not dependency[key]:
            raise ProductStoreError("The compiled Darwin composition identity is invalid.")
    if type(dependency["control_revision"]) is not int or dependency["control_revision"] <= 0:
        raise ProductStoreError("The compiled Darwin control revision is invalid.")
    return dict(dependency)


def _step_actions(compiled: Mapping[str, Any]) -> dict[str, str]:
    scenario = compiled.get("scenario")
    steps = scenario.get("steps") if isinstance(scenario, Mapping) else None
    implementations = compiled.get("action_implementations")
    if not isinstance(steps, list) or not isinstance(implementations, Mapping):
        raise ProductStoreError("The compiled Darwin scenario has no steps.")
    result: dict[str, str] = {}
    for step in steps:
        if not isinstance(step, Mapping):
            raise ProductStoreError("The compiled Darwin scenario contains an invalid step.")
        step_id, behavior_id = step.get("id"), step.get("behavior_id")
        if (
            not isinstance(step_id, str)
            or not isinstance(behavior_id, str)
            or behavior_id not in _ACTIONS.values()
            or implementations.get(step_id) != behavior_id
            or step_id in result
        ):
            raise ProductStoreError("The compiled Darwin step identity is invalid.")
        result[step_id] = behavior_id
    if set(result) != set(implementations):
        raise ProductStoreError("The compiled Darwin implementation inventory changed.")
    return result


def _acceptance_clock() -> tuple[int, int]:
    return time.time_ns() // 1_000_000, darwin_clock_ns()


def _require_current_acceptance(dispatch, binding, cleanup_claim=None) -> None:
    """Durable success uses the original clocks, including time spent writing."""
    wall, monotonic = _acceptance_clock()
    wall, monotonic = _time_pair(wall, monotonic, "success acceptance")
    intent = dispatch["intent"]
    if (
        not intent["issued_at_ms"] <= wall < intent["expires_at_ms"]
        or not intent["issued_monotonic_ns"] <= monotonic < intent["deadline_ns"]
        or not binding["issued_at_ms"] <= wall < binding["expires_at_ms"]
        or monotonic >= binding["original_deadline_ns"]
        or cleanup_claim is not None
        and (
            not cleanup_claim["issued_at_ms"] <= wall < cleanup_claim["expires_at_ms"]
            or not cleanup_claim["issued_monotonic_ns"] <= monotonic < cleanup_claim["deadline_ns"]
        )
    ):
        raise ProductStoreError("The original Darwin durable-success deadline has expired.")


@contextmanager
def _success_acceptance(dispatch, binding, cleanup_claim=None):
    _require_current_acceptance(dispatch, binding, cleanup_claim)
    yield
    _require_current_acceptance(dispatch, binding, cleanup_claim)


def _validate_closure_budget(connection, attempt_id, reservation, closure) -> None:
    used = closure["shared_request_budget_used"]
    if type(used) is not int or not 0 <= used <= MAX_REQUESTS:
        raise ProductStoreError("The original producer's cumulative budget is invalid.")
    for step_id in (reservation["probe_step_id"], reservation["owner_step_id"]):
        receipt = _event(connection, attempt_id, "receipt", step_id)
        if receipt is not None and receipt["state"] == "complete":
            # The pair is reserved before the first read and never refunded.
            # Control requests and prior attempts also consume this counter.
            retained = receipt.get("shared_request_budget_used")
            if type(retained) is not int or retained != used:
                raise ProductStoreError(
                    "The closure changed the original cumulative request budget."
                )


def _mac_enrollment_digest(connection, binding: Mapping[str, Any]) -> str:
    from . import product_store_macos_file_access as macos

    row = connection.execute(
        "SELECT * FROM file_access_enrollments WHERE enrollment_id=?",
        (binding["enrollment_id"],),
    ).fetchone()
    enrolled = _file_access_document(row)
    canonical = macos.enrollment_document(macos.setup_document(enrolled["setup"]))
    if enrolled != canonical:
        raise ProductStoreError("The original Darwin enrollment lineage changed.")
    return content_hash(canonical)


def _original_macos_control(connection, dependency: Mapping[str, Any]):
    from .macos_file_access_contract import validate_binding

    row = connection.execute(
        "SELECT * FROM file_access_revisions WHERE control_owner_id=? AND revision=?",
        (dependency["control_owner_id"], dependency["control_revision"]),
    ).fetchone()
    if row is None:
        view = _file_access_imported_at(connection, dependency["control_owner_id"])
    else:
        control = _file_access_document(row)
        if control.get("revision") != dependency["control_revision"]:
            raise ProductStoreError("The original Darwin control revision changed.")
        view = {"document": control, "document_digest": row["document_digest"]}
    if view is None:
        raise ProductStoreError("The original Darwin control revision is unavailable.")
    control = view["document"]
    binding = validate_binding(control.get("binding"))
    baseline = control.get("baseline")
    resource_id = "file-resource-" + content_hash(binding["resource"])[7:39]
    if (
        view["document_digest"] != dependency["control_digest"]
        or control.get("control_owner_id") != dependency["control_owner_id"]
        or control.get("enrollment_id") != binding["enrollment_id"]
        or control.get("generation") != binding["generation"]
        or control.get("revision") != dependency["control_revision"]
        or control.get("status") != "hardened"
        or not isinstance(baseline, Mapping)
        or baseline.get("baseline_digest") != dependency["baseline_digest"]
        or content_hash(binding) != dependency["binding_digest"]
        or binding["generation"] != dependency["resource_generation"]
        or binding["control_revision"] != dependency["control_revision"]
        or content_hash(binding["resource"]) != dependency["resource_digest"]
        or resource_id != dependency["resource_id"]
        or binding["custody_digest"] != dependency["workspace_custody_digest"]
        or _mac_enrollment_digest(connection, binding) != dependency["probe_enrollment_digest"]
    ):
        raise ProductStoreError(
            "The original Darwin control or binding differs from the compiled pack."
        )
    return view, control, binding


def guard_control(store, connection, grant: Mapping[str, Any]) -> None:
    """Require the current original hardened control for new Mac business authority."""
    environment = grant.get("environment")
    if not isinstance(environment, Mapping):
        raise ProductStoreError("The Mac control environment is unavailable.")
    dependency = {
        key: environment[key]
        for key in (
            "control_owner_id",
            "control_digest",
            "resource_id",
            "resource_generation",
            "resource_digest",
            "probe_enrollment_digest",
            "baseline_digest",
            "control_revision",
            "workspace_custody_digest",
            "binding_digest",
        )
    }
    _, control, _ = _original_macos_control(connection, dependency)
    current = _file_access_control_at(connection, dependency["control_owner_id"])
    if (
        current["document_digest"] != dependency["control_digest"]
        or current["document"] != control
        or _file_access_pending(connection, dependency["control_owner_id"])
    ):
        raise ProductStoreError("The exact current hardened Mac control is unavailable.")


def reserve_macos_capability_attempt(
    store,
    attempt_id: str,
    *,
    now_ms: int,
    monotonic_ns: int,
    business_deadline_ns: int,
    cleanup_deadline_ns: int,
    workspace_attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind the whole fixed two-call attempt before any operation dispatches."""
    now_ms, monotonic_ns = _time_pair(now_ms, monotonic_ns, "attempt start")
    business_deadline_ns = _integer(business_deadline_ns, "business deadline")
    cleanup_deadline_ns = _integer(cleanup_deadline_ns, "cleanup deadline")
    if workspace_attestation is not None and not isinstance(workspace_attestation, Mapping):
        raise ProductStoreError("The original workspace attestation is invalid.")
    with store._connection(write=True) as connection:
        row, lease, compiled = records._attempt_at(connection, attempt_id)
        records._claim_at(connection, attempt_id, lease)
        dependency = _mac_dependency(compiled)
        workspace = cleanup.workspace_at(connection, attempt_id, lease)
        retained_dependency = store._capability_dependency_at(connection, attempt_id, lease)
        attestation = _verify_workspace_attestation(
            store, connection, attempt_id, lease, compiled, "reserve", workspace_attestation
        )
        control_view = _file_access_control_at(connection, dependency["control_owner_id"])
        _, control, binding = _original_macos_control(connection, dependency)
        if (
            retained_dependency.get("attempt_id") != attempt_id
            or retained_dependency.get("lease_digest") != lease["lease_digest"]
            or retained_dependency.get("resource_generation") != dependency["resource_generation"]
            or retained_dependency.get("control_revision") != dependency["control_revision"]
            or retained_dependency.get("binding_digest") != dependency["binding_digest"]
            or content_hash(binding) != dependency["binding_digest"]
            or control_view["document_digest"] != dependency["control_digest"]
            or control.get("status") != "hardened"
            or _file_access_pending(connection, dependency["control_owner_id"])
        ):
            raise ProductStoreError("The Darwin dependency or original workspace binding changed.")
        actions = _step_actions(compiled)
        for name in ("probe", "verify_owner", "close_attempt"):
            step_id = dependency[
                {
                    "probe": "probe_step_id",
                    "verify_owner": "owner_step_id",
                    "close_attempt": "cleanup_step_id",
                }[name]
            ]
            if actions.get(step_id) != _ACTIONS[name]:
                raise ProductStoreError(
                    "The compiled Darwin task actions differ from the fixed pack."
                )
        if (
            binding.get("generation") != dependency["resource_generation"]
            or binding.get("control_revision") != dependency["control_revision"]
            or not isinstance(binding.get("original_deadline_ns"), int)
            or not isinstance(binding.get("expires_at_ms"), int)
            or not now_ms < lease["business_expires_at_ms"]
            or not now_ms < binding["expires_at_ms"]
            or not monotonic_ns < business_deadline_ns <= binding["original_deadline_ns"]
            or not business_deadline_ns < cleanup_deadline_ns <= binding["original_deadline_ns"]
            or not lease["created_at_ms"] <= now_ms < lease["business_expires_at_ms"]
            or cleanup_deadline_ns <= monotonic_ns
        ):
            raise ProductStoreError("The Darwin attempt deadlines exceed their original authority.")
        document = {
            "schema_version": _ATTEMPT_SCHEMA,
            "attempt_id": attempt_id,
            "grant_id": lease["grant_id"],
            "grant_digest": lease["grant_digest"],
            "lease_digest": lease["lease_digest"],
            "compiled_digest": lease["compiled_digest"],
            "job_id": lease["job_id"],
            "run_id": lease["run_id"],
            "control_owner_id": lease["control_owner_id"],
            "workspace_binding_digest": content_hash(workspace),
            "dependency_digest": content_hash(retained_dependency),
            "probe_step_id": dependency["probe_step_id"],
            "owner_step_id": dependency["owner_step_id"],
            "cleanup_step_id": dependency["cleanup_step_id"],
            "issued_at_ms": now_ms,
            "business_expires_at_ms": min(
                lease["business_expires_at_ms"], binding["expires_at_ms"]
            ),
            "cleanup_expires_at_ms": min(lease["attempt_expires_at_ms"], binding["expires_at_ms"]),
            "issued_monotonic_ns": monotonic_ns,
            "business_deadline_ns": business_deadline_ns,
            "cleanup_deadline_ns": cleanup_deadline_ns,
            "primitive_budget": {"probe": 1, "verify_owner": 1, "total": 2},
        }
        if (
            not document["issued_at_ms"]
            < document["business_expires_at_ms"]
            < document["cleanup_expires_at_ms"]
        ):
            raise ProductStoreError("The retained Darwin deadline order is invalid.")
        existing = connection.execute(
            "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        prior_attestation = _event(connection, attempt_id, "workspace_reserved", attempt_id)
        if existing is not None:
            if records._document(existing) != document or prior_attestation != dict(attestation):
                raise ProductStoreError("The Darwin attempt reservation is already immutable.")
            return document
        connection.execute(
            "INSERT INTO capability_macos_file_access_attempts VALUES(?,?,?)",
            (attempt_id, canonical_json(document), content_hash(document)),
        )
        _append(
            connection,
            "capability_macos_file_access_events",
            attempt_id,
            "workspace_reserved",
            attempt_id,
            attestation,
        )
        return document


def begin_macos_capability_dispatch(
    store,
    task_id: str,
    transport_request_hash: str,
    *,
    now_ms: int,
    now_monotonic_ns: int,
    creator_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Commit a one-shot Darwin dispatch marker before the bridge writes bytes."""
    digest(transport_request_hash, "Darwin transport identity")
    now_ms, now_monotonic_ns = _time_pair(now_ms, now_monotonic_ns, "dispatch time")
    if not isinstance(creator_context, Mapping):
        raise ProductStoreError("The original creator context is required.")
    from .execution_contracts import execution_task_identity
    from .product_store_macos_file_access import exact, require

    with store._connection(write=True) as connection:
        task = records._one(
            connection, "SELECT * FROM capability_task_claims WHERE task_id=?", task_id
        )
        attempt_id = task["attempt_id"]
        reservation_row = records._one(
            connection,
            "SELECT * FROM capability_macos_file_access_attempts WHERE attempt_id=?",
            attempt_id,
        )
        reservation = records._document(reservation_row)
        _, lease, compiled = records._attempt_at(connection, attempt_id)
        records._claim_at(connection, attempt_id, lease)
        actions = _step_actions(compiled)
        action_id = actions.get(task["step_id"])
        operation = next((name for name, value in _ACTIONS.items() if value == action_id), None)
        if (
            operation is None
            or task["step_id"]
            != reservation[
                {
                    "probe": "probe_step_id",
                    "verify_owner": "owner_step_id",
                    "close_attempt": "cleanup_step_id",
                }[operation]
            ]
        ):
            raise ProductStoreError("The task is outside the exact compiled Darwin attempt.")
        # Revalidate the ordinary registered runner envelope before creating the one-shot marker.
        payload_purpose = "macos_cleanup" if operation == "close_attempt" else "business"
        payload = _payload_at(store, connection, task, lease, compiled, purpose=payload_purpose)
        manifest, profile = payload["manifest"], payload["runner_profile"]
        dependency = _mac_dependency(compiled)
        retained_dependency = store._capability_dependency_at(connection, attempt_id, lease)
        _, original_control, original_binding = _original_macos_control(connection, dependency)
        if (
            execution_task_identity(manifest, profile) != (task_id, transport_request_hash)
            or manifest.get("action_id") != _ACTIONS[operation]
            or manifest.get("params") != {}
            or manifest.get("platform") != "macos"
            or profile.get("platform") != "macos"
            or profile.get("macos_file_access_binding") != original_binding
            or retained_dependency.get("binding_digest") != content_hash(original_binding)
            or profile.get("macos_file_access_binding") != creator_context.get("binding")
        ):
            raise ProductStoreError(
                "The retained Darwin task payload differs from its creator context."
            )
        exact(
            creator_context,
            {"schema_version", "operation", "state", "binding", "probe_digest", "context_digest"},
            "Darwin creator context",
        )
        require(
            creator_context["schema_version"] == "bluefire.macos-file-access-creator-context.v1"
            and creator_context["operation"] == operation
            and creator_context["context_digest"]
            == content_hash(
                {key: value for key, value in creator_context.items() if key != "context_digest"}
            )
            and creator_context["binding"] == profile["macos_file_access_binding"]
        )
        if operation != "close_attempt":
            _, grant, event = records._grant_at(connection, lease["grant_id"])
            current_control = _file_access_control_at(connection, dependency["control_owner_id"])
            if (
                now_ms < reservation["issued_at_ms"]
                or now_monotonic_ns < reservation["issued_monotonic_ns"]
                or event["status"] != "active"
                or now_ms < records._lineage_time(connection, lease["lineage_id"])
                or now_ms >= reservation["business_expires_at_ms"]
                or now_monotonic_ns >= reservation["business_deadline_ns"]
                or current_control["document_digest"] != dependency["control_digest"]
                or current_control["document"] != original_control
                or _file_access_pending(connection, dependency["control_owner_id"])
            ):
                raise ProductStoreError("Darwin business authority is stopped or expired.")
            store._guard_capability_control(connection, grant)
        else:
            if (
                now_ms < reservation["issued_at_ms"]
                or now_monotonic_ns < reservation["issued_monotonic_ns"]
                or now_ms < records._lineage_time(connection, lease["lineage_id"])
                or now_ms >= reservation["cleanup_expires_at_ms"]
                or now_monotonic_ns >= reservation["cleanup_deadline_ns"]
            ):
                raise ProductStoreError("Darwin attempt closure authority is expired.")
        if connection.execute(
            "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?", (attempt_id,)
        ).fetchone():
            raise ProductStoreError("A settled Darwin attempt cannot dispatch again.")
        prior = _event(connection, attempt_id, "receipt", reservation["probe_step_id"])
        probe_task_id = None
        probe_receipt_digest = None
        pre_close_attestation = None
        if operation == "probe":
            probe_task_id = task_id
        elif operation == "verify_owner":
            if prior is None or prior["state"] != "complete":
                raise ProductStoreError(
                    "Owner verification requires the exact prior probe receipt."
                )
            probe_task_id = prior["task_id"]
            probe_receipt_digest = prior["native_receipt_digest"]
            if creator_context.get("probe_digest") != probe_receipt_digest:
                raise ProductStoreError(
                    "The original creator no longer retains this probe receipt."
                )
        elif operation == "close_attempt":
            closures = _task_closures(connection, attempt_id, reservation)
            if (
                prior is None
                and closures
                or prior is not None
                and prior["state"] not in {"complete", "not_sent"}
            ):
                raise ProductStoreError("Attempt closure requires resolved probe disposition.")
            if prior is not None and prior["state"] == "complete":
                probe_task_id = prior["task_id"]
                probe_receipt_digest = prior["native_receipt_digest"]
                if creator_context.get("probe_digest") != probe_receipt_digest:
                    raise ProductStoreError(
                        "The original creator no longer retains this probe receipt."
                    )
            # With no completed current probe, the creator may still retain an
            # older enrollment-global probe. It is not adopted into this attempt.
            pre_close_attestation = _verify_workspace_attestation(
                store, connection, attempt_id, lease, compiled, "pre_close", None
            )
            cleanup_event = _event(connection, attempt_id, "cleanup_claim", "close_attempt")
            registration = _event(connection, attempt_id, "cleanup_task_registered", task_id)
            if (
                cleanup_event is None
                or registration is None
                or registration.get("task_id") != task_id
                or registration.get("step_id") != task["step_id"]
                or registration.get("request_hash") != task["request_hash"]
                or registration.get("transport_request_hash") != transport_request_hash
                or registration.get("cleanup_claim_digest") != cleanup_event["claim_digest"]
                or registration.get("payload_digest") != content_hash(payload)
            ):
                raise ProductStoreError(
                    "The Mac closure task lacks its exact dedicated registration."
                )
        from .macos_file_access_contract import MAX_OPERATION_NS

        binding = creator_context["binding"]
        intent_start_ms = now_ms
        intent_start_ns = now_monotonic_ns
        expiry_cap_ms = (
            reservation["business_expires_at_ms"]
            if operation != "close_attempt"
            else reservation["cleanup_expires_at_ms"]
        )
        deadline_cap_ns = (
            reservation["business_deadline_ns"]
            if operation != "close_attempt"
            else reservation["cleanup_deadline_ns"]
        )
        intent = {
            "schema_version": "bluefire.macos-file-access-reviewed-task.v1",
            "operation": operation,
            "task_id": task_id,
            "transport_request_hash": transport_request_hash,
            "context_digest": creator_context["context_digest"],
            "binding_digest": content_hash(binding),
            "control_revision": binding["control_revision"],
            "issued_at_ms": intent_start_ms,
            "expires_at_ms": min(expiry_cap_ms, intent_start_ms + MAX_OPERATION_NS // 1_000_000),
            "issued_monotonic_ns": intent_start_ns,
            "deadline_ns": min(deadline_cap_ns, intent_start_ns + MAX_OPERATION_NS),
        }
        if (
            not intent["issued_at_ms"] < intent["expires_at_ms"]
            or not intent["issued_monotonic_ns"] < intent["deadline_ns"]
        ):
            raise ProductStoreError("The original Darwin operation deadline has expired.")
        marker = {
            "schema_version": "bluefire.macos-file-access-dispatch-marker.v1",
            "attempt_id": attempt_id,
            "task_id": task_id,
            "step_id": task["step_id"],
            "request_hash": task["request_hash"],
            "transport_request_hash": transport_request_hash,
            "operation": operation,
            "intent": intent,
            "creator_context_digest": creator_context["context_digest"],
            "marked_at_ms": now_ms,
            "marked_monotonic_ns": now_monotonic_ns,
        }
        _append(
            connection,
            "capability_macos_file_access_events",
            attempt_id,
            "dispatch",
            task_id,
            marker,
        )
        if pre_close_attestation is not None:
            _append(
                connection,
                "capability_macos_file_access_events",
                attempt_id,
                "workspace_pre_close",
                task_id,
                pre_close_attestation,
            )
        claim = {
            "job_id": lease["job_id"],
            "task_id": task_id,
            "step_id": task["step_id"],
            "request_hash": task["request_hash"],
            "transport_request_hash": transport_request_hash,
            "manifest": manifest,
            "runner_profile": profile,
        }
        attempt = {
            **reservation,
            "probe_task_id": probe_task_id,
            "probe_receipt_digest": probe_receipt_digest,
            "task_closures": (
                _task_closures(connection, attempt_id, reservation)
                if operation == "close_attempt"
                else []
            ),
            "cleanup_claim": None,
            "cleanup_claim_digest": None,
        }
        if operation == "close_attempt":
            attempt["cleanup_claim"] = cleanup_event["claim"]
            attempt["cleanup_claim_digest"] = cleanup_event["claim_digest"]
            if manifest.get("macos_file_access_cleanup") != cleanup_event["claim"]:
                raise ProductStoreError(
                    "The close manifest differs from its retained cleanup claim."
                )
        body = {
            "schema_version": "bluefire.macos-file-access-committed-task.v1",
            "intent": intent,
            "claim": claim,
            "preparation_digest": reservation_row["document_digest"],
            "job_id": lease["job_id"],
            "attempt": attempt,
            "cancelled": False,
        }
        return {**body, "dispatch_digest": content_hash(body)}


def _verify_workspace_attestation(store, connection, attempt_id, lease, compiled, phase, proof):
    try:
        verifier = store._validate_macos_workspace_attestation
    except AttributeError as exc:
        raise ProductStoreError("The original Darwin workspace verifier is unavailable.") from exc
    verified = verifier(connection, attempt_id, lease, compiled, phase=phase, proof=proof)
    if not isinstance(verified, Mapping):
        raise ProductStoreError("The original Darwin workspace attestation is invalid.")
    document = dict(verified)
    expected_fields = {
        "schema_version",
        "attempt_id",
        "lease_digest",
        "compiled_digest",
        "workspace_path_digest",
        "workspace_identity_digest",
        "phase",
        "entry_count",
        "state",
    }
    workspace = cleanup.workspace_at(connection, attempt_id, lease)
    if (
        set(document) != expected_fields
        or document["schema_version"] != "bluefire.macos-file-access-empty-workspace.v1"
        or document["attempt_id"] != attempt_id
        or document["lease_digest"] != lease["lease_digest"]
        or document["compiled_digest"] != lease["compiled_digest"]
        or document["workspace_path_digest"] != workspace["workspace_path_digest"]
        or phase not in {"reserve", "pre_close", "post_close"}
        or document["phase"] != phase
        or type(document["entry_count"]) is not int
        or document["entry_count"] != 0
        or document["state"] != "verified_empty"
    ):
        raise ProductStoreError(
            "The original Darwin workspace attestation does not bind this phase."
        )
    digest(document["workspace_identity_digest"], "Darwin workspace identity")
    return document


def _task_closures(connection, attempt_id, reservation):
    all_tasks = connection.execute(
        "SELECT * FROM capability_task_claims WHERE attempt_id=? ORDER BY step_id",
        (attempt_id,),
    ).fetchall()
    expected_steps = {reservation["probe_step_id"], reservation["owner_step_id"]}
    task_steps = {task["step_id"] for task in all_tasks}
    if not task_steps <= expected_steps | {reservation["cleanup_step_id"]}:
        raise ProductStoreError(
            "Attempt closure requires only its exact registered probe and owner tasks."
        )
    tasks = [task for task in all_tasks if task["step_id"] in expected_steps]
    business_steps = {task["step_id"] for task in tasks}
    probe_event = _event(connection, attempt_id, "receipt", reservation["probe_step_id"])
    if reservation["owner_step_id"] in business_steps and (
        probe_event is None or probe_event["state"] != "complete"
    ):
        raise ProductStoreError("Owner request evidence requires a completed original probe.")
    result = []
    for task in tasks:
        receipt = _event(connection, attempt_id, "receipt", task["step_id"])
        if receipt is None or receipt["task_id"] != task["task_id"]:
            raise ProductStoreError("Attempt closure lacks exact per-task request evidence.")
        if receipt["state"] not in {"complete", "not_sent"}:
            raise ProductStoreError("Unknown Darwin dispatch remains unsettled and read-only.")
        terminal = records._document(
            records._one(
                connection,
                "SELECT * FROM capability_task_terminals WHERE task_id=?",
                task["task_id"],
            )
        )
        if (
            terminal["attempt_id"] != attempt_id
            or terminal["request_hash"] != task["request_hash"]
            or terminal["terminal_digest"] != receipt["terminal_digest"]
        ):
            raise ProductStoreError("Attempt closure lacks its exact authenticated task terminal.")
        result.append(
            {
                "task_id": task["task_id"],
                "transport_request_hash": receipt["transport_request_hash"],
                "request_hash": task["request_hash"],
                "state": receipt["state"],
                "native_receipt_digest": receipt["native_receipt_digest"],
            }
        )
    return result


def claim_macos_capability_cleanup(
    store, attempt_id: str, *, now_ms: int, now_monotonic_ns: int
) -> dict[str, Any]:
    from . import product_store_macos_completion as completion

    return completion.claim_macos_capability_cleanup(
        store,
        attempt_id,
        journal=sys.modules[__name__],
        now_ms=now_ms,
        now_monotonic_ns=now_monotonic_ns,
    )


def register_macos_capability_cleanup_task(
    store,
    attempt_id: str,
    *,
    task_id: str,
    step_id: str,
    request_hash: str,
    expected_document_digest: str,
    now_ms: int,
    now_monotonic_ns: int,
    manifest: Mapping[str, Any],
    runner_profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Register only the distinct attempt-closure task, using the normal runner payload journal."""
    from . import product_store_macos_completion as completion

    return completion.register_macos_capability_cleanup_task(
        store,
        attempt_id,
        journal=sys.modules[__name__],
        task_id=task_id,
        step_id=step_id,
        request_hash=request_hash,
        expected_document_digest=expected_document_digest,
        now_ms=now_ms,
        now_monotonic_ns=now_monotonic_ns,
        manifest=manifest,
        runner_profile=runner_profile,
    )


def record_macos_capability_terminal(
    store, task_id: str, *, result: Mapping[str, Any]
) -> dict[str, Any]:
    from . import product_store_macos_completion as completion

    return completion.record_macos_capability_terminal(
        store, task_id, journal=sys.modules[__name__], result=result
    )


def _intent_for_dispatch(dispatch: Mapping[str, Any]) -> dict[str, Any]:
    # Dispatch records retain only the context digest; the original reviewed intent is
    # reconstructed from these immutable fields and the registered task identity.
    return dict(dispatch["intent"])


def close_macos_capability_attempt(
    store,
    attempt_id: str,
    *,
    cleanup_task_id: str,
    result: Mapping[str, Any],
    workspace_attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Settle only with the exact producer closure and trusted empty workspace proof."""
    from . import product_store_macos_completion as completion

    return completion.close_macos_capability_attempt(
        store,
        attempt_id,
        journal=sys.modules[__name__],
        cleanup_task_id=cleanup_task_id,
        result=result,
        workspace_attestation=workspace_attestation,
    )


def get_macos_capability_closure(store, attempt_id: str) -> dict[str, Any]:
    with store._connection() as connection:
        return records._document(
            records._one(
                connection,
                "SELECT * FROM capability_macos_file_access_closures WHERE attempt_id=?",
                attempt_id,
            )
        )
