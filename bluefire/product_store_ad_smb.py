"""Finite AD reservations and original-task records in the existing jobs database."""

from __future__ import annotations

from copy import deepcopy

from . import ad_smb_results as result
from .ad_smb_contract import AdSmbError, exact
from .product_store_assistance import job_at, patch
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

_PRE_DISPATCH_FAILURE_SCHEMA = "bluefire.ad-smb-pre-dispatch-failure.v1"


def owner_at(store, connection, identifier):
    owner = job_at(store, connection, result.job_id(identifier))
    if owner["kind"] != result.OWNER_KIND:
        raise ProductStoreError("Select a saved AD exercise.")
    result.environment(owner["request"]["environment"])
    result.readiness(owner["request"]["readiness"])
    return owner


def create_owner(store, payload, *, submission_id, intent_digest):
    identifier, binding = store._job_submission_binding(submission_id, intent_digest)
    exact(payload, {"environment", "readiness", "submitted_request"}, "saved AD exercise")
    exact(payload["submitted_request"], {"environment_id"}, "AD selected environment")
    if intent_digest != content_hash(payload["submitted_request"]):
        raise AdSmbError("AD submission must bind its exact requested environment.")
    selected = result.environment(payload["environment"])
    if selected["environment_id"] != payload["submitted_request"]["environment_id"]:
        raise AdSmbError("AD saved environment differs from its submitted selection.")
    if not result.readiness(payload["readiness"])["available"]:
        raise AdSmbError("AD native prerequisites are unavailable.")
    safe = safe_document({**payload, "_submission": binding}, context="AD saved exercise")
    with store._connection(write=True) as connection:
        old = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
        if old is not None:
            return store._matching_job_submission(old, result.OWNER_KIND, binding)
        progress = {
            "revision": 0,
            "operations": [],
            "reserved": {},
            "pending_operation": None,
            "policy_state": "baseline",
            "stopped": False,
        }
        stamp = utc_now()
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) VALUES(?,?,'completed',?,?,?,?)",
            (
                identifier,
                result.OWNER_KIND,
                canonical_json(safe),
                canonical_json(progress),
                stamp,
                stamp,
            ),
        )
        return owner_at(store, connection, identifier)


def list_owners(store):
    with store._connection() as connection:
        rows = connection.execute(
            "SELECT * FROM jobs WHERE kind = ? ORDER BY created_at,job_id", (result.OWNER_KIND,)
        ).fetchall()
        return [store._job_from_row(row) for row in rows]


def _expected_progress(prior, child_id, phase):
    return {
        **prior,
        "revision": prior["revision"] + 1,
        "pending_operation": child_id,
        "reserved": {
            key: prior["reserved"].get(key, 0) + value
            for key, value in result.phase_budget(phase).items()
        },
    }


def _saved_owner(owner, child):
    marker = child["request"]["ad_smb"]
    return {**owner, "progress": marker["prior_progress"]}


def _validate_child(owner, child):
    payload = child["request"]
    exact(payload, {"ad_smb", "submitted_request", "requests", "_submission"}, "AD operation")
    marker = payload["ad_smb"]
    exact(
        marker,
        {"workflow_job_id", "operation_job_id", "phase", "prior_progress", "review"},
        "AD operation marker",
    )
    if (
        child["kind"] != result.OPERATION_KIND
        or marker["workflow_job_id"] != owner["job_id"]
        or marker["operation_job_id"] != child["job_id"]
        or marker["phase"] != payload["submitted_request"]["phase"]
    ):
        raise AdSmbError("AD operation does not belong to its saved exercise.")
    prior_owner = _saved_owner(owner, child)
    if marker["review"] != result.review_document(prior_owner, marker["phase"]):
        raise AdSmbError("AD operation changed its exact reviewed preimage.")
    submitted = payload["submitted_request"]
    exact(
        submitted,
        {"workflow_job_id", "phase", "review_digest", "reviewed_by"},
        "AD reviewed submission",
    )
    if (
        submitted["workflow_job_id"] != owner["job_id"]
        or submitted["review_digest"] != marker["review"]["review_digest"]
        or payload["_submission"]["intent_digest"] != content_hash(submitted)
    ):
        raise AdSmbError("AD operation lost its exact submitted review.")
    result.reviewer(submitted["reviewed_by"])
    requests = payload["requests"]
    if not isinstance(requests, list) or len(requests) != len(result.PHASES[marker["phase"]]):
        raise AdSmbError("AD operation request sequence is incomplete.")
    for index, request in enumerate(requests):
        checked = result.validate_request(prior_owner, request, marker["review"])
        if (
            checked["index"] != index
            or checked["operation_job_id"] != child["job_id"]
            or checked["phase"] != marker["phase"]
            or checked["reviewed_by"] != submitted["reviewed_by"]
            or (checked["requested_at"], checked["deadline"])
            != (requests[0]["requested_at"], requests[0]["deadline"])
        ):
            raise AdSmbError("AD step order or operation identity changed.")
    return prior_owner


def _active_at(store, connection, identifier):
    child = job_at(store, connection, result.job_id(identifier))
    owner = owner_at(store, connection, child["request"]["ad_smb"]["workflow_job_id"])
    _validate_child(owner, child)
    marker = child["request"]["ad_smb"]
    expected = _expected_progress(marker["prior_progress"], identifier, marker["phase"])
    current = owner["progress"]
    if current["stopped"] and not expected["stopped"]:
        expected = {**expected, "stopped": True, "revision": expected["revision"] + 1}
    if current != expected:
        raise AdSmbError("This AD operation is no longer the exact reserved stage.")
    return owner, child


def reserve_operation(store, payload, *, submission_id, intent_digest):
    identifier, binding = store._job_submission_binding(submission_id, intent_digest)
    safe = safe_document({**payload, "_submission": binding}, context="AD operation")
    with store._connection(write=True) as connection:
        old = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
        if old is not None:
            return store._matching_job_submission(old, result.OPERATION_KIND, binding), False
        owner = owner_at(store, connection, safe["ad_smb"]["workflow_job_id"])
        child = {"job_id": identifier, "kind": result.OPERATION_KIND, "request": safe}
        _validate_child(owner, child)
        if owner["progress"] != safe["ad_smb"]["prior_progress"]:
            raise AdSmbError("AD stage needs a fresh review after another operation.")
        scope = owner["request"]["environment"]["scope"]
        for row in connection.execute(
            "SELECT * FROM jobs WHERE kind = ? AND job_id != ?",
            (result.OWNER_KIND, owner["job_id"]),
        ).fetchall():
            peer = store._job_from_row(row)
            other = peer["request"]["environment"]["scope"]
            same_member = scope["hosts"]["member"]["host_id"] == other["hosts"]["member"]["host_id"]
            same_resource = scope["share"]["unc"] == other["share"]["unc"] or (
                scope["share"]["volume_serial"],
                scope["share"]["root_file_id"],
            ) == (other["share"]["volume_serial"], other["share"]["root_file_id"])
            if (
                same_member
                and same_resource
                and (
                    peer["progress"]["pending_operation"]
                    or peer["progress"]["policy_state"] in {"hardened", "unknown"}
                )
            ):
                raise AdSmbError("Another saved AD stage retains this exact member resource.")
        stamp = utc_now()
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) VALUES(?,?,'queued',?,?,?,?)",
            (
                identifier,
                result.OPERATION_KIND,
                canonical_json(safe),
                canonical_json({"tasks": [], "run_id": None}),
                stamp,
                stamp,
            ),
        )
        patch(
            connection,
            owner,
            _expected_progress(owner["progress"], identifier, safe["ad_smb"]["phase"]),
        )
        return job_at(store, connection, identifier), True


def active(store, identifier):
    with store._connection() as connection:
        return _active_at(store, connection, identifier)


def retain_run(store, identifier, run_id, initial):
    with store._connection(write=True) as connection:
        _owner, child = _active_at(store, connection, identifier)
        previous = child["progress"].get("run_id")
        if previous is not None and (
            previous != run_id or child["progress"].get("initial_run") != initial
        ):
            raise AdSmbError("AD original run identity cannot be replaced.")
        patch(
            connection,
            child,
            {"run_id": run_id, "initial_run": safe_document(initial, context="AD original run")},
        )


def retain_original(store, identifier, index, context):
    with store._connection(write=True) as connection:
        owner, child = _active_at(store, connection, identifier)
        if owner["progress"]["stopped"] != child["request"]["ad_smb"]["prior_progress"]["stopped"]:
            raise AdSmbError("AD work was stopped before dispatch.")
        if child["state"] != "running" or child["progress"]["run_id"] is None:
            raise AdSmbError("AD dispatch requires its active original run.")
        tasks = deepcopy(child["progress"]["tasks"])
        if (
            type(index) is not int
            or not 0 <= index < len(child["request"]["requests"])
            or index != len(tasks)
            or any(task["execution"] is None for task in tasks)
        ):
            raise AdSmbError("AD original tasks cannot be replayed or reordered.")
        request = child["request"]["requests"][index]
        checked = result.original_context(request, context)
        tasks.append({"index": index, "context": checked, "execution": None, "recovery": None})
        patch(connection, child, {"tasks": tasks})


def record_terminal(store, identifier, index, execution):
    with store._connection(write=True) as connection:
        owner, child = _active_at(store, connection, identifier)
        if type(index) is not int or not 0 <= index < len(child["request"]["requests"]):
            raise AdSmbError("AD terminal step index is invalid.")
        checked = result.validate_execution(child["request"]["requests"][index], execution)
        if checked["provenance"] != owner["request"]["environment"]["provenance"]:
            raise AdSmbError("AD evidence provenance differs from the selected executor.")
        tasks = deepcopy(child["progress"]["tasks"])
        if (
            index == len(tasks)
            and checked["dispatch"] == "not_started"
            and all(task["execution"] is not None for task in tasks)
        ):
            tasks.append({"index": index, "context": None, "execution": None, "recovery": None})
        if not 0 <= index < len(tasks):
            raise AdSmbError("AD terminal has no exact original task checkpoint.")
        task = tasks[index]
        if task["execution"] is not None and task["execution"] != checked:
            raise AdSmbError("An AD original terminal cannot be overwritten.")
        if checked["dispatch"] != "not_started" and task["context"] is None:
            raise AdSmbError("Attempted AD work lacks its exact native task.")
        if task["context"] is not None:
            result.original_context(child["request"]["requests"][index], task["context"])
        task["execution"] = checked
        patch(connection, child, {"tasks": tasks})


def record_recovery(store, identifier, index, context, execution):
    with store._connection(write=True) as connection:
        owner, child = _active_at(store, connection, identifier)
        if child["state"] not in result.TERMINAL:
            raise AdSmbError("Original recovery requires a terminal local job.")
        tasks = deepcopy(child["progress"]["tasks"])
        if type(index) is not int or not 0 <= index < len(tasks):
            raise AdSmbError("No original AD task exists for recovery.")
        task = tasks[index]
        request = child["request"]["requests"][index]
        if task["context"] is None or result.original_context(request, context) != task["context"]:
            raise AdSmbError("Recovery changed the original authenticated channel binding.")
        checked = result.validate_execution(request, execution)
        if checked["provenance"] != owner["request"]["environment"]["provenance"]:
            raise AdSmbError("AD recovered evidence changed its provenance.")
        if task["execution"] is not None and task["execution"] != checked:
            raise AdSmbError("A saved original terminal cannot be replaced by recovery.")
        if task["recovery"] is not None and task["recovery"] != checked:
            raise AdSmbError("An original recovery result cannot be overwritten.")
        task["recovery"] = checked
        patch(connection, child, {"tasks": tasks})


def _installed_pre_dispatch_failure(child):
    progress = child["progress"]
    run_id = progress.get("run_id")
    if not isinstance(run_id, str) or not isinstance(progress.get("initial_run"), dict):
        raise AdSmbError("AD pre-dispatch failure requires its retained original run.")
    request = child["request"]["requests"][0]
    return {
        "schema_version": _PRE_DISPATCH_FAILURE_SCHEMA,
        "operation_job_id": child["job_id"],
        "run_id": run_id,
        "request_index": 0,
        "request_digest": content_hash(request),
        "boundary": "before_durable_original_checkpoint",
        "producer": "bluefire.ad-smb-controller",
    }


def record_installed_pre_dispatch_failure(store, identifier, index, request):
    """Retain a proven installed no-dispatch boundary only while no task exists."""
    with store._connection(write=True) as connection:
        _owner, child = _active_at(store, connection, identifier)
        expected_request = child["request"]["requests"][0]
        if (
            child["state"] not in {"running", "cancelling"}
            or type(index) is not int
            or index != 0
            or request != expected_request
        ):
            raise AdSmbError("AD pre-dispatch failure does not match an untouched first request.")
        if child["progress"]["tasks"] != []:
            return False
        marker = _installed_pre_dispatch_failure(child)
        previous = child["progress"].get("pre_dispatch_failure")
        if previous is not None and previous != marker:
            raise AdSmbError("AD pre-dispatch failure marker cannot be replaced.")
        patch(connection, child, {"pre_dispatch_failure": marker})
        return True


def adopt_installed_pre_dispatch_failure(store, identifier):
    """Settle an explicitly marked installed failure before the first task checkpoint."""
    with store._connection(write=True) as connection:
        _owner, child = _active_at(store, connection, identifier)
        tasks = child["progress"]["tasks"]
        marker = _installed_pre_dispatch_failure(child)
        if (
            child["state"] not in result.TERMINAL
            or child["progress"].get("pre_dispatch_failure") != marker
        ):
            raise AdSmbError(
                "AD pre-dispatch recovery requires the exact installed-executor failure marker."
            )
        request = child["request"]["requests"][0]
        execution = result.validate_controller_local_execution(
            request,
            {
                "schema_version": "bluefire.ad-smb-execution.v1",
                "request_digest": content_hash(request),
                "provenance": "controller_local",
                "dispatch": "not_started",
                "cleanup": "verified",
                "observation": None,
            },
        )
        adopted = {
            "index": 0,
            "context": None,
            "execution": execution,
            "recovery": None,
        }
        if tasks == [adopted]:
            return execution
        if tasks != []:
            raise AdSmbError("AD pre-dispatch recovery cannot replace original task evidence.")
        patch(
            connection,
            child,
            {"tasks": [adopted]},
        )
        return execution


def _executions(owner, child):
    tasks = child["progress"]["tasks"]
    marker = child["progress"].get("pre_dispatch_failure")
    if marker is not None:
        if marker != _installed_pre_dispatch_failure(child) or len(tasks) != 1:
            raise AdSmbError("AD installed pre-dispatch evidence marker changed.")
        adopted = tasks[0]
        if (
            adopted.get("index") != 0
            or adopted.get("context") is not None
            or adopted.get("recovery") is not None
            or not isinstance(adopted.get("execution"), dict)
            or adopted["execution"].get("dispatch") != "not_started"
            or adopted["execution"].get("observation") is not None
        ):
            raise AdSmbError("AD installed pre-dispatch evidence is not the local adoption.")
    executions = []
    for index, task in enumerate(tasks):
        exact(task, {"index", "context", "execution", "recovery"}, "AD task checkpoint")
        execution = task["recovery"] or task["execution"]
        if (
            task["index"] != index
            or execution is None
            or index >= len(child["request"]["requests"])
        ):
            raise AdSmbError("AD original task evidence remains unresolved.")
        request = child["request"]["requests"][index]
        if task["context"] is not None:
            result.original_context(request, task["context"])
        controller_local = marker is not None and index == 0
        checked = (
            result.validate_controller_local_execution(request, execution)
            if controller_local
            else result.validate_execution(request, execution)
        )
        if (
            (
                checked["provenance"]
                != (
                    "controller_local"
                    if controller_local
                    else owner["request"]["environment"]["provenance"]
                )
            )
            or (checked["dispatch"] != "not_started" and task["context"] is None)
            or (
                task["execution"] is not None
                and task["recovery"] is not None
                and task["execution"] != task["recovery"]
            )
        ):
            raise AdSmbError("AD original terminal provenance or context changed.")
        executions.append(checked)
    if not executions:
        raise AdSmbError("AD stage has no original terminal evidence.")
    return executions


def settled_evidence(store, identifier):
    with store._connection() as connection:
        owner, child = _active_at(store, connection, identifier)
        executions = _executions(owner, child)
        return (
            owner,
            child,
            executions,
            result.outcome(
                child["request"]["ad_smb"]["phase"], executions, owner["progress"]["operations"]
            ),
        )


def finish(store, identifier, publish):
    with store._connection(write=True) as connection:
        owner, child = _active_at(store, connection, identifier)
        executions = _executions(owner, child)
        run_id = child["progress"]["run_id"]
        if not isinstance(run_id, str):
            raise AdSmbError("AD stage has no original run.")
        phase = child["request"]["ad_smb"]["phase"]
        outcome = result.outcome(phase, executions, owner["progress"]["operations"])
        if outcome["state"] == "unknown" or outcome["cleanup"] != "verified":
            raise AdSmbError("AD unsettled results require original-task recovery.")
        # Serialize local publication and its durable release across service instances.
        # Any partial bundle is retained and refused by the trusted RunStore callback.
        publish(owner, child, executions, outcome)
        policy = owner["progress"]["policy_state"]
        if outcome["state"] == "complete" and phase in {"harden", "rollback"}:
            policy = "hardened" if phase == "harden" else "baseline"
        history = [
            *owner["progress"]["operations"],
            {
                "job_id": identifier,
                "phase": phase,
                "run_id": run_id,
                "outcome": outcome,
                "executions": executions,
            },
        ]
        patch(
            connection,
            owner,
            {
                "revision": owner["progress"]["revision"] + 1,
                "operations": history,
                "pending_operation": None,
                "policy_state": policy,
            },
        )
        return outcome


def stop(store, identifier):
    with store._connection(write=True) as connection:
        owner = owner_at(store, connection, identifier)
        if not owner["progress"]["stopped"]:
            patch(
                connection, owner, {"stopped": True, "revision": owner["progress"]["revision"] + 1}
            )
        return owner["progress"]["pending_operation"]
