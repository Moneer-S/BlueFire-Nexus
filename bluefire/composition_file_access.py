"""Concrete retained-file dependency hooks on the shared composition coordinator."""

from .capability_grant import objective_result
from .capability_packs import FILE_ACCESS_METHODS
from .detection_evaluations import _source_binding
from .evidence import EvidenceProvenance
from .file_access_contract import validate_file_access_observation, verify_file_access_binding
from .product_store_errors import ProductStoreError
from .util import content_hash


def prepare(jobs, job_id, attempt_id, current):
    binding = current["file_access_binding"].to_dict()
    dependency = {
        "binding_digest": content_hash(binding),
        "resource_generation": binding["resource_generation"],
        "control_revision": binding["control_revision"],
    }
    jobs.store.bind_capability_file_access(attempt_id, **dependency)
    jobs._publish(
        job_id,
        {
            "prepare_started": True,
            "phase": "verifying_file_access",
            "file_access_dependency": dependency,
        },
    )


def record_terminal(jobs, job_id, attempt_id, current, step, manifest, task_id, result):
    binding = current["file_access_binding"].to_dict()
    if result.get("schema_version") == "bluefire.task-not-sent.v1":
        proof = {
            "state": "not_sent",
            "binding_digest": content_hash(binding),
            "observation_digest": content_hash(result),
        }
    elif result.get("status") == "success" and step.action_id in FILE_ACCESS_METHODS[:2]:
        observation = validate_file_access_observation(
            result.get("output", {}).get("observation"),
            binding=binding,
            request_hash=manifest["request_hash"],
            reader="non_owner" if step.action_id == FILE_ACCESS_METHODS[0] else "owner",
        )
        if observation["observed_at_ms"] > jobs.clock():
            raise ProductStoreError("File-access observation is from a future clock.")
        proof = {
            "state": "verified_closed",
            "binding_digest": content_hash(binding),
            "observation_digest": content_hash(observation),
        }
    else:
        jobs._publish(job_id, {"file_access_request_state": "unknown"})
        return
    jobs.store.record_capability_file_access_terminal(
        attempt_id,
        task_id=task_id,
        request_hash=manifest["request_hash"],
        terminal_digest=content_hash(result),
        proof=proof,
    )


def settle(jobs, marker, job_id, lease, run_result, cleanup_result):
    attempt = jobs.store.get_capability_attempt(marker["attempt_id"])
    native = {"state": "not_started", "run_id": marker["run_id"]}
    if attempt["tasks"]:
        if cleanup_result is None:
            jobs._publish(job_id, {"settlement": "pending_cleanup"})
            return
        native = {
            "state": "complete",
            "run_id": marker["run_id"],
            "task_ids": sorted(row["task_id"] for row in attempt["tasks"]),
            "cleanup_digest": cleanup_result["digest"],
        }
    try:
        closure = jobs.store.capability_file_access_closure(marker["attempt_id"])
    except (ProductStoreError, ValueError, KeyError):
        try:
            recover_requests(jobs, marker["attempt_id"])
            closure = jobs.store.capability_file_access_closure(marker["attempt_id"])
        except (ProductStoreError, ValueError, KeyError, OSError):
            jobs._publish(
                job_id, {"settlement": "pending_cleanup", "file_access_request_state": "unknown"}
            )
            return
    receipt = {
        "schema_version": "bluefire.file-access-attempt-settlement.v1",
        "attempt_id": marker["attempt_id"],
        "lease_digest": lease["lease_digest"],
        "file_access": closure,
        "native": native,
    }
    jobs.store.settle_capability_attempt(marker["attempt_id"], receipt)
    jobs._publish(job_id, {"settlement": "settled", "file_access_request_state": "verified_closed"})
    if run_result is not None:
        try:
            result = jobs._verified_result(jobs.store.get_capability_attempt(marker["attempt_id"]))
        except (ProductStoreError, ValueError, KeyError) as exc:
            jobs._publish(job_id, {"verified_result_problem": str(exc)[:1000]})
        else:
            jobs._publish(
                job_id, {"verified_result": result, "verified_result_digest": content_hash(result)}
            )


def recover_requests(jobs, attempt_id):
    """Query original worker closure only after every native business task ended."""
    from .file_access_closure import recover_file_access_closure
    from .product_store_capability_dependencies import dependency_at
    from .product_store_capability_grants import _attempt_at, _document, _one

    with jobs.store._connection() as connection:
        _, lease, compiled = _attempt_at(connection, attempt_id)
        dependency = dependency_at(connection, attempt_id, lease)
        pending = []
        for task in connection.execute(
            "SELECT * FROM capability_task_claims WHERE attempt_id=? ORDER BY task_id",
            (attempt_id,),
        ):
            terminal = _document(
                _one(
                    connection,
                    "SELECT * FROM capability_task_terminals WHERE task_id=?",
                    task["task_id"],
                )
            )
            if not connection.execute(
                "SELECT 1 FROM capability_file_access_terminals WHERE task_id=?", (task["task_id"],)
            ).fetchone():
                pending.append((dict(task), terminal))
    control = jobs.store.get_file_access_control_revision(
        compiled["file_access"]["control_owner_id"], compiled["file_access"]["control_revision"]
    )
    binding = control["document"]["binding"]
    if (
        control["document_digest"] != compiled["file_access"]["control_digest"]
        or content_hash(binding) != dependency["binding_digest"]
    ):
        raise ProductStoreError("Closure recovery changed its original retained resource binding.")
    verified = verify_file_access_binding(
        binding, expected_document_digest=dependency["binding_digest"], now_ms=jobs.clock()
    )
    for task, terminal in pending:
        if task["request_hash"] != terminal["request_hash"]:
            raise ProductStoreError("Closure recovery lacks its original authenticated terminal.")
        if task["step_id"] == compiled["file_access"]["probe_step_id"]:
            evidence = recover_file_access_closure(verified, request_hash=task["request_hash"])
        elif task["step_id"] == compiled["file_access"]["owner_step_id"]:
            evidence = terminal
        else:
            raise ProductStoreError("Closure recovery found an unexpected business task.")
        jobs.store.record_capability_file_access_terminal(
            attempt_id,
            task_id=task["task_id"],
            request_hash=task["request_hash"],
            terminal_digest=terminal["terminal_digest"],
            proof={
                "state": "verified_closed",
                "binding_digest": dependency["binding_digest"],
                "observation_digest": content_hash(evidence),
            },
        )


def verified_result(jobs, attempt, run, records, observed):
    lease, compiled = attempt["lease"], attempt["compiled"]
    dependency = compiled["file_access"]
    control = jobs.store.get_file_access_control_revision(
        dependency["control_owner_id"], dependency["control_revision"]
    )
    binding = control["document"]["binding"]
    retained = jobs.store.capability_file_access_evidence(lease["attempt_id"])
    if (
        control["document_digest"] != dependency["control_digest"]
        or content_hash(binding) != retained["binding"]["binding_digest"]
    ):
        raise ProductStoreError(
            "The attempt evidence belongs to another retained resource revision."
        )
    tasks = {row["step_id"]: row for row in attempt["tasks"]}
    terminals = {row["task_id"]: row for row in retained["terminals"]}
    observations = {}
    for reader, step_key, method in (
        ("non_owner", "probe_step_id", FILE_ACCESS_METHODS[0]),
        ("owner", "owner_step_id", FILE_ACCESS_METHODS[1]),
    ):
        task = tasks[dependency[step_key]]
        candidates = [
            record
            for record in records
            if record.step_id == task["step_id"]
            and record.action_id == method
            and record.provenance is EvidenceProvenance.EXECUTED
            and record.content.get("runner_task_id") == task["task_id"]
            and record.content.get("request_hash") == task["request_hash"]
        ]
        if len(candidates) != 1:
            raise ProductStoreError(
                "The exact authenticated file-access task evidence is unavailable."
            )
        observation = validate_file_access_observation(
            candidates[0].content.get("output", {}).get("observation"),
            binding=binding,
            request_hash=task["request_hash"],
            reader=reader,
        )
        if terminals[task["task_id"]]["proof"] != {
            "state": "verified_closed",
            "binding_digest": content_hash(binding),
            "observation_digest": content_hash(observation),
        }:
            raise ProductStoreError(
                "The retained closure differs from the immutable native observation."
            )
        if (
            not lease["created_at_ms"]
            <= observation["observed_at_ms"]
            < lease["business_expires_at_ms"]
        ):
            raise ProductStoreError(
                "The file-access observation is outside its exact attempt lifetime."
            )
        observations[reader] = observation
    probe, owner = observations["non_owner"], observations["owner"]
    owner_step = next(row for row in run["steps"] if row["step_id"] == dependency["owner_step_id"])
    verification = owner_step.get("artifacts", {}).get("verification", {})
    if (
        verification.get("probe_observation_digest") != content_hash(probe)
        or verification.get("observation_digest") != content_hash(owner)
        or verification.get("request_hash") != owner["request_hash"]
    ):
        raise ProductStoreError("Owner verification lost its exact preceding probe artifact.")
    if owner["observed_at_ms"] < probe["observed_at_ms"]:
        raise ProductStoreError("Owner verification must freshly follow the non-owner probe.")
    grant = jobs.store.get_capability_grant(lease["grant_id"], now_ms=jobs.clock())["document"]
    result = {
        "probe_verified": True,
        "non_owner_decision": probe["outcome"],
        "owner_verified": True,
        "owner_decision": owner["outcome"],
        "resource_digest": content_hash(binding["resource"]),
        "resource_generation": binding["resource_generation"],
        "control_revision": binding["control_revision"],
        "probe_enrollment_digest": binding["enrollment_digest"],
        "mode": owner["mode"],
        "sha256": owner["sha256"],
        "record_count": owner["record_count"],
        "identity_unchanged": True,
        "parents_unchanged": True,
        "acl_unchanged": True,
    }
    cleanup = {
        "run": (
            "complete"
            if run.get("cleanup", {}).get("success") is True
            and run["cleanup"].get("outstanding_receipt_count") == 0
            else "incomplete"
        ),
        "request": "verified_closed",
    }
    outcome = objective_result(
        grant, {**result, "run_cleanup": cleanup["run"], "request_cleanup": cleanup["request"]}
    )
    return {
        "run_id": lease["run_id"],
        "source_binding": _source_binding(run, records, observed),
        "file_access_result": result,
        "cleanup": cleanup,
        "objective": outcome,
    }


def proposal_context(grant, facts, initial, initial_scenario):
    return {
        "schema_version": "bluefire.composition-proposal-context.v1",
        "grant_id": grant["grant_id"],
        "objective": grant["objective"],
        "snapshot": grant["snapshot"],
        "facts": facts,
        "initial_proposal": initial,
        "initial_scenario": initial_scenario,
    }
