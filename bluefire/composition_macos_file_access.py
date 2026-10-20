"""Composition hooks for the closed, metadata-only Darwin file-access pack."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from . import capability_macos_file_access as macos_pack
from . import macos_file_access_method as method
from .detection_evaluations import _source_binding
from .evidence import EvidenceProvenance
from .macos_attempt_workspace import MacOSAttemptWorkspaceGuard
from .macos_file_access_contract import validate_binding
from .product_store_errors import ProductStoreError
from .util import content_hash


def attempt_deadlines(binding, lease, origin_ms, started_ns):
    cleanup_reserve_ns = (
        lease["attempt_expires_at_ms"] - lease["business_expires_at_ms"]
    ) * 1_000_000
    cleanup_deadline_ns = min(
        binding["original_deadline_ns"],
        started_ns + (lease["attempt_expires_at_ms"] - origin_ms) * 1_000_000,
    )
    business_deadline_ns = min(
        cleanup_deadline_ns - cleanup_reserve_ns,
        started_ns + (lease["business_expires_at_ms"] - origin_ms) * 1_000_000,
    )
    if cleanup_reserve_ns <= 0 or business_deadline_ns <= started_ns:
        raise ProductStoreError("The original workspace has no business window before cleanup.")
    return business_deadline_ns, cleanup_deadline_ns


def attempt_admission_deadlines(binding, reservation, grant_expiry_ms, origin_ms, started_ns):
    cleanup_reserve_ms = reservation["cleanup_reserve_ms"]
    attempt_ms = reservation["reserved_attempt_ms"]
    predicted_lease = {
        "business_expires_at_ms": min(grant_expiry_ms, origin_ms + attempt_ms - cleanup_reserve_ms),
        "attempt_expires_at_ms": origin_ms + attempt_ms,
    }
    return attempt_deadlines(binding, predicted_lease, origin_ms, started_ns)


def admit_attempt(jobs, current, compiled, grant, marker):
    from .macos_file_access_peer import darwin_clock_ns

    attempt_admission_deadlines(
        current["macos_file_access_binding"].to_dict(),
        compiled["reservation"],
        grant["expires_at_ms"],
        jobs.clock(),
        darwin_clock_ns(),
    )
    current["runner"].reserve_composition_probe_budget(
        attempt_id=marker["attempt_id"],
        compiled_digest=marker["compiled_digest"],
        current_environment=current["current_environment"],
    )


def reserve_attempt(jobs, attempt_id, current, lease, origin, macos_clock, macos_started):
    assert macos_clock is not None and macos_started is not None
    binding = current["macos_file_access_binding"].to_dict()
    business_deadline_ns, cleanup_deadline_ns = attempt_deadlines(
        binding, lease, origin, macos_started
    )
    jobs.store.reserve_macos_capability_attempt(
        attempt_id,
        now_ms=jobs.clock(),
        monotonic_ns=macos_clock(),
        business_deadline_ns=business_deadline_ns,
        cleanup_deadline_ns=cleanup_deadline_ns,
    )


def claim_cleanup_authority(
    jobs, attempt_id, profile, params, receipts, sealed_profile, macos_clock
):
    assert macos_clock is not None
    if params or receipts or profile != sealed_profile:
        raise ProductStoreError("macOS closure cannot acquire filesystem receipt authority.")
    return jobs.store.claim_macos_capability_cleanup(
        attempt_id,
        now_ms=jobs.clock(),
        now_monotonic_ns=macos_clock(),
    )


def prepare(jobs, job_id: str, attempt_id: str, current: Mapping[str, Any]) -> None:
    dependency = jobs.store.bind_macos_capability_file_access(attempt_id)
    jobs._publish(
        job_id,
        {
            "prepare_started": True,
            "phase": "verifying_macos_file_access",
            "macos_file_access_dependency": dependency,
        },
    )


def create_workspace(jobs, attempt_id: str, current: Mapping[str, Any]):
    claim = jobs.store.claim_macos_attempt_workspace(
        attempt_id,
        current["sandbox"],
        now_ms=jobs.clock(),
        current_environment=current["current_environment"],
    )
    try:
        workspace = jobs.service._isolated_owned_sandbox(current["sandbox"], attempt_id)
        guard = MacOSAttemptWorkspaceGuard(
            workspace,
            attempt_id=attempt_id,
            lease_digest=claim.lease_digest,
            compiled_digest=claim.compiled_digest,
        )
        jobs.store.attach_macos_attempt_workspace_guard(claim, current["sandbox"], workspace, guard)
        return workspace
    except BaseException:
        jobs.store.release_macos_attempt_workspace(attempt_id)
        raise


def record_terminal(
    jobs, job_id: str, attempt_id: str, current, step, manifest, task_id: str, result
) -> None:
    """Persist each exact terminal; close only through the dedicated Mac authority."""
    if manifest.get("action_id") == method.CLOSE_ACTION and result.get("status") != "success":
        jobs._publish(job_id, {"macos_file_access_request_state": "unknown"})
        return
    jobs.store.record_macos_capability_terminal(task_id, result=result)
    if manifest.get("action_id") != method.CLOSE_ACTION:
        return
    closure = jobs.store.close_macos_capability_attempt(
        attempt_id, cleanup_task_id=task_id, result=result
    )
    jobs._publish(
        job_id,
        {
            "macos_attempt_closure": closure,
            "macos_attempt_closure_digest": content_hash(closure),
            "macos_file_access_request_state": "verified_closed",
        },
    )


def settle(jobs, marker, job_id, lease, run_result, cleanup_result) -> None:
    """Settle only after the original producer's non-replayable closure is retained."""
    attempt_id = marker["attempt_id"]
    try:
        jobs.store.get_macos_capability_closure(attempt_id)
    except (ProductStoreError, ValueError, KeyError):
        # The one-shot closure cannot be replayed; retain pending state without recovery.
        jobs._publish(
            job_id,
            {"settlement": "pending_cleanup", "macos_file_access_request_state": "unknown"},
        )
        return

    from .product_store_macos_settlement import receipt as settlement_receipt

    try:
        receipt = settlement_receipt(jobs.store, attempt_id)
        jobs.store.settle_capability_attempt(attempt_id, receipt)
    except (ProductStoreError, ValueError, KeyError):
        jobs._publish(
            job_id,
            {"settlement": "pending_cleanup", "macos_file_access_request_state": "unknown"},
        )
        return
    jobs._publish(
        job_id,
        {"settlement": "settled", "macos_file_access_request_state": "verified_closed"},
    )
    if run_result is None:
        return
    try:
        result = jobs._verified_result(jobs.store.get_capability_attempt(attempt_id))
    except (ProductStoreError, ValueError, KeyError) as exc:
        jobs._publish(job_id, {"verified_result_problem": str(exc)[:1000]})
        return
    jobs._publish(
        job_id, {"verified_result": result, "verified_result_digest": content_hash(result)}
    )


def recovery_events(jobs, attempt_id):
    with jobs.store._connection() as connection:
        rows = connection.execute(
            "SELECT event_type,event_key FROM capability_macos_file_access_events "
            "WHERE attempt_id=? AND event_type IN ('dispatch','cleanup_claim','producer_closure')",
            (attempt_id,),
        ).fetchall()
        return {(row["event_type"], row["event_key"]) for row in rows}


def retain_close_recovery(jobs, attempt_id, marker, job_id, lease, orchestrator):
    """Keep only original-process authority for a proven zero-dispatch close retry."""
    from .macos_attempt_workspace import MacOSAttemptWorkspaceGuard

    context = getattr(orchestrator, "_macos_recovery_context", None)
    guard = jobs.store._macos_attempt_workspaces.get(attempt_id)
    events = jobs._macos_recovery_events(attempt_id)
    progress = jobs.store.get_job(job_id)["progress"]
    guard_matches = (
        type(guard) is MacOSAttemptWorkspaceGuard
        and guard._pid == os.getpid()
        and guard._attempt_id == attempt_id
        and guard._lease_digest == lease.get("lease_digest")
        and guard._compiled_digest == marker.get("compiled_digest")
    )
    if (
        jobs.store._macos_workspace_pid != os.getpid()
        or not guard_matches
        or not isinstance(context, dict)
        or context.get("run_id") != marker["run_id"]
        or progress.get("settlement") != "pending_cleanup"
        or any(event_type == "dispatch" for event_type, _ in events)
        or ("cleanup_claim", "close_attempt") in events
        or any(event_type == "producer_closure" for event_type, _ in events)
    ):
        return False
    try:
        jobs.store.get_macos_capability_closure(attempt_id)
    except (ProductStoreError, KeyError):
        pass
    else:
        return False
    with jobs._macos_recovery_lock:
        jobs._macos_recoveries[attempt_id] = {
            "owner_id": marker["parent_job_id"],
            "job_id": job_id,
            "marker": dict(marker),
            "lease": dict(lease),
            "orchestrator": orchestrator,
            "context": dict(context),
        }
        jobs._publish(
            job_id,
            {"macos_recovery": {"state": "available", "scope": "close_only"}},
        )
    return True


def finish_close_recovery(jobs, attempt_id, marker, job_id, lease, orchestrator):
    try:
        retained = jobs._retain_macos_close_recovery(
            attempt_id, marker, job_id, lease, orchestrator
        )
    except Exception:
        with jobs._macos_recovery_lock:
            jobs._macos_recoveries.pop(attempt_id, None)
        retained = False
    if not retained:
        jobs.store.release_macos_attempt_workspace(attempt_id)


def recover_attempt(jobs, owner_id: str, attempt_id: str):
    """Close a retained zero-dispatch attempt once; never recreate lost authority."""
    jobs._owner(owner_id)
    children = {
        row["request"]["composition_attempt"]["attempt_id"]: row for row in jobs._children(owner_id)
    }
    child = children.get(attempt_id)
    if child is None:
        raise ProductStoreError("Select an exact attempt belonging to this objective.")
    marker = child["request"]["composition_attempt"]
    attempt = jobs.store.get_capability_attempt(attempt_id)
    if (
        not isinstance(attempt.get("compiled", {}).get("macos_file_access"), Mapping)
        or attempt.get("lease", {}).get("run_id") != marker.get("run_id")
        or attempt.get("lease", {}).get("compiled_digest") != marker.get("compiled_digest")
        or marker.get("parent_job_id") != owner_id
    ):
        raise ProductStoreError("Recovery is limited to the exact original macOS attempt.")
    job_id = child["job_id"]
    with jobs._macos_recovery_lock:
        # A competing recovery may have completed while this request waited
        # for the lock. Never replace its terminal state using stale progress.
        progress = jobs.store.get_job(job_id)["progress"]
        recovery_state = progress.get("macos_recovery", {})
        if recovery_state.get("state") in {"closed", "unavailable", "unresolved"}:
            return jobs.read(owner_id)
        if progress.get("settlement") != "pending_cleanup":
            return jobs.read(owner_id)

        retained = jobs._macos_recoveries.get(attempt_id)
        if retained is None:
            jobs._publish(
                job_id,
                {
                    "macos_recovery": {
                        "state": "unavailable",
                        "reason": "original_process_authority_unavailable",
                    }
                },
            )
            return jobs.read(owner_id)
        if retained["owner_id"] != owner_id or retained["job_id"] != job_id:
            raise ProductStoreError("The retained close authority belongs to another attempt.")
        events = jobs._macos_recovery_events(attempt_id)
        from .macos_attempt_workspace import MacOSAttemptWorkspaceGuard

        guard = jobs.store._macos_attempt_workspaces.get(attempt_id)
        guard_matches = (
            type(guard) is MacOSAttemptWorkspaceGuard
            and guard._pid == os.getpid()
            and guard._attempt_id == attempt_id
            and guard._lease_digest == retained["lease"].get("lease_digest")
            and guard._compiled_digest == retained["marker"].get("compiled_digest")
        )
        if (
            jobs.store._macos_workspace_pid != os.getpid()
            or not guard_matches
            or any(event_type == "dispatch" for event_type, _ in events)
            or ("cleanup_claim", "close_attempt") in events
            or any(event_type == "producer_closure" for event_type, _ in events)
        ):
            jobs._macos_recoveries.pop(attempt_id, None)
            jobs.store.release_macos_attempt_workspace(attempt_id)
            jobs._publish(
                job_id,
                {
                    "macos_recovery": {
                        "state": "unavailable",
                        "reason": "dispatch_or_original_guard_changed",
                    }
                },
            )
            return jobs.read(owner_id)

        try:
            attempt = jobs.store.get_capability_attempt(attempt_id)
            from . import product_store_macos_composition as macos_journal

            for task in attempt["tasks"]:
                with jobs.store._connection() as connection:
                    receipt = macos_journal._event(
                        connection, attempt_id, "receipt", task["step_id"]
                    )
                    terminal = connection.execute(
                        "SELECT attempt_id,request_hash,terminal_digest FROM "
                        "capability_task_terminals WHERE task_id=?",
                        (task["task_id"],),
                    ).fetchone()
                if receipt is None and terminal is None:
                    not_sent = {
                        "schema_version": "bluefire.task-not-sent.v1",
                        "task_id": task["task_id"],
                        "request_hash": task["request_hash"],
                    }
                    jobs.store.record_capability_task_terminal(
                        task["task_id"],
                        request_hash=task["request_hash"],
                        terminal_digest=content_hash(not_sent),
                    )
                    jobs.store.record_macos_capability_terminal(task["task_id"], result=not_sent)
                elif (
                    receipt is None
                    or receipt.get("state") != "not_sent"
                    or terminal is None
                    or terminal["attempt_id"] != attempt_id
                    or terminal["request_hash"] != task["request_hash"]
                    or terminal["terminal_digest"] != receipt.get("terminal_digest")
                ):
                    raise ProductStoreError("An attempt task is not provably undispatched.")

            recovery = retained["orchestrator"]
            recovery._macos_close_attempted = False
            recovery._attempt_emergency_cleanup(**retained["context"])
            jobs.store.get_macos_capability_closure(attempt_id)
            jobs._settle_attempt(retained["marker"], job_id, retained["lease"], None, None)
            settled = jobs.store.get_job(job_id)["progress"].get("settlement") == "settled"
            jobs._publish(
                job_id,
                {
                    "macos_recovery": {
                        "state": "closed" if settled else "unresolved",
                        "scope": "close_only",
                        **({} if settled else {"reason": "settlement_unverified"}),
                    }
                },
            )
        except Exception:
            jobs._publish(
                job_id,
                {
                    "macos_recovery": {
                        "state": "unresolved",
                        "reason": "original_close_not_verified",
                    }
                },
            )
        finally:
            jobs._macos_recoveries.pop(attempt_id, None)
            jobs.store.release_macos_attempt_workspace(attempt_id)
    return jobs.read(owner_id)


def _terminal_events(store, attempt_id: str):
    from .product_store_capability_grants import _document

    with store._connection() as connection:
        rows = connection.execute(
            "SELECT event_key,document_json,document_digest FROM capability_macos_file_access_events "
            "WHERE attempt_id=? AND event_type='receipt'",
            (attempt_id,),
        ).fetchall()
        events = {}
        for row in rows:
            event = _document(row)
            if event.get("step_id") is not None:
                events[event["step_id"]] = event
            else:
                events[row["event_key"]] = event
        dispatch_rows = connection.execute(
            "SELECT event_key,document_json,document_digest FROM capability_macos_file_access_events "
            "WHERE attempt_id=? AND event_type='dispatch'",
            (attempt_id,),
        ).fetchall()
        dispatches = {row["event_key"]: _document(row) for row in dispatch_rows}
        workspace_rows = connection.execute(
            "SELECT event_type,event_key,document_json,document_digest FROM "
            "capability_macos_file_access_events WHERE attempt_id=? "
            "AND event_type IN ('workspace_reserved','workspace_pre_close','workspace_post_close')",
            (attempt_id,),
        ).fetchall()
        workspaces = {
            (row["event_type"], row["event_key"]): _document(row) for row in workspace_rows
        }
        terminal_rows = connection.execute(
            "SELECT t.* FROM capability_task_terminals t "
            "JOIN capability_task_claims c ON c.task_id=t.task_id WHERE c.attempt_id=?",
            (attempt_id,),
        ).fetchall()
        terminals = {}
        for row in terminal_rows:
            terminal = _document(row)
            terminals[terminal["task_id"]] = terminal
    return events, terminals, dispatches, workspaces


def _exact_task_evidence(records, task, method_id: str, run_id: str):
    candidates = [
        record
        for record in records
        if record.run_id == run_id
        and record.step_id == task["step_id"]
        and record.action_id == method_id
        and record.provenance is EvidenceProvenance.EXECUTED
        and record.content.get("runner_task_id") == task["task_id"]
        and record.content.get("request_hash") == task["request_hash"]
    ]
    if len(candidates) != 1:
        raise ProductStoreError("The exact executed Darwin task evidence is unavailable.")
    return candidates[0]


def verified_result(jobs, attempt, run, records, observed):
    lease, compiled = attempt["lease"], attempt["compiled"]
    dependency = compiled["macos_file_access"]
    attempt_id, run_id = lease["attempt_id"], lease["run_id"]
    control = jobs.store.get_file_access_control_revision(
        dependency["control_owner_id"], dependency["control_revision"]
    )
    binding = validate_binding(control["document"].get("binding"))
    if (
        control["document_digest"] != dependency["control_digest"]
        or control["document"].get("revision") != dependency["control_revision"]
        or control["document"].get("status") != "hardened"
        or run.get("run_id") != run_id
        or not isinstance(binding, Mapping)
        or content_hash(dict(binding)) != dependency["binding_digest"]
    ):
        raise ProductStoreError("The attempt evidence belongs to another original Mac control.")

    tasks = {row["step_id"]: row for row in attempt["tasks"]}
    receipt_events, task_terminals, dispatches, workspace_events = _terminal_events(
        jobs.store, attempt_id
    )
    observations: dict[str, dict[str, Any]] = {}
    native_receipts: dict[str, dict[str, Any]] = {}
    by_reader = (
        ("non_owner", "probe_step_id", method.PROBE_ACTION),
        ("owner", "owner_step_id", method.OWNER_ACTION),
    )
    for reader, step_key, method_id in by_reader:
        task = tasks.get(dependency[step_key])
        if task is None:
            raise ProductStoreError("The exact Darwin business task is unavailable.")
        record = _exact_task_evidence(records, task, method_id, run_id)
        output = record.content.get("output")
        if not isinstance(output, Mapping):
            raise ProductStoreError("The executed Darwin evidence has no original receipt output.")
        receipt = output.get("macos_receipt")
        if not isinstance(receipt, Mapping):
            raise ProductStoreError("The original native Darwin receipt is unavailable.")
        dispatch = dispatches.get(task["task_id"])
        if not isinstance(dispatch, Mapping) or not isinstance(dispatch.get("intent"), Mapping):
            raise ProductStoreError("The original reviewed Darwin intent is unavailable.")
        raw_receipt = method.validate_read_receipt(receipt, dispatch["intent"], binding)
        metadata = method.validate_metadata(output.get("observation"), raw_receipt)
        terminal = receipt_events.get(task["step_id"])
        task_terminal = task_terminals.get(task["task_id"])
        if (
            terminal is None
            or task_terminal is None
            or terminal.get("task_id") != task["task_id"]
            or terminal.get("step_id") != task["step_id"]
            or terminal.get("request_hash") != task["request_hash"]
            or terminal.get("state") != "complete"
            or terminal.get("native_receipt_digest") != content_hash(raw_receipt)
            or terminal.get("observation_digest") != content_hash(metadata)
            or terminal.get("transport_request_hash") != dispatch.get("transport_request_hash")
            or dispatch.get("request_hash") != task["request_hash"]
            or dispatch.get("step_id") != task["step_id"]
            or task_terminal.get("request_hash") != task["request_hash"]
            or task_terminal.get("terminal_digest") != terminal.get("terminal_digest")
            or task_terminal.get("attempt_id") != attempt_id
            or metadata.get("attempt_id") != attempt_id
            or metadata.get("run_id") != run_id
            or metadata.get("step_id") != task["step_id"]
            or metadata.get("request_hash") != task["request_hash"]
            or metadata.get("binding") != dict(binding)
            or metadata.get("reader") != reader
        ):
            raise ProductStoreError("The Darwin metadata differs from its immutable task receipt.")
        observations[reader] = metadata
        native_receipts[reader] = raw_receipt

    probe, owner = observations["non_owner"], observations["owner"]
    probe_receipt, owner_receipt = native_receipts["non_owner"], native_receipts["owner"]
    if (
        owner["probe_task_id"] != probe["intent"]["task_id"]
        or owner["probe_receipt_digest"] != content_hash(probe_receipt)
        or owner["observed_at_ms"] < probe["observed_at_ms"]
    ):
        raise ProductStoreError("Owner evidence lost the exact preceding probe receipt.")

    steps = {row["step_id"]: row for row in run["steps"]}
    probe_artifact = steps[dependency["probe_step_id"]].get("artifacts", {}).get("probe")
    if (
        not isinstance(probe_artifact, Mapping)
        or probe_artifact.get("observation") != probe
        or probe_artifact.get("native_receipt_digest") != content_hash(probe_receipt)
        or probe_artifact.get("observation_digest") != content_hash(probe)
    ):
        raise ProductStoreError("The finalized run changed its original probe artifact.")
    owner_artifact = steps[dependency["owner_step_id"]].get("artifacts", {}).get("verification")
    if not isinstance(owner_artifact, Mapping):
        raise ProductStoreError("The finalized run lacks the owner verification artifact.")
    verification = owner_artifact.get("observation")
    if (
        verification != owner
        or owner_artifact.get("native_receipt_digest") != content_hash(owner_receipt)
        or owner_artifact.get("observation_digest") != content_hash(owner)
    ):
        raise ProductStoreError("The finalized owner artifact changed its authenticated receipt.")

    probe_terminal = probe_receipt["terminals"][0]
    owner_terminal = owner_receipt["terminals"][0]
    if owner_terminal["outcome"] != "allowed" or owner_terminal["fresh_read"] is None:
        raise ProductStoreError("The authenticated owner read did not produce fresh content.")
    fresh = owner_terminal["fresh_read"]
    resource = binding["resource"]
    if (
        fresh["sha256"] != resource["sha256"]
        or fresh["record_count"] != resource["record_count"]
        or owner["outcome"] != "allowed"
        or probe["outcome"] not in {"allowed", "denied"}
        or not lease["created_at_ms"] <= probe["observed_at_ms"] < lease["business_expires_at_ms"]
        or not lease["created_at_ms"] <= owner["observed_at_ms"] < lease["business_expires_at_ms"]
    ):
        raise ProductStoreError("The fresh Mac read is outside the retained objective or lifetime.")

    closure_row = jobs.store.get_macos_capability_closure(attempt_id)
    from .product_store_macos_settlement import receipt as settlement_receipt

    settlement = settlement_receipt(jobs.store, attempt_id)
    close_task = tasks.get(dependency["cleanup_step_id"])
    if close_task is None:
        raise ProductStoreError("The exact Mac attempt-closure task is unavailable.")
    closure_artifact = steps[dependency["cleanup_step_id"]].get("artifacts", {}).get("closure")
    close_dispatch = dispatches.get(close_task["task_id"])
    close_terminal = task_terminals.get(close_task["task_id"])
    if (
        not isinstance(closure_artifact, Mapping)
        or closure_artifact.get("type") != method.CLOSURE_TYPE
        or closure_artifact.get("closure_digest") != closure_row.get("closure_digest")
    ):
        raise ProductStoreError("The finalized run lacks the retained attempt-closure artifact.")
    closure = method.validate_closure(closure_artifact.get("attempt_closure"))
    reserved_workspace = workspace_events.get(("workspace_reserved", attempt_id))
    pre_workspace = workspace_events.get(("workspace_pre_close", close_task["task_id"]))
    post_workspace = workspace_events.get(("workspace_post_close", close_task["task_id"]))
    if (
        content_hash(closure) != closure_row.get("closure_digest")
        or closure["attempt_id"] != attempt_id
        or closure["run_id"] != run_id
        or closure["cleanup_task_id"] != close_task["task_id"]
        or closure["binding_digest"] != dependency["binding_digest"]
        or closure_row.get("attempt_id") != attempt_id
        or closure_row.get("lease_digest") != lease["lease_digest"]
        or closure_row.get("compiled_digest") != lease["compiled_digest"]
        or closure_row.get("cleanup_task_id") != close_task["task_id"]
        or settlement.get("attempt_id") != attempt_id
        or settlement.get("lease_digest") != lease["lease_digest"]
        or settlement.get("run_id") != run_id
        or settlement.get("macos_closure_digest") != content_hash(closure_row)
        or not isinstance(close_dispatch, Mapping)
        or not isinstance(close_terminal, Mapping)
        or content_hash(close_dispatch) != closure_row.get("cleanup_dispatch_digest")
        or close_terminal.get("terminal_digest") != closure_row.get("cleanup_terminal_digest")
        or content_hash(closure["task_closures"]) != closure_row.get("task_closures_digest")
        or closure["attempt_artifacts"] != "not_created"
        or closure["whole_enrollment_cleanup"] is not False
        or closure_row.get("artifact_state") != "not_created"
        or not isinstance(reserved_workspace, Mapping)
        or not isinstance(pre_workspace, Mapping)
        or not isinstance(post_workspace, Mapping)
        or content_hash(pre_workspace) != closure_row.get("pre_close_workspace_attestation_digest")
        or content_hash(post_workspace) != closure_row.get("workspace_attestation_digest")
        or any(
            proof.get("attempt_id") != attempt_id
            or proof.get("lease_digest") != lease["lease_digest"]
            or proof.get("compiled_digest") != lease["compiled_digest"]
            or proof.get("phase") != phase
            or proof.get("entry_count") != 0
            or proof.get("state") != "verified_empty"
            for proof, phase in (
                (reserved_workspace, "reserve"),
                (pre_workspace, "pre_close"),
                (post_workspace, "post_close"),
            )
        )
        or any(
            proof.get("schema_version") != "bluefire.macos-file-access-empty-workspace.v1"
            for proof in (reserved_workspace, pre_workspace, post_workspace)
        )
        or len(
            {
                proof.get("workspace_path_digest")
                for proof in (reserved_workspace, pre_workspace, post_workspace)
            }
        )
        != 1
        or len(
            {
                proof.get("workspace_identity_digest")
                for proof in (reserved_workspace, pre_workspace, post_workspace)
            }
        )
        != 1
    ):
        raise ProductStoreError("The immutable Mac closure differs from this exact attempt.")

    result = {
        "probe_verified": True,
        "non_owner_decision": probe_terminal["outcome"],
        "owner_verified": True,
        "owner_decision": owner_terminal["outcome"],
        "resource_digest": dependency["resource_digest"],
        "resource_generation": dependency["resource_generation"],
        "control_revision": dependency["control_revision"],
        "binding_digest": dependency["binding_digest"],
        "sha256": fresh["sha256"],
        "record_count": fresh["record_count"],
        "request_closure": "verified_closed",
        "attempt_artifacts": "not_created",
        "workers_retained": closure["original_workers"] == "retained",
        "whole_enrollment_cleanup": closure["whole_enrollment_cleanup"],
    }
    objective = macos_pack.objective_result(
        jobs.store.get_capability_grant(lease["grant_id"], now_ms=jobs.clock())["document"],
        result,
    )
    return {
        "run_id": run_id,
        "source_binding": _source_binding(run, records, observed),
        "macos_file_access_result": result,
        "cleanup": {
            "request": "verified_closed",
            "attempt_artifacts": "not_created",
            "workers": "retained",
            "whole_enrollment": False,
        },
        "objective": objective,
    }
