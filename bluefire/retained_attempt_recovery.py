"""Restart closure of retained attempts without replaying business actions."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Mapping

from . import product_store_retained_recovery as ledger
from .adaptive_dispatch import reviewed_operation
from .capability_packs import RECEIVER_RETAINED_PACK, grant_pack
from .contracts import ExecutionMode, ScenarioDefinition
from .execution_contracts import execution_task_identity
from .execution_progress import validate_cleanup_result
from .orchestrator import Orchestrator
from .product_store_errors import ProductStoreError
from .retained_receiver_closure import close_exact_receiver
from .run_store import RunStoreError
from .runner_client import InventoryBoundRunner
from .runner_contracts import _verified_grant_cleanup, build_execution_manifest
from .runner_private_files import _windows_extended_path
from .runner_receipt_validation import discover_runner_receipts
from .util import content_hash


def _runner(jobs, workspace, *, execution):
    service = jobs.service
    profile_document = workspace["runner_profile"]
    profile = service._profile(profile_document["profile_id"], ExecutionMode.EXECUTE)
    if profile is None:
        raise ProductStoreError("Original runner profile is unavailable.")
    readiness = workspace["runner_readiness"]
    if execution or service._native_tool_setup_runner_factory is not None:
        raw, sandbox = service.runner_factory(profile)
    else:
        raw, sandbox = service.runner_lifecycle.recovery_client_for_profile(profile.id)
    if Path(workspace["workspace_path"]).parent.parent != Path(sandbox).resolve(strict=True):
        raise ProductStoreError("Original runner sandbox changed.")
    wrapped = InventoryBoundRunner(
        raw,
        expected_inventory_digest=readiness["inventory_digest"],
        expected_identity_digest=readiness["runner_identity_digest"],
        recovery_identity=readiness["recovery_identity"],
        dispatch_lease=service._catalog_dispatch_lease(readiness["catalog_authority"]),
    )
    wrapped.inventory()
    return raw, wrapped, profile


def _recovered_result(raw, task):
    payload = task["payload"]
    if (
        payload is None
        or payload.get("schema_version") != "bluefire.capability-task-payload.v2"
        or payload.get("runner_wal")
        != {
            "schema_version": "bluefire.runner-wal-request.v1",
            "task_id": task["task_id"],
            "request_hash": payload.get("transport_request_hash"),
            "recovery_operation": "recover",
        }
    ):
        raise ProductStoreError("Original task has no exact recoverable request contract.")
    recovered = raw.recover(task["task_id"], payload["transport_request_hash"])
    if (
        recovered.get("original_task_id") != task["task_id"]
        or recovered.get("original_request_hash") != payload["transport_request_hash"]
    ):
        raise ProductStoreError("Original runner task outcome remains unknown.")
    if (
        recovered.get("state") == "not_found"
        and recovered.get("result") is None
        and recovered.get("cleanup_required") is False
        and recovered.get("receipt_ids") == []
        and payload.get("dispatch_protocol") == "bluefire.capability-task-dispatch-intent.v1"
    ):
        return {
            "schema_version": "bluefire.task-not-sent.v1",
            "task_id": task["task_id"],
            "request_hash": task["request_hash"],
        }
    if recovered.get("state") == "recovery_required" and (
        recovered.get("result") is None
        and recovered.get("cleanup_required") is True
        and recovered.get("error_code") == "recovery_required"
        and isinstance(recovered.get("receipt_ids"), list)
        and recovered["receipt_ids"]
    ):
        receipt_ids = Orchestrator._validated_receipt_ids(recovered["receipt_ids"])
        return {
            "schema_version": "bluefire.task-recovery-required.v1",
            "task_id": task["task_id"],
            "request_hash": task["request_hash"],
            "receipt_ids": list(receipt_ids),
        }
    if recovered.get("state") != "completed" or not isinstance(recovered.get("result"), Mapping):
        raise ProductStoreError("Original runner task outcome remains unknown.")
    result = recovered["result"]
    Orchestrator._validate_runner_result(payload["manifest"], payload["runner_profile"], result)
    Orchestrator._validated_receipt_ids(result.get("receipt_ids", []))
    validate_cleanup_result(payload["manifest"], result)
    return result


def _recovered_cleanup_result(raw, task):
    recovered = raw.recover(task["task_id"], task["transport_request_hash"])
    if (
        recovered.get("original_task_id") != task["task_id"]
        or recovered.get("original_request_hash") != task["transport_request_hash"]
    ):
        raise ProductStoreError("Recovery cleanup task outcome remains unknown.")
    if recovered.get("state") != "completed" or not isinstance(recovered.get("result"), Mapping):
        raise ProductStoreError("Recovery cleanup task outcome remains unknown.")
    return recovered["result"]


def _receipts(workspace, tasks):
    documents: dict[str, Any] = {}
    root = Path(workspace["workspace_path"])

    def directory_exists(path):
        return (_windows_extended_path(path) if os.name == "nt" else path).is_dir()

    all_unsent = bool(tasks) and all(
        task["terminal"] is not None
        and task["terminal"]["terminal_digest"]
        == content_hash(
            {
                "schema_version": "bluefire.task-not-sent.v1",
                "task_id": task["task_id"],
                "request_hash": task["request_hash"],
            }
        )
        for task in tasks
    )
    if tasks and not all_unsent and not directory_exists(root / ".bluefire" / "receipts"):
        raise ProductStoreError("Original runner receipt directory cannot prove absence.")
    if tasks and not all_unsent and not directory_exists(root / ".bluefire" / "receipt-commits"):
        raise ProductStoreError("Original runner receipt commits cannot prove absence.")
    profile_id = workspace["runner_profile"]["profile_id"]
    raw = discover_runner_receipts(root, expected_profile_id=profile_id, _documents=documents)
    committed = discover_runner_receipts(root, expected_profile_id=profile_id, require_commit=True)
    if set(raw) != set(committed) or set(raw) != set(documents):
        raise ProductStoreError("Original receipt commitment is uncertain.")
    by_request = {task["request_hash"]: task for task in tasks}
    if len(by_request) != len(tasks):
        raise ProductStoreError("Original task request identities are ambiguous.")
    rows = []
    workspace_ids = set()
    for receipt_id in raw:
        receipt = documents[receipt_id]
        source = by_request.get(receipt["request_hash"])
        if source is None or receipt["action_id"] != source["payload"]["manifest"]["action_id"]:
            raise ProductStoreError("Owned receipt cannot be mapped to an original task.")
        workspace_ids.add(receipt["workspace_id"])
        rows.append(
            {
                "receipt_id": receipt_id,
                "source_request_hash": source["request_hash"],
                "source_task_id": source["task_id"],
            }
        )
    if len(workspace_ids) > 1:
        raise ProductStoreError("Owned receipts have different workspace identities.")
    inspection = {
        "schema_version": "bluefire.capability-receipt-inspection.v1",
        "workspace_binding_digest": content_hash(workspace),
        "receipts": rows,
        "workspace_ids": sorted(workspace_ids),
    }
    return rows, (next(iter(workspace_ids)) if workspace_ids else None), content_hash(inspection)


def _cleanup_step(jobs, snapshot, profile):
    scenario = ScenarioDefinition.from_mapping(snapshot["compiled"]["scenario"])
    engine = jobs._orchestrator({"registry": jobs.service.registry, "runner": None})
    plan = engine.planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        autonomy="off",
        ai_enabled=False,
        action_implementations=snapshot["compiled"]["action_implementations"],
    )
    if content_hash(plan.to_dict()) != snapshot["lease"]["plan_digest"]:
        raise ProductStoreError("Original compiled plan changed before recovery cleanup.")
    steps = [step for step in plan.steps if step.action_id == "sandbox.cleanup.v1"]
    if (
        len(steps) != 1
        or steps[0].behavior_id != "sandbox.cleanup.v1"
        or steps[0].execution_binding is not None
    ):
        raise ProductStoreError("Original plan has no single compiled native cleanup task.")
    return steps[0]


def _claim_and_dispatch_cleanup(
    jobs, snapshot, raw, wrapped, profile, receipts, workspace_id, *, stop_event=None
):
    if stop_event is not None and stop_event.is_set():
        return None
    attempt_id = snapshot["lease"]["attempt_id"]
    workspace = snapshot["workspace"]
    generation = ledger.begin_generation(jobs.store, attempt_id, jobs.clock())
    claim = ledger.claim_cleanup(
        jobs.store,
        attempt_id,
        generation=generation,
        workspace_id=workspace_id,
        receipts=receipts,
        now_ms=jobs.clock(),
        timeout_ms=min(120000, max(1000, snapshot["lease"]["reservation"]["cleanup_reserve_ms"])),
    )
    refreshed = ledger.snapshot(jobs.store, attempt_id)
    existing = refreshed["recovery_task"]
    if existing is None:
        step = _cleanup_step(jobs, snapshot, profile)
        manifest = build_execution_manifest(
            run_id=snapshot["lease"]["run_id"],
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action=jobs.service.registry.get_action("sandbox.cleanup.v1"),
            runner_profile=workspace["runner_profile"],
            params={"receipt_ids": [row["receipt_id"] for row in receipts]},
            filesystem_scope=(),
            network_destinations=(),
            evidence_refs=(),
            approval_record=None,
            grant_cleanup=_verified_grant_cleanup(
                claim["document"], expected_document_digest=claim["document_digest"]
            ),
            reviewed_operation=reviewed_operation(step, workspace["runner_profile"]),
        )
        task_id, _ = execution_task_identity(manifest, workspace["runner_profile"])
        if stop_event is not None and stop_event.is_set():
            return None
        try:
            existing, created = ledger.register_cleanup_task(
                jobs.store,
                attempt_id,
                generation=generation,
                task_id=task_id,
                manifest=manifest,
                profile=workspace["runner_profile"],
                now_ms=jobs.clock(),
            )
        except ProductStoreError:
            winner = ledger.snapshot(jobs.store, attempt_id)["recovery_task"]
            if winner is None or winner["generation"] != generation:
                raise
            existing, created = winner, False
        if created:
            # Registration consumed this one finite task. Shutdown must let it
            # finish: cancellation can lose exact partial-removal evidence.
            result = wrapped.execute_task(
                manifest,
                workspace["runner_profile"],
                task_id=task_id,
                cancel_event=threading.Event(),
                durable_result_path=jobs.service.store.root
                / ".bluefire-runner-results"
                / f"{task_id}.json",
            )
    else:
        created = False
    if not created:
        # The saved task may have completed while the caller lost its acknowledgment.
        if stop_event is not None and stop_event.is_set():
            return None
        result = _recovered_cleanup_result(raw, existing)
        if stop_event is not None and stop_event.is_set():
            return None
    Orchestrator._validate_runner_result(existing["manifest"], existing["runner_profile"], result)
    validate_cleanup_result(existing["manifest"], result)
    survivors, _, inspection_digest = _receipts(workspace, snapshot["tasks"])
    return ledger.record_cleanup_terminal(
        jobs.store,
        attempt_id,
        task_id=existing["task_id"],
        result=result,
        remaining_receipts=survivors,
        inspection_digest=inspection_digest,
    )


def _try_v1(jobs, snapshot, closure, *, recovery_required=False):
    if recovery_required or snapshot["recovery_history"]:
        return False
    run_id = snapshot["lease"]["run_id"]
    try:
        run = jobs.service.store.get_run(run_id, require_finalized=True)
    except (OSError, ValueError, RunStoreError):
        return False
    state = jobs.store.get_job(snapshot["lease"]["job_id"])["progress"]
    session = state.get("session")
    receipt = state.get("receiver_cleanup_receipt")
    if (
        run.get("cleanup", {}).get("success") is not True
        or run["cleanup"].get("outstanding_receipt_count") != 0
        or state.get("receiver_closed") is not True
        or state.get("receiver_observation", {}).get("state") != "verified"
        or not isinstance(session, dict)
        or not isinstance(receipt, dict)
        or session.get("receiver_session_id") != closure["session_generation"]
        or session.get("receiver_process_id") != closure["process_id"]
        or session.get("creation_identity") != closure["creation_identity"]
        or receipt.get("verified_closed") is not True
        or receipt.get("process_id") != closure["process_id"]
        or receipt.get("creation_identity") != closure["creation_identity"]
    ):
        return False
    tasks = snapshot["tasks"]
    if any(task["terminal"] is None for task in tasks):
        return False
    original_cleanup = snapshot["original_cleanup_task"]
    if original_cleanup is not None and original_cleanup["terminal"] is None:
        return False
    cleanup_digest = (
        original_cleanup["terminal"]["terminal_digest"]
        if original_cleanup is not None
        else content_hash(run["cleanup"])
    )
    native = (
        {
            "state": "complete",
            "run_id": run_id,
            "task_ids": sorted(task["task_id"] for task in tasks),
            "cleanup_digest": cleanup_digest,
        }
        if tasks
        else {"state": "not_started", "run_id": run_id}
    )
    settlement = {
        "schema_version": "bluefire.capability-attempt-settlement.v1",
        "attempt_id": snapshot["lease"]["attempt_id"],
        "lease_digest": snapshot["lease"]["lease_digest"],
        "receiver": {
            "state": "verified_closed",
            "session_generation": closure["session_generation"],
            "review_digest": closure["review_digest"],
            "receipt_digest": content_hash(receipt),
        },
        "native": native,
    }
    try:
        jobs.store.settle_capability_attempt(snapshot["lease"]["attempt_id"], settlement)
    except ProductStoreError:
        return False
    ledger.repair_progress(jobs.store, snapshot["lease"]["attempt_id"], settlement)
    return True


def recover_one(jobs, attempt_id, *, stop_event=None):
    if stop_event is not None and stop_event.is_set():
        return "pending"
    snapshot = ledger.snapshot(jobs.store, attempt_id)
    settlement = snapshot["settlement"]
    if settlement is not None:
        ledger.repair_progress(jobs.store, attempt_id, settlement)
        return "settled"
    workspace, receiver = snapshot["workspace"], snapshot["receiver"]
    if (
        receiver is None
        or receiver.get("schema_version") != "bluefire.capability-receiver-binding.v2"
        or workspace is not None
        and workspace.get("schema_version") != "bluefire.capability-workspace-binding.v2"
    ):
        return "pending"
    receiver_closure = snapshot["receiver_closure"]
    if receiver_closure is None:
        proof = close_exact_receiver(receiver["process_id"], receiver["creation_identity"])
        receiver_closure = ledger.record_receiver_closure(jobs.store, attempt_id, proof)
    if workspace is None:
        if snapshot["tasks"] or snapshot["original_cleanup_task"] or snapshot["recovery_claim"]:
            return "pending"
        generation = ledger.begin_generation(jobs.store, attempt_id, jobs.clock())
        cleanup_closure = ledger.record_cleanup_closure(
            jobs.store,
            attempt_id,
            generation=generation,
            inspection_digest=ledger.no_dispatch_digest(
                attempt_id, snapshot["lease"]["lease_digest"]
            ),
        )
        settlement = {
            "schema_version": "bluefire.capability-attempt-settlement.v2",
            "attempt_id": attempt_id,
            "lease_digest": snapshot["lease"]["lease_digest"],
            "generation": generation,
            "disposition": "interrupted_unusable",
            "native": {"state": "verified_clean", "closure_digest": content_hash(cleanup_closure)},
            "receiver": {
                "state": "verified_closed",
                "closure_digest": content_hash(receiver_closure),
            },
        }
        jobs.store.settle_capability_attempt(attempt_id, settlement)
        ledger.repair_progress(jobs.store, attempt_id, settlement)
        return "settled"
    if stop_event is not None and stop_event.is_set():
        return "pending"
    raw, _wrapped, _profile = _runner(jobs, workspace, execution=False)
    tasks = snapshot["tasks"]
    known_receipts = set()
    recovery_required = False
    for task in tasks:
        if stop_event is not None and stop_event.is_set():
            return "pending"
        payload = task["payload"]
        if payload is None:
            return "pending"
        jobs.store.get_capability_task_payload(task["task_id"], payload["transport_request_hash"])
        unsent = {
            "schema_version": "bluefire.task-not-sent.v1",
            "task_id": task["task_id"],
            "request_hash": task["request_hash"],
        }
        if task["terminal"] is not None and task["terminal"]["terminal_digest"] == content_hash(
            unsent
        ):
            if payload.get("dispatch_protocol") == "bluefire.capability-task-dispatch-intent.v1":
                try:
                    jobs.store.record_capability_task_no_send(
                        attempt_id,
                        task_id=task["task_id"],
                        request_hash=task["request_hash"],
                        transport_request_hash=payload["transport_request_hash"],
                    )
                except ProductStoreError:
                    return "pending"
            result = unsent
        else:
            if stop_event is not None and stop_event.is_set():
                return "pending"
            try:
                result = _recovered_result(raw, task)
            except ProductStoreError:
                return "pending"
            if stop_event is not None and stop_event.is_set():
                return "pending"
        if task["terminal"] is None:
            if result == unsent:
                try:
                    jobs.store.record_capability_task_no_send(
                        attempt_id,
                        task_id=task["task_id"],
                        request_hash=task["request_hash"],
                        transport_request_hash=payload["transport_request_hash"],
                    )
                except ProductStoreError:
                    return "pending"
            else:
                jobs.store.record_capability_task_terminal(
                    task["task_id"],
                    request_hash=task["request_hash"],
                    terminal_digest=content_hash(result),
                )
        elif task["terminal"]["terminal_digest"] != content_hash(result):
            raise ProductStoreError("Original runner WAL differs from its terminal.")
        recovery_required = (
            result.get("schema_version")
            in {"bluefire.task-not-sent.v1", "bluefire.task-recovery-required.v1"}
            or recovery_required
        )
        known_receipts.update(result.get("receipt_ids", []))
    original_cleanup = snapshot["original_cleanup_task"]
    original_cleanup_ids: set[str] = set()
    original_cleanup_verified: set[str] = set()
    if original_cleanup is not None:
        if stop_event is not None and stop_event.is_set():
            return "pending"
        cleanup = jobs.store.get_capability_cleanup(attempt_id)
        claim = cleanup["task"]
        if claim is None:
            return "pending"
        payload = jobs.store.get_capability_cleanup_task_payload(
            claim["task_id"],
            ledger._optional_transport_hash(jobs.store, claim["task_id"]),
        )["payload"]
        unsent_cleanup = {
            "schema_version": "bluefire.task-not-sent.v1",
            "task_id": claim["task_id"],
            "request_hash": claim["request_hash"],
        }
        if original_cleanup["terminal"] is not None and original_cleanup["terminal"][
            "terminal_digest"
        ] == content_hash(unsent_cleanup):
            result = unsent_cleanup
        else:
            if stop_event is not None and stop_event.is_set():
                return "pending"
            recovered = raw.recover(claim["task_id"], payload["transport_request_hash"])
            if stop_event is not None and stop_event.is_set():
                return "pending"
            if (
                recovered.get("state") != "completed"
                or recovered.get("original_task_id") != claim["task_id"]
                or recovered.get("original_request_hash") != payload["transport_request_hash"]
                or not isinstance(recovered.get("result"), Mapping)
            ):
                return "pending"
            result = recovered["result"]
            Orchestrator._validate_runner_result(
                payload["manifest"], payload["runner_profile"], result
            )
            validate_cleanup_result(payload["manifest"], result)
        if original_cleanup["terminal"] is None:
            jobs.store.record_capability_cleanup_terminal(
                claim["task_id"],
                request_hash=claim["request_hash"],
                terminal_digest=content_hash(result),
            )
        elif original_cleanup["terminal"]["terminal_digest"] != content_hash(result):
            raise ProductStoreError("Original cleanup WAL differs from its terminal.")
        if result.get("schema_version") != "bluefire.task-not-sent.v1":
            original_cleanup_ids = set(payload["manifest"]["params"]["receipt_ids"])
            report = result.get("cleanup")
            if isinstance(report, Mapping) and (
                report.get("verification_performed") is True
                and report.get("requested_receipts") == len(original_cleanup_ids)
                and type(report.get("verified_receipts")) is int
            ):
                verified_ids = report.get("verified_receipt_ids")
                if verified_ids is not None:
                    if (
                        not set(verified_ids) <= original_cleanup_ids
                        or len(verified_ids) != report["verified_receipts"]
                    ):
                        raise ProductStoreError("Original cleanup verified another receipt.")
                    original_cleanup_verified = set(verified_ids)
                elif result.get("status") == "success" and report["verified_receipts"] == len(
                    original_cleanup_ids
                ):
                    original_cleanup_verified = original_cleanup_ids
        if result.get("status") != "success":
            recovery_required = True
    for _ in range(512):
        if stop_event is not None and stop_event.is_set():
            return "pending"
        snapshot = ledger.snapshot(jobs.store, attempt_id)
        receipts, workspace_id, inspection_digest = _receipts(workspace, snapshot["tasks"])
        raw_receipt_ids = {row["receipt_id"] for row in receipts}
        if snapshot["recovery_task"] is not None and snapshot["recovery_terminal"] is None:
            recovery_task = snapshot["recovery_task"]
            if stop_event is not None and stop_event.is_set():
                return "pending"
            try:
                recovered_result = _recovered_cleanup_result(raw, recovery_task)
            except ProductStoreError:
                return "pending"
            if stop_event is not None and stop_event.is_set():
                return "pending"
            ledger.record_cleanup_terminal(
                jobs.store,
                attempt_id,
                task_id=recovery_task["task_id"],
                result=recovered_result,
                remaining_receipts=receipts,
                inspection_digest=inspection_digest,
            )
            snapshot = ledger.snapshot(jobs.store, attempt_id)
        recovery_cleaned: set[str] = set()
        for history in snapshot["recovery_history"]:
            terminal = history["terminal"]
            if terminal is None:
                return "pending"
            claimed_ids = set(history["task"]["manifest"]["params"]["receipt_ids"])
            remaining_ids = {row["receipt_id"] for row in terminal["remaining_receipts"]}
            removed_ids = claimed_ids - remaining_ids
            if (
                not remaining_ids <= claimed_ids
                or removed_ids & recovery_cleaned
                or removed_ids & raw_receipt_ids
            ):
                raise ProductStoreError("Recovery cleanup lineage changed.")
            recovery_cleaned.update(removed_ids)
        original_cleaned = original_cleanup_verified - raw_receipt_ids
        if (
            not raw_receipt_ids <= known_receipts
            or not known_receipts <= raw_receipt_ids | original_cleaned | recovery_cleaned
        ):
            raise ProductStoreError("Original owned receipts have no verified cleanup lineage.")
        latest_terminal = snapshot["recovery_terminal"]
        if latest_terminal is not None and (
            latest_terminal["remaining_receipts"] != receipts
            or latest_terminal["inspection_digest"] != inspection_digest
        ):
            raise ProductStoreError("Recovery receipt inspection changed after cleanup.")
        if not receipts:
            if latest_terminal is not None and latest_terminal["result"]["status"] != "success":
                return "pending"
            terminal_digest = latest_terminal["terminal_digest"] if latest_terminal else None
            break
        if workspace_id is None:
            return "pending"
        if latest_terminal is not None:
            last_count = len(snapshot["recovery_task"]["manifest"]["params"]["receipt_ids"])
            if len(receipts) >= last_count:
                return "pending"
        if stop_event is not None and stop_event.is_set():
            return "pending"
        raw_execute, wrapped_execute, profile = _runner(jobs, workspace, execution=True)
        _claim_and_dispatch_cleanup(
            jobs,
            snapshot,
            raw_execute,
            wrapped_execute,
            profile,
            receipts,
            workspace_id,
            stop_event=stop_event,
        )
    else:
        return "pending"
    if stop_event is not None and stop_event.is_set():
        return "pending"
    generation = ledger.begin_generation(jobs.store, attempt_id, jobs.clock())
    cleanup_closure = ledger.record_cleanup_closure(
        jobs.store,
        attempt_id,
        generation=generation,
        inspection_digest=inspection_digest,
        terminal_digest=terminal_digest,
    )
    snapshot = ledger.snapshot(jobs.store, attempt_id)
    if _try_v1(jobs, snapshot, receiver_closure, recovery_required=recovery_required):
        return "settled"
    settlement = {
        "schema_version": "bluefire.capability-attempt-settlement.v2",
        "attempt_id": attempt_id,
        "lease_digest": snapshot["lease"]["lease_digest"],
        "generation": generation,
        "disposition": "interrupted_unusable",
        "native": {"state": "verified_clean", "closure_digest": content_hash(cleanup_closure)},
        "receiver": {"state": "verified_closed", "closure_digest": content_hash(receiver_closure)},
    }
    jobs.store.settle_capability_attempt(attempt_id, settlement)
    ledger.repair_progress(jobs.store, attempt_id, settlement)
    return "settled"


def recover_all(jobs, *, stop_event=None):
    summary = {"examined": 0, "settled": 0, "pending": 0}
    cursor = 0
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        page = ledger.list_pending(jobs.store, after_rowid=cursor)
        if not page:
            break
        for rowid, attempt_id in page:
            if stop_event is not None and stop_event.is_set():
                return summary
            cursor = rowid
            try:
                attempt = jobs.store.get_capability_attempt(attempt_id)
                grant = jobs.store.get_capability_grant(
                    attempt["lease"]["grant_id"], now_ms=jobs.clock()
                )["document"]
                if grant_pack(grant) != RECEIVER_RETAINED_PACK:
                    continue
                summary["examined"] += 1
                outcome = recover_one(jobs, attempt_id, stop_event=stop_event)
                summary["settled" if outcome == "settled" else "pending"] += 1
            except Exception:
                # Startup must expose uncertainty, not turn it into new work.
                summary["pending"] += 1
    return summary
