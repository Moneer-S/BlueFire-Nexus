"""Read-only reconciliation of original retained-file tasks and receipt ownership."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .capability_packs import FILE_ACCESS_METHODS
from .evidence import SandboxObserver
from .file_access_closure import recover_file_access_closure
from .file_access_contract import validate_file_access_observation, verify_file_access_binding
from .file_access_receipts import original_receipts as original_receipts
from .product_store_errors import ProductStoreError
from .runner_client import execution_task_identity
from .runner_receipt_authority import validate_result_receipts
from .util import content_hash, parse_iso8601_datetime


def receipt_snapshot(engine, profile):
    documents = {}
    root = Path(profile["sandbox_root"])
    engine._discover_runner_receipts(
        root, expected_profile_id=profile["profile_id"], _documents=documents
    )
    committed = engine._discover_runner_receipts(
        root, expected_profile_id=profile["profile_id"], require_commit=True
    )
    return {"documents": documents, "committed": list(committed)}


def _file_preimage(observer, entry):
    parts = observer._validated_parts(entry["relative_path"])
    try:
        descriptor = observer._open_file(parts)
    except FileNotFoundError:
        return {"present": False}
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > 64 * 1024 * 1024
        ):
            raise ProductStoreError("An original receipt path is no longer a bounded owned file.")
        digest, size = hashlib.sha256(), 0
        while chunk := os.read(descriptor, 65536):
            size += len(chunk)
            if size > 64 * 1024 * 1024:
                raise ProductStoreError("An original receipt path exceeded its bound.")
            digest.update(chunk)
        after = os.fstat(descriptor)

        def identity(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                info.st_nlink,
            )

        observer._assert_root_identity()
        if (
            identity(before) != identity(after)
            or size != entry["size"]
            or digest.hexdigest() != entry["sha256"]
        ):
            raise ProductStoreError(
                "An original receipt file changed; recovery needs an owner decision."
            )
        return {
            "present": True,
            "device": after.st_dev,
            "inode": after.st_ino,
            "mode": stat.S_IMODE(after.st_mode),
            "uid": after.st_uid,
            "gid": after.st_gid,
            "size": size,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def workspace_preimage(root, receipts):
    observer = SandboxObserver(Path(root))
    paths = {}
    for receipt in receipts.values():
        for entry in receipt["paths"]:
            if entry["kind"] == "file":
                paths[entry["relative_path"]] = _file_preimage(observer, entry)
    return {"root_identity": list(observer._root_identity), "paths": paths}


def validate_inventory(engine, inventory):
    if not isinstance(inventory, list) or not 1 <= len(inventory) <= 2:
        raise ProductStoreError("Partial recovery requires its original bounded workspaces.")
    if len({row["root"] for row in inventory}) != len(inventory):
        raise ProductStoreError("Partial recovery repeated a workspace.")
    for row in inventory:
        profile = row["profile"]
        if profile["sandbox_root"] != row["root"] or content_hash(profile) != row["profile_digest"]:
            raise ProductStoreError("Partial recovery changed an original sealed profile.")
        snapshot = receipt_snapshot(engine, profile)
        if (
            snapshot != row["snapshot"]
            or workspace_preimage(row["root"], snapshot["documents"]) != row["preimage"]
        ):
            raise ProductStoreError("Original owned receipts or reset preimage changed.")
    return inventory


def validate_terminal(engine, task, result):
    if result.get("schema_version") == "bluefire.task-not-sent.v1":
        if result != {
            "schema_version": "bluefire.task-not-sent.v1",
            "task_id": task["task_id"],
            "request_hash": task["request_hash"],
        }:
            raise ProductStoreError("Unsent terminal changed its exact original task.")
        return
    if result.get("schema_version") == "bluefire.authenticated-task-cancelled.v1":
        if (
            result.get("task_id") != task["task_id"]
            or result.get("request_hash") != task["request_hash"]
            or result.get("control_cleanup_verified") is not True
        ):
            raise ProductStoreError("Cancellation lacks its exact authenticated native closure.")
        return
    engine._validate_runner_result(task["manifest"], task["runner_profile"], result)
    engine._validated_receipt_ids(result.get("receipt_ids", []))
    engine._validate_cleanup_result(task["manifest"], result)


def validate_task_observation(task, result, *, binding, reader, now_ms):
    observation = validate_file_access_observation(
        result.get("output", {}).get("observation"),
        binding=binding,
        request_hash=task["request_hash"],
        reader=reader,
    )
    requested_at, expires_at = (
        int(parse_iso8601_datetime(task["manifest"][key]).timestamp() * 1000)
        for key in ("requested_at", "expires_at")
    )
    if (
        not requested_at <= observation["observed_at_ms"] < expires_at
        or observation["observed_at_ms"] > now_ms
    ):
        raise ProductStoreError("File-access observation is outside its original task lifetime.")
    return observation


def close_worker(control, task, result):
    if task["manifest"]["action_id"] != FILE_ACCESS_METHODS[0]:
        return
    binding = task["runner_profile"]["file_access_binding"]
    if result.get("schema_version") == "bluefire.task-not-sent.v1":
        proof = {
            "state": "not_sent",
            "binding_digest": content_hash(binding),
            "evidence_digest": content_hash(result),
        }
    elif result.get("status") == "success":
        observation = validate_task_observation(
            task,
            result,
            binding=binding,
            reader="non_owner",
            now_ms=control.clock(),
        )
        proof = {
            "state": "verified_closed",
            "binding_digest": content_hash(binding),
            "evidence_digest": content_hash(observation),
        }
    else:
        verified = verify_file_access_binding(
            binding, expected_document_digest=content_hash(binding), now_ms=control.clock()
        )
        closure = recover_file_access_closure(verified, request_hash=task["request_hash"])
        proof = {
            "state": "verified_closed",
            "binding_digest": content_hash(binding),
            "evidence_digest": content_hash(closure),
        }
    control.store.record_file_access_worker_closure(
        task["task_id"], request_hash=task["request_hash"], proof=proof
    )


def recover_tasks(control, job_id, prepared, engine, runner):
    saved = control.store.file_access_operation_records(job_id)
    for row in saved["tasks"]:
        task = row["task"]
        expected_id, transport_hash = execution_task_identity(
            task["manifest"], task["runner_profile"]
        )
        if task["task_id"] != expected_id or task["transport_request_hash"] != transport_hash:
            raise ProductStoreError("The original native payload identity changed.")
        if row["terminal"] is None:
            recovered = runner.recover(task["task_id"], transport_hash)
            if (
                recovered.get("state") != "completed"
                or recovered.get("original_task_id") != task["task_id"]
                or recovered.get("original_request_hash") != transport_hash
            ):
                raise ProductStoreError(
                    "The exact original task has no authenticated completed result."
                )
            result = recovered["result"]
            validate_terminal(engine, task, result)
            control.store.record_file_access_task_terminal(
                task["task_id"],
                request_hash=task["request_hash"],
                result=result,
                receipt_snapshot=receipt_snapshot(engine, task["runner_profile"]),
            )
        else:
            result = row["terminal"]["result"]
            validate_terminal(engine, task, result)
        close_worker(control, task, result)
    return validated_outputs(control.store.file_access_operation_records(job_id), prepared, engine)


def validated_outputs(saved, prepared, engine):
    from .file_access_plan import _inputs, _receipts, plan_step

    outputs, complete = {}, True
    for index, row in enumerate(saved["tasks"]):
        task, terminal = row["task"], row["terminal"]
        if terminal is None or task["step_id"] != prepared["recipe"][index]["step_id"]:
            raise ProductStoreError("The original task sequence is unresolved.")
        result = terminal["result"]
        validate_terminal(engine, task, result)
        if not complete:
            raise ProductStoreError("A task followed an unsuccessful original predecessor.")
        if result.get("schema_version") != "bluefire.runner-result.v1":
            complete = False
            continue
        identity = task["step_id"]
        step = plan_step(prepared["plan"]["steps"][index])
        inputs = _inputs(identity, outputs, prepared["source"])
        receipt_ids = _receipts(identity, outputs, prepared["source"])
        adapted = engine.adapter.adapt(step, bound_inputs=inputs, receipt_ids=receipt_ids)
        snapshot = terminal["receipt_snapshot"]
        current = [
            key
            for key in snapshot["committed"]
            if snapshot["documents"][key]["request_hash"] == task["request_hash"]
            and snapshot["documents"][key]["action_id"] == task["manifest"]["action_id"]
        ]
        retained = (
            receipt_ids if task["manifest"]["action_id"] == "sandbox.permission.chmod.v1" else []
        )
        validate_result_receipts(
            returned=result["receipt_ids"],
            prior_request_commits=(),
            current_request_commits=current,
            retained=retained,
            committed_ownership=snapshot["committed"],
            status=result["status"],
            has_observable_paths=bool(adapted.observable_paths),
        )
        if result.get("status") != "success":
            complete = False
            continue
        outputs[identity] = engine.adapter.logical_outputs(
            step,
            bound_inputs=inputs,
            runner_output=result.get("output"),
            receipt_ids=result["receipt_ids"],
        )
    return outputs, complete and len(saved["tasks"]) == len(prepared["recipe"])


def partial_inventory(saved, prepared, engine):
    known = original_receipts(saved["tasks"], prepared)
    inventory, surviving, consumed = [], set(), set()
    for row in saved["tasks"]:
        task, terminal = row["task"], row["terminal"]
        if (
            task["manifest"]["action_id"] == "sandbox.cleanup.v1"
            and terminal["result"].get("status") == "success"
        ):
            for receipt_id in task["manifest"]["params"]["receipt_ids"]:
                if (
                    receipt_id not in known
                    or known[receipt_id]["root"] != task["runner_profile"]["sandbox_root"]
                ):
                    raise ProductStoreError(
                        "Cleanup consumed authority from another original workspace."
                    )
                consumed.add(receipt_id)
    for workspace, profile in prepared["profiles"].items():
        snapshot = receipt_snapshot(engine, profile)
        sources = {}
        for receipt_id, receipt in snapshot["documents"].items():
            original = known.get(receipt_id)
            if (
                original is None
                or original["root"] != profile["sandbox_root"]
                or original["receipt"] != receipt
            ):
                raise ProductStoreError("An owned receipt has no exact original task provenance.")
            sources[receipt_id] = {key: value for key, value in original.items() if key != "root"}
            surviving.add(receipt_id)
        if sources:
            inventory.append(
                {
                    "workspace": workspace,
                    "root": profile["sandbox_root"],
                    "profile": profile,
                    "profile_digest": content_hash(profile),
                    "run_id": prepared["run_id"],
                    "sources": sources,
                    "snapshot": snapshot,
                    "preimage": workspace_preimage(profile["sandbox_root"], snapshot["documents"]),
                }
            )
    if set(known) - surviving - consumed or surviving & consumed:
        raise ProductStoreError("An original receipt disappeared without exact verified cleanup.")
    if not inventory:
        raise ProductStoreError(
            "No surviving original receipt establishes a partial reset obligation."
        )
    return inventory
