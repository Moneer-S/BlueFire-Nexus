"""Fixed reviewed control recipes over the existing authenticated single-task path."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from . import file_access_context
from .adaptive_dispatch import operation_identity
from .approvals import execution_approval_binding, execution_intent_id, validate_claimed_approval
from .config import AutonomyLevel
from .evidence import SandboxObserver
from .file_access_contract import verify_file_access_binding
from .file_access_plan import _inputs as _inputs
from .file_access_plan import _plan as _plan
from .file_access_plan import _receipts as _receipts
from .file_access_plan import plan_step as plan_step
from .file_access_plan import recipe as recipe
from .orchestrator import Orchestrator
from .product_store_errors import ProductStoreError
from .runner_contracts import build_runner_profile
from .util import content_hash


def _engine(control, current):
    catalog = control.service._catalog_snapshot
    return Orchestrator(
        current["registry"],
        control.service.store,
        runner=current["runner"],
        approval_store=control.store,
        action_bindings=catalog.action_bindings,
        provider_artifacts=catalog.provider_artifacts,
        catalog_authority=catalog.to_dict(),
    )


def _iso(milliseconds):
    return (
        datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat().replace("+00:00", "Z")
    )


def _approval(control, current, scenario, plan, request, context):
    binding = execution_approval_binding(
        registry=current["registry"],
        scenario=scenario,
        plan=plan.to_dict(),
        profile=current["profile"],
        target_scope=current["run_intent"]["target_scope"],
        autonomy=AutonomyLevel.OFF,
        ai_provider={},
        context=context,
        runner_readiness=current["runner_readiness"],
        catalog_authority=control.service._catalog_snapshot.to_dict(),
    )
    common = {
        "expected_state_digest": binding["state_digest"],
        "expected_plan_digest": binding["plan_digest"],
        "expected_target_scope_digest": binding["target_scope_digest"],
    }
    pending = control.store.create_approval_request(
        run_id=execution_intent_id(binding),
        state_digest=binding["state_digest"],
        plan_digest=binding["plan_digest"],
        profile_id=binding["profile_id"],
        target_scope_digest=binding["target_scope_digest"],
        maximum_tier=binding["maximum_tier"],
        expires_at=_iso(request["review"]["expires_at_ms"]),
    )
    approved = control.store.approve(
        pending["approval_id"],
        approved_by=request["reviewed_by"],
        expires_at=_iso(request["review"]["expires_at_ms"]),
        **common,
    )
    consumed = control.store.consume_approval(
        approved["approval_id"], nonce=approved["nonce"], **common
    )
    claimed = control.store.claim_consumed_approval(
        consumed["approval_id"],
        nonce=consumed["nonce"],
        approved_by=request["reviewed_by"],
        expected_profile_id=binding["profile_id"],
        expected_maximum_tier=binding["maximum_tier"],
        **common,
    )
    return validate_claimed_approval(claimed, binding=binding, approved_by=request["reviewed_by"])


def _retained_source(engine, current):
    if current["control"] is None:
        return None
    document = current["control"]["document"]
    source = document["source"]
    if document["status"] == "recovery_required":
        from .file_access_recovery import validate_inventory

        validate_inventory(engine, source["recovery"])
        return source
    enrolled = current["enrollment"]["document"]
    if (
        source["workspace"] != enrolled["root"]["path"]
        or source["profile_id"] != current["profile"].id
        or source["enrollment_digest"] != current["enrollment"]["document_digest"]
    ):
        raise ProductStoreError("The retained source workspace, profile or enrollment changed.")
    receipts = {}
    engine._discover_runner_receipts(
        Path(source["workspace"]),
        expected_profile_id=source["profile_id"],
        require_commit=True,
        _documents=receipts,
    )
    receipt_id = source["fixture"]["receipt_ids"][0]
    if (
        source["fixture"]["receipt_ids"] != [receipt_id]
        or receipts.get(receipt_id) != source["creation_receipt"]
        or source["creation_receipt"]["request_hash"] != source["creation_request_hash"]
        or source["fixture"]["path"] != "fixtures/transformed.jsonl"
        or "sha256:" + source["fixture"]["sha256"] != document["binding"]["resource"]["sha256"]
        or source["fixture"]["size"] != document["binding"]["resource"]["size"]
    ):
        raise ProductStoreError("The exact retained input or its creation receipt changed.")
    return source


def _prepare(control, ctx, request, current, engine, scenario, plan):
    if any(step.execution_binding is not None for step in plan.steps):
        raise ProductStoreError(
            "Retained-file control recipes require their fixed built-in methods."
        )
    operation = request["review"]["operation"]
    source = _retained_source(engine, current)
    prior = None if current["control"] is None else current["control"]["document"]
    revision = 1 if prior is None else prior["revision"] + 1
    roots = {"retained": current["enrollment"]["document"]["root"]["path"]}
    if source is not None and "recovery" in source:
        roots.update({row["workspace"]: row["root"] for row in source["recovery"]})
    if operation in ("baseline", "rollback"):
        roots["observation"] = str(
            control.service._isolated_owned_sandbox(
                current["sandbox"], "file-access-" + ctx.job_id[4:]
            )
        )
    target_binding = None
    if prior is not None and prior["binding"] is not None:
        target_binding = deepcopy(prior["binding"])
        target_binding["control_revision"] = revision
        if operation in ("harden", "rollback"):
            target_binding["mode"] = "0600" if operation == "harden" else "0640"
    envelope = {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": request["review_digest"],
        "operations": [operation_identity(step) for step in plan.steps],
    }
    prepared = {
        "schema_version": "bluefire.file-access-operation-preparation.v1",
        "job_id": ctx.job_id,
        "run_id": control.service.store._new_run_id(),
        "context_digest": current["context_digest"],
        "enrollment_digest": current["enrollment"]["document_digest"],
        "recipe": recipe(operation, prior),
        "plan": plan.to_dict(),
        "source": source,
        "prior": prior,
        "target_binding": target_binding,
        "target_binding_digest": content_hash(target_binding),
        "revision": revision,
        "roots": roots,
    }
    profiles = {}
    for workspace, root in roots.items():
        profiles[workspace] = build_runner_profile(
            current["profile"],
            sandbox_root=root,
            filesystem_scope=engine._filesystem_scope(plan),
            network_destinations=(),
            reviewed_execution=envelope,
            **(
                {
                    "file_access_binding": verify_file_access_binding(
                        prepared["target_binding"],
                        expected_document_digest=prepared["target_binding_digest"],
                        now_ms=control.clock(),
                    )
                }
                if workspace == "observation" and operation != "reset"
                else {}
            ),
        )
    return {**prepared, "profiles": profiles, "profile_document": current["profile"].to_dict()}


def _execute(control, ctx, request):
    operation = request["review"]["operation"]
    current = control._context(operation, request["review"]["control_owner_id"])
    if current["context_digest"] != request["review"]["context_digest"]:
        raise ProductStoreError("The reviewed operation preimage changed before dispatch.")
    engine = _engine(control, current)
    scenario, plan = _plan(engine, current, operation)
    prepared = _prepare(control, ctx, request, current, engine, scenario, plan)
    approval = _approval(
        control,
        current,
        scenario,
        plan,
        request,
        {"file_access_operation": prepared, "operator_review": request["review"]},
    )
    prepared = {**prepared, "approval": approval}
    control.store.prepare_file_access_operation(ctx.job_id, prepared)
    outputs = {}
    try:
        for step, row in zip(plan.steps, prepared["recipe"], strict=True):
            ctx.checkpoint()
            profile = prepared["profiles"][row["workspace"]]

            def validate_context(step=step):
                fresh_enrollment = file_access_context.read_file_access_enrollment(
                    now_ms=control.clock()
                )
                if fresh_enrollment != current["enrollment"]:
                    raise ProductStoreError("The setup generation changed before task admission.")
                if current["control"] is not None:
                    retained = control.store.get_file_access_control(
                        request["review"]["control_owner_id"]
                    )
                    if retained["document_digest"] != request["review"]["control_digest"]:
                        raise ProductStoreError(
                            "The retained control changed before task admission."
                        )
                    if "recovery" in prepared["source"]:
                        from .file_access_recovery import receipt_snapshot, validate_inventory

                        remaining = []
                        for owned in prepared["source"]["recovery"]:
                            if "reset_" + owned["workspace"] in outputs:
                                if receipt_snapshot(engine, owned["profile"])["documents"]:
                                    raise ProductStoreError(
                                        "A cleaned original workspace acquired new receipt ownership."
                                    )
                            else:
                                remaining.append(owned)
                        validate_inventory(engine, remaining)
                    else:
                        _retained_source(engine, current)
                if step.action_id != "sandbox.cleanup.v1" and step.step_id not in (
                    "seed",
                    "transform",
                ):
                    inspected = file_access_context.binding(
                        current["enrollment"], revision=prepared["revision"], now_ms=control.clock()
                    )
                    expected = prepared["target_binding"]
                    if step.step_id == "mode" and current["control"] is not None:
                        expected = {
                            **current["control"]["document"]["binding"],
                            "control_revision": prepared["revision"],
                        }
                    if expected is not None and inspected != expected:
                        raise ProductStoreError("The exact retained input changed before dispatch.")

            def before_task(
                actual_step,
                inputs,
                manifest,
                task_id,
                profile=profile,
                validate_context=validate_context,
            ):
                control.store.register_file_access_task(
                    ctx.job_id,
                    task_id=task_id,
                    step_id=actual_step.step_id,
                    manifest=manifest,
                    runner_profile=profile,
                    now_ms=control.clock(),
                    validate_context=validate_context,
                )

            def after_task(actual_step, manifest, task_id, result, profile=profile, **_kwargs):
                if task_id not in {
                    row["task"]["task_id"]
                    for row in control.store.file_access_operation_records(ctx.job_id)["tasks"]
                }:
                    return
                from .file_access_recovery import close_worker, receipt_snapshot

                control.store.record_file_access_task_terminal(
                    task_id,
                    request_hash=manifest["request_hash"],
                    result=result,
                    receipt_snapshot=receipt_snapshot(engine, profile),
                )
                if (
                    result.get("status") == "success"
                    or result.get("schema_version") == "bluefire.task-not-sent.v1"
                ):
                    task = next(
                        row["task"]
                        for row in control.store.file_access_operation_records(ctx.job_id)["tasks"]
                        if row["task"]["task_id"] == task_id
                    )
                    close_worker(control, task, result)

            lifecycle = SimpleNamespace(before_task=before_task, after_task=after_task)
            result, records, _decision, _returned = engine._execute_step(
                run_id=prepared["run_id"],
                step=step,
                bound_inputs=_inputs(step.step_id, outputs, prepared["source"]),
                parent_ids=(),
                profile=current["profile"],
                runner_profile=profile,
                observer=SandboxObserver(Path(profile["sandbox_root"])),
                approved_by=request["reviewed_by"],
                approval_record=approval,
                authorized_target_scope=current["run_intent"]["target_scope"],
                receipt_ids=_receipts(step.step_id, outputs, prepared["source"]),
                cancel_event=ctx.cancellation_event,
                task_lifecycle=lifecycle,
            )
            control._publish(ctx.job_id, {"phase": step.step_id})
            if result["status"] != "success":
                raise ProductStoreError(
                    "The exact retained-file task did not complete successfully."
                )
            outputs[step.step_id] = result["artifacts"]
        _finish(control, ctx.job_id, request, prepared, current, engine, outputs)
    except BaseException:
        records = control.store.file_access_operation_records(ctx.job_id)
        if records["outcome"] is None:
            control.store.finish_file_access_operation(
                ctx.job_id,
                outcome={
                    "state": "unknown" if records["tasks"] else "refused_no_effect",
                    "evidence_digest": content_hash(records["tasks"]),
                },
            )
        control._publish(
            ctx.job_id, {"phase": "uncertain" if records["tasks"] else "not_dispatched"}
        )
        raise


def _finish(
    control, job_id, request, prepared, current, engine, outputs, *, expected_outcome_digest=None
):
    operation = request["review"]["operation"]
    owner_id = job_id if operation == "create" else request["review"]["control_owner_id"]
    records = control.store.file_access_operation_records(job_id)
    task_by_step = {row["task"]["step_id"]: row for row in records["tasks"]}
    if set(task_by_step) != {row["step_id"] for row in prepared["recipe"]} or any(
        row["terminal"] is None or row["terminal"]["result"].get("status") != "success"
        for row in records["tasks"]
    ):
        raise ProductStoreError(
            "The retained operation lacks every exact successful task terminal."
        )
    source = prepared["source"]
    prior = prepared["prior"]
    baseline = None if prior is None else prior["baseline"]
    binding = prepared["target_binding"]
    if operation == "reset":
        from .file_access_recovery import receipt_snapshot

        if any(
            receipt_snapshot(engine, profile)["documents"]
            for profile in prepared["profiles"].values()
        ):
            raise ProductStoreError("Reset left an original owned receipt unresolved.")
    if operation != "reset":
        binding = file_access_context.binding(
            current["enrollment"], revision=prepared["revision"], now_ms=control.clock()
        )
        if prepared["target_binding"] is not None and binding != prepared["target_binding"]:
            raise ProductStoreError(
                "The completed operation changed its exact retained data or control postimage."
            )
    if operation == "create":
        fixture = outputs["transform"]["fixture"]
        receipts = {}
        engine._discover_runner_receipts(
            Path(prepared["roots"]["retained"]),
            expected_profile_id=current["profile"].id,
            require_commit=True,
            _documents=receipts,
        )
        if (
            len(fixture["receipt_ids"]) != 1
            or set(receipts) != set(fixture["receipt_ids"])
            or binding["mode"] != "0640"
            or binding["resource"]["record_count"] != 8
            or binding["resource"]["sha256"] != "sha256:" + fixture["sha256"]
        ):
            raise ProductStoreError(
                "Creation did not leave exactly the reviewed retained generated resource."
            )
        source = {
            "workspace": prepared["roots"]["retained"],
            "profile_id": current["profile"].id,
            "profile_digest": content_hash(prepared["profiles"]["retained"]),
            "enrollment_digest": current["enrollment"]["document_digest"],
            "fixture": fixture,
            "creation_task_id": task_by_step["transform"]["task"]["task_id"],
            "creation_request_hash": task_by_step["transform"]["task"]["request_hash"],
            "creation_receipt": receipts[fixture["receipt_ids"][0]],
        }
    observation = None
    if operation in ("baseline", "rollback"):
        from .file_access_observation import baseline_record, control_observation

        observation = control_observation(
            operation, records["tasks"], binding=binding, now_ms=control.clock()
        )
        probe = task_by_step["probe"]["terminal"]["result"]["output"]["observation"]
        owner = task_by_step["owner"]["terminal"]["result"]["output"]["observation"]
        verification = outputs.get("owner", {}).get("verification", {})
        if (
            verification.get("probe_observation_digest") != content_hash(probe)
            or verification.get("observation_digest") != content_hash(owner)
            or verification.get("request_hash") != owner["request_hash"]
        ):
            raise ProductStoreError("Owner verification lost its exact preceding fresh probe.")
        if operation == "baseline":
            baseline = baseline_record(job_id, observation)
    status = {
        "create": "created",
        "baseline": "baseline_verified",
        "harden": "hardened",
        "rollback": "rolled_back",
        "reset": "reset",
    }[operation]
    document = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": owner_id,
        "enrollment_id": current["enrollment"]["document"]["enrollment_id"],
        "revision": prepared["revision"],
        "status": status,
        "binding": binding,
        "binding_digest": content_hash(binding),
        "source": source,
        "baseline": baseline,
    }
    control.store.finish_file_access_operation(
        job_id,
        outcome={"state": "complete", "evidence_digest": content_hash(records["tasks"])},
        control=document,
        expected_outcome_digest=expected_outcome_digest,
        verified_observation=observation,
        now_ms=control.clock(),
    )


def execute(control, ctx, request):
    try:
        _execute(control, ctx, request)
    except BaseException:
        records = control.store.file_access_operation_records(ctx.job_id)
        if records["outcome"] is None:
            state = "unknown" if records["tasks"] else "refused_no_effect"
            control.store.finish_file_access_operation(
                ctx.job_id,
                outcome={"state": state, "evidence_digest": content_hash(records["tasks"])},
            )
        control._publish(
            ctx.job_id, {"phase": "uncertain" if records["tasks"] else "not_dispatched"}
        )
        raise
