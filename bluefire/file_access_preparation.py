"""Pure admission checks for fixed retained-file preparations and task payloads."""

from types import SimpleNamespace

from .domain_errors import ProductStoreError
from .util import content_hash, parse_iso8601_datetime


def validate_preparation(prepared, original, enrollment, prior):
    from .adaptive_dispatch import operation_identity
    from .config import RunnerProfile
    from .file_access_plan import _plan, plan_step, recipe
    from .planner import DeterministicPlanner
    from .registry import load_builtin_registry
    from .runner_contracts import (
        _TIER_RANK,
        current_platform,
        effect_capabilities,
        execution_limits,
        seal_profile,
    )
    from .runner_plan_scope import filesystem_scope
    from .runner_reviewed_execution import canonical_reviewed_execution

    review, context = original["review"], original["review_context"]
    rows = recipe(review["operation"], prior)
    revision = 1 if prior is None else prior["revision"] + 1
    target = (
        None
        if prior is None or prior["binding"] is None
        else {**prior["binding"], "control_revision": revision}
    )
    if target is not None and review["operation"] in ("harden", "rollback"):
        target["mode"] = "0600" if review["operation"] == "harden" else "0640"
    plan = prepared["plan"]
    base = RunnerProfile.from_mapping(prepared["profile_document"])
    registry = load_builtin_registry()
    _, expected_plan = _plan(
        SimpleNamespace(planner=DeterministicPlanner(registry)),
        {
            "registry": registry,
            "profile": base,
            "control": None if prior is None else {"document": prior},
        },
        review["operation"],
    )
    if (
        prepared["schema_version"] != "bluefire.file-access-operation-preparation.v1"
        or prepared["context_digest"] != review["context_digest"]
        or prepared["enrollment_digest"] != original["enrollment_digest"]
        or prepared["recipe"] != rows
        or context["recipe"] != rows
        or prepared["prior"] != prior
        or prepared["source"] != (None if prior is None else prior["source"])
        or prepared["revision"] != revision
        or prepared["target_binding"] != target
        or prepared["target_binding_digest"] != content_hash(target)
        or content_hash(prepared["profile_document"]) != context["profile_digest"]
        or (None if prior is None else content_hash(prior)) != review["control_digest"]
        or plan["mode"] != "execute"
        or plan["autonomy"] != "off"
        or plan["ai_enabled"] is not False
        or plan["ai_provider"] != {}
        or plan["edges"] != []
        or plan["runner_profile_id"] != context["profile_id"]
        or len(plan["steps"]) != len(rows)
        or plan != expected_plan.to_dict()
    ):
        raise ProductStoreError(
            "The preparation differs from the exact reviewed recipe or preimage."
        )
    for step, row in zip(plan["steps"], rows, strict=True):
        if (
            any(
                step[key] != row[key]
                for key in ("step_id", "action_id", "behavior_id", "parameters")
            )
            or step["inputs"] != {}
        ):
            raise ProductStoreError("The preparation changed a fixed operation step.")
    roots = prepared["roots"]
    if (
        set(roots) != {"retained", *[row["workspace"] for row in rows]}
        or roots["retained"] != enrollment["root"]["path"]
        or len(set(roots.values())) != len(roots)
    ):
        raise ProductStoreError("The preparation changed its original owned workspaces.")
    if set(prepared["profiles"]) != set(roots):
        raise ProductStoreError("The preparation lacks every exact sealed workspace profile.")
    envelope = {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": review["review_digest"],
        "operations": [operation_identity(plan_step(step)) for step in plan["steps"]],
    }
    for workspace, profile in prepared["profiles"].items():
        expected_profile = {
            "schema_version": "bluefire.runner-profile.v1",
            "profile_id": base.id,
            "runner_id": "bluefire-rust-runner.v1",
            "platform": current_platform(),
            "sandbox_root": roots[workspace],
            "allowed_actions": sorted({row["action_id"] for row in rows}),
            "control_blocked_actions": list(base.blocked_actions),
            "capabilities": effect_capabilities(base.capabilities),
            "max_safety_tier": max(base.safety_tiers, key=_TIER_RANK.__getitem__).value,
            "approval_required_at_or_above": "safe" if base.approval_required else None,
            "target_scope": {
                "filesystem": list(
                    filesystem_scope(expected_plan, opcode_for_step=lambda step: step.action_id)
                ),
                "network": [],
            },
            "limits": execution_limits(base),
            "reviewed_execution": envelope,
        }
        installations = [
            installation
            for installation in (item.to_dict() for item in base.native_tool_installations)
            if installation["platform"] == expected_profile["platform"]
            and installation["adapter_id"] in expected_profile["allowed_actions"]
        ]
        if installations:
            expected_profile["native_tool_installations"] = installations
        if target is not None and workspace == "observation":
            expected_profile["file_access_binding"] = target
        if (
            seal_profile(expected_profile) != profile
            or profile["sandbox_root"] != roots[workspace]
            or profile["profile_id"] != context["profile_id"]
            or profile.get("reviewed_execution") != canonical_reviewed_execution(envelope)
            or profile.get("file_access_binding")
            != (target if workspace == "observation" else None)
        ):
            raise ProductStoreError("The preparation changed a reviewed sealed profile.")
    approved = prepared["approval"]
    if (
        approved.get("approved_by") != original["submitted_request"]["reviewed_by"]
        or int(parse_iso8601_datetime(approved["expires_at"]).timestamp() * 1000)
        > review["expires_at_ms"]
    ):
        raise ProductStoreError("The preparation approval differs from its operator review.")


def validate_task(prepared, prefix, task_id, step_id, manifest, profile, *, now_ms):
    from .adaptive_dispatch import reviewed_operation
    from .capability_resources import exact
    from .execution_contracts import execution_task_identity
    from .file_access_plan import _inputs, _receipts, plan_step
    from .runner_adapter import RunnerActionAdapter
    from .runner_contracts import effect_capabilities, seal_manifest

    rows = prepared["recipe"]
    if len(prefix) >= len(rows) or rows[len(prefix)]["step_id"] != step_id:
        raise ProductStoreError("The task does not follow the fixed original recipe.")
    outputs, adapter = {}, RunnerActionAdapter()
    for index, previous in enumerate(prefix):
        row = rows[index]
        result = previous["terminal"]["result"]
        if previous["task"]["step_id"] != row["step_id"] or result.get("status") != "success":
            raise ProductStoreError("The task lacks its exact successful predecessor.")
        outputs[row["step_id"]] = adapter.logical_outputs(
            plan_step(prepared["plan"]["steps"][index]),
            bound_inputs=_inputs(row["step_id"], outputs, prepared["source"]),
            runner_output=result.get("output"),
            receipt_ids=result["receipt_ids"],
        )
    row = rows[len(prefix)]
    step = plan_step(prepared["plan"]["steps"][len(prefix)])
    exact(
        manifest,
        {
            "schema_version",
            "request_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "mode",
            "runner_id",
            "runner_profile_id",
            "platform",
            "requested_at",
            "expires_at",
            "params",
            "target_scope",
            "required_capabilities",
            "safety_tier",
            "limits",
            "cleanup_action_id",
            "policy_digest",
            "approval",
            "evidence_refs",
            "request_hash",
            "reviewed_operation",
        },
        "fixed file-access native manifest",
    )
    adapted = adapter.adapt(
        step,
        bound_inputs=_inputs(step_id, outputs, prepared["source"]),
        receipt_ids=_receipts(step_id, outputs, prepared["source"]),
    )
    approval = manifest.get("approval")
    exact(
        approval,
        {"approved_by", "approved_at", "expires_at", "request_hash"},
        "file-access native approval",
    )
    requested_at, expires_at = (
        int(parse_iso8601_datetime(manifest[key]).timestamp() * 1000)
        for key in ("requested_at", "expires_at")
    )
    approved_at, approval_expires_at = (
        int(parse_iso8601_datetime(approval[key]).timestamp() * 1000)
        for key in ("approved_at", "expires_at")
    )
    if (
        profile != prepared["profiles"][row["workspace"]]
        or seal_manifest(manifest) != manifest
        or execution_task_identity(manifest, profile)[0] != task_id
        or manifest.get("params") != adapted.params
        or manifest.get("target_scope")
        != {
            "filesystem": list(adapted.filesystem_scope),
            "network": list(adapted.network_destinations),
        }
        or manifest.get("policy_digest") != profile["policy_digest"]
        or manifest.get("runner_profile_id") != profile["profile_id"]
        or manifest.get("runner_id") != profile["runner_id"]
        or manifest.get("platform") != profile["platform"]
        or manifest.get("reviewed_operation") != reviewed_operation(step, profile)
        or manifest.get("execution_binding") != step.execution_binding
        or manifest.get("mode") != "execute"
        or manifest.get("run_id") != prepared["run_id"]
        or manifest.get("step_id") != step.step_id
        or manifest.get("behavior_id") != step.behavior_id
        or manifest.get("action_id") != step.action_id
        or manifest.get("required_capabilities") != effect_capabilities(step.required_capabilities)
        or manifest.get("safety_tier") != step.safety_tier.value
        or manifest.get("cleanup_action_id") != "sandbox.cleanup.v1"
        or manifest.get("evidence_refs") != []
        or manifest.get("limits") != profile["limits"]
        or not approved_at <= requested_at <= now_ms < min(expires_at, approval_expires_at)
        or expires_at - requested_at != 300_000
        or not isinstance(approval, dict)
        or approval.get("approved_by") != prepared["approval"]["approved_by"]
        or any(
            parse_iso8601_datetime(approval[key])
            != parse_iso8601_datetime(prepared["approval"][key])
            for key in ("approved_at", "expires_at")
        )
    ):
        raise ProductStoreError(
            "The task differs from its exact sealed preparation or owned inputs."
        )
