"""Strict content-addressed contracts for materialized replay checkpoints."""

# ruff: noqa: E701, E702

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .util import canonical_json_bytes, content_hash


class CheckpointError(ValueError):
    """Raised when checkpoint or restoration data is unsafe or inconsistent."""


CHECKPOINT_SCHEMA = "bluefire.replay-checkpoint.v1"
RESTORATION_SCHEMA = "bluefire.replay-restoration-plan.v1"
AUTHORITY_SCHEMA = "bluefire.replay-checkpoint-authority.v1"
CLEANUP_SCHEMA = "bluefire.replay-checkpoint-cleanup.v1"

# Compact exact wire inventories keep this module within its architecture budget.
# fmt: off
_CHECKPOINT_FIELDS = frozenset("schema_version checkpoint_id manifest_hash source_run_id source_binding_hash checkpoint_before_step_id source_scenario source_plan executed_steps artifacts artifact_state_hash material_files material_state_hash source_authority source_cleanup collector_lineage_hash".split())
_SCENARIO_FIELDS = frozenset("scenario_id scenario_hash start_step_id metadata_hash edges_hash steps".split())
_SCENARIO_STEP_FIELDS = frozenset("step_id behavior_id parameters_hash contract_hash step_hash".split())
_PLAN_FIELDS = frozenset("plan_hash scenario_id scenario_hash runner_profile_id mode autonomy ai_provider_hash metadata_hash steps".split())
_PLAN_STEP_FIELDS = frozenset("step_id behavior_id action_id parameters_hash step_hash".split())
_EXECUTED_STEP_FIELDS = frozenset("step_id behavior_id action_id status artifacts_hash".split())
_ARTIFACT_ROW_FIELDS = frozenset("step_id artifacts artifacts_hash".split())
_MATERIAL_FIELDS = frozenset("relative_path kind sha256 size_bytes source_step_id artifact_name".split())
_SOURCE_AUTHORITY_INPUT_FIELDS = frozenset("profile target_scope catalog_authority runner_readiness".split())
_AUTHORITY_FIELDS = frozenset("schema_version profile target_scope catalog runner".split())
_PROFILE_FIELDS = frozenset("profile_id profile_hash mode environment_type platforms scope_refs capabilities safety_tiers approval_required enabled_actions blocked_actions cleanup_policy budgets".split())
_BUDGET_FIELDS = frozenset("max_steps max_seconds max_artifacts max_bytes".split())
_SCOPE_FIELDS = frozenset("scope_refs scope_hash".split())
_CATALOG_FIELDS = frozenset("schema_version catalog_hash generation catalog_digest authority_digest".split())
_RUNNER_FIELDS = frozenset("schema_version readiness_hash profile_id platform runner_identity_digest inventory_digest effective_inventory_digest catalog_hash".split())
_CLEANUP_INPUT_FIELDS = frozenset("attempted success outstanding_receipt_count".split())
_CLEANUP_FIELDS = frozenset("schema_version state cleanup_hash attempted success outstanding_receipt_count".split())
_VARIANT_INPUT_FIELDS = frozenset("parameter_steps behavior_steps action_steps autonomy_changed profile_changed defense_change".split())
_VARIANT_FIELDS = frozenset("parameter_steps behavior_steps action_steps autonomy_changed profile_changed defense_change_digest".split())
_RESTORATION_FIELDS = frozenset("schema_version plan_hash checkpoint_id checkpoint_manifest_hash source_run_id checkpoint_before_step_id strategy prefix_step_ids artifact_state_hash material_state_hash target variant_impact verification".split())
_TARGET_FIELDS = frozenset("scenario_hash compiled_plan_hash profile_id profile_hash scope_hash catalog_hash runner_readiness_hash runner_identity_digest inventory_digest effective_inventory_digest platform autonomy ai_provider_hash".split())
_VERIFICATION_FIELDS = frozenset("require_prefix_hash_match require_material_hash_match require_fresh_approval reuse_source_receipts require_fresh_cleanup_receipts require_zero_outstanding_cleanup".split())
_VERIFICATION = {"require_prefix_hash_match": True, "require_material_hash_match": True, "require_fresh_approval": True, "reuse_source_receipts": False, "require_fresh_cleanup_receipts": True, "require_zero_outstanding_cleanup": True}
# fmt: on

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DRIVE = re.compile(r"^[A-Za-z]:")
_DEVICE = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
_SENSITIVE_MARKERS = frozenset(
    "apikey authorization cookie credential nonce password privatekey providerartifact receipt secret token".split()
)
_MAX_STEPS = 256
_MAX_MATERIAL_FILES = 512
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_MATERIAL_BYTES = 256 * 1024 * 1024


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CheckpointError(f"{context} must be an object with string keys")
    return value


def _exact(value: Mapping[str, Any], fields: frozenset[str], context: str) -> None:
    if set(value) != fields:
        raise CheckpointError(f"{context} fields do not match the checkpoint schema")


def _text(value: Any, context: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise CheckpointError(f"{context} must be bounded non-empty text")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, maximum=256)
    if _IDENTIFIER.fullmatch(text) is None:
        raise CheckpointError(f"{context} is not a safe identifier")
    return text


def _digest(value: Any, context: str, *, raw_allowed: bool = False) -> str:
    if isinstance(value, str) and _DIGEST.fullmatch(value):
        return value
    if raw_allowed and isinstance(value, str) and _RAW_DIGEST.fullmatch(value):
        return "sha256:" + value
    raise CheckpointError(f"{context} must be a canonical sha256 digest")


def _bounded_int(value: Any, context: str, *, minimum: int = 0, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CheckpointError(f"{context} is outside its integer bound")
    return int(value)


def _json_copy(value: Any, context: str, *, reject_sensitive: bool = False) -> Any:
    count = 0

    def inspect(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > 20_000 or depth > 12:
            raise CheckpointError(f"{context} exceeds its structural bound")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            return
        if isinstance(item, str):
            if len(item) > 16_384 or "\x00" in item:
                raise CheckpointError(f"{context} contains unsafe text")
            return
        if isinstance(item, Mapping):
            if len(item) > 1_024:
                raise CheckpointError(f"{context} contains an oversized object")
            for key, nested in item.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise CheckpointError(f"{context} contains an invalid field name")
                compact = re.sub(r"[^a-z0-9]", "", key.casefold())
                if reject_sensitive and any(marker in compact for marker in _SENSITIVE_MARKERS):
                    raise CheckpointError(f"{context} contains forbidden sensitive authority")
                inspect(nested, depth + 1)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if len(item) > 2_048:
                raise CheckpointError(f"{context} contains an oversized list")
            for nested in item:
                inspect(nested, depth + 1)
            return
        raise CheckpointError(f"{context} is not strict JSON data")

    inspect(value, 0)
    try:
        encoded = canonical_json_bytes(value)
        if len(encoded) > _MAX_JSON_BYTES:
            raise CheckpointError(f"{context} exceeds its byte bound")
        return json.loads(encoded)
    except (OverflowError, TypeError, ValueError) as exc:
        raise CheckpointError(f"{context} is not canonical JSON data") from exc


def _safe_path(value: Any, context: str) -> str:
    raw = _text(value, context, maximum=500)
    if raw.startswith(("/", "\\")) or _DRIVE.match(raw):
        raise CheckpointError(f"{context} must be a relative material path")
    canonical = raw.replace("\\", "/")
    parts = canonical.split("/")
    if (
        not parts
        or any(not part or part in {".", ".."} for part in parts)
        or any(":" in part or part.endswith((".", " ")) for part in parts)
        or any(_DEVICE.fullmatch(part) for part in parts)
        or any(any(ord(character) < 32 for character in part) for part in parts)
    ):
        raise CheckpointError(f"{context} is unsafe")
    return "/".join(parts)


def _string_list(
    value: Any,
    context: str,
    *,
    maximum: int = _MAX_STEPS,
    sorted_output: bool = False,
) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) > maximum:
        raise CheckpointError(f"{context} must be a bounded list")
    result = [_identifier(item, f"{context} item") for item in value]
    if len(result) != len(set(result)):
        raise CheckpointError(f"{context} contains duplicates")
    return sorted(result) if sorted_output else result


# These constructors are intentionally compact: each emits one exact wire
# record, while the validators below independently reconstruct relationships.
# fmt: off
def _scenario_summary(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); cloned = _json_copy(source, context)
    scenario_id = _identifier(source.get("id"), f"{context}.id"); start = _identifier(source.get("start"), f"{context}.start")
    raw_steps = source.get("steps")
    if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes)) or not 1 <= len(raw_steps) <= _MAX_STEPS:
        raise CheckpointError(f"{context}.steps must be a bounded non-empty list")
    steps: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_steps):
        step = _mapping(raw, f"{context}.steps[{index}]"); parameters = _mapping(step.get("parameters", {}), f"{context}.steps[{index}].parameters")
        contract = {key: item for key, item in step.items() if key not in {"behavior_id", "parameters"}}
        steps.append({"step_id": _identifier(step.get("id"), f"{context}.steps[{index}].id"), "behavior_id": _identifier(step.get("behavior_id"), f"{context}.steps[{index}].behavior_id"), "parameters_hash": content_hash(parameters), "contract_hash": content_hash(contract), "step_hash": content_hash(step)})
    step_ids = [row["step_id"] for row in steps]
    if len(step_ids) != len(set(step_ids)) or start not in step_ids: raise CheckpointError(f"{context} step identities are invalid")
    metadata = {key: item for key, item in source.items() if key not in {"steps", "edges"}}
    return {"scenario_id": scenario_id, "scenario_hash": content_hash(cloned), "start_step_id": start, "metadata_hash": content_hash(metadata), "edges_hash": content_hash(source.get("edges", [])), "steps": steps}

def _plan_summary(value: Mapping[str, Any], scenario: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); cloned = _json_copy(source, context); raw_steps = source.get("steps")
    if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes)) or not 1 <= len(raw_steps) <= _MAX_STEPS: raise CheckpointError(f"{context}.steps is invalid")
    steps: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_steps):
        step = _mapping(raw, f"{context}.steps[{index}]"); action = step.get("action_id"); parameters = _mapping(step.get("parameters", {}), f"{context}.steps[{index}].parameters")
        steps.append({"step_id": _identifier(step.get("step_id"), f"{context}.steps[{index}].step_id"), "behavior_id": _identifier(step.get("behavior_id"), f"{context}.steps[{index}].behavior_id"), "action_id": _identifier(action, f"{context}.steps[{index}].action_id") if action is not None else None, "parameters_hash": content_hash(parameters), "step_hash": content_hash(step)})
    scenario_steps = scenario["steps"]
    if [row["step_id"] for row in steps] != [row["step_id"] for row in scenario_steps]: raise CheckpointError(f"{context} step order does not match the scenario")
    if any(planned["behavior_id"] != defined["behavior_id"] or planned["parameters_hash"] != defined["parameters_hash"] for planned, defined in zip(steps, scenario_steps, strict=True)): raise CheckpointError(f"{context} behavior or parameters do not match the scenario")
    scenario_id = _identifier(source.get("scenario_id"), f"{context}.scenario_id"); scenario_hash = _digest(source.get("scenario_digest"), f"{context}.scenario_digest")
    if scenario_id != scenario["scenario_id"] or scenario_hash != scenario["scenario_hash"]: raise CheckpointError(f"{context} scenario binding is invalid")
    mode = _text(source.get("mode"), f"{context}.mode", maximum=32); autonomy = _text(source.get("autonomy", "off"), f"{context}.autonomy", maximum=32)
    if mode != "execute" or autonomy not in {"off", "assist", "auto"}: raise CheckpointError(f"{context} is not an Execute plan with valid autonomy")
    excluded = {"steps", "scenario_digest", "runner_profile_id", "autonomy", "ai_enabled", "ai_provider"}
    metadata = {key: item for key, item in source.items() if key not in excluded}
    return {"plan_hash": content_hash(cloned), "scenario_id": scenario_id, "scenario_hash": scenario_hash, "runner_profile_id": _identifier(source.get("runner_profile_id"), f"{context}.runner_profile_id"), "mode": mode, "autonomy": autonomy, "ai_provider_hash": content_hash(source.get("ai_provider", {})), "metadata_hash": content_hash(metadata), "steps": steps}

def _profile_summary(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); cloned = _json_copy(source, context); budgets = _mapping(source.get("budgets"), f"{context}.budgets"); _exact(budgets, _BUDGET_FIELDS, f"{context}.budgets")
    normalized_budgets = {key: _bounded_int(budgets[key], f"{context}.budgets.{key}", minimum=1, maximum=2**63 - 1) for key in sorted(_BUDGET_FIELDS)}
    profile: dict[str, Any] = {"profile_id": _identifier(source.get("id"), f"{context}.id"), "profile_hash": content_hash(cloned), "mode": _text(source.get("mode"), f"{context}.mode", maximum=32), "environment_type": _identifier(source.get("environment_type"), f"{context}.environment_type"), "platforms": _string_list(source.get("platforms"), f"{context}.platforms", maximum=16), "scope_refs": _string_list(source.get("scope"), f"{context}.scope", maximum=64), "capabilities": _string_list(source.get("capabilities"), f"{context}.capabilities", maximum=128), "safety_tiers": _string_list(source.get("safety_tiers"), f"{context}.safety_tiers", maximum=8), "approval_required": source.get("approval_required"), "enabled_actions": _string_list(source.get("enabled_actions"), f"{context}.enabled_actions", maximum=512), "blocked_actions": _string_list(source.get("blocked_actions", []), f"{context}.blocked_actions", maximum=512), "cleanup_policy": _text(source.get("cleanup_policy"), f"{context}.cleanup_policy", maximum=64), "budgets": normalized_budgets}
    unsafe = profile["mode"] != "execute" or profile["approval_required"] is not True or profile["cleanup_policy"] != "always" or not profile["platforms"] or not profile["scope_refs"] or "sandbox.cleanup.v1" not in profile["enabled_actions"] or "sandbox.cleanup.v1" in profile["blocked_actions"]
    if unsafe: raise CheckpointError(f"{context} is not a cleanup-safe Execute profile")
    return profile

def _scope_summary(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context)
    if set(source) != {"scope_refs"}: raise CheckpointError(f"{context} must contain only scope_refs")
    refs = _string_list(source.get("scope_refs"), f"{context}.scope_refs", maximum=64)
    if not refs: raise CheckpointError(f"{context}.scope_refs cannot be empty")
    canonical = {"scope_refs": sorted(refs)}
    return {**canonical, "scope_hash": content_hash(canonical)}

def _catalog_summary(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); cloned = _json_copy(source, context)
    if source.get("schema_version") != "bluefire.action-catalog-authority.v1": raise CheckpointError(f"{context} schema is invalid")
    authority_digest = _digest(source.get("authority_digest"), f"{context}.authority_digest"); body = dict(source); body.pop("authority_digest", None)
    if authority_digest != content_hash(body): raise CheckpointError(f"{context} authority digest is invalid")
    return {"schema_version": str(source["schema_version"]), "catalog_hash": content_hash(cloned), "generation": _bounded_int(source.get("generation"), f"{context}.generation", maximum=2**63 - 1), "catalog_digest": _digest(source.get("catalog_digest"), f"{context}.catalog_digest"), "authority_digest": authority_digest}

def _runner_summary(value: Mapping[str, Any], catalog: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); cloned = _json_copy(source, context)
    if source.get("schema_version") != "bluefire.execute-readiness.v1": raise CheckpointError(f"{context} schema is invalid")
    identity = _mapping(source.get("runner_identity"), f"{context}.runner_identity"); identity_digest = _digest(source.get("runner_identity_digest"), f"{context}.runner_identity_digest")
    if identity_digest != content_hash(identity): raise CheckpointError(f"{context} runner identity digest is invalid")
    readiness_catalog = _mapping(source.get("catalog_authority"), f"{context}.catalog_authority")
    if content_hash(readiness_catalog) != catalog["catalog_hash"]: raise CheckpointError(f"{context} catalog binding is invalid")
    return {"schema_version": str(source["schema_version"]), "readiness_hash": content_hash(cloned), "profile_id": _identifier(source.get("profile_id"), f"{context}.profile_id"), "platform": _identifier(source.get("platform"), f"{context}.platform"), "runner_identity_digest": identity_digest, "inventory_digest": _digest(source.get("inventory_digest"), f"{context}.inventory_digest"), "effective_inventory_digest": _digest(source.get("effective_inventory_digest"), f"{context}.effective_inventory_digest"), "catalog_hash": catalog["catalog_hash"]}

def _authority_summary(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); _exact(source, _SOURCE_AUTHORITY_INPUT_FIELDS, context)
    profile = _profile_summary(_mapping(source["profile"], f"{context}.profile"), f"{context}.profile"); scope = _scope_summary(_mapping(source["target_scope"], f"{context}.target_scope"), f"{context}.target_scope")
    catalog = _catalog_summary(_mapping(source["catalog_authority"], f"{context}.catalog_authority"), f"{context}.catalog_authority"); runner = _runner_summary(_mapping(source["runner_readiness"], f"{context}.runner_readiness"), catalog, f"{context}.runner_readiness")
    if runner["profile_id"] != profile["profile_id"] or runner["platform"] not in profile["platforms"] or not set(scope["scope_refs"]).issubset(profile["scope_refs"]): raise CheckpointError(f"{context} profile, runner, or scope bindings disagree")
    return {"schema_version": AUTHORITY_SCHEMA, "profile": profile, "target_scope": scope, "catalog": catalog, "runner": runner}

def _cleanup_summary(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    source = _mapping(value, context); _exact(source, _CLEANUP_INPUT_FIELDS, context)
    if source.get("attempted") is not True or source.get("success") is not True or source.get("outstanding_receipt_count") != 0 or isinstance(source.get("outstanding_receipt_count"), bool): raise CheckpointError(f"{context} must be completed with zero outstanding cleanup")
    body = {"attempted": True, "success": True, "outstanding_receipt_count": 0}
    return {"schema_version": CLEANUP_SCHEMA, "state": "completed", "cleanup_hash": content_hash(body), **body}
# The formatter remains disabled through the builders, whose long exact records
# are clearer as compact wire-schema literals.
def _artifact_rows(artifacts: Mapping[str, Any], prefix: Sequence[str], context: str) -> list[dict[str, Any]]:
    source = _mapping(artifacts, context)
    if set(source) != set(prefix):
        raise CheckpointError(f"{context} must contain exactly the executed prefix")
    rows: list[dict[str, Any]] = []
    for step_id in prefix:
        value = _mapping(source[step_id], f"{context}.{step_id}")
        cloned = _json_copy(value, f"{context}.{step_id}", reject_sensitive=True)
        rows.append({"step_id": step_id, "artifacts": cloned, "artifacts_hash": content_hash(cloned)})
    return rows


def _material_rows(material_files: Sequence[Mapping[str, Any]], artifact_rows: Sequence[Mapping[str, Any]], prefix: Sequence[str], context: str) -> list[dict[str, Any]]:
    if not isinstance(material_files, Sequence) or isinstance(material_files, (str, bytes)) or not 1 <= len(material_files) <= _MAX_MATERIAL_FILES:
        raise CheckpointError(f"{context} must be a bounded non-empty list")
    artifacts_by_step = {str(row["step_id"]): row["artifacts"] for row in artifact_rows}
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(material_files):
        row = _mapping(raw, f"{context}[{index}]")
        _exact(row, _MATERIAL_FIELDS, f"{context}[{index}]")
        kind = row.get("kind")
        if kind != "file":
            raise CheckpointError(f"{context}[{index}] cannot contain links or directories")
        source_step = _identifier(row.get("source_step_id"), f"{context}[{index}].source_step_id")
        if source_step not in prefix:
            raise CheckpointError(f"{context}[{index}] is not produced by the executed prefix")
        artifact_name = _identifier(row.get("artifact_name"), f"{context}[{index}].artifact_name")
        step_artifacts = _mapping(artifacts_by_step[source_step], f"{context}[{index}] artifacts")
        logical = _mapping(step_artifacts.get(artifact_name), f"{context}[{index}] logical artifact")
        relative_path = _safe_path(row.get("relative_path"), f"{context}[{index}].relative_path")
        logical_path = logical.get("path", logical.get("artifact"))
        logical_digest = _digest(logical.get("sha256"), f"{context}[{index}] logical sha256", raw_allowed=True)
        digest = _digest(row.get("sha256"), f"{context}[{index}].sha256", raw_allowed=True)
        size = _bounded_int(row.get("size_bytes"), f"{context}[{index}].size_bytes", minimum=1, maximum=_MAX_MATERIAL_BYTES)
        if _safe_path(logical_path, f"{context}[{index}] logical path") != relative_path:
            raise CheckpointError(f"{context}[{index}] path is not bound to its logical artifact")
        if logical_digest != digest:
            raise CheckpointError(f"{context}[{index}] hash is not bound to its logical artifact")
        logical_size = logical.get("size", logical.get("size_bytes"))
        if logical_size is not None and logical_size != size:
            raise CheckpointError(f"{context}[{index}] size is not bound to its logical artifact")
        rows.append({"relative_path": relative_path, "kind": "file", "sha256": digest, "size_bytes": size, "source_step_id": source_step, "artifact_name": artifact_name})
    keys = [(row["relative_path"], row["source_step_id"], row["artifact_name"]) for row in rows]
    if len({row["relative_path"] for row in rows}) != len(rows) or len(set(keys)) != len(rows):
        raise CheckpointError(f"{context} contains duplicate material identities")
    if sum(int(row["size_bytes"]) for row in rows) > _MAX_MATERIAL_BYTES:
        raise CheckpointError(f"{context} exceeds its aggregate byte bound")
    return sorted(rows, key=lambda row: (row["relative_path"], row["source_step_id"], row["artifact_name"]))


def _manifest_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"checkpoint_id", "manifest_hash"}}


def _checkpoint_id(manifest_hash: str) -> str:
    return "checkpoint-" + manifest_hash.removeprefix("sha256:")


def build_checkpoint(*, source_run_id: str, source_binding_hash: str, scenario: Mapping[str, Any], plan: Mapping[str, Any], checkpoint_before_step_id: str, executed_steps: Sequence[Mapping[str, Any]], artifacts: Mapping[str, Any], material_files: Sequence[Mapping[str, Any]], source_authority: Mapping[str, Any], source_cleanup: Mapping[str, Any], collector_lineage: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    """Build a canonical checkpoint manifest for a completed Execute run."""

    run_id = _identifier(source_run_id, "source_run_id")
    if not run_id.startswith("run-"):
        raise CheckpointError("source_run_id must identify a run")
    binding_hash = _digest(source_binding_hash, "source_binding_hash")
    scenario_summary = _scenario_summary(scenario, "scenario")
    plan_summary = _plan_summary(plan, scenario_summary, "plan")
    checkpoint_step = _identifier(checkpoint_before_step_id, "checkpoint_before_step_id")
    plan_step_ids = [str(row["step_id"]) for row in plan_summary["steps"]]
    if checkpoint_step not in plan_step_ids or plan_step_ids.index(checkpoint_step) == 0:
        raise CheckpointError("checkpoint must follow a non-empty executable prefix")
    prefix = plan_step_ids[: plan_step_ids.index(checkpoint_step)]
    if not isinstance(executed_steps, Sequence) or isinstance(executed_steps, (str, bytes)) or len(executed_steps) != len(prefix):
        raise CheckpointError("executed_steps must be the exact ordered checkpoint prefix")
    artifact_rows = _artifact_rows(artifacts, prefix, "artifacts")
    artifact_by_step = {str(row["step_id"]): row for row in artifact_rows}
    executed: list[dict[str, Any]] = []
    for index, raw in enumerate(executed_steps):
        row = _mapping(raw, f"executed_steps[{index}]")
        step_id = _identifier(row.get("step_id"), f"executed_steps[{index}].step_id")
        planned = plan_summary["steps"][index]
        behavior_id = _identifier(row.get("behavior_id"), f"executed_steps[{index}].behavior_id")
        action_id = _identifier(row.get("action_id"), f"executed_steps[{index}].action_id")
        status = _text(row.get("status"), f"executed_steps[{index}].status", maximum=32)
        if step_id != prefix[index] or behavior_id != planned["behavior_id"] or action_id != planned["action_id"] or status not in {"success", "partial"}:
            raise CheckpointError("executed_steps do not match the successful plan prefix")
        executed.append({"step_id": step_id, "behavior_id": behavior_id, "action_id": action_id, "status": status, "artifacts_hash": artifact_by_step[step_id]["artifacts_hash"]})
    material = _material_rows(material_files, artifact_rows, prefix, "material_files")
    authority = _authority_summary(source_authority, "source_authority")
    if authority["profile"]["profile_id"] != plan_summary["runner_profile_id"]:
        raise CheckpointError("source profile does not match the checkpoint plan")
    total_size = sum(int(row["size_bytes"]) for row in material)
    if authority["profile"]["budgets"]["max_artifacts"] < len(material) or authority["profile"]["budgets"]["max_bytes"] < total_size:
        raise CheckpointError("checkpoint material exceeds the source profile budget")
    cleanup = _cleanup_summary(source_cleanup, "source_cleanup")
    collector_hash = None
    if collector_lineage is not None:
        collector_hash = content_hash(_json_copy(collector_lineage, "collector_lineage"))
    body: dict[str, Any] = {"schema_version": CHECKPOINT_SCHEMA, "source_run_id": run_id, "source_binding_hash": binding_hash, "checkpoint_before_step_id": checkpoint_step, "source_scenario": scenario_summary, "source_plan": plan_summary, "executed_steps": executed, "artifacts": artifact_rows, "artifact_state_hash": content_hash(artifact_rows), "material_files": material, "material_state_hash": content_hash(material), "source_authority": authority, "source_cleanup": cleanup, "collector_lineage_hash": collector_hash}
    manifest_hash = content_hash(body)
    checkpoint = {**body, "checkpoint_id": _checkpoint_id(manifest_hash), "manifest_hash": manifest_hash}
    return validate_checkpoint(checkpoint)
# fmt: on


def _validate_scenario_summary(value: Any) -> dict[str, Any]:
    source = _mapping(value, "checkpoint source_scenario")
    _exact(source, _SCENARIO_FIELDS, "checkpoint source_scenario")
    steps = source.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)) or not steps:
        raise CheckpointError("checkpoint source_scenario.steps is invalid")
    normalized_steps: list[dict[str, Any]] = []
    for raw in steps:
        row = _mapping(raw, "checkpoint scenario step")
        _exact(row, _SCENARIO_STEP_FIELDS, "checkpoint scenario step")
        normalized_steps.append(
            {
                "step_id": _identifier(row["step_id"], "checkpoint scenario step_id"),
                "behavior_id": _identifier(row["behavior_id"], "checkpoint scenario behavior_id"),
                "parameters_hash": _digest(row["parameters_hash"], "scenario parameters_hash"),
                "contract_hash": _digest(row["contract_hash"], "scenario contract_hash"),
                "step_hash": _digest(row["step_hash"], "scenario step_hash"),
            }
        )
    ids = [row["step_id"] for row in normalized_steps]
    start = _identifier(source["start_step_id"], "checkpoint scenario start_step_id")
    if len(ids) != len(set(ids)) or len(ids) > _MAX_STEPS or start not in ids:
        raise CheckpointError("checkpoint scenario step identities are invalid")
    return {
        "scenario_id": _identifier(source["scenario_id"], "checkpoint scenario_id"),
        "scenario_hash": _digest(source["scenario_hash"], "checkpoint scenario_hash"),
        "start_step_id": start,
        "metadata_hash": _digest(source["metadata_hash"], "checkpoint scenario metadata_hash"),
        "edges_hash": _digest(source["edges_hash"], "checkpoint scenario edges_hash"),
        "steps": normalized_steps,
    }


def _validate_plan_summary(value: Any, scenario: Mapping[str, Any]) -> dict[str, Any]:
    source = _mapping(value, "checkpoint source_plan")
    _exact(source, _PLAN_FIELDS, "checkpoint source_plan")
    raw_steps = source.get("steps")
    if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes)):
        raise CheckpointError("checkpoint source_plan.steps is invalid")
    steps: list[dict[str, Any]] = []
    for raw in raw_steps:
        row = _mapping(raw, "checkpoint plan step")
        _exact(row, _PLAN_STEP_FIELDS, "checkpoint plan step")
        action = row.get("action_id")
        steps.append(
            {
                "step_id": _identifier(row["step_id"], "checkpoint plan step_id"),
                "behavior_id": _identifier(row["behavior_id"], "checkpoint plan behavior_id"),
                "action_id": _identifier(action, "checkpoint plan action_id") if action else None,
                "parameters_hash": _digest(row["parameters_hash"], "plan parameters_hash"),
                "step_hash": _digest(row["step_hash"], "plan step_hash"),
            }
        )
    if len(steps) > _MAX_STEPS or len(steps) != len(scenario["steps"]):
        raise CheckpointError("checkpoint plan step count is invalid")
    if any(
        planned["step_id"] != defined["step_id"]
        or planned["behavior_id"] != defined["behavior_id"]
        or planned["parameters_hash"] != defined["parameters_hash"]
        for planned, defined in zip(steps, scenario["steps"], strict=True)
    ):
        raise CheckpointError("checkpoint plan does not match its scenario summary")
    if source.get("mode") != "execute" or source.get("autonomy") not in {"off", "assist", "auto"}:
        raise CheckpointError("checkpoint plan execution identity is invalid")
    if (
        source.get("scenario_id") != scenario["scenario_id"]
        or source.get("scenario_hash") != scenario["scenario_hash"]
    ):
        raise CheckpointError("checkpoint plan scenario binding is invalid")
    return {
        "plan_hash": _digest(source["plan_hash"], "checkpoint plan_hash"),
        "scenario_id": str(source["scenario_id"]),
        "scenario_hash": str(source["scenario_hash"]),
        "runner_profile_id": _identifier(
            source["runner_profile_id"], "checkpoint runner_profile_id"
        ),
        "mode": "execute",
        "autonomy": str(source["autonomy"]),
        "ai_provider_hash": _digest(source["ai_provider_hash"], "checkpoint ai_provider_hash"),
        "metadata_hash": _digest(source["metadata_hash"], "checkpoint plan metadata_hash"),
        "steps": steps,
    }


def _validate_profile_summary(value: Any) -> dict[str, Any]:
    source = _mapping(value, "checkpoint profile")
    _exact(source, _PROFILE_FIELDS, "checkpoint profile")
    budgets = _mapping(source["budgets"], "checkpoint profile budgets")
    _exact(budgets, _BUDGET_FIELDS, "checkpoint profile budgets")
    result = dict(source)
    result["profile_id"] = _identifier(source["profile_id"], "checkpoint profile_id")
    result["profile_hash"] = _digest(source["profile_hash"], "checkpoint profile_hash")
    for field in (
        "platforms",
        "scope_refs",
        "capabilities",
        "safety_tiers",
        "enabled_actions",
        "blocked_actions",
    ):
        result[field] = _string_list(source[field], f"checkpoint profile {field}", maximum=512)
    result["budgets"] = {
        key: _bounded_int(budgets[key], f"checkpoint budget {key}", minimum=1, maximum=2**63 - 1)
        for key in sorted(_BUDGET_FIELDS)
    }
    if (
        source.get("mode") != "execute"
        or source.get("approval_required") is not True
        or source.get("cleanup_policy") != "always"
        or "sandbox.cleanup.v1" not in result["enabled_actions"]
        or "sandbox.cleanup.v1" in result["blocked_actions"]
    ):
        raise CheckpointError("checkpoint profile is not cleanup-safe")
    return result


def _validate_authority_summary(value: Any) -> dict[str, Any]:
    source = _mapping(value, "checkpoint source_authority")
    _exact(source, _AUTHORITY_FIELDS, "checkpoint source_authority")
    if source.get("schema_version") != AUTHORITY_SCHEMA:
        raise CheckpointError("checkpoint source_authority schema is invalid")
    profile = _validate_profile_summary(source["profile"])
    scope = _mapping(source["target_scope"], "checkpoint target_scope")
    _exact(scope, _SCOPE_FIELDS, "checkpoint target_scope")
    refs = _string_list(scope["scope_refs"], "checkpoint target_scope refs", maximum=64)
    if refs != sorted(refs) or scope.get("scope_hash") != content_hash({"scope_refs": refs}):
        raise CheckpointError("checkpoint target_scope is not canonical")
    catalog = _mapping(source["catalog"], "checkpoint catalog")
    _exact(catalog, _CATALOG_FIELDS, "checkpoint catalog")
    if catalog.get("schema_version") != "bluefire.action-catalog-authority.v1":
        raise CheckpointError("checkpoint catalog schema is invalid")
    normalized_catalog = dict(catalog)
    normalized_catalog["catalog_hash"] = _digest(catalog["catalog_hash"], "catalog_hash")
    normalized_catalog["catalog_digest"] = _digest(catalog["catalog_digest"], "catalog_digest")
    normalized_catalog["authority_digest"] = _digest(
        catalog["authority_digest"], "catalog authority_digest"
    )
    _bounded_int(catalog["generation"], "catalog generation", maximum=2**63 - 1)
    runner = _mapping(source["runner"], "checkpoint runner")
    _exact(runner, _RUNNER_FIELDS, "checkpoint runner")
    if runner.get("schema_version") != "bluefire.execute-readiness.v1":
        raise CheckpointError("checkpoint runner schema is invalid")
    normalized_runner = dict(runner)
    for field in (
        "readiness_hash",
        "runner_identity_digest",
        "inventory_digest",
        "effective_inventory_digest",
        "catalog_hash",
    ):
        normalized_runner[field] = _digest(runner[field], f"runner {field}")
    normalized_runner["profile_id"] = _identifier(runner["profile_id"], "runner profile_id")
    normalized_runner["platform"] = _identifier(runner["platform"], "runner platform")
    if (
        normalized_runner["profile_id"] != profile["profile_id"]
        or normalized_runner["platform"] not in profile["platforms"]
        or normalized_runner["catalog_hash"] != normalized_catalog["catalog_hash"]
        or not set(refs).issubset(profile["scope_refs"])
    ):
        raise CheckpointError("checkpoint source authority bindings disagree")
    return {
        "schema_version": AUTHORITY_SCHEMA,
        "profile": profile,
        "target_scope": {"scope_refs": refs, "scope_hash": str(scope["scope_hash"])},
        "catalog": normalized_catalog,
        "runner": normalized_runner,
    }


def _validate_cleanup_summary(value: Any) -> dict[str, Any]:
    source = _mapping(value, "checkpoint source_cleanup")
    _exact(source, _CLEANUP_FIELDS, "checkpoint source_cleanup")
    body = {
        "attempted": source.get("attempted"),
        "success": source.get("success"),
        "outstanding_receipt_count": source.get("outstanding_receipt_count"),
    }
    if (
        source.get("schema_version") != CLEANUP_SCHEMA
        or source.get("state") != "completed"
        or body != {"attempted": True, "success": True, "outstanding_receipt_count": 0}
        or source.get("cleanup_hash") != content_hash(body)
    ):
        raise CheckpointError("checkpoint cleanup binding is invalid")
    return dict(source)


def validate_checkpoint(
    value: Mapping[str, Any],
    *,
    expected_source_run_id: str | None = None,
    expected_step_id: str | None = None,
    expected_source_binding_hash: str | None = None,
) -> Mapping[str, Any]:
    """Validate and detach an exact checkpoint manifest."""

    source = _mapping(value, "checkpoint")
    _exact(source, _CHECKPOINT_FIELDS, "checkpoint")
    if source.get("schema_version") != CHECKPOINT_SCHEMA:
        raise CheckpointError("checkpoint schema_version is invalid")
    run_id = _identifier(source.get("source_run_id"), "checkpoint source_run_id")
    source_binding_hash = _digest(
        source.get("source_binding_hash"), "checkpoint source_binding_hash"
    )
    step_id = _identifier(source.get("checkpoint_before_step_id"), "checkpoint step_id")
    if expected_source_run_id is not None and run_id != expected_source_run_id:
        raise CheckpointError("checkpoint belongs to another source run")
    if expected_step_id is not None and step_id != expected_step_id:
        raise CheckpointError("checkpoint belongs to another resume step")
    if expected_source_binding_hash is not None and source_binding_hash != _digest(
        expected_source_binding_hash, "expected checkpoint source_binding_hash"
    ):
        raise CheckpointError("checkpoint source binding does not match its verified run bundle")
    scenario = _validate_scenario_summary(source.get("source_scenario"))
    plan = _validate_plan_summary(source.get("source_plan"), scenario)
    plan_ids = [str(row["step_id"]) for row in plan["steps"]]
    if step_id not in plan_ids or plan_ids.index(step_id) == 0:
        raise CheckpointError("checkpoint resume step has no materialized prefix")
    prefix = plan_ids[: plan_ids.index(step_id)]
    raw_artifacts = source.get("artifacts")
    if not isinstance(raw_artifacts, Sequence) or isinstance(raw_artifacts, (str, bytes)):
        raise CheckpointError("checkpoint artifacts must be a list")
    artifact_rows: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_artifacts):
        row = _mapping(raw, f"checkpoint artifacts[{index}]")
        _exact(row, _ARTIFACT_ROW_FIELDS, f"checkpoint artifacts[{index}]")
        step = _identifier(row["step_id"], "checkpoint artifact step_id")
        artifacts = _mapping(row["artifacts"], "checkpoint logical artifacts")
        cloned = _json_copy(artifacts, "checkpoint logical artifacts", reject_sensitive=True)
        if row.get("artifacts_hash") != content_hash(cloned):
            raise CheckpointError("checkpoint logical artifact hash is invalid")
        artifact_rows.append(
            {"step_id": step, "artifacts": cloned, "artifacts_hash": row["artifacts_hash"]}
        )
    if [row["step_id"] for row in artifact_rows] != prefix:
        raise CheckpointError("checkpoint artifacts do not match the ordered prefix")
    raw_executed = source.get("executed_steps")
    if not isinstance(raw_executed, Sequence) or isinstance(raw_executed, (str, bytes)):
        raise CheckpointError("checkpoint executed_steps must be a list")
    if len(raw_executed) != len(prefix):
        raise CheckpointError("checkpoint executed_steps do not match the prefix")
    executed: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_executed):
        row = _mapping(raw, f"checkpoint executed_steps[{index}]")
        _exact(row, _EXECUTED_STEP_FIELDS, f"checkpoint executed_steps[{index}]")
        planned = plan["steps"][index]
        normalized = {
            "step_id": _identifier(row["step_id"], "checkpoint executed step_id"),
            "behavior_id": _identifier(row["behavior_id"], "checkpoint executed behavior_id"),
            "action_id": _identifier(row["action_id"], "checkpoint executed action_id"),
            "status": _text(row["status"], "checkpoint executed status", maximum=32),
            "artifacts_hash": _digest(row["artifacts_hash"], "checkpoint artifacts_hash"),
        }
        if (
            normalized["step_id"] != prefix[index]
            or normalized["behavior_id"] != planned["behavior_id"]
            or normalized["action_id"] != planned["action_id"]
            or normalized["status"] not in {"success", "partial"}
            or normalized["artifacts_hash"] != artifact_rows[index]["artifacts_hash"]
        ):
            raise CheckpointError("checkpoint executed prefix is semantically inconsistent")
        executed.append(normalized)
    raw_material = source.get("material_files")
    if not isinstance(raw_material, Sequence) or isinstance(raw_material, (str, bytes)):
        raise CheckpointError("checkpoint material_files must be a list")
    material = _material_rows(raw_material, artifact_rows, prefix, "checkpoint material_files")
    if list(raw_material) != material:
        raise CheckpointError("checkpoint material_files are not canonically sorted")
    authority = _validate_authority_summary(source.get("source_authority"))
    cleanup = _validate_cleanup_summary(source.get("source_cleanup"))
    if authority["profile"]["profile_id"] != plan["runner_profile_id"]:
        raise CheckpointError("checkpoint plan and authority profiles disagree")
    if source.get("artifact_state_hash") != content_hash(artifact_rows):
        raise CheckpointError("checkpoint artifact_state_hash is invalid")
    if source.get("material_state_hash") != content_hash(material):
        raise CheckpointError("checkpoint material_state_hash is invalid")
    collector_hash = source.get("collector_lineage_hash")
    if collector_hash is not None:
        _digest(collector_hash, "checkpoint collector_lineage_hash")
    manifest_hash = _digest(source.get("manifest_hash"), "checkpoint manifest_hash")
    if manifest_hash != content_hash(_manifest_body(source)):
        raise CheckpointError("checkpoint manifest_hash is invalid")
    if source.get("checkpoint_id") != _checkpoint_id(manifest_hash):
        raise CheckpointError("checkpoint_id does not match the manifest hash")
    validated_checkpoint: dict[str, Any] = {
        **dict(source),
        "source_binding_hash": source_binding_hash,
        "source_scenario": scenario,
        "source_plan": plan,
        "executed_steps": executed,
        "artifacts": artifact_rows,
        "material_files": material,
        "source_authority": authority,
        "source_cleanup": cleanup,
    }
    return _mapping(_json_copy(validated_checkpoint, "checkpoint"), "validated checkpoint")


def checkpoint_for_step(
    checkpoints: Sequence[Mapping[str, Any]], step_id: str
) -> Mapping[str, Any]:
    """Return the one valid checkpoint immediately before ``step_id``."""

    selected_step = _identifier(step_id, "checkpoint lookup step_id")
    if (
        not isinstance(checkpoints, Sequence)
        or isinstance(checkpoints, (str, bytes))
        or len(checkpoints) > _MAX_STEPS
    ):
        raise CheckpointError("checkpoints must be a bounded list")
    validated = [validate_checkpoint(item) for item in checkpoints]
    ids = [str(item["checkpoint_id"]) for item in validated]
    steps = [str(item["checkpoint_before_step_id"]) for item in validated]
    if len(ids) != len(set(ids)) or len(steps) != len(set(steps)):
        raise CheckpointError("checkpoint inventory contains duplicate identities")
    matches = [item for item in validated if item["checkpoint_before_step_id"] == selected_step]
    if len(matches) != 1:
        raise CheckpointError("exactly one checkpoint is required for the selected step")
    return matches[0]


def _variant_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    source = _mapping(value, "variant_impact")
    _exact(source, _VARIANT_INPUT_FIELDS, "variant_impact")
    result: dict[str, Any] = {
        "parameter_steps": _string_list(
            source["parameter_steps"], "variant_impact.parameter_steps", sorted_output=True
        ),
        "behavior_steps": _string_list(
            source["behavior_steps"], "variant_impact.behavior_steps", sorted_output=True
        ),
        "action_steps": _string_list(
            source["action_steps"], "variant_impact.action_steps", sorted_output=True
        ),
        "autonomy_changed": source.get("autonomy_changed"),
        "profile_changed": source.get("profile_changed"),
        "defense_change_digest": None,
    }
    if not isinstance(result["autonomy_changed"], bool) or not isinstance(
        result["profile_changed"], bool
    ):
        raise CheckpointError("variant_impact change flags must be booleans")
    defense = source.get("defense_change")
    if defense is not None:
        text = _text(defense, "variant_impact.defense_change", maximum=2_000)
        result["defense_change_digest"] = content_hash({"defense_change": text})
    return result


def _changed_steps(source: Mapping[str, Any], target: Mapping[str, Any], field: str) -> set[str]:
    return {
        str(left["step_id"])
        for left, right in zip(source["steps"], target["steps"], strict=True)
        if left[field] != right[field]
    }


def build_restoration_plan(
    checkpoint: Mapping[str, Any],
    *,
    target_scenario: Mapping[str, Any],
    target_plan: Mapping[str, Any],
    target_profile: Mapping[str, Any],
    target_scope: Mapping[str, Any],
    target_catalog_authority: Mapping[str, Any],
    target_runner_readiness: Mapping[str, Any],
    variant_impact: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Bind a fresh recreation-and-verification plan to one checkpoint."""

    trusted = validate_checkpoint(checkpoint)
    scenario = _scenario_summary(target_scenario, "target_scenario")
    plan = _plan_summary(target_plan, scenario, "target_plan")
    profile = _profile_summary(target_profile, "target_profile")
    scope = _scope_summary(target_scope, "target_scope")
    catalog = _catalog_summary(target_catalog_authority, "target_catalog_authority")
    runner = _runner_summary(target_runner_readiness, catalog, "target_runner_readiness")
    variant = _variant_summary(variant_impact)
    source_scenario = trusted["source_scenario"]
    source_plan = trusted["source_plan"]
    source_authority = trusted["source_authority"]
    source_profile = source_authority["profile"]
    source_runner = source_authority["runner"]
    source_step_ids = [str(row["step_id"]) for row in source_scenario["steps"]]
    target_step_ids = [str(row["step_id"]) for row in scenario["steps"]]
    if (
        scenario["scenario_id"] != source_scenario["scenario_id"]
        or scenario["start_step_id"] != source_scenario["start_step_id"]
        or target_step_ids != source_step_ids
        or scenario["metadata_hash"] != source_scenario["metadata_hash"]
        or scenario["edges_hash"] != source_scenario["edges_hash"]
        or plan["metadata_hash"] != source_plan["metadata_hash"]
        or plan["mode"] != source_plan["mode"]
    ):
        raise CheckpointError("target scenario or plan changes checkpoint structure")
    if any(
        left["contract_hash"] != right["contract_hash"]
        for left, right in zip(source_scenario["steps"], scenario["steps"], strict=True)
    ):
        raise CheckpointError("target scenario changes a step contract")
    parameter_changes = _changed_steps(source_scenario, scenario, "parameters_hash")
    behavior_changes = _changed_steps(source_scenario, scenario, "behavior_id")
    action_changes = _changed_steps(source_plan, plan, "action_id")
    if parameter_changes != set(variant["parameter_steps"]):
        raise CheckpointError("declared parameter impact does not match the target scenario")
    if behavior_changes != set(variant["behavior_steps"]):
        raise CheckpointError("declared behavior impact does not match the target scenario")
    if action_changes != set(variant["action_steps"]):
        raise CheckpointError("declared action impact does not match the target plan")
    checkpoint_index = source_step_ids.index(str(trusted["checkpoint_before_step_id"]))
    changed = parameter_changes | behavior_changes | action_changes
    if any(source_step_ids.index(step_id) < checkpoint_index for step_id in changed):
        raise CheckpointError("a replay variant changes the materialized prefix")
    prefix = source_step_ids[:checkpoint_index]
    if any(
        source_scenario["steps"][index]["step_hash"] != scenario["steps"][index]["step_hash"]
        or source_plan["steps"][index]["step_hash"] != plan["steps"][index]["step_hash"]
        for index in range(checkpoint_index)
    ):
        raise CheckpointError("target prefix does not match the trusted checkpoint")
    autonomy_changed = plan["autonomy"] != source_plan["autonomy"]
    profile_changed = profile["profile_id"] != source_profile["profile_id"]
    if autonomy_changed is not variant["autonomy_changed"]:
        raise CheckpointError("declared autonomy impact does not match the target plan")
    if profile_changed is not variant["profile_changed"]:
        raise CheckpointError("declared profile impact does not match the target profile")
    if not autonomy_changed and plan["ai_provider_hash"] != source_plan["ai_provider_hash"]:
        raise CheckpointError("AI provider changed without an autonomy variant")
    if (
        plan["runner_profile_id"] != profile["profile_id"]
        or runner["profile_id"] != profile["profile_id"]
    ):
        raise CheckpointError("target plan, profile, and runner bindings disagree")
    if scope["scope_hash"] != source_authority["target_scope"]["scope_hash"]:
        raise CheckpointError("checkpoint restoration cannot change target scope")
    if catalog["catalog_hash"] != source_authority["catalog"]["catalog_hash"]:
        raise CheckpointError("checkpoint restoration cannot change catalog authority")
    if (
        runner["runner_identity_digest"] != source_runner["runner_identity_digest"]
        or runner["inventory_digest"] != source_runner["inventory_digest"]
        or runner["platform"] not in profile["platforms"]
        or not set(scope["scope_refs"]).issubset(profile["scope_refs"])
    ):
        raise CheckpointError("target runner or profile is incompatible with the checkpoint")
    if not profile_changed and profile["profile_hash"] != source_profile["profile_hash"]:
        raise CheckpointError("unchanged target profile does not match the source profile")
    if profile_changed and (
        profile["mode"] != source_profile["mode"]
        or profile["environment_type"] != source_profile["environment_type"]
    ):
        raise CheckpointError("changed target profile is not checkpoint-compatible")
    enabled = set(profile["enabled_actions"])
    blocked = set(profile["blocked_actions"])
    for index in range(checkpoint_index):
        action_id = plan["steps"][index]["action_id"]
        if action_id not in enabled or action_id in blocked:
            raise CheckpointError("target profile cannot recreate the checkpoint prefix")
    total_size = sum(int(row["size_bytes"]) for row in trusted["material_files"])
    if (
        profile["budgets"]["max_steps"] < len(plan["steps"])
        or profile["budgets"]["max_artifacts"] < len(trusted["material_files"])
        or profile["budgets"]["max_bytes"] < total_size
    ):
        raise CheckpointError("target profile cannot satisfy checkpoint material bounds")
    target = {
        "scenario_hash": scenario["scenario_hash"],
        "compiled_plan_hash": plan["plan_hash"],
        "profile_id": profile["profile_id"],
        "profile_hash": profile["profile_hash"],
        "scope_hash": scope["scope_hash"],
        "catalog_hash": catalog["catalog_hash"],
        "runner_readiness_hash": runner["readiness_hash"],
        "runner_identity_digest": runner["runner_identity_digest"],
        "inventory_digest": runner["inventory_digest"],
        "effective_inventory_digest": runner["effective_inventory_digest"],
        "platform": runner["platform"],
        "autonomy": plan["autonomy"],
        "ai_provider_hash": plan["ai_provider_hash"],
    }
    body = {
        "schema_version": RESTORATION_SCHEMA,
        "checkpoint_id": trusted["checkpoint_id"],
        "checkpoint_manifest_hash": trusted["manifest_hash"],
        "source_run_id": trusted["source_run_id"],
        "checkpoint_before_step_id": trusted["checkpoint_before_step_id"],
        "strategy": "recreate_prefix_then_verify",
        "prefix_step_ids": prefix,
        "artifact_state_hash": trusted["artifact_state_hash"],
        "material_state_hash": trusted["material_state_hash"],
        "target": target,
        "variant_impact": variant,
        "verification": dict(_VERIFICATION),
    }
    result = {**body, "plan_hash": content_hash(body)}
    return validate_restoration_plan(result, trusted)


def validate_restoration_plan(
    value: Mapping[str, Any], checkpoint: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Validate a restoration plan against its immutable checkpoint."""

    trusted = validate_checkpoint(checkpoint)
    source = _mapping(value, "restoration plan")
    _exact(source, _RESTORATION_FIELDS, "restoration plan")
    if source.get("schema_version") != RESTORATION_SCHEMA:
        raise CheckpointError("restoration plan schema_version is invalid")
    body = {key: item for key, item in source.items() if key != "plan_hash"}
    if source.get("plan_hash") != content_hash(body):
        raise CheckpointError("restoration plan_hash is invalid")
    expected = {
        "checkpoint_id": trusted["checkpoint_id"],
        "checkpoint_manifest_hash": trusted["manifest_hash"],
        "source_run_id": trusted["source_run_id"],
        "checkpoint_before_step_id": trusted["checkpoint_before_step_id"],
        "artifact_state_hash": trusted["artifact_state_hash"],
        "material_state_hash": trusted["material_state_hash"],
    }
    if any(source.get(key) != item for key, item in expected.items()):
        raise CheckpointError("restoration plan does not bind the selected checkpoint")
    if source.get("strategy") != "recreate_prefix_then_verify":
        raise CheckpointError("restoration strategy is invalid")
    prefix = _string_list(source.get("prefix_step_ids"), "restoration prefix_step_ids")
    expected_prefix = [str(row["step_id"]) for row in trusted["executed_steps"]]
    if prefix != expected_prefix:
        raise CheckpointError("restoration prefix does not match the checkpoint")
    target = _mapping(source.get("target"), "restoration target")
    _exact(target, _TARGET_FIELDS, "restoration target")
    normalized_target = dict(target)
    for field in (
        "scenario_hash",
        "compiled_plan_hash",
        "profile_hash",
        "scope_hash",
        "catalog_hash",
        "runner_readiness_hash",
        "runner_identity_digest",
        "inventory_digest",
        "effective_inventory_digest",
        "ai_provider_hash",
    ):
        normalized_target[field] = _digest(target[field], f"restoration target {field}")
    normalized_target["profile_id"] = _identifier(target["profile_id"], "target profile_id")
    normalized_target["platform"] = _identifier(target["platform"], "target platform")
    if target.get("autonomy") not in {"off", "assist", "auto"}:
        raise CheckpointError("restoration target autonomy is invalid")
    variant = _mapping(source.get("variant_impact"), "restoration variant_impact")
    _exact(variant, _VARIANT_FIELDS, "restoration variant_impact")
    normalized_variant: dict[str, Any] = {
        "parameter_steps": _string_list(
            variant["parameter_steps"], "restoration parameter_steps", sorted_output=True
        ),
        "behavior_steps": _string_list(
            variant["behavior_steps"], "restoration behavior_steps", sorted_output=True
        ),
        "action_steps": _string_list(
            variant["action_steps"], "restoration action_steps", sorted_output=True
        ),
        "autonomy_changed": variant.get("autonomy_changed"),
        "profile_changed": variant.get("profile_changed"),
        "defense_change_digest": variant.get("defense_change_digest"),
    }
    if not isinstance(normalized_variant["autonomy_changed"], bool) or not isinstance(
        normalized_variant["profile_changed"], bool
    ):
        raise CheckpointError("restoration variant flags are invalid")
    if normalized_variant["defense_change_digest"] is not None:
        normalized_variant["defense_change_digest"] = _digest(
            normalized_variant["defense_change_digest"], "restoration defense_change_digest"
        )
    checkpoint_index = len(prefix)
    source_ids = [str(row["step_id"]) for row in trusted["source_plan"]["steps"]]
    for field in ("parameter_steps", "behavior_steps", "action_steps"):
        if any(step not in source_ids[checkpoint_index:] for step in normalized_variant[field]):
            raise CheckpointError("restoration variant changes the materialized prefix")
    source_plan = trusted["source_plan"]
    source_authority = trusted["source_authority"]
    source_profile = source_authority["profile"]
    source_runner = source_authority["runner"]
    if (
        normalized_target["scope_hash"] != source_authority["target_scope"]["scope_hash"]
        or normalized_target["catalog_hash"] != source_authority["catalog"]["catalog_hash"]
        or normalized_target["runner_identity_digest"] != source_runner["runner_identity_digest"]
        or normalized_target["inventory_digest"] != source_runner["inventory_digest"]
    ):
        raise CheckpointError("restoration target authority changed after planning")
    profile_changed = normalized_target["profile_id"] != source_profile["profile_id"]
    autonomy_changed = normalized_target["autonomy"] != source_plan["autonomy"]
    if profile_changed is not normalized_variant["profile_changed"]:
        raise CheckpointError("restoration profile impact is inconsistent")
    if autonomy_changed is not normalized_variant["autonomy_changed"]:
        raise CheckpointError("restoration autonomy impact is inconsistent")
    if not profile_changed and normalized_target["profile_hash"] != source_profile["profile_hash"]:
        raise CheckpointError("restoration source profile hash changed")
    if (
        not autonomy_changed
        and normalized_target["ai_provider_hash"] != source_plan["ai_provider_hash"]
    ):
        raise CheckpointError("restoration AI provider changed without an autonomy change")
    if (
        not any(
            normalized_variant[field]
            for field in ("parameter_steps", "behavior_steps", "action_steps")
        )
        and normalized_target["scenario_hash"] != trusted["source_scenario"]["scenario_hash"]
    ):
        raise CheckpointError("restoration scenario changed without a declared step variant")
    verification = _mapping(source.get("verification"), "restoration verification")
    _exact(verification, _VERIFICATION_FIELDS, "restoration verification")
    if dict(verification) != _VERIFICATION:
        raise CheckpointError("restoration verification policy was weakened")
    normalized: dict[str, Any] = {
        **dict(source),
        "prefix_step_ids": prefix,
        "target": normalized_target,
        "variant_impact": normalized_variant,
        "verification": dict(_VERIFICATION),
    }
    return _mapping(_json_copy(normalized, "restoration plan"), "validated restoration plan")


__all__ = [
    "CheckpointError",
    "build_checkpoint",
    "build_restoration_plan",
    "checkpoint_for_step",
    "validate_checkpoint",
    "validate_restoration_plan",
]
