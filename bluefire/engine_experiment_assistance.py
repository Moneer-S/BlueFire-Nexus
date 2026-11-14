"""Bounded Assistant context for one saved external-engine experiment.

The caller must supply the exact workspace returned by the canonical presenter,
the service-owned RunStore reader, and the trusted presentation used to build
it. This adapter invokes the canonical checker, verifies its identities, then
copies only small allowlisted display facts and evidence summaries. It has no
provider, job, target, artifact, defense, recovery, or execution authority.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, cast

from .engine_experiment import EngineExperiment, EngineExperimentError
from .engine_experiment_projection import EngineRunSource
from .engine_experiment_workspace import checked_engine_experiment_workspace
from .util import canonical_json_bytes, content_hash, json_clone


class EngineExperimentAssistanceError(ValueError):
    """Raised when saved Assistant context cannot be bound exactly."""


KIND = "engine_experiment"
_MAX_CONTEXT_BYTES = 64 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_CHECK_ID = re.compile(r"^controller-check-[0-9a-f]{32}$")
_LOCAL_PATH = re.compile(
    r"(?ix)(?:"
    r"(?<![A-Za-z0-9])[a-z]:[\\/]"
    r"|file://"
    r"|\\\\[^\\\s]+\\"
    r"|(?<![A-Za-z0-9/])/(?!/)(?=\S)(?:[^/\s]+/)*[^/\s]*"
    r"|(?:^|\s)(?:\.\.?[\\/]|~[\\/])\S+"
    r")"
)
_SECRET = re.compile(
    r"(?ix)(?:"
    r"-----BEGIN\s+[A-Z0-9 ]*(?:PRIVATE|SECRET)\s+KEY(?:\s+BLOCK)?-----"
    r"|(?:^|[^a-z0-9])(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|"
    r"signing[_-]?key|secret|token|password|passwd|passphrase|private[_-]?key|"
    r"credential|authorization|cookie)(?:[_-][a-z0-9]+)*"
    r"\s*[:=]\s*\S+"
    r"|\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"session[_-]?token|token|password|passwd|client[_-]?secret|secret|"
    r"private[_-]?key|signing[_-]?key|credential|authorization|cookie)"
    r"\b\s*[:=]\s*\S+"
    r"|\b(?:authorization\s*:\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r"|[?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"session[_-]?token|token|password|client[_-]?secret|secret|credential|sig|"
    r"signature|x-amz-signature|x-goog-signature)=[^&\s]+"
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bglpat-[A-Za-z0-9_-]{20,}\b"
    r"|\b(?:hf_|npm_)[A-Za-z0-9]{20,}\b"
    r"|\bpypi-[A-Za-z0-9_-]{20,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    r"|\bsk-[A-Za-z0-9_-]{12,}"
    r")"
)
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|"
    r"password|passwd|passphrase|secret|credential|authorization|cookie|session)"
    r"(?:[_-]|$)"
)

_ALLOWED_CONTEXT_KEYS = frozenset(
    {
        "adaptive_search",
        "after_target_snapshot_ref",
        "analysis_only",
        "application_receipt_ref",
        "assessment",
        "attempt_id",
        "attempts",
        "before_target_snapshot_ref",
        "capabilities",
        "category",
        "change_id",
        "check_id",
        "checks",
        "cleanup",
        "cleanup_state",
        "completeness",
        "conclusion",
        "context_digest",
        "current_target",
        "current_target_snapshot_ref",
        "data_destination",
        "defense",
        "display_name",
        "disposable",
        "engine_id",
        "engine_reported_evidence_count",
        "engine_version",
        "environment",
        "evidence_id",
        "expected_sources",
        "experiment_id",
        "headline",
        "id",
        "independent_observations",
        "items",
        "job_id",
        "kind",
        "legitimate_use",
        "limit_qualified",
        "limitations",
        "live_model_inference_proven",
        "mechanism_ref",
        "missing_sources",
        "model_id",
        "model_provider",
        "objective",
        "observations",
        "original_mechanism",
        "performer",
        "platform",
        "producer",
        "proof_scope",
        "provenance",
        "provider",
        "receipt_ref",
        "reconciliation_receipt_ref",
        "record_hash",
        "reference_summary",
        "retained_reproducer",
        "revision",
        "role",
        "rollback_operation_ref",
        "rollback_receipt_ref",
        "run_id",
        "schema_version",
        "selected",
        "selected_record",
        "state",
        "status",
        "summary",
        "support_refs",
        "telemetry_health",
        "test_provider",
        "timestamp",
        "title",
        "unknowns",
        "verified_sources",
        "workflow_state",
        "workspace_digest",
    }
)

_SELECTION_FIELDS = frozenset(
    {"kind", "experiment_id", "workspace_digest", "attempt_id", "check_id"}
)
_WORKSPACE_FIELDS = frozenset(
    {
        "schema_version",
        "workspace_digest",
        "experiment_id",
        "revision",
        "experiment_digest",
        "objective",
        "environment",
        "current_target",
        "engine_setup",
        "authorization",
        "defensive_change",
        "projection",
        "actions",
        "selected_context",
        "limitations",
    }
)
_PROJECTION_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "revision",
        "experiment_digest",
        "workflow_state",
        "conclusion",
        "attempts",
        "checks",
        "observations",
        "run_integrity",
        "projection_digest",
    }
)
_PROJECTION_ATTEMPT_FIELDS = frozenset(
    {
        "role",
        "attempt_id",
        "job_id",
        "run_id",
        "state",
        "completeness",
        "engine",
        "model",
        "target_snapshot_ref",
        "delegation_digest",
        "execution_approval_id",
        "execution_approval_digest",
        "cleanup",
        "engine_evidence_count",
        "limitations",
    }
)
_PROJECTION_CHECK_FIELDS = frozenset(
    {
        "role",
        "check_id",
        "job_id",
        "run_id",
        "state",
        "performer",
        "mechanism_ref",
        "target_snapshot_ref",
        "input_digest",
        "result_digest",
        "independent_evidence_refs",
        "cleanup",
    }
)
_PROJECTION_OBSERVATION_FIELDS = frozenset(
    {
        "evidence_id",
        "run_id",
        "attempt_id",
        "check_id",
        "mechanism_ref",
        "target_snapshot_ref",
        "assessment",
        "record_hash",
    }
)
_ATTEMPT_DETAIL_FIELDS = frozenset(
    {
        "attempt_id",
        "role",
        "job_id",
        "run_id",
        "upstream_session_id",
        "state",
        "completeness",
        "exit_reason",
        "started_at",
        "finished_at",
        "usage",
        "findings",
        "observations",
        "artifacts",
        "cleanup",
        "resume_supported",
    }
)
_CHECK_DETAIL_FIELDS = frozenset(
    {
        "check_id",
        "role",
        "job_id",
        "run_id",
        "performer",
        "mechanism_ref",
        "target_snapshot_ref",
        "input_digest",
        "result_digest",
        "state",
        "independent_evidence_refs",
        "created_at",
        "settled_at",
        "observations",
        "cleanup",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "evidence_id",
        "attempt_id",
        "category",
        "provenance",
        "summary",
        "producer",
        "timestamp",
        "limitations",
    }
)
_CHECK_OBSERVATION_FIELDS = frozenset(
    {
        "evidence_id",
        "check_id",
        "category",
        "provenance",
        "summary",
        "producer",
        "timestamp",
        "limitations",
    }
)
_FINDING_FIELDS = frozenset(
    {
        "finding_id",
        "attempt_id",
        "title",
        "severity",
        "mechanism_digest",
        "status",
        "summary",
        "source_artifact_id",
        "evidence_ids",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {"artifact_id", "attempt_id", "name", "sha256", "bytes", "media_type", "access"}
)
_CONCLUSION_FIELDS = frozenset(
    {
        "headline",
        "original_mechanism",
        "retained_reproducer",
        "adaptive_search",
        "legitimate_use",
        "telemetry_health",
        "cleanup",
        "defense",
        "unknowns",
    }
)
_RESULT_FIELDS = frozenset({"status", "run_id", "support_refs"})
_ADAPTIVE_RESULT_FIELDS = frozenset({"status", "run_id", "support_refs", "limit_qualified"})
_TELEMETRY_FIELDS = frozenset({"status", "expected_sources", "verified_sources", "missing_sources"})
_CLEANUP_FIELDS = frozenset({"status", "items"})
_CLEANUP_ITEM_FIELDS = frozenset({"kind", "id", "state", "receipt_ref"})
_DEFENSE_FIELDS = frozenset(
    {
        "state",
        "change_id",
        "mechanism_ref",
        "before_target_snapshot_ref",
        "after_target_snapshot_ref",
        "current_target_snapshot_ref",
        "application_receipt_ref",
        "reconciliation_receipt_ref",
        "rollback_operation_ref",
        "rollback_receipt_ref",
    }
)
_HEADLINES = frozenset(
    {
        "inconclusive_original_mechanism",
        "original_mechanism_still_succeeds",
        "inconclusive_retest",
        "original_blocked_legitimate_use_failed",
        "original_blocked_legitimate_use_unknown",
        "original_blocked_alternate_path_found",
        "original_blocked_no_remaining_path_observed_within_limits",
        "original_blocked_adaptive_result_unknown",
    }
)
_SOURCE_ROLES = frozenset({"baseline", "retained_reproducer", "adaptive_search", "legitimate_use"})

_LIMITATIONS = (
    "This context explains one exact saved engine-experiment workspace. It cannot dispatch, approve, cancel, recover, apply or roll back a defense, access a target, or grant authority.",
    "Engine assertions and tool results remain engine-reported material; only separately recorded target observations support security conclusions.",
    "A no-path result is bounded to the recorded routes and limits. It does not establish that the environment is secure.",
    "Saved observations are historical. They do not establish the current state of a mutable target when the current target is unavailable.",
    "Artifact names and bodies, raw tool output, local paths, credentials, and provider secrets are not included.",
)


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineExperimentAssistanceError(f"{label} fields changed")
    return value


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or _LOCAL_PATH.search(value)
        or _SECRET.search(value)
    ):
        raise EngineExperimentAssistanceError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineExperimentAssistanceError(f"{label} is invalid")
    return value


def _strings(value: Any, label: str, *, maximum: int = 32) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise EngineExperimentAssistanceError(f"{label} is invalid")
    result = [_text(item, f"{label} item", maximum=500) for item in value]
    if len(set(result)) != len(result):
        raise EngineExperimentAssistanceError(f"{label} contains duplicates")
    return result


def _optional_text(value: Any, label: str, *, maximum: int = 200) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum=maximum)


def _optional_digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _digest(value, label)


def _conclusion_result(
    value: Any,
    label: str,
    statuses: frozenset[str],
    *,
    adaptive: bool = False,
) -> dict[str, Any]:
    row = _exact(
        value,
        _ADAPTIVE_RESULT_FIELDS if adaptive else _RESULT_FIELDS,
        label,
    )
    status = row["status"]
    if status not in statuses:
        raise EngineExperimentAssistanceError(f"{label} status changed")
    result: dict[str, Any] = {
        "status": status,
        "run_id": _optional_text(row["run_id"], f"{label} run identity"),
        "support_refs": _strings(row["support_refs"], f"{label} support references", maximum=256),
    }
    if adaptive:
        if not isinstance(row["limit_qualified"], bool):
            raise EngineExperimentAssistanceError(f"{label} qualification changed")
        result["limit_qualified"] = row["limit_qualified"]
    return result


def _conclusion_telemetry(value: Any) -> dict[str, Any]:
    row = _exact(value, _TELEMETRY_FIELDS, "conclusion telemetry")
    status = row["status"]
    if status not in {"not_started", "complete", "partial", "unavailable"}:
        raise EngineExperimentAssistanceError("conclusion telemetry status changed")
    sources = {
        name: _strings(row[name], f"conclusion telemetry {name}", maximum=4)
        for name in ("expected_sources", "verified_sources", "missing_sources")
    }
    expected = set(sources["expected_sources"])
    verified = set(sources["verified_sources"])
    missing = set(sources["missing_sources"])
    if (
        not expected <= _SOURCE_ROLES
        or not verified <= expected
        or not missing <= expected
        or verified & missing
        or verified | missing != expected
    ):
        raise EngineExperimentAssistanceError("conclusion telemetry sources changed")
    return {"status": status, **sources}


def _conclusion_cleanup(value: Any) -> dict[str, Any]:
    row = _exact(value, _CLEANUP_FIELDS, "conclusion cleanup")
    status = row["status"]
    cleanup_states = {"pending", "verified_absent", "residue", "unknown"}
    if status not in cleanup_states | {"not_started"}:
        raise EngineExperimentAssistanceError("conclusion cleanup status changed")
    raw_items = row["items"]
    if not isinstance(raw_items, list) or len(raw_items) > 256:
        raise EngineExperimentAssistanceError("conclusion cleanup items changed")
    items: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for value_item in raw_items:
        item = _exact(value_item, _CLEANUP_ITEM_FIELDS, "conclusion cleanup item")
        kind = item["kind"]
        identity = _text(item["id"], "conclusion cleanup identity", maximum=80)
        state = item["state"]
        if kind not in {"engine_attempt", "controller_check"} or state not in cleanup_states:
            raise EngineExperimentAssistanceError("conclusion cleanup item changed")
        pair = (cast(str, kind), identity)
        if pair in identities:
            raise EngineExperimentAssistanceError("conclusion cleanup item is repeated")
        identities.add(pair)
        items.append(
            {
                "kind": kind,
                "id": identity,
                "state": state,
                "receipt_ref": _optional_digest(item["receipt_ref"], "conclusion cleanup receipt"),
            }
        )
    return {"status": status, "items": items}


def _conclusion_defense(value: Any) -> dict[str, Any]:
    row = _exact(value, _DEFENSE_FIELDS, "conclusion defense")
    state = row["state"]
    if state not in {
        "not_reviewed",
        "reviewed",
        "applied",
        "retained",
        "rolled_back",
        "unknown",
    }:
        raise EngineExperimentAssistanceError("conclusion defense state changed")
    return {
        "state": state,
        "change_id": _optional_text(
            row["change_id"], "conclusion defense change identity", maximum=80
        ),
        "mechanism_ref": _optional_digest(row["mechanism_ref"], "conclusion defense mechanism"),
        "before_target_snapshot_ref": _optional_digest(
            row["before_target_snapshot_ref"], "conclusion defense before target"
        ),
        "after_target_snapshot_ref": _optional_digest(
            row["after_target_snapshot_ref"], "conclusion defense after target"
        ),
        "current_target_snapshot_ref": _optional_digest(
            row["current_target_snapshot_ref"], "conclusion defense current target"
        ),
        "application_receipt_ref": _optional_digest(
            row["application_receipt_ref"], "conclusion defense application receipt"
        ),
        "reconciliation_receipt_ref": _optional_digest(
            row["reconciliation_receipt_ref"],
            "conclusion defense reconciliation receipt",
        ),
        "rollback_operation_ref": _optional_digest(
            row["rollback_operation_ref"], "conclusion defense rollback operation"
        ),
        "rollback_receipt_ref": _optional_digest(
            row["rollback_receipt_ref"], "conclusion defense rollback receipt"
        ),
    }


def _validated_conclusion(value: Any) -> dict[str, Any]:
    row = _exact(value, _CONCLUSION_FIELDS, "engine experiment conclusion")
    headline = row["headline"]
    if headline not in _HEADLINES:
        raise EngineExperimentAssistanceError("engine experiment conclusion changed")
    return {
        "headline": headline,
        "original_mechanism": _conclusion_result(
            row["original_mechanism"],
            "original mechanism conclusion",
            frozenset({"not_attempted", "established", "not_established", "unknown"}),
        ),
        "retained_reproducer": _conclusion_result(
            row["retained_reproducer"],
            "retained reproducer conclusion",
            frozenset(
                {
                    "not_attempted",
                    "still_succeeds",
                    "blocked",
                    "not_established",
                    "unknown",
                }
            ),
        ),
        "adaptive_search": _conclusion_result(
            row["adaptive_search"],
            "adaptive search conclusion",
            frozenset(
                {
                    "not_attempted",
                    "remaining_path_found",
                    "no_path_observed_within_limits",
                    "inconclusive",
                    "pending",
                }
            ),
            adaptive=True,
        ),
        "legitimate_use": _conclusion_result(
            row["legitimate_use"],
            "legitimate use conclusion",
            frozenset({"not_attempted", "failed", "passed", "unknown"}),
        ),
        "telemetry_health": _conclusion_telemetry(row["telemetry_health"]),
        "cleanup": _conclusion_cleanup(row["cleanup"]),
        "defense": _conclusion_defense(row["defense"]),
        "unknowns": _strings(row["unknowns"], "conclusion unknowns"),
    }


def _validate_public_tree(value: Any, *, depth: int = 0) -> None:
    if depth > 12:
        raise EngineExperimentAssistanceError("Assistant context is too deeply nested")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        _text(value, "Assistant context text", maximum=2_000)
        return
    if isinstance(value, list):
        if len(value) > 512:
            raise EngineExperimentAssistanceError("Assistant context list is too large")
        for item in value:
            _validate_public_tree(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise EngineExperimentAssistanceError("Assistant context object is too large")
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or key not in _ALLOWED_CONTEXT_KEYS
                or _SENSITIVE_KEY.search(key) is not None
            ):
                raise EngineExperimentAssistanceError("Assistant context key is invalid")
            _validate_public_tree(item, depth=depth + 1)
        return
    raise EngineExperimentAssistanceError("Assistant context contains an unsupported value")


def _selection(value: Mapping[str, Any]) -> dict[str, Any]:
    row = _exact(value, _SELECTION_FIELDS, "engine Assistant selection")
    experiment_id = row["experiment_id"]
    attempt_id = row["attempt_id"]
    check_id = row["check_id"]
    if (
        row["kind"] != KIND
        or not isinstance(experiment_id, str)
        or _EXPERIMENT_ID.fullmatch(experiment_id) is None
        or not isinstance(row["workspace_digest"], str)
        or _DIGEST.fullmatch(row["workspace_digest"]) is None
        or (
            attempt_id is not None
            and (not isinstance(attempt_id, str) or _ATTEMPT_ID.fullmatch(attempt_id) is None)
        )
        or (
            check_id is not None
            and (not isinstance(check_id, str) or _CHECK_ID.fullmatch(check_id) is None)
        )
        or (attempt_id is not None and check_id is not None)
    ):
        raise EngineExperimentAssistanceError("engine Assistant selection is invalid")
    return dict(cast(dict[str, Any], json_clone(row)))


def engine_experiment_assistance_selection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and detach the exact saved engine-experiment selection."""

    return _selection(value)


def _validate_workspace(
    experiment: EngineExperiment,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(experiment, EngineExperiment):
        raise EngineExperimentAssistanceError(
            "engine Assistant context requires controller-rehydrated state"
        )
    try:
        experiment.validate()
    except EngineExperimentError as exc:
        raise EngineExperimentAssistanceError("engine experiment is invalid") from exc
    row = _exact(value, _WORKSPACE_FIELDS, "engine experiment workspace")
    if row["schema_version"] != "bluefire.engine-experiment-workspace.v1":
        raise EngineExperimentAssistanceError("engine workspace version is unsupported")
    if (
        row["experiment_id"] != experiment.experiment_id
        or row["revision"] != experiment.revision
        or row["experiment_digest"] != experiment.digest
    ):
        raise EngineExperimentAssistanceError("engine workspace identity changed")
    claimed = _digest(row["workspace_digest"], "workspace digest")
    body = dict(cast(dict[str, Any], json_clone(row)))
    body.pop("workspace_digest")
    if claimed != content_hash(body):
        raise EngineExperimentAssistanceError("engine workspace digest changed")

    objective = _exact(
        row["objective"], frozenset({"objective_ref", "title", "summary"}), "objective"
    )
    if objective["objective_ref"] != experiment.objective_ref:
        raise EngineExperimentAssistanceError("objective identity changed")
    _text(objective["title"], "objective title", maximum=200)
    _text(objective["summary"], "objective summary", maximum=1000)
    environment = _exact(
        row["environment"],
        frozenset({"environment_ref", "environment_id", "display_name", "platform", "disposable"}),
        "environment",
    )
    if (
        environment["environment_ref"] != experiment.environment_ref
        or environment["disposable"] is not True
        or environment["platform"] not in {"linux", "windows", "macos"}
    ):
        raise EngineExperimentAssistanceError("engine environment changed")
    _text(environment["display_name"], "environment name", maximum=200)

    projection = _exact(row["projection"], _PROJECTION_FIELDS, "engine projection")
    if projection["schema_version"] != "bluefire.engine-experiment-projection.v1":
        raise EngineExperimentAssistanceError("engine projection version is unsupported")
    if (
        projection["experiment_id"] != experiment.experiment_id
        or projection["revision"] != experiment.revision
        or projection["experiment_digest"] != experiment.digest
    ):
        raise EngineExperimentAssistanceError("engine projection identity changed")
    projection_body = dict(cast(dict[str, Any], json_clone(projection)))
    projection_claimed = _digest(
        projection_body.pop("projection_digest", None), "projection digest"
    )
    if projection_claimed != content_hash(projection_body):
        raise EngineExperimentAssistanceError("engine projection digest changed")

    attempts = projection["attempts"]
    if not isinstance(attempts, list) or len(attempts) != len(experiment.attempts):
        raise EngineExperimentAssistanceError("projected attempts changed")
    for projected, saved_attempt in zip(attempts, experiment.attempts, strict=True):
        attempt = _exact(projected, _PROJECTION_ATTEMPT_FIELDS, "projected attempt")
        binding = saved_attempt.record.binding
        if (
            attempt["attempt_id"] != binding.attempt_id
            or attempt["role"] != binding.role.value
            or attempt["job_id"] != saved_attempt.job_id
            or attempt["run_id"] != binding.run_id
            or attempt["state"] != saved_attempt.record.state.value
            or attempt["completeness"] != saved_attempt.record.completeness.value
            or attempt["execution_approval_id"] != saved_attempt.execution_approval_id
            or attempt["execution_approval_digest"] != saved_attempt.execution_approval_digest
            or attempt["delegation_digest"] != saved_attempt.delegation_digest
            or attempt["engine_evidence_count"] != len(saved_attempt.evidence)
        ):
            raise EngineExperimentAssistanceError("projected attempt identity changed")

    checks = projection["checks"]
    if not isinstance(checks, list) or len(checks) != len(experiment.checks):
        raise EngineExperimentAssistanceError("projected checks changed")
    for projected, saved_check in zip(checks, experiment.checks, strict=True):
        check = _exact(projected, _PROJECTION_CHECK_FIELDS, "projected check")
        if (
            check["check_id"] != saved_check.check_id
            or check["role"] != saved_check.role.value
            or check["job_id"] != saved_check.job_id
            or check["run_id"] != saved_check.run_id
            or check["state"] != saved_check.state.value
            or check["performer"] != saved_check.performer.value
            or check["mechanism_ref"] != saved_check.mechanism_ref
            or check["target_snapshot_ref"] != saved_check.target_snapshot_ref
            or check["input_digest"] != saved_check.input_digest
            or check["result_digest"] != saved_check.result_digest
            or check["independent_evidence_refs"] != list(saved_check.independent_evidence_refs)
        ):
            raise EngineExperimentAssistanceError("projected check identity changed")

    saved_observations = {item.evidence_id: item for item in experiment.independent_observations}
    observations = projection["observations"]
    if not isinstance(observations, list) or len(observations) > 256:
        raise EngineExperimentAssistanceError("projected observations changed")
    for projected in observations:
        observation = _exact(projected, _PROJECTION_OBSERVATION_FIELDS, "projected observation")
        saved_observation = saved_observations.get(cast(str, observation["evidence_id"]))
        if saved_observation is None or dict(cast(dict[str, Any], json_clone(observation))) != {
            "evidence_id": saved_observation.evidence_id,
            "run_id": saved_observation.evidence.run_id,
            "attempt_id": saved_observation.attempt_id,
            "check_id": saved_observation.check_id,
            "mechanism_ref": saved_observation.mechanism_ref,
            "target_snapshot_ref": saved_observation.target_snapshot_ref,
            "assessment": saved_observation.assessment,
            "record_hash": saved_observation.evidence.record_hash,
        }:
            raise EngineExperimentAssistanceError("projected observation changed")

    _strings(row["limitations"], "workspace limitations")
    return dict(cast(dict[str, Any], json_clone(row)))


def _selected_summary(
    workspace: Mapping[str, Any], selection: Mapping[str, Any]
) -> dict[str, Any] | None:
    selected = workspace["selected_context"]
    attempt_id = selection["attempt_id"]
    check_id = selection["check_id"]
    if attempt_id is None and check_id is None:
        if selected is not None:
            raise EngineExperimentAssistanceError("engine selection changed")
        return None
    if not isinstance(selected, Mapping) or set(selected) != (
        {"kind", "attempt"} if attempt_id is not None else {"kind", "check"}
    ):
        raise EngineExperimentAssistanceError("selected engine context changed")

    if attempt_id is not None:
        if selected["kind"] != "engine_attempt":
            raise EngineExperimentAssistanceError("selected attempt context changed")
        detail = _exact(selected["attempt"], _ATTEMPT_DETAIL_FIELDS, "selected attempt")
        if detail["attempt_id"] != attempt_id:
            raise EngineExperimentAssistanceError("selected attempt identity changed")
        observations = _selected_observations(
            detail["observations"], attempt_id=attempt_id, check_id=None
        )
        findings = detail["findings"]
        artifacts = detail["artifacts"]
        if not isinstance(findings, list) or not isinstance(artifacts, list):
            raise EngineExperimentAssistanceError("selected attempt details changed")
        if len(findings) > 256 or len(artifacts) > 256:
            raise EngineExperimentAssistanceError("selected attempt details are too large")
        for item in findings:
            finding = _exact(item, _FINDING_FIELDS, "selected finding")
            if finding["attempt_id"] != attempt_id:
                raise EngineExperimentAssistanceError("selected finding owner changed")
            _text(finding["title"], "finding title", maximum=200)
            _text(finding["summary"], "finding summary", maximum=1000)
            _digest(finding["mechanism_digest"], "finding mechanism")
            if not isinstance(finding["evidence_ids"], list):
                raise EngineExperimentAssistanceError("selected finding evidence changed")
        for item in artifacts:
            artifact = _exact(item, _ARTIFACT_FIELDS, "selected artifact")
            name = _text(artifact["name"], "artifact name", maximum=240)
            if (
                artifact["attempt_id"] != attempt_id
                or "/" in name
                or "\\" in name
                or name in {".", ".."}
                or isinstance(artifact["bytes"], bool)
                or not isinstance(artifact["bytes"], int)
                or not 0 <= artifact["bytes"] <= 64 * 1024 * 1024
                or artifact["access"] not in {"private", "reviewable"}
            ):
                raise EngineExperimentAssistanceError("selected artifact changed")
            _digest(artifact["sha256"], "artifact digest")
            _text(artifact["media_type"], "artifact media type", maximum=100)
        return {
            "kind": "engine_attempt",
            "id": attempt_id,
            "role": detail["role"],
            "job_id": detail["job_id"],
            "run_id": detail["run_id"],
            "state": detail["state"],
            "completeness": detail["completeness"],
            "observations": observations,
            "cleanup": _cleanup_summary(detail["cleanup"]),
        }

    if selected["kind"] != "controller_check":
        raise EngineExperimentAssistanceError("selected check context changed")
    detail = _exact(selected["check"], _CHECK_DETAIL_FIELDS, "selected check")
    if detail["check_id"] != check_id:
        raise EngineExperimentAssistanceError("selected check identity changed")
    return {
        "kind": "controller_check",
        "id": check_id,
        "role": detail["role"],
        "job_id": detail["job_id"],
        "run_id": detail["run_id"],
        "state": detail["state"],
        "performer": detail["performer"],
        "observations": _selected_observations(
            detail["observations"], attempt_id=None, check_id=cast(str, check_id)
        ),
        "cleanup": _cleanup_summary(detail["cleanup"]),
    }


def _cleanup_summary(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        frozenset({"state", "receipt_ref", "finished_at", "limitations"}),
        "selected cleanup",
    )
    return {
        "state": row["state"],
        "receipt_ref": row["receipt_ref"],
        "limitations": _strings(row["limitations"], "cleanup limitations", maximum=16),
    }


def _selected_observations(
    value: Any,
    *,
    attempt_id: str | None,
    check_id: str | None,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 256:
        raise EngineExperimentAssistanceError("selected observations changed")
    result: list[dict[str, Any]] = []
    for item in value:
        fields = _OBSERVATION_FIELDS if attempt_id is not None else _CHECK_OBSERVATION_FIELDS
        row = _exact(item, fields, "selected observation")
        owner_key = "attempt_id" if attempt_id is not None else "check_id"
        owner = attempt_id if attempt_id is not None else check_id
        if row[owner_key] != owner:
            raise EngineExperimentAssistanceError("selected observation owner changed")
        category = row["category"]
        provenance = row["provenance"]
        if (
            (category == "engine_assertion" and provenance != "engine_reported")
            or (category == "tool_result" and provenance != "runner_reported")
            or (
                category not in {"engine_assertion", "tool_result"}
                and provenance not in {"observed", "control_blocked"}
            )
        ):
            raise EngineExperimentAssistanceError("selected observation provenance changed")
        result.append(
            {
                "evidence_id": row["evidence_id"],
                "category": category,
                "provenance": provenance,
                "summary": _text(row["summary"], "evidence summary", maximum=1000),
                "producer": _text(row["producer"], "evidence producer", maximum=200),
                "timestamp": row["timestamp"],
                "limitations": _strings(row["limitations"], "evidence limitations", maximum=16),
            }
        )
    return result


def _reference_summary(
    workspace: Mapping[str, Any], selection: Mapping[str, Any]
) -> dict[str, Any]:
    objective = cast(Mapping[str, Any], workspace["objective"])
    environment = cast(Mapping[str, Any], workspace["environment"])
    setup = cast(Mapping[str, Any], workspace["engine_setup"])
    engine = cast(Mapping[str, Any], setup["engine"])
    model = cast(Mapping[str, Any], setup["model"])
    projection = cast(Mapping[str, Any], workspace["projection"])
    attempts = cast(list[Mapping[str, Any]], projection["attempts"])
    checks = cast(list[Mapping[str, Any]], projection["checks"])
    observations = cast(list[Mapping[str, Any]], projection["observations"])
    current_target = workspace["current_target"]
    if current_target is not None:
        _exact(
            current_target,
            frozenset({"snapshot_ref", "display_name", "captured_at"}),
            "current target",
        )
    if not isinstance(model.get("test_provider"), bool):
        raise EngineExperimentAssistanceError("model provider classification changed")

    return {
        "schema_version": "bluefire.engine-experiment-assistance-summary.v1",
        "proof_scope": "saved_engine_experiment_only",
        "experiment_id": workspace["experiment_id"],
        "revision": workspace["revision"],
        "workspace_digest": workspace["workspace_digest"],
        "workflow_state": projection["workflow_state"],
        "objective": {
            "title": _text(objective["title"], "objective title", maximum=200),
            "summary": _text(objective["summary"], "objective summary", maximum=1000),
        },
        "environment": {
            "display_name": _text(environment["display_name"], "environment name", maximum=200),
            "platform": environment["platform"],
            "disposable": True,
            "current_target": "unknown" if current_target is None else "established",
        },
        "provider": {
            "engine_id": engine["id"],
            "engine_version": engine["version"],
            "model_provider": model["provider"],
            "model_id": model["id"],
            "data_destination": model["data_destination"],
            "test_provider": model["test_provider"],
            "live_model_inference_proven": False,
        },
        "attempts": [
            {
                "role": item["role"],
                "attempt_id": item["attempt_id"],
                "run_id": item["run_id"],
                "state": item["state"],
                "completeness": item["completeness"],
                "engine_reported_evidence_count": item["engine_evidence_count"],
                "cleanup_state": cast(Mapping[str, Any], item["cleanup"])["state"],
            }
            for item in attempts
        ],
        "checks": [
            {
                "role": item["role"],
                "check_id": item["check_id"],
                "run_id": item["run_id"],
                "state": item["state"],
                "performer": item["performer"],
                "cleanup_state": cast(Mapping[str, Any], item["cleanup"])["state"],
            }
            for item in checks
        ],
        "independent_observations": [
            {
                "evidence_id": item["evidence_id"],
                "run_id": item["run_id"],
                "attempt_id": item["attempt_id"],
                "check_id": item["check_id"],
                "assessment": item["assessment"],
                "record_hash": item["record_hash"],
            }
            for item in observations
        ],
        "conclusion": _validated_conclusion(projection["conclusion"]),
        "selected_record": _selected_summary(workspace, selection),
    }


def engine_experiment_assistance_context(
    experiment: EngineExperiment,
    workspace: Mapping[str, Any],
    selection: Mapping[str, Any],
    *,
    run_source: EngineRunSource,
    presentation: Mapping[str, Any],
) -> dict[str, Any]:
    """Capture one immutable, analysis-only context from canonical sources."""
    try:
        checked_selection = _selection(selection)
        if checked_selection["experiment_id"] != experiment.experiment_id:
            raise EngineExperimentAssistanceError("engine Assistant selection changed")
        checked_workspace = _validate_workspace(experiment, workspace)
        canonical_workspace = checked_engine_experiment_workspace(
            checked_workspace,
            experiment,
            run_source,
            presentation,
        )
        if canonical_json_bytes(canonical_workspace) != canonical_json_bytes(checked_workspace):
            raise EngineExperimentAssistanceError(
                "engine Assistant workspace differs from its canonical presenter"
            )
        if checked_selection["workspace_digest"] != checked_workspace["workspace_digest"]:
            raise EngineExperimentAssistanceError("engine Assistant selection changed")
        summary = _reference_summary(checked_workspace, checked_selection)
        limitations = list(_LIMITATIONS)
        limitations.extend(_strings(checked_workspace["limitations"], "workspace limitations"))
        if cast(Mapping[str, Any], summary["provider"])["test_provider"]:
            limitations.append(
                "Labeled test-provider responses establish application mechanics only, not live-model decision quality."
            )
        unique_limitations = list(dict.fromkeys(limitations))
        if len(unique_limitations) > 40:
            raise EngineExperimentAssistanceError("Assistant limitations exceed their bound")
        document = {
            "schema_version": "bluefire.assistance-context.v1",
            "selected": checked_selection,
            "analysis_only": True,
            "capabilities": [],
            "reference_summary": summary,
            "limitations": unique_limitations,
        }
        result = {**document, "context_digest": content_hash(document)}
        _validate_public_tree(result)
        if len(canonical_json_bytes(result)) > _MAX_CONTEXT_BYTES:
            raise EngineExperimentAssistanceError("engine Assistant context exceeds its bound")
        return result
    except EngineExperimentAssistanceError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise EngineExperimentAssistanceError(
            "engine Assistant context is unavailable or changed"
        ) from exc


__all__ = [
    "EngineExperimentAssistanceError",
    "engine_experiment_assistance_context",
    "engine_experiment_assistance_selection",
]
