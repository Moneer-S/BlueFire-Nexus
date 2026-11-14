"""Pure validation for controller-owned engine experiment presentation records.

Persistence and the workspace presenter use this same contract to reject stale
identities and private material. These checks perform no reads, writes, dispatch,
or projection and confer no engine or target authority.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, cast

from .engine_experiment import EngineExperiment
from .util import json_clone, parse_iso8601_datetime


class EngineExperimentWorkspaceError(ValueError):
    """Raised when a workspace would differ from canonical controller state."""


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_TIMESTAMP = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?Z$")
_LOCAL_PATH = re.compile(
    r"(?i)(?:(?<![A-Za-z0-9])[a-z]:[\\/]|file://|\\\\[^\\\s]+\\|"
    r"(?:^|\s)/(?:home|users|tmp|root|private)/)"
)
_SECRET = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\s*[:=]|"
    r"authorization\s*:\s*bearer\s+|\bsk-[A-Za-z0-9_-]{12,})"
)


_PRESENTATION_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "revision",
        "experiment_digest",
        "objective",
        "environment",
        "current_target",
        "engine_setup",
        "authorization",
        "defensive_change",
        "selection",
        "limitations",
    }
)


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineExperimentWorkspaceError(f"{label} fields changed")
    return value


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineExperimentWorkspaceError(f"{label} is invalid")
    return value


def _public_text(value: Any, label: str, *, maximum: int = 512) -> str:
    result = _text(value, label, maximum=maximum)
    if _LOCAL_PATH.search(result) or _SECRET.search(result):
        raise EngineExperimentWorkspaceError(f"{label} contains private material")
    return result


def _digest(value: Any, label: str) -> str:
    result = _text(value, label, maximum=71)
    if _DIGEST.fullmatch(result) is None:
        raise EngineExperimentWorkspaceError(f"{label} is invalid")
    return result


def _timestamp(value: Any, label: str) -> str:
    result = _text(value, label, maximum=40)
    if _TIMESTAMP.fullmatch(result) is None:
        raise EngineExperimentWorkspaceError(f"{label} is invalid")
    try:
        parse_iso8601_datetime(result)
    except ValueError as exc:
        raise EngineExperimentWorkspaceError(f"{label} is invalid") from exc
    return result


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EngineExperimentWorkspaceError(f"{label} is invalid")
    return cast(int, value)


def _strings(
    value: Any,
    label: str,
    *,
    maximum: int = 32,
    item_maximum: int = 500,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise EngineExperimentWorkspaceError(f"{label} is invalid")
    result = [_public_text(item, f"{label} item", maximum=item_maximum) for item in value]
    if len(set(result)) != len(result):
        raise EngineExperimentWorkspaceError(f"{label} contains duplicates")
    return result


def _checked_presentation(value: Mapping[str, Any], experiment: EngineExperiment) -> dict[str, Any]:
    row = _exact(value, _PRESENTATION_FIELDS, "engine workspace presentation")
    if row["schema_version"] != "bluefire.engine-experiment-presentation.v1":
        raise EngineExperimentWorkspaceError("engine workspace presentation is unsupported")
    if (
        row["experiment_id"] != experiment.experiment_id
        or row["revision"] != experiment.revision
        or row["experiment_digest"] != experiment.digest
    ):
        raise EngineExperimentWorkspaceError("engine workspace presentation identity changed")

    objective = _exact(
        row["objective"], frozenset({"objective_ref", "title", "summary"}), "objective"
    )
    checked_objective = {
        "objective_ref": _digest(objective["objective_ref"], "objective reference"),
        "title": _public_text(objective["title"], "objective title", maximum=200),
        "summary": _public_text(objective["summary"], "objective summary", maximum=1000),
    }
    if checked_objective["objective_ref"] != experiment.objective_ref:
        raise EngineExperimentWorkspaceError("objective reference changed")

    environment = _exact(
        row["environment"],
        frozenset({"environment_ref", "environment_id", "display_name", "platform", "disposable"}),
        "environment",
    )
    platform = environment["platform"]
    if platform not in {"linux", "windows", "macos"} or environment["disposable"] is not True:
        raise EngineExperimentWorkspaceError("external engine environment is invalid")
    checked_environment = {
        "environment_ref": _digest(environment["environment_ref"], "environment reference"),
        "environment_id": _public_text(
            environment["environment_id"], "environment identity", maximum=180
        ),
        "display_name": _public_text(
            environment["display_name"], "environment display name", maximum=200
        ),
        "platform": platform,
        "disposable": True,
    }
    if checked_environment["environment_ref"] != experiment.environment_ref:
        raise EngineExperimentWorkspaceError("environment reference changed")

    checked_target: dict[str, Any] | None
    if experiment.current_target_snapshot_ref is None:
        if row["current_target"] is not None:
            raise EngineExperimentWorkspaceError("unknown current target was fabricated")
        checked_target = None
    else:
        target = _exact(
            row["current_target"],
            frozenset({"snapshot_ref", "display_name", "captured_at"}),
            "current target",
        )
        checked_target = {
            "snapshot_ref": _digest(target["snapshot_ref"], "current target snapshot"),
            "display_name": _public_text(
                target["display_name"], "current target display name", maximum=200
            ),
            "captured_at": _timestamp(target["captured_at"], "current target capture time"),
        }
        if checked_target["snapshot_ref"] != experiment.current_target_snapshot_ref:
            raise EngineExperimentWorkspaceError("current target snapshot changed")
        captured = parse_iso8601_datetime(cast(str, checked_target["captured_at"]))
        updated = parse_iso8601_datetime(experiment.updated_at)
        initial_snapshot = checked_target["snapshot_ref"] == experiment.initial_target_snapshot_ref
        if captured > updated or (
            not initial_snapshot and captured < parse_iso8601_datetime(experiment.created_at)
        ):
            raise EngineExperimentWorkspaceError("current target capture time changed")

    setup = _exact(row["engine_setup"], frozenset({"engine", "model"}), "engine setup")
    engine = _exact(
        setup["engine"],
        frozenset(
            {
                "id",
                "display_name",
                "version",
                "revision",
                "package_digest",
                "sandbox_image_digest",
            }
        ),
        "engine setup identity",
    )
    model = _exact(
        setup["model"],
        frozenset(
            {
                "provider",
                "id",
                "data_destination",
                "authorization_digest",
                "test_provider",
            }
        ),
        "model setup identity",
    )
    engine_id = _public_text(engine["id"], "engine identity", maximum=80)
    revision = _text(engine["revision"], "engine revision", maximum=40)
    provider = _public_text(model["provider"], "model provider", maximum=80)
    if engine_id != "strix" or _REVISION.fullmatch(revision) is None:
        raise EngineExperimentWorkspaceError("engine setup identity is invalid")
    if _SOURCE_ID.fullmatch(provider) is None or not isinstance(model["test_provider"], bool):
        raise EngineExperimentWorkspaceError("model setup identity is invalid")
    checked_setup: dict[str, Any] = {
        "engine": {
            "id": engine_id,
            "display_name": _public_text(
                engine["display_name"], "engine display name", maximum=100
            ),
            "version": _public_text(engine["version"], "engine version", maximum=80),
            "revision": revision,
            "package_digest": _digest(engine["package_digest"], "engine package"),
            "sandbox_image_digest": _digest(engine["sandbox_image_digest"], "engine sandbox image"),
        },
        "model": {
            "provider": provider,
            "id": _public_text(model["id"], "model identity", maximum=160),
            "data_destination": _public_text(
                model["data_destination"], "model data destination", maximum=200
            ),
            "authorization_digest": _digest(model["authorization_digest"], "model authorization"),
            "test_provider": model["test_provider"],
        },
    }

    authorization = _exact(
        row["authorization"],
        frozenset(
            {
                "scope_ref",
                "scope_version",
                "wall_clock_seconds",
                "action_limit",
                "artifact_byte_limit",
                "cost_limit_microunits",
            }
        ),
        "engine authorization",
    )
    checked_authorization: dict[str, Any] = {
        "scope_ref": _digest(authorization["scope_ref"], "authorization scope"),
        "scope_version": _text(
            authorization["scope_version"], "authorization scope version", maximum=80
        ),
        "wall_clock_seconds": _integer(
            authorization["wall_clock_seconds"],
            "wall clock limit",
            minimum=1,
            maximum=7_200,
        ),
        "action_limit": _integer(
            authorization["action_limit"], "action limit", minimum=1, maximum=512
        ),
        "artifact_byte_limit": _integer(
            authorization["artifact_byte_limit"],
            "artifact byte limit",
            minimum=1,
            maximum=64 * 1024 * 1024,
        ),
        "cost_limit_microunits": _integer(
            authorization["cost_limit_microunits"],
            "cost limit",
            minimum=0,
            maximum=10_000_000_000,
        ),
    }
    if (
        checked_authorization["scope_ref"] != experiment.scope_ref
        or checked_authorization["scope_version"] != experiment.scope_version
    ):
        raise EngineExperimentWorkspaceError("authorization scope changed")

    for entry in experiment.attempts:
        binding = entry.record.binding
        expected_engine = {
            "id": binding.engine_id,
            "version": binding.engine_version,
            "revision": binding.engine_revision,
            "package_digest": binding.engine_package_digest,
        }
        checked_engine = cast(Mapping[str, Any], checked_setup["engine"])
        checked_model = cast(Mapping[str, Any], checked_setup["model"])
        visible_engine = {
            key: checked_engine[key] for key in ("id", "version", "revision", "package_digest")
        }
        expected_model = {
            "provider": binding.model_provider,
            "id": binding.model_id,
            "data_destination": binding.model_data_destination,
            "authorization_digest": binding.model_authorization_ref,
        }
        visible_model = {
            key: checked_model[key]
            for key in ("provider", "id", "data_destination", "authorization_digest")
        }
        expected_limits = {
            "wall_clock_seconds": binding.wall_clock_seconds,
            "action_limit": binding.action_limit,
            "artifact_byte_limit": binding.artifact_byte_limit,
            "cost_limit_microunits": binding.cost_limit_microunits,
        }
        visible_limits = {
            key: checked_authorization[key]
            for key in (
                "wall_clock_seconds",
                "action_limit",
                "artifact_byte_limit",
                "cost_limit_microunits",
            )
        }
        if (
            visible_engine != expected_engine
            or visible_model != expected_model
            or visible_limits != expected_limits
        ):
            raise EngineExperimentWorkspaceError("engine attempt setup changed")

    checked_defense = _checked_defense(row["defensive_change"], experiment)
    checked_selection = _checked_selection(row["selection"], experiment)
    limitations = _strings(row["limitations"], "workspace limitations")
    return {
        "objective": checked_objective,
        "environment": checked_environment,
        "current_target": checked_target,
        "engine_setup": checked_setup,
        "authorization": checked_authorization,
        "defensive_change": checked_defense,
        "selection": checked_selection,
        "limitations": limitations,
    }


def _checked_defense(value: Any, experiment: EngineExperiment) -> dict[str, Any] | None:
    change = experiment.defense_change
    if change is None:
        if value is not None:
            raise EngineExperimentWorkspaceError("defensive change was fabricated")
        return None
    row = _exact(
        value,
        frozenset(
            {
                "change_id",
                "state",
                "kind",
                "summary",
                "mechanism_ref",
                "before_target_snapshot_ref",
                "after_target_snapshot_ref",
                "rollback_digest",
                "applied_at",
            }
        ),
        "defensive change presentation",
    )
    if row["kind"] not in {
        "configuration",
        "permission",
        "identity",
        "prevention",
        "visibility",
        "detection",
    }:
        raise EngineExperimentWorkspaceError("defensive change kind is invalid")
    applied_at = (
        None
        if row["applied_at"] is None
        else _timestamp(row["applied_at"], "defensive change application time")
    )
    result = {
        "change_id": row["change_id"],
        "state": row["state"],
        "kind": row["kind"],
        "summary": _public_text(row["summary"], "defensive change summary", maximum=1000),
        "mechanism_ref": _digest(row["mechanism_ref"], "defensive mechanism"),
        "before_target_snapshot_ref": _digest(
            row["before_target_snapshot_ref"], "defensive change preimage"
        ),
        "after_target_snapshot_ref": _digest(
            row["after_target_snapshot_ref"], "defensive change result"
        ),
        "rollback_digest": _digest(row["rollback_digest"], "defensive rollback"),
        "applied_at": applied_at,
    }
    expected = {
        "change_id": change.change_id,
        "state": change.state.value,
        "mechanism_ref": change.mechanism_ref,
        "before_target_snapshot_ref": change.before_target_snapshot_ref,
        "after_target_snapshot_ref": change.after_target_snapshot_ref,
        "rollback_digest": change.rollback_digest,
        "applied_at": change.applied_at,
    }
    if any(result[key] != expected[key] for key in expected):
        raise EngineExperimentWorkspaceError("defensive change presentation changed")
    return result


def _checked_selection(value: Any, experiment: EngineExperiment) -> dict[str, Any] | None:
    if value is None:
        return None
    row = _exact(
        value,
        frozenset({"kind", "id", "role", "job_id", "run_id"}),
        "engine workspace selection",
    )
    if row["kind"] == "engine_attempt":
        attempt_matches = [
            entry for entry in experiment.attempts if entry.record.binding.attempt_id == row["id"]
        ]
        if len(attempt_matches) != 1:
            raise EngineExperimentWorkspaceError("selected engine attempt is unavailable")
        entry = attempt_matches[0]
        binding = entry.record.binding
        expected = {
            "kind": "engine_attempt",
            "id": binding.attempt_id,
            "role": binding.role.value,
            "job_id": entry.job_id,
            "run_id": binding.run_id,
        }
    elif row["kind"] == "controller_check":
        check_matches = [check for check in experiment.checks if check.check_id == row["id"]]
        if len(check_matches) != 1:
            raise EngineExperimentWorkspaceError("selected controller check is unavailable")
        check = check_matches[0]
        expected = {
            "kind": "controller_check",
            "id": check.check_id,
            "role": check.role.value,
            "job_id": check.job_id,
            "run_id": check.run_id,
        }
    else:
        raise EngineExperimentWorkspaceError("engine workspace selection kind is invalid")
    if dict(json_clone(row)) != expected:
        raise EngineExperimentWorkspaceError("engine workspace selection changed")
    return expected
