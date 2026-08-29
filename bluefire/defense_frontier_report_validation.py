"""Independent validators for GATE-04 reports derived from run bundles."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .comparison import compare_runs
from .config import AIProviderKind, load_config
from .defense_frontier import (
    CANONICAL_PROFILE_ID,
    COMPARISON_SCHEMA,
    DEFENSE_SCHEMA,
    FRONTIER_PROFILE_ID,
    PROVIDER_ID,
    REAL_PROVIDER_ID,
    SCENARIO_ID,
    STRUCTURAL_SCHEMA,
)
from .run_store import RunStore
from .util import content_hash, file_hash


class DefenseFrontierValidationError(ValueError):
    """Raised when persisted frontier evidence cannot support a gate claim."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DefenseFrontierValidationError(message)


def _exact(value: Mapping[str, Any], fields: set[str], context: str) -> None:
    _require(set(value) == fields, f"{context} fields are invalid")


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{context} is not an object")
    return value


def _list(value: Any, context: str, *, length: int | None = None) -> list[Any]:
    _require(isinstance(value, list), f"{context} is not a list")
    if length is not None:
        _require(len(value) == length, f"{context} has invalid cardinality")
    return value


def _validate_defense(
    report: Mapping[str, Any],
    canonical: Mapping[str, Any],
    frontier: Mapping[str, Any],
    replay: Mapping[str, Any],
) -> None:
    _exact(report, {"schema_version", "passed", "changes"}, "defense report")
    _require(
        report.get("schema_version") == DEFENSE_SCHEMA and report.get("passed") is True,
        "defense report did not pass",
    )
    changes = _list(report.get("changes"), "defense changes", length=2)
    first = _mapping(changes[0], "initial defense change")
    second = _mapping(changes[1], "replay defense change")
    common = {
        "change_id",
        "kind",
        "applied",
        "from_profile_id",
        "to_profile_id",
        "from_profile_digest",
        "to_profile_digest",
        "expected_effect",
        "observed_effect",
        "from_run_id",
        "to_run_id",
    }
    _exact(first, common, "initial defense change")
    _exact(second, common | {"replay_lineage_digest"}, "replay defense change")
    profile_digests = [
        content_hash(_mapping(run.get("profile"), "run profile"))
        for run in (canonical, frontier, replay)
    ]
    _require(
        first
        == {
            "change_id": "defense.loopback.block.v1",
            "kind": "runner-profile-control",
            "applied": True,
            "from_profile_id": CANONICAL_PROFILE_ID,
            "to_profile_id": FRONTIER_PROFILE_ID,
            "from_profile_digest": profile_digests[0],
            "to_profile_digest": profile_digests[1],
            "expected_effect": "block sandbox.network.loopback.v1 before dispatch",
            "observed_effect": "control_blocked_then_registered_local_export",
            "from_run_id": canonical.get("run_id"),
            "to_run_id": frontier.get("run_id"),
        },
        "initial defense change is not bound to the profile transition",
    )
    _require(
        second
        == {
            "change_id": "defense.loopback.restore.v1",
            "kind": "runner-profile-control",
            "applied": True,
            "from_profile_id": FRONTIER_PROFILE_ID,
            "to_profile_id": CANONICAL_PROFILE_ID,
            "from_profile_digest": profile_digests[1],
            "to_profile_digest": profile_digests[2],
            "expected_effect": "restore reviewed authenticated loopback transport",
            "observed_effect": "canonical_transport_replayed",
            "from_run_id": frontier.get("run_id"),
            "to_run_id": replay.get("run_id"),
            "replay_lineage_digest": content_hash(replay.get("replay")),
        },
        "replay defense change is not bound to the profile transition",
    )


def _validate_comparison(
    report: Mapping[str, Any],
    store: RunStore,
    run_ids: Sequence[str],
) -> None:
    _exact(
        report,
        {
            "schema_version",
            "passed",
            "run_ids",
            "primary",
            "defense_replay",
            "required_explanations",
        },
        "comparison report",
    )
    _require(
        report.get("schema_version") == COMPARISON_SCHEMA and report.get("passed") is True,
        "comparison report did not pass",
    )
    _require(report.get("run_ids") == list(run_ids), "comparison run ordering is invalid")
    _require(
        report.get("primary") == compare_runs(store, run_ids),
        "primary comparison is not reproducible",
    )
    defense = compare_runs(store, run_ids[1:])
    _require(
        report.get("defense_replay") == defense,
        "defense replay comparison is not reproducible",
    )
    required = [
        "path_difference",
        "first_block",
        "prevention_bypass",
        "detection_bypass",
        "telemetry_delta",
        "objective_result",
        "authoritative_cleanup",
        "defensive_effect",
    ]
    _require(
        report.get("required_explanations") == required,
        "comparison explanation inventory is invalid",
    )
    deltas = _list(defense.get("deltas"), "defense comparison deltas", length=1)
    explanation = _mapping(
        _mapping(deltas[0], "defense comparison delta").get("frontier_explanation"),
        "frontier explanation",
    )
    _require(
        set(explanation) == {"schema_version", "from_run_id", "to_run_id", *required},
        "frontier explanation fields are incomplete",
    )
    _require(
        _mapping(explanation.get("path_difference"), "path explanation").get("changed") is True
        and _mapping(explanation.get("first_block"), "block explanation").get("from") is not None
        and _mapping(explanation.get("prevention_bypass"), "prevention explanation").get(
            "supported"
        )
        is True
        and _mapping(explanation.get("detection_bypass"), "detection explanation").get("supported")
        is True
        and _mapping(explanation.get("objective_result"), "objective explanation").get("to_reached")
        is True
        and _mapping(explanation.get("authoritative_cleanup"), "cleanup explanation").get(
            "both_authoritative"
        )
        is True
        and _mapping(explanation.get("defensive_effect"), "defensive explanation").get("assessment")
        == "regressed",
        "defense replay comparison does not explain the proven bypass and regression",
    )


def _validate_structural(report: Mapping[str, Any], repository: Path) -> None:
    _exact(
        report,
        {"schema_version", "passed", "scenario_contract", "real_provider_contract"},
        "structural report",
    )
    _require(
        report.get("schema_version") == STRUCTURAL_SCHEMA and report.get("passed") is True,
        "structural report did not pass",
    )
    scenario = _mapping(report.get("scenario_contract"), "scenario contract")
    real = _mapping(report.get("real_provider_contract"), "real provider contract")
    source = repository / "scenarios" / "ai_adaptive_safe_chain.yaml"
    packaged = repository / "bluefire" / "data" / source.name
    _require(
        scenario
        == {
            "scenario_id": SCENARIO_ID,
            "source_sha256": file_hash(source),
            "packaged_sha256": file_hash(packaged),
        }
        and source.read_bytes() == packaged.read_bytes(),
        "frontier scenario packaging contract is invalid",
    )
    config = load_config(repository / "bluefire" / "data" / "bluefire.example.yaml")
    provider = config.ai.provider(REAL_PROVIDER_ID)
    _require(
        provider.kind is AIProviderKind.OPENAI_RESPONSES
        and provider.api_key is not None
        and provider.api_key.env == "OPENAI_API_KEY"
        and provider.endpoint is not None
        and provider.endpoint.startswith("https://")
        and config.ai.fallback.id == PROVIDER_ID
        and real
        == {
            "provider_id": REAL_PROVIDER_ID,
            "kind": "openai_responses",
            "endpoint_scheme": "https",
            "credential_reference": "OPENAI_API_KEY",
            "fallback_provider_id": PROVIDER_ID,
            "manual_key_required_for_release": False,
            "proposal_only": True,
        },
        "generic OpenAI-compatible provider contract is invalid",
    )


__all__ = [
    "DefenseFrontierValidationError",
    "_exact",
    "_list",
    "_mapping",
    "_require",
    "_validate_comparison",
    "_validate_defense",
    "_validate_structural",
]
