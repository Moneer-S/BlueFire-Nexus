from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bluefire.comparison import compare_runs
from bluefire.run_store import RunStore
from bluefire.util import content_hash

_UNBOUND = object()


def _run(
    store: RunStore,
    *,
    objective: bool,
    observed: int,
    detection_matches: int,
    benign_matches: int,
    autonomy: str,
    catalog_authority: Any = _UNBOUND,
    evidence: list[dict[str, Any]] | None = None,
    replay: dict[str, Any] | None = None,
    target_scope: dict[str, Any] | None = None,
    authorized_target_scope: Any = _UNBOUND,
    steps: list[dict[str, Any]] | None = None,
    plan_steps: list[dict[str, Any]] | None = None,
    planner_decisions: list[dict[str, Any]] | None = None,
    cleanup: Any = _UNBOUND,
    detection_candidates: list[dict[str, Any]] | None = None,
) -> str:
    policy: dict[str, Any] = {"schema_version": "bluefire.run-policy.v1"}
    if catalog_authority is not _UNBOUND:
        policy["preflight"] = {"catalog_authority": catalog_authority}
    handle = store.create_run(
        scenario={"schema_version": "bluefire.scenario.v1", "id": "scenario.test.v1"},
        plan={"schema_version": "bluefire.plan.v1", "steps": plan_steps or []},
        policy=policy,
        profile=None,
    )
    evidence_records = (
        evidence
        if evidence is not None
        else [
            {"evidence_id": f"evidence-{index}", "provenance": "observed"}
            for index in range(observed)
        ]
    )
    result = {
        "schema_version": "bluefire.run-result.v1",
        "status": "completed" if objective else "incomplete",
        "mode": "simulate",
        "scenario_id": "scenario.test.v1",
        "objective_reached": objective,
        "autonomy": autonomy,
        "ai_provider": {"provider_id": "deterministic-offline.v1"},
        "ai_proposals": (
            [{"application_status": "recorded_for_review"}] if autonomy != "off" else []
        ),
        "replay": replay,
        "target_scope": target_scope,
        "authorized_target_scope": (
            target_scope if authorized_target_scope is _UNBOUND else authorized_target_scope
        ),
        "steps": (
            steps
            if steps is not None
            else [
                {
                    "step_id": "observe",
                    "status": "success" if objective else "failed",
                    "telemetry": ["fixture.observed"],
                    "policy": {"status": "allowed"},
                }
            ]
        ),
        "planner_decisions": (
            planner_decisions
            if planner_decisions is not None
            else [{"remaining_budgets": {"steps": 2}}]
        ),
    }
    if cleanup is not _UNBOUND:
        result["cleanup"] = cleanup
    store.finalize(
        handle.run_id,
        result=result,
        evidence=evidence_records,
        detections=(
            detection_candidates
            if detection_candidates is not None
            else [
                {
                    "candidate_id": "candidate-test",
                    "state": "benign_evaluated",
                    "match_count": detection_matches,
                    "benign_match_count": benign_matches,
                }
            ]
        ),
    )
    return handle.run_id


def _sha(character: str) -> str:
    return "sha256:" + character * 64


def _package(package_id: str, version: str, generation: int, character: str) -> dict[str, Any]:
    return {
        "package_id": package_id,
        "package_version": version,
        "package_digest": _sha(character),
        "content_digest": _sha(chr(ord(character) + 1)),
        "publisher_id": f"publisher.{package_id}",
        "key_id": f"key.{package_id}",
        "signer_fingerprint": _sha(chr(ord(character) + 2)),
        "activated_generation": generation,
        "runner_identity_digest": _sha("d"),
        "runner_inventory_digest": _sha("e"),
        "runner_platform": "windows-x86_64",
        "behavior_ids": [f"{package_id}.behavior.v1"],
        "action_ids": [f"{package_id}.action.v1"],
    }


def _authority(generation: int, packages: list[dict[str, Any]]) -> dict[str, Any]:
    catalog_digest = _sha("a" if generation == 1 else "b")
    action_bindings = [
        {
            "schema_version": "bluefire.runner-execution-binding.v1",
            "catalog_generation": generation,
            "catalog_digest": catalog_digest,
            "logical_behavior_id": package["behavior_ids"][0],
            "logical_action_id": package["action_ids"][0],
            "package_id": package["package_id"],
            "package_version": package["package_version"],
            "package_digest": package["package_digest"],
            "content_digest": package["content_digest"],
            "program_digest": _sha("f"),
            "runner_opcode": "sandbox.collect.v1",
            "opcode_contract_digest": _sha("9"),
            "constants": {"method": "metadata"},
        }
        for package in packages
    ]
    body = {
        "schema_version": "bluefire.action-catalog-authority.v1",
        "generation": generation,
        "catalog_digest": catalog_digest,
        "built_in_catalog_digest": _sha("0"),
        "packages": packages,
        "action_bindings": action_bindings,
    }
    return {**body, "authority_digest": content_hash(body)}


def test_comparison_reports_evidence_detection_ai_and_assessment(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(
        store,
        objective=False,
        observed=1,
        detection_matches=1,
        benign_matches=1,
        autonomy="off",
    )
    candidate = _run(
        store,
        objective=True,
        observed=3,
        detection_matches=2,
        benign_matches=0,
        autonomy="assist",
    )

    comparison = compare_runs(store, [baseline, candidate])
    delta = comparison["deltas"][0]

    assert comparison["summaries"][1]["evidence_provenance"] == {"observed": 3}
    assert all(
        summary["catalog_authority"]["state"] == "legacy_unbound"
        for summary in comparison["summaries"]
    )
    assert comparison["summaries"][1]["ai_proposal_count"] == 1
    assert comparison["summaries"][1]["ai_applications"] == {"recorded_for_review": 1}
    assert delta["evidence_delta"]["observed"] == 2
    assert delta["detection_match_delta"] == 1
    assert delta["benign_match_delta"] == -1
    assert delta["autonomy_changed"] is True
    assert delta["material_configuration_changed"] is False
    assert delta["assessment"] == "improved"


def test_comparison_exposes_all_canonical_dimensions_and_meaningful_deltas(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    baseline_step = {
        "step_id": "observe",
        "behavior_id": "sandbox.discovery.list.v1",
        "action_id": "sandbox.discovery.list.v1",
        "simulation_id": None,
    }
    candidate_step = {
        "step_id": "observe",
        "behavior_id": "sandbox.discovery.metadata.v1",
        "action_id": "sandbox.discovery.metadata.v1",
        "simulation_id": None,
    }
    baseline = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=1,
        benign_matches=0,
        autonomy="off",
        target_scope={"scope_refs": ["sandbox.workspace"]},
        plan_steps=[baseline_step],
        steps=[{**baseline_step, "status": "success", "policy": {"status": "allowed"}}],
        planner_decisions=[
            {
                "decision_id": "decision-baseline",
                "selected_step_id": "observe",
                "selected_behavior_id": "sandbox.discovery.list.v1",
                "selected_action_id": "sandbox.discovery.list.v1",
                "selected_edge": {
                    "from_step": "prepare",
                    "outcome": "success",
                    "to_step": "observe",
                },
                "execution_disposition": "execute",
                "remaining_budgets": {"steps": 4, "bytes": 4096},
                "reason": "raw planner rationale must not be exposed",
            }
        ],
    )
    candidate = _run(
        store,
        objective=True,
        observed=2,
        detection_matches=2,
        benign_matches=0,
        autonomy="assist",
        target_scope={"scope_refs": ["sandbox.workspace", "network.loopback"]},
        plan_steps=[candidate_step],
        steps=[{**candidate_step, "status": "success", "policy": {"status": "allowed"}}],
        planner_decisions=[
            {
                "decision_id": "decision-candidate",
                "selected_step_id": "observe_metadata",
                "selected_behavior_id": "sandbox.discovery.metadata.v1",
                "selected_action_id": "sandbox.discovery.metadata.v1",
                "selected_edge": {
                    "from_step": "prepare",
                    "outcome": "success",
                    "to_step": "observe_metadata",
                },
                "execution_disposition": "execute",
                "remaining_budgets": {"steps": 2, "bytes": 3072},
                "reason": "another private planner rationale",
            }
        ],
    )

    comparison = compare_runs(store, [baseline, candidate])
    expected_dimensions = {
        "planner",
        "scope",
        "implementation",
        "evidence",
        "detection",
        "cleanup",
        "budgets",
        "assessment",
    }

    assert all(
        set(summary["dimensions"]) == expected_dimensions for summary in comparison["summaries"]
    )
    delta_dimensions = comparison["deltas"][0]["dimensions"]
    assert set(delta_dimensions) == expected_dimensions
    assert delta_dimensions["planner"] == {
        "changed": True,
        "from_digest": comparison["summaries"][0]["dimensions"]["planner"]["decision_digest"],
        "to_digest": comparison["summaries"][1]["dimensions"]["planner"]["decision_digest"],
        "decision_count_delta": 0,
        "selected_steps_added": ["observe_metadata"],
        "selected_steps_removed": ["observe"],
    }
    assert delta_dimensions["implementation"]["changed"] is True
    assert delta_dimensions["implementation"]["steps_changed"] == ["observe"]
    assert delta_dimensions["budgets"]["changed"] is True
    assert delta_dimensions["budgets"]["remaining_delta"] == {
        "bytes": -1024,
        "steps": -2,
    }
    assert delta_dimensions["scope"]["changed"] is True
    assert delta_dimensions["evidence"]["changed"] is True
    assert delta_dimensions["detection"]["changed"] is True
    assert delta_dimensions["assessment"]["classification"] == "improved"
    assert "raw planner rationale" not in json.dumps(comparison)
    assert "private planner rationale" not in json.dumps(comparison)


def test_frontier_explanation_uses_path_identity_and_observed_detection(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    cleanup = {"attempted": True, "success": True, "outstanding_receipt_count": 0}
    baseline = _run(
        store,
        objective=False,
        observed=2,
        detection_matches=3,
        benign_matches=0,
        autonomy="off",
        steps=[
            {
                "step_id": "reach_objective",
                "behavior_id": "sandbox.loopback.request.v1",
                "action_id": "sandbox.loopback.request.v1",
                "status": "control_blocked",
                "telemetry": ["network.prevented"],
                "policy": {"status": "control_blocked"},
            },
            {
                "step_id": "cleanup_workspace",
                "behavior_id": "sandbox.cleanup.v1",
                "action_id": "sandbox.cleanup.v1",
                "status": "success",
                "telemetry": ["cleanup.verified"],
                "policy": {"status": "allowed"},
            },
        ],
        cleanup=cleanup,
        detection_candidates=[
            {
                "candidate_id": "candidate-test",
                "state": "observed_exercised",
                "match_count": 3,
                "benign_match_count": 0,
                "observed_evidence_ids": ["evidence-0", "evidence-1"],
            }
        ],
    )
    alternate_options: dict[str, Any] = {
        "observed": 1,
        "detection_matches": 2,
        "benign_matches": 0,
        "autonomy": "auto",
        "steps": [
            {
                "step_id": "reach_objective",
                "behavior_id": "sandbox.local.export.v1",
                "action_id": "sandbox.local.export.v1",
                "status": "success",
                "telemetry": ["local.exported"],
                "policy": {"status": "allowed"},
            },
            {
                "step_id": "cleanup_workspace",
                "behavior_id": "sandbox.cleanup.v1",
                "action_id": "sandbox.cleanup.v1",
                "status": "success",
                "telemetry": ["cleanup.verified"],
                "policy": {"status": "allowed"},
            },
        ],
        "cleanup": cleanup,
        "detection_candidates": [
            {
                "candidate_id": "candidate-test",
                "state": "observed_exercised",
                "match_count": 2,
                "benign_match_count": 0,
                "observed_evidence_ids": ["evidence-0"],
            }
        ],
        "replay": {
            "exact": False,
            "source_run_id": baseline,
            "source_scenario_digest": content_hash(
                {"schema_version": "bluefire.scenario.v1", "id": "scenario.test.v1"}
            ),
            "defense_change": "network prevention enabled",
        },
    }
    successful_alternate = _run(store, objective=True, **alternate_options)
    unsuccessful_alternate = _run(store, objective=False, **alternate_options)
    fixture_only_alternate = _run(
        store,
        objective=True,
        **{
            **alternate_options,
            "detection_candidates": [
                {
                    "candidate_id": "candidate-test",
                    "state": "fixture_exercised",
                    "match_count": 1,
                    "benign_match_count": 0,
                }
            ],
        },
    )

    comparison = compare_runs(
        store,
        [
            baseline,
            successful_alternate,
            unsuccessful_alternate,
            fixture_only_alternate,
        ],
    )
    successful = comparison["deltas"][0]
    explanation = successful["frontier_explanation"]

    assert successful["first_path_divergence"] == 0
    assert (
        successful["first_path_divergence"]
        == explanation["path_difference"]["first_divergence_index"]
    )
    assert explanation["path_difference"]["from"] == {
        "step_id": "reach_objective",
        "behavior_id": "sandbox.loopback.request.v1",
        "action_id": "sandbox.loopback.request.v1",
    }
    assert explanation["path_difference"]["to"] == {
        "step_id": "reach_objective",
        "behavior_id": "sandbox.local.export.v1",
        "action_id": "sandbox.local.export.v1",
    }
    assert explanation["first_block"]["from"]["step_id"] == "reach_objective"
    assert explanation["first_block"]["to"] is None
    assert explanation["prevention_bypass"]["supported"] is True
    assert successful["observed_detection_match_delta"] == -1
    assert successful["fixture_detection_match_delta"] == 0
    assert explanation["detection_bypass"] == {
        "occurred": True,
        "supported": True,
        "alternate_path": True,
        "objective_success": True,
        "objective_success_required": True,
        "observed_reduction": True,
        "from_observed_matches": 2,
        "to_observed_matches": 1,
        "observed_match_delta": -1,
        "fixture_match_delta": 0,
        "total_match_delta": -1,
    }
    assert explanation["telemetry_delta"] == {
        "added": ["local.exported"],
        "removed": ["network.prevented"],
        "changed": True,
    }
    assert explanation["objective_result"] == {
        "from_reached": False,
        "to_reached": True,
        "changed": True,
        "outcome": "recovered",
    }
    assert explanation["authoritative_cleanup"]["both_authoritative"] is True
    assert explanation["defensive_effect"] == {
        "change_declared": True,
        "effect": {
            "improvements": [],
            "regressions": [
                "objective_recovered",
                "prevention_bypassed",
                "observed_detection_bypassed",
            ],
        },
        "assessment": "regressed",
    }
    assert comparison["deltas"][1]["frontier_explanation"]["detection_bypass"]["supported"] is False
    fixture_only = comparison["deltas"][2]
    assert fixture_only["detection_match_delta"] == -2
    assert fixture_only["observed_detection_match_delta"] is None
    assert fixture_only["frontier_explanation"]["detection_bypass"]["supported"] is False


def test_frontier_explanation_rejects_detached_detection_and_lineage(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    cleanup = {"attempted": True, "success": True, "outstanding_receipt_count": 0}
    baseline = _run(
        store,
        objective=False,
        observed=1,
        detection_matches=1,
        benign_matches=0,
        autonomy="off",
        cleanup=cleanup,
        detection_candidates=[
            {
                "candidate_id": "candidate-test",
                "state": "observed_exercised",
                "match_count": 1,
                "benign_match_count": 0,
                "observed_evidence_ids": ["evidence-0"],
            }
        ],
    )
    candidate = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=0,
        benign_matches=0,
        autonomy="auto",
        cleanup=cleanup,
        replay={
            "exact": False,
            "source_run_id": "run-unrelated",
            "source_scenario_digest": content_hash(
                {"schema_version": "bluefire.scenario.v1", "id": "scenario.test.v1"}
            ),
            "defense_change": "unrelated change",
        },
        steps=[
            {
                "step_id": "alternate",
                "behavior_id": "sandbox.local.export.v1",
                "action_id": "sandbox.local.export.v1",
                "status": "success",
                "policy": {"status": "allowed"},
            }
        ],
        detection_candidates=[
            {
                "candidate_id": "candidate-test",
                "state": "observed_exercised",
                "match_count": 0,
                "benign_match_count": 0,
                "observed_evidence_ids": ["detached-evidence-id"],
            }
        ],
    )

    delta = compare_runs(store, [baseline, candidate])["deltas"][0]
    explanation = delta["frontier_explanation"]
    assert delta["observed_detection_match_delta"] is None
    assert explanation["prevention_bypass"]["supported"] is False
    assert explanation["detection_bypass"]["supported"] is False
    assert explanation["defensive_effect"]["assessment"] == "not_attributable"


def test_comparison_rejects_contradictory_cleanup_as_authoritative(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    run_id = _run(
        store,
        objective=False,
        observed=0,
        detection_matches=0,
        benign_matches=0,
        autonomy="off",
        steps=[{"step_id": "cleanup_workspace", "status": "failed"}],
        cleanup={"attempted": True, "success": True, "outstanding_receipt_count": 0},
    )
    comparison = compare_runs(
        store,
        [
            run_id,
            _run(
                store,
                objective=False,
                observed=0,
                detection_matches=0,
                benign_matches=0,
                autonomy="off",
            ),
        ],
    )

    summary = comparison["summaries"][0]
    assert summary["cleanup"]["authoritative"] is False
    assert summary["cleanup"]["state"] == "contradictory"
    assert summary["cleanup_success"] is False


def test_comparison_reports_sanitized_observed_artifact_and_gap_deltas(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(
        store,
        objective=True,
        observed=0,
        detection_matches=0,
        benign_matches=0,
        autonomy="off",
        evidence=[
            {
                "evidence_id": "evidence-baseline",
                "step_id": "stage_records",
                "provenance": "observed",
                "producer": "collector.filesystem.sandbox.v1",
                "content": {
                    "artifact_type": "file_observation",
                    "path": "staged/bundle.jsonl",
                    "sha256": "1" * 64,
                    "size_bytes": 12,
                },
                "content_hash": _sha("1"),
            }
        ],
    )
    candidate = _run(
        store,
        objective=True,
        observed=0,
        detection_matches=0,
        benign_matches=0,
        autonomy="off",
        evidence=[
            {
                "evidence_id": "evidence-candidate",
                "step_id": "stage_records",
                "provenance": "observed",
                "producer": "collector.filesystem.sandbox.v1",
                "content": {
                    "artifact_type": "file_observation",
                    "path": "staged/bundle.jsonl",
                    "sha256": "2" * 64,
                    "size_bytes": 24,
                },
                "content_hash": _sha("2"),
            },
            {
                "evidence_id": "evidence-gap",
                "step_id": "audit_logs",
                "provenance": "unknown",
                "producer": "collector.sysmon-eventlog.v1",
                "content": {
                    "artifact_type": "evidence_gap",
                    "requested_artifact": "host-audit",
                    "reason": "raw collector failure with local detail",
                },
                "content_hash": _sha("3"),
            },
        ],
    )

    comparison = compare_runs(store, [baseline, candidate])
    candidate_details = comparison["summaries"][1]["evidence_details"]
    delta = comparison["deltas"][0]["evidence_detail_delta"]

    assert candidate_details["producer_counts"] == {
        "collector.filesystem.sandbox.v1": 1,
        "collector.sysmon-eventlog.v1": 1,
    }
    assert delta["observed_artifacts_changed"] == [
        {
            "from": comparison["summaries"][0]["evidence_details"]["observed_artifacts"][0],
            "to": candidate_details["observed_artifacts"][0],
        }
    ]
    assert delta["producer_delta"]["collector.sysmon-eventlog.v1"] == 1
    assert delta["evidence_gaps_added"][0]["reason_code"] == "unclassified"
    assert delta["evidence_gaps_added"][0]["reason_hash"].startswith("sha256:")
    assert "raw collector failure" not in json.dumps(comparison)


def test_comparison_reports_sanitized_replay_variant_and_target_scope_delta(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=0,
        benign_matches=0,
        autonomy="off",
        target_scope={"scope_refs": ["sandbox.workspace"]},
    )
    replay_lineage = {
        "schema_version": "bluefire.replay-lineage.v1",
        "source_run_id": baseline,
        "source_scenario_digest": _sha("8"),
        "exact": False,
        "from_step_id": "observe",
        "swap_step_id": "observe",
        "swap_behavior_id": "sandbox.discovery.metadata.v1",
        "parameter_overrides": {"observe": {"record_count": 3}},
        "action_implementation_overrides": {"observe": "sandbox.discovery.metadata.v1"},
        "action_reselection_steps": ["observe"],
        "action_implementations_changed": True,
        "ai_changed": True,
        "autonomy_from": "off",
        "autonomy_to": "assist",
        "ai_provider_changed": True,
        "ai_provider_from": "deterministic-offline.v1",
        "ai_provider_to": "openai-responses.v1",
        "profile_changed": True,
        "defense_change": "sensitive defense note contents must not appear",
    }
    candidate = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=0,
        benign_matches=0,
        autonomy="assist",
        replay=replay_lineage,
        target_scope={"scope_refs": ["sandbox.workspace", "lab.identity"]},
    )

    comparison = compare_runs(store, [baseline, candidate])
    baseline_summary, candidate_summary = comparison["summaries"]
    delta = comparison["deltas"][0]
    encoded = json.dumps(comparison)

    assert baseline_summary["target_scope"]["scope_ref_count"] == 1
    assert candidate_summary["target_scope"]["scope_ref_count"] == 2
    assert candidate_summary["replay_lineage"]["variant_types"] == [
        "action_implementations",
        "ai",
        "defense_change",
        "from_node",
        "parameters",
        "profile",
        "swap",
    ]
    assert candidate_summary["replay_lineage"]["parameter_override_names"] == {
        "observe": ["record_count"]
    }
    assert candidate_summary["replay_lineage"]["defense_change_declared"] is True
    assert candidate_summary["replay_lineage"]["defense_change_digest"].startswith("sha256:")
    assert delta["target_scope_changed"] is True
    assert delta["replay_lineage_changed"] is True
    assert delta["replay_lineage_delta"]["action_implementations_changed"] is True
    assert delta["configuration_changes"] == ["target_scope", "action_implementations"]
    assert "replay_variant_changed" in delta["signals"]
    assert "target_scope_changed" in delta["signals"]
    assert "sensitive defense note" not in encoded


def test_comparison_summarizes_canonical_authorized_target_scope(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=0,
        benign_matches=0,
        autonomy="off",
        target_scope={"scope_refs": ["requested.one", "requested.two"]},
        authorized_target_scope={"scope_refs": ["sandbox.workspace"]},
    )
    candidate = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=0,
        benign_matches=0,
        autonomy="off",
        target_scope={"scope_refs": ["requested.one"]},
        authorized_target_scope={"scope_refs": ["sandbox.workspace", "lab.identity"]},
    )

    comparison = compare_runs(store, [baseline, candidate])

    assert comparison["summaries"][0]["target_scope"]["scope_ref_count"] == 1
    assert comparison["summaries"][1]["target_scope"]["scope_ref_count"] == 2
    assert comparison["deltas"][0]["target_scope_changed"] is True
    assert "target_scope" in comparison["deltas"][0]["configuration_changes"]


def test_comparison_does_not_substitute_requested_scope_for_invalid_authority(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    run_ids = [
        _run(
            store,
            objective=True,
            observed=1,
            detection_matches=0,
            benign_matches=0,
            autonomy="off",
            target_scope={"scope_refs": [requested]},
            authorized_target_scope=None,
        )
        for requested in ("requested.one", "requested.two")
    ]

    comparison = compare_runs(store, run_ids)

    assert [row["target_scope"]["state"] for row in comparison["summaries"]] == [
        "not_recorded",
        "not_recorded",
    ]
    assert comparison["deltas"][0]["target_scope_changed"] is False


def test_comparison_reports_deterministic_catalog_authority_lineage(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    baseline_authority = _authority(1, [_package("alpha", "1.0.0", 1, "1")])
    candidate_authority = _authority(
        2,
        [
            _package("bravo", "1.0.0", 2, "4"),
            _package("alpha", "2.0.0", 2, "7"),
        ],
    )
    baseline = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=1,
        benign_matches=0,
        autonomy="off",
        catalog_authority=baseline_authority,
    )
    candidate = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=1,
        benign_matches=0,
        autonomy="off",
        catalog_authority=candidate_authority,
    )

    comparison = compare_runs(store, [baseline, candidate])
    baseline_summary, candidate_summary = comparison["summaries"]
    delta = comparison["deltas"][0]

    assert baseline_summary["catalog_authority"] == {
        "state": "bound",
        "schema_version": "bluefire.action-catalog-authority.v1",
        "generation": 1,
        "catalog_digest": baseline_authority["catalog_digest"],
        "authority_digest": baseline_authority["authority_digest"],
        "authority_record_digest": content_hash(baseline_authority),
        "package_count": 1,
        "packages": [
            {
                key: baseline_authority["packages"][0][key]
                for key in (
                    "package_id",
                    "package_version",
                    "package_digest",
                    "content_digest",
                    "publisher_id",
                    "key_id",
                    "signer_fingerprint",
                    "activated_generation",
                )
            }
        ],
    }
    assert [
        package["package_id"] for package in candidate_summary["catalog_authority"]["packages"]
    ] == ["alpha", "bravo"]
    assert "action_bindings" not in json.dumps(comparison)
    assert "constants" not in json.dumps(comparison)
    assert delta["catalog_authority_changed"] is True
    assert delta["material_configuration_changed"] is True
    assert delta["configuration_changes"] == ["catalog_authority"]
    assert delta["signals"] == ["catalog_authority_changed"]
    assert delta["catalog_authority_delta"] == {
        "changed": True,
        "fields_changed": [
            "generation",
            "catalog_digest",
            "authority_digest",
            "authority_record_digest",
        ],
        "from_state": "bound",
        "to_state": "bound",
        "from_generation": 1,
        "to_generation": 2,
        "generation_delta": 1,
        "from_catalog_digest": baseline_authority["catalog_digest"],
        "to_catalog_digest": candidate_authority["catalog_digest"],
        "from_authority_digest": baseline_authority["authority_digest"],
        "to_authority_digest": candidate_authority["authority_digest"],
        "packages_added": [candidate_summary["catalog_authority"]["packages"][1]],
        "packages_removed": [],
        "packages_changed": [
            {
                "package_id": "alpha",
                "from": baseline_summary["catalog_authority"]["packages"][0],
                "to": candidate_summary["catalog_authority"]["packages"][0],
            }
        ],
    }


def test_comparison_preserves_legacy_and_sanitizes_malformed_authority(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=1,
        benign_matches=0,
        autonomy="off",
    )
    malformed = {
        "schema_version": "bluefire.action-catalog-authority.v1",
        "generation": True,
        "packages": 7,
        "action_bindings": [],
        "package_bytes": "must-not-appear",
    }
    candidate = _run(
        store,
        objective=True,
        observed=1,
        detection_matches=1,
        benign_matches=0,
        autonomy="off",
        catalog_authority=malformed,
    )

    comparison = compare_runs(store, [baseline, candidate])
    repeated = compare_runs(store, [baseline, candidate])
    legacy_summary, malformed_summary = comparison["summaries"]
    delta = comparison["deltas"][0]

    assert comparison == repeated
    assert legacy_summary["catalog_authority"]["state"] == "legacy_unbound"
    assert malformed_summary["catalog_authority"] == {
        "state": "malformed",
        "schema_version": None,
        "generation": None,
        "catalog_digest": None,
        "authority_digest": None,
        "authority_record_digest": content_hash(malformed),
        "package_count": 0,
        "packages": [],
        "error_codes": sorted(
            {
                "authority_digest_invalid",
                "authority_digest_mismatch",
                "authority_fields_invalid",
                "built_in_catalog_digest_invalid",
                "catalog_digest_invalid",
                "generation_invalid",
                "packages_invalid",
            }
        ),
    }
    assert "must-not-appear" not in json.dumps(comparison)
    assert "package_bytes" not in json.dumps(comparison)
    assert delta["catalog_authority_changed"] is True
    assert delta["catalog_authority_delta"]["from_state"] == "legacy_unbound"
    assert delta["catalog_authority_delta"]["to_state"] == "malformed"
    assert delta["assessment"] == "mixed"
