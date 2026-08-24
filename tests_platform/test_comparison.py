from __future__ import annotations

from pathlib import Path

from bluefire.comparison import compare_runs
from bluefire.run_store import RunStore


def _run(
    store: RunStore,
    *,
    objective: bool,
    observed: int,
    detection_matches: int,
    benign_matches: int,
    autonomy: str,
) -> str:
    handle = store.create_run(
        scenario={"schema_version": "bluefire.scenario.v1", "id": "scenario.test.v1"},
        plan={"schema_version": "bluefire.plan.v1", "steps": []},
        policy={"schema_version": "bluefire.run-policy.v1"},
        profile=None,
    )
    evidence = [
        {"evidence_id": f"evidence-{index}", "provenance": "observed"} for index in range(observed)
    ]
    store.finalize(
        handle.run_id,
        result={
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
            "steps": [
                {
                    "step_id": "observe",
                    "status": "success" if objective else "failed",
                    "telemetry": ["fixture.observed"],
                    "policy": {"status": "allowed"},
                }
            ],
            "planner_decisions": [{"remaining_budgets": {"steps": 2}}],
        },
        evidence=evidence,
        detections=[
            {
                "candidate_id": "candidate-test",
                "state": "benign_evaluated",
                "match_count": detection_matches,
                "benign_match_count": benign_matches,
            }
        ],
    )
    return handle.run_id


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
    assert comparison["summaries"][1]["ai_proposal_count"] == 1
    assert comparison["summaries"][1]["ai_applications"] == {"recorded_for_review": 1}
    assert delta["evidence_delta"]["observed"] == 2
    assert delta["detection_match_delta"] == 1
    assert delta["benign_match_delta"] == -1
    assert delta["autonomy_changed"] is True
    assert delta["assessment"] == "improved"
