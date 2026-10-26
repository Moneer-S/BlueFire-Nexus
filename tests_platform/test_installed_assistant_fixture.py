"""Pure contract tests for the optional installed Assistant loopback fixture."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from tools.verify_installed_browser import (
    _FIXTURE_MODEL,
    _FIXTURE_PURPOSES,
    _assistant_fixture_journey_passed,
    _fixture_output_for_request,
    _fixture_outputs,
    _fixture_request_allowed,
)


def request_for(purpose: str) -> dict[str, object]:
    return {
        "model": _FIXTURE_MODEL,
        "instructions": "Bounded fixture instructions",
        "input": "Bounded fixture input",
        "max_output_tokens": 64,
        "store": False,
        "parallel_tool_calls": False,
        "tools": [],
        "tool_choice": "none",
        "text": {
            "format": {
                "type": "json_schema",
                "name": purpose,
                "schema": {"type": "object"},
                "strict": True,
            }
        },
    }


def assistant_report() -> dict[str, object]:
    run_id = "run-20261025T104447Z-e876d141530b4989"
    evidence_id = "evidence-0123456789abcdefabcd"
    candidate_id = "detection-0123456789abcdefabcd"
    evaluation_id = "detection-evaluation-" + "a" * 64
    actions = ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1"]
    counts = {
        "assistant_turns": 2,
        "model_requests": 4,
        "run_preflight": 1,
        "run_submission": 1,
        "execute_approval": 1,
        "runner_bootstrap": 1,
        "runner_start": 1,
        "runner_stop": 1,
        "detection_source": 1,
        "detection_context": 1,
        "detection_validate": 1,
        "detection_review": 1,
    }
    return {
        "schema_version": "bluefire.installed-assistant-fixture.v2",
        "status": "passed",
        "evidence_scope": "Generated fixture observations are normalized metadata, not target telemetry or held-out detection evidence.",
        "deadline_controls": {
            "outer_budget_remaining_at_browser_launch_ms": 220_000,
            "work_deadline_enforced": True,
            "cleanup_reserve_ms": 55_000,
            "outer_margin_ms": 2_000,
        },
        "blocked_requests": [],
        "errors": [],
        "checks": [
            "approved_two_step_execute_run_completed_with_observed_generated_fixture_metadata",
            "reviewed_fixture_detection_saved_and_evaluated_against_its_development_run",
            "saved_detection_candidate_and_development_evaluation_reopened_by_exact_ids",
        ],
        "graph_simulation": {"native_execution": False},
        "execute_preflight": {
            "mode": "execute",
            "autonomy": "off",
            "ai_enabled": False,
            "ai_provider_id": "deterministic-offline.v1",
            "actions": actions,
        },
        "generated_fixture_execute": {
            "status": "completed",
            "native_execution": True,
            "mode": "execute",
            "autonomy": "off",
            "runner_profile_id": "sandbox-execute.v1",
            "run_id": run_id,
            "job_id": "job-" + "b" * 32,
            "step_count": 2,
            "observed_metadata_record_count": 1,
            "observed_evidence_ids": [evidence_id],
            "observed_records": [
                {
                    "evidence_id": evidence_id,
                    "run_id": run_id,
                    "step_id": "create_fixture",
                    "behavior_id": actions[0],
                    "action_id": actions[0],
                    "producer": "collector.filesystem.sandbox.v1",
                }
            ],
            "cleanup": {"attempted": True, "success": True},
        },
        "detection_application": {
            "candidate_id": candidate_id,
            "evaluation_id": evaluation_id,
            "run_id": run_id,
            "development_case": True,
            "backend_executed": True,
            "result_state": "matched",
            "observed_match_count": 1,
            "benign_match_count": 1,
        },
        "detection_reopened": {
            "candidate_id": candidate_id,
            "evaluation_id": evaluation_id,
            "run_id": run_id,
            "revision": 2,
            "definition_digest": "sha256:" + "c" * 64,
            "development_case": True,
            "evaluation_use": "development",
        },
        "provider_requests": {
            "count": 4,
            "purposes": list(_FIXTURE_PURPOSES),
            "request_bytes": 1024,
        },
        "cleanup": {"runner_stopped": True, "execute_job_terminal": True},
        "request_counts": counts,
    }


def allowed(
    request: object,
    *,
    index: int,
    total_bytes: int = 0,
    auth: str | None = None,
    body_bytes: int = 100,
) -> bool:
    purpose = _FIXTURE_PURPOSES[index] if index < len(_FIXTURE_PURPOSES) else None
    model = request.get("model") if isinstance(request, dict) else None
    return _fixture_request_allowed(
        request,
        purpose=purpose,
        model=model,
        body_bytes=body_bytes,
        authorization=auth,
        request_index=index,
        accumulated_bytes=total_bytes,
    )


@pytest.mark.parametrize("index", range(4))
def test_fixture_accepts_only_the_four_ordered_structured_purposes(index: int) -> None:
    purpose = _FIXTURE_PURPOSES[index]
    assert allowed(request_for(purpose), index=index)


def test_fixture_rejects_purposes_in_the_wrong_order() -> None:
    assert not allowed(request_for(_FIXTURE_PURPOSES[1]), index=0)


def test_fixture_rejects_a_fifth_model_request() -> None:
    assert not allowed(request_for("unexpected"), index=4)


@pytest.mark.parametrize(
    ("index", "mutation", "auth", "total_bytes"),
    [
        (0, lambda request: request.update(model="other-model"), None, 0),
        (
            0,
            lambda request: request["text"]["format"].update(name="bluefire_ai_graph_draft"),
            None,
            0,
        ),
        (0, lambda request: request.update(extra="field"), None, 0),
        (0, lambda request: request.update(store=True), None, 0),
        (0, lambda request: request.update(max_output_tokens=65), None, 0),
        (0, lambda request: None, "Bearer secret", 0),
        (0, lambda request: None, None, 2_097_053),
    ],
)
def test_fixture_rejects_out_of_scope_envelopes(
    index: int, mutation, auth: str | None, total_bytes: int
) -> None:
    request = (
        deepcopy(request_for(_FIXTURE_PURPOSES[index]))
        if index < len(_FIXTURE_PURPOSES)
        else request_for("unexpected")
    )
    mutation(request)
    assert not allowed(request, index=index, auth=auth, total_bytes=total_bytes)


def test_fixture_outputs_bound_graph_and_detection_workflows() -> None:
    outputs = _fixture_outputs()
    assert len(outputs) == 4
    assert outputs[0]["steps"][0]["capability_id"] == "graph.propose_and_validate"
    draft = outputs[1]
    assert len(draft["steps"]) == 2
    assert draft["steps"][0]["parameters"]["record_count"] == 4
    assert draft["steps"][1]["parameters"]["redact_values"] is True
    assert outputs[2]["steps"][0]["capability_id"] == "detection.create_and_evaluate"
    assert (
        outputs[3]["source"]
        == "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'"
    )
    assert outputs[3]["evidence_refs"] == []


def test_detection_source_fixture_cites_only_a_supplied_observation() -> None:
    evidence_id = "evidence-0123456789abcdefabcd"
    request = request_for(_FIXTURE_PURPOSES[3])
    request["input"] = json.dumps({"observations": [{"evidence_id": evidence_id}]})
    output = _fixture_output_for_request(3, request)
    assert output["evidence_refs"] == [evidence_id]
    assert "generated fixture observations only" in output["limitations"][0].lower()
    assert "held-out detection quality" in output["limitations"][1].lower()


def test_detection_source_fixture_refuses_missing_or_invalid_observed_references() -> None:
    request = request_for(_FIXTURE_PURPOSES[3])
    request["input"] = json.dumps({"observations": []})
    with pytest.raises(ValueError):
        _fixture_output_for_request(3, request)
    request["input"] = json.dumps({"observations": [{"evidence_id": "evidence-invalid"}]})
    with pytest.raises(ValueError):
        _fixture_output_for_request(3, request)


def test_fixture_rejects_per_request_byte_limit() -> None:
    request = request_for(_FIXTURE_PURPOSES[0])
    assert not allowed(request, index=0, body_bytes=1_048_577)
    assert not allowed(request, index=0, body_bytes=0)


def test_assistant_journey_validator_accepts_honest_benign_match_result() -> None:
    report = assistant_report()
    assert report["detection_application"]["benign_match_count"] == 1
    assert _assistant_fixture_journey_passed(report)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report["generated_fixture_execute"]["observed_records"][0].update(
            run_id="run-20261025T104447Z-aaaaaaaaaaaaaaaa"
        ),
        lambda report: report["generated_fixture_execute"]["observed_records"][0].update(
            producer="runner-receipt"
        ),
        lambda report: report["generated_fixture_execute"]["observed_records"][0].update(
            action_id="sandbox.fixture.transform.v1"
        ),
        lambda report: report["detection_reopened"].update(
            evaluation_id="detection-evaluation-" + "d" * 64
        ),
        lambda report: report["detection_reopened"].update(
            run_id="run-20261025T104447Z-aaaaaaaaaaaaaaaa"
        ),
        lambda report: report["detection_reopened"].update(development_case=False),
        lambda report: report["execute_preflight"].update(autonomy="auto"),
        lambda report: report["deadline_controls"].update(work_deadline_enforced=False),
        lambda report: report["deadline_controls"].update(cleanup_reserve_ms=0),
    ],
)
def test_assistant_journey_validator_rejects_unbound_results(mutation) -> None:
    report = assistant_report()
    mutation(report)
    assert not _assistant_fixture_journey_passed(report)
