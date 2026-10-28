"""Pure contract tests for the optional installed Assistant loopback fixture."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from bluefire.ai_composition_contract import OUTPUT_SCHEMA
from bluefire.capability_resources import METHODS
from tools.verify_installed_browser import (
    _COMPOSITION_PURPOSES,
    _FIXTURE_MODEL,
    _FIXTURE_PURPOSES,
    _RECEIVER_COMPOSITION_PURPOSE,
    _assistant_fixture_journey_passed,
    _fixture_output_for_request,
    _fixture_outputs,
    _fixture_request_allowed,
    _receiver_fixture_output_for_request,
    _receiver_fixture_request_allowed,
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


def receiver_request() -> dict[str, object]:
    request = request_for(_RECEIVER_COMPOSITION_PURPOSE)
    request["max_output_tokens"] = 1024
    request["text"]["format"]["schema"] = deepcopy(OUTPUT_SCHEMA)
    selected_steps = [
        ("create_fixture", METHODS[0], {"record_count": 8}),
        ("transform_fixture", METHODS[1], {"redact_values": False}),
        ("inspect_fixture_metadata", METHODS[3], {}),
        ("stage_records", METHODS[4], {"bundle_format": "jsonl"}),
        ("handoff_to_receiver", METHODS[5], {"port": 4317}),
        ("cleanup_workspace", METHODS[6], {"verify_removal": True}),
    ]
    request["input"] = json.dumps(
        {
            "schema_version": "bluefire.composition-model-context.v1",
            "objective": {
                "predicate": {
                    "kind": "redacted_delivery_preserves_records",
                    "record_count": 8,
                }
            },
            "revision": False,
            "methods": [{"behavior_id": method} for method in METHODS],
            "facts": [
                {
                    "evidence_ref": "policy",
                    "kind": "retained_policy",
                    "provenance": "observed",
                    "value": {"status": "retained"},
                }
            ],
            "initial_proposal": {
                "schema_version": "bluefire.composition-proposal.v1",
                "title": "Installed receiver proposal",
                "start": "seed",
                "steps": [
                    {"id": identity, "behavior_id": method, "parameters": parameters}
                    for identity, method, parameters in selected_steps
                ],
                "edges": [],
                "evidence_refs": "[EVIDENCE CONTENT OMITTED]",
                "rationale": "Use the observed retained receiver policy.",
            },
        }
    )
    return request


def receiver_allowed(
    request: object,
    *,
    index: int = 0,
    purpose: str = _RECEIVER_COMPOSITION_PURPOSE,
    auth: str | None = None,
    body_bytes: int = 100,
    total_bytes: int = 0,
) -> bool:
    return _receiver_fixture_request_allowed(
        request,
        purpose=purpose,
        model=request.get("model") if isinstance(request, dict) else None,
        body_bytes=body_bytes,
        authorization=auth,
        request_index=index,
        accumulated_bytes=total_bytes,
    )


def assistant_report() -> dict[str, object]:
    run_id = "run-20261025T104447Z-e876d141530b4989"
    evidence_id = "evidence-0123456789abcdefabcd"
    candidate_id = "detection-0123456789abcdefabcd"
    evaluation_id = "detection-evaluation-" + "a" * 64
    actions = ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1", "sandbox.cleanup.v1"]
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
            "approved_fixture_execute_run_completed_with_explicit_cleanup_and_observed_generated_fixture_metadata",
            "reviewed_fixture_detection_saved_and_evaluated_against_its_development_run",
            "saved_detection_candidate_and_development_evaluation_reopened_by_exact_ids",
            *[
                check
                for purpose in _COMPOSITION_PURPOSES
                for check in (
                    f"composition_purpose_{purpose}_separate_from_receiver_in_settings",
                    f"composition_purpose_{purpose}_persisted_and_revoked_without_request",
                )
            ],
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
            "step_count": 3,
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
        "model_purpose_authorizations": {
            "original_authorization": "revoked",
            "selected_purposes": [
                {"purpose": purpose, "status": "revoked", "model_requests": 0}
                for purpose in _COMPOSITION_PURPOSES
            ],
            "receiver_purpose_selected": False,
            "model_requests_before": 4,
            "model_requests_after": 4,
        },
        "route_counts": {
            "authorization": 1,
            "composition_purpose_authorization": 2,
            "authorization_revoke": 3,
        },
        "cleanup": {
            "runner_stopped": True,
            "execute_job_terminal": True,
            "model_authorizations_revoked": True,
        },
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
    assert len(draft["steps"]) == 3
    assert draft["steps"][0]["parameters"]["record_count"] == 4
    assert draft["steps"][1]["parameters"]["redact_values"] is True
    assert draft["steps"][2] == {
        "id": "cleanup_workspace",
        "behavior_id": "sandbox.cleanup.v1",
        "parameters": {"verify_removal": True},
    }
    assert draft["edges"] == [
        {"from_step": "create_fixture", "outcome": "success", "to_step": "transform_fixture"},
        {"from_step": "transform_fixture", "outcome": "success", "to_step": "cleanup_workspace"},
    ]
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


def test_receiver_fixture_is_one_exact_request_separate_from_four_assistant_requests() -> None:
    request = receiver_request()
    assert receiver_allowed(request)
    assert not receiver_allowed(request, index=1)
    assert not allowed(request, index=0)
    assert allowed(request_for(_FIXTURE_PURPOSES[0]), index=0)
    assert not receiver_allowed(request_for(_FIXTURE_PURPOSES[0]))


@pytest.mark.parametrize(
    ("mutation", "index", "purpose", "auth", "body_bytes", "total_bytes"),
    [
        (
            lambda request: request.update(model="other-model"),
            0,
            _RECEIVER_COMPOSITION_PURPOSE,
            None,
            100,
            0,
        ),
        (
            lambda request: request.update(max_output_tokens=64),
            0,
            _RECEIVER_COMPOSITION_PURPOSE,
            None,
            100,
            0,
        ),
        (
            lambda request: request.update(extra="field"),
            0,
            _RECEIVER_COMPOSITION_PURPOSE,
            None,
            100,
            0,
        ),
        (
            lambda request: request["text"]["format"].update(name="bluefire_ai_graph_draft"),
            0,
            _RECEIVER_COMPOSITION_PURPOSE,
            None,
            100,
            0,
        ),
        (
            lambda request: request["text"]["format"].update(schema={"type": "object"}),
            0,
            _RECEIVER_COMPOSITION_PURPOSE,
            None,
            100,
            0,
        ),
        (lambda request: None, 0, "bluefire_ai_graph_draft", None, 100, 0),
        (lambda request: None, 0, _RECEIVER_COMPOSITION_PURPOSE, "Bearer secret", 100, 0),
        (lambda request: None, 0, _RECEIVER_COMPOSITION_PURPOSE, None, 0, 0),
        (lambda request: None, 0, _RECEIVER_COMPOSITION_PURPOSE, None, 262_145, 0),
        (lambda request: None, 0, _RECEIVER_COMPOSITION_PURPOSE, None, 100, 262_045),
    ],
)
def test_receiver_fixture_rejects_other_purposes_schemas_and_budgets(
    mutation, index: int, purpose: str, auth: str | None, body_bytes: int, total_bytes: int
) -> None:
    request = receiver_request()
    mutation(request)
    assert not receiver_allowed(
        request,
        index=index,
        purpose=purpose,
        auth=auth,
        body_bytes=body_bytes,
        total_bytes=total_bytes,
    )


def test_receiver_fixture_restores_only_the_supplied_retained_policy_reference() -> None:
    request = receiver_request()
    context = json.loads(request["input"])
    expected = {
        **context["initial_proposal"],
        "evidence_refs": [context["facts"][0]["evidence_ref"]],
    }
    assert _receiver_fixture_output_for_request(request) == expected
    assert json.loads(request["input"])["initial_proposal"]["evidence_refs"] == (
        "[EVIDENCE CONTENT OMITTED]"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda context: context.update(revision=True),
        lambda context: context["objective"]["predicate"].update(record_count=7),
        lambda context: context["methods"].pop(),
        lambda context: context["facts"][0].update(evidence_ref="unknown"),
        lambda context: context["facts"][0].update(provenance="model"),
        lambda context: context["facts"][0]["value"].update(status="unknown"),
        lambda context: context["initial_proposal"].update(evidence_refs=["policy"]),
        lambda context: context["initial_proposal"]["steps"].pop(),
        lambda context: context["initial_proposal"]["steps"][1]["parameters"].update(
            redact_values=True
        ),
    ],
)
def test_receiver_fixture_refuses_unbound_model_context(mutation) -> None:
    request = receiver_request()
    context = json.loads(request["input"])
    mutation(context)
    request["input"] = json.dumps(context)
    with pytest.raises(ValueError):
        _receiver_fixture_output_for_request(request)


def test_assistant_journey_validator_accepts_observed_match_count_and_development_classification() -> (
    None
):
    report = assistant_report()
    assert report["detection_application"]["observed_match_count"] == 1
    assert "benign_match_count" not in report["detection_application"]
    assert _assistant_fixture_journey_passed(report)


@pytest.mark.parametrize("count", [True, -1, 1.0, "1", None])
def test_assistant_journey_validator_rejects_invalid_observed_match_count(count) -> None:
    report = assistant_report()
    report["detection_application"]["observed_match_count"] = count
    assert not _assistant_fixture_journey_passed(report)


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
        lambda report: report["execute_preflight"]["actions"].pop(),
        lambda report: report["generated_fixture_execute"].update(step_count=2),
        lambda report: report["deadline_controls"].update(work_deadline_enforced=False),
        lambda report: report["deadline_controls"].update(cleanup_reserve_ms=0),
        lambda report: report["model_purpose_authorizations"].update(
            receiver_purpose_selected=True
        ),
        lambda report: report["model_purpose_authorizations"].update(model_requests_after=5),
        lambda report: report["model_purpose_authorizations"]["selected_purposes"][0].update(
            purpose="bluefire_composition_proposal"
        ),
        lambda report: report["model_purpose_authorizations"]["selected_purposes"][1].update(
            status="active"
        ),
        lambda report: report["route_counts"].update(composition_purpose_authorization=1),
        lambda report: report["route_counts"].update(authorization_revoke=4),
        lambda report: report["cleanup"].update(model_authorizations_revoked=False),
        lambda report: report["checks"].remove(
            "composition_purpose_bluefire_macos_file_access_composition_proposal_persisted_and_revoked_without_request"
        ),
    ],
)
def test_assistant_journey_validator_rejects_unbound_results(mutation) -> None:
    report = assistant_report()
    mutation(report)
    assert not _assistant_fixture_journey_passed(report)
