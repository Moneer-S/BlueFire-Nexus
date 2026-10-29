"""Pure contract tests for the optional installed Assistant loopback fixture."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

import bluefire
from bluefire.ai_composition_contract import (
    EVIDENCE_OUTPUT_SCHEMA,
    OUTPUT_SCHEMA,
    REFRESH_PREREQUISITES,
    RETAINED_OUTPUT_SCHEMA,
)
from bluefire.capability_resources import METHODS, semantic_ports
from bluefire.contracts import load_scenario
from bluefire.retained_artifacts import METHOD as RETAINED_METHOD
from bluefire.retained_artifacts import PACK as RETAINED_PACK
from bluefire.retained_artifacts import POLICY as RETAINED_POLICY
from bluefire.util import content_hash
from tools.verify_installed_browser import (
    _COMPOSITION_PURPOSES,
    _FIXTURE_MODEL,
    _FIXTURE_PURPOSES,
    _RECEIVER_COMPOSITION_PURPOSE,
    _RECEIVER_EVIDENCE_PURPOSE,
    _RECEIVER_RETAINED_PURPOSE,
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
    source = load_scenario(
        Path(bluefire.__file__).parent / "data" / "receiver_defense_validation.yaml"
    ).to_dict()
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
                "start": source["start"],
                "steps": [
                    {key: row[key] for key in ("id", "behavior_id", "parameters")}
                    for row in source["steps"]
                ],
                "edges": source["edges"],
                "evidence_refs": "[EVIDENCE CONTENT OMITTED]",
                "rationale": "Use the observed retained receiver policy.",
            },
        }
    )
    return request


def receiver_evidence_request() -> dict[str, object]:
    """Authored context for pure fixture checks, never installed or native proof."""
    request = receiver_request()
    supplied = json.loads(request["input"])
    initial = supplied["initial_proposal"]
    request["text"]["format"].update(
        name=_RECEIVER_EVIDENCE_PURPOSE, schema=deepcopy(EVIDENCE_OUTPUT_SCHEMA)
    )
    supplied.update(
        schema_version="bluefire.composition-evidence-model-context.v1",
        revision=True,
        initial_proposal=None,
    )
    supplied["objective"] = {
        "question": "Can redacted generated records satisfy the retained receiver policy?",
        "predicate": {
            "kind": "redacted_delivery_preserves_records",
            "record_count": 8,
            "data_class": "generated_public_jsonl",
        },
    }
    parameters = {row["behavior_id"]: row["parameters"] for row in initial["steps"]}
    supplied["methods"] = []
    for method in METHODS:
        ports = semantic_ports(method)
        supplied["methods"].append(
            {
                "behavior_id": method,
                **{
                    kind: [
                        {
                            "name": row[0],
                            "type": row[1],
                            "multiple": row[2],
                            "required": row[3] if kind == "inputs" else True,
                            "description": "Reviewed fixture port",
                        }
                        for row in ports[index]
                    ]
                    for index, kind in enumerate(("inputs", "outputs"))
                },
                "parameter_domains": (
                    {"redact_values": [False, True]}
                    if method == METHODS[1]
                    else {key: [value] for key, value in parameters.get(method, {}).items()}
                ),
            }
        )
    policy_digest = content_hash("authored retained policy")
    supplied["facts"] = [
        {"evidence_ref": identity, "kind": kind, "provenance": "observed", "value": value}
        for identity, kind, value in (
            ("policy", "retained_policy", {"status": "retained", "policy_digest": policy_digest}),
            (
                "result",
                "receiver_result",
                {
                    "decision": "policy_refused",
                    "policy_digest": policy_digest,
                    "record_count": 8,
                    "redacted_record_count": 0,
                    "retained_record_count": 8,
                    "empty_record_count": 0,
                },
            ),
            ("cleanup", "cleanup", {"run": "complete", "receiver": "verified_closed"}),
        )
    ]
    attempt_id = "attempt-" + "a" * 32
    source_digest = content_hash("authored source")
    record_ref = {
        "owner_id": "job-" + "b" * 32,
        "attempt_id": attempt_id,
        "job_id": "job-" + "c" * 32,
        "run_id": "run-20261029T123456Z-0123456789abcdef",
        "evidence_id": "evidence-0123456789abcdefabcd",
        "record_hash": content_hash("authored record"),
        "source_binding_digest": source_digest,
    }
    finding = {
        "finding_id": "finding-" + content_hash(record_ref).removeprefix("sha256:"),
        "evidence_id": record_ref["evidence_id"],
        "step_id": "stage_records",
        "behavior_id": METHODS[4],
        "action_id": METHODS[4],
        "provenance": "observed",
        "semantic_kind": "observed_filesystem",
        "observed_at": "2026-10-29T12:34:56Z",
        "content_hash": content_hash("authored content"),
        "record_hash": record_ref["record_hash"],
        "summary": {
            "sha256": content_hash("authored staged artifact").removeprefix("sha256:"),
            "size_bytes": 840,
        },
        "applicability": {"status": "historical_only", "reason": "current_state_not_verified"},
        "record_ref": record_ref,
    }
    supplied["historical_context"] = {
        "knowledge_digest": content_hash("authored knowledge"),
        "attempt_ids": [attempt_id],
        "attempts": [
            {
                "attempt_id": attempt_id,
                "source_binding_digest": source_digest,
                "findings": [finding],
            }
        ],
        "choices": [
            {
                "attempt_id": attempt_id,
                "compiled_digest": content_hash("authored compiled graph"),
                "semantic_digest": content_hash("authored semantics"),
                "step_id": row["id"],
                "behavior_id": row["behavior_id"],
                "parameters": row["parameters"],
                "inputs": {},
            }
            for row in initial["steps"]
        ],
    }
    request["input"] = json.dumps(supplied)
    return request


def receiver_retained_request(*, revision: bool = False) -> dict[str, object]:
    """Pure authored metadata for the separate bounded retained-result purpose."""
    request = receiver_evidence_request()
    value = json.loads(request["input"])
    request["text"]["format"].update(
        name=_RECEIVER_RETAINED_PURPOSE, schema=deepcopy(RETAINED_OUTPUT_SCHEMA)
    )
    value.update(schema_version="bluefire.retained-composition-model-context.v1", revision=revision)
    ports = semantic_ports(RETAINED_METHOD, pack=RETAINED_PACK)
    value["methods"].append(
        {
            "behavior_id": RETAINED_METHOD,
            **{
                kind: [
                    {
                        "name": row[0],
                        "type": row[1],
                        "multiple": row[2],
                        "required": row[3] if kind == "inputs" else True,
                        "description": "Reviewed retained result port",
                    }
                    for row in ports[index]
                ]
                for index, kind in enumerate(("inputs", "outputs"))
            },
            "parameter_domains": {"source_ref": {"kind": "sealed_same_lineage_generated_jsonl"}},
        }
    )
    value["retained_artifacts"] = {
        "policy": deepcopy(RETAINED_POLICY),
        "available_sources": [],
        "availability": "none_available",
    }
    if revision:
        finding = value["historical_context"]["attempts"][0]["findings"][0]
        finding["semantic_kind"] = "observed_filesystem"
        finding["summary"] = {"sha256": "a" * 64, "size_bytes": 672}
        source = {
            "run_id": finding["record_ref"]["run_id"],
            "attempt_id": finding["record_ref"]["attempt_id"],
            "lineage_id": "lineage-authored",
            "step_id": finding["step_id"],
            "artifact": "bundle",
            "artifact_type": "artifact.sandbox.bundle.v1",
            "sha256": "a" * 64,
            "size_bytes": 672,
        }
        source["source_ref"] = content_hash(source)
        value["retained_artifacts"].update(available_sources=[source], availability="available")
    else:
        value["facts"] = value["facts"][:1]
        value["historical_context"] = None
        value["initial_proposal"] = json.loads(receiver_request()["input"])["initial_proposal"]
        value["initial_proposal"]["evidence_refs"] = ["policy"]
    request["input"] = json.dumps(value)
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


def test_receiver_fixture_is_four_ordered_requests_separate_from_assistant_requests() -> None:
    request = receiver_request()
    evidence = receiver_evidence_request()
    assert receiver_allowed(request)
    assert not receiver_allowed(request, index=1)
    assert receiver_allowed(
        evidence,
        index=1,
        purpose=_RECEIVER_EVIDENCE_PURPOSE,
        total_bytes=262_144,
        body_bytes=262_144,
    )
    assert not receiver_allowed(evidence, index=0, purpose=_RECEIVER_EVIDENCE_PURPOSE)
    assert not receiver_allowed(evidence, index=2, purpose=_RECEIVER_EVIDENCE_PURPOSE)
    assert not receiver_allowed(evidence, index=-1, purpose=_RECEIVER_EVIDENCE_PURPOSE)
    assert not allowed(request, index=0)
    assert allowed(request_for(_FIXTURE_PURPOSES[0]), index=0)
    assert not receiver_allowed(request_for(_FIXTURE_PURPOSES[0]))
    for index, revision in ((2, False), (3, True)):
        retained = receiver_retained_request(revision=revision)
        assert receiver_allowed(
            retained,
            index=index,
            purpose=_RECEIVER_RETAINED_PURPOSE,
            body_bytes=262_144,
            total_bytes=262_144 * index,
        )
        assert not receiver_allowed(retained, index=5 - index, purpose=_RECEIVER_RETAINED_PURPOSE)
        assert not receiver_allowed(retained, index=4, purpose=_RECEIVER_RETAINED_PURPOSE)
        assert not receiver_allowed(retained, index=1, purpose=_RECEIVER_RETAINED_PURPOSE)
        assert not allowed(retained, index=index)


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
        (lambda request: None, 0, _RECEIVER_COMPOSITION_PURPOSE, None, 100, 1_048_477),
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


def test_receiver_evidence_fixture_reuses_exact_later_finding_without_promoting_it_to_current_proof() -> (
    None
):
    request = receiver_evidence_request()
    before = deepcopy(request)
    context = json.loads(request["input"])
    history = context["historical_context"]
    actual = _receiver_fixture_output_for_request(request)
    assert request == before
    assert actual["schema_version"] == "bluefire.composition-evidence-proposal.v1"
    candidate = actual["candidate"]
    original = _receiver_fixture_output_for_request(receiver_request())
    expected_steps = deepcopy(original["steps"])
    expected_steps[1]["parameters"]["redact_values"] = True
    assert candidate["steps"] == expected_steps
    assert candidate["start"] == original["start"]
    assert candidate["edges"] == original["edges"]
    assert candidate["evidence_refs"] == ["policy", "result", "cleanup"]
    chosen = actual["reconsideration"]["reconsidered_choices"]
    assert len(chosen) == 1
    assert {key: chosen[0][key] for key in ("attempt_id", "compiled_digest", "step_id")} == {
        key: history["choices"][1][key] for key in ("attempt_id", "compiled_digest", "step_id")
    }
    source = history["attempts"][0]["findings"][0]
    assert chosen[0]["finding_refs"] == [{key: source[key] for key in ("finding_id", "record_ref")}]
    assert source["step_id"] == "stage_records"
    assert source["finding_id"] not in candidate["evidence_refs"]
    assert [
        row["prerequisite"] for row in actual["reconsideration"]["refresh_requirements"]
    ] == list(REFRESH_PREREQUISITES)
    assert (
        "historical findings" in actual["reconsideration"]["refresh_requirements"][0]["explanation"]
    )


@pytest.mark.parametrize("schema", [OUTPUT_SCHEMA, {"type": "object"}])
def test_receiver_evidence_fixture_requires_its_distinct_output_schema(schema) -> None:
    request = receiver_evidence_request()
    request["text"]["format"]["schema"] = schema
    assert not receiver_allowed(request, index=1, purpose=_RECEIVER_EVIDENCE_PURPOSE)
    original = receiver_request()
    original["text"]["format"]["schema"] = EVIDENCE_OUTPUT_SCHEMA
    assert not receiver_allowed(original)


@pytest.mark.parametrize("evidence", [False, True])
def test_receiver_fixture_refuses_context_crossed_between_purposes(evidence: bool) -> None:
    request = receiver_evidence_request() if evidence else receiver_request()
    request["text"]["format"]["name"] = (
        _RECEIVER_COMPOSITION_PURPOSE if evidence else _RECEIVER_EVIDENCE_PURPOSE
    )
    with pytest.raises(ValueError):
        _receiver_fixture_output_for_request(request)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(revision=False),
        lambda value: value.update(initial_proposal={}),
        lambda value: value.update(schema_version="bluefire.composition-model-context.v1"),
        lambda value: value["facts"].pop(),
        lambda value: value["facts"].__setitem__(1, deepcopy(value["facts"][0])),
        lambda value: value["facts"][1].update(evidence_ref="policy"),
        lambda value: value["facts"][1].update(provenance="synthetic"),
        lambda value: value["facts"][1]["value"].update(decision="accepted"),
        lambda value: value["facts"][1]["value"].update(policy_digest=content_hash("changed")),
        lambda value: value["facts"][2]["value"].update(run="incomplete"),
        lambda value: value["methods"][5]["parameter_domains"].update(port=[65534]),
        lambda value: value["historical_context"]["choices"].pop(),
        lambda value: value["historical_context"]["choices"][1]["parameters"].update(
            redact_values=True
        ),
        lambda value: value["historical_context"]["choices"][1].update(
            compiled_digest=content_hash("foreign")
        ),
        lambda value: value["historical_context"]["attempts"][0].update(findings=[]),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0].update(
            provenance="synthetic"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0].update(
            step_id="transform_fixture"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0].update(
            finding_id="finding-" + "0" * 64
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0][
            "record_ref"
        ].update(run_id="other-run"),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].update(
            size_bytes=0
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].pop(
            "sha256"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].pop(
            "size_bytes"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].update(
            size_bytes=True
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0].update(
            semantic_kind="observed_collection"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0][
            "applicability"
        ].update(status="current"),
    ],
)
def test_receiver_evidence_fixture_refuses_missing_stale_or_mismatched_support(mutation) -> None:
    request = receiver_evidence_request()
    context = json.loads(request["input"])
    mutation(context)
    request["input"] = json.dumps(context)
    with pytest.raises(ValueError):
        _receiver_fixture_output_for_request(request)


def test_receiver_evidence_fixture_uses_supplied_current_fact_names() -> None:
    request = receiver_evidence_request()
    context = json.loads(request["input"])
    for index, fact in enumerate(context["facts"]):
        fact["evidence_ref"] = f"fresh-{index}"
    request["input"] = json.dumps(context)
    actual = _receiver_fixture_output_for_request(request)
    assert actual["candidate"]["evidence_refs"] == ["fresh-0", "fresh-1", "fresh-2"]


def test_retained_fixture_initial_keeps_real_unredacted_graph_and_no_history() -> None:
    request = receiver_retained_request()
    before = deepcopy(request)
    value = json.loads(request["input"])
    result = _receiver_fixture_output_for_request(request)
    assert request == before
    assert result == {
        "schema_version": "bluefire.retained-composition-proposal.v1",
        "candidate": value["initial_proposal"],
        "reconsideration": None,
    }
    assert result["candidate"]["steps"][1]["parameters"] == {"redact_values": False}
    assert all(row["behavior_id"] != RETAINED_METHOD for row in result["candidate"]["steps"])


def test_retained_fixture_continuation_materializes_exact_bundle_without_recreating_source() -> (
    None
):
    request = receiver_retained_request(revision=True)
    before = deepcopy(request)
    value = json.loads(request["input"])
    source = value["retained_artifacts"]["available_sources"][0]
    result = _receiver_fixture_output_for_request(request)
    assert request == before
    assert result["schema_version"] == "bluefire.retained-composition-proposal.v1"
    candidate = result["candidate"]
    original = _receiver_fixture_output_for_request(receiver_request())
    assert candidate["start"] == "reuse_retained_bundle"
    assert candidate["steps"][0] == {
        "id": "reuse_retained_bundle",
        "behavior_id": RETAINED_METHOD,
        "parameters": {"source_ref": source["source_ref"]},
    }
    expected_steps = deepcopy(original["steps"][1:])
    expected_steps[0]["parameters"] = {"redact_values": True}
    assert candidate["steps"][1:] == expected_steps
    assert all(row["behavior_id"] != METHODS[0] for row in candidate["steps"])
    expected_edges = deepcopy(original["edges"])
    expected_edges[0]["from_step"] = "reuse_retained_bundle"
    assert candidate["edges"] == expected_edges
    assert candidate["evidence_refs"] == ["policy", "result", "cleanup"]
    chosen = result["reconsideration"]["reconsidered_choices"][0]
    finding = value["historical_context"]["attempts"][0]["findings"][0]
    assert finding["semantic_kind"] == "observed_filesystem"
    assert set(finding["summary"]) == {"sha256", "size_bytes"}
    assert value["facts"][1]["kind"] == "receiver_result"
    assert value["facts"][1]["value"]["decision"] == "policy_refused"
    assert value["facts"][1]["value"]["retained_record_count"] == 8
    assert chosen["step_id"] == "transform_fixture"
    assert chosen["attempt_id"] == source["attempt_id"]
    assert chosen["finding_refs"] == [
        {"finding_id": finding["finding_id"], "record_ref": finding["record_ref"]}
    ]
    assert source["source_ref"] not in candidate["evidence_refs"]
    assert finding["finding_id"] not in candidate["evidence_refs"]
    assert "payload_hex" not in json.dumps(result)
    assert [
        row["prerequisite"] for row in result["reconsideration"]["refresh_requirements"]
    ] == list(REFRESH_PREREQUISITES)


@pytest.mark.parametrize("index,revision", [(2, False), (3, True)])
@pytest.mark.parametrize(
    "mutation",
    [
        lambda request: request["text"]["format"].update(schema=OUTPUT_SCHEMA),
        lambda request: request["text"]["format"].update(schema=EVIDENCE_OUTPUT_SCHEMA),
        lambda request: request["text"]["format"].update(name=_RECEIVER_COMPOSITION_PURPOSE),
        lambda request: request.update(max_output_tokens=1025),
        lambda request: request.update(input="not-json"),
    ],
)
def test_retained_fixture_request_rejects_wrong_schema_phase_or_output_limit(
    index, revision, mutation
) -> None:
    request = receiver_retained_request(revision=revision)
    mutation(request)
    assert not receiver_allowed(request, index=index, purpose=_RECEIVER_RETAINED_PURPOSE)


def test_retained_fixture_request_rejects_byte_overflow_and_credentials() -> None:
    request = receiver_retained_request(revision=True)
    assert not receiver_allowed(
        request, index=3, purpose=_RECEIVER_RETAINED_PURPOSE, body_bytes=262_145
    )
    assert not receiver_allowed(
        request, index=3, purpose=_RECEIVER_RETAINED_PURPOSE, body_bytes=100, total_bytes=1_048_477
    )
    assert not receiver_allowed(
        request, index=3, purpose=_RECEIVER_RETAINED_PURPOSE, auth="Bearer unexpected"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["retained_artifacts"].update(availability="available"),
        lambda value: value["retained_artifacts"]["policy"].update(max_bytes_per_artifact=1),
        lambda value: value.update(historical_context={}),
        lambda value: value["initial_proposal"]["steps"][1]["parameters"].update(
            redact_values=True
        ),
        lambda value: value["initial_proposal"]["edges"].pop(),
        lambda value: value["initial_proposal"].update(evidence_refs=["made-up"]),
        lambda value: value["initial_proposal"].update(evidence_refs="[EVIDENCE CONTENT OMITTED]"),
        lambda value: value.update(payload_hex="00"),
    ],
)
def test_retained_fixture_initial_refuses_changes_to_scope_or_metadata(mutation) -> None:
    request = receiver_retained_request()
    value = json.loads(request["input"])
    mutation(value)
    request["input"] = json.dumps(value)
    with pytest.raises(ValueError):
        _receiver_fixture_output_for_request(request)


def _change_retained_source(value, **changes) -> None:
    source = value["retained_artifacts"]["available_sources"][0]
    source.update(changes)
    source["source_ref"] = content_hash(
        {key: item for key, item in source.items() if key != "source_ref"}
    )


def test_known_refusal_fixture_does_not_invent_a_receiver_decision_from_an_unknown_result() -> None:
    from bluefire.ai_composition_evidence_data import validate_retained_model_context

    request = receiver_retained_request(revision=True)
    value = json.loads(request["input"])
    source = value["retained_artifacts"]["available_sources"][0]
    value["facts"][1].update(
        kind="retained_artifact_result",
        value={
            "source": deepcopy(source),
            "prior_run_id": source["run_id"],
            "later_failure": {"step_id": "handoff_to_receiver", "outcome": "failed"},
            "receiver_decision": "unknown",
        },
    )
    validate_retained_model_context(value)
    request["input"] = json.dumps(value)
    with pytest.raises(ValueError):
        _receiver_fixture_output_for_request(request)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["retained_artifacts"].update(
            available_sources=[], availability="none_available"
        ),
        lambda value: value["retained_artifacts"].update(availability="none_available"),
        lambda value: value["retained_artifacts"]["available_sources"].append(
            deepcopy(value["retained_artifacts"]["available_sources"][0])
        ),
        lambda value: _change_retained_source(
            value, run_id="run-20261029T123457Z-1123456789abcdef"
        ),
        lambda value: _change_retained_source(value, attempt_id="attempt-" + "d" * 32),
        lambda value: _change_retained_source(value, step_id="transform_fixture"),
        lambda value: _change_retained_source(value, sha256="b" * 64),
        lambda value: _change_retained_source(value, size_bytes=673),
        lambda value: _change_retained_source(value, size_bytes=0),
        lambda value: _change_retained_source(value, size_bytes=262_145),
        lambda value: _change_retained_source(value, artifact_type="artifact.sandbox.workspace.v1"),
        lambda value: value["retained_artifacts"]["available_sources"][0].update(
            source_ref="sha256:" + "0" * 64
        ),
        lambda value: value["retained_artifacts"]["available_sources"][0].update(payload_hex="00"),
        lambda value: value["facts"][1]["value"].update(decision="unknown"),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].pop(
            "sha256"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].pop(
            "size_bytes"
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0]["summary"].update(
            size_bytes=0
        ),
        lambda value: value["historical_context"]["attempts"][0]["findings"][0].update(
            semantic_kind="observed_collection"
        ),
        lambda value: value.update(historical_context=None),
    ],
)
def test_retained_fixture_continuation_refuses_unavailable_or_mismatched_original_bytes(
    mutation,
) -> None:
    request = receiver_retained_request(revision=True)
    value = json.loads(request["input"])
    mutation(value)
    request["input"] = json.dumps(value)
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
