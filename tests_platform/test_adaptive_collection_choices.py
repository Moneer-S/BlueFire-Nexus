"""Authored software cases for real catalog methods; no live model or lab effects."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.adaptive_execution import compile_adaptive_authorization, validate_selected_method
from bluefire.adaptive_record_validation import validate_v4_attempt_record
from bluefire.adaptive_runtime import propose_reviewed_method
from bluefire.ai import AIProposal, AIProviderResult, validate_persisted_proposal_record
from bluefire.config import AIProviderConfig, AutonomyLevel, load_config
from bluefire.contracts import ExecutionMode, ScenarioDefinition, StepOutcome, load_scenario
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.planner import DeterministicPlanner
from bluefire.registry import load_builtin_registry
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]
JSONL = "sandbox.collection.records.v1"
GZIP = "sandbox.collection.atomic-gzip.v1"
USTAR = "sandbox.collection.archive.v1"
LIMIT = 1024
OBJECTIVE = "Retain all eight original sample values within 1024 output bytes, then clean up."
NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)
RUN_ID = "run-20260912T000000Z-0000000000000020"


class AuthoredSizeProvider:
    """Choose from the request's actual size projection, without a transport."""

    def __init__(self):
        self.config = AIProviderConfig.from_mapping(
            {"id": "test.collection-choice.v1", "kind": "deterministic", "model": "authored-case"}
        )
        self.requests = []

    def propose(self, request):
        self.requests.append(request)
        options = request.context["registered_options"]
        assert {item["action_id"] for item in options} == {JSONL, GZIP}
        limits = {item["plan_step"]["parameters"]["max_collection_bytes"] for item in options}
        assert limits == {LIMIT}
        source = request.context["observations"]["attempts"][0]["evidence"][0]
        # Reported execution stays reported; it is never relabeled independent observation.
        size_field = "size_bytes" if source["provenance"] == "observed" else "reported_size_bytes"
        action_id = JSONL if source["facts"][size_field] <= LIMIT else GZIP
        selected = next(item for item in options if item["action_id"] == action_id)
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "select_registered_action",
                "selected_step_id": selected["step_id"],
                "selected_behavior_id": selected["behavior_id"],
                "selected_action_id": action_id,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Authored software choice from source size; compression success remains unknown.",
                "alternatives": [],
                "confidence": 0.8,
                "requires_operator_review": False,
            }
        )
        return AIProviderResult(
            self.config.id,
            self.config.id,
            self.config.model,
            proposal,
            "authored-software-response",
            1,
            False,
            None,
            {},
        )


def reviewed_experiment():
    registry = load_builtin_registry()
    planner = DeterministicPlanner(registry)
    raw = load_scenario(ROOT / "scenarios/atomic_gzip_collection.yaml").to_dict()
    raw["purpose"] = OBJECTIVE
    collection = next(step for step in raw["steps"] if step["id"] == "stage_collection")
    collection.update(
        behavior_id=USTAR,
        alternates=[JSONL, GZIP],
        parameters={"stage_variant": "primary", "max_collection_bytes": LIMIT},
    )
    raw["adaptive_execution"] = {
        "schema_version": "bluefire.adaptive-execution.v1",
        "steps": [
            {
                "step_id": "stage_collection",
                "methods": [
                    {"behavior_id": method, "action_id": method} for method in (USTAR, JSONL, GZIP)
                ],
            }
        ],
        "eligible_outcomes": ["blocked", "failed"],
        "max_retries": 1,
        "on_provider_failure": "stop",
    }
    scenario = ScenarioDefinition.from_mapping(raw)
    profile = next(
        item
        for item in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if item.id == "sandbox-execute.v1"
    )
    plan = planner.compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile, autonomy=AutonomyLevel.AUTO
    )
    scope = {"scope_refs": ["sandbox.workspace"]}
    authority = compile_adaptive_authorization(
        registry=registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=scope,
        platform="linux",
        planner=planner,
    )
    assert authority is not None
    return registry, planner, scenario, profile, plan, scope, authority


def authored_source(plan, *, size, provenance):
    """Model the existing collector/runner envelopes, not an observed lab execution."""
    step = next(item for item in plan.steps if item.step_id == "transform_fixture")
    source_digest = content_hash({"authored_source_size": size}).removeprefix("sha256:")
    if provenance is EvidenceProvenance.OBSERVED:
        fields = {"path": "fixtures/transformed.jsonl", "size_bytes": size, "sha256": source_digest}
        content = {
            **fields,
            "artifact_type": "collector_observation",
            "observation_kind": "filesystem",
            "observed_fields": fields,
            "mechanism": "independent-file-handle-read",
        }
        producer = "collector.filesystem.sandbox.v1"
    else:
        content = {
            "runner_status": "success",
            "output": {
                "artifact": "fixtures/transformed.jsonl",
                "size": size,
                "sha256": source_digest,
                "record_count": 8,
            },
        }
        producer = "bluefire-rust-runner"
    content.update(stdout="private-log-fixture", credential="private-key-fixture")
    record = EvidenceRecord.create(
        run_id=RUN_ID,
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action_id=step.action_id,
        provenance=provenance,
        producer=producer,
        runner_profile_id=plan.runner_profile_id,
        target_scope_ref="sandbox.workspace",
        content=content,
        timestamp=NOW.isoformat(),
        limitations=("Authored test envelope; not live-provider or lab evidence.",),
    )
    row = {
        "step_id": step.step_id,
        "behavior_id": step.behavior_id,
        "action_id": step.action_id,
        "status": "success",
        "evidence_ids": [record.evidence_id],
    }
    artifacts = {
        "select_records": {
            "records": [
                {
                    "type": "artifact.sandbox.discovery.records.v1",
                    "kind": "file",
                    "path": "fixtures/transformed.jsonl",
                    "record_count": 8,
                    "sha256": source_digest,
                }
            ]
        }
    }
    return row, record, artifacts


@pytest.mark.parametrize("provenance", [EvidenceProvenance.OBSERVED, EvidenceProvenance.EXECUTED])
def test_real_collection_choices_change_with_source_size_without_widening_authority(provenance):
    registry, planner, scenario, profile, plan, scope, authority = reviewed_experiment()
    retained_plan, retained_authority = deepcopy(plan.to_dict()), deepcopy(authority)
    current = next(step for step in plan.steps if step.step_id == "stage_collection")
    provider = AuthoredSizeProvider()
    choices = []
    for size, expected in ((700, JSONL), (1400, GZIP)):
        source_row, source, artifacts = authored_source(plan, size=size, provenance=provenance)
        rows = [
            source_row,
            {
                "step_id": current.step_id,
                "behavior_id": current.behavior_id,
                "action_id": current.action_id,
                "status": "blocked",
                "evidence_ids": [],
                "error": {"code": "collection_output_limit"},
                "policy": {"status": "allowed"},
            },
        ]
        retained_inputs = deepcopy(artifacts)
        decision = planner.decide_next(
            run_id=RUN_ID,
            scenario=scenario,
            plan=plan,
            current_step_id=current.step_id,
            outcome=StepOutcome.BLOCKED,
            state={"steps": rows, "artifacts": artifacts},
            completed_steps=4,
        )
        validated = []

        def recheck(step, *, is_retry=True, validated=validated):
            choice = validate_selected_method(
                authorization=authority,
                expected_authorization_digest=authority["authorization_digest"],
                step=step,
                profile=profile,
                target_scope=scope,
                platform="linux",
                registry=registry,
                remaining_steps=2,
                remaining_seconds=20.0,
                retries_used=0 if is_retry else 1,
                approval_expires_at=(NOW + timedelta(minutes=5)).isoformat(),
                now=NOW,
                is_retry=is_retry,
            )
            validated.append(choice)
            return choice

        result = propose_reviewed_method(
            run_id=RUN_ID,
            plan=plan,
            current_step=current,
            outcome="blocked",
            decision=decision,
            authorization=authority,
            policy=authority["policy"],
            provider=provider,
            steps=rows,
            evidence=[source],
            artifacts=artifacts,
            platform="linux",
            remaining_steps=2,
            remaining_seconds=20.0,
            retries_used=0,
            validate_choice=recheck,
            check_cancelled=lambda: None,
        )
        assert not result.stop and result.selected_step is not None
        selected = result.selected_step
        assert selected.action_id == selected.behavior_id == expected
        assert len(validated) == 1
        assert recheck(selected, is_retry=False) == validated[0]
        assert selected.inputs == current.inputs
        assert (
            selected.parameters
            == current.parameters
            == {
                "stage_variant": "primary",
                "max_collection_bytes": LIMIT,
            }
        )
        assert selected.to_dict() == validated[0]["plan_step"]
        assert set(selected.required_capabilities) <= set(validated[0]["capabilities"])
        assert set(validated[0]["capabilities"]) <= set(profile.capabilities)
        assert selected.expected_outputs == current.expected_outputs
        assert artifacts == retained_inputs and plan.to_dict() == retained_plan
        assert authority == retained_authority
        request = provider.requests[-1]
        assert request.objective == plan.objective == OBJECTIVE
        assert request.allowed_step_ids == (current.step_id,)
        assert set(request.allowed_action_ids) == {JSONL, GZIP}
        projection = request.context["observations"]
        projected = projection["attempts"][0]["evidence"][0]
        assert projected["evidence_id"] == source.evidence_id
        assert projected["record_hash"] == source.record_hash
        assert projected["provenance"] == provenance.value
        size_field = (
            "size_bytes" if provenance is EvidenceProvenance.OBSERVED else "reported_size_bytes"
        )
        assert projected["facts"][size_field] == size
        assert ("reported_size_bytes" not in projected["facts"]) is (
            provenance is EvidenceProvenance.OBSERVED
        )
        failure = projection["attempts"][-1]["failure"]
        assert failure["classification"] == "resource_limit"
        assert failure["target_prevention"] == "not_established"
        assert projection["remaining_budgets"] == {"steps": 2, "seconds": 20.0, "retries": 1}
        assert (
            "Reported execution alone does not independently verify the objective."
            in projection["unknowns"]
        )
        encoded = canonical_json_bytes(projection)
        assert (
            b"private" not in encoded and b"stdout" not in encoded and b"credential" not in encoded
        )
        record = result.record
        assert record["authorization_digest"] == authority["authorization_digest"]
        assert record["decision_source"] == "deterministic_provider"
        assert record["provider_attempt"]["kind"] == "deterministic"
        assert record["provider"]["used_fallback"] is False
        assert record["application_status"] == "applied_reviewed_method"
        assert record["applied_step"] == selected.to_dict()
        assert record["planner_state"] == request.context
        assert validate_v4_attempt_record(record) == request.context
        assert validate_persisted_proposal_record(record).selected_action_id == expected
        choices.append(selected.action_id)
    assert choices == [JSONL, GZIP]
