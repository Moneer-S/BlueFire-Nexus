from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.ai import (
    AIProposal,
    AIProposalRequest,
    AIProviderHealth,
    AIProviderResult,
    DeterministicOfflineProvider,
    build_ai_provider,
)
from bluefire.api import APIError
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel, load_config
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.job_runtime import JobState
from bluefire.orchestrator import Orchestrator
from bluefire.registry import BehaviorRegistry, load_builtin_registry
from bluefire.run_store import RunStore
from bluefire.runner_contracts import current_platform
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.service import BlueFireService
from bluefire.simulation import SimulationError, SimulationRegistry
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]
EXECUTE_ACTIONS = {
    "endpoint.discovery.processes.v1",
    "endpoint.discovery.system.v1",
    "sandbox.archive.tar.v1",
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.discovery.recursive.v1",
    "sandbox.execution.native-canary.v1",
    "sandbox.identity-material.inspect.v1",
    "sandbox.identity-material.seed.v1",
    "sandbox.observability.variant.v1",
    "sandbox.peer.handoff.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
    "sandbox.cleanup.v1",
}
SECURE_RECEIPT_EXECUTION_TIMEOUT = 60


def _write_bound_receipt(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> str:
    sandbox_root = Path(str(profile["sandbox_root"]))
    receipt_root = sandbox_root / ".bluefire" / "receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    workspace_id = hashlib.sha256(
        str(sandbox_root.resolve(strict=True)).replace("\\", "/").encode("utf-8")
    ).hexdigest()
    action_id = str(manifest["action_id"])
    params = manifest.get("params")
    params = params if isinstance(params, Mapping) else {}
    if action_id == "sandbox.fixture.create.v1":
        owned_path = str(params.get("path", "fixtures/input.jsonl"))
    elif action_id == "sandbox.fixture.transform.v1":
        owned_path = str(params.get("output", "fixtures/transformed.jsonl"))
    elif action_id == "sandbox.collection.stage.v1":
        owned_path = f"staged/bundle.{params.get('bundle_format', 'jsonl')}"
    else:
        owned_path = f"exports/{params.get('retention_label', 'ephemeral')}/bundle.bin"
    identity = {
        "schema_version": "bluefire.receipt/v1",
        "request_hash": manifest["request_hash"],
        "action_id": action_id,
        "runner_profile_id": profile["profile_id"],
        "workspace_id": workspace_id,
        "created_at": "2026-08-24T00:00:00Z",
        "paths": [
            {
                "relative_path": owned_path,
                "kind": "file",
                "sha256": "0" * 64,
                "size": 0,
            }
        ],
    }
    receipt_id = content_hash(identity).removeprefix("sha256:")
    (receipt_root / f"{receipt_id}.json").write_bytes(
        canonical_json_bytes({"receipt_id": receipt_id, **identity})
    )
    commit_root = sandbox_root / ".bluefire" / "receipt-commits"
    commit_root.mkdir(parents=True, exist_ok=True)
    (commit_root / f"{receipt_id}.json").write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "bluefire.receipt-commit/v1",
                "receipt_id": receipt_id,
                "runner_profile_id": profile["profile_id"],
                "workspace_id": workspace_id,
                "committed_at": "2026-08-24T00:00:01Z",
            }
        )
    )
    return receipt_id


class ProposalLifecycleRunner:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.record_count = 6

    def inventory(self) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "runner_id": "bluefire-proposal-test-runner.v1",
            "runner_version": "test-1.0.0",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "platform": current_platform(),
            "actions": [
                {
                    "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                    "action_id": action_id,
                    "action_version": BUILTIN_RUNNER_ACTION_VERSIONS[action_id],
                    "readiness": "ready",
                }
                for action_id in sorted(EXECUTE_ACTIONS)
            ],
        }

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        action_id = str(manifest["action_id"])
        self.calls.append(action_id)
        if action_id == "sandbox.fixture.create.v1":
            self.record_count = int(manifest["params"].get("record_count", 6))
        outputs: dict[str, Mapping[str, Any]] = {
            "sandbox.fixture.create.v1": {
                "artifact": "fixtures/input.jsonl",
                "sha256": "1" * 64,
                "size": 128,
                "template": "telemetry-seed",
                "record_count": self.record_count,
                "format": "jsonl",
            },
            "sandbox.fixture.transform.v1": {
                "artifact": "fixtures/transformed.jsonl",
                "sha256": "2" * 64,
                "size": 128,
                "record_count": self.record_count,
                "redact_values": manifest["params"].get("redact_values", True),
                "redacted_value_count": (
                    self.record_count if manifest["params"].get("redact_values", True) else 0
                ),
                "format": "jsonl",
                "implementation": "in_process_reviewed_jsonl_transform",
            },
            "sandbox.discovery.list.v1": {
                "path": "fixtures/transformed.jsonl",
                "entries": [
                    {
                        "path": "fixtures/transformed.jsonl",
                        "name": "transformed.jsonl",
                        "kind": "file",
                        "size": 16,
                    }
                ],
                "returned_entries": 1,
                "target_cardinality": "one",
            },
            "sandbox.discovery.metadata.v1": {
                "entries": [
                    {
                        "path": "fixtures/transformed.jsonl",
                        "name": "transformed.jsonl",
                        "kind": "file",
                        "size": 16,
                        "readonly": True,
                    }
                ],
                "path": "fixtures/transformed.jsonl",
                "returned_entries": 1,
                "target_cardinality": "one",
            },
            "sandbox.collection.stage.v1": {
                "artifact": f"staged/bundle.{manifest['params'].get('bundle_format', 'jsonl')}",
                "format": manifest["params"].get("bundle_format", "jsonl"),
                "record_count": self.record_count,
                "size": 16,
                "sha256": "3" * 64,
                "input_count": 1,
                "accepted_input_count": 1,
                "rejected_input_count": 0,
                "complete": True,
            },
            "sandbox.network.loopback.v1": {"bytes_sent": 16},
            "sandbox.export.local.v1": {
                "artifact": (
                    f"exports/{manifest['params'].get('retention_label', 'ephemeral')}/bundle.bin"
                ),
                "source": manifest["params"].get("source"),
                "size": 16,
                "retention_label": manifest["params"].get("retention_label", "ephemeral"),
                "sha256": "4" * 64,
                "destination_policy": "runner_fixed_retention_destination",
            },
            "sandbox.cleanup.v1": {},
        }
        mutating = {
            "sandbox.fixture.create.v1",
            "sandbox.fixture.transform.v1",
            "sandbox.collection.stage.v1",
            "sandbox.export.local.v1",
        }
        receipts = [_write_bound_receipt(manifest, profile)] if action_id in mutating else []
        cleanup_report = None
        if action_id == "sandbox.cleanup.v1":
            requested = list(manifest["params"].get("receipt_ids", []))
            receipt_root = Path(str(profile["sandbox_root"])) / ".bluefire" / "receipts"
            commit_root = Path(str(profile["sandbox_root"])) / ".bluefire" / "receipt-commits"
            for receipt_id in requested:
                (receipt_root / f"{receipt_id}.json").unlink(missing_ok=True)
                (commit_root / f"{receipt_id}.json").unlink(missing_ok=True)
            cleanup_report = {
                "requested_receipts": len(requested),
                "removed_paths": [],
                "already_absent_receipts": [],
                "retained_paths": [],
                "errors": [],
                "verification_performed": True,
                "verified_removed_paths": 0,
                "verified_absent_paths": 0,
                "verified_receipts": len(requested),
            }
            outputs[action_id] = cleanup_report
        return {
            "schema_version": "bluefire.runner-result.v1",
            "request_id": manifest["request_id"],
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": action_id,
            "runner_id": manifest["runner_id"],
            "runner_profile_id": manifest["runner_profile_id"],
            "request_hash": manifest["request_hash"],
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": "success",
            "output": outputs[action_id],
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "proposal-lifecycle-fake", "status": "success"}],
            "receipt_ids": receipts,
            "cleanup": cleanup_report,
            "error": None,
            "limitations": ["Structured fake; no side effect occurred."],
        }


class AlternateProposalProvider:
    def __init__(self, config: AIProviderConfig) -> None:
        self.config = config
        self.offline = DeterministicOfflineProvider(config)
        self.requests: list[AIProposalRequest] = []

    def health(self) -> AIProviderHealth:
        return self.offline.health()

    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        self.requests.append(request)
        alternate_id = "sandbox.discovery.metadata.v1"
        if alternate_id not in request.allowed_behavior_ids:
            return self.offline.propose(request)
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "select_registered",
                "selected_step_id": "discover_records",
                "selected_behavior_id": alternate_id,
                "selected_action_id": None,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Use the graph-registered metadata alternate.",
                "alternatives": [],
                "confidence": 0.9,
                "requires_operator_review": request.autonomy is AutonomyLevel.ASSIST,
            }
        )
        request.validate_proposal(proposal)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id="scripted-registered-alternate",
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class RepeatingTransport:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls = 0

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        self.calls += 1
        return self.payload


class ReviewRequiredAutoProvider(AlternateProposalProvider):
    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        self.requests.append(request)
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "select_registered",
                "selected_step_id": request.allowed_step_ids[0],
                "selected_behavior_id": request.allowed_behavior_ids[0],
                "selected_action_id": None,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Require explicit review even though this option is registered.",
                "alternatives": [],
                "confidence": 0.75,
                "requires_operator_review": True,
            }
        )
        request.validate_proposal(proposal)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id="scripted-review-required",
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class ParameterProposalProvider(AlternateProposalProvider):
    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        self.requests.append(request)
        schemas = request.allowed_parameter_schemas.get("transform_fixture")
        if not schemas or "redact_values" not in schemas:
            return self.offline.propose(request)
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "change_parameters",
                "selected_step_id": "transform_fixture",
                "selected_behavior_id": "sandbox.fixture.transform.v1",
                "selected_action_id": None,
                "selected_edge": None,
                "parameter_changes": [{"name": "redact_values", "value": False}],
                "rationale": "Use the registered boolean parameter value.",
                "alternatives": [],
                "confidence": 0.9,
                "requires_operator_review": request.autonomy is AutonomyLevel.ASSIST,
            }
        )
        request.validate_proposal(proposal)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id="scripted-typed-parameter",
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class RetryProposalProvider(AlternateProposalProvider):
    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        self.requests.append(request)
        if not request.retryable_step_ids:
            return self.offline.propose(request)
        step_id = request.retryable_step_ids[0]
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "retry_registered",
                "selected_step_id": step_id,
                "selected_behavior_id": request.allowed_behavior_ids[0],
                "selected_action_id": None,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Use the single registered adaptive retry.",
                "alternatives": [],
                "confidence": 0.9,
                "requires_operator_review": request.autonomy is AutonomyLevel.ASSIST,
            }
        )
        request.validate_proposal(proposal)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id="scripted-bounded-retry",
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class ActionProposalProvider(AlternateProposalProvider):
    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        self.requests.append(request)
        selected_action = "sandbox.discovery.metadata.v1"
        if (
            "discover_records" not in request.allowed_step_ids
            or selected_action not in request.allowed_action_ids
        ):
            return self.offline.propose(request)
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "select_registered_action",
                "selected_step_id": "discover_records",
                "selected_behavior_id": "sandbox.discovery.list.v1",
                "selected_action_id": selected_action,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Select the other registered profile-enabled implementation.",
                "alternatives": [],
                "confidence": 0.9,
                "requires_operator_review": True,
            }
        )
        request.validate_proposal(proposal)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id="scripted-registered-action",
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class NextNodeProposalProvider(AlternateProposalProvider):
    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        self.requests.append(request)
        if not request.allowed_edges:
            return self.offline.propose(request)
        edge = request.allowed_edges[0]
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "select_next_node",
                "selected_step_id": edge["to_step"],
                "selected_behavior_id": request.allowed_behavior_ids[0],
                "selected_action_id": None,
                "selected_edge": dict(edge),
                "parameter_changes": [],
                "rationale": "Select only the exact edge registered for the observed outcome.",
                "alternatives": [],
                "confidence": 1.0,
                "requires_operator_review": False,
            }
        )
        request.validate_proposal(proposal)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id="scripted-registered-next-node",
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class FailFirstSimulations:
    def __init__(self, *, failures: int) -> None:
        self.delegate = SimulationRegistry()
        self.failures = failures
        self.attempts = 0

    def execute(self, step, *, bound_inputs):
        if step.step_id == "create_persistence_canary":
            self.attempts += 1
            if self.attempts <= self.failures:
                raise SimulationError("bounded injected simulation failure")
        return self.delegate.execute(step, bound_inputs=bound_inputs)


def _invalid_response() -> bytes:
    proposal: dict[str, Any] = {
        "schema_version": "bluefire.ai-proposal.v2",
        "proposal_type": "select_registered",
        "selected_step_id": "unregistered_step",
        "selected_behavior_id": "unregistered.behavior.v1",
        "selected_action_id": None,
        "selected_edge": None,
        "parameter_changes": [],
        "rationale": "Attempt to leave the request allowlist.",
        "alternatives": [],
        "confidence": 0.9,
        "requires_operator_review": False,
    }
    return canonical_json_bytes(
        {
            "id": "resp_invalid_allowlist",
            "model": "gpt-4o-mini",
            "status": "completed",
            "error": None,
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": canonical_json_bytes(proposal).decode("utf-8"),
                        }
                    ],
                }
            ],
            "usage": {"input_tokens": 20, "output_tokens": 40, "total_tokens": 60},
        }
    )


def _request(autonomy: str, provider_id: str = "deterministic-offline.v1") -> dict[str, Any]:
    return {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "simulate",
        "autonomy": autonomy,
        "ai_provider_id": provider_id,
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
    }


def test_off_never_constructs_or_calls_a_proposal_provider(tmp_path: Path) -> None:
    factory_calls = 0

    def factory(config: AIConfig, provider_id: str) -> AlternateProposalProvider:
        nonlocal factory_calls
        factory_calls += 1
        return AlternateProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    result = service.run(_request("off"))

    assert factory_calls == 0
    assert result["ai_proposals"] == []
    assert not any(event["event_type"] == "ai.proposal" for event in result["events"])


@pytest.mark.parametrize(
    ("autonomy", "expected_behavior", "application_status"),
    [
        ("assist", "sandbox.discovery.list.v1", "awaiting_operator_approval"),
        ("auto", "sandbox.discovery.metadata.v1", "applied_registered_alternate"),
    ],
)
def test_assist_records_and_auto_applies_only_the_registered_alternate(
    tmp_path: Path,
    autonomy: str,
    expected_behavior: str,
    application_status: str,
) -> None:
    provider: AlternateProposalProvider | None = None

    def factory(config: AIConfig, provider_id: str) -> AlternateProposalProvider:
        nonlocal provider
        provider = AlternateProposalProvider(config.provider(provider_id))
        return provider

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    result = service.run(_request(autonomy))

    assert provider is not None
    assert provider.requests
    assert all(request.allowed_action_ids == () for request in provider.requests)
    proposal_record = next(
        record
        for record in result["ai_proposals"]
        if record["proposal"]
        and record["proposal"]["selected_behavior_id"] == "sandbox.discovery.metadata.v1"
    )
    assert proposal_record["application_status"] == application_status
    discovery = next(
        (row for row in result["steps"] if row["step_id"] == "discover_records"),
        None,
    )
    if autonomy == "assist":
        assert result["status"] == "awaiting_approval"
        assert discovery is None
    else:
        assert discovery is not None
        assert discovery["behavior_id"] == expected_behavior
    deterministic = next(
        decision
        for decision in result["planner_decisions"]
        if decision["selected_step_id"] == "discover_records"
    )
    assert deterministic["selected_behavior_id"] == "sandbox.discovery.list.v1"
    proposal_events = [event for event in result["events"] if event["event_type"] == "ai.proposal"]
    assert len(proposal_events) == len(result["ai_proposals"])


def test_invalid_remote_output_uses_deterministic_fallback_and_preserves_graph(
    tmp_path: Path,
) -> None:
    transport = RepeatingTransport(_invalid_response())

    def factory(config: AIConfig, provider_id: str):
        return build_ai_provider(
            config,
            provider_id=provider_id,
            environ={"OPENAI_API_KEY": "integration-test-key"},  # pragma: allowlist secret
            transport=transport,
            sleeper=lambda _delay: None,
        )

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    result = service.run(_request("auto", "openai-responses.v1"))

    assert transport.calls == len(result["ai_proposals"])
    assert all(record["provider"]["used_fallback"] for record in result["ai_proposals"])
    assert all(
        record["provider"]["effective_provider_id"] == "deterministic-offline.v1"
        for record in result["ai_proposals"]
    )
    discovery = next(row for row in result["steps"] if row["step_id"] == "discover_records")
    assert discovery["behavior_id"] == "sandbox.discovery.list.v1"


def test_auto_review_required_proposal_stops_before_graph_mutation(tmp_path: Path) -> None:
    def factory(config: AIConfig, provider_id: str) -> ReviewRequiredAutoProvider:
        return ReviewRequiredAutoProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    result = service.run(_request("auto"))

    assert result["status"] == "awaiting_approval"
    assert result["approval_pause"]["resume_requires_replan"] is True
    assert len(result["steps"]) == 1
    assert result["ai_proposals"][0]["application_status"] == "awaiting_operator_approval"
    assert any(event["event_type"] == "run.awaiting_approval" for event in result["events"])


def test_auto_review_required_job_remains_at_durable_proposal_gate(tmp_path: Path) -> None:
    def factory(config: AIConfig, provider_id: str) -> ReviewRequiredAutoProvider:
        return ReviewRequiredAutoProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )
    submission = service.submit_run(_request("auto"))
    job_id = str(submission["job"]["job_id"])
    awaiting = service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=5,
    )

    assert awaiting["state"] == "awaiting_approval"
    review = service.proposal_review(
        job_id,
        str(awaiting["progress"]["proposal_record_id"]),
    )
    assert review["status"] == "pending"
    service.cancel_job(job_id)
    assert service.job_controller.wait(job_id, timeout=5)["state"] == "cancelled"
    service.close()


def test_assist_proposal_acceptance_replans_and_resumes_simulate_job(tmp_path: Path) -> None:
    def factory(config: AIConfig, provider_id: str) -> AlternateProposalProvider:
        return AlternateProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )
    submission = service.submit_run(_request("assist"))
    job_id = str(submission["job"]["job_id"])
    awaiting = service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=5,
    )
    proposal_record_id = str(awaiting["progress"]["proposal_record_id"])
    review = service.proposal_review(job_id, proposal_record_id)
    decision = {
        "decided_by": "simulation-reviewer",
        "state_digest": review["state_digest"],
        "plan_digest": review["plan_digest"],
        "proposal_digest": review["proposal_digest"],
    }

    with pytest.raises(APIError) as tampered:
        service.accept_proposal_review(
            job_id,
            proposal_record_id,
            {**decision, "proposal_digest": "sha256:" + "0" * 64},
        )
    assert tampered.value.code == "proposal_acceptance_refused"
    assert service.job(job_id)["state"] == "awaiting_approval"

    accepted = service.accept_proposal_review(job_id, proposal_record_id, decision)
    assert accepted["proposal"]["status"] == "accepted"
    assert accepted["approval_request"] is None
    completed = service.job_controller.wait(job_id, timeout=5)
    assert completed["state"] == "completed", completed["error"]
    continuation = service.detail(str(completed["result_ref"]))
    discovery = next(row for row in continuation["steps"] if row["step_id"] == "discover_records")
    assert discovery["behavior_id"] == "sandbox.discovery.metadata.v1"
    assert continuation["replay"]["proposal_resolution"]["proposal_record_id"] == proposal_record_id
    with pytest.raises(APIError) as stale:
        service.accept_proposal_review(job_id, proposal_record_id, decision)
    assert stale.value.code == "proposal_acceptance_refused"
    service.close()


def test_assist_proposal_rejection_and_cancellation_do_not_resume(tmp_path: Path) -> None:
    def factory(config: AIConfig, provider_id: str) -> AlternateProposalProvider:
        return AlternateProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    def pending_job() -> tuple[str, Mapping[str, Any]]:
        submission = service.submit_run(_request("assist"))
        job_id = str(submission["job"]["job_id"])
        awaiting = service.job_controller.wait_for_state(
            job_id,
            {JobState.AWAITING_APPROVAL},
            timeout=5,
        )
        review = service.proposal_review(
            job_id,
            str(awaiting["progress"]["proposal_record_id"]),
        )
        return job_id, review

    rejected_job_id, review = pending_job()
    rejected = service.reject_proposal_review(
        rejected_job_id,
        str(review["proposal_record_id"]),
        {
            "decided_by": "simulation-reviewer",
            "state_digest": review["state_digest"],
            "plan_digest": review["plan_digest"],
            "proposal_digest": review["proposal_digest"],
        },
    )
    assert rejected["proposal"]["status"] == "rejected"
    finished = service.job_controller.wait(rejected_job_id, timeout=5)
    assert finished["state"] == "completed"
    assert finished["result_ref"] == review["source_run_id"]

    cancelled_job_id, cancelled_review = pending_job()
    service.cancel_job(cancelled_job_id)
    cancelled = service.job_controller.wait(cancelled_job_id, timeout=5)
    assert cancelled["state"] == "cancelled"
    assert (
        service.proposal_review(
            cancelled_job_id,
            str(cancelled_review["proposal_record_id"]),
        )["status"]
        == "pending"
    )
    service.close()


def test_execute_proposal_acceptance_requires_a_fresh_exact_approval(tmp_path: Path) -> None:
    runner = ProposalLifecycleRunner()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    def provider_factory(config: AIConfig, provider_id: str) -> AlternateProposalProvider:
        return AlternateProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
        ai_provider_factory=provider_factory,
    )
    profile = next(item for item in service.config.runner_profiles if item.mode.value == "execute")
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "assist",
            "target_scope": {"scope_refs": list(profile.scope)},
        }
    )
    job_id = str(submission["job"]["job_id"])
    service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=5,
    )
    original_approval_id = str(submission["approval_request"]["approval_id"])
    service.approve_job(job_id, {"approved_by": "initial-execute-reviewer"})
    proposal_gate = service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=SECURE_RECEIPT_EXECUTION_TIMEOUT,
    )
    proposal_record_id = str(proposal_gate["progress"]["proposal_record_id"])
    review = service.proposal_review(job_id, proposal_record_id)
    accepted = service.accept_proposal_review(
        job_id,
        proposal_record_id,
        {
            "decided_by": "proposal-reviewer",
            "state_digest": review["state_digest"],
            "plan_digest": review["plan_digest"],
            "proposal_digest": review["proposal_digest"],
        },
    )
    fresh_approval_id = str(accepted["approval_request"]["approval_id"])

    assert accepted["job"]["state"] == "awaiting_approval"
    assert fresh_approval_id != original_approval_id
    assert service.product_store.get_approval_request(original_approval_id)["status"] == "claimed"
    reloaded = service.job(job_id)
    assert reloaded["approval_request"]["approval_id"] == fresh_approval_id
    assert reloaded["approval_request"]["status"] == "pending"
    assert "nonce" not in reloaded["approval_request"]

    tampered_job = service.job(job_id)
    tampered_progress = dict(tampered_job["progress"])
    tampered_progress["approval_request_id"] = original_approval_id
    service.product_store.transition_job(
        job_id,
        "awaiting_approval",
        progress=tampered_progress,
    )
    with pytest.raises(APIError) as reused:
        service.approve_job(job_id, {"approved_by": "must-not-reuse"})
    assert reused.value.code == "approval_refused"
    tampered_progress["approval_request_id"] = fresh_approval_id
    service.product_store.transition_job(
        job_id,
        "awaiting_approval",
        progress=tampered_progress,
    )

    approved = service.approve_job(job_id, {"approved_by": "fresh-execute-reviewer"})
    assert approved["approval_request"]["approval_id"] == fresh_approval_id
    completed = service.job_controller.wait(job_id, timeout=SECURE_RECEIPT_EXECUTION_TIMEOUT)
    assert completed["state"] == "completed"
    assert service.product_store.get_approval_request(fresh_approval_id)["status"] == "claimed"
    continuation = service.detail(str(completed["result_ref"]))
    assert continuation["replay"]["proposal_resolution"]["proposal_record_id"] == (
        proposal_record_id
    )
    assert runner.calls
    service.close()


def test_auto_applies_registered_typed_parameter_change_in_simulate(tmp_path: Path) -> None:
    def factory(config: AIConfig, provider_id: str) -> ParameterProposalProvider:
        return ParameterProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    result = service.run(_request("auto"))

    transformed = next(row for row in result["steps"] if row["step_id"] == "transform_fixture")
    assert transformed["artifacts"]["fixture"]["redact_values"] is False
    proposal = next(
        item
        for item in result["ai_proposals"]
        if item.get("application_status") == "applied_typed_parameters"
    )
    assert proposal["proposal"]["parameter_changes"] == [{"name": "redact_values", "value": False}]
    assert proposal["applied_step"]["parameters"] == {"redact_values": False}
    assert proposal["proposal_policy_evaluation"]["status"] == "permitted"
    service.close()


def test_auto_next_node_selection_stays_on_the_observed_registered_edge(
    tmp_path: Path,
) -> None:
    def factory(config: AIConfig, provider_id: str) -> NextNodeProposalProvider:
        return NextNodeProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        ai_provider_factory=factory,
    )

    result = service.run(_request("auto"))

    selections = [
        item
        for item in result["ai_proposals"]
        if isinstance(item.get("proposal"), Mapping)
        and item["proposal"].get("proposal_type") == "select_next_node"
    ]
    assert selections
    assert all(
        item["application_status"] == "accepted_registered_next_node"
        and item["proposal"]["selected_edge"]["outcome"] == item["outcome"]
        and item["proposal"]["selected_edge"] in item["allowed_edges"]
        for item in selections
    )
    assert result["status"] == "completed"
    service.close()


def test_execute_registered_action_change_gets_fresh_approval_and_full_replay(
    tmp_path: Path,
) -> None:
    base_registry = load_builtin_registry()
    behavior_id = "sandbox.discovery.list.v1"
    registry = BehaviorRegistry(
        [
            (
                replace(
                    item,
                    action_ids=(
                        "sandbox.discovery.list.v1",
                        "sandbox.discovery.metadata.v1",
                    ),
                )
                if item.id == behavior_id
                else item
            )
            for item in (
                base_registry.get_behavior(item_id) for item_id in base_registry.behavior_ids
            )
        ],
        [base_registry.get_action(item_id) for item_id in base_registry.action_ids],
    )
    runner = ProposalLifecycleRunner()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    def provider_factory(config: AIConfig, provider_id: str) -> ActionProposalProvider:
        return ActionProposalProvider(config.provider(provider_id))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        registry=registry,
        runner_factory=lambda _profile: (runner, sandbox),
        ai_provider_factory=provider_factory,
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "assist",
            "target_scope": {"scope_refs": list(profile.scope)},
        }
    )
    job_id = str(submission["job"]["job_id"])
    original_approval_id = str(submission["approval_request"]["approval_id"])
    service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=5,
    )
    service.approve_job(job_id, {"approved_by": "initial-reviewer"})
    gate = service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=SECURE_RECEIPT_EXECUTION_TIMEOUT,
    )
    review = service.proposal_review(job_id, str(gate["progress"]["proposal_record_id"]))
    proposal = review["record"]["proposal"]
    assert proposal["proposal_type"] == "select_registered_action"
    assert proposal["selected_action_id"] == "sandbox.discovery.metadata.v1"

    accepted = service.accept_proposal_review(
        job_id,
        str(review["proposal_record_id"]),
        {
            "decided_by": "proposal-reviewer",
            "state_digest": review["state_digest"],
            "plan_digest": review["plan_digest"],
            "proposal_digest": review["proposal_digest"],
        },
    )
    fresh_approval_id = str(accepted["approval_request"]["approval_id"])
    assert fresh_approval_id != original_approval_id
    continuation_audit = accepted["proposal"]["resolution"]["continuation"]
    assert continuation_audit["selected_action_id"] == "sandbox.discovery.metadata.v1"
    assert continuation_audit["resume_from_step_id"] is None
    assert continuation_audit["replay"]["execute_fresh_workspace_full_replay"] is True

    service.approve_job(job_id, {"approved_by": "fresh-reviewer"})
    completed = service.job_controller.wait(job_id, timeout=SECURE_RECEIPT_EXECUTION_TIMEOUT)
    assert completed["state"] == "completed", completed["error"]
    result = service.detail(str(completed["result_ref"]))
    discovery_plan = next(
        step for step in result["plan"]["steps"] if step["step_id"] == "discover_records"
    )
    assert discovery_plan["action_id"] == "sandbox.discovery.metadata.v1"
    assert runner.calls.count("sandbox.fixture.create.v1") == 2
    assert result["replay"]["continuation_policy_digest"].startswith("sha256:")
    service.close()


@pytest.mark.parametrize("failures", [1, 2])
def test_auto_retry_is_single_bounded_attempt_with_distinct_evidence(
    tmp_path: Path,
    failures: int,
) -> None:
    config = load_config(ROOT / "config" / "bluefire.example.yaml").ai
    provider = RetryProposalProvider(config.fallback)
    orchestrator = Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        proposal_provider=provider,
    )
    simulations = FailFirstSimulations(failures=failures)
    orchestrator.simulations = simulations  # type: ignore[assignment]
    scenario = load_scenario(ROOT / "scenarios" / "restricted_persistence_canary.yaml")

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.SIMULATE,
        autonomy=AutonomyLevel.AUTO,
        ai_provider=provider.config.runtime_metadata(),
    )

    attempts = [row for row in result["steps"] if row["step_id"] == "create_persistence_canary"]
    assert len(attempts) == 2
    assert attempts[0]["status"] == "failed"
    assert len({attempts[0]["evidence_ids"][0], attempts[1]["evidence_ids"][0]}) == 2
    assert simulations.attempts == 2
    assert result["adaptive_retry"] == {"maximum": 1, "used": 1, "remaining": 0}
    assert (
        sum(
            item.get("application_status") == "applied_registered_retry"
            for item in result["ai_proposals"]
        )
        == 1
    )
