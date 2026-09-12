"""Normal service approval/run integration with deterministic providers and a fake runner."""

import threading
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from bluefire.ai import AIProposal, AIProviderResult, DeterministicOfflineProvider
from bluefire.config import AutonomyLevel
from bluefire.contracts import load_scenario
from bluefire.job_runtime import JobState
from bluefire.runner_transport_errors import RunnerTaskCancelled
from bluefire.service import BlueFireService
from tests_platform.test_adaptive_authorization import POLICY
from tests_platform.test_ai_integration import ProposalLifecycleRunner

ROOT = Path(__file__).resolve().parents[1]


class FailFirstDiscoveryRunner(ProposalLifecycleRunner):
    def __init__(self):
        super().__init__()
        self.manifests = []

    def execute(self, manifest, profile):
        self.manifests.append((manifest, profile))
        result = super().execute(manifest, profile)
        if manifest["action_id"] == "sandbox.discovery.list.v1":
            result.update(
                status="failed",
                output=None,
                error={"code": "execution_failed", "message": "Authored software test failure."},
            )
        return result


class MethodProvider:
    def __init__(self, config, *, stop=False):
        self.config, self.stop = config, stop
        self.offline = DeterministicOfflineProvider(config)
        self.requests = []

    def propose(self, request):
        self.requests.append(request)
        if request.context["schema_version"] != "bluefire.planner-state.v2":
            return self.offline.propose(request)
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "stop" if self.stop else "select_registered_action",
                "selected_step_id": None if self.stop else "discover_records",
                "selected_behavior_id": None if self.stop else "sandbox.discovery.metadata.v1",
                "selected_action_id": None if self.stop else "sandbox.discovery.metadata.v1",
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Choose the reviewed metadata method after the observed discovery failure.",
                "alternatives": [],
                "confidence": 0.8,
                "requires_operator_review": request.autonomy is AutonomyLevel.ASSIST,
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


@pytest.mark.parametrize("stop", [False, True])
def test_execute_adaptation_consumes_one_approval_and_retains_both_attempts(tmp_path, stop):
    runner = FailFirstDiscoveryRunner()
    with TemporaryDirectory(prefix="bf-adaptive-test-") as owned:
        sandbox = Path(owned) / "sandbox"
        sandbox.mkdir()
        service = BlueFireService(
            project_root=ROOT,
            runs_dir=tmp_path / "runs",
            runner_factory=lambda profile: (runner, sandbox),
            ai_provider_factory=lambda config, provider_id: MethodProvider(
                config.provider(provider_id), stop=stop
            ),
        )
        try:
            scenario = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml").to_dict()
            scenario["adaptive_execution"] = POLICY
            profile = next(
                item for item in service.config.runner_profiles if item.id == "sandbox-execute.v1"
            )
            request = {
                "scenario": scenario,
                "mode": "execute",
                "autonomy": "auto",
                "runner_profile_id": profile.id,
                "target_scope": {"scope_refs": list(profile.scope)},
            }
            preflight = service.preflight(request)
            assert preflight["adaptive_authorization"]["policy"] == POLICY
            submitted = service.submit_run(request)
            job_id = submitted["job"]["job_id"]
            service.job_controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=5)
            approval_id = submitted["approval_request"]["approval_id"]
            service.approve_job(job_id, {"approved_by": "deterministic-test-reviewer"})
            completed = service.job_controller.wait(job_id, timeout=60)
            assert completed["state"] == "completed", completed
            assert service.product_store.get_approval_request(approval_id)["status"] == "claimed"
            run = service.detail(completed["result_ref"])
            rows = [row for row in run["steps"] if row["step_id"] == "discover_records"]
            assert rows[0]["status"] == "failed"
            assert len(rows) == (1 if stop else 2)
            assert runner.calls[-1] == "sandbox.cleanup.v1"
            proposal = next(
                row for row in run["ai_proposals"] if row["schema_version"].endswith(".v4")
            )
            if stop:
                assert run["planning_stopped"] is True and run["objective_reached"] is False
                assert "sandbox.discovery.metadata.v1" not in runner.calls
            else:
                assert rows[1]["action_id"] == "sandbox.discovery.metadata.v1"
                assert run["adaptive_retry"]["used"] == 1
                assert proposal["decision_source"] == "deterministic_provider"
                assert run["approval_pause"] is None
            assert run["cleanup"]["outstanding_receipt_count"] == 0
            for manifest, native_profile in runner.manifests:
                assert (
                    manifest["reviewed_operation"]["authorization_digest"]
                    == native_profile["reviewed_execution"]["authorization_digest"]
                )
                assert manifest["reviewed_operation"]["action_id"] == manifest["action_id"]
        finally:
            service.close()


@pytest.mark.parametrize(
    "boundary", ["provider_return", "record_persisted", "alternate_dispatch", "first_dispatch"]
)
def test_cancellation_at_adaptive_decision_preserves_attempts_and_only_cleans_up(
    tmp_path, monkeypatch, boundary
):
    entered, released = threading.Event(), threading.Event()

    class HeldRunner(FailFirstDiscoveryRunner):
        def execute_task(self, manifest, profile, *, task_id, cancel_event, durable_result_path):
            result = self.execute(manifest, profile)
            cancelled_action = (
                "sandbox.fixture.create.v1"
                if boundary == "first_dispatch"
                else "sandbox.discovery.metadata.v1"
            )
            if manifest["action_id"] == cancelled_action:
                entered.set()
                assert released.wait(15), "test did not release its owned dispatch"
                assert cancel_event.is_set()
                raise RunnerTaskCancelled(
                    "authored cancelled runner task", cooperative_requested=True
                )
            return result

    runner = HeldRunner() if boundary.endswith("dispatch") else FailFirstDiscoveryRunner()

    class HeldProvider(MethodProvider):
        def propose(self, request):
            result = super().propose(request)
            if request.context["schema_version"] == "bluefire.planner-state.v2":
                entered.set()
                assert released.wait(15), "test did not release its owned proposal"
            return result

    with TemporaryDirectory(prefix="bf-adaptive-cancel-") as owned:
        sandbox = Path(owned) / "sandbox"
        sandbox.mkdir()
        service = BlueFireService(
            project_root=ROOT,
            runs_dir=tmp_path / "runs",
            runner_factory=lambda profile: (runner, sandbox),
            ai_provider_factory=lambda config, provider_id: (
                HeldProvider(config.provider(provider_id))
                if boundary == "provider_return"
                else MethodProvider(config.provider(provider_id))
            ),
        )
        if boundary == "record_persisted":
            append = service.store.append_event

            def hold_record(run_id, event_type, data):
                result = append(run_id, event_type, data)
                if event_type == "ai.proposal" and data["schema_version"].endswith(".v4"):
                    entered.set()
                    assert released.wait(15), "test did not release its owned record"
                    raise RunnerTaskCancelled("authored interruption after durable selection")
                return result

            monkeypatch.setattr(service.store, "append_event", hold_record)
        try:
            scenario = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml").to_dict()
            scenario["adaptive_execution"] = POLICY
            profile = next(
                item for item in service.config.runner_profiles if item.id == "sandbox-execute.v1"
            )
            submitted = service.submit_run(
                {
                    "scenario": scenario,
                    "mode": "execute",
                    "autonomy": "auto",
                    "runner_profile_id": profile.id,
                    "target_scope": {"scope_refs": list(profile.scope)},
                }
            )
            job_id = submitted["job"]["job_id"]
            service.job_controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=5)
            service.approve_job(job_id, {"approved_by": "cancellation-test-reviewer"})
            assert entered.wait(15)
            service.cancel_job(job_id)
            released.set()
            cancelled = service.job_controller.wait(job_id, timeout=30)
            assert cancelled["state"] == "cancelled", cancelled
            assert ("sandbox.discovery.metadata.v1" in runner.calls) == (
                boundary == "alternate_dispatch"
            )
            assert runner.calls[-1] == "sandbox.cleanup.v1"
            assert cancelled["result_ref"] is not None, cancelled
            run = service.detail(cancelled["result_ref"])
            assert run["status"] == "cancelled"
            assert run.get("objective_reached") is not True
            if boundary != "first_dispatch":
                assert any(row["step_id"] == "discover_records" for row in run["steps"])
            if boundary.endswith("dispatch"):
                interrupted = next(row for row in run["steps"] if "interruption" in row)
                assert interrupted["runner_task_id"] and interrupted["request_hash"]
                assert interrupted["interruption"]["effect_outcome"] == "unknown"
                assert interrupted["interruption"]["dispatch_requested"] is True
                assert interrupted["interruption"]["runner_result_received"] is False
                assert "runner_status" not in interrupted
                assert any(
                    record["evidence_id"] in interrupted["evidence_ids"]
                    and record["provenance"] == "unknown"
                    for record in run["evidence"]["records"]
                )
                if boundary == "alternate_dispatch":
                    assert (
                        len([row for row in run["steps"] if row["step_id"] == "discover_records"])
                        == 2
                    )
                    assert run["adaptive_retry"]["used"] == 1
            assert run["cleanup"]["outstanding_receipt_count"] == 0
            assert service.store.validate_bundle(run["run_id"])["valid"]
            if boundary == "record_persisted":
                assert any(row["schema_version"].endswith(".v4") for row in run["ai_proposals"])
        finally:
            released.set()
            service.close()


def test_assist_method_review_requires_fresh_approval_and_replays_selected_method_once(
    tmp_path, monkeypatch
):
    runner = FailFirstDiscoveryRunner()
    with TemporaryDirectory(prefix="bf-adaptive-assist-") as owned:
        sandbox = Path(owned) / "sandbox"
        sandbox.mkdir()
        service = BlueFireService(
            project_root=ROOT,
            runs_dir=tmp_path / "runs",
            runner_factory=lambda profile: (runner, sandbox),
            ai_provider_factory=lambda config, provider_id: MethodProvider(
                config.provider(provider_id)
            ),
        )
        try:
            review_errors = []
            original_create_review = service.product_store.create_ai_proposal_review

            def capture_review_error(**kwargs):
                try:
                    return original_create_review(**kwargs)
                except Exception as exc:
                    review_errors.append((str(exc), repr(exc.__cause__)))
                    raise

            monkeypatch.setattr(
                service.product_store, "create_ai_proposal_review", capture_review_error
            )
            scenario = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml").to_dict()
            scenario["adaptive_execution"] = POLICY
            profile = next(
                item for item in service.config.runner_profiles if item.id == "sandbox-execute.v1"
            )
            submitted = service.submit_run(
                {
                    "scenario": scenario,
                    "mode": "execute",
                    "autonomy": "assist",
                    "runner_profile_id": profile.id,
                    "target_scope": {"scope_refs": list(profile.scope)},
                }
            )
            job_id = submitted["job"]["job_id"]
            service.job_controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=5)
            original_approval = submitted["approval_request"]["approval_id"]
            service.approve_job(job_id, {"approved_by": "initial-test-reviewer"})
            paused = service.job_controller.wait_for_state(
                job_id, {JobState.AWAITING_APPROVAL, JobState.FAILED}, timeout=60
            )
            assert paused["state"] == "awaiting_approval", (paused, review_errors)
            proposal_id = paused["progress"]["proposal_record_id"]
            review = service.proposal_review(job_id, proposal_id)
            calls_before_review = list(runner.calls)
            accepted = service.accept_proposal_review(
                job_id,
                proposal_id,
                {
                    "decided_by": "method-test-reviewer",
                    "state_digest": review["state_digest"],
                    "plan_digest": review["plan_digest"],
                    "proposal_digest": review["proposal_digest"],
                },
            )
            assert accepted["approval_request"]["approval_id"] != original_approval
            assert runner.calls == calls_before_review
            service.approve_job(job_id, {"approved_by": "fresh-replay-test-reviewer"})
            completed = service.job_controller.wait(job_id, timeout=60)
            assert completed["state"] == "completed", completed
            replay = service.detail(completed["result_ref"])
            attempts = [row for row in replay["steps"] if row["step_id"] == "discover_records"]
            assert (
                len(attempts) == 1 and attempts[0]["action_id"] == "sandbox.discovery.metadata.v1"
            )
            assert replay["adaptive_retry"]["used"] == 1
            assert replay["replay"]["proposal_resolution"]["method_replay_from_start"] is True
            assert replay["cleanup"]["outstanding_receipt_count"] == 0
        finally:
            service.close()
