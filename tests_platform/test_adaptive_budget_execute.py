"""Ordinary approval/job integration with authored failures, not native or live-provider proof."""

import hashlib
import threading
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from bluefire.ai import AIProposal, AIProviderResult
from bluefire.config import AutonomyLevel, RunnerProfile, load_config
from bluefire.contracts import load_scenario
from bluefire.job_runtime import JobState
from bluefire.runner_transport_errors import RunnerReadinessError, RunnerTaskCancelled
from bluefire.service import BlueFireService
from bluefire.tool_adapters import gzip
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_integration import ProposalLifecycleRunner
from tests_platform.test_gzip_tool_binding import (
    _descriptor,
    _inspection_result,
)
from tests_platform.test_gzip_tool_binding import (
    candidate as gzip_candidate,
)
from tests_platform.test_gzip_tool_binding import (
    installation as gzip_installation,
)
from tests_platform.test_gzip_tool_binding import (
    result as gzip_candidate_result,
)

ROOT = Path(__file__).resolve().parents[1]
GZIP = "sandbox.collection.atomic-gzip.v1"
ARCHIVE = "sandbox.collection.archive.v1"
RECORDS = "sandbox.collection.records.v1"
METHODS = (GZIP, ARCHIVE, RECORDS)
METADATA = "sandbox.discovery.metadata.v1"
LIST = "sandbox.discovery.list.v1"


class BudgetMethodProvider:
    """Choose an actual offered tuple, with no model transport or fabricated effect."""

    def __init__(self, config, requests):
        self.config = config
        self.requests = requests

    def propose(self, request):
        self.requests.append(request)
        assert (
            request.context["schema_version"] == "bluefire.planner-state.v3"
        ), "v2 execution must never call the legacy generic proposal path"
        option = request.context["registered_options"][0]
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "select_registered_action",
                "selected_step_id": option["step_id"],
                "selected_behavior_id": option["behavior_id"],
                "selected_action_id": option["action_id"],
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Authored choice of the next reviewed method after an authored failure.",
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
            "authored-budget-integration-response",
            1,
            False,
            None,
            {},
        )


class BudgetRunner(ProposalLifecycleRunner):
    """Existing fake lifecycle plus explicit failed collection response envelopes.

    The inventory's Linux platform is authored in the fixture. No collection,
    gzip executable, native process or network operation is actually performed.
    Existing receipt/cleanup fixture behavior remains in force for preparation.
    """

    def __init__(self, *, fail_discovery=False, hold_alternate=False, reported_last_success=False):
        super().__init__()
        self.fail_discovery = fail_discovery
        self.hold_alternate = hold_alternate
        self.reported_last_success = reported_last_success
        self.entered = threading.Event()
        self.released = threading.Event()
        self.manifests = []
        self.native_inspections = 0

    def inventory(self):
        value = dict(super().inventory())
        value["platform"] = "linux"
        value["actions"] = [item for item in value["actions"] if item["action_id"] != GZIP] + [
            _descriptor(GZIP, gzip.VERSION, gzip.CONTRACT.digest, gzip.TOOL_ID)
        ]
        return value

    def inspect_native_tool_candidate(self, request):
        assert request == gzip_candidate()
        self.native_inspections += 1
        return gzip_candidate_result()

    def inspect_native_tool(self, record):
        value = gzip_installation()
        assert record == value.to_dict()
        self.native_inspections += 1
        return _inspection_result(value)

    def execute(self, manifest, profile):
        self.manifests.append((manifest, profile))
        action = manifest["action_id"]
        if action not in METHODS:
            result = super().execute(manifest, profile)
            if action == METADATA and self.fail_discovery:
                result.update(
                    status="failed",
                    output=None,
                    error={"code": "execution_failed", "message": "Authored discovery failure."},
                )
            return result
        self.calls.append(action)
        result = {
            "schema_version": "bluefire.runner-result.v1",
            **{
                field: manifest[field]
                for field in (
                    "request_id",
                    "run_id",
                    "step_id",
                    "behavior_id",
                    "action_id",
                    "runner_id",
                    "runner_profile_id",
                    "request_hash",
                )
            },
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": "failed",
            "output": None,
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "authored-budget-failure", "status": "failed"}],
            "receipt_ids": [],
            "cleanup": None,
            "error": {"code": "execution_failed", "message": "Authored collection failure."},
            "limitations": ["Authored response envelope; no collection method actually executed."],
        }
        if self.reported_last_success and action == RECORDS:
            # Reported success is deliberately not backed by a collection file.
            # The ordinary observer must retain the missing observation as unknown.
            relative = "staged/collection/bundle.jsonl"
            result.update(
                status="success",
                output={
                    "artifact": relative,
                    "container": "jsonl",
                    "input_count": 1,
                    "source_sha256": manifest["params"]["expected_sha256"],
                    "size": 16,
                    "sha256": "3" * 64,
                },
                error=None,
                evidence=[{"kind": "authored-reported-success", "status": "success"}],
                receipt_ids=[self._authored_collection_receipt(manifest, profile, relative)],
            )
        return result

    @staticmethod
    def _authored_collection_receipt(manifest, profile, relative):
        """Use the existing fixture receipt protocol with this method's exact path."""
        sandbox = Path(profile["sandbox_root"])
        workspace_id = hashlib.sha256(
            str(sandbox.resolve(strict=True)).replace("\\", "/").encode("utf-8")
        ).hexdigest()
        identity = {
            "schema_version": "bluefire.receipt/v1",
            "request_hash": manifest["request_hash"],
            "action_id": manifest["action_id"],
            "runner_profile_id": profile["profile_id"],
            "workspace_id": workspace_id,
            "created_at": "2026-08-24T00:00:00Z",
            "paths": [{"relative_path": relative, "kind": "file", "sha256": "0" * 64, "size": 0}],
        }
        receipt_id = content_hash(identity).removeprefix("sha256:")
        for directory, document in (
            ("receipts", {"receipt_id": receipt_id, **identity}),
            (
                "receipt-commits",
                {
                    "schema_version": "bluefire.receipt-commit/v1",
                    "receipt_id": receipt_id,
                    "runner_profile_id": profile["profile_id"],
                    "workspace_id": workspace_id,
                    "committed_at": "2026-08-24T00:00:01Z",
                },
            ),
        ):
            path = sandbox / ".bluefire" / directory
            path.mkdir(parents=True, exist_ok=True)
            (path / f"{receipt_id}.json").write_bytes(canonical_json_bytes(document))
        return receipt_id

    def execute_task(self, manifest, profile, *, task_id, cancel_event, durable_result_path):
        result = self.execute(manifest, profile)
        if self.hold_alternate and manifest["action_id"] == ARCHIVE:
            self.entered.set()
            assert self.released.wait(15), "test did not release its owned alternate"
            assert cancel_event.is_set()
            raise RunnerTaskCancelled("authored interrupted alternate", cooperative_requested=True)
        return result


def scenario_document(*, step_cap=2, lineage_cap=2, discovery=False):
    scenario = load_scenario(ROOT / "scenarios/atomic_gzip_collection.yaml").to_dict()
    collection = next(step for step in scenario["steps"] if step["id"] == "stage_collection")
    collection["alternates"] = [ARCHIVE, RECORDS]
    groups = []
    if discovery:
        selected = next(step for step in scenario["steps"] if step["id"] == "select_records")
        selected["alternates"] = [LIST]
        groups.append(
            {
                "step_id": "select_records",
                "max_retries": 1,
                "methods": [{"behavior_id": item, "action_id": item} for item in (METADATA, LIST)],
            }
        )
    groups.append(
        {
            "step_id": "stage_collection",
            "max_retries": step_cap,
            "methods": [{"behavior_id": item, "action_id": item} for item in METHODS],
        }
    )
    scenario["adaptive_execution"] = {
        "schema_version": "bluefire.adaptive-execution.v2",
        "max_retries": lineage_cap,
        "steps": groups,
        "eligible_outcomes": ["blocked", "failed", "partial"],
        "on_provider_failure": "stop",
    }
    return scenario


@contextmanager
def authored_service(tmp_path, monkeypatch, runner):
    # This changes the authored control-plane platform identity, never runs a
    # Linux native tool. All effect dispatch remains on BudgetRunner above.
    monkeypatch.setattr("bluefire.runner_contracts.host_platform.system", lambda: "Linux")
    requests = []
    with TemporaryDirectory(prefix="bf-adaptive-budget-") as owned:
        sandbox = Path(owned) / "sandbox"
        sandbox.mkdir()
        config = load_config(ROOT / "config/bluefire.example.yaml")
        service = BlueFireService(
            project_root=ROOT,
            config=config,
            runs_dir=tmp_path / "runs",
            runner_factory=lambda profile: (runner, sandbox),
            ai_provider_factory=lambda config, provider_id: BudgetMethodProvider(
                config.provider(provider_id), requests
            ),
        )
        try:
            default_profile = next(
                item for item in config.runner_profiles if item.id == "sandbox-execute.v1"
            )
            assert GZIP not in default_profile.enabled_actions
            assert not default_profile.native_tool_installations
            draft = replace(
                default_profile,
                id="test.adaptive-budget-gzip.v1",
                platforms=("linux",),
                enabled_actions=(*default_profile.enabled_actions, GZIP),
            ).to_dict()
            service.save_resource(
                "runner_profile", draft["id"], {"document": draft, "status": "draft"}
            )
            with pytest.raises(RunnerReadinessError, match="not ready"):
                service._execute_readiness_boundary(RunnerProfile.from_mapping(draft))
            inspected = service.inspect_runner_profile_tool(draft["id"], gzip_candidate())
            assert inspected == gzip_candidate_result()
            draft["native_tool_installations"] = [inspected["installation"]]
            service.save_resource(
                "runner_profile", draft["id"], {"document": draft, "status": "draft"}
            )
            service.activate_resource("runner_profile", draft["id"], {})
            active = service.product_store.get_resource("runner_profile", draft["id"])
            assert active["status"] == "active"
            profile = RunnerProfile.from_mapping(active["document"])
            assert profile.native_tool_installations[0].digest == gzip_installation().digest
            _, _, readiness = service._execute_readiness_boundary(profile)
            gzip_readiness = next(
                row for row in readiness["enabled_actions"] if row["action_id"] == GZIP
            )
            assert gzip_readiness["readiness"] == "ready"
            assert gzip_readiness["native_tool_installation_digest"] == gzip_installation().digest
            assert runner.native_inspections >= 2
            assert runner.calls == []
            yield service, requests
        finally:
            runner.released.set()
            service.close()


def submit(service, scenario, *, autonomy="auto"):
    profile = next(
        item for item in service._runner_profiles() if item.id == "test.adaptive-budget-gzip.v1"
    )
    request = {
        "scenario": scenario,
        "mode": "execute",
        "autonomy": autonomy,
        "runner_profile_id": profile.id,
        "target_scope": {"scope_refs": list(profile.scope)},
    }
    preflight = service.preflight(request)
    assert (
        preflight["adaptive_authorization"]["schema_version"]
        == "bluefire.adaptive-authorization.v2"
    )
    assert preflight["adaptive_authorization"]["policy"] == scenario["adaptive_execution"]
    submitted = service.submit_run(request)
    job_id = submitted["job"]["job_id"]
    service.job_controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=5)
    return job_id, submitted["approval_request"]["approval_id"]


def completed_run(service, job_id):
    completed = service.job_controller.wait(job_id, timeout=60)
    assert completed["state"] == "completed", completed
    return service.detail(completed["result_ref"])


def assert_authority_and_cleanup(service, runner, run):
    assert run["cleanup"]["outstanding_receipt_count"] == 0
    assert runner.calls[-1] == "sandbox.cleanup.v1"
    assert service.store.validate_bundle(run["run_id"])["valid"]
    # Recovery retains approval identity in the immutable run policy even when
    # cancellation precedes creation of the complete result presentation.
    assert (
        service.product_store.get_approval_request(run["policy"]["approval"]["approval_id"])[
            "status"
        ]
        == "claimed"
    )
    for manifest, profile in runner.manifests:
        assert manifest["reviewed_operation"]["authorization_digest"] == (
            profile["reviewed_execution"]["authorization_digest"]
        )
        assert manifest["reviewed_operation"]["action_id"] == manifest["action_id"]
        assert manifest["platform"] == profile["platform"] == "linux"


def test_v2_auto_tries_three_distinct_reviewed_methods_under_one_consumed_approval(
    tmp_path, monkeypatch
):
    runner = BudgetRunner()
    with authored_service(tmp_path, monkeypatch, runner) as (service, requests):
        job_id, approval_id = submit(service, scenario_document())
        assert runner.calls == []
        service.approve_job(job_id, {"approved_by": "authored-budget-reviewer"})
        run = completed_run(service, job_id)
        rows = [row for row in run["steps"] if row["step_id"] == "stage_collection"]
        assert [row["action_id"] for row in rows] == list(METHODS)
        assert all(row["status"] == "failed" for row in rows)
        assert [action for action in runner.calls if action in METHODS] == list(METHODS)
        assert len(requests) == 2
        assert [request.allowed_action_ids for request in requests] == [
            (ARCHIVE, RECORDS),
            (RECORDS,),
        ]
        budget = run["adaptive_retry"]
        assert (budget["maximum"], budget["used"], budget["remaining"]) == (2, 2, 0)
        assert budget["per_step"]["stage_collection"] == {"maximum": 2, "used": 2, "remaining": 0}
        assert [row["action_id"] for row in budget["attempted_methods"]] == list(METHODS)
        proposals = [row for row in run["ai_proposals"] if row["schema_version"].endswith(".v5")]
        assert [row["proposal_policy"]["adaptive_retries_used"] for row in proposals] == [0, 1, 2]
        assert [row["provider_called"] for row in proposals] == [True, True, False]
        assert proposals[-1]["application_status"] == "stopped_budget_exhausted"
        assert run["approval"]["approval_id"] == approval_id
        assert run["planning_stopped"] is True and run["objective_reached"] is False
        assert_authority_and_cleanup(service, runner, run)


@pytest.mark.parametrize("boundary", ["step", "lineage"])
def test_v2_each_budget_stops_before_an_available_third_collection_method(
    tmp_path, monkeypatch, boundary
):
    runner = BudgetRunner(fail_discovery=boundary == "lineage")
    scenario = scenario_document(step_cap=1 if boundary == "step" else 2, discovery=True)
    with authored_service(tmp_path, monkeypatch, runner) as (service, requests):
        job_id, _ = submit(service, scenario)
        service.approve_job(job_id, {"approved_by": "authored-exhaustion-reviewer"})
        run = completed_run(service, job_id)
        assert [action for action in runner.calls if action in METHODS] == [GZIP, ARCHIVE]
        assert RECORDS not in runner.calls
        budget = run["adaptive_retry"]
        assert budget["per_step"]["stage_collection"]["used"] == 1
        assert budget["remaining"] == (1 if boundary == "step" else 0)
        assert budget["per_step"]["stage_collection"]["remaining"] == (
            0 if boundary == "step" else 1
        )
        assert budget["per_step"]["select_records"]["used"] == (0 if boundary == "step" else 1)
        assert len(requests) == (1 if boundary == "step" else 2)
        stopped = [row for row in run["ai_proposals"] if row["schema_version"].endswith(".v5")][-1]
        assert stopped["application_status"] == "stopped_budget_exhausted"
        assert stopped["provider_called"] is False
        assert [option["action_id"] for option in stopped["registered_options"]] == [RECORDS]
        assert run["planning_stopped"] is True and run["objective_reached"] is False
        assert_authority_and_cleanup(service, runner, run)


def test_v2_cancelled_alternate_retains_its_reserved_budget_and_unknown_effect_outcome(
    tmp_path, monkeypatch
):
    runner = BudgetRunner(hold_alternate=True)
    with authored_service(tmp_path, monkeypatch, runner) as (service, requests):
        job_id, _ = submit(service, scenario_document())
        service.approve_job(job_id, {"approved_by": "authored-cancellation-reviewer"})
        assert runner.entered.wait(15), "owned alternate was not reached"
        service.cancel_job(job_id)
        runner.released.set()
        cancelled = service.job_controller.wait(job_id, timeout=30)
        assert cancelled["state"] == "cancelled", cancelled
        run = service.detail(cancelled["result_ref"])
        assert run["status"] == "cancelled" and run.get("objective_reached") is not True
        assert [action for action in runner.calls if action in METHODS] == [GZIP, ARCHIVE]
        assert len(requests) == 1 and RECORDS not in runner.calls
        budget = run["adaptive_retry"]
        assert (budget["used"], budget["remaining"]) == (1, 1)
        assert budget["per_step"]["stage_collection"]["used"] == 1
        assert [row["action_id"] for row in budget["reservations"]] == [ARCHIVE]
        assert [row["action_id"] for row in budget["attempted_methods"]] == [GZIP, ARCHIVE]
        interrupted = next(row for row in run["steps"] if "interruption" in row)
        assert interrupted["action_id"] == ARCHIVE
        assert interrupted["interruption"]["effect_outcome"] == "unknown"
        assert interrupted["interruption"]["dispatch_requested"] is True
        assert interrupted["interruption"]["runner_result_received"] is False
        assert interrupted["runner_task_id"] and interrupted["request_hash"]
        assert_authority_and_cleanup(service, runner, run)


def test_v2_assist_continuations_require_fresh_approvals_and_never_reexecute_a_method(
    tmp_path, monkeypatch
):
    runner = BudgetRunner()
    with authored_service(tmp_path, monkeypatch, runner) as (service, requests):
        job_id, first_approval = submit(service, scenario_document(), autonomy="assist")
        approvals = [first_approval]
        source_runs = []
        service.approve_job(job_id, {"approved_by": "authored-initial-reviewer"})
        for used, selected in enumerate((ARCHIVE, RECORDS)):
            paused = service.job_controller.wait_for_state(
                job_id, {JobState.AWAITING_APPROVAL, JobState.FAILED}, timeout=60
            )
            assert paused["state"] == "awaiting_approval", paused
            proposal_id = paused["progress"]["proposal_record_id"]
            review = service.proposal_review(job_id, proposal_id)
            source = service.detail(review["source_run_id"])
            source_runs.append(source["run_id"])
            assert source["adaptive_retry"]["used"] == used
            assert source["adaptive_retry"]["per_step"]["stage_collection"]["used"] == used
            assert [
                row["action_id"] for row in source["steps"] if row["step_id"] == "stage_collection"
            ] == [METHODS[used]]
            proposal = next(
                row
                for row in source["ai_proposals"]
                if row["application_status"] == "awaiting_operator_approval"
            )
            assert proposal["schema_version"] == "bluefire.ai-proposal-record.v5"
            assert proposal["registered_step"]["action_id"] == selected
            before_accept = list(runner.calls)
            accepted = service.accept_proposal_review(
                job_id,
                proposal_id,
                {
                    "decided_by": "authored-method-reviewer",
                    "state_digest": review["state_digest"],
                    "plan_digest": review["plan_digest"],
                    "proposal_digest": review["proposal_digest"],
                },
            )
            approval_id = accepted["approval_request"]["approval_id"]
            assert approval_id not in approvals
            approvals.append(approval_id)
            assert runner.calls == before_accept
            assert selected not in runner.calls
            assert service.detail(source["run_id"])["adaptive_retry"] == source["adaptive_retry"]
            service.approve_job(job_id, {"approved_by": "authored-fresh-continuation-reviewer"})
        final = completed_run(service, job_id)
        assert final["run_id"] not in source_runs and len(set(source_runs)) == 2
        assert [action for action in runner.calls if action in METHODS] == list(METHODS)
        assert len(requests) == 2
        assert [
            row["action_id"] for row in final["steps"] if row["step_id"] == "stage_collection"
        ] == [RECORDS]
        assert final["adaptive_retry"]["used"] == 2 and final["adaptive_retry"]["remaining"] == 0
        assert [row["action_id"] for row in final["adaptive_retry"]["reservations"]] == [
            ARCHIVE,
            RECORDS,
        ]
        assert [row["action_id"] for row in final["adaptive_retry"]["attempted_methods"]] == list(
            METHODS
        )
        assert (
            final["replay"]["proposal_resolution"]["schema_version"]
            == "bluefire.ai-proposal-resolution-lineage.v5"
        )
        assert final["replay"]["proposal_resolution"]["method_replay_from_start"] is True
        assert all(
            service.product_store.get_approval_request(item)["status"] == "claimed"
            for item in approvals
        )
        assert final["planning_stopped"] is True and final["objective_reached"] is False
        assert_authority_and_cleanup(service, runner, final)


def test_v2_success_after_two_pivots_uses_deterministic_successor_without_legacy_proposal(
    tmp_path, monkeypatch
):
    runner = BudgetRunner(reported_last_success=True)
    with authored_service(tmp_path, monkeypatch, runner) as (service, requests):
        job_id, _ = submit(service, scenario_document())
        service.approve_job(job_id, {"approved_by": "authored-success-path-reviewer"})
        run = completed_run(service, job_id)
        rows = [row for row in run["steps"] if row["step_id"] == "stage_collection"]
        assert [(row["action_id"], row["status"]) for row in rows] == [
            (GZIP, "failed"),
            (ARCHIVE, "failed"),
            (RECORDS, "success"),
        ]
        assert run["steps"][-1]["step_id"] == "cleanup_workspace"
        assert run["steps"][-1]["status"] == "success"
        assert run["adaptive_retry"]["used"] == 2
        assert len(requests) == 2
        assert all(
            request.context["schema_version"] == "bluefire.planner-state.v3" for request in requests
        )
        assert len(run["ai_proposals"]) == 2
        assert all(
            row["schema_version"] == "bluefire.ai-proposal-record.v5" for row in run["ai_proposals"]
        )
        assert run.get("planning_stopped") is not True
        # The fake reported success does not become observed objective evidence.
        collection_evidence = [
            row for row in run["evidence"]["records"] if row["step_id"] == "stage_collection"
        ]
        assert any(row["provenance"] == "unknown" for row in collection_evidence)
        assert not any(row["provenance"] == "observed" for row in collection_evidence)
        assert_authority_and_cleanup(service, runner, run)


def test_first_continuation_checkpoint_cancellation_preserves_inherited_ledger(
    tmp_path, monkeypatch
):
    runner = BudgetRunner()
    with authored_service(tmp_path, monkeypatch, runner) as (service, requests):
        job_id, initial_approval = submit(service, scenario_document(), autonomy="assist")
        service.approve_job(job_id, {"approved_by": "authored-source-reviewer"})
        paused = service.job_controller.wait_for_state(
            job_id, {JobState.AWAITING_APPROVAL, JobState.FAILED}, timeout=60
        )
        assert paused["state"] == "awaiting_approval", paused
        proposal_id = paused["progress"]["proposal_record_id"]
        review = service.proposal_review(job_id, proposal_id)
        source = service.detail(review["source_run_id"])
        assert source["adaptive_retry"]["used"] == 0
        accepted = service.accept_proposal_review(
            job_id,
            proposal_id,
            {
                "decided_by": "authored-continuation-reviewer",
                "state_digest": review["state_digest"],
                "plan_digest": review["plan_digest"],
                "proposal_digest": review["proposal_digest"],
            },
        )
        next_approval = accepted["approval_request"]["approval_id"]
        assert next_approval != initial_approval
        calls_before = list(runner.calls)
        captured = []
        checkpoint_factory = service._execution_checkpoint

        def cancelled_checkpoint(approval_id, downstream):
            normal = checkpoint_factory(approval_id, downstream)

            def checkpoint(progress):
                normal(progress)
                if progress.get("run_id") and progress.get("completed_steps") == 0:
                    assert approval_id == next_approval
                    assert not captured, "continuation must stop at its first run checkpoint"
                    partial = service.store.read_json(progress["run_id"], "result.json")
                    captured.append(deepcopy(partial))
                    service.cancel_job(job_id)
                    raise RunnerTaskCancelled(
                        "authored cancellation at initial continuation checkpoint"
                    )

            return checkpoint

        monkeypatch.setattr(service, "_execution_checkpoint", cancelled_checkpoint)
        service.approve_job(job_id, {"approved_by": "authored-fresh-checkpoint-reviewer"})
        cancelled = service.job_controller.wait(job_id, timeout=30)
        assert cancelled["state"] == "cancelled", cancelled
        assert len(captured) == 1
        partial = captured[0]
        inherited = partial["replay"]["adaptive_budget"]
        assert inherited["used"] == inherited["per_step"]["stage_collection"]["used"] == 1
        assert inherited["remaining"] == 1
        assert [row["action_id"] for row in inherited["reservations"]] == [ARCHIVE]
        assert [row["action_id"] for row in inherited["attempted_methods"]] == [GZIP, ARCHIVE]
        assert partial["adaptive_retry"] == inherited
        final = service.detail(cancelled["result_ref"])
        assert final["run_id"] == partial["run_id"] != source["run_id"]
        assert final["status"] == "cancelled" and final.get("objective_reached") is not True
        assert final["adaptive_retry"] == final["replay"]["adaptive_budget"] == inherited
        assert final["steps"] == [] and final["ai_proposals"] == []
        assert runner.calls == calls_before and len(requests) == 1
        assert service.detail(source["run_id"])["adaptive_retry"] == source["adaptive_retry"]
        assert final["cleanup"]["outstanding_receipt_count"] == 0
        assert service.store.validate_bundle(final["run_id"])["valid"]
        assert service.product_store.get_approval_request(next_approval)["status"] == "claimed"
