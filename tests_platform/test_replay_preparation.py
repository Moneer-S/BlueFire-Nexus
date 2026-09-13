from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest

from bluefire.application_errors import APIError
from bluefire.approvals import execution_approval_binding
from bluefire.config import AutonomyLevel
from bluefire.contracts import ExecutionMode
from bluefire.orchestrator import Orchestrator
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_service import ReadyInventoryRunner

ROOT = Path(__file__).resolve().parents[1]
SCOPE = {"scope_refs": ["sandbox.workspace"]}


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[BlueFireService]:
    clock = datetime.now(timezone.utc)

    class ReviewClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return clock if tz is not None else clock.replace(tzinfo=None)

    monkeypatch.setattr("bluefire.service.datetime", ReviewClock)
    runner = ReadyInventoryRunner()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    instance = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        yield instance
    finally:
        instance.close()


def source_run(service: BlueFireService, *, execute: bool = False) -> Mapping[str, Any]:
    if not execute:
        return service.run(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "simulate",
                "autonomy": "off",
            }
        )
    # Persist a file-only canonical source fixture. No runner execution or
    # observed effect is claimed; tests stop dispatch at the approval boundary.
    scenario = service._scenario_or_api_error({"scenario_id": "scenario.sandbox.research.chain.v1"})
    profile = service._profile("sandbox-execute.v1", ExecutionMode.EXECUTE)
    assert profile is not None
    provider = service._ai_provider_metadata(AutonomyLevel.OFF, "deterministic-offline.v1")
    plan = (
        Orchestrator(service.registry, service.store)
        .planner.compile(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            autonomy=AutonomyLevel.OFF,
            ai_provider=provider,
        )
        .to_dict()
    )
    handle = service.store.create_run(
        scenario=scenario.to_dict(),
        plan=plan,
        policy={"preflight": {"catalog_authority": service._catalog_snapshot.to_dict()}},
        profile=profile.to_dict(),
    )
    service.store.finalize(
        handle.run_id,
        result={
            "status": "failed",
            "mode": "execute",
            "scenario_id": scenario.id,
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "ai_provider": provider,
            "steps": [],
            "target_scope": SCOPE,
        },
        evidence=[],
        detections=[],
    )
    return service.store.get_run(handle.run_id)


def forbid(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("preparation reached an effect, approval, job, or workspace mutation")


def block_effects(service: BlueFireService, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Orchestrator, "run", forbid)
    for name in ("create_approval_request", "approve", "consume_approval"):
        monkeypatch.setattr(service.product_store, name, forbid)
    monkeypatch.setattr(service.job_controller, "submit", forbid)
    monkeypatch.setattr(service, "_isolated_execution_sandbox", forbid)
    monkeypatch.setattr(service, "_bind_execution_workspace", forbid)


@pytest.mark.parametrize("execute", [False, True])
def test_preparation_is_stable_read_only_and_displays_actual_full_plan(
    service: BlueFireService, monkeypatch: pytest.MonkeyPatch, execute: bool
) -> None:
    source = source_run(service, execute=execute)
    original = deepcopy(source)
    request = {
        "parameter_overrides": {"create_fixture": {"record_count": 3}},
        **({"target_scope": SCOPE} if execute else {}),
    }
    original_request = deepcopy(request)
    run_ids = [run["run_id"] for run in service.store.list_runs()]
    block_effects(service, monkeypatch)
    prepared = service.prepare_replay(source["run_id"], request)
    repeated = service.prepare_replay(source["run_id"], request)
    assert prepared == repeated
    assert request == original_request
    assert service.store.get_run(source["run_id"]) == original
    assert [run["run_id"] for run in service.store.list_runs()] == run_ids
    assert prepared["effects_started"] is False and prepared["approval_created"] is False
    assert prepared["replay_extent"] == "full"
    step = next(row for row in prepared["scenario"]["steps"] if row["id"] == "create_fixture")
    assert step["parameters"]["record_count"] == 3
    planned = next(
        row for row in prepared["preflight"]["plan"]["steps"] if row["step_id"] == "create_fixture"
    )
    assert planned["parameters"]["record_count"] == 3
    assert prepared["binding"]["source"]["manifest_digest"] == content_hash(source["manifest"])
    assert prepared["binding"]["request_digest"] == content_hash(request)
    assert prepared["preflight"]["status"] == ("approval_required" if execute else "ready")


def test_prepared_simulate_replay_runs_exact_reviewed_graph_and_keeps_lineage(
    service: BlueFireService,
) -> None:
    source = source_run(service)
    preparation = service.prepare_replay(source["run_id"], {"exact": True})
    replay = service.replay(
        source["run_id"],
        {
            **preparation["replay_request"],
            "preparation_id": preparation["preparation_id"],
            "preparation_context": preparation["preparation_context"],
        },
    )
    assert replay["scenario"] == preparation["scenario"]
    assert replay["plan"] == preparation["preflight"]["plan"]
    assert replay["replay"] == preparation["lineage"]
    assert replay["replay"]["source_run_id"] == source["run_id"]


def test_execute_preparation_matches_actual_approval_binding_without_creating_it(
    service: BlueFireService, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = source_run(service, execute=True)
    preparation = service.prepare_replay(source["run_id"], {"exact": True, "target_scope": SCOPE})
    observed_at = datetime.fromisoformat(
        preparation["preflight"]["runner_readiness"]["freshness"]["observed_at"].replace(
            "Z", "+00:00"
        )
    )

    class LaterClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return observed_at + timedelta(seconds=10)

    monkeypatch.setattr("bluefire.service.datetime", LaterClock)
    block_effects(service, monkeypatch)

    class ReachedApproval(BaseException):
        pass

    def inspect_approval(**values: Any) -> Any:
        orchestrator = values["orchestrator"]
        plan = orchestrator.preflight(
            values["scenario"],
            mode=ExecutionMode.EXECUTE,
            profile=values["profile"],
            autonomy=values["autonomy"],
            ai_provider=values["ai_provider"],
            approval_present=True,
            action_implementations=values["action_implementations"],
        ).plan
        binding = execution_approval_binding(
            registry=orchestrator.registry,
            scenario=values["scenario"],
            plan=plan,
            profile=values["profile"],
            target_scope=values["target_scope"],
            autonomy=values["autonomy"],
            ai_provider=values["ai_provider"],
            context=values["context"],
            runner_readiness=values["runner_readiness"],
            catalog_authority=orchestrator.catalog_authority,
        )
        assert binding == preparation["preflight"]["approval_binding"]
        raise ReachedApproval

    monkeypatch.setattr(service, "_bind_and_consume_approval", inspect_approval)
    with pytest.raises(ReachedApproval):
        service.replay(
            source["run_id"],
            {
                **preparation["replay_request"],
                "preparation_id": preparation["preparation_id"],
                "preparation_context": preparation["preparation_context"],
                "approval": {"confirmed": True, "approved_by": "reviewer"},
            },
        )


@pytest.mark.parametrize("change", ["payload", "source", "profile", "collector"])
def test_preparation_drift_is_refused_before_approval_or_effects(
    service: BlueFireService, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    source = source_run(service, execute=True)
    request: dict[str, Any] = {"target_scope": SCOPE}
    preparation = service.prepare_replay(source["run_id"], request)
    if change == "payload":
        request["parameter_overrides"] = {"create_fixture": {"record_count": 3}}
    elif change == "source":
        original = service.store.get_run
        monkeypatch.setattr(
            service.store,
            "get_run",
            lambda run_id: {**original(run_id), "source_revision_witness": True},
        )
    elif change == "profile":
        original_profile = service._profile_for_catalog

        def changed_profile(*args: Any, **kwargs: Any) -> Any:
            profile = original_profile(*args, **kwargs)
            return replace(
                profile,
                budgets=replace(profile.budgets, max_seconds=profile.budgets.max_seconds - 1),
            )

        monkeypatch.setattr(service, "_profile_for_catalog", changed_profile)
    elif change == "collector":
        request["collectors"] = ["collector.collection-semantics.sandbox.v1"]
    block_effects(service, monkeypatch)
    with pytest.raises(APIError) as error:
        service.replay(
            source["run_id"],
            {
                **request,
                "preparation_id": preparation["preparation_id"],
                "preparation_context": preparation["preparation_context"],
                "approval": {"confirmed": True, "approved_by": "reviewer"},
            },
        )
    assert "preparation changed" in str(error.value.details)


@pytest.mark.parametrize(
    "payload",
    [
        {"approval": {"confirmed": True, "approved_by": "caller"}},
        {"preparation_id": "caller"},
        {"source": {}},
        {"scenario": {}},
        {"from_step_id": []},
        {"exact": "true"},
        {"swap_step_id": 4},
    ],
)
def test_preparation_rejects_authority_and_malformed_options_before_resolution(
    service: BlueFireService, monkeypatch: pytest.MonkeyPatch, payload: Mapping[str, Any]
) -> None:
    monkeypatch.setattr(service, "_resolve_replay_source_locked", forbid)
    with pytest.raises(APIError, match="could not be prepared"):
        service.prepare_replay("run-not-read", payload)


def test_preparation_refuses_unavailable_runner_without_a_successful_review(
    service: BlueFireService,
) -> None:
    source = source_run(service, execute=True)
    service.runner_factory = lambda _profile: (_ for _ in ()).throw(OSError("unavailable"))
    with pytest.raises(APIError) as error:
        service.prepare_replay(source["run_id"], {"target_scope": SCOPE})
    assert error.value.code == "replay_preparation_refused"
    assert error.value.details == {"reason_code": "runner_readiness_required"}


def test_exact_preparation_keeps_existing_collector_refusal(service: BlueFireService) -> None:
    source = source_run(service, execute=True)
    with pytest.raises(APIError) as error:
        service.prepare_replay(
            source["run_id"],
            {
                "exact": True,
                "target_scope": SCOPE,
                "collectors": ["collector.collection-semantics.sandbox.v1"],
            },
        )
    assert "exact replay cannot change collector" in str(error.value.details)


@pytest.mark.parametrize("change", ["expired", "future", "runner", "inventory", "sandbox"])
def test_live_readiness_changes_are_refused_before_approval(service, monkeypatch, tmp_path, change):
    source = source_run(service, execute=True)
    preparation = service.prepare_replay(source["run_id"], {"target_scope": SCOPE})
    context = deepcopy(preparation["preparation_context"])
    runner, sandbox = service.runner_factory(
        service._profile("sandbox-execute.v1", ExecutionMode.EXECUTE)
    )
    if change in {"expired", "future"}:
        freshness = context["runner_readiness"]["freshness"]
        observed = datetime.fromisoformat(freshness["observed_at"].replace("Z", "+00:00"))
        offset = -freshness["max_age_seconds"] - 1 if change == "expired" else 30
        freshness["observed_at"] = (observed + timedelta(seconds=offset)).isoformat()
    elif change == "runner":

        class ReplacedRunner(ReadyInventoryRunner):
            pass

        service.runner_factory = lambda _profile: (ReplacedRunner(), sandbox)
    elif change == "inventory":
        runner.actions = set(runner.actions) - {"sandbox.fixture.create.v1"}
    else:
        other_sandbox = tmp_path / "replacement-sandbox"
        other_sandbox.mkdir()
        service.runner_factory = lambda _profile: (runner, other_sandbox)
    block_effects(service, monkeypatch)
    with pytest.raises(APIError) as error:
        service.replay(
            source["run_id"],
            {
                **preparation["replay_request"],
                "preparation_id": preparation["preparation_id"],
                "preparation_context": context,
                "approval": {"confirmed": True, "approved_by": "reviewer"},
            },
        )
    assert error.value.code == "replay_refused"
    assert any(term in str(error.value.details).lower() for term in ("readiness", "inventory"))
    assert runner.execute_calls == 0


@pytest.mark.parametrize(
    "change", ["missing_context", "missing_id", "schema", "extra", "oversized", "null_execute"]
)
def test_invalid_review_context_is_refused_before_effects(service, monkeypatch, change):
    source = source_run(service, execute=True)
    preparation = service.prepare_replay(source["run_id"], {"target_scope": SCOPE})
    payload = {
        **preparation["replay_request"],
        "preparation_id": preparation["preparation_id"],
        "preparation_context": deepcopy(preparation["preparation_context"]),
        "approval": {"confirmed": True, "approved_by": "reviewer"},
    }
    if change == "missing_context":
        del payload["preparation_context"]
    elif change == "missing_id":
        del payload["preparation_id"]
    elif change == "schema":
        payload["preparation_context"]["schema_version"] = "unknown"
    elif change == "extra":
        payload["preparation_context"]["approved"] = True
    elif change == "oversized":
        payload["preparation_context"]["runner_readiness"]["extra"] = "x" * 65536
    else:
        payload["preparation_context"]["runner_readiness"] = None
    block_effects(service, monkeypatch)
    with pytest.raises(APIError) as error:
        service.replay(source["run_id"], payload)
    assert error.value.code == "replay_refused"
    assert "preparation" in str(error.value.details)


def test_preparation_identity_does_not_supply_execute_approval(service, monkeypatch):
    source = source_run(service, execute=True)
    preparation = service.prepare_replay(source["run_id"], {"target_scope": SCOPE})
    block_effects(service, monkeypatch)
    with pytest.raises(APIError) as error:
        service.replay(
            source["run_id"],
            {
                **preparation["replay_request"],
                "preparation_id": preparation["preparation_id"],
                "preparation_context": preparation["preparation_context"],
            },
        )
    assert error.value.code == "approval_required"


def test_exact_simulate_preparation_uses_only_resolved_historical_registry(service, monkeypatch):
    from bluefire.registry import BehaviorRegistry

    source = source_run(service)
    original_resolver = service._historical_action_catalog
    historical_tier = service._maximum_tier(
        service._scenario_or_api_error({"scenario": source["scenario"]})
    )

    def distinct_historical_registry(authority):
        catalog, resolved_authority = original_resolver(authority)
        historical = BehaviorRegistry(catalog.registry.behaviors, catalog.registry.actions)
        return replace(catalog, registry=historical), resolved_authority

    # Historical resolution is a separate immutable registry. Once resolved,
    # preparation must not consult the currently active registry for its tier.
    monkeypatch.setattr(service, "_historical_action_catalog", distinct_historical_registry)
    monkeypatch.setattr(service.registry, "get_behavior", forbid)
    block_effects(service, monkeypatch)
    preparation = service.prepare_replay(source["run_id"], {"exact": True})
    assert preparation["preflight"]["status"] == "ready"
    assert preparation["preflight"]["safety_tier"] == historical_tier
    assert preparation["scenario"] == source["scenario"]
    assert preparation["preflight"]["plan"] == source["plan"]


def test_preparation_binds_managed_collector_authority_before_approval(service, monkeypatch):
    from bluefire.collectors import CollectorRegistry, CollectorRuntimeSettings, FilesystemCollector

    source = source_run(service, execute=True)
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {"schedule": "after_each_producer", "paths": ["staged/bundle.jsonl"]},
            }
        }
    )
    service.collector_registry_factory = lambda root: CollectorRegistry(
        (FilesystemCollector(root, max_file_bytes=1024),)
    )
    block_effects(service, monkeypatch)
    preparation = service.prepare_replay(
        source["run_id"], {"target_scope": SCOPE, "collector_runtime": runtime.to_dict()}
    )
    assert preparation["preflight"]["collector_binding"]["settings_hash"] == runtime.settings_hash
    assert preparation["preflight"]["collector_registry_authority"] is not None
    service.collector_registry_factory = lambda root: CollectorRegistry(
        (FilesystemCollector(root, max_file_bytes=2048),)
    )
    with pytest.raises(APIError) as error:
        service.replay(
            source["run_id"],
            {
                **preparation["replay_request"],
                "preparation_id": preparation["preparation_id"],
                "preparation_context": preparation["preparation_context"],
                "approval": {"confirmed": True, "approved_by": "reviewer"},
            },
        )
    assert "preparation changed" in str(error.value.details)
