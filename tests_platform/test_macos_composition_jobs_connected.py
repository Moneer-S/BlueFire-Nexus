"""Real composition jobs, orchestration and run bundles; fake Darwin/OS boundary only."""

import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock
from types import SimpleNamespace

import pytest

from bluefire import collectors as collector_module
from bluefire import composition_context, composition_jobs, orchestrator, policy, runner_contracts
from bluefire import macos_file_access_control as macos_control
from bluefire import macos_file_access_method as method
from bluefire import product_store_macos_settlement as settlement
from bluefire.action_catalog import ActionCatalogSnapshot
from bluefire.capability_packs import MACOS_FILE_ACCESS_METHODS, MACOS_FILE_ACCESS_PACK
from bluefire.composition_jobs import CompositionJobs
from bluefire.macos_file_access_context import OriginalMacOSCompositionRunner
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RUN_ID_RE, RunStore
from bluefire.runner_contracts import verify_macos_file_access_binding
from bluefire.util import content_hash
from tests_platform import test_macos_composition_connected as connected_cases
from tests_platform.test_runner_contracts import _execute_profile


def test_macos_attempt_deadlines_preserve_cleanup_reserve_at_workspace_expiry():
    origin_ms = 1_000
    started_ns = 5_000_000_000
    lease = {"business_expires_at_ms": 131_000, "attempt_expires_at_ms": 151_000}
    business, cleanup = composition_jobs._macos_attempt_deadlines(
        {"original_deadline_ns": started_ns + 120_000_000_000},
        lease,
        origin_ms,
        started_ns,
    )
    assert cleanup == started_ns + 120_000_000_000
    assert business == cleanup - 20_000_000_000
    assert business < cleanup


def test_macos_admission_rejects_cleanup_only_window_and_caps_late_business_time():
    reservation = {"reserved_attempt_ms": 30_000, "cleanup_reserve_ms": 5_000}
    origin_ms = 1_000
    started_ns = 5_000_000_000
    with pytest.raises(ProductStoreError, match="no business window"):
        composition_jobs._macos_attempt_admission_deadlines(
            {"original_deadline_ns": started_ns + 5_000_000_000},
            reservation,
            100_000,
            origin_ms,
            started_ns,
        )

    business, cleanup = composition_jobs._macos_attempt_admission_deadlines(
        {"original_deadline_ns": started_ns + 8_000_000_000},
        reservation,
        100_000,
        origin_ms,
        started_ns,
    )
    assert cleanup == started_ns + 8_000_000_000
    assert business == started_ns + 3_000_000_000


creator_fake = connected_cases.creator_fake
original = connected_cases.original
pack_state = connected_cases.pack_state
connected = connected_cases.connected


@pytest.fixture
def jobs_connected(connected, pack_state, tmp_path, monkeypatch):
    context = connected
    store, state = context.store, context.state
    # The imported fixture already owns a one-shot claimed attempt. Settle it
    # honestly rather than deleting its rows or reusing its synthetic plan claim.
    for index in range(3):
        assert context.execute(index)["status"] == "success"
    store.settle_capability_attempt(
        context.lease["attempt_id"], settlement.receipt(store, context.lease["attempt_id"])
    )
    assert store.get_capability_attempt(context.lease["attempt_id"])["state"] == "settled"
    store.release_macos_attempt_workspace(context.lease["attempt_id"])
    assert context.producer._used_budget == 5
    state.update(wall=6000, clock=5_000_001_000)
    grant_view = store.get_capability_grant(context.lease["grant_id"], now_ms=state["wall"])
    assert grant_view["cleanup_state"] == "settled"
    grant = grant_view["document"]
    environment = grant["environment"]
    objective_id = store.get_job(context.lease["job_id"])["request"]["composition_attempt"][
        "parent_job_id"
    ]
    endpoint = macos_control.endpoint(None)
    endpoint._recipe = {
        "binding": endpoint.current_setup()["binding"],
        "source_sha256": {
            name: content_hash({"fake protected source": name})
            for name in (
                "bluefire/macos_file_access_context.py",
                "bluefire/macos_file_access_bridge.py",
                "bluefire/macos_file_access_method.py",
                "bluefire/runner_contracts.py",
                "bluefire/macos_file_access_workspace_bootstrap.py",
                "bluefire/product_store_macos_composition.py",
                "bluefire/product_store_macos_completion.py",
                "bluefire/product_store_macos_workspace.py",
                "bluefire/product_store_macos_settlement.py",
                "bluefire/macos_file_access_intent.py",
                "bluefire/macos_attempt_workspace.py",
                "bluefire/composition_macos_file_access.py",
                "bluefire/macos_file_access_clock.py",
                "bluefire/macos_file_access_control.py",
                "bluefire/macos_file_access_workspace_validation.py",
                "bluefire/macos_file_access_endpoint.py",
                "bluefire/composition_result.py",
                "bluefire/product_store_capability_payloads.py",
                "bluefire/product_store_file_access_records.py",
                "bluefire/product_store_macos_setup.py",
            )
        },
        "runtime_sha256": {"fake-python": content_hash("fake protected interpreter")},
    }
    run_store = RunStore(tmp_path / "orchestrated-runs")
    registry = pack_state["registry"]
    catalog_document = store.get_action_package_catalog_snapshot()
    assert catalog_document["packages"] == []
    catalog = ActionCatalogSnapshot.compose(
        registry,
        generation=catalog_document["generation"],
        catalog_digest=catalog_document["catalog_digest"],
    )
    indexed = []
    service = SimpleNamespace(
        product_store=store,
        job_controller=SimpleNamespace(),
        store=run_store,
        _catalog_snapshot=catalog,
        _index_run=indexed.append,
        _isolated_owned_sandbox=lambda root, attempt_id: root / attempt_id,
        detection_lab=SimpleNamespace(run_store=run_store),
    )
    runner = OriginalMacOSCompositionRunner(service)
    profile = replace(
        _execute_profile(),
        platforms=("macos",),
        enabled_actions=MACOS_FILE_ACCESS_METHODS,
        native_tool_installations=(),
    )
    binding = context.producer._binding()
    current = {
        "registry": catalog.registry,
        "implementation_digests": pack_state["implementations"],
        "current_environment": environment,
        "profile": profile,
        "runner": runner,
        "sandbox": tmp_path / "orchestrated-workspaces",
        "collector_runtime": None,
        "collector_ids": (),
        "runner_readiness": {
            "schema_version": "bluefire.macos-workspace-readiness.v1",
            "platform": "macos",
            "transport": runner.transport_identity(),
            "inventory": runner.inventory(),
            "evidence": "original_producer_metadata",
            "independent_telemetry": False,
        },
        "run_intent": {
            "runner_profile_id": profile.id,
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        },
        "macos_file_access_binding": verify_macos_file_access_binding(
            binding,
            expected_document_digest=content_hash(binding),
            now_ms=state["wall"],
            now_monotonic_ns=state["clock"],
        ),
    }

    def resolve(selected_service, owner_id, *, pack):
        assert selected_service is service and owner_id == environment["control_owner_id"]
        assert pack == MACOS_FILE_ACCESS_PACK
        endpoint.assert_current()
        return current

    monkeypatch.setattr(composition_context, "resolve", resolve)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = datetime.fromtimestamp(state["wall"] / 1000, timezone.utc)
            return value if tz is None else value.astimezone(tz)

    monkeypatch.setattr(runner_contracts, "datetime", FixedDateTime)
    monkeypatch.setattr(policy, "datetime", FixedDateTime)
    monkeypatch.setattr(runner_contracts, "current_platform", lambda: "macos")
    monkeypatch.setattr(orchestrator, "current_platform", lambda: "macos")
    observers = []

    class MetadataOnlyObserver:
        def __init__(self, sandbox_root, **options):
            assert not options or (
                set(options) == {"max_file_bytes", "read_timeout_seconds"}
                and type(options["max_file_bytes"]) is int
                and options["max_file_bytes"]
                in (64 * 1024 * 1024, collector_module.MAX_COLLECTION_BYTES)
                and type(options["read_timeout_seconds"]) is float
                and options["read_timeout_seconds"] == 5.0
            )
            self.root = Path(sandbox_root).absolute()
            assert self.root == (current["sandbox"] / marker["attempt_id"]).absolute()
            assert self.root.is_dir()
            self.constructor_options = dict(options)
            self.observation_calls = []
            observers.append(self)

        def observe_file(self, **request):
            self.observation_calls.append(request)
            raise AssertionError("The metadata-only Mac graph must not observe filesystem reports")

        def empty_posix_inventory(self):
            raise AssertionError(
                "The synthetic observer cannot establish original directory custody"
            )

    # Direct and default-registry observers would pin Windows handles here.
    # Their construction supplies no read evidence or custody proof; both uses refuse.
    monkeypatch.setattr(orchestrator, "SandboxObserver", MetadataOnlyObserver)
    monkeypatch.setattr(collector_module, "SandboxObserver", MetadataOnlyObserver)
    collector_dispatches = []

    def refuse_collection(_registry, *args, **kwargs):
        collector_dispatches.append((args, kwargs))
        raise AssertionError("The metadata-only Mac graph must not dispatch any collector")

    monkeypatch.setattr(collector_module.CollectorRegistry, "collect", refuse_collection)
    monkeypatch.setattr(collector_module.CollectorRegistry, "collect_configured", refuse_collection)
    monitors = []

    class Monitor:
        def __init__(self, *, target, name, daemon):
            self.target, self.started, self.joined = target, False, False
            assert daemon and name.startswith("composition-deadline-")
            monitors.append(self)

        def start(self):
            self.started = True

        def join(self, *, timeout):
            assert timeout == 2
            self.joined = True

        def is_alive(self):
            return False

    monkeypatch.setattr(
        composition_jobs, "threading", SimpleNamespace(Event=Event, Thread=Monitor, Lock=Lock)
    )
    jobs = CompositionJobs(service, clock=lambda: state["wall"])
    token = uuid.uuid4()
    run_id = run_store._new_run_id()
    assert RUN_ID_RE.fullmatch(run_id)
    marker = {
        "parent_job_id": objective_id,
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "attempt_id": "attempt-" + token.hex,
        "compiled_digest": context.compiled["compiled_digest"],
        "run_id": run_id,
    }
    request = {"composition_attempt": marker}
    job, created = store.create_idempotent_job(
        "composition.attempt",
        request,
        submission_id=str(token),
        intent_digest=content_hash(request),
    )
    assert created and job["job_id"] == "job-" + token.hex
    store.transition_job(job["job_id"], "planning")
    store.transition_job(job["job_id"], "running")
    checkpoints = []
    ctx = SimpleNamespace(
        job_id=job["job_id"],
        cancellation_event=Event(),
        checkpoint=lambda *values: checkpoints.append(values),
    )
    before_frames, before_phases = len(context.frames), len(context.guard_phases)

    def run():
        assert current["collector_ids"] == () and current["collector_runtime"] is None
        return jobs._execute(ctx, request, context.compiled)

    return SimpleNamespace(
        context=context,
        store=store,
        run_store=run_store,
        jobs=jobs,
        run=run,
        marker=marker,
        run_id=run_id,
        job_id=job["job_id"],
        monitors=monitors,
        observers=observers,
        collector_dispatches=collector_dispatches,
        indexed=indexed,
        checkpoints=checkpoints,
        before_frames=before_frames,
        before_phases=before_phases,
    )


def _assert_finalized_without_native_artifact_reports(current):
    run = current.run_store.get_run(current.run_id)
    assert run["manifest"]["run_id"] == run["run_id"] == current.run_id
    assert run["scenario"] == current.context.compiled["scenario"]
    assert {
        row["step_id"]: row["action_id"] for row in run["plan"]["steps"]
    } == current.context.compiled["action_implementations"]
    rows = run["evidence"]["records"]
    actual = [row for row in rows if row["producer"] == "bluefire-macos-original-workspace"]
    assert actual
    assert all(row["content"]["expected_observable_paths"] == [] for row in actual)
    assert all(row["provenance"] != "observed" for row in rows)
    assert run["policy"]["runner_readiness"]["independent_telemetry"] is False
    assert "collector_binding" not in run["policy"]["approval_context"]
    assert "collector_registry_authority" not in run["policy"]["approval_context"]
    assert current.monitors and all(row.started and row.joined for row in current.monitors)
    assert [row.constructor_options for row in current.observers] == [
        {},
        {"max_file_bytes": 64 * 1024 * 1024, "read_timeout_seconds": 5.0},
        {"max_file_bytes": collector_module.MAX_COLLECTION_BYTES, "read_timeout_seconds": 5.0},
    ]
    assert all(not row.observation_calls for row in current.observers)
    assert not current.collector_dispatches
    assert current.marker["attempt_id"] not in current.store._macos_attempt_workspaces
    assert current.checkpoints
    return run, actual


def test_real_jobs_orchestrator_and_run_store_preserve_exact_mac_attempt_chain(jobs_connected):
    current = jobs_connected
    result = current.run()
    assert result.result_ref == current.run_id
    run, evidence = _assert_finalized_without_native_artifact_reports(current)
    attempt = current.store.get_capability_attempt(current.marker["attempt_id"])
    assert attempt["state"] == "settled"
    assert attempt["lease"]["plan_digest"] == content_hash(run["plan"])
    claim = attempt["claim"]
    assert content_hash(claim["document"]) == claim["document_digest"]
    assert run["policy"]["grant_attempt"] == runner_contracts._canonical_grant_attempt(
        claim["document"], wire=False
    )
    assert len(attempt["tasks"]) == len(evidence) == 3
    assert {row["action_id"] for row in evidence} == set(MACOS_FILE_ACCESS_METHODS)
    assert {row["content"]["runner_task_id"] for row in evidence} == {
        row["task_id"] for row in attempt["tasks"]
    }
    steps = {row["action_id"]: row for row in run["steps"]}
    assert steps[method.PROBE_ACTION]["artifacts"]["probe"]["type"] == method.PROBE_TYPE
    assert steps[method.OWNER_ACTION]["artifacts"]["verification"]["type"] == method.VERIFY_TYPE
    closure = steps[method.CLOSE_ACTION]["artifacts"]["closure"]["attempt_closure"]
    assert closure["original_workers"] == "retained" and not closure["whole_enrollment_cleanup"]
    frames = current.context.frames[current.before_frames :]
    assert len(frames) == 3 and frames[-1]["intent"]["operation"] == "close_attempt"
    assert (
        frames[-1]["claim"]["manifest"]["macos_file_access_cleanup"]
        == frames[-1]["attempt"]["cleanup_claim"]
    )
    assert current.context.producer._used_budget == 7
    assert current.context.guard_phases[current.before_phases :] == [
        "reserve",
        "pre_close",
        "post_close",
    ]
    assert len(current.indexed) == 1
    progress = current.store.get_job(current.job_id)["progress"]
    assert progress["settlement"] == "settled" and progress["finalized_run_id"] == current.run_id
    assert progress["macos_file_access_request_state"] == "verified_closed"


def test_unknown_owner_keeps_finalized_run_evidence_but_cannot_settle_or_replay(jobs_connected):
    current = jobs_connected
    current.context.state["fail_role"] = "owner"
    result = current.run()
    assert result.result_ref == current.run_id
    run, evidence = _assert_finalized_without_native_artifact_reports(current)
    assert len(evidence) == 2
    unknown = next(row for row in evidence if row["action_id"] == method.OWNER_ACTION)
    assert unknown["content"]["runner_status"] == "error"
    assert unknown["content"]["output"]["macos_receipt"]["state"] == "unknown"
    attempt = current.store.get_capability_attempt(current.marker["attempt_id"])
    assert attempt["state"] == "claimed" and len(attempt["tasks"]) == 2
    progress = current.store.get_job(current.job_id)["progress"]
    assert progress["settlement"] == "pending_cleanup"
    assert progress["finalized_run_id"] == current.run_id
    assert progress["macos_file_access_request_state"] == "unknown"
    assert current.context.producer._used_budget == 7
    assert len(current.context.frames[current.before_frames :]) == 2
    assert run.get("cleanup", {}).get("success") is not True
    assert run["status"] == "incomplete" and run["objective_reached"] is False
    assert run["attempt_closure"]["attempted"] is True
    assert run["attempt_closure"]["success"] is False
    close = next(row for row in run["steps"] if row["action_id"] == method.CLOSE_ACTION)
    assert close["status"] == "blocked" and close["execution_disposition"] == "not_dispatched"
    assert close["artifacts"] == {} and close["receipts"] == []
    assert len(current.indexed) == 1
    prior_calls = len(current.context.state["calls"])
    with pytest.raises(ProductStoreError, match="Unknown Darwin dispatch"):
        current.store.claim_macos_capability_cleanup(
            current.marker["attempt_id"],
            now_ms=current.context.state["wall"],
            now_monotonic_ns=current.context.state["clock"],
        )
    assert len(current.context.frames[current.before_frames :]) == 2
    assert len(current.context.state["calls"]) == prior_calls
    with current.store._connection() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM capability_attempt_settlements WHERE attempt_id=?",
                (current.marker["attempt_id"],),
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM capability_macos_file_access_closures WHERE attempt_id=?",
                (current.marker["attempt_id"],),
            ).fetchone()
            is None
        )
