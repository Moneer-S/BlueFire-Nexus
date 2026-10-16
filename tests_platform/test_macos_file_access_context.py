"""Pure context/preflight contracts; endpoint, paths and storage are all fakes."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from threading import RLock
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_context as context
from bluefire import macos_file_access_control as macos_control
from bluefire import product_store_macos_file_access as macos
from bluefire.capability_packs import MACOS_FILE_ACCESS_METHODS
from bluefire.config import EnvironmentReference, EnvironmentType, RunnerProfile
from bluefire.contracts import (
    ActionDefinition,
    BehaviorDefinition,
    ExecutionMode,
    ScenarioDefinition,
    StepOutcome,
)
from bluefire.macos_file_access_endpoint import OriginalWorkspaceEndpoint
from bluefire.orchestrator import Orchestrator
from bluefire.product_store_errors import ProductStoreError
from bluefire.registry import BehaviorRegistry
from bluefire.runner_contracts import VerifiedMacOSFileAccessBinding
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_macos_file_access_contract import binding

REQUIRED_SOURCES = (
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
PROVENANCE = {
    "source": "Pure context fake",
    "reference": "test:macos-context",
    "license": "MIT",
    "derived": False,
}


def profile():
    return RunnerProfile.from_mapping(
        {
            "id": "runner-profile.macos-test.v1",
            "mode": "execute",
            "environment_type": "disposable",
            "platforms": ["macos"],
            "runner_binary": {"env": "BLUEFIRE_MACOS_RUNNER"},
            "sandbox_root": {"env": "BLUEFIRE_MACOS_SANDBOX"},
            "scope": ["sandbox.workspace"],
            "network_allowlist": [],
            "capabilities": ["filesystem.read", "cleanup"],
            "safety_tiers": ["controlled"],
            "approval_required": True,
            "enabled_actions": list(MACOS_FILE_ACCESS_METHODS),
            "blocked_actions": [],
            "cleanup_policy": "always",
            "budgets": {"max_steps": 3, "max_seconds": 10, "max_artifacts": 8, "max_bytes": 1024},
            "secrets": {},
        }
    )


def registry():
    ports = [
        (
            [],
            [
                {"name": "probe", "type": "artifact.macos_file_access.probe.v1"},
                {"name": "workspace", "type": "artifact.macos_file_access.attempt.v1"},
            ],
        ),
        (
            [{"name": "probe", "type": "artifact.macos_file_access.probe.v1"}],
            [{"name": "verification", "type": "artifact.macos_file_access.verification.v1"}],
        ),
        (
            [{"name": "workspace", "type": "artifact.macos_file_access.attempt.v1"}],
            [{"name": "closure", "type": "artifact.macos_file_access.attempt_closure.v1"}],
        ),
    ]
    actions, behaviors = [], []
    for index, action in enumerate(MACOS_FILE_ACCESS_METHODS):
        inputs, outputs = ports[index]
        common = {
            "id": action,
            "title": "Pure metadata method",
            "purpose": "Pure context/preflight fake only",
            "safety_tier": "controlled",
            "platforms": ["macos"],
            "capabilities": ["cleanup"] if index == 2 else ["filesystem.read"],
            "inputs": inputs,
            "outputs": outputs,
            "parameters": [],
            "provenance": PROVENANCE,
        }
        actions.append(
            ActionDefinition.from_mapping(
                {
                    **common,
                    "schema_version": "bluefire.action.v1",
                    "mutates": False,
                    "cleanup_action_id": None if index == 2 else MACOS_FILE_ACCESS_METHODS[2],
                }
            )
        )
        behaviors.append(
            BehaviorDefinition.from_mapping(
                {
                    **common,
                    "schema_version": "bluefire.behavior.v1",
                    "execution_state": "action",
                    "techniques": [],
                    "simulation_id": None,
                    "action_ids": [action],
                    "telemetry": [],
                    "detection_hints": [],
                    "limitations": ["Pure metadata fake only"],
                }
            )
        )
    return BehaviorRegistry(behaviors, actions)


@pytest.fixture
def original(monkeypatch):
    initial = binding()
    actual = {**deepcopy(initial), "mode": "0600", "control_revision": 3}
    setup = {"schema_version": macos.SETUP_SCHEMA, "binding": initial}
    enrolled = macos.enrollment_document(setup)
    control = {
        **macos.imported_control(setup),
        "revision": 3,
        "status": "hardened",
        "binding": actual,
        "binding_digest": content_hash(actual),
        "baseline": {
            "baseline_digest": content_hash("synthetic-baseline"),
            "non_owner": "allowed",
            "owner": "allowed",
            "record_count": 8,
            "sha256": actual["resource"]["sha256"],
        },
    }
    owner = control["control_owner_id"]
    state = {
        "control": control,
        "creator": deepcopy(actual),
        "pending": None,
        "lost": False,
        "guards": 0,
        "reviews": [],
        "collectors": [],
    }
    endpoint = object.__new__(OriginalWorkspaceEndpoint)
    endpoint._recipe = {
        "binding": deepcopy(initial),
        "workspace_root": str(Path("/synthetic/original-workspace").absolute()),
        "source_sha256": {name: "a" * 64 for name in REQUIRED_SOURCES},
        "runtime_sha256": {"synthetic/runtime.py": "b" * 64},
    }

    def assert_current(self, handshake=False):
        assert self is endpoint
        state["guards"] += 1
        if state["lost"]:
            raise OSError("synthetic original endpoint lost")
        return 1.0

    def review_context(self, operation):
        assert self is endpoint and operation == "probe"
        assert_current(self)
        state["reviews"].append(operation)
        return {"binding": deepcopy(state["creator"])}

    monkeypatch.setattr(OriginalWorkspaceEndpoint, "assert_current", assert_current)
    monkeypatch.setattr(OriginalWorkspaceEndpoint, "current_setup", lambda self: deepcopy(setup))
    monkeypatch.setattr(OriginalWorkspaceEndpoint, "review_context", review_context)
    monkeypatch.setattr(context, "darwin_clock_ns", lambda: 6000)
    sandbox = Path(endpoint._recipe["workspace_root"]) / "sandbox"
    monkeypatch.setattr(Path, "is_dir", lambda self: self == sandbox)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self.absolute())
    catalog = SimpleNamespace(
        registry=registry(),
        profile=lambda profile: profile,
        to_dict=lambda: {"catalog": "pure fake"},
    )
    active = profile()
    service = object.__new__(BlueFireService)
    service._macos_workspace_endpoint = endpoint
    service._runtime_configuration_lock = RLock()
    service._runtime_runner_profiles = (active,)
    # Deliberately different immutable startup config: context must use effective profiles.
    service.config = SimpleNamespace(runner_profiles=(replace(active, enabled_actions=()),))
    service._catalog_snapshot = catalog

    def get_control(identity):
        assert identity == owner
        document = deepcopy(state["control"])
        return {
            "document": document,
            "document_digest": content_hash(document),
            "pending_operation": state["pending"],
        }

    service.product_store = SimpleNamespace(
        get_file_access_control=get_control,
        get_file_access_enrollment=lambda identity: {
            "document": deepcopy(enrolled),
            "document_digest": content_hash(enrolled),
        },
    )

    def collector_binding(ids, runtime):
        state["collectors"].append((ids, runtime))
        return {"collector_ids": list(ids), "runtime": runtime}

    service._collector_binding = collector_binding
    return SimpleNamespace(
        service=service,
        endpoint=endpoint,
        state=state,
        owner=owner,
        active=active,
        initial=initial,
        actual=actual,
        enrolled=enrolled,
        sandbox=sandbox,
    )


def resolve(original):
    return context.composition(original.service, original.owner, 5000)


def test_effective_profile_and_original_binding_are_used_without_rust_or_collectors(original):
    assert macos_control.endpoint(original.service) is original.endpoint
    current = resolve(original)
    assert current["profile"] == original.active
    assert current["profile"] != original.service.config.runner_profiles[0]
    assert type(current["runner"]) is context.OriginalMacOSCompositionRunner
    assert type(current["macos_file_access_binding"]) is VerifiedMacOSFileAccessBinding
    assert current["macos_file_access_binding"].to_dict() == original.actual
    assert current["sandbox"] == original.sandbox
    assert current["collector_ids"] == () and current["collector_runtime"] is None
    assert original.state["collectors"] == [((), None)]
    environment = current["current_environment"]
    assert environment["enrollment_digest"] == content_hash(current["transport"])
    assert environment["probe_enrollment_digest"] == content_hash(original.enrolled)
    assert environment["enrollment_digest"] != environment["probe_enrollment_digest"]
    assert environment["binding_digest"] == content_hash(original.actual)
    assert environment["workspace_custody_digest"] == original.initial["custody_digest"]
    assert current["baseline"] == original.state["control"]["baseline"]
    assert set(current["implementation_digests"]) == set(MACOS_FILE_ACCESS_METHODS)


@pytest.mark.parametrize("kind", ["inactive", "blocked", "missing_method", "ambiguous"])
def test_effective_profile_removal_or_change_is_not_replaced_by_startup_config(original, kind):
    original.service.config = SimpleNamespace(runner_profiles=(original.active,))
    choices = {
        "inactive": (),
        "blocked": (replace(original.active, blocked_actions=(MACOS_FILE_ACCESS_METHODS[0],)),),
        "missing_method": (
            replace(original.active, enabled_actions=MACOS_FILE_ACCESS_METHODS[:2]),
        ),
        "ambiguous": (original.active, replace(original.active, id="runner-profile.other.v1")),
    }
    original.service._runtime_runner_profiles = choices[kind]
    with pytest.raises(ProductStoreError, match="Select one original workspace profile"):
        resolve(original)


@pytest.mark.parametrize(
    "kind", ["environment", "runner_ref", "sandbox_ref", "secret", "network", "tool"]
)
def test_effective_profile_cannot_replace_original_workspace_or_add_effect_authority(
    original, kind
):
    changes = {
        "environment": {"environment_type": EnvironmentType.PERSISTENT_LAB},
        "runner_ref": {"runner_binary": EnvironmentReference("OTHER_RUNNER")},
        "sandbox_ref": {"sandbox_root": EnvironmentReference("OTHER_SANDBOX")},
        "secret": {"secrets": {"secret": EnvironmentReference("OTHER_SECRET")}},
        "network": {"network_allowlist": ("127.0.0.0/8",)},
        "tool": {"native_tool_installations": (object(),)},
    }
    original.service._runtime_runner_profiles = (replace(original.active, **changes[kind]),)
    with pytest.raises(ProductStoreError, match="extra effect authority"):
        resolve(original)


@pytest.mark.parametrize("kind", ["wrapper", "lost", "different_live", "digest", "revision"])
def test_original_endpoint_and_exact_current_control_are_required(original, kind):
    if kind == "wrapper":
        original.service._macos_workspace_endpoint = SimpleNamespace(assert_current=lambda: 1.0)
    elif kind == "lost":
        original.state["lost"] = True
    elif kind == "different_live":
        original.state["creator"]["custody_digest"] = content_hash("other creator")
    elif kind == "digest":
        original.state["control"]["binding_digest"] = content_hash("other binding")
    else:
        original.state["control"]["revision"] = 4
    with pytest.raises((OSError, ValueError, ProductStoreError)):
        resolve(original)


@pytest.mark.parametrize(
    "field", ["generation", "custody_digest", "resource", "owner", "original_deadline_ns"]
)
def test_live_and_stored_binding_cannot_change_original_immutable_enrollment(original, field):
    changed = deepcopy(original.actual)
    replacement = {
        "generation": "file-generation-" + "9" * 32,
        "custody_digest": content_hash("other custody"),
        "resource": {**changed["resource"], "inode": 99},
        "owner": {**changed["owner"], "groups": [501, 503]},
        "original_deadline_ns": changed["original_deadline_ns"] - 1,
    }
    changed[field] = replacement[field]
    original.state["creator"] = deepcopy(changed)
    original.state["control"]["binding"] = changed
    original.state["control"]["binding_digest"] = content_hash(changed)
    original.state["control"]["generation"] = changed["generation"]
    with pytest.raises(ProductStoreError, match="creator or retained control changed"):
        resolve(original)


@pytest.mark.parametrize(
    "source",
    [
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
    ],
)
def test_original_transport_requires_each_composition_source_pin(original, source):
    del original.endpoint._recipe["source_sha256"][source]
    with pytest.raises(ProductStoreError, match="does not pin the composition implementation"):
        resolve(original)


def test_inventory_rechecks_original_custody_and_runtime_snapshot(original):
    current = resolve(original)
    runner = current["runner"]
    inventory = runner.inventory()
    original.endpoint._recipe["runtime_sha256"]["synthetic/runtime.py"] = "c" * 64
    assert runner.inventory()["transport_digest"] != inventory["transport_digest"]
    with pytest.raises(ProductStoreError, match="exact method graph"):
        runner.validate_plan_inventory(SimpleNamespace(steps=[]), inventory)
    original.state["lost"] = True
    with pytest.raises(OSError, match="original endpoint lost"):
        runner.inventory()


@pytest.mark.parametrize("kind", ["pending", "not_hardened", "no_baseline", "other_enrollment"])
def test_review_requires_settled_original_hardened_control_with_baseline(original, kind):
    if kind == "pending":
        original.state["pending"] = "synthetic-pending"
    elif kind == "not_hardened":
        original.state["control"]["status"] = "baseline_verified"
    elif kind == "no_baseline":
        original.state["control"]["baseline"] = None
    else:
        original.state["control"]["enrollment_id"] = "file-enrollment-" + "9" * 32
    with pytest.raises(ProductStoreError, match="settled hardened"):
        resolve(original)
    assert original.state["reviews"] == []


def scenario():
    methods = MACOS_FILE_ACCESS_METHODS
    return ScenarioDefinition.from_mapping(
        {
            "schema_version": "bluefire.scenario.v1",
            "id": "scenario.macos-context-fake.v1",
            "title": "Pure Mac preflight",
            "purpose": "Pure context/preflight fake only",
            "start": "probe",
            "steps": [
                {"id": "probe", "behavior_id": methods[0], "parameters": {}},
                {
                    "id": "owner",
                    "behavior_id": methods[1],
                    "parameters": {},
                    "inputs": {"probe": {"from_step": "probe", "artifact": "probe"}},
                },
                {
                    "id": "close",
                    "behavior_id": methods[2],
                    "parameters": {},
                    "inputs": {"workspace": {"from_step": "probe", "artifact": "workspace"}},
                },
            ],
            "edges": [
                {"from_step": start, "outcome": outcome.value, "to_step": end}
                for start, end in (("probe", "owner"), ("owner", "close"))
                for outcome in StepOutcome
            ],
            "provenance": PROVENANCE,
        }
    )


def test_custom_original_inventory_and_distinct_close_use_existing_preflight(original, monkeypatch):
    current = resolve(original)
    runner = current["runner"]
    engine = Orchestrator(
        current["registry"],
        store=SimpleNamespace(),
        runner=runner,
        macos_file_access_binding=current["macos_file_access_binding"],
    )
    monkeypatch.setattr(
        engine,
        "_validate_inventory",
        lambda *args, **kwargs: pytest.fail("Mac preflight used Rust inventory authority"),
    )
    graph = scenario()
    report = engine.preflight(
        graph, mode=ExecutionMode.EXECUTE, profile=current["profile"], approval_present=True
    )
    assert report.status == "ready" and report.actions == MACOS_FILE_ACCESS_METHODS
    plan = engine.planner.compile(graph, mode=ExecutionMode.EXECUTE, profile=current["profile"])
    inventory = runner.inventory()
    assert inventory["schema_version"] == context.INVENTORY_SCHEMA
    assert inventory["evidence"] == "original_producer_metadata"
    assert inventory["native_filesystem_receipts"] is False
    runner.validate_plan_inventory(plan, inventory)
    assert engine._cleanup_preflight_problems(plan, current["profile"]) == ()
    changed = deepcopy(inventory)
    changed["actions"].append({"action_id": "sandbox.cleanup.v1", "readiness": "ready"})
    with pytest.raises(ProductStoreError, match="exact method graph"):
        runner.validate_plan_inventory(plan, changed)
    assert (
        engine.preflight(
            graph, mode=ExecutionMode.EXECUTE, profile=current["profile"], approval_present=False
        ).status
        == "approval_required"
    )


@pytest.mark.parametrize("change", ["method", "parameters", "behavior"])
def test_original_inventory_rejects_nonexact_plan_even_with_same_transport(original, change):
    current = resolve(original)
    engine = Orchestrator(
        current["registry"],
        store=SimpleNamespace(),
        runner=current["runner"],
        macos_file_access_binding=current["macos_file_access_binding"],
    )
    plan = engine.planner.compile(
        scenario(), mode=ExecutionMode.EXECUTE, profile=current["profile"]
    )
    first = plan.steps[0]
    mutation = {
        "method": {"action_id": "sandbox.cleanup.v1"},
        "parameters": {"parameters": {"path": "unreviewed"}},
        "behavior": {"behavior_id": "file_access.probe.non_owner.v1"},
    }
    changed = replace(plan, steps=(replace(first, **mutation[change]), *plan.steps[1:]))
    with pytest.raises(ProductStoreError, match="exact method graph"):
        current["runner"].validate_plan_inventory(changed, current["runner"].inventory())
