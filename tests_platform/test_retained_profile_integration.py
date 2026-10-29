"""Versioned packaged method selection without a runner or an authority upgrade."""

from pathlib import Path

import pytest

from bluefire.capability_grant import create_grant
from bluefire.capability_resources import METHODS
from bluefire.config import load_config
from bluefire.contracts import ExecutionMode
from bluefire.product_store import ProductStore
from bluefire.retained_artifact_contract import METHOD
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_capability_composition import state as state

ROOT = Path(__file__).resolve().parents[1]
LEGACY_PROFILE = "sandbox-endpoint-deep-lab.v1"
RETAINED_PROFILE = "sandbox-endpoint-deep-lab.v2"
LEGACY_ACTIONS = (
    "sandbox.execution.native-canary.v1",
    "endpoint.discovery.system.v1",
    "endpoint.discovery.processes.v1",
    "sandbox.restricted.persistence-marker.v1",
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.collection.stage.v1",
    "sandbox.observability.variant.v1",
    "sandbox.peer.handoff.v1",
    "sandbox.cleanup.v1",
)


@pytest.mark.parametrize("relative", ["config", "bluefire/data"])
def test_retained_profile_is_an_explicit_revision_with_a_closed_action_set(relative):
    config = load_config(ROOT / relative / "bluefire.example.yaml")
    profiles = {profile.id: profile for profile in config.runner_profiles}
    legacy = profiles[LEGACY_PROFILE]
    retained = profiles[RETAINED_PROFILE]
    assert legacy.enabled_actions == LEGACY_ACTIONS
    assert retained.enabled_actions == (*LEGACY_ACTIONS[:9], METHOD, *LEGACY_ACTIONS[9:])
    expected = {
        **legacy.to_dict(),
        "id": RETAINED_PROFILE,
        "enabled_actions": list(retained.enabled_actions),
    }
    assert retained.to_dict() == expected
    assert content_hash(retained.to_dict()) != content_hash(legacy.to_dict())
    assert retained.approval_required
    for profile in config.runner_profiles:
        if profile.id != RETAINED_PROFILE:
            assert METHOD not in profile.enabled_actions


def test_fresh_installed_profile_requires_explicit_retained_revision_selection(tmp_path):
    service = BlueFireService(
        project_root=tmp_path / "installed",
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.db",
    )
    try:
        legacy = service._profile(LEGACY_PROFILE, ExecutionMode.EXECUTE)
        retained = service._profile(RETAINED_PROFILE, ExecutionMode.EXECUTE)
        assert legacy.enabled_actions == LEGACY_ACTIONS
        assert METHOD in retained.enabled_actions
        assert METHOD not in retained.blocked_actions
        assert service.config.active_profile != RETAINED_PROFILE
        saved = service.product_store.get_resource("runner_profile", RETAINED_PROFILE)
        assert saved["status"] == "configured"
        assert saved["document"] == retained.to_dict()
    finally:
        service.close()


def test_legacy_grant_on_retained_profile_keeps_its_original_method_authority(state):
    config = load_config(ROOT / "bluefire/data/bluefire.example.yaml")
    profile = next(profile for profile in config.runner_profiles if profile.id == RETAINED_PROFILE)
    old = state["grant"]
    environment = {**old["environment"], "profile_digest": content_hash(profile.to_dict())}
    grant = create_grant(
        registry=state["registry"],
        implementation_digests=state["implementation_digests"],
        environment=environment,
        **{
            key: old[key]
            for key in (
                "objective",
                "limits",
                "grant_id",
                "approved_by",
                "created_at_ms",
                "expires_at_ms",
            )
        },
    )
    assert METHOD in profile.enabled_actions
    assert grant["schema_version"] == "bluefire.capability-grant.v1"
    assert tuple(method["action_id"] for method in grant["snapshot"]["methods"]) == METHODS
    assert METHOD not in {method["action_id"] for method in grant["snapshot"]["methods"]}
    assert grant["snapshot"]["artifact_context"]["materialization"] == "fresh_attempt"
    assert "retention" not in grant["snapshot"]["artifact_context"]
    assert grant["environment"] == environment
    assert old["environment"]["control_digest"] == environment["control_digest"]


@pytest.mark.parametrize("status", ["configured", "active", "inactive"])
def test_packaged_revision_preserves_saved_legacy_profile_across_reopen(tmp_path, status):
    config = load_config(ROOT / "bluefire/data/bluefire.example.yaml")
    legacy = next(profile for profile in config.runner_profiles if profile.id == LEGACY_PROFILE)
    store = ProductStore(tmp_path / "product.db")
    before = store.save_resource("runner_profile", LEGACY_PROFILE, legacy.to_dict(), status=status)
    for _ in range(2):
        service = BlueFireService(
            project_root=tmp_path / "installed",
            runs_dir=tmp_path / "runs",
            product_db_path=tmp_path / "product.db",
        )
        try:
            profiles = {profile.id: profile for profile in service._runner_profiles()}
            if status == "inactive":
                assert LEGACY_PROFILE not in profiles
            else:
                assert profiles[LEGACY_PROFILE].to_dict() == legacy.to_dict()
                assert METHOD not in profiles[LEGACY_PROFILE].enabled_actions
            assert service.product_store.get_resource("runner_profile", LEGACY_PROFILE) == before
            assert METHOD in profiles[RETAINED_PROFILE].enabled_actions
        finally:
            service.close()
