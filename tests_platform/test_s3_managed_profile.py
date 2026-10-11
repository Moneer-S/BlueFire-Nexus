"""Dedicated S3 profile drafts persist without enrolling or executing a host."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from bluefire.application_errors import APIError
from bluefire.config import RunnerProfile
from bluefire.contracts import ExecutionMode
from bluefire.registry import RegistryError, load_builtin_registry
from bluefire.runner_contracts import seal_profile
from bluefire.s3_access_contract import S3AccessScope
from bluefire.s3_access_executor import configured_executor
from bluefire.s3_access_onboarding import setup_profiles
from bluefire.s3_access_profile import ACTION, validate_managed_s3_profile
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_s3_access_executor import configured as configured

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def document():
    value = json.loads((ROOT / "frontend/src/lib/s3-profile-template.json").read_text())
    value["id"] = "test-s3-setup.v1"
    return value


@pytest.fixture
def service(tmp_path):
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.db"
    )
    try:
        yield instance
    finally:
        instance.close()


def test_ui_template_is_valid_but_never_an_ordinary_catalog_method(document):
    profile = RunnerProfile.from_mapping(document)
    assert validate_managed_s3_profile(profile)
    registry = load_builtin_registry()
    assert ACTION not in registry.action_ids
    with pytest.raises(RegistryError):
        registry.validate_runner_profile(profile)


def test_explicit_activation_persists_and_deactivation_removes_setup_selection(
    service, document, monkeypatch
):
    def unexpected(*args, **kwargs):
        pytest.fail("Profile management must not contact or prepare a runner")

    monkeypatch.setattr(service.runner_lifecycle, "client_for_profile", unexpected)
    saved = service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    assert saved["resource"]["status"] == "draft"
    assert setup_profiles(service)["profiles"] == []
    service._refresh_runtime_configuration()
    assert setup_profiles(service)["profiles"] == []
    activated = service.activate_resource("runner_profile", document["id"], {})
    assert activated["resource"]["status"] == "active"
    assert [row["profile_id"] for row in setup_profiles(service)["profiles"]] == [document["id"]]
    service._refresh_runtime_configuration()
    assert len(setup_profiles(service)["profiles"]) == 1
    ordinary = service._profile(document["id"], ExecutionMode.EXECUTE)
    assert ordinary is not None and ACTION not in ordinary.enabled_actions
    assert ACTION not in {row["id"] for row in service.catalog()["actions"]}
    service.deactivate_resource("runner_profile", document["id"], {})
    assert setup_profiles(service)["profiles"] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("environment_type", "production"),
        ("platforms", ["linux", "windows"]),
        ("scope", ["sandbox.workspace", "network.loopback"]),
        ("network_allowlist", ["127.0.0.0/8"]),
        ("capabilities", ["cloud.aws.s3.access", "filesystem.write"]),
        ("capabilities", ["filesystem.write"]),
        ("enabled_actions", [ACTION, "sandbox.cleanup.v1"]),
        ("enabled_actions", ["sandbox.cleanup.v1"]),
        ("blocked_actions", [ACTION]),
        ("safety_tiers", ["safe", "controlled", "restricted"]),
        ("approval_required", False),
        ("cleanup_policy", "manual"),
        ("secrets", {"cloud": {"env": "UNUSED_TEST_REFERENCE"}}),
    ],
)
def test_mixed_or_wider_s3_profile_cannot_activate(service, document, field, value):
    document = deepcopy(document)
    document[field] = value
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    with pytest.raises(APIError) as refused:
        service.activate_resource("runner_profile", document["id"], {})
    assert refused.value.code == "resource_activation_invalid"
    assert service.resource("runner_profile", document["id"])["resource"]["status"] == "draft"
    assert setup_profiles(service)["profiles"] == []


def test_ordinary_profiles_still_use_normal_registry(service):
    profile = service.config.runner_profiles[0]
    assert not validate_managed_s3_profile(profile)
    assert service._validated_runner_profile(profile.to_dict(), profile.id) == profile


def test_activation_requires_budget_for_largest_fixed_stage(service, document):
    from bluefire.s3_access_results import PHASES

    minimum = max(map(len, PHASES.values()))
    assert minimum == 2
    document["budgets"]["max_steps"] = minimum - 1
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    with pytest.raises(APIError) as caught:
        service.activate_resource("runner_profile", document["id"], {})
    assert caught.value.code == "resource_activation_invalid"
    assert setup_profiles(service)["profiles"] == []
    document["budgets"]["max_steps"] = minimum
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    service.activate_resource("runner_profile", document["id"], {})
    assert setup_profiles(service)["profiles"][0]["profile_digest"] == content_hash(
        RunnerProfile.from_mapping(document).to_dict()
    )


def test_managed_only_activation_edit_and_deactivation_reach_the_executor(
    service, document, configured, monkeypatch
):
    native = configured.row["profile"]
    native["profile_id"] = document["id"]
    configured.row["profile"] = seal_profile(native)
    configured.row["managed_profile_digest"] = content_hash(
        RunnerProfile.from_mapping(document).to_dict()
    )
    monkeypatch.setattr(
        service.runner_lifecycle,
        "client_for_profile",
        configured.service.runner_lifecycle.client_for_profile,
    )
    executor = configured_executor(service)
    scope = S3AccessScope.from_mapping(configured.row["environment"]["scope"])
    assert document["id"] not in {p.id for p in service.config.runner_profiles}
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    assert executor.environments() == []
    service.activate_resource("runner_profile", document["id"], {})
    assert executor.readiness(scope)["available"] is True
    service.deactivate_resource("runner_profile", document["id"], {})
    assert executor.environments() == []
    document["budgets"]["max_seconds"] = 30
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    service.activate_resource("runner_profile", document["id"], {})
    assert executor.readiness(scope)["problem"] == "profile_changed"
    assert not executor.readiness(scope)["available"]
    assert configured.client.calls == []
