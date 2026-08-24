from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.api import APIError
from bluefire.config import AutonomyLevel
from bluefire.contracts import load_scenario
from bluefire.service import BlueFireService

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "scenarios" / "sandbox_research_chain.yaml"


def _plugin_manifest(
    plugin_id: str = "plugin.managed.catalog.v1",
    *,
    enabled: bool = True,
    trust: str = "reviewed",
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.plugin.v1",
        "id": plugin_id,
        "name": "Managed catalog metadata",
        "version": "1.0.0",
        "enabled": enabled,
        "trust": trust,
        "integrity": {"algorithm": "sha256", "digest": "a" * 64},
        "license": "MIT",
        "provenance": {
            "source": "Reviewed test fixture",
            "reference": "tests_platform/test_management_service.py",
            "license": "MIT",
            "derived": False,
        },
        "permissions": ["catalog.read"],
        "capabilities": ["sandbox.discovery"],
        "behavior_ids": ["sandbox.fixture.create.v1"],
        "action_ids": [],
    }


@pytest.fixture
def service(tmp_path: Path):
    instance = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    try:
        yield instance
    finally:
        instance.close()


def test_settings_list_upsert_and_reject_ambiguous_or_secret_values(
    service: BlueFireService,
) -> None:
    saved = service.upsert_setting(
        "ui.preferences",
        {"value": {"theme": "dark", "density": "comfortable"}},
    )
    listed = service.settings()

    assert saved["setting"]["key"] == "ui.preferences"
    assert saved["setting"]["value"] == {"theme": "dark", "density": "comfortable"}
    assert saved["setting"] in listed["settings"]

    with pytest.raises(APIError) as unknown_field:
        service.upsert_setting("ui.preferences", {"value": {}, "unexpected": True})
    assert unknown_field.value.status == 400
    assert unknown_field.value.code == "setting_request_invalid"

    with pytest.raises(APIError) as plaintext_secret:
        service.upsert_setting(
            "provider.private",
            {"value": {"nested": {"credentials": "plaintext-value"}}},
        )
    assert plaintext_secret.value.status == 422
    assert plaintext_secret.value.code == "setting_invalid"
    assert "environment-variable reference" in plaintext_secret.value.details[0]


def test_scenario_versions_save_list_and_get_exact_content(
    service: BlueFireService,
) -> None:
    original = load_scenario(SCENARIO_PATH).to_dict()
    scenario_id = str(original["id"])
    baseline = service.scenario_version(scenario_id, version=1)
    revised_document = {**original, "title": "Neutral sandbox research chain — managed revision"}

    revised = service.save_scenario_version({"scenario": revised_document})
    active = service.scenario_version(scenario_id)
    listed = service.scenario_versions()

    assert baseline["scenario"]["version"] == 1
    assert revised["scenario"]["version"] == 2
    assert active["scenario"]["version"] == 2
    assert active["scenario"]["document"]["title"] == revised_document["title"]
    assert any(
        row["scenario_id"] == scenario_id and row["version"] == 2 for row in listed["scenarios"]
    )

    duplicate = service.save_scenario_version({"scenario": revised_document})
    assert duplicate["scenario"]["version"] == 2


def test_scenario_management_rejects_unknown_fields_invalid_graphs_and_missing_versions(
    service: BlueFireService,
) -> None:
    original = load_scenario(SCENARIO_PATH).to_dict()

    with pytest.raises(APIError) as unknown_field:
        service.save_scenario_version({"scenario": original, "activate": True})
    assert unknown_field.value.code == "scenario_version_request_invalid"

    invalid = dict(original)
    invalid["steps"] = [
        {**step, "behavior_id": "behavior.not.registered.v1"} if index == 0 else step
        for index, step in enumerate(original["steps"])
    ]
    with pytest.raises(APIError) as invalid_graph:
        service.save_scenario_version({"scenario": invalid})
    assert invalid_graph.value.status == 422
    assert invalid_graph.value.code == "scenario_version_invalid"

    with pytest.raises(APIError) as missing:
        service.scenario_version("scenario.missing.v1", version=1)
    assert missing.value.status == 404
    assert missing.value.code == "scenario_version_not_found"


def test_all_allowlisted_resource_kinds_round_trip(service: BlueFireService) -> None:
    kinds = {
        "action",
        "collector",
        "comparison",
        "detection_backend",
        "model_provider",
        "research_source",
        "runner",
        "runner_profile",
    }

    for kind in sorted(kinds):
        resource_id = f"example.{kind.replace('_', '-')}.v1"
        saved = service.save_resource(
            kind,
            resource_id,
            {
                "document": {"label": f"Managed {kind}", "enabled": True},
                "status": "draft",
            },
        )
        fetched = service.resource(kind, resource_id)
        listed = service.resources(kind)

        assert saved["resource"] == fetched["resource"]
        assert saved["resource"]["status"] == "draft"
        assert any(row["id"] == resource_id for row in listed["resources"])


def test_plugin_save_requires_strict_matching_declarative_manifest(
    service: BlueFireService,
) -> None:
    plugin_id = "plugin.managed.catalog.v1"
    invalid_documents = [
        {**_plugin_manifest(plugin_id), "schema_version": "bluefire.plugin.v2"},
        {**_plugin_manifest("plugin.different.v1")},
        {**_plugin_manifest(plugin_id), "python_entry_point": "unsafe.module:load"},
        {**_plugin_manifest(plugin_id), "command": "free-form --execution"},
    ]
    for document in invalid_documents:
        with pytest.raises(APIError) as rejected:
            service.save_resource("plugin", plugin_id, {"document": document})
        assert rejected.value.status == 422
        assert rejected.value.code == "plugin_manifest_invalid"

    with pytest.raises(APIError) as status_bypass:
        service.save_resource(
            "plugin",
            plugin_id,
            {"document": _plugin_manifest(plugin_id), "status": "active"},
        )
    assert status_bypass.value.status == 400
    assert status_bypass.value.code == "plugin_request_invalid"
    assert service.resources("plugin")["inventory"]["manifest_count"] == 0


def test_untrusted_or_disabled_plugin_manifest_cannot_activate(
    service: BlueFireService,
) -> None:
    untrusted_id = "plugin.untrusted.catalog.v1"
    disabled_id = "plugin.disabled.catalog.v1"
    untrusted = service.save_resource(
        "plugin",
        untrusted_id,
        {"document": _plugin_manifest(untrusted_id, trust="untrusted")},
    )
    disabled = service.save_resource(
        "plugin",
        disabled_id,
        {"document": _plugin_manifest(disabled_id, enabled=False)},
    )

    assert untrusted["resource"]["status"] == "review_required"
    assert disabled["resource"]["status"] == "disabled"
    for plugin_id in (untrusted_id, disabled_id):
        with pytest.raises(APIError) as refused:
            service.activate_resource("plugin", plugin_id, {})
        assert refused.value.status == 409
        assert refused.value.code == "plugin_activation_refused"
    assert service.resources("plugin")["inventory"]["active_manifest_ids"] == []


def test_reviewed_plugin_activation_is_metadata_only_and_persists_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "product.sqlite3"
    runs = tmp_path / "runs"
    plugin_id = "plugin.persisted.catalog.v1"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    saved = first.save_resource(
        "plugin",
        plugin_id,
        {"document": _plugin_manifest(plugin_id)},
    )
    assert saved["resource"]["status"] == "ready"
    activated = first.activate_resource("plugin", plugin_id, {})
    assert activated["resource"]["status"] == "active"
    assert activated["registration"] == "metadata_only"
    assert activated["executable_loading"] is False
    assert activated["dynamic_actions"] is False
    assert activated["inventory"]["active_manifest_ids"] == [plugin_id]
    assert "python_entry_point" not in activated["resource"]["document"]
    assert "command" not in activated["resource"]["document"]
    first.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    try:
        persisted = restarted.resource("plugin", plugin_id)["resource"]
        inventory = restarted.resources("plugin")["inventory"]
        assert persisted["status"] == "active"
        assert inventory["health"]["state"] == "ready"
        assert inventory["active_manifest_ids"] == [plugin_id]
        assert inventory["executable_loading"] is False
        assert inventory["dynamic_actions"] is False
        assert inventory["python_entry_points"] is False

        deactivated = restarted.deactivate_resource("plugin", plugin_id, {})
        assert deactivated["resource"]["status"] == "inactive"
        assert deactivated["health"]["state"] == "inactive"
        assert deactivated["inventory"]["active_manifest_ids"] == []
        assert restarted.resource("plugin", plugin_id)["resource"]["status"] == "inactive"
    finally:
        restarted.close()


def test_resource_management_rejects_unknown_kinds_fields_statuses_and_secrets(
    service: BlueFireService,
) -> None:
    with pytest.raises(APIError) as unknown_kind:
        service.resources("collectors")
    assert unknown_kind.value.status == 400
    assert unknown_kind.value.code == "resource_kind_invalid"

    with pytest.raises(APIError) as unknown_field:
        service.save_resource(
            "collector",
            "collector.example.v1",
            {"document": {}, "unexpected": True},
        )
    assert unknown_field.value.code == "resource_request_invalid"

    with pytest.raises(APIError) as invalid_status:
        service.save_resource(
            "collector",
            "collector.example.v1",
            {"document": {}, "status": "Needs review"},
        )
    assert invalid_status.value.code == "resource_status_invalid"

    with pytest.raises(APIError) as plaintext_secret:
        service.save_resource(
            "model_provider",
            "provider.private.v1",
            {"document": {"api_key": "plaintext-value"}},  # pragma: allowlist secret
        )
    assert plaintext_secret.value.status == 422
    assert plaintext_secret.value.code == "resource_invalid"
    assert "environment-variable reference" in plaintext_secret.value.details[0]

    with pytest.raises(APIError) as invalid_id:
        service.resource("collector", "Collector.Uppercase")
    assert invalid_id.value.code == "management_identifier_invalid"


def test_malformed_runtime_resources_never_activate(service: BlueFireService) -> None:
    profile_id = "profile.invalid.v1"
    provider_id = "provider.invalid.v1"
    service.save_resource(
        "runner_profile",
        profile_id,
        {"document": {"id": profile_id}, "status": "draft"},
    )
    service.save_resource(
        "model_provider",
        provider_id,
        {
            "document": {
                "id": provider_id,
                "kind": "openai_responses",
                "model": "bounded-model",
            },
            "status": "draft",
        },
    )

    for kind, resource_id in (
        ("runner_profile", profile_id),
        ("model_provider", provider_id),
    ):
        with pytest.raises(APIError) as activation:
            service.activate_resource(kind, resource_id, {})
        assert activation.value.status == 422
        assert activation.value.code == "resource_activation_invalid"
        assert service.resource(kind, resource_id)["resource"]["status"] == "draft"

    with pytest.raises(APIError) as bypass:
        service.save_resource(
            "runner_profile",
            profile_id,
            {"document": {"id": profile_id}, "status": "active"},
        )
    assert bypass.value.code == "resource_activation_required"
    catalog = service.catalog()
    assert profile_id not in {item["id"] for item in catalog["runner_profiles"]}
    assert provider_id not in {item["provider_id"] for item in catalog["ai"]["providers"]}


def test_activated_runner_profile_drives_preflight_and_probe_is_sanitized(
    tmp_path: Path,
) -> None:
    selected_profiles = []

    class InventoryRunner:
        def inventory(self) -> Mapping[str, Any]:
            return {
                "schema_version": "bluefire.runner-inventory.v1",
                "runner_version": "9.8.7",
                "platform": "windows",
                "secret": "must-not-surface",  # pragma: allowlist secret
                "actions": [
                    {
                        "action_id": "sandbox.cleanup.v1",
                        "action_version": "1.0.0",
                        "readiness": "ready",
                        "command": "must-not-surface",
                    }
                ],
            }

        def execute(
            self,
            _manifest: Mapping[str, Any],
            _profile: Mapping[str, Any],
        ) -> Mapping[str, Any]:
            raise AssertionError("preflight and probe must not execute actions")

    runner = InventoryRunner()

    def runner_factory(profile):
        selected_profiles.append(profile)
        return runner, tmp_path

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=runner_factory,
    )
    try:
        base = next(
            profile for profile in service.config.runner_profiles if profile.mode.value == "execute"
        )
        document = base.to_dict()
        document["id"] = "profile.persisted-execute.v1"
        service.save_resource(
            "runner_profile",
            document["id"],
            {"document": document, "status": "draft"},
        )
        service.activate_resource("runner_profile", document["id"], {})

        report = service.preflight(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "execute",
                "runner_profile_id": document["id"],
                "autonomy": "off",
                "target_scope": {"scope_refs": list(base.scope)},
            }
        )
        assert report["runner_profile"] == document["id"]
        assert selected_profiles[-1].id == document["id"]

        probe = service.probe_runner_profile(document["id"], {})
        assert probe["version"] == "9.8.7"
        assert probe["platform"] == "windows"
        assert probe["actions"] == [
            {
                "action_id": "sandbox.cleanup.v1",
                "version": "1.0.0",
                "readiness": "ready",
            }
        ]
        assert probe["health"]["state"] == "degraded"
        assert "must-not-surface" not in str(probe)
    finally:
        service.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    try:
        assert document["id"] in {item["id"] for item in restarted.catalog()["runner_profiles"]}
        restarted.deactivate_resource("runner_profile", document["id"], {})
        assert document["id"] not in {item["id"] for item in restarted.catalog()["runner_profiles"]}
    finally:
        restarted.close()


def test_activated_ai_provider_is_authoritative_and_persists_across_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "product.sqlite3"
    runs = tmp_path / "runs"
    provider_id = "deterministic.persisted.v1"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    provider_document = first.config.ai.fallback.to_dict()
    provider_document.update({"id": provider_id, "model": "persisted-planner.v7"})
    first.save_resource(
        "model_provider",
        provider_id,
        {"document": provider_document, "status": "draft"},
    )
    activated = first.activate_resource("model_provider", provider_id, {})
    assert activated["resource"]["status"] == "active"
    with pytest.raises(APIError) as active_edit:
        first.save_resource(
            "model_provider",
            provider_id,
            {"document": provider_document, "status": "draft"},
        )
    assert active_edit.value.code == "resource_deactivation_required"

    report = first.preflight(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": "assist",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        }
    )
    proposal_provider = first._proposal_provider(AutonomyLevel.ASSIST, report["ai_provider"])
    assert report["ai_provider"]["provider_id"] == provider_id
    assert report["ai_provider"]["model"] == "persisted-planner.v7"
    assert proposal_provider is not None
    assert proposal_provider.config.id == provider_id
    assert first._runtime_ai().fallback.kind.value == "deterministic"
    first.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    try:
        catalog = restarted.catalog()
        assert catalog["ai"]["active_provider"] == provider_id
        persisted = restarted.resource("model_provider", provider_id)["resource"]
        assert persisted["status"] == "active"
        assert (
            next(item for item in catalog["ai"]["providers"] if item["provider_id"] == provider_id)[
                "model"
            ]
            == "persisted-planner.v7"
        )

        restarted.deactivate_resource("model_provider", provider_id, {})
        assert restarted.catalog()["ai"]["active_provider"] != provider_id
        assert restarted.resource("model_provider", provider_id)["resource"]["status"] == "inactive"
        edited = restarted.save_resource(
            "model_provider",
            provider_id,
            {
                "document": {**provider_document, "model": "persisted-planner.v8"},
                "status": "draft",
            },
        )
        assert edited["resource"]["status"] == "inactive"
    finally:
        restarted.close()
