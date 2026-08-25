from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
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
        {
            "value": {
                "schema_version": "bluefire.ui-preferences.v1",
                "theme": "dark",
                "effect_mode": "simulate",
                "autonomy": "off",
            }
        },
    )
    listed = service.settings()

    assert saved["setting"]["key"] == "ui.preferences"
    assert saved["setting"]["value"] == {
        "schema_version": "bluefire.ui-preferences.v1",
        "theme": "dark",
        "effect_mode": "simulate",
        "autonomy": "off",
    }
    assert saved["setting"] in listed["settings"]

    with pytest.raises(APIError) as unknown_field:
        service.upsert_setting("ui.preferences", {"value": {}, "unexpected": True})
    assert unknown_field.value.status == 400
    assert unknown_field.value.code == "setting_request_invalid"

    with pytest.raises(APIError) as unsupported_key:
        service.upsert_setting(
            "provider.private",
            {"value": {"nested": {"credentials": "plaintext-value"}}},
        )
    assert unsupported_key.value.status == 400
    assert unsupported_key.value.code == "setting_key_unsupported"

    with pytest.raises(APIError) as authority_field:
        service.upsert_setting(
            "ui.preferences",
            {
                "value": {
                    "schema_version": "bluefire.ui-preferences.v1",
                    "theme": "dark",
                    "effect_mode": "simulate",
                    "autonomy": "off",
                    "endpoint": "ghp_FAKE_CREDENTIAL_SHAPED_VALUE",
                }
            },
        )
    assert authority_field.value.status == 400
    assert authority_field.value.code == "setting_value_invalid"


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


def test_active_and_custom_scenarios_and_managed_resources_survive_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "product.sqlite3"
    runs = tmp_path / "runs"
    original = load_scenario(SCENARIO_PATH).to_dict()
    revised_document = {
        **original,
        "title": "Operator-selected durable revision",
        "purpose": "Prove the selected built-in revision is used after restart.",
    }
    custom_document = {
        **original,
        "id": "scenario.sandbox.persistence.custom.v1",
        "title": "Persisted custom scenario",
        "purpose": "Prove a custom durable scenario remains listable and runnable.",
    }
    expected_resources: dict[str, Mapping[str, Any]] = {}

    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    try:
        revised = first.save_scenario_version({"scenario": revised_document})
        custom = first.save_scenario_version({"scenario": custom_document})
        assert revised["scenario"]["version"] == 2
        assert custom["scenario"]["version"] == 1

        for kind in ("action", "collector", "research_source", "detection_backend"):
            seeded = first.resources(kind)["resources"][0]
            document = dict(seeded["document"])
            if kind == "research_source":
                resource_id = "research.operator-persistence.v1"
                document = {
                    **document,
                    "id": resource_id,
                    "name": "Operator persistence research source",
                    "notes": "Unique draft metadata preserved across restart.",
                }
                status = "draft"
            else:
                resource_id = str(seeded["id"])
                document["operator_override"] = {"preserve_on_restart": True}
                status = "disabled"
            edited = first.save_resource(
                kind,
                resource_id,
                {
                    "document": document,
                    "status": status,
                },
            )["resource"]
            expected_resources[kind] = edited
    finally:
        first.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    try:
        active = restarted.scenario_version(str(original["id"]))["scenario"]
        listed = {str(document["id"]): document for document in restarted.scenarios()["scenarios"]}
        assert active["version"] == 2
        assert active["document"] == revised_document
        assert listed[str(original["id"])] == revised_document
        assert listed[str(custom_document["id"])] == custom_document

        revised_run = restarted.run(
            {
                "scenario_id": original["id"],
                "mode": "simulate",
                "autonomy": "off",
                "target_scope": {"scope_refs": ["sandbox.workspace"]},
            }
        )
        custom_run = restarted.run(
            {
                "scenario_id": custom_document["id"],
                "mode": "simulate",
                "autonomy": "off",
                "target_scope": {"scope_refs": ["sandbox.workspace"]},
            }
        )
        assert revised_run["objective"] == revised_document["purpose"]
        assert custom_run["scenario_id"] == custom_document["id"]
        assert custom_run["objective"] == custom_document["purpose"]

        for kind, expected in expected_resources.items():
            assert restarted.resource(kind, str(expected["id"]))["resource"] == expected
    finally:
        restarted.close()


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


def test_research_source_requires_strict_pinned_matching_metadata(
    service: BlueFireService,
) -> None:
    source_id = "research.example-pinned.v1"
    document = {
        "schema_version": "bluefire.research-source.v1",
        "id": source_id,
        "name": "Example pinned source",
        "source_type": "documentation",
        "authority": "Example authority",
        "reference_url": "https://example.test/project/tree/v1.2.3",
        "version": "1.2.3",
        "pin": "v1.2.3",
        "retrieved_at": "2026-08-25",
        "license": "MIT",
        "license_url": "https://example.test/project/blob/v1.2.3/LICENSE",
        "license_review": "reviewed",
        "relationship": "comparative",
        "uses": ["comparison", "research_reference"],
        "cache_policy": "metadata_only",
        "executable_content": False,
        "notes": "Metadata only; no remote content is fetched or executed.",
    }

    saved = service.save_resource(
        "research_source",
        source_id,
        {"document": document, "status": "draft"},
    )
    assert saved["resource"]["document"] == document
    assert saved["resource"]["status"] == "draft"

    duplicate = service.save_resource(
        "research_source",
        source_id,
        {"document": document, "status": "draft"},
    )
    assert duplicate == saved

    promoted = service.save_resource(
        "research_source",
        source_id,
        {"document": document, "status": "pinned"},
    )
    assert promoted["resource"]["status"] == "pinned"
    assert promoted["resource"]["digest"] == saved["resource"]["digest"]
    assert promoted["resource"]["created_at"] == saved["resource"]["created_at"]

    pinned_duplicate = service.save_resource(
        "research_source",
        source_id,
        {"document": document, "status": "pinned"},
    )
    assert pinned_duplicate == promoted

    with pytest.raises(APIError) as downgrade:
        service.save_resource(
            "research_source",
            source_id,
            {"document": document, "status": "draft"},
        )
    assert downgrade.value.status == 409
    assert downgrade.value.code == "research_source_integrity_conflict"
    assert "cannot be downgraded" in downgrade.value.details[0]

    valid_mutations = [
        {**document, "notes": "Attempted in-place document rewrite."},
        {**document, "version": "1.2.4"},
        {
            **document,
            "pin": "v1.2.4",
            "reference_url": "https://example.test/project/tree/v1.2.4",
        },
        {
            **document,
            "reference_url": "https://example.test/other-project/tree/v1.2.3",
        },
        {**document, "license": "Apache-2.0"},
        {
            **document,
            "license_url": "https://example.test/project/blob/v1.2.3/COPYING",
        },
    ]
    for mutation in valid_mutations:
        with pytest.raises(APIError) as rewrite:
            service.save_resource(
                "research_source",
                source_id,
                {"document": mutation, "status": "pinned"},
            )
        assert rewrite.value.status == 409
        assert rewrite.value.code == "research_source_integrity_conflict"
        assert "use a new research source ID" in rewrite.value.details[0]

    with pytest.raises(APIError) as unsupported_status:
        service.save_resource(
            "research_source",
            "research.invalid-status.v1",
            {"document": {**document, "id": "research.invalid-status.v1"}, "status": "ready"},
        )
    assert unsupported_status.value.status == 409
    assert unsupported_status.value.code == "research_source_integrity_conflict"

    with pytest.raises(APIError) as mismatched:
        service.save_resource(
            "research_source",
            "research.other.v1",
            {"document": document, "status": "draft"},
        )
    assert mismatched.value.code == "research_source_invalid"

    with pytest.raises(APIError) as mutable:
        service.save_resource(
            "research_source",
            source_id,
            {
                "document": {
                    **document,
                    "pin": "main",
                    "reference_url": "https://example.test/project/tree/main",
                },
                "status": "draft",
            },
        )
    assert mutable.value.status == 409
    assert mutable.value.code == "research_source_integrity_conflict"


def test_research_source_create_is_serialized_across_store_instances(tmp_path: Path) -> None:
    database = tmp_path / "product.sqlite3"
    runs = tmp_path / "runs"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    second = BlueFireService(
        project_root=ROOT,
        runs_dir=runs,
        product_db_path=database,
    )
    try:
        seeded = first.resources("research_source")["resources"][0]
        source_id = "research.concurrent-create.v1"
        base = {
            **seeded["document"],
            "id": source_id,
            "name": "Concurrent create invariant",
        }
        documents = [
            {**base, "notes": "First competing immutable document."},
            {**base, "notes": "Second competing immutable document."},
        ]
        barrier = Barrier(2)

        def save(instance: BlueFireService, document: Mapping[str, Any]) -> Mapping[str, Any]:
            barrier.wait()
            try:
                response = instance.save_resource(
                    "research_source",
                    source_id,
                    {"document": document, "status": "draft"},
                )
            except APIError as exc:
                return {"outcome": "conflict", "status": exc.status, "code": exc.code}
            return {"outcome": "saved", "response": response}

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(save, first, documents[0]),
                executor.submit(save, second, documents[1]),
            ]
            outcomes = [future.result(timeout=10) for future in futures]

        assert sorted(str(outcome["outcome"]) for outcome in outcomes) == [
            "conflict",
            "saved",
        ]
        conflict = next(outcome for outcome in outcomes if outcome["outcome"] == "conflict")
        assert conflict == {
            "outcome": "conflict",
            "status": 409,
            "code": "research_source_integrity_conflict",
        }
        persisted = first.resource("research_source", source_id)["resource"]
        assert persisted["status"] == "draft"
        assert persisted["document"] in documents
    finally:
        second.close()
        first.close()


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

    with pytest.raises(APIError) as disguised_secret:
        service.save_resource(
            "model_provider",
            "provider.disguised-secret.v1",
            {
                "document": {
                    "id": "provider.disguised-secret.v1",
                    "kind": "deterministic",
                    "model": "offline",
                    "endpoint": "ghp_FAKECREDENTIALVALUE123456789",  # pragma: allowlist secret
                },
                "status": "draft",
            },
        )
    assert disguised_secret.value.status == 422
    assert disguised_secret.value.code == "resource_invalid"
    assert "credential-shaped plaintext value" in disguised_secret.value.details[0]

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
