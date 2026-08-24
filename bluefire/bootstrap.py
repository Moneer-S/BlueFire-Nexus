"""Seed durable product metadata from reviewed built-in contracts."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping

from .ai import ai_runtime_metadata
from .collectors import (
    FilesystemCollector,
    JsonLinesFixtureCollector,
    optional_collector_descriptors,
)
from .config import BlueFireConfig
from .contracts import ScenarioDefinition
from .detections import ExternalDetectionValidator
from .product_store import ProductStore, ProductStoreError
from .registry import BehaviorRegistry
from .research import load_builtin_research_registry


def seed_product_metadata(
    store: ProductStore,
    *,
    registry: BehaviorRegistry,
    config: BlueFireConfig,
    scenarios: Iterable[ScenarioDefinition],
) -> Mapping[str, int]:
    """Idempotently seed content-addressed local metadata.

    Configuration remains declarative and secret-safe. Provider credential values
    are never resolved; only their environment-variable references are persisted.
    """

    counts: Counter[str] = Counter()
    for scenario in scenarios:
        registry.validate_scenario(scenario)
        store.save_scenario(scenario.to_dict())
        counts["scenario"] += 1

    for action_id in registry.action_ids:
        store.save_resource(
            "action",
            action_id,
            registry.get_action(action_id).to_dict(),
            status="registered",
        )
        counts["action"] += 1

    for profile in config.runner_profiles:
        try:
            store.get_resource("runner_profile", profile.id)
        except ProductStoreError:
            store.save_resource(
                "runner_profile",
                profile.id,
                profile.to_dict(),
                status="configured",
            )
        counts["runner_profile"] += 1

    for provider in config.ai.providers:
        runtime = ai_runtime_metadata(
            config.ai,
            autonomy=config.autonomy,
            provider_id=provider.id,
        )
        health = runtime.get("health", {})
        state = (
            str(health.get("state", "unavailable"))
            if isinstance(health, Mapping)
            else "unavailable"
        )
        try:
            store.get_resource("model_provider", provider.id)
        except ProductStoreError:
            store.save_resource(
                "model_provider",
                provider.id,
                {"config": provider.to_dict(), "runtime": dict(runtime)},
                status=state,
            )
        counts["model_provider"] += 1

    collector_descriptors = (
        FilesystemCollector.descriptor,
        JsonLinesFixtureCollector.descriptor,
        *optional_collector_descriptors(),
    )
    for descriptor in collector_descriptors:
        built_in = descriptor.id in {
            FilesystemCollector.descriptor.id,
            JsonLinesFixtureCollector.descriptor.id,
        }
        store.save_resource(
            "collector",
            descriptor.id,
            descriptor.to_dict(),
            status="available_per_run" if built_in else "not_configured",
        )
        counts["collector"] += 1

    for source in load_builtin_research_registry().all():
        store.save_resource(
            "research_source",
            source.id,
            source.to_dict(),
            status="pinned",
        )
        counts["research_source"] += 1

    backend_ids = {
        "pySigma": "detection-backend.pysigma.v1",
        "YARA-Python": "detection-backend.yara-python.v1",
        "SPL structural checker": "detection-backend.spl-structural.v1",
    }
    for name, health in ExternalDetectionValidator.health().items():
        ready = bool(health.get("ready"))
        store.save_resource(
            "detection_backend",
            backend_ids[name],
            {"name": name, **dict(health)},
            status="ready" if ready else "unavailable",
        )
        counts["detection_backend"] += 1

    return dict(sorted(counts.items()))


__all__ = ["seed_product_metadata"]
