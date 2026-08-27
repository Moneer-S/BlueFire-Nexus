from __future__ import annotations

import json
from pathlib import Path

from bluefire.bootstrap import seed_product_metadata
from bluefire.config import load_config
from bluefire.contracts import ScenarioDefinition, load_scenario
from bluefire.product_store import ProductStore
from bluefire.registry import load_builtin_registry

ROOT = Path(__file__).resolve().parents[1]


def test_bootstrap_seeds_versioned_secret_safe_product_metadata(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    registry = load_builtin_registry()
    scenarios = tuple(load_scenario(path) for path in sorted((ROOT / "scenarios").glob("*.yaml")))
    config = load_config(ROOT / "config" / "bluefire.example.yaml")

    first = seed_product_metadata(
        store,
        registry=registry,
        config=config,
        scenarios=scenarios,
    )
    second = seed_product_metadata(
        store,
        registry=registry,
        config=config,
        scenarios=scenarios,
    )

    assert first == second
    assert first["scenario"] == 7
    assert first["action"] == 18
    assert first["collector"] >= 6
    assert len(store.list_scenarios()) == 7
    assert len(store.list_resources("action")) == 18
    providers = store.list_resources("model_provider")
    serialized = json.dumps(providers, sort_keys=True)
    assert "OPENAI_API_KEY" in serialized
    assert "Bearer " not in serialized
    assert providers[1]["document"]["config"]["api_key"] == {"env": "OPENAI_API_KEY"}


def test_packaged_scenario_upgrade_is_added_without_replacing_active_head(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    registry = load_builtin_registry()
    scenarios = tuple(load_scenario(path) for path in sorted((ROOT / "scenarios").glob("*.yaml")))
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    selected = scenarios[0]

    seed_product_metadata(
        store,
        registry=registry,
        config=config,
        scenarios=scenarios,
    )
    operator_document = {
        **selected.to_dict(),
        "title": "Operator-selected scenario revision",
        "purpose": "Prove that an explicitly selected durable version remains authoritative.",
    }
    operator_version = store.save_scenario(operator_document)
    packaged_upgrade = ScenarioDefinition.from_mapping(
        {
            **selected.to_dict(),
            "title": "Later packaged scenario revision",
            "purpose": "Represent a later built-in release without selecting it for the operator.",
        }
    )

    seed_product_metadata(
        store,
        registry=registry,
        config=config,
        scenarios=tuple(
            packaged_upgrade if scenario.id == selected.id else scenario for scenario in scenarios
        ),
    )

    active = store.get_scenario(selected.id)
    imported = store.get_scenario(selected.id, version=3)
    assert operator_version["version"] == 2
    assert active["version"] == 2
    assert active["document"] == operator_document
    assert imported["document"] == packaged_upgrade.to_dict()
