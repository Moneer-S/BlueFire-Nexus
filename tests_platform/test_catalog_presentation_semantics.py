from pathlib import Path

import yaml

from bluefire.registry import load_builtin_registry

ROOT = Path(__file__).resolve().parents[1]


def test_current_catalog_maps_effects_without_claiming_unperformed_techniques():
    items = yaml.safe_load((ROOT / "bluefire/catalog/behaviors.yaml").read_text(encoding="utf-8"))[
        "items"
    ]
    by_id = {item["id"]: item for item in items}
    assert by_id["sandbox.restricted.persistence-marker.v1"]["techniques"] == []
    assert by_id["sandbox.network.loopback.v1"]["techniques"] == []
    assert by_id["sandbox.archive.tar.v1"]["techniques"] == ["T1560"]
    assert by_id["sandbox.collection.atomic-gzip.v1"]["techniques"] == ["T1560.001"]
    for identity in [
        "sandbox.identity-material.inspect.v1",
        "sandbox.credential.peer-challenge.v1",
        "sandbox.peer.handoff.v1",
    ]:
        assert by_id[identity]["techniques"] == []
    assert by_id["research.persistence.change.v1"]["execution_state"] == "metadata_only"
    assert by_id["research.persistence.change.v1"]["techniques"] == ["T1547"]
    registry = load_builtin_registry()
    assert registry.get_behavior("sandbox.restricted.persistence-marker.v1").action_ids == (
        "sandbox.restricted.persistence-marker.v1",
    )


def test_packaged_example_copies_remain_identical():
    for source in (ROOT / "scenarios").glob("*.yaml"):
        packaged = ROOT / "bluefire/data" / source.name
        if packaged.exists():
            assert packaged.read_bytes() == source.read_bytes(), source.name
