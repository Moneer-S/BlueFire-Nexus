"""Compatibility and canonical serialization after collector contract extraction."""

from dataclasses import FrozenInstanceError

import pytest

from bluefire import collector_contracts, collector_interfaces, collector_schedule, collectors


def test_collector_contract_reexports_keep_type_and_error_identity() -> None:
    for name in (
        "CollectorError",
        "CollectorReadiness",
        "CollectorDescriptor",
        "CollectorHealth",
        "CollectionRequest",
        "CollectionResult",
        "CollectorRuntimeSettings",
        "CollectionSession",
        "Collector",
    ):
        assert getattr(collectors, name) is getattr(collector_contracts, name)
    assert collector_interfaces.CollectorDescriptor is collectors.CollectorDescriptor
    assert collector_schedule.CollectionSession is collectors.CollectionSession
    with pytest.raises(collectors.CollectorError, match="collector timeout"):
        collector_contracts.CollectionRequest(
            "run", "step", "behavior", "profile", "scope", timeout_seconds=0
        )


def test_runtime_contract_remains_frozen_and_serializes_through_legacy_session_surface() -> None:
    settings = {
        "schema_version": "bluefire.collector-runtime-settings.v1",
        "collectors": {
            "collector.filesystem.v1": {"enabled": False, "settings": {"paths": ["staged/a.txt"]}}
        },
    }
    runtime = collector_contracts.CollectorRuntimeSettings.from_mapping(settings)
    settings["collectors"]["collector.filesystem.v1"]["settings"]["paths"].append("later.txt")
    assert runtime.to_dict()["collectors"]["collector.filesystem.v1"]["settings"]["paths"] == [
        "staged/a.txt"
    ]
    with pytest.raises(TypeError):
        runtime.collectors["collector.filesystem.v1"]["enabled"] = True
    with pytest.raises(FrozenInstanceError):
        runtime.schema_version = "changed"
    encoded = collectors.CollectionSession(runtime, {}).to_dict()
    decoded = collector_contracts.CollectionSession.from_mapping(encoded)
    assert decoded.to_dict() == encoded
    assert decoded.settings.settings_hash == runtime.settings_hash
    encoded["settings_hash"] = "sha256:" + "0" * 64
    with pytest.raises(collectors.CollectorError, match="hashes or settings"):
        collector_contracts.CollectionSession.from_mapping(encoded)
