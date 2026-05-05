"""Focused tests for the standard `collection` module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    CollectionModule,
    _COLLECTION_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "collection-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


def test_default_technique_is_file_staging(tmp_path: Path) -> None:
    mod = CollectionModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1074.001"]
    assert result.artifacts["technique"] == "file_staging"
    assert result.detection_hints["mitre_technique"] == "T1074.001"
    assert result.telemetry[0].event_type == "collection_file_staging"


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("file_staging", "T1074.001"),
        ("directory_staging", "T1074.001"),
        ("archive_collected", "T1560"),
        ("archive_compressed", "T1560.002"),
        ("archive_encrypted", "T1560.001"),
        ("keyboard_capture", "T1056.001"),
        ("clipboard_capture", "T1115"),
        ("screen_capture", "T1113"),
        ("audio_capture", "T1123"),
        ("email_collection", "T1114.001"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = CollectionModule()
    result = mod.execute({"technique": technique, "target": "lab-host"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre]
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["collection_technique"] == technique


def test_unknown_technique_falls_back_with_marker(tmp_path: Path) -> None:
    mod = CollectionModule()
    result = mod.execute({"technique": "not_a_thing"}, _ctx(tmp_path))
    assert result.artifacts["technique"] == "file_staging"
    assert result.techniques == ["T1074.001"]
    assert (
        result.detection_hints.get("unrecognized_collection_technique") == "not_a_thing"
    )


def test_target_is_recorded(tmp_path: Path) -> None:
    mod = CollectionModule()
    result = mod.execute(
        {"technique": "email_collection", "target": "exec-laptop-09"},
        _ctx(tmp_path),
    )
    assert result.artifacts["target"] == "exec-laptop-09"
    assert result.detection_hints["target_host"] == "exec-laptop-09"
    assert "exec-laptop-09" in result.detection_hints["title"]


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    mod = CollectionModule()
    seen: set[str] = set()
    for technique in _COLLECTION_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_COLLECTION_PROFILES)


def test_logsource_categories_span_file_and_process(tmp_path: Path) -> None:
    mod = CollectionModule()
    categories: set[str] = set()
    for technique in _COLLECTION_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        categories.add(result.detection_hints["logsource"]["category"])
    assert "file_event" in categories
    assert "process_creation" in categories


def test_module_registers_at_canonical_name() -> None:
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    assert "collection" in modules
    assert isinstance(modules["collection"], CollectionModule)


def test_module_advertises_all_catalog_techniques() -> None:
    expected = {profile["mitre"] for profile in _COLLECTION_PROFILES.values()}
    advertised = set(CollectionModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Missing techniques on class attribute: {expected - advertised}"
    )
