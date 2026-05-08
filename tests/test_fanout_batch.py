"""Per-input fan-out tests for the 7 modules upgraded in this batch.

Each module gets the same shape of test as discovery / credential_access:

* default profile
* parametrized over every catalog entry; MITRE technique mirrors catalog
* unknown input falls back to default and records the rejected value
* every catalog entry emits a distinct telemetry event_type
* class `attack_techniques` covers every catalog MITRE id

The tests are parametrized over module + profile so adding a new profile
to any catalog automatically gets covered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple, Type

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.base import BaseModule
from src.core.modules.impl.standard_modules import (
    AntiDetectionModule,
    CommandControlModule,
    DefenseEvasionModule,
    ExfiltrationModule,
    IntelligenceModule,
    NetworkObfuscatorModule,
    PersistenceModule,
    ReconnaissanceModule,
    ResourceDevelopmentModule,
    _ANTI_DETECTION_PROFILES,
    _COMMAND_CONTROL_PROFILES,
    _DEFENSE_EVASION_PROFILES,
    _EXFILTRATION_PROFILES,
    _INTELLIGENCE_PROFILES,
    _NETWORK_OBFUSCATOR_PROFILES,
    _PERSISTENCE_PROFILES,
    _RECONNAISSANCE_PROFILES,
    _RESOURCE_DEVELOPMENT_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "fanout-batch-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


# (module class, profile catalog dict, name of the input param the module reads,
#  default catalog key, optional additional params dict)
_MODULES: Tuple[Tuple[Type[BaseModule], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]], ...] = (
    (CommandControlModule, _COMMAND_CONTROL_PROFILES, "channel", "http", {}),
    (PersistenceModule, _PERSISTENCE_PROFILES, "technique", "scheduled_task", {"target": "lab"}),
    (DefenseEvasionModule, _DEFENSE_EVASION_PROFILES, "technique", "argument_spoofing", {"target": "lab"}),
    (NetworkObfuscatorModule, _NETWORK_OBFUSCATOR_PROFILES, "protocol", "dns", {}),
    (IntelligenceModule, _INTELLIGENCE_PROFILES, "intelligence_type", "actor_research", {"focus": "apt29"}),
    (ReconnaissanceModule, _RECONNAISSANCE_PROFILES, "source", "osint", {}),
    (ResourceDevelopmentModule, _RESOURCE_DEVELOPMENT_PROFILES, "resource_type", "domain", {}),
    (AntiDetectionModule, _ANTI_DETECTION_PROFILES, "method", "memory_evasion", {"target": "lab"}),
    (ExfiltrationModule, _EXFILTRATION_PROFILES, "method", "via_c2", {"target": "lab"}),
)


@pytest.fixture(params=_MODULES, ids=lambda m: m[0].__name__)
def module_under_test(request) -> Tuple[Type[BaseModule], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]]:
    return request.param


def test_default_input_resolves_to_documented_default(
    module_under_test: Tuple[Type[BaseModule], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]],
    tmp_path: Path,
) -> None:
    cls, catalog, _input_key, default_key, extras = module_under_test
    mod = cls()
    result = mod.execute(dict(extras), _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == [catalog[default_key]["mitre"]]


def test_unknown_input_falls_back_with_marker(
    module_under_test: Tuple[Type[BaseModule], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]],
    tmp_path: Path,
) -> None:
    cls, catalog, input_key, default_key, extras = module_under_test
    mod = cls()
    params = {**extras, input_key: "definitely_not_a_real_value_zzz"}
    result = mod.execute(params, _ctx(tmp_path))
    # Falls back to documented default (the unrecognized value is what we passed)
    assert result.techniques == [catalog[default_key]["mitre"]]
    # Some `unrecognized_*` key surfaces the rejected value.
    surfaced = [v for k, v in result.detection_hints.items() if k.startswith("unrecognized_")]
    assert "definitely_not_a_real_value_zzz" in surfaced


def test_each_catalog_entry_maps_to_its_mitre_id_and_event_type(
    module_under_test: Tuple[Type[BaseModule], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]],
    tmp_path: Path,
) -> None:
    cls, catalog, input_key, _default_key, extras = module_under_test
    mod = cls()
    seen_event_types: set[str] = set()
    for key, profile in catalog.items():
        params = {**extras, input_key: key}
        result = mod.execute(params, _ctx(tmp_path))
        assert result.techniques == [profile["mitre"]], (
            f"{cls.__name__}/{key} expected {profile['mitre']}, got {result.techniques}"
        )
        assert isinstance(result.telemetry[0], TelemetryEvent)
        assert result.telemetry[0].event_type == profile["event_type"]
        seen_event_types.add(result.telemetry[0].event_type)
    assert len(seen_event_types) == len(catalog), (
        f"{cls.__name__}: expected {len(catalog)} distinct event_types, got {len(seen_event_types)}"
    )


def test_class_attack_techniques_covers_every_catalog_mitre(
    module_under_test: Tuple[Type[BaseModule], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]],
) -> None:
    cls, catalog, *_ = module_under_test
    expected = {profile["mitre"] for profile in catalog.values()}
    advertised = set(cls.attack_techniques)
    assert expected.issubset(advertised), (
        f"{cls.__name__} class attack_techniques missing entries: {expected - advertised}"
    )


def test_resource_development_legacy_infrastructure_alias_maps_to_vps(tmp_path: Path) -> None:
    """Backwards-compat: legacy default `resource_type=infrastructure` still
    works after the fan-out and resolves to the `vps` profile (T1583.003)."""
    mod = ResourceDevelopmentModule()
    result = mod.execute({"resource_type": "infrastructure"}, _ctx(tmp_path))
    assert result.artifacts["resource_type"] == "vps"
    assert result.techniques == ["T1583.003"]
    # Backwards-compat alias -> NOT recorded as unrecognized.
    assert "unrecognized_resource_type" not in result.detection_hints


def test_intelligence_default_focus_preserved(tmp_path: Path) -> None:
    """Backwards-compat: prior callers passed only `focus`; module still works."""
    mod = IntelligenceModule()
    result = mod.execute({"focus": "apt28"}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.artifacts["focus"] == "apt28"
    # Default intelligence_type is actor_research -> T1591.002
    assert result.techniques == ["T1591.002"]
