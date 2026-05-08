"""Focused tests for the standard `anti_detection` module.

Mirrors the structure of `test_credential_access_module.py`. The
fan-out across every catalog entry is parametrized via
`tests/test_fanout_batch.py`; this file pins per-method invariants
the fan-out harness does not assert on (target propagation,
logsource diversity, no leak of the historic
``anti_detection.method`` synthetic field, mitre-id integrity, the
shape of the registered runtime entry).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    AntiDetectionModule,
    _ANTI_DETECTION_DEFAULT,
    _ANTI_DETECTION_PROFILES,
)


def _ctx(tmp_path: Path, **overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "run_id": "anti-detection-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }
    base.update(overrides)
    return base


def test_default_method_is_memory_evasion(tmp_path: Path) -> None:
    """No `method` -> falls back to memory_evasion (T1055).

    This preserves the historic apt29_credential_access.yaml step
    that calls `module: anti_detection` with `method: memory_evasion`
    explicitly; an empty input must resolve to the same profile.
    """
    mod = AntiDetectionModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1055"]
    assert result.artifacts["method"] == "memory_evasion"
    assert result.detection_hints["mitre_technique"] == "T1055"
    assert result.telemetry[0].event_type == "anti_detection_memory_evasion"


@pytest.mark.parametrize(
    "method,expected_mitre",
    [
        ("memory_evasion", "T1055"),
        ("code_obfuscation", "T1027"),
        ("anti_debug", "T1622"),
        ("anti_sandbox", "T1497.001"),
        ("anti_vm", "T1497.001"),
        ("timestomp", "T1070.006"),
        ("log_clear", "T1070.001"),
        ("dynamic_api", "T1027.007"),
        ("reflective_loading", "T1620"),
        ("process_hollowing", "T1055.012"),
        ("string_encryption", "T1027.013"),
        ("api_unhooking", "T1562.001"),
    ],
)
def test_method_fans_out_to_correct_mitre(
    method: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = AntiDetectionModule()
    result = mod.execute({"method": method, "target": "lab-host"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre], (
        f"{method} should emit {expected_mitre}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["anti_detection_method"] == method
    assert result.artifacts["mitre_technique"] == expected_mitre


def test_unknown_method_falls_back_with_marker(tmp_path: Path) -> None:
    mod = AntiDetectionModule()
    result = mod.execute(
        {"method": "definitely_not_a_real_method_zzz"}, _ctx(tmp_path)
    )
    assert result.artifacts["method"] == _ANTI_DETECTION_DEFAULT
    assert result.techniques == [_ANTI_DETECTION_PROFILES[_ANTI_DETECTION_DEFAULT]["mitre"]]
    assert (
        result.detection_hints.get("unrecognized_anti_detection_method")
        == "definitely_not_a_real_method_zzz"
    )


def test_target_lands_in_artifact_telemetry_and_hints(tmp_path: Path) -> None:
    mod = AntiDetectionModule()
    result = mod.execute(
        {"method": "log_clear", "target": "dc-01"}, _ctx(tmp_path)
    )
    assert result.artifacts["target"] == "dc-01"
    assert result.telemetry[0].details["target"] == "dc-01"
    assert result.detection_hints["target_host"] == "dc-01"
    assert "dc-01" in result.detection_hints["title"]


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    mod = AntiDetectionModule()
    seen: set[str] = set()
    for method in _ANTI_DETECTION_PROFILES:
        result = mod.execute({"method": method}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_ANTI_DETECTION_PROFILES), (
        f"Expected {len(_ANTI_DETECTION_PROFILES)} distinct event types, got {len(seen)}"
    )


def test_logsource_varies_across_catalog(tmp_path: Path) -> None:
    """The catalog must span more than just process_creation/windows.

    The pre-catalog implementation emitted a single hardcoded
    `process_creation/linux` regardless of method; that pattern is
    what this test exists to reject.
    """
    mod = AntiDetectionModule()
    categories: set[str] = set()
    products: set[str] = set()
    for method in _ANTI_DETECTION_PROFILES:
        result = mod.execute({"method": method}, _ctx(tmp_path))
        logsource = result.detection_hints["logsource"]
        categories.add(logsource["category"])
        products.add(logsource["product"])
    assert "process_creation" in categories
    assert "process_access" in categories
    assert "registry_event" in categories
    assert "file_event" in categories
    assert "image_load" in categories
    # Anti-detection is a Windows-tradecraft tactic; the catalog targets
    # Sysmon-style fields. If a future contributor adds a Linux/macOS
    # variant the assertion below should be loosened, not removed.
    assert products == {"windows"}


def test_detection_selection_uses_real_sysmon_field_names(tmp_path: Path) -> None:
    """Selection keys must NOT use the synthetic `anti_detection.method` field.

    The pre-catalog implementation emitted
    `selection: {anti_detection.method: <method>}`, which is not a
    real telemetry field anywhere; a Sigma rule generated from that
    cannot fire on Sysmon. Every profile in the catalog must use a
    Sysmon-recognisable Windows event field.
    """
    mod = AntiDetectionModule()
    real_field_prefixes = (
        "ParentImage",
        "ParentCommandLine",
        "Image",
        "ImageLoaded",
        "CommandLine",
        "TargetFilename",
        "TargetObject",
        "CallTrace",
        "EventID",
    )
    for method in _ANTI_DETECTION_PROFILES:
        result = mod.execute({"method": method}, _ctx(tmp_path))
        selection = result.detection_hints["detection"]["selection"]
        assert "anti_detection.method" not in selection, (
            f"{method} regressed to legacy synthetic field"
        )
        keys = list(selection.keys())
        assert keys, f"{method}: empty selection block"
        for key in keys:
            base = key.split("|", 1)[0]
            assert base in real_field_prefixes, (
                f"{method}: selection key '{key}' is not a recognised Sysmon field"
            )


def test_target_propagation_via_target_from_step(tmp_path: Path) -> None:
    """`target_from_step` picks up target from a previous step's artifacts."""
    mod = AntiDetectionModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "discover-hosts": {
                "artifacts": {"targets": ["finance-laptop-07", "hr-laptop-12"]}
            }
        },
    )
    result = mod.execute(
        {"method": "log_clear", "target_from_step": "discover-hosts"}, context
    )
    assert result.artifacts["target"] == "finance-laptop-07"
    assert result.artifacts["target_propagated_from_step"] == "discover-hosts"
    assert result.detection_hints["target_propagated_from_step"] == "discover-hosts"
    assert result.telemetry[0].details["target_propagated_from_step"] == "discover-hosts"


def test_explicit_target_wins_over_target_from_step(tmp_path: Path) -> None:
    mod = AntiDetectionModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "discover-hosts": {"artifacts": {"target": "from-discovery"}}
        },
    )
    result = mod.execute(
        {
            "method": "memory_evasion",
            "target": "explicit-target",
            "target_from_step": "discover-hosts",
        },
        context,
    )
    assert result.artifacts["target"] == "explicit-target"
    assert "target_propagated_from_step" not in result.artifacts


def test_module_advertises_all_catalog_techniques_in_attack_techniques() -> None:
    expected = {profile["mitre"] for profile in _ANTI_DETECTION_PROFILES.values()}
    advertised = set(AntiDetectionModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Class attack_techniques missing entries: {expected - advertised}"
    )
    # No stale id should remain after the catalog upgrade.
    assert advertised == expected


def test_module_registers_at_canonical_name() -> None:
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    assert "anti_detection" in modules
    assert isinstance(modules["anti_detection"], AntiDetectionModule)


def test_no_profile_uses_legacy_synthetic_field() -> None:
    """Static guard: no profile may regress to using the BlueFire-internal
    `anti_detection.method` field as the detection selection key."""
    for method, profile in _ANTI_DETECTION_PROFILES.items():
        assert profile["selection_field"] != "anti_detection.method", (
            f"{method}: selection_field reverted to legacy synthetic field"
        )


def test_every_profile_carries_per_method_telemetry_details(tmp_path: Path) -> None:
    """Every profile must contribute method-specific detail keys to the
    telemetry payload, not just echo the input method back."""
    mod = AntiDetectionModule()
    for method, profile in _ANTI_DETECTION_PROFILES.items():
        result = mod.execute({"method": method}, _ctx(tmp_path))
        details = result.telemetry[0].details
        # Every per-profile detail key from the catalog must surface.
        for key, value in profile["details"].items():
            assert details.get(key) == value, (
                f"{method}: telemetry details missing per-method key '{key}'"
            )


def test_no_profile_detail_overrides_canonical_artifact_target(tmp_path: Path) -> None:
    """Regression for: a profile detail key shadowing the canonical
    ``target`` artifact field would break downstream
    ``target_from_step`` propagation, since
    ``resolve_target_from_step`` reads ``artifacts["target"]`` from
    the upstream step.

    The merge order in :class:`AntiDetectionModule` is profile
    details first, canonical fields last - so any profile that
    accidentally reuses ``target`` as a per-method label still
    produces a host-shaped artifact ``target``.
    """
    mod = AntiDetectionModule()
    for method in _ANTI_DETECTION_PROFILES:
        result = mod.execute(
            {"method": method, "target": "operator-supplied-host"},
            _ctx(tmp_path),
        )
        assert result.artifacts["target"] == "operator-supplied-host", (
            f"{method}: profile details overwrote canonical target -> "
            f"{result.artifacts.get('target')!r}"
        )
        # Canonical fields stay canonical even when the profile
        # would have shadowed them.
        assert result.artifacts["method"] == method
        assert result.artifacts["mitre_technique"] == _ANTI_DETECTION_PROFILES[method]["mitre"]


def test_no_profile_detail_uses_reserved_canonical_keys() -> None:
    """Static guard against future contributors reusing canonical keys.

    The merge discipline above protects runtime, but a profile
    detail named ``target`` / ``method`` / ``mitre_technique`` is
    a smell regardless: it implies the contributor was trying to
    set the canonical field rather than emit a per-method label.
    Reject it at definition time so the contributor picks a
    namespaced key instead (e.g. ``target_file`` for timestomp).
    """
    reserved = {"target", "method", "mitre_technique"}
    for name, profile in _ANTI_DETECTION_PROFILES.items():
        clashes = reserved & set(profile["details"].keys())
        assert not clashes, (
            f"{name}: profile details reuses reserved canonical keys "
            f"{sorted(clashes)} - rename to a namespaced form "
            f"(e.g. target -> target_file / target_process)"
        )


def test_timestomp_target_file_surfaces_under_namespaced_key(tmp_path: Path) -> None:
    """The timestomp profile's per-method file target lands as
    ``target_file`` (namespaced) - not ``target``, which is
    reserved for the host the operator is acting on.
    """
    mod = AntiDetectionModule()
    result = mod.execute(
        {"method": "timestomp", "target": "host-7"}, _ctx(tmp_path)
    )
    assert result.artifacts["target"] == "host-7"
    assert (
        result.artifacts.get("target_file")
        == "C:\\Windows\\System32\\drivers\\etc\\hosts"
    )
