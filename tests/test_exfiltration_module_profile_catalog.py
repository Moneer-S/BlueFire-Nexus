"""Focused tests for the standard `exfiltration` module's profile catalog.

Mirrors the structure of ``test_anti_detection_module.py``. The
fan-out across every catalog entry is parametrized via
``tests/test_fanout_batch.py``; this file pins per-method invariants
the fan-out harness does not assert on (alias resolution, destructive
guard interplay with the catalog, no leak of the historic
``exfil.method`` synthetic field, mitre-id integrity, the shape of
the registered runtime entry).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    ExfiltrationModule,
    _EXFILTRATION_ALIASES,
    _EXFILTRATION_DEFAULT,
    _EXFILTRATION_PROFILES,
)


def _ctx(tmp_path: Path, **overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "run_id": "exfil-catalog-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }
    base.update(overrides)
    return base


def test_default_method_is_via_c2(tmp_path: Path) -> None:
    """No `method` -> falls back to via_c2 (T1041)."""
    mod = ExfiltrationModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1041"]
    assert result.artifacts["method"] == "via_c2"
    assert result.detection_hints["mitre_technique"] == "T1041"
    assert result.telemetry[0].event_type == "exfiltration_via_c2"


@pytest.mark.parametrize(
    "method,expected_mitre",
    [
        ("via_c2", "T1041"),
        ("dns_tunneling", "T1048.003"),
        ("https_to_cloud_storage", "T1567.002"),
        ("https_to_code_repo", "T1567.001"),
        ("https_to_web_service", "T1567"),
        ("email_smtp", "T1048.003"),
        ("ftp_to_remote", "T1048.003"),
        ("alt_protocol_unencrypted", "T1048.003"),
        ("alt_protocol_symmetric", "T1048.001"),
        ("alt_protocol_asymmetric", "T1048.002"),
        ("scheduled_transfer", "T1029"),
        ("usb_removable_media", "T1052.001"),
        ("bluetooth", "T1011.001"),
        ("traffic_duplication", "T1020.001"),
    ],
)
def test_method_fans_out_to_correct_mitre(
    method: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = ExfiltrationModule()
    result = mod.execute({"method": method, "target": "lab-host"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre], (
        f"{method} should emit {expected_mitre}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["exfiltration_method"] == method
    assert result.artifacts["mitre_technique"] == expected_mitre


def test_unknown_method_falls_back_with_marker(tmp_path: Path) -> None:
    mod = ExfiltrationModule()
    result = mod.execute(
        {"method": "definitely_not_a_real_exfil_method_zzz"}, _ctx(tmp_path)
    )
    assert result.artifacts["method"] == _EXFILTRATION_DEFAULT
    assert result.techniques == [
        _EXFILTRATION_PROFILES[_EXFILTRATION_DEFAULT]["mitre"]
    ]
    assert (
        result.detection_hints.get("unrecognized_exfiltration_method")
        == "definitely_not_a_real_exfil_method_zzz"
    )


@pytest.mark.parametrize(
    "alias,canonical",
    sorted(_EXFILTRATION_ALIASES.items()),
)
def test_alias_resolves_to_canonical_method_without_marker(
    alias: str, canonical: str, tmp_path: Path
) -> None:
    """Operator shortcuts (`c2`, `dns`, `usb`, ...) resolve cleanly.

    An alias should:
    - resolve to the canonical key,
    - emit the canonical mitre,
    - NOT carry the `unrecognized_exfiltration_method` marker (it is
      recognised, just under a friendlier name).
    """
    mod = ExfiltrationModule()
    result = mod.execute({"method": alias}, _ctx(tmp_path))
    assert result.artifacts["method"] == canonical, (
        f"alias `{alias}` should resolve to `{canonical}`"
    )
    assert result.techniques == [_EXFILTRATION_PROFILES[canonical]["mitre"]]
    assert "unrecognized_exfiltration_method" not in result.detection_hints


def test_each_profile_emits_distinct_event_type(tmp_path: Path) -> None:
    seen: set[str] = set()
    mod = ExfiltrationModule()
    for method in _EXFILTRATION_PROFILES:
        result = mod.execute({"method": method}, _ctx(tmp_path))
        ev: TelemetryEvent = result.telemetry[0]
        assert ev.event_type not in seen, (
            f"event_type collision for method `{method}`: {ev.event_type}"
        )
        seen.add(ev.event_type)


def test_each_profile_emits_specific_logsource(tmp_path: Path) -> None:
    """No profile may fall back to the generic process_creation/windows.

    Every entry must declare both `category` and `product`.
    """
    mod = ExfiltrationModule()
    for method, profile in _EXFILTRATION_PROFILES.items():
        result = mod.execute({"method": method}, _ctx(tmp_path))
        logsource = result.detection_hints["logsource"]
        assert logsource.get("category"), method
        assert logsource.get("product"), method
        # Catalog source-of-truth must match emitted hint exactly.
        assert logsource == profile["logsource"], method


def test_no_synthetic_exfil_method_field_in_selection(tmp_path: Path) -> None:
    """Detection draft must not use the historic synthetic field.

    Pre-catalog, every selection was ``exfil.method: <method>`` —
    this is not a real telemetry field anywhere. The catalog moves
    every method to a Sigma-shaped selection (e.g. `dns.question.name`,
    `network.dst_port`, `TargetFilename|contains`). Pin that no
    method regresses to the synthetic field.
    """
    mod = ExfiltrationModule()
    for method in _EXFILTRATION_PROFILES:
        result = mod.execute({"method": method}, _ctx(tmp_path))
        selection = result.detection_hints["detection"]["selection"]
        assert "exfil.method" not in selection, method


def test_destructive_guard_uses_resolved_mitre_not_t1041(tmp_path: Path) -> None:
    """Destructive guard surfaces the canonical mitre of the selected method.

    Was historically pinned to T1041 even when the operator selected
    a non-C2 method. After the catalog the failure record reflects
    the actual technique (so risk / detection / coverage downstream
    don't claim the wrong mitre when the gate fires).
    """
    mod = ExfiltrationModule()
    result = mod.execute(
        {"method": "https_to_cloud_storage", "destructive": True},
        _ctx(tmp_path),
    )
    assert result.status == "failure"
    assert result.error == "missing_lab_acknowledgment"
    assert result.techniques == ["T1567.002"]


def test_attack_techniques_class_attr_covers_every_profile() -> None:
    """`ExfiltrationModule.attack_techniques` is the union of catalog mitres.

    Pinned so the registry/coverage sees every advertised technique.
    """
    declared = set(ExfiltrationModule.attack_techniques)
    catalog = {profile["mitre"] for profile in _EXFILTRATION_PROFILES.values()}
    assert declared == catalog


def test_canonical_artifact_keys_are_not_overwritten_by_profile_details(
    tmp_path: Path,
) -> None:
    """Profile `details` keys cannot shadow the canonical fields.

    The canonical artifact / details dict carries `method`,
    `target`, `mitre_technique`, `artifact_name` (artifacts only) /
    `artifact` (details only). These must always reflect the
    resolved method/target, not whatever a future profile happens
    to put under the same key.
    """
    mod = ExfiltrationModule()
    for method, profile in _EXFILTRATION_PROFILES.items():
        result = mod.execute({"method": method, "target": "host-x"}, _ctx(tmp_path))
        assert result.artifacts["method"] == method, method
        assert result.artifacts["target"] == "host-x", method
        assert result.artifacts["mitre_technique"] == profile["mitre"], method
        # detail snapshot
        details = result.telemetry[0].details
        assert details["method"] == method, method
        assert details["target"] == "host-x", method
        assert details["mitre_technique"] == profile["mitre"], method


def test_propagation_marker_lands_in_artifacts_hints_and_telemetry(
    tmp_path: Path,
) -> None:
    """`target_propagated_from_step` surfaces in all three of artifacts /
    detection_hints / telemetry.details when the step propagates.

    Mirrors the per-method propagation test in
    `test_exfiltration_target_propagation.py` but parametrized over
    every catalog entry.
    """
    upstream = {
        "stage-collected-data": {
            "status": "success",
            "module": "collection",
            "techniques": ["T1074.001"],
            "artifacts": {"target": "corp-fileshare"},
        }
    }
    mod = ExfiltrationModule()
    for method in _EXFILTRATION_PROFILES:
        result = mod.execute(
            {"method": method, "target_from_step": "stage-collected-data"},
            _ctx(tmp_path, previous_step_results=upstream),
        )
        assert result.artifacts.get("target") == "corp-fileshare", method
        assert (
            result.artifacts.get("target_propagated_from_step")
            == "stage-collected-data"
        ), method
        assert (
            result.detection_hints.get("target_propagated_from_step")
            == "stage-collected-data"
        ), method
        assert (
            result.telemetry[0].details.get("target_propagated_from_step")
            == "stage-collected-data"
        ), method
