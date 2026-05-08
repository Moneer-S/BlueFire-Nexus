"""Focused tests for the standard `initial_access` module's profile catalog.

InitialAccessModule was historically pinned to bare T1566 with the
synthetic `vector` field as the only Sigma discriminator —
generated rules could not fire on any real telemetry, and the
declared MITRE was wrong for every non-phishing vector. This file
mirrors ``test_anti_detection_module.py`` and pins per-vector
invariants the fan-out harness does not assert on.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    InitialAccessModule,
    _INITIAL_ACCESS_ALIASES,
    _INITIAL_ACCESS_DEFAULT,
    _INITIAL_ACCESS_PROFILES,
)


def _ctx(tmp_path: Path, **overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "run_id": "initial-access-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }
    base.update(overrides)
    return base


def test_default_vector_is_phishing_email(tmp_path: Path) -> None:
    """No `vector` -> falls back to phishing_email (T1566 parent)."""
    mod = InitialAccessModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1566"]
    assert result.artifacts["vector"] == "phishing_email"
    assert result.detection_hints["mitre_technique"] == "T1566"
    assert result.telemetry[0].event_type == "initial_access_phishing_email"


@pytest.mark.parametrize(
    "vector,expected_mitre",
    [
        ("phishing_email", "T1566"),
        ("phishing_attachment", "T1566.001"),
        ("phishing_link", "T1566.002"),
        ("spearphishing_via_service", "T1566.003"),
        ("spearphishing_voice", "T1566.004"),
        ("valid_accounts", "T1078"),
        ("default_accounts", "T1078.001"),
        ("domain_accounts", "T1078.002"),
        ("local_accounts", "T1078.003"),
        ("cloud_accounts", "T1078.004"),
        ("exploit_public_app", "T1190"),
        ("external_remote_services", "T1133"),
        ("trusted_relationship", "T1199"),
        ("hardware_additions", "T1200"),
        ("removable_media", "T1091"),
        ("drive_by_compromise", "T1189"),
        ("supply_chain", "T1195"),
    ],
)
def test_vector_fans_out_to_correct_mitre(
    vector: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = InitialAccessModule()
    result = mod.execute({"vector": vector, "target": "user@example.invalid"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre], (
        f"{vector} should emit {expected_mitre}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["initial_access_vector"] == vector
    assert result.artifacts["mitre_technique"] == expected_mitre


def test_unknown_vector_falls_back_with_marker(tmp_path: Path) -> None:
    mod = InitialAccessModule()
    result = mod.execute(
        {"vector": "definitely_not_a_real_vector_zzz"}, _ctx(tmp_path)
    )
    assert result.artifacts["vector"] == _INITIAL_ACCESS_DEFAULT
    assert result.techniques == [
        _INITIAL_ACCESS_PROFILES[_INITIAL_ACCESS_DEFAULT]["mitre"]
    ]
    assert (
        result.detection_hints.get("unrecognized_initial_access_vector")
        == "definitely_not_a_real_vector_zzz"
    )


@pytest.mark.parametrize(
    "alias,canonical",
    sorted(_INITIAL_ACCESS_ALIASES.items()),
)
def test_alias_resolves_to_canonical_vector_without_marker(
    alias: str, canonical: str, tmp_path: Path
) -> None:
    """Operator shortcuts (`spearphishing_attachment`, `vpn`, `usb_drop`, ...)
    resolve cleanly without the unrecognised-vector marker.
    """
    mod = InitialAccessModule()
    result = mod.execute({"vector": alias}, _ctx(tmp_path))
    assert result.artifacts["vector"] == canonical, (
        f"alias `{alias}` should resolve to `{canonical}`"
    )
    assert result.techniques == [_INITIAL_ACCESS_PROFILES[canonical]["mitre"]]
    assert "unrecognized_initial_access_vector" not in result.detection_hints


def test_each_profile_emits_distinct_event_type(tmp_path: Path) -> None:
    seen: set[str] = set()
    mod = InitialAccessModule()
    for vector in _INITIAL_ACCESS_PROFILES:
        result = mod.execute({"vector": vector}, _ctx(tmp_path))
        ev: TelemetryEvent = result.telemetry[0]
        assert ev.event_type not in seen, (
            f"event_type collision for vector `{vector}`: {ev.event_type}"
        )
        seen.add(ev.event_type)


def test_each_profile_emits_specific_logsource(tmp_path: Path) -> None:
    """Every profile declares both `category` and `product`.

    Pre-catalog every entry collapsed to ``email/generic``, which is
    wrong for non-phishing vectors (RDP / web exploit / USB drop).
    """
    mod = InitialAccessModule()
    for vector, profile in _INITIAL_ACCESS_PROFILES.items():
        result = mod.execute({"vector": vector}, _ctx(tmp_path))
        logsource = result.detection_hints["logsource"]
        assert logsource.get("category"), vector
        assert logsource.get("product"), vector
        assert logsource == profile["logsource"], vector


def test_no_synthetic_vector_field_in_selection(tmp_path: Path) -> None:
    """Detection draft must not use the historic synthetic field.

    Pre-catalog, every selection was ``vector: <vector>`` — this is
    not a real telemetry field anywhere. Pin that no vector
    regresses to that synthetic key.
    """
    mod = InitialAccessModule()
    for vector in _INITIAL_ACCESS_PROFILES:
        result = mod.execute({"vector": vector}, _ctx(tmp_path))
        selection = result.detection_hints["detection"]["selection"]
        # The literal synthetic field name (``vector``) must not be a
        # selection key. (The catalog uses Sigma-shaped keys like
        # ``email.subject|contains``, ``http.url|contains``, etc.)
        assert "vector" not in selection, vector


def test_attack_techniques_class_attr_covers_every_profile() -> None:
    """`InitialAccessModule.attack_techniques` is the union of catalog mitres.

    Pinned so the registry/coverage sees every advertised technique.
    """
    declared = set(InitialAccessModule.attack_techniques)
    catalog = {profile["mitre"] for profile in _INITIAL_ACCESS_PROFILES.values()}
    assert declared == catalog


def test_canonical_artifact_keys_are_not_overwritten_by_profile_details(
    tmp_path: Path,
) -> None:
    """Profile `details` keys cannot shadow the canonical fields."""
    mod = InitialAccessModule()
    for vector, profile in _INITIAL_ACCESS_PROFILES.items():
        result = mod.execute(
            {"vector": vector, "target": "alice@example.invalid"}, _ctx(tmp_path)
        )
        assert result.artifacts["vector"] == vector, vector
        assert result.artifacts["target"] == "alice@example.invalid", vector
        assert result.artifacts["mitre_technique"] == profile["mitre"], vector
        details = result.telemetry[0].details
        assert details["vector"] == vector, vector
        assert details["target"] == "alice@example.invalid", vector
        assert details["mitre_technique"] == profile["mitre"], vector


def test_default_target_is_lab_user(tmp_path: Path) -> None:
    """No `target` -> falls back to lab-user (preserves historic shape)."""
    mod = InitialAccessModule()
    result = mod.execute({"vector": "phishing_link"}, _ctx(tmp_path))
    assert result.artifacts["target"] == "lab-user"
    assert result.detection_hints["target_user"] == "lab-user"
