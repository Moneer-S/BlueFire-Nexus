"""Cross-cutting simple-mode config presets.

Pinned invariants:

1. Five named presets exist and their override dicts are documented:
   `local_safe`, `lab_legacy_enabled`, `ai_enabled`, `ai_disabled`,
   `strict_local`.
2. After applying any preset to a fresh `ConfigManager`, the resolved
   AI / safety / legacy state matches the preset's documented
   intent.
3. ``local_safe`` and ``strict_local`` keep the runtime offline
   (``is_offline_ai(config)`` returns True).
4. ``lab_legacy_enabled`` enables the master legacy toggle but
   keeps ``global_mode == "simulate"`` and lab confirmation off so
   emulate mode stays gated.
5. ``ai_enabled`` flips the copilot enabled bit but does NOT switch
   the provider away from the template (no remote-provider impl).
6. Unknown preset names raise a clear ``ValueError`` listing the
   accepted names.
7. ``apply_simple_preset`` requires a ``ConfigManager``-like object;
   raises ``TypeError`` otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.config import ConfigManager
from src.core.configuration import (
    apply_simple_preset,
    get_ai_config,
    get_safety_config,
    is_offline_ai,
    simple_preset_catalog,
    simple_preset_names,
    simple_preset_overrides,
)


# ---------------------------------------------------------------------------
# Catalogue shape
# ---------------------------------------------------------------------------


def test_simple_preset_names_lists_five_canonical_presets() -> None:
    names = simple_preset_names()
    assert set(names) == {
        "local_safe",
        "lab_legacy_enabled",
        "ai_enabled",
        "ai_disabled",
        "strict_local",
    }


def test_simple_preset_catalog_returns_deep_copy() -> None:
    catalog_a = simple_preset_catalog()
    catalog_b = simple_preset_catalog()
    catalog_a["local_safe"]["overrides"]["general.dry_run"] = "MUTATED"
    # Mutating one copy must NOT affect a fresh fetch.
    assert catalog_b["local_safe"]["overrides"]["general.dry_run"] is True


def test_every_preset_has_description_and_overrides() -> None:
    catalog = simple_preset_catalog()
    for name, entry in catalog.items():
        assert isinstance(entry["description"], str) and entry["description"]
        assert isinstance(entry["overrides"], dict) and entry["overrides"], (
            f"preset {name!r} has empty overrides"
        )


# ---------------------------------------------------------------------------
# Overrides correctness — preset content matches documented intent
# ---------------------------------------------------------------------------


def test_local_safe_keeps_runtime_offline_with_no_legacy() -> None:
    overrides = simple_preset_overrides("local_safe")
    assert overrides["general.dry_run"] is True
    assert overrides["modules.ai.enabled"] is False
    assert overrides["modules.ai.provider"] == "template"
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is False
    assert overrides["modules.legacy.global_mode"] == "simulate"


def test_lab_legacy_enabled_turns_on_master_toggle_simulate_only() -> None:
    overrides = simple_preset_overrides("lab_legacy_enabled")
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is True
    assert overrides["modules.legacy.global_mode"] == "simulate"
    # Emulate must remain gated — lab confirmation stays off until
    # operator explicitly opts in.
    assert overrides["modules.legacy.global_lab_acknowledged"] is False
    assert overrides["modules.legacy.lab_confirmation"] is False
    # AI stays offline.
    assert overrides["modules.ai.enabled"] is False
    assert overrides["modules.ai.provider"] == "template"


def test_ai_enabled_flips_enabled_bit_keeps_template_provider() -> None:
    overrides = simple_preset_overrides("ai_enabled")
    assert overrides["modules.ai.enabled"] is True
    # No remote-provider implementation today; provider stays at
    # template even after enabling the copilot artifact layer.
    assert overrides["modules.ai.provider"] == "template"
    assert "modules.legacy.enable_all_lab_capabilities" not in overrides


def test_ai_disabled_flips_enabled_bit_off() -> None:
    overrides = simple_preset_overrides("ai_disabled")
    assert overrides["modules.ai.enabled"] is False
    assert overrides["modules.ai.provider"] == "template"


def test_strict_local_locks_safety_gates_to_loopback_only() -> None:
    overrides = simple_preset_overrides("strict_local")
    assert overrides["general.dry_run"] is True
    assert overrides["general.safeties.allowed_subnets"] == []
    assert overrides["general.safeties.allowed_domains"] == ["localhost"]
    assert overrides["modules.ai.enabled"] is False
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is False


# ---------------------------------------------------------------------------
# apply_simple_preset — end-to-end via ConfigManager
# ---------------------------------------------------------------------------


def _fresh_manager(tmp_path: Path) -> ConfigManager:
    cfg_path = tmp_path / "config.yaml"
    return ConfigManager(str(cfg_path))


def test_applying_local_safe_keeps_runtime_offline(tmp_path: Path) -> None:
    cm = _fresh_manager(tmp_path)
    apply_simple_preset(cm, "local_safe")
    config = cm.to_dict()
    assert is_offline_ai(config) is True
    safety = get_safety_config(config)
    assert safety["dry_run"] is True


def test_applying_lab_legacy_enabled_turns_on_master_toggle(tmp_path: Path) -> None:
    cm = _fresh_manager(tmp_path)
    apply_simple_preset(cm, "lab_legacy_enabled")
    config = cm.to_dict()
    legacy = config["modules"]["legacy"]
    assert legacy["enable_all_lab_capabilities"] is True
    assert legacy["global_mode"] == "simulate"
    assert legacy.get("global_lab_acknowledged", False) is False
    # AI remains offline even with the legacy master toggle on.
    assert is_offline_ai(config) is True


def test_applying_ai_enabled_keeps_provider_template(tmp_path: Path) -> None:
    cm = _fresh_manager(tmp_path)
    apply_simple_preset(cm, "ai_enabled")
    config = cm.to_dict()
    ai = get_ai_config(config)
    assert ai["enabled"] is True
    assert ai["provider"] == "template"
    # Even with copilot enabled, is_offline_ai() must remain True
    # because the template provider produces deterministic offline
    # output.
    assert is_offline_ai(config) is True


def test_applying_strict_local_zeroes_safety_subnets(tmp_path: Path) -> None:
    cm = _fresh_manager(tmp_path)
    apply_simple_preset(cm, "strict_local")
    config = cm.to_dict()
    safety = get_safety_config(config)
    assert safety["allowed_subnets"] == []
    assert safety["allowed_domains"] == ["localhost"]
    assert is_offline_ai(config) is True


def test_applying_two_presets_layers_the_second_on_top(tmp_path: Path) -> None:
    """``apply_simple_preset`` is additive — later application wins."""
    cm = _fresh_manager(tmp_path)
    apply_simple_preset(cm, "lab_legacy_enabled")
    # Re-apply local_safe — should turn the master legacy toggle off.
    apply_simple_preset(cm, "local_safe")
    legacy = cm.to_dict()["modules"]["legacy"]
    assert legacy["enable_all_lab_capabilities"] is False


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_unknown_preset_name_raises_value_error_listing_accepted_names() -> None:
    with pytest.raises(ValueError) as excinfo:
        simple_preset_overrides("nope")
    msg = str(excinfo.value)
    assert "nope" in msg
    for canonical in (
        "local_safe",
        "lab_legacy_enabled",
        "ai_enabled",
        "ai_disabled",
        "strict_local",
    ):
        assert canonical in msg


def test_apply_simple_preset_requires_configmanager_like_object() -> None:
    with pytest.raises(TypeError):
        apply_simple_preset(object(), "local_safe")


def test_apply_simple_preset_with_unknown_name_raises_before_mutating(
    tmp_path: Path,
) -> None:
    cm = _fresh_manager(tmp_path)
    snapshot = cm.to_dict()
    with pytest.raises(ValueError):
        apply_simple_preset(cm, "definitely-not-a-preset")
    # No partial mutation: the unknown-name check fires before any
    # `.set()` calls, so the config is identical to the snapshot.
    assert cm.to_dict() == snapshot
