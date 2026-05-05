from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.legacy_controls import (
    evaluate_legacy_capability,
    legacy_preset_overrides,
    resolve_legacy_preset_name,
)


def test_legacy_master_toggle_enables_capabilities(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.enable_all_lab_capabilities", True)
    cfg.set("modules.legacy.lab_confirmation", True)
    cfg.save()

    reloaded = ConfigManager(str(cfg_path))
    decision = evaluate_legacy_capability(
        reloaded.to_dict(),
        "c2_pack",
        "dns_tunneling",
    )
    assert decision.enabled is True
    assert decision.acknowledged is True
    assert decision.activation_source == "master_toggle"


def test_legacy_granular_toggle_enables_single_capability(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.c2_pack.capabilities.dns_tunneling.enabled", True)
    cfg.save()

    reloaded = ConfigManager(str(cfg_path))
    dns_decision = evaluate_legacy_capability(
        reloaded.to_dict(),
        "c2_pack",
        "dns_tunneling",
    )
    flux_decision = evaluate_legacy_capability(
        reloaded.to_dict(),
        "c2_pack",
        "tls_fast_flux",
    )
    assert dns_decision.enabled is True
    assert flux_decision.enabled is False


def test_legacy_module_runs_with_granular_enablement(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.actor_pack.capabilities.apt29.enabled", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_apt29_research",
        {"technique": "phishing", "target": "lab-user"},
    )

    assert result["status"] == "success"
    assert result["module"] == "legacy_apt29_research"
    assert result["artifacts"]["legacy"]["pack"] == "actor_pack"
    assert result["artifacts"]["legacy"]["mode"] == "simulate"


def test_legacy_protocol_alias_resolves_granular_enablement(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.c2_pack.capabilities.websocket_quic.enabled", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "quic_c2",
            "endpoint": "quic://edge.example.lab:4433",
            "cadence_seconds": 12,
        },
    )

    assert result["status"] == "success"
    assert result["module"] == "legacy_protocol_research"
    assert result["artifacts"]["legacy"]["capability"] == "websocket_quic"
    assert result["artifacts"]["legacy"]["payload"]["protocol"] == "websocket_quic"


def test_legacy_stealth_alias_uses_anti_detection_capability(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.stealth_pack.capabilities.anti_detection_legacy.enabled", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_detection", "target": "analysis-node"},
    )

    assert result["status"] == "success"
    assert result["module"] == "legacy_stealth_research"
    assert result["artifacts"]["legacy"]["capability"] == "anti_detection_legacy"
    assert result["artifacts"]["legacy"]["payload"]["capability"] == "anti_detection_legacy"


def test_decision_summary_message_reports_emulate_ack_state(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.actor_pack.capabilities.apt29.enabled", True)
    cfg.set("modules.legacy.actor_pack.capabilities.apt29.mode", "emulate")
    cfg.save()

    reloaded = ConfigManager(str(cfg_path))
    decision = evaluate_legacy_capability(
        reloaded.to_dict(),
        "actor_pack",
        "apt29",
    )
    assert "emulate blocked until lab confirmation" in decision.summary_message()


def test_legacy_preset_alias_resolves_to_canonical_profile() -> None:
    assert resolve_legacy_preset_name("baseline") == "safe-baseline"
    assert resolve_legacy_preset_name("all-simulate") == "full-simulate"


def test_legacy_preset_full_emulate_enables_all_with_ack() -> None:
    overrides = legacy_preset_overrides("full-emulate")
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is True
    assert overrides["modules.legacy.global_mode"] == "emulate"
    assert overrides["modules.legacy.global_lab_acknowledged"] is True
    assert overrides["modules.legacy.lab_confirmation"] is True
    assert overrides["modules.legacy.actor_pack.capabilities.apt29.enabled"] is True
    assert overrides["modules.legacy.c2_pack.capabilities.websocket_quic.mode"] == "emulate"
    assert (
        overrides["modules.legacy.stealth_pack.capabilities.anti_detection_legacy.lab_confirmation"]
        is True
    )


def test_legacy_preset_safe_baseline_disables_all_capabilities() -> None:
    overrides = legacy_preset_overrides("safe-baseline")
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is False
    assert overrides["modules.legacy.global_mode"] == "simulate"
    assert overrides["modules.legacy.actor_pack.enabled"] is False
    assert overrides["modules.legacy.c2_pack.capabilities.dns_tunneling.enabled"] is False
    assert overrides["modules.legacy.stealth_pack.capabilities.dynamic_api.enabled"] is False
