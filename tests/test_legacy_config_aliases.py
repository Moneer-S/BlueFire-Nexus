from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.legacy_controls import evaluate_legacy_capability, summarize_legacy_controls


def test_legacy_config_accepts_old_lab_fields(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.enable_all_lab_capabilities", True)
    cfg.set("modules.legacy.lab_acknowledged", True)
    cfg.set("modules.legacy.lab_mode", "emulate")
    cfg.save()

    reloaded = ConfigManager(str(cfg_path))
    decision = evaluate_legacy_capability(
        reloaded.to_dict(),
        "actor_pack",
        "apt29",
    )
    assert decision.enabled is True
    assert decision.mode == "emulate"
    assert decision.acknowledged is True


def test_legacy_config_accepts_capability_emulate_enabled(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.c2_pack.capabilities.websocket_quic.enabled", True)
    cfg.set("modules.legacy.c2_pack.capabilities.websocket_quic.emulate_enabled", True)
    cfg.set("modules.legacy.c2_pack.capabilities.websocket_quic.lab_confirmation", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "quic_c2",
            "endpoint": "quic://edge.example.lab:4433",
            "cadence_seconds": 10,
        },
    )

    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    assert payload["protocol"] == "websocket_quic"


def test_legacy_summary_lists_aliases_with_canonical_names(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.c2_pack.capabilities.quic_c2.enabled", True)
    cfg.set("modules.legacy.stealth_pack.capabilities.anti_detection.enabled", True)
    cfg.save()

    summary = summarize_legacy_controls(ConfigManager(str(cfg_path)).to_dict())
    c2_caps = summary["packs"]["c2_pack"]["enabled_capabilities"]
    stealth_caps = summary["packs"]["stealth_pack"]["enabled_capabilities"]
    assert "websocket_quic" in c2_caps
    assert "quic_c2" not in c2_caps
    assert "anti_detection_legacy" in stealth_caps
    assert "anti_detection" not in stealth_caps
