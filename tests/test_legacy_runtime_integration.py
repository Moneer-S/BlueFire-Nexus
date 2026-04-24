from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager


def _base_cfg(tmp_path: Path) -> Path:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.lab_confirmation", True)
    cfg.save()
    return cfg_path


def test_protocol_emulate_executes_runtime_and_returns_outcome(tmp_path: Path) -> None:
    cfg_path = _base_cfg(tmp_path)
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.c2_pack.capabilities.dns_tunneling.enabled", True)
    cfg.set("modules.legacy.c2_pack.capabilities.dns_tunneling.mode", "emulate")
    cfg.set("modules.legacy.c2_pack.capabilities.dns_tunneling.lab_confirmation", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "dns_tunneling",
            "endpoint": "exfil.example.lab",
            "data_size": 128,
            "network_touch": False,
        },
    )

    assert result["status"] == "success"
    runtime = result["artifacts"]["legacy"]["payload"]["runtime_outcome"]
    assert runtime["status"] in {"success", "failure"}
    assert runtime["protocol"] == "dns_tunneling"


def test_stealth_alias_capability_resolves_and_runs(tmp_path: Path) -> None:
    cfg_path = _base_cfg(tmp_path)
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.stealth_pack.capabilities.anti_detection_legacy.enabled", True)
    cfg.set("modules.legacy.stealth_pack.capabilities.anti_detection_legacy.mode", "simulate")
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_detection", "target": "host-1"},
    )

    assert result["status"] == "success"
    legacy = result["artifacts"]["legacy"]
    assert legacy["capability"] == "anti_detection_legacy"
    assert legacy["mode"] == "simulate"


def test_actor_emulate_returns_runtime_indicators(tmp_path: Path) -> None:
    cfg_path = _base_cfg(tmp_path)
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.actor_pack.capabilities.apt28.enabled", True)
    cfg.set("modules.legacy.actor_pack.capabilities.apt28.mode", "emulate")
    cfg.set("modules.legacy.actor_pack.capabilities.apt28.lab_confirmation", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_apt28_research",
        {"tactic": "execution", "technique": "powershell", "target": "lab-user"},
    )

    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert "runtime_outcome" in payload
    assert payload["runtime_outcome"]["status"] in {"completed", "success", "failure"}


def test_cli_overrides_accept_alias_capabilities(tmp_path: Path) -> None:
    cfg_path = _base_cfg(tmp_path)
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.c2_pack.enabled", True)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    nexus.config_manager.set("modules.legacy.c2_pack.capabilities.quic_c2.enabled", True)
    nexus.config_manager.set("modules.legacy.c2_pack.capabilities.quic_c2.mode", "simulate")
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()

    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "quic_c2",
            "endpoint": "quic://edge.example.lab:4433",
            "cadence_seconds": 8,
        },
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["protocol"] == "websocket_quic"
