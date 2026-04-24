from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.legacy_controls import evaluate_legacy_capability


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
