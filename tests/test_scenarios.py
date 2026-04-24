from pathlib import Path

from src.core.scenario import load_scenario


def test_scenario_files_load() -> None:
    scenario_dir = Path("scenarios")
    files = list(scenario_dir.glob("*.yaml"))
    assert files
    for file_path in files:
        scenario = load_scenario(file_path)
        assert scenario.name
        assert scenario.steps


def test_legacy_flagship_scenario_contains_new_modules() -> None:
    scenario = load_scenario(Path("scenarios/legacy_flagship_blended.yaml"))
    modules = [step.module for step in scenario.steps]
    assert "legacy_actor_profile" in modules
    assert "legacy_protocol_research" in modules
    assert "legacy_stealth_research" in modules


def test_legacy_protocol_scenario_covers_all_protocol_variants() -> None:
    scenario = load_scenario(Path("scenarios/legacy_c2_protocols.yaml"))
    protocols = {
        str(step.params.get("protocol"))
        for step in scenario.steps
        if step.module == "legacy_protocol_research"
    }
    assert protocols == {
        "dns_tunneling",
        "tls_fast_flux",
        "websocket_quic",
        "solana_rpc",
        "network_obfuscator_legacy",
    }


def test_legacy_stealth_scenario_uses_legacy_alias_for_antidetection() -> None:
    scenario = load_scenario(Path("scenarios/legacy_stealth_research.yaml"))
    stealth_caps = {
        str(step.params.get("capability"))
        for step in scenario.steps
        if step.module == "legacy_stealth_research"
    }
    assert "anti_detection_legacy" in stealth_caps
