from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from bluefire.config import BlueFireConfig, ConfigError, EnvironmentType, load_config
from bluefire.contracts import ContractError, ExecutionMode

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "bluefire.example.yaml"


def test_example_config_uses_exactly_two_modes_and_loopback_only() -> None:
    config = load_config(CONFIG_PATH)
    assert {mode.value for mode in ExecutionMode} == {"simulate", "execute"}
    assert config.mode is ExecutionMode.SIMULATE
    assert config.active_runner_profile.environment_type is EnvironmentType.DISPOSABLE
    for profile in config.runner_profiles:
        assert profile.platforms == ("windows", "linux", "macos")
        assert all(
            ipaddress.ip_network(network).is_loopback for network in profile.network_allowlist
        )


def test_environment_values_remain_unresolved_references(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLUEFIRE_RUNNER_BINARY", "sensitive-local-value")
    config = load_config(CONFIG_PATH)
    assert config.active_runner_profile.runner_binary.env == "BLUEFIRE_RUNNER_BINARY"
    assert "sensitive-local-value" not in repr(config)


def test_ai_flag_is_independent_of_mode() -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    raw["ai"]["enabled"] = True
    simulated = BlueFireConfig.from_mapping(raw)
    assert simulated.mode is ExecutionMode.SIMULATE
    assert simulated.ai_enabled is True

    raw["mode"] = "execute"
    raw["active_profile"] = "sandbox-execute.v1"
    raw["ai"]["enabled"] = False
    executed = BlueFireConfig.from_mapping(raw)
    assert executed.mode is ExecutionMode.EXECUTE
    assert executed.ai_enabled is False


def test_execute_profile_requires_approval() -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    execute_profile = next(
        profile for profile in raw["runner_profiles"] if profile["mode"] == "execute"
    )
    execute_profile["approval_required"] = False
    with pytest.raises(ConfigError, match="must require approval"):
        BlueFireConfig.from_mapping(raw)


def test_config_rejects_unknown_fields_and_allows_explicit_block_override() -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    raw["legacy_mode"] = "emulate"
    with pytest.raises(ContractError, match="unknown fields"):
        BlueFireConfig.from_mapping(raw)

    raw = load_config(CONFIG_PATH).to_dict()
    execute_profile = next(
        profile for profile in raw["runner_profiles"] if profile["mode"] == "execute"
    )
    execute_profile["blocked_actions"] = [execute_profile["enabled_actions"][0]]
    parsed = BlueFireConfig.from_mapping(raw)
    selected = next(
        profile for profile in parsed.runner_profiles if profile.mode is ExecutionMode.EXECUTE
    )
    assert selected.blocked_actions[0] in selected.enabled_actions
