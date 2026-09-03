from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from bluefire.config import (
    AIProviderKind,
    AutonomyLevel,
    BlueFireConfig,
    ConfigError,
    EnvironmentType,
    load_config,
)
from bluefire.contracts import ContractError, ExecutionMode

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "bluefire.example.yaml"


def test_example_config_uses_exactly_two_modes_and_loopback_only() -> None:
    config = load_config(CONFIG_PATH)
    assert {mode.value for mode in ExecutionMode} == {"simulate", "execute"}
    assert config.mode is ExecutionMode.SIMULATE
    assert config.active_runner_profile.environment_type is EnvironmentType.DISPOSABLE
    for profile in config.runner_profiles:
        assert profile.platforms
        assert set(profile.platforms) <= {"windows", "linux", "macos"}
        assert all(
            ipaddress.ip_network(network).is_loopback for network in profile.network_allowlist
        )


def test_seeded_execute_profiles_budget_the_installed_ten_step_journey() -> None:
    config = load_config(CONFIG_PATH)
    profiles = {
        profile.id: profile
        for profile in config.runner_profiles
        if profile.id in {"sandbox-execute.v1", "sandbox-blocked-network.v1"}
    }

    assert set(profiles) == {"sandbox-execute.v1", "sandbox-blocked-network.v1"}
    assert all(profile.budgets.max_steps == 12 for profile in profiles.values())
    assert all(profile.budgets.max_seconds == 120 for profile in profiles.values())
    assert all(len(profile.capabilities) == 21 for profile in profiles.values())
    assert all(len(profile.enabled_actions) == 17 for profile in profiles.values())
    assert profiles["sandbox-execute.v1"].blocked_actions == ()
    assert profiles["sandbox-blocked-network.v1"].blocked_actions == (
        "sandbox.network.loopback.v1",
        "sandbox.peer.handoff.v1",
    )


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("max_steps", 256),
        ("max_seconds", 24 * 60 * 60),
        ("max_artifacts", 512),
        ("max_bytes", 256 * 1024 * 1024),
    ],
)
def test_runner_budgets_enforce_runtime_and_wire_bounds(field: str, maximum: int) -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    budgets = raw["runner_profiles"][0]["budgets"]
    budgets[field] = maximum
    parsed = BlueFireConfig.from_mapping(raw)

    assert parsed.runner_profiles[0].budgets.to_dict()[field] == maximum

    budgets[field] = maximum + 1
    with pytest.raises(ConfigError, match=field):
        BlueFireConfig.from_mapping(raw)


def test_load_config_rejects_max_seconds_too_large_for_runtime_conversion(
    tmp_path: Path,
) -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    raw["runner_profiles"][0]["budgets"]["max_seconds"] = 10**400
    config_path = tmp_path / "oversized-runner-budget.yaml"
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match="max_seconds"):
        load_config(config_path)


def test_environment_values_remain_unresolved_references(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLUEFIRE_RUNNER_BINARY", "sensitive-local-value")
    config = load_config(CONFIG_PATH)
    assert config.active_runner_profile.runner_binary.env == "BLUEFIRE_RUNNER_BINARY"
    assert "sensitive-local-value" not in repr(config)


def test_ai_autonomy_is_independent_of_mode() -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    raw["ai"]["autonomy"] = "auto"
    simulated = BlueFireConfig.from_mapping(raw)
    assert simulated.mode is ExecutionMode.SIMULATE
    assert simulated.autonomy is AutonomyLevel.AUTO
    assert simulated.ai_enabled is True

    raw["mode"] = "execute"
    raw["active_profile"] = "sandbox-execute.v1"
    raw["ai"]["autonomy"] = "off"
    executed = BlueFireConfig.from_mapping(raw)
    assert executed.mode is ExecutionMode.EXECUTE
    assert executed.autonomy is AutonomyLevel.OFF
    assert executed.ai_enabled is False


@pytest.mark.parametrize(
    ("enabled", "expected"),
    [(False, AutonomyLevel.OFF), (True, AutonomyLevel.ASSIST)],
)
def test_legacy_ai_enabled_migrates_to_safe_autonomy(
    enabled: bool, expected: AutonomyLevel
) -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    raw["ai"] = {"enabled": enabled}
    parsed = BlueFireConfig.from_mapping(raw)

    assert parsed.autonomy is expected
    assert parsed.ai.provider().kind is AIProviderKind.DETERMINISTIC
    assert "enabled" not in parsed.to_dict()["ai"]


def test_ai_provider_configuration_is_strict() -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    raw["ai"]["autonomy"] = "advisory"
    with pytest.raises(ContractError, match="must be one of: off, assist, auto"):
        BlueFireConfig.from_mapping(raw)

    raw = load_config(CONFIG_PATH).to_dict()
    remote = next(
        provider for provider in raw["ai"]["providers"] if provider["kind"] == "openai_responses"
    )
    remote["endpoint"] = "http://example.test/v1/responses"
    with pytest.raises(ConfigError, match="must use HTTPS"):
        BlueFireConfig.from_mapping(raw)


def test_execute_profile_requires_approval() -> None:
    raw = load_config(CONFIG_PATH).to_dict()
    execute_profile = next(
        profile for profile in raw["runner_profiles"] if profile["mode"] == "execute"
    )
    execute_profile["approval_required"] = False
    with pytest.raises(ConfigError, match="must require approval"):
        BlueFireConfig.from_mapping(raw)


def test_restricted_profile_is_narrow_and_requires_exact_approval() -> None:
    config = load_config(CONFIG_PATH)
    profile = next(
        item for item in config.runner_profiles if item.id == "sandbox-restricted-owned.v1"
    )

    assert profile.mode is ExecutionMode.EXECUTE
    assert profile.approval_required is True
    assert tuple(tier.value for tier in profile.safety_tiers) == ("safe", "restricted")
    assert profile.scope == ("sandbox.workspace",)
    assert profile.network_allowlist == ()
    assert profile.enabled_actions == (
        "sandbox.restricted.persistence-marker.v1",
        "sandbox.cleanup.v1",
    )


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
