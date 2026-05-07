"""Central configuration helpers — precedence, defaults, AI shape.

Pinned invariants:

1. ``resolve_setting`` honours the documented precedence
   CLI > scenario > config > env > default.
2. ``resolve_output_root`` honours config > env > default.
3. ``get_ai_config`` defaults to offline template provider with no
   API keys, no network, no Ollama default.
4. ``get_ai_config`` parses an OpenAI-compatible config without
   triggering any network call.
5. ``get_safety_config`` returns the local-first safety baseline.
6. ``get_mutation_config`` defaults to disabled.
7. ``is_legacy_capability_enabled`` agrees with
   ``evaluate_legacy_capability`` on the enabled bit.
8. Helpers tolerate malformed config (None, non-mapping) by
   returning documented defaults rather than raising.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from src.core.configuration import (
    get_ai_config,
    get_mutation_config,
    get_safety_config,
    is_legacy_capability_enabled,
    is_offline_ai,
    resolve_output_root,
    resolve_setting,
)
from src.core.legacy_controls import evaluate_legacy_capability


# ---------------------------------------------------------------------------
# resolve_setting precedence
# ---------------------------------------------------------------------------


def test_resolve_setting_cli_wins_over_everything() -> None:
    assert (
        resolve_setting(
            cli="cli-value",
            scenario="scenario-value",
            config="config-value",
            env="env-value",
            default="default-value",
        )
        == "cli-value"
    )


def test_resolve_setting_scenario_beats_config_env_default() -> None:
    assert (
        resolve_setting(
            scenario="scenario-value",
            config="config-value",
            env="env-value",
            default="default-value",
        )
        == "scenario-value"
    )


def test_resolve_setting_config_beats_env_and_default() -> None:
    assert (
        resolve_setting(
            config="config-value",
            env="env-value",
            default="default-value",
        )
        == "config-value"
    )


def test_resolve_setting_env_beats_default() -> None:
    assert resolve_setting(env="env-value", default="default-value") == "env-value"


def test_resolve_setting_falls_back_to_default_when_all_absent() -> None:
    assert resolve_setting(default="fallback") == "fallback"


def test_resolve_setting_falsy_truthy_only_skips_empty_string() -> None:
    """With truthy_only (default), empty string is treated as absent."""
    assert (
        resolve_setting(
            cli="",
            scenario="scenario-value",
            default="default-value",
        )
        == "scenario-value"
    )


def test_resolve_setting_truthy_only_false_treats_zero_as_present() -> None:
    """With truthy_only=False, an explicit 0 / False / "" wins over later layers."""
    assert (
        resolve_setting(
            cli=0,
            scenario=42,
            default=99,
            truthy_only=False,
        )
        == 0
    )


# ---------------------------------------------------------------------------
# resolve_output_root precedence
# ---------------------------------------------------------------------------


def test_resolve_output_root_uses_config_first(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(tmp_path / "env"))
    config = {"general": {"output_root": str(tmp_path / "config")}}
    assert resolve_output_root(config) == tmp_path / "config"


def test_resolve_output_root_falls_back_to_env_when_config_absent(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(tmp_path / "env"))
    assert resolve_output_root(None) == tmp_path / "env"
    assert resolve_output_root({}) == tmp_path / "env"


def test_resolve_output_root_default_when_no_config_and_no_env(monkeypatch) -> None:
    monkeypatch.delenv("BLUEFIRE_OUTPUT_ROOT", raising=False)
    from pathlib import Path

    assert resolve_output_root(None) == Path("output")


# ---------------------------------------------------------------------------
# resolve_output_root — non-string values are treated as unset
# (closes Codex P2 on PR #34)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "non_string_value",
    [None, False, True, 0, 1, [], {}, ["valid-path"]],
)
def test_resolve_output_root_treats_non_string_value_as_unset(
    monkeypatch, tmp_path, non_string_value
) -> None:
    """Anything that is not a string should fall through to env/default
    rather than being coerced via str() into a literal directory name
    like ``"None"`` / ``"False"`` / ``"0"``.
    """
    from pathlib import Path

    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(tmp_path / "env"))
    config = {"general": {"output_root": non_string_value}}
    # Falls through to env, not Path("None") / Path("False") / Path("0").
    assert resolve_output_root(config) == tmp_path / "env"


def test_resolve_output_root_treats_empty_string_as_unset(monkeypatch, tmp_path) -> None:
    """Empty string remains "unset" (existing behaviour preserved)."""
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(tmp_path / "env"))
    assert resolve_output_root({"general": {"output_root": ""}}) == tmp_path / "env"
    assert resolve_output_root({"general": {"output_root": "   "}}) == tmp_path / "env"


def test_resolve_output_root_uses_explicit_string_value(monkeypatch, tmp_path) -> None:
    """A real string value is honoured (sanity check for the type check)."""
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(tmp_path / "env"))
    config = {"general": {"output_root": str(tmp_path / "explicit")}}
    assert resolve_output_root(config) == tmp_path / "explicit"


def test_resolve_output_root_does_not_coerce_none_into_directory_named_none(
    monkeypatch,
) -> None:
    """Regression for the original Codex P2 footgun: ``output_root: null``
    used to yield ``Path("None")`` (a literal directory). Must now
    treat ``None`` as unset and fall back to the documented default.
    """
    from pathlib import Path

    monkeypatch.delenv("BLUEFIRE_OUTPUT_ROOT", raising=False)
    config = {"general": {"output_root": None}}
    resolved = resolve_output_root(config)
    assert resolved == Path("output")
    assert str(resolved) != "None"
    assert "None" not in resolved.parts


# ---------------------------------------------------------------------------
# get_ai_config — offline by default, no Ollama, no network
# ---------------------------------------------------------------------------


def test_get_ai_config_returns_offline_template_default() -> None:
    cfg = get_ai_config(None)
    assert cfg["provider"] == "template"
    assert cfg["enabled"] is False
    assert cfg["api_base"] == ""
    assert cfg["api_key_env"] == ""
    assert cfg["model"] == "default"
    assert cfg["timeout"] == 30
    assert cfg["max_tokens"] == 1024


def test_get_ai_config_default_is_not_ollama() -> None:
    """Hard guarantee: Ollama must NOT be the default provider."""
    cfg = get_ai_config(None)
    assert cfg["provider"] != "ollama"


def test_get_ai_config_known_providers_includes_openai_compatible_and_ollama() -> None:
    """The catalogue can list providers; the *default* still is template."""
    cfg = get_ai_config(None)
    assert "openai_compatible" in cfg["known_providers"]
    assert "ollama" in cfg["known_providers"]
    assert "template" in cfg["known_providers"]


def test_get_ai_config_parses_openai_compatible_without_network() -> None:
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "model-z",
                "api_base": "http://lab.example/v1",
                "api_key_env": "OPENAI_COMPATIBLE_API_KEY",
                "timeout": 45,
                "max_tokens": 2048,
            }
        },
    }
    cfg = get_ai_config(config)
    assert cfg["provider"] == "openai_compatible"
    assert cfg["enabled"] is True
    assert cfg["api_base"] == "http://lab.example/v1"
    assert cfg["api_key_env"] == "OPENAI_COMPATIBLE_API_KEY"
    assert cfg["model"] == "model-z"
    assert cfg["timeout"] == 45
    assert cfg["max_tokens"] == 2048


def test_get_ai_config_provider_block_fills_empty_module_fields() -> None:
    """`ai_providers.<provider>` populates empty `modules.ai.*` defaults."""
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "",
                "api_base": "",
            }
        },
        "ai_providers": {
            "openai_compatible": {
                "api_base": "http://lab.example/v1",
                "model": "vendor-model",
            }
        },
    }
    cfg = get_ai_config(config)
    assert cfg["api_base"] == "http://lab.example/v1"
    assert cfg["model"] == "vendor-model"


def test_get_ai_config_explicit_module_value_beats_provider_block() -> None:
    """Explicit `modules.ai.api_base` is not overwritten by the provider block."""
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai_compatible",
                "api_base": "http://explicit/v1",
            }
        },
        "ai_providers": {"openai_compatible": {"api_base": "http://provider-block/v1"}},
    }
    assert get_ai_config(config)["api_base"] == "http://explicit/v1"


def test_get_ai_config_handles_garbage_input_gracefully() -> None:
    """Non-mapping config returns documented defaults rather than crashing."""
    cfg = get_ai_config("not a dict")  # type: ignore[arg-type]
    assert cfg["provider"] == "template"
    cfg = get_ai_config({"modules": "not a dict"})  # type: ignore[dict-item]
    assert cfg["provider"] == "template"
    cfg = get_ai_config({"modules": {"ai": "not a dict"}})  # type: ignore[dict-item]
    assert cfg["provider"] == "template"


def test_get_ai_config_invalid_timeout_falls_back_to_default() -> None:
    cfg = get_ai_config(
        {"modules": {"ai": {"timeout": "not-a-number", "max_tokens": "nope"}}}
    )
    assert cfg["timeout"] == 30
    assert cfg["max_tokens"] == 1024


# ---------------------------------------------------------------------------
# is_offline_ai
# ---------------------------------------------------------------------------


def test_is_offline_ai_true_for_default_config() -> None:
    assert is_offline_ai(None) is True
    assert is_offline_ai({}) is True


def test_is_offline_ai_true_for_template_provider_even_when_enabled() -> None:
    assert (
        is_offline_ai({"modules": {"ai": {"enabled": True, "provider": "template"}}})
        is True
    )


def test_is_offline_ai_false_for_enabled_remote_provider() -> None:
    assert (
        is_offline_ai(
            {"modules": {"ai": {"enabled": True, "provider": "openai_compatible"}}}
        )
        is False
    )


# ---------------------------------------------------------------------------
# get_safety_config
# ---------------------------------------------------------------------------


def test_get_safety_config_returns_local_first_defaults() -> None:
    cfg = get_safety_config(None)
    assert cfg["dry_run"] is True
    assert cfg["auto_wipe"] is False
    assert cfg["max_runtime"] == 3600
    assert "10.0.0.0/24" in cfg["allowed_subnets"]
    assert "*.example.lab" in cfg["allowed_domains"]


def test_get_safety_config_honours_explicit_overrides() -> None:
    config = {
        "general": {
            "dry_run": False,
            "safeties": {
                "auto_wipe": True,
                "max_runtime": 120,
                "allowed_subnets": ["192.168.0.0/16"],
                "allowed_domains": ["lab.test"],
            },
        }
    }
    cfg = get_safety_config(config)
    assert cfg["dry_run"] is False
    assert cfg["auto_wipe"] is True
    assert cfg["max_runtime"] == 120
    assert cfg["allowed_subnets"] == ["192.168.0.0/16"]
    assert cfg["allowed_domains"] == ["lab.test"]


def test_get_safety_config_handles_garbage_input_gracefully() -> None:
    cfg = get_safety_config(None)
    assert cfg["dry_run"] is True
    cfg = get_safety_config({"general": "not a dict"})  # type: ignore[dict-item]
    assert cfg["dry_run"] is True


# ---------------------------------------------------------------------------
# get_mutation_config
# ---------------------------------------------------------------------------


def test_get_mutation_config_default_is_disabled() -> None:
    cfg = get_mutation_config(None)
    assert cfg["enabled"] is False
    assert cfg["default_strategy"] == ""
    assert "low_noise" in cfg["allowed_strategies"]


def test_get_mutation_config_honours_explicit_strategy() -> None:
    cfg = get_mutation_config(
        {"modules": {"mutation": {"enabled": True, "default_strategy": "low_noise"}}}
    )
    assert cfg["enabled"] is True
    assert cfg["default_strategy"] == "low_noise"


# ---------------------------------------------------------------------------
# is_legacy_capability_enabled — agrees with full evaluator
# ---------------------------------------------------------------------------


def _legacy_cfg(enabled: bool) -> Dict[str, Any]:
    return {
        "modules": {
            "legacy": {
                "actor_pack": {
                    "enabled": enabled,
                    "mode": "simulate",
                    "lab_confirmation": True,
                    "capabilities": {
                        "apt29": {"enabled": enabled, "mode": "simulate"},
                    },
                }
            }
        }
    }


def test_is_legacy_capability_enabled_true_when_enabled() -> None:
    cfg = _legacy_cfg(True)
    assert is_legacy_capability_enabled(cfg, "actor_pack", "apt29") is True
    assert (
        evaluate_legacy_capability(cfg, "actor_pack", "apt29").enabled is True
    )


def test_is_legacy_capability_enabled_false_when_disabled() -> None:
    cfg = _legacy_cfg(False)
    assert is_legacy_capability_enabled(cfg, "actor_pack", "apt29") is False
    assert (
        evaluate_legacy_capability(cfg, "actor_pack", "apt29").enabled is False
    )


def test_is_legacy_capability_enabled_safe_for_garbage_input() -> None:
    assert is_legacy_capability_enabled(None, "actor_pack", "apt29") is False
    assert is_legacy_capability_enabled("not a dict", "actor_pack", "apt29") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Default-config integration — ConfigManager produces compatible output
# ---------------------------------------------------------------------------


def test_default_configmanager_satisfies_offline_ai_invariant(tmp_path) -> None:
    """The shipped default config must keep the runtime offline."""
    from src.core.config import ConfigManager

    cfg_path = tmp_path / "config.yaml"
    config_manager = ConfigManager(str(cfg_path))
    config = config_manager.to_dict()

    assert is_offline_ai(config) is True
    ai = get_ai_config(config)
    assert ai["provider"] == "template"
    assert ai["enabled"] is False
    # The new shape keys are present in the default config.
    assert ai["api_key_env"] == ""
    assert ai["timeout"] == 30
    assert ai["max_tokens"] == 1024


def test_default_configmanager_keeps_safety_baseline(tmp_path) -> None:
    from src.core.config import ConfigManager

    cfg_path = tmp_path / "config.yaml"
    config = ConfigManager(str(cfg_path)).to_dict()
    safety = get_safety_config(config)
    assert safety["dry_run"] is True
    assert safety["max_runtime"] == 3600
