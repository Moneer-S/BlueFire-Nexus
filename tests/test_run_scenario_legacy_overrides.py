from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus
from src.run_scenario import (
    _apply_guided_preset_recommendation,
    _apply_legacy_overrides,
    _build_parser,
)


def test_run_scenario_granular_alias_override_enables_canonical_capability() -> None:
    parser = _build_parser()
    args = parser.parse_args(
        [
            "--legacy-pack",
            "c2_pack",
            "--legacy-capability",
            "quic_c2",
            "--legacy-mode",
            "simulate",
        ]
    )
    nexus = BlueFireNexus(str(Path("config.yaml")))
    _apply_legacy_overrides(nexus, args)
    summary = nexus.legacy_activation_summary()
    assert "websocket_quic" in summary["packs"]["c2_pack"]["enabled_capabilities"]


def test_run_scenario_invalid_legacy_mode_raises_value_error() -> None:
    parser = _build_parser()
    args = parser.parse_args([])
    args.legacy_mode = "invalid"
    nexus = BlueFireNexus(str(Path("config.yaml")))
    try:
        _apply_legacy_overrides(nexus, args)
    except ValueError as exc:
        assert "legacy mode must be either 'simulate' or 'emulate'" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid legacy mode")


def test_run_scenario_preset_sets_active_preset() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--legacy-preset", "c2-sim"])
    nexus = BlueFireNexus(str(Path("config.yaml")))
    _apply_legacy_overrides(nexus, args)
    summary = nexus.legacy_activation_summary()
    assert summary["active_preset"] == "c2-simulate"


def test_run_scenario_manual_pack_override_sets_manual_active_preset() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--legacy-pack", "stealth_pack"])
    nexus = BlueFireNexus(str(Path("config.yaml")))
    _apply_legacy_overrides(nexus, args)
    summary = nexus.legacy_activation_summary()
    assert summary["active_preset"] == "stealth_pack-manual"


def test_run_scenario_guided_recommendation_flag_is_available() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--legacy-guided"])
    assert args.legacy_guided is True


def test_run_scenario_guided_recommendation_handles_free_text_objective() -> None:
    nexus = BlueFireNexus(str(Path("config.yaml")))

    recommendation = _apply_guided_preset_recommendation(
        nexus,
        scenario_path="scenarios/apt29_credential_access.yaml",
        apply_recommendation=True,
    )
    assert recommendation["objective"] in {
        "safe-evaluation",
        "detection-regression",
        "protocol-research",
        "stealth-research",
        "full-lab-emulation",
    }
    assert recommendation["recommended_preset"] in {
        "safe-baseline",
        "full-simulate",
        "c2-simulate",
        "stealth-simulate",
        "full-emulate",
    }
