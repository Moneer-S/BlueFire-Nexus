from src.core.legacy_controls import recommend_legacy_preset_for_objective


def test_guided_mapping_prefers_protocol_from_modules() -> None:
    rec = recommend_legacy_preset_for_objective(
        "simulate detection coverage",
        modules=["legacy_protocol_research"],
    )
    assert rec["objective"] == "protocol-research"
    assert rec["recommended_preset"] == "c2-simulate"


def test_guided_mapping_prefers_stealth_from_modules() -> None:
    rec = recommend_legacy_preset_for_objective(
        "detection regression for stealth tuning",
        modules=["legacy_stealth_research"],
    )
    assert rec["objective"] == "stealth-research"
    assert rec["recommended_preset"] == "stealth-simulate"
