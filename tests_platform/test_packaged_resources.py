from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_packaged_defaults_match_checkout_examples() -> None:
    pairs = [
        (
            ROOT / "config" / "bluefire.example.yaml",
            ROOT / "bluefire" / "data" / "bluefire.example.yaml",
        )
    ]
    pairs.extend(
        (scenario, ROOT / "bluefire" / "data" / scenario.name)
        for scenario in sorted((ROOT / "scenarios").glob("*.yaml"))
    )
    for checkout, packaged in pairs:
        assert packaged.read_bytes() == checkout.read_bytes()
