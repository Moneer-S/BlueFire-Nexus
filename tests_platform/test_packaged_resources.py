from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_packaged_defaults_match_checkout_examples() -> None:
    pairs = (
        (
            ROOT / "config" / "bluefire.example.yaml",
            ROOT / "bluefire" / "data" / "bluefire.example.yaml",
        ),
        (
            ROOT / "scenarios" / "sandbox_research_chain.yaml",
            ROOT / "bluefire" / "data" / "sandbox_research_chain.yaml",
        ),
    )
    for checkout, packaged in pairs:
        assert packaged.read_bytes() == checkout.read_bytes()
