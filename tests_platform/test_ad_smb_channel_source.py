"""Exact source inventory remains closed after the reviewed trust-only hook."""

from pathlib import Path

from tools.provider_boundary_inventory import (
    _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES,
    _reviewed_python_process_boundary_sources,
    _trusted_process_boundary_inventory_is_fixed,
)

ROOT = Path(__file__).resolve().parents[1]


def test_reviewed_inventory_includes_exact_trust_hook_without_wider_exemption():
    texts = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    assert _trusted_process_boundary_inventory_is_fixed()
    assert _reviewed_python_process_boundary_sources(texts)
    assert _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES["bluefire/runner_trust.py"] == (
        "sha256:d8f422bdc47425a2bf655f723848dc44cbb04c1a5aba85851743e5a1321a2d4d"
    )
    texts["bluefire/runner_trust.py"] += "\n# Unreviewed source change, with no shell call.\n"
    assert not _reviewed_python_process_boundary_sources(texts)


def test_missing_or_additional_source_still_refused():
    texts = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    original = texts.pop("bluefire/runner_trust.py")
    assert not _reviewed_python_process_boundary_sources(texts)
    texts["bluefire/runner_trust.py"] = original
    texts["bluefire/unreviewed.py"] = ""
    assert not _reviewed_python_process_boundary_sources(texts)
