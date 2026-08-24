from __future__ import annotations

import pytest

from bluefire.research import (
    ResearchRegistry,
    ResearchRelationship,
    ResearchSource,
    ResearchSourceError,
    load_builtin_research_registry,
)


def _source(**overrides):
    values = {
        "schema_version": "bluefire.research-source.v1",
        "id": "research.example.v1",
        "name": "Example source",
        "source_type": "documentation",
        "authority": "Example authority",
        "reference_url": "https://example.test/reference",
        "version": "1.0",
        "pin": "v1.0",
        "retrieved_at": "2026-08-24",
        "license": "MIT",
        "license_url": "https://example.test/license",
        "license_review": "reviewed",
        "relationship": "comparative",
        "uses": ["research_reference"],
        "cache_policy": "metadata_only",
        "executable_content": False,
        "notes": "Metadata-only test source.",
    }
    values.update(overrides)
    return values


def test_builtin_registry_is_pinned_licensed_and_attributed() -> None:
    sources = load_builtin_research_registry().all()

    assert len(sources) >= 4
    assert all(source.pin and source.version and source.retrieved_at for source in sources)
    assert all(source.license and source.license_url for source in sources)
    assert all(source.reference_url.startswith("https://") for source in sources)
    assert {source.relationship for source in sources} >= {
        ResearchRelationship.IMPORTED,
        ResearchRelationship.INSPIRED,
        ResearchRelationship.COMPARATIVE,
    }


def test_source_rejects_unpinned_or_credentialed_reference() -> None:
    with pytest.raises(ResearchSourceError, match="pin"):
        ResearchSource.from_mapping(_source(pin=""))
    with pytest.raises(ResearchSourceError, match="without credentials"):
        ResearchSource.from_mapping(
            _source(
                reference_url="https://operator:secret@example.test/reference"  # pragma: allowlist secret
            )
        )


def test_metadata_only_source_cannot_claim_imported_content() -> None:
    with pytest.raises(ResearchSourceError, match="metadata-only"):
        ResearchSource.from_mapping(_source(relationship="imported"))


def test_registry_rejects_duplicates_and_unknown_ids() -> None:
    source = ResearchSource.from_mapping(_source())
    with pytest.raises(ResearchSourceError, match="duplicate"):
        ResearchRegistry((source, source))
    with pytest.raises(ResearchSourceError, match="unknown"):
        ResearchRegistry((source,)).get("research.missing.v1")
