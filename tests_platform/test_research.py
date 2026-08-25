from __future__ import annotations

import pytest

from bluefire.registry import load_builtin_registry
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
        "reference_url": "https://example.test/reference/v1.0",
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


def test_builtin_registry_uses_reviewed_immutable_current_references() -> None:
    sources = {source.id: source for source in load_builtin_research_registry().all()}

    assert sources["research.mitre-attack-enterprise.v1"].version == "19.2"
    assert sources["research.mitre-attack-enterprise.v1"].pin == (
        "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"  # pragma: allowlist secret
    )
    assert sources["research.pysigma.v1"].version == "1.5.0"
    assert sources["research.yara-python.v1"].version == "4.5.5"
    assert sources["research.atomic-red-team.v1"].pin == (
        "6132b92779873cb0d05bef07ba0a480d47eb1cc8"  # pragma: allowlist secret
    )
    assert all("/master/" not in source.reference_url for source in sources.values())
    assert all("/main/" not in source.reference_url for source in sources.values())
    assert all(source.pin in source.reference_url for source in sources.values())
    attack = sources["research.mitre-attack-enterprise.v1"]
    assert attack.pin in attack.license_url


def test_behavior_provenance_points_to_the_registered_attack_reference() -> None:
    research = load_builtin_research_registry().get("research.mitre-attack-enterprise.v1")
    behavior = load_builtin_registry().get_behavior("endpoint.discovery.system.v1")

    assert behavior.provenance.reference == research.reference_url
    assert behavior.provenance.license == research.license
    assert "comparative" in behavior.provenance.source.lower()


def test_source_rejects_unpinned_or_credentialed_reference() -> None:
    with pytest.raises(ResearchSourceError, match="pin"):
        ResearchSource.from_mapping(_source(pin=""))
    with pytest.raises(ResearchSourceError, match="without credentials"):
        ResearchSource.from_mapping(
            _source(
                reference_url="https://operator:secret@example.test/reference"  # pragma: allowlist secret
            )
        )


@pytest.mark.parametrize("mutable_pin", ["HEAD", "latest", "main", "master", "trunk"])
def test_source_rejects_mutable_pins(mutable_pin: str) -> None:
    with pytest.raises(ResearchSourceError, match="immutable version or commit"):
        ResearchSource.from_mapping(
            _source(
                pin=mutable_pin,
                reference_url=f"https://example.test/reference/{mutable_pin}",
            )
        )


def test_source_requires_reference_url_to_bind_exact_pin() -> None:
    with pytest.raises(ResearchSourceError, match="include its exact immutable pin"):
        ResearchSource.from_mapping(
            _source(reference_url="https://example.test/reference/releases")
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
