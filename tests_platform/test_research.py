from __future__ import annotations

import pytest

from bluefire.registry import load_builtin_registry
from bluefire.research import (
    ResearchRegistry,
    ResearchRelationship,
    ResearchSource,
    ResearchSourceError,
    SourceUseClassification,
    load_builtin_research_registry,
)


def _source(**overrides):
    values = {
        "schema_version": "bluefire.research-source.v1",
        "id": "research.example.v1",
        "name": "Example source",
        "source_type": "documentation",
        "project": "example/project",
        "authority": "Example authority",
        "reference_url": "https://example.test/reference/v1.0",
        "version": "1.0",
        "pin": "v1.0",
        "exact_ref": "v1.0",
        "retrieved_at": "2026-08-24",
        "license": "MIT",
        "license_url": "https://example.test/license",
        "file_level_license_review": "Example files reviewed.",
        "trademark_considerations": "No trademark use beyond attribution.",
        "license_review": "reviewed",
        "relationship": "comparative",
        "use_classification": "reference_only",
        "uses": ["research_reference"],
        "imported_paths": [],
        "cache_policy": "metadata_only",
        "executable_content": False,
        "attribution": "Example attribution.",
        "security_review": "No executable content was imported.",
        "last_verified_at": "2026-08-24",
        "update_status": "current",
        "transformation_history": "No imported or adapted content.",
        "notes": "Metadata-only test source.",
    }
    values.update(overrides)
    return values


def test_builtin_registry_is_pinned_licensed_and_attributed() -> None:
    sources = load_builtin_research_registry().all()

    assert len(sources) >= 4
    assert all(source.pin and source.version and source.retrieved_at for source in sources)
    assert all(source.license and source.license_url for source in sources)
    assert all(source.project and source.exact_ref for source in sources)
    assert all(source.attribution and source.security_review for source in sources)
    assert all(source.reference_url.startswith("https://") for source in sources)
    assert {source.relationship for source in sources} >= {
        ResearchRelationship.IMPORTED,
        ResearchRelationship.INSPIRED,
        ResearchRelationship.COMPARATIVE,
    }
    assert {source.use_classification for source in sources} >= {
        SourceUseClassification.REFERENCE_ONLY,
        SourceUseClassification.METADATA_IMPORT,
        SourceUseClassification.EXTERNAL_ADAPTER,
    }


def test_builtin_registry_uses_reviewed_immutable_current_references() -> None:
    sources = {source.id: source for source in load_builtin_research_registry().all()}

    assert sources["research.mitre-attack-enterprise.v1"].version == "19.2"
    assert sources["research.mitre-attack-enterprise.v1"].pin == (
        "8543c5b05bd9bbcace9fc37f30bba96b675b6f33"  # pragma: allowlist secret
    )
    assert sources["research.pysigma.v1"].version == "1.5.0"
    assert sources["research.yara-python.v1"].version == "4.5.4"
    assert sources["research.pysigma-backend-sqlite.v1"].version == "1.2.2"
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
    assert "reviewed" in behavior.provenance.source.lower()
    assert "t1082" in behavior.provenance.source.lower()


def test_vendored_declarative_policy_is_limited_to_non_executable_imported_metadata() -> None:
    reviewed = _source(
        relationship="imported",
        use_classification="metadata_import",
        imported_paths=["bluefire/data/reviewed.json"],
        cache_policy="vendored_declarative",
        executable_content=False,
    )

    source = ResearchSource.from_mapping(reviewed)
    assert source.cache_policy == "vendored_declarative"

    for changes in (
        {"relationship": "comparative"},
        {"use_classification": "reference_only"},
        {"license_review": "conditional"},
        {"imported_paths": []},
        {"executable_content": True},
    ):
        with pytest.raises(ResearchSourceError):
            ResearchSource.from_mapping({**reviewed, **changes})

    for imported_path in (
        "../outside.json",
        "/absolute.json",
        "C:/windows.json",
        "bluefire\\data\\windows.json",
        "https://example.test/source.json",
        "bluefire//data/source.json",
    ):
        with pytest.raises(ResearchSourceError, match="repository-relative POSIX"):
            ResearchSource.from_mapping({**reviewed, "imported_paths": [imported_path]})


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


def test_source_intake_classification_enforces_content_boundaries() -> None:
    source = ResearchSource.from_mapping(
        _source(
            use_classification="clean_reimplementation",
            transformation_history="Behavior independently implemented from public docs.",
        )
    )

    assert source.use_classification is SourceUseClassification.CLEAN_REIMPLEMENTATION

    with pytest.raises(ResearchSourceError, match="imported_paths must be empty"):
        ResearchSource.from_mapping(
            _source(
                use_classification="reference_only",
                imported_paths=["bluefire/copied.py"],
            )
        )
    with pytest.raises(ResearchSourceError, match="adapted/copied paths"):
        ResearchSource.from_mapping(_source(use_classification="compatible_code_adaptation"))
    with pytest.raises(ResearchSourceError, match="external executable content"):
        ResearchSource.from_mapping(
            _source(use_classification="external_adapter", executable_content=False)
        )


@pytest.mark.parametrize(
    ("classification", "changes"),
    [
        ("reference_only", {}),
        ("clean_reimplementation", {"relationship": "inspired"}),
        (
            "metadata_import",
            {
                "relationship": "imported",
                "cache_policy": "vendored_declarative",
                "imported_paths": ["bluefire/data/reviewed.json"],
            },
        ),
        (
            "external_adapter",
            {
                "relationship": "imported",
                "cache_policy": "external_only",
                "executable_content": True,
            },
        ),
        (
            "compatible_code_adaptation",
            {
                "relationship": "adapted",
                "cache_policy": "vendored_code",
                "executable_content": True,
                "imported_paths": ["bluefire/adapters/reviewed.py"],
            },
        ),
        (
            "incompatible_or_restricted",
            {"license_review": "prohibited"},
        ),
    ],
)
def test_all_six_source_classifications_have_a_valid_bounded_handling_model(
    classification: str,
    changes: dict,
) -> None:
    source = ResearchSource.from_mapping(_source(use_classification=classification, **changes))

    assert source.use_classification.value == classification


@pytest.mark.parametrize(
    "changes",
    [
        {
            "use_classification": "reference_only",
            "cache_policy": "vendored_code",
            "executable_content": True,
        },
        {
            "use_classification": "metadata_import",
            "relationship": "imported",
            "cache_policy": "vendored_code",
            "executable_content": True,
            "imported_paths": ["bluefire/data/reviewed.json"],
        },
        {
            "use_classification": "clean_reimplementation",
            "relationship": "inspired",
            "cache_policy": "vendored_code",
            "executable_content": True,
        },
        {
            "use_classification": "incompatible_or_restricted",
            "license_review": "prohibited",
            "cache_policy": "vendored_code",
            "executable_content": True,
        },
        {"use_classification": "reference_only", "executable_content": True},
        {
            "use_classification": "clean_reimplementation",
            "relationship": "imported",
            "cache_policy": "external_only",
            "executable_content": True,
        },
        {
            "use_classification": "incompatible_or_restricted",
            "license_review": "prohibited",
            "cache_policy": "external_only",
            "executable_content": True,
        },
    ],
)
def test_source_classification_refuses_inconsistent_content_handling(changes: dict) -> None:
    with pytest.raises(ResearchSourceError, match="inconsistent content handling"):
        ResearchSource.from_mapping(_source(**changes))


def test_registry_rejects_duplicates_and_unknown_ids() -> None:
    source = ResearchSource.from_mapping(_source())
    with pytest.raises(ResearchSourceError, match="duplicate"):
        ResearchRegistry((source, source))
    with pytest.raises(ResearchSourceError, match="unknown"):
        ResearchRegistry((source,)).get("research.missing.v1")
