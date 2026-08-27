"""Pinned public-research provenance without vendoring external corpora."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from importlib import resources
from typing import Any, Iterable
from urllib.parse import urlparse

import yaml

from .contracts import ContractError, _mapping, _stable_id, _strict_fields, _string


class ResearchSourceError(ContractError):
    pass


class ResearchRelationship(str, Enum):
    IMPORTED = "imported"
    ADAPTED = "adapted"
    INSPIRED = "inspired"
    COMPARATIVE = "comparative"


class LicenseReview(str, Enum):
    REVIEWED = "reviewed"
    CONDITIONAL = "conditional"
    PROHIBITED = "prohibited"


class SourceUseClassification(str, Enum):
    REFERENCE_ONLY = "reference_only"
    METADATA_IMPORT = "metadata_import"
    CLEAN_REIMPLEMENTATION = "clean_reimplementation"
    EXTERNAL_ADAPTER = "external_adapter"
    COMPATIBLE_CODE_ADAPTATION = "compatible_code_adaptation"
    INCOMPATIBLE_OR_RESTRICTED = "incompatible_or_restricted"


_SOURCE_TYPES = {"dataset", "documentation", "software", "rule_corpus"}
_CACHE_POLICIES = {"external_only", "metadata_only"}
_USES = {"behavior_mapping", "comparison", "parser_validation", "research_reference"}
_UPDATE_STATUSES = {"current", "review_due", "superseded", "blocked"}


@dataclass(frozen=True, slots=True)
class ResearchSource:
    schema_version: str
    id: str
    name: str
    source_type: str
    project: str
    authority: str
    reference_url: str
    version: str
    pin: str
    exact_ref: str
    retrieved_at: str
    license: str
    license_url: str
    file_level_license_review: str
    trademark_considerations: str
    license_review: LicenseReview
    relationship: ResearchRelationship
    use_classification: SourceUseClassification
    uses: tuple[str, ...]
    imported_paths: tuple[str, ...]
    cache_policy: str
    executable_content: bool
    attribution: str
    security_review: str
    last_verified_at: str
    update_status: str
    transformation_history: str
    notes: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "research source") -> "ResearchSource":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "schema_version",
                "id",
                "name",
                "source_type",
                "project",
                "authority",
                "reference_url",
                "version",
                "pin",
                "exact_ref",
                "retrieved_at",
                "license",
                "license_url",
                "file_level_license_review",
                "trademark_considerations",
                "license_review",
                "relationship",
                "use_classification",
                "uses",
                "imported_paths",
                "cache_policy",
                "executable_content",
                "attribution",
                "security_review",
                "last_verified_at",
                "update_status",
                "transformation_history",
                "notes",
            },
            required={
                "schema_version",
                "id",
                "name",
                "source_type",
                "project",
                "authority",
                "reference_url",
                "version",
                "pin",
                "exact_ref",
                "retrieved_at",
                "license",
                "license_url",
                "file_level_license_review",
                "trademark_considerations",
                "license_review",
                "relationship",
                "use_classification",
                "uses",
                "imported_paths",
                "cache_policy",
                "executable_content",
                "attribution",
                "security_review",
                "last_verified_at",
                "update_status",
                "transformation_history",
                "notes",
            },
            context=context,
        )
        if data["schema_version"] != "bluefire.research-source.v1":
            raise ResearchSourceError(
                f"{context}.schema_version must be bluefire.research-source.v1"
            )
        source_type = _string(data["source_type"], f"{context}.source_type")
        if source_type not in _SOURCE_TYPES:
            raise ResearchSourceError(f"{context}.source_type is unsupported")
        cache_policy = _string(data["cache_policy"], f"{context}.cache_policy")
        if cache_policy not in _CACHE_POLICIES:
            raise ResearchSourceError(f"{context}.cache_policy is unsupported")
        uses_value = data["uses"]
        if not isinstance(uses_value, list) or not uses_value:
            raise ResearchSourceError(f"{context}.uses must be a non-empty list")
        uses = tuple(_string(item, f"{context}.uses") for item in uses_value)
        if len(uses) != len(set(uses)) or any(item not in _USES for item in uses):
            raise ResearchSourceError(f"{context}.uses contains duplicate or unsupported values")
        executable_content = data["executable_content"]
        if not isinstance(executable_content, bool):
            raise ResearchSourceError(f"{context}.executable_content must be a boolean")
        pin = data["pin"]
        if not isinstance(pin, str) or not pin.strip():
            raise ResearchSourceError(f"{context}.pin must be a non-empty version or commit")
        pin = pin.strip()
        if pin.casefold() in {"head", "latest", "main", "master", "trunk"}:
            raise ResearchSourceError(f"{context}.pin must be an immutable version or commit")
        reference_url = _https_url(data["reference_url"], f"{context}.reference_url")
        if pin not in urlparse(reference_url).path:
            raise ResearchSourceError(
                f"{context}.reference_url must include its exact immutable pin"
            )
        license_url = _https_url(data["license_url"], f"{context}.license_url")
        retrieved_at = _string(data["retrieved_at"], f"{context}.retrieved_at")
        try:
            date.fromisoformat(retrieved_at)
        except ValueError as exc:
            raise ResearchSourceError(f"{context}.retrieved_at must be an ISO date") from exc
        try:
            relationship = ResearchRelationship(data["relationship"])
            license_review = LicenseReview(data["license_review"])
        except (TypeError, ValueError) as exc:
            raise ResearchSourceError(f"{context} has an invalid enum value") from exc
        if relationship is ResearchRelationship.IMPORTED and cache_policy == "metadata_only":
            raise ResearchSourceError(
                f"{context} cannot claim imported content under a metadata-only policy"
            )
        if license_review is LicenseReview.PROHIBITED and relationship in {
            ResearchRelationship.IMPORTED,
            ResearchRelationship.ADAPTED,
        }:
            raise ResearchSourceError(f"{context} cannot import prohibited content")
        try:
            use_classification = SourceUseClassification(data["use_classification"])
        except (TypeError, ValueError) as exc:
            raise ResearchSourceError(f"{context}.use_classification is unsupported") from exc
        imported_paths = _string_tuple(data["imported_paths"], f"{context}.imported_paths")
        if use_classification in {
            SourceUseClassification.REFERENCE_ONLY,
            SourceUseClassification.INCOMPATIBLE_OR_RESTRICTED,
        } and imported_paths:
            raise ResearchSourceError(
                f"{context}.imported_paths must be empty for {use_classification.value}"
            )
        if use_classification is SourceUseClassification.COMPATIBLE_CODE_ADAPTATION:
            if not imported_paths:
                raise ResearchSourceError(
                    f"{context}.imported_paths must identify adapted/copied paths"
                )
            if license_review is not LicenseReview.REVIEWED:
                raise ResearchSourceError(
                    f"{context}.license_review must be reviewed before code adaptation"
                )
        if use_classification is SourceUseClassification.INCOMPATIBLE_OR_RESTRICTED:
            if license_review is not LicenseReview.PROHIBITED:
                raise ResearchSourceError(
                    f"{context}.license_review must be prohibited for restricted sources"
                )
        if use_classification is SourceUseClassification.EXTERNAL_ADAPTER:
            if cache_policy != "external_only" or not executable_content:
                raise ResearchSourceError(
                    f"{context}.external_adapter sources must remain external executable content"
                )
        update_status = _string(data["update_status"], f"{context}.update_status")
        if update_status not in _UPDATE_STATUSES:
            raise ResearchSourceError(f"{context}.update_status is unsupported")
        last_verified_at = _string(data["last_verified_at"], f"{context}.last_verified_at")
        try:
            date.fromisoformat(last_verified_at)
        except ValueError as exc:
            raise ResearchSourceError(f"{context}.last_verified_at must be an ISO date") from exc
        return cls(
            schema_version="bluefire.research-source.v1",
            id=_stable_id(data["id"], f"{context}.id"),
            name=_string(data["name"], f"{context}.name"),
            source_type=source_type,
            project=_string(data["project"], f"{context}.project"),
            authority=_string(data["authority"], f"{context}.authority"),
            reference_url=reference_url,
            version=_string(data["version"], f"{context}.version"),
            pin=pin,
            exact_ref=_string(data["exact_ref"], f"{context}.exact_ref"),
            retrieved_at=retrieved_at,
            license=_string(data["license"], f"{context}.license"),
            license_url=license_url,
            file_level_license_review=_string(
                data["file_level_license_review"],
                f"{context}.file_level_license_review",
            ),
            trademark_considerations=_string(
                data["trademark_considerations"],
                f"{context}.trademark_considerations",
            ),
            license_review=license_review,
            relationship=relationship,
            use_classification=use_classification,
            uses=uses,
            imported_paths=imported_paths,
            cache_policy=cache_policy,
            executable_content=executable_content,
            attribution=_string(data["attribution"], f"{context}.attribution"),
            security_review=_string(data["security_review"], f"{context}.security_review"),
            last_verified_at=last_verified_at,
            update_status=update_status,
            transformation_history=_string(
                data["transformation_history"],
                f"{context}.transformation_history",
            ),
            notes=_string(data["notes"], f"{context}.notes"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "name": self.name,
            "source_type": self.source_type,
            "project": self.project,
            "authority": self.authority,
            "reference_url": self.reference_url,
            "version": self.version,
            "pin": self.pin,
            "exact_ref": self.exact_ref,
            "retrieved_at": self.retrieved_at,
            "license": self.license,
            "license_url": self.license_url,
            "file_level_license_review": self.file_level_license_review,
            "trademark_considerations": self.trademark_considerations,
            "license_review": self.license_review.value,
            "relationship": self.relationship.value,
            "use_classification": self.use_classification.value,
            "uses": list(self.uses),
            "imported_paths": list(self.imported_paths),
            "cache_policy": self.cache_policy,
            "executable_content": self.executable_content,
            "attribution": self.attribution,
            "security_review": self.security_review,
            "last_verified_at": self.last_verified_at,
            "update_status": self.update_status,
            "transformation_history": self.transformation_history,
            "notes": self.notes,
        }


class ResearchRegistry:
    def __init__(self, sources: Iterable[ResearchSource]) -> None:
        self._sources: dict[str, ResearchSource] = {}
        for source in sources:
            if source.id in self._sources:
                raise ResearchSourceError(f"duplicate research source id: {source.id}")
            self._sources[source.id] = source

    def all(self) -> tuple[ResearchSource, ...]:
        return tuple(self._sources[key] for key in sorted(self._sources))

    def get(self, source_id: str) -> ResearchSource:
        try:
            return self._sources[source_id]
        except KeyError as exc:
            raise ResearchSourceError(f"unknown research source id: {source_id}") from exc


def load_builtin_research_registry() -> ResearchRegistry:
    resource = resources.files("bluefire.data").joinpath("research_sources.yaml")
    try:
        value = yaml.safe_load(resource.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ResearchSourceError("unable to load built-in research sources") from exc
    data = _mapping(value, "research source registry")
    _strict_fields(
        data,
        allowed={"schema_version", "sources"},
        required={"schema_version", "sources"},
        context="research source registry",
    )
    if data["schema_version"] != "bluefire.research-registry.v1":
        raise ResearchSourceError(
            "research source registry.schema_version must be bluefire.research-registry.v1"
        )
    values = data["sources"]
    if not isinstance(values, list):
        raise ResearchSourceError("research source registry.sources must be a list")
    return ResearchRegistry(
        ResearchSource.from_mapping(item, f"research source registry.sources[{index}]")
        for index, item in enumerate(values)
    )


def _https_url(value: Any, context: str) -> str:
    url = _string(value, context)
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ResearchSourceError(f"{context} must be a public HTTPS URL without credentials")
    return url


def _string_tuple(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ResearchSourceError(f"{context} must be a list")
    items = tuple(_string(item, context) for item in value)
    if len(items) != len(set(items)):
        raise ResearchSourceError(f"{context} must not contain duplicates")
    return items


__all__ = [
    "LicenseReview",
    "ResearchRegistry",
    "ResearchRelationship",
    "ResearchSource",
    "ResearchSourceError",
    "SourceUseClassification",
    "load_builtin_research_registry",
]
