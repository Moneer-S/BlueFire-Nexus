"""Declarative plugin manifests.

Loading a manifest never imports plugin code or discovers Python entry points.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    SourceProvenance,
    _bool,
    _enum,
    _load_yaml_mapping,
    _mapping,
    _namespace,
    _stable_id,
    _strict_fields,
    _string,
    _strings,
)


class PluginManifestError(ContractError):
    pass


class PluginTrust(str, Enum):
    UNTRUSTED = "untrusted"
    REVIEWED = "reviewed"
    TRUSTED = "trusted"


_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class IntegrityRecord:
    algorithm: str
    digest: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "integrity") -> "IntegrityRecord":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"algorithm", "digest"},
            required={"algorithm", "digest"},
            context=context,
        )
        algorithm = _string(data["algorithm"], f"{context}.algorithm")
        digest = _string(data["digest"], f"{context}.digest")
        if algorithm != "sha256":
            raise PluginManifestError(f"{context}.algorithm must be sha256")
        if not _SHA256.fullmatch(digest):
            raise PluginManifestError(f"{context}.digest must be a lowercase SHA-256 digest")
        return cls(algorithm=algorithm, digest=digest)

    def to_dict(self) -> dict[str, str]:
        return {"algorithm": self.algorithm, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class PluginManifest:
    schema_version: str
    id: str
    name: str
    version: str
    enabled: bool
    trust: PluginTrust
    integrity: IntegrityRecord
    license: str
    provenance: SourceProvenance
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    behavior_ids: tuple[str, ...]
    action_ids: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str = "plugin manifest") -> "PluginManifest":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "schema_version",
                "id",
                "name",
                "version",
                "enabled",
                "trust",
                "integrity",
                "license",
                "provenance",
                "permissions",
                "capabilities",
                "behavior_ids",
                "action_ids",
            },
            required={
                "schema_version",
                "id",
                "name",
                "version",
                "enabled",
                "trust",
                "integrity",
                "license",
                "provenance",
                "permissions",
                "capabilities",
                "behavior_ids",
                "action_ids",
            },
            context=context,
        )
        if data["schema_version"] != "bluefire.plugin.v1":
            raise PluginManifestError(f"{context}.schema_version must be bluefire.plugin.v1")
        version = _string(data["version"], f"{context}.version")
        if not _SEMVER.fullmatch(version):
            raise PluginManifestError(f"{context}.version must be semantic versioning")
        permissions = _strings(data["permissions"], f"{context}.permissions")
        capabilities = _strings(data["capabilities"], f"{context}.capabilities")
        for index, permission in enumerate(permissions):
            _namespace(permission, f"{context}.permissions[{index}]")
        for index, capability in enumerate(capabilities):
            _namespace(capability, f"{context}.capabilities[{index}]")
        return cls(
            schema_version="bluefire.plugin.v1",
            id=_stable_id(data["id"], f"{context}.id"),
            name=_string(data["name"], f"{context}.name"),
            version=version,
            enabled=_bool(data["enabled"], f"{context}.enabled"),
            trust=_enum(PluginTrust, data["trust"], f"{context}.trust"),
            integrity=IntegrityRecord.from_mapping(data["integrity"], f"{context}.integrity"),
            license=_string(data["license"], f"{context}.license"),
            provenance=SourceProvenance.from_mapping(data["provenance"], f"{context}.provenance"),
            permissions=permissions,
            capabilities=capabilities,
            behavior_ids=_strings(data["behavior_ids"], f"{context}.behavior_ids", stable_ids=True),
            action_ids=_strings(data["action_ids"], f"{context}.action_ids", stable_ids=True),
        )

    def to_dict(self) -> dict[str, Any]:
        provenance = self.provenance.to_dict()
        if not provenance.get("notes"):
            # ``notes`` is optional in the strict source contract; omitting an
            # absent value keeps the canonical manifest round-trippable.
            provenance.pop("notes", None)
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "enabled": self.enabled,
            "trust": self.trust.value,
            "integrity": self.integrity.to_dict(),
            "license": self.license,
            "provenance": provenance,
            "permissions": list(self.permissions),
            "capabilities": list(self.capabilities),
            "behavior_ids": list(self.behavior_ids),
            "action_ids": list(self.action_ids),
        }


def load_plugin_manifest(path: str | Path) -> PluginManifest:
    return PluginManifest.from_mapping(_load_yaml_mapping(path, "plugin manifest"))


__all__ = [
    "IntegrityRecord",
    "PluginManifest",
    "PluginManifestError",
    "PluginTrust",
    "load_plugin_manifest",
]
