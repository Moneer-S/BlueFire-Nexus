"""Strict inventory for the three maintained official deep-behavior packs."""

from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, cast

from .config import load_config
from .contracts import load_scenario
from .registry import load_builtin_registry
from .util import content_hash, file_hash

PACKS_SCHEMA = "bluefire.official-behavior-packs.v1"
PACK_REPORT_SCHEMA = "bluefire.deep-behavior-pack-inventory.v1"
PACKS_PATH = "bluefire/data/deep_behavior_packs.json"

EXPECTED_PACK_PHASES: Mapping[str, tuple[str, ...]] = {
    "bluefire.endpoint-identity.v1": (
        "execution",
        "discovery",
        "collection_staging",
        "persistence",
        "authorized_credentials",
        "disposable_lateral",
        "telemetry_shaping",
        "cleanup",
    ),
    "bluefire.linux-container.v1": (
        "process_effects",
        "filesystem_effects",
        "internal_network_effects",
        "runtime_observation",
        "alternate_implementation",
        "cleanup",
    ),
    "bluefire.aws-identity-lab.v1": (
        "credential_binding",
        "enumeration",
        "control_plane_action",
        "cleanup_revocation",
        "audit_telemetry",
        "simulate",
        "execute",
        "manual_smoke",
    ),
}

_PACK_IDENTITIES: Mapping[str, tuple[str, tuple[str, ...], str | None, str, str]] = {
    "bluefire.endpoint-identity.v1": (
        "endpoint_identity",
        ("windows",),
        "endpoint_deep_behavior_lab.yaml",
        "sandbox-endpoint-deep-lab.v1",
        "bluefire.native-runner",
    ),
    "bluefire.linux-container.v1": (
        "linux_container",
        ("linux",),
        "linux_container_validation.yaml",
        "sandbox-execute.v1",
        "bluefire.native-runner",
    ),
    "bluefire.aws-identity-lab.v1": (
        "aws_identity",
        ("aws",),
        None,
        "aws-identity-lab.v1",
        "bluefire.cloud_identity_pack",
    ),
}

_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_PHASE_ID = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_MAX_MANIFEST_BYTES = 128 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class DeepBehaviorPackError(ValueError):
    """The maintained official pack inventory is invalid or incomplete."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DeepBehaviorPackError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeepBehaviorPackError("the official pack manifest contains a duplicate key")
        result[key] = value
    return result


def _mapping(value: Any, fields: set[str], message: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields, message)
    return cast(Mapping[str, Any], value)


def _strings(value: Any, message: str) -> tuple[str, ...]:
    _require(
        isinstance(value, list)
        and bool(value)
        and len(value) == len(set(value))
        and all(isinstance(item, str) and item for item in value),
        message,
    )
    return tuple(cast(list[str], value))


@dataclass(frozen=True, slots=True)
class PackPhase:
    phase_id: str
    operation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OfficialBehaviorPack:
    pack_id: str
    title: str
    kind: str
    platforms: tuple[str, ...]
    scenario_asset: str | None
    runner_profile_id: str
    implementation: str
    phases: tuple[PackPhase, ...]
    limitations: tuple[str, ...]

    @property
    def operation_ids(self) -> tuple[str, ...]:
        return tuple(item for phase in self.phases for item in phase.operation_ids)

    def public_record(self) -> Mapping[str, Any]:
        return {
            "pack_id": self.pack_id,
            "kind": self.kind,
            "platforms": list(self.platforms),
            "scenario_asset": self.scenario_asset,
            "runner_profile_id": self.runner_profile_id,
            "implementation": self.implementation,
            "phases": [phase.phase_id for phase in self.phases],
            "operation_count": len(self.operation_ids),
        }


def _safe_manifest(path: Path) -> Mapping[str, Any]:
    details = path.lstat()
    _require(
        stat.S_ISREG(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
        and 0 < details.st_size <= _MAX_MANIFEST_BYTES,
        "the official pack manifest is absent, unsafe, or unbounded",
    )
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeepBehaviorPackError("the official pack manifest is invalid JSON") from exc
    return _mapping(
        value,
        {"schema_version", "packs"},
        "the official pack manifest schema is not exact",
    )


def _parse_pack(value: Any) -> OfficialBehaviorPack:
    data = _mapping(
        value,
        {
            "pack_id",
            "title",
            "kind",
            "platforms",
            "scenario_asset",
            "runner_profile_id",
            "implementation",
            "phases",
            "limitations",
        },
        "an official pack record is not exact",
    )
    pack_id = cast(str, data.get("pack_id"))
    _require(
        isinstance(pack_id, str) and _STABLE_ID.fullmatch(pack_id) is not None,
        "pack ID is invalid",
    )
    _require(pack_id in _PACK_IDENTITIES, "the official pack inventory contains an unknown pack")
    title = cast(str, data.get("title"))
    kind = cast(str, data.get("kind"))
    runner_profile_id = cast(str, data.get("runner_profile_id"))
    implementation = cast(str, data.get("implementation"))
    scenario_asset = cast(str | None, data.get("scenario_asset"))
    platforms = _strings(data.get("platforms"), "pack platforms are invalid")
    limitations = _strings(data.get("limitations"), "pack limitations are invalid")
    _require(
        isinstance(title, str)
        and 1 <= len(title) <= 160
        and isinstance(kind, str)
        and isinstance(runner_profile_id, str)
        and _STABLE_ID.fullmatch(runner_profile_id) is not None
        and isinstance(implementation, str)
        and 1 <= len(implementation) <= 128
        and (scenario_asset is None or isinstance(scenario_asset, str)),
        "an official pack identity is invalid",
    )
    raw_phases = data.get("phases")
    _require(isinstance(raw_phases, list) and bool(raw_phases), "pack phases are absent")
    raw_phases = cast(list[Any], raw_phases)
    phases: list[PackPhase] = []
    for raw in raw_phases:
        phase = _mapping(raw, {"phase_id", "behavior_ids"}, "a pack phase is not exact")
        phase_id = cast(str, phase.get("phase_id"))
        operations = _strings(phase.get("behavior_ids"), "pack phase operations are invalid")
        _require(
            isinstance(phase_id, str)
            and _PHASE_ID.fullmatch(phase_id) is not None
            and all(_STABLE_ID.fullmatch(item) is not None for item in operations),
            "a pack phase identity is invalid",
        )
        phases.append(PackPhase(phase_id=phase_id, operation_ids=operations))
    _require(
        tuple(phase.phase_id for phase in phases) == EXPECTED_PACK_PHASES[pack_id],
        "the official pack phase inventory is incomplete or reordered",
    )
    _require(
        len({item for phase in phases for item in phase.operation_ids})
        == sum(len(phase.operation_ids) for phase in phases),
        "an official pack reuses an operation across phases",
    )
    expected = _PACK_IDENTITIES[pack_id]
    _require(
        (kind, platforms, scenario_asset, runner_profile_id, implementation) == expected,
        "an official pack identity diverges from the maintained contract",
    )
    return OfficialBehaviorPack(
        pack_id=pack_id,
        title=title,
        kind=kind,
        platforms=platforms,
        scenario_asset=scenario_asset,
        runner_profile_id=runner_profile_id,
        implementation=implementation,
        phases=tuple(phases),
        limitations=limitations,
    )


def _validate_maintained_assets(root: Path, packs: tuple[OfficialBehaviorPack, ...]) -> None:
    registry = load_builtin_registry()
    registry_ids = set(registry.behavior_ids) | set(registry.action_ids)
    config = load_config(root / "config" / "bluefire.example.yaml")
    profiles = {profile.id: profile for profile in config.runner_profiles}
    for pack in packs:
        if pack.kind == "aws_identity":
            _require(
                all(operation.startswith("aws.identity.") for operation in pack.operation_ids),
                "the AWS pack contains a non-AWS operation",
            )
            continue
        _require(pack.runner_profile_id in profiles, "an official pack runner profile is absent")
        _require(
            all(operation in registry_ids for operation in pack.operation_ids),
            "an official native pack references an unregistered operation",
        )
        scenario_asset = pack.scenario_asset
        _require(scenario_asset is not None, "an official native pack scenario is absent")
        scenario_asset = cast(str, scenario_asset)
        source = root / "scenarios" / scenario_asset
        packaged = root / "bluefire" / "data" / scenario_asset
        _require(
            source.is_file()
            and packaged.is_file()
            and not source.is_symlink()
            and not packaged.is_symlink()
            and source.read_bytes() == packaged.read_bytes(),
            "an official pack scenario and packaged copy diverge",
        )
        scenario = load_scenario(source)
        available = {
            operation
            for step in scenario.steps
            for operation in (step.behavior_id, *step.alternates)
        }
        _require(
            all(
                operation in available or operation == "sandbox.peer.handoff.v1"
                for operation in pack.operation_ids
            ),
            "an official native pack phase is absent from its scenario",
        )


def load_official_behavior_packs(repository: Path) -> tuple[OfficialBehaviorPack, ...]:
    root = repository.resolve(strict=True)
    manifest = _safe_manifest(root / PACKS_PATH)
    _require(manifest.get("schema_version") == PACKS_SCHEMA, "pack schema version is unsupported")
    raw_packs = manifest.get("packs")
    _require(isinstance(raw_packs, list) and len(raw_packs) == 3, "pack inventory is incomplete")
    raw_packs = cast(list[Any], raw_packs)
    packs = tuple(_parse_pack(item) for item in raw_packs)
    _require(
        tuple(pack.pack_id for pack in packs) == tuple(EXPECTED_PACK_PHASES),
        "pack inventory is incomplete or reordered",
    )
    _validate_maintained_assets(root, packs)
    return packs


def official_pack_inventory(repository: Path) -> Mapping[str, Any]:
    root = repository.resolve(strict=True)
    packs = load_official_behavior_packs(root)
    records = [dict(pack.public_record()) for pack in packs]
    return {
        "schema_version": PACK_REPORT_SCHEMA,
        "passed": True,
        "manifest": PACKS_PATH,
        "manifest_sha256": file_hash(root / PACKS_PATH),
        "packs": records,
        "inventory_sha256": content_hash(records),
    }


__all__ = [
    "EXPECTED_PACK_PHASES",
    "PACKS_PATH",
    "PACKS_SCHEMA",
    "PACK_REPORT_SCHEMA",
    "DeepBehaviorPackError",
    "OfficialBehaviorPack",
    "PackPhase",
    "load_official_behavior_packs",
    "official_pack_inventory",
]
