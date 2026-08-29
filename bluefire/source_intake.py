"""Bounded, deterministic intake for reviewed declarative source metadata.

Requests select only transformers assembled into trusted product code. Source
bytes cannot select imports, commands, dependencies, or executors. Validation
and transformation finish before one content-addressed envelope is published.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .source_intake_contracts import (
    MAX_SOURCE_BYTES,
    IntakeSource,
    SourceIntakeError,
    SourceIntakeRequest,
    TransformerSelection,
    _bounded_text,
    _error,
    _https_url,
    _identifier,
)
from .util import canonical_json_bytes, content_hash

MAX_OUTPUT_BYTES = 512 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 2048
MAX_CONTAINER_ITEMS = 512
MAX_STRING_CHARS = 32768

_BUNDLE_OBJECT_ID = re.compile(
    r"^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_ATTACK_OBJECT_ID = re.compile(
    r"^attack-pattern--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_ATTACK_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_ATTACK_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_WINDOWS_REPARSE_POINT = 0x0400

# Field-name scan before and after transformation. Descriptive prose is safe to
# discard; structured fields that could materialize executable content are not.
_FORBIDDEN_MATERIALIZATION_FIELDS = frozenset(
    (
        "argument arguments argv binary binaries cmd command commandline commands "
        "dependencies dependency downloadurl executable executables executor executors "
        "filecontent filecontents getprereqcommand input inputargument inputarguments inputs "
        "installcommand installscript interpreter payload payloads prereqcommand requirements "
        "runtimecommand script scripts shell sourcecode"
    ).split()
)
_FORBIDDEN_MATERIALIZATION_STEMS = ("command", "dependency", "executor", "input", "payload")


@dataclass(frozen=True, slots=True)
class SourceTransformation:
    """Metadata plus a complete JSON-pointer disposition for every source field."""

    metadata: Mapping[str, Any]
    projected_fields: tuple[str, ...]
    discarded_fields: tuple[str, ...]


TransformerFunction = Callable[[Any], SourceTransformation]


@dataclass(frozen=True, slots=True)
class SourceTransformer:
    """A transformer explicitly assembled into trusted product code."""

    name: str
    version: str
    output_schema: str
    transform: TransformerFunction


class SourceTransformerRegistry:
    """Immutable exact-name/version allowlist with no runtime entry points."""

    def __init__(self, transformers: Iterable[SourceTransformer]) -> None:
        entries: dict[tuple[str, str], SourceTransformer] = {}
        for transformer in transformers:
            selection = TransformerSelection.from_mapping(
                {"name": transformer.name, "version": transformer.version},
                "source transformer",
            )
            output_schema = _identifier(
                transformer.output_schema, "source transformer.output_schema"
            )
            if not callable(transformer.transform):
                raise _error("source transformer.transform must be callable")
            key = (selection.name, selection.version)
            if key in entries:
                raise _error("source transformer registry contains a duplicate name/version")
            entries[key] = SourceTransformer(
                selection.name, selection.version, output_schema, transformer.transform
            )
        if not entries:
            raise _error("source transformer registry must not be empty")
        self._entries = MappingProxyType(entries)

    def select(self, name: str, version: str) -> SourceTransformer:
        try:
            return self._entries[(name, version)]
        except KeyError as exc:
            raise _error("source transformer name/version is not allowlisted") from exc

    def inventory(self) -> tuple[dict[str, str], ...]:
        ordered = sorted(self._entries.values(), key=lambda item: (item.name, item.version))
        return tuple(
            {"name": item.name, "output_schema": item.output_schema, "version": item.version}
            for item in ordered
        )


@dataclass(frozen=True, slots=True)
class SourceIntakeResult:
    path: Path
    record_sha256: str
    output_sha256: str
    envelope: Mapping[str, Any]


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("source JSON contains a duplicate object field")
        result[key] = value
    return result


def _reject_number(_text: str) -> Any:
    raise _error("source JSON floating-point numbers are not supported")


def _parse_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise _error("source JSON integer exceeds the signed 64-bit boundary")
    value = int(text)
    if not -(2**63) <= value <= 2**63 - 1:
        raise _error("source JSON integer exceeds the signed 64-bit boundary")
    return value


def _validate_json_value(value: Any, *, context: str) -> None:
    stack: list[tuple[Any, int, str]] = [(value, 1, context)]
    nodes = 0
    while stack:
        current, depth, location = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise _error(f"{context} exceeds the JSON node limit")
        if depth > MAX_JSON_DEPTH:
            raise _error(f"{context} exceeds the JSON depth limit")
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int) and not isinstance(current, bool):
            if not -(2**63) <= current <= 2**63 - 1:
                raise _error(f"{location} integer exceeds the signed 64-bit boundary")
            continue
        if isinstance(current, str):
            invalid_control = any(
                (ord(char) < 32 and char not in "\t\n\r") or ord(char) == 127 for char in current
            )
            if (
                len(current) > MAX_STRING_CHARS
                or unicodedata.normalize("NFC", current) != current
                or any(0xD800 <= ord(char) <= 0xDFFF for char in current)
                or invalid_control
            ):
                raise _error(f"{location} contains an invalid or oversized JSON string")
            continue
        if isinstance(current, list):
            if len(current) > MAX_CONTAINER_ITEMS:
                raise _error(f"{location} exceeds the array item limit")
            stack.extend(
                (item, depth + 1, f"{location}[{index}]")
                for index, item in reversed(tuple(enumerate(current)))
            )
            continue
        if isinstance(current, dict):
            if len(current) > MAX_CONTAINER_ITEMS:
                raise _error(f"{location} exceeds the object field limit")
            for key, item in reversed(tuple(current.items())):
                _bounded_text(key, f"{location} field name", maximum=256)
                stack.append((item, depth + 1, f"{location}.{key}"))
            continue
        raise _error(f"{location} contains an unsupported JSON value")


def _reject_materialization_fields(value: Any, *, context: str) -> None:
    stack: list[tuple[Any, str]] = [(value, context)]
    while stack:
        current, location = stack.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
                if normalized in _FORBIDDEN_MATERIALIZATION_FIELDS or any(
                    stem in normalized for stem in _FORBIDDEN_MATERIALIZATION_STEMS
                ):
                    raise _error(f"{location} contains forbidden materialization field {key!r}")
                stack.append((item, f"{location}.{key}"))
        elif isinstance(current, list):
            stack.extend((item, f"{location}[{index}]") for index, item in enumerate(current))


def _json_field_paths(value: Any) -> tuple[str, ...]:
    paths: set[str] = set()
    stack: list[tuple[Any, str]] = [(value, "")]
    while stack:
        current, parent = stack.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                path = f"{parent}/{key.replace('~', '~0').replace('/', '~1')}"
                paths.add(path)
                stack.append((item, path))
        elif isinstance(current, list):
            stack.extend((item, f"{parent}/{index}") for index, item in enumerate(current))
    return tuple(sorted(paths))


def _parse_source_json(payload: bytes) -> tuple[Any, bytes]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_json_pairs,
            parse_float=_reject_number,
            parse_int=_parse_integer,
            parse_constant=_reject_number,
        )
    except SourceIntakeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _error("source must contain bounded UTF-8 JSON") from exc
    _validate_json_value(value, context="source JSON")
    _reject_materialization_fields(value, context="source JSON")
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise _error("source must contain bounded canonical JSON values") from exc
    if not canonical or len(canonical) > MAX_SOURCE_BYTES:
        raise _error("canonicalized source JSON exceeds its byte limit")
    return value, canonical


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def _existing_safe_root(value: Path, *, context: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _error(f"{context} must be an absolute existing directory")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _error(f"{context} is unavailable") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise _error(f"{context} must not be a symbolic link or reparse point")
    return resolved


def _path_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _safe_source_chain(root: Path, relative_path: str) -> list[tuple[Path, tuple[int, int, int]]]:
    chain: list[tuple[Path, tuple[int, int, int]]] = []
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise _error("source root became unavailable") from exc
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise _error("source root is unsafe")
    chain.append((root, _path_identity(root_metadata)))
    candidate = root
    parts = PurePosixPath(relative_path).parts
    for index, part in enumerate(parts):
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise _error("reviewed source file is unavailable") from exc
        if _is_link_or_reparse(metadata):
            raise _error("source path may not contain symbolic links or reparse points")
        if index == len(parts) - 1:
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise _error("reviewed source must be one regular, singly-linked file")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise _error("source path contains a non-directory component")
        chain.append((candidate, _path_identity(metadata)))
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise _error("source path escapes its configured root") from exc
    return chain


def _read_verified_source(root: Path, source: IntakeSource) -> bytes:
    chain = _safe_source_chain(root, source.path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(chain[-1][0], flags)
        before = os.fstat(descriptor)
        if (
            _path_identity(before) != chain[-1][1]
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != source.size_bytes
        ):
            raise _error("reviewed source identity or size does not match its request")
        observed = bytearray()
        while len(observed) <= source.size_bytes:
            block = os.read(descriptor, min(64 * 1024, source.size_bytes + 1 - len(observed)))
            if not block:
                break
            observed.extend(block)
        after = os.fstat(descriptor)
        if (
            len(observed) != source.size_bytes
            or _path_identity(after) != _path_identity(before)
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise _error("reviewed source changed while it was read")
    except OSError as exc:
        raise _error("reviewed source could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    for path, identity in chain:
        try:
            current = path.lstat()
        except OSError as exc:
            raise _error("source path changed while it was read") from exc
        if _is_link_or_reparse(current) or _path_identity(current) != identity:
            raise _error("source path changed while it was read")
    payload = bytes(observed)
    if "sha256:" + hashlib.sha256(payload).hexdigest() != source.sha256:
        raise _error("reviewed source SHA-256 does not match its request")
    return payload


def _attack_timestamp(value: Any, context: str) -> tuple[str, datetime]:
    result = _bounded_text(value, context, maximum=32)
    if _UTC_TIMESTAMP.fullmatch(result) is None:
        raise _error(f"{context} must be a canonical UTC STIX timestamp")
    try:
        parsed = datetime.fromisoformat(result.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise _error(f"{context} must be a valid UTC STIX timestamp") from exc
    return result, parsed


def _mitre_attack_technique_v1(value: Any) -> SourceTransformation:
    context = "MITRE ATT&CK technique source"
    outer_required = {"type", "id", "spec_version", "objects"}
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _error(f"{context} must be one STIX bundle")
    missing = outer_required - set(value)
    if missing:
        raise _error(f"{context} bundle is missing fields: {', '.join(sorted(missing))}")
    if value["type"] != "bundle" or value["spec_version"] != "2.0":
        raise _error(f"{context} must be a STIX 2.0 bundle")
    bundle_id = _bounded_text(value["id"], f"{context} bundle.id", maximum=64)
    if _BUNDLE_OBJECT_ID.fullmatch(bundle_id) is None:
        raise _error(f"{context} bundle.id must be a canonical STIX bundle ID")
    objects = value["objects"]
    if not isinstance(objects, list) or len(objects) != 1:
        raise _error(f"{context} bundle.objects must contain exactly one object")
    data = objects[0]
    required = {
        "type",
        "id",
        "created",
        "modified",
        "name",
        "revoked",
        "x_mitre_deprecated",
        "x_mitre_version",
        "external_references",
    }
    if not isinstance(data, Mapping) or any(not isinstance(key, str) for key in data):
        raise _error(f"{context} bundle object must be an object")
    missing = required - set(data)
    if missing:
        raise _error(f"{context} object is missing fields: {', '.join(sorted(missing))}")
    if data["type"] != "attack-pattern":
        raise _error(f"{context}.type must be attack-pattern")
    object_id = _bounded_text(data["id"], f"{context}.id", maximum=64)
    if _ATTACK_OBJECT_ID.fullmatch(object_id) is None:
        raise _error(f"{context}.id must be a canonical STIX attack-pattern ID")
    name = _bounded_text(data["name"], f"{context}.name", maximum=256)
    version = _bounded_text(data["x_mitre_version"], f"{context}.x_mitre_version", maximum=32)
    if _ATTACK_VERSION.fullmatch(version) is None:
        raise _error(f"{context}.x_mitre_version must be major.minor")
    created, created_at = _attack_timestamp(data["created"], f"{context}.created")
    modified, modified_at = _attack_timestamp(data["modified"], f"{context}.modified")
    if modified_at < created_at:
        raise _error(f"{context}.modified must not precede created")
    revoked, deprecated = data["revoked"], data["x_mitre_deprecated"]
    if not isinstance(revoked, bool) or not isinstance(deprecated, bool):
        raise _error(f"{context} revoked/deprecated fields must be booleans")
    references = data["external_references"]
    if not isinstance(references, list) or not 1 <= len(references) <= 32:
        raise _error(f"{context}.external_references must be a bounded non-empty list")
    if any(not isinstance(item, Mapping) for item in references):
        raise _error(f"{context}.external_references entries must be objects")
    indexes = [
        index for index, item in enumerate(references) if item.get("source_name") == "mitre-attack"
    ]
    if len(indexes) != 1:
        raise _error(f"{context} must contain exactly one mitre-attack technique reference")
    reference_index = indexes[0]
    reference = references[reference_index]
    reference_fields = {"source_name", "external_id", "url"}
    if reference_fields - set(reference):
        raise _error(f"{context} mitre-attack reference is incomplete")
    technique_id = _bounded_text(
        reference["external_id"], f"{context} reference external_id", maximum=16
    )
    if _ATTACK_TECHNIQUE_ID.fullmatch(technique_id) is None:
        raise _error(f"{context} reference external_id must be a MITRE technique ID")
    reference_url = _https_url(reference["url"], f"{context} reference url")
    expected_path = "/techniques/" + technique_id.replace(".", "/")
    parsed_reference = urlsplit(reference_url)
    if parsed_reference.hostname != "attack.mitre.org" or parsed_reference.path != expected_path:
        raise _error(f"{context} reference URL must exactly match its MITRE technique ID")
    projected = {
        *(f"/{field}" for field in outer_required),
        *(f"/objects/0/{field}" for field in required),
        *(
            f"/objects/0/external_references/{reference_index}/{field}"
            for field in reference_fields
        ),
    }
    all_fields = set(_json_field_paths(value))
    return SourceTransformation(
        metadata={
            "created": created,
            "deprecated": deprecated,
            "modified": modified,
            "name": name,
            "reference_url": reference_url,
            "revoked": revoked,
            "schema_version": "bluefire.mitre-attack-technique-metadata.v1",
            "source_object_id": object_id,
            "technique_id": technique_id,
            "x_mitre_version": version,
        },
        projected_fields=tuple(sorted(projected)),
        discarded_fields=tuple(sorted(all_fields - projected)),
    )


BUILTIN_SOURCE_TRANSFORMERS = SourceTransformerRegistry(
    (
        SourceTransformer(
            "mitre-attack-technique-v1",
            "1.0.0",
            "bluefire.mitre-attack-technique-metadata.v1",
            _mitre_attack_technique_v1,
        ),
    )
)


def _apply_transformer(
    document: Any,
    selection: TransformerSelection,
    registry: SourceTransformerRegistry,
) -> tuple[Mapping[str, Any], bytes, Mapping[str, list[str]]]:
    transformer = registry.select(selection.name, selection.version)
    source_snapshot = canonical_json_bytes(document)

    def invoke() -> SourceTransformation:
        detached = json.loads(source_snapshot)
        return transformer.transform(detached)

    try:
        outcome = invoke()
        repeated = invoke()
    except SourceIntakeError:
        raise
    except Exception as exc:
        raise _error("allowlisted source transformer rejected the source") from exc
    if not isinstance(outcome, SourceTransformation) or not isinstance(
        repeated, SourceTransformation
    ):
        raise _error("allowlisted source transformer returned an invalid outcome")
    if outcome != repeated:
        raise _error("allowlisted source transformer is not deterministic")
    transformed = outcome.metadata
    _validate_json_value(transformed, context="transformed metadata")
    _reject_materialization_fields(transformed, context="transformed metadata")
    if not isinstance(transformed, Mapping):
        raise _error("allowlisted source transformer must return one metadata object")
    projected, discarded = outcome.projected_fields, outcome.discarded_fields
    expected_fields = set(_json_field_paths(document))
    if (
        not isinstance(projected, tuple)
        or not isinstance(discarded, tuple)
        or any(not isinstance(field, str) for field in (*projected, *discarded))
        or projected != tuple(sorted(set(projected)))
        or discarded != tuple(sorted(set(discarded)))
        or set(projected) & set(discarded)
        or set(projected) | set(discarded) != expected_fields
    ):
        raise _error("allowlisted source transformer returned an incomplete field disposition")
    if transformed.get("schema_version") != transformer.output_schema:
        raise _error("allowlisted source transformer returned an unexpected schema")
    try:
        payload = canonical_json_bytes(transformed)
    except (TypeError, ValueError, RecursionError) as exc:
        raise _error("allowlisted source transformer returned invalid JSON") from exc
    if not payload or len(payload) > MAX_OUTPUT_BYTES:
        raise _error("transformed metadata exceeds its output byte limit")
    return (
        json.loads(payload),
        payload,
        {"discarded": list(discarded), "projected_or_validated": list(projected)},
    )


def _unlink_owned(path: Path, identity: tuple[int, int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if not _is_link_or_reparse(current) and _path_identity(current) == identity:
            path.unlink()
    except OSError:
        pass


def _publish_new_file(root: Path, name: str, payload: bytes) -> Path:
    if not payload or len(payload) > MAX_OUTPUT_BYTES:
        raise _error("source intake envelope exceeds its output byte limit")
    target = root / name
    temporary = root / f".{name}.{secrets.token_hex(16)}.tmp"
    try:
        root_before = root.lstat()
        target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise _error("source intake destination is unavailable") from exc
    else:
        raise _error("source intake output already exists")
    if _is_link_or_reparse(root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise _error("source intake destination root is unsafe")
    descriptor: int | None = None
    temporary_identity: tuple[int, int, int] | None = None
    published_identity: tuple[int, int, int] | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        opened = os.fstat(descriptor)
        temporary_identity = _path_identity(opened)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise _error("source intake temporary output is unsafe")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise _error("source intake output write made no progress")
            offset += written
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= len(payload):
            block = os.read(descriptor, min(64 * 1024, len(payload) + 1 - len(observed)))
            if not block:
                break
            observed.extend(block)
        current = os.fstat(descriptor)
        if (
            bytes(observed) != payload
            or _path_identity(current) != temporary_identity
            or current.st_nlink != 1
        ):
            raise _error("source intake temporary output changed during publication")
        current_root = root.lstat()
        if _is_link_or_reparse(current_root) or _path_identity(current_root) != _path_identity(
            root_before
        ):
            raise _error("source intake destination root changed during publication")
        os.link(temporary, target, follow_symlinks=False)
        published_identity = temporary_identity
        published = target.lstat()
        if _is_link_or_reparse(published) or _path_identity(published) != temporary_identity:
            raise _error("source intake published output has an unexpected identity")
        published_identity = _path_identity(published)
        os.close(descriptor)
        descriptor = None
        temporary.unlink()
        temporary_identity = None
        verification = os.open(
            target, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            final = os.fstat(verification)
            final_payload = bytearray()
            while len(final_payload) <= len(payload):
                block = os.read(verification, min(64 * 1024, len(payload) + 1 - len(final_payload)))
                if not block:
                    break
                final_payload.extend(block)
        finally:
            os.close(verification)
        if (
            _path_identity(final) != published_identity
            or final.st_nlink != 1
            or bytes(final_payload) != payload
        ):
            raise _error("source intake published output failed final verification")
    except SourceIntakeError:
        _unlink_owned(target, published_identity)
        raise
    except OSError as exc:
        _unlink_owned(target, published_identity)
        raise _error("source intake output could not be atomically published") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        _unlink_owned(temporary, temporary_identity)
    try:
        directory_descriptor = os.open(root, os.O_RDONLY)
    except OSError:
        directory_descriptor = None
    if directory_descriptor is not None:
        try:
            os.fsync(directory_descriptor)
        except OSError:
            pass
        finally:
            os.close(directory_descriptor)
    return target


def perform_source_intake(
    source_root: Path,
    destination_root: Path,
    request: SourceIntakeRequest | Mapping[str, Any],
    *,
    registry: SourceTransformerRegistry = BUILTIN_SOURCE_TRANSFORMERS,
) -> SourceIntakeResult:
    """Verify, transform, and atomically persist one reviewed metadata source."""

    request_value = asdict(request) if isinstance(request, SourceIntakeRequest) else request
    parsed = SourceIntakeRequest.from_mapping(request_value)
    source_directory = _existing_safe_root(source_root, context="source root")
    destination_directory = _existing_safe_root(
        destination_root, context="source intake destination root"
    )
    source_payload = _read_verified_source(source_directory, parsed.source)
    source_document, canonical_source = _parse_source_json(source_payload)
    transformed, transformed_payload, field_disposition = _apply_transformer(
        source_document, parsed.transformer, registry
    )
    output_sha256 = "sha256:" + hashlib.sha256(transformed_payload).hexdigest()
    canonical_input_sha256 = "sha256:" + hashlib.sha256(canonical_source).hexdigest()
    record: dict[str, Any] = {
        "intake_id": parsed.intake_id,
        "output": transformed,
        "provenance": asdict(parsed.provenance),
        "review": asdict(parsed.review),
        "schema_version": "bluefire.source-intake-record.v1",
        "source": asdict(parsed.source),
        "transformation_history": [
            {
                "canonical_input_sha256": canonical_input_sha256,
                "canonical_input_size_bytes": len(canonical_source),
                "input_sha256": parsed.source.sha256,
                "input_size_bytes": parsed.source.size_bytes,
                "operation": "declarative_metadata_projection",
                "output_sha256": output_sha256,
                "output_size_bytes": len(transformed_payload),
                "sequence": 1,
                "source_field_disposition": field_disposition,
                "transformer": asdict(parsed.transformer),
            }
        ],
        "transformer": asdict(parsed.transformer),
    }
    record_sha256 = content_hash(record)
    envelope = {
        "record": record,
        "record_sha256": record_sha256,
        "schema_version": "bluefire.source-intake-envelope.v1",
    }
    envelope_payload = canonical_json_bytes(envelope)
    output_path = _publish_new_file(
        destination_directory, f"{parsed.intake_id}.json", envelope_payload
    )
    return SourceIntakeResult(
        output_path, record_sha256, output_sha256, json.loads(envelope_payload)
    )
