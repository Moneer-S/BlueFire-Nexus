"""Independent package and repository runner authority for Gate 11."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping, Sequence

from .config import RunnerProfile, load_config
from .cross_platform_committed_linux_artifact import (
    CommittedLinuxArtifactError,
    load_committed_linux_artifact,
)
from .cross_platform_readiness import _macos_process_adapter_is_in_process
from .cross_platform_recovery_report_validation import validate_recovery_witness_binding
from .registry import load_builtin_registry
from .runner_bootstrap import (
    RunnerBootstrapError,
    current_platform,
    parse_runner_manifest,
    wheel_platform_tag,
)
from .runner_inventory import BUILTIN_RUNNER_ACTION_VERSIONS
from .util import canonical_json_bytes, content_hash

_WHEEL = re.compile(
    r"^bluefire_nexus-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?)-"
    r"py3-none-win_amd64\.whl$"
)
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_TASK = re.compile(r"^execute-[0-9a-f]{64}$")
_PRIVATE_PATH = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")


class CrossPlatformArtifactValidationError(ValueError):
    """Raised when fixed Gate 11 runner bytes are invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CrossPlatformArtifactValidationError(message)


def _fields(value: str) -> set[str]:
    return set(value.split())


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CrossPlatformArtifactValidationError(f"{label} fields are invalid")
    return value


def _timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").tzinfo == timezone.utc
    except ValueError:
        return False


def _path_free(value: Any) -> bool:
    if isinstance(value, Mapping):
        return all(_path_free(key) and _path_free(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return all(_path_free(item) for item in value)
    return not isinstance(value, str) or (
        _PRIVATE_PATH.search(value) is None and "file://" not in value.lower()
    )


def _file_identity(row: Any) -> tuple[Any, ...]:
    return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_nlink


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "a runner manifest contains duplicate keys")
        result[key] = value
    return result


def _json(payload: bytes) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CrossPlatformArtifactValidationError(
            "the runner manifest is not strict JSON"
        ) from exc


def _is_link(details: Any) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE
    )


def _safe_directory(path: Path, label: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise CrossPlatformArtifactValidationError(f"{label} is unavailable") from exc
    _require(stat.S_ISDIR(details.st_mode) and not _is_link(details), f"{label} is unsafe")


def _safe_file(path: Path, maximum: int, label: str) -> tuple[int, str, bytes]:
    try:
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and not _is_link(before)
            and before.st_nlink == 1
            and 1 <= before.st_size <= maximum,
            f"{label} is not a safe bounded file",
        )
        payload = path.read_bytes()
        after = path.lstat()
    except CrossPlatformArtifactValidationError:
        raise
    except OSError as exc:
        raise CrossPlatformArtifactValidationError(f"{label} is unavailable") from exc
    _require(
        _file_identity(before) == _file_identity(after) and len(payload) == before.st_size,
        f"{label} changed",
    )
    return len(payload), "sha256:" + hashlib.sha256(payload).hexdigest(), payload


def _safe_member(name: str) -> bool:
    normalized = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(normalized)
    return bool(
        normalized
        and "\x00" not in name
        and "\\" not in name
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _record_rows(payload: bytes) -> Mapping[str, tuple[str, str]]:
    _require(0 < len(payload) <= 4 * 1024 * 1024, "the wheel RECORD is unbounded")
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error) as exc:
        raise CrossPlatformArtifactValidationError("the wheel RECORD is invalid") from exc
    result: dict[str, tuple[str, str]] = {}
    for row in rows:
        _require(
            len(row) == 3 and _safe_member(row[0]) and row[0] not in result,
            "the wheel RECORD has an invalid or duplicate row",
        )
        result[row[0]] = (row[1], row[2])
    return result


def _verify_record(name: str, payload: bytes, row: tuple[str, str]) -> None:
    encoded = row[0].removeprefix("sha256=")
    _require(
        row[1] == str(len(payload))
        and row[0].startswith("sha256=")
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is not None,
        f"wheel RECORD binding is invalid for {name}",
    )
    try:
        observed = base64.urlsafe_b64decode(encoded + "=")
    except ValueError as exc:
        raise CrossPlatformArtifactValidationError("a wheel RECORD digest is invalid") from exc
    _require(observed == hashlib.sha256(payload).digest(), f"wheel RECORD mismatch for {name}")


def _architecture(payload: bytes, platform: str) -> str:
    if platform == "windows":
        _require(len(payload) >= 64 and payload[:2] == b"MZ", "the wheel runner is not PE")
        offset = int.from_bytes(payload[0x3C:0x40], "little")
        _require(
            offset + 6 <= len(payload) and payload[offset : offset + 4] == b"PE\0\0",
            "the wheel runner has an invalid PE header",
        )
        machine = int.from_bytes(payload[offset + 4 : offset + 6], "little")
        return {0x8664: "x86_64", 0xAA64: "aarch64"}.get(machine, "unknown")
    _require(
        len(payload) >= 20 and payload[:4] == b"\x7fELF" and payload[4] == 2,
        "the repository runner is not ELF64",
    )
    order: Literal["little", "big"]
    if payload[5] == 1:
        order = "little"
    elif payload[5] == 2:
        order = "big"
    else:
        raise CrossPlatformArtifactValidationError(
            "the repository runner has an invalid ELF header"
        )
    return {62: "x86_64", 183: "aarch64"}.get(int.from_bytes(payload[18:20], order), "unknown")


def validate_windows_wheel(evidence_dir: Path) -> Mapping[str, Any]:
    package = evidence_dir / "package"
    _safe_directory(package, "Gate 11 package directory")
    try:
        entries = sorted(package.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CrossPlatformArtifactValidationError(
            "Gate 11 package inventory is unavailable"
        ) from exc
    match = _WHEEL.fullmatch(entries[0].name) if len(entries) == 1 else None
    if match is None:
        raise CrossPlatformArtifactValidationError(
            "Gate 11 package directory must contain one Windows wheel"
        )
    wheel = entries[0]
    version = str(match.group("version"))
    package_root = f"bluefire_nexus-{version}.data/purelib/bluefire/native"
    wheel_size, wheel_digest, wheel_bytes = _safe_file(
        wheel, 256 * 1024 * 1024, "built Windows wheel"
    )
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes), "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            _require(
                0 < len(infos) <= 8192
                and len(names) == len(set(names))
                and all(_safe_member(name) for name in names),
                "the built wheel member inventory is unsafe",
            )
            files: list[str] = []
            total = 0
            for info in infos:
                unix_mode = int(info.external_attr) >> 16
                _require(
                    not (info.flag_bits & 1)
                    and not stat.S_ISLNK(unix_mode)
                    and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    and 0 <= info.file_size <= 128 * 1024 * 1024
                    and 0 <= info.compress_size <= 256 * 1024 * 1024
                    and (info.file_size == 0 or info.compress_size > 0)
                    and info.file_size <= 1000 * max(1, info.compress_size),
                    "the built wheel contains an unsafe member",
                )
                total += info.file_size
                if not info.is_dir():
                    files.append(info.filename)
            _require(total <= 256 * 1024 * 1024, "the built wheel expands beyond its bound")
            manifest_member = f"{package_root}/runner-manifest.json"
            binary_member = f"{package_root}/bluefire-runner.exe"
            runner_members = [
                name
                for name in files
                if name.endswith("/bluefire/native/bluefire-runner")
                or name.endswith("/bluefire/native/bluefire-runner.exe")
            ]
            records = [name for name in files if name.endswith(".dist-info/RECORD")]
            wheel_metadata = [name for name in files if name.endswith(".dist-info/WHEEL")]
            package_metadata = [name for name in files if name.endswith(".dist-info/METADATA")]
            _require(
                manifest_member in files
                and runner_members == [binary_member]
                and len(records) == len(wheel_metadata) == len(package_metadata) == 1,
                "the wheel lacks one exact native resource, RECORD, WHEEL, or METADATA",
            )
            payloads = {name: archive.read(name) for name in files}
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise CrossPlatformArtifactValidationError("the built Windows wheel is invalid") from exc
    dist_info = f"bluefire_nexus-{version}.dist-info"
    record_member = records[0]
    _require(
        record_member == f"{dist_info}/RECORD"
        and wheel_metadata[0] == f"{dist_info}/WHEEL"
        and package_metadata[0] == f"{dist_info}/METADATA",
        "wheel filename and dist-info identity do not match",
    )
    rows = _record_rows(payloads[record_member])
    _require(set(rows) == set(files), "the wheel RECORD inventory is incomplete")
    for name, payload in payloads.items():
        if name == record_member:
            _require(rows[name] == ("", ""), "the wheel RECORD self-row is invalid")
        else:
            _verify_record(name, payload, rows[name])
    try:
        wheel_lines = payloads[wheel_metadata[0]].decode("utf-8").splitlines()
        metadata_lines = payloads[package_metadata[0]].decode("utf-8").splitlines()
        manifest = parse_runner_manifest(
            _json(payloads[manifest_member]), platform_name="windows", architecture="x86_64"
        )
    except (UnicodeError, RunnerBootstrapError) as exc:
        raise CrossPlatformArtifactValidationError("the wheel contract is incompatible") from exc
    binary = payloads[binary_member]
    _require(
        wheel_lines.count("Tag: py3-none-win_amd64") == 1
        and wheel_lines.count("Root-Is-Purelib: false") == 1
        and metadata_lines.count("Name: bluefire-nexus") == 1
        and metadata_lines.count(f"Version: {version}") == 1
        and manifest.product_version == version
        and _architecture(binary, "windows") == "x86_64"
        and len(binary) == manifest.size
        and hashlib.sha256(binary).hexdigest() == manifest.sha256,
        "the wheel identity or native bytes do not match the package contract",
    )
    return {
        "source": "built-wheel-member",
        "runner_id": manifest.runner_id,
        "runner_version": manifest.runner_version,
        "platform": "windows",
        "architecture": "x86_64",
        "wheel_file": wheel.name,
        "wheel_sha256": wheel_digest,
        "wheel_size": wheel_size,
        "manifest_member": manifest_member,
        "manifest_sha256": "sha256:" + hashlib.sha256(payloads[manifest_member]).hexdigest(),
        "manifest_size": len(payloads[manifest_member]),
        "binary_member": binary_member,
        "binary_sha256": "sha256:" + hashlib.sha256(binary).hexdigest(),
        "binary_size": len(binary),
        "record_member": record_member,
        "record_sha256": "sha256:" + hashlib.sha256(payloads[record_member]).hexdigest(),
        "record_bound": True,
    }


def validate_linux_repository_runner(
    repository: Path, *, expected_binding: Mapping[str, str]
) -> Mapping[str, Any]:
    try:
        artifact = load_committed_linux_artifact(
            repository,
            repository_commit=str(expected_binding.get("repository_commit", "")),
            repository_tree=str(expected_binding.get("repository_tree", "")),
        )
    except (OSError, CommittedLinuxArtifactError) as exc:
        raise CrossPlatformArtifactValidationError(
            "the commit-bound Linux runner is incompatible"
        ) from exc
    return dict(artifact.record)


def linux_wheelhouse_unavailable(repository: Path) -> bool:
    _, _, payload = _safe_file(
        repository / "bluefire" / "data" / "gate11_linux_wheelhouse.json",
        64 * 1024,
        "Gate 11 Linux wheelhouse lock",
    )
    value = _json(payload)
    _require(
        isinstance(value, Mapping)
        and set(value) == {"schema_version", "platform", "architecture", "python", "wheels"},
        "the Gate 11 Linux wheelhouse lock fields are invalid",
    )
    python = value.get("python")
    wheels = value.get("wheels")
    _require(
        value.get("schema_version") == "bluefire.linux-wheelhouse.v1"
        and value.get("platform") == "linux"
        and value.get("architecture") == "x86_64"
        and python == {"implementation": "cpython", "major": 3, "minor": 12}
        and isinstance(wheels, list)
        and len(wheels) == 5,
        "the Gate 11 Linux wheelhouse lock identity is invalid",
    )
    expected: dict[str, Mapping[str, Any]] = {}
    for row in wheels:
        _require(
            isinstance(row, Mapping)
            and set(row) == {"distribution", "version", "filename", "size", "sha256"}
            and isinstance(row.get("distribution"), str)
            and isinstance(row.get("version"), str)
            and isinstance(row.get("filename"), str)
            and Path(str(row["filename"])).name == row["filename"]
            and type(row.get("size")) is int
            and 1 <= int(row["size"]) <= 128 * 1024 * 1024
            and _RAW_SHA256.fullmatch(str(row.get("sha256"))) is not None,
            "the Gate 11 Linux wheelhouse lock contains an invalid row",
        )
        expected[str(row["filename"])] = row
    _require(
        [row["distribution"] for row in wheels]
        == ["cffi", "cryptography", "pycparser", "PyNaCl", "PyYAML"]
        and len(expected) == len(wheels),
        "the Gate 11 Linux wheelhouse lock inventory is invalid",
    )
    configured = os.environ.get("BLUEFIRE_GATE11_LINUX_WHEELHOUSE", "").strip()
    if not configured:
        return True
    root = Path(configured)
    if not root.is_absolute():
        return True
    try:
        _safe_directory(root, "configured Gate 11 Linux wheelhouse")
        entries = {item.name: item for item in root.iterdir()}
        if set(entries) != set(expected):
            return True
        for name, row in expected.items():
            size, digest, _ = _safe_file(
                entries[name], 128 * 1024 * 1024, "configured Gate 11 Linux wheel"
            )
            if size != row["size"] or digest != "sha256:" + str(row["sha256"]):
                return True
    except (OSError, CrossPlatformArtifactValidationError):
        return True
    return False


def validate_run_readiness(
    value: Any, profile: RunnerProfile, platform: str, runner: Mapping[str, Any]
) -> str:
    row = _exact(
        value,
        _fields(
            "schema_version profile_id runner_identity runner_identity_digest inventory_digest "
            "effective_inventory_digest catalog_authority platform enabled_actions sandbox freshness recovery_identity"
        ),
        "run readiness",
    )
    identity = _exact(
        row.get("runner_identity"),
        _fields("transport runner_id runner_version platform runner_binary_digest"),
        "run runner identity",
    )
    recovery = _exact(
        row.get("recovery_identity"),
        _fields(
            "schema_version transport inventory_status cleanup_action_digest receipt_protocol runner_binary_digest"
        ),
        "run recovery identity",
    )
    sandbox = _exact(
        row.get("sandbox"),
        _fields("state root_digest execution_parent checked_without_creation"),
        "run sandbox readiness",
    )
    freshness = _exact(
        row.get("freshness"), _fields("observed_at max_age_seconds"), "run freshness"
    )
    catalog = _exact(
        row.get("catalog_authority"),
        _fields(
            "schema_version generation catalog_digest built_in_catalog_digest packages action_bindings authority_digest"
        ),
        "run catalog authority",
    )
    catalog_body = dict(catalog)
    authority_digest = catalog_body.pop("authority_digest")
    registry = load_builtin_registry()
    built_in_digest = content_hash(
        {
            "schema_version": "bluefire.built-in-catalog-snapshot.v1",
            "behaviors": [item.to_dict() for item in registry.behaviors],
            "actions": [item.to_dict() for item in registry.actions],
        }
    )
    actions = row.get("enabled_actions")
    if not isinstance(actions, list):
        raise CrossPlatformArtifactValidationError("run readiness actions are invalid")
    action_rows = [
        _exact(
            item,
            _fields("action_id action_version readiness contract_digest"),
            "run readiness action",
        )
        for item in actions
    ]
    cleanup = next(
        (item for item in action_rows if item.get("action_id") == "sandbox.cleanup.v1"), None
    )
    _require(
        row.get("schema_version") == "bluefire.execute-readiness.v1"
        and row.get("profile_id") == profile.id
        and row.get("platform") == platform
        and identity.get("runner_id") == runner.get("runner_id")
        and identity.get("runner_version") == runner.get("runner_version")
        and identity.get("platform") == platform
        and identity.get("runner_binary_digest") == runner.get("binary_sha256")
        and isinstance(identity.get("transport"), str)
        and bool(identity["transport"])
        and row.get("runner_identity_digest") == content_hash(identity)
        and all(
            _SHA256.fullmatch(str(row.get(key))) is not None
            for key in ("inventory_digest", "effective_inventory_digest")
        )
        and [item.get("action_id") for item in action_rows] == sorted(profile.enabled_actions)
        and all(
            item.get("readiness") == "ready"
            and BUILTIN_RUNNER_ACTION_VERSIONS.get(str(item.get("action_id")))
            == item.get("action_version")
            and _SHA256.fullmatch(str(item.get("contract_digest"))) is not None
            for item in action_rows
        )
        and catalog.get("schema_version") == "bluefire.action-catalog-authority.v1"
        and catalog.get("generation") == 0
        and catalog.get("packages") == []
        and catalog.get("action_bindings") == []
        and catalog.get("catalog_digest")
        == content_hash(
            {"schema_version": "bluefire.active-action-package-catalog.v1", "packages": []}
        )
        and catalog.get("built_in_catalog_digest") == built_in_digest
        and authority_digest == content_hash(catalog_body)
        and row.get("effective_inventory_digest")
        == content_hash(
            {
                "schema_version": "bluefire.effective-runner-inventory.v1",
                "native_inventory_digest": row.get("inventory_digest"),
                "catalog_authority": dict(catalog),
                "actions": [dict(item) for item in action_rows],
            }
        )
        and freshness == {"observed_at": freshness.get("observed_at"), "max_age_seconds": 15 * 60}
        and _timestamp(freshness.get("observed_at"))
        and recovery.get("schema_version") == "bluefire.runner-recovery-identity.v1"
        and recovery.get("transport") == identity.get("transport")
        and recovery.get("inventory_status") == "cleanup_available"
        and recovery.get("receipt_protocol") == "bluefire.runner-receipt-wal.v2"
        and recovery.get("runner_binary_digest") == runner.get("binary_sha256")
        and cleanup is not None
        and recovery.get("cleanup_action_digest") == content_hash(cleanup)
        and sandbox.get("state") == "ready"
        and sandbox.get("execution_parent") == "ready"
        and sandbox.get("checked_without_creation") is True
        and _SHA256.fullmatch(str(sandbox.get("root_digest"))) is not None,
        "run readiness does not bind the independently verified runner",
    )
    return str(row["inventory_digest"])


def _runner_result(value: Any, label: str) -> Mapping[str, Any]:
    row = _exact(
        value,
        _fields(
            "schema_version request_id run_id step_id behavior_id action_id status runner_id "
            "runner_profile_id platform request_hash policy_digest started_at finished_at output "
            "stdout stderr receipt_ids cleanup evidence error limitations"
        ),
        label,
    )
    for name in ("stdout", "stderr"):
        stream = _exact(row.get(name), _fields("text total_bytes truncated"), f"{label} {name}")
        _require(
            isinstance(stream.get("text"), str)
            and type(stream.get("total_bytes")) is int
            and len(stream["text"].encode("utf-8")) <= stream["total_bytes"] <= 4 * 1024 * 1024
            and isinstance(stream.get("truncated"), bool),
            f"{label} {name} is invalid",
        )
    _require(
        row.get("schema_version") == "bluefire.runner-result.v1"
        and row.get("status") == "success"
        and row.get("platform") == "windows"
        and row.get("runner_id") == "bluefire-rust-runner.v1"
        and row.get("runner_profile_id") == "sandbox-endpoint-deep-lab.v1"
        and _SHA256.fullmatch(str(row.get("request_hash"))) is not None
        and _SHA256.fullmatch(str(row.get("policy_digest"))) is not None
        and _timestamp(row.get("started_at"))
        and _timestamp(row.get("finished_at"))
        and isinstance(row.get("output"), Mapping)
        and isinstance(row.get("receipt_ids"), list)
        and isinstance(row.get("evidence"), list)
        and row.get("error") is None
        and isinstance(row.get("limitations"), list),
        f"{label} is invalid",
    )
    return row


def _receipt_body(
    value: Any, receipt_id: str, request_hash: str, output: Mapping[str, Any]
) -> Mapping[str, Any]:
    row = _exact(
        value,
        _fields(
            "schema_version receipt_id request_hash action_id runner_profile_id workspace_id created_at paths"
        ),
        "recovery receipt body",
    )
    identity = {key: item for key, item in row.items() if key != "receipt_id"}
    file_row = {
        "relative_path": "gate11-recovery/transport-recovery.jsonl",
        "kind": "file",
        "sha256": output.get("sha256"),
        "size": output.get("size"),
    }
    directory_row = {
        "relative_path": "gate11-recovery",
        "kind": "directory",
        "sha256": None,
        "size": None,
    }
    _require(
        row.get("schema_version") == "bluefire.receipt/v1"
        and row.get("receipt_id")
        == receipt_id
        == hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        and row.get("request_hash") == request_hash
        and row.get("action_id") == "sandbox.fixture.create.v1"
        and row.get("runner_profile_id") == "sandbox-endpoint-deep-lab.v1"
        and _RAW_SHA256.fullmatch(str(row.get("workspace_id"))) is not None
        and _timestamp(row.get("created_at"))
        and row.get("paths") == [file_row, directory_row],
        "recovery receipt is not bound to the effect",
    )
    return row


def _transport_identity(value: Any) -> Mapping[str, Any]:
    row = _exact(
        value,
        _fields(
            "schema_version runner_id client_id transport tls server_fingerprint client_fingerprint "
            "authenticated_peer_fingerprint enrollment_generation runner_binary_digest inventory_digest"
        ),
        "recovery transport identity",
    )
    _require(
        row.get("schema_version") == "bluefire.runner-transport-identity.v1"
        and row.get("runner_id") == "bluefire-rust-runner.v1"
        and isinstance(row.get("client_id"), str)
        and bool(row["client_id"])
        and row.get("transport") == "mutual-tls-loopback"
        and row.get("tls") == "TLSv1.3"
        and row.get("client_fingerprint") == row.get("authenticated_peer_fingerprint")
        and all(
            _SHA256.fullmatch(str(row.get(name))) is not None
            for name in (
                "server_fingerprint",
                "client_fingerprint",
                "enrollment_generation",
                "runner_binary_digest",
                "inventory_digest",
            )
        ),
        "recovery transport identity is invalid",
    )
    return row


def validate_transport_recovery_report(value: Any) -> None:
    row = _exact(
        value,
        _fields("schema_version passed proof_kind platform transport recovery witness_validation"),
        "recovery report",
    )
    transport = _exact(
        row.get("transport"),
        _fields(
            "tls authentication multiprocess host_interrupted host_restarted client_process_id"
        ),
        "recovery boundary",
    )
    recovery = _exact(
        row.get("recovery"),
        _fields(
            "task_id request_hash result_before result_after result_digest_before result_digest_after "
            "result_identical receipt_id receipt_body_before receipt_body_after receipt_body_digest_before "
            "receipt_body_digest_after receipt_commit_body_before receipt_commit_body_after receipt_commit_digest_before "
            "receipt_commit_digest_after receipt_ids_before receipt_ids_after receipt_commit_ids_before "
            "receipt_commit_ids_after effect_relative_path effect_digest_before effect_digest_after effect_size_before "
            "effect_size_after effect_count_before effect_count_after effect_not_duplicated ledger_generation_before "
            "ledger_generation_after ledger_generation_stable host_identity_before host_identity_after "
            "host_identity_changed transport_identity_before transport_identity_after transport_identity_stable "
            "interruption cleanup_result cleanup_result_digest receipt_ids_after_cleanup receipt_commit_ids_after_cleanup "
            "effect_exists_after_cleanup effect_directory_exists_after_cleanup cleanup_reconciled"
        ),
        "recovery proof",
    )
    _require(
        row.get("schema_version") == "bluefire.cross-platform-transport-recovery.v1"
        and row.get("passed") is True
        and row.get("proof_kind") == "dynamic"
        and row.get("platform") == "windows"
        and transport
        == {
            "tls": "TLSv1.3",
            "authentication": "mutual-tls-plus-enrollment-hmac",
            "multiprocess": True,
            "host_interrupted": True,
            "host_restarted": True,
            "client_process_id": transport.get("client_process_id"),
        }
        and type(transport.get("client_process_id")) is int
        and transport["client_process_id"] > 0
        and _path_free(row),
        "recovery report boundary is invalid",
    )
    before = _runner_result(recovery.get("result_before"), "recovery result before")
    after = _runner_result(recovery.get("result_after"), "recovery result after")
    output = _exact(
        before.get("output"),
        _fields("artifact sha256 size template record_count format"),
        "recovery effect output",
    )
    receipt_id = recovery.get("receipt_id")
    request_hash = recovery.get("request_hash")
    _require(
        recovery.get("task_id") == "execute-" + str(request_hash).removeprefix("sha256:")
        and _TASK.fullmatch(str(recovery.get("task_id"))) is not None
        and _SHA256.fullmatch(str(request_hash)) is not None
        and before.get("action_id") == "sandbox.fixture.create.v1"
        and output.get("artifact") == "gate11-recovery/transport-recovery.jsonl"
        and _RAW_SHA256.fullmatch(str(output.get("sha256"))) is not None
        and type(output.get("size")) is int
        and output["size"] > 0
        and output.get("template") == "telemetry-seed"
        and output.get("record_count") == 1
        and output.get("format") == "jsonl"
        and _RAW_SHA256.fullmatch(str(receipt_id)) is not None
        and before.get("receipt_ids") == [receipt_id]
        and canonical_json_bytes(before) == canonical_json_bytes(after)
        and recovery.get("result_digest_before") == content_hash(before)
        and recovery.get("result_digest_after") == content_hash(after)
        and recovery.get("result_identical") is True,
        "recovered result is not the exact committed result",
    )
    receipt_before = _receipt_body(
        recovery.get("receipt_body_before"),
        str(receipt_id),
        str(before.get("request_hash")),
        output,
    )
    receipt_after = _receipt_body(
        recovery.get("receipt_body_after"), str(receipt_id), str(before.get("request_hash")), output
    )
    commits = []
    for name in ("receipt_commit_body_before", "receipt_commit_body_after"):
        commit = _exact(
            recovery.get(name),
            _fields("schema_version receipt_id runner_profile_id workspace_id committed_at"),
            name,
        )
        _require(
            commit.get("schema_version") == "bluefire.receipt-commit/v1"
            and commit.get("receipt_id") == receipt_id
            and commit.get("runner_profile_id") == receipt_before.get("runner_profile_id")
            and commit.get("workspace_id") == receipt_before.get("workspace_id")
            and _timestamp(commit.get("committed_at")),
            "recovery receipt commit is invalid",
        )
        commits.append(commit)
    _require(
        receipt_before == receipt_after
        and recovery.get("receipt_body_digest_before") == content_hash(receipt_before)
        and recovery.get("receipt_body_digest_after") == content_hash(receipt_after)
        and commits[0] == commits[1]
        and recovery.get("receipt_commit_digest_before") == content_hash(commits[0])
        and recovery.get("receipt_commit_digest_after") == content_hash(commits[1])
        and recovery.get("receipt_ids_before") == recovery.get("receipt_ids_after") == [receipt_id]
        and recovery.get("receipt_commit_ids_before")
        == recovery.get("receipt_commit_ids_after")
        == [receipt_id]
        and recovery.get("effect_relative_path") == output.get("artifact")
        and recovery.get("effect_digest_before")
        == recovery.get("effect_digest_after")
        == "sha256:" + str(output["sha256"])
        and recovery.get("effect_size_before")
        == recovery.get("effect_size_after")
        == output.get("size")
        and recovery.get("effect_count_before") == recovery.get("effect_count_after") == 1
        and recovery.get("effect_not_duplicated") is True
        and recovery.get("ledger_generation_before") == recovery.get("ledger_generation_after")
        and _SHA256.fullmatch(str(recovery.get("ledger_generation_before"))) is not None
        and recovery.get("ledger_generation_stable") is True,
        "recovery durable receipt or effect binding is invalid",
    )
    transport_before = _transport_identity(recovery.get("transport_identity_before"))
    transport_after = _transport_identity(recovery.get("transport_identity_after"))
    hosts = []
    host_fields = _fields(
        "process_id launch_id server_instance_id started_at_ns runner_id client_id server_fingerprint runner_binary_digest"
    )
    for name, identity in (("before", transport_before), ("after", transport_after)):
        host = _exact(recovery.get(f"host_identity_{name}"), host_fields, f"recovery host {name}")
        _require(
            type(host.get("process_id")) is int
            and host["process_id"] > 0
            and type(host.get("started_at_ns")) is int
            and host["started_at_ns"] > 0
            and all(
                isinstance(host.get(key), str) and bool(host[key])
                for key in ("launch_id", "server_instance_id")
            )
            and all(
                host.get(key) == identity.get(key)
                for key in ("runner_id", "client_id", "server_fingerprint", "runner_binary_digest")
            ),
            f"recovery host {name} is invalid",
        )
        hosts.append(host)
    interruption = _exact(
        recovery.get("interruption"),
        _fields(
            "profile_id launch_id process_id server_instance_id identity_bound process_handle_terminated process_absent"
        ),
        "recovery interruption",
    )
    cleanup_result = _runner_result(recovery.get("cleanup_result"), "recovery cleanup result")
    cleanup = _exact(
        cleanup_result.get("cleanup"),
        _fields(
            "requested_receipts removed_paths already_absent_receipts retained_paths errors verification_performed verified_removed_paths verified_absent_paths verified_receipts"
        ),
        "recovery cleanup",
    )
    _require(
        transport_before == transport_after
        and recovery.get("transport_identity_stable") is True
        and transport.get("client_process_id")
        not in {hosts[0]["process_id"], hosts[1]["process_id"]}
        and all(
            hosts[0][key] != hosts[1][key]
            for key in ("process_id", "launch_id", "server_instance_id", "started_at_ns")
        )
        and recovery.get("host_identity_changed") is True
        and interruption
        == {
            "profile_id": "sandbox-endpoint-deep-lab.v1",
            "launch_id": hosts[0]["launch_id"],
            "process_id": hosts[0]["process_id"],
            "server_instance_id": hosts[0]["server_instance_id"],
            "identity_bound": True,
            "process_handle_terminated": True,
            "process_absent": True,
        }
        and cleanup_result.get("action_id") == "sandbox.cleanup.v1"
        and recovery.get("cleanup_result_digest") == content_hash(cleanup_result)
        and cleanup
        == {
            "requested_receipts": 1,
            "removed_paths": ["gate11-recovery/transport-recovery.jsonl", "gate11-recovery"],
            "already_absent_receipts": [],
            "retained_paths": [],
            "errors": [],
            "verification_performed": True,
            "verified_removed_paths": 2,
            "verified_absent_paths": 0,
            "verified_receipts": 1,
        }
        and recovery.get("receipt_ids_after_cleanup") == []
        and recovery.get("receipt_commit_ids_after_cleanup") == []
        and recovery.get("effect_exists_after_cleanup") is False
        and recovery.get("effect_directory_exists_after_cleanup") is False
        and recovery.get("cleanup_reconciled") is True,
        "recovery lifecycle or exact cleanup binding is invalid",
    )
    try:
        validate_recovery_witness_binding(row["witness_validation"], recovery, transport)
    except (KeyError, TypeError, ValueError) as exc:
        raise CrossPlatformArtifactValidationError("recovery live witness is invalid") from exc


def validate_gate_verification_document(
    value: Any,
    *,
    expected_checks: Mapping[str, bool],
    expected_run_ids: Sequence[str],
    expected_suite_tests: Sequence[str],
    report_paths: Sequence[str],
) -> None:
    row = _exact(
        value,
        _fields("schema_version passed helper suite checks run_ids reports proof_kinds"),
        "Gate 11 verification report",
    )
    helper = _exact(
        row.get("helper"),
        _fields(
            "schema_version status reports run_count blocking_check exit_code command protocol_valid"
        ),
        "Gate 11 helper verification",
    )
    suite = _exact(
        row.get("suite"),
        _fields(
            "schema_version suite_id command exit_code passed tests passed_tests failed_tests skipped_tests"
        ),
        "Gate 11 pytest verification",
    )
    expected_tests = list(expected_suite_tests)
    _require(
        row.get("schema_version") == "bluefire.cross-platform-gate-verification.v1"
        and row.get("passed") is True
        and helper.get("schema_version") == "bluefire.cross-platform-helper.v1"
        and helper.get("status") == "passed"
        and helper.get("reports") == list(report_paths)
        and helper.get("run_count") == 2
        and helper.get("blocking_check") is None
        and helper.get("exit_code") == 0
        and helper.get("command")
        == ["{python}", "tools/run_cross_platform_gate_journey.py", "{fixed-arguments}"]
        and helper.get("protocol_valid") is True
        and suite.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and suite.get("suite_id") == "cross-platform-contracts"
        and suite.get("exit_code") == 0
        and suite.get("passed") is True
        and suite.get("passed_tests") == expected_tests
        and suite.get("tests") == len(expected_tests)
        and suite.get("failed_tests") == []
        and suite.get("skipped_tests") == []
        and row.get("checks") == dict(expected_checks)
        and row.get("run_ids") == list(expected_run_ids)
        and row.get("reports") == list(report_paths)
        and row.get("proof_kinds") == ["dynamic", "structural"],
        "Gate 11 verification report is inconsistent",
    )


def validate_macos_structural_contract(repository: Path, value: Any) -> None:
    _require(
        isinstance(value, Mapping)
        and set(value)
        == {
            "schema_version",
            "passed",
            "proof_kind",
            "platform",
            "dynamic_proof",
            "availability",
            "contract",
        },
        "the macOS report fields are invalid",
    )
    availability = value.get("availability")
    contract = value.get("contract")
    expected_contract = {
        "platform_enum": True,
        "profile_metadata": True,
        "package_metadata": True,
        "rust_target_cfg": True,
        "fixed_process_adapter": True,
        "x86_64_wheel_tag": "macosx_11_0_x86_64",
        "aarch64_wheel_tag": "macosx_11_0_arm64",
    }
    _require(
        value.get("schema_version") == "bluefire.cross-platform-macos-contract.v1"
        and value.get("passed") is True
        and value.get("proof_kind") == "structural"
        and value.get("platform") == "macos"
        and value.get("dynamic_proof") is False
        and availability == {"state": "structural", "code": "macos_host_unavailable"}
        and contract == expected_contract,
        "macOS evidence is not strictly structural",
    )
    try:
        contract_text = (repository / "runner" / "src" / "contract.rs").read_text(encoding="utf-8")
        process_text = (repository / "runner" / "src" / "process.rs").read_text(encoding="utf-8")
        setup_text = (repository / "setup.py").read_text(encoding="utf-8")
        config = load_config(repository / "bluefire" / "data" / "bluefire.example.yaml")
        native_canary = load_builtin_registry().get_action("sandbox.execution.native-canary.v1")
    except (OSError, UnicodeError, ValueError) as exc:
        raise CrossPlatformArtifactValidationError("macOS source contract is unavailable") from exc
    _require(
        current_platform("darwin") == "macos"
        and wheel_platform_tag("macos", "x86_64") == contract["x86_64_wheel_tag"]
        and wheel_platform_tag("macos", "aarch64") == contract["aarch64_wheel_tag"]
        and "Macos" in contract_text
        and 'target_os = "macos"' in contract_text
        and _macos_process_adapter_is_in_process(process_text)
        and '("macos", "x86_64")' in setup_text
        and '("macos", "aarch64")' in setup_text
        and any("macos" in profile.platforms for profile in config.runner_profiles)
        and "macos" in native_canary.platforms,
        "macOS structural source contract is incomplete",
    )


__all__ = [
    "CrossPlatformArtifactValidationError",
    "linux_wheelhouse_unavailable",
    "validate_gate_verification_document",
    "validate_linux_repository_runner",
    "validate_macos_structural_contract",
    "validate_run_readiness",
    "validate_transport_recovery_report",
    "validate_windows_wheel",
]
