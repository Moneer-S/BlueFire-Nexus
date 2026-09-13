"""Build, inspect, and stage the exact Windows wheel member used by Gate 11."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .install_gate import _archive_committed_source
from .install_gate import _environment as _build_environment
from .install_gate import _run as _run_release_process
from .runner_bootstrap import (
    RunnerBootstrapError,
    inspect_native_architecture,
    load_runner_manifest,
)

_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_MEMBER_COUNT = 8192
_WHEEL_NAME = re.compile(
    r"^bluefire_nexus-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?)-"
    r"py3-none-win_amd64\.whl$"
)


class WheelJourneyError(ValueError):
    """Raised when a built wheel cannot bind the executed Windows resource."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WheelJourneyError(message)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _safe_file(path: Path, maximum: int) -> tuple[int, str, bytes]:
    details = path.lstat()
    is_reparse = bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    _require(
        stat.S_ISREG(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not is_reparse
        and details.st_nlink == 1
        and 1 <= details.st_size <= maximum,
        "the built Windows wheel is not a safe bounded regular file",
    )
    before = (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        _require(
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) == before,
            "the built Windows wheel identity changed",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
        _require(
            len(payload) == opened.st_size
            and len(payload) <= maximum
            and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == before
            and (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) == before,
            "the built Windows wheel changed during inspection",
        )
        return len(payload), _digest(payload), payload
    finally:
        os.close(descriptor)


def _safe_member_name(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return False
    normalized = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(normalized)
    return bool(
        normalized
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _record_rows(payload: bytes) -> Mapping[str, tuple[str, str]]:
    _require(0 < len(payload) <= 4 * 1024 * 1024, "the wheel RECORD is unbounded")
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error) as exc:
        raise WheelJourneyError("the wheel RECORD is invalid") from exc
    result: dict[str, tuple[str, str]] = {}
    for row in rows:
        _require(
            len(row) == 3 and _safe_member_name(row[0]) and row[0] not in result,
            "the wheel RECORD has an invalid or duplicate row",
        )
        result[row[0]] = (row[1], row[2])
    return result


def _verify_record_member(name: str, payload: bytes, row: tuple[str, str]) -> None:
    digest_field, size_field = row
    _require(size_field == str(len(payload)), "a wheel RECORD size does not match its member")
    _require(digest_field.startswith("sha256="), "a wheel RECORD digest is unsupported")
    encoded = digest_field.removeprefix("sha256=")
    _require(
        re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is not None, "a wheel RECORD digest is invalid"
    )
    try:
        observed = base64.urlsafe_b64decode(encoded + "=")
    except ValueError as exc:
        raise WheelJourneyError("a wheel RECORD digest is invalid") from exc
    _require(
        len(observed) == 32 and observed == hashlib.sha256(payload).digest(),
        f"wheel RECORD digest mismatch for {name}",
    )


def _write_member(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "wheel member extraction made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_windows_wheel_resource(
    repository: Path,
    evidence_dir: Path,
    runtime: Path,
) -> tuple[Mapping[str, Any], Path]:
    """Build from committed source and return the verified extracted native resource root."""

    source = runtime / "committed-source"
    source_archive = runtime / "committed-source.tar"
    package_dir = evidence_dir / "package"
    _require(not package_dir.exists(), "the Gate 11 wheel evidence destination is stale")
    try:
        _archive_committed_source(repository, source, source_archive)
        package_dir.mkdir()
        _run_release_process(
            [
                os.fspath(Path(sys.executable).resolve(strict=True)),
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                os.fspath(package_dir),
                os.fspath(source),
            ],
            cwd=runtime,
            environment=_build_environment(),
            timeout_seconds=300,
            failure_label="Gate 11 Windows wheel build",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise WheelJourneyError("the Gate 11 Windows wheel could not be built") from exc
    entries = sorted(package_dir.iterdir(), key=lambda item: item.name)
    match = _WHEEL_NAME.fullmatch(entries[0].name) if len(entries) == 1 else None
    if match is None:
        raise WheelJourneyError(
            "the Gate 11 package directory does not contain one exact Windows wheel"
        )
    wheel = entries[0]
    version = str(match.group("version"))
    package_root = f"bluefire_nexus-{version}.data/purelib/bluefire/native"
    wheel_size, wheel_digest, wheel_payload = _safe_file(wheel, _MAX_WHEEL_BYTES)
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_payload), "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            _require(
                0 < len(infos) <= _MAX_MEMBER_COUNT
                and len(names) == len(set(names))
                and all(_safe_member_name(name) for name in names),
                "the built wheel member inventory is unsafe",
            )
            total_size = 0
            file_names: list[str] = []
            for info in infos:
                unix_mode = int(info.external_attr) >> 16
                _require(
                    not (info.flag_bits & 0x1)
                    and not stat.S_ISLNK(unix_mode)
                    and 0 <= info.file_size <= _MAX_MEMBER_BYTES,
                    "the built wheel contains an unsafe member",
                )
                total_size += info.file_size
                if not info.is_dir():
                    file_names.append(info.filename)
            _require(total_size <= _MAX_WHEEL_BYTES, "the built wheel expands beyond its bound")
            manifest_member = f"{package_root}/runner-manifest.json"
            binary_member = f"{package_root}/bluefire-runner.exe"
            manifests = [name for name in file_names if name == manifest_member]
            binaries = [name for name in file_names if name == binary_member]
            runner_members = [
                name
                for name in file_names
                if name.endswith("/bluefire/native/bluefire-runner")
                or name.endswith("/bluefire/native/bluefire-runner.exe")
            ]
            records = [name for name in file_names if name.endswith(".dist-info/RECORD")]
            wheel_metadata = [name for name in file_names if name.endswith(".dist-info/WHEEL")]
            package_metadata = [name for name in file_names if name.endswith(".dist-info/METADATA")]
            _require(
                len(manifests)
                == len(binaries)
                == len(records)
                == len(wheel_metadata)
                == len(package_metadata)
                == 1,
                "the built wheel lacks an exact native resource or package metadata",
            )
            _require(runner_members == binaries, "the built wheel contains a foreign native runner")
            manifest_member = manifests[0]
            binary_member = binaries[0]
            record_member = records[0]
            wheel_member = wheel_metadata[0]
            metadata_member = package_metadata[0]
            payloads = {name: archive.read(name) for name in file_names}
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WheelJourneyError("the built Windows wheel could not be inspected") from exc
    dist_info = f"bluefire_nexus-{version}.dist-info"
    _require(
        record_member == f"{dist_info}/RECORD"
        and wheel_member == f"{dist_info}/WHEEL"
        and metadata_member == f"{dist_info}/METADATA",
        "the wheel filename and dist-info identity do not match",
    )
    rows = _record_rows(payloads[record_member])
    _require(set(rows) == set(file_names), "the wheel RECORD inventory is incomplete")
    for name, payload in payloads.items():
        if name == record_member:
            _require(rows[name] == ("", ""), "the wheel RECORD self-row is invalid")
        else:
            _verify_record_member(name, payload, rows[name])
    try:
        wheel_text = payloads[wheel_member].decode("utf-8")
        metadata_text = payloads[metadata_member].decode("utf-8")
    except UnicodeError as exc:
        raise WheelJourneyError("the built wheel metadata is invalid") from exc
    _require(
        wheel_text.splitlines().count("Tag: py3-none-win_amd64") == 1
        and wheel_text.splitlines().count("Root-Is-Purelib: false") == 1
        and metadata_text.splitlines().count("Name: bluefire-nexus") == 1
        and metadata_text.splitlines().count(f"Version: {version}") == 1,
        "the built wheel metadata does not identify the Windows native target",
    )
    resource_root = runtime / "wheel-resource"
    resource_root.mkdir()
    _write_member(resource_root / "runner-manifest.json", payloads[manifest_member])
    _write_member(resource_root / "bluefire-runner.exe", payloads[binary_member])
    try:
        manifest = load_runner_manifest(
            resource_root=resource_root,
            platform_name="windows",
            architecture="x86_64",
        )
        architecture = inspect_native_architecture(
            resource_root / "bluefire-runner.exe", platform_name="windows"
        )
    except RunnerBootstrapError as exc:
        raise WheelJourneyError("the extracted Windows wheel resource is incompatible") from exc
    _require(
        architecture == "x86_64"
        and manifest.product_version == version
        and len(payloads[binary_member]) == manifest.size
        and _digest(payloads[binary_member]) == "sha256:" + manifest.sha256,
        "the extracted Windows wheel resource does not match its manifest",
    )
    return (
        {
            "source": "built-wheel-member",
            "runner_id": manifest.runner_id,
            "runner_version": manifest.runner_version,
            "platform": "windows",
            "architecture": "x86_64",
            "wheel_file": wheel.name,
            "wheel_sha256": wheel_digest,
            "wheel_size": wheel_size,
            "manifest_member": manifest_member,
            "manifest_sha256": _digest(payloads[manifest_member]),
            "manifest_size": len(payloads[manifest_member]),
            "binary_member": binary_member,
            "binary_sha256": _digest(payloads[binary_member]),
            "binary_size": len(payloads[binary_member]),
            "record_member": record_member,
            "record_sha256": _digest(payloads[record_member]),
            "record_bound": True,
        },
        resource_root,
    )


__all__ = ["WheelJourneyError", "build_windows_wheel_resource"]
