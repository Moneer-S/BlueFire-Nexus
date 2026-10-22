"""Validate candidate wheel assets and write an unsigned release checksum manifest."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import email.policy
import hashlib
import io
import json
import re
import stat
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Sequence

if __package__:
    from . import verify_packaged_runner as verifier
else:
    import verify_packaged_runner as verifier

_MAX_WHEEL_BYTES = 1024 * 1024 * 1024
_MAX_REPORT_BYTES = 64 * 1024
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_BUILD_INFO_BYTES = 16 * 1024
_MAX_RUNNER_BYTES = 512 * 1024 * 1024
_MAX_RECORD_BYTES = 4 * 1024 * 1024
_OUTPUT_NAMES = {"SHA256SUMS", "release-assets.json"}
_TARGETS = {
    "win_amd64": ("windows", "x86_64", "bluefire-runner.exe"),
    "linux_x86_64": ("linux", "x86_64", "bluefire-runner"),
    "macosx_11_0_x86_64": ("macos", "x86_64", "bluefire-runner"),
    "macosx_11_0_arm64": ("macos", "aarch64", "bluefire-runner"),
}
_NORMALIZED_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:rc(?:0|[1-9][0-9]*))?$"
)
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_BUILD_INFO_FIELDS = {
    "schema_version",
    "version",
    "source_revision",
    "source_provenance",
    "ui_files",
    "ui_digest",
}
_UI_NAMES = ("app.js", "index.html", "styles.css")


def _read_regular(path: Path, maximum: int) -> bytes:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
        or not 0 < info.st_size <= maximum
    ):
        raise ValueError("release asset input is not a bounded regular file")
    payload = path.read_bytes()
    current = path.lstat()
    if (
        len(payload) != info.st_size
        or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
        or _is_reparse(current)
        or current.st_nlink != 1
    ):
        raise ValueError("release asset input changed while being read")
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _sha256_file(path: Path, maximum: int) -> str:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or not 0 < before.st_size <= maximum
    ):
        raise ValueError("wheel is not a bounded regular file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            if size > maximum:
                raise ValueError("wheel exceeds its size limit")
            digest.update(chunk)
    after = path.lstat()
    if (
        size != before.st_size
        or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or _is_reparse(after)
        or after.st_nlink != 1
    ):
        raise ValueError("wheel changed while being read")
    return digest.hexdigest()


def _is_reparse(details: Any) -> bool:
    return bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _require_directory(path: Path) -> None:
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or _is_reparse(details):
        raise ValueError("asset directory must be a real non-reparse directory")


def _parse_headers(payload: bytes) -> Any:
    message = BytesParser(policy=email.policy.default).parsebytes(payload)
    if message.defects:
        raise ValueError("wheel metadata headers are malformed")
    return message


def _strict_json(payload: bytes) -> Any:
    return json.loads(payload.decode("utf-8"), object_pairs_hook=verifier._duplicates_rejected)


def _check_archive_names(names: Sequence[str]) -> None:
    if len(names) != len(set(names)):
        raise ValueError("wheel contains duplicate member names")
    for name in names:
        parts = name.split("/")
        if parts[-1] == "":
            parts.pop()
        if (
            not name
            or "\\" in name
            or name.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError("wheel contains an unsafe member name")


def _member_bytes(archive: zipfile.ZipFile, name: str, maximum: int) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > maximum:
        raise ValueError("wheel metadata exceeds its size limit")
    with archive.open(info) as member:
        payload = member.read(maximum + 1)
    if len(payload) != info.file_size or len(payload) > maximum:
        raise ValueError("wheel member size is inconsistent")
    return payload


def _member_digest(
    archive: zipfile.ZipFile, name: str, maximum: int, *, allow_empty: bool = False
) -> tuple[int, str]:
    info = archive.getinfo(name)
    if (info.file_size <= 0 and not allow_empty) or info.file_size > maximum:
        raise ValueError("wheel member size is outside its allowed range")
    member_type = stat.S_IFMT(info.external_attr >> 16)
    if member_type not in {0, stat.S_IFREG}:
        raise ValueError("wheel contains a non-regular member")
    digest = hashlib.sha256()
    size = 0
    with archive.open(info) as member:
        for chunk in iter(lambda: member.read(64 * 1024), b""):
            size += len(chunk)
            if size > maximum:
                raise ValueError("native runner exceeds its size limit")
            digest.update(chunk)
    if size != info.file_size:
        raise ValueError("native runner size is inconsistent")
    return size, digest.hexdigest()


def _validate_record(archive: zipfile.ZipFile, record_name: str) -> None:
    """Require a complete SHA-256 RECORD for every regular wheel member."""
    record_bytes = _member_bytes(archive, record_name, _MAX_RECORD_BYTES)
    try:
        rows = list(csv.reader(io.StringIO(record_bytes.decode("utf-8"), newline=""), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise ValueError("wheel RECORD is malformed") from exc

    signature_names = {f"{record_name}.jws", f"{record_name}.p7s"}
    expected_members = {
        info.filename: info
        for info in archive.infolist()
        if not info.is_dir() and info.filename not in signature_names
    }
    for info in archive.infolist():
        member_type = stat.S_IFMT(info.external_attr >> 16)
        allowed_types = {0, stat.S_IFDIR} if info.is_dir() else {0, stat.S_IFREG}
        if member_type not in allowed_types:
            raise ValueError("wheel contains a non-regular member")
        if info.filename in signature_names and info.file_size > _MAX_METADATA_BYTES:
            raise ValueError("wheel signature member exceeds its size limit")
    if record_name not in expected_members:
        raise ValueError("wheel RECORD is missing")
    if sum(info.file_size for info in expected_members.values()) > _MAX_WHEEL_BYTES:
        raise ValueError("wheel contents exceed their aggregate size limit")

    seen: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise ValueError("wheel RECORD row has an invalid shape")
        name, digest_field, size_field = row
        if not name or name in seen:
            raise ValueError("wheel RECORD contains a duplicate or empty member")
        seen.add(name)
        info = expected_members.get(name)
        if info is None:
            raise ValueError("wheel RECORD references a missing member")
        if name == record_name:
            if digest_field or size_field:
                raise ValueError("wheel RECORD must leave its own hash and size blank")
            continue
        if (
            not digest_field.startswith("sha256=")
            or not size_field.isascii()
            or not size_field.isdecimal()
        ):
            raise ValueError("wheel RECORD hash or size is invalid")
        try:
            encoded_digest = digest_field[7:]
            recorded_digest = base64.urlsafe_b64decode(
                encoded_digest + "=" * (-len(encoded_digest) % 4)
            )
        except (ValueError, binascii.Error) as exc:
            raise ValueError("wheel RECORD hash is invalid") from exc
        if base64.urlsafe_b64encode(recorded_digest).decode("ascii").rstrip("=") != encoded_digest:
            raise ValueError("wheel RECORD hash is not canonical")
        if (
            size_field != str(info.file_size)
            or len(recorded_digest) != hashlib.sha256().digest_size
        ):
            raise ValueError("wheel RECORD size or hash length is invalid")
        observed_size, observed_sha = _member_digest(
            archive, name, _MAX_WHEEL_BYTES, allow_empty=True
        )
        if observed_size != info.file_size or recorded_digest.hex() != observed_sha:
            raise ValueError("wheel RECORD does not match member contents")

    if seen != set(expected_members):
        raise ValueError("wheel RECORD does not enumerate every member")


def _inspect_wheel(
    wheel: Path,
    *,
    version: str,
    source_revision: str,
    tag: str,
    platform: str,
    architecture: str,
) -> dict[str, Any]:
    if not _NORMALIZED_VERSION.fullmatch(version):
        raise ValueError("expected version must use normalized PEP 440 spelling")
    expected_name = f"bluefire_nexus-{version}-py3-none-{tag}.whl"
    if wheel.name != expected_name:
        raise ValueError("wheel filename does not match its expected version and platform")
    wheel_sha = _sha256_file(wheel, _MAX_WHEEL_BYTES)
    expected_runner_version = verifier._native_runner_version(version)

    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        _check_archive_names(names)
        dist_info = f"bluefire_nexus-{version}.dist-info"
        metadata_name = f"{dist_info}/METADATA"
        wheel_name = f"{dist_info}/WHEEL"
        record_name = f"{dist_info}/RECORD"
        dist_info_roots = {
            name.split("/", 1)[0] for name in names if name.split("/", 1)[0].endswith(".dist-info")
        }
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        manifest_names = [
            name for name in names if name.endswith("/bluefire/native/runner-manifest.json")
        ]
        build_info_names = [
            name
            for name in names
            if name == "bluefire/_build_info.json" or name.endswith("/bluefire/_build_info.json")
        ]
        canonical_package_roots = (
            f"bluefire_nexus-{version}.data/purelib/",
            f"bluefire_nexus-{version}.data/platlib/",
        )
        canonical_manifest_names = {
            f"{root}bluefire/native/runner-manifest.json" for root in canonical_package_roots
        }
        if (
            dist_info_roots != {dist_info}
            or metadata_names != [metadata_name]
            or wheel_names != [wheel_name]
            or len(manifest_names) != 1
            or len(build_info_names) != 1
        ):
            raise ValueError(
                "wheel must contain exactly one metadata file, build identity, and native manifest"
            )
        if manifest_names[0] not in canonical_manifest_names:
            raise ValueError("native manifest is not rooted at the canonical BlueFire package path")
        expected_build_info = manifest_names[0].removesuffix("native/runner-manifest.json")
        expected_build_info += "_build_info.json"
        if build_info_names[0] != expected_build_info:
            raise ValueError("build identity and native manifest have different package roots")
        _validate_record(archive, record_name)

        build_info = _strict_json(
            _member_bytes(archive, build_info_names[0], _MAX_BUILD_INFO_BYTES)
        )
        if not isinstance(build_info, dict) or set(build_info) != _BUILD_INFO_FIELDS:
            raise ValueError("wheel build identity has an invalid shape")
        if (
            build_info["schema_version"] != "bluefire.build-metadata.v1"
            or build_info["version"] != version
            or build_info["source_revision"] != source_revision
            or build_info["source_provenance"] != "git_archive"
        ):
            raise ValueError(
                "wheel build identity does not match the expected source revision and version"
            )
        files = build_info["ui_files"]
        if not isinstance(files, list) or len(files) != len(_UI_NAMES):
            raise ValueError("wheel build identity has an invalid UI inventory")
        ui_root = build_info_names[0].removesuffix("_build_info.json") + "ui/"
        for item, name in zip(files, _UI_NAMES, strict=True):
            if (
                not isinstance(item, dict)
                or set(item) != {"name", "sha256", "size"}
                or item["name"] != name
                or type(item["size"]) is not int
                or not 0 < item["size"] <= 8 * 1024 * 1024
                or not isinstance(item["sha256"], str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["sha256"])
            ):
                raise ValueError("wheel build identity has an invalid UI inventory")
            ui_path = ui_root + name
            if ui_path not in names:
                raise ValueError("wheel build identity references a missing UI member")
            actual_size, actual_sha = _member_digest(archive, ui_path, 8 * 1024 * 1024)
            if item["size"] != actual_size or item["sha256"] != "sha256:" + actual_sha:
                raise ValueError("wheel build identity does not match its UI member")
        if build_info["ui_digest"] != "sha256:" + _sha256(_canonical_json(files)):
            raise ValueError("wheel build identity UI digest is invalid")

        metadata = _parse_headers(_member_bytes(archive, metadata_name, _MAX_METADATA_BYTES))
        if metadata.get_all("Name", []) != ["bluefire-nexus"] or metadata.get_all(
            "Version", []
        ) != [version]:
            raise ValueError("wheel metadata has the wrong distribution or version")

        expected_wheel_tag = f"py3-none-{tag}"
        wheel_metadata = _parse_headers(_member_bytes(archive, wheel_name, _MAX_METADATA_BYTES))
        if wheel_metadata.get_all("Tag", []) != [expected_wheel_tag] or wheel_metadata.get_all(
            "Root-Is-Purelib", []
        ) != ["false"]:
            raise ValueError("wheel metadata does not match the expected native platform tag")

        manifest = verifier._exact_mapping(
            _strict_json(_member_bytes(archive, manifest_names[0], _MAX_METADATA_BYTES)),
            {"schema_version", "product", "runner", "artifact"},
        )
        product = verifier._exact_mapping(manifest["product"], {"name", "version"})
        runner = verifier._exact_mapping(
            manifest["runner"],
            {"id", "version", "inventory_schema", "action_sdk_version", "receipt_protocol"},
        )
        artifact = verifier._exact_mapping(
            manifest["artifact"],
            {"filename", "platform", "architecture", "size", "sha256", "wheel_platform_tag"},
        )
        executable = "bluefire-runner.exe" if platform == "windows" else "bluefire-runner"
        executable_names = verifier._native_runner_members(names, executable)
        if manifest["schema_version"] != "bluefire.native-runner-package.v1":
            raise ValueError("native runner manifest schema is unsupported")
        if (
            product != {"name": "bluefire-nexus", "version": version}
            or runner.get("version") != expected_runner_version
            or runner.get("id") != "bluefire-rust-runner.v1"
        ):
            raise ValueError("native runner manifest has the wrong product or version")
        expected_contract = {
            "inventory_schema": "bluefire.runner-inventory.v1",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        }
        if {key: runner.get(key) for key in expected_contract} != expected_contract:
            raise ValueError("native runner manifest compatibility contract is invalid")
        expected_artifact = {
            "filename": executable,
            "platform": platform,
            "architecture": architecture,
            "wheel_platform_tag": tag,
        }
        if {key: artifact.get(key) for key in expected_artifact} != expected_artifact:
            raise ValueError("native runner manifest target does not match the requested platform")
        runner_size, runner_sha = _member_digest(archive, executable_names[0], _MAX_RUNNER_BYTES)
        if artifact.get("size") != runner_size or artifact.get("sha256") != runner_sha:
            raise ValueError("native runner manifest digest does not match its embedded binary")

    if _sha256_file(wheel, _MAX_WHEEL_BYTES) != wheel_sha:
        raise ValueError("wheel changed during inspection")
    return {
        "wheel": wheel.name,
        "wheel_sha256": wheel_sha,
        "source_revision": source_revision,
        "platform": platform,
        "architecture": architecture,
        "tag": tag,
        "native_runner_version": expected_runner_version,
        "runner": {"filename": executable, "size": runner_size, "sha256": runner_sha},
    }


def build_release_asset_outputs(
    asset_dir: Path, *, version: str, source_revision: str, expected_tags: Sequence[str]
) -> tuple[bytes, bytes]:
    """Validate each requested wheel/report pair and return deterministic output bytes."""
    if not _NORMALIZED_VERSION.fullmatch(version):
        raise ValueError("expected version must use normalized PEP 440 spelling")
    if not isinstance(source_revision, str) or not _SOURCE_REVISION.fullmatch(source_revision):
        raise ValueError("expected source revision must be a full lowercase 40-hex Git revision")
    if (
        not expected_tags
        or any(type(tag) is not str for tag in expected_tags)
        or len(expected_tags) != len(set(expected_tags))
    ):
        raise ValueError("expected platform tags must be non-empty and distinct")
    if any(tag not in _TARGETS for tag in expected_tags):
        raise ValueError("an expected platform tag is unsupported")
    _require_directory(asset_dir)

    expected_names = set(expected_tags) | _OUTPUT_NAMES
    actual_names = {entry.name for entry in asset_dir.iterdir()}
    if set(expected_tags) - actual_names:
        raise ValueError("one or more expected platform assets are missing")
    if actual_names - expected_names:
        raise ValueError("asset directory contains unexpected entries")
    assets: list[dict[str, Any]] = []
    checksum_rows: list[tuple[str, str]] = []
    for tag in sorted(expected_tags):
        target_dir = asset_dir / tag
        _require_directory(target_dir)
        platform, architecture, _executable = _TARGETS[tag]
        wheel_name = f"bluefire_nexus-{version}-py3-none-{tag}.whl"
        expected_files = {wheel_name, "package-inspection.json"}
        files = {entry.name for entry in target_dir.iterdir()}
        if files != expected_files:
            raise ValueError(
                "platform directory must contain exactly one wheel and inspection report"
            )
        wheel = target_dir / wheel_name
        inspection_path = target_dir / "package-inspection.json"
        inspection_bytes = _read_regular(inspection_path, _MAX_REPORT_BYTES)
        inspection = verifier._exact_mapping(
            _strict_json(inspection_bytes),
            {
                "schema_version",
                "wheel",
                "wheel_sha256",
                "tag",
                "platform",
                "architecture",
                "runner",
                "verified",
            },
        )
        inspected = _inspect_wheel(
            wheel,
            version=version,
            source_revision=source_revision,
            tag=tag,
            platform=platform,
            architecture=architecture,
        )
        runner_report = verifier._exact_mapping(
            inspection["runner"], {"filename", "size", "sha256"}
        )
        if (
            inspection["schema_version"] != "bluefire.package-inspection.v1"
            or inspection["verified"] is not True
            or inspection["wheel"] != wheel_name
            or inspection["wheel_sha256"] != inspected["wheel_sha256"]
            or inspection["tag"] != f"py3-none-{tag}"
            or inspection["platform"] != platform
            or inspection["architecture"] != architecture
            or runner_report != inspected["runner"]
        ):
            raise ValueError("package-inspection report does not bind to the wheel contents")

        staging_wheel = f"{tag}/{wheel_name}"
        relative_report = f"{tag}/package-inspection.json"
        assets.append(
            {
                **inspected,
                "published_filename": wheel_name,
                "staging_wheel_path": staging_wheel,
                "inspection_report_path": relative_report,
                "inspection_report_sha256": _sha256(inspection_bytes),
            }
        )
        checksum_rows.extend(
            [
                (inspected["wheel_sha256"], wheel_name),
            ]
        )

    manifest = {
        "schema_version": "bluefire.release-assets.v1",
        "version": version,
        "source_revision": source_revision,
        "native_runner_version": verifier._native_runner_version(version),
        "checksum_file": "SHA256SUMS",
        "assets": assets,
        "integrity_note": "Checksums are unsigned content hashes, not publisher attestations.",
    }
    checksums = "".join(f"{digest}  {path}\n" for digest, path in sorted(checksum_rows)).encode(
        "ascii"
    )
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return checksums, manifest_bytes


def _write_same_or_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or _read_regular(path, len(payload) + 1) != payload:
            raise ValueError("refusing to overwrite a different release manifest")
        return
    with path.open("xb") as handle:
        handle.write(payload)


def _check_output(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or _read_regular(path, len(payload) + 1) != payload:
            raise ValueError("refusing to overwrite a different release manifest")


def write_release_asset_outputs(
    asset_dir: Path, *, version: str, source_revision: str, expected_tags: Sequence[str]
) -> None:
    checksums, manifest = build_release_asset_outputs(
        asset_dir,
        version=version,
        source_revision=source_revision,
        expected_tags=expected_tags,
    )
    _check_output(asset_dir / "SHA256SUMS", checksums)
    _check_output(asset_dir / "release-assets.json", manifest)
    _write_same_or_new(asset_dir / "SHA256SUMS", checksums)
    _write_same_or_new(asset_dir / "release-assets.json", manifest)


def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument(
        "--version", required=True, help="normalized candidate version, e.g. 3.0.0rc2"
    )
    parser.add_argument("--source-revision", required=True, help="full lowercase 40-hex Git commit")
    parser.add_argument("--expected-tag", action="append", choices=sorted(_TARGETS), required=True)
    args = parser.parse_args(argv)
    write_release_asset_outputs(
        args.asset_dir,
        version=args.version,
        source_revision=args.source_revision,
        expected_tags=args.expected_tag,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
