"""Build-only hook for the platform-native BlueFire wheel.

The release workflow must stage exactly one reviewed runner and its manifest
before invoking the build backend.  This module deliberately uses only the
standard library plus declared build requirements so isolated PEP 517 builds
never import BlueFire's runtime dependency graph.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from pathlib import Path
from typing import Any

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel

_ROOT = Path(__file__).resolve().parent
_NATIVE = _ROOT / "bluefire" / "native"
_MANIFEST = _NATIVE / "runner-manifest.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLATFORMS = {
    ("windows", "x86_64"): ("bluefire-runner.exe", "win_amd64"),
    ("windows", "aarch64"): ("bluefire-runner.exe", "win_arm64"),
    ("linux", "x86_64"): ("bluefire-runner", "linux_x86_64"),
    ("linux", "aarch64"): ("bluefire-runner", "linux_aarch64"),
    ("macos", "x86_64"): ("bluefire-runner", "macosx_11_0_x86_64"),
    ("macos", "aarch64"): ("bluefire-runner", "macosx_11_0_arm64"),
}


def _build_host() -> tuple[str, str]:
    """Return the only native target an implicit wheel build may package."""

    platform_name = {
        "win32": "windows",
        "linux": "linux",
        "darwin": "macos",
    }.get(sys.platform)
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(platform.machine().strip().casefold().replace("-", "_"))
    if platform_name is None or architecture is None:
        raise RuntimeError("native runner build host is unsupported")
    return platform_name, architecture


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("native runner manifest contains a duplicate key")
        result[key] = value
    return result


def _mapping(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError("native runner manifest has an invalid shape")
    return value


def _native_architecture(path: Path, platform_name: str) -> str:
    """Read the executable header instead of trusting release labels."""

    with path.open("rb") as handle:
        header = handle.read(1024 * 1024)
    if platform_name == "windows":
        if len(header) < 64 or header[:2] != b"MZ":
            raise RuntimeError("native runner executable format is invalid")
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        if pe_offset + 6 > len(header) or header[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise RuntimeError("native runner executable format is invalid")
        machine = int.from_bytes(header[pe_offset + 4 : pe_offset + 6], "little")
        architectures = {0x8664: "x86_64", 0xAA64: "aarch64"}
    elif platform_name == "linux":
        if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2:
            raise RuntimeError("native runner executable format is invalid")
        byte_order = {1: "little", 2: "big"}.get(header[5])
        if byte_order is None:
            raise RuntimeError("native runner executable format is invalid")
        machine = int.from_bytes(header[18:20], byte_order)
        architectures = {62: "x86_64", 183: "aarch64"}
    else:
        byte_orders = {b"\xcf\xfa\xed\xfe": "little", b"\xfe\xed\xfa\xcf": "big"}
        byte_order = byte_orders.get(header[:4])
        if len(header) < 8 or byte_order is None:
            raise RuntimeError("native runner executable format is invalid")
        machine = int.from_bytes(header[4:8], byte_order)
        architectures = {0x01000007: "x86_64", 0x0100000C: "aarch64"}
    try:
        return architectures[machine]
    except KeyError as exc:
        raise RuntimeError("native runner executable architecture is unsupported") from exc


def _verified_platform_tag(
    product_version: str,
    *,
    explicit_platform_tag: str | None = None,
) -> str:
    try:
        payload = _MANIFEST.read_bytes()
        if not payload or len(payload) > 64 * 1024:
            raise RuntimeError("native runner manifest is missing or oversized")
        root = _mapping(
            json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object),
            {"schema_version", "product", "runner", "artifact"},
        )
        product = _mapping(root["product"], {"name", "version"})
        runner = _mapping(
            root["runner"],
            {"id", "version", "inventory_schema", "action_sdk_version", "receipt_protocol"},
        )
        artifact = _mapping(
            root["artifact"],
            {
                "filename",
                "platform",
                "architecture",
                "size",
                "sha256",
                "wheel_platform_tag",
            },
        )
        platform_key = (artifact["platform"], artifact["architecture"])
        filename, platform_tag = _PLATFORMS[platform_key]
        if explicit_platform_tag is None:
            if platform_key != _build_host():
                raise RuntimeError(
                    "native runner manifest does not match the build host; "
                    "stage the host artifact or supply an explicit --plat-name target"
                )
        elif explicit_platform_tag != platform_tag:
            raise RuntimeError("native runner manifest does not match the explicit wheel target")
        size = artifact["size"]
        digest = artifact["sha256"]
        expected_contract = {
            "schema_version": "bluefire.native-runner-package.v1",
            "product_name": "bluefire-nexus",
            "product_version": product_version,
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": product_version,
            "inventory_schema": "bluefire.runner-inventory.v1",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "filename": filename,
            "platform_tag": platform_tag,
        }
        actual_contract = {
            "schema_version": root["schema_version"],
            "product_name": product["name"],
            "product_version": product["version"],
            "runner_id": runner["id"],
            "runner_version": runner["version"],
            "inventory_schema": runner["inventory_schema"],
            "action_sdk_version": runner["action_sdk_version"],
            "receipt_protocol": runner["receipt_protocol"],
            "filename": artifact["filename"],
            "platform_tag": artifact["wheel_platform_tag"],
        }
        if actual_contract != expected_contract:
            raise RuntimeError("native runner manifest is incompatible with this wheel")
        if type(size) is not int or not 1 <= size <= 128 * 1024 * 1024:
            raise RuntimeError("native runner size is invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RuntimeError("native runner digest is invalid")
        runner_path = _NATIVE / filename
        if runner_path.is_symlink() or not runner_path.is_file():
            raise RuntimeError("native runner artifact is unavailable")
        if _native_architecture(runner_path, artifact["platform"]) != artifact["architecture"]:
            raise RuntimeError("native runner artifact architecture is incompatible")
        observed = hashlib.sha256(runner_path.read_bytes()).hexdigest()
        if runner_path.stat().st_size != size or observed != digest:
            raise RuntimeError("native runner artifact failed build-time integrity verification")
        return platform_tag
    except (KeyError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("native runner package resources are invalid") from exc


class PlatformNativeWheel(bdist_wheel):
    """Mark the verified runner-bearing wheel as platform specific."""

    def finalize_options(self) -> None:
        explicit_platform_tag = self.plat_name
        super().finalize_options()
        self.plat_name = _verified_platform_tag(
            str(self.distribution.metadata.version),
            explicit_platform_tag=explicit_platform_tag,
        )
        self.root_is_pure = False

    def get_tag(self) -> tuple[str, str, str]:
        """The Rust executable is platform-specific but Python-ABI independent."""

        _python, _abi, platform_tag = super().get_tag()
        return "py3", "none", platform_tag


setup(cmdclass={"bdist_wheel": PlatformNativeWheel})
