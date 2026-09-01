from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from setuptools.dist import Distribution

from bluefire import __version__

REPOSITORY = Path(__file__).resolve().parents[1]
PRODUCT_VERSION = __version__


def _load_build_hook() -> dict[str, Any]:
    with patch("setuptools.setup") as setup:
        namespace = runpy.run_path(
            str(REPOSITORY / "setup.py"),
            run_name="bluefire_native_wheel_build_test",
        )
    assert set(setup.call_args.kwargs["cmdclass"]) == {"bdist_wheel"}
    return namespace


def _native_payload(platform_name: str, architecture: str = "x86_64") -> bytes:
    payload = bytearray(256)
    if platform_name == "windows":
        payload[:2] = b"MZ"
        payload[0x3C:0x40] = (128).to_bytes(4, "little")
        payload[128:132] = b"PE\0\0"
        machine = {"x86_64": 0x8664, "aarch64": 0xAA64}[architecture]
        payload[132:134] = machine.to_bytes(2, "little")
    elif platform_name == "linux":
        payload[:6] = b"\x7fELF\x02\x01"
        machine = {"x86_64": 62, "aarch64": 183}[architecture]
        payload[18:20] = machine.to_bytes(2, "little")
    else:
        payload[:4] = b"\xcf\xfa\xed\xfe"
        machine = {"x86_64": 0x01000007, "aarch64": 0x0100000C}[architecture]
        payload[4:8] = machine.to_bytes(4, "little")
    return bytes(payload)


def _stage_manifest(
    root: Path,
    *,
    platform_name: str,
    architecture: str = "x86_64",
) -> tuple[Path, str]:
    native = root / "bluefire" / "native"
    native.mkdir(parents=True)
    filename = "bluefire-runner.exe" if platform_name == "windows" else "bluefire-runner"
    platform_tag = {
        ("windows", "x86_64"): "win_amd64",
        ("linux", "x86_64"): "linux_x86_64",
        ("macos", "x86_64"): "macosx_11_0_x86_64",
    }[(platform_name, architecture)]
    payload = _native_payload(platform_name, architecture)
    (native / filename).write_bytes(payload)
    manifest = {
        "schema_version": "bluefire.native-runner-package.v1",
        "product": {"name": "bluefire-nexus", "version": PRODUCT_VERSION},
        "runner": {
            "id": "bluefire-rust-runner.v1",
            "version": PRODUCT_VERSION,
            "inventory_schema": "bluefire.runner-inventory.v1",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        },
        "artifact": {
            "filename": filename,
            "platform": platform_name,
            "architecture": architecture,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "wheel_platform_tag": platform_tag,
        },
    }
    manifest_path = native / "runner-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return native, platform_tag


def _bind_native_root(namespace: dict[str, Any], native: Path) -> None:
    globals_ = namespace["_verified_platform_tag"].__globals__
    globals_["_NATIVE"] = native
    globals_["_MANIFEST"] = native / "runner-manifest.json"


@pytest.mark.parametrize(
    ("sys_platform", "machine", "manifest_platform", "expected_tag"),
    [
        ("win32", "AMD64", "windows", "win_amd64"),
        ("linux", "x86_64", "linux", "linux_x86_64"),
        ("darwin", "x86_64", "macos", "macosx_11_0_x86_64"),
    ],
)
def test_implicit_wheel_target_must_match_each_supported_build_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sys_platform: str,
    machine: str,
    manifest_platform: str,
    expected_tag: str,
) -> None:
    namespace = _load_build_hook()
    native, _ = _stage_manifest(tmp_path, platform_name=manifest_platform)
    _bind_native_root(namespace, native)
    monkeypatch.setattr(namespace["sys"], "platform", sys_platform)
    monkeypatch.setattr(namespace["platform"], "machine", lambda: machine)

    assert namespace["_verified_platform_tag"](PRODUCT_VERSION) == expected_tag


def test_implicit_wheel_build_rejects_a_foreign_committed_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _load_build_hook()
    native, _ = _stage_manifest(tmp_path, platform_name="windows")
    _bind_native_root(namespace, native)
    monkeypatch.setattr(namespace["sys"], "platform", "linux")
    monkeypatch.setattr(namespace["platform"], "machine", lambda: "x86_64")

    with pytest.raises(RuntimeError, match="does not match the build host"):
        namespace["_verified_platform_tag"](PRODUCT_VERSION)


def test_cross_build_requires_the_exact_explicit_wheel_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _load_build_hook()
    native, platform_tag = _stage_manifest(tmp_path, platform_name="windows")
    _bind_native_root(namespace, native)
    monkeypatch.setattr(namespace["sys"], "platform", "linux")
    monkeypatch.setattr(namespace["platform"], "machine", lambda: "x86_64")

    assert (
        namespace["_verified_platform_tag"](
            PRODUCT_VERSION,
            explicit_platform_tag=platform_tag,
        )
        == platform_tag
    )
    with pytest.raises(RuntimeError, match="does not match the explicit wheel target"):
        namespace["_verified_platform_tag"](
            PRODUCT_VERSION,
            explicit_platform_tag="linux_x86_64",
        )


def test_wheel_command_forwards_only_an_explicit_pre_finalize_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _load_build_hook()
    command_type = namespace["PlatformNativeWheel"]
    observed: list[tuple[str, str | None]] = []

    def verify(version: str, *, explicit_platform_tag: str | None = None) -> str:
        observed.append((version, explicit_platform_tag))
        return "win_amd64"

    monkeypatch.setitem(command_type.finalize_options.__globals__, "_verified_platform_tag", verify)
    monkeypatch.setattr(namespace["bdist_wheel"], "finalize_options", lambda _self: None)
    command = command_type(Distribution({"name": "bluefire-nexus", "version": PRODUCT_VERSION}))
    command.plat_name = "win_amd64"

    command.finalize_options()

    assert observed == [(PRODUCT_VERSION, "win_amd64")]
    assert command.plat_name == "win_amd64"
    assert command.root_is_pure is False
