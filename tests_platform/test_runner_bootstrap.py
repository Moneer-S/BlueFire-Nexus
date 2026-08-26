from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.runner_bootstrap import (
    ACTION_SDK_VERSION,
    INVENTORY_SCHEMA_VERSION,
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    RECEIPT_PROTOCOL_VERSION,
    RUNNER_BINARY_ENV,
    RUNNER_ID,
    SANDBOX_ROOT_ENV,
    RunnerBootstrapError,
    RunnerPackageManifest,
    bootstrap_runner,
    load_runner_manifest,
    parse_runner_manifest,
    validate_runner_inventory,
)
from tools.stage_native_runner import stage_native_runner

PRODUCT_VERSION = "0.1.0"
PLATFORM = "windows"
ARCHITECTURE = "x86_64"
FILENAME = "bluefire-runner.exe"
WHEEL_TAG = "win_amd64"


def _fake_pe(*, architecture: str = ARCHITECTURE) -> bytes:
    machine = {"x86_64": 0x8664, "aarch64": 0xAA64}[architecture]
    payload = bytearray(256)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\0\0"
    payload[132:134] = machine.to_bytes(2, "little")
    return bytes(payload)


def _manifest(payload: bytes | None = None) -> RunnerPackageManifest:
    payload = _fake_pe() if payload is None else payload
    return RunnerPackageManifest(
        product_version=PRODUCT_VERSION,
        runner_version=PRODUCT_VERSION,
        platform=PLATFORM,
        architecture=ARCHITECTURE,
        filename=FILENAME,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        wheel_platform_tag=WHEEL_TAG,
    )


def _inventory(**changes: Any) -> Mapping[str, Any]:
    value: dict[str, Any] = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "runner_id": RUNNER_ID,
        "runner_version": PRODUCT_VERSION,
        "action_sdk_version": ACTION_SDK_VERSION,
        "receipt_protocol": RECEIPT_PROTOCOL_VERSION,
        "platform": PLATFORM,
        "actions": [],
    }
    value.update(changes)
    return value


def _resource_root(tmp_path: Path, payload: bytes | None = None) -> Path:
    payload = _fake_pe() if payload is None else payload
    root = tmp_path / "resources"
    root.mkdir()
    (root / FILENAME).write_bytes(payload)
    (root / MANIFEST_FILENAME).write_text(
        json.dumps(_manifest(payload).to_dict(), sort_keys=True),
        encoding="utf-8",
    )
    return root


def test_packaged_runner_bootstrap_is_atomic_private_and_path_safe(tmp_path: Path) -> None:
    resources = _resource_root(tmp_path)
    managed = tmp_path / "managed"

    result = bootstrap_runner(
        environ={},
        resource_root=resources,
        managed_root=managed,
        product_version=PRODUCT_VERSION,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        inventory_probe=lambda _binary: _inventory(),
    )

    assert result.source == "packaged"
    assert result.managed_binary is True
    assert result.managed_sandbox is True
    assert result.binary_path.read_bytes() == (resources / FILENAME).read_bytes()
    assert result.sandbox_path.is_dir()
    assert not list(managed.rglob("*.tmp"))
    if os.name != "nt":
        assert stat.S_IMODE(result.binary_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(managed.stat().st_mode) == 0o700

    serialized = json.dumps(result.public_status(), sort_keys=True)
    assert str(tmp_path) not in serialized
    assert str(tmp_path) not in repr(result)
    assert result.public_status()["artifact"] == {
        "managed": True,
        "size": _manifest().size,
        "sha256": "sha256:" + _manifest().sha256,
        "wheel_platform_tag": WHEEL_TAG,
    }


def test_bootstrap_refuses_tampered_source_without_installing_it(tmp_path: Path) -> None:
    resources = _resource_root(tmp_path)
    (resources / FILENAME).write_bytes(b"tampered")

    with pytest.raises(RunnerBootstrapError) as refused:
        bootstrap_runner(
            environ={},
            resource_root=resources,
            managed_root=tmp_path / "managed",
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            inventory_probe=lambda _binary: _inventory(),
        )

    assert "integrity" in str(refused.value).casefold()
    assert str(tmp_path) not in str(refused.value)
    assert not list((tmp_path / "managed").rglob(FILENAME))


def test_bootstrap_rechecks_integrity_after_health_probe(tmp_path: Path) -> None:
    resources = _resource_root(tmp_path)

    def corrupt_after_copy(binary: Path) -> Mapping[str, Any]:
        binary.write_bytes(b"changed after atomic copy")
        return _inventory()

    with pytest.raises(RunnerBootstrapError, match="changed during health verification"):
        bootstrap_runner(
            environ={},
            resource_root=resources,
            managed_root=tmp_path / "managed",
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            inventory_probe=corrupt_after_copy,
        )


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("root", "schema_version", "bluefire.native-runner-package.v2"),
        ("product", "name", "another-product"),
        ("product", "version", "9.9.9"),
        ("runner", "id", "different-runner.v1"),
        ("runner", "version", "9.9.9"),
        ("runner", "inventory_schema", "bluefire.runner-inventory.v2"),
        ("runner", "action_sdk_version", "bluefire.runner-action-sdk.v2"),
        ("runner", "receipt_protocol", "bluefire.runner-receipt-wal.v1"),
        ("artifact", "platform", "linux"),
        ("artifact", "architecture", "aarch64"),
        ("artifact", "wheel_platform_tag", "any"),
        ("artifact", "sha256", "A" * 64),
    ],
)
def test_manifest_refuses_incompatible_or_invalid_contracts(
    section: str,
    field: str,
    value: str,
) -> None:
    document = copy.deepcopy(_manifest().to_dict())
    target = document if section == "root" else document[section]
    target[field] = value

    with pytest.raises(RunnerBootstrapError):
        parse_runner_manifest(
            document,
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
        )


def test_manifest_is_strict_and_duplicate_json_keys_are_refused(tmp_path: Path) -> None:
    document = _manifest().to_dict()
    document["unexpected"] = True
    with pytest.raises(RunnerBootstrapError, match="manifest is invalid"):
        parse_runner_manifest(
            document,
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
        )

    root = tmp_path / "resources"
    root.mkdir()
    (root / MANIFEST_FILENAME).write_text(
        '{"schema_version":"%s","schema_version":"%s"}'
        % (MANIFEST_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION),
        encoding="utf-8",
    )
    with pytest.raises(RunnerBootstrapError, match="manifest is invalid"):
        load_runner_manifest(
            resource_root=root,
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runner_id", "another-runner.v1"),
        ("runner_version", "0.2.0"),
        ("action_sdk_version", "bluefire.runner-action-sdk.v2"),
        ("receipt_protocol", "bluefire.runner-receipt-wal.v1"),
        ("platform", "linux"),
    ],
)
def test_inventory_must_match_manifest_compatibility(field: str, value: str) -> None:
    with pytest.raises(RunnerBootstrapError, match="incompatibility"):
        validate_runner_inventory(_inventory(**{field: value}), _manifest())


def test_environment_override_is_explicit_and_sandbox_still_has_managed_fallback(
    tmp_path: Path,
) -> None:
    override = tmp_path / FILENAME
    override.write_bytes(_fake_pe())

    result = bootstrap_runner(
        environ={RUNNER_BINARY_ENV: str(override)},
        managed_root=tmp_path / "managed",
        product_version=PRODUCT_VERSION,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        inventory_probe=lambda binary: (
            _inventory() if binary == override.resolve(strict=True) else {}
        ),
    )

    assert result.source == "environment_override"
    assert result.managed_binary is False
    assert result.binary_path == override.resolve(strict=True)
    assert result.managed_sandbox is True
    assert result.public_status()["artifact"]["wheel_platform_tag"] is None
    assert str(override) not in json.dumps(result.public_status())


def test_environment_sandbox_override_remains_an_advanced_unmanaged_path(
    tmp_path: Path,
) -> None:
    resources = _resource_root(tmp_path)
    sandbox = tmp_path / "operator-sandbox"

    result = bootstrap_runner(
        environ={SANDBOX_ROOT_ENV: str(sandbox)},
        resource_root=resources,
        managed_root=tmp_path / "managed",
        product_version=PRODUCT_VERSION,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        inventory_probe=lambda _binary: _inventory(),
    )

    assert result.sandbox_path == sandbox.resolve(strict=True)
    assert result.managed_sandbox is False
    assert str(sandbox) not in json.dumps(result.public_status())


def test_staging_helper_writes_only_verified_platform_specific_assets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"

    manifest = stage_native_runner(
        runner.resolve(),
        output,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        product_version=PRODUCT_VERSION,
        inventory=_inventory(),
    )

    assert manifest.wheel_platform_tag == WHEEL_TAG
    assert (output / FILENAME).read_bytes() == runner.read_bytes()
    assert json.loads((output / MANIFEST_FILENAME).read_text(encoding="utf-8")) == (
        manifest.to_dict()
    )
    assert not list(output.glob("*.tmp"))


def test_staging_refuses_mislabeled_executable_architecture(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe(architecture="aarch64"))

    with pytest.raises(RunnerBootstrapError, match="staging input"):
        stage_native_runner(
            runner.resolve(),
            tmp_path / "stage",
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )
