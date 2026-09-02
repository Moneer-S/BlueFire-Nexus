"""Verified bootstrap for the platform-native BlueFire runner.

Native artifacts are generated during platform packaging and are never source
fallbacks.  The installed artifact is copied into a private, stable directory
before execution so zipped/importlib resources and package upgrades cannot
silently change the approved executable path.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform
import re
import stat
import tempfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

from .runner_inventory import (
    BUILTIN_RUNNER_ACTION_IDS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
    RUNNER_INVENTORY_SCHEMA_VERSION,
    RunnerInventoryAuthorityError,
    validate_builtin_action_inventory,
)
from .version import __version__
from .windows_owner_acl import WindowsOwnerAclError, apply_owner_private_acl_path

MANIFEST_SCHEMA_VERSION = "bluefire.native-runner-package.v1"
BOOTSTRAP_STATUS_SCHEMA_VERSION = "bluefire.runner-bootstrap-status.v1"
PRODUCT_NAME = "bluefire-nexus"
RUNNER_ID = "bluefire-rust-runner.v1"
INVENTORY_SCHEMA_VERSION = RUNNER_INVENTORY_SCHEMA_VERSION
ACTION_SDK_VERSION = RUNNER_ACTION_SDK_SCHEMA_VERSION
RECEIPT_PROTOCOL_VERSION = "bluefire.runner-receipt-wal.v2"

RUNNER_BINARY_ENV = "BLUEFIRE_RUNNER_BINARY"
SANDBOX_ROOT_ENV = "BLUEFIRE_SANDBOX_ROOT"
MANIFEST_FILENAME = "runner-manifest.json"

_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_RUNNER_BYTES = 128 * 1024 * 1024
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_WHEEL_TAGS = {
    ("windows", "x86_64"): "win_amd64",
    ("windows", "aarch64"): "win_arm64",
    ("linux", "x86_64"): "linux_x86_64",
    ("linux", "aarch64"): "linux_aarch64",
    ("macos", "x86_64"): "macosx_11_0_x86_64",
    ("macos", "aarch64"): "macosx_11_0_arm64",
}


class RunnerBootstrapError(RuntimeError):
    """A deliberately path-free runner bootstrap refusal."""


@dataclass(frozen=True, slots=True)
class RunnerPackageManifest:
    product_version: str
    runner_version: str
    platform: str
    architecture: str
    filename: str
    size: int
    sha256: str
    wheel_platform_tag: str
    runner_id: str = RUNNER_ID
    inventory_schema: str = INVENTORY_SCHEMA_VERSION
    action_sdk_version: str = ACTION_SDK_VERSION
    receipt_protocol: str = RECEIPT_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "product": {"name": PRODUCT_NAME, "version": self.product_version},
            "runner": {
                "id": self.runner_id,
                "version": self.runner_version,
                "inventory_schema": self.inventory_schema,
                "action_sdk_version": self.action_sdk_version,
                "receipt_protocol": self.receipt_protocol,
            },
            "artifact": {
                "filename": self.filename,
                "platform": self.platform,
                "architecture": self.architecture,
                "size": self.size,
                "sha256": self.sha256,
                "wheel_platform_tag": self.wheel_platform_tag,
            },
        }


@dataclass(frozen=True, slots=True, repr=False)
class BootstrappedRunner:
    binary_path: Path
    sandbox_path: Path
    source: str
    managed_binary: bool
    managed_sandbox: bool
    manifest: RunnerPackageManifest
    binary_sha256: str

    def __repr__(self) -> str:
        return (
            "BootstrappedRunner(source="
            f"{self.source!r}, platform={self.manifest.platform!r}, "
            f"architecture={self.manifest.architecture!r})"
        )

    def public_status(self) -> Mapping[str, Any]:
        """Return readiness without local paths or environment values."""

        return {
            "schema_version": BOOTSTRAP_STATUS_SCHEMA_VERSION,
            "state": "ready",
            "source": self.source,
            "platform": self.manifest.platform,
            "architecture": self.manifest.architecture,
            "product_version": self.manifest.product_version,
            "runner": {
                "id": self.manifest.runner_id,
                "version": self.manifest.runner_version,
                "inventory_schema": self.manifest.inventory_schema,
                "action_sdk_version": self.manifest.action_sdk_version,
                "receipt_protocol": self.manifest.receipt_protocol,
            },
            "artifact": {
                "managed": self.managed_binary,
                "size": self.manifest.size,
                "sha256": "sha256:" + self.binary_sha256,
                "wheel_platform_tag": (
                    self.manifest.wheel_platform_tag if self.managed_binary else None
                ),
            },
            "sandbox": {"state": "ready", "managed": self.managed_sandbox},
            "health": {"inventory": "compatible", "integrity": "verified"},
        }


InventoryProbe = Callable[[Path], Mapping[str, Any]]


def current_platform(value: str | None = None) -> str:
    raw = (value or host_platform.system()).strip().casefold()
    aliases = {"win32": "windows", "darwin": "macos"}
    normalized = aliases.get(raw, raw)
    if normalized not in {"windows", "linux", "macos"}:
        raise RunnerBootstrapError("This platform has no compatible packaged runner.")
    return normalized


def current_architecture(value: str | None = None) -> str:
    raw = (value or host_platform.machine()).strip().casefold().replace("-", "_")
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "arm64": "aarch64",
    }
    normalized = aliases.get(raw, raw)
    if normalized not in {"x86_64", "aarch64"}:
        raise RunnerBootstrapError("This architecture has no compatible packaged runner.")
    return normalized


def wheel_platform_tag(platform_name: str, architecture: str) -> str:
    try:
        return _WHEEL_TAGS[(platform_name, architecture)]
    except KeyError as exc:
        raise RunnerBootstrapError("This host has no supported native wheel tag.") from exc


def managed_product_root(
    *,
    environ: Mapping[str, str] | None = None,
    platform_name: str | None = None,
) -> Path:
    """Return a platform-appropriate per-user root without creating it."""

    values = os.environ if environ is None else environ
    system = current_platform(platform_name)
    if system == "windows":
        base = values.get("LOCALAPPDATA", "").strip()
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        return Path(base).expanduser() / "BlueFire Nexus"
    if system == "macos":
        return Path.home() / "Library" / "Application Support" / "BlueFire Nexus"
    base = values.get("XDG_STATE_HOME", "").strip()
    if base:
        return Path(base).expanduser() / "bluefire-nexus"
    return Path.home() / ".local" / "state" / "bluefire-nexus"


def load_runner_manifest(
    *,
    resource_root: Any | None = None,
    product_version: str = __version__,
    platform_name: str | None = None,
    architecture: str | None = None,
) -> RunnerPackageManifest:
    """Load and strictly validate the manifest for this exact host/product."""

    root = files("bluefire.native") if resource_root is None else resource_root
    try:
        payload = root.joinpath(MANIFEST_FILENAME).read_bytes()
    except (AttributeError, OSError) as exc:
        raise RunnerBootstrapError("A compatible packaged runner is not available.") from exc
    if not payload or len(payload) > _MAX_MANIFEST_BYTES:
        raise RunnerBootstrapError("The packaged runner manifest is invalid.")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RunnerBootstrapError("The packaged runner manifest is invalid.") from exc
    return parse_runner_manifest(
        value,
        product_version=product_version,
        platform_name=platform_name,
        architecture=architecture,
    )


def parse_runner_manifest(
    value: Any,
    *,
    product_version: str = __version__,
    platform_name: str | None = None,
    architecture: str | None = None,
) -> RunnerPackageManifest:
    """Validate an already-decoded manifest without accepting extension fields."""

    root = _exact_mapping(value, {"schema_version", "product", "runner", "artifact"})
    product = _exact_mapping(root.get("product"), {"name", "version"})
    runner = _exact_mapping(
        root.get("runner"),
        {"id", "version", "inventory_schema", "action_sdk_version", "receipt_protocol"},
    )
    artifact = _exact_mapping(
        root.get("artifact"),
        {
            "filename",
            "platform",
            "architecture",
            "size",
            "sha256",
            "wheel_platform_tag",
        },
    )
    system = current_platform(platform_name)
    machine = current_architecture(architecture)
    expected_filename = "bluefire-runner.exe" if system == "windows" else "bluefire-runner"
    expected_tag = wheel_platform_tag(system, machine)
    expected = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "product_name": PRODUCT_NAME,
        "product_version": product_version,
        "runner_id": RUNNER_ID,
        "runner_version": product_version,
        "inventory_schema": INVENTORY_SCHEMA_VERSION,
        "action_sdk_version": ACTION_SDK_VERSION,
        "receipt_protocol": RECEIPT_PROTOCOL_VERSION,
        "platform": system,
        "architecture": machine,
        "filename": expected_filename,
        "wheel_platform_tag": expected_tag,
    }
    actual = {
        "schema_version": root.get("schema_version"),
        "product_name": product.get("name"),
        "product_version": product.get("version"),
        "runner_id": runner.get("id"),
        "runner_version": runner.get("version"),
        "inventory_schema": runner.get("inventory_schema"),
        "action_sdk_version": runner.get("action_sdk_version"),
        "receipt_protocol": runner.get("receipt_protocol"),
        "platform": artifact.get("platform"),
        "architecture": artifact.get("architecture"),
        "filename": artifact.get("filename"),
        "wheel_platform_tag": artifact.get("wheel_platform_tag"),
    }
    if actual != expected:
        raise RunnerBootstrapError("The packaged runner is incompatible with this product or host.")
    if not _VERSION.fullmatch(product_version) or not _VERSION.fullmatch(str(runner["version"])):
        raise RunnerBootstrapError("The packaged runner manifest is invalid.")
    size = artifact.get("size")
    digest = artifact.get("sha256")
    if (
        type(size) is not int
        or not 1 <= size <= _MAX_RUNNER_BYTES
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
    ):
        raise RunnerBootstrapError("The packaged runner manifest is invalid.")
    return RunnerPackageManifest(
        product_version=product_version,
        runner_version=str(runner["version"]),
        platform=system,
        architecture=machine,
        filename=expected_filename,
        size=size,
        sha256=digest,
        wheel_platform_tag=expected_tag,
    )


def validate_runner_inventory(
    inventory: Mapping[str, Any],
    manifest: RunnerPackageManifest,
) -> None:
    """Require the running binary to match its packaged compatibility contract."""

    required = {
        "schema_version": manifest.inventory_schema,
        "runner_id": manifest.runner_id,
        "runner_version": manifest.runner_version,
        "action_sdk_version": manifest.action_sdk_version,
        "receipt_protocol": manifest.receipt_protocol,
        "platform": manifest.platform,
    }
    if not isinstance(inventory, Mapping) or any(
        inventory.get(key) != expected for key, expected in required.items()
    ):
        raise RunnerBootstrapError("Runner health verification reported an incompatibility.")
    try:
        validate_builtin_action_inventory(
            inventory,
            required_action_ids=BUILTIN_RUNNER_ACTION_IDS,
            require_exact_catalog=True,
        )
    except RunnerInventoryAuthorityError:
        raise RunnerBootstrapError(
            "Runner health verification returned an invalid inventory."
        ) from None


def bootstrap_runner(
    *,
    environ: Mapping[str, str] | None = None,
    resource_root: Any | None = None,
    managed_root: str | Path | None = None,
    product_version: str = __version__,
    platform_name: str | None = None,
    architecture: str | None = None,
    inventory_probe: InventoryProbe | None = None,
) -> BootstrappedRunner:
    """Resolve an advanced override or install and verify the packaged runner."""

    values = os.environ if environ is None else environ
    system = current_platform(platform_name)
    machine = current_architecture(architecture)
    root = (
        Path(managed_root)
        if managed_root is not None
        else managed_product_root(environ=values, platform_name=system)
    )
    managed = _private_directory(root)
    sandbox_value = values.get(SANDBOX_ROOT_ENV, "").strip()
    if sandbox_value:
        sandbox = _operator_directory(sandbox_value)
        managed_sandbox = False
    else:
        sandbox = _private_child(managed, "sandbox")
        managed_sandbox = True

    override = values.get(RUNNER_BINARY_ENV, "").strip()
    if override:
        binary = _operator_binary(override, system)
        size, digest = _hash_file(binary)
        if not 1 <= size <= _MAX_RUNNER_BYTES:
            raise RunnerBootstrapError("The configured runner binary is invalid.")
        manifest = RunnerPackageManifest(
            product_version=product_version,
            runner_version=product_version,
            platform=system,
            architecture=machine,
            filename=("bluefire-runner.exe" if system == "windows" else "bluefire-runner"),
            size=size,
            sha256=digest,
            wheel_platform_tag=wheel_platform_tag(system, machine),
        )
        source = "environment_override"
        managed_binary = False
    else:
        manifest = load_runner_manifest(
            resource_root=resource_root,
            product_version=product_version,
            platform_name=system,
            architecture=machine,
        )
        resource = (files("bluefire.native") if resource_root is None else resource_root).joinpath(
            manifest.filename
        )
        binary = _install_packaged_runner(resource, manifest, managed)
        digest = manifest.sha256
        source = "packaged"
        managed_binary = True

    if inspect_native_architecture(binary, platform_name=system) != machine:
        raise RunnerBootstrapError("The runner binary architecture is incompatible with this host.")
    probe = inventory_probe or _default_inventory_probe(managed)
    try:
        inventory = probe(binary)
    except RunnerBootstrapError:
        raise
    except Exception as exc:
        raise RunnerBootstrapError("Runner health verification could not be completed.") from exc
    validate_runner_inventory(inventory, manifest)
    final_size, final_digest = _hash_file(binary)
    if final_size != manifest.size or final_digest != digest:
        raise RunnerBootstrapError("Runner integrity changed during health verification.")
    return BootstrappedRunner(
        binary_path=binary,
        sandbox_path=sandbox,
        source=source,
        managed_binary=managed_binary,
        managed_sandbox=managed_sandbox,
        manifest=manifest,
        binary_sha256=final_digest,
    )


def build_runner_manifest(
    artifact: Path,
    *,
    product_version: str,
    platform_name: str,
    architecture: str,
) -> RunnerPackageManifest:
    """Create manifest metadata for a packaging-time, already-built artifact."""

    system = current_platform(platform_name)
    machine = current_architecture(architecture)
    size, digest = _hash_file(artifact)
    expected_name = "bluefire-runner.exe" if system == "windows" else "bluefire-runner"
    if (
        artifact.name != expected_name
        or not _VERSION.fullmatch(product_version)
        or inspect_native_architecture(artifact, platform_name=system) != machine
    ):
        raise RunnerBootstrapError("The native runner staging input is invalid.")
    return RunnerPackageManifest(
        product_version=product_version,
        runner_version=product_version,
        platform=system,
        architecture=machine,
        filename=expected_name,
        size=size,
        sha256=digest,
        wheel_platform_tag=wheel_platform_tag(system, machine),
    )


def inspect_native_architecture(
    artifact: str | Path,
    *,
    platform_name: str | None = None,
) -> str:
    """Return the 64-bit executable architecture from PE, ELF, or Mach-O headers."""

    system = current_platform(platform_name)
    try:
        with Path(artifact).open("rb") as handle:
            header = handle.read(1024 * 1024)
    except OSError as exc:
        raise RunnerBootstrapError("The runner executable format could not be verified.") from exc
    if system == "windows":
        if len(header) < 64 or header[:2] != b"MZ":
            raise RunnerBootstrapError("The runner executable format is invalid.")
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        if pe_offset + 6 > len(header) or header[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise RunnerBootstrapError("The runner executable format is invalid.")
        machine = int.from_bytes(header[pe_offset + 4 : pe_offset + 6], "little")
        architectures = {0x8664: "x86_64", 0xAA64: "aarch64"}
    elif system == "linux":
        if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2:
            raise RunnerBootstrapError("The runner executable format is invalid.")
        byte_order: Literal["little", "big"]
        if header[5] == 1:
            byte_order = "little"
        elif header[5] == 2:
            byte_order = "big"
        else:
            raise RunnerBootstrapError("The runner executable format is invalid.")
        machine = int.from_bytes(header[18:20], byte_order)
        architectures = {62: "x86_64", 183: "aarch64"}
    else:
        if len(header) < 8:
            raise RunnerBootstrapError("The runner executable format is invalid.")
        if header[:4] == b"\xcf\xfa\xed\xfe":
            byte_order = "little"
        elif header[:4] == b"\xfe\xed\xfa\xcf":
            byte_order = "big"
        else:
            raise RunnerBootstrapError("The runner executable format is invalid.")
        machine = int.from_bytes(header[4:8], byte_order)
        architectures = {0x01000007: "x86_64", 0x0100000C: "aarch64"}
    try:
        return architectures[machine]
    except KeyError as exc:
        raise RunnerBootstrapError("The runner executable architecture is unsupported.") from exc


def _install_packaged_runner(
    resource: Any,
    manifest: RunnerPackageManifest,
    managed_root: Path,
) -> Path:
    source_size, source_digest = _hash_resource(resource, manifest.size)
    if source_size != manifest.size or source_digest != manifest.sha256:
        raise RunnerBootstrapError("Packaged runner integrity verification failed.")
    target_root = _private_child(
        managed_root,
        "runner",
        f"{manifest.runner_version}-{manifest.platform}-{manifest.architecture}",
        manifest.sha256,
    )
    target = target_root / manifest.filename
    if target.exists() or _is_link_or_reparse(target):
        if _is_link_or_reparse(target) or not target.is_file():
            raise RunnerBootstrapError("The managed runner executable is unavailable or unsafe.")
        _set_executable_mode(target)
        installed_size, installed_digest = _hash_file(target)
        if installed_size != manifest.size or installed_digest != manifest.sha256:
            raise RunnerBootstrapError("Managed runner integrity verification failed.")
        return target.resolve(strict=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".runner-", suffix=".tmp", dir=target_root)
    temporary = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "wb") as destination, resource.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > manifest.size:
                    raise RunnerBootstrapError("Packaged runner integrity verification failed.")
                digest.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if total != manifest.size or digest.hexdigest() != manifest.sha256:
            raise RunnerBootstrapError("Packaged runner integrity verification failed.")
        _set_executable_mode(temporary)
        try:
            os.link(temporary, target)
        except FileExistsError:
            pass
        _set_executable_mode(target)
        installed_size, installed_digest = _hash_file(target)
        if installed_size != manifest.size or installed_digest != manifest.sha256:
            raise RunnerBootstrapError("Installed runner integrity verification failed.")
        return target.resolve(strict=True)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The packaged runner could not be installed safely.") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _default_inventory_probe(work_root: Path) -> InventoryProbe:
    def probe(binary: Path) -> Mapping[str, Any]:
        from .runner_client import SubprocessRustRunner

        runner = SubprocessRustRunner(
            binary,
            _private_child(work_root, "transport"),
            timeout_seconds=10.0,
            output_limit_bytes=2 * 1024 * 1024,
        )
        return runner.inventory()

    return probe


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _exact_mapping(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerBootstrapError("The packaged runner manifest is invalid.")
    return value


def _hash_resource(resource: Any, expected_size: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    try:
        with resource.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    break
                digest.update(chunk)
    except (AttributeError, OSError) as exc:
        raise RunnerBootstrapError("The packaged runner artifact is unavailable.") from exc
    return total, digest.hexdigest()


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_RUNNER_BYTES:
                    raise RunnerBootstrapError(
                        "The runner binary exceeds the supported size limit."
                    )
                digest.update(chunk)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The runner binary could not be verified.") from exc
    return total, digest.hexdigest()


def _operator_binary(raw: str, platform_name: str) -> Path:
    path = Path(raw).expanduser()
    try:
        if (
            not path.is_absolute()
            or _is_link_or_reparse(path)
            or not path.is_file()
            or (platform_name == "windows" and path.suffix.casefold() != ".exe")
            or (platform_name != "windows" and not os.access(path, os.X_OK))
        ):
            raise RunnerBootstrapError("The configured runner binary is invalid.")
        return path.resolve(strict=True)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The configured runner binary is invalid.") from exc


def _operator_directory(raw: str) -> Path:
    path = Path(raw).expanduser()
    try:
        if not path.is_absolute() or _is_link_or_reparse(path):
            raise RunnerBootstrapError("The configured sandbox root is invalid.")
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir() or not os.access(path, os.W_OK):
            raise RunnerBootstrapError("The configured sandbox root is invalid.")
        return path.resolve(strict=True)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The configured sandbox root is invalid.") from exc


def _private_directory(raw: str | Path) -> Path:
    path = Path(raw).expanduser()
    try:
        if not path.is_absolute() or _is_link_or_reparse(path):
            raise RunnerBootstrapError("The managed runner directory is unavailable or unsafe.")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _is_link_or_reparse(path) or not path.is_dir():
            raise RunnerBootstrapError("The managed runner directory is unavailable or unsafe.")
        resolved = path.resolve(strict=True)
        if os.name == "nt":
            apply_owner_private_acl_path(resolved, directory=True)
        else:
            details = resolved.stat()
            getuid = getattr(os, "getuid", None)
            if callable(getuid) and details.st_uid != getuid():
                raise RunnerBootstrapError(
                    "The managed runner directory is not owned by this user."
                )
            os.chmod(resolved, 0o700)
            if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
                raise RunnerBootstrapError("The managed runner directory permissions are unsafe.")
        return resolved
    except RunnerBootstrapError:
        raise
    except (OSError, WindowsOwnerAclError) as exc:
        raise RunnerBootstrapError(
            "The managed runner directory is unavailable or unsafe."
        ) from exc


def _private_child(root: Path, *segments: str) -> Path:
    current = _private_directory(root)
    try:
        for segment in segments:
            if (
                not segment
                or segment in {".", ".."}
                or Path(segment).name != segment
                or any(
                    character
                    not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                    for character in segment
                )
            ):
                raise RunnerBootstrapError("The managed runner directory is unavailable or unsafe.")
            candidate = current / segment
            if _is_link_or_reparse(candidate):
                raise RunnerBootstrapError("The managed runner directory is unavailable or unsafe.")
            candidate.mkdir(mode=0o700, exist_ok=True)
            if _is_link_or_reparse(candidate) or not candidate.is_dir():
                raise RunnerBootstrapError("The managed runner directory is unavailable or unsafe.")
            resolved = _private_directory(candidate)
            if resolved.parent != current:
                raise RunnerBootstrapError("The managed runner directory is unavailable or unsafe.")
            current = resolved
        return current
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError(
            "The managed runner directory is unavailable or unsafe."
        ) from exc


def _set_executable_mode(path: Path) -> None:
    try:
        if os.name == "nt":
            # Atomic installation temporarily uses a second hard-link name for
            # this exact verified binary before the staging name is removed.
            apply_owner_private_acl_path(path, directory=False, allow_hardlinks=True)
        else:
            os.chmod(path, 0o700)
            if stat.S_IMODE(path.stat().st_mode) != 0o700:
                raise OSError("unsafe executable permissions")
    except (OSError, WindowsOwnerAclError) as exc:
        raise RunnerBootstrapError("The managed runner executable permissions are unsafe.") from exc


def _is_link_or_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if os.name == "nt" and path.exists():
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            return bool(attributes & reparse)
        return False
    except OSError:
        return True


__all__ = [
    "ACTION_SDK_VERSION",
    "BOOTSTRAP_STATUS_SCHEMA_VERSION",
    "BootstrappedRunner",
    "INVENTORY_SCHEMA_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "PRODUCT_NAME",
    "RECEIPT_PROTOCOL_VERSION",
    "RUNNER_BINARY_ENV",
    "RUNNER_ID",
    "RunnerBootstrapError",
    "RunnerPackageManifest",
    "SANDBOX_ROOT_ENV",
    "bootstrap_runner",
    "build_runner_manifest",
    "current_architecture",
    "current_platform",
    "inspect_native_architecture",
    "load_runner_manifest",
    "parse_runner_manifest",
    "validate_runner_inventory",
    "wheel_platform_tag",
]
