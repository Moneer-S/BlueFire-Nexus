"""Stage one verified Rust runner for a platform-specific BlueFire wheel.

This helper is intentionally explicit: release automation supplies the native
binary, target platform, and architecture, and the helper writes generated
package resources.  It never downloads or builds executable content.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire import __version__
from bluefire.runner_bootstrap import (
    MANIFEST_FILENAME,
    RunnerBootstrapError,
    RunnerPackageManifest,
    build_runner_manifest,
    validate_runner_inventory,
)
from bluefire.runner_client import SubprocessRustRunner
from bluefire.util import canonical_json_bytes


def stage_native_runner(
    runner_binary: str | Path,
    output_root: str | Path,
    *,
    platform_name: str,
    architecture: str,
    product_version: str = __version__,
    inventory: Mapping[str, Any] | None = None,
) -> RunnerPackageManifest:
    """Verify and atomically stage an artifact and its strict manifest."""

    source = Path(runner_binary).expanduser()
    destination_root = Path(output_root).expanduser()
    try:
        if not source.is_absolute() or source.is_symlink() or not source.is_file():
            raise RunnerBootstrapError("The native runner staging input is invalid.")
        source = source.resolve(strict=True)
        destination_root.mkdir(parents=True, exist_ok=True)
        destination_root = destination_root.resolve(strict=True)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The native runner staging location is unavailable.") from exc

    manifest = build_runner_manifest(
        source,
        product_version=product_version,
        platform_name=platform_name,
        architecture=architecture,
    )
    observed_inventory = inventory if inventory is not None else _probe_inventory(source)
    validate_runner_inventory(observed_inventory, manifest)

    artifact_target = destination_root / manifest.filename
    manifest_target = destination_root / MANIFEST_FILENAME
    artifact_temporary = _temporary_path(destination_root, ".native-runner-")
    manifest_temporary = _temporary_path(destination_root, ".native-manifest-")
    try:
        shutil.copyfile(source, artifact_temporary)
        if os.name != "nt":
            os.chmod(artifact_temporary, 0o700)
        staged = _manifest_for_staged_bytes(artifact_temporary, manifest)
        if staged.size != manifest.size or staged.sha256 != manifest.sha256:
            raise RunnerBootstrapError("The staged native runner failed integrity verification.")
        manifest_temporary.write_bytes(canonical_json_bytes(manifest.to_dict()) + b"\n")
        with artifact_temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        with manifest_temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(artifact_temporary, artifact_target)
        os.replace(manifest_temporary, manifest_target)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The native runner could not be staged safely.") from exc
    finally:
        artifact_temporary.unlink(missing_ok=True)
        manifest_temporary.unlink(missing_ok=True)
    return manifest


def _manifest_for_staged_bytes(
    staged_path: Path,
    expected: RunnerPackageManifest,
) -> RunnerPackageManifest:
    import hashlib

    digest = hashlib.sha256()
    size = 0
    with staged_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return RunnerPackageManifest(
        product_version=expected.product_version,
        runner_version=expected.runner_version,
        platform=expected.platform,
        architecture=expected.architecture,
        filename=expected.filename,
        size=size,
        sha256=digest.hexdigest(),
        wheel_platform_tag=expected.wheel_platform_tag,
    )


def _probe_inventory(binary: Path) -> Mapping[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="bluefire-native-stage-") as work_root:
            return SubprocessRustRunner(
                binary,
                work_root,
                timeout_seconds=10.0,
                output_limit_bytes=2 * 1024 * 1024,
            ).inventory()
    except Exception as exc:
        raise RunnerBootstrapError("The native runner inventory could not be verified.") from exc


def _temporary_path(root: Path, prefix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=root)
    os.close(descriptor)
    return Path(name)


def _load_inventory(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerBootstrapError("The supplied runner inventory is invalid.") from exc
    if not isinstance(value, Mapping):
        raise RunnerBootstrapError("The supplied runner inventory is invalid.")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=("windows", "linux", "macos"))
    parser.add_argument("--architecture", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--product-version", default=__version__)
    parser.add_argument("--inventory-json", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = stage_native_runner(
            args.runner,
            args.output_root,
            platform_name=args.platform,
            architecture=args.architecture,
            product_version=args.product_version,
            inventory=(
                _load_inventory(args.inventory_json) if args.inventory_json is not None else None
            ),
        )
    except RunnerBootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(manifest.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
