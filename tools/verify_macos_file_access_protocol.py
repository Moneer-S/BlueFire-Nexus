"""Verify only the fixed installed Darwin protocol capability."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from bluefire import __version__
from bluefire.macos_file_access_peer import _BSDInfo, _Timebase
from bluefire.runner_bootstrap import (
    inspect_native_architecture,
    load_runner_manifest,
)

TIMEOUT_SECONDS = 5
EXPECTED = {
    "schema_version": "bluefire.macos-file-access-capability.v1",
    "protocol_supported": True,
    "native_backend_available": True,
    "live_ready": False,
    "scope": "protocol_support_only",
    "max_bytes": 1_048_576,
    "max_message": 16_384,
    "max_requests": 64,
    "max_operation_ns": 5_000_000_000,
    "monotonic_clock": "darwin-mach-absolute-ns",
}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def validate_capability(stdout: bytes, stderr: bytes, returncode: int) -> dict[str, Any]:
    if (
        returncode != 0
        or stderr
        or len(stdout) > 4096
        or not stdout.endswith(b"\n")
        or stdout.count(b"\n") != 1
        or stdout[:-1].strip() != stdout[:-1]
    ):
        raise RuntimeError("fixed installed capability command failed")
    value = json.loads(stdout[:-1].decode("utf-8"), object_pairs_hook=_strict_object)
    if (
        type(value) is not dict
        or set(value) != set(EXPECTED)
        or any(
            type(value[key]) is not type(expected) or value[key] != expected
            for key, expected in EXPECTED.items()
        )
    ):
        raise RuntimeError("installed capability contract differs")
    return value


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_ctypes_layout() -> None:
    if (
        platform.system() != "Darwin"
        or platform.machine() != "arm64"
        or sys.byteorder != "little"
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(_BSDInfo) != 136
        or _BSDInfo.start_seconds.offset != 120
        or _BSDInfo.start_microseconds.offset != 128
        or ctypes.sizeof(_Timebase) != 8
        or _Timebase.denom.offset != 4
    ):
        raise RuntimeError("Darwin ctypes ABI layout is unsupported")


def _installed_runner(forbid_root: Path) -> tuple[Path, str, int]:
    from importlib.resources import files

    import bluefire

    package_root = Path(bluefire.__file__).resolve(strict=True).parent
    forbidden = forbid_root.resolve(strict=True)
    if _inside(package_root, forbidden):
        raise RuntimeError("package import came from the checkout")
    resource = files("bluefire.native")
    manifest = load_runner_manifest(
        resource_root=resource,
        product_version=__version__,
        platform_name="macos",
        architecture="aarch64",
    )
    candidate = Path(os.fspath(cast(os.PathLike[str], resource.joinpath(manifest.filename))))
    if candidate.is_symlink():
        raise RuntimeError("packaged native runner is a symlink")
    binary = candidate.resolve(strict=True)
    if not _inside(binary, package_root / "native"):
        raise RuntimeError("packaged native runner escaped its resource directory")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    size = binary.stat().st_size
    if (
        digest != manifest.sha256
        or size != manifest.size
        or inspect_native_architecture(binary, platform_name="macos") != "aarch64"
    ):
        raise RuntimeError("installed native runner failed its manifest")
    return binary, digest, size


def _capability(binary: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(binary), "macos-file-access-capability"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=TIMEOUT_SECONDS,
        check=False,
        shell=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    return validate_capability(result.stdout, result.stderr, result.returncode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _validate_ctypes_layout()
        forbidden = args.forbid_root.resolve(strict=True)
        if _inside(Path(__file__).resolve(strict=True), forbidden):
            raise RuntimeError("verifier ran from the checkout")
        binary, digest, size = _installed_runner(forbidden)
        capability = _capability(binary)
        report = {
            "schema_version": "bluefire.macos-file-access-installed-protocol-check.v1",
            "status": "passed",
            "platform": "macos",
            "architecture": "aarch64",
            "source_checkout_imported": False,
            "native_runner_sha256": digest,
            "native_runner_bytes": size,
            "command": ["bluefire-runner", "macos-file-access-capability"],
            "timeout_seconds": TIMEOUT_SECONDS,
            "capability": capability,
            "scope": "protocol_and_native_abi_support_only",
            "live_file_access_performed": False,
            "file_worker_executed": False,
            "setup_executed": False,
            "account_or_acl_claim": False,
        }
    except Exception as exc:
        report = {
            "schema_version": "bluefire.macos-file-access-installed-protocol-check.v1",
            "status": "failed",
            "error_type": type(exc).__name__,
            "scope": "protocol_and_native_abi_support_only",
            "live_file_access_performed": False,
            "file_worker_executed": False,
            "setup_executed": False,
            "account_or_acl_claim": False,
        }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"status": report["status"], "report": str(args.report)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
