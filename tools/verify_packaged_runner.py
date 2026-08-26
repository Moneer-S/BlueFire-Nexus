"""Inspect a native wheel and smoke its installed Rust runner.

Release CI invokes ``inspect`` before installation and copies this file outside
the checkout before invoking ``smoke`` with the fresh wheel-only interpreter.
The smoke creates one deterministic fixture and then removes it through the
runner's receipt-bound cleanup action.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _exact_mapping(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError("packaged runner manifest has an unsupported shape")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_report(path: Path | None, report: Mapping[str, Any]) -> None:
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(payload, end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    print(payload, end="")


def inspect_wheel(args: argparse.Namespace) -> int:
    wheel_dir = args.wheel_dir.resolve(strict=True)
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel, found {len(wheels)}")
    wheel = wheels[0]
    expected_tag = f"py3-none-{args.wheel_platform_tag}"
    if not wheel.name.endswith(f"-{expected_tag}.whl"):
        raise RuntimeError("wheel filename does not carry the expected platform tag")

    executable_name = "bluefire-runner.exe" if args.platform == "windows" else "bluefire-runner"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        wheel_metadata = [name for name in names if name.endswith(".dist-info/WHEEL")]
        manifests = [
            name for name in names if name.endswith("/bluefire/native/runner-manifest.json")
        ]
        executables = [
            name for name in names if name.endswith(f"/bluefire/native/{executable_name}")
        ]
        if len(wheel_metadata) != 1 or len(manifests) != 1 or len(executables) != 1:
            raise RuntimeError("wheel must contain exactly one metadata file, manifest, and runner")
        metadata = archive.read(wheel_metadata[0]).decode("utf-8")
        if f"Tag: {expected_tag}" not in metadata.splitlines():
            raise RuntimeError("wheel metadata does not carry the expected platform tag")
        if "Root-Is-Purelib: false" not in metadata.splitlines():
            raise RuntimeError("native runner wheel is incorrectly marked as pure Python")

        manifest = _exact_mapping(
            json.loads(
                archive.read(manifests[0]).decode("utf-8"),
                object_pairs_hook=_duplicates_rejected,
            ),
            {"schema_version", "product", "runner", "artifact"},
        )
        product = _exact_mapping(manifest["product"], {"name", "version"})
        runner = _exact_mapping(
            manifest["runner"],
            {
                "id",
                "version",
                "inventory_schema",
                "action_sdk_version",
                "receipt_protocol",
            },
        )
        artifact = _exact_mapping(
            manifest["artifact"],
            {
                "filename",
                "platform",
                "architecture",
                "size",
                "sha256",
                "wheel_platform_tag",
            },
        )
        expected_contract = {
            "schema_version": "bluefire.native-runner-package.v1",
            "product_name": "bluefire-nexus",
            "runner_id": "bluefire-rust-runner.v1",
            "inventory_schema": "bluefire.runner-inventory.v1",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        }
        observed_contract = {
            "schema_version": manifest["schema_version"],
            "product_name": product["name"],
            "runner_id": runner["id"],
            "inventory_schema": runner["inventory_schema"],
            "action_sdk_version": runner["action_sdk_version"],
            "receipt_protocol": runner["receipt_protocol"],
        }
        if observed_contract != expected_contract or product["version"] != runner["version"]:
            raise RuntimeError("packaged runner compatibility contract is invalid")
        expected_artifact = {
            "platform": args.platform,
            "architecture": args.architecture,
            "filename": executable_name,
            "wheel_platform_tag": args.wheel_platform_tag,
        }
        if {key: artifact.get(key) for key in expected_artifact} != expected_artifact:
            raise RuntimeError("packaged runner identity does not match the matrix target")
        executable = archive.read(executables[0])
        if artifact.get("size") != len(executable):
            raise RuntimeError("packaged runner size does not match its manifest")
        executable_digest = hashlib.sha256(executable).hexdigest()
        if artifact.get("sha256") != executable_digest:
            raise RuntimeError("packaged runner digest does not match its manifest")

    _write_report(
        args.report,
        {
            "schema_version": "bluefire.package-inspection.v1",
            "wheel": wheel.name,
            "wheel_sha256": _sha256(wheel),
            "tag": expected_tag,
            "platform": args.platform,
            "architecture": args.architecture,
            "runner": {
                "filename": executable_name,
                "size": len(executable),
                "sha256": executable_digest,
            },
            "verified": True,
        },
    )
    return 0


def smoke_installed_runner(args: argparse.Namespace) -> int:
    # Imports deliberately happen only in smoke mode, under the fresh venv.
    import bluefire
    from bluefire.contracts import ActionDefinition, SafetyTier, SourceProvenance
    from bluefire.runner_bootstrap import bootstrap_runner, current_platform
    from bluefire.runner_client import SubprocessRustRunner
    from bluefire.runner_contracts import build_execution_manifest, seal_profile

    package_path = Path(bluefire.__file__).resolve(strict=True)
    checkout = args.forbid_root.resolve(strict=True)
    try:
        package_path.relative_to(checkout)
    except ValueError:
        pass
    else:
        raise RuntimeError("smoke imported BlueFire from the checkout instead of the wheel")
    if "BLUEFIRE_RUNNER_BINARY" in os.environ or "BLUEFIRE_SANDBOX_ROOT" in os.environ:
        raise RuntimeError("source runner overrides must be absent during installed-wheel smoke")

    work_root = args.work_root.resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    bootstrapped = bootstrap_runner(environ={}, managed_root=work_root / "managed")
    status = bootstrapped.public_status()
    if status.get("state") != "ready" or status.get("source") != "packaged":
        raise RuntimeError("installed runner bootstrap did not reach packaged readiness")

    runner = SubprocessRustRunner(
        bootstrapped.binary_path,
        work_root / "transport",
        timeout_seconds=30.0,
        output_limit_bytes=4 * 1024 * 1024,
    )
    inventory = runner.inventory()
    if inventory.get("runner_id") != "bluefire-rust-runner.v1":
        raise RuntimeError("installed runner returned an unexpected identity")

    sandbox = work_root / "sandbox"
    sandbox.mkdir()
    platform = current_platform()
    limits = {
        "timeout_ms": 10_000,
        "max_stdout_bytes": 64 * 1024,
        "max_stderr_bytes": 64 * 1024,
        "max_artifact_bytes": 1024 * 1024,
        "max_files": 32,
    }
    profile = seal_profile(
        {
            "schema_version": "bluefire.runner-profile.v1",
            "profile_id": "wheel-smoke.v1",
            "runner_id": str(inventory["runner_id"]),
            "platform": platform,
            "sandbox_root": str(sandbox.resolve(strict=True)),
            "allowed_actions": ["sandbox.fixture.create.v1", "sandbox.cleanup.v1"],
            "control_blocked_actions": [],
            "capabilities": ["filesystem_write", "cleanup"],
            "max_safety_tier": "safe",
            "approval_required_at_or_above": None,
            "target_scope": {"filesystem": ["fixtures"], "network": []},
            "limits": limits,
            "policy_digest": "",
        }
    )
    provenance = SourceProvenance(
        source="BlueFire Nexus release verification",
        reference="installed native runner smoke",
        license="MIT",
        derived=False,
    )
    create_action = ActionDefinition(
        schema_version="bluefire.action.v1",
        id="sandbox.fixture.create.v1",
        title="Create smoke fixture",
        purpose="Verify the installed native runner can create one bounded fixture.",
        cleanup_action_id="sandbox.cleanup.v1",
        capabilities=("filesystem.write",),
        safety_tier=SafetyTier.SAFE,
        platforms=(platform,),
        inputs=(),
        outputs=(),
        parameters=(),
        mutates=True,
        provenance=provenance,
    )
    create = build_execution_manifest(
        run_id="run:wheel-smoke",
        step_id="create-fixture",
        behavior_id=create_action.id,
        action=create_action,
        runner_profile=profile,
        params={"path": "fixtures/smoke.txt", "content_template": "telemetry-seed"},
        filesystem_scope=("fixtures/smoke.txt",),
        approval_record=None,
    )
    created = runner.execute(create, profile)
    receipts = created.get("receipt_ids")
    if created.get("status") != "success" or not isinstance(receipts, list) or len(receipts) != 1:
        raise RuntimeError("installed runner did not create a receipt-bound fixture")
    if not (sandbox / "fixtures" / "smoke.txt").is_file():
        raise RuntimeError("installed runner did not create the expected sandbox fixture")

    cleanup_action = ActionDefinition(
        schema_version="bluefire.action.v1",
        id="sandbox.cleanup.v1",
        title="Clean smoke fixture",
        purpose="Verify receipt-bound cleanup with the installed native runner.",
        cleanup_action_id=None,
        capabilities=("filesystem.write", "cleanup"),
        safety_tier=SafetyTier.SAFE,
        platforms=(platform,),
        inputs=(),
        outputs=(),
        parameters=(),
        mutates=True,
        provenance=provenance,
    )
    cleanup = build_execution_manifest(
        run_id="run:wheel-smoke",
        step_id="cleanup-fixture",
        behavior_id=cleanup_action.id,
        action=cleanup_action,
        runner_profile=profile,
        params={"receipt_ids": receipts},
        filesystem_scope=(),
        approval_record=None,
    )
    cleaned = runner.execute(cleanup, profile)
    remaining_files = [path for path in sandbox.rglob("*") if path.is_file()]
    if cleaned.get("status") != "success" or remaining_files:
        raise RuntimeError("installed runner cleanup did not reconcile the sandbox to zero files")

    _write_report(
        args.report,
        {
            "schema_version": "bluefire.installed-wheel-smoke.v1",
            "package_version": bluefire.__version__,
            "bootstrap": status,
            "inventory": {
                "runner_id": inventory.get("runner_id"),
                "runner_version": inventory.get("runner_version"),
                "platform": inventory.get("platform"),
                "action_count": len(inventory.get("actions", [])),
            },
            "execute": {"status": created.get("status"), "receipt_count": len(receipts)},
            "cleanup": {"status": cleaned.get("status"), "remaining_file_count": 0},
            "verified": True,
        },
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Inspect one wheel in a distribution directory")
    inspect.add_argument("--wheel-dir", type=Path, required=True)
    inspect.add_argument("--platform", choices=("windows", "linux", "macos"), required=True)
    inspect.add_argument("--architecture", choices=("x86_64", "aarch64"), required=True)
    inspect.add_argument("--wheel-platform-tag", required=True)
    inspect.add_argument("--report", type=Path)
    inspect.set_defaults(handler=inspect_wheel)

    smoke = commands.add_parser("smoke", help="Bootstrap and execute with an installed wheel")
    smoke.add_argument("--work-root", type=Path, required=True)
    smoke.add_argument("--forbid-root", type=Path, required=True)
    smoke.add_argument("--report", type=Path)
    smoke.set_defaults(handler=smoke_installed_runner)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        print("packaged runner verification failed", file=sys.stderr)
        raise SystemExit(2) from None
