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
        params={
            "path": "fixtures/smoke.jsonl",
            "content_template": "telemetry-seed",
            "record_count": 1,
        },
        filesystem_scope=("fixtures/smoke.jsonl",),
        approval_record=None,
    )
    created = runner.execute(create, profile)
    receipts = created.get("receipt_ids")
    if created.get("status") != "success" or not isinstance(receipts, list) or len(receipts) != 1:
        raise RuntimeError("installed runner did not create a receipt-bound fixture")
    fixture_path = sandbox / "fixtures" / "smoke.jsonl"
    if not fixture_path.is_file():
        raise RuntimeError("installed runner did not create the expected sandbox fixture")
    expected_record = {
        "record_id": "synthetic-001",
        "synthetic": True,
        "template": "telemetry-seed",
        "value": "telemetry-value-001",
    }
    expected_fixture = (
        json.dumps(expected_record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    fixture_bytes = fixture_path.read_bytes()
    create_output = created.get("output")
    if (
        fixture_bytes != expected_fixture
        or not isinstance(create_output, Mapping)
        or set(create_output)
        != {"artifact", "sha256", "size", "template", "record_count", "format"}
        or create_output.get("artifact") != "fixtures/smoke.jsonl"
        or create_output.get("template") != "telemetry-seed"
        or create_output.get("record_count") != 1
        or create_output.get("format") != "jsonl"
        or create_output.get("size") != len(expected_fixture)
        or create_output.get("sha256") != hashlib.sha256(expected_fixture).hexdigest()
    ):
        raise RuntimeError("installed runner did not satisfy the fixture-create v2 contract")

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
    cleanup_report = cleaned.get("cleanup")
    requested_receipts = (
        cleanup_report.get("requested_receipts") if isinstance(cleanup_report, Mapping) else None
    )
    verified_receipts = (
        cleanup_report.get("verified_receipts") if isinstance(cleanup_report, Mapping) else None
    )
    if (
        cleaned.get("status") != "success"
        or not isinstance(cleanup_report, Mapping)
        or cleaned.get("output") != cleanup_report
        or type(requested_receipts) is not int
        or requested_receipts != 1
        or cleanup_report.get("verification_performed") is not True
        or type(verified_receipts) is not int
        or verified_receipts != 1
        or cleanup_report.get("errors") != []
        or cleanup_report.get("retained_paths") != []
        or remaining_files
    ):
        raise RuntimeError("installed runner cleanup did not reconcile the sandbox to zero files")

    alias_runner = SubprocessRustRunner(
        bootstrapped.binary_path,
        work_root / "alias-transport",
        timeout_seconds=30.0,
        output_limit_bytes=4 * 1024 * 1024,
    )
    signed_alias = _smoke_signed_package_alias(alias_runner, work_root)

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
            "signed_alias": signed_alias,
            "verified": True,
        },
    )
    return 0


def _smoke_signed_package_alias(runner: Any, work_root: Path) -> Mapping[str, Any]:
    """Activate and Execute one signed logical alias from the installed wheel."""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from bluefire.action_packages import (
        ACTION_PACKAGE_PAYLOAD_SCHEMA,
        ACTION_PROGRAM_ADAPTER,
        ACTION_PROGRAM_SCHEMA,
        build_signed_action_package,
        canonical_public_key_b64u,
    )
    from bluefire.service import BlueFireService

    publisher_id = "bluefire.release-smoke"
    key_id = "wheel-smoke-2026"
    package_id = "bluefire.release-smoke.endpoint-pack"
    behavior_id = "bluefire.release-smoke.endpoint-profile.v1"
    action_id = "bluefire.release-smoke.endpoint-profile-action.v1"
    provenance = {
        "source": "BlueFire installed-wheel verification",
        "reference": "urn:bluefire:wheel-smoke:endpoint-profile:sha256:" + "b" * 64,
        "license": "MIT",
        "derived": False,
        "notes": "Declarative binding to one compiled reviewed native operation.",
    }
    manifest = {
        "package_id": package_id,
        "version": "1.0.0",
        "compatibility": {
            "minimum_bluefire_version": "0.1.0",
            "maximum_bluefire_version_exclusive": "1.0.0",
        },
        "license": {
            "spdx_id": "MIT",
            "notice": "Copyright 2026 BlueFire installed-wheel verification; MIT licensed.",
        },
        "provenance": {
            "publisher_id": publisher_id,
            "source": "BlueFire installed-wheel verification",
            "reference": "urn:bluefire:wheel-smoke:package:1.0.0",
            "revision": "a" * 40,
        },
        "platforms": ["linux", "macos", "windows"],
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "safety_tiers": ["safe"],
        "behavior_ids": [behavior_id],
        "action_ids": [action_id],
    }
    outputs = [
        {
            "name": "system",
            "type": "artifact.endpoint.system-profile.v1",
            "description": "Bounded system profile.",
        }
    ]
    payload = {
        "schema_version": ACTION_PACKAGE_PAYLOAD_SCHEMA,
        "behaviors": [
            {
                "schema_version": "bluefire.behavior.v1",
                "id": behavior_id,
                "title": "Observe bounded endpoint identity",
                "purpose": "Return non-sensitive operating-system and architecture facts.",
                "execution_state": "action",
                "safety_tier": "safe",
                "platforms": ["linux", "macos", "windows"],
                "techniques": ["T1082"],
                "capabilities": ["endpoint.discovery", "system.discovery"],
                "inputs": [],
                "outputs": outputs,
                "parameters": [],
                "action_ids": [action_id],
                "telemetry": ["endpoint.discovery.system_observed"],
                "detection_hints": ["Compare with independent host inventory."],
                "provenance": provenance,
                "limitations": ["Does not inspect accounts, networks, or file content."],
            }
        ],
        "actions": [
            {
                "definition": {
                    "schema_version": "bluefire.action.v1",
                    "id": action_id,
                    "title": "Observe bounded endpoint identity",
                    "purpose": "Use the reviewed compiled system-profile operation.",
                    "safety_tier": "safe",
                    "capabilities": ["endpoint.discovery", "system.discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "inputs": [],
                    "outputs": outputs,
                    "parameters": [],
                    "mutates": False,
                    "cleanup_action_id": None,
                    "provenance": provenance,
                },
                "program": {
                    "schema_version": ACTION_PROGRAM_SCHEMA,
                    "steps": [
                        {
                            "opcode": "endpoint.discovery.system.v1",
                            "adapter": ACTION_PROGRAM_ADAPTER,
                            "constants": {},
                        }
                    ],
                },
            }
        ],
    }
    key = Ed25519PrivateKey.generate()
    envelope = json.loads(
        build_signed_action_package(
            manifest=manifest,
            payload=payload,
            key_id=key_id,
            private_key=key,
        )
    )
    project_root = work_root / "installed-project"
    alias_sandbox = work_root / "alias-sandbox"
    project_root.mkdir()
    alias_sandbox.mkdir()
    service = BlueFireService(
        project_root=project_root,
        runs_dir=work_root / "alias-runs",
        product_db_path=work_root / "alias-product.sqlite3",
        runner_factory=lambda _profile: (runner, alias_sandbox),
    )
    try:
        service.trust_action_package_publisher(
            {
                "publisher_id": publisher_id,
                "key_id": key_id,
                "public_key": canonical_public_key_b64u(key.public_key()),
                "provenance": {
                    "source": "BlueFire installed-wheel verification",
                    "purpose": "wheel-only signed alias acceptance",
                },
                "trusted_by": "wheel-smoke-reviewer",
            }
        )
        service.install_action_package(
            {"envelope": envelope, "installed_by": "wheel-smoke-installer"}
        )
        profile = next(
            item for item in service.config.runner_profiles if item.mode.value == "execute"
        )
        activated = service.activate_action_package(
            package_id,
            "1.0.0",
            {
                "runner_profile_id": profile.id,
                "activated_by": "wheel-smoke-operator",
                "reason": "verify the installed signed alias against the packaged native runner",
            },
        )
        result = service.run(
            {
                "scenario": {
                    "schema_version": "bluefire.scenario.v1",
                    "id": "scenario.installed-wheel.signed-alias.v1",
                    "title": "Installed-wheel signed alias",
                    "purpose": "Execute one signed logical alias through its reviewed opcode.",
                    "start": "observe_system",
                    "steps": [{"id": "observe_system", "behavior_id": behavior_id}],
                    "edges": [],
                    "provenance": {
                        "source": "BlueFire installed-wheel verification",
                        "reference": "scenario.installed-wheel.signed-alias.v1",
                        "license": "MIT",
                        "derived": False,
                        "notes": "No external content.",
                    },
                    "limitations": ["Observes bounded operating-system identity only."],
                },
                "mode": "execute",
                "runner_profile_id": profile.id,
                "autonomy": "off",
                "target_scope": {"scope_refs": list(profile.scope)},
                "approval": {
                    "confirmed": True,
                    "approved_by": "wheel-smoke-reviewer",
                },
            }
        )
    finally:
        service.close()
    step = result["steps"][0]
    binding = step.get("execution_binding")
    alias_remaining_files = [
        str(path.relative_to(alias_sandbox)) for path in alias_sandbox.rglob("*") if path.is_file()
    ]
    if (
        result.get("status") != "completed"
        or result.get("objective_reached") is not True
        or step.get("behavior_id") != behavior_id
        or step.get("action_id") != action_id
        or step.get("status") != "success"
        or not isinstance(binding, Mapping)
        or binding.get("runner_opcode") != "endpoint.discovery.system.v1"
        or activated.get("catalog", {}).get("generation") != 1
        or alias_remaining_files
    ):
        raise RuntimeError(
            "installed signed package alias did not execute exactly: "
            + json.dumps(
                {
                    "result_status": result.get("status"),
                    "objective_reached": result.get("objective_reached"),
                    "step_behavior_id": step.get("behavior_id"),
                    "step_action_id": step.get("action_id"),
                    "step_status": step.get("status"),
                    "step_error": step.get("error"),
                    "step_message": step.get("message"),
                    "runner_opcode": (
                        binding.get("runner_opcode") if isinstance(binding, Mapping) else None
                    ),
                    "catalog_generation": activated.get("catalog", {}).get("generation"),
                    "remaining_files": alias_remaining_files,
                },
                sort_keys=True,
            )
        )
    return {
        "status": "success",
        "catalog_generation": 1,
        "logical_behavior_id": behavior_id,
        "logical_action_id": action_id,
        "runner_opcode": "endpoint.discovery.system.v1",
        "remaining_file_count": 0,
    }


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
