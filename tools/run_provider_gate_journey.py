"""Produce machine-verifiable GATE-02 provider evidence.

This fixed-argument entrypoint composes committed-fixture, source-audit, and real
runner evidence without accepting caller-supplied executable content.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import provider_gate_runtime_evidence as _runtime_evidence
from tools.provider_gate_common import (
    JOURNEY_SCHEMA,
    ProviderGateError,
    _assert_public_report,
    _write_json,
)
from tools.provider_gate_fixture_evidence import _fixture_set, _structural_report
from tools.provider_gate_source_audit import (
    _python_shell_findings as _python_shell_findings,
)
from tools.provider_gate_source_audit import (
    _runner_client_popen_contract as _runner_client_popen_contract,
)
from tools.provider_gate_source_audit import (
    _runner_lifecycle_popen_contract as _runner_lifecycle_popen_contract,
)

BlueFireService = _runtime_evidence.BlueFireService
_runner_context = _runtime_evidence._runner_context


def _journey_report(
    repository: Path,
    evidence_dir: Path,
    index: Mapping[str, Any],
    trusts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return _runtime_evidence._journey_report(
        repository,
        evidence_dir,
        index,
        trusts,
        runner_context=_runner_context,
        service_factory=BlueFireService,
    )


def run_provider_gate_journey(
    repository: Path, evidence_dir: Path
) -> tuple[dict[str, object], dict[str, object]]:
    repository = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    if not destination.is_dir() or destination.is_symlink():
        raise ProviderGateError("provider gate evidence directory is invalid")
    index, trusts, packages = _fixture_set(repository)
    artifact_hex_values = tuple(
        sorted(
            {
                package.provider_artifact_bytes.hex()
                for package in packages.values()
                if package.provider_artifact_bytes is not None
            }
        )
    )
    structural = _structural_report(repository, index, trusts, packages)
    _assert_public_report(structural, artifact_hex_values, "provider structural report")
    _write_json(destination / "provider-structural-report.json", structural)
    if structural["passed"] is not True:
        raise ProviderGateError("provider structural checks failed")
    journey = _journey_report(repository, destination, index, trusts)
    private_store_paths = (
        destination / "provider-product.sqlite3",
        destination / "provider-product.sqlite3-wal",
        destination / "provider-product.sqlite3-shm",
    )
    if any(path.exists() for path in private_store_paths):
        raise ProviderGateError("provider private product store was not removed")
    journey["checks"]["limits_cleanup"]["private_product_store_removed"] = True
    _assert_public_report(journey, artifact_hex_values, "provider journey report")
    _write_json(destination / "provider-journey-report.json", journey)
    if journey["passed"] is not True:
        raise ProviderGateError("provider journey checks failed")
    return structural, journey


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        structural, journey = run_provider_gate_journey(args.repository, args.evidence_dir)
    except Exception as exc:
        if isinstance(exc, ProviderGateError):
            error_code = exc.code
            message = str(exc)
        else:
            error_code = "provider_gate_internal_error"
            message = "provider gate internal failure"
        print(
            json.dumps(
                {
                    "schema_version": JOURNEY_SCHEMA,
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error_code": error_code,
                    "message": message,
                },
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "schema_version": JOURNEY_SCHEMA,
                "status": "passed",
                "structural_checks": sorted(structural["checks"]),
                "journey_checks": sorted(journey["checks"]),
                "run_count": len(journey["run_bundles"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ProviderGateError", "run_provider_gate_journey"]
