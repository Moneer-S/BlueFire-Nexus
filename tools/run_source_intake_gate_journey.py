"""Fixed-argument helper for producing GATE-09 source-intake evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.source_intake_journey import (
    BROWSER_INTAKE_ARTIFACT,
    BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    HELPER_SCHEMA,
    INTAKE_ARTIFACT,
    PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    PRODUCT_DB_ARTIFACT,
    REPORT_PATHS,
    SourceIntakeJourneyError,
    produce_source_intake_gate_evidence,
)


def _failure(code: str, message: str) -> dict[str, object]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "error_code": code,
        "message": message,
    }


def run_source_intake_gate_journey(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, object]:
    destination = evidence_dir.resolve(strict=True)
    summary = produce_source_intake_gate_evidence(repository, destination)
    required = (
        *REPORT_PATHS,
        PRODUCT_DB_ARTIFACT,
        INTAKE_ARTIFACT,
        BROWSER_INTAKE_ARTIFACT,
        PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
        BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    )
    if any(not (destination / name).is_file() for name in required):
        raise SourceIntakeJourneyError("GATE-09 evidence producer omitted a required artifact")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_source_intake_gate_journey.py")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_source_intake_gate_journey(args.repository, args.evidence_dir)
        exit_code = 0 if summary.get("status") == "passed" else 1
    except SourceIntakeJourneyError:
        summary = _failure(
            "source_intake_journey_unproven",
            "GATE-09 evidence production did not complete",
        )
        exit_code = 1
    except (OSError, RuntimeError, TypeError, ValueError):
        summary = _failure(
            "source_intake_journey_internal_failure",
            "GATE-09 evidence production failed",
        )
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_source_intake_gate_journey"]
