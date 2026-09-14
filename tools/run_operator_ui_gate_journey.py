"""Fixed-argument helper for producing GATE-08 operator UI evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.operator_ui_journey import (
    HELPER_SCHEMA,
    REPORT_PATHS,
    OperatorUIJourneyError,
    produce_operator_ui_gate_evidence,
)


def _failure(code: str, message: str) -> dict[str, object]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "error_code": code,
        "message": message,
    }


def run_operator_ui_gate_journey(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, object]:
    destination = evidence_dir.resolve(strict=True)
    summary = produce_operator_ui_gate_evidence(repository, destination)
    if any(not (destination / name).is_file() for name in REPORT_PATHS):
        raise OperatorUIJourneyError("GATE-08 evidence producer omitted a required report")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_operator_ui_gate_journey.py")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_operator_ui_gate_journey(args.repository, args.evidence_dir)
        exit_code = 0 if summary.get("status") == "passed" else 1
    except OperatorUIJourneyError as exc:
        summary = _failure("operator_ui_journey_unproven", str(exc))
        exit_code = 1
    except (OSError, RuntimeError, TypeError, ValueError):
        summary = _failure(
            "operator_ui_journey_internal_failure",
            "GATE-08 evidence production failed",
        )
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_operator_ui_gate_journey"]
