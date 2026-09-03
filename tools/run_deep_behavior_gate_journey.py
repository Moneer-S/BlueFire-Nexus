"""Fixed-argument helper for producing GATE-03 behavior-pack evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.deep_behavior_journey import (
    HELPER_SCHEMA,
    JOURNEY_REPORT_PATHS,
    DeepBehaviorJourneyError,
    produce_deep_behavior_gate_evidence,
)


def _failure(code: str, message: str) -> dict[str, object]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "error_code": code,
        "message": message,
    }


def run_deep_behavior_gate_journey(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, object]:
    destination = evidence_dir.resolve(strict=True)
    summary = produce_deep_behavior_gate_evidence(repository, destination)
    if summary.get("status") == "passed" and any(
        not (destination / name).is_file() for name in JOURNEY_REPORT_PATHS
    ):
        raise DeepBehaviorJourneyError("GATE-03 evidence producer omitted a required report")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_deep_behavior_gate_journey.py")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_deep_behavior_gate_journey(args.repository, args.evidence_dir)
        exit_code = (
            0
            if summary.get("status") == "passed" or summary.get("blocking_check") == "linux_primary"
            else 1
        )
    except DeepBehaviorJourneyError as exc:
        summary = _failure("deep_behavior_journey_unproven", str(exc))
        exit_code = 1
    except (OSError, RuntimeError, TypeError, ValueError):
        summary = _failure(
            "deep_behavior_journey_internal_failure",
            "GATE-03 evidence production failed",
        )
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_deep_behavior_gate_journey"]
