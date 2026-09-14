"""Fresh product journeys used by the GATE-12 release-readiness workflow.

The release gate deliberately reuses the maintained GATE-04 and GATE-08
producers instead of inventing a second, weaker product path.  Each producer
writes into its own new directory.  The aggregate report contains only
relative references and is independently revalidated by the parent workflow.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from .defense_frontier import (
    COMPARISON_REPORT,
    produce_defense_frontier_evidence,
)
from .defense_frontier import (
    HELPER_SCHEMA as FRONTIER_HELPER_SCHEMA,
)
from .defense_frontier import (
    JOURNEY_REPORT as FRONTIER_JOURNEY_REPORT,
)
from .defense_frontier import (
    REPORT_PATHS as FRONTIER_REPORT_PATHS,
)
from .operator_ui_journey import (
    HELPER_SCHEMA as OPERATOR_HELPER_SCHEMA,
)
from .operator_ui_journey import (
    JOURNEY_REPORT as OPERATOR_JOURNEY_REPORT,
)
from .operator_ui_journey import (
    REPORT_PATHS as OPERATOR_REPORT_PATHS,
)
from .operator_ui_journey import (
    SCREENSHOT_ARTIFACTS,
    produce_operator_ui_gate_evidence,
)

JOURNEY_REPORT = "gate12-release-journey.json"
JOURNEY_SCHEMA = "bluefire.release-readiness-journey.v1"
HELPER_SCHEMA = "bluefire.gate-12-helper.v1"
REPORT_PATHS = (JOURNEY_REPORT,)

_MAX_REPORT_BYTES = 2 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ReleaseReadinessJourneyError(ValueError):
    """Raised when a fresh release journey cannot be established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseReadinessJourneyError(message)


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        details = path.lstat()
        _require(
            stat.S_ISREG(details.st_mode)
            and not _is_link_or_reparse(path)
            and 0 < details.st_size <= _MAX_REPORT_BYTES,
            "a release subjourney report is absent, unsafe, or unbounded",
        )
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseReadinessJourneyError("a release subjourney report is invalid") from exc
    _require(isinstance(value, Mapping), "a release subjourney report is not an object")
    return dict(value)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(
        path.parent.is_dir() and not path.exists() and len(payload) <= _MAX_REPORT_BYTES,
        "the release journey report path is stale or unbounded",
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "the release journey report write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise ReleaseReadinessJourneyError(
            "the release journey report could not be written"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _prefixed_bundles(report: Mapping[str, Any], prefix: str) -> list[dict[str, str]]:
    raw = report.get("run_bundles")
    rows = raw if isinstance(raw, list) else []
    _require(bool(rows), "a release subjourney omitted run bundles")
    result: list[dict[str, str]] = []
    for item in rows:
        _require(
            isinstance(item, Mapping)
            and set(item) == {"run_id", "path"}
            and isinstance(item.get("run_id"), str)
            and isinstance(item.get("path"), str),
            "a release subjourney run reference is invalid",
        )
        result.append(
            {
                "run_id": str(item["run_id"]),
                "path": f"{prefix}/{item['path']}",
            }
        )
    return result


def produce_release_readiness_evidence(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, Any]:
    """Run fresh defense-frontier and production-browser journeys."""

    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(
        root.is_dir()
        and destination.is_dir()
        and not _is_link_or_reparse(root)
        and not _is_link_or_reparse(destination),
        "GATE-12 journey roots must be regular directories",
    )
    _require(
        not (destination / JOURNEY_REPORT).exists()
        and not (destination / "frontier").exists()
        and not (destination / "operator").exists(),
        "GATE-12 evidence contains stale journey artifacts",
    )

    frontier_root = destination / "frontier"
    operator_root = destination / "operator"
    frontier_root.mkdir(mode=0o700)
    operator_root.mkdir(mode=0o700)

    frontier_summary = produce_defense_frontier_evidence(root, frontier_root)
    _require(
        frontier_summary
        == {
            "schema_version": FRONTIER_HELPER_SCHEMA,
            "status": "passed",
            "reports": list(FRONTIER_REPORT_PATHS),
            "run_count": 3,
        },
        "the fresh defense-frontier subjourney did not complete",
    )
    operator_summary = produce_operator_ui_gate_evidence(root, operator_root)
    _require(
        operator_summary
        == {
            "schema_version": OPERATOR_HELPER_SCHEMA,
            "status": "passed",
            "reports": list(OPERATOR_REPORT_PATHS),
            "run_count": 4,
            "blocking_check": None,
        },
        "the fresh production-browser subjourney did not complete",
    )

    frontier = _read_json(frontier_root / FRONTIER_JOURNEY_REPORT)
    operator = _read_json(operator_root / OPERATOR_JOURNEY_REPORT)
    bundles = [
        *_prefixed_bundles(frontier, "frontier"),
        *_prefixed_bundles(operator, "operator"),
    ]
    run_ids = [item["run_id"] for item in bundles]
    _require(len(run_ids) == len(set(run_ids)) == 7, "fresh release run IDs are not unique")

    report = {
        "schema_version": JOURNEY_SCHEMA,
        "passed": True,
        "journeys": {
            "defense_frontier": {
                "helper_schema": FRONTIER_HELPER_SCHEMA,
                "reports": [f"frontier/{name}" for name in FRONTIER_REPORT_PATHS],
                "comparison_report": f"frontier/{COMPARISON_REPORT}",
                "run_count": 3,
            },
            "production_operator": {
                "helper_schema": OPERATOR_HELPER_SCHEMA,
                "reports": [f"operator/{name}" for name in OPERATOR_REPORT_PATHS],
                "screenshots": [f"operator/{name}" for name in SCREENSHOT_ARTIFACTS],
                "run_count": 4,
            },
        },
        "run_bundles": bundles,
        "production_playwright_specs": ["frontend/tests/e2e/operator-production.spec.ts"],
        "source_checkout_writes": [],
    }
    _write_json(destination / JOURNEY_REPORT, report)
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "passed",
        "reports": list(REPORT_PATHS),
        "run_count": len(run_ids),
        "screenshot_count": len(SCREENSHOT_ARTIFACTS),
        "blocking_check": None,
    }


__all__ = [
    "HELPER_SCHEMA",
    "JOURNEY_REPORT",
    "JOURNEY_SCHEMA",
    "REPORT_PATHS",
    "ReleaseReadinessJourneyError",
    "produce_release_readiness_evidence",
]
