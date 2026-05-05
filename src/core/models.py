"""Core data models for BlueFire-Nexus."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

LOGGER = logging.getLogger(__name__)

# Allowed module result statuses.
#
# - success:          ran to completion, produced expected artifacts/telemetry.
# - failure:          ran but did not complete the requested operation.
# - blocked:          refused to run because a safety/lab gate is not satisfied.
# - skipped:          intentionally not run (e.g. capability disabled, platform
#                     mismatch, no-op in current mode).
# - partial_success:  produced some telemetry/artifacts but did not complete
#                     every requested step. Real distinct state, not aliased
#                     to "success".
ModuleStatus = Literal["success", "failure", "blocked", "skipped", "partial_success"]
ALLOWED_STATUSES: frozenset[str] = frozenset(
    ("success", "failure", "blocked", "skipped", "partial_success")
)


def utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class TelemetryEvent:
    """A telemetry event emitted by a module execution."""

    event_type: str
    module: str
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    timestamp: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class ModuleResult:
    """Normalized module execution output."""

    status: str
    module: str
    message: str = ""
    techniques: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    telemetry: List[TelemetryEvent] = field(default_factory=list)
    detection_hints: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        # Soft warning only — never raise, to keep forward compatibility for
        # plugin/legacy modules that have not been audited yet. Phase 7 contract
        # tests surface non-conformant statuses as test failures instead.
        if self.status not in ALLOWED_STATUSES:
            LOGGER.warning(
                "ModuleResult for module '%s' uses non-standard status %r; "
                "expected one of %s",
                self.module,
                self.status,
                sorted(ALLOWED_STATUSES),
            )


@dataclass(slots=True)
class RunContext:
    """Execution context shared across module runs."""

    run_id: str
    output_dir: Path
    config: Dict[str, Any]
    dry_run: bool
    max_runtime: int
    allowed_subnets: List[str]
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class RunStep:
    """Single scenario step definition."""

    step_id: str
    name: str
    module: str
    params: Dict[str, Any]


@dataclass(slots=True)
class ScenarioDefinition:
    """Loaded scenario metadata and execution steps."""

    name: str
    description: str
    objective: str
    attack_techniques: List[str]
    expected_detections: List[str]
    fail_fast: bool
    steps: List[RunStep]
