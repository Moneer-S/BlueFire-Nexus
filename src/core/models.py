"""Core data models for BlueFire-Nexus."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


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
