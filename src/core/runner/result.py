"""Typed task result returned by a :class:`RunnerBackend`.

Mirrors :class:`~src.core.runner.manifest.TaskManifest` -- every
runner backend returns a :class:`TaskResult` for every manifest it
accepts. The result carries:

- ``status``: one of :class:`TaskStatus`. ``refused`` is reserved for
  manifests the backend rejected after construction (e.g. the runner
  doesn't support the requested platform).
- the original manifest's provenance fields, repeated on the result
  so a defender reading the result alone can correlate it back to the
  manifest without joining tables.
- typed artifacts the runner produced (typed via the existing
  ``ArtifactSpec`` vocabulary in
  :mod:`src.core.modules.contracts`).
- telemetry rows + detection-hint rows the runner emitted.
- elapsed wall-clock time + an optional error message on failure.

The dataclass is frozen so a downstream consumer cannot rewrite the
result. A backend that needs to update fields after construction
returns a new :class:`TaskResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple


class TaskStatus(str, Enum):
    """Canonical task-result status vocabulary.

    Subclassing ``str`` lets the enum serialise to JSON cleanly without
    a custom encoder; ``TaskStatus.SUCCESS == "success"`` is True so
    code that compares against the bare string keeps working.
    """

    # Task accepted and ran to completion.
    SUCCESS = "success"
    # Task accepted but failed during execution.
    FAILURE = "failure"
    # Task accepted, ran, produced partial results.
    PARTIAL = "partial"
    # Task rejected before execution -- the backend refused to run it
    # (e.g. unsupported platform, gate not satisfied). Distinct from
    # "failure" so downstream telemetry can distinguish "code blew up"
    # from "policy refused".
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class TaskResult:
    """Typed, immutable result a :class:`RunnerBackend` returns.

    The field set mirrors the manifest's provenance + the standard
    runtime output shape (artifacts / telemetry / detection_hints /
    elapsed_ms / error). Frozen so a consumer can't silently rewrite
    a result mid-pipeline.
    """

    # --- provenance: echoes the manifest --------------------------
    task_type: str
    run_id: str
    step_id: str
    module: str
    profile: str
    mode: str
    platform: str
    runner_id: str
    requested_at: str

    # --- result -----------------------------------------------------
    status: TaskStatus
    artifacts: Tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    telemetry: Tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    detection_hints: Tuple[Mapping[str, Any], ...] = field(
        default_factory=tuple
    )
    elapsed_ms: int = 0
    completed_at: Optional[str] = None
    error: Optional[str] = None
    refusal_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict of the result.

        Mirrors the dataclass shape exactly. Tuples are converted to
        lists (JSON has no tuple type); the status enum is rendered as
        its string value.
        """

        return {
            "task_type": self.task_type,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "module": self.module,
            "profile": self.profile,
            "mode": self.mode,
            "platform": self.platform,
            "runner_id": self.runner_id,
            "requested_at": self.requested_at,
            "status": self.status.value,
            "artifacts": [dict(a) for a in self.artifacts],
            "telemetry": [dict(t) for t in self.telemetry],
            "detection_hints": [dict(d) for d in self.detection_hints],
            "elapsed_ms": self.elapsed_ms,
            "completed_at": self.completed_at,
            "error": self.error,
            "refusal_reason": self.refusal_reason,
        }

    @property
    def is_success(self) -> bool:
        return self.status == TaskStatus.SUCCESS

    @property
    def is_refused(self) -> bool:
        return self.status == TaskStatus.REFUSED


__all__ = [
    "TaskResult",
    "TaskStatus",
]
