"""LocalRunner -- the only shipped :class:`RunnerBackend`.

Runs typed module-profile / scenario-step tasks IN-PROCESS. No
subprocess spawn, no network call, no background persistence. The
runner is intentionally a thin shim:

- validates the manifest a second time (defence in depth -- the
  manifest constructor already validates, but the runner's own
  validation captures a future code path that constructs manifests
  without going through ``__post_init__``);
- if the registered module exposes a typed
  ``run_operation(data)``-style entrypoint, dispatches the task
  through it and packages the result as a typed
  :class:`~src.core.runner.result.TaskResult`;
- if the module isn't in the registry (the abstraction is being used
  in a planning / preview context where no real module is wired),
  returns a :class:`TaskStatus.REFUSED` result -- never a synthetic
  success.

The runner does NOT:

- spawn subprocesses (``subprocess.Popen`` etc are not imported here);
- open network sockets;
- wait on background threads (every ``accept`` call returns on the
  caller thread before the function returns);
- persist anything to disk beyond what the dispatched module's
  ``run_operation`` already does.

A future authorized lab runner will satisfy the same Protocol with a
typed RPC channel + a signed task manifest. This module is the
in-process baseline that lets the rest of the system (operator
console, CLI, telemetry) treat "runner backend: X" as a swappable
abstraction today.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, FrozenSet, Mapping, Optional

from .manifest import (
    ALLOWED_TASK_TYPES,
    TaskManifest,
    TaskValidationError,
)
from .result import TaskResult, TaskStatus

LOGGER = logging.getLogger(__name__)


class LocalRunner:
    """In-process runner backend.

    Accepts every task type currently in :data:`ALLOWED_TASK_TYPES`
    -- a future task type would need to be added there explicitly,
    and the runner's :meth:`accept` already routes by ``task_type``,
    so a new type without a code path here returns ``REFUSED`` rather
    than silently no-op.

    ``module_registry`` is a duck-typed mapping (typically
    :func:`src.core.modules.build_runtime_modules`'s output, but any
    ``Mapping[str, ModuleLike]`` works). Dependency-injected so tests
    can construct a fake registry without spinning up the full
    runtime. When ``module_registry`` is ``None`` the runner refuses
    every accept call -- the abstraction is alive but no execution
    surface is wired.
    """

    runner_id: str = "local"
    supported_task_types: FrozenSet[str] = ALLOWED_TASK_TYPES

    def __init__(
        self,
        module_registry: Optional[Mapping[str, Any]] = None,
        *,
        runner_id: Optional[str] = None,
    ) -> None:
        self._registry = module_registry
        if runner_id is not None:
            # Allow operator-side override (e.g. ``"local-windows-host-1"``)
            # while keeping the class default short. Spelled-out
            # runner_id values appear in TaskResult.runner_id and the
            # operator console's runner-backend section, so downstream
            # consumers see a stable label.
            object.__setattr__(self, "runner_id", runner_id)

    def describe(self) -> str:
        """Short prose label for the operator console.

        Mirrors the contract surface in ``RunnerBackend.describe``.
        Stays terse so the operator console renders cleanly in the
        runner-backend section.
        """

        registry_count = (
            len(self._registry) if self._registry is not None else 0
        )
        if registry_count == 0:
            return (
                f"LocalRunner (runner_id={self.runner_id!r}) -- "
                "in-process; no module registry wired (planning-only)."
            )
        return (
            f"LocalRunner (runner_id={self.runner_id!r}) -- "
            f"in-process; {registry_count} registered modules; no "
            "subprocess / no network."
        )

    def accept(self, manifest: TaskManifest) -> TaskResult:
        """Validate ``manifest``, dispatch in-process, return a TaskResult.

        Returns ``TaskStatus.REFUSED`` (rather than raising) for every
        failure mode that doesn't represent a programmer error. That
        keeps the orchestrator's dispatch loop clean: every accept
        call returns a typed result, and a defender reading the
        result alone can see "refusal_reason" without joining tables.
        Validation errors raised by :class:`TaskManifest` itself
        DO bubble up -- those are construction-time errors the caller
        is responsible for handling.
        """

        # Defence in depth: re-validate. The manifest's own
        # ``__post_init__`` already did this; running it again here
        # catches a future code path that constructs manifests
        # without going through dataclass init.
        try:
            self._reject_forbidden_params(manifest)
        except TaskValidationError as exc:
            return self._refused(manifest, str(exc))

        if manifest.task_type not in self.supported_task_types:
            return self._refused(
                manifest,
                f"task_type {manifest.task_type!r} not supported by "
                f"runner_id={self.runner_id!r}; supported: "
                f"{sorted(self.supported_task_types)}",
            )

        if self._registry is None:
            return self._refused(
                manifest,
                "no module registry wired; LocalRunner is in "
                "planning-only mode.",
            )

        module = self._registry.get(manifest.module)
        if module is None:
            return self._refused(
                manifest,
                f"module {manifest.module!r} not in registry; "
                "manifest cannot be dispatched.",
            )

        # Dispatch by task_type. Both currently supported types route
        # to the module's ``run_operation`` entrypoint with the typed
        # params. A future type (e.g. ``policy_check``) gets its own
        # dispatch branch here.
        run_operation = getattr(module, "run_operation", None)
        if not callable(run_operation):
            return self._refused(
                manifest,
                f"module {manifest.module!r} does not expose a "
                "run_operation(data) entrypoint; cannot dispatch.",
            )

        return self._dispatch_run_operation(manifest, run_operation)

    # ------------------------------------------------------------------
    # internals

    def _reject_forbidden_params(self, manifest: TaskManifest) -> None:
        """Belt-and-braces forbidden-params check.

        ``TaskManifest.__post_init__`` already validates this list at
        construction time, but the runner re-checks because:
        (a) callers might subclass ``TaskManifest`` with relaxed init,
        (b) a future serialisation-only path could bypass init,
        (c) it costs nothing.
        """

        from .manifest import FORBIDDEN_PARAM_KEYS

        forbidden_present = sorted(
            set(manifest.params) & FORBIDDEN_PARAM_KEYS
        )
        if forbidden_present:
            raise TaskValidationError(
                f"forbidden param keys present {forbidden_present}; "
                "the typed module-profile path is the only sanctioned "
                "execution surface."
            )

    def _dispatch_run_operation(
        self,
        manifest: TaskManifest,
        run_operation: Any,
    ) -> TaskResult:
        """Call the module's ``run_operation`` and package its output.

        The module's ``run_operation`` is the existing runtime contract
        (see ``src.core.modules`` for the concrete shape). The runner
        does not transform the input ``params`` -- it forwards them
        as the module's ``data`` argument. The module is responsible
        for its own typed-output shape; the runner unpacks
        ``artifacts`` / ``telemetry`` / ``detection_hints`` from the
        returned dict if present, and falls back to empty tuples
        otherwise so a minimal module that only returns
        ``{"status": "ok"}`` still produces a valid TaskResult.
        """

        start = time.perf_counter()
        try:
            payload = run_operation(dict(manifest.params))
        except Exception as exc:  # pragma: no cover - module-specific
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            LOGGER.exception(
                "LocalRunner: run_operation raised on module %s",
                manifest.module,
            )
            return self._failure(manifest, str(exc), elapsed_ms=elapsed_ms)
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        if not isinstance(payload, Mapping):
            return self._failure(
                manifest,
                f"module {manifest.module!r} returned non-mapping "
                f"payload of type {type(payload).__name__}; expected dict",
                elapsed_ms=elapsed_ms,
            )

        artifacts = tuple(self._normalise_rows(payload, "artifacts"))
        telemetry = tuple(self._normalise_rows(payload, "telemetry"))
        detection_hints = tuple(
            self._normalise_rows(payload, "detection_hints")
        )

        # Status: prefer the module's own status field if present;
        # default to SUCCESS. ``failure`` -> FAILURE; anything else
        # falls into PARTIAL.
        status_str = str(payload.get("status", "success")).lower()
        if status_str == "success":
            status = TaskStatus.SUCCESS
        elif status_str in ("failure", "error"):
            status = TaskStatus.FAILURE
        elif status_str == "refused":
            status = TaskStatus.REFUSED
        else:
            status = TaskStatus.PARTIAL

        return TaskResult(
            task_type=manifest.task_type,
            run_id=manifest.run_id,
            step_id=manifest.step_id,
            module=manifest.module,
            profile=manifest.profile,
            mode=manifest.mode,
            platform=manifest.platform,
            runner_id=manifest.runner_id,
            requested_at=manifest.requested_at,
            status=status,
            artifacts=artifacts,
            telemetry=telemetry,
            detection_hints=detection_hints,
            elapsed_ms=elapsed_ms,
            completed_at=datetime.now(timezone.utc).isoformat(),
            error=None,
        )

    @staticmethod
    def _normalise_rows(payload: Mapping[str, Any], key: str) -> list:
        """Pluck a list of mappings out of ``payload[key]``.

        Returns an empty list when ``payload[key]`` is missing /
        ``None`` / non-list. Each row is shallow-copied via ``dict()``
        so the runner's tuple is decoupled from the module's mutable
        list; a downstream module that mutates its own state list
        can't retroactively change the result we already returned.
        """

        rows = payload.get(key)
        if not isinstance(rows, list):
            return []
        return [dict(row) for row in rows if isinstance(row, Mapping)]

    def _refused(self, manifest: TaskManifest, reason: str) -> TaskResult:
        """Build a ``REFUSED`` TaskResult with provenance echoed."""

        return TaskResult(
            task_type=manifest.task_type,
            run_id=manifest.run_id,
            step_id=manifest.step_id,
            module=manifest.module,
            profile=manifest.profile,
            mode=manifest.mode,
            platform=manifest.platform,
            runner_id=manifest.runner_id,
            requested_at=manifest.requested_at,
            status=TaskStatus.REFUSED,
            elapsed_ms=0,
            completed_at=datetime.now(timezone.utc).isoformat(),
            refusal_reason=reason,
        )

    def _failure(
        self,
        manifest: TaskManifest,
        error: str,
        *,
        elapsed_ms: int,
    ) -> TaskResult:
        """Build a ``FAILURE`` TaskResult with provenance echoed."""

        return TaskResult(
            task_type=manifest.task_type,
            run_id=manifest.run_id,
            step_id=manifest.step_id,
            module=manifest.module,
            profile=manifest.profile,
            mode=manifest.mode,
            platform=manifest.platform,
            runner_id=manifest.runner_id,
            requested_at=manifest.requested_at,
            status=TaskStatus.FAILURE,
            elapsed_ms=elapsed_ms,
            completed_at=datetime.now(timezone.utc).isoformat(),
            error=error,
        )


__all__ = ["LocalRunner"]
