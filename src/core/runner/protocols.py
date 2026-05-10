"""Runner-backend protocol.

Every concrete runner backend implements :class:`RunnerBackend`. The
protocol is runtime-checkable so an orchestrator can assert at startup
that whatever object it was handed (in-process, future lab-runner,
future authorized-execution-worker) actually conforms.

Method surface intentionally minimal:

- :attr:`runner_id` -- short string identifying the backend (e.g.
  ``"local"`` for the in-process runner). Echoed into every
  :class:`~src.core.runner.result.TaskResult` so a defender reading
  output alone knows which backend produced the rows.
- :attr:`supported_task_types` -- frozen subset of
  :data:`~src.core.runner.manifest.ALLOWED_TASK_TYPES` the backend
  accepts. The orchestrator uses this to dispatch.
- :meth:`accept` -- accept a :class:`TaskManifest`, run it (or refuse),
  and return a :class:`TaskResult`. Backend implementations are
  responsible for echoing the manifest's provenance into the result.
- :meth:`describe` -- short prose label for the operator console.
  Printed in the runner-backend section so the operator sees which
  backend the orchestrator is using right now.

Protocol-only -- this module imports nothing from anywhere except the
typing stdlib so a future `import src.core.runner.protocols` from a
lab-runner subprocess stays cheap.
"""

from __future__ import annotations

from typing import FrozenSet, Protocol, runtime_checkable

from .manifest import TaskManifest
from .result import TaskResult


@runtime_checkable
class RunnerBackend(Protocol):
    """Contract every runner backend implements.

    See module docstring for surface notes. ``runtime_checkable`` so
    the orchestrator can ``isinstance(backend, RunnerBackend)`` --
    handy for guard rails when wiring third-party / future lab-runner
    backends.
    """

    @property
    def runner_id(self) -> str:
        ...

    @property
    def supported_task_types(self) -> FrozenSet[str]:
        ...

    def accept(self, manifest: TaskManifest) -> TaskResult:
        ...

    def describe(self) -> str:
        ...


__all__ = ["RunnerBackend"]
