"""Runner-backend abstraction.

Foundation for a future Nexus + authorized lab-runner split. The abstraction
is intentionally narrow: a typed task manifest, a typed task result, a
``RunnerBackend`` protocol that any runner implementation satisfies, and a
``LocalRunner`` that runs tasks in-process (no network, no subprocess).

The package is read-only by design -- nothing in here starts a server,
opens a network socket, spawns a subprocess, or mutates filesystem state
beyond the typed artifacts the task explicitly produces. The runtime
safety model (``src.core.safety``, ``src.core.legacy_controls``) is
unchanged; this package is a planning surface for an eventual lab-runner
deployment, not a runner that takes over the existing
``BlueFireNexus.execute_operation`` path.

What this package will NOT do:

- accept arbitrary command / script / shellcode strings
- spawn subprocesses
- open network sockets
- maintain background state across tasks
- act as a C2 listener / reverse-callback / beacon receiver
- implement a Rust agent (deferred per maintainer direction)
- implement a remote agent / hosted GUI (deferred)

The intent is that a future Nexus operator-console can advertise "runner
backend: local" today; when the eventual authorized lab runner ships, the
operator console swaps the backend without touching any other surface.

Public surface:

- :class:`RunnerBackend` -- runtime-checkable Protocol every backend
  implements.
- :class:`TaskManifest` -- typed, immutable description of a single task
  the operator console would dispatch.
- :class:`TaskResult` -- typed, immutable result the runner returns.
- :class:`LocalRunner` -- the only shipped backend. In-process; no
  network; no subprocess.
- :class:`TaskValidationError` -- raised by ``LocalRunner.accept`` when a
  manifest contains a forbidden field (``command`` / ``script`` /
  ``shellcode`` / ``binary`` / ``exe`` / ``dll``) or fails another
  static validation rule.
- :data:`ALLOWED_TASK_TYPES` -- frozen set of accepted ``task_type``
  values. New types must be added here explicitly.
- :data:`FORBIDDEN_PARAM_KEYS` -- frozen set of parameter keys the
  runner refuses to accept; the typed module-profile abstraction is
  the only sanctioned execution path.
"""

from __future__ import annotations

from .local_runner import LocalRunner
from .manifest import (
    ALLOWED_TASK_TYPES,
    FORBIDDEN_PARAM_KEYS,
    TaskManifest,
    TaskValidationError,
)
from .protocols import RunnerBackend
from .result import TaskResult, TaskStatus

__all__ = [
    "ALLOWED_TASK_TYPES",
    "FORBIDDEN_PARAM_KEYS",
    "LocalRunner",
    "RunnerBackend",
    "TaskManifest",
    "TaskResult",
    "TaskStatus",
    "TaskValidationError",
]
