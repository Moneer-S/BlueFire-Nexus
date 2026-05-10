"""Typed task manifest for the runner-backend abstraction.

A :class:`TaskManifest` is the only way an operator-console / orchestrator
hands work to a :class:`~src.core.runner.protocols.RunnerBackend`. The
manifest is intentionally narrow:

- ``task_type`` must be in :data:`ALLOWED_TASK_TYPES`. The catalog is
  closed; a new ``task_type`` requires a code change here AND a code
  change in the runner that handles it.
- ``params`` may not contain any of the keys in
  :data:`FORBIDDEN_PARAM_KEYS`. That set explicitly rejects
  ``command`` / ``script`` / ``shellcode`` / ``binary`` / ``exe`` /
  ``dll`` / ``raw_bytes`` -- the typed module-profile abstraction is
  the only sanctioned execution path. A future runner that wanted
  arbitrary command execution would need to land its own task_type and
  accept the security review that comes with it.
- Provenance fields are mandatory and immutable: ``run_id``, ``step_id``,
  ``module``, ``profile``, ``mode``, ``platform``, ``requested_at``,
  ``runner_id``. Every artifact / telemetry row a backend emits MUST
  echo the manifest's provenance so a defender reconstructing the run
  can correlate output rows back to the manifest that produced them.

This module is offline-only: it never opens a network socket, never
spawns a subprocess, never writes to disk. It is a typed validation
surface for a callable that already exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, Mapping, Optional


# Canonical task-type catalog. The runtime accepts ONLY these types. A
# new task type requires a code change here AND a code change in every
# backend that wants to accept it -- the closed catalog is the
# whole point of the abstraction.
ALLOWED_TASK_TYPES: FrozenSet[str] = frozenset(
    {
        # Run a single registered module's typed profile. The profile
        # name is in ``params["profile"]`` and must match a registered
        # profile in the runtime catalog.
        "module_profile",
        # Run a typed scenario step. Step id + scenario id are in the
        # provenance fields. Used by the future Nexus -> lab-runner
        # split where the operator-console dispatches a scenario step
        # to a separate runner process.
        "scenario_step",
    }
)


# Parameter keys the runner refuses to accept. Spelling out a key here
# is a deliberate "this is not a sanctioned execution path" -- the
# typed module-profile abstraction is the only way a manifest reaches
# real code. Adding a key to this set is a code-review-grade decision.
FORBIDDEN_PARAM_KEYS: FrozenSet[str] = frozenset(
    {
        # Free-form command-string execution. Always forbidden; run a
        # typed module profile instead.
        "command",
        "cmd",
        "command_line",
        "argv",
        # Free-form script-string execution (powershell / python / etc).
        "script",
        "powershell",
        "python_script",
        "bash_script",
        # Shellcode / raw-byte execution. Always forbidden.
        "shellcode",
        "raw_bytes",
        "raw_payload",
        "encoded_payload",
        # Binary-blob deployment. Always forbidden; the typed module
        # profile is the only way to ask for any artifact production.
        "binary",
        "binary_b64",
        "exe",
        "exe_b64",
        "dll",
        "dll_b64",
        # Embedded code-execution constructs.
        "exec",
        "eval",
        "lambda_body",
    }
)


# Canonical mode values the manifest accepts. Must stay in lockstep
# with :data:`src.core.modes.MODE_NAMES`. Re-declared here (rather than
# imported) so the runner package stays import-cheap and circle-free.
ALLOWED_MODES: FrozenSet[str] = frozenset({"simulate", "emulate", "live-lab"})


# Canonical platform values. ``any`` is accepted for cross-platform
# tasks. New platforms get added here explicitly.
ALLOWED_PLATFORMS: FrozenSet[str] = frozenset(
    {"windows", "linux", "macos", "any"}
)


class TaskValidationError(ValueError):
    """Raised when a :class:`TaskManifest` fails static validation.

    The runner backends use this exception type rather than the generic
    ``ValueError`` so a caller can distinguish a manifest-validation
    refusal (this exception) from a runtime error during task
    execution (different exception in the eventual runner code).
    """


@dataclass(frozen=True, slots=True)
class TaskManifest:
    """Typed, immutable description of a single runner task.

    Constructed by the orchestrator / operator console; consumed by a
    :class:`~src.core.runner.protocols.RunnerBackend`. The dataclass is
    frozen so a backend cannot rewrite the manifest mid-flight; every
    backend signs / hashes the manifest as the canonical record of
    what was requested.

    Validation rules (enforced in :meth:`__post_init__`):

    - ``task_type`` must be in :data:`ALLOWED_TASK_TYPES`.
    - ``mode`` must be in :data:`ALLOWED_MODES`.
    - ``platform`` must be in :data:`ALLOWED_PLATFORMS`.
    - ``run_id`` / ``step_id`` / ``module`` / ``profile`` /
      ``runner_id`` are non-empty strings.
    - ``params`` does not contain any key in
      :data:`FORBIDDEN_PARAM_KEYS`.
    - ``params`` is a flat-ish mapping of typed scalars / lists /
      dicts. Bytes / file handles / callables are rejected --
      anything beyond JSON-serialisable values is a code smell that a
      runner is being asked to do something the abstraction does not
      sanction.
    """

    task_type: str
    run_id: str
    step_id: str
    module: str
    profile: str
    mode: str
    platform: str
    requested_at: str
    runner_id: str
    params: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:  # noqa: D401 - dataclass validator
        # Validate by reflecting onto a list of (field, value) pairs.
        # Frozen dataclasses can't mutate attributes, but raising in
        # __post_init__ surfaces validation errors at construction
        # time -- which is exactly when we want them.
        if self.task_type not in ALLOWED_TASK_TYPES:
            raise TaskValidationError(
                f"task_type {self.task_type!r} not in allowed catalog "
                f"{sorted(ALLOWED_TASK_TYPES)}; new types must be added "
                "to ALLOWED_TASK_TYPES explicitly."
            )
        if self.mode not in ALLOWED_MODES:
            raise TaskValidationError(
                f"mode {self.mode!r} not in {sorted(ALLOWED_MODES)}"
            )
        if self.platform not in ALLOWED_PLATFORMS:
            raise TaskValidationError(
                f"platform {self.platform!r} not in "
                f"{sorted(ALLOWED_PLATFORMS)}"
            )
        for prov_key in ("run_id", "step_id", "module", "profile", "runner_id"):
            value = getattr(self, prov_key)
            if not isinstance(value, str) or not value.strip():
                raise TaskValidationError(
                    f"{prov_key} must be a non-empty string; got "
                    f"{value!r}"
                )
        if not isinstance(self.requested_at, str) or not self.requested_at:
            raise TaskValidationError(
                "requested_at must be a non-empty ISO-8601 timestamp string"
            )
        if not isinstance(self.params, Mapping):
            raise TaskValidationError(
                f"params must be a Mapping; got {type(self.params).__name__}"
            )
        forbidden_present = sorted(set(self.params) & FORBIDDEN_PARAM_KEYS)
        if forbidden_present:
            raise TaskValidationError(
                "task manifest rejected: forbidden param keys present "
                f"{forbidden_present}. The typed module-profile path is the "
                "only sanctioned execution surface; arbitrary command / "
                "script / shellcode / binary deployment is out of scope "
                "for the runner abstraction."
            )
        # Strict typed-scalars-only check on params values. Catches
        # bytes, callables, file handles, etc.
        _validate_params_value(self.params, path="params")

    @classmethod
    def now(cls) -> str:
        """Return a UTC ISO-8601 timestamp suitable for ``requested_at``.

        Centralised here so callers don't reinvent the timestamp shape.
        Uses ``datetime.now(timezone.utc).isoformat()`` -- a lab
        runner / Nexus split that compares manifests across processes
        relies on the timestamp shape being stable across all
        producers.
        """

        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict of the manifest.

        Backends use this when persisting / forwarding the manifest.
        Mirrors the dataclass fields exactly so a future
        ``TaskManifest.from_dict`` can be added trivially.
        """

        return {
            "task_type": self.task_type,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "module": self.module,
            "profile": self.profile,
            "mode": self.mode,
            "platform": self.platform,
            "requested_at": self.requested_at,
            "runner_id": self.runner_id,
            "params": dict(self.params),
        }


# JSON-serialisable scalar types accepted in ``params``. Anything else
# is rejected at manifest construction time. Mappings + sequences of
# these are also OK (recursively).
_ALLOWED_SCALARS = (str, int, float, bool, type(None))


def _validate_params_value(value: Any, *, path: str) -> None:
    """Recursively validate a params value tree.

    Accepts: scalars (str/int/float/bool/None), Mappings of str ->
    accepted-value, and lists/tuples of accepted-value. Rejects
    anything else -- bytes, callables, file handles, custom classes
    -- so a backend never has to figure out what to do with an
    unexpected python object. Raises :class:`TaskValidationError` with
    a path that traces the offending nested key for clear diagnostics.
    """

    if isinstance(value, _ALLOWED_SCALARS):
        return
    if isinstance(value, Mapping):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise TaskValidationError(
                    f"{path} keys must be strings; got "
                    f"{type(key).__name__} at {path}"
                )
            _validate_params_value(sub, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, sub in enumerate(value):
            _validate_params_value(sub, path=f"{path}[{index}]")
        return
    raise TaskValidationError(
        f"unsupported param value type at {path}: "
        f"{type(value).__name__}. Only JSON-serialisable scalars / "
        "lists / dicts of strings -> scalars are accepted."
    )


def make_manifest(
    *,
    task_type: str,
    run_id: str,
    step_id: str,
    module: str,
    profile: str,
    mode: str,
    platform: str,
    runner_id: str = "local",
    requested_at: Optional[str] = None,
    params: Optional[Mapping[str, Any]] = None,
) -> TaskManifest:
    """Convenience constructor that fills the timestamp + default runner_id.

    Mirrors :class:`TaskManifest` but with sensible defaults so callers
    that don't care about the exact UTC timestamp can let the helper
    fill it in. Validation is performed by :class:`TaskManifest` --
    the helper does not relax any rule.
    """

    return TaskManifest(
        task_type=task_type,
        run_id=run_id,
        step_id=step_id,
        module=module,
        profile=profile,
        mode=mode,
        platform=platform,
        requested_at=requested_at or TaskManifest.now(),
        runner_id=runner_id,
        params=dict(params or {}),
    )


__all__ = [
    "ALLOWED_MODES",
    "ALLOWED_PLATFORMS",
    "ALLOWED_TASK_TYPES",
    "FORBIDDEN_PARAM_KEYS",
    "TaskManifest",
    "TaskValidationError",
    "make_manifest",
]
