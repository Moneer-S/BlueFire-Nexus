"""Tests for the runner-backend abstraction.

The runner abstraction is a foundation for a future Nexus + lab-runner
split. These tests pin the contract surface every backend is required
to satisfy:

- typed task-manifest validation (allowed task types, forbidden param
  keys, required provenance fields);
- typed task-result shape (provenance echoed, status enum stable);
- the in-process :class:`LocalRunner`'s dispatch contract (registry-
  miss / non-callable run_operation / non-mapping return / forbidden
  params -> typed REFUSED / FAILURE results, never silent success);
- the no-network / no-subprocess invariant for the LocalRunner path.

A regression on any of these would either weaken the safety surface
(e.g. forbidden param keys silently accepted) or break the swappable-
backend contract the operator-console depends on.
"""

from __future__ import annotations

import sys
from typing import Any, Dict
from unittest.mock import patch

import pytest

from src.core.runner import (
    ALLOWED_TASK_TYPES,
    FORBIDDEN_PARAM_KEYS,
    LocalRunner,
    RunnerBackend,
    TaskManifest,
    TaskResult,
    TaskStatus,
    TaskValidationError,
)
from src.core.runner.manifest import (
    ALLOWED_MODES,
    ALLOWED_PLATFORMS,
    make_manifest,
)


# ---------------------------------------------------------------------------
# Helper: a minimal duck-typed module the LocalRunner can dispatch through
# ---------------------------------------------------------------------------


class _StubModule:
    """Minimal stand-in for a registered module.

    Exposes a ``run_operation(data)`` method that returns a typed
    payload dict. The shape mirrors what runtime modules return so the
    LocalRunner's normalisation paths are exercised.
    """

    def __init__(
        self,
        *,
        status: str = "success",
        artifacts: list | None = None,
        telemetry: list | None = None,
        detection_hints: list | None = None,
        raise_exc: BaseException | None = None,
        return_value: Any = None,
    ) -> None:
        self._status = status
        self._artifacts = artifacts or []
        self._telemetry = telemetry or []
        self._detection_hints = detection_hints or []
        self._raise_exc = raise_exc
        self._return_value = return_value
        self.calls: list[Dict[str, Any]] = []

    def run_operation(self, data: Dict[str, Any]) -> Any:
        self.calls.append(dict(data))
        if self._raise_exc is not None:
            raise self._raise_exc
        if self._return_value is not None:
            return self._return_value
        return {
            "status": self._status,
            "artifacts": self._artifacts,
            "telemetry": self._telemetry,
            "detection_hints": self._detection_hints,
        }


def _valid_manifest(**overrides: Any) -> TaskManifest:
    """Build a minimal-valid manifest; tests override individual fields."""

    defaults: Dict[str, Any] = dict(
        task_type="module_profile",
        run_id="run-1",
        step_id="step-1",
        module="credential_access",
        profile="kerberoast",
        mode="simulate",
        platform="windows",
        runner_id="local",
    )
    defaults.update(overrides)
    return make_manifest(**defaults)


# ---------------------------------------------------------------------------
# TaskManifest validation
# ---------------------------------------------------------------------------


def test_manifest_accepts_minimal_valid_construction() -> None:
    """A manifest with every required field set + an empty ``params``
    constructs cleanly. The dataclass is frozen, so attribute access
    proves the construction completed."""

    manifest = _valid_manifest()
    assert manifest.task_type == "module_profile"
    assert manifest.module == "credential_access"
    assert manifest.profile == "kerberoast"
    assert manifest.mode == "simulate"
    assert manifest.platform == "windows"
    assert manifest.runner_id == "local"
    assert manifest.params == {}
    # requested_at is a stable ISO string.
    assert "T" in manifest.requested_at
    # Frozen contract: assignment raises.
    with pytest.raises(Exception):
        manifest.module = "other"  # type: ignore[misc]


def test_manifest_rejects_unknown_task_type() -> None:
    """A task_type not in ALLOWED_TASK_TYPES is rejected with a
    TaskValidationError. Pin the explicit error type so callers can
    distinguish manifest-validation refusals from runtime exceptions."""

    with pytest.raises(TaskValidationError, match="task_type"):
        _valid_manifest(task_type="run_arbitrary_command")


def test_manifest_rejects_unknown_mode() -> None:
    """``mode`` must be in ALLOWED_MODES."""

    with pytest.raises(TaskValidationError, match="mode"):
        _valid_manifest(mode="production")


def test_manifest_rejects_unknown_platform() -> None:
    """``platform`` must be in ALLOWED_PLATFORMS."""

    with pytest.raises(TaskValidationError, match="platform"):
        _valid_manifest(platform="solaris")


@pytest.mark.parametrize(
    "field_name", ["run_id", "step_id", "module", "profile", "runner_id"]
)
def test_manifest_rejects_empty_provenance_field(field_name: str) -> None:
    """Every provenance string must be non-empty and stripped. Pin
    each field individually so a regression that drops the check on
    one field surfaces as a localised failure."""

    with pytest.raises(TaskValidationError, match=field_name):
        _valid_manifest(**{field_name: ""})
    with pytest.raises(TaskValidationError, match=field_name):
        _valid_manifest(**{field_name: "   "})


@pytest.mark.parametrize("forbidden", sorted(FORBIDDEN_PARAM_KEYS))
def test_manifest_rejects_forbidden_param_keys(forbidden: str) -> None:
    """Every key in FORBIDDEN_PARAM_KEYS is refused at manifest
    construction time. Parametrised over the full set so a future
    addition to FORBIDDEN_PARAM_KEYS gets a regression test for free."""

    with pytest.raises(TaskValidationError, match="forbidden"):
        _valid_manifest(params={forbidden: "doesn't matter"})


def test_manifest_rejects_bytes_param_value() -> None:
    """``params`` must be JSON-serialisable. Bytes are a common
    smuggling shape for raw shellcode / binary blobs and are
    explicitly rejected."""

    with pytest.raises(TaskValidationError, match="bytes"):
        _valid_manifest(params={"target": b"\x90" * 8})


def test_manifest_rejects_callable_param_value() -> None:
    """A callable in ``params`` is a code-execution smuggling shape;
    reject."""

    with pytest.raises(TaskValidationError, match="function"):
        _valid_manifest(params={"target": lambda x: x})


def test_manifest_accepts_nested_typed_params() -> None:
    """Nested mappings + lists of scalars are accepted. Pin the
    happy-path through the recursive validator so an over-strict
    refactor that breaks legitimate nested params surfaces here."""

    manifest = _valid_manifest(
        params={
            "target_subnets": ["10.10.0.0/24", "192.168.50.0/24"],
            "options": {
                "timeout_s": 30,
                "retries": 3,
                "preserve_artifacts": True,
                "label": "lab-only",
            },
        }
    )
    assert manifest.params["target_subnets"][0] == "10.10.0.0/24"


def test_manifest_rejects_non_mapping_params() -> None:
    """``params`` must be a Mapping. A list, tuple, or scalar at the
    top level is a programmer error and raises."""

    with pytest.raises(TaskValidationError, match="Mapping"):
        TaskManifest(
            task_type="module_profile",
            run_id="r",
            step_id="s",
            module="m",
            profile="p",
            mode="simulate",
            platform="any",
            runner_id="local",
            requested_at=TaskManifest.now(),
            params=["not", "a", "mapping"],  # type: ignore[arg-type]
        )


def test_manifest_params_cannot_be_mutated_after_construction() -> None:
    """The caller's mapping is deep-copied + wrapped in a
    ``MappingProxyType`` at construction time, so a mutation on the
    original mapping does not leak through, and a mutation through
    ``manifest.params[...] = ...`` raises. Pin both halves so a
    refactor that drops either guard fails here."""

    original_params = {"target": "lab-host", "nested": {"k": "v"}}
    manifest = _valid_manifest(params=original_params)

    # Mutating the caller's mapping does not change manifest.params.
    original_params["target"] = "production-host"
    original_params["nested"]["k"] = "tampered"
    assert manifest.params["target"] == "lab-host"
    assert manifest.params["nested"]["k"] == "v"

    # Mutating manifest.params directly raises TypeError (read-only proxy).
    with pytest.raises(TypeError):
        manifest.params["target"] = "production-host"  # type: ignore[index]


def test_manifest_params_cannot_smuggle_forbidden_key_post_construction() -> None:
    """A caller cannot bypass forbidden-key validation by mutating
    the original ``params`` mapping after construction. The
    deep-copy + read-only proxy ensures the validated state is the
    permanent state."""

    original_params: dict[str, object] = {"target": "lab-host"}
    manifest = _valid_manifest(params=original_params)
    # Try to inject a forbidden key on the original mapping.
    original_params["command"] = "rm -rf /"
    # The manifest's params do not see the post-construction mutation.
    assert "command" not in manifest.params


def test_manifest_to_dict_roundtrip_includes_every_field() -> None:
    """Pin the JSON-serialisable shape so a future field addition
    that forgets to plumb through ``to_dict`` surfaces here."""

    manifest = _valid_manifest(params={"target": "lab-host"})
    payload = manifest.to_dict()
    expected_fields = {
        "task_type",
        "run_id",
        "step_id",
        "module",
        "profile",
        "mode",
        "platform",
        "requested_at",
        "runner_id",
        "params",
    }
    assert set(payload) == expected_fields
    assert payload["params"] == {"target": "lab-host"}


# ---------------------------------------------------------------------------
# Sanity: ALLOWED_* sets are non-empty + frozen
# ---------------------------------------------------------------------------


def test_allowed_task_types_is_non_empty_frozenset() -> None:
    assert len(ALLOWED_TASK_TYPES) > 0
    assert isinstance(ALLOWED_TASK_TYPES, frozenset)


def test_allowed_modes_match_canonical_mode_names() -> None:
    """The runner's accepted modes MUST stay in lockstep with
    :data:`src.core.modes.MODE_NAMES`. A future mode addition that
    forgets to update :data:`src.core.runner.manifest.ALLOWED_MODES`
    would let manifests slip through with a mode the rest of the
    runtime can't honour."""

    from src.core.modes import MODE_NAMES

    assert ALLOWED_MODES == frozenset(MODE_NAMES)


def test_allowed_platforms_includes_canonical_set() -> None:
    """Pin the supported platforms so a future addition surfaces here."""

    assert {"windows", "linux", "macos", "any"} <= ALLOWED_PLATFORMS


def test_forbidden_param_keys_is_non_empty_and_includes_command() -> None:
    """Spot-check that the forbidden-keys list at minimum captures the
    canonical command / script / shellcode names."""

    assert FORBIDDEN_PARAM_KEYS >= {
        "command",
        "script",
        "shellcode",
        "binary",
        "exe",
        "dll",
    }


# ---------------------------------------------------------------------------
# LocalRunner contract
# ---------------------------------------------------------------------------


def test_local_runner_satisfies_runner_backend_protocol() -> None:
    """LocalRunner satisfies the runtime-checkable RunnerBackend
    protocol so an orchestrator can ``isinstance`` against it."""

    runner = LocalRunner()
    assert isinstance(runner, RunnerBackend)


def test_local_runner_default_runner_id_is_local() -> None:
    runner = LocalRunner()
    assert runner.runner_id == "local"


def test_local_runner_describe_renders_planning_only_when_no_registry() -> None:
    runner = LocalRunner()
    label = runner.describe()
    assert "planning-only" in label
    assert "in-process" in label


def test_local_runner_describe_renders_module_count_when_registry_supplied() -> None:
    runner = LocalRunner({"a": object(), "b": object()})
    label = runner.describe()
    assert "2 registered modules" in label
    assert "no subprocess" in label


def test_local_runner_refuses_when_no_registry_wired() -> None:
    """A LocalRunner with no module registry refuses every accept call
    with REFUSED status (not synthetic SUCCESS). Defender-readable
    refusal_reason."""

    runner = LocalRunner()
    result = runner.accept(_valid_manifest())
    assert isinstance(result, TaskResult)
    assert result.status == TaskStatus.REFUSED
    assert "no module registry" in (result.refusal_reason or "")
    # Provenance echoed.
    assert result.run_id == "run-1"
    assert result.step_id == "step-1"
    assert result.module == "credential_access"


def test_local_runner_refuses_when_module_missing_from_registry() -> None:
    runner = LocalRunner({"discovery": _StubModule()})
    result = runner.accept(_valid_manifest(module="not_in_registry"))
    assert result.status == TaskStatus.REFUSED
    assert "not in registry" in (result.refusal_reason or "")


def test_local_runner_refuses_when_module_lacks_run_operation() -> None:
    """A module without a ``run_operation`` callable cannot be
    dispatched. Refused, not crashed."""

    class _NoRunOperation:
        pass

    runner = LocalRunner({"credential_access": _NoRunOperation()})
    result = runner.accept(_valid_manifest())
    assert result.status == TaskStatus.REFUSED
    assert "run_operation" in (result.refusal_reason or "")


def test_local_runner_dispatches_module_run_operation_with_params() -> None:
    """The runner forwards manifest.params verbatim into the module's
    ``run_operation(data)`` and unpacks the typed-output rows into the
    TaskResult."""

    stub = _StubModule(
        status="success",
        artifacts=[{"type": "ticket", "value": "TGT-1"}],
        telemetry=[{"event": "kerberoast.attempt", "count": 1}],
        detection_hints=[{"rule": "T1558.003"}],
    )
    runner = LocalRunner({"credential_access": stub})
    manifest = _valid_manifest(params={"target_user": "svc-account"})
    result = runner.accept(manifest)

    assert result.status == TaskStatus.SUCCESS
    assert stub.calls == [{"target_user": "svc-account"}]
    assert result.artifacts == ({"type": "ticket", "value": "TGT-1"},)
    assert result.telemetry == ({"event": "kerberoast.attempt", "count": 1},)
    assert result.detection_hints == ({"rule": "T1558.003"},)
    assert result.elapsed_ms >= 0


def test_local_runner_packages_module_failure_status_into_failure_result() -> None:
    """A module returning ``status: failure`` produces TaskStatus.FAILURE."""

    stub = _StubModule(status="failure")
    runner = LocalRunner({"credential_access": stub})
    result = runner.accept(_valid_manifest())
    assert result.status == TaskStatus.FAILURE


def test_local_runner_packages_module_partial_status_into_partial_result() -> None:
    """A module returning anything other than success/failure/error/refused
    rolls up to TaskStatus.PARTIAL so a defender sees something happened."""

    stub = _StubModule(status="partial_success")
    runner = LocalRunner({"credential_access": stub})
    result = runner.accept(_valid_manifest())
    assert result.status == TaskStatus.PARTIAL


def test_local_runner_returns_failure_when_module_returns_non_mapping() -> None:
    """A module that returns something other than a Mapping is a
    contract violation -- runner returns FAILURE with an explanatory
    error, doesn't crash."""

    stub = _StubModule(return_value="not a dict")
    runner = LocalRunner({"credential_access": stub})
    result = runner.accept(_valid_manifest())
    assert result.status == TaskStatus.FAILURE
    assert "non-mapping" in (result.error or "")


def test_local_runner_does_not_import_subprocess_or_socket() -> None:
    """The LocalRunner module must not import subprocess or socket --
    those are the canonical "the runner is doing something it
    shouldn't" smells. Pin the import contract so a future refactor
    that pulls in either gets caught here.

    Inspects the module's globals; doesn't actually exec the runner."""

    import src.core.runner.local_runner as local_runner

    src = local_runner.__dict__
    assert "subprocess" not in src
    assert "socket" not in src
    # Also: the module file's source string must not import either,
    # to catch a path-import ("import subprocess as sp") that would
    # land a binding under a different name.
    import inspect

    text = inspect.getsource(local_runner)
    assert "import subprocess" not in text
    assert "import socket" not in text


def test_local_runner_provenance_is_echoed_on_every_result() -> None:
    """Every TaskResult carries the manifest's provenance fields.
    A result alone lets a defender trace the manifest."""

    stub = _StubModule()
    runner = LocalRunner({"credential_access": stub}, runner_id="local-host-1")
    manifest = _valid_manifest(
        run_id="run-42",
        step_id="step-7",
        profile="ptt",
        mode="emulate",
        platform="linux",
        runner_id="local-host-1",
    )
    result = runner.accept(manifest)
    assert result.run_id == "run-42"
    assert result.step_id == "step-7"
    assert result.profile == "ptt"
    assert result.mode == "emulate"
    assert result.platform == "linux"
    assert result.runner_id == "local-host-1"
    # And the timestamp from the manifest is preserved (so a
    # "requested_at" downstream still represents request time, not
    # completion time -- that's the ``completed_at`` field).
    assert result.requested_at == manifest.requested_at


def test_local_runner_result_runner_id_reflects_backend_not_manifest() -> None:
    """When the manifest's ``runner_id`` and the backend's
    ``runner_id`` differ, the TaskResult ``runner_id`` reflects the
    backend that actually executed the task, not the value the
    operator wrote on the manifest. Pin so a misrouted manifest can
    be attributed to the backend that handled it."""

    stub = _StubModule()
    runner = LocalRunner({"credential_access": stub}, runner_id="actual-backend")
    manifest = _valid_manifest(runner_id="declared-backend")
    result = runner.accept(manifest)
    assert result.runner_id == "actual-backend"


def test_local_runner_result_runner_id_uses_backend_on_refused_path() -> None:
    """The ``REFUSED`` path also reflects the backend's runner_id, not
    the manifest's. The refused-result attribution must be consistent
    with the dispatch-path attribution above."""

    runner = LocalRunner(runner_id="actual-backend")  # no registry
    manifest = _valid_manifest(runner_id="declared-backend")
    result = runner.accept(manifest)
    assert result.is_refused
    assert result.runner_id == "actual-backend"


# ---------------------------------------------------------------------------
# TaskResult shape
# ---------------------------------------------------------------------------


def test_task_result_to_dict_roundtrip_renders_every_field() -> None:
    runner = LocalRunner({"credential_access": _StubModule()})
    result = runner.accept(_valid_manifest())
    payload = result.to_dict()
    expected = {
        "task_type",
        "run_id",
        "step_id",
        "module",
        "profile",
        "mode",
        "platform",
        "runner_id",
        "requested_at",
        "status",
        "artifacts",
        "telemetry",
        "detection_hints",
        "elapsed_ms",
        "completed_at",
        "error",
        "refusal_reason",
    }
    assert set(payload) == expected
    assert payload["status"] == "success"


def test_task_status_enum_serialises_as_string() -> None:
    """TaskStatus subclasses str so JSON serialisation is trivial. Pin
    the contract so a future refactor that breaks the str-subclass
    surface gets caught here."""

    assert TaskStatus.SUCCESS == "success"
    assert TaskStatus.REFUSED == "refused"
    assert isinstance(TaskStatus.FAILURE, str)


def test_task_result_is_success_helper() -> None:
    runner = LocalRunner({"credential_access": _StubModule(status="success")})
    result = runner.accept(_valid_manifest())
    assert result.is_success
    assert not result.is_refused


def test_task_result_is_refused_helper() -> None:
    runner = LocalRunner()  # no registry
    result = runner.accept(_valid_manifest())
    assert result.is_refused
    assert not result.is_success
