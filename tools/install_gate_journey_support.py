"""Isolated process and validation support for the Gate 01 wheel journey."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

PROFILE_ID = "sandbox-restricted-owned.v1"
SCENARIO_ID = "scenario.restricted.persistence-canary.v1"
COLLECTOR_ID = "collector.filesystem.sandbox.v1"
RUNNER_ID = "bluefire-rust-runner.v1"
SCOPE = {"scope_refs": ["sandbox.workspace"]}
CANARY_PATH = "restricted/persistence-marker.json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPROVAL_FIELDS = (
    "state_digest",
    "plan_digest",
    "target_scope_digest",
    "profile_id",
    "maximum_tier",
)
_SEEDED_STEPS = (
    (
        "create_persistence_canary",
        "sandbox.restricted.persistence-marker.v1",
        {"label": "persistence_detection_canary"},
    ),
    ("cleanup_workspace", "sandbox.cleanup.v1", {"verify_removal": True}),
)
_DOM_MARKERS = (
    "Mission control",
    "Design the path. Observe the defense.",
    "Local service ready",
    'href="#/runs"',
    "Behavior contracts",
    "Registered actions",
)
_MAX_DOM_BYTES = 16 * 1024 * 1024


class SupportError(RuntimeError):
    """A bounded, path-free support failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SupportError(code, message)


def _content_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_package_version(distribution_version: str, module_version: str) -> None:
    _require(
        distribution_version == module_version,
        "package_version_mismatch",
        "installed distribution and imported package versions differ",
    )


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kernel32() -> Any:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def attach_process_tree(process: subprocess.Popen[Any]) -> int:
    """Put a just-launched Windows process and future children in a kill-on-close job."""

    _require(
        os.name == "nt", "process_containment_unsupported", "process containment is unavailable"
    )
    _require(
        process.poll() is None, "process_exited_early", "managed process exited before containment"
    )
    kernel = _kernel32()
    handle = kernel.CreateJobObjectW(None, None)
    _require(bool(handle), "process_job_create_failed", "process containment could not be created")
    limits = _ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
    configured = kernel.SetInformationJobObject(
        handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    )
    assigned = configured and kernel.AssignProcessToJobObject(handle, int(process._handle))
    if not assigned:
        kernel.CloseHandle(handle)
        raise SupportError("process_job_assign_failed", "managed process could not be contained")
    return int(handle)


def terminate_process_tree(process: subprocess.Popen[Any], job_handle: int | None) -> None:
    """Terminate an entire contained tree and wait for the parent to settle."""

    if os.name == "nt" and process.poll() is None:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    if job_handle is not None and os.name == "nt":
        kernel = _kernel32()
        kernel.TerminateJobObject(job_handle, 1)
        kernel.CloseHandle(job_handle)
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired as exc:
        raise SupportError(
            "process_tree_survived", "managed process tree did not terminate"
        ) from exc


def remove_ephemeral_tree(path: Path, *, expected_parent: Path) -> None:
    """Delete one exact helper-owned child tree, retrying transient Windows locks."""

    target = path.resolve(strict=False)
    parent = expected_parent.resolve(strict=True)
    _require(
        target != parent and target.is_relative_to(parent),
        "ephemeral_cleanup_scope_invalid",
        "ephemeral cleanup scope is invalid",
    )
    for _attempt in range(30):
        try:
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
            if not os.path.lexists(path):
                return
        except OSError:
            time.sleep(0.1)
    raise SupportError("ephemeral_cleanup_failed", "ephemeral runtime state survived cleanup")


def cleanup_all(
    actions: Sequence[Callable[[], None]],
    *,
    code: str,
    message: str,
) -> None:
    """Attempt every owned cleanup action before reporting one bounded failure."""

    failed = False
    for action in actions:
        try:
            action()
        except Exception:
            failed = True
    if failed:
        raise SupportError(code, message)


def cleanup_journey(
    *,
    probe: tuple[subprocess.Popen[Any], int | None] | None,
    service: tuple[subprocess.Popen[Any], int | None] | None,
    fallback_teardown: Callable[[], None] | None,
    runtime_root: Path,
    expected_parent: Path,
) -> None:
    """Clean every process and runtime tree owned by the installed journey."""

    actions: list[Callable[[], None]] = []
    if probe is not None:
        actions.append(lambda: terminate_process_tree(*probe))
    if fallback_teardown is not None:
        actions.append(fallback_teardown)
    if service is not None:
        actions.append(lambda: terminate_process_tree(*service))
    actions.append(lambda: remove_ephemeral_tree(runtime_root, expected_parent=expected_parent))
    cleanup_all(
        actions,
        code="journey_cleanup_failed",
        message="installed-wheel journey cleanup was incomplete",
    )


def validate_rendered_dom(dom: str) -> None:
    """Require authenticated, API-backed React output absent from the static shell."""

    _require(
        all(marker in dom for marker in _DOM_MARKERS)
        and "Local service unavailable" not in dom
        and "Service unavailable" not in dom
        and "Unexpected Application Error" not in dom,
        "ui_runtime_probe_invalid",
        "packaged UI did not render its authenticated API-backed root route",
    )


def validate_runs_dom(dom: str) -> None:
    """Require the packaged guided Execute route to render through React."""

    _require(
        'aria-label="Guided local Execute"' in dom
        and "Preflight every path. Observe every decision." in dom
        and "Runner ready to approved run" in dom
        and ("Verify &amp; enroll local runner" in dom or "Verify & enroll local runner" in dom)
        and "Unexpected Application Error" not in dom
        and "Service unavailable" not in dom,
        "ui_runs_route_invalid",
        "packaged UI did not render the guided Execute route",
    )


def _seeded_plan_is_valid(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    steps = value.get("steps")
    if (
        value.get("schema_version") != "bluefire.plan.v1"
        or value.get("scenario_id") != SCENARIO_ID
        or value.get("mode") != "execute"
        or value.get("autonomy") != "off"
        or value.get("runner_profile_id") != PROFILE_ID
        or not isinstance(steps, list)
        or len(steps) != len(_SEEDED_STEPS)
    ):
        return False
    return all(
        isinstance(step, Mapping)
        and step.get("step_id") == step_id
        and step.get("behavior_id") == behavior_id
        and step.get("action_id") == behavior_id
        and step.get("parameters") == parameters
        for step, (step_id, behavior_id, parameters) in zip(steps, _SEEDED_STEPS, strict=True)
    )


def _catalog_contract(catalog: Any, kind: str, contract_id: str) -> Mapping[str, Any] | None:
    if not isinstance(catalog, Mapping):
        return None
    rows = catalog.get(kind)
    if not isinstance(rows, list):
        return None
    matches = [row for row in rows if isinstance(row, Mapping) and row.get("id") == contract_id]
    return matches[0] if len(matches) == 1 else None


def _seeded_envelope_is_valid(value: Any, catalog: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping):
        return False
    steps = value.get("steps")
    if (
        value.get("schema_version") != "bluefire.approval-envelope.v1"
        or value.get("scenario_id") != SCENARIO_ID
        or not isinstance(steps, list)
        or len(steps) != len(_SEEDED_STEPS)
    ):
        return False
    for step, (step_id, behavior_id, parameters) in zip(steps, _SEEDED_STEPS, strict=True):
        expected_behavior = _catalog_contract(catalog, "behaviors", behavior_id)
        expected_action = _catalog_contract(catalog, "actions", behavior_id)
        if expected_behavior is None or expected_action is None:
            return False
        if not isinstance(step, Mapping) or step.get("step_id") != step_id:
            return False
        options = step.get("options")
        if not isinstance(options, list) or len(options) != 1:
            return False
        option = options[0]
        if not isinstance(option, Mapping):
            return False
        contract = option.get("contract")
        actions = option.get("actions")
        if (
            option.get("behavior_id") != behavior_id
            or option.get("is_primary") is not True
            or option.get("resolved_parameters") != parameters
            or not isinstance(contract, Mapping)
            or contract.get("id") != behavior_id
            or contract != expected_behavior
            or option.get("contract_digest") != _content_hash(contract)
            or not isinstance(actions, list)
            or len(actions) != 1
            or not isinstance(actions[0], Mapping)
        ):
            return False
        action_contract = actions[0].get("contract")
        if (
            actions[0].get("action_id") != behavior_id
            or not isinstance(action_contract, Mapping)
            or action_contract.get("id") != behavior_id
            or action_contract != expected_action
            or actions[0].get("contract_digest") != _content_hash(action_contract)
        ):
            return False
    return True


def _edge_dom(edge: Path, profile_root: Path, url: str) -> str:
    command = [
        os.fspath(edge),
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-proxy-server",
        f"--user-data-dir={profile_root}",
        "--virtual-time-budget=20000",
        "--dump-dom",
        url,
    ]
    process: subprocess.Popen[bytes] | None = None
    job_handle: int | None = None
    try:
        process = subprocess.Popen(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        job_handle = attach_process_tree(process)
        try:
            stdout, _stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise SupportError(
                "ui_runtime_probe_timeout", "packaged UI runtime probe timed out"
            ) from exc
        _require(
            process.returncode == 0 and 0 < len(stdout) <= _MAX_DOM_BYTES,
            "ui_runtime_probe_failed",
            "packaged UI runtime probe failed",
        )
        try:
            dom = stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SupportError(
                "ui_runtime_dom_invalid", "packaged UI rendered invalid DOM"
            ) from exc
        return dom
    finally:
        if process is not None:
            terminate_process_tree(process, job_handle)


def probe_packaged_ui(port: int, capability: str, profile_root: Path) -> dict[str, Any]:
    """Execute installed UI JavaScript and inspect authenticated root and Runs routes."""

    candidates = (
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
    )
    edge = next(
        (
            root / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            for root in candidates
            if (root / "Microsoft" / "Edge" / "Application" / "msedge.exe").is_file()
        ),
        None,
    )
    _require(
        edge is not None, "ui_runtime_engine_missing", "packaged UI runtime engine is unavailable"
    )
    profile_root.mkdir(parents=False, exist_ok=False)
    try:
        root_dom = _edge_dom(
            edge,
            profile_root,
            f"http://127.0.0.1:{port}/#bluefire-session={capability}",
        )
        validate_rendered_dom(root_dom)
        runs_dom = _edge_dom(edge, profile_root, f"http://127.0.0.1:{port}/#/runs")
        validate_runs_dom(runs_dom)
        return {
            "engine": "edge-headless",
            "browser_sandbox": "disabled-for-ephemeral-probe",
            "network_scope": "loopback-only",
            "javascript_executed": True,
            "authenticated_root_rendered": True,
            "catalog_data_rendered": True,
            "runs_navigation_present": True,
            "runs_route_rendered": True,
            "guided_execute_rendered": True,
        }
    finally:
        remove_ephemeral_tree(profile_root, expected_parent=profile_root.parent)


def validate_preflight(
    value: Mapping[str, Any], catalog: Mapping[str, Any]
) -> tuple[dict[str, str], str]:
    binding = validate_binding(value.get("approval_binding"))
    envelope = value.get("approval_envelope")
    _require(
        value.get("status") == "approval_required"
        and value.get("ready") is False
        and value.get("runner_profile") == PROFILE_ID
        and value.get("scope") == SCOPE
        and value.get("autonomy") == "off"
        and value.get("approval") == "required"
        and value.get("collectors") == [COLLECTOR_ID]
        and value.get("collector_binding")
        == {
            "schema_version": "bluefire.collector-binding.v1",
            "collectors": [COLLECTOR_ID],
            "authority": "declared-per-run-observable-artifacts",
        }
        and _seeded_plan_is_valid(value.get("plan"))
        and binding["plan_digest"] == _content_hash(value["plan"])
        and binding["target_scope_digest"] == _content_hash(SCOPE)
        and _seeded_envelope_is_valid(envelope, catalog),
        "execute_preflight_invalid",
        "seeded Execute preflight approval envelope is invalid",
    )
    envelope_digest = envelope.get("envelope_digest")
    envelope_body = dict(envelope)
    envelope_body.pop("envelope_digest", None)
    _require(
        isinstance(envelope_digest, str)
        and _DIGEST.fullmatch(envelope_digest) is not None
        and envelope_digest == _content_hash(envelope_body),
        "execute_preflight_envelope_invalid",
        "seeded Execute preflight envelope digest is invalid",
    )
    return binding, envelope_digest


def validate_binding(value: Any, *, expected: Mapping[str, str] | None = None) -> dict[str, str]:
    _require(
        isinstance(value, Mapping) and set(value) == set(_APPROVAL_FIELDS),
        "approval_binding_invalid",
        "Execute approval binding has an invalid shape",
    )
    binding = {field: str(value[field]) for field in _APPROVAL_FIELDS}
    _require(
        all(_DIGEST.fullmatch(binding[field]) for field in _APPROVAL_FIELDS[:3])
        and binding["profile_id"] == PROFILE_ID
        and binding["maximum_tier"] == "restricted"
        and (expected is None or binding == dict(expected)),
        "approval_binding_mismatch",
        "Execute approval binding is empty or changed",
    )
    return binding


def validate_approval(
    value: Any,
    *,
    binding: Mapping[str, str],
    status: str,
    approved_by: str | None,
) -> str:
    _require(
        isinstance(value, Mapping), "approval_record_invalid", "approval record is unavailable"
    )
    approval_id = value.get("approval_id")
    _require(
        isinstance(approval_id, str)
        and re.fullmatch(r"approval-[0-9a-f]{32}", approval_id) is not None
        and value.get("status") == status
        and value.get("approved_by") == approved_by
        and "nonce" not in value
        and all(value.get(field) == binding[field] for field in _APPROVAL_FIELDS),
        "approval_record_mismatch",
        "durable approval record is not bound to the exact Execute intent",
    )
    return approval_id


def validate_job_approval_pointers(
    snapshots: Sequence[Mapping[str, Any]], *, job_id: str, approval_id: str
) -> dict[str, Any]:
    _require(
        len(snapshots) == 4,
        "execute_job_pointer_invalid",
        "Execute approval is not cross-bound through every durable job snapshot",
    )
    for index, snapshot in enumerate(snapshots):
        request = snapshot.get("request")
        progress = snapshot.get("progress")
        _require(
            snapshot.get("job_id") == job_id
            and isinstance(request, Mapping)
            and request.get("approval_request_id") == approval_id
            and isinstance(progress, Mapping)
            and (
                "approval_request_id" not in progress
                or progress.get("approval_request_id") == approval_id
            )
            and ("approval_ref" not in progress or progress.get("approval_ref") == approval_id)
            and (index < 2 or progress.get("approval_ref") == approval_id),
            "execute_job_pointer_invalid",
            "Execute approval is not cross-bound through every durable job snapshot",
        )
    return {
        "job_id": job_id,
        "request_approval_id": approval_id,
        "progress_approval_ref": approval_id,
        "snapshot_count": len(snapshots),
        "cross_bound": True,
    }


def validate_fresh_replay_approval(
    source: Any,
    replay: Any,
    source_summary: Mapping[str, Any],
    replay_summary: Mapping[str, Any],
    *,
    source_approval_id: str,
    source_binding: Mapping[str, str],
) -> None:
    source_approval = source.get("approval") if isinstance(source, Mapping) else None
    replay_approval = replay.get("approval") if isinstance(replay, Mapping) else None
    replay_binding = replay_summary.get("approval_binding")
    stable_fields = ("plan_digest", "target_scope_digest", "profile_id", "maximum_tier")
    _require(
        isinstance(source_approval, Mapping)
        and isinstance(replay_approval, Mapping)
        and isinstance(replay_binding, Mapping)
        and source_summary.get("approval_id") == source_approval_id
        and source_approval.get("approval_id") != replay_approval.get("approval_id")
        and all(replay_binding.get(field) == source_binding[field] for field in stable_fields)
        and replay_binding.get("state_digest") != source_binding["state_digest"],
        "replay_approval_reused",
        "Execute replay did not use a fresh context-bound approval",
    )


def assert_canary_absent(sandbox_root: Path, approval_id: str) -> None:
    execution_parent = sandbox_root / ".bluefire-executions"
    workspace = execution_parent / approval_id
    _require(
        sandbox_root.is_absolute()
        and sandbox_root.name == "sandbox"
        and sandbox_root.parent.name == "runtime"
        and sandbox_root.parent.parent.name == "BlueFire Nexus"
        and execution_parent.is_dir()
        and not execution_parent.is_symlink()
        and workspace.is_dir()
        and not workspace.is_symlink()
        and workspace.parent == execution_parent
        and workspace.name == approval_id
        and not os.path.lexists(workspace / Path(CANARY_PATH))
        and not os.path.lexists(workspace / "restricted"),
        "residual_canary_present",
        "restricted persistence canary survived cleanup",
    )


def wait_for_job(
    fetch: Callable[[], Mapping[str, Any]],
    *,
    wanted: str,
    timeout: float,
) -> Mapping[str, Any]:
    deadline = time.monotonic() + timeout
    terminal = {"completed", "failed", "cancelled", "interrupted"}
    while time.monotonic() < deadline:
        job = fetch()
        state = job.get("state")
        if state == wanted:
            return job
        if state in terminal:
            break
        time.sleep(0.2 if wanted == "completed" else 0.1)
    if wanted == "awaiting_approval":
        raise SupportError("approval_gate_missing", "Execute job did not reach its approval gate")
    raise SupportError("job_timeout", "approved Execute job did not settle")


def validate_bundles(runs_dir: Path, run_ids: Sequence[str]) -> None:
    from bluefire.run_store import RunStore

    store = RunStore(runs_dir)
    expected_binding = {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        "acceptance_id": os.environ.get("BLUEFIRE_ACCEPTANCE_ID"),
        "gate_id": os.environ.get("BLUEFIRE_ACCEPTANCE_GATE_ID"),
        "contract_sha256": os.environ.get("BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256"),
        "repository_commit": os.environ.get("BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"),
        "repository_tree": os.environ.get("BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE"),
        "release": os.environ.get("BLUEFIRE_ACCEPTANCE_RELEASE"),
    }
    for run_id in run_ids:
        validation = store.validate_bundle(run_id)
        run = store.get_run(run_id)
        _require(
            validation.get("valid") is True
            and run.get("acceptance_binding") == expected_binding
            and (runs_dir / run_id / "manifest.json").is_file(),
            "run_bundle_invalid",
            "a canonical acceptance-bound run bundle was invalid",
        )


def validate_run(
    run: Mapping[str, Any],
    *,
    sandbox_root: Path,
    approval_binding: Mapping[str, str] | None,
    approved_by: str,
    replay_of: str | None,
) -> dict[str, Any]:
    steps = run.get("steps")
    cleanup = run.get("cleanup")
    lineage = run.get("replay")
    _require(
        run.get("status") == "completed"
        and run.get("mode") == "execute"
        and run.get("autonomy") == "off"
        and run.get("scenario_id") == SCENARIO_ID
        and run.get("runner_profile_id") == PROFILE_ID
        and run.get("authorized_target_scope") == SCOPE
        and run.get("objective_reached") is True
        and isinstance(steps, list)
        and len(steps) == 2
        and all(isinstance(step, Mapping) and step.get("status") == "success" for step in steps)
        and all(
            step.get("step_id") == step_id
            and step.get("behavior_id") == behavior_id
            and step.get("action_id") == behavior_id
            for step, (step_id, behavior_id, _parameters) in zip(steps, _SEEDED_STEPS, strict=True)
        )
        and cleanup == {"attempted": True, "success": True, "outstanding_receipt_count": 0},
        "execute_run_invalid",
        "Execute run did not complete inside its canonical profile and scope",
    )
    actual_binding = validate_binding(
        {field: run.get("approval", {}).get(field) for field in _APPROVAL_FIELDS},
        expected=approval_binding,
    )
    _require(
        _seeded_plan_is_valid(run.get("plan"))
        and _content_hash(run["plan"]) == actual_binding["plan_digest"],
        "execute_plan_binding_invalid",
        "Execute run plan does not match its reviewed approval binding",
    )
    approval_id = validate_approval(
        run.get("approval"),
        binding=actual_binding,
        status="claimed",
        approved_by=approved_by,
    )
    if replay_of is None:
        _require(lineage is None, "source_lineage_invalid", "source run has replay lineage")
    else:
        _require(
            isinstance(lineage, Mapping)
            and lineage.get("source_run_id") == replay_of
            and lineage.get("exact") is True,
            "replay_lineage_invalid",
            "exact replay lineage is invalid",
        )
    observation = _validate_evidence(run, steps)
    assert_canary_absent(sandbox_root, approval_id)
    return {
        "run_id": str(run["run_id"]),
        "status": "completed",
        "objective_reached": True,
        "scenario_id": SCENARIO_ID,
        "runner_profile_id": PROFILE_ID,
        "scope_refs": ["sandbox.workspace"],
        "step_count": len(steps),
        "evidence_provenance": ["executed", "observed"],
        "cleanup": dict(cleanup),
        "approval_id": approval_id,
        "approval_status": "claimed",
        "approval_binding": actual_binding,
        "approval_operator": approved_by,
        "observation": observation,
        "residual_canary_absent": True,
        "replay_source_run_id": replay_of,
    }


def _validate_evidence(
    run: Mapping[str, Any], steps: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    evidence = run.get("evidence")
    records = evidence.get("records") if isinstance(evidence, Mapping) else None
    _require(
        isinstance(records, list)
        and len(records) == 3
        and all(isinstance(row, Mapping) for row in records),
        "execute_evidence_invalid",
        "Execute run does not contain the exact evidence chain",
    )
    executed = next(
        (
            row
            for row in records
            if row.get("provenance") == "executed"
            and row.get("step_id") == "create_persistence_canary"
        ),
        None,
    )
    observed = next((row for row in records if row.get("provenance") == "observed"), None)
    cleaned = next((row for row in records if row.get("step_id") == "cleanup_workspace"), None)
    _require(
        all(isinstance(row, Mapping) for row in (executed, observed, cleaned)),
        "execute_evidence_roles_invalid",
        "Execute evidence roles are incomplete",
    )
    executed_id = executed.get("evidence_id")
    observed_id = observed.get("evidence_id")
    cleaned_id = cleaned.get("evidence_id")
    output = executed.get("content", {}).get("output", {})
    observed_content = observed.get("content", {})
    artifact_digest = output.get("sha256")
    cleanup_output = cleaned.get("content", {}).get("output", {})
    marker = steps[0].get("artifacts", {}).get("marker", {})
    _require(
        all(
            isinstance(evidence_id, str) and evidence_id
            for evidence_id in (executed_id, observed_id, cleaned_id)
        )
        and len({executed_id, observed_id, cleaned_id}) == 3
        and all(record.get("run_id") == run.get("run_id") for record in records)
        and all(record.get("runner_profile_id") == PROFILE_ID for record in records)
        and executed.get("producer") == "bluefire-rust-runner"
        and executed.get("behavior_id") == _SEEDED_STEPS[0][1]
        and executed.get("action_id") == "sandbox.restricted.persistence-marker.v1"
        and output.get("artifact") == CANARY_PATH
        and isinstance(artifact_digest, str)
        and _DIGEST.fullmatch(artifact_digest) is not None
        and observed.get("producer") == COLLECTOR_ID
        and observed.get("action_id") == executed.get("action_id")
        and observed.get("behavior_id") == _SEEDED_STEPS[0][1]
        and observed.get("step_id") == executed.get("step_id")
        and observed.get("parent_evidence_ids") == [executed_id]
        and observed_content.get("artifact_type") == "file_observation"
        and observed_content.get("collector_id") == COLLECTOR_ID
        and observed_content.get("path") == CANARY_PATH
        and observed_content.get("sha256") == artifact_digest[7:]
        and isinstance(observed_content.get("size_bytes"), int)
        and observed_content["size_bytes"] > 0
        and marker.get("path") == CANARY_PATH
        and marker.get("sha256") == artifact_digest
        and steps[0].get("evidence_ids") == [executed_id, observed_id]
        and executed_id != observed_id,
        "observer_lineage_invalid",
        "independent observer evidence is not linked to the executed canary artifact",
    )
    _require(
        cleaned.get("producer") == "bluefire-rust-runner"
        and cleaned.get("provenance") == "executed"
        and cleaned.get("behavior_id") == _SEEDED_STEPS[1][1]
        and cleaned.get("action_id") == "sandbox.cleanup.v1"
        and cleaned.get("parent_evidence_ids") == [executed_id, observed_id]
        and executed_id != observed_id
        and steps[1].get("evidence_ids") == [cleaned_id]
        and cleanup_output.get("verification_performed") is True
        and CANARY_PATH in cleanup_output.get("removed_paths", [])
        and cleanup_output.get("verified_receipts") == 1
        and cleanup_output.get("retained_paths") == []
        and cleanup_output.get("errors") == [],
        "cleanup_evidence_invalid",
        "cleanup evidence does not prove removal of the observed canary",
    )
    return {
        "producer": COLLECTOR_ID,
        "collector_id": COLLECTOR_ID,
        "artifact_path": CANARY_PATH,
        "artifact_digest": artifact_digest,
        "parent_linked": True,
    }
