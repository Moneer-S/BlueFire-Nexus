"""Stopped history upgrades use sealed fixtures without launching a runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.runner_lifecycle as lifecycle_module
from bluefire import __version__
from bluefire.config import load_config
from bluefire.registry import load_builtin_registry
from bluefire.runner_bootstrap import (
    BootstrappedRunner,
    RunnerPackageManifest,
    current_architecture,
    current_platform,
    wheel_platform_tag,
)
from bluefire.runner_contracts import (
    build_execution_manifest,
    build_runner_profile,
    seal_manifest,
    seal_profile,
)
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from bluefire.runner_transport import runner_result_namespace_path
from bluefire.runner_trust import load_local_enrollment
from bluefire.util import canonical_json_bytes, content_hash, file_hash
from tests_platform.runner_lifecycle_host_helper import ProcessTestSecretProvider
from tests_platform.test_authenticated_runner_transport import _result
from tests_platform.test_runner_lifecycle import PROFILE_ID, _create_test_ledger

ROOT = Path(__file__).resolve().parents[1]


class _StagedBootstrap:
    """Stage distinct owned byte fixtures; native verification is out of scope."""

    def __init__(self) -> None:
        self.version = "1.0.0"
        self.binaries: dict[str, Path] = {}

    def __call__(self, **values: Any) -> BootstrappedRunner:
        root = Path(values["managed_root"])
        sandbox = root / "sandbox"
        sandbox.mkdir(parents=True, exist_ok=True)
        platform = current_platform(values.get("platform_name"))
        architecture = current_architecture(values.get("architecture"))
        filename = "bluefire-runner.exe" if platform == "windows" else "bluefire-runner"
        binary = root / "runner" / self.version / filename
        binary.parent.mkdir(parents=True, exist_ok=True)
        if not binary.exists():
            binary.write_bytes(f"owned non-executable upgrade fixture {self.version}\n".encode())
        self.binaries[self.version] = binary
        digest = file_hash(binary).removeprefix("sha256:")
        manifest = RunnerPackageManifest(
            product_version=str(values.get("product_version") or __version__),
            runner_version=self.version,
            platform=platform,
            architecture=architecture,
            filename=filename,
            size=binary.stat().st_size,
            sha256=digest,
            wheel_platform_tag=wheel_platform_tag(platform, architecture),
        )
        return BootstrappedRunner(
            binary_path=binary.resolve(strict=True),
            sandbox_path=sandbox.resolve(strict=True),
            source="packaged",
            managed_binary=True,
            managed_sandbox=True,
            manifest=manifest,
            binary_sha256=digest,
        )


@dataclass
class _HistoryFixture:
    lifecycle: ManagedRunnerLifecycle
    factory: _StagedBootstrap
    manifest: dict[str, Any]
    profile: dict[str, Any]
    result_path: Path

    @property
    def old_binary(self) -> Path:
        return self.factory.binaries["1.0.0"]

    def review(self) -> Mapping[str, Any]:
        return self.lifecycle.review_upgrade(allowed_profile_ids=(PROFILE_ID,))

    def apply(self, review: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.lifecycle.bootstrap(
            allowed_profile_ids=(PROFILE_ID,),
            allow_upgrade=True,
            upgrade_review_digest=review["review_digest"],
        )


def _result_filename(task_id: str) -> str:
    return hashlib.sha256(task_id.encode()).hexdigest()[:40] + ".json"


def _replace_execute_documents(history: _HistoryFixture) -> None:
    """Update the outer transport identity while retaining the supplied inner seals."""
    payload = {"manifest": history.manifest, "profile": history.profile}
    request_hash = content_hash(payload)
    task_id = "execute-" + request_hash.removeprefix("sha256:")
    with sqlite3.connect(history.lifecycle.ledger_path) as connection:
        connection.execute(
            "UPDATE transport_tasks SET task_id = ?, request_hash = ?, execute_payload_json = ?",
            (task_id, request_hash, canonical_json_bytes(payload)),
        )
    destination = history.result_path.with_name(_result_filename(task_id))
    if history.result_path.exists() and destination != history.result_path:
        history.result_path.rename(destination)
    history.result_path = destination


@pytest.fixture
def history(tmp_path_factory: pytest.TempPathFactory) -> _HistoryFixture:
    tmp_path = tmp_path_factory.mktemp("h")
    factory = _StagedBootstrap()
    lifecycle = ManagedRunnerLifecycle(
        tmp_path / "managed",
        secret_provider=ProcessTestSecretProvider(),
        bootstrap_factory=factory,
    )
    lifecycle.bootstrap(allowed_profile_ids=(PROFILE_ID,))
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    configured = next(profile for profile in config.runner_profiles if profile.id == PROFILE_ID)
    profile = build_runner_profile(
        configured,
        sandbox_root=lifecycle.runtime_root / "sandbox",
        platform=current_platform(),
    )
    action = load_builtin_registry().get_action("endpoint.discovery.system.v1")
    manifest = build_execution_manifest(
        run_id="run-20260825T120000Z-0123456789abcdef",
        step_id="inspect_system",
        behavior_id=action.id,
        action=action,
        runner_profile=profile,
        params={},
        filesystem_scope=(),
        approval_record=None,
        now=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
    )
    generation = _create_test_ledger(lifecycle, (("execute", "completed", 0),))
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=lifecycle.secret_provider,
    )
    namespace = runner_result_namespace_path(
        lifecycle.ledger_path, enrollment, ledger_generation=generation
    )
    namespace.mkdir(parents=True)
    fixture = _HistoryFixture(lifecycle, factory, manifest, profile, namespace / "placeholder.json")
    _replace_execute_documents(fixture)
    result = _result(manifest, profile)
    with sqlite3.connect(lifecycle.ledger_path) as connection:
        connection.execute(
            "UPDATE transport_tasks SET result_json = ?",
            (canonical_json_bytes({"result": result}),),
        )
    # Native durable results are pretty JSON; equality is over the decoded object.
    fixture.result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    factory.version = "2.0.0"
    return fixture


def _preserved_bytes(history: _HistoryFixture) -> dict[Path, bytes]:
    paths = [history.old_binary, history.lifecycle.ledger_path, history.result_path]
    paths.extend(path for path in history.lifecycle.enrollment_root.rglob("*") if path.is_file())
    return {path: path.read_bytes() for path in paths}


def _assert_review_refused(history: _HistoryFixture) -> None:
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    old_binary = history.old_binary.read_bytes()
    with pytest.raises(RunnerLifecycleError):
        history.review()
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert history.old_binary.read_bytes() == old_binary


def test_review_of_settled_history_does_not_activate_replacement(history: _HistoryFixture) -> None:
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    preserved = _preserved_bytes(history)

    review = history.review()

    assert review["schema_version"] == "bluefire.runner-upgrade-review.v1"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", review["review_digest"])
    assert review["history"]["execute_rows"] == 1
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == preserved
    assert history.lifecycle.status(profile_id=PROFILE_ID)["runner"]["runner_version"] == "1.0.0"
    assert history.factory.binaries["2.0.0"] != history.old_binary


def test_reviewed_upgrade_preserves_binary_history_results_and_enrollment(
    history: _HistoryFixture,
) -> None:
    preserved = _preserved_bytes(history)
    review = history.review()

    result = history.apply(review)

    assert result["runner"]["runner_version"] == "2.0.0"
    assert result["runner"]["binary_digest"] == file_hash(history.factory.binaries["2.0.0"])
    assert _preserved_bytes(history) == preserved
    assert history.lifecycle.status(profile_id=PROFILE_ID)["runner"]["runner_version"] == "2.0.0"


@pytest.mark.parametrize("allow_upgrade", [False, True])
def test_history_upgrade_still_requires_explicit_review_digest(
    history: _HistoryFixture, allow_upgrade: bool
) -> None:
    history.review()
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    preserved = _preserved_bytes(history)

    with pytest.raises(RunnerLifecycleError):
        history.lifecycle.bootstrap(allowed_profile_ids=(PROFILE_ID,), allow_upgrade=allow_upgrade)

    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == preserved


@pytest.mark.parametrize("changed", ["ledger", "result", "old_binary", "replacement_binary"])
def test_review_digest_refuses_changed_history_or_binary(
    history: _HistoryFixture, changed: str
) -> None:
    review = history.review()
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    if changed == "ledger":
        # Same generation, row count and valid terminal state; the snapshot changed.
        with sqlite3.connect(history.lifecycle.ledger_path) as connection:
            connection.execute("UPDATE transport_tasks SET updated_at = updated_at + 1")
    elif changed == "result":
        result = json.loads(history.result_path.read_text(encoding="utf-8"))
        result["output"]["call"] = 2
        history.result_path.write_text(json.dumps(result), encoding="utf-8")
    else:
        binary = (
            history.old_binary if changed == "old_binary" else history.factory.binaries["2.0.0"]
        )
        binary.write_bytes(binary.read_bytes() + b"changed after review\n")
    changed_bytes = _preserved_bytes(history)

    with pytest.raises(RunnerLifecycleError):
        history.apply(review)

    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == changed_bytes


def test_placeholder_execute_row_is_not_accepted_as_settled_history(
    history: _HistoryFixture,
) -> None:
    with sqlite3.connect(history.lifecycle.ledger_path) as connection:
        connection.execute(
            "UPDATE transport_tasks SET execute_payload_json = ?",
            (canonical_json_bytes({"request": 0}),),
        )
    _assert_review_refused(history)


@pytest.mark.parametrize("document", ["manifest", "profile"])
def test_outer_transport_hash_cannot_hide_invalid_internal_seal(
    history: _HistoryFixture, document: str
) -> None:
    if document == "manifest":
        history.manifest["params"]["unreviewed"] = True
    else:
        history.profile["allowed_actions"].append("unreviewed.action.v1")
    _replace_execute_documents(history)

    _assert_review_refused(history)


@pytest.mark.parametrize("changed", ["orphan", "missing"])
def test_settled_history_requires_exact_durable_result_coverage(
    history: _HistoryFixture, changed: str
) -> None:
    if changed == "orphan":
        orphan = history.result_path.with_name("e" * 40 + ".json")
        orphan.write_bytes(history.result_path.read_bytes())
    else:
        history.result_path.unlink()

    _assert_review_refused(history)


@pytest.mark.parametrize("state", ["failed", "cancelled", "timed_out"])
def test_terminal_execute_with_dispatched_effects_still_requires_recovery(
    history: _HistoryFixture, state: str
) -> None:
    with sqlite3.connect(history.lifecycle.ledger_path) as connection:
        connection.execute(
            "UPDATE transport_tasks SET state = ?, result_json = NULL, effect_dispatched = 1",
            (state,),
        )
    history.result_path.unlink()

    _assert_review_refused(history)


@pytest.mark.parametrize("obligation", ["receipts", "receipt-commits", "watchdog"])
def test_settled_history_upgrade_refuses_receipt_or_watchdog_obligations(
    history: _HistoryFixture, obligation: str
) -> None:
    if obligation == "watchdog":
        directory = history.result_path.parent / (".bluefire-watchdog-" + "b" * 64)
    else:
        directory = history.lifecycle.runtime_root / "sandbox" / ".bluefire" / obligation
    directory.mkdir(parents=True)
    marker = directory / "retained.json"
    marker.write_bytes(b"{}\n")

    _assert_review_refused(history)

    assert marker.read_bytes() == b"{}\n"


@pytest.mark.parametrize("boundary", ["approved", "missing", "selected", "committed"])
def test_interrupted_upgrade_requires_exact_review_and_preserves_all_history(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    before = _preserved_bytes(history)
    review = history.review()
    write = lifecycle_module._write_private_json

    def interrupt(path: Path, value: Mapping[str, Any], **kwargs: Any) -> None:
        if boundary == "missing" and path == history.lifecycle.bootstrap_record_path:
            raise OSError("interrupted before publication")
        write(path, value, **kwargs)
        if (
            (boundary == "approved" and path.name == "upgrade-pending.json")
            or (boundary == "selected" and path == history.lifecycle.bootstrap_record_path)
            or (
                boundary == "committed"
                and path.name.startswith("upgrade-")
                and path.name != "upgrade-pending.json"
            )
        ):
            raise OSError("interrupted after durable publication")

    with monkeypatch.context() as patch:
        patch.setattr(lifecycle_module, "_write_private_json", interrupt)
        with pytest.raises(RunnerLifecycleError):
            history.apply(review)
    assert _preserved_bytes(history) == before
    assert history.lifecycle.status()["upgrade_recovery_required"] is True
    assert history.lifecycle.status()["state"] == "unavailable"
    for operation in (
        lambda: history.lifecycle.start(profile_id=PROFILE_ID),
        lambda: history.lifecycle.stop(profile_id=PROFILE_ID),
        lambda: history.lifecycle.bootstrap(allowed_profile_ids=(PROFILE_ID,), allow_upgrade=True),
    ):
        with pytest.raises(RunnerLifecycleError, match="interrupted"):
            operation()
    rereview = history.review()
    assert rereview["recovery_required"] is True
    assert rereview["review_digest"] == review["review_digest"]
    history.apply(rereview)
    assert _preserved_bytes(history) == before
    assert not (history.lifecycle.control_root / "upgrade-pending.json").exists()
    receipt = json.loads(next(history.lifecycle.control_root.glob("upgrade-*.json")).read_bytes())
    assert receipt["state"] == "committed"
    assert receipt["review"]["old"]["binary_digest"] == file_hash(history.old_binary)
    assert receipt["review"]["new"]["binary_digest"] == file_hash(history.factory.binaries["2.0.0"])


@pytest.mark.parametrize("target", ["manifest", "profile", "sandbox"])
def test_resealed_incomplete_or_different_sandbox_history_is_not_accepted(
    history: _HistoryFixture,
    target: str,
) -> None:
    if target == "manifest":
        history.manifest.pop("limits")
    elif target == "profile":
        history.profile.pop("limits")
    else:
        other = history.lifecycle.runtime_root / "other-sandbox"
        other.mkdir()
        history.profile["sandbox_root"] = str(other)
    history.profile = seal_profile(history.profile)
    history.manifest["policy_digest"] = history.profile["policy_digest"]
    history.manifest = seal_manifest(history.manifest)
    _replace_execute_documents(history)
    _assert_review_refused(history)


def test_upgrade_admission_refuses_active_work_without_blocking_cancellation(
    tmp_path: Path,
) -> None:
    from bluefire.job_runtime import JobRuntimeError, RunJobController
    from bluefire.product_store import ProductStore

    running = threading.Event()

    def work(context: Any, request: Any) -> None:
        running.set()
        context.cooperative_wait(10)

    with RunJobController(ProductStore(tmp_path / "jobs.db"), work, max_workers=1) as controller:
        job = controller.submit("scenario.run", {})
        assert running.wait(2)
        with pytest.raises(JobRuntimeError, match="idle"):
            with controller.idle_guard():
                pytest.fail("active work admitted maintenance")
        controller.cancel(str(job["job_id"]))
        assert controller.wait(str(job["job_id"]), timeout=3)["state"] == "cancelled"
        with controller.idle_guard(), controller.idle_guard():
            assert controller.active_job_ids == ()
            with pytest.raises(JobRuntimeError, match="maintenance"):
                controller.submit("scenario.run", {})


def test_upgrade_admission_holds_new_job_submission_until_transition_finishes(
    tmp_path: Path,
) -> None:
    from bluefire.job_runtime import JobResult, RunJobController
    from bluefire.product_store import ProductStore

    entered = threading.Event()
    submitted = threading.Event()
    with RunJobController(
        ProductStore(tmp_path / "jobs.db"), lambda *_: JobResult(), max_workers=1
    ) as controller:

        def submit() -> None:
            entered.set()
            controller.submit("scenario.run", {})
            submitted.set()

        with controller.idle_guard():
            worker = threading.Thread(target=submit)
            worker.start()
            assert entered.wait(2)
            assert not submitted.wait(0.05)
        worker.join(timeout=3)
        assert submitted.is_set()


def test_reviewed_upgrade_api_and_cli_forward_exact_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    from bluefire import cli
    from tests_platform.test_api import json_body, request, running_server
    from tests_platform.test_cli import _RecordingService

    digest = "sha256:" + "a" * 64
    with running_server() as (server, service):
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            service,
            "review_runner_upgrade",
            lambda **values: calls.append(values) or {"review_digest": digest},
            raising=False,
        )
        monkeypatch.setattr(
            service,
            "bootstrap_runner",
            lambda **values: calls.append(values) or {"state": "stopped"},
        )
        status, _, body = request(
            server, "POST", "/api/v1/runner/upgrade-review", body={"profile_id": PROFILE_ID}
        )
        assert status == 200 and json_body(body)["review_digest"] == digest
        status, _, _ = request(
            server,
            "POST",
            "/api/v1/runner/bootstrap",
            body={"profile_id": PROFILE_ID, "allow_upgrade": True, "upgrade_review_digest": digest},
        )
        assert status == 200
        assert calls == [
            {"profile_id": PROFILE_ID},
            {"profile_id": PROFILE_ID, "allow_upgrade": True, "upgrade_review_digest": digest},
        ]
        status, _, _ = request(
            server,
            "POST",
            "/api/v1/runner/upgrade-review",
            body={"profile_id": PROFILE_ID, "allow_upgrade": True},
        )
        assert status == 400 and len(calls) == 2
    recording = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _: recording)
    cli._execute(cli._parser().parse_args(["runner", "upgrade-review", "--profile", PROFILE_ID]))
    cli._execute(
        cli._parser().parse_args(
            ["runner", "bootstrap", "--allow-upgrade", "--upgrade-review-digest", digest]
        )
    )
    assert recording.calls == [
        ("review_runner_upgrade", (), {"profile_id": PROFILE_ID}),
        (
            "bootstrap_runner",
            (),
            {"profile_id": None, "allow_upgrade": True, "upgrade_review_digest": digest},
        ),
    ]


def test_pending_upgrade_rechecks_current_profiles_and_authentication(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = "sha256:" + "a" * 64
    review = history.lifecycle.review_upgrade(
        allowed_profile_ids=(PROFILE_ID,), profile_binding=binding
    )
    original = lifecycle_module._write_private_json

    def interrupted(path: Path, value: Mapping[str, Any], **kwargs: Any) -> None:
        original(path, value, **kwargs)
        if path.name == "upgrade-pending.json":
            raise OSError("interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(lifecycle_module, "_write_private_json", interrupted)
        with pytest.raises(RunnerLifecycleError):
            history.lifecycle.bootstrap(
                allowed_profile_ids=(PROFILE_ID,),
                allow_upgrade=True,
                upgrade_review_digest=review["review_digest"],
                profile_binding=binding,
            )
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    with pytest.raises(RunnerLifecycleError):
        history.lifecycle.review_upgrade(
            allowed_profile_ids=(PROFILE_ID,), profile_binding="sha256:" + "b" * 64
        )
    with pytest.raises(RunnerLifecycleError):
        history.lifecycle.bootstrap(
            allowed_profile_ids=(PROFILE_ID,),
            allow_upgrade=True,
            upgrade_review_digest=review["review_digest"],
            profile_binding="sha256:" + "b" * 64,
        )
    pending_path = history.lifecycle.control_root / "upgrade-pending.json"
    pending = json.loads(pending_path.read_bytes())
    pending["review"]["profile_binding"] = "sha256:" + "b" * 64
    pending_path.write_bytes(canonical_json_bytes(pending))
    with pytest.raises(RunnerLifecycleError):
        history.lifecycle.review_upgrade(
            allowed_profile_ids=(PROFILE_ID,), profile_binding="sha256:" + "b" * 64
        )
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap


def test_raced_bootstrap_destination_is_preserved_and_activation_stays_pending(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bluefire.runner_private_files import _PinnedPrivateDirectory

    review = history.review()
    foreign = b'{"foreign":"preserve this raced entry"}'
    original = _PinnedPrivateDirectory.unlink

    def raced(self: Any, name: str, **kwargs: Any) -> None:
        if self.path / name == history.lifecycle.bootstrap_record_path:
            history.lifecycle.bootstrap_record_path.write_bytes(foreign)
        original(self, name, **kwargs)

    monkeypatch.setattr(_PinnedPrivateDirectory, "unlink", raced)
    with pytest.raises(RunnerLifecycleError):
        history.apply(review)
    assert history.lifecycle.bootstrap_record_path.read_bytes() == foreign
    assert history.lifecycle.status()["state"] == "unavailable"
    with pytest.raises(RunnerLifecycleError):
        history.review()


def test_switch_uses_snapshot_without_permission_repair(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bluefire.runner_private_files import _PinnedPrivateDirectory

    original = _PinnedPrivateDirectory.unlink
    calls: list[Mapping[str, Any]] = []

    def inspected(self: Any, name: str, **kwargs: Any) -> None:
        if self.path / name == history.lifecycle.bootstrap_record_path:
            calls.append(kwargs)
            assert kwargs["apply_permissions"] is False
            assert kwargs["expected_snapshot"] is not None
        original(self, name, **kwargs)

    monkeypatch.setattr(_PinnedPrivateDirectory, "unlink", inspected)
    history.apply(history.review())
    assert len(calls) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX ctime changes on chmod even for unchanged mode")
def test_posix_snapshot_switch_preserves_private_mode_and_history(history: _HistoryFixture) -> None:
    bootstrap = history.lifecycle.bootstrap_record_path
    bootstrap.chmod(0o600)
    before = _preserved_bytes(history)
    history.apply(history.review())
    assert stat.S_IMODE(bootstrap.stat().st_mode) == 0o600
    assert _preserved_bytes(history) == before


def test_review_and_apply_refuse_a_held_transport_ledger_lock(history: _HistoryFixture) -> None:
    review = history.review()
    before = history.lifecycle.bootstrap_record_path.read_bytes()
    with history.lifecycle._upgrade_ledger_guard():
        with pytest.raises(RunnerLifecycleError):
            history.review()
        with pytest.raises(RunnerLifecycleError):
            history.apply(review)
    assert history.lifecycle.bootstrap_record_path.read_bytes() == before
