"""Fixed setup supervision with fake processes/handles only; never launch Windows APIs."""

from __future__ import annotations

import io
import json
import struct
import threading
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_setup_child as entry
from bluefire import windows_file_access_setup_process as process
from bluefire.util import canonical_json_bytes
from tests_platform.test_windows_file_access_setup_binding import supervision

ISSUED = 1_700_000_000_000
MONO = 10_000_000_000


def request():
    return {
        "schema_version": entry.REQUEST_SCHEMA,
        "profile_id": "existing-source",
        "confirm_create": True,
        "original_issued_at_ms": ISSUED,
        "original_deadline_ns": MONO + 5_000_000_000,
        "supervision": supervision(),
    }


def result():
    return {
        "schema_version": "bluefire.windows-file-local-setup-result.v1",
        "generation": "a" * 32,
        "setup_receipt_digest": "sha256:" + "b" * 64,
        "publication": "complete",
        "context_available": False,
        "account_cleanup_required": True,
        "external_hard_deadline_required": True,
        "settled": False,
    }


def terminal():
    return {"schema_version": entry.RESULT_SCHEMA, "result": result(), "error": None}


def frame(row):
    raw = canonical_json_bytes(row)
    return struct.pack("<I", len(raw)) + raw


@pytest.fixture
def clocks(monkeypatch):
    now = {"mono": MONO, "wall": ISSUED}
    monkeypatch.setattr(process.time, "monotonic_ns", lambda: now["mono"])
    monkeypatch.setattr(process.time, "time_ns", lambda: now["wall"] * 1_000_000)
    monkeypatch.setattr(entry.binding, "require_child_handoff", lambda row: nullcontext())
    return now


class Handle(int):
    def __new__(cls):
        obj = super().__new__(cls, 100)
        obj.closed = False
        obj.calls = 0
        obj.fail = False
        return obj

    def Close(self):
        self.calls += 1
        self.closed = True
        if self.fail:
            raise OSError("synthetic close ambiguity")


class FakeProcess:
    def __init__(self):
        self.pid, self._handle, self.returncode = 71, Handle(), 0
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(frame(terminal()))
        self.stderr = io.BytesIO()
        self.kills = self.waits = 0
        self.refuse_exit = False

    def poll(self):
        return None if self.refuse_exit else self.returncode

    def wait(self, *, timeout):
        self.waits += 1
        if self.refuse_exit:
            raise TimeoutError("synthetic child never reaped")
        return self.returncode

    def kill(self):
        self.kills += 1


class FakeContainment:
    def __init__(self, *, kill_on_close):
        assert kill_on_close is True
        self.events = []
        self.fail_finish = self.fail_start = False

    def create_job(self):
        self.events.append("create")
        return 200

    def adopt_retained_job(self, job, child):
        assert job == 200 and child.pid == 71
        self.events.append("adopt")

    def assign_retained(self, job, child):
        self.events.append("assign")

    def resume_retained(self, child, job, generation):
        self.events.append("resume")

    def drain_retained(self, child, job):
        self.events.append("drain")
        return True

    def finish_retained(self, child, job):
        self.events.append("final-drain-close")
        return not self.fail_finish

    def close_retained_start_handles(self, child):
        self.events.append("startup-close")
        return not self.fail_start

    def close_handle(self, handle):
        self.events.append("unassigned-job-close")
        return True


@pytest.fixture
def fake(monkeypatch, clocks):
    child = FakeProcess()
    owners = []
    monkeypatch.setattr(process, "WindowsJobContainment", FakeContainment)
    monkeypatch.setattr(process.sys, "platform", "win32")

    def launch(owner):
        owners.append(owner)
        owner.request = canonical_json_bytes(request())
        owner.job, owner.process, owner.handle, owner.pid = 200, child, child._handle, child.pid
        owner.containment.adopt_retained_job(200, child)
        owner.adopted = True
        owner.current()
        owner.containment.assign_retained(200, child)
        owner.current()
        owner.resumed = True
        owner.containment.resume_retained(child, 200, object())
        owner.current()

    monkeypatch.setattr(process.SetupCleanupOwner, "_launch", launch)
    return child, owners


def run():
    return process.run_setup_process("existing-source", cancellation_event=threading.Event())


def test_fake_child_complete_requires_protocol_exit_and_every_cleanup(fake):
    child, owners = fake
    outcome = run()
    assert outcome.terminal == terminal() and outcome.dispatch == "completed"
    assert outcome.process_cleanup == "verified" and outcome.cleanup_owner is None
    assert outcome.settled is False and outcome.terminal["result"]["context_available"] is False
    owner = owners[0]
    assert owner.request == canonical_json_bytes(request())
    assert owner.containment.events == [
        "adopt",
        "assign",
        "resume",
        "drain",
        "final-drain-close",
        "startup-close",
    ]
    assert child.waits == 1 and child._handle.calls == 1
    assert all(stream.closed for stream in (child.stdin, child.stdout, child.stderr))


def test_generic_child_failure_stays_unknown_after_verified_process_cleanup(fake, monkeypatch):
    child, _ = fake

    def derive(row):
        raise RuntimeError("synthetic private failure after possible effects")

    monkeypatch.setattr(entry, "_derive", derive)
    output = io.BytesIO()
    child.returncode = entry._run(io.BytesIO(frame(request())), output)
    assert child.returncode == 4
    child.stdout = io.BytesIO(output.getvalue())
    outcome = run()
    assert outcome.terminal == {
        "schema_version": entry.RESULT_SCHEMA,
        "result": None,
        "error": None,
    }
    assert outcome.dispatch == "unknown" and outcome.issue == "child_outcome_unknown"
    assert outcome.process_cleanup == "verified" and outcome.cleanup_owner is None
    assert outcome.settled is False
    assert "private failure" not in repr(outcome)


@pytest.mark.parametrize(
    "kind", ["extra", "oversized", "bad_schema", "nonzero", "stderr", "utf8", "duplicate"]
)
def test_bad_or_incomplete_terminal_is_unknown_after_resume(fake, kind):
    child, _ = fake
    if kind == "extra":
        child.stdout = io.BytesIO(frame(terminal()) + b"x")
    elif kind == "oversized":
        child.stdout = io.BytesIO(struct.pack("<I", entry.OUTPUT_MAX + 1))
    elif kind == "bad_schema":
        row = terminal()
        row["result"]["settled"] = True
        child.stdout = io.BytesIO(frame(row))
    elif kind == "nonzero":
        child.returncode = 4
    elif kind == "stderr":
        child.stderr = io.BytesIO(b"synthetic private detail")
    else:
        raw = b"\xff" if kind == "utf8" else b'{"schema_version":1,"schema_version":2}'
        child.stdout = io.BytesIO(struct.pack("<I", len(raw)) + raw)
    outcome = run()
    assert outcome.terminal is None and outcome.dispatch == "unknown"
    assert outcome.process_cleanup == "verified" and outcome.issue is not None
    assert "private detail" not in repr(outcome)


@pytest.mark.parametrize("fault", ["job", "startup", "handle", "pipe", "exit", "pins"])
def test_cleanup_failure_is_retained_not_inferred_from_empty_job(fake, monkeypatch, fault):
    child, owners = fake
    original = process.SetupCleanupOwner._launch

    def launch(owner):
        original(owner)
        owner.containment.fail_finish = fault == "job"
        owner.containment.fail_start = fault == "startup"
        child._handle.fail = fault == "handle"
        if fault == "pipe":
            owner.ambiguous_pipes.add("stdout")
        if fault == "exit":
            # The bounded parent deadline will stop the exchange waiting for exit.
            owner.issue = "deadline"
            child.refuse_exit = True
        if fault == "pins":
            owner.pins.callback(lambda: (_ for _ in ()).throw(OSError("pin close")))

    monkeypatch.setattr(process.SetupCleanupOwner, "_launch", launch)
    outcome = run()
    assert outcome.process_cleanup == "unknown" and outcome.cleanup_owner is owners[0]
    assert outcome.issue == "cleanup_unknown" and outcome.terminal is None
    if fault in {"handle", "pins"}:
        assert not outcome.cleanup_owner.retry_cleanup()
        if fault == "handle":
            assert child._handle.calls == 1


def test_cancelled_before_launch_never_creates_child(fake):
    _, owners = fake
    cancel = threading.Event()
    cancel.set()
    outcome = process.run_setup_process("existing-source", cancellation_event=cancel)
    assert outcome.dispatch == "not_started" and outcome.process_cleanup == "verified"
    assert outcome.issue == "cancelled" and owners == []


@pytest.mark.parametrize("rollback", [False, True])
def test_original_deadline_ends_before_resume_without_new_interval(
    fake, clocks, monkeypatch, rollback
):
    child, _ = fake

    def launch(owner):
        owner.job, owner.process, owner.handle, owner.pid = 200, child, child._handle, child.pid
        owner.containment.adopt_retained_job(200, child)
        owner.adopted = True
        if rollback:
            clocks["wall"] = ISSUED - 1
        else:
            clocks["mono"] += 5_000_000_000
        owner.current()
        pytest.fail("Expired setup was allowed to resume")

    monkeypatch.setattr(process.SetupCleanupOwner, "_launch", launch)
    outcome = run()
    assert outcome.dispatch == "not_started" and outcome.issue == "deadline"
    assert outcome.process_cleanup == "verified" and child._handle.closed


def test_blocked_assignment_keeps_handles_until_thread_ends_then_fresh_drain(
    fake, clocks, monkeypatch
):
    child, owners = fake
    started, release = threading.Event(), threading.Event()

    def assign(self, job, item):
        self.events.append("assign-blocked")
        started.set()
        assert release.wait(2)
        self.events.append("assign-ended")

    monkeypatch.setattr(FakeContainment, "assign_retained", assign)

    # Advance the clock only after the worker is blocked inside assignment.
    holder = []
    worker = threading.Thread(target=lambda: holder.append(run()))
    worker.start()
    assert started.wait(1)
    clocks["mono"] += 5_000_000_000
    worker.join(1.5)
    assert not worker.is_alive()
    outcome = holder[0]
    assert outcome.process_cleanup == "unknown" and outcome.cleanup_owner is owners[0]
    assert not child._handle.closed and not child.stdout.closed
    assert "final-drain-close" not in owners[0].containment.events
    release.set()
    owners[0].exchange.join(1)
    assert outcome.cleanup_owner.retry_cleanup()
    assert "resume" not in owners[0].containment.events
    assert owners[0].containment.events.index("assign-ended") < owners[0].containment.events.index(
        "final-drain-close"
    )


def test_child_derives_only_after_closed_original_request(clocks, monkeypatch):
    calls = []
    monkeypatch.setattr(entry, "_derive", lambda row: calls.append(row) or result())
    output = io.BytesIO()
    assert entry._run(io.BytesIO(frame(request())), output) == 0
    assert calls == [request()]
    raw = output.getvalue()
    assert struct.unpack("<I", raw[:4])[0] == len(raw) - 4
    assert process._terminal(raw[4:], 0) == terminal()


@pytest.mark.parametrize(
    "change", ["extra", "deadline", "expired", "rollback", "intent", "path", "trailing"]
)
def test_child_bad_or_stale_input_never_derives_authority(clocks, monkeypatch, change):
    row = request()
    if change == "extra":
        row["owner_sid"] = "caller assertion"
    elif change == "deadline":
        row["original_deadline_ns"] += 1
    elif change == "expired":
        clocks["mono"] += 5_000_000_000
    elif change == "rollback":
        clocks["wall"] -= 1
    elif change == "intent":
        row["confirm_create"] = 1
    elif change == "path":
        row["profile_id"] = "C:\\arbitrary"
    monkeypatch.setattr(entry, "_derive", lambda row: pytest.fail("Must not derive"))
    output = io.BytesIO()
    assert entry._run(io.BytesIO(frame(row) + (b"x" if change == "trailing" else b"")), output) == 4
    assert json.loads(output.getvalue()[4:])["result"] is None


def test_child_retains_truthful_partial_failure(clocks, monkeypatch):
    from bluefire.windows_file_access_enrollment_setup import WindowsFileSetupError

    def derive(row):
        raise WindowsFileSetupError(
            "account_creation", bootstrap_mutated=True, intent_persisted=True
        )

    monkeypatch.setattr(entry, "_derive", derive)
    output = io.BytesIO()
    assert entry._run(io.BytesIO(frame(request())), output) == 4
    assert process._terminal(output.getvalue()[4:], 4)["error"] == {
        "stage": "account_creation",
        "bootstrap_mutated": True,
        "intent_persisted": True,
    }


@pytest.mark.parametrize("late", [None, "create", "transfer"])
def test_real_launch_recipe_is_fixed_pinned_and_suspended(clocks, monkeypatch, tmp_path, late):
    runtime = tmp_path / "python.exe"
    script = tmp_path / "windows_file_access_setup_child.py"
    module = tmp_path / "windows_file_access_setup_process.py"
    for item in (runtime, script, module):
        item.write_bytes(b"synthetic test-only source")
    calls = []
    child_process = FakeProcess()
    monkeypatch.setattr(process, "WindowsJobContainment", FakeContainment)
    monkeypatch.setattr(
        FakeContainment,
        "system_directory",
        lambda self: tmp_path / "Windows" / "System32",
        raising=False,
    )
    monkeypatch.setattr(process.sys, "_base_executable", str(runtime))
    monkeypatch.setattr(process, "__file__", str(module))
    monkeypatch.setattr(entry, "_managed_root", lambda: tmp_path)
    monkeypatch.setattr(
        process, "_PinnedDirectory", lambda *args, **kwargs: __import__("contextlib").nullcontext()
    )
    monkeypatch.setattr(process, "_is_link_or_reparse", lambda path: False)
    descriptors = iter(range(10, 16))
    monkeypatch.setattr(
        process,
        "os",
        SimpleNamespace(
            pipe=lambda: (next(descriptors), next(descriptors)),
            fdopen=lambda descriptor, mode, buffering: io.BytesIO(),
            close=lambda descriptor: None,
        ),
    )

    def transfer(handle, ends):
        assert handle == 100 and ends == (10, 13, 15)
        if late == "transfer":
            clocks["mono"] += 5_000_000_000
        return supervision()

    monkeypatch.setattr(process.binding, "transfer_to_child", transfer)

    @contextmanager
    def pinned(path, digest):
        calls.append((path, digest))
        yield str(path), ()

    monkeypatch.setattr(process, "_pinned_launch_file", pinned)
    monkeypatch.setattr(
        process.child,
        "capture_retained_child",
        lambda handle, job, expected_pid: SimpleNamespace(process_id=expected_pid),
    )

    def popen(argv, **kwargs):
        assert argv == [str(runtime), "-I", "-B", "-X", "utf8", str(script)]
        assert kwargs["creationflags"] == 0x00000008 | 0x00000200 | 0x00000004
        assert kwargs["close_fds"] and not kwargs["shell"]
        assert set(kwargs["env"]) == {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        assert kwargs["cwd"] == tmp_path
        assert (kwargs["stdin"], kwargs["stdout"], kwargs["stderr"]) == (10, 13, 15)
        if late == "create":
            clocks["mono"] += 5_000_000_000
        return child_process

    monkeypatch.setattr(process.subprocess, "Popen", popen)
    owner = process.SetupCleanupOwner("existing-source", threading.Event())
    if late:
        with pytest.raises(RuntimeError, match="Original setup interval ended"):
            owner._launch()
        assert "resume" not in owner.containment.events and owner.resumed is False
    else:
        owner._launch()
        assert owner.containment.events == ["create", "adopt", "assign", "resume"]
        assert owner.request == canonical_json_bytes(request())
    assert [path for path, _ in calls] == [runtime, script]
    assert owner.retry_cleanup()


@pytest.mark.parametrize("fault", ["platform", "isolation", "module", "arguments", "path"])
def test_child_main_refuses_nonfixed_entry_before_input(monkeypatch, fault):
    fake_sys = SimpleNamespace(
        platform="win32", flags=SimpleNamespace(isolated=1), argv=[entry.__file__]
    )
    monkeypatch.setattr(entry, "sys", fake_sys)
    monkeypatch.setattr(entry, "__package__", "")
    if fault == "platform":
        fake_sys.platform = "linux"
    elif fault == "isolation":
        fake_sys.flags.isolated = 0
    elif fault == "module":
        monkeypatch.setattr(entry, "__package__", "bluefire")
    elif fault == "arguments":
        fake_sys.argv.append("caller-module")
    else:
        fake_sys.argv = ["other.py"]
    monkeypatch.setattr(
        entry, "_run", lambda *args: pytest.fail("Invalid entry must not read or derive")
    )
    assert entry.main() == 4


@pytest.mark.parametrize("handoff", [True, False])
def test_guarded_main_requires_actual_handoff_before_deriving(clocks, monkeypatch, handoff):
    events = []
    output = io.BytesIO()
    monkeypatch.setattr(
        entry,
        "sys",
        SimpleNamespace(
            platform="win32",
            flags=SimpleNamespace(isolated=1),
            argv=[entry.__file__],
            stdin=SimpleNamespace(buffer=io.BytesIO(frame(request()))),
            stdout=SimpleNamespace(buffer=output),
        ),
    )
    monkeypatch.setattr(entry, "__package__", "")

    @contextmanager
    def verify(row):
        assert row == supervision()
        events.append("os-handoff")
        if not handoff:
            raise RuntimeError("synthetic handoff refusal")
        yield

    monkeypatch.setattr(entry.binding, "require_child_handoff", verify)
    monkeypatch.setattr(entry, "_derive", lambda row: events.append("derive") or result())
    assert entry.main() == (0 if handoff else 4)
    assert events == (["os-handoff", "derive"] if handoff else ["os-handoff"])
    assert json.loads(output.getvalue()[4:])["result"] == (result() if handoff else None)


def test_managed_root_uses_existing_os_token_profile_not_ambient_aliases(monkeypatch, tmp_path):
    from bluefire import runner_bootstrap, runtime_paths

    observed = []
    temp = tmp_path / "actual-profile" / "AppData" / "Local" / "Temp"
    monkeypatch.setattr(runtime_paths, "runtime_temp_parent", lambda: temp)
    monkeypatch.setenv("LOCALAPPDATA", "caller-alias")
    monkeypatch.setenv("USERPROFILE", "caller-profile")

    def root(*, environ, platform_name):
        observed.append((environ, platform_name))
        return temp.parent / "BlueFire Nexus"

    monkeypatch.setattr(runner_bootstrap, "managed_product_root", root)
    assert entry._managed_root() == temp.parent / "BlueFire Nexus"
    assert observed == [({"LOCALAPPDATA": str(temp.parent)}, "windows")]


def test_actual_profile_lookup_failure_does_not_fall_back_to_environment(monkeypatch):
    from bluefire import runner_bootstrap, runtime_paths

    monkeypatch.setenv("LOCALAPPDATA", "caller-alias")
    monkeypatch.setattr(
        runtime_paths,
        "runtime_temp_parent",
        lambda: (_ for _ in ()).throw(OSError("synthetic token query failure")),
    )
    monkeypatch.setattr(
        runner_bootstrap, "managed_product_root", lambda **kwargs: pytest.fail("No fallback")
    )
    with pytest.raises(OSError, match="synthetic token"):
        entry._managed_root()


def test_fixed_root_lookup_failure_prevents_parent_launch_and_child_derivation(clocks, monkeypatch):
    from bluefire import runner_lifecycle

    monkeypatch.setattr(process, "WindowsJobContainment", FakeContainment)
    monkeypatch.setattr(
        entry, "_managed_root", lambda: (_ for _ in ()).throw(OSError("fixed root unavailable"))
    )
    monkeypatch.setattr(process.subprocess, "Popen", lambda *a, **k: pytest.fail("No launch"))
    monkeypatch.setattr(
        runner_lifecycle, "ManagedRunnerLifecycle", lambda *a: pytest.fail("No lifecycle")
    )
    owner = process.SetupCleanupOwner("existing-source", threading.Event())
    with pytest.raises(OSError, match="fixed root"):
        owner._launch()
    with pytest.raises(OSError, match="fixed root"):
        entry._derive(request())
    assert owner.containment.events == [] and owner.retry_cleanup()


def test_child_uses_shared_fixed_root_and_original_clocks_only(clocks, monkeypatch, tmp_path):
    from bluefire import runner_lifecycle
    from bluefire import windows_file_access_enrollment_setup as setup

    root = tmp_path / "actual-token-root"
    marker, calls = object(), []
    monkeypatch.setattr(entry, "_managed_root", lambda: root)
    monkeypatch.setattr(
        runner_lifecycle, "ManagedRunnerLifecycle", lambda path: calls.append(path) or marker
    )

    def derive(profile, **kwargs):
        assert profile == "existing-source"
        assert kwargs == {
            "lifecycle": marker,
            "original_issued_at_ms": ISSUED,
            "original_deadline": (MONO + 5_000_000_000) / 1_000_000_000,
        }
        return result()

    monkeypatch.setattr(setup, "_run_local_setup_child", derive)
    assert entry._derive(request()) == result()
    assert calls == [root]


@pytest.mark.parametrize("kind", ["complete", "partial", "refused", "unknown", "cleanup"])
def test_public_projection_is_serializable_and_keeps_cleanup_unknown(monkeypatch, kind):
    owner = object() if kind == "cleanup" else None
    row = terminal()
    if kind != "complete":
        row["result"] = None
        row["error"] = (
            {
                "stage": "account_creation" if kind == "partial" else "authority",
                "bootstrap_mutated": kind == "partial",
                "intent_persisted": kind == "partial",
            }
            if kind in {"partial", "refused"}
            else None
        )
    outcome = process.SetupProcessOutcome(
        None if kind == "cleanup" else row,
        "unknown" if kind in {"unknown", "cleanup"} else "completed",
        "unknown" if kind == "cleanup" else "verified",
        (
            "cleanup_unknown"
            if kind == "cleanup"
            else ("child_outcome_unknown" if kind == "unknown" else None)
        ),
        owner,
    )
    monkeypatch.setattr(process, "run_setup_process", lambda *args, **kwargs: outcome)
    projected = process.setup_windows_file_access_local("existing-source")
    assert json.loads(json.dumps(projected)) == projected
    assert projected["publication"] == ("complete" if kind == "complete" else "not_established")
    assert projected["result"] == (result() if kind == "complete" else None)
    assert (
        projected["context_available"]
        is projected["native_read_proof"]
        is projected["settled"]
        is False
    )
    assert (
        projected["account_object_cleanup"]
        == {
            "complete": "required",
            "partial": "required",
            "refused": "not_required",
            "unknown": "unknown",
            "cleanup": "unknown",
        }[kind]
    )
    assert projected["cleanup_retry_available"] is False
    assert projected["cleanup_owner_lifetime"] == (
        "cli_process_only" if kind == "cleanup" else None
    )
    if kind == "cleanup":
        assert projected["issue"] == "cleanup_unknown"
        assert "no retained retry handle" in projected["cleanup_limitation"]
        assert "never replay setup" in projected["cleanup_limitation"]
    elif kind == "unknown":
        assert projected["dispatch"] == "unknown" and projected["issue"] == "child_outcome_unknown"


@pytest.mark.parametrize(
    "override", ["config", "runs", "internal_config", "provider", "confirmation"]
)
def test_cli_refuses_overrides_before_service_or_setup(monkeypatch, override):
    from bluefire import cli

    args = cli._parser().parse_args(
        [
            "runner",
            "windows-file-setup",
            "--profile",
            "existing-source",
            "--confirm-create-local-reader",
        ]
    )
    kwargs = {}
    if override == "config":
        args.config = "caller-config"
    elif override == "runs":
        args.runs_dir = "caller-root"
    elif override == "internal_config":
        kwargs["config"] = object()
    elif override == "provider":
        kwargs["ai_provider_access"] = object()
    else:
        args.confirm_create_local_reader = False
    monkeypatch.setattr(cli, "_service", lambda *a, **k: pytest.fail("No service construction"))
    monkeypatch.setattr(
        process, "setup_windows_file_access_local", lambda *a, **k: pytest.fail("No setup")
    )
    with pytest.raises(ValueError):
        cli._execute(args, **kwargs)


@pytest.mark.parametrize("complete", [True, False])
def test_cli_exit_status_does_not_call_unknown_setup_success(monkeypatch, complete):
    from bluefire import cli

    projected = {"publication": "complete" if complete else "not_established", "settled": False}
    monkeypatch.setattr(process, "setup_windows_file_access_local", lambda profile: projected)
    monkeypatch.setattr(cli, "_service", lambda *a, **k: pytest.fail("No service construction"))
    output = []
    monkeypatch.setattr(cli, "_json", output.append)
    code = cli.main(
        [
            "runner",
            "windows-file-setup",
            "--profile",
            "existing-source",
            "--confirm-create-local-reader",
        ]
    )
    assert code == (0 if complete else 4)
    assert output == [projected]
