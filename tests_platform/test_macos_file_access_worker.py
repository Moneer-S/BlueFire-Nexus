"""Exact retained-launch plumbing with fake I/O, never a Darwin process."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_worker as worker
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from bluefire.macos_file_access_peer import MacOSChildConsistency
from tests_platform.test_macos_file_access_contract import binding, observation, request


class Socket:
    family = 1  # Darwin AF_UNIX, represented only by this fake socket.

    def __init__(self, fd):
        self.fd = fd
        self.closed = False
        self.close_calls = 0
        self.fail_close = False

    def fileno(self):
        return self.fd

    def getsockopt(self, *_args):
        return worker.socket.SOCK_STREAM

    def getpeername(self):
        return ""

    def close(self):
        self.close_calls += 1
        self.closed = True
        if self.fail_close:
            self.fail_close = False
            raise OSError("fake uncertain descriptor close")


class Channel:
    def __init__(self, stream, _binding, *, role):
        self.stream = stream
        self.role = role
        self.usable = True
        self.requests = []
        self.after = None
        self._close_attempted = False
        self._local_cleanup_unknown = False

    @property
    def local_cleanup_unknown(self):
        return self._local_cleanup_unknown

    def exchange(self, original):
        self.requests.append(original)
        result = observation(original)
        if original["operation"] == "read_owner":
            result["principal"] = original["binding"]["owner"]
        if original["operation"] == "close":
            result.update(
                outcome="closed",
                principal=None,
                fresh_read=None,
                request_handle_cleanup="not_opened",
                held_handle_cleanup="closed",
            )
            self.usable = False
        if self.after:
            self.after()
        return result

    def abandon(self):
        self.usable = False
        if self._close_attempted:
            return
        self._close_attempted = True
        try:
            self.stream.close()
        except BaseException:
            self._local_cleanup_unknown = True
            raise


class Process:
    pid = 103
    returncode = None


@pytest.fixture
def fake(monkeypatch):
    state = dict(
        monotonic=1000,
        wall=1000,
        launches=0,
        factory=0,
        mode="normal",
        reserve=True,
        release=False,
        releases=0,
        observed=0,
        wrong_start=False,
        go=False,
    )
    runtime = object.__new__(worker.runner.SubprocessRustRunner)
    runtime.runner_binary = Path("/fixed/native")
    runtime.runner_binary_digest = "sha256:" + "1" * 64
    runtime.work_root = Path("/fixed/work")
    runtime._watchdog_interpreter = Path("/fixed/python")
    runtime._watchdog_interpreter_digest = "sha256:" + "2" * 64
    runtime.parent_death_script = Path("/fixed/helper.py")
    runtime.parent_death_script_digest = "sha256:" + "3" * 64
    runtime._kill_child_on_job_close = False
    runtime._darwin_no_fork_proven = set()
    quarantined = set()
    active = {}
    monkeypatch.setattr(worker.runner, "_DARWIN_ACTIVE_PROCESSES", active)
    runtime._reserve_darwin_process_slot = lambda _token: state["reserve"]
    runtime._cancel_darwin_process_slot = lambda _token: None
    runtime._darwin_process_is_indeterminate = lambda process: process in quarantined
    runtime._refresh_darwin_no_fork_proof = (
        lambda process: process in runtime._darwin_no_fork_proven
    )
    runtime._quarantine_interrupted_darwin_launch = quarantined.add

    def release(process, **_options):
        state["releases"] += 1
        if state["release"]:
            active.pop(process, None)
            quarantined.discard(process)
            process.returncode = 0
        return state["release"]

    runtime._release_darwin_process_group = release
    runtime._reconcile_indeterminate_darwin_process = release

    def registered(_token, sink, arguments, **options):
        state["factory"] += 1
        state["arguments"], state["options"] = arguments, options
        process = Process()
        active[process] = runtime
        sink.append(process)
        return process

    runtime._spawn_registered_darwin_popen = registered

    @contextmanager
    def pinned(_path, _digest):
        yield "/fixed/.bluefire-verified-launch-native", ()

    def spawn(target, **options):
        state["launches"] += 1
        state["target"], state["launch_options"] = list(target), options
        if state["mode"] == "no_object":
            raise OSError("fake ambiguous launch")
        arguments = ["fixed-helper"] * 16 + list(target)
        if state["mode"] == "changed_recipe":
            arguments[17] = "inventory"
        process = options["popen_factory"](
            arguments,
            pass_fds=(9, 11, 100, 101),
            _bluefire_descriptor_argument_indexes=(7, 12, 13),
            _bluefire_descriptor_list_argument_indexes=(15,),
        )
        if state["mode"] == "before_proof":
            raise OSError("fake failure before nofork proof")
        options["proof_sink"].append(process)
        if state["mode"] == "late_before_go":
            state["monotonic"] = 5000001000
        options["proof_callback"](process)
        state["go"] = True
        return process

    def observe(process, *, expected_ids, expected_start):
        state["observed"] += 1
        start = (100, 1) if not state["wrong_start"] else (100, 2)
        if expected_start is not None and expected_start != start:
            raise MacOSFileAccessContractError("fake changed child")
        return MacOSChildConsistency(
            process.pid, 50, start, tuple(expected_ids[key] for key in worker._IDS)
        )

    monkeypatch.setattr(worker, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(worker, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0))
    monkeypatch.setattr(
        worker,
        "socket",
        SimpleNamespace(
            socket=Socket,
            AF_UNIX=Socket.family,
            SOL_SOCKET=worker.socket.SOL_SOCKET,
            SO_TYPE=worker.socket.SO_TYPE,
            SOCK_STREAM=worker.socket.SOCK_STREAM,
        ),
    )
    monkeypatch.setattr(worker, "MacOSPrimitiveChannel", Channel)
    monkeypatch.setattr(worker.runner, "_pinned_launch_file", pinned)
    monkeypatch.setattr(worker, "spawn_no_fork_exec", spawn)
    monkeypatch.setattr(worker, "observe_owned_child", observe)
    monkeypatch.setattr(worker, "darwin_clock_ns", lambda: state["monotonic"])

    def sleep(seconds):
        state["monotonic"] += max(1, int(seconds * 1_000_000_000))

    monkeypatch.setattr(
        worker, "time", SimpleNamespace(time_ns=lambda: state["wall"] * 1000000, sleep=sleep)
    )

    def build(role="reader"):
        return worker.MacOSFileAccessWorker(
            runtime,
            binding(),
            role=role,
            resource_fd=9,
            channel=Socket(10),
            child_channel=Socket(11),
        )

    return build, state, runtime, active, quarantined


def test_fixed_recipe_registered_remapping_and_original_nofork_owner(fake):
    build, state, runtime, active, _quarantined = fake
    owner = build()
    owner.start()
    assert state["target"][1:] == [
        "macos-file-access-reader",
        "--directory-fd",
        "9",
        "--channel-fd",
        "11",
        "--original-deadline-ns",
        "900000001000",
        "--uid",
        "502",
        "--gid",
        "501",
        "--groups",
        "501",
    ]
    assert state["options"]["_bluefire_descriptor_argument_indexes"] == (7, 12, 13, 19, 21)
    assert state["options"]["_bluefire_descriptor_list_argument_indexes"] == (15,)
    assert state["launch_options"]["options"] == dict(
        start_new_session=True, close_fds=True, umask=0o077
    )
    assert state["launch_options"]["inherited_descriptors"] == (9, 11)
    assert state["launch_options"]["environment"] == dict(
        PATH="/usr/bin:/bin", LANG="C", LC_ALL="C"
    )
    assert (
        state["launch_options"]["stdout"]
        == state["launch_options"]["stderr"]
        == worker.subprocess.DEVNULL
    )
    assert active[owner._process] is runtime
    assert owner._process in runtime._darwin_no_fork_proven
    assert owner._child_channel.closed
    result = owner.exchange(request())
    assert result["outcome"] == "allowed" and result["prevention_proven"] is False
    assert state["observed"] == 3


@pytest.mark.parametrize(
    "role,command,flag,uid",
    [
        ("owner", "macos-file-access-reader", "--directory-fd", "501"),
        ("control", "macos-file-access-owner-control", "--leaf-fd", "501"),
    ],
)
def test_creator_recipe_not_request_selects_role(fake, role, command, flag, uid):
    build, state, *_rest = fake
    owner = build(role)
    owner.start()
    assert state["target"][1:3] == [command, flag]
    assert state["target"][9] == uid


@pytest.mark.parametrize("mode", ["before_proof", "late_before_go"])
def test_created_original_is_retained_and_quarantined_even_before_proof(fake, mode):
    build, state, runtime, active, quarantined = fake
    state["mode"] = mode
    owner = build()
    with pytest.raises((OSError, MacOSFileAccessContractError)):
        owner.start()
    assert len(owner._processes) == 1
    original = owner._processes[0]
    assert active[original] is runtime and original in quarantined
    assert not state["go"] and not owner.settle()
    assert state["launches"] == state["factory"] == 1
    with pytest.raises(MacOSFileAccessContractError):
        owner.start()
    assert state["launches"] == 1


@pytest.mark.parametrize("mode", ["no_object", "changed_recipe"])
def test_ambiguous_missing_object_never_infers_cleanup_or_retries(fake, mode):
    build, state, *_rest = fake
    state["mode"] = mode
    owner = build()
    with pytest.raises((OSError, MacOSFileAccessContractError)):
        owner.start()
    assert not owner._processes and not owner.settle()
    assert state["factory"] == 0
    assert state["launches"] == 1


def test_expired_original_refuses_before_reserving_or_creating(fake):
    build, state, *_rest = fake
    owner = build()
    state["monotonic"] = owner._binding["original_deadline_ns"]
    with pytest.raises(MacOSFileAccessContractError):
        owner.start()
    assert state["launches"] == state["factory"] == 0


def test_bounded_registry_refusal_creates_no_process(fake):
    build, state, *_rest = fake
    state["reserve"] = False
    owner = build()
    with pytest.raises(MacOSFileAccessContractError):
        owner.start()
    assert state["launches"] == 0
    assert owner.settle()


@pytest.mark.parametrize("drift", ["start", "registry", "deadline"])
def test_post_exchange_drift_cannot_publish_success(fake, drift):
    build, state, _runtime, active, _quarantined = fake
    owner = build()
    owner.start()

    def changed():
        if drift == "start":
            state["wrong_start"] = True
        elif drift == "registry":
            active.pop(owner._process)
        else:
            state["monotonic"] = request()["deadline_ns"]

    owner._channel.after = changed
    with pytest.raises(MacOSFileAccessContractError):
        owner.exchange(request())
    assert len(owner._channel.requests) == 1
    with pytest.raises(MacOSFileAccessContractError):
        owner.exchange(request())
    assert len(owner._channel.requests) == 1


def test_mutated_caller_request_cannot_skip_post_read_child_check(fake):
    build, state, *_rest = fake
    owner = build()
    owner.start()
    original = request()
    owner._channel.after = lambda: original.update(operation="close")
    assert owner.exchange(original)["operation"] == "read_reader"
    assert state["observed"] == 3


def test_close_response_is_not_whole_process_cleanup_and_settle_only_releases(fake):
    build, state, _runtime, active, _quarantined = fake
    owner = build()
    owner.start()
    result = owner.exchange(request("close"))
    assert result["outcome"] == "closed" and not owner._settled
    assert not owner.settle()
    assert owner._process in active
    observed, launches = state["observed"], state["launches"]
    state["release"] = True
    assert owner.settle() and owner.settle()
    assert not active and state["observed"] == observed and state["launches"] == launches


def test_concurrent_start_is_not_queued_or_created(fake):
    build, state, *_rest = fake
    owner = build()
    owner._lock.acquire()
    try:
        with pytest.raises(MacOSFileAccessContractError):
            owner.start()
    finally:
        owner._lock.release()
    assert state["launches"] == 0


def test_successful_launch_child_close_failure_stays_unknown(fake):
    build, state, _runtime, active, quarantined = fake
    owner = build()
    owner._child_channel.fail_close = True
    with pytest.raises(OSError):
        owner.start()
    assert owner._child_channel.closed and owner._child_channel.close_calls == 1
    assert owner._process in quarantined
    state["release"] = True
    assert not owner.settle() and not owner.settle()
    assert state["releases"] == 2 and not active
    assert owner._child_channel.close_calls == 1 and not owner._settled


@pytest.mark.parametrize("phase", ["start_error", "exchange_error", "settle"])
def test_channel_close_failure_stays_unknown_while_runtime_release_is_attempted(fake, phase):
    build, state, _runtime, active, _quarantined = fake
    owner = build()
    if phase == "start_error":
        state["mode"] = "before_proof"
    else:
        owner.start()
    owner._channel.stream.fail_close = True
    if phase == "start_error":
        with pytest.raises(OSError):
            owner.start()
    elif phase == "exchange_error":
        owner._channel.after = lambda: state.update(monotonic=request()["deadline_ns"])
        with pytest.raises(OSError):
            owner.exchange(request())
    else:
        assert not owner.settle()
    assert owner._channel.local_cleanup_unknown
    state["release"] = True
    assert not owner.settle() and not owner.settle()
    assert state["releases"] >= 2 and not active
    assert owner._channel.stream.close_calls == 1 and not owner._settled


def test_earlier_channel_close_uncertainty_survives_successful_abandon(fake):
    build, state, _runtime, active, _quarantined = fake
    owner = build()
    owner.start()

    def failed_inside_channel():
        owner._channel._local_cleanup_unknown = True
        raise OSError("fake earlier channel close failure")

    owner._channel.after = failed_inside_channel
    with pytest.raises(OSError):
        owner.exchange(request())
    assert owner._channel.stream.closed and owner._channel.stream.close_calls == 1
    state["release"] = True
    assert not owner.settle() and not owner.settle()
    assert state["releases"] == 2 and not active and not owner._settled


def test_settle_before_start_retains_child_close_failure(fake):
    build, state, *_rest = fake
    owner = build()
    owner._child_channel.fail_close = True
    assert not owner.settle() and not owner.settle()
    assert owner._child_channel.closed and owner._child_channel.close_calls == 1
    assert state["releases"] == 0 and not owner._settled
