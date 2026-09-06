"""Owned-session state tests with fake processes; no subprocesses are launched."""

from __future__ import annotations

import copy
import io
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bluefire import receiver_session as session_module
from bluefire.receiver_policy import REDACTED_ONLY_POLICY, ReceiverContentPolicy
from bluefire.receiver_session import OwnedReceiverSession
from bluefire.receiver_session_contract import (
    ReceiverSessionError,
    decode_frame,
    encode_frame,
    prepare_frame,
    ready_binding,
    task_frame,
    validate_ready,
    validate_terminal,
)
from bluefire.util import content_hash
from tests_platform.test_receiver_policy import public_records

GENERATION = "sha256:" + "1" * 64
TASK_ID = "execute-" + "2" * 64


def documents():
    prepared = prepare_frame(
        launch_id="3" * 64,
        policy_id=REDACTED_ONLY_POLICY,
        port=4317,
        generation=GENERATION,
        deadline_ns=time.monotonic_ns() + 60_000_000_000,
        expires_at_ms=time.time_ns() // 1_000_000 + 60_000,
    )
    binding = ready_binding(
        prepared, session_id="4" * 64, process_id=901, creation_identity="123456"
    )
    decision = dict(ReceiverContentPolicy(REDACTED_ONLY_POLICY).inspect(public_records()))
    decision.update(
        schema_version="bluefire.receiver-content-decision.v1",
        task_id=TASK_ID,
        receiver_session_id="4" * 64,
        receiver_process_id=901,
        authenticated=True,
    )
    task = task_frame(
        binding,
        task_id=TASK_ID,
        digest=decision["sha256"],
        size=decision["bytes_received"],
        review_digest=binding["review_digest"],
        now_ns=time.monotonic_ns(),
    )
    terminal = {
        "kind": "terminal",
        "review_digest": binding["review_digest"],
        "task_digest": content_hash(task),
        "summary": {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "content_policy_decision",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 0,
            "requests_refused": 1,
        },
        "decision": decision,
    }
    return prepared, binding, task, terminal


@pytest.mark.parametrize(
    "field,value",
    [
        ("receiver_process_id", 902),
        ("creation_identity", "other"),
        ("port", 4318),
        ("deadline_ns", 0),
        ("policy_digest", GENERATION),
        ("worker_generation", "sha256:" + "9" * 64),
        ("maximum_decisions", True),
    ],
)
def test_ready_identity_binds_every_reviewed_dimension(field, value):
    prepared, binding, _task, _terminal = documents()
    binding[field] = value
    with pytest.raises(ReceiverSessionError):
        validate_ready(
            {"kind": "ready", "binding": binding},
            prepared,
            process_id=901,
            creation_identity="123456",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_id", "other"),
        ("sha256", "9" * 64),
        ("bytes_received", True),
        ("receiver_session_id", "5" * 64),
        ("receiver_process_id", 902),
        ("policy_digest", GENERATION),
        ("authenticated", False),
    ],
)
def test_terminal_rejects_foreign_task_body_session_policy_and_process_identity(field, value):
    _prepared, binding, task, terminal = documents()
    terminal["decision"][field] = value
    with pytest.raises(ReceiverSessionError):
        validate_terminal(terminal, binding, task)


def test_frame_parser_rejects_extra_fields_duplicate_fields_and_truncation():
    _prepared, binding, task, terminal = documents()
    assert decode_frame(encode_frame(terminal)) == terminal
    for payload in (b'{"kind":"ready","kind":"terminal"}\n', b"{}", b"x" * 8193):
        with pytest.raises(ReceiverSessionError):
            decode_frame(payload)
    terminal["body"] = "not permitted"
    with pytest.raises(ReceiverSessionError):
        validate_terminal(terminal, binding, task)


class Stream(io.BytesIO):
    def fileno(self):
        return 17


class Process:
    pid = 901
    returncode = None

    def __init__(self):
        self.stdin = Stream()
        self.stdout = Stream()


class Containment:
    def __init__(self, process, *, release=True):
        self.process = process
        self.succeeds = release
        self.released = False
        self.calls = []

    def contains(self, _process):
        return not self.released

    def was_released(self, _process):
        return self.released

    def release(self, process, *, terminate):
        self.calls.append(terminate)
        if self.succeeds:
            self.released = True
            process.returncode = 0
        return self.succeeds


def monitored(monkeypatch, *, release=True, terminal_change=None, missing_terminal=False):
    _prepared, binding, task, terminal = documents()
    if terminal_change:
        terminal_change(terminal)
    session = OwnedReceiverSession()
    process = Process()
    containment = Containment(process, release=release)
    session._process = process
    session._containment = containment
    session._binding = binding
    session._task = task
    frames = iter(
        [
            {
                "kind": "bound",
                "review_digest": binding["review_digest"],
                "task_digest": content_hash(task),
            }
        ]
        + ([] if missing_terminal else [terminal])
    )
    monkeypatch.setattr(session_module, "read_frame", lambda *_args, **_kwargs: next(frames))
    monkeypatch.setattr(session_module, "require_eof", lambda _descriptor: None)
    monkeypatch.setattr(session_module, "_RETAINED", {})
    session._monitor()
    return session, containment


def test_decision_becomes_observed_only_after_exact_owned_process_reconciliation(monkeypatch):
    session, containment = monitored(monkeypatch)
    observed = session.wait_observation(timeout_seconds=0)
    assert observed["state"] == "verified"
    assert observed["terminal"]["decision"]["decision"] == "policy_refused"
    assert observed["process_exit"] == {
        "process_id": 901,
        "creation_identity": "123456",
        "returncode": 0,
        "observed_at_ms": observed["process_exit"]["observed_at_ms"],
    }
    assert containment.calls == [False]
    observed["terminal"]["decision"]["decision"] = "accepted"
    assert (
        session.wait_observation(timeout_seconds=0)["terminal"]["decision"]["decision"]
        == "policy_refused"
    )


def test_missing_terminal_is_insufficient_and_never_a_zero_match_or_success(monkeypatch):
    session, containment = monitored(monkeypatch, missing_terminal=True)
    assert session.wait_observation(timeout_seconds=0)["state"] == "insufficient_evidence"
    assert containment.calls == [True]


def test_failed_exit_keeps_recoverable_owned_process_and_no_verified_observation(monkeypatch):
    session, containment = monitored(monkeypatch, release=False)
    assert session.wait_observation(timeout_seconds=0)["state"] == "insufficient_evidence"
    assert session_module._RETAINED[session._launch_id] is session
    assert not session._process.stdout.closed
    containment.succeeds = True
    assert session_module.reconcile_retained_receiver_sessions() == {
        "reconciled": 1,
        "remaining": 0,
    }
    assert session._process.stdout.closed
    # Retrying cleanup cannot retroactively create missing evidence.
    assert session.wait_observation(timeout_seconds=0)["state"] == "insufficient_evidence"


@pytest.mark.parametrize("change", ["expired", "review", "generation", "consumed"])
def test_stale_readiness_never_silently_refreshes_or_rebinds(monkeypatch, change):
    _prepared, binding, task, _terminal = documents()
    session = OwnedReceiverSession()
    session._binding = copy.deepcopy(binding)
    if change == "expired":
        session._binding["deadline_ns"] = time.monotonic_ns() - 1
    if change == "consumed":
        session._task = task
    monkeypatch.setattr(
        session_module,
        "worker_generation",
        lambda: "changed" if change == "generation" else GENERATION,
    )
    writes = []
    monkeypatch.setattr(session_module, "write_frame", lambda *_args: writes.append(True))
    with pytest.raises(ReceiverSessionError):
        session.bind_task(
            TASK_ID,
            digest=task["sha256"],
            size=task["size_bytes"],
            review_digest="changed" if change == "review" else binding["review_digest"],
        )
    assert writes == []


def test_platform_unavailability_precedes_any_spawn(monkeypatch):
    monkeypatch.setattr(session_module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(
        session_module,
        "_spawn_owned_worker",
        lambda *_args: pytest.fail("spawned on unavailable platform"),
    )
    with pytest.raises(ReceiverSessionError, match="Linux"):
        OwnedReceiverSession.prepare(REDACTED_ONLY_POLICY)


def test_fixed_worker_launch_pins_both_inodes_and_has_no_caller_command_or_environment(
    monkeypatch, tmp_path
):
    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"not executed")
    active = []
    captures = []

    @contextmanager
    def pin(path, digest):
        assert digest == GENERATION
        descriptor = 80 + len(active)
        active.append(path)
        try:
            yield f"/proc/self/fd/{descriptor}", (descriptor,)
        finally:
            active.pop()

    class FakePopen:
        @classmethod
        def __class_getitem__(cls, _item):
            return cls

        def __init__(self, argv, **options):
            assert len(active) == 2
            captures.append((argv, options))

    monkeypatch.setattr(session_module, "sys", SimpleNamespace(executable=str(interpreter)))
    monkeypatch.setattr(session_module.Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setattr(session_module, "managed_product_root", lambda: tmp_path / "bluefire-nexus")
    monkeypatch.setattr(session_module, "file_hash", lambda _path: GENERATION)
    monkeypatch.setattr(session_module, "_pinned_launch_file", pin)
    monkeypatch.setattr(
        session_module, "subprocess", SimpleNamespace(Popen=FakePopen, PIPE=-1, DEVNULL=-3)
    )
    sink = []
    process = session_module._spawn_owned_worker("3" * 64, sink)
    assert sink == [process]
    argv, options = captures[0]
    assert argv == [
        str(interpreter),
        "-I",
        "/proc/self/fd/81",
        "--parent",
        str(session_module.os.getpid()),
        "--launch",
        "3" * 64,
    ]
    assert options["executable"] == "/proc/self/fd/80"
    assert options["shell"] is False and options["start_new_session"] is True
    assert options["pass_fds"] == (80, 81) and options["close_fds"] is True
    assert set(options["env"]) == {"HOME", "XDG_STATE_HOME", "LANG", "LC_ALL"}
    assert options["env"]["XDG_STATE_HOME"] == str(tmp_path)
    assert options["stderr"] == -3
    assert active == []


def test_constructor_interruption_retains_then_pins_and_reconciles_the_partial_child(monkeypatch):
    process = Process()
    process._child_created = True
    events = []

    class Guard:
        registered = False
        released = False

        @staticmethod
        def available():
            return True

        def contains(self, _process):
            return self.registered and not self.released

        def was_released(self, _process):
            return self.released

        def register(self, actual):
            assert actual is process
            events.append("pin")
            self.registered = True

        def release(self, actual, *, terminate):
            assert actual is process and terminate and self.registered
            events.append("reconcile")
            self.released = True
            actual.returncode = -15
            return True

    def interrupted(_launch, sink):
        sink.append(process)
        raise KeyboardInterrupt()

    monkeypatch.setattr(session_module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(session_module, "LinuxPrivateProcessContainment", Guard)
    monkeypatch.setattr(session_module, "worker_generation", lambda: GENERATION)
    monkeypatch.setattr(session_module, "_spawn_owned_worker", interrupted)
    with pytest.raises(KeyboardInterrupt):
        OwnedReceiverSession.prepare(REDACTED_ONLY_POLICY)
    assert events == ["pin", "reconcile"]
    assert process.stdin.closed and process.stdout.closed
