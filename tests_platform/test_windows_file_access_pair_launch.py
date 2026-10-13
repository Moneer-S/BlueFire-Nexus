"""Fixed pair launcher using fake image handles, pipes, Popen and Job APIs only."""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_pair_launch as module
from bluefire.util import canonical_json_bytes
from tests_platform import test_windows_file_access_pair_credential as credential_fakes
from tests_platform import test_windows_file_access_pair_provenance as provenance
from tests_platform import test_windows_file_access_pair_wire as pair
from tests_platform import test_windows_file_access_process as process_fakes
from tests_platform.test_windows_file_access_pair_process import partial as partial_pair

_ROOT = Path("C:/managed-bluefire")
_IMAGE_PATH = _ROOT / "bluefire-runner.exe"
_IMAGE = b"synthetic held runner image"
_IMAGE_SHA = "sha256:" + hashlib.sha256(_IMAGE).hexdigest()
_FILE_ID = "0102030405060708090a0b0c0d0e0f10"


class LaunchContainment(process_fakes.Containment):
    def __init__(self, events):
        super().__init__()
        self.events = events

    def system_directory(self):
        return Path("C:/Windows/System32")

    def create_job(self):
        self.events.append("job_create")
        return 5001

    def close_handle(self, handle):
        self.events.append(("job_close", handle))
        return handle == 5001


class TracedPipe(process_fakes.Pipe):
    def __init__(self, events, label, data=b"", eof=None):
        super().__init__(data, eof)
        self.events, self.label = events, label

    def close(self):
        self.events.append(("pipe_close", self.label))
        super().close()


@pytest.fixture
def harness(monkeypatch):
    process_fakes.setup.__wrapped__(monkeypatch)
    state = credential_fakes.boundary.__wrapped__(monkeypatch)
    source = provenance.pair_source()
    image = {
        "sha256": _IMAGE_SHA,
        "size_bytes": len(_IMAGE),
        "identity": {"volume_serial": "fedcba9876543210", "file_id": _FILE_ID},
    }
    source["native_image"] = image
    source["transport"]["runner_binary_digest"] = _IMAGE_SHA
    state.record["native_image"] = image
    state.receipt["source"] = source

    retained = module.wire.validate_pair_retained_packet(state.original, state.packet._raw)
    ready, terminal = pair.envelopes(retained)
    ready_bytes, terminal_bytes = canonical_json_bytes(ready), canonical_json_bytes(terminal)
    output_bytes = [process_fakes.framed(ready_bytes) + process_fakes.framed(terminal_bytes)]
    exit_code = [0]

    events, image_paths, descriptors, offsets, streams = [], [], {}, {}, []
    popen_calls, containment_instances, process_holder = [], [], []
    pipe_pairs = []
    pin_exit_entered, pin_exit_release = threading.Event(), threading.Event()
    pin_exit_block = [False]
    next_descriptor = [100]
    source_transport = source["transport"]
    manifest = SimpleNamespace(
        sha256=_IMAGE_SHA.removeprefix("sha256:"),
        size=len(_IMAGE),
        runner_version="0.1.0",
    )
    bootstrap_digest = [_IMAGE_SHA]
    client_transport = [source_transport]

    class PinnedDirectory:
        def __init__(self, path, **kwargs):
            assert path == _ROOT and kwargs == {
                "private": True,
                "verify_permissions_only": True,
            }

        def __enter__(self):
            events.append("pin_enter")
            return self

        def __exit__(self, *_args):
            if pin_exit_block[0]:
                pin_exit_entered.set()
                pin_exit_release.wait(timeout=8)
            events.append("pin_close")

    class Lifecycle:
        def __init__(self, root):
            assert root == _ROOT

        def _load_active_enrollment(self):
            return object()

        def _load_bootstrap(self, _local):
            return SimpleNamespace(
                source="packaged",
                managed_binary=True,
                binary_digest=bootstrap_digest[0],
                runner_version="0.1.0",
                binary_path=_IMAGE_PATH,
            )

        def client_for_profile(self, profile_id):
            assert profile_id == source["source_profile_id"]
            client = SimpleNamespace(transport_identity=lambda: client_transport[0])
            return client, None

    def open_observation(path, *, directory, data=False):
        assert data is not directory
        descriptor = next_descriptor[0]
        next_descriptor[0] += 1
        image_paths.append((path, directory, data))
        descriptors[descriptor] = (path, directory)
        offsets[descriptor] = 0
        return descriptor

    def inspect_observation(descriptor, *, directory):
        path, stored_directory = descriptors[descriptor]
        assert directory is stored_directory
        identity = (1, 1) if directory else (2, 2)
        return SimpleNamespace(
            identity=identity,
            final_path="\\\\?\\" + os.fspath(path),
            directory=directory,
            size=0 if directory else len(_IMAGE),
            links=1,
            attributes=0,
            created=1,
            written=2,
            changed=3,
        )

    def read_image(descriptor, count):
        assert descriptor in descriptors and not descriptors[descriptor][1]
        offset = offsets[descriptor]
        chunk = _IMAGE[offset : offset + count]
        offsets[descriptor] += len(chunk)
        return chunk

    def fake_pipe():
        read, write = next_descriptor[0], next_descriptor[0] + 1
        next_descriptor[0] += 2
        pipe_pairs.append((read, write))
        return read, write

    def fake_fdopen(_descriptor, mode, *, buffering):
        assert buffering == 0
        if mode == "wb":
            stream = TracedPipe(events, "stdin")
        elif not any(item.label == "stdout" for item in streams):

            def eof():
                if process_holder:
                    process_holder[0].exit()

            stream = TracedPipe(events, "stdout", output_bytes[0], eof)
        else:
            stream = TracedPipe(events, "stderr")
        streams.append(stream)
        return stream

    def fake_close(descriptor):
        events.append(("fd_close", descriptor))

    def fake_popen(args, **kwargs):
        popen_calls.append((args, kwargs))
        child = process_fakes.Process(b"", b"", exit_code[0])
        original_close = child._handle.Close

        def close_handle():
            events.append("process_handle_close")
            original_close()

        child._handle.Close = close_handle
        process_holder.append(child)
        return child

    def containment_factory(*, kill_on_close):
        assert kill_on_close is True
        instance = LaunchContainment(events)
        containment_instances.append(instance)
        return instance

    monkeypatch.setattr(module, "_utc", lambda: pair.v1.NOW)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: 100.0))
    monkeypatch.setattr(module, "_managed_root", lambda: _ROOT)
    monkeypatch.setattr(module, "_PinnedDirectory", PinnedDirectory)
    monkeypatch.setattr(module, "ManagedRunnerLifecycle", Lifecycle)
    monkeypatch.setattr(module, "load_runner_manifest", lambda **_kwargs: manifest)
    monkeypatch.setattr(module.handles, "open_observation", open_observation)
    monkeypatch.setattr(module.handles, "inspect_observation", inspect_observation)
    monkeypatch.setattr(
        module, "file_identity_wire", lambda *_identity: ("fedcba9876543210", _FILE_ID)
    )
    monkeypatch.setattr(module.os, "read", read_image)
    monkeypatch.setattr(module.os, "pipe", fake_pipe)
    monkeypatch.setattr(module.os, "fdopen", fake_fdopen)
    monkeypatch.setattr(module.os, "close", fake_close)
    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(module, "WindowsJobContainment", containment_factory)
    return SimpleNamespace(
        state=state,
        events=events,
        image_paths=image_paths,
        descriptors=descriptors,
        streams=streams,
        popen_calls=popen_calls,
        containments=containment_instances,
        process_holder=process_holder,
        pipe_pairs=pipe_pairs,
        bootstrap_digest=bootstrap_digest,
        client_transport=client_transport,
        pin_exit_entered=pin_exit_entered,
        pin_exit_release=pin_exit_release,
        pin_exit_block=pin_exit_block,
        ready=ready_bytes,
        terminal=terminal_bytes,
        output_bytes=output_bytes,
        exit_code=exit_code,
    )


def launch(harness, *, cancellation=None):
    state = harness.state
    return module.launch_pair_baseline(
        state.checked,
        state.original,
        state.packet,
        state.producer,
        revalidate_original=state.revalidate,
        evidence_sink=lambda *_args: None,
        cancellation_event=cancellation or state.cancellation,
    )


def test_pinned_pair_image_launch_uses_fixed_command_and_closes_everything(harness):
    result = launch(harness)

    assert result.process is not None and result.process.projection is not None
    assert result.process.cleanup == result.cleanup == "verified" and result.settled is False
    assert result.process.projection.outcome == "allowed" and not result.process.settled
    assert len(harness.popen_calls) == 1
    args, kwargs = harness.popen_calls[0]
    assert args == [os.fspath(_IMAGE_PATH), "windows-file-baseline-worker"]
    assert kwargs["cwd"] == _ROOT
    assert kwargs["env"] == {
        "SYSTEMROOT": "C:\\Windows",
        "WINDIR": "C:\\Windows",
        "TEMP": os.fspath(_ROOT),
        "TMP": os.fspath(_ROOT),
    }
    assert kwargs["shell"] is False and kwargs["close_fds"] is True and kwargs["bufsize"] == 0
    assert kwargs["creationflags"] == 0x08000000 | 0x00000200 | 0x00000004
    assert [entry[0] for entry in harness.image_paths] == [Path("C:/"), _ROOT, _IMAGE_PATH]
    assert [(directory, data) for _, directory, data in harness.image_paths] == [
        (True, False),
        (True, False),
        (False, True),
    ]
    assert "pin_enter" in harness.events and "pin_close" in harness.events
    assert harness.events.index("process_handle_close") < harness.events.index("pin_close")
    assert all(stream.closed for stream in harness.streams)
    assert harness.state.producer.credential_cleanup == "verified"
    assert harness.state.wiped and all(not any(value) for value in harness.state.wiped)


def test_partial_pair_keeps_reader_allowed_owner_unknown_and_cleanup_verified(harness):
    retained = module.wire.validate_pair_retained_packet(
        harness.state.original, harness.state.packet._raw
    )
    ready, terminal = partial_pair(retained)
    ready_bytes, terminal_bytes = canonical_json_bytes(ready), canonical_json_bytes(terminal)
    harness.output_bytes[0] = process_fakes.framed(ready_bytes) + process_fakes.framed(
        terminal_bytes
    )
    harness.exit_code[0] = 4

    result = launch(harness)

    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert result.process is not None and result.process.projection is not None
    assert result.process.projection.reader_outcome == "allowed"
    assert result.process.projection.owner_outcome == "unknown"
    assert result.process.projection.outcome == "unknown"
    assert result.process.issue == "worker_failed" and not result.settled


def test_supervisor_raise_after_retention_reuses_same_owner_without_fallback(harness, monkeypatch):
    real_owner = module.PairLaunchOwner
    owners = []

    class TrackedPairLaunchOwner(real_owner):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owners.append(self)

    real_supervise = module.supervisor.supervise_pair_suspended
    retained, calls = [], []

    def raise_after_retention(*args, **kwargs):
        calls.append(True)
        retain = kwargs["retain_cleanup_owner"]

        def capture(owner):
            retained.append(owner)
            retain(owner)

        kwargs["retain_cleanup_owner"] = capture
        real_supervise(*args, **kwargs)
        raise KeyboardInterrupt()

    monkeypatch.setattr(module, "PairLaunchOwner", TrackedPairLaunchOwner)
    monkeypatch.setattr(module.supervisor, "supervise_pair_suspended", raise_after_retention)
    result = launch(harness)

    assert len(owners) == len(retained) == len(calls) == 1
    assert owners[0].retained_owner is retained[0] and owners[0].transferred
    assert retained[0].adoption_attempted and retained[0].adopted
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert result.process is not None and result.process.projection is None
    assert result.process.dispatch == "unknown" and not result.settled
    assert result.process.cleanup == "verified"
    assert result.process.cleanup_receipt is retained[0].cleanup_receipt
    assert harness.popen_calls and len(harness.popen_calls) == 1
    assert harness.process_holder[0].resumed and len(harness.process_holder[0].stdin.writes) == 2
    assert harness.containments[0].calls.count("adopt") == 1


def test_supervisor_fault_after_retention_before_adoption_reuses_exact_owner(harness, monkeypatch):
    real_cleanup_owner = module.supervisor.CleanupOwner
    cleanup_owners = []

    class TrackedCleanupOwner(real_cleanup_owner):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            cleanup_owners.append(self)

    retained, supervisor_calls = [], []

    def fault_before_adoption(process, **kwargs):
        supervisor_calls.append(True)
        owner = module.supervisor.CleanupOwner(
            process,
            kwargs["owned_job"],
            kwargs["containment"],
            kwargs["prepared_packet"],
            kwargs["original_reservation"],
            kwargs["revalidate_original"],
            kwargs["begin_producer"],
            kwargs["cancellation_event"],
            kwargs["evidence_sink"],
            _protocol=module.supervisor._Protocol.PAIR_V2,
            release_launch_resources=kwargs["release_launch_resources"],
        )
        retained.append(owner)
        kwargs["retain_cleanup_owner"](owner)
        raise KeyboardInterrupt()

    monkeypatch.setattr(module.supervisor, "CleanupOwner", TrackedCleanupOwner)
    monkeypatch.setattr(module.supervisor, "supervise_pair_suspended", fault_before_adoption)
    result = launch(harness)

    assert len(cleanup_owners) == len(retained) == len(supervisor_calls) == 1
    assert retained[0] is cleanup_owners[0] and retained[0].adopted
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert result.process is not None and result.process.projection is None
    assert result.process.dispatch == "not_started" and result.process.cleanup == "verified"
    assert result.process.cleanup_receipt is retained[0].cleanup_receipt
    assert len(harness.popen_calls) == 1 and not harness.process_holder[0].resumed
    assert harness.process_holder[0].stdin.writes == []
    assert harness.containments[0].calls.count("adopt") == 1


def test_blocked_pinned_image_release_cannot_mint_cleanup_receipt(harness, monkeypatch):
    harness.pin_exit_block[0] = True
    real_supervise = module.supervisor.supervise_pair_suspended
    retained = []

    def observe_retention(*args, **kwargs):
        retain = kwargs["retain_cleanup_owner"]

        def capture(owner):
            retained.append(owner)
            retain(owner)

        kwargs["retain_cleanup_owner"] = capture
        return real_supervise(*args, **kwargs)

    monkeypatch.setattr(module.supervisor, "supervise_pair_suspended", observe_retention)
    outcomes = []
    caller = threading.Thread(target=lambda: outcomes.append(launch(harness)), daemon=True)
    caller.start()
    try:
        assert harness.pin_exit_entered.wait(timeout=3)
        caller.join(timeout=4)
        assert not caller.is_alive() and len(outcomes) == 1 and len(retained) == 1
        assert outcomes[0].cleanup == "unknown" and outcomes[0].cleanup_owner is not None
        assert retained[0].cleanup_receipt is None
        assert not retained[0].verified and not retained[0].launch_resources_closed
        assert retained[0].handle_closed and retained[0].job_closed
    finally:
        harness.pin_exit_release.set()
        caller.join(timeout=3)

    assert not caller.is_alive()
    assert outcomes[0].cleanup_owner is not None
    assert outcomes[0].cleanup_owner.retry_cleanup()
    assert retained[0].verified and retained[0].cleanup_receipt is not None


def test_child_end_raw_descriptor_close_exception_is_never_retried(harness, monkeypatch):
    real_close = module.os.close
    attempts = []

    def ambiguous_child_end(descriptor):
        target = harness.pipe_pairs[1][1] if len(harness.pipe_pairs) > 1 else None
        if descriptor == target:
            attempts.append(descriptor)
            raise OSError("synthetic child-end close ambiguity")
        return real_close(descriptor)

    monkeypatch.setattr(module.os, "close", ambiguous_child_end)
    result = launch(harness)
    target = harness.pipe_pairs[1][1]

    assert result.cleanup == "unknown" and result.cleanup_owner is not None
    assert result.cleanup_owner.fd_ambiguous and attempts == [target]
    assert result.process is not None and result.process.cleanup == "unknown"
    assert not harness.process_holder[0].resumed
    assert harness.process_holder[0].stdin.writes == []
    assert len(harness.popen_calls) == 1
    assert result.cleanup_owner.retry_cleanup() is False
    assert attempts == [target]


@pytest.mark.parametrize("fault", ["image_digest", "source_transport"])
def test_invalid_held_image_or_source_refuses_before_popen_and_releases_pin(harness, fault):
    if fault == "image_digest":
        harness.bootstrap_digest[0] = "sha256:" + "b" * 64
    else:
        harness.client_transport[0] = {**harness.client_transport[0], "client_id": "different"}

    result = launch(harness)

    assert result.process is None and result.dispatch == "not_started"
    assert result.cleanup == "verified" and result.issue == "launch_refused"
    assert harness.popen_calls == [] and harness.image_paths == []
    assert harness.events.count("pin_enter") == harness.events.count("pin_close") == 1


def test_original_cancellation_prevents_image_access_and_popen(harness):
    harness.state.cancellation.set()

    result = launch(harness)

    assert result.process is None and result.dispatch == "not_started"
    assert result.cleanup == "verified" and harness.popen_calls == []
    assert harness.image_paths == [] and "pin_enter" not in harness.events


def test_popen_failure_remains_unknown_and_retry_never_relaunches(harness, monkeypatch):
    calls = []

    def fail_popen(*_args, **_kwargs):
        calls.append(True)
        raise KeyboardInterrupt()

    monkeypatch.setattr(module.subprocess, "Popen", fail_popen)
    result = launch(harness)

    assert result.cleanup == "unknown" and result.cleanup_owner is not None
    assert result.dispatch == "unknown" and calls == [True]
    owner = result.cleanup_owner
    assert owner.creation_unknown and owner.process is None and owner.resources_closed
    assert owner.retry_cleanup() is False and calls == [True]


def test_cancel_during_blocked_popen_retains_same_owner_without_begin_or_relaunch(
    harness, monkeypatch
):
    entered, release = threading.Event(), threading.Event()
    original_popen = module.subprocess.Popen
    popen_calls = []

    def delayed_popen(*args, **kwargs):
        popen_calls.append(True)
        entered.set()
        release.wait(timeout=3)
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", delayed_popen)
    trigger = threading.Thread(
        target=lambda: (entered.wait(timeout=2), harness.state.cancellation.set()),
        daemon=True,
    )
    trigger.start()
    result = None
    try:
        result = launch(harness)
        assert entered.is_set() and result.cleanup == "unknown" and result.cleanup_owner is not None
    finally:
        release.set()
        trigger.join(timeout=2)

    owner = result.cleanup_owner
    assert owner is not None and owner.worker is not None
    owner.worker.join(timeout=3)
    assert not owner.worker.is_alive()
    assert owner.retained_owner is not None
    assert owner.retry_cleanup()
    assert owner.result is not None and owner.result.cleanup == "verified"
    assert popen_calls == [True] and owner.process is harness.process_holder[0]
    assert owner.process.stdin.writes == [] and not owner.process.resumed


def test_ambiguous_private_pipe_close_never_claims_cleanup_or_relaunches(harness, monkeypatch):
    real_close = module.os.close
    failed = []

    def ambiguous_close(descriptor):
        if descriptor >= 100 and descriptor % 2 == 0 and not failed:
            failed.append(descriptor)
            raise OSError("synthetic descriptor close ambiguity")
        return real_close(descriptor)

    monkeypatch.setattr(module.os, "close", ambiguous_close)
    result = launch(harness)

    assert result.cleanup == "unknown" and result.cleanup_owner is not None
    owner = result.cleanup_owner
    assert owner.fd_ambiguous and not owner.resources_closed
    assert owner.process is harness.process_holder[0]
    assert owner.process.stdin.writes == [] and not owner.process.resumed
    assert len(harness.popen_calls) == 1 and owner.retry_cleanup() is False


def test_supervisor_handoff_exception_uses_cleanup_only_fallback(harness, monkeypatch):
    calls = []

    def fail_before_owner(*_args, **_kwargs):
        calls.append(True)
        raise KeyboardInterrupt()

    monkeypatch.setattr(module.supervisor, "supervise_pair_suspended", fail_before_owner)
    result = launch(harness)

    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert len(calls) == 1 and len(harness.popen_calls) == 1
    assert result.process is not None and result.process.projection is None
    assert result.process.dispatch == "not_started" and not result.process.settled
    assert not harness.process_holder[0].resumed
    assert harness.process_holder[0].stdin.writes == []
