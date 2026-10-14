"""Pinned v3 query with fake handles, subprocess, Job and protected source only."""

from __future__ import annotations

import io
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_correction_capability as module
from bluefire import windows_file_access_correction_child as child
from bluefire.util import canonical_json_bytes
from tests_platform.test_windows_file_access_correction_control_process import (
    control_child as control_child,
)
from tests_platform.test_windows_file_access_correction_control_process import frame
from tests_platform.test_windows_file_access_correction_credential import correction as correction
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_pair_observation import pair_observed as pair_observed


def capability_record(version):
    return {
        "schema_version": "bluefire.windows-file-worker-capability.v3",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": version,
        "platform": "windows",
        "architecture": "x86_64",
        "supported": True,
        "worker_command": "windows-file-correction-worker",
        "worker_schema": "bluefire.windows-file-worker-request.v3",
        "read_schema": "bluefire.windows-fixed-read-pair-correction.v3",
        "scope": "protocol_support_only",
        "action_id": "private.windows.file_read_pair_correction.v3",
        "capability": "windows_file_read_pair_correction",
        "max_data_opens": 2,
        "max_bytes_per_read": 1048576,
        "max_total_read_bytes": 2097152,
        "max_execution_ms": 5000,
    }


@pytest.fixture
def capability(correction, monkeypatch):
    c = correction
    c.state["pairs"] = c.state["channels"] = 0
    flags = SimpleNamespace(fault=None, queried=False)
    opened, closed, streams, queries, jobs = {}, [], {}, [], []
    source = json.loads(c.checked_setup._receipt)["source"]
    version = source["capability"]["runner_version"]
    image_identity = source["native_image"]["identity"]
    volume = int(image_identity["volume_serial"], 16)
    file_id = int.from_bytes(bytes.fromhex(image_identity["file_id"]), "little")
    old_read = module.observe.os.read

    def open_metadata(path, *, directory, data):
        assert data is not directory
        descriptor = 100 + len(opened)
        opened[descriptor] = (str(path), directory)
        if not directory:
            assert str(path) == c.image
            streams[descriptor] = io.BytesIO(c.backend.files[c.image])
        return descriptor

    def facts(descriptor, *, directory):
        path, actual = opened[descriptor]
        assert directory is actual
        identity = (volume, file_id if not directory else len(path) + 50)
        changed = 3
        if flags.queried and flags.fault == ("ancestor" if directory else "image"):
            changed = 4
        return SimpleNamespace(
            identity=identity,
            final_path="\\\\?\\" + path,
            size=0 if directory else source["native_image"]["size_bytes"],
            changed=changed,
        )

    def read(descriptor, size):
        return (
            streams[descriptor].read(size) if descriptor in streams else old_read(descriptor, size)
        )

    def close(descriptor):
        closed.append(descriptor)
        if flags.fault == "close" and descriptor == 100:
            raise OSError("synthetic held handle ambiguity")

    class JobApi:
        def current_job(self):
            jobs.append("same-retained-job")
            if flags.fault == "job" or (flags.fault == "job-after-query" and flags.queried):
                raise RuntimeError("synthetic Job membership drift")

    def query(argv, **kwargs):
        assert argv == [c.image, "windows-file-correction-worker-capability"]
        assert kwargs["stdin"] == module.subprocess.DEVNULL
        assert kwargs["shell"] is kwargs["check"] is False and kwargs["close_fds"] is True
        assert kwargs["creationflags"] == 0x08000000
        assert 0 < kwargs["timeout"] <= 5
        assert opened and not closed
        queries.append((argv, kwargs["timeout"]))
        row = capability_record(version)
        if flags.fault == "unsupported":
            row["supported"] = False
        elif flags.fault == "v2":
            row = source["capability"]
        elif flags.fault == "version":
            row["runner_version"] = "99.0.0"
        elif flags.fault == "bool-bound":
            row["max_execution_ms"] = 5000.0
        elif flags.fault == "truthy-support":
            row["supported"] = 1
        elif flags.fault == "extra":
            row["access_proof"] = True
        raw = canonical_json_bytes(row)
        if flags.fault == "oversize":
            raw += b" " * 1025
        elif flags.fault == "malformed":
            raw = b"not JSON"
        kwargs["stdout"].write(raw)
        if flags.fault == "stderr":
            kwargs["stderr"].write(b"synthetic private failure")
        flags.queried = True
        if flags.fault == "late-query":
            c.state["mono"] += kwargs["timeout"]
        elif flags.fault == "expired-query":
            c.state["wall"] = c.binding["expires_at_ms"]
        elif flags.fault == "owner":
            c.state["owner"] = replace(c.backend.owner, token_id=999)
        elif flags.fault == "channel":
            c.state["fault"] = "channel"
            c.state["channels"] = 1
        return SimpleNamespace(returncode=4 if flags.fault == "exit" else 0)

    monkeypatch.setattr(module.handles, "open_observation", open_metadata)
    monkeypatch.setattr(module.handles, "inspect_observation", facts)
    monkeypatch.setattr(module.observe, "os", SimpleNamespace(fspath=str, read=read))
    monkeypatch.setattr(module, "os", SimpleNamespace(fspath=str, close=close))
    monkeypatch.setattr(module.supervision, "_Api", JobApi)
    monkeypatch.setattr(module.tempfile, "TemporaryFile", io.BytesIO)
    monkeypatch.setattr(module.subprocess, "run", query)

    def held(deadline=14.0, cancelled=lambda: False):
        return module.held_correction_capability(
            c.checked_setup,
            original_deadline=deadline,
            expires_at_ms=c.binding["expires_at_ms"],
            cancelled=cancelled,
        )

    return SimpleNamespace(**locals())


def test_exact_v3_support_queries_once_keeps_image_and_ancestors_held(capability):
    v = capability
    with v.held() as recheck:
        assert not v.closed and v.jobs
        recheck()
        assert len(v.queries) == 1
        assert any(directory for _, directory in v.opened.values())
        assert any(not directory for _, directory in v.opened.values())
    assert len(v.closed) == len(v.opened) and set(v.closed) == set(v.opened)


@pytest.mark.parametrize(
    "fault",
    [
        "unsupported",
        "v2",
        "version",
        "bool-bound",
        "truthy-support",
        "extra",
        "oversize",
        "malformed",
        "stderr",
        "exit",
        "late-query",
        "expired-query",
        "owner",
        "channel",
        "image",
        "ancestor",
        "job",
        "job-after-query",
        "close",
    ],
)
def test_unsupported_drift_late_or_unclean_never_returns_verified_support(capability, fault):
    v = capability
    v.flags.fault = fault
    with pytest.raises(module.WindowsCorrectionCapabilityError) as error:
        with v.held():
            assert fault == "close"
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert "synthetic" not in str(error.value)
    assert len(v.closed) == len(v.opened) and set(v.closed) == set(v.opened)


def test_query_limit_is_five_seconds_without_renewing_or_shortening_operation(capability):
    v = capability
    with v.held(deadline=20.0) as recheck:
        assert v.queries[0][1] == 5.0
        v.c.state["mono"] = 16.0
        v.c.state["wall"] += 6000
        recheck()
        assert len(v.queries) == 1


@pytest.mark.parametrize("fault", ["deadline", "cancelled"])
def test_original_deadline_or_cancellation_refuses_before_query(capability, fault):
    v = capability
    with pytest.raises(module.WindowsCorrectionCapabilityError):
        with v.held(
            deadline=10.0 if fault == "deadline" else 14.0, cancelled=lambda: fault == "cancelled"
        ):
            pytest.fail("No expired support context")
    assert v.queries == [] and v.opened == {}


@pytest.mark.parametrize("fault", ["v2", "unsupported"])
def test_old_v2_only_or_unsupported_image_fails_before_correction_transition(
    capability, control_child, monkeypatch, fault
):
    v, control = capability, control_child
    v.flags.fault = fault
    monkeypatch.setattr(child, "held_correction_capability", module.held_correction_capability)
    output = io.BytesIO()
    assert child._run(io.BytesIO(frame(control.request)), output) == 4
    assert json.loads(output.getvalue()[4:])["result"] is None
    assert "transition" not in control.events and control.flags.effects == 0
    assert len(v.queries) == 1 and len(v.closed) == len(v.opened)


def test_child_rechecks_image_channel_before_setter_with_handles_still_held(
    capability, control_child, monkeypatch
):
    v, control = capability, control_child
    monkeypatch.setattr(child, "held_correction_capability", module.held_correction_capability)
    old_transition = child.transition_windows_file_access

    def transition(request, *, admit, before_apply):
        assert not v.closed and len(v.queries) == 1
        return old_transition(request, admit=admit, before_apply=before_apply)

    monkeypatch.setattr(child, "transition_windows_file_access", transition)
    output = io.BytesIO()
    assert child._run(io.BytesIO(frame(control.request)), output) == 0
    assert json.loads(output.getvalue()[4:])["result"]["target"] == "metadata_only"
    assert control.flags.effects == 1 and len(v.queries) == 1
    assert len(v.closed) == len(v.opened)


@pytest.mark.parametrize("fault", ["image", "ancestor", "channel", "job", "owner", "deadline"])
def test_post_admission_drift_is_rechecked_before_any_setter(
    capability, control_child, monkeypatch, fault
):
    v, control = capability, control_child
    monkeypatch.setattr(child, "held_correction_capability", module.held_correction_capability)
    old_transition = child.transition_windows_file_access

    def transition(request, *, admit, before_apply):
        def admitted():
            admit()
            if fault == "channel":
                v.c.state["fault"] = "channel"
                v.c.state["channels"] = 1
            elif fault == "owner":
                v.c.state["owner"] = replace(v.c.backend.owner, token_id=999)
            elif fault == "deadline":
                v.c.state["mono"] = 14.0
            else:
                v.flags.fault = fault

        return old_transition(request, admit=admitted, before_apply=before_apply)

    monkeypatch.setattr(child, "transition_windows_file_access", transition)
    output = io.BytesIO()
    assert child._run(io.BytesIO(frame(control.request)), output) == 4
    assert json.loads(output.getvalue()[4:])["result"] is None
    assert control.flags.effects == 0 and len(v.queries) == 1
    assert len(v.closed) == len(v.opened)
