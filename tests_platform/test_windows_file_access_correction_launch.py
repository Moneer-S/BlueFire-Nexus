"""Synthetic correction launcher routing; all process and handle seams are faked."""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_pair_launch as module
from bluefire import windows_file_access_correction_admission as correction_admission
from bluefire import windows_file_access_correction_credential as correction_credential
from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_process as supervisor
from bluefire.util import content_hash
from tests_platform import test_windows_file_access_pair_launch as pair_launch
from tests_platform import test_windows_file_access_pair_wire as pair_wire

pytest_plugins = ("tests_platform.test_windows_file_access_correction_credential",)


@pytest.fixture
def launch_harness(monkeypatch):
    return pair_launch.harness.__wrapped__(monkeypatch)


def initialized_correction_owner(harness):
    state = harness.state
    owner = object.__new__(module.CorrectionLaunchOwner)
    owner._initialize(
        state.original,
        state.packet,
        state.producer,
        state.revalidate,
        lambda *_args: None,
        state.cancellation,
    )
    owner.record, owner.receipt = state.record, state.receipt
    return owner


@pytest.mark.timeout(15)
def test_correction_owner_uses_fixed_correction_worker_and_releases_pins(
    launch_harness,
):
    owner = initialized_correction_owner(launch_harness)
    owner._launch()

    assert len(launch_harness.popen_calls) == 1
    args, kwargs = launch_harness.popen_calls[0]
    assert args == [os.fspath(pair_launch._IMAGE_PATH), "windows-file-correction-worker"]
    assert kwargs["shell"] is False and kwargs["close_fds"] is True
    assert "pin_enter" in launch_harness.events
    owner._release_resources()
    assert "pin_close" in launch_harness.events


@pytest.mark.timeout(15)
def test_correction_work_routes_only_to_v3_supervisor(launch_harness, monkeypatch):
    owner = initialized_correction_owner(launch_harness)
    owner.process = object()
    owner.job = 5001
    owner.containment = object()
    calls = []

    def supervise(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(dispatch="not_started", issue=None)

    def forbidden_pair(*_args, **_kwargs):
        pytest.fail("correction launch crossed into the pair-v2 supervisor")

    monkeypatch.setattr(owner, "_launch", lambda: None)
    monkeypatch.setattr(module.supervisor, "supervise_correction_suspended", supervise)
    monkeypatch.setattr(module.supervisor, "supervise_pair_suspended", forbidden_pair)
    owner._work()

    assert len(calls) == 1
    assert calls[0][0][0] is owner.process
    assert owner._protocol is supervisor._Protocol.CORRECTION_V3
    assert calls[0][1]["prepared_packet"] is owner.packet


@pytest.mark.timeout(15)
def test_pair_v2_postimage_and_original_are_refused_before_any_pin(launch_harness, monkeypatch):
    state = launch_harness.state
    monkeypatch.setattr(module.sys, "platform", "win32")

    with pytest.raises(Exception):
        module.launch_correction_retest(
            state.checked,
            state.original,
            state.packet,
            state.producer,
            revalidate_original=state.revalidate,
            evidence_sink=lambda *_args: None,
            cancellation_event=state.cancellation,
        )

    assert launch_harness.popen_calls == []
    assert "pin_enter" not in launch_harness.events


@pytest.mark.timeout(15)
def test_wrong_producer_and_v1_original_are_refused_before_side_effects(correction):
    c = correction
    with pytest.raises(Exception):
        module.CorrectionLaunchOwner(
            c.checked,
            c.original,
            c.packet,
            None,
            c.revalidate,
            lambda *_args: None,
            c.cancelled,
        )
    legacy_original, legacy_packet, _ = pair_wire.prepared()
    with pytest.raises(Exception):
        module.CorrectionLaunchOwner(
            c.checked,
            legacy_original,
            legacy_packet,
            c.producer,
            c.revalidate,
            lambda *_args: None,
            c.cancelled,
        )


@pytest.mark.timeout(15)
def test_valid_postimage_binds_exact_correction_producer(correction):
    c = correction
    owner = module.CorrectionLaunchOwner(
        c.checked,
        c.original,
        c.packet,
        c.producer,
        c.revalidate,
        lambda *_args: None,
        c.cancelled,
    )
    assert owner._protocol is supervisor._Protocol.CORRECTION_V3
    assert owner.producer is c.producer and owner.packet is c.packet

    with pytest.raises(Exception):
        module.CorrectionLaunchOwner(
            c.checked,
            c.original,
            c.packet,
            object(),
            c.revalidate,
            lambda *_args: None,
            c.cancelled,
        )


@pytest.mark.timeout(15)
def test_valid_postimage_rejects_original_with_different_binding(correction):
    c = correction
    alternate_binding = {
        **c.binding,
        "previous_descriptor_sha256": content_hash({"synthetic": "other-descriptor"}),
    }
    context, expected = correction_admission.build_retest_original(
        alternate_binding,
        c.checked_setup,
        issued_at_ms=c.state["wall"],
        reviewed_by="synthetic-operator",
    )
    alternate_original = wire.validate_correction_original_reservation(
        context, expected_binding=expected
    )
    alternate_packet = wire.prepare_correction_packet(
        alternate_original,
        challenge="e" * 64,
        clock=c.utc(),
        monotonic_now=c.state["mono"],
        original_monotonic_deadline=14.0,
    )
    producer = object.__new__(correction_credential.CorrectionBeginProducer)
    producer._checked = c.checked
    producer._original = alternate_original
    producer._packet = alternate_packet
    producer._cancellation = c.cancelled

    with pytest.raises(Exception):
        module.CorrectionLaunchOwner(
            c.checked,
            alternate_original,
            alternate_packet,
            producer,
            c.revalidate,
            lambda *_args: None,
            c.cancelled,
        )
    with pytest.raises(Exception):
        module.CorrectionLaunchOwner(
            checked,
            state.original,
            state.packet,
            state.producer,
            state.revalidate,
            lambda *_args: None,
            state.cancellation,
        )


@pytest.mark.timeout(15)
def test_pre_begin_process_creation_failure_stops_producer_and_releases_pin(
    launch_harness, monkeypatch
):
    owner = initialized_correction_owner(launch_harness)
    state = launch_harness.state
    monkeypatch.setattr(
        module.subprocess, "Popen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )

    owner._work()

    assert owner.process is None
    assert owner.issue == "launch_unknown"
    assert state.producer._stopped.is_set()
    assert "pin_enter" in launch_harness.events
    assert "pin_close" in launch_harness.events
    assert not launch_harness.popen_calls
