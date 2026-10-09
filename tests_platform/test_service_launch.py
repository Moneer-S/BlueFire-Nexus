"""Protected launch consistency/refusal tests; no service or manager runs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import bluefire.service_launch as launch
from bluefire.owned_service_authority import (
    ADMISSION_SCHEMA,
    OwnedServiceAdmission,
    OwnedServiceGrant,
)
from bluefire.runner_client import RunnerTransportError, SubprocessRustRunner
from bluefire.runner_host import default_host_command
from bluefire.util import canonical_json_bytes, content_hash, file_hash


@pytest.fixture
def configured(monkeypatch):
    fixture = json.loads(
        Path(__file__).with_name("fixtures").joinpath("owned_service_admission_v1.json").read_text()
    )
    public = {
        "runner_id": fixture["manifest"]["runner_id"],
        "client_id": "synthetic-client",
        "ca_fingerprint": "sha256:" + "1" * 64,
        "server_fingerprint": "sha256:" + "2" * 64,
        "client_fingerprint": "sha256:" + "3" * 64,
    }
    issuer = {
        "runner_id": public["runner_id"],
        "client_id": public["client_id"],
        "enrollment_generation": content_hash(public),
        "peer_fingerprint": public["client_fingerprint"],
        "server_instance_id": "synthetic-host",
    }
    admission = OwnedServiceAdmission.create(
        OwnedServiceGrant.from_mapping(fixture["admission"]["grant"]), issuer=issuer
    )
    enrollment = SimpleNamespace(
        runner_id=public["runner_id"],
        client_id=public["client_id"],
        metadata=public,
        allowed_profile_ids=(fixture["profile"]["profile_id"],),
        hmac_key=lambda: b"s" * 32,
    )
    configured_root = Path("synthetic-configured-enrollment")
    loads, channels = [], []

    def load(_pid, *, expected_root, secret_provider, **_kwargs):
        assert expected_root == configured_root and secret_provider is None
        loads.append(expected_root)
        return enrollment

    def capture(context, envelope):
        channels.append((context, json.loads(envelope)))
        return SimpleNamespace(close=lambda: None)

    original = launch.validate_owned_service_grant_for_request
    now = datetime.fromisoformat(fixture["now"].replace("Z", "+00:00"))
    monkeypatch.setattr(launch, "_configured_host_enrollment", load)
    monkeypatch.setattr(launch, "_channels", capture)
    monkeypatch.setattr(
        launch,
        "_process_identity",
        lambda pid: {"pid": pid, "start_ticks": 1, "executable_digest": "sha256:" + "4" * 64},
    )
    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setattr(
        launch,
        "validate_owned_service_grant_for_request",
        lambda *a, **kw: original(*a, **kw, now=now),
    )
    return SimpleNamespace(
        authority=launch.ConfiguredServiceLaunchAuthority(configured_root, None),
        admission=admission,
        manifest=fixture["manifest"],
        profile=fixture["profile"],
        task_id=fixture["admission"]["grant"]["execution"]["task_id"],
        channels=channels,
        loads=loads,
        enrollment=enrollment,
        issuer=issuer,
    )


def prepare(fixture, *, admission=None, **changes):
    return fixture.authority.prepare(
        admission or fixture.admission,
        changes.get("manifest", fixture.manifest),
        changes.get("profile", fixture.profile),
        task_id=changes.get("task_id", fixture.task_id),
        runner_digest="sha256:" + "4" * 64,
        watchdog_digest="sha256:" + "5" * 64,
        interpreter_digest="sha256:" + "6" * 64,
    )


def test_configured_enrollment_context_is_separate_and_binds_exact_admission(configured):
    prepare(configured)
    context, envelope = configured.channels[0]
    assert context["stage"] == "host" and context["schema_version"] == launch.PROTOCOL
    assert "key" not in envelope and "key" not in envelope["admission"]
    assert context["key"].encode() not in canonical_json_bytes(envelope)
    expected = hmac.new(
        bytes.fromhex(context["key"]), configured.admission.canonical_bytes(), hashlib.sha256
    ).hexdigest()
    assert envelope["authentication"] == expected
    assert envelope["admission"] == configured.admission.to_dict()
    assert len(configured.loads) == 1


@pytest.mark.parametrize(
    "field", ["runner_id", "client_id", "enrollment_generation", "peer_fingerprint"]
)
def test_self_authored_issuer_does_not_replace_configured_enrollment(configured, field):
    issuer = dict(configured.issuer)
    issuer[field] = (
        "sha256:" + "a" * 64
        if field == "enrollment_generation"
        else "sha256:" + "a" * 64 if field == "peer_fingerprint" else "other-identity"
    )
    forged = OwnedServiceAdmission.create(
        OwnedServiceGrant.from_mapping(configured.admission.to_dict()["grant"]), issuer=issuer
    )
    with pytest.raises(RunnerTransportError):
        prepare(configured, admission=forged)
    assert not configured.channels


def test_enrollment_is_reloaded_and_profile_allowlist_rechecked(configured):
    prepare(configured)
    configured.enrollment.allowed_profile_ids = ()
    with pytest.raises(RunnerTransportError):
        prepare(configured)
    assert len(configured.loads) == 2 and len(configured.channels) == 1


@pytest.mark.parametrize("field", ["manifest", "profile", "task_id"])
def test_request_substitution_never_gets_a_launch_channel(configured, field):
    changed = (
        ("execute-" + "f" * 64)
        if field == "task_id"
        else {**getattr(configured, field), "unreviewed": True}
    )
    with pytest.raises(RunnerTransportError):
        prepare(configured, **{field: changed})
    assert not configured.channels


def test_bare_local_service_request_refuses_before_result_or_launch_work():
    runner = object.__new__(SubprocessRustRunner)
    runner._service_launch_authority = None
    assert runner.owned_service_admission_protocol is None
    with pytest.raises(RunnerTransportError, match="protected admission"):
        runner.execute_task(
            {"action_id": launch.SERVICE_ACTION_ID},
            {},
            task_id="unused",
            cancel_event=threading.Event(),
            durable_result_path="unused",
        )
    assert not hasattr(runner, "_durable_results")


def test_explicit_protocol_is_only_present_for_configured_host(configured):
    runner = object.__new__(SubprocessRustRunner)
    runner._service_launch_authority = configured.authority
    assert runner.owned_service_admission_protocol == ADMISSION_SCHEMA


def test_legacy_watchdog_without_service_channel_is_unchanged(monkeypatch):
    monkeypatch.delenv(launch._CONTEXT_ENV, raising=False)
    monkeypatch.delenv(launch._ENVELOPE_ENV, raising=False)
    assert (
        launch.consume_service_launch(
            {},
            {},
            task_id="legacy-task",
            runner_digest="unused",
            watchdog_digest="unused",
            interpreter_digest="unused",
        )
        is None
    )
    with pytest.raises(RunnerTransportError):
        launch.consume_service_launch(
            {"action_id": launch.SERVICE_ACTION_ID},
            {},
            task_id="unused",
            runner_digest="unused",
            watchdog_digest="unused",
            interpreter_digest="unused",
        )


@pytest.fixture
def synthetic_descriptors(monkeypatch):
    created, closed = [], []

    def seal(payload):
        descriptor = 501 + len(created)
        created.append((descriptor, payload))
        return descriptor

    monkeypatch.setattr(launch, "_sealed_descriptor", seal)
    monkeypatch.setattr(launch, "_read_sealed", lambda *_args, **_kwargs: b"synthetic")
    monkeypatch.setattr(launch.os, "close", closed.append)
    return SimpleNamespace(created=created, closed=closed)


@pytest.mark.parametrize("state_home", [None, "", " \t "])
def test_launch_captures_relocated_home_before_watchdog_environment_is_cleared(
    monkeypatch, tmp_path, synthetic_descriptors, state_home
):
    from bluefire.secret_store import _posix_managed_product_root

    relocated_home = tmp_path / "relocated-home"
    monkeypatch.setenv("HOME", str(relocated_home))
    monkeypatch.setenv("USERPROFILE", str(relocated_home))
    if state_home is None:
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    else:
        monkeypatch.setenv("XDG_STATE_HOME", state_home)
    channel = launch._channels({"synthetic": True}, b"synthetic-envelope")
    expected_state = relocated_home / ".local" / "state"

    monkeypatch.setenv("HOME", str(tmp_path / "different-home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "different-home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "different-state"))
    assert channel.environment == {
        launch._CONTEXT_ENV: "501",
        launch._ENVELOPE_ENV: "502",
        "XDG_STATE_HOME": str(expected_state),
    }
    assert (
        _posix_managed_product_root(environ=channel.environment, platform_name="linux")
        == expected_state / "bluefire-nexus"
    )
    channel.close()
    assert synthetic_descriptors.closed == [501, 502]


@pytest.mark.parametrize("state_form", ["absolute", "whitespace", "tilde"])
def test_explicit_state_home_uses_product_precedence_and_normalization(
    monkeypatch, tmp_path, synthetic_descriptors, state_form
):
    relocated_home = tmp_path / "relocated-home"
    monkeypatch.setenv("HOME", str(relocated_home))
    monkeypatch.setenv("USERPROFILE", str(relocated_home))
    expected_state = tmp_path / "explicit-state"
    configured_state = str(expected_state)
    if state_form == "whitespace":
        configured_state = f" \t{configured_state} \t"
    elif state_form == "tilde":
        configured_state = "~/explicit-state"
        expected_state = relocated_home / "explicit-state"
    monkeypatch.setenv("XDG_STATE_HOME", configured_state)

    channel = launch._channels({"synthetic": True}, b"synthetic-envelope")
    assert channel.environment["XDG_STATE_HOME"] == str(expected_state)
    assert "HOME" not in channel.environment and "USERPROFILE" not in channel.environment
    channel.close()
    assert synthetic_descriptors.closed == [501, 502]


def test_missing_home_captures_the_normal_account_home_fallback(
    monkeypatch, tmp_path, synthetic_descriptors
):
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    account_home = tmp_path / "account-home"
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: account_home))

    channel = launch._channels({"synthetic": True}, b"synthetic-envelope")
    assert channel.environment["XDG_STATE_HOME"] == str(account_home / ".local" / "state")
    channel.close()
    assert synthetic_descriptors.closed == [501, 502]


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux owner-private product secret store"
)
def test_captured_state_home_reopens_only_the_synthetic_protected_store(monkeypatch, tmp_path):
    from bluefire.secret_store import SecretStoreError, default_secret_provider

    relocated_home = tmp_path / "relocated-home"
    account_home = tmp_path / "account-home"
    monkeypatch.setenv("HOME", str(relocated_home))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    plaintext = b"authored synthetic service-launch bytes"
    opaque = default_secret_provider().protect("synthetic.service-launch", plaintext)
    channel = launch._channels({"synthetic": True}, b"synthetic-envelope")
    try:
        monkeypatch.delenv("HOME")
        monkeypatch.delenv("USERPROFILE", raising=False)
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: account_home))
        with pytest.raises(SecretStoreError):
            default_secret_provider().unprotect("synthetic.service-launch", opaque)
        assert not account_home.exists()

        environment = channel.environment
        assert "HOME" not in environment and "USERPROFILE" not in environment
        monkeypatch.setenv("XDG_STATE_HOME", environment["XDG_STATE_HOME"])
        assert default_secret_provider().unprotect("synthetic.service-launch", opaque) == plaintext
        assert not account_home.exists()
    finally:
        channel.close()


@pytest.mark.parametrize("state_form", ["relative", "parent", "nul"])
def test_invalid_state_home_refuses_before_creating_descriptors(
    monkeypatch, tmp_path, synthetic_descriptors, state_form
):
    state_home = {
        "relative": "relative-state",
        "parent": str(tmp_path / ".." / "state"),
        "nul": str(tmp_path / "invalid\0state"),
    }[state_form]
    monkeypatch.setattr(launch.os, "environ", {"XDG_STATE_HOME": state_home})
    with pytest.raises(RunnerTransportError, match="Protected owned-service launch"):
        launch._channels({"synthetic": True}, b"synthetic-envelope")
    assert synthetic_descriptors.created == [] and synthetic_descriptors.closed == []


@pytest.mark.parametrize("error", [OSError, RuntimeError, UnicodeError, ValueError])
def test_state_home_resolution_failure_cannot_leak_descriptors(
    monkeypatch, synthetic_descriptors, error
):
    import bluefire.secret_store as secret_store

    def unavailable(**_kwargs):
        raise error("Synthetic unavailable home")

    monkeypatch.setattr(secret_store, "_posix_managed_product_root", unavailable)
    with pytest.raises(RunnerTransportError, match="Protected owned-service launch"):
        launch._channels({"synthetic": True}, b"synthetic-envelope")
    assert synthetic_descriptors.created == [] and synthetic_descriptors.closed == []


def test_second_descriptor_failure_closes_the_first_after_state_capture(
    monkeypatch, tmp_path, synthetic_descriptors
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    seal = launch._sealed_descriptor

    def fail_second(payload):
        if synthetic_descriptors.created:
            raise OSError("Synthetic descriptor failure")
        return seal(payload)

    monkeypatch.setattr(launch, "_sealed_descriptor", fail_second)
    with pytest.raises(OSError, match="Synthetic descriptor failure"):
        launch._channels({"synthetic": True}, b"synthetic-envelope")
    assert len(synthetic_descriptors.created) == 1
    assert synthetic_descriptors.closed == [501]


def test_invalid_channel_cleanup_preserves_refusal_and_closes_both_descriptors(monkeypatch):
    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setenv(launch._CONTEXT_ENV, "501")
    monkeypatch.setenv(launch._ENVELOPE_ENV, "502")
    closed = []

    def reject(*_args, **_kwargs):
        raise RunnerTransportError("Invalid inherited channel.")

    def close(fd):
        closed.append(fd)
        raise OSError("Invalid descriptor.")

    monkeypatch.setattr(launch, "_read_sealed", reject)
    monkeypatch.setattr(launch.os, "close", close)
    with pytest.raises(RunnerTransportError, match="Protected owned-service launch"):
        launch.consume_service_launch(
            {},
            {},
            task_id="unused",
            runner_digest="unused",
            watchdog_digest="unused",
            interpreter_digest="unused",
        )
    assert set(closed) == {501, 502} and len(closed) == 2
    assert launch._CONTEXT_ENV not in os.environ and launch._ENVELOPE_ENV not in os.environ


def test_native_watchdog_pin_matches_packaged_source():
    root = Path(__file__).resolve().parents[1]
    native = (root / "runner/src/service_admission_channel.rs").read_text(encoding="utf-8")
    pin = re.search(r'WATCHDOG_SOURCE_SHA256:\s*&str\s*=\s*"([0-9a-f]{64})"', native)
    assert pin is not None
    packaged = (root / "bluefire/runner_watchdog.py").read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(packaged).hexdigest() == pin.group(1)


def test_configured_host_grammar_is_the_actual_product_launch(tmp_path):
    command = default_host_command(
        enrollment_root=tmp_path / "enrollment",
        runner_binary=tmp_path / "runner",
        work_root=tmp_path / "work",
        state_path=tmp_path / "state",
        process_record_path=tmp_path / "record",
        start_gate_path=tmp_path / "gate",
        launch_id="a" * 64,
        runner_timeout_seconds=35,
    )
    raw = b"\0".join(os.fsencode(argument) for argument in command) + b"\0"
    arguments = launch._parse_host_arguments(raw)
    assert arguments["--enrollment-root"] == str(tmp_path / "enrollment")
    for changed in (
        raw.replace(b"-m\0bluefire.runner_host", b"-c\0bluefire.runner_host"),
        raw.replace(b"bluefire.runner_host", b"self.authored.host"),
        raw.replace(b"--state-path", b"--enrollment-root"),
        raw[:-1],
        raw + b"extra\0",
    ):
        with pytest.raises(RunnerTransportError):
            launch._parse_host_arguments(changed)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux inherited sealed descriptors"
)
def test_sealed_data_alone_and_replaced_parent_are_not_authority(monkeypatch):
    context = launch._sealed_descriptor(canonical_json_bytes({"key": "0" * 64}))
    envelope = launch._sealed_descriptor(canonical_json_bytes({"admission": {}}))
    monkeypatch.setenv(launch._CONTEXT_ENV, str(context))
    monkeypatch.setenv(launch._ENVELOPE_ENV, str(envelope))
    with pytest.raises(RunnerTransportError):
        launch.consume_service_launch(
            {},
            {},
            task_id="unused",
            runner_digest="unused",
            watchdog_digest="unused",
            interpreter_digest="unused",
        )
    for descriptor in (context, envelope):
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert launch._CONTEXT_ENV not in os.environ and launch._ENVELOPE_ENV not in os.environ


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux inherited sealed descriptors"
)
def test_fully_sealed_self_signed_channel_is_not_a_configured_host(monkeypatch):
    fixture = json.loads(
        Path(__file__).with_name("fixtures").joinpath("owned_service_admission_v1.json").read_text()
    )
    admission = OwnedServiceAdmission.from_mapping(fixture["admission"])
    issuer = dict(fixture["admission"]["issuer"])
    issuer.pop("server_instance_id")
    key = b"self-signed-test-key-only".ljust(32, b"0")
    envelope = canonical_json_bytes(
        {
            "admission": admission.to_dict(),
            "authentication": hmac.new(
                key, admission.canonical_bytes(), hashlib.sha256
            ).hexdigest(),
        }
    )
    interpreter = file_hash(Path("/proc/self/exe"))
    context = {
        "schema_version": launch.PROTOCOL,
        "stage": "host",
        "issuer": issuer,
        "enrollment_digest": content_hash(issuer),
        "key": key.hex(),
        "envelope_digest": "sha256:" + hashlib.sha256(envelope).hexdigest(),
        "parent": launch._process_identity(os.getpid()),
        "runner_digest": "sha256:" + "4" * 64,
        "watchdog_digest": "sha256:" + "5" * 64,
        "interpreter_digest": interpreter,
    }
    channel = launch._channels(context, envelope)
    original = launch.validate_owned_service_grant_for_request
    now = datetime.fromisoformat(fixture["now"].replace("Z", "+00:00"))
    monkeypatch.setattr(
        launch,
        "validate_owned_service_grant_for_request",
        lambda *args, **kwargs: original(*args, **kwargs, now=now),
    )
    child = os.fork()
    if child == 0:
        try:
            os.environ.update(channel.environment)
            result = launch.consume_service_launch(
                fixture["manifest"],
                fixture["profile"],
                task_id=fixture["admission"]["grant"]["execution"]["task_id"],
                runner_digest=context["runner_digest"],
                watchdog_digest=context["watchdog_digest"],
                interpreter_digest=interpreter,
            )
            if result is not None:
                result.close()
        except RunnerTransportError:
            os._exit(0)
        except BaseException:
            os._exit(3)
        os._exit(2)
    waited = False
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            process, status = os.waitpid(child, os.WNOHANG)
            if process == child:
                waited = True
                assert os.waitstatus_to_exitcode(status) == 0
                break
            time.sleep(0.01)
        assert waited, "owned launch-refusal child did not exit"
    finally:
        if not waited:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        channel.close()
