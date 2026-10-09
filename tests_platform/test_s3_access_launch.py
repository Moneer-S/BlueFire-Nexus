"""Fake descriptor lifecycle proves channel binding, not installed host isolation."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import s3_access_launch as launch
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.util import canonical_json_bytes
from tests_platform.test_s3_access_admission import admitted_fixture
from tests_platform.test_s3_access_wire import NOW, credential_row


@pytest.fixture
def prepared(monkeypatch):
    fixture = admitted_fixture()
    material = canonical_json_bytes(credential_row())
    fixture["credential_digest"] = "sha256:" + hashlib.sha256(material).hexdigest()
    issuer = dict(fixture["issuer"])
    issuer.pop("server_instance_id")
    enrollment = SimpleNamespace(hmac_key=lambda: b"synthetic-not-a-secret" * 3)
    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setattr(launch.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(launch, "datetime", SimpleNamespace(now=lambda tz: NOW))
    monkeypatch.setattr(launch, "_configured_host_enrollment", lambda *args, **kwargs: enrollment)
    monkeypatch.setattr(launch, "_enrollment_issuer", lambda value: issuer)
    monkeypatch.setattr(
        launch,
        "_process_identity",
        lambda pid: {"pid": pid, "start_ticks": 123, "executable_digest": "sha256:" + "c" * 64},
    )
    monkeypatch.setattr(
        launch, "_current_material", lambda *args: (fixture["configuration"], material)
    )
    channels = []

    def collect(context, envelope, secret):
        row = SimpleNamespace(
            context=deepcopy(context), envelope=envelope, material=secret, closed=False
        )
        row.close = lambda: setattr(row, "closed", True)
        channels.append(row)
        return row

    monkeypatch.setattr(launch, "_channels", collect)
    keywords = {name: fixture[name] for name in ("task_id", "runner_digest")}
    keywords.update(watchdog_digest="sha256:" + "b" * 64, interpreter_digest="sha256:" + "c" * 64)
    value = launch.ConfiguredS3LaunchAuthority(Path("/configured"), None).prepare(
        launch.S3LaunchIntent(fixture["issuer"]),
        fixture["manifest"],
        fixture["profile"],
        **keywords,
    )
    return SimpleNamespace(
        value=value, fixture=fixture, keywords=keywords, channels=channels, material=material
    )


def _watchdog(monkeypatch, prepared):
    value = prepared.value
    # Fake the transition from actual host to its direct watchdog child.
    value.context["parent"] = launch._process_identity(launch.os.getppid())
    payloads = {31: canonical_json_bytes(value.context), 32: value.envelope, 33: value.material}
    for name, descriptor in zip(launch._ENV, payloads, strict=True):
        monkeypatch.setenv(name, str(descriptor))
    monkeypatch.setattr(launch, "_read_sealed", lambda descriptor, **kwargs: payloads[descriptor])
    closed = []
    monkeypatch.setattr(launch.os, "close", closed.append)
    return payloads, closed


def test_host_places_synthetic_material_only_in_third_channel(prepared):
    assert prepared.material not in prepared.value.envelope
    assert prepared.material not in canonical_json_bytes(prepared.value.context)
    assert prepared.value.context["stage"] == "host"
    assert (
        json.loads(prepared.value.envelope)["admission"]["credential_digest"]
        == prepared.fixture["credential_digest"]
    )


def test_watchdog_independently_rechecks_then_reissues_and_closes_old_channels(
    monkeypatch, prepared
):
    _, closed = _watchdog(monkeypatch, prepared)
    result = launch.consume_s3_launch(
        prepared.fixture["manifest"], prepared.fixture["profile"], **prepared.keywords
    )
    assert result.context["stage"] == "watchdog"
    assert result.context["parent"] == launch._process_identity(launch.os.getpid())
    assert result.material == prepared.material
    assert sorted(closed) == [31, 32, 33]
    assert all(name not in launch.os.environ for name in launch._ENV)


@pytest.mark.parametrize(
    "fault", ["material", "authentication", "host_config", "interpreter", "duplicate_key"]
)
def test_invalid_handoff_never_releases_new_material_and_closes_owned_channels(
    monkeypatch, prepared, fault
):
    payloads, closed = _watchdog(monkeypatch, prepared)
    if fault == "material":
        payloads[33] = b"not-the-configured-material"
    elif fault == "authentication":
        envelope = json.loads(payloads[32])
        envelope["authentication"] = "a" * 64
        payloads[32] = canonical_json_bytes(envelope)
    elif fault == "host_config":
        prepared.fixture["configuration"]["environments"][0]["runtime_digest"] = (
            "sha256:" + "a" * 64
        )
    elif fault == "interpreter":
        prepared.keywords["interpreter_digest"] = "sha256:" + "a" * 64
    else:
        payloads[31] = b'{"stage":"host",' + payloads[31][1:]
    with pytest.raises(RunnerTransportError, match="Protected S3"):
        launch.consume_s3_launch(
            prepared.fixture["manifest"], prepared.fixture["profile"], **prepared.keywords
        )
    assert len(prepared.channels) == 1
    assert sorted(closed) == [31, 32, 33]


def test_s3_action_without_inherited_admission_fails_closed(monkeypatch):
    for name in launch._ENV:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RunnerTransportError):
        launch.consume_s3_launch(
            {"action_id": launch.ACTION},
            {},
            task_id="no",
            runner_digest="no",
            watchdog_digest="no",
            interpreter_digest="no",
        )
