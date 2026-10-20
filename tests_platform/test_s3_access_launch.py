"""Fake descriptor lifecycle proves channel binding, not installed host isolation."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import s3_access_launch as launch
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.s3_access_admission import S3HostAdmission
from bluefire.s3_access_recovery import BOUND_SCHEMA, execution_manifest, validate_recovery_context
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_admission import admitted_fixture, reseal
from tests_platform.test_s3_access_wire import credential_row
from tests_platform.test_s3_audit_admission import audit_admitted, original_context
from tests_platform.test_s3_audit_collection_admission import collection_admitted


def _prepared_fixture(monkeypatch, fixture, original=None):
    material = canonical_json_bytes(credential_row())
    fixture["credential_digest"] = "sha256:" + hashlib.sha256(material).hexdigest()
    issuer = dict(fixture["issuer"])
    issuer.pop("server_instance_id")
    enrollment = SimpleNamespace(hmac_key=lambda: b"synthetic-not-a-secret" * 3)
    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setattr(launch.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(launch, "datetime", SimpleNamespace(now=lambda tz: fixture["now"]))
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
        value=value,
        fixture=fixture,
        keywords=keywords,
        channels=channels,
        material=material,
        original=original,
    )


@pytest.fixture
def prepared(monkeypatch):
    return _prepared_fixture(monkeypatch, admitted_fixture())


@pytest.fixture(params=["baseline", "retest"])
def audited_prepared(monkeypatch, request):
    fixture = collection_admitted(request.param)
    worker_request = S3WorkerRequest.from_mapping(fixture["manifest"]["params"]["worker_request"])
    original_pair = worker_request.to_dict()["audit"]["original_pair"]
    original_request, original_template = original_context(audit_admitted())
    # Collector recovery is run-bound: preserve the admitted run ID in schema v2.
    fixture["manifest"] = execution_manifest(
        worker_request,
        fixture["manifest"]["params"]["workflow_approval"],
        fixture["profile"],
        run_id=fixture["manifest"]["run_id"],
    )
    reseal(fixture)
    transport_hash = content_hash({"manifest": fixture["manifest"], "profile": fixture["profile"]})
    original = {
        "schema_version": BOUND_SCHEMA,
        "request_digest": worker_request.digest,
        "task_id": "execute-" + transport_hash.removeprefix("sha256:"),
        "transport_request_hash": transport_hash,
        "manifest": fixture["manifest"],
        "profile": fixture["profile"],
        "transport_identity": original_template["transport_identity"],
    }
    assert original_request.to_dict()["operation"] == "inspect_policy"
    assert validate_recovery_context(worker_request, original) == original
    prepared = _prepared_fixture(monkeypatch, fixture, original)
    prepared.pair = original_pair
    prepared.request = worker_request
    return prepared


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


def test_audited_watchdog_preserves_original_source_pair_and_task_identity(
    monkeypatch, audited_prepared
):
    fixture = audited_prepared.fixture
    original = audited_prepared.original
    envelope = json.loads(audited_prepared.value.envelope)
    admission = envelope["admission"]
    collection = audited_prepared.request.to_dict()
    assert collection["operation"] == "collect_audit"
    assert collection["audit"]["original_pair"] == audited_prepared.pair
    assert admission["schema_version"] == "bluefire.s3-access-admission.v3"
    workflow = admission["host"]["audit_workflow"]
    source = fixture["configuration"]["environments"][0]["audit_source"]
    assert workflow["source"] == source
    assert content_hash(workflow["source"]) == content_hash(source)
    approval = original["manifest"]["params"]["workflow_approval"]
    assert approval["prior_run_ids"] == [row["run_id"] for row in audited_prepared.pair["reads"]]
    assert original["schema_version"] == BOUND_SCHEMA
    assert original["manifest"]["run_id"] == fixture["manifest"]["run_id"]
    assert original["manifest"] == fixture["manifest"]
    assert admission["manifest_digest"] == content_hash(original["manifest"])
    assert admission["request_digest"] == audited_prepared.request.digest
    assert admission["approval_digest"] == content_hash(approval)
    assert audited_prepared.keywords["task_id"] == original["task_id"]

    _, closed = _watchdog(monkeypatch, audited_prepared)
    result = launch.consume_s3_launch(
        fixture["manifest"], fixture["profile"], **audited_prepared.keywords
    )
    assert json.loads(result.envelope) == envelope
    assert result.context["stage"] == "watchdog"
    assert result.material == audited_prepared.material
    assert audited_prepared.keywords["task_id"] == original["task_id"]
    assert sorted(closed) == [31, 32, 33]


@pytest.mark.parametrize("fault", ["source", "original_runs"])
def test_audited_watchdog_refuses_source_or_original_context_drift_and_closes_channels(
    monkeypatch, audited_prepared, fault
):
    _, closed = _watchdog(monkeypatch, audited_prepared)
    fixture = audited_prepared.fixture
    manifest = fixture["manifest"]
    keywords = dict(audited_prepared.keywords)
    if fault == "source":
        fixture["configuration"]["environments"][0]["audit_source"][
            "audit_source_id"
        ] = "substituted-audit-trail"
    else:
        changed = deepcopy(fixture)
        raw_request = deepcopy(changed["manifest"]["params"]["worker_request"])
        raw_request["audit"]["original_pair"]["reads"][0]["run_id"] = (
            "run-20261009T000015Z-" + "9" * 16
        )
        changed_request = S3WorkerRequest.from_mapping(raw_request)
        approval = changed["manifest"]["params"]["workflow_approval"]
        approval["request_digest"] = changed_request.digest
        approval["prior_run_ids"] = [
            row["run_id"] for row in changed_request.to_dict()["audit"]["original_pair"]["reads"]
        ]
        changed["manifest"] = execution_manifest(
            changed_request,
            approval,
            changed["profile"],
            run_id=changed["manifest"]["run_id"],
        )
        reseal(changed)
        assert (
            S3HostAdmission.issue(**changed).to_dict()["request_digest"] == changed_request.digest
        )
        manifest = changed["manifest"]
        keywords["task_id"] = changed["task_id"]
    with pytest.raises(RunnerTransportError, match="Protected S3"):
        launch.consume_s3_launch(manifest, fixture["profile"], **keywords)
    assert len(audited_prepared.channels) == 1
    assert sorted(closed) == [31, 32, 33]


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
