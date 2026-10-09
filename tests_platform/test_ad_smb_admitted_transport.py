"""Synthetic trust/process/socket boundaries; no Windows, enrollment or AD effects."""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_admitted_transport as admitted
from bluefire import ad_smb_channel as channels
from bluefire import ad_smb_channel_transport as controls
from bluefire import ad_smb_receiver as receiver
from bluefire.ad_smb_channel import AdSmbHostChannel
from bluefire.ad_smb_contract import AdSmbScope
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_inventory import canonical_runner_inventory
from bluefire.runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    _RequestRefusal,
)
from bluefire.runner_transport_errors import RunnerAuthenticationError, RunnerConnectionError
from bluefire.runner_transport_security import sign_request
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_channel import enrollment, request
from tests_platform.test_ad_smb_contract import NOW, pin
from tests_platform.test_ad_smb_native_member_results import audit_fixture
from tests_platform.test_ad_smb_native_results import denied
from tests_platform.test_ad_smb_receiver import original, read_record, record
from tests_platform.test_ad_smb_worker_wire import rebind_context
from tests_platform.test_authenticated_runner_transport import _inventory


@pytest.fixture(autouse=True)
def no_effects(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=2)

    monkeypatch.setattr(channels, "datetime", Clock)
    monkeypatch.setattr(admitted, "_now", lambda: Clock.now())
    monkeypatch.setattr(receiver, "_now", lambda: Clock.now())
    monkeypatch.setattr(controls.socket, "socket", lambda *a, **k: pytest.fail("no socket"))
    monkeypatch.setattr(SubprocessRustRunner, "inventory", lambda *a: pytest.fail("no process"))


def bare_client(value, channel):
    client = object.__new__(admitted.AdmittedAdSmbClient)
    client.channel = channel
    client._ad_profile = admitted._profile(
        AdSmbScope.from_mapping(value["manifest"]["params"]["ad_smb_request"]["scope"]),
        channel,
        value["profile"],
    )
    client.profile_id = value["profile"]["profile_id"]
    client.recovery_attempts = 3
    client.recovery_delay_seconds = 0
    return client


def recovery(value, state="not_found", result=None):
    return dict(
        original_task_id=value["task_id"],
        original_request_hash=value["transport_request_hash"],
        state=state,
        result=result,
        error_code=None,
        cancellation_requested=False,
        receipt_ids=[],
        cleanup_required=False,
    )


@pytest.fixture
def constructor(tmp_path, monkeypatch):
    calls = []
    state = SimpleNamespace(late_failure=False, cleanup_failure=False, inventory_failure=False)

    class Listener:
        closed = False

        def fileno(self):
            return -1 if self.closed else 123

    @contextmanager
    def guard(self):
        calls.append("hold")
        yield self._runner_binary_digest
        calls.append("release")
        if state.late_failure:
            raise RunnerAuthenticationError("synthetic guard drift")

    @contextmanager
    def root_guard(*args, **kwargs):
        calls.append("root_hold")
        yield
        calls.append("root_release")

    def inventory(self, enrolled):
        calls.append("inventory")
        assert calls[-2] == "hold"
        if state.inventory_failure:
            raise RunnerAuthenticationError("synthetic inventory mismatch")
        return {"platform": "windows"}, {}

    def base(self, *args, **kwargs):
        calls.append("base")
        self._listener = Listener()
        self._ledger_lock = object()
        state.instance = self

    def stop(self):
        calls.append("shutdown")
        if not state.cleanup_failure:
            self._listener.closed = True
            self._ledger_lock = None

    def metadata(root, *, scope, channel, expected_digest, secret_provider=None):
        assert expected_digest == pin("9")
        calls.append("metadata")
        return object()

    monkeypatch.setattr(admitted.sys, "platform", "win32")
    monkeypatch.setattr(admitted, "_validated_enrollment_root", lambda path: tmp_path)
    monkeypatch.setattr(admitted, "_PinnedDirectory", root_guard)
    monkeypatch.setattr(
        admitted, "load_channel_enrollment", lambda *a, **k: calls.append("enrollment") or object()
    )
    monkeypatch.setattr(admitted, "load_credential_binding", metadata)
    monkeypatch.setattr(
        admitted.AdmittedAdSmbReceiver,
        "_bind_runner_binary",
        lambda self: (Path("C:/fixed.exe"), self.channel.to_dict()["runner_binary_digest"]),
    )
    monkeypatch.setattr(admitted.AdmittedAdSmbReceiver, "_verified_runner_binary_guard", guard)
    monkeypatch.setattr(admitted.AdmittedAdSmbReceiver, "_validated_inventory", inventory)
    monkeypatch.setattr(controls.EnrolledAdSmbServer, "__init__", base)
    monkeypatch.setattr(AuthenticatedRunnerServer, "shutdown", stop)

    def create(phase="inspect", **changes):
        value, channel = original(phase)
        runner = object.__new__(SubprocessRustRunner)
        runner.timeout_seconds, runner.output_limit_bytes, runner.work_root = 30, 1048576, tmp_path
        kwargs = dict(
            state_path=tmp_path / "unused.sqlite3",
            scope=AdSmbScope.from_mapping(value["manifest"]["params"]["ad_smb_request"]["scope"]),
            channel=channel,
            profile=value["profile"],
            credential_root=tmp_path / "credentials" if phase == "baseline" else None,
            credential_binding_digest=pin("9") if phase == "baseline" else None,
        )
        kwargs.update(changes)
        return admitted.AdmittedAdSmbReceiver(tmp_path / "enrollment", runner, **kwargs)

    return create, calls, state


@pytest.mark.parametrize("phase", ["inspect", "baseline"])
def test_constructor_checks_metadata_and_held_native_inventory_before_base(constructor, phase):
    create, calls, _ = constructor
    instance = create(phase)
    assert calls.index("inventory") < calls.index("base") < calls.index("release")
    assert ("metadata" in calls) == (phase == "baseline")
    assert "shutdown" not in calls
    assert instance.ad_smb_execution_available is False


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_guard_failure_after_base_closes_resources_or_reports_unknown(constructor, cleanup_failure):
    create, calls, state = constructor
    state.late_failure, state.cleanup_failure = True, cleanup_failure
    with pytest.raises(RunnerAuthenticationError) as error:
        create()
    assert calls[-1] == "shutdown"
    assert ("unverified" in str(error.value)) == cleanup_failure
    assert state.instance._listener.closed is not cleanup_failure


def test_inventory_failure_never_constructs_listener(constructor):
    create, calls, state = constructor
    state.inventory_failure = True
    with pytest.raises(RunnerAuthenticationError):
        create()
    assert "base" not in calls


@pytest.mark.parametrize("changed", [False, True])
def test_existing_bounded_inventory_api_checks_exact_generation(constructor, monkeypatch, changed):
    create, calls, _ = constructor
    value, channel = original()
    scope = AdSmbScope.from_mapping(value["manifest"]["params"]["ad_smb_request"]["scope"])
    native = _inventory()
    row = channel.to_dict()
    row["inventory_digest"] = content_hash(canonical_runner_inventory(native))
    channel = AdSmbHostChannel.from_mapping(scope, row)
    if changed:
        native["runner_version"] = "unexpected"
    monkeypatch.setattr(
        admitted.AdmittedAdSmbReceiver,
        "_validated_inventory",
        controls.EnrolledAdSmbServer._validated_inventory,
    )
    monkeypatch.setattr(
        admitted, "load_channel_enrollment", lambda *a, **k: enrollment(k["channel"])
    )
    monkeypatch.setattr(
        SubprocessRustRunner, "inventory", lambda self: calls.append("fixed_inventory") or native
    )
    if changed:
        with pytest.raises(RunnerAuthenticationError):
            create(channel=channel)
        assert "base" not in calls
    else:
        create(channel=channel)
        assert calls.index("fixed_inventory") < calls.index("base")
        assert calls.count("hold") == 2


@pytest.mark.parametrize("phase,credential", [("inspect", Path("synthetic")), ("baseline", None)])
def test_member_reader_material_separation_before_base(constructor, phase, credential):
    create, calls, _ = constructor
    with pytest.raises(RunnerAuthenticationError):
        create(phase, credential_root=credential)
    assert "base" not in calls and "metadata" not in calls


def test_non_windows_constructor_refuses_before_any_boundary(constructor, monkeypatch):
    create, calls, _ = constructor
    monkeypatch.setattr(admitted.sys, "platform", "linux")
    with pytest.raises(RunnerAuthenticationError):
        create()
    assert calls == []


@pytest.mark.parametrize(
    "phase,pin_value", [("inspect", pin("9")), ("baseline", None), ("baseline", "bad")]
)
def test_credential_metadata_requires_explicit_client_only_pin(constructor, phase, pin_value):
    create, calls, _ = constructor
    with pytest.raises(RunnerAuthenticationError):
        create(phase, credential_binding_digest=pin_value)
    assert "metadata" not in calls and "base" not in calls


def test_original_reader_binding_must_match_constructor(constructor):
    create, _, _ = constructor
    server = create("baseline")
    value, _ = original("baseline")
    assert server._context(value["manifest"], value["profile"]) == receiver.context(
        value["manifest"], value["profile"]
    )
    changed = rebind_context(value, principal_binding_digest=pin("e"))
    with pytest.raises(ValueError, match="reader binding"):
        server._context(changed["manifest"], changed["profile"])


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("allowed_actions", ["ordinary.action"]),
        ("platform", "linux"),
        ("limits", {"timeout_ms": 0}),
        ("extra", True),
    ],
)
def test_profile_mutation_before_any_boundary(constructor, field, replacement):
    create, calls, _ = constructor
    value, _ = original()
    profile = deepcopy(value["profile"])
    profile[field] = replacement
    with pytest.raises(RunnerAuthenticationError):
        create(profile=profile)
    assert calls == []


@pytest.mark.parametrize("forbidden", ["shutdown", "s3_access_environments"])
def test_admitted_receiver_validates_hmac_and_exact_execute_only(forbidden):
    value, channel = original()
    server = object.__new__(admitted.AdmittedAdSmbReceiver)
    server.channel, server._ad_profile = channel, canonical_json_bytes(value["profile"])
    payload = {"manifest": value["manifest"], "profile": value["profile"]}
    unsigned = request(channel, "execute", payload)
    unsigned.update(task_id=value["task_id"], request_hash=value["transport_request_hash"])
    unsigned.pop("authentication")
    submitted = sign_request(enrollment(channel), unsigned)
    assert server._validated_request(submitted, enrollment(channel)) == submitted
    with pytest.raises(RunnerAuthenticationError):
        server._validated_request({**submitted, "authentication": "bad"}, enrollment(channel))
    with pytest.raises(_RequestRefusal):
        server._validated_request(request(channel, forbidden), enrollment(channel))


@pytest.mark.parametrize(
    "operation",
    ["shutdown", "native_tool_inspect", "owned_service_execute", "s3_access_environments"],
)
def test_client_rejects_non_ad_dispatch(operation):
    value, channel = original()
    with pytest.raises(RunnerAuthenticationError):
        bare_client(value, channel)._call(operation, {}, task_id=value["task_id"])


def test_lost_response_not_found_never_resends_execute(monkeypatch):
    value, channel = original()
    client = bare_client(value, channel)
    calls = []

    def call(self, operation, payload, **kwargs):
        calls.append(operation)
        if operation == "execute":
            raise RunnerConnectionError("synthetic lost response")
        return recovery(value)

    monkeypatch.setattr(AuthenticatedRunnerClient, "_call", call)
    with pytest.raises(RunnerConnectionError, match="no replacement Execute"):
        client.execute(value["manifest"], value["profile"])
    assert calls == ["execute", "recover", "recover", "recover"]


def test_recovered_native_error_remains_error_and_no_execute(monkeypatch):
    value, channel = original()
    saved = record(value, channel)
    client = bare_client(value, channel)
    calls = []
    monkeypatch.setattr(
        AuthenticatedRunnerClient,
        "_call",
        lambda self, operation, *a, **k: calls.append(operation)
        or recovery(value, "completed", saved),
    )
    observed = client.recover_original(value["manifest"], value["profile"])
    assert observed["result"] == saved
    assert observed["result"]["issue"] == "native_error"
    assert calls == ["recover"]


@pytest.mark.parametrize("kind", ["denied", "partial_audit", "unknown_write"])
def test_original_negative_and_partial_observations_remain_unchanged(monkeypatch, kind):
    phase = {"denied": "baseline", "partial_audit": "audit", "unknown_write": "harden"}[kind]
    value, channel = original(phase)
    if kind == "denied":
        saved = read_record(value, channel, 123)
        denied(saved["terminal"]["result"])
    else:
        saved = record(value, channel, error=False)
        if kind == "partial_audit":
            _, raw = audit_fixture()
            raw["state"] = "byte_limit"
            raw["utf8_bytes"] = len(raw["raw_events"][0].encode())
        else:
            raw = {
                "state": "unknown",
                "write_attempted": True,
                "set_status": 5,
                "readback": None,
                "issue": "set_response_failed_state_unknown",
            }
        saved["terminal"]["result"] = raw
    monkeypatch.setattr(
        AuthenticatedRunnerClient, "_call", lambda *a, **k: recovery(value, "completed", saved)
    )
    monkeypatch.setattr(admitted, "_now", lambda: NOW + timedelta(seconds=40))
    observed = bare_client(value, channel).recover_original(value["manifest"], value["profile"])
    assert observed["result"] == saved
    assert (
        observed["result"]["terminal"]["result"]["state"]
        == {
            "denied": "open_access_denied",
            "partial_audit": "byte_limit",
            "unknown_write": "unknown",
        }[kind]
    )


def test_client_constructor_uses_exact_profile_before_enrollment(monkeypatch):
    value, channel = original()
    scope = AdSmbScope.from_mapping(value["manifest"]["params"]["ad_smb_request"]["scope"])
    calls = []
    monkeypatch.setattr(controls.EnrolledAdSmbClient, "__init__", lambda *a, **k: calls.append(k))
    client = admitted.AdmittedAdSmbClient(
        "unused", scope=scope, channel=channel, profile=value["profile"]
    )
    assert len(calls) == 1 and client._ad_profile == canonical_json_bytes(value["profile"])
    with pytest.raises(RunnerAuthenticationError):
        admitted.AdmittedAdSmbClient("unused", scope=scope, channel=channel, profile={})
    assert len(calls) == 1


@pytest.mark.parametrize(
    "change", ["task", "hash", "state", "extra", "partial_result", "receipt", "bool", "error"]
)
def test_recovery_closed_original_response(monkeypatch, change):
    value, channel = original()
    row = recovery(value)
    if change == "task":
        row["original_task_id"] = "other"
    elif change == "hash":
        row["original_request_hash"] = "sha256:" + "0" * 64
    elif change == "state":
        row["state"] = "success"
    elif change == "extra":
        row["extra"] = True
    elif change == "partial_result":
        row["result"] = {}
    elif change == "receipt":
        row["receipt_ids"] = ["0" * 64]
    elif change == "bool":
        row["cleanup_required"] = 0
    else:
        row["error_code"] = "untrusted raw detail"
    monkeypatch.setattr(AuthenticatedRunnerClient, "_call", lambda *a, **k: row)
    with pytest.raises(RunnerAuthenticationError):
        bare_client(value, channel).recover_original(value["manifest"], value["profile"])


def test_invalid_completed_native_payload_not_upgraded(monkeypatch):
    value, channel = original()
    saved = record(value, channel, error=False)
    monkeypatch.setattr(
        AuthenticatedRunnerClient, "_call", lambda *a, **k: recovery(value, "completed", saved)
    )
    with pytest.raises(RunnerAuthenticationError):
        bare_client(value, channel).recover_original(value["manifest"], value["profile"])


def test_owned_grant_rejected_before_transport():
    value, channel = original()
    with pytest.raises(RunnerAuthenticationError):
        bare_client(value, channel).execute_task(
            value["manifest"],
            value["profile"],
            task_id=value["task_id"],
            cancel_event=None,
            durable_result_path="unused",
            owned_service_grant={},
        )


def test_ordinary_channel_classes_stay_control_only():
    value, channel = original()
    client = object.__new__(controls.EnrolledAdSmbClient)
    client.channel = channel
    client.profile_id = value["profile"]["profile_id"]
    with pytest.raises(RunnerAuthenticationError):
        client.execute(value["manifest"], value["profile"])
    assert not controls.EnrolledAdSmbClient.ad_smb_execution_available
    assert not controls.EnrolledAdSmbServer.ad_smb_execution_available
