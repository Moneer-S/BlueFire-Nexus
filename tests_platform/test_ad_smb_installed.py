"""Synthetic private-file/client boundaries; no transport or enrollment effects."""

import threading
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_execution as execution
from bluefire import ad_smb_installed as installed
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.ad_smb_jobs import AdSmbJobs
from bluefire.ad_smb_receiver_results import context
from bluefire.job_runtime import JobCancelled
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_contract import NOW, pin
from tests_platform.test_ad_smb_jobs import workspace as workspace
from tests_platform.test_ad_smb_receiver import original, read_record
from tests_platform.test_ad_smb_worker_wire import rebind_context


def configuration(root):
    member, member_channel = original("inspect")
    client, client_channel = original("baseline")
    request = client["manifest"]["params"]["ad_smb_request"]
    public = {
        "environment_id": "ad-env-" + "a" * 32,
        "scope": request["scope"],
        "member": member["transport_identity"],
        "client": client["transport_identity"],
        "principal_binding_digest": request["principal_binding_digest"],
        "provenance": "runner_reported",
    }
    row = {
        "environment": public,
        "profiles": {"member": member["profile"], "client": client["profile"]},
        "channels": {"member": member_channel.to_dict(), "client": client_channel.to_dict()},
    }
    client = rebind_context(client, environment_digest=content_hash(public))
    return installed.InstalledEnvironment.from_mapping(root, row), client, client_channel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    entry, original_task, channel = configuration(tmp_path)
    calls = []
    state = SimpleNamespace(
        entries=(entry,), recovery="completed", identity=True, result=None, unavailable=set()
    )

    def load(root):
        assert root == tmp_path
        calls.append("load")
        return state.entries

    class Client:
        def transport_identity(self):
            calls.append("health")
            role = self.role
            if role in state.unavailable:
                raise OSError("private diagnostic must not escape")
            return {
                **entry.public[role],
                "host_role": role,
                "ad_smb_execution_available": state.identity,
                "readiness_scope": "configuration_only",
            }

        def execute_task(self, manifest, profile, **kwargs):
            calls.append("execute")
            assert "checkpoint" in calls and calls.index("checkpoint") < calls.index("execute")
            assert kwargs["task_id"] == original_task["task_id"]
            assert kwargs["durable_result_path"].is_absolute()
            assert "owned_service_grant" not in kwargs
            return state.result or read_record(context(manifest, profile), channel, 123)

        def recover_original(self, manifest, profile):
            calls.append("recover")
            assert manifest == original_task["manifest"] and profile == original_task["profile"]
            return {
                "state": state.recovery,
                "result": state.result or read_record(original_task, channel, 123),
            }

    def client(self, role):
        calls.append("client:" + role)
        value = Client()
        value.role = role
        return value

    monkeypatch.setattr(execution, "load_installed", load)
    monkeypatch.setattr(installed.InstalledEnvironment, "client", client)
    monkeypatch.setattr(execution, "now", lambda: NOW)
    executor = execution.InstalledAdSmbExecutor(tmp_path)
    calls.clear()
    return executor, entry, original_task, state, calls


def test_config_rederives_exact_role_profile_and_channel(tmp_path):
    entry, _, _ = configuration(tmp_path)
    assert entry.public["provenance"] == "runner_reported"
    assert entry.channel("member").to_dict()["role"] == "member"
    detached = entry.to_dict()
    detached["profiles"]["member"]["limits"]["timeout_ms"] = 1
    assert entry.to_dict() != detached
    with pytest.raises(AdSmbError):
        installed.InstalledEnvironment.from_mapping(tmp_path, detached)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda x: x.update(extra="ignored"),
        lambda x: x["environment"].update(provenance="synthetic_fixture"),
        lambda x: x["environment"]["member"].update(native_generation=pin("f")),
        lambda x: x["channels"].update(extra={}),
        lambda x: x["profiles"].update(client=x["profiles"]["member"]),
    ],
)
def test_config_rejects_unsupported_or_changed_bindings(tmp_path, mutate):
    entry, _, _ = configuration(tmp_path)
    row = entry.to_dict()
    mutate(row)
    with pytest.raises(AdSmbError):
        installed.InstalledEnvironment.from_mapping(tmp_path, row)


@pytest.mark.parametrize(
    "kind", ["valid", "extra", "duplicate", "count", "raw_secret", "duplicate_key"]
)
def test_loader_closed_file_and_inventory(tmp_path, monkeypatch, kind):
    entry, _, _ = configuration(tmp_path)
    row = {"schema_version": installed.CONFIG_SCHEMA, "environments": [entry.to_dict()]}
    if kind == "extra":
        row["path"] = "other"
    elif kind == "duplicate":
        row["environments"] *= 2
    elif kind == "count":
        row["environments"] = []
    elif kind == "raw_secret":
        row["environments"][0]["password"] = "synthetic must not echo"
    raw = canonical_json_bytes(row)
    if kind == "duplicate_key":
        raw = b'{"schema_version":"a","schema_version":"b","environments":[]}'

    class Pinned:
        def __init__(self, root, *, private, verify_permissions_only):
            assert root == tmp_path and private and verify_permissions_only

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def names(self, *, maximum):
            assert maximum == 9
            return ["controller.json"]

        def read(self, name, *, maximum):
            assert name == "controller.json" and maximum == installed.CONFIG_MAX
            return raw

    monkeypatch.setattr(installed, "_PinnedDirectory", Pinned)
    monkeypatch.setattr(installed, "private_root", lambda x: x)
    if kind == "valid":
        loaded = installed.load_installed(tmp_path)
        assert len(loaded) == 1 and loaded[0].public == entry.public
        return
    with pytest.raises(AdSmbError) as error:
        installed.load_installed(tmp_path)
    assert "synthetic must not echo" not in str(error.value)


def test_current_admission_precedes_checkpoint_then_only_one_execute(setup):
    executor, _, task, _, calls = setup
    result = executor.execute(
        task["manifest"]["params"]["ad_smb_request"],
        cancellation_event=threading.Event(),
        before_dispatch=lambda row: calls.append("checkpoint"),
    )
    assert calls.count("execute") == 1
    assert calls.index("health") < calls.index("checkpoint") < calls.index("execute")
    assert result["observation"]["state"] == "bytes_matched"


def test_checkpoint_failure_never_dispatches(setup):
    executor, _, task, _, calls = setup

    def refuse(_):
        raise AdSmbError("synthetic durable failure")

    with pytest.raises(execution.AdSmbPreDispatchFailure):
        executor.execute(
            task["manifest"]["params"]["ad_smb_request"],
            cancellation_event=threading.Event(),
            before_dispatch=refuse,
        )
    assert "execute" not in calls


def test_checkpoint_cancellation_remains_cancellation_without_dispatch(setup):
    executor, _, task, _, calls = setup

    def cancel(_):
        raise JobCancelled("authored cancellation")

    with pytest.raises(execution.AdSmbPreDispatchCancelled):
        executor.execute(
            task["manifest"]["params"]["ad_smb_request"],
            cancellation_event=threading.Event(),
            before_dispatch=cancel,
        )
    assert "execute" not in calls


@pytest.mark.parametrize("kind", ["false", "value", "awaitable", "coroutine"])
def test_checkpoint_must_return_none_without_running_returned_work(setup, kind):
    executor, _, task, _, calls = setup

    class Awaitable:
        def __await__(self):
            pytest.fail("returned checkpoint work must never run")
            yield

    async def unfinished():
        pytest.fail("returned checkpoint coroutine must never run")

    pending = unfinished() if kind == "coroutine" else None
    value = {"false": False, "value": "unfinished", "awaitable": Awaitable(), "coroutine": pending}[
        kind
    ]

    def incomplete(_):
        calls.append("checkpoint")
        return value

    try:
        with pytest.raises(AdSmbError, match="checkpoint.*synchronously"):
            executor.execute(
                task["manifest"]["params"]["ad_smb_request"],
                cancellation_event=threading.Event(),
                before_dispatch=incomplete,
            )
        assert "execute" not in calls and calls.count("checkpoint") == 1
    finally:
        if pending is not None:
            pending.close()


def test_cancelled_before_dispatch_has_no_channel_or_checkpoint(setup):
    executor, _, task, _, calls = setup
    stop = threading.Event()
    stop.set()
    with pytest.raises(execution.AdSmbPreDispatchCancelled):
        executor.execute(
            task["manifest"]["params"]["ad_smb_request"],
            cancellation_event=stop,
            before_dispatch=lambda _: pytest.fail("no checkpoint"),
        )
    assert calls == []


def test_config_removed_after_checkpoint_never_dispatches(setup):
    executor, _, task, state, calls = setup
    with pytest.raises(AdSmbError) as error:
        executor.execute(
            task["manifest"]["params"]["ad_smb_request"],
            cancellation_event=threading.Event(),
            before_dispatch=lambda _: setattr(state, "entries", ()),
        )
    assert not isinstance(error.value, execution.AdSmbPreDispatchFailure)
    assert "execute" not in calls


def test_cancel_after_checkpoint_never_dispatches(setup):
    executor, _, task, _, calls = setup
    stop = threading.Event()
    result = executor.execute(
        task["manifest"]["params"]["ad_smb_request"],
        cancellation_event=stop,
        before_dispatch=lambda _: stop.set(),
    )
    assert result["dispatch"] == "not_started" and "execute" not in calls


def test_changed_environment_digest_refuses_before_health_or_dispatch(setup):
    executor, _, task, _, calls = setup
    changed = dict(task["manifest"]["params"]["ad_smb_request"], environment_digest=pin("e"))
    with pytest.raises(AdSmbError):
        executor.execute(
            changed,
            cancellation_event=threading.Event(),
            before_dispatch=lambda _: pytest.fail("no checkpoint"),
        )
    assert calls == ["load"]


def test_installed_client_uses_fixed_own_role_path_and_exact_binding(tmp_path, monkeypatch):
    saved, _, _ = configuration(tmp_path)
    calls = []
    monkeypatch.setattr(installed, "AdmittedAdSmbClient", lambda *a, **kw: calls.append((a, kw)))
    saved.client("client")
    saved.client("member")
    for role, (args, kwargs) in zip(("client", "member"), calls, strict=True):
        assert args == (tmp_path / saved.public["environment_id"] / role,)
        assert kwargs["channel"].digest == saved.public[role]["channel_digest"]
        assert kwargs["credential_binding_digest"] == (
            saved.public["principal_binding_digest"] if role == "client" else None
        )
        assert "secret_provider" not in kwargs


@pytest.mark.parametrize("status", ["completed", "not_found", "running", "failed"])
def test_recovery_uses_only_exact_original_without_readiness_or_replay(setup, status):
    executor, _, task, state, calls = setup
    state.recovery = status
    result = executor.recover_original(task["manifest"]["params"]["ad_smb_request"], task)
    assert result["status"] == ("terminal" if status == "completed" else "unavailable")
    assert calls == ["load", "client:client", "recover"]


def test_recovery_rejects_malformed_native_original(setup):
    executor, _, task, state, calls = setup
    state.result = {"schema_version": "unknown"}
    with pytest.raises(AdSmbError):
        executor.recover_original(task["manifest"]["params"]["ad_smb_request"], task)
    assert "execute" not in calls and "health" not in calls


def test_not_admitted_health_fails_closed(setup):
    executor, entry, _, state, calls = setup
    state.identity = False
    assert executor.readiness(AdSmbScope.from_mapping(entry.public["scope"]))["available"] is False
    assert "execute" not in calls


def test_installed_default_never_creates_or_starts_missing_setup(tmp_path):
    service = SimpleNamespace(runner_lifecycle=SimpleNamespace(root=tmp_path))
    assert isinstance(execution.configured_executor(service), execution.UnavailableAdSmbExecutor)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("unavailable", [set(), {"member"}, {"client"}, {"member", "client"}])
def test_role_readiness_is_independent_configured_health_only(setup, unavailable):
    executor, entry, _, state, calls = setup
    state.unavailable = unavailable
    ready = executor.readiness(AdSmbScope.from_mapping(entry.public["scope"]))
    assert ready["member_observation"] == ("member" not in unavailable)
    assert (
        ready["client_read_admission"]
        == ready["secret_channel_available"]
        == ("client" not in unavailable)
    )
    assert ready["available"] == (not unavailable)
    assert ready["problem"] == (
        "role_channels_unavailable"
        if len(unavailable) == 2
        else next(iter(unavailable)) + "_channel_unavailable" if unavailable else None
    )
    assert ready["binding_digest"] == (None if unavailable else entry.digest)
    assert "private diagnostic" not in str(ready)
    assert calls == ["load", "client:member", "health", "client:client", "health"]


@pytest.mark.parametrize("clock", [NOW - timedelta(days=1), NOW + timedelta(days=1)])
def test_noncurrent_scope_never_contacts_either_channel(setup, monkeypatch, clock):
    executor, entry, _, _, calls = setup
    monkeypatch.setattr(execution, "now", lambda: clock)
    ready = executor.readiness(AdSmbScope.from_mapping(entry.public["scope"]))
    assert ready["problem"] == "scope_not_current"
    assert not any(
        ready[key]
        for key in (
            "available",
            "member_observation",
            "client_read_admission",
            "secret_channel_available",
        )
    )
    assert calls == []


def test_workspace_refresh_recovers_later_enrollment_and_preserves_saved_evidence(
    workspace, tmp_path, monkeypatch
):
    _, _, service = workspace
    root = tmp_path / "managed"
    service.runner_lifecycle = SimpleNamespace(root=root)
    entry, _, _ = configuration(root / "ad-smb")
    state = SimpleNamespace(enrolled=False)
    calls = []

    def load(path):
        assert path == root / "ad-smb"
        if not state.enrolled:
            raise AdSmbError("Private setup detail")
        return (entry,)

    def client(_entry, role):
        def identity():
            calls.append(role)
            return {
                **entry.public[role],
                "host_role": role,
                "ad_smb_execution_available": True,
                "readiness_scope": "configuration_only",
            }

        return SimpleNamespace(transport_identity=identity)

    monkeypatch.setattr(execution, "load_installed", load)
    monkeypatch.setattr(execution, "now", lambda: NOW)
    monkeypatch.setattr(installed.InstalledEnvironment, "client", client)
    jobs = AdSmbJobs(service, clock=lambda: NOW)
    assert jobs.environments() == {"environments": [], "native_execution_available": False}
    assert not root.exists() and calls == []
    state.enrolled = True
    assert jobs.environments()["native_execution_available"] is True
    assert calls == ["member", "client"]
    owner = jobs.create(
        {"submission_id": str(uuid.uuid4()), "environment_id": entry.public["environment_id"]}
    )
    assert owner["execution_integration"] == "configured_admission"
    before = owner["workflow"]
    calls.clear()
    state.enrolled = False
    assert jobs.environments() == {"environments": [], "native_execution_available": False}
    saved = jobs.read(before["job_id"])
    assert saved["execution_integration"] == "unavailable" and saved["workflow"] == before
    with pytest.raises(AdSmbError, match="prerequisites"):
        jobs.review(before["job_id"], "inspect")
    assert not root.exists() and calls == []
