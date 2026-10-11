"""Saved S3 operations use the authenticated host, never an ambient SDK."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from bluefire import s3_access_executor as module
from bluefire.runner_contracts import execution_limits, seal_profile
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_host_config import public_environments
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import content_hash
from tests_platform.s3_profile_fixtures import managed_profile
from tests_platform.test_s3_access_admission import admitted_fixture
from tests_platform.test_s3_access_wire import NOW


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


@pytest.fixture
def configured(monkeypatch, tmp_path):
    fixture = admitted_fixture()
    fixture["profile"]["sandbox_root"] = str(tmp_path)
    fixture["profile"] = seal_profile(fixture["profile"])
    entry = fixture["configuration"]["environments"][0]
    row = {
        "environment": public_environments(fixture["configuration"])[0],
        "profile": fixture["profile"],
        "runtime_digest": entry["runtime_digest"],
        "worker_generation": entry["worker_generation"],
        "available": True,
        "problem": None,
    }

    class Client:
        calls = []
        error = None
        corrupt = None
        recovery_calls = []

        def transport_identity(self):
            return deepcopy(self.identity)

        def recover(self, task_id, request_hash):
            self.recovery_calls.append((task_id, request_hash))
            return deepcopy(self.recovery)

        def s3_access_environments(self):
            return [deepcopy(row)]

        def execute_task(self, manifest, profile, **kwargs):
            self.calls.append((manifest, profile, kwargs))
            if self.error:
                raise self.error
            request = S3WorkerRequest.from_mapping(manifest["params"]["worker_request"])
            execution = module._UnavailableExecutor().execute(
                request, authorization={}, cancellation_event=Event()
            )
            result = {
                field: manifest[field]
                for field in (
                    "request_id",
                    "run_id",
                    "step_id",
                    "behavior_id",
                    "action_id",
                    "runner_id",
                    "runner_profile_id",
                    "platform",
                    "request_hash",
                    "policy_digest",
                )
            }
            result.update(
                schema_version="bluefire.runner-result.v1", output={"s3_execution": execution}
            )
            if self.corrupt:
                self.corrupt(result)
            self.result = deepcopy(result)
            return result

    client = Client()
    client.identity = {
        "schema_version": "bluefire.runner-transport-identity.v1",
        "runner_id": fixture["profile"]["runner_id"],
        "client_id": "client.test.v1",
        "transport": "mutual-tls-loopback",
        "tls": "TLSv1.3",
        **{
            key: "sha256:" + "a" * 64
            for key in (
                "server_fingerprint",
                "client_fingerprint",
                "authenticated_peer_fingerprint",
                "enrollment_generation",
                "runner_binary_digest",
                "inventory_digest",
            )
        },
    }
    profile = managed_profile(fixture["profile"]["profile_id"])
    row["managed_profile_digest"] = content_hash(profile.to_dict())
    lifecycle = SimpleNamespace(client_for_profile=lambda *args, **kwargs: (client, tmp_path))
    service = SimpleNamespace(
        config=SimpleNamespace(runner_profiles=()),
        runner_lifecycle=lifecycle,
        active_profiles=(profile,),
    )
    service._runner_profiles = lambda: service.active_profiles
    monkeypatch.setattr(module, "AuthenticatedRunnerClient", Client)
    monkeypatch.setattr(module, "datetime", Clock)
    return SimpleNamespace(
        executor=module.configured_executor(service),
        service=service,
        client=client,
        profile=profile,
        row=row,
        request=S3WorkerRequest.from_mapping(fixture["manifest"]["params"]["worker_request"]),
        approval=fixture["manifest"]["params"]["workflow_approval"],
    )


def test_unconfigured_executor_never_bootstraps_a_host():
    executor = module.configured_executor(SimpleNamespace())
    assert executor.environments() == []


def test_only_safe_environment_fields_are_exposed(configured):
    assert configured.executor.environments() == [configured.row["environment"]]
    readiness = configured.executor.readiness(
        S3AccessScope.from_mapping(configured.row["environment"]["scope"])
    )
    assert readiness["available"] is True
    assert readiness["runtime_digest"] == configured.row["runtime_digest"]
    assert "profile" not in readiness and "runtime_root" not in readiness


def test_active_managed_profiles_refresh_without_static_config_fallback(configured):
    assert configured.service.config.runner_profiles == ()
    assert configured.executor.environments() == [configured.row["environment"]]
    configured.service.config.runner_profiles = (configured.profile,)
    configured.service.active_profiles = ()
    assert configured.executor.environments() == []
    configured.service.active_profiles = (configured.profile,)
    assert configured.executor.environments() == [configured.row["environment"]]


@pytest.mark.parametrize("steps", [1, 11, 13])
def test_installed_profile_must_retain_the_original_complete_step_budget(configured, steps):
    original_limits = execution_limits(configured.profile)
    configured.profile.budgets = replace(configured.profile.budgets, max_steps=steps)
    assert execution_limits(configured.profile) == original_limits
    readiness = configured.executor.readiness(
        S3AccessScope.from_mapping(configured.request.to_dict()["scope"])
    )
    assert readiness["available"] is False
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started" and result["send_debits"] == 0
    assert configured.client.calls == []


@pytest.mark.parametrize("field", ["runner_binary", "sandbox_root"])
def test_same_native_policy_cannot_rebind_changed_managed_references(configured, field):
    before = execution_limits(configured.profile)
    setattr(
        configured.profile,
        field,
        replace(getattr(configured.profile, field), env="OTHER_TEST_REFERENCE"),
    )
    assert execution_limits(configured.profile) == before
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started" and not configured.client.calls


@pytest.mark.parametrize("binding", [None, "sha256:" + "f" * 64])
def test_legacy_or_different_retained_profile_binding_is_not_current(configured, binding):
    configured.row["managed_profile_digest"] = binding
    readiness = configured.executor.readiness(
        S3AccessScope.from_mapping(configured.request.to_dict()["scope"])
    )
    assert readiness["available"] is False and readiness["problem"] == "profile_changed"
    assert configured.executor.environments() == [configured.row["environment"]]
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started" and not configured.client.calls


def test_new_matching_install_cannot_authorize_an_undersized_stage_budget(configured):
    configured.profile.budgets = replace(configured.profile.budgets, max_steps=1)
    configured.row["managed_profile_digest"] = content_hash(configured.profile.to_dict())
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started" and not configured.client.calls


@pytest.mark.parametrize("seconds", [30, 180])
def test_same_id_reactivation_with_changed_budget_requires_new_host_policy(configured, seconds):
    configured.profile.budgets = replace(configured.profile.budgets, max_seconds=seconds)
    readiness = configured.executor.readiness(
        S3AccessScope.from_mapping(configured.request.to_dict()["scope"])
    )
    assert readiness["available"] is False and readiness["problem"] == "profile_changed"
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started" and result["send_debits"] == 0
    assert configured.client.calls == []
    configured.row["profile"]["limits"] = execution_limits(configured.profile)
    configured.row["profile"] = seal_profile(configured.row["profile"])
    configured.row["managed_profile_digest"] = content_hash(configured.profile.to_dict())
    assert (
        configured.executor.readiness(
            S3AccessScope.from_mapping(configured.request.to_dict()["scope"])
        )["available"]
        is True
    )


@pytest.mark.parametrize(
    "change", ["runner", "sandbox", "network", "actions", "approval", "seal", "extra"]
)
def test_stale_native_host_bindings_never_dispatch(configured, change):
    native = configured.row["profile"]
    if change == "runner":
        native["runner_id"] = "different-runner"
    elif change == "sandbox":
        native["sandbox_root"] += "-different"
    elif change == "network":
        native["target_scope"]["network"] = [{"host": "example.invalid", "port": 443}]
    elif change == "actions":
        native["allowed_actions"].append("sandbox.cleanup.v1")
    elif change == "approval":
        native["approval_required_at_or_above"] = None
    elif change == "extra":
        native["unreviewed"] = True
    if change != "seal":
        configured.row["profile"] = seal_profile(native)
    else:
        native["policy_digest"] = "sha256:" + "0" * 64
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started" and not configured.client.calls


@pytest.mark.parametrize(
    "change", ["deactivate", "budget", "host", "runtime", "profile_version", "binding"]
)
def test_checkpoint_callback_cannot_dispatch_after_profile_or_host_drift(configured, change):
    contexts = []

    def checkpoint(context):
        contexts.append(deepcopy(context))
        if change == "deactivate":
            configured.service.active_profiles = ()
        elif change == "budget":
            configured.profile.budgets = replace(configured.profile.budgets, max_seconds=30)
        elif change == "host":
            configured.client.identity["enrollment_generation"] = "sha256:" + "b" * 64
        elif change == "runtime":
            configured.row["runtime_digest"] = "sha256:" + "b" * 64
        elif change == "binding":
            configured.row["managed_profile_digest"] = "sha256:" + "b" * 64
        else:
            configured.profile.budgets = replace(configured.profile.budgets, max_steps=11)

    result = configured.executor.execute(
        configured.request,
        authorization=configured.approval,
        cancellation_event=Event(),
        before_dispatch=checkpoint,
    )
    assert result["dispatch"] == "not_started" and result["send_debits"] == 0
    assert len(contexts) == 1 and not configured.client.calls


def test_profile_change_during_discovery_does_not_leave_an_environment(configured):
    def environments():
        configured.service.active_profiles = ()
        return [deepcopy(configured.row)]

    configured.client.s3_access_environments = environments
    assert configured.executor.environments() == []


def test_later_host_discovery_cannot_preserve_an_earlier_deactivated_profile(configured):
    original = configured.client.s3_access_environments
    calls = []
    second = managed_profile("second-profile.v1")
    configured.service.active_profiles = (configured.profile, second)

    def environments():
        calls.append(True)
        if len(calls) == 1:
            return original()
        configured.service.active_profiles = (second,)
        return []

    configured.client.s3_access_environments = environments
    assert configured.executor.environments() == []
    assert len(calls) == 2


@pytest.mark.parametrize("problem", ["access_reference_absent", "access_reference_expired"])
def test_unready_reference_retains_environment_and_never_dispatches(configured, problem):
    configured.row.update(available=False, problem=problem)
    executor = configured.executor
    assert executor.environments() == [configured.row["environment"]]
    readiness = executor.readiness(
        S3AccessScope.from_mapping(configured.row["environment"]["scope"])
    )
    assert readiness["available"] is False and readiness["problem"] == problem
    result = executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started"
    assert configured.client.calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("enabled_actions", ()),
        ("blocked_actions", (module.ACTION,)),
        ("capabilities", ("network.loopback",)),
        ("platforms", ("windows",)),
    ],
)
def test_ineligible_local_profile_never_reaches_host(configured, field, value):
    setattr(configured.profile, field, value)
    configured.service.runner_lifecycle.client_for_profile = lambda *a, **k: pytest.fail(
        "host was contacted"
    )
    assert configured.executor.environments() == []


def test_duplicate_environment_or_scope_is_not_arbitrarily_selected(configured):
    configured.service.active_profiles = (configured.profile, configured.profile)
    assert configured.executor.environments() == []


def test_changed_scope_from_second_visible_host_cannot_bypass_bucket_barrier(configured):
    first = configured.client
    second = type(first)()
    second.identity = deepcopy(first.identity)
    other = deepcopy(configured.row)
    other["environment"]["environment_id"] = "second-host"
    other["environment"]["scope"]["expires_at"] = "2026-10-09T00:59:00Z"
    other["profile"]["profile_id"] = "second-profile"
    second.s3_access_environments = lambda: [other]
    profile = deepcopy(configured.profile)
    profile.id = "second-profile"
    configured.service.active_profiles = (configured.profile, profile)
    configured.service.runner_lifecycle.client_for_profile = lambda identity, **kwargs: (
        first if identity == configured.profile.id else second,
        Path("/unused"),
    )
    assert configured.executor.environments() == []
    assert not configured.executor.readiness(
        S3AccessScope.from_mapping(configured.row["environment"]["scope"])
    )["available"]


def test_non_authenticated_runner_is_not_a_fallback(configured):
    configured.service.runner_lifecycle.client_for_profile = lambda *a, **k: (
        object(),
        Path("/unused"),
    )
    assert configured.executor.environments() == []


def test_execute_uses_exact_manifest_approval_and_existing_cancel_signal(configured):
    cancelled = Event()
    result = configured.executor.execute(
        configured.request,
        authorization=configured.approval,
        cancellation_event=cancelled,
        before_dispatch=lambda context: None,
    )
    assert result["admission"]["accepted"] is False
    manifest, profile, kwargs = configured.client.calls[0]
    assert manifest["params"]["worker_request"] == configured.request.to_dict()
    assert manifest["params"]["workflow_approval"] == configured.approval
    assert manifest["target_scope"] == {"filesystem": [], "network": []}
    assert manifest["required_capabilities"] == ["cloud_aws_s3_access"]
    assert kwargs["cancel_event"] is cancelled
    assert kwargs["durable_result_path"].is_absolute()
    assert module._manifest(configured.request, configured.approval, profile) == manifest


@pytest.mark.parametrize("field", ["runtime_digest", "worker_generation"])
def test_runtime_drift_is_refused_before_dispatch(configured, field):
    configured.row[field] = "sha256:" + "0" * 64
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=Event()
    )
    assert result["dispatch"] == "not_started"
    assert not configured.client.calls


def test_already_cancelled_never_discovers_or_dispatches(configured):
    cancelled = Event()
    cancelled.set()
    configured.service.runner_lifecycle.client_for_profile = lambda *a, **k: pytest.fail(
        "host was contacted"
    )
    result = configured.executor.execute(
        configured.request, authorization=configured.approval, cancellation_event=cancelled
    )
    assert result["admission"]["problem"] == "cancelled"


def test_lost_transport_result_is_not_fabricated_as_not_started(configured):
    configured.client.error = RuntimeError("private transport detail")
    with pytest.raises(S3AccessError, match="no verified final runner result") as caught:
        configured.executor.execute(
            configured.request,
            authorization=configured.approval,
            cancellation_event=Event(),
            before_dispatch=lambda context: None,
        )
    assert "private transport detail" not in str(caught.value)
    assert len(configured.client.calls) == 1


@pytest.mark.parametrize("kind", ["request", "synthetic", "extra_output"])
def test_wrong_or_synthetic_native_result_is_not_admitted(configured, kind):
    def corrupt(result):
        if kind == "request":
            result["request_id"] = "different-request"
        elif kind == "synthetic":
            result["output"]["s3_execution"]["provenance"] = "synthetic"
        else:
            result["output"]["unreviewed"] = True

    configured.client.corrupt = corrupt
    with pytest.raises(S3AccessError, match="no verified final runner result"):
        configured.executor.execute(
            configured.request,
            authorization=configured.approval,
            cancellation_event=Event(),
            before_dispatch=lambda context: None,
        )
