"""Saved profile selection and drift checks; no runner, cloud or setup effects."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import s3_access_onboarding as onboarding
from bluefire.application_errors import APIError
from bluefire.contracts import ExecutionMode, SafetyTier
from bluefire.runner_contracts import execution_limits, seal_profile
from bluefire.runner_lifecycle import RunnerLifecycleError
from bluefire.s3_access_setup_status import _result
from bluefire.util import content_hash
from tests_platform.test_s3_access_host_config import configured as host_configuration


@pytest.fixture
def configured(monkeypatch):
    calls = []
    profile = SimpleNamespace(
        id="s3-test",
        mode=ExecutionMode.EXECUTE,
        platforms=("linux",),
        capabilities=("cloud.aws.s3.access",),
        enabled_actions=(onboarding.ACTION,),
        blocked_actions=(),
        budgets=SimpleNamespace(max_seconds=60, max_bytes=5242880, max_artifacts=100),
        safety_tiers=(SafetyTier.SAFE, SafetyTier.CONTROLLED),
        approval_required=True,
        to_dict=lambda: {"id": "s3-test", "private_path": "/not-public"},
    )

    class Client:
        identity = {"generation": "original"}
        version = "original"

        def inventory(self):
            calls.append("inventory")
            return {"version": self.version}

        def s3_access_setup_status(self):
            calls.append("inspect")
            return _result("s3-test", "missing")

    client = Client()

    def connect(profile_id, *, profile_budget_seconds):
        assert profile_id == profile.id and profile_budget_seconds == 60
        calls.append("connect")
        return client, None

    service = SimpleNamespace(
        _runner_profiles=lambda: (profile,),
        runner_lifecycle=SimpleNamespace(client_for_profile=connect),
    )
    monkeypatch.setattr(onboarding, "AuthenticatedRunnerClient", Client)
    monkeypatch.setattr(onboarding, "canonical_runner_inventory", deepcopy)
    monkeypatch.setattr(
        onboarding, "runner_transport_identity", lambda runner, _: deepcopy(runner.identity)
    )
    request = {"profile_id": profile.id, "profile_digest": content_hash(profile.to_dict())}
    return SimpleNamespace(
        profile=profile, client=client, service=service, calls=calls, request=request
    )


def test_list_is_inert_and_does_not_expose_profile_paths(configured):
    value = onboarding.setup_profiles(configured.service)
    assert value == {
        "schema_version": onboarding.SCHEMA,
        "profiles": [configured.request],
        "truncated": False,
    }
    assert configured.calls == [] and "/not-public" not in str(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("platforms", ("windows",)),
        ("platforms", ("linux", "windows")),
        ("mode", ExecutionMode.SIMULATE),
        ("capabilities", ()),
        ("enabled_actions", ()),
        ("blocked_actions", (onboarding.ACTION,)),
    ],
)
def test_only_active_eligible_profile_can_be_checked(configured, field, value):
    setattr(configured.profile, field, value)
    assert onboarding.setup_profiles(configured.service)["profiles"] == []
    with pytest.raises(APIError) as caught:
        onboarding.check_setup(configured.service, configured.request)
    assert caught.value.code == "s3_setup_profile_changed"
    assert configured.calls == []


def test_check_binds_inventory_transport_and_saved_profile(configured):
    value = onboarding.check_setup(configured.service, configured.request)
    assert value["schema_version"] == onboarding.CHECK_SCHEMA
    assert value["profile_digest"] == configured.request["profile_digest"]
    assert value["host_state"] == "authenticated"
    assert value["setup"]["configuration_state"] == "missing"
    assert configured.calls == ["connect", "inventory", "inspect", "inventory"]
    assert configured.client.socket_timeout_seconds == 15
    assert "/not-public" not in str(value)


@pytest.mark.parametrize("drift", ["inventory", "transport", "profile", "response"])
def test_drift_cannot_leave_a_successful_setup_check(configured, drift):
    original = configured.client.s3_access_setup_status

    def inspect():
        value = original()
        if drift == "inventory":
            configured.client.version = "changed"
        elif drift == "transport":
            configured.client.identity = {"generation": "changed"}
        elif drift == "profile":
            configured.profile.to_dict = lambda: {"id": "s3-test", "changed": True}
        else:
            value["extra"] = "private"
        return value

    configured.client.s3_access_setup_status = inspect
    if drift == "profile":
        with pytest.raises(APIError) as caught:
            onboarding.check_setup(configured.service, configured.request)
        assert caught.value.code == "s3_setup_profile_changed"
    else:
        value = onboarding.check_setup(configured.service, configured.request)
        assert value["host_state"] == "unavailable" and value["setup"] is None
        assert "private" not in str(value)


def test_unavailable_host_does_not_start_or_enroll(configured):
    def connect(*args, **kwargs):
        raise RunnerLifecycleError("private local details")

    configured.service.runner_lifecycle.client_for_profile = connect
    value = onboarding.check_setup(configured.service, configured.request)
    assert value["host_state"] == "unavailable" and value["setup"] is None
    assert "private" not in str(value) and configured.calls == []


@pytest.mark.parametrize("mutation", ["unknown", "stale", "path"])
def test_changed_or_widened_request_does_not_connect(configured, mutation):
    if mutation == "unknown":
        configured.request["credentials"] = "not accepted"
    elif mutation == "stale":
        configured.request["profile_digest"] = "sha256:" + "f" * 64
    else:
        configured.request["profile_id"] = "../../other"
    with pytest.raises(APIError):
        onboarding.check_setup(configured.service, configured.request)
    assert configured.calls == []


def draft_request(configured):
    row = host_configuration()
    profile = row["environments"][0]["profile"]
    profile["profile_id"] = configured.profile.id
    profile["limits"] = execution_limits(configured.profile)
    row["environments"][0]["profile"] = seal_profile(profile)
    return {**configured.request, "configuration_json": json.dumps(row, indent=2)}


def test_draft_review_is_structural_and_retains_exact_source_without_host_effects(configured):
    request = draft_request(configured)
    row = json.loads(request["configuration_json"])
    value = onboarding.review_draft(configured.service, request)
    assert value["schema_version"] == onboarding.DRAFT_SCHEMA
    assert value["validation_scope"] == "structural_only"
    assert value["profile_digest"] == request["profile_digest"]
    assert (
        value["source_sha256"]
        == "sha256:" + hashlib.sha256(request["configuration_json"].encode()).hexdigest()
    )
    assert value["configuration_digest"] == content_hash(row)
    assert value["environments"][0]["bucket"] == row["environments"][0]["scope"]["bucket"]
    assert value["environments"][0]["fixture_generation"] == 1
    assert "/opt/" not in str(value) and "credential_reference" not in str(value)
    assert configured.calls == []
    changed_whitespace = {**request, "configuration_json": request["configuration_json"] + "\n"}
    again = onboarding.review_draft(configured.service, changed_whitespace)
    assert again["configuration_digest"] == value["configuration_digest"]
    assert again["source_sha256"] != value["source_sha256"]


@pytest.mark.parametrize(
    "mutation",
    [
        "credentials",
        "profile_secret",
        "scope_secret",
        "policy_secret",
        "target_secret",
        "limits_secret",
        "profile_extra_action",
        "profile_extra_capability",
        "network",
        "filesystem",
        "boolean_limit",
        "raised_limit",
        "runtime_path",
        "wrong_profile",
        "wrong_seal",
        "wrong_policy",
        "duplicate_environment",
        "opaque",
        "no_approval",
    ],
)
def test_draft_refuses_widening_extra_fields_and_secrets_without_echo(configured, mutation):
    request = draft_request(configured)
    row = json.loads(request["configuration_json"])
    entry = row["environments"][0]
    profile = entry["profile"]
    if mutation == "credentials":
        row["credentials"] = "do-not-echo"
    elif mutation == "profile_secret":
        profile["token"] = "do-not-echo"
    elif mutation == "scope_secret":
        entry["scope"]["token"] = "do-not-echo"
    elif mutation == "policy_secret":
        entry["baseline_policy"]["token"] = "do-not-echo"
    elif mutation == "target_secret":
        profile["target_scope"]["token"] = "do-not-echo"
    elif mutation == "limits_secret":
        profile["limits"]["token"] = "do-not-echo"
    elif mutation == "profile_extra_action":
        profile["allowed_actions"].append("sandbox.fixture.create.v1")
    elif mutation == "profile_extra_capability":
        profile["capabilities"].append("filesystem_write")
    elif mutation == "network":
        profile["target_scope"]["network"] = [{"host": "do-not-echo"}]
    elif mutation == "filesystem":
        profile["target_scope"]["filesystem"] = ["/do-not-echo"]
    elif mutation == "boolean_limit":
        profile["limits"]["max_files"] = True
    elif mutation == "raised_limit":
        profile["limits"]["max_files"] += 1
    elif mutation == "runtime_path":
        entry["runtime_root"] = "/opt/../do-not-echo"
    elif mutation == "wrong_profile":
        profile["profile_id"] = "another-profile"
    elif mutation == "wrong_policy":
        entry["baseline_policy"]["Statement"][0]["Action"] = "s3:PutObject"
    elif mutation == "duplicate_environment":
        row["environments"].append(deepcopy(entry))
    elif mutation == "opaque":
        entry["credential_reference"] = "do-not-echo"
    elif mutation == "no_approval":
        profile["approval_required_at_or_above"] = None
    if mutation != "wrong_seal":
        entry["profile"] = seal_profile(profile)
    else:
        profile["policy_digest"] = "sha256:" + "f" * 64
    request["configuration_json"] = json.dumps(row)
    with pytest.raises(APIError) as caught:
        onboarding.review_draft(configured.service, request)
    assert caught.value.code == "s3_setup_draft_invalid"
    assert "do-not-echo" not in str(caught.value)
    assert configured.calls == []


@pytest.mark.parametrize(
    "source",
    [
        "{}",
        "null",
        '{"runner_id":"first","runner_id":"second"}',
        '{"value":NaN}',
        "x" * (128 * 1024 + 1),
        "\ud800",
        {},
    ],
    ids=["empty", "null", "duplicate", "nonfinite", "oversize", "surrogate", "not_text"],
)
def test_draft_requires_strict_bounded_json_text(configured, source):
    with pytest.raises(APIError) as caught:
        onboarding.review_draft(
            configured.service, {**configured.request, "configuration_json": source}
        )
    assert caught.value.code == "s3_setup_draft_invalid"
    assert configured.calls == []


def test_draft_checks_saved_profile_drift_after_validation(configured, monkeypatch):
    request = draft_request(configured)
    original = onboarding.validate_configuration

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        configured.profile.to_dict = lambda: {"id": "s3-test", "changed": True}
        return result

    monkeypatch.setattr(onboarding, "validate_configuration", changed)
    with pytest.raises(APIError) as caught:
        onboarding.review_draft(configured.service, request)
    assert caught.value.code == "s3_setup_profile_changed"
    assert configured.calls == []


def test_draft_does_not_implicitly_add_fixture_authority(configured):
    request = draft_request(configured)
    value = onboarding.review_draft(configured.service, request)
    assert value["environments"][0]["fixture_generation"] == 1
    row = json.loads(request["configuration_json"])
    row["schema_version"] = "bluefire.s3-host-environments.v2"
    request["configuration_json"] = json.dumps(row)
    with pytest.raises(APIError):
        onboarding.review_draft(configured.service, request)
    assert configured.calls == []


def test_browser_draft_fixture_passes_the_real_structural_contract(configured):
    source = (Path(__file__).parent / "fixtures/s3_setup_draft_v1.json").read_text(encoding="utf-8")
    value = onboarding.review_draft(
        configured.service, {**configured.request, "configuration_json": source}
    )
    assert value["configuration_digest"] == content_hash(json.loads(source))
    assert value["validation_scope"] == "structural_only"
    assert configured.calls == []
