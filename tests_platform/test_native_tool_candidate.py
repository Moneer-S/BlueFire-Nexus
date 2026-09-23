"""Offline setup evidence, transport and saved-profile regressions; no utility runs."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire.application_errors import APIError
from bluefire.contracts import ContractError
from bluefire.native_tool_candidate import SCHEMA, validate_candidate_inspection
from bluefire.native_tool_installations import CANDIDATE_SCHEMA, canonical_native_tool_candidate
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.runner_transport import AuthenticatedRunnerServer, RunnerRemoteError
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_native_tool_approval_binding import ROOT, configured_profile
from tests_platform.test_native_tool_inspection_transport import (
    InspectingRunner,
    record,
    transport_support,
)
from tests_platform.test_native_tool_inspection_transport import enrollment_root as enrollment_root
from tests_platform.test_native_tool_inspection_transport import secret_provider as secret_provider


def candidate():
    return {
        "schema_version": CANDIDATE_SCHEMA,
        "action_id": "sandbox.permission.chmod.v1",
        "installation_location": "/usr/bin/chmod",
        "tool_version": "9.5",
    }


def result():
    return {
        "schema_version": SCHEMA,
        "candidate_digest": content_hash(candidate()),
        "status": "ready",
        "code": "verified",
        "installation": record(),
        "platform": "linux",
        "architecture": "x86_64",
    }


@pytest.mark.parametrize(
    "change",
    [
        {"extra": "ignored"},
        {"content_sha256": "sha256:" + "a" * 64},
        {"tool_version": ".9.5"},
        {"installation_location": "/usr/bin/../chmod"},
        {"installation_location": "/usr/bin/chmod\n"},
        {"installation_location": "/usr/bin/"},
    ],
)
def test_candidate_refuses_unreviewed_fields_and_unsafe_values(change):
    with pytest.raises(ContractError):
        canonical_native_tool_candidate({**candidate(), **change})


@pytest.mark.parametrize(
    "field,value",
    [
        ("installation_location", "/usr/bin/other"),
        ("tool_version", "9.6"),
        ("adapter_contract_digest", "sha256:" + "c" * 64),
        ("architecture", "aarch64"),
        ("tool_id", "other.tool.v1"),
        ("size_bytes", True),
    ],
)
def test_candidate_response_cannot_substitute_setup_identity(field, value):
    response = result()
    response["installation"][field] = value
    with pytest.raises(ContractError):
        validate_candidate_inspection(candidate(), response)


def test_candidate_response_is_bound_and_unavailable_has_no_identity():
    assert validate_candidate_inspection(candidate(), result()) == result()
    response = result()
    response["candidate_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError):
        validate_candidate_inspection(candidate(), response)
    response = {
        **result(),
        "status": "unavailable",
        "code": "unsafe_installation",
        "installation": None,
    }
    assert validate_candidate_inspection(candidate(), response)["installation"] is None
    response["installation"] = record()
    with pytest.raises(ContractError):
        validate_candidate_inspection(candidate(), response)


def test_unknown_gnu_build_remains_unavailable_without_saved_identity():
    response = {
        **result(),
        "status": "unavailable",
        "code": "unrecognized_tool_build",
        "installation": None,
    }
    assert validate_candidate_inspection(candidate(), response) == response
    response["installation"] = record()
    with pytest.raises(ContractError):
        validate_candidate_inspection(candidate(), response)


def test_subprocess_candidate_uses_fixed_readonly_command_and_removes_record(tmp_path):
    runner = object.__new__(SubprocessRustRunner)
    runner.work_root, runner.runner_binary = tmp_path, Path("/opt/bluefire/runner")

    def invoke(argv):
        assert argv[:3] == [
            str(runner.runner_binary),
            "inspect-native-tool-candidate",
            "--candidate",
        ]
        assert len(argv) == 5 and argv[4] == "--json"
        path = Path(argv[3])
        assert path.is_relative_to(tmp_path)
        assert json.loads(path.read_bytes()) == candidate()
        return json.dumps(result()).encode()

    runner._invoke = invoke
    assert runner.inspect_native_tool_candidate(candidate()) == result()
    assert list(tmp_path.iterdir()) == []


class CandidateRunner(InspectingRunner):
    def inspect_native_tool_candidate(self, request):
        assert request == candidate()
        self.inspect_calls += 1
        return result()


def test_authenticated_candidate_setup_never_dispatches_effect(
    enrollment_root, secret_provider, tmp_path
):
    runner = CandidateRunner()
    with AuthenticatedRunnerServer(
        enrollment_root, runner, tmp_path / "transport.sqlite3", secret_provider=secret_provider
    ) as server:
        observed = transport_support._client(
            enrollment_root, server, secret_provider
        ).inspect_native_tool_candidate(candidate())
    assert observed == result()
    assert runner.inspect_calls == 1 and runner.execute_calls == 0


def test_authenticated_candidate_refuses_non_tool_action(
    enrollment_root, secret_provider, tmp_path
):
    runner = CandidateRunner()
    with AuthenticatedRunnerServer(
        enrollment_root, runner, tmp_path / "transport.sqlite3", secret_provider=secret_provider
    ) as server:
        with pytest.raises(RunnerRemoteError):
            transport_support._client(
                enrollment_root, server, secret_provider
            ).inspect_native_tool_candidate(
                {**candidate(), "action_id": "sandbox.fixture.create.v1"}
            )
    assert runner.inspect_calls == 0 and runner.execute_calls == 0


def test_default_setup_inspects_unenrolled_draft_through_existing_authenticated_host(
    enrollment_root, secret_provider, tmp_path
):
    runner = CandidateRunner()
    with AuthenticatedRunnerServer(
        enrollment_root, runner, tmp_path / "transport.sqlite3", secret_provider=secret_provider
    ) as server:
        client = transport_support._client(enrollment_root, server, secret_provider)
        selected = []

        class ExistingHost:
            def status(self):
                return ManagedRunnerLifecycle._status_payload(
                    SimpleNamespace(runner_id="runner.test"),
                    state="ready",
                    enrollment_state="active",
                    process_state="authenticated",
                    profile_id=client.profile_id,
                )

            def client_for_profile(self, profile_id):
                assert profile_id == client.profile_id
                selected.append(profile_id)
                return client, tmp_path / "workspace"

        service = BlueFireService(
            project_root=ROOT, runs_dir=tmp_path / "runs", runner_lifecycle=ExistingHost()
        )
        try:
            document = configured_profile().to_dict()
            document.update(
                id="draft.permission-unenrolled.v1",
                platforms=["linux"],
                native_tool_installations=[],
            )
            assert document["id"] != client.profile_id
            service.save_resource(
                "runner_profile", document["id"], {"document": document, "status": "draft"}
            )
            before = deepcopy(service.product_store.get_resource("runner_profile", document["id"]))
            assert service.inspect_runner_profile_tool(document["id"], candidate()) == result()
            assert service.product_store.get_resource("runner_profile", document["id"]) == before
            assert selected == [client.profile_id]
            assert document["id"] not in {profile.id for profile in service._runner_profiles()}
            assert service.store.list_runs() == []
        finally:
            service.close()
    assert runner.inspect_calls == 1 and runner.execute_calls == 0


@pytest.fixture
def setup_service(tmp_path):
    runner = CandidateRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda profile: (runner, tmp_path / "workspace"),
    )
    document = configured_profile().to_dict()
    document.update(platforms=["linux"], native_tool_installations=[])
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    try:
        yield service, runner, document
    finally:
        service.close()


def test_profile_candidate_inspection_does_not_save_activate_or_approve(setup_service):
    service, runner, document = setup_service
    before = deepcopy(service.product_store.get_resource("runner_profile", document["id"]))
    assert service.inspect_runner_profile_tool(document["id"], candidate()) == result()
    assert service.product_store.get_resource("runner_profile", document["id"]) == before
    assert service.store.list_runs() == []
    assert runner.inspect_calls == 1 and runner.execute_calls == 0


@pytest.mark.parametrize("change", ["inventory", "profile", "invalid-result"])
def test_candidate_inspection_refuses_changed_authority_or_invalid_output(setup_service, change):
    service, runner, document = setup_service

    def inspect(request):
        if change == "inventory":
            inventory = runner.inventory()
            runner.inventory = lambda: {**inventory, "runner_version": "9.9.9"}
        if change == "profile":
            changed = deepcopy(document)
            changed["budgets"]["max_steps"] -= 1
            service.save_resource(
                "runner_profile", document["id"], {"document": changed, "status": "draft"}
            )
        return {"private": "/sensitive/location"} if change == "invalid-result" else result()

    runner.inspect_native_tool_candidate = inspect
    with pytest.raises(APIError) as error:
        service.inspect_runner_profile_tool(document["id"], candidate())
    assert error.value.code == "native_tool_inspection_unavailable"
    assert "sensitive" not in str(error.value)


def test_profile_setup_requires_enabled_method_before_readonly_dispatch(setup_service):
    service, runner, document = setup_service
    document["enabled_actions"].remove(candidate()["action_id"])
    service.save_resource(
        "runner_profile", document["id"], {"document": document, "status": "draft"}
    )
    with pytest.raises(APIError) as error:
        service.inspect_runner_profile_tool(document["id"], candidate())
    assert error.value.code == "native_tool_setup_invalid"
    assert runner.inspect_calls == 0
