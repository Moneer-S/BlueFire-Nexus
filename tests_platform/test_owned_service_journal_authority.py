from __future__ import annotations

import os
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire.contracts import ContractError, ExecutionMode
from bluefire.owned_service_authority import OwnedServiceScope, compile_owned_service_scope
from bluefire.owned_service_orchestration import (
    compile_run_scope_orchestrator,
    pending_service_operation_binding,
    recheck_pending_service_operation_binding,
    validate_run_options,
)
from bluefire.tool_adapters.service_journal import ServiceIntentJournal
from bluefire.tool_adapters.service_lifecycle import OwnedUserService
from bluefire.tool_adapters.service_operation_binding import ServiceOperationBinding
from bluefire.util import content_hash
from tests_platform.test_owned_service_authority import _profile, _scope


@pytest.fixture(autouse=True)
def private_test_parent(tmp_path: Any) -> None:
    if os.name == "nt":
        from bluefire.windows_owner_acl import apply_owner_private_acl_path

        apply_owner_private_acl_path(tmp_path, directory=True)
    else:
        tmp_path.chmod(0o700)


def _reviewed_scope() -> tuple[dict[str, Any], OwnedServiceScope, dict[str, Any]]:
    profile = _profile()
    target_scope = {"scope_refs": []}
    raw_scope = _scope(profile)
    raw_scope["target_scope_digest"] = content_hash(target_scope)
    scope = compile_owned_service_scope(raw_scope, profile=profile)
    return profile, scope, target_scope


def _journal(tmp_path: Any, scope: OwnedServiceScope) -> ServiceIntentJournal:
    journal = ServiceIntentJournal(tmp_path / "service-intents.sqlite3")
    identity = OwnedUserService.from_mapping(scope.identity_mapping())
    journal.reserve(identity, "service-journal-test.v1")
    journal.begin(identity.digest, "create_unit", expected_revision=0)
    return journal


def _compile(
    profile: dict[str, Any],
    scope: OwnedServiceScope,
    target_scope: dict[str, Any],
    journal: ServiceIntentJournal | None,
) -> tuple[OwnedServiceScope | None, ServiceOperationBinding | None]:
    document = scope.to_dict()
    step = SimpleNamespace(step_id=document["step_id"], action_id=document["action_id"])
    return compile_run_scope_orchestrator(
        scope,
        profile=profile,
        scenario_id=document["scenario_id"],
        plan_steps=[step],
        target_scope=target_scope,
        service_journal=journal,
    )


def test_orchestration_captures_exact_pending_binding_from_real_journal(tmp_path: Any) -> None:
    profile, scope, target_scope = _reviewed_scope()
    journal = _journal(tmp_path, scope)

    compiled_scope, binding = _compile(profile, scope, target_scope, journal)

    assert compiled_scope == scope
    assert binding is not None
    record = journal.get(OwnedUserService.from_mapping(scope.identity_mapping()).digest)
    assert binding.to_dict()["journal_record_hash"] == content_hash(
        {key: value for key, value in record.items() if key != "recovery_state"}
    )
    assert binding.to_dict()["operation"] == "create_unit"
    assert binding.to_dict()["journal_revision"] == 1


def test_orchestration_rejects_fabricated_but_valid_pending_binding(tmp_path: Any) -> None:
    _profile_doc, scope, _target_scope = _reviewed_scope()
    journal = _journal(tmp_path, scope)
    actual = pending_service_operation_binding(journal, scope)
    fabricated_document = deepcopy(actual.to_dict())
    fabricated_document["journal_request_id"] = "fabricated-request.v1"
    fabricated_document["journal_record_hash"] = "sha256:" + "1" * 64
    fabricated_document["operation_id"] = "op-" + "2" * 32
    fabricated = ServiceOperationBinding.from_mapping(fabricated_document)

    with pytest.raises(ContractError, match="changed before dispatch"):
        recheck_pending_service_operation_binding(journal, scope, fabricated)


@pytest.mark.parametrize("transition", ["completed", "stale", "refreshed"])
def test_orchestration_rechecks_captured_pending_revision(tmp_path: Any, transition: str) -> None:
    _profile_doc, scope, _target_scope = _reviewed_scope()
    journal = _journal(tmp_path, scope)
    captured = pending_service_operation_binding(journal, scope)
    document = captured.to_dict()
    identity_digest = document["identity_digest"]
    operation_id = document["operation_id"]

    if transition == "completed":
        journal.finish(identity_digest, operation_id, "succeeded", expected_revision=1)
    elif transition == "stale":
        journal.finish(identity_digest, operation_id, "failed", expected_revision=1)
    else:
        journal.finish(identity_digest, operation_id, "succeeded", expected_revision=1)
        journal.begin(identity_digest, "reload", expected_revision=2)

    with pytest.raises(ContractError, match="changed before dispatch"):
        recheck_pending_service_operation_binding(journal, scope, captured)


def test_owned_service_requires_journal_but_legacy_path_remains_available() -> None:
    _profile_doc, scope, _target_scope = _reviewed_scope()
    with pytest.raises(ContractError, match="configured service intent journal"):
        pending_service_operation_binding(None, scope)

    validate_run_options(
        None,
        False,
        mode=ExecutionMode.SIMULATE,
        execute_mode=ExecutionMode.EXECUTE,
        replay=None,
        replay_checkpoint=None,
        resume_from_step_id=None,
    )
