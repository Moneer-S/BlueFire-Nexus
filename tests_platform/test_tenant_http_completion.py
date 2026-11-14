from __future__ import annotations

import json
import threading
from dataclasses import replace

import pytest

from bluefire.engine_relay import BoundedRelayAudit, EngineRelayError
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.tenant_engine_run_trace import verify_tenant_engine_run_trace
from bluefire.tenant_http_completion import (
    ControllerOwnedTenantHttpCompletion,
    TenantHttpCompletionError,
)
from bluefire.tenant_http_run_trace import compile_tenant_http_run_trace_v2
from bluefire.tenant_http_target_adapter import TenantRecordHttpTargetAdapterV2
from bluefire.tenant_http_target_relay import ControlledTenantHttpRelayV2
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_tenant_http_target_v2 import _bridge, _completion, _hash, _request, _setup
from tests_platform.test_tenant_record_target_adapter import NOW, _protect


def _completed(tmp_path):
    case = _setup(tmp_path)
    request = _request(case[6])
    observed = _bridge(case, request, case[-1].handle(request))
    owner = _completion(case, tmp_path)
    receipt = case[-1].revoke(owner)
    return case, request, observed, owner, receipt


def _compile(case, owner, observed=None, request=None):
    return compile_tenant_http_run_trace_v2(
        profile=case[6],
        run_id=case[5].run_id,
        retained_controller_trace=case[-1].controller_trace(),
        retained_bridged_results={} if observed is None else {request.request_id: observed},
        state="completed",
        completion_owner=owner,
        finished_ns=1_000_000_001,
    )


def test_completion_is_durable_exact_and_independently_reopened(tmp_path):
    case, request, observed, owner, receipt = _completed(tmp_path)
    trace = case[-1].controller_trace()
    saved = json.loads((owner._root / owner._name).read_bytes())
    assert saved["receipt"] == receipt.to_dict()
    assert content_hash(saved["adapter_revocation"]) == receipt.adapter_revocation_ref
    reopened_owner = ControllerOwnedTenantHttpCompletion(
        root=owner._root,
        artifacts=owner._artifacts,
        binding=case[5],
        profile=case[6],
        monotonic_ns=lambda: 1_000_000_000,
    )
    reopened = reopened_owner.reopen_for_trace(
        profile=case[6], run_id=case[5].run_id, controller_trace=trace
    )
    assert reopened == receipt and reopened is not receipt
    assert case[-1].revoke(reopened_owner) == receipt
    bundle = _compile(case, reopened_owner, observed, request)
    result = verify_tenant_engine_run_trace(
        binding=bundle.binding,
        events=bundle.events,
        terminal=bundle.terminal,
        retained_results=bundle.results,
        retained_terminal_ref=bundle.terminal.digest,
        reopened_cessation=bundle.reopened_cessation,
    )
    assert result.completeness == "complete"


def test_caller_settlement_claims_are_not_a_compiler_input(tmp_path):
    case = _setup(tmp_path)
    with pytest.raises(TypeError):
        compile_tenant_http_run_trace_v2(
            profile=case[6],
            run_id=case[5].run_id,
            retained_controller_trace=case[-1].controller_trace(),
            retained_bridged_results={},
            state="completed",
            owned_work_settled=True,
            cessation_ref=_hash("claim"),
            finished_ns=1_000_000_001,
        )
    bundle = _compile(case, None)
    assert bundle.terminal.owned_work_settled is False
    assert bundle.terminal.cessation_ref is None


@pytest.mark.parametrize("ambiguous", (False, True))
def test_failed_or_ambiguous_adapter_revoke_stays_unresolved(tmp_path, monkeypatch, ambiguous):
    case = _setup(tmp_path)
    owner = _completion(case, tmp_path)

    def failed():
        if ambiguous:
            return _hash("digest-is-not-an-adapter-receipt")
        raise OSError("adapter unavailable")

    monkeypatch.setattr(case[7], "revoke_http_profile", failed)
    with pytest.raises(EngineRelayError, match="unresolved"):
        case[-1].revoke(owner)
    trace = case[-1].controller_trace()
    assert trace["revoked"] is False and trace["revocation_state"] == "unresolved"
    assert not (owner._root / owner._name).exists()
    with pytest.raises(EngineRelayError):
        case[-1].handle(_request(case[6]))
    with pytest.raises(EngineRelayError):
        case[-1].revoke(owner)
    with pytest.raises(TenantHttpCompletionError):
        owner.reconcile_relay(case[-1])
    assert _compile(case, owner).terminal.owned_work_settled is False


def test_revoke_gates_new_requests_before_adapter_returns(tmp_path, monkeypatch):
    case = _setup(tmp_path)
    owner = _completion(case, tmp_path)
    entered, released = threading.Event(), threading.Event()
    original = case[7].revoke_http_profile

    def blocked():
        entered.set()
        assert released.wait(5)
        return original()

    monkeypatch.setattr(case[7], "revoke_http_profile", blocked)
    output = []
    thread = threading.Thread(target=lambda: output.append(case[-1].revoke(owner)))
    thread.start()
    assert entered.wait(5)
    assert case[-1].controller_trace()["revoked"] is False
    with pytest.raises(EngineRelayError):
        case[-1].handle(_request(case[6]))
    assert not case[4].calls
    released.set()
    thread.join(5)
    assert not thread.is_alive() and len(output) == 1
    assert case[-1].controller_trace()["revoked"] is True


def test_write_failure_never_publishes_settled_or_retries(tmp_path, monkeypatch):
    case = _setup(tmp_path)
    owner = _completion(case, tmp_path)
    original = _PinnedPrivateDirectory.open_new

    def failed(directory, name, **kwargs):
        if name == owner._name:
            raise OSError("write failed")
        return original(directory, name, **kwargs)

    monkeypatch.setattr(_PinnedPrivateDirectory, "open_new", failed)
    with pytest.raises(EngineRelayError):
        case[-1].revoke(owner)
    assert case[-1].controller_trace()["revoked"] is False
    monkeypatch.setattr(_PinnedPrivateDirectory, "open_new", original)
    with pytest.raises(EngineRelayError):
        case[-1].revoke(owner)
    assert not (owner._root / owner._name).exists()


def test_post_write_reopen_failure_requires_exact_reconciliation(tmp_path, monkeypatch):
    case = _setup(tmp_path)
    owner = _completion(case, tmp_path)
    original = owner.reopen_for_trace

    def failed(**_kwargs):
        raise TenantHttpCompletionError("reopen unavailable")

    monkeypatch.setattr(owner, "reopen_for_trace", failed)
    with pytest.raises(EngineRelayError):
        case[-1].revoke(owner)
    assert (owner._root / owner._name).exists()
    assert case[-1].controller_trace()["revoked"] is False
    monkeypatch.setattr(owner, "reopen_for_trace", original)
    receipt = owner.reconcile_relay(case[-1])
    assert receipt.controller_trace_ref == case[-1].controller_trace()["trace_ref"]
    assert case[-1].controller_trace()["revoked"] is True


def test_closed_trace_is_immutable_after_refused_late_calls(tmp_path):
    case, _request_value, _observed, _owner, _receipt = _completed(tmp_path)
    before = case[-1].controller_trace()
    with pytest.raises(EngineRelayError):
        case[-1].handle(_request(case[6], number=2))
    assert case[-1].controller_trace() == before


@pytest.mark.parametrize("field", ("run", "profile", "trace"))
def test_reopen_rejects_run_profile_and_trace_substitution(tmp_path, field):
    case, _request_value, _observed, owner, _receipt = _completed(tmp_path)
    trace = case[-1].controller_trace()
    run_id, profile = case[5].run_id, case[6]
    if field == "run":
        run_id = "run-20261104T150000Z-" + "f" * 16
    elif field == "profile":
        profile = replace(profile, asset_ref=_hash("substituted-asset"))
    else:
        trace["response_bytes"] += 1
        trace["trace_ref"] = content_hash(
            {key: value for key, value in trace.items() if key != "trace_ref"}
        )
    with pytest.raises(TenantHttpCompletionError):
        owner.reopen_for_trace(profile=profile, run_id=run_id, controller_trace=trace)


def test_receipt_cannot_close_a_fresh_relay_for_same_profile(tmp_path):
    case, _request_value, _observed, owner, _receipt = _completed(tmp_path)
    adapter = TenantRecordHttpTargetAdapterV2(
        scratch_root=tmp_path, source=case[3], transport=case[4], monotonic_ns=lambda: 1_000_000_000
    )
    fresh = ControlledTenantHttpRelayV2(
        case[6], adapter, BoundedRelayAudit(), clock=lambda: NOW, monotonic_ns=lambda: 1_000_000_000
    )
    assert (
        fresh.controller_trace()["relay_instance_id"]
        != case[-1].controller_trace()["relay_instance_id"]
    )
    with pytest.raises(EngineRelayError):
        fresh.revoke(owner)
    with pytest.raises(TenantHttpCompletionError):
        owner.reconcile_relay(fresh)
    assert fresh.controller_trace()["revoked"] is False


def test_fake_owner_cannot_return_another_relays_genuine_receipt(tmp_path):
    case, _request_value, _observed, _owner, receipt = _completed(tmp_path)
    adapter = TenantRecordHttpTargetAdapterV2(
        scratch_root=tmp_path, source=case[3], transport=case[4], monotonic_ns=lambda: 1_000_000_000
    )
    fresh = ControlledTenantHttpRelayV2(
        case[6], adapter, BoundedRelayAudit(), clock=lambda: NOW, monotonic_ns=lambda: 1_000_000_000
    )

    class FakeOwner:
        def settle_relay(self, relay):
            assert relay.controller_trace()["revocation_state"] == "closing"
            return receipt

    with pytest.raises(EngineRelayError):
        fresh.revoke(FakeOwner())
    assert fresh.controller_trace()["revoked"] is False
    assert fresh.controller_trace()["revocation_state"] == "unresolved"
    with pytest.raises(EngineRelayError):
        fresh.handle(_request(case[6], number=2))


@pytest.mark.parametrize("damage", ("missing", "partial", "adapter", "worker", "root"))
def test_reopen_requires_intact_protected_receipt_and_worker_source(tmp_path, damage):
    case, _request_value, _observed, owner, _receipt = _completed(tmp_path)
    path = owner._root / owner._name
    if damage == "missing":
        path.unlink()
    elif damage == "partial":
        path.write_bytes(b'{"receipt":')
    elif damage == "adapter":
        value = json.loads(path.read_bytes())
        value["adapter_revocation"]["accepted_http_calls"] += 1
        path.write_bytes(canonical_json_bytes(value))
    elif damage == "worker":
        manifest = owner._artifacts.root / case[5].attempt_id / "manifest.json"
        value = json.loads(manifest.read_bytes())
        value["source_collection_seal"]["worker_state"] = "running"
        manifest.write_bytes(canonical_json_bytes(value) + b"\n")
    else:
        owner._root.rename(owner._root.with_name("old-completion-receipts"))
        owner._root.mkdir()
        _protect(owner._root, directory=True)
    with pytest.raises(TenantHttpCompletionError):
        owner.reopen_for_trace(
            profile=case[6], run_id=case[5].run_id, controller_trace=case[-1].controller_trace()
        )
    bundle = _compile(case, owner)
    assert bundle.terminal.owned_work_settled is False
