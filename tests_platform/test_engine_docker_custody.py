from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.engine_docker_custody import EngineDockerCustodyError, ProductStoreDockerProxyCustody
from bluefire.engine_docker_exec_admission import DockerExecBindingV2
from bluefire.engine_docker_exec_dispatch import DockerExecDispatchRuntimeV2
from bluefire.engine_docker_proxy import (
    DockerDaemonExchange,
    DockerPolicyProxy,
    DockerProxyAuditRecord,
    DockerProxyState,
    EngineDockerProxyError,
)
from bluefire.product_store import ProductStore
from bluefire.util import content_hash
from tests_platform.docker_exec_runtime_fixture import runtime_resources
from tests_platform.test_engine_docker_control import policy_v2
from tests_platform.test_engine_docker_exec_admission import CREATE, admission, exec_body
from tests_platform.test_engine_docker_proxy import (
    CONTAINER_ID,
    EXEC_ID,
    Audit,
    Cancel,
    Clock,
    Transport,
    create_body,
    inspect_body_v2,
    ownership,
    policy,
    raw_request,
    raw_response,
)

REQUEST = "sha256:" + "a" * 64
REQUEST_REF = "sha256:" + "b" * 64
RESPONSE = "sha256:" + "c" * 64


def journal(tmp_path: Path) -> tuple[ProductStore, ProductStoreDockerProxyCustody]:
    store = ProductStore(tmp_path / "product.sqlite")
    return store, ProductStoreDockerProxyCustody(
        store, policy=policy(), initial_state=DockerProxyState.create(ownership())
    )


def prepare(adapter: ProductStoreDockerProxyCustody, before: DockerProxyState) -> None:
    adapter.prepare(
        request_ref=REQUEST_REF,
        sequence=1,
        operation="container_create",
        request_digest=REQUEST,
        policy_digest=policy().policy_digest,
        state=before,
    )


def record(
    before: DockerProxyState,
    after: DockerProxyState,
    *,
    phase: str = "validated",
) -> DockerProxyAuditRecord:
    return DockerProxyAuditRecord(
        schema_version="bluefire.engine-docker-proxy-audit.v1",
        request_ref=REQUEST_REF,
        sequence=1,
        phase=phase,
        outcome="accepted",
        operation="container_create",
        policy_digest=policy().policy_digest,
        request_digest=REQUEST,
        response_digest=RESPONSE,
        state_before_digest=before.state_digest,
        state_after_digest=after.state_digest,
        started_monotonic_ns=10,
        ended_monotonic_ns=20,
        reconciliation_required=after.reconciliation_required,
    )


def retain_v2_transition(
    adapter: ProductStoreDockerProxyCustody,
    before: DockerProxyState,
    after: DockerProxyState,
    *,
    sequence: int,
    operation: str,
) -> tuple[DockerProxyAuditRecord, DockerProxyAuditRecord]:
    request_ref = "sha256:" + f"{sequence:064x}"
    request_digest = "sha256:" + f"{sequence + 100:064x}"
    adapter.prepare(
        request_ref=request_ref,
        sequence=sequence,
        operation=operation,
        request_digest=request_digest,
        policy_digest=policy_v2().policy_digest,
        state=before,
    )
    validated = DockerProxyAuditRecord(
        schema_version="bluefire.engine-docker-proxy-audit.v1",
        request_ref=request_ref,
        sequence=sequence,
        phase="validated",
        outcome="accepted",
        operation=operation,
        policy_digest=policy_v2().policy_digest,
        request_digest=request_digest,
        response_digest="sha256:" + f"{sequence + 200:064x}",
        state_before_digest=before.state_digest,
        state_after_digest=after.state_digest,
        started_monotonic_ns=sequence * 10,
        ended_monotonic_ns=sequence * 10 + 1,
        reconciliation_required=False,
    )
    adapter.retain(validated, after)
    adapter.append(validated)
    published = replace(validated, phase="published", ended_monotonic_ns=sequence * 10 + 2)
    adapter.retain(published, after)
    adapter.append(published)
    return validated, published


def test_v2_custody_rehydrates_only_the_live_exact_admission(tmp_path: Path) -> None:
    current_policy = policy_v2()
    admitted = admission(policy=current_policy)
    store = ProductStore(tmp_path / "v2-product.sqlite")
    initial = DockerProxyState.create(ownership(container=True))
    adapter = ProductStoreDockerProxyCustody(
        store,
        policy=current_policy,
        initial_state=initial,
    )
    created_binding = DockerExecBindingV2(
        EXEC_ID,
        admitted,
        deadline_monotonic_ns=10_000,
    )
    created = replace(
        initial,
        ownership=ownership(container=True, exec_id=True),
        generation=1,
        v2_exec_bindings=(created_binding,),
        v2_exec_operation_ids=(admitted.request.operation_id,),
    )
    retain_v2_transition(
        adapter,
        initial,
        created,
        sequence=1,
        operation="container_exec_create",
    )
    started = replace(
        created,
        generation=2,
        v2_exec_bindings=(replace(created_binding, phase="started"),),
    )
    retain_v2_transition(
        adapter,
        created,
        started,
        sequence=2,
        operation="exec_start",
    )

    reopened = adapter.reopen()
    assert reopened.state == started
    assert reopened.state.v2_exec_bindings[0].admission is admitted
    assert not reopened.state.reconciliation_required
    assert reopened.sequence == 2
    assert reopened.unresolved_operations == ()


def test_fresh_v2_reopen_preserves_evidence_and_fences_missing_admission(
    tmp_path: Path,
) -> None:
    current_policy = policy_v2()
    admitted = admission(policy=current_policy)
    store = ProductStore(tmp_path / "v2-fresh-product.sqlite")
    initial = DockerProxyState.create(ownership(container=True))
    adapter = ProductStoreDockerProxyCustody(
        store,
        policy=current_policy,
        initial_state=initial,
    )
    created_binding = DockerExecBindingV2(
        EXEC_ID,
        admitted,
        deadline_monotonic_ns=10_000,
    )
    created = replace(
        initial,
        ownership=ownership(container=True, exec_id=True),
        generation=1,
        v2_exec_bindings=(created_binding,),
        v2_exec_operation_ids=(admitted.request.operation_id,),
    )
    retain_v2_transition(
        adapter,
        initial,
        created,
        sequence=1,
        operation="container_exec_create",
    )
    started = replace(
        created,
        generation=2,
        v2_exec_bindings=(replace(created_binding, phase="started"),),
    )
    retain_v2_transition(
        adapter,
        created,
        started,
        sequence=2,
        operation="exec_start",
    )

    fresh = ProductStoreDockerProxyCustody(
        ProductStore(store.path),
        policy=current_policy,
    ).reopen()
    assert fresh.state.reconciliation_required
    assert fresh.state.v2_exec_bindings == ()
    assert fresh.state.v2_exec_operation_ids == (admitted.request.operation_id,)
    assert fresh.state.ownership == started.ownership
    assert fresh.sequence == 2
    assert len(fresh.audits) == 4
    assert fresh.unresolved_operations == ()
    assert fresh.known_exec_bindings == ((EXEC_ID, CONTAINER_ID),)
    assert fresh.audits[-1].state_after_digest == started.state_digest
    assert fresh.state.state_digest != started.state_digest
    with store._connection() as connection:
        documents = "\n".join(
            row[0]
            for row in connection.execute(
                "SELECT document_json FROM engine_docker_custody_events ORDER BY event_sequence"
            )
        )
    assert "opaque_ref" not in documents
    assert "printf" not in documents

    fresh_adapter = ProductStoreDockerProxyCustody(ProductStore(store.path), policy=current_policy)
    with pytest.raises(EngineDockerCustodyError, match="reconciliation"):
        fresh_adapter.prepare(
            request_ref="sha256:" + "f" * 64,
            sequence=3,
            operation="exec_inspect",
            request_digest="sha256:" + "e" * 64,
            policy_digest=current_policy.policy_digest,
            state=fresh.state,
        )


def test_missing_v2_exec_owner_refuses_without_stranding_durable_intent(tmp_path: Path) -> None:
    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        current_policy = policy_v2()
        owned = ownership(container=True)
        custody = ProductStoreDockerProxyCustody(
            ProductStore(tmp_path / "v2-preflight.sqlite"),
            policy=current_policy,
            initial_state=DockerProxyState.create(owned),
        )
        runtime_without_owner = DockerExecDispatchRuntimeV2(
            authority=resources.authority,
            journal=resources.journal,
            monotonic_ns=resources.clock,
        )
        transport = Transport(raw_response(201, {"Id": EXEC_ID}))
        proxy = DockerPolicyProxy(
            policy=current_policy,
            ownership=owned,
            transport=transport,
            audit=custody,
            custody=custody,
            monotonic_ns=resources.clock,
            exec_runtime=runtime_without_owner,
            exec_cancellation=resources.cancellation,
        )
        refused = proxy.handle(
            raw_request("POST", CREATE, exec_body(admitted)),
            Cancel(),
            exec_admission=admitted,
        )
        assert refused.status_code == 503
        assert transport.seen == []
        reopened = custody.reopen()
        assert reopened.sequence == 1
        assert reopened.unresolved_operations == ()
        assert not reopened.state.reconciliation_required
        assert reopened.audits[-1].outcome == "exec_custody_unavailable"

        transport.response = raw_response(200, inspect_body_v2(current_policy))
        inspected = proxy.handle(
            raw_request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), Cancel()
        )
        assert inspected.status_code == 200
        assert custody.reopen().sequence == 2


def test_durable_audit_and_full_custody_reopen(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    after = replace(before, ownership=ownership(container=True, exec_id=True), generation=1)
    validated = record(before, after)
    adapter.retain(validated, after)
    assert adapter.append(validated) == content_hash(validated.to_dict())
    published = replace(validated, phase="published")
    adapter.retain(published, after)
    adapter.append(published)

    reopened = ProductStoreDockerProxyCustody(ProductStore(store.path), policy=policy()).reopen()
    assert reopened.state == after
    assert reopened.sequence == 1
    assert reopened.audits == (validated, published)
    assert reopened.unresolved_operations == ()
    assert reopened.known_container_ids == (CONTAINER_ID,)
    assert reopened.known_exec_bindings == ((EXEC_ID, CONTAINER_ID),)


def test_prepared_operation_survives_crash_without_resource_id(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    reopened = ProductStoreDockerProxyCustody(ProductStore(store.path), policy=policy()).reopen()
    assert reopened.state.reconciliation_required
    assert reopened.state.ownership == before.ownership
    assert reopened.sequence == 1
    assert reopened.unresolved_operations[0].request_digest == REQUEST
    assert reopened.known_container_ids == ()
    with pytest.raises(EngineDockerCustodyError, match="reconciliation"):
        adapter.prepare(
            request_ref="sha256:" + "d" * 64,
            sequence=2,
            operation="container_create",
            request_digest=REQUEST,
            policy_digest=policy().policy_digest,
            state=before,
        )


def test_new_prepared_sequence_must_follow_reopened_sequence_exactly(tmp_path: Path) -> None:
    _, adapter = journal(tmp_path)
    before = adapter.reopen().state
    with pytest.raises(EngineDockerCustodyError, match="sequence is discontinuous"):
        adapter.prepare(
            request_ref=REQUEST_REF,
            sequence=2,
            operation="container_create",
            request_digest=REQUEST,
            policy_digest=policy().policy_digest,
            state=before,
        )
    assert adapter.reopen().sequence == 0


def test_exact_prepared_operation_is_idempotent(tmp_path: Path) -> None:
    _, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    prepare(adapter, before)
    reopened = adapter.reopen()
    assert reopened.sequence == 1
    assert len(reopened.unresolved_operations) == 1


@pytest.mark.parametrize("acknowledge", [False, True])
def test_unpublished_retained_state_remains_fenced(tmp_path: Path, acknowledge: bool) -> None:
    store, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    after = replace(before, ownership=ownership(pending=True), generation=1)
    validated = record(before, after)
    adapter.retain(validated, after)
    if acknowledge:
        adapter.append(validated)
    reopened = ProductStoreDockerProxyCustody(ProductStore(store.path), policy=policy()).reopen()
    assert reopened.state.reconciliation_required
    assert reopened.state.ownership.pending_container_ids == (CONTAINER_ID,)
    assert len(reopened.unresolved_operations) == 1
    assert reopened.known_container_ids == (CONTAINER_ID,)


def test_published_custody_without_audit_commit_is_fenced(tmp_path: Path) -> None:
    _, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    after = replace(before, ownership=ownership(pending=True), generation=1)
    validated = record(before, after)
    adapter.retain(validated, after)
    adapter.append(validated)
    adapter.retain(replace(validated, phase="published"), after)
    assert adapter.reopen().state.reconciliation_required
    assert len(adapter.reopen().unresolved_operations) == 1


def test_idempotent_hooks_do_not_duplicate_or_rewrite_history(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    prepare(adapter, before)
    after = replace(before, ownership=ownership(pending=True), generation=1)
    item = record(before, after)
    adapter.retain(item, after)
    adapter.retain(item, after)
    adapter.append(item)
    adapter.append(item)
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_docker_custody_events").fetchone()[0]
            == 4
        )
    with pytest.raises(EngineDockerCustodyError, match="changed"):
        adapter.append(replace(item, ended_monotonic_ns=21))


def test_receipt_requires_matching_retained_state(tmp_path: Path) -> None:
    _, adapter = journal(tmp_path)
    before = adapter.reopen().state
    prepare(adapter, before)
    after = replace(before, ownership=ownership(pending=True), generation=1)
    item = record(before, after)
    with pytest.raises(EngineDockerCustodyError, match="retained custody"):
        adapter.append(item)
    with pytest.raises(EngineDockerCustodyError, match="does not match"):
        adapter.retain(item, before)
    assert adapter.reopen().known_container_ids == ()


def test_reopen_refuses_policy_daemon_and_initial_state_changes(tmp_path: Path) -> None:
    store, _ = journal(tmp_path)
    with pytest.raises(EngineDockerCustodyError, match="binding"):
        ProductStoreDockerProxyCustody(store, policy=replace(policy(), api_version="v1.48"))
    with pytest.raises(EngineDockerCustodyError, match="binding"):
        ProductStoreDockerProxyCustody(
            store, policy=replace(policy(), daemon_instance_digest="sha256:" + "f" * 64)
        )
    with pytest.raises(EngineDockerCustodyError, match="initial state changed"):
        ProductStoreDockerProxyCustody(
            store, policy=policy(), initial_state=DockerProxyState.create(ownership(pending=True))
        )


def test_sql_update_delete_and_replace_are_refused(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    for sql in (
        "UPDATE engine_docker_custody_events SET event_key='changed'",
        "DELETE FROM engine_docker_custody_events",
        "INSERT OR REPLACE INTO engine_docker_custody_events SELECT * FROM engine_docker_custody_events",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            with store._connection(write=True) as connection:
                connection.execute(sql)
    assert adapter.reopen().sequence == 0


def test_missing_trigger_is_detected_and_never_repaired(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    with store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER engine_docker_custody_no_delete")
    with pytest.raises(EngineDockerCustodyError, match="guard"):
        adapter.reopen()
    with pytest.raises(EngineDockerCustodyError, match="guard"):
        ProductStoreDockerProxyCustody(store, policy=policy())


def test_hash_chain_corruption_is_refused_after_guard_restored(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    with store._connection(write=True) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='engine_docker_custody_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER engine_docker_custody_no_update")
        connection.execute("UPDATE engine_docker_custody_events SET event_digest=?", (REQUEST,))
        connection.execute(trigger)
    with pytest.raises(EngineDockerCustodyError, match="chain audit"):
        adapter.reopen()


def test_refusal_audit_without_send_is_retained_and_reopened(tmp_path: Path) -> None:
    _, adapter = journal(tmp_path)
    before = adapter.reopen().state
    item = replace(record(before, before), phase="refused", outcome="policy_refused")
    adapter.retain(item, before)
    adapter.append(item)
    reopened = adapter.reopen()
    assert reopened.audits == (item,)
    assert reopened.sequence == 1
    assert not reopened.state.reconciliation_required
    assert reopened.unresolved_operations == ()


def test_proxy_create_reopens_pending_and_restored_sequence(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    transport = Transport(raw_response(201, {"Id": CONTAINER_ID, "Warnings": []}))
    proxy = DockerPolicyProxy(
        policy=policy(),
        ownership=ownership(),
        transport=transport,
        audit=adapter,
        custody=adapter,
        monotonic_ns=Clock(),
    )
    request = raw_request(
        "POST", f"/v1.47/containers/create?name={policy().container_name}", create_body()
    )
    assert proxy.handle(request, Cancel()).status_code == 201
    reopened_adapter = ProductStoreDockerProxyCustody(ProductStore(store.path), policy=policy())
    reopened = reopened_adapter.reopen()
    assert reopened.state.ownership.pending_container_ids == (CONTAINER_ID,)
    assert reopened.state.ownership.container_ids == ()
    assert reopened.sequence == 1
    assert not reopened.state.reconciliation_required
    with pytest.raises(EngineDockerProxyError, match="durable custody is not pristine"):
        DockerPolicyProxy(
            policy=policy(),
            ownership=reopened.state.ownership,
            transport=transport,
            audit=reopened_adapter,
            custody=reopened_adapter,
            monotonic_ns=Clock(),
        )
    assert len(transport.seen) == 1
    transport.response = raw_response(
        200,
        b"OK",
        content_type="text/plain; charset=utf-8",
        extra_headers=(
            ("Cache-Control", "no-cache, no-store, must-revalidate"),
            ("Pragma", "no-cache"),
        ),
    )
    restored = DockerPolicyProxy(
        policy=policy(),
        ownership=reopened.state.ownership,
        transport=transport,
        audit=reopened_adapter,
        custody=reopened_adapter,
        monotonic_ns=Clock(),
        restore_from_custody=True,
    )
    assert restored.handle(raw_request("GET", "/_ping"), Cancel()).status_code == 200
    assert reopened_adapter.reopen().sequence == 2
    assert len(transport.seen) == 2


def test_proxy_restore_requires_store_backed_custody() -> None:
    with pytest.raises(EngineDockerProxyError, match="durable custody is unavailable"):
        DockerPolicyProxy(
            policy=policy(),
            ownership=ownership(),
            transport=Transport(raw_response(200, b"OK", content_type="text/plain")),
            audit=Audit(),
            monotonic_ns=Clock(),
            restore_from_custody=True,
        )


def test_proxy_restore_rejects_custody_for_another_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, other_custody = journal(tmp_path)
    reopened = other_custody.reopen()
    monkeypatch.setattr(
        other_custody,
        "reopen",
        lambda: replace(reopened, attempt_id="engine-attempt-" + "9" * 32),
    )
    with pytest.raises(EngineDockerProxyError, match="does not match ownership"):
        DockerPolicyProxy(
            policy=policy(),
            ownership=ownership(),
            transport=Transport(raw_response(200, b"OK", content_type="text/plain")),
            audit=other_custody,
            custody=other_custody,
            monotonic_ns=Clock(),
            restore_from_custody=True,
        )


def test_proxy_prepare_failure_prevents_transport(tmp_path: Path) -> None:
    store, adapter = journal(tmp_path)
    with store._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER fail_docker_prepare BEFORE INSERT ON engine_docker_custody_events "
            "WHEN NEW.event_key LIKE 'prepared:%' BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    transport = Transport(raw_response(200, b"OK", content_type="text/plain"))
    proxy = DockerPolicyProxy(
        policy=policy(),
        ownership=ownership(),
        transport=transport,
        audit=adapter,
        custody=adapter,
        monotonic_ns=Clock(),
    )
    assert proxy.handle(raw_request("GET", "/_ping"), Cancel()).status_code == 503
    assert transport.seen == []
    reopened = adapter.reopen()
    assert reopened.unresolved_operations == ()
    assert reopened.audits[0].outcome == "audit_failed"


def test_ambiguous_proxy_failure_reopens_fenced_and_never_resends(tmp_path: Path) -> None:
    class DisconnectTransport(Transport):
        def exchange(self, raw_request_value: bytes, **kwargs: object) -> DockerDaemonExchange:
            self.seen.append(raw_request_value)
            raise ConnectionError("owned fake daemon disconnected after request")

    store, adapter = journal(tmp_path)
    transport = DisconnectTransport(b"")
    proxy = DockerPolicyProxy(
        policy=policy(),
        ownership=ownership(),
        transport=transport,
        audit=adapter,
        custody=adapter,
        monotonic_ns=Clock(),
    )
    request = raw_request(
        "POST", f"/v1.47/containers/create?name={policy().container_name}", create_body()
    )
    assert proxy.handle(request, Cancel()).status_code == 503
    reopened_adapter = ProductStoreDockerProxyCustody(ProductStore(store.path), policy=policy())
    reopened = reopened_adapter.reopen()
    assert reopened.state.reconciliation_required
    assert reopened.unresolved_operations[0].operation == "container_create"
    restored = DockerPolicyProxy(
        policy=policy(),
        ownership=reopened.state.ownership,
        transport=transport,
        audit=reopened_adapter,
        custody=reopened_adapter,
        monotonic_ns=Clock(),
        restore_from_custody=True,
    )
    assert restored.handle(request, Cancel()).status_code == 503
    assert len(transport.seen) == 1
