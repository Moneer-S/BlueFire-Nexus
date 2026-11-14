"""Cancellation rows remain bound to one precommitted installed owner."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.engine_docker_cancellation_audit_store import (
    CancellationAuditStoreError,
    ProductStoreDockerExecCancellationAuditV2,
)
from bluefire.engine_docker_exec_cancellation import DockerExecCancellationAuditRecordV2
from bluefire.product_store import ProductStore
from bluefire.util import content_hash


def _digest(label: str) -> str:
    return content_hash(label)


def _store(path: Path) -> ProductStoreDockerExecCancellationAuditV2:
    return ProductStoreDockerExecCancellationAuditV2(
        ProductStore(path),
        attempt_id="engine-attempt-" + "a" * 32,
        claim_ref=_digest("claim"),
        controller_fence=_digest("fence"),
        transaction_ref=_digest("transaction"),
        owner_ref=_digest("owner"),
        owner_binding_ref=_digest("owner-binding"),
    )


def _record() -> DockerExecCancellationAuditRecordV2:
    return DockerExecCancellationAuditRecordV2(
        admission_digest=_digest("admission"),
        attempt_id="engine-attempt-" + "a" * 32,
        container_id="b" * 64,
        operation_id="operation-" + "c" * 32,
        custody_plan_digest=_digest("custody"),
        network_policy_digest=_digest("network"),
        authority_ref=_digest("authority"),
        claim_ref=_digest("claim"),
        controller_fence=_digest("fence"),
        reason="cancelled",
        phase="requested",
        monotonic_ns=123,
    )


def test_cancellation_audit_reopens_exact_committed_chain(tmp_path: Path) -> None:
    path = tmp_path / "product.sqlite"
    sink = _store(path)
    requested = _record()
    first_ref = sink.append(requested)
    verified = replace(
        requested,
        phase="absence_verified",
        monotonic_ns=124,
        stop_snapshot_digest=_digest("stopped"),
        inspect_snapshot_digest=_digest("inspected"),
    )
    second_ref = sink.append(verified)
    reopened = _store(path).reopen()
    assert [item.record_ref for item in reopened] == [first_ref, second_ref]
    assert reopened[1].previous_entry_ref == reopened[0].entry_ref
    assert reopened[1].record == verified


def test_cancellation_audit_rejects_foreign_claim_and_immutable_update(tmp_path: Path) -> None:
    path = tmp_path / "product.sqlite"
    sink = _store(path)
    with pytest.raises(CancellationAuditStoreError, match="another owner"):
        sink.append(replace(_record(), claim_ref=_digest("foreign")))
    sink.append(_record())
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.DatabaseError):
        connection.execute(
            "UPDATE docker_exec_cancellation_audit_v2 SET record_ref=? WHERE sequence=1",
            (_digest("changed"),),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"phase": "absence_verified"},
        {"phase": "unknown"},
        {"phase": "unrecognized"},
        {"admission_digest": "not-a-digest"},
    ],
)
def test_cancellation_audit_refuses_unsupported_proof(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    sink = _store(tmp_path / "product.sqlite")
    with pytest.raises(CancellationAuditStoreError):
        sink.append(replace(_record(), **changes))
    assert sink.reopen() == ()
