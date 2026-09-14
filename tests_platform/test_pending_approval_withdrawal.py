from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.util import content_hash


def pending(store: ProductStore) -> Mapping[str, Any]:
    return store.create_approval_request(
        run_id="run-pending-publication",
        state_digest=content_hash({"state": "test"}),
        plan_digest=content_hash({"plan": "test"}),
        profile_id="sandbox-execute.v1",
        target_scope_digest=content_hash({"scope": "test"}),
        maximum_tier="controlled",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    )


def binding(record: Mapping[str, Any]) -> dict[str, str]:
    return {
        f"expected_{field}": record[field]
        for field in ("state_digest", "plan_digest", "target_scope_digest")
    }


def test_withdrawal_preserves_binding_and_cannot_create_or_consume_authority(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "product.db")
    original = pending(store)
    approval_id = original["approval_id"]
    withdrawn = store.withdraw_pending_approval(approval_id)
    assert withdrawn == {**original, "status": "withdrawn"}
    assert withdrawn["nonce"] is None
    assert withdrawn["approved_by"] is None
    assert ProductStore(store.path).withdraw_pending_approval(approval_id) == withdrawn
    with pytest.raises(ProductStoreError, match="not pending"):
        store.approve(approval_id, approved_by="test-reviewer", **binding(original))
    with pytest.raises(ProductStoreError, match="unavailable"):
        store.consume_approval(approval_id, nonce="no-capability", **binding(original))
    with pytest.raises(ProductStoreError, match="unavailable"):
        store.claim_consumed_approval(
            approval_id,
            nonce="no-capability",
            approved_by="test-reviewer",
            expected_profile_id=original["profile_id"],
            expected_maximum_tier=original["maximum_tier"],
            **binding(original),
        )
    assert store.get_approval_request(approval_id) == withdrawn


@pytest.mark.parametrize("status", ["approved", "consumed", "claimed"])
def test_withdrawal_cannot_revoke_released_authority(tmp_path: Path, status: str) -> None:
    store = ProductStore(tmp_path / "product.db")
    original = pending(store)
    approval_id = original["approval_id"]
    released = store.approve(approval_id, approved_by="test-reviewer", **binding(original))
    if status in {"consumed", "claimed"}:
        released = store.consume_approval(approval_id, nonce=released["nonce"], **binding(original))
    if status == "claimed":
        released = store.claim_consumed_approval(
            approval_id,
            nonce=released["nonce"],
            approved_by="test-reviewer",
            expected_profile_id=original["profile_id"],
            expected_maximum_tier=original["maximum_tier"],
            **binding(original),
        )
    with pytest.raises(ProductStoreError, match="only a pending"):
        store.withdraw_pending_approval(approval_id)
    assert store.get_approval_request(approval_id) == released


def test_withdrawal_refuses_unknown_identity_without_changing_other_requests(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "product.db")
    original = pending(store)
    with pytest.raises(ProductStoreError, match="not found"):
        store.withdraw_pending_approval("approval-missing")
    assert store.get_approval_request(original["approval_id"]) == original


def test_cross_store_approval_and_withdrawal_race_has_one_winner(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "product.db")
    other = ProductStore(store.path)
    original = pending(store)
    barrier = threading.Barrier(2)

    def operation(withdraw: bool) -> str:
        barrier.wait(timeout=5)
        try:
            if withdraw:
                result = store.withdraw_pending_approval(original["approval_id"])
            else:
                result = other.approve(
                    original["approval_id"], approved_by="test-reviewer", **binding(original)
                )
            return str(result["status"])
        except ProductStoreError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(operation, [False, True]))
    assert results.count("refused") == 1
    final = store.get_approval_request(original["approval_id"])
    assert final["status"] in {"approved", "withdrawn"}
    assert final["status"] in results
    assert (final["nonce"] is None) == (final["status"] == "withdrawn")
