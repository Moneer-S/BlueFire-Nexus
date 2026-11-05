from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bluefire.tenant_record_lab import (
    TenantRecordLabError,
    baseline_defense_config,
    defense_change_receipt,
    generate_tenant_record_fixture,
    hardened_defense_config,
    mint_lab_session,
    verify_lab_session,
)
from bluefire.util import canonical_json_bytes

SEED = b"tenant-lab-test-seed-000000000001"
KEY = b"tenant-lab-signing-key-material-0000000000000001"
NOW = datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc)


def test_fixture_is_deterministic_bounded_generated_jsonl() -> None:
    first = generate_tenant_record_fixture(SEED)
    second = generate_tenant_record_fixture(SEED)

    assert first == second
    assert first.probe_tenant_id != first.protected_tenant_id
    assert first.jsonl == b"".join(
        canonical_json_bytes(record.to_dict()) + b"\n" for record in first.records
    )
    assert first.binding()["record_count"] == 4
    assert all(record.generated_value.startswith("testdata-") for record in first.records)


def test_held_out_fixture_changes_ids_order_and_route_priority() -> None:
    primary = generate_tenant_record_fixture(SEED)
    held_out = generate_tenant_record_fixture(SEED, held_out=True)

    assert held_out.fixture_id != primary.fixture_id
    assert held_out.protected_tenant_id != primary.protected_tenant_id
    assert held_out.route_order == ("bounded_export", "record_lookup")
    assert primary.route_order == ("record_lookup", "bounded_export")
    assert [record.label for record in held_out.records] != [
        record.label for record in primary.records
    ]


def test_defense_change_binds_exact_preimage_and_rollback() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    baseline = baseline_defense_config(fixture)
    hardened = hardened_defense_config(
        fixture,
        signing_key=KEY,
        key_id="key-tenant-lab",
        application_nonce="apply-tenant-lab-0001",
        prior=baseline,
    )
    receipt = defense_change_receipt(
        baseline,
        hardened,
        responsible_actor="bluefire-controller",
        applied_at="2026-11-04T15:00:00Z",
    )

    assert hardened.target_snapshot_id != baseline.target_snapshot_id
    assert hardened.service_generation != baseline.service_generation
    assert hardened.fixture_digest == baseline.fixture_digest == fixture.digest
    assert receipt["preimage_digest"] == receipt["rollback_material_digest"]
    assert receipt["target_snapshot_before"] == baseline.target_snapshot_id
    assert receipt["target_snapshot_after"] == hardened.target_snapshot_id
    assert KEY not in canonical_json_bytes(hardened.to_dict())

    reapplied = hardened_defense_config(
        fixture,
        signing_key=KEY,
        key_id="key-tenant-lab",
        application_nonce="apply-tenant-lab-0002",
        prior=baseline,
    )
    assert reapplied.target_snapshot_id != hardened.target_snapshot_id
    assert reapplied.service_generation != hardened.service_generation


def test_signed_session_is_bound_to_identity_snapshot_and_expiry() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    hardened = hardened_defense_config(
        fixture,
        signing_key=KEY,
        key_id="key-tenant-lab",
        application_nonce="apply-tenant-lab-0001",
        prior=baseline_defense_config(fixture),
    )
    token = mint_lab_session(
        fixture,
        hardened,
        signing_key=KEY,
        subject_id=fixture.legitimate_subject_id,
        tenant_id=fixture.protected_tenant_id,
        issued_at=NOW,
        lifetime_seconds=60,
    )

    payload = verify_lab_session(
        token, fixture, hardened, signing_key=KEY, now=NOW + timedelta(seconds=30)
    )
    assert payload["tenant_id"] == fixture.protected_tenant_id
    assert payload["target_snapshot_id"] == hardened.target_snapshot_id

    with pytest.raises(TenantRecordLabError, match="expired"):
        verify_lab_session(
            token, fixture, hardened, signing_key=KEY, now=NOW + timedelta(seconds=60)
        )
    with pytest.raises(TenantRecordLabError, match="signature"):
        verify_lab_session(
            token[:-1] + ("A" if token[-1] != "A" else "B"),
            fixture,
            hardened,
            signing_key=KEY,
            now=NOW,
        )


@pytest.mark.parametrize("seed", [b"short", "not-bytes", b"x" * 65])
def test_fixture_refuses_unbounded_or_nonbyte_seed(seed: object) -> None:
    with pytest.raises(TenantRecordLabError):
        generate_tenant_record_fixture(seed)  # type: ignore[arg-type]
