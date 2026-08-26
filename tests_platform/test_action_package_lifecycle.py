from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire.action_packages import (
    ACTION_PACKAGE_PAYLOAD_SCHEMA,
    ACTION_PROGRAM_ADAPTER,
    ACTION_PROGRAM_SCHEMA,
    MAX_ENVELOPE_BYTES,
    build_signed_action_package,
    verify_action_package,
)
from bluefire.product_store import (
    ActionPackageConflictError,
    ActionPackageIntegrityError,
    ProductStore,
    ProductStoreError,
)
from bluefire.util import canonical_json_bytes, content_hash

PUBLISHER_ID = "store-test.publisher"
KEY_ID = "release-2026"
PACKAGE_ID = "store-test.endpoint-pack"
BEHAVIOR_ID = "store-test.endpoint-profile.v1"
ACTION_ID = "store-test.endpoint-profile-action.v1"


def _source_provenance() -> dict[str, Any]:
    return {
        "source": "Reviewed neutral endpoint package fixture",
        "reference": "urn:bluefire:test:store-package-source:sha256:" + "b" * 64,
        "license": "MIT",
        "derived": False,
        "notes": "Declarative mapping to a compiled BlueFire operation.",
    }


def _manifest(version: str = "1.2.3", *, revision: str | None = None) -> dict[str, Any]:
    return {
        "package_id": PACKAGE_ID,
        "version": version,
        "compatibility": {
            "minimum_bluefire_version": "0.1.0",
            "maximum_bluefire_version_exclusive": "1.0.0",
        },
        "license": {
            "spdx_id": "MIT",
            "notice": "Copyright 2026 Store Test Publisher; MIT licensed.",
        },
        "provenance": {
            "publisher_id": PUBLISHER_ID,
            "source": "Reviewed store lifecycle fixture",
            "reference": f"urn:bluefire:test:store-package:{version}",
            "revision": revision or "a" * 40,
        },
        "platforms": ["linux", "macos", "windows"],
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "safety_tiers": ["safe"],
        "behavior_ids": [BEHAVIOR_ID],
        "action_ids": [ACTION_ID],
    }


def _payload() -> dict[str, Any]:
    behavior = {
        "schema_version": "bluefire.behavior.v1",
        "id": BEHAVIOR_ID,
        "title": "Observe bounded endpoint identity",
        "purpose": "Return non-sensitive operating-system and architecture facts.",
        "execution_state": "action",
        "safety_tier": "safe",
        "platforms": ["linux", "macos", "windows"],
        "techniques": ["T1082"],
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "inputs": [],
        "outputs": [
            {
                "name": "system",
                "type": "artifact.endpoint.system-profile.v1",
                "description": "Bounded system profile.",
            }
        ],
        "parameters": [],
        "action_ids": [ACTION_ID],
        "telemetry": ["endpoint.discovery.system_observed"],
        "detection_hints": ["Compare with independent host inventory."],
        "provenance": _source_provenance(),
        "limitations": ["Does not inspect accounts, networks, or file content."],
    }
    action = {
        "schema_version": "bluefire.action.v1",
        "id": ACTION_ID,
        "title": "Observe bounded endpoint identity",
        "purpose": "Use the reviewed compiled system-profile operation.",
        "safety_tier": "safe",
        "capabilities": ["endpoint.discovery", "system.discovery"],
        "platforms": ["linux", "macos", "windows"],
        "inputs": [],
        "outputs": [
            {
                "name": "system",
                "type": "artifact.endpoint.system-profile.v1",
                "description": "Bounded system profile.",
            }
        ],
        "parameters": [],
        "mutates": False,
        "cleanup_action_id": None,
        "provenance": _source_provenance(),
    }
    return {
        "schema_version": ACTION_PACKAGE_PAYLOAD_SCHEMA,
        "behaviors": [behavior],
        "actions": [
            {
                "definition": action,
                "program": {
                    "schema_version": ACTION_PROGRAM_SCHEMA,
                    "steps": [
                        {
                            "opcode": "endpoint.discovery.system.v1",
                            "adapter": ACTION_PROGRAM_ADAPTER,
                            "constants": {},
                        }
                    ],
                },
            }
        ],
    }


def _enroll(store: ProductStore, key: Ed25519PrivateKey) -> dict[str, Any]:
    return dict(
        store.trust_action_package_publisher(
            publisher_id=PUBLISHER_ID,
            key_id=KEY_ID,
            public_key=key.public_key(),
            provenance={"source": "local test enrollment", "purpose": "test-only"},
            trusted_by="test-operator",
        )
    )


def _verified(
    store: ProductStore,
    key: Ed25519PrivateKey,
    version: str = "1.2.3",
    *,
    revision: str | None = None,
) -> Any:
    envelope = build_signed_action_package(
        manifest=_manifest(version, revision=revision),
        payload=_payload(),
        key_id=KEY_ID,
        private_key=key,
    )
    return verify_action_package(
        envelope,
        trusted_signers=store.trusted_action_package_signers(),
        bluefire_version="0.1.0",
        platform="windows",
    )


def _verified_named_package(
    store: ProductStore,
    key: Ed25519PrivateKey,
    *,
    package_id: str,
    version: str,
    behavior_id: str,
    action_id: str,
) -> Any:
    manifest = _manifest(version)
    manifest["package_id"] = package_id
    manifest["provenance"]["reference"] = f"urn:bluefire:test:store-package:{package_id}:{version}"
    manifest["behavior_ids"] = [behavior_id]
    manifest["action_ids"] = [action_id]
    payload = _payload()
    payload["behaviors"][0]["id"] = behavior_id
    payload["behaviors"][0]["action_ids"] = [action_id]
    payload["actions"][0]["definition"]["id"] = action_id
    envelope = build_signed_action_package(
        manifest=manifest,
        payload=payload,
        key_id=KEY_ID,
        private_key=key,
    )
    return verify_action_package(
        envelope,
        trusted_signers=store.trusted_action_package_signers(),
        bluefire_version="0.1.0",
        platform="windows",
    )


def _runner_inventory(*, readiness: str = "ready") -> dict[str, Any]:
    return {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": "bluefire-runner",
        "runner_version": "0.1.0",
        "action_sdk_version": "1.0.0",
        "receipt_protocol": "bluefire.runner-receipt.v1",
        "platform": "windows",
        "actions": [
            {
                "action_id": "endpoint.discovery.system.v1",
                "action_version": "1.0.0",
                "readiness": readiness,
            }
        ],
    }


def _invalid_signature_result(verified: Any) -> Any:
    document = json.loads(verified.canonical_envelope_bytes)
    invalid_signature = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode("ascii")
    document["signature"]["value"] = invalid_signature
    envelope = canonical_json_bytes(document)
    return replace(
        verified,
        canonical_envelope_bytes=envelope,
        package_digest="sha256:" + hashlib.sha256(envelope).hexdigest(),
        signature_b64u=invalid_signature,
    )


def test_v5_plugin_metadata_is_preserved_and_active_status_is_demoted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-v5.sqlite3"
    document = {
        "schema_version": "bluefire.plugin.v1",
        "id": "legacy.plugin.v1",
        "enabled": True,
        "trust": "reviewed",
    }
    document_json = canonical_json_bytes(document).decode("utf-8")
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_migrations(version, applied_at)
        VALUES (5, '2026-08-25T00:00:00Z');
        CREATE TABLE resources (
            kind TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            document_json TEXT NOT NULL,
            digest TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (kind, resource_id)
        );
        """)
    connection.execute(
        """
        INSERT INTO resources VALUES ('plugin', ?, ?, ?, 'active', ?, ?)
        """,
        (
            document["id"],
            document_json,
            content_hash(document),
            "2026-08-25T00:00:01Z",
            "2026-08-25T00:00:02Z",
        ),
    )
    connection.commit()
    connection.close()

    store = ProductStore(path)

    assert store.schema_version == 7
    assert store.list_action_packages() == []
    assert store.get_resource("plugin", str(document["id"]))["status"] == "legacy_metadata"
    assert store.list_legacy_action_package_metadata() == [
        {
            "schema_version": "bluefire.legacy-action-package-metadata.v1",
            "resource_id": document["id"],
            "document": document,
            "digest": content_hash(document),
            "legacy_status": "active",
            "status": "legacy_metadata",
            "executable": False,
            "resource_created_at": "2026-08-25T00:00:01Z",
            "resource_updated_at": "2026-08-25T00:00:02Z",
            "captured_at": store.list_legacy_action_package_metadata()[0]["captured_at"],
        }
    ]
    assert ProductStore(path).list_legacy_action_package_metadata()[0]["legacy_status"] == "active"
    with pytest.raises(ProductStoreError, match="legacy plugin metadata cannot be activated"):
        store.save_resource(
            "plugin",
            str(document["id"]),
            document,
            status="active",
        )


def test_local_trust_install_idempotency_upgrade_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "product.sqlite3"
    store = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    trust = _enroll(store, key)
    duplicate_trust = _enroll(store, key)

    assert duplicate_trust == trust
    assert trust["trust_source"] == "local_operator"
    first_verified = _verified(store, key)
    first = store.install_action_package(first_verified, installed_by="test-operator")
    duplicate = store.install_action_package(first_verified, installed_by="another-operator")

    assert duplicate["installed_at"] == first["installed_at"]
    assert duplicate["installed_by"] == "test-operator"
    assert duplicate["canonical_envelope_bytes"] == first_verified.canonical_envelope_bytes
    assert duplicate["canonical_content_bytes"] == first_verified.canonical_content_bytes
    assert duplicate["trust"]["state"] == "trusted"
    assert duplicate["active"] is False
    assert duplicate["active_version"] is None
    assert len(store.list_action_package_lifecycle_events(PACKAGE_ID)) == 1

    second = store.install_action_package(
        _verified(store, key, "1.2.4"), installed_by="test-operator"
    )
    versions = store.list_action_package_versions(PACKAGE_ID)

    assert second["version"] == "1.2.4"
    assert store.list_action_packages()[0]["version"] == "1.2.4"
    assert "canonical_envelope_bytes" not in store.list_action_packages()[0]
    assert [item["status"] for item in versions] == ["superseded", "installed"]
    events = store.list_action_package_lifecycle_events(PACKAGE_ID)
    assert [event["event_type"] for event in events] == ["installed", "installed"]
    assert events[1]["details"]["previous_installed_version"] == "1.2.3"

    restarted = ProductStore(path).get_action_package(PACKAGE_ID)
    assert restarted["version"] == "1.2.4"
    assert restarted["canonical_envelope_bytes"] == second["canonical_envelope_bytes"]
    assert restarted["canonical_content_bytes"] == second["canonical_content_bytes"]


def test_trust_and_immutable_version_conflicts_are_rejected(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "conflicts.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)

    with pytest.raises(ActionPackageConflictError, match="immutable"):
        store.trust_action_package_publisher(
            publisher_id=PUBLISHER_ID,
            key_id=KEY_ID,
            public_key=key.public_key(),
            provenance={"source": "rewritten provenance"},
            trusted_by="test-operator",
        )
    with pytest.raises(ActionPackageConflictError, match="another publisher"):
        store.trust_action_package_publisher(
            publisher_id="different.publisher",
            key_id="different-key",
            public_key=key.public_key(),
            provenance={"source": "duplicate key binding"},
            trusted_by="test-operator",
        )

    original = _verified(store, key)
    store.install_action_package(original, installed_by="test-operator")
    conflicting = _verified(store, key, revision="b" * 40)
    with pytest.raises(ActionPackageConflictError, match="different immutable content"):
        store.install_action_package(conflicting, installed_by="test-operator")

    forged_digest = replace(original, package_digest="sha256:" + "0" * 64)
    with pytest.raises(ActionPackageIntegrityError, match="envelope digest"):
        store.install_action_package(forged_digest, installed_by="test-operator")
    oversized = b"{" + b"x" * MAX_ENVELOPE_BYTES
    oversized_result = replace(
        original,
        canonical_envelope_bytes=oversized,
        package_digest="sha256:" + hashlib.sha256(oversized).hexdigest(),
    )
    with pytest.raises(ActionPackageIntegrityError, match="1 to"):
        store.install_action_package(oversized_result, installed_by="test-operator")

    deeply_nested = b'{"value":' + b"[" * 10_000 + b"0" + b"]" * 10_000 + b"}"
    deeply_nested_result = replace(
        original,
        canonical_envelope_bytes=deeply_nested,
        package_digest="sha256:" + hashlib.sha256(deeply_nested).hexdigest(),
    )
    with pytest.raises(ActionPackageIntegrityError, match="canonical UTF-8 JSON"):
        store.install_action_package(deeply_nested_result, installed_by="test-operator")


def test_install_requires_independent_local_trust(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    trusted_store = ProductStore(tmp_path / "verifier.sqlite3")
    _enroll(trusted_store, key)
    verified = _verified(trusted_store, key)
    empty_store = ProductStore(tmp_path / "untrusted.sqlite3")

    with pytest.raises(ActionPackageIntegrityError, match="local publisher trust"):
        empty_store.install_action_package(verified, installed_by="test-operator")


def test_store_refuses_low_order_ed25519_trust_enrollment(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "low-order.sqlite3")

    with pytest.raises(ActionPackageIntegrityError, match="valid Ed25519 public key"):
        store.trust_action_package_publisher(
            publisher_id=PUBLISHER_ID,
            key_id=KEY_ID,
            public_key=b"\x01" + b"\x00" * 31,
            provenance={"source": "untrusted low-order fixture"},
            trusted_by="test-operator",
        )
    assert store.list_trusted_action_package_publishers() == []


def test_constructed_verifier_result_cannot_bypass_signature_verification(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "forged-result.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    forged = _invalid_signature_result(_verified(store, key))

    with pytest.raises(ActionPackageIntegrityError, match="cryptographic verification"):
        store.install_action_package(forged, installed_by="test-operator")
    assert store.list_action_packages() == []


def test_revoked_signer_is_denied_but_existing_package_remains_auditable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "revoked.sqlite3"
    store = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    verified = _verified(store, key)
    store.install_action_package(verified, installed_by="test-operator")

    revoked = store.revoke_action_package_publisher(
        PUBLISHER_ID,
        KEY_ID,
        revoked_by="security-operator",
        reason="test key compromise",
    )

    assert revoked["trust_state"] == "revoked"
    assert store.trusted_action_package_signers() == {}
    assert store.get_action_package(PACKAGE_ID)["trust"]["state"] == "revoked"
    with pytest.raises(ActionPackageIntegrityError, match="suspended or revoked"):
        store.install_action_package(verified, installed_by="test-operator")
    with pytest.raises(ActionPackageConflictError, match="cannot be re-trusted"):
        _enroll(store, key)
    assert [
        item["trust_state"]
        for item in store.list_action_package_publisher_trust_events(PUBLISHER_ID, KEY_ID)
    ] == ["trusted", "revoked"]
    assert ProductStore(path).get_action_package(PACKAGE_ID)["trust"]["state"] == "revoked"

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="invalid action-package trust transition"):
            connection.execute(
                """
                INSERT INTO action_package_publisher_trust_events(
                    event_id, publisher_id, key_id, trust_state,
                    actor, reason, created_at
                ) VALUES ('forged-retrust', ?, ?, 'trusted', 'attacker', 'rollback', 'later')
                """,
                (PUBLISHER_ID, KEY_ID),
            )


def test_invalid_surviving_retrust_event_fails_closed_across_inventory(tmp_path: Path) -> None:
    path = tmp_path / "invalid-retrust.sqlite3"
    store = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    store.install_action_package(_verified(store, key), installed_by="test-operator")
    store.revoke_action_package_publisher(
        PUBLISHER_ID,
        KEY_ID,
        revoked_by="security-operator",
        reason="test revocation",
    )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER action_package_trust_events_valid_transition")
        connection.execute(
            """
            INSERT INTO action_package_publisher_trust_events(
                event_id, publisher_id, key_id, trust_state,
                actor, reason, created_at
            ) VALUES ('invalid-retrust', ?, ?, 'trusted', 'attacker', 'rollback', 'later')
            """,
            (PUBLISHER_ID, KEY_ID),
        )

    with pytest.raises(ActionPackageIntegrityError, match="event chain is invalid"):
        store.get_trusted_action_package_publisher(PUBLISHER_ID, KEY_ID)
    with pytest.raises(ActionPackageIntegrityError, match="event chain is invalid"):
        store.trusted_action_package_signers()
    with pytest.raises(ActionPackageIntegrityError, match="event chain is invalid"):
        store.get_action_package(PACKAGE_ID)


def test_suspended_trust_can_only_progress_to_permanent_revocation(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "suspended.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)

    suspended = store.suspend_action_package_publisher(
        PUBLISHER_ID,
        KEY_ID,
        suspended_by="security-operator",
        reason="investigation",
    )
    revoked = store.revoke_action_package_publisher(
        PUBLISHER_ID,
        KEY_ID,
        revoked_by="security-operator",
        reason="confirmed compromise",
    )

    assert suspended["trust_state"] == "suspended"
    assert revoked["trust_state"] == "revoked"
    assert store.trusted_action_package_signers() == {}
    assert [
        item["trust_state"]
        for item in store.list_action_package_publisher_trust_events(PUBLISHER_ID, KEY_ID)
    ] == ["trusted", "suspended", "revoked"]


def test_persisted_package_tamper_is_detected_and_events_are_append_only(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "tamper.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    installed = store.install_action_package(_verified(store, key), installed_by="test-operator")

    with sqlite3.connect(store.path) as connection:
        # Bypass the application-level append-only trigger, then corrupt signed
        # bytes. Signature/digest verification remains independently useful.
        connection.execute("DROP TRIGGER action_package_versions_no_update")
        connection.execute(
            """
            UPDATE action_package_versions SET canonical_envelope_bytes = ?
            WHERE package_id = ? AND version = ?
            """,
            (b"{}", PACKAGE_ID, installed["version"]),
        )
    with pytest.raises(
        ActionPackageIntegrityError, match="cryptographic verification|digest check"
    ):
        store.get_action_package(PACKAGE_ID)

    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE action_package_lifecycle_events SET actor = 'tamper'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM action_package_lifecycle_events")
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint"):
            connection.execute(
                """
                INSERT INTO action_package_lifecycle_events(
                    event_id, package_id, version, event_type,
                    actor, details_json, created_at
                ) VALUES ('forged-activation', ?, ?, 'activated', 'attacker', '{}', 'later')
                """,
                (PACKAGE_ID, installed["version"]),
            )


def test_self_consistent_invalid_signature_row_mutation_is_detected(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "signature-tamper.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    verified = _verified(store, key)
    store.install_action_package(verified, installed_by="test-operator")
    forged = _invalid_signature_result(verified)

    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER action_package_versions_no_update")
        connection.execute(
            """
            UPDATE action_package_versions
            SET canonical_envelope_bytes = ?, package_digest = ?, signature_b64u = ?
            WHERE package_id = ? AND version = ?
            """,
            (
                forged.canonical_envelope_bytes,
                forged.package_digest,
                forged.signature_b64u,
                PACKAGE_ID,
                verified.manifest.version,
            ),
        )

    with pytest.raises(ActionPackageIntegrityError, match="cryptographic verification"):
        store.get_action_package(PACKAGE_ID)


def test_concurrent_exact_install_has_one_version_and_one_event(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.sqlite3"
    owner = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(owner, key)
    verified = _verified(owner, key)
    stores = [ProductStore(path) for _ in range(8)]
    barrier = threading.Barrier(len(stores))
    results: list[str] = []
    errors: list[BaseException] = []
    result_lock = threading.Lock()

    def install(store: ProductStore) -> None:
        try:
            barrier.wait(timeout=5)
            result = store.install_action_package(verified, installed_by="test-operator")
            with result_lock:
                results.append(str(result["package_digest"]))
        except BaseException as exc:  # pragma: no cover - asserted below
            with result_lock:
                errors.append(exc)

    threads = [threading.Thread(target=install, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    assert len(results) == len(stores)
    assert set(results) == {verified.package_digest}
    assert len(owner.list_action_package_versions(PACKAGE_ID)) == 1
    assert len(owner.list_action_package_lifecycle_events(PACKAGE_ID)) == 1


def test_concurrent_versions_select_highest_semver_head_deterministically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-upgrade.sqlite3"
    owner = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(owner, key)
    packages = [_verified(owner, key, "1.2.3"), _verified(owner, key, "1.2.4")]
    stores = [ProductStore(path), ProductStore(path)]
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def install(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            stores[index].install_action_package(
                packages[index], installed_by=f"test-operator-{index}"
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=install, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    assert owner.get_action_package(PACKAGE_ID)["version"] == "1.2.4"
    versions = {item["version"]: item for item in owner.list_action_package_versions(PACKAGE_ID)}
    assert versions["1.2.3"]["status"] == "superseded"
    assert versions["1.2.4"]["status"] == "installed"
    assert len(owner.list_action_package_lifecycle_events(PACKAGE_ID)) == 2


@pytest.mark.parametrize(
    ("first_version", "second_version"),
    [("1.2.3+alpha", "1.2.3+beta"), ("1.2.3+beta", "1.2.3+alpha")],
)
def test_equal_precedence_build_variants_are_rejected_in_both_orders(
    tmp_path: Path,
    first_version: str,
    second_version: str,
) -> None:
    store = ProductStore(tmp_path / f"build-{first_version[-1]}.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    store.install_action_package(_verified(store, key, first_version), installed_by="test-operator")

    with pytest.raises(ActionPackageConflictError, match="share SemVer precedence"):
        store.install_action_package(
            _verified(store, key, second_version), installed_by="test-operator"
        )
    assert [item["version"] for item in store.list_action_package_versions(PACKAGE_ID)] == [
        first_version
    ]


def test_concurrent_equal_precedence_build_variants_have_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "concurrent-build.sqlite3"
    owner = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(owner, key)
    packages = [
        _verified(owner, key, "1.2.3+alpha"),
        _verified(owner, key, "1.2.3+beta"),
    ]
    stores = [ProductStore(path), ProductStore(path)]
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def install(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            stores[index].install_action_package(
                packages[index], installed_by=f"test-operator-{index}"
            )
            outcome = "installed"
        except ActionPackageConflictError:
            outcome = "conflict"
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=install, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert sorted(outcomes) == ["conflict", "installed"]
    assert len(owner.list_action_package_versions(PACKAGE_ID)) == 1


def test_mutable_installed_head_cannot_roll_inventory_back(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "head-rollback.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    store.install_action_package(_verified(store, key, "1.2.3"), installed_by="operator")
    store.install_action_package(_verified(store, key, "1.2.4"), installed_by="operator")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE action_package_heads SET installed_version = '1.2.3' WHERE package_id = ?",
            (PACKAGE_ID,),
        )

    assert store.get_action_package(PACKAGE_ID)["version"] == "1.2.4"
    assert store.list_action_packages()[0]["version"] == "1.2.4"


def test_target_incompatible_package_can_be_staged_for_later_activation(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "staged.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    manifest = _manifest()
    manifest["compatibility"] = {
        "minimum_bluefire_version": "2.0.0",
        "maximum_bluefire_version_exclusive": "3.0.0",
    }
    manifest["platforms"] = ["linux"]
    payload = _payload()
    payload["behaviors"][0]["platforms"] = ["linux"]
    payload["actions"][0]["definition"]["platforms"] = ["linux"]
    envelope = build_signed_action_package(
        manifest=manifest,
        payload=payload,
        key_id=KEY_ID,
        private_key=key,
    )
    verified = verify_action_package(
        envelope,
        trusted_signers=store.trusted_action_package_signers(),
        bluefire_version=None,
        platform=None,
    )

    staged = store.install_action_package(verified, installed_by="test-operator")

    assert staged["status"] == "installed"
    assert staged["verification"]["compatibility"] == "deferred_to_activation"
    assert staged["manifest"]["platforms"] == ["linux"]


def test_activation_upgrade_removal_and_exact_historical_recovery(tmp_path: Path) -> None:
    path = tmp_path / "activation-history.sqlite3"
    store = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    first_install = store.install_action_package(
        _verified(store, key, "1.2.3"), installed_by="operator"
    )
    first_preflight = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.3",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "1" * 64,
    )

    first_active = store.activate_action_package(
        first_preflight, activated_by="operator", reason="publish reviewed package"
    )
    first_snapshot = store.get_action_package_catalog_snapshot()

    assert first_active["active"] is True
    assert first_active["active_generation"] == 1
    assert first_snapshot["generation"] == 1
    assert first_snapshot["packages"][0]["verified_activation"] == first_preflight
    assert (
        first_snapshot["packages"][0]["canonical_envelope_bytes"]
        == first_install["canonical_envelope_bytes"]
    )
    retry_preflight = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.3",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "1" * 64,
    )
    retry = store.activate_action_package(
        retry_preflight, activated_by="operator", reason="idempotent activation retry"
    )
    assert retry["active_generation"] == 1
    assert len(store.list_action_package_activation_events()) == 1

    store.install_action_package(_verified(store, key, "1.2.4"), installed_by="operator")
    assert store.get_action_package(PACKAGE_ID, "1.2.3")["active"] is True
    assert store.get_action_package(PACKAGE_ID)["active_version"] == "1.2.3"
    second_preflight = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.4",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "2" * 64,
    )
    store.activate_action_package(
        second_preflight, activated_by="operator", reason="upgrade reviewed package"
    )
    second_snapshot = store.get_action_package_catalog_snapshot()
    assert second_snapshot["generation"] == 2
    assert second_snapshot["packages"][0]["version"] == "1.2.4"

    removed = store.remove_action_package(
        PACKAGE_ID,
        "1.2.4",
        second_snapshot["packages"][0]["package_digest"],
        expected_catalog_generation=second_snapshot["generation"],
        expected_catalog_digest=second_snapshot["catalog_digest"],
        removed_by="operator",
        reason="retire reviewed package",
    )
    current = store.get_action_package_catalog_snapshot()
    recovered_first = store.get_action_package_catalog_snapshot(1)
    recovered_second = ProductStore(path).get_action_package_catalog_snapshot(2)

    assert removed["status"] == "removed"
    assert current["generation"] == 3
    assert current["packages"] == []
    assert recovered_first["packages"][0]["version"] == "1.2.3"
    assert (
        recovered_first["packages"][0]["canonical_envelope_bytes"]
        == first_install["canonical_envelope_bytes"]
    )
    assert recovered_second["packages"][0]["version"] == "1.2.4"
    assert recovered_second["packages"][0]["verified_activation"] == second_preflight
    with pytest.raises(ActionPackageConflictError, match="approved generation"):
        store.assert_action_package_catalog_snapshot(
            second_snapshot["generation"], second_snapshot["catalog_digest"]
        )
    with pytest.raises(ProductStoreError, match="generation was not found"):
        store.get_action_package_catalog_snapshot(99)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM action_package_versions WHERE package_id = ?", (PACKAGE_ID,)
        ).fetchone() == (2,)


def test_activation_preflight_is_stale_after_installed_head_changes(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "stale-head.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    store.install_action_package(_verified(store, key, "1.2.3"), installed_by="operator")
    preflight = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.3",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "3" * 64,
    )
    store.install_action_package(_verified(store, key, "1.2.4"), installed_by="operator")

    with pytest.raises(ActionPackageConflictError, match="installed head changed"):
        store.activate_action_package(
            preflight, activated_by="operator", reason="stale activation must fail"
        )
    assert store.list_action_package_activation_events() == []
    assert store.get_action_package_catalog_snapshot()["generation"] == 0


@pytest.mark.parametrize("transition", ["suspend", "revoke"])
def test_trust_loss_atomically_deactivates_current_packages(
    tmp_path: Path, transition: str
) -> None:
    path = tmp_path / f"trust-{transition}.sqlite3"
    store = ProductStore(path)
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    store.install_action_package(_verified(store, key), installed_by="operator")
    preflight = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.3",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "4" * 64,
    )
    store.activate_action_package(
        preflight, activated_by="operator", reason="activate before trust transition"
    )

    if transition == "suspend":
        store.suspend_action_package_publisher(
            PUBLISHER_ID, KEY_ID, suspended_by="operator", reason="investigate signer"
        )
    else:
        store.revoke_action_package_publisher(
            PUBLISHER_ID, KEY_ID, revoked_by="operator", reason="retire signer"
        )

    restarted = ProductStore(path)
    snapshot = restarted.get_action_package_catalog_snapshot()
    events = restarted.list_action_package_activation_events()
    assert snapshot["generation"] == 2
    assert snapshot["packages"] == []
    assert (
        events[-1]["cause"]
        == {
            "suspend": "trust_suspended",
            "revoke": "trust_revoked",
        }[transition]
    )
    assert restarted.get_action_package(PACKAGE_ID)["active"] is False


def test_activation_event_chain_and_projection_tampering_fail_closed(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "activation-tamper.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    store.install_action_package(_verified(store, key), installed_by="operator")
    preflight = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.3",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "5" * 64,
    )
    store.activate_action_package(
        preflight, activated_by="operator", reason="activate before tamper test"
    )
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM action_package_activation_events")
        connection.execute(
            "UPDATE action_package_heads SET active_version = NULL, active_generation = NULL"
        )
        connection.commit()

    with pytest.raises(ActionPackageIntegrityError, match="projection"):
        store.get_action_package_catalog_snapshot()
    # Historical recovery is derived from immutable events and deliberately
    # ignores today's mutable projection.
    historical = store.get_action_package_catalog_snapshot(1)
    assert historical["packages"][0]["verified_activation"] == preflight


def test_future_schema_is_refused_without_mutating_database(tmp_path: Path) -> None:
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
            INSERT INTO schema_migrations VALUES (999, 'future');
            CREATE TABLE sentinel (value TEXT NOT NULL);
            INSERT INTO sentinel VALUES ('unchanged');
            """)
    with sqlite3.connect(path) as connection:
        before_schema = connection.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        before_data = connection.execute("SELECT * FROM sentinel").fetchall()

    with pytest.raises(ProductStoreError, match="newer than this application"):
        ProductStore(path)

    with sqlite3.connect(path) as connection:
        after_schema = connection.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        after_data = connection.execute("SELECT * FROM sentinel").fetchall()
    assert after_schema == before_schema
    assert after_data == before_data


def test_expected_digest_shape_and_schema_constraints_are_enforced(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "shape.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    verified = _verified(store, key)

    malformed = replace(verified, package_digest=verified.package_digest.upper())
    with pytest.raises(ActionPackageIntegrityError, match="exact lowercase"):
        store.install_action_package(malformed, installed_by="test-operator")

    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (7,)
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert {
        "trusted_action_package_publishers",
        "action_package_versions",
        "action_package_heads",
        "action_package_lifecycle_events",
        "action_package_activation_events",
        "action_package_tombstones",
        "legacy_action_package_metadata",
    }.issubset(tables)


def test_install_reserves_ids_from_every_immutable_version_not_only_current_head(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "permanent-reservations.sqlite3")
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    retired_behavior = "reservation.retired-behavior.v1"
    retired_action = "reservation.retired-action.v1"

    store.install_action_package(
        _verified_named_package(
            store,
            key,
            package_id="reservation.owner-a",
            version="1.0.0",
            behavior_id=retired_behavior,
            action_id=retired_action,
        ),
        installed_by="reservation-test",
    )
    store.install_action_package(
        _verified_named_package(
            store,
            key,
            package_id="reservation.owner-a",
            version="2.0.0",
            behavior_id="reservation.current-behavior.v1",
            action_id="reservation.current-action.v1",
        ),
        installed_by="reservation-test",
    )

    with pytest.raises(ActionPackageIntegrityError, match="independent local"):
        store.install_action_package(
            _verified_named_package(
                store,
                key,
                package_id="reservation.owner-b",
                version="1.0.0",
                behavior_id=retired_behavior,
                action_id=retired_action,
            ),
            installed_by="reservation-test",
        )


def test_two_product_stores_cannot_race_colliding_package_id_reservations(
    tmp_path: Path,
) -> None:
    database = tmp_path / "reservation-race.sqlite3"
    first = ProductStore(database)
    second = ProductStore(database)
    key = Ed25519PrivateKey.generate()
    _enroll(first, key)
    packages = (
        _verified_named_package(
            first,
            key,
            package_id="reservation.racer-a",
            version="1.0.0",
            behavior_id="reservation.raced-behavior.v1",
            action_id="reservation.raced-action.v1",
        ),
        _verified_named_package(
            first,
            key,
            package_id="reservation.racer-b",
            version="1.0.0",
            behavior_id="reservation.raced-behavior.v1",
            action_id="reservation.raced-action.v1",
        ),
    )
    barrier = threading.Barrier(3)
    outcomes: list[object] = []
    outcomes_lock = threading.Lock()

    def install(store: ProductStore, package: Any) -> None:
        barrier.wait()
        try:
            outcome: object = store.install_action_package(
                package,
                installed_by="reservation-race-test",
            )
        except BaseException as exc:
            outcome = exc
        with outcomes_lock:
            outcomes.append(outcome)

    threads = (
        threading.Thread(target=install, args=(first, packages[0]), daemon=True),
        threading.Thread(target=install, args=(second, packages[1]), daemon=True),
    )
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert len([item for item in outcomes if isinstance(item, Mapping)]) == 1
    failures = [item for item in outcomes if isinstance(item, BaseException)]
    assert len(failures) == 1
    assert isinstance(failures[0], ActionPackageIntegrityError)
    assert len(first.list_action_packages()) == 1
