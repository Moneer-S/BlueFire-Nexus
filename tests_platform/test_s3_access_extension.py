"""Real local trust/filesystem tests with synthetic protected material, never AWS."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import s3_access_runtime
from bluefire import s3_access_setup as setup
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.runner_trust import (
    RunnerTrustError,
    create_local_enrollment,
    load_local_enrollment,
    revoke_local_enrollment,
)
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_extension_store import S3ExtensionStore
from bluefire.s3_access_host_config import temporary_material
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.secret_store import InMemorySecretProvider
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_host_config import configured
from tests_platform.test_s3_access_wire import NOW, credential_row, request_row


@pytest.fixture
def local(tmp_path, monkeypatch):
    parent = tmp_path / "managed"
    parent.mkdir(mode=0o700)
    with _PinnedPrivateDirectory(parent):
        pass
    configuration = configured()
    provider = InMemorySecretProvider()
    enrollment = create_local_enrollment(
        parent / "enrollment",
        runner_id=configuration["runner_id"],
        client_id="s3-extension-test",
        allowed_profile_ids=[configuration["environments"][0]["profile"]["profile_id"]],
        secret_provider=provider,
    )
    # Only runtime installation inspection is synthetic; real trust reload stays intact.
    monkeypatch.setattr(
        s3_access_runtime,
        "validate_runtime",
        lambda root, expected: SimpleNamespace(
            worker_generation=configuration["environments"][0]["worker_generation"]
        ),
    )
    return enrollment, configuration, provider


def publish(local):
    enrollment, configuration, _ = local
    review = setup.review_configuration(enrollment, configuration, clock=lambda: NOW)
    return setup.apply_configuration(enrollment, configuration, review, clock=lambda: NOW)


def imported(local):
    committed = publish(local)
    enrollment, _, _ = local
    return setup.import_temporary_material(
        enrollment,
        "test-environment",
        canonical_json_bytes(credential_row()),
        expected_revision=committed["revision_digest"],
        clock=lambda: NOW,
    )


def test_real_enrollment_reloads_with_separate_extension_and_opaque_reference(local):
    enrollment, configuration, provider = local
    trust_names = {path.name for path in enrollment.root.iterdir()}
    committed = imported(local)
    loaded = load_local_enrollment(enrollment.root, secret_provider=provider)
    assert loaded.metadata == enrollment.metadata
    assert {path.name for path in enrollment.root.iterdir()} == trust_names
    assert setup.read_configuration(loaded) == configuration
    state = setup.inspect_extension(loaded, clock=lambda: NOW)
    assert state["revision_digest"] == committed["revision_digest"]
    assert state["references"] == [
        {
            "environment_id": "test-environment",
            "state": "current",
            "expires_at": credential_row()["expires_at"],
        }
    ]
    store = S3ExtensionStore(loaded)
    for path in store.root.iterdir():
        retained = path.read_bytes()
        assert credential_row()["access_key"].encode() not in retained
        assert credential_row()["secret_key"].encode() not in retained
        assert credential_row()["token"].encode() not in retained
    request = S3WorkerRequest.from_mapping(request_row())
    assert (
        json.loads(
            temporary_material(loaded, configuration["environments"][0], request, lambda: NOW)
        )
        == credential_row()
    )


def test_status_and_config_never_decrypt_aws_material(local, monkeypatch):
    enrollment, configuration, provider = local
    imported(local)
    original = provider.unprotect
    seen = []

    def unprotect(purpose, opaque):
        seen.append(purpose)
        assert not purpose.startswith("bluefire.s3-temporary.v1:")
        return original(purpose, opaque)

    monkeypatch.setattr(provider, "unprotect", unprotect)
    assert setup.read_configuration(enrollment) == configuration
    assert (
        setup.inspect_extension(enrollment, clock=lambda: NOW)["references"][0]["state"]
        == "current"
    )
    assert seen  # Normal managed TLS/HMAC authentication is still exercised.


def test_existing_trust_root_still_rejects_extension_files(local):
    enrollment, _, provider = local
    with _PinnedPrivateDirectory(enrollment.root) as directory:
        directory.create("s3-access.json", b"{}", maximum=16)
    with pytest.raises(RunnerTrustError):
        load_local_enrollment(enrollment.root, secret_provider=provider)


def test_same_configuration_reapply_is_inert_and_complete_authority_is_compared(local):
    enrollment, configuration, _ = local
    reviewed = setup.review_configuration(enrollment, configuration, clock=lambda: NOW)
    first = setup.apply_configuration(enrollment, configuration, reviewed, clock=lambda: NOW)
    again = setup.apply_configuration(
        enrollment, deepcopy(configuration), reviewed, clock=lambda: NOW
    )
    assert again == {"status": "already_configured", "revision_digest": first["revision_digest"]}
    assert S3ExtensionStore(enrollment).read()["sequence"] == 1
    for key in ("ledger_root", "runtime_root", "exclusive_writer_digest"):
        changed = deepcopy(configuration)
        changed["environments"][0][key] = "/other" if key.endswith("root") else "sha256:" + "f" * 64
        with pytest.raises(S3AccessError, match="history review"):
            setup.review_configuration(enrollment, changed, clock=lambda: NOW)


def test_complete_profile_binding_is_retained_and_cannot_be_silently_rebound(local):
    enrollment, configuration, provider = local
    configuration["schema_version"] = "bluefire.s3-host-environments.v3"
    configuration["environments"][0]["managed_profile_digest"] = "sha256:" + "a" * 64
    committed = publish(local)
    loaded = load_local_enrollment(enrollment.root, secret_provider=provider)
    retained = setup.read_configuration(loaded)
    assert retained == configuration
    changed = deepcopy(configuration)
    changed["environments"][0]["managed_profile_digest"] = "sha256:" + "b" * 64
    with pytest.raises(S3AccessError, match="history review"):
        setup.review_configuration(loaded, changed, clock=lambda: NOW)
    assert setup.read_configuration(loaded) == retained
    assert (
        setup.inspect_extension(loaded, clock=lambda: NOW)["revision_digest"]
        == committed["revision_digest"]
    )


@pytest.mark.parametrize("kind", ["expired", "changed", "stale_revision"])
def test_configuration_review_refuses_changed_binding(local, kind):
    enrollment, configuration, _ = local
    review = setup.review_configuration(enrollment, configuration, clock=lambda: NOW)
    offset = 0

    def clock():
        return NOW + timedelta(seconds=offset)

    if kind == "expired":
        offset = 121
    elif kind == "changed":
        review["binding"]["client_id"] = "different"
    else:
        review["expected_revision"] = "sha256:" + "e" * 64
        review["review_digest"] = content_hash(
            {key: value for key, value in review.items() if key != "review_digest"}
        )
    with pytest.raises(S3AccessError):
        setup.apply_configuration(enrollment, configuration, review, clock=clock)


def test_secret_refresh_is_exact_scope_bound_non_refunding_append(local):
    enrollment, configuration, _ = local
    original = publish(local)
    first = setup.import_temporary_material(
        enrollment,
        "test-environment",
        canonical_json_bytes(credential_row()),
        expected_revision=original["revision_digest"],
        clock=lambda: NOW,
    )
    with pytest.raises(S3AccessError, match="revision changed"):
        setup.import_temporary_material(
            enrollment,
            "test-environment",
            canonical_json_bytes(credential_row()),
            expected_revision=original["revision_digest"],
            clock=lambda: NOW,
        )
    second = setup.import_temporary_material(
        enrollment,
        "test-environment",
        canonical_json_bytes(credential_row()),
        expected_revision=first["revision_digest"],
        clock=lambda: NOW,
    )
    current = S3ExtensionStore(enrollment).read()
    assert current["sequence"] == 3 and current["previous_digest"] == first["revision_digest"]
    assert current["configuration"] == configuration
    assert second["revision_digest"] == content_hash(current)


def test_secret_import_uses_one_instant_with_advancing_clock(local):
    enrollment, _, _ = local
    configured = publish(local)
    calls = 0

    def clock():
        nonlocal calls
        instant = NOW + timedelta(microseconds=calls)
        calls += 1
        return instant

    imported = setup.import_temporary_material(
        enrollment,
        "test-environment",
        canonical_json_bytes(credential_row()),
        expected_revision=configured["revision_digest"],
        clock=clock,
    )
    assert imported["status"] == "reference_imported"
    assert calls == 1
    assert S3ExtensionStore(enrollment).read()["sequence"] == 2


@pytest.mark.parametrize("kind", ["missing_environment", "expired", "too_long", "not_bytes"])
def test_secret_import_refuses_invalid_inputs_before_publication(local, kind):
    enrollment, _, _ = local
    first = publish(local)
    raw = credential_row()
    environment_id = "test-environment"
    if kind == "missing_environment":
        environment_id = "foreign"
    elif kind == "expired":
        raw["expires_at"] = NOW.isoformat()
    elif kind == "too_long":
        raw["expires_at"] = (NOW + timedelta(seconds=901)).isoformat()
    payload = canonical_json_bytes(raw) if kind != "not_bytes" else raw
    with pytest.raises(S3AccessError):
        setup.import_temporary_material(
            enrollment,
            environment_id,
            payload,
            expected_revision=first["revision_digest"],
            clock=lambda: NOW,
        )
    assert S3ExtensionStore(enrollment).read()["sequence"] == 1


def test_expired_reference_is_visible_but_never_usable(local):
    enrollment, configuration, _ = local
    imported(local)

    def later():
        return NOW + timedelta(seconds=901)

    assert setup.inspect_extension(enrollment, clock=later)["references"][0]["state"] == "expired"
    with pytest.raises(S3AccessError):
        temporary_material(
            enrollment,
            configuration["environments"][0],
            S3WorkerRequest.from_mapping(request_row()),
            later,
        )


def test_failed_publication_retains_exact_pending_without_replay(local, monkeypatch):
    enrollment, configuration, _ = local
    first = publish(local)
    original = _PinnedPrivateDirectory.promote

    def fail(self, source, destination, **kwargs):
        if source == ".pending.json":
            raise OSError("injected publication failure")
        return original(self, source, destination, **kwargs)

    monkeypatch.setattr(_PinnedPrivateDirectory, "promote", fail)
    with pytest.raises(OSError):
        setup.import_temporary_material(
            enrollment,
            "test-environment",
            canonical_json_bytes(credential_row()),
            expected_revision=first["revision_digest"],
            clock=lambda: NOW,
        )
    store = S3ExtensionStore(enrollment)
    pending = json.loads((store.root / ".pending.json").read_bytes())
    assert (
        pending["operation"] == "credentials"
        and pending["previous_digest"] == first["revision_digest"]
    )
    assert pending["configuration"] == configuration
    assert store.publication_state(content_hash(pending)) == {
        "status": "incomplete",
        "matches": True,
    }
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    with pytest.raises(S3AccessError, match="incomplete"):
        setup.inspect_extension(enrollment, clock=lambda: NOW)
    assert {path.name: path.read_bytes() for path in store.root.iterdir()} == before


def test_committed_lost_ack_is_read_only_exact_reconciliation(local):
    enrollment, _, _ = local
    result = imported(local)
    store = S3ExtensionStore(enrollment)
    assert store.publication_state(result["revision_digest"]) == {
        "status": "committed",
        "matches": True,
    }
    assert store.publication_state("sha256:" + "0" * 64) == {
        "status": "not_found",
        "matches": False,
    }
    assert store.read()["sequence"] == 2


def test_pending_copy_of_committed_record_remains_incomplete_without_replay(local):
    enrollment, _, _ = local
    result = imported(local)
    store = S3ExtensionStore(enrollment)
    current = store.read()
    with _PinnedPrivateDirectory(store.root) as directory:
        directory.create(".pending.json", canonical_json_bytes(current), maximum=1024 * 1024)
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    assert store.publication_state(result["revision_digest"]) == {
        "status": "incomplete",
        "matches": True,
    }
    with pytest.raises(S3AccessError, match="incomplete"):
        store.read()
    assert {path.name: path.read_bytes() for path in store.root.iterdir()} == before


@pytest.mark.parametrize("change", ["revoke", "replace"])
@pytest.mark.parametrize("operation", ["read", "append", "reconcile", "inspect"])
def test_retained_store_refuses_changed_real_enrollment(local, change, operation):
    enrollment, configuration, provider = local
    result = publish(local)
    store = S3ExtensionStore(enrollment)
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    if change == "revoke":
        revoke_local_enrollment(enrollment.root, secret_provider=provider)
    else:
        enrollment.root.rename(enrollment.root.with_name("previous-enrollment"))
        replacement = create_local_enrollment(
            enrollment.root,
            runner_id=enrollment.runner_id,
            client_id=enrollment.client_id,
            allowed_profile_ids=enrollment.allowed_profile_ids,
            secret_provider=provider,
        )
        assert replacement.metadata != enrollment.metadata
    with pytest.raises((S3AccessError, RunnerTrustError)):
        if operation == "read":
            store.read()
        elif operation == "append":
            store.append(
                configuration,
                {},
                operation="configure",
                expected_revision=result["revision_digest"],
            )
        else:
            store.publication_state(result["revision_digest"] if operation == "reconcile" else None)
    assert {path.name: path.read_bytes() for path in store.root.iterdir()} == before


@pytest.mark.parametrize("kind", ["unknown", "gap", "hardlink"])
def test_extension_refuses_unknown_missing_or_linked_records(local, kind):
    enrollment, _, _ = local
    publish(local)
    root = S3ExtensionStore(enrollment).root
    if kind == "unknown":
        with _PinnedPrivateDirectory(root) as directory:
            directory.create("unknown.json", b"{}", maximum=16)
    elif kind == "gap":
        (root / "revision-0001.json").rename(root / "revision-0002.json")
    else:
        os.link(root / "revision-0001.json", root / "alias.json")
    with pytest.raises((S3AccessError, OSError)):
        S3ExtensionStore(enrollment).read()


def test_foreign_enrollment_cannot_adopt_extension(local):
    enrollment, configuration, provider = local
    publish(local)
    parent = enrollment.root.parent / "other-managed"
    parent.mkdir(mode=0o700)
    with _PinnedPrivateDirectory(parent):
        pass
    foreign = create_local_enrollment(
        parent / "enrollment",
        runner_id=enrollment.runner_id,
        client_id="other-client",
        allowed_profile_ids=enrollment.allowed_profile_ids,
        secret_provider=provider,
    )
    source = S3ExtensionStore(enrollment).root / "revision-0001.json"
    other = parent / "s3-access"
    other.mkdir(mode=0o700)
    with _PinnedPrivateDirectory(other) as directory:
        directory.create(source.name, source.read_bytes(), maximum=1024 * 1024)
    with pytest.raises(S3AccessError, match="binding changed"):
        S3ExtensionStore(foreign).read()


def test_bounded_revision_exhaustion_never_evicts_records(local):
    enrollment, _, _ = local
    current = publish(local)
    for _ in range(31):
        current = setup.import_temporary_material(
            enrollment,
            "test-environment",
            canonical_json_bytes(credential_row()),
            expected_revision=current["revision_digest"],
            clock=lambda: NOW,
        )
    assert (
        setup.inspect_extension(enrollment, clock=lambda: NOW)["status"]
        == "revision_allowance_exhausted"
    )
    store = S3ExtensionStore(enrollment)
    before = {path.name for path in store.root.iterdir()}
    with pytest.raises(S3AccessError, match="allowance is exhausted"):
        setup.import_temporary_material(
            enrollment,
            "test-environment",
            canonical_json_bytes(credential_row()),
            expected_revision=current["revision_digest"],
            clock=lambda: NOW,
        )
    assert len(before) == 32 and {path.name for path in store.root.iterdir()} == before
