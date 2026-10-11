"""Finish exact local records after lost publication responses, without AWS calls."""

from __future__ import annotations

import json
import os
from datetime import timedelta

import pytest

from bluefire import s3_access_setup as setup
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.runner_trust import RunnerTrustError, revoke_local_enrollment
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_extension_store import S3ExtensionStore
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_extension import local as local
from tests_platform.test_s3_access_extension import publish
from tests_platform.test_s3_access_wire import NOW, credential_row


def interrupted(local, monkeypatch, operation="credentials", after=False):
    enrollment, configuration, _ = local
    first = publish(local) if operation == "credentials" else None
    original = _PinnedPrivateDirectory.promote

    def fail(directory, source, destination, **options):
        assert options["atomic_no_replace"] is True
        if source == ".pending.json":
            if after:
                original(directory, source, destination, **options)
            raise OSError("injected lost publication response")
        return original(directory, source, destination, **options)

    with monkeypatch.context() as patch:
        patch.setattr(_PinnedPrivateDirectory, "promote", fail)
        with pytest.raises(OSError, match="injected"):
            if first:
                setup.import_temporary_material(
                    enrollment,
                    "test-environment",
                    canonical_json_bytes(credential_row()),
                    expected_revision=first["revision_digest"],
                    clock=lambda: NOW,
                )
            else:
                review = setup.review_configuration(enrollment, configuration, clock=lambda: NOW)
                setup.apply_configuration(enrollment, configuration, review, clock=lambda: NOW)
    return S3ExtensionStore(enrollment)


@pytest.mark.parametrize("operation", ["configure", "credentials"])
@pytest.mark.parametrize("after", [False, True])
def test_exact_completion_is_idempotent_and_never_decrypts_or_refreshes(
    local, monkeypatch, operation, after
):
    store = interrupted(local, monkeypatch, operation, after)
    state = store.publication_state()
    original_unprotect = local[2].unprotect

    def unprotect(purpose, protected):
        assert not purpose.startswith("bluefire.s3-temporary.v1:")
        return original_unprotect(purpose, protected)

    monkeypatch.setattr(local[2], "unprotect", unprotect)
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    payload = before[".pending.json"] if not after else before[max(before)]
    pending = json.loads(payload)
    result = store.complete_publication(state["record_digest"])
    assert result == {
        "status": "already_committed" if after else "committed",
        "revision_digest": content_hash(pending),
    }
    current = store.read()
    assert current == pending
    assert current["sequence"] == (1 if operation == "configure" else 2)
    assert (store.root / store._filename(current["sequence"])).read_bytes() == payload
    assert not (store.root / ".pending.json").exists()
    assert store.complete_publication(result["revision_digest"])["status"] == "already_committed"
    if operation == "credentials":
        late = setup.inspect_extension(local[0], clock=lambda: NOW + timedelta(seconds=901))
        assert late["references"][0]["state"] == "expired"
        assert late["references"][0]["expires_at"] == credential_row()["expires_at"]


@pytest.mark.parametrize("kind", ["digest", "authentication", "unknown", "hardlink", "revoke"])
def test_changed_or_unsafe_pending_state_is_preserved_without_completion(local, monkeypatch, kind):
    store = interrupted(local, monkeypatch)
    expected = store.publication_state()["record_digest"]
    if kind == "digest":
        expected = "sha256:" + "0" * 64
    elif kind == "authentication":
        path = store.root / ".pending.json"
        row = json.loads(path.read_bytes())
        row["authentication"] = "sha256:" + "0" * 64
        path.write_bytes(canonical_json_bytes(row))
        expected = content_hash(row)
    elif kind == "unknown":
        with _PinnedPrivateDirectory(store.root) as directory:
            directory.create("extra.json", b"{}", maximum=2)
    elif kind == "hardlink":
        os.link(store.root / ".pending.json", store.root.parent / "untrusted-alias")
    else:
        revoke_local_enrollment(local[0].root, secret_provider=local[2])
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    with pytest.raises((S3AccessError, RunnerTrustError, OSError)):
        store.complete_publication(expected)
    assert {path.name: path.read_bytes() for path in store.root.iterdir()} == before


def test_failure_during_completion_keeps_same_claim_for_retry(local, monkeypatch):
    store = interrupted(local, monkeypatch)
    expected = store.publication_state()["record_digest"]
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    with monkeypatch.context() as patch:
        patch.setattr(
            _PinnedPrivateDirectory,
            "promote",
            lambda *_a, **_k: (_ for _ in ()).throw(OSError("injected retry interruption")),
        )
        with pytest.raises(OSError, match="injected"):
            store.complete_publication(expected)
    assert {path.name: path.read_bytes() for path in store.root.iterdir()} == before
    assert store.complete_publication(expected)["status"] == "committed"
    assert store.read()["sequence"] == 2


def test_exact_pending_copy_is_removed_only_after_committed_history_validation(local, monkeypatch):
    store = interrupted(local, monkeypatch, after=True)
    current = store.read()
    payload = canonical_json_bytes(current)
    with _PinnedPrivateDirectory(store.root) as directory:
        directory.create(".pending.json", payload, maximum=len(payload), atomic_no_replace=True)
    assert store.complete_publication(content_hash(current))["status"] == "committed"
    assert store.read() == current
    assert sorted(path.name for path in store.root.iterdir()) == [
        "revision-0001.json",
        "revision-0002.json",
    ]


def test_completion_does_not_create_absent_storage(local):
    store = S3ExtensionStore(local[0])
    with pytest.raises((OSError, RunnerTrustError)):
        store.complete_publication("sha256:" + "0" * 64)
    assert not store.root.exists()
