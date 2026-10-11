"""Read-only diagnostics with real private storage and synthetic runtime evidence."""

from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import s3_access_runtime
from bluefire import s3_access_setup_status as status
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_extension_store import S3ExtensionStore
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_extension import imported, publish
from tests_platform.test_s3_access_extension import local as local
from tests_platform.test_s3_access_setup_transport import client, server, snapshot
from tests_platform.test_s3_access_wire import NOW, credential_row


@pytest.fixture
def portable(local, monkeypatch):
    monkeypatch.setattr(status, "require_owned_host", lambda: None)
    monkeypatch.setattr(status, "validate_runtime", s3_access_runtime.validate_runtime)
    return local


def inspect(local, clock=lambda: NOW, profile_id=None):
    enrollment, configuration, _ = local
    profile_id = profile_id or configuration["environments"][0]["profile"]["profile_id"]
    value = status.inspect_status(enrollment, profile_id, clock=clock)
    return status.validate_status(value, profile_id=profile_id)


def test_missing_status_does_not_create_an_extension(portable):
    root = S3ExtensionStore(portable[0]).root
    assert inspect(portable)["configuration_state"] == "missing"
    assert not root.exists()


@pytest.mark.parametrize("reference", ["absent", "current", "expired"])
def test_independent_states_never_decrypt_cloud_material(portable, monkeypatch, reference):
    if reference == "absent":
        publish(portable)
    else:
        imported(portable)
    enrollment, _, provider = portable
    original = provider.unprotect

    def unprotect(purpose, opaque):
        assert not purpose.startswith("bluefire.s3-temporary.v1:")
        return original(purpose, opaque)

    monkeypatch.setattr(provider, "unprotect", unprotect)
    root = S3ExtensionStore(enrollment).root
    before = snapshot(root)
    value = inspect(
        portable, clock=lambda: NOW + timedelta(days=1) if reference == "expired" else NOW
    )
    assert value["configuration_state"] == "configured"
    assert value["environments"] == [
        {
            "environment_id": "test-environment",
            "runtime_state": "verified",
            "access_reference_state": reference,
            "scope_state": "not_current" if reference == "expired" else "current",
            "fixture_generation": 1,
        }
    ]
    assert snapshot(root) == before
    for secret in credential_row().values():
        assert secret not in str(value)
    assert all(
        key not in str(value)
        for key in ("runtime_root", "ledger_root", "opaque", "purpose", "bucket", "account_id")
    )


@pytest.mark.parametrize("mutation", ["missing", "changed"])
def test_runtime_failure_is_separate_from_current_reference(portable, monkeypatch, mutation):
    imported(portable)

    def runtime(*args):
        if mutation == "missing":
            raise OSError("private installation path")
        return SimpleNamespace(worker_generation="sha256:" + "f" * 64)

    monkeypatch.setattr(status, "validate_runtime", runtime)
    row = inspect(portable)["environments"][0]
    assert row["runtime_state"] == "unavailable"
    assert row["access_reference_state"] == "current"


@pytest.mark.parametrize("valid", [False, True])
def test_pending_state_is_retained_and_never_completed(portable, valid):
    publish(portable)
    store = S3ExtensionStore(portable[0])
    payload = canonical_json_bytes(store.read()) if valid else b"{}"
    with _PinnedPrivateDirectory(store.root) as directory:
        directory.create(".pending.json", payload, maximum=len(payload))
    before = snapshot(store.root)
    value = inspect(portable)
    assert value["configuration_state"] == ("incomplete" if valid else "invalid")
    assert value["revision_digest"] is None and value["environments"] == []
    assert snapshot(store.root) == before


def test_revision_change_during_runtime_check_is_not_readiness(portable, monkeypatch):
    publish(portable)
    original = status.validate_runtime

    def runtime(*args):
        imported(portable)
        return original(*args)

    monkeypatch.setattr(status, "validate_runtime", runtime)
    assert inspect(portable)["configuration_state"] == "invalid"


def test_other_profile_does_not_receive_environment_metadata(portable):
    imported(portable)
    value = inspect(portable, profile_id="another-profile")
    assert value["configuration_state"] == "profile_missing"
    assert value["environments"] == []


@pytest.mark.parametrize(
    "mutation",
    [
        "field",
        "profile",
        "context",
        "revision",
        "state",
        "extra_env",
        "generation",
        "runtime",
        "reference",
        "scope",
    ],
)
def test_response_contract_is_closed_and_bound(portable, mutation):
    imported(portable)
    value = deepcopy(inspect(portable))
    profile_id = value["profile_id"]
    if mutation == "field":
        value["private_path"] = "/private"
    elif mutation == "profile":
        value["profile_id"] = "another-profile"
    elif mutation == "context":
        value["context_digest"] = "sha256:" + "f" * 64
    elif mutation == "revision":
        value["revision_digest"] = None
    elif mutation == "state":
        value["configuration_state"] = "missing"
    elif mutation == "extra_env":
        value["environments"] *= 2
    else:
        key, replacement = {
            "generation": ("fixture_generation", True),
            "runtime": ("runtime_state", "ready"),
            "reference": ("access_reference_state", "verified_aws"),
            "scope": ("scope_state", "renewed"),
        }[mutation]
        value["environments"][0][key] = replacement
    if mutation != "context":
        value["context_digest"] = content_hash(
            {key: item for key, item in value.items() if key != "context_digest"}
        )
    with pytest.raises(S3AccessError):
        status.validate_status(value, profile_id=profile_id)


def test_real_mtls_checks_setup_without_starting_a_worker(portable, monkeypatch):
    imported(portable)
    expected = inspect(portable)
    original = status.inspect_status
    monkeypatch.setattr(
        status,
        "inspect_status",
        lambda enrollment, profile_id: original(enrollment, profile_id, clock=lambda: NOW),
    )
    before = snapshot(S3ExtensionStore(portable[0]).root)
    with server(portable) as host:
        value = client(portable, host).s3_access_setup_status()
        assert value == expected
        assert host.runner.calls == 0
    assert snapshot(S3ExtensionStore(portable[0]).root) == before
    assert host._serve_thread is None or not host._serve_thread.is_alive()


def test_unsupported_host_does_not_read_storage(local, monkeypatch):
    def unsupported():
        raise S3AccessError("unsupported")

    monkeypatch.setattr(status, "require_owned_host", unsupported)
    monkeypatch.setattr(
        status, "S3ExtensionStore", lambda *_: pytest.fail("unsupported host read storage")
    )
    assert inspect(local)["configuration_state"] == "unsupported_host"
