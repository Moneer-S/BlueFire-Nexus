"""The S3 discovery extension uses authenticated host configuration only."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import s3_access_transport as module
from bluefire.runner_transport_errors import RunnerAuthenticationError
from bluefire.s3_access_host_config import public_environments
from tests_platform.test_s3_access_host_config import checked, configured


@pytest.fixture
def host(monkeypatch):
    configuration = checked(configured())
    entry = configuration["environments"][0]
    monkeypatch.setattr(module, "read_configuration", lambda enrollment: configuration)
    from bluefire import s3_access_runtime

    monkeypatch.setattr(
        s3_access_runtime,
        "validate_runtime",
        lambda *args: SimpleNamespace(worker_generation=entry["worker_generation"]),
    )
    descriptor = {"action_id": module.ACTION, "capabilities": ["cloud_aws_s3_access"]}
    server = SimpleNamespace(
        _require_payload=lambda request, fields: None,
        _verified_runner_binary_digest=lambda: "sha256:" + "f" * 64,
        _validated_inventory=lambda enrollment: ({"actions": [descriptor]}, {}),
        runner=SimpleNamespace(s3_access_admission_protocol=module.SCHEMA),
    )
    return SimpleNamespace(
        configuration=configuration, entry=entry, server=server, descriptor=descriptor
    )


def response(host):
    return module.server_environments(
        host.server,
        {"profile_id": host.entry["profile"]["profile_id"]},
        object(),
        refusal=RuntimeError,
    )


def test_discovery_contains_no_secret_reference_or_runtime_path(host):
    rows = response(host)["environments"]
    assert len(rows) == 1 and rows[0]["available"] is True
    assert rows[0]["environment"] == public_environments(host.configuration)[0]
    assert "credential_reference" not in str(rows)
    assert "runtime_root" not in str(rows)
    assert "ledger_root" not in str(rows)


@pytest.mark.parametrize("kind", ["authority", "capability", "action"])
def test_discovery_requires_new_native_capability_and_launch_authority(host, kind):
    if kind == "authority":
        host.server.runner.s3_access_admission_protocol = None
    elif kind == "capability":
        host.descriptor["capabilities"] = ["network_loopback"]
    else:
        host.descriptor["action_id"] = "tool.adapter.v1"
    assert response(host) == {"environments": []}


def test_protected_runtime_failure_retains_readable_unavailable_environment(host, monkeypatch):
    from bluefire import s3_access_runtime

    def unavailable(*args):
        raise ValueError("private path")

    monkeypatch.setattr(s3_access_runtime, "validate_runtime", unavailable)
    row = response(host)["environments"][0]
    assert row["available"] is False and row["problem"] == "runtime_unavailable"
    assert "private path" not in str(row)


def client(host, payload):
    return SimpleNamespace(
        profile_id=host.entry["profile"]["profile_id"],
        _call=lambda *args, **kwargs: payload,
        _random_task=lambda prefix: prefix,
    )


def test_client_validates_exact_enrolled_response(host):
    payload = response(host)
    assert module.client_environments(client(host, payload)) == payload["environments"]


@pytest.mark.parametrize("kind", ["extra", "duplicate", "seal", "profile", "boolean", "secret"])
def test_client_rejects_ambiguous_or_unsealed_discovery(host, kind):
    payload = deepcopy(response(host))
    row = payload["environments"][0]
    if kind == "extra":
        payload["unknown"] = True
    elif kind == "duplicate":
        payload["environments"].append(deepcopy(row))
    elif kind == "seal":
        row["profile"]["policy_digest"] = "sha256:" + "0" * 64
    elif kind == "profile":
        row["profile"]["profile_id"] = "other-profile"
    elif kind == "boolean":
        row["available"] = 1
    else:
        row["secret"] = "not-allowed"
    with pytest.raises(RunnerAuthenticationError, match="response is invalid"):
        module.client_environments(client(host, payload))


def test_shared_enrollment_projection_preserves_existing_binding():
    from bluefire.runner_transport import _enrollment_binding
    from bluefire.util import content_hash

    public = {
        "runner_id": "runner",
        "client_id": "client",
        "ca_fingerprint": "ca",
        "server_fingerprint": "server",
        "client_fingerprint": "client-certificate",
    }
    enrollment = SimpleNamespace(runner_id="runner", client_id="client", metadata=public)
    assert _enrollment_binding(enrollment, "peer") == {
        **public,
        "peer_fingerprint": "peer",
        "enrollment_generation": content_hash(public),
    }


@pytest.mark.parametrize(
    "field,value",
    [("state", 1), ("cancelled", 1), ("cancellation_requested", 1), ("original_task_id", "other")],
)
def test_shared_cancellation_validator_keeps_closed_original_contract(field, value):
    from bluefire.runner_transport import AuthenticatedRunnerClient

    row = {
        "original_task_id": "task",
        "original_request_hash": "hash",
        "state": "cancelled",
        "cancellation_requested": True,
        "cancelled": True,
    }
    assert AuthenticatedRunnerClient._validated_cancellation_payload(row, "task", "hash") is row
    row[field] = value
    with pytest.raises(RunnerAuthenticationError, match="cancellation response is invalid"):
        AuthenticatedRunnerClient._validated_cancellation_payload(row, "task", "hash")
