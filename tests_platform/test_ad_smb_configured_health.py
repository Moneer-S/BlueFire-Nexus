"""Fake signed-payload hook only; no network, keys or native inventory."""

from copy import deepcopy

import pytest

from bluefire import ad_smb_admitted_transport as admitted
from bluefire.ad_smb_contract import AdSmbError
from bluefire.runner_transport import AuthenticatedRunnerClient, AuthenticatedRunnerServer
from bluefire.runner_transport_errors import RunnerAuthenticationError
from tests_platform.test_ad_smb_admitted_transport import bare_client
from tests_platform.test_ad_smb_admitted_transport import no_effects as no_effects
from tests_platform.test_ad_smb_contract import pin
from tests_platform.test_ad_smb_receiver import original


def health(value, channel):
    numbers = {
        "rows",
        "capacity",
        "execute_rows",
        "execute_capacity",
        "control_reserve",
        "blob_bytes",
        "committed_bytes",
        "byte_capacity",
        "execute_byte_capacity",
        "control_reserve_bytes",
    }
    row = {
        key: "synthetic"
        for key in (
            "runner_id",
            "client_id",
            "server_instance_id",
            "transport",
            "tls",
            "server_fingerprint",
            "client_fingerprint",
            "authenticated_peer_fingerprint",
            "enrollment_generation",
            "runner_binary_digest",
            "inventory_digest",
        )
    }
    row.update(
        schema_version="bluefire.runner-health.v1",
        status="ready",
        profile_id=value["profile"]["profile_id"],
        execution_timeout_seconds=30,
        ledger={**dict.fromkeys(numbers, 1), "generation": pin("e"), "accepting_execute": True},
        ad_smb_admission=admitted._admission(
            channel, pin("9") if channel.to_dict()["role"] == "client" else None
        ),
    )
    return row


@pytest.mark.parametrize("phase", ["inspect", "baseline"])
def test_exact_config_health_is_only_configuration_claim(monkeypatch, phase):
    value, channel = original(phase)
    client = bare_client(value, channel)
    expected = health(value, channel)
    client._ad_expected_admission = deepcopy(expected["ad_smb_admission"])
    monkeypatch.setattr(AuthenticatedRunnerClient, "health", lambda _: expected)
    assert client.health() == expected
    assert client.health()["ad_smb_admission"]["readiness_scope"] == "configuration_only"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.pop("ad_smb_admission"),
        lambda row: row.update(extra="private data"),
        lambda row: row["ad_smb_admission"].update(credential_binding_digest=pin("e")),
        lambda row: row["ad_smb_admission"].update(profile_digest=pin("e")),
        lambda row: row["ad_smb_admission"].update(readiness_scope="physical_host_attested"),
        lambda row: row["ledger"].update(accepting_execute=False),
        lambda row: row["ledger"].update(rows=True),
        lambda row: row["ledger"].update(extra=0),
        lambda row: row.update(execution_timeout_seconds=float("inf")),
    ],
)
def test_stale_not_admitted_or_open_health_is_refused(monkeypatch, mutate):
    value, channel = original("baseline")
    client = bare_client(value, channel)
    row = health(value, channel)
    client._ad_expected_admission = deepcopy(row["ad_smb_admission"])
    mutate(row)
    monkeypatch.setattr(AuthenticatedRunnerClient, "health", lambda _: row)
    with pytest.raises((AdSmbError, RunnerAuthenticationError)):
        client.health()


def test_health_extension_is_in_payload_before_existing_signer_and_rechecks_metadata(monkeypatch):
    value, channel = original("baseline")
    server = object.__new__(admitted.AdmittedAdSmbReceiver)
    server.channel = channel
    server._ad_credential_root, server._ad_scope = "synthetic-root", "synthetic-scope"
    server._ad_credential_digest, server._ad_secret_provider = pin("9"), None
    calls = []
    monkeypatch.setattr(admitted, "load_credential_binding", lambda *a, **k: calls.append(k))
    monkeypatch.setattr(
        AuthenticatedRunnerServer,
        "_success_response",
        lambda self, request, enrollment, payload: {"signed": payload},
    )
    result = server._success_response({"operation": "health"}, object(), {"status": "ready"})
    assert result["signed"]["ad_smb_admission"] == admitted._admission(channel, pin("9"))
    assert calls[0]["expected_digest"] == pin("9")
    calls.clear()
    assert server._success_response({"operation": "recover"}, object(), {"original": True}) == {
        "signed": {"original": True}
    }
    assert calls == []
