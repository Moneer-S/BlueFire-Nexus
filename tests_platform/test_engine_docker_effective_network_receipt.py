"""A V2 network receipt follows a validated and durably published inspect only."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.engine_docker_custody import ProductStoreDockerProxyCustody
from bluefire.engine_docker_proxy import (
    DockerPolicyProxy,
    DockerProxyState,
    DockerV2EffectiveNetworkBinding,
    EngineDockerProxyError,
)
from bluefire.product_store import ProductStore
from bluefire.util import content_hash
from tests_platform.test_engine_docker_control import policy_v2
from tests_platform.test_engine_docker_proxy import (
    CONTAINER_ID,
    Cancel,
    Clock,
    Transport,
    inspect_body_v2,
    ownership,
    raw_request,
    raw_response,
)


def _binding(policy) -> DockerV2EffectiveNetworkBinding:
    return DockerV2EffectiveNetworkBinding(
        attempt_id=policy.attempt_id,
        claim_ref="sha256:" + "a" * 64,
        controller_fence="sha256:" + "b" * 64,
        network_policy_digest=policy.network_policy_digest,
        target_plan_digest="sha256:" + "c" * 64,
    )


def _inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_phase: str | None = None,
    extra_network: bool = False,
):
    policy = policy_v2()
    observation = inspect_body_v2(policy)
    if extra_network:
        observation["NetworkSettings"]["Networks"]["bridge"] = {"NetworkID": "e" * 64}
    custody = ProductStoreDockerProxyCustody(
        ProductStore(tmp_path / "network-receipt.sqlite"),
        policy=policy,
        initial_state=DockerProxyState.create(ownership(pending=True)),
    )
    if fail_phase is not None:
        original_append = custody.append

        def fail_published(record):
            if record.phase == fail_phase:
                raise RuntimeError("audit unavailable")
            return original_append(record)

        monkeypatch.setattr(custody, "append", fail_published)
    proxy = DockerPolicyProxy(
        policy=policy,
        ownership=ownership(pending=True),
        transport=Transport(raw_response(200, observation)),
        audit=custody,
        custody=custody,
        monotonic_ns=Clock(),
        effective_network_binding=_binding(policy),
    )
    assert proxy.effective_network_receipt() is None
    result = proxy.handle(raw_request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), Cancel())
    return policy, custody, proxy, result


def test_v2_effective_network_receipt_binds_published_inspect_and_sole_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, custody, proxy, result = _inspection(tmp_path, monkeypatch)
    assert result.status_code == 200
    receipt = proxy.effective_network_receipt()
    assert receipt is not None
    assert receipt.attempt_id == policy.attempt_id
    assert receipt.container_id == CONTAINER_ID
    assert receipt.network_policy_digest == policy.network_policy_digest
    assert receipt.observed_network_id == policy.network_id
    assert receipt.observed_network_name == policy.network_name
    assert receipt.disallowed_networks_absent is True
    published = custody.reopen().audits[-1]
    assert receipt.published_audit_ref == content_hash(published.to_dict())
    assert published.phase == "published"
    assert published.operation == "container_inspect"
    assert receipt.inspect_response_digest == published.response_digest
    assert receipt.receipt_ref == content_hash(receipt.to_dict())
    receipt.require(binding=_binding(policy), policy=policy, state=proxy.snapshot())


@pytest.mark.parametrize("fail_phase,extra_network", [("published", False), (None, True)])
def test_v2_effective_network_receipt_refuses_unpublished_or_extra_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_phase: str | None,
    extra_network: bool,
) -> None:
    _policy, _custody, proxy, result = _inspection(
        tmp_path, monkeypatch, fail_phase=fail_phase, extra_network=extra_network
    )
    assert result.status_code == 503
    assert proxy.effective_network_receipt() is None


def test_v2_effective_network_binding_and_receipt_refuse_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, custody, proxy, result = _inspection(tmp_path, monkeypatch)
    assert result.status_code == 200
    receipt = proxy.effective_network_receipt()
    assert receipt is not None
    with pytest.raises(EngineDockerProxyError, match="not current"):
        receipt.require(
            binding=replace(_binding(policy), controller_fence="sha256:" + "f" * 64),
            policy=policy,
            state=proxy.snapshot(),
        )
    with pytest.raises(EngineDockerProxyError, match="binding differs"):
        DockerPolicyProxy(
            policy=policy,
            ownership=ownership(pending=True),
            transport=Transport(raw_response(200, inspect_body_v2(policy))),
            audit=custody,
            custody=custody,
            monotonic_ns=Clock(),
            effective_network_binding=replace(
                _binding(policy), network_policy_digest="sha256:" + "f" * 64
            ),
        )


def test_v2_effective_network_receipt_fences_new_unsettled_custody_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, custody, proxy, result = _inspection(tmp_path, monkeypatch)
    assert result.status_code == 200
    assert proxy.effective_network_receipt() is not None
    custody.prepare(
        request_ref="sha256:" + "d" * 64,
        sequence=2,
        operation="container_inspect",
        request_digest="sha256:" + "e" * 64,
        policy_digest=policy.policy_digest,
        state=proxy.snapshot(),
    )
    assert proxy.effective_network_receipt() is None
