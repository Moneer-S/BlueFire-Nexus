"""Installed V2 attachment refuses dispatch without current owned placement."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from bluefire.engine_docker_custody import ProductStoreDockerProxyCustody
from bluefire.engine_docker_proxy import (
    DockerPolicyProxy,
    DockerProxyState,
    DockerV2EffectiveNetworkBinding,
)
from bluefire.engine_installed_v2_exec_attachment import (
    ControllerOwnedV2NetworkDispatch,
    InstalledV2ExecAttachmentError,
    _require_published_container_provenance,
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
from tests_platform.test_engine_installed_v2_openers import _case


def _guarded(tmp_path: Path):
    _binding, _delegation, _accepted, plan, snapshot = _case()
    activation = snapshot.activation
    policy = policy_v2()
    target_digest = content_hash(
        {
            "scope": plan.to_dict()["admission"]["scope"],
            "network_plan": plan.to_dict()["admission"]["network_plan"],
        }
    )
    custody = ProductStoreDockerProxyCustody(
        ProductStore(tmp_path / "product.sqlite"),
        policy=policy,
        initial_state=DockerProxyState.create(ownership(pending=True)),
    )
    transport = Transport(raw_response(200, inspect_body_v2(policy)))
    proxy = DockerPolicyProxy(
        policy=policy,
        ownership=ownership(pending=True),
        transport=transport,
        audit=custody,
        custody=custody,
        monotonic_ns=Clock(),
        effective_network_binding=DockerV2EffectiveNetworkBinding(
            attempt_id=policy.attempt_id,
            claim_ref=activation.claim_ref,
            controller_fence=activation.controller_fence,
            network_policy_digest=policy.network_policy_digest,
            target_plan_digest=target_digest,
        ),
    )
    active = [True]
    held = [False]

    def current():
        if not active[0]:
            raise RuntimeError("transaction inactive")
        return activation

    @contextmanager
    def hold_active():
        held[0] = True
        try:
            yield current()
        finally:
            held[0] = False

    dispatch = ControllerOwnedV2NetworkDispatch(
        proxy=proxy,
        policy=policy,
        launch_plan=plan,
        claim_ref=activation.claim_ref,
        controller_fence=activation.controller_fence,
        require_active_activation=current,
        hold_active_scope=hold_active,
    )
    return dispatch, transport, active, held, activation


def test_fresh_inspect_is_published_and_bound_to_active_claim(tmp_path: Path) -> None:
    dispatch, transport, active, held, _activation = _guarded(tmp_path)
    original_exchange = transport.exchange

    def exchange_under_hold(*args, **kwargs):
        assert held[0] is True
        return original_exchange(*args, **kwargs)

    transport.exchange = exchange_under_hold
    receipt = dispatch.refresh_network_receipt(container_id=CONTAINER_ID, cancellation=Cancel())
    assert receipt.container_id == CONTAINER_ID
    assert receipt.target_plan_digest == dispatch.target_plan_digest
    assert len(transport.seen) == 1
    assert held[0] is False
    active[0] = False
    with pytest.raises(RuntimeError, match="transaction inactive"):
        dispatch.refresh_network_receipt(container_id=CONTAINER_ID, cancellation=Cancel())
    assert len(transport.seen) == 1


def test_other_activation_cannot_reuse_network_receipt(tmp_path: Path) -> None:
    dispatch, transport, _active, _held, _activation = _guarded(tmp_path)
    dispatch._require_active_activation = lambda: object()
    with pytest.raises(InstalledV2ExecAttachmentError, match="active execution identity"):
        dispatch.handle(raw_request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), Cancel())
    assert transport.seen == []


def test_seeded_owned_container_cannot_become_installed_attachment(tmp_path: Path) -> None:
    policy = policy_v2()
    custody = ProductStoreDockerProxyCustody(
        ProductStore(tmp_path / "product.sqlite"),
        policy=policy,
        initial_state=DockerProxyState.create(ownership(container=True)),
    )
    with pytest.raises(InstalledV2ExecAttachmentError, match="published create"):
        _require_published_container_provenance(custody.reopen(), container_id=CONTAINER_ID)
